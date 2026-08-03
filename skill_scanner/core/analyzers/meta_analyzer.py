# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
LLM Meta-Analyzer for Agent Skills Security Scanner.

Performs second-pass LLM analysis on findings from multiple analyzers to:
- Filter false positives based on contextual understanding
- Prioritize findings by actual exploitability and impact
- Correlate related findings across analyzers
- Detect threats that other analyzers may have missed
- Provide actionable remediation guidance

The meta-analyzer runs AFTER all other analyzers complete, reviewing their
collective findings to provide expert-level security assessment.

Requirements:
    - Enable via CLI --enable-meta flag
    - Requires LLM API key (uses same config as LLM analyzer)
    - Works best with 2+ analyzers for cross-correlation
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...threats.threats import ThreatMapping
from ..models import Finding, ScanResult, Severity, Skill, ThreatCategory
from .base import BaseAnalyzer
from .llm_provider_config import ProviderConfig
from .llm_request_handler import (
    _TEMPERATURE_UNSET,
    LLMRequestHandler,
    LLMTokenUsage,
    _add_token_usage,
    _empty_token_usage,
    _extract_token_usage,
    _resolve_temperature,
)
from .llm_request_options import resolve_llm_user, supports_openai_user_param

if TYPE_CHECKING:
    from ...core.scan_policy import LLMAnalysisPolicy, ScanPolicy

logger = logging.getLogger(__name__)

# Meta-analysis responses contain substantially more than a classification bit:
# confidence, rationale, impact, and (occasionally) correlations/recommendations.
# Keep enough output headroom for those fields instead of filling max_tokens with
# the optimistic minimum representation.
_ESTIMATED_OUTPUT_TOKENS_PER_FINDING = 80
_OUTPUT_TOKEN_UTILIZATION = 0.75

# Check for LiteLLM availability
try:
    from litellm import acompletion

    LITELLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False
    acompletion = None


@dataclass
class MetaAnalysisResult:
    """Result of meta-analysis on security findings.

    Attributes:
        validated_findings: Findings confirmed as true positives with enriched data.
        false_positives: Findings identified as likely false positives.
        missed_threats: NEW threats found by meta-analyzer that other analyzers missed.
        priority_order: Ordered list of finding indices by priority (highest first).
        correlations: Groups of related findings.
        recommendations: Actionable recommendations for remediation.
        overall_risk_assessment: Summary risk assessment for the skill.
        analysis_warnings: Explicit descriptions of batches that could not be
            fully analyzed. Findings in those batches are retained safely.
    """

    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    missed_threats: list[dict[str, Any]] = field(default_factory=list)
    priority_order: list[int] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    overall_risk_assessment: dict[str, Any] = field(default_factory=dict)
    analysis_warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "validated_findings": self.validated_findings,
            "false_positives": self.false_positives,
            "missed_threats": self.missed_threats,
            "priority_order": self.priority_order,
            "correlations": self.correlations,
            "recommendations": self.recommendations,
            "overall_risk_assessment": self.overall_risk_assessment,
            "analysis_warnings": self.analysis_warnings,
            "summary": {
                "total_original": len(self.validated_findings) + len(self.false_positives),
                "validated_count": len(self.validated_findings),
                "false_positive_count": len(self.false_positives),
                "missed_threats_count": len(self.missed_threats),
                "recommendations_count": len(self.recommendations),
            },
        }

    def get_validated_findings(self, skill: Skill) -> list[Finding]:
        """Convert validated findings back to Finding objects.

        Args:
            skill: The skill being analyzed (for context).

        Returns:
            List of validated Finding objects with meta-analysis enrichments.
        """
        findings: list[Finding] = []
        for finding_data in self.validated_findings:
            try:
                # Parse severity
                severity_str = finding_data.get("severity", "MEDIUM").upper()
                severity = Severity(severity_str)

                # Parse category
                category_str = finding_data.get("category", "policy_violation")
                try:
                    category = ThreatCategory(category_str)
                except ValueError:
                    category = ThreatCategory.POLICY_VIOLATION

                # Build metadata with meta-analysis enrichments
                metadata = dict(finding_data.get("metadata", {}))
                if "confidence" in finding_data:
                    metadata["meta_confidence"] = finding_data["confidence"]
                if "confidence_reason" in finding_data:
                    metadata["meta_confidence_reason"] = finding_data["confidence_reason"]
                if "exploitability" in finding_data:
                    metadata["meta_exploitability"] = finding_data["exploitability"]
                if "impact" in finding_data:
                    metadata["meta_impact"] = finding_data["impact"]
                if "priority_rank" in finding_data:
                    metadata["meta_priority_rank"] = finding_data["priority_rank"]
                degraded = bool(finding_data.get("meta_analysis_degraded"))
                metadata["meta_validated"] = not degraded
                if degraded:
                    metadata["meta_analysis_degraded"] = True

                finding = Finding(
                    id=finding_data.get("id", f"meta_{skill.name}_{len(findings)}"),
                    rule_id=finding_data.get("rule_id", "META_VALIDATED"),
                    category=category,
                    severity=severity,
                    title=finding_data.get("title", ""),
                    description=finding_data.get("description", ""),
                    file_path=finding_data.get("file_path"),
                    line_number=finding_data.get("line_number"),
                    snippet=finding_data.get("snippet"),
                    remediation=finding_data.get("remediation"),
                    analyzer="meta",
                    metadata=metadata,
                )
                findings.append(finding)
            except Exception:
                # Skip malformed findings
                continue
        return findings

    def get_missed_threats(self, skill: Skill) -> list[Finding]:
        """Convert missed threats to Finding objects.

        These are NEW threats detected by meta-analyzer that other analyzers missed.

        Args:
            skill: The skill being analyzed.

        Returns:
            List of new Finding objects from meta-analysis.
        """
        findings = []
        for idx, threat_data in enumerate(self.missed_threats):
            try:
                severity_str = threat_data.get("severity", "HIGH").upper()
                severity = Severity(severity_str)

                # Map threat category from AITech code if available
                aitech_code = threat_data.get("aitech")
                if aitech_code:
                    category_str = ThreatMapping.get_threat_category_from_aitech(aitech_code)
                else:
                    category_str = threat_data.get("category", "policy_violation")

                try:
                    category = ThreatCategory(category_str)
                except ValueError:
                    category = ThreatCategory.POLICY_VIOLATION

                finding = Finding(
                    id=f"meta_missed_{skill.name}_{idx}",
                    rule_id="META_DETECTED",
                    category=category,
                    severity=severity,
                    title=threat_data.get("title", "Threat detected by meta-analysis"),
                    description=threat_data.get("description", ""),
                    file_path=threat_data.get("file_path"),
                    line_number=threat_data.get("line_number"),
                    snippet=threat_data.get("evidence"),
                    remediation=threat_data.get("remediation"),
                    analyzer="meta",
                    metadata={
                        "meta_detected": True,
                        "detection_reason": threat_data.get("detection_reason", ""),
                        "meta_confidence": threat_data.get("confidence", "MEDIUM"),
                        "aitech": aitech_code,
                    },
                )
                findings.append(finding)
            except Exception:
                continue
        return findings


class MetaAnalysisTruncatedError(RuntimeError):
    """Raised when the provider reports an output-token truncation."""


class MetaAnalysisParseError(ValueError):
    """Raised when a meta-analysis response cannot be parsed as valid JSON."""


class MetaAnalyzer(BaseAnalyzer):
    """LLM-based meta-analyzer for reviewing and refining security findings.

    This analyzer performs a second-pass analysis on findings from all other
    analyzers to provide expert-level security assessment. It:
    - Filters false positives using contextual understanding
    - Prioritizes findings by actual risk
    - Correlates related findings across analyzers
    - Detects threats that other analyzers may have missed
    - Provides specific remediation recommendations

    The meta-analyzer runs AFTER all other analyzers complete.

    Example:
        >>> meta = MetaAnalyzer(model="claude-3-5-sonnet-20241022", api_key=api_key)
        >>> result = await meta.analyze_with_findings(skill, all_findings, analyzers_used)
        >>> validated = result.get_validated_findings(skill)
    """

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        max_tokens: int = 8192,
        temperature: Any = _TEMPERATURE_UNSET,
        max_retries: int = 3,
        timeout: int = 180,
        # Azure-specific
        base_url: str | None = None,
        api_version: str | None = None,
        # AWS Bedrock-specific
        aws_region: str | None = None,
        aws_profile: str | None = None,
        aws_session_token: str | None = None,
        llm_user: str | None = None,
        # Policy (optional – uses generous defaults × meta multiplier)
        policy: ScanPolicy | None = None,
    ):
        """Initialize the Meta Analyzer.

        Args:
            model: Model identifier (defaults to claude-3-5-sonnet-20241022)
            api_key: API key (if None, reads from environment)
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature (low for consistency).  Pass
                ``None`` to omit the parameter from the request entirely —
                required for models that reject ``temperature`` (e.g. Claude
                4.x via Bedrock, OpenAI o1-series).  When omitted, resolves
                from ``SKILL_SCANNER_META_LLM_TEMPERATURE`` (then
                ``SKILL_SCANNER_LLM_TEMPERATURE``); a numeric value is
                parsed as a float and ``"none"`` drops the parameter.
            max_retries: Max retry attempts on rate limits
            timeout: Request timeout in seconds
            base_url: Custom base URL (for Azure)
            api_version: API version (for Azure)
            aws_region: AWS region (for Bedrock)
            aws_profile: AWS profile name (for Bedrock)
            aws_session_token: AWS session token (for Bedrock)
            llm_user: Optional raw Chat Completions user field for OpenAI-compatible routes.
            policy: Scan policy providing LLM context budget thresholds.
                The meta analyzer applies ``meta_budget_multiplier`` on top of
                the base limits.  When ``None``, generous defaults are used.
        """
        super().__init__("meta_analyzer")

        # Store LLM analysis budget policy (lazy import to avoid circular deps)
        if policy is not None:
            self.llm_policy: LLMAnalysisPolicy = policy.llm_analysis
        else:
            from ...core.scan_policy import LLMAnalysisPolicy

            self.llm_policy = LLMAnalysisPolicy()

        if not LITELLM_AVAILABLE:
            raise ImportError("LiteLLM is required for MetaAnalyzer. Install with: pip install litellm")

        # Use SKILL_SCANNER_* env vars only (no provider-specific fallbacks)
        # Priority: meta-specific > scanner-wide
        self.api_key = (
            api_key
            or os.getenv("SKILL_SCANNER_META_LLM_API_KEY")  # Meta-specific
            or os.getenv("SKILL_SCANNER_LLM_API_KEY")  # Scanner-wide
        )
        self.model = (
            model
            or os.getenv("SKILL_SCANNER_META_LLM_MODEL")  # Meta-specific
            or os.getenv("SKILL_SCANNER_LLM_MODEL")  # Scanner-wide
            or "claude-3-5-sonnet-20241022"
        )
        self.base_url = (
            base_url
            or os.getenv("SKILL_SCANNER_META_LLM_BASE_URL")  # Meta-specific
            or os.getenv("SKILL_SCANNER_LLM_BASE_URL")  # Scanner-wide
        )
        self.api_version = (
            api_version
            or os.getenv("SKILL_SCANNER_META_LLM_API_VERSION")  # Meta-specific
            or os.getenv("SKILL_SCANNER_LLM_API_VERSION")  # Scanner-wide
        )
        self.provider = os.getenv("SKILL_SCANNER_LLM_PROVIDER")
        self.llm_user = resolve_llm_user(llm_user)

        # AWS Bedrock settings
        self.aws_region = aws_region
        self.aws_profile = aws_profile
        self.aws_session_token = aws_session_token
        self.is_bedrock = self.model and "bedrock/" in self.model

        # Validate configuration
        if not self.api_key and not self.is_bedrock:
            raise ValueError(
                "Meta-Analyzer LLM API key not configured. "
                "Set SKILL_SCANNER_META_LLM_API_KEY or SKILL_SCANNER_LLM_API_KEY environment variable."
            )

        # Azure validation
        if self.model and self.model.startswith("azure/"):
            if not self.base_url:
                raise ValueError(
                    "Azure OpenAI base URL not configured for meta-analyzer. "
                    "Set SKILL_SCANNER_META_LLM_BASE_URL environment variable."
                )
            if not self.api_version:
                raise ValueError(
                    "Azure OpenAI API version not configured for meta-analyzer. "
                    "Set SKILL_SCANNER_META_LLM_API_VERSION environment variable."
                )

        self.max_tokens = max_tokens
        # Resolve temperature: explicit arg > meta-specific env > scanner-wide
        # env > default.  ``None`` here means "omit ``temperature`` from the
        # outgoing request" (Claude 4.x on Bedrock, OpenAI o1-series).
        if temperature is _TEMPERATURE_UNSET and "SKILL_SCANNER_META_LLM_TEMPERATURE" in os.environ:
            self.temperature = _resolve_temperature(
                _TEMPERATURE_UNSET,
                "SKILL_SCANNER_META_LLM_TEMPERATURE",
                default=0.1,
            )
        else:
            self.temperature = _resolve_temperature(
                temperature,
                "SKILL_SCANNER_LLM_TEMPERATURE",
                default=0.1,
            )
        self.max_retries = max_retries
        self.timeout = timeout

        # Cumulative token usage across all LLM calls in the most recent analyze_with_findings() run.
        self._llm_usage: LLMTokenUsage = _empty_token_usage()

        # Load prompts
        self._load_prompts()

    @property
    def llm_usage(self) -> LLMTokenUsage:
        """Cumulative token usage from the most recent analyze_with_findings() run."""
        return dict(self._llm_usage)  # type: ignore[return-value]

    def _load_prompts(self):
        """Load meta-analysis prompt templates from files."""
        prompts_dir = Path(__file__).parent.parent.parent / "data" / "prompts"
        meta_prompt_file = prompts_dir / "skill_meta_analysis_prompt.md"

        try:
            if meta_prompt_file.exists():
                self.system_prompt = meta_prompt_file.read_text(encoding="utf-8")
            else:
                logger.warning("Meta-analysis prompt not found at %s", meta_prompt_file)
                self.system_prompt = self._get_default_system_prompt()
        except Exception as e:
            logger.warning("Failed to load meta-analysis prompt: %s", e)
            self.system_prompt = self._get_default_system_prompt()

    def _get_default_system_prompt(self) -> str:
        """Get default system prompt if file not found."""
        return """You are a senior security analyst performing meta-analysis on Agent Skill security findings.
Your role is to review findings from multiple analyzers, identify false positives,
prioritize by actual risk, correlate related issues, and provide actionable recommendations.

Respond with JSON containing your analysis following the required schema."""

    def analyze(self, skill: Skill) -> list[Finding]:
        """Analyze a skill (no-op for meta-analyzer).

        The meta-analyzer requires findings from other analyzers.
        Use analyze_with_findings() instead.

        Args:
            skill: The skill to analyze

        Returns:
            Empty list (meta-analyzer needs existing findings)
        """
        logger.warning(
            "MetaAnalyzer.analyze() was called directly for '%s', but meta-analysis "
            "requires findings from other analyzers. Use analyze_with_findings() instead, "
            "or pass --enable-meta via the CLI. No meta-analysis was performed.",
            skill.name,
        )
        return []

    async def analyze_with_findings(
        self,
        skill: Skill,
        findings: list[Finding],
        analyzers_used: list[str],
    ) -> MetaAnalysisResult:
        """Perform meta-analysis on findings from other analyzers.

        Args:
            skill: The skill being analyzed
            findings: List of findings from all other analyzers
            analyzers_used: Names of analyzers that produced the findings

        Returns:
            MetaAnalysisResult with validated findings, false positives, and recommendations
        """
        self._llm_usage = _empty_token_usage()

        if not findings:
            return MetaAnalysisResult(
                overall_risk_assessment={
                    "risk_level": "SAFE",
                    "summary": "No security findings to analyze - skill appears safe.",
                }
            )

        # Generate random delimiters for prompt injection protection
        random_id = secrets.token_hex(16)
        start_tag = f"<!---SKILL_CONTENT_START_{random_id}--->"
        end_tag = f"<!---SKILL_CONTENT_END_{random_id}--->"

        # Build skill context with budget gating
        skill_context, budget_skipped = self._build_skill_context(skill)

        # Emit INFO findings for content that exceeded the meta budget
        lp = self.llm_policy
        for item in budget_skipped:
            threshold = item["threshold_name"]
            findings.append(
                Finding(
                    id=f"meta_budget_{item['path']}",
                    rule_id="LLM_CONTEXT_BUDGET_EXCEEDED",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title=f"'{item['path']}' excluded from meta-analysis ({item['size']:,} chars)",
                    description=item["reason"],
                    file_path=item["path"],
                    remediation=(
                        f"Increase {threshold} (currently "
                        f"{getattr(lp, threshold.split('.')[-1], '?'):,} x "
                        f"{lp.meta_budget_multiplier}) or "
                        f"llm_analysis.meta_budget_multiplier in your scan policy."
                    ),
                    analyzer="meta_analyzer",
                )
            )

        batch_size = self._max_findings_per_batch()
        result = MetaAnalysisResult()

        for batch_number, start in enumerate(range(0, len(findings), batch_size), start=1):
            indices = list(range(start, min(start + batch_size, len(findings))))
            logger.info(
                "Meta-analysis batch %d: classifying findings %d-%d (%d findings)",
                batch_number,
                indices[0],
                indices[-1],
                len(indices),
            )
            batch_result = await self._analyze_batch(
                skill=skill,
                findings=findings,
                indices=indices,
                skill_context=skill_context,
                analyzers_used=analyzers_used,
                start_tag=start_tag,
                end_tag=end_tag,
            )
            self._merge_batch_result(result, batch_result)

        # Classification entries are emitted in global index order regardless
        # of how truncation retries split a batch.
        result.validated_findings.sort(key=lambda item: item["_index"])
        result.false_positives.sort(key=lambda item: item["_index"])
        if result.analysis_warnings:
            self._mark_result_degraded(result)

        logger.info(
            "Meta-analysis complete: %d validated, %d false positives filtered, %d new threats detected%s",
            len(result.validated_findings),
            len(result.false_positives),
            len(result.missed_threats),
            f", {len(result.analysis_warnings)} degraded batch(es)" if result.analysis_warnings else "",
        )

        return result

    def _max_findings_per_batch(self) -> int:
        """Estimate a safe batch size from the configured output-token cap."""
        output_budget = max(1, int(self.max_tokens * _OUTPUT_TOKEN_UTILIZATION))
        return max(1, output_budget // _ESTIMATED_OUTPUT_TOKENS_PER_FINDING)

    async def _analyze_batch(
        self,
        skill: Skill,
        findings: list[Finding],
        indices: list[int],
        skill_context: str,
        analyzers_used: list[str],
        start_tag: str,
        end_tag: str,
    ) -> MetaAnalysisResult:
        """Analyze one global-indexed batch, narrowing only on truncation."""
        batch_findings = [findings[index] for index in indices]
        findings_data = self._serialize_findings(batch_findings, indices=indices)
        user_prompt = self._build_user_prompt(
            skill=skill,
            skill_context=skill_context,
            findings_data=findings_data,
            analyzers_used=analyzers_used,
            start_tag=start_tag,
            end_tag=end_tag,
        )

        try:
            response = await self._make_llm_request(self.system_prompt, user_prompt)
        except MetaAnalysisTruncatedError:
            if len(indices) > 1:
                midpoint = len(indices) // 2
                logger.warning(
                    "Meta-analysis response truncated for findings %d-%d; retrying as %d and %d findings",
                    indices[0],
                    indices[-1],
                    midpoint,
                    len(indices) - midpoint,
                )
                narrowed = MetaAnalysisResult()
                for narrowed_indices in (indices[:midpoint], indices[midpoint:]):
                    narrowed_result = await self._analyze_batch(
                        skill=skill,
                        findings=findings,
                        indices=narrowed_indices,
                        skill_context=skill_context,
                        analyzers_used=analyzers_used,
                        start_tag=start_tag,
                        end_tag=end_tag,
                    )
                    self._merge_batch_result(narrowed, narrowed_result)
                return narrowed
            return self._degraded_batch_result(
                findings,
                indices,
                code="META_BATCH_TRUNCATED",
                message="Provider truncated the response for a single finding; the finding was retained unchanged.",
            )
        except Exception as exc:
            return self._degraded_batch_result(
                findings,
                indices,
                code="META_BATCH_REQUEST_FAILED",
                message=f"Meta-analysis request failed ({type(exc).__name__}); this batch was retained unchanged.",
            )

        try:
            batch_result = self._parse_response(
                response,
                batch_findings,
                original_indices=indices,
                fallback_on_error=False,
            )
        except MetaAnalysisParseError as exc:
            return self._degraded_batch_result(
                findings,
                indices,
                code="META_BATCH_PARSE_FAILED",
                message=f"Meta-analysis response was malformed ({exc}); this batch was retained unchanged.",
            )

        return self._normalize_batch_result(batch_result, findings, indices)

    def _normalize_batch_result(
        self,
        result: MetaAnalysisResult,
        findings: list[Finding],
        expected_indices: list[int],
    ) -> MetaAnalysisResult:
        """Enforce one deterministic classification for every expected index."""
        expected = set(expected_indices)
        validated: dict[int, dict[str, Any]] = {}
        false_positives: dict[int, dict[str, Any]] = {}
        invalid_entries = 0

        for entry in result.validated_findings:
            index = entry.get("_index") if isinstance(entry, dict) else None
            if type(index) is not int or index not in expected or index in validated:
                invalid_entries += 1
                continue
            validated[index] = entry

        for entry in result.false_positives:
            index = entry.get("_index") if isinstance(entry, dict) else None
            # A duplicated classification is retained as validated, which is
            # the security-conservative interpretation.
            if type(index) is not int or index not in expected or index in validated or index in false_positives:
                invalid_entries += 1
                continue
            false_positives[index] = entry

        missing = sorted(expected - validated.keys() - false_positives.keys())
        for index in missing:
            fallback = self._finding_to_dict(findings[index], index=index)
            fallback["meta_analysis_degraded"] = True
            validated[index] = fallback

        if invalid_entries or missing:
            details = []
            if invalid_entries:
                details.append(f"ignored {invalid_entries} invalid or duplicate classification(s)")
            if missing:
                details.append(f"retained {len(missing)} unclassified finding(s)")
            result.analysis_warnings.append(
                self._batch_warning(
                    code="META_BATCH_INCOMPLETE",
                    message="; ".join(details),
                    indices=expected_indices,
                )
            )
            logger.error(
                "Meta-analysis batch %d-%d was incomplete: %s",
                expected_indices[0],
                expected_indices[-1],
                "; ".join(details),
            )

        result.validated_findings = [validated[index] for index in sorted(validated)]
        result.false_positives = [false_positives[index] for index in sorted(false_positives)]

        # Keep model priority within the batch, but remove duplicates, invalid
        # values, and false-positive indices. Append any validated omissions in
        # global order so downstream ranking is total and deterministic.
        priority_order: list[int] = []
        for index in result.priority_order:
            if type(index) is int and index in validated and index not in priority_order:
                priority_order.append(index)
        priority_order.extend(index for index in sorted(validated) if index not in priority_order)
        result.priority_order = priority_order
        return result

    def _degraded_batch_result(
        self,
        findings: list[Finding],
        indices: list[int],
        *,
        code: str,
        message: str,
    ) -> MetaAnalysisResult:
        """Retain one failed batch with global indices and a visible warning."""
        logger.error("%s for findings %d-%d", message, indices[0], indices[-1])
        validated = []
        for index in indices:
            fallback = self._finding_to_dict(findings[index], index=index)
            fallback["meta_analysis_degraded"] = True
            validated.append(fallback)
        return MetaAnalysisResult(
            validated_findings=validated,
            priority_order=list(indices),
            analysis_warnings=[self._batch_warning(code=code, message=message, indices=indices)],
        )

    @staticmethod
    def _batch_warning(*, code: str, message: str, indices: list[int]) -> dict[str, Any]:
        return {
            "code": code,
            "message": message,
            "first_index": indices[0],
            "last_index": indices[-1],
            "finding_count": len(indices),
        }

    def _merge_batch_result(self, result: MetaAnalysisResult, batch_result: MetaAnalysisResult) -> None:
        """Merge a batch in call order while de-duplicating aggregate fields."""
        result.validated_findings.extend(batch_result.validated_findings)
        result.false_positives.extend(batch_result.false_positives)
        self._extend_unique_dicts(result.missed_threats, batch_result.missed_threats)
        self._extend_unique_dicts(result.correlations, batch_result.correlations)
        self._extend_unique_dicts(result.recommendations, batch_result.recommendations)
        result.analysis_warnings.extend(batch_result.analysis_warnings)

        for index in batch_result.priority_order:
            if index not in result.priority_order:
                result.priority_order.append(index)

        batch_risk = batch_result.overall_risk_assessment
        if batch_risk and (
            not result.overall_risk_assessment
            or self._risk_rank(batch_risk) > self._risk_rank(result.overall_risk_assessment)
        ):
            result.overall_risk_assessment = dict(batch_risk)

    @staticmethod
    def _extend_unique_dicts(target: list[dict[str, Any]], additions: list[dict[str, Any]]) -> None:
        """Append JSON-like dicts once, preserving first-seen order."""
        seen = {json.dumps(item, sort_keys=True, default=str) for item in target}
        for item in additions:
            key = json.dumps(item, sort_keys=True, default=str)
            if key not in seen:
                target.append(item)
                seen.add(key)

    @staticmethod
    def _risk_rank(assessment: dict[str, Any]) -> int:
        risk = str(assessment.get("risk_level", "")).upper()
        return {"UNKNOWN": 0, "SAFE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}.get(risk, 0)

    @staticmethod
    def _mark_result_degraded(result: MetaAnalysisResult) -> None:
        assessment = dict(result.overall_risk_assessment)
        partial_risk = assessment.get("risk_level")
        partial_verdict = assessment.get("skill_verdict")
        partial_summary = assessment.get("summary")
        if partial_risk:
            assessment["partial_risk_level"] = partial_risk
        if partial_verdict:
            assessment["partial_skill_verdict"] = partial_verdict
        if partial_summary:
            assessment["partial_summary"] = partial_summary

        # Reporters surface risk_level/skill_verdict but not the structured
        # degradation fields. Never present a conclusive SAFE/LOW (or any
        # other final verdict) when at least one batch was not analyzed.
        assessment["risk_level"] = "UNKNOWN"
        assessment["skill_verdict"] = "UNKNOWN"
        assessment["summary"] = (
            "Meta-analysis was incomplete because one or more batches could not be fully analyzed. "
            "Original findings from those batches were retained."
        )
        assessment["meta_analysis_status"] = "degraded"
        assessment["meta_analysis_warnings"] = list(result.analysis_warnings)
        result.overall_risk_assessment = assessment

    def _build_skill_context(self, skill: Skill) -> tuple[str, list[dict]]:
        """Build comprehensive skill context for meta-analysis.

        Uses policy-driven budget gating (meta multiplier applied).
        Content that fits within budget is included in full — **no truncation**.
        Content that exceeds the budget is skipped and reported.

        Returns:
            Tuple of (context_string, skipped_items) where *skipped_items*
            is a list of dicts with keys ``path``, ``size``, ``reason``,
            and ``threshold_name``.
        """
        lp = self.llm_policy
        max_instruction = lp.meta_max_instruction_body_chars
        max_code_file = lp.meta_max_code_file_chars
        max_total = lp.meta_max_total_prompt_chars

        lines: list[str] = []
        skipped: list[dict] = []
        total_size = 0

        lines.append(f"## Skill: {skill.name}")
        lines.append(f"**Description:** {skill.description}")
        lines.append(f"**Directory:** {skill.directory}")
        lines.append("")

        # Manifest info
        lines.append("### Manifest")
        lines.append(f"- License: {skill.manifest.license or 'Not specified'}")
        lines.append(f"- Compatibility: {skill.manifest.compatibility or 'Not specified'}")
        lines.append(
            f"- Allowed Tools: {', '.join(skill.manifest.allowed_tools) if skill.manifest.allowed_tools else 'Not specified'}"
        )
        lines.append("")

        # Full instruction body — include full or skip entirely
        lines.append("### SKILL.md Instructions (Full)")
        instruction_size = len(skill.instruction_body)
        if instruction_size > max_instruction:
            skipped.append(
                {
                    "path": "SKILL.md (instruction body)",
                    "size": instruction_size,
                    "reason": (
                        f"instruction body ({instruction_size:,} chars) exceeds meta limit "
                        f"({max_instruction:,} = {lp.max_instruction_body_chars:,} x {lp.meta_budget_multiplier})"
                    ),
                    "threshold_name": "llm_analysis.max_instruction_body_chars",
                }
            )
            lines.append("*(instruction body excluded — exceeds budget)*")
        else:
            lines.append(f"```markdown\n{skill.instruction_body}\n```")
            total_size += instruction_size
        lines.append("")

        # Files summary
        lines.append("### Files in Skill Package")
        for f in skill.files:
            lines.append(f"- {f.relative_path} ({f.file_type}, {f.size_bytes} bytes)")
        lines.append("")

        # Full file contents for code files — budget gated, no truncation
        lines.append("### File Contents")
        code_extensions = {".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".yaml", ".yml", ".json", ".toml"}

        for f in skill.files:
            file_ext = Path(f.relative_path).suffix.lower()
            if file_ext not in code_extensions and f.file_type not in ("python", "bash", "script"):
                continue

            try:
                file_path = Path(skill.directory) / f.relative_path
                if not (file_path.exists() and file_path.is_file()):
                    continue
                content = file_path.read_text(encoding="utf-8", errors="replace")
                file_size = len(content)

                # Per-file budget check
                if file_size > max_code_file:
                    skipped.append(
                        {
                            "path": str(f.relative_path),
                            "size": file_size,
                            "reason": (
                                f"file size ({file_size:,} chars) exceeds meta per-file limit "
                                f"({max_code_file:,} = {lp.max_code_file_chars:,} x {lp.meta_budget_multiplier})"
                            ),
                            "threshold_name": "llm_analysis.max_code_file_chars",
                        }
                    )
                    continue

                # Total budget check
                if total_size + file_size > max_total:
                    skipped.append(
                        {
                            "path": str(f.relative_path),
                            "size": file_size,
                            "reason": (
                                f"including this file would exceed the meta total prompt budget "
                                f"({total_size + file_size:,} > {max_total:,} = "
                                f"{lp.max_total_prompt_chars:,} x {lp.meta_budget_multiplier})"
                            ),
                            "threshold_name": "llm_analysis.max_total_prompt_chars",
                        }
                    )
                    continue

                lines.append(f"\n#### {f.relative_path}")
                lines.append(f"```{file_ext.lstrip('.') or 'text'}\n{content}\n```")
                total_size += file_size
            except Exception:
                pass

        lines.append("")

        # Referenced files
        if skill.referenced_files:
            lines.append("### Referenced Files")
            for ref in skill.referenced_files:
                lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines), skipped

    def _serialize_findings(self, findings: list[Finding], indices: list[int] | None = None) -> str:
        """Serialize findings to JSON while preserving optional global indices."""
        if indices is None:
            indices = list(range(len(findings)))
        if len(indices) != len(findings):
            raise ValueError("indices must contain one entry per finding")

        findings_list = []
        for index, f in zip(indices, findings, strict=True):
            findings_list.append(
                {
                    "_index": index,
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "snippet": f.snippet[:200] if f.snippet else None,
                    "analyzer": f.analyzer,
                }
            )
        return json.dumps(findings_list, indent=2)

    def _finding_to_dict(self, finding: Finding, index: int | None = None) -> dict[str, Any]:
        """Convert Finding to dictionary."""
        result = {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "snippet": finding.snippet,
            "remediation": finding.remediation,
            "analyzer": finding.analyzer,
            "metadata": finding.metadata,
        }
        if index is not None:
            result["_index"] = index
        return result

    def _build_user_prompt(
        self,
        skill: Skill,
        skill_context: str,
        findings_data: str,
        analyzers_used: list[str],
        start_tag: str,
        end_tag: str,
    ) -> str:
        """Build the user prompt for meta-analysis."""
        num_findings = findings_data.count('"_index"')
        return f"""## Meta-Analysis Request

You have {num_findings} findings from {len(analyzers_used)} analyzers. Your job is to **filter the noise and prioritize what matters**.

**IMPORTANT**: You have FULL ACCESS to the skill content below - including complete SKILL.md and all code files. Use this to VERIFY findings are accurate.

### Analyzers Used
{", ".join(analyzers_used)}

### Skill Context (FULL CONTENT)
{start_tag}
{skill_context}
{end_tag}

### Findings from Analyzers ({num_findings} total)
```json
{findings_data}
```

### Your Task (IN ORDER OF IMPORTANCE)

1. **CORRELATE AND GROUP** (Most Important)
   - Group related findings into `correlations` (e.g., 4 YARA autonomy_abuse hits on consecutive lines = 1 group, pipeline + static findings about the same exfil chain = 1 group)
   - Keep ALL grouped findings in `validated_findings` — correlations are for GROUPING, not removing

2. **FILTER GENUINE FALSE POSITIVES**
   - VERIFY each finding against the actual code above
   - Only mark as FP if the code is genuinely benign (keyword in comment, safe library use, internal file read)
   - Do NOT mark a finding as FP just because another analyzer already covers it

3. **PRIORITIZE BY ACTUAL RISK**
   - What should the developer fix FIRST? Put it at index 0 in priority_order
   - CRITICAL: Active data exfiltration, credential theft, prompt injection
   - HIGH: Command injection, system modification
   - MEDIUM: Potential issues that need more context

4. **MAKE ACTIONABLE RECOMMENDATIONS**
   - Every recommendation needs a specific fix
   - "Don't do X" is not actionable. "Replace X with Y" is actionable.

5. **DETECT MISSED THREATS** (ONLY if obvious)
   - Leave missed_threats EMPTY unless there's something critical all analyzers missed.

**IMPORTANT: COMPACT OUTPUT FORMAT**
- Use COMPACT format for `validated_findings`: only `_index`, `confidence`, `confidence_reason`, `exploitability`, `impact`. Do NOT echo back title, description, file_path, snippet.
- Output `overall_risk_assessment` and `correlations` FIRST in the JSON (before the large arrays).
- Classify every `_index` listed in this batch into either `validated_findings` or `false_positives`.

Respond with a JSON object following the schema in the system prompt."""

    async def _make_llm_request(self, system_prompt: str, user_prompt: str) -> str:
        """Make a request to the LLM API."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        api_params: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "timeout": float(self.timeout),
        }
        if self.temperature is not None:
            api_params["temperature"] = self.temperature

        if self.api_key:
            api_params["api_key"] = self.api_key

        if self.base_url:
            api_params["api_base"] = self.base_url

        if self.api_version:
            api_params["api_version"] = self.api_version

        if self.llm_user and supports_openai_user_param(self.model, self.provider):
            api_params["user"] = self.llm_user

        # AWS Bedrock configuration
        if self.aws_region:
            api_params["aws_region_name"] = self.aws_region
        if self.aws_session_token:
            api_params["aws_session_token"] = self.aws_session_token
        if self.aws_profile:
            api_params["aws_profile_name"] = self.aws_profile

        # Retry logic with exponential backoff
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = await acompletion(**api_params, drop_params=True)
                _add_token_usage(self._llm_usage, _extract_token_usage(response))
                choice = response.choices[0]
                if self._is_truncated_choice(choice):
                    raise MetaAnalysisTruncatedError(
                        "LLM response reached max_tokens before completing the meta-analysis batch"
                    )
                content: str = choice.message.content or ""
                return content

            except MetaAnalysisTruncatedError:
                # Retrying the same prompt cannot make it fit. The batch
                # orchestrator will narrow the request instead.
                raise
            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()

                is_retryable = any(
                    keyword in error_msg
                    for keyword in [
                        "timeout",
                        "tls",
                        "connection",
                        "network",
                        "rate limit",
                        "throttle",
                        "429",
                        "503",
                        "504",
                    ]
                )

                if attempt < self.max_retries - 1 and is_retryable:
                    delay = (2**attempt) * 1.0
                    logger.warning("Meta-analysis LLM request failed (attempt %d): %s", attempt + 1, e)
                    await asyncio.sleep(delay)
                else:
                    if last_exception is not None:
                        raise last_exception
                    raise RuntimeError("LLM request failed")

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("All retries exhausted")

    @staticmethod
    def _is_truncated_choice(choice: Any) -> bool:
        """Return whether a normalized or native finish reason hit an output limit."""
        reasons = [getattr(choice, "finish_reason", None)]
        provider_fields = getattr(choice, "provider_specific_fields", None)
        if isinstance(provider_fields, dict):
            reasons.append(provider_fields.get("native_finish_reason"))

        # LiteLLM maps Anthropic/Bedrock ``max_tokens`` and Gemini/Vertex
        # ``MAX_TOKENS`` to ``length``. It also retains the original value in
        # provider_specific_fields, and OpenAI-compatible routes may return a
        # raw max-output-token variant without normalization.
        for reason in reasons:
            reason = getattr(reason, "value", reason)
            if not isinstance(reason, str):
                continue
            compact = reason.strip().lower().replace("-", "_").replace("_", "")
            if compact in {"length", "maxtoken", "maxtokens", "maxoutputtoken", "maxoutputtokens"}:
                return True
        return False

    def _parse_response(
        self,
        response: str,
        original_findings: list[Finding],
        *,
        original_indices: list[int] | None = None,
        fallback_on_error: bool = True,
    ) -> MetaAnalysisResult:
        """Parse the LLM meta-analysis response."""
        if original_indices is None:
            original_indices = list(range(len(original_findings)))
        try:
            json_data = self._extract_json_from_response(response)
            if not isinstance(json_data, dict):
                raise ValueError("Meta-analysis response must be a JSON object")

            list_fields = (
                "validated_findings",
                "false_positives",
                "missed_threats",
                "priority_order",
                "correlations",
                "recommendations",
            )
            for field_name in list_fields:
                if not isinstance(json_data.get(field_name, []), list):
                    raise ValueError(f"{field_name} must be a JSON array")
            if not isinstance(json_data.get("overall_risk_assessment", {}), dict):
                raise ValueError("overall_risk_assessment must be a JSON object")

            result = MetaAnalysisResult(
                validated_findings=json_data.get("validated_findings", []),
                false_positives=json_data.get("false_positives", []),
                missed_threats=json_data.get("missed_threats", []),
                priority_order=json_data.get("priority_order", []),
                correlations=json_data.get("correlations", []),
                recommendations=json_data.get("recommendations", []),
                overall_risk_assessment=json_data.get("overall_risk_assessment", {}),
            )

            # Enrich validated findings with original data
            self._enrich_findings(result, original_findings, original_indices=original_indices)

            return result

        except (json.JSONDecodeError, ValueError, TypeError, AttributeError) as e:
            logger.error("Failed to parse meta-analysis response: %s", e)
            if not fallback_on_error:
                raise MetaAnalysisParseError(str(e)) from e
            # Return original findings as validated
            return MetaAnalysisResult(
                validated_findings=[
                    {
                        **self._finding_to_dict(finding, index=index),
                        "meta_analysis_degraded": True,
                    }
                    for index, finding in zip(original_indices, original_findings, strict=True)
                ],
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": "Failed to parse meta-analysis response",
                },
                analysis_warnings=[
                    self._batch_warning(
                        code="META_BATCH_PARSE_FAILED",
                        message=f"Meta-analysis response was malformed ({e}); findings were retained unchanged.",
                        indices=original_indices,
                    )
                ],
            )

    def _extract_json_from_response(self, response: str) -> dict[str, Any]:
        """Extract JSON from LLM response using multiple strategies."""
        if not response or not response.strip():
            raise ValueError("Empty response from LLM")

        # Strategy 1: Parse entire response as JSON
        try:
            result: dict[str, Any] = json.loads(response.strip())
            return result
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract from markdown code blocks
        try:
            json_start = "```json"
            json_end = "```"

            start_idx = response.find(json_start)
            if start_idx != -1:
                content_start = start_idx + len(json_start)
                end_idx = response.find(json_end, content_start)

                if end_idx != -1:
                    json_str = response[content_start:end_idx].strip()
                    parsed: dict[str, Any] = json.loads(json_str)
                    return parsed
        except json.JSONDecodeError:
            pass

        # Strategy 3: Find JSON object by balanced braces
        try:
            start_idx = response.find("{")
            if start_idx != -1:
                brace_count = 0
                end_idx = -1

                for i in range(start_idx, len(response)):
                    if response[i] == "{":
                        brace_count += 1
                    elif response[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break

                if end_idx != -1:
                    json_content = response[start_idx:end_idx]
                    parsed_obj: dict[str, Any] = json.loads(json_content)
                    return parsed_obj
        except json.JSONDecodeError:
            pass

        raise ValueError("No valid JSON found in response")

    def _enrich_findings(
        self,
        result: MetaAnalysisResult,
        original_findings: list[Finding],
        *,
        original_indices: list[int] | None = None,
    ) -> None:
        """Enrich validated findings with original finding data."""
        if original_indices is None:
            original_indices = list(range(len(original_findings)))
        original_lookup = {
            index: self._finding_to_dict(finding)
            for index, finding in zip(original_indices, original_findings, strict=True)
        }

        # Enrich validated findings
        for finding in result.validated_findings:
            idx = finding.get("_index")
            if idx is not None and idx in original_lookup:
                original = original_lookup[idx]
                for key, value in original.items():
                    if key not in finding:
                        finding[key] = value

        # Enrich false positives
        for finding in result.false_positives:
            idx = finding.get("_index")
            if idx is not None and idx in original_lookup:
                original = original_lookup[idx]
                for key, value in original.items():
                    if key not in finding:
                        finding[key] = value


def apply_meta_analysis_to_results(
    original_findings: list[Finding],
    meta_result: MetaAnalysisResult,
    skill: Skill,
) -> list[Finding]:
    """Apply meta-analysis results to enrich all findings with metadata.

    This function:
    1. Marks false positives with metadata (but keeps them in output)
    2. Adds meta-analysis enrichments to validated findings
    3. Adds any new threats detected by meta-analyzer

    All findings are retained in the output with metadata indicating whether
    they were identified as false positives. This allows downstream consumers
    (like VS Code extensions) to filter or display them as needed.

    Args:
        original_findings: Original findings from all analyzers
        meta_result: Results from meta-analysis
        skill: The skill being analyzed

    Returns:
        All findings with meta-analysis metadata added
    """
    # Build false positive lookup with reasons and metadata
    fp_data: dict[int, dict[str, Any]] = {}
    for fp in meta_result.false_positives:
        if "_index" in fp:
            fp_data[fp["_index"]] = {
                "reason": fp.get("reason") or fp.get("false_positive_reason") or "Identified as likely false positive",
                "confidence": fp.get("confidence"),
            }

    # Build enrichment lookup from validated findings
    enrichments: dict[int, dict[str, Any]] = {}
    priority_lookup: dict[int, int] = {}

    # Build priority rank lookup from priority_order
    for rank, idx in enumerate(meta_result.priority_order, start=1):
        priority_lookup[idx] = rank

    for vf in meta_result.validated_findings:
        idx_raw = vf.get("_index")
        vf_idx = idx_raw if isinstance(idx_raw, int) else None
        if vf_idx is not None:
            degraded = bool(vf.get("meta_analysis_degraded"))
            enrichment = {
                "meta_validated": not degraded,
                "meta_confidence": vf.get("confidence"),
                "meta_confidence_reason": vf.get("confidence_reason"),
                "meta_exploitability": vf.get("exploitability"),
                "meta_impact": vf.get("impact"),
            }
            if degraded:
                enrichment["meta_analysis_degraded"] = True
            enrichments[vf_idx] = enrichment

    # Enrich all findings (do not filter out false positives)
    result_findings = []
    for i, finding in enumerate(original_findings):
        # Mark false positives with metadata (but keep them in output)
        if i in fp_data:
            finding.metadata["meta_false_positive"] = True
            finding.metadata["meta_reason"] = fp_data[i]["reason"]
            if fp_data[i].get("confidence") is not None:
                finding.metadata["meta_confidence"] = fp_data[i]["confidence"]
        else:
            # Mark as validated (not a false positive)
            finding.metadata["meta_false_positive"] = False

            # Add enrichments if available for validated findings
            if i in enrichments:
                for key, value in enrichments[i].items():
                    if value is not None:
                        finding.metadata[key] = value
            else:
                finding.metadata["meta_reviewed"] = True

        # Add priority rank if available
        if i in priority_lookup:
            finding.metadata["meta_priority"] = priority_lookup[i]

        result_findings.append(finding)

    # Add missed threats as new findings
    missed_findings = meta_result.get_missed_threats(skill)
    for mf in missed_findings:
        mf.metadata["meta_false_positive"] = False
    result_findings.extend(missed_findings)

    return result_findings


def merge_meta_analyzer_usage(result: ScanResult, meta_analyzer: MetaAnalyzer) -> None:
    """Fold a MetaAnalyzer's token usage into a scan result's aggregated ``llm_usage``.

    MetaAnalyzer always runs as a separate post-processing step after
    ``SkillScanner`` has already produced a ``ScanResult`` (see
    ``analyze_with_findings``), so its token spend isn't captured by
    ``SkillScanner``'s own per-scan aggregation. Call this immediately after
    ``analyze_with_findings()`` to fold the meta-analysis call(s) in.
    """
    usage = meta_analyzer.llm_usage
    if not any(usage.values()):
        return
    aggregated: LLMTokenUsage = dict(result.llm_usage) if result.llm_usage else _empty_token_usage()  # type: ignore[assignment]
    _add_token_usage(aggregated, usage)
    result.llm_usage = dict(aggregated)  # type: ignore[arg-type]
