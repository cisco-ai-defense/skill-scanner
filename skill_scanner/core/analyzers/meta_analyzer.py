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
from ..models import Finding, Severity, Skill, ThreatCategory
from .base import BaseAnalyzer
from .llm_provider_config import ProviderConfig
from .llm_request_handler import LLMRequestHandler

if TYPE_CHECKING:
    from ...core.scan_policy import LLMAnalysisPolicy, ScanPolicy

logger = logging.getLogger(__name__)

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
    """

    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    missed_threats: list[dict[str, Any]] = field(default_factory=list)
    priority_order: list[int] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    overall_risk_assessment: dict[str, Any] = field(default_factory=dict)

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
                metadata["meta_validated"] = True

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
        temperature: float = 0.1,
        max_retries: int = 3,
        timeout: int = 180,
        # Azure-specific
        base_url: str | None = None,
        api_version: str | None = None,
        # AWS Bedrock-specific
        aws_region: str | None = None,
        aws_profile: str | None = None,
        aws_session_token: str | None = None,
        # Policy (optional – uses generous defaults × meta multiplier)
        policy: ScanPolicy | None = None,
    ):
        """Initialize the Meta Analyzer.

        Args:
            model: Model identifier (defaults to claude-3-5-sonnet-20241022)
            api_key: API key (if None, reads from environment)
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature (low for consistency)
            max_retries: Max retry attempts on rate limits
            timeout: Request timeout in seconds
            base_url: Custom base URL (for Azure)
            api_version: API version (for Azure)
            aws_region: AWS region (for Bedrock)
            aws_profile: AWS profile name (for Bedrock)
            aws_session_token: AWS session token (for Bedrock)
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
        self.temperature = temperature
        self.max_retries = max_retries
        self.timeout = timeout

        # Load prompts
        self._load_prompts()

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

        # Build findings data
        findings_data = self._serialize_findings(findings)

        # Build user prompt
        user_prompt = self._build_user_prompt(
            skill=skill,
            skill_context=skill_context,
            findings_data=findings_data,
            analyzers_used=analyzers_used,
            start_tag=start_tag,
            end_tag=end_tag,
        )

        try:
            # Make LLM request
            response = await self._make_llm_request(self.system_prompt, user_prompt)

            # Parse response
            result = self._parse_response(response, findings)

            # Follow-up pass for uncovered findings
            result = await self._cover_remaining_findings(
                result, findings, skill, skill_context, analyzers_used, start_tag, end_tag
            )

            logger.info(
                "Meta-analysis complete: %d validated, %d false positives filtered, %d new threats detected",
                len(result.validated_findings),
                len(result.false_positives),
                len(result.missed_threats),
            )

            return result

        except Exception as e:
            logger.error("Meta-analysis failed: %s", e)
            # Return original findings as validated if analysis fails
            return MetaAnalysisResult(
                validated_findings=[self._finding_to_dict(f) for f in findings],
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": f"Meta-analysis failed: {str(e)}. Original findings preserved.",
                },
            )

    async def _cover_remaining_findings(
        self,
        result: MetaAnalysisResult,
        findings: list[Finding],
        skill: Skill,
        skill_context: str,
        analyzers_used: list[str],
        start_tag: str,
        end_tag: str,
    ) -> MetaAnalysisResult:
        """Send a follow-up request for any findings the first pass didn't classify."""
        all_indices = set(range(len(findings)))

        covered = set()
        for vf in result.validated_findings:
            idx = vf.get("_index")
            if isinstance(idx, int):
                covered.add(idx)
        for fp in result.false_positives:
            idx = fp.get("_index")
            if isinstance(idx, int):
                covered.add(idx)

        remaining = sorted(all_indices - covered)
        if not remaining:
            return result

        logger.info(
            "Meta follow-up: %d/%d findings uncovered, sending follow-up request",
            len(remaining),
            len(findings),
        )

        # Build a focused list of only the uncovered findings
        remaining_findings = [findings[i] for i in remaining]
        remaining_data = []
        for orig_idx, f in zip(remaining, remaining_findings, strict=False):
            remaining_data.append(
                {
                    "_index": orig_idx,
                    "rule_id": f.rule_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description[:200],
                    "file_path": f.file_path,
                    "analyzer": f.analyzer,
                }
            )
        remaining_json = json.dumps(remaining_data, indent=2)

        followup_prompt = f"""## Follow-Up: Classify Remaining Findings

The previous analysis covered {len(covered)}/{len(findings)} findings. The following {len(remaining)} findings were NOT classified.

Classify each into EITHER `validated_findings` or `false_positives`.

### Skill Context
{start_tag}
Skill: {skill.name}
Description: {skill.description}
{end_tag}

### Unclassified Findings
```json
{remaining_json}
```

Respond with a JSON object. Use COMPACT format for validated entries:
```json
{{
  "validated_findings": [
    {{"_index": N, "confidence": "HIGH|MEDIUM|LOW", "confidence_reason": "brief reason", "exploitability": "brief", "impact": "brief"}}
  ],
  "false_positives": [
    {{"_index": N, "false_positive_reason": "brief reason"}}
  ]
}}
```
Every `_index` above MUST appear in exactly one list."""

        try:
            followup_response = await self._make_llm_request(self.system_prompt, followup_prompt)
            followup_result = self._parse_response(followup_response, findings)

            # Merge into original result
            result.validated_findings.extend(followup_result.validated_findings)
            result.false_positives.extend(followup_result.false_positives)

            logger.info(
                "Meta follow-up complete: +%d validated, +%d false positives",
                len(followup_result.validated_findings),
                len(followup_result.false_positives),
            )
        except Exception as e:
            logger.warning("Meta follow-up failed: %s — uncovered findings will pass through as-is", e)

        return result

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

    def _serialize_findings(self, findings: list[Finding]) -> str:
        """Serialize findings to JSON for the prompt."""
        findings_list = []
        for i, f in enumerate(findings):
            findings_list.append(
                {
                    "_index": i,
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

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        """Convert Finding to dictionary."""
        return {
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
- Classify every finding (`_index` 0 to {num_findings - 1}) into either `validated_findings` or `false_positives`.

Respond with a JSON object following the schema in the system prompt."""

    async def _make_llm_request(self, system_prompt: str, user_prompt: str) -> str:
        """Make a request to the LLM API."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        api_params = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": float(self.timeout),
        }

        if self.api_key:
            api_params["api_key"] = self.api_key

        if self.base_url:
            api_params["api_base"] = self.base_url

        if self.api_version:
            api_params["api_version"] = self.api_version

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
                response = await acompletion(**api_params)
                content: str = response.choices[0].message.content or ""
                return content

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

    def _parse_response(self, response: str, original_findings: list[Finding]) -> MetaAnalysisResult:
        """Parse the LLM meta-analysis response."""
        try:
            json_data = self._extract_json_from_response(response)

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
            self._enrich_findings(result, original_findings)

            return result

        except (json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to parse meta-analysis response: %s", e)
            # Return original findings as validated
            return MetaAnalysisResult(
                validated_findings=[self._finding_to_dict(f) for f in original_findings],
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": "Failed to parse meta-analysis response",
                },
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

        # Strategy 4: Attempt to repair truncated JSON (common with large outputs)
        try:
            start_idx = response.find("{")
            if start_idx != -1:
                json_fragment = response[start_idx:]
                # Close unclosed braces/brackets
                open_braces = json_fragment.count("{") - json_fragment.count("}")
                open_brackets = json_fragment.count("[") - json_fragment.count("]")

                if open_braces > 0 or open_brackets > 0:
                    # Truncate to last complete entry (last comma or closing bracket)
                    last_good = max(json_fragment.rfind("},"), json_fragment.rfind("],"), json_fragment.rfind("}"))
                    if last_good > 0:
                        repaired = json_fragment[: last_good + 1]
                        repaired += "]}" * open_brackets
                        repaired += "}" * max(0, repaired.count("{") - repaired.count("}"))
                        parsed_repaired: dict[str, Any] = json.loads(repaired)
                        logger.warning("Recovered truncated meta-analysis JSON response")
                        return parsed_repaired
        except (json.JSONDecodeError, ValueError):
            pass

        raise ValueError("No valid JSON found in response")

    def _enrich_findings(self, result: MetaAnalysisResult, original_findings: list[Finding]) -> None:
        """Enrich validated findings with original finding data."""
        original_lookup = {i: self._finding_to_dict(f) for i, f in enumerate(original_findings)}

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
            enrichments[vf_idx] = {
                "meta_validated": True,
                "meta_confidence": vf.get("confidence"),
                "meta_confidence_reason": vf.get("confidence_reason"),
                "meta_exploitability": vf.get("exploitability"),
                "meta_impact": vf.get("impact"),
            }

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
