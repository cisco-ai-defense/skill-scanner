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
Core scanner engine for orchestrating skill analysis.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ..utils.file_utils import FileValidationError
from ..utils.logging_context import scan_log_context
from .analyzability import AnalyzabilityReport, compute_analyzability
from .analyzer_factory import build_core_analyzers
from .analyzers.base import BaseAnalyzer
from .analyzers.llm_request_handler import _add_token_usage, _empty_token_usage
from .cel import CelGate, CelMode, CelRule, CelTelemetry
from .extractors.content_extractor import ContentExtractor
from .loader import SkillLoader, SkillLoadError
from .models import Finding, Report, ScanResult, Severity, Skill, SkillManifest, ThreatCategory
from .scan_policy import ScanPolicy

if TYPE_CHECKING:
    from .rule_registry import RuleRegistry

logger = logging.getLogger(__name__)

_LOAD_REJECTION_ERROR_CODE = "SKILL_METADATA_SIZE_LIMIT_EXCEEDED"


class _SkillMetadataSizeRejection(SkillLoadError):
    """Internal stat-only signal for a closed manifest-size rejection."""

    def __init__(self, path: Path, *, size_bytes: int, limit_bytes: int) -> None:
        super().__init__(f"{path.name} exceeds maximum size ({limit_bytes} bytes): {path}")
        self.path = path
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes


# Common stop words for Jaccard similarity - created once at module level
_STOP_WORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "can",
        "may",
        "might",
        "must",
        "shall",
        "to",
        "of",
        "in",
        "for",
        "on",
        "with",
        "at",
        "by",
        "from",
        "as",
        "into",
        "through",
        "and",
        "or",
        "but",
        "if",
        "then",
        "else",
        "when",
        "up",
        "down",
        "out",
        "that",
        "this",
        "these",
        "those",
        "it",
        "its",
        "they",
        "them",
        "their",
    }
)


class SkillScanner:
    """Main scanner that orchestrates skill analysis."""

    # Upper bound on directories visited during recursive discovery. Guards
    # against a hostile symlink fan-out (e.g. ``trap -> /``) turning a scan into
    # a full-filesystem crawl. Far above any realistic skill tree (issue #116).
    _MAX_WALK_DIRS = 100_000
    _CLOSED_BUNDLED_PYTHON_ANALYZERS = frozenset(
        {
            "analyzability",
            "behavioral",
            "bytecode",
            "content_extractor",
            "correlation",
            "cross_skill",
            "osv",
            "pipeline",
            "scanner",
            "skill_loader",
            "trigger",
            "virustotal",
        }
    )

    def __init__(
        self,
        analyzers: list[BaseAnalyzer] | None = None,
        use_virustotal: bool = False,
        virustotal_api_key: str | None = None,
        virustotal_upload_files: bool = False,
        policy: ScanPolicy | None = None,
        rule_registry: RuleRegistry | None = None,
        cel_rules: list[CelRule] | None = None,
    ):
        """
        Initialize scanner with analyzers.

        Args:
            analyzers: List of analyzers to use. If None, uses default (static).
            use_virustotal: Whether to enable VirusTotal binary scanning
            virustotal_api_key: VirusTotal API key (required if use_virustotal=True)
            virustotal_upload_files: If True, upload unknown files to VT. If False (default),
                                    only check existing hashes
            policy: Scan policy for org-specific allowlists and rule scoping.
                If None, loads built-in defaults.
            rule_registry: Optional validated rule registry.  When ``cel_rules``
                is omitted, CEL gates declared by registry rules are used.
            cel_rules: Optional explicit immutable CEL rule set.  Supplying this
                takes precedence over rules discovered from ``rule_registry``.

        Raises:
            CelRuntimeUnavailable: If selected rule packs contain CEL gates
                but the qualified official helper is absent. ``off`` disables
                decisions, not authoritative startup validation.
            ValueError: If a CEL expression cannot be validated or compiled.
        """
        self.policy = policy or ScanPolicy.default()
        if rule_registry is None:
            # Pack integrity is a scanner-startup invariant even when CEL is
            # off.  The loader process-caches the validated bundled snapshot
            # and returns an isolated registry generation to each scanner.
            from .rule_registry import PackLoader

            rule_registry = PackLoader().build_registry()
        self.rule_registry = rule_registry

        # Resolve the immutable rule generation now; construct the native
        # gate after all other initialization so a later analyzer/loader
        # failure cannot strand its persistent helper process.
        resolved_cel_rules = list(cel_rules) if cel_rules is not None else self._cel_rules_from_registry(rule_registry)

        if analyzers is None:
            # Delegate to the centralised factory so core analyzer
            # construction is defined in exactly one place.
            self.analyzers: list[BaseAnalyzer] = build_core_analyzers(self.policy)

            if use_virustotal and virustotal_api_key:
                from .analyzers.virustotal_analyzer import VirusTotalAnalyzer

                vt_analyzer = VirusTotalAnalyzer(
                    api_key=virustotal_api_key, enabled=True, upload_files=virustotal_upload_files
                )
                self.analyzers.append(vt_analyzer)
        else:
            self.analyzers = analyzers

        # Warn if MetaAnalyzer is in the analyzers list -- it must be
        # orchestrated separately via analyze_with_findings().
        for a in self.analyzers:
            if a.get_name() == "meta_analyzer":
                logger.warning(
                    "MetaAnalyzer was passed in the analyzers list, but it cannot "
                    "produce findings via the normal analyze() pipeline. It will be "
                    "skipped during scanning. Use the CLI --enable-meta flag or call "
                    "MetaAnalyzer.analyze_with_findings() after scanning instead."
                )
                break

        loader_max_bytes = self.policy.file_limits.max_loader_file_size_bytes
        self.loader = SkillLoader(max_file_size_bytes=loader_max_bytes)
        self.content_extractor = ContentExtractor()

        # Trusted expressions are authoritatively validated and atomically
        # compiled at startup, before any package can be scanned.  CEL off
        # disables decisions but does not bypass pack validation.
        self.cel_gate = CelGate(resolved_cel_rules, self.policy.cel.mode)

    @staticmethod
    def _cel_rules_from_registry(rule_registry: RuleRegistry | None) -> list[CelRule]:
        """Extract manifest CEL gates without coupling to pack loading.

        Registry validation and trusted-pack discovery happen before scanner
        construction.  Older registries without CEL metadata naturally yield
        an empty rule set, preserving compatibility during the shadow rollout.
        """
        if rule_registry is None:
            return []
        cel_rules: list[CelRule] = []
        for definition in rule_registry.all_rules().values():
            cel_rule = getattr(definition, "cel", None)
            if isinstance(cel_rule, CelRule):
                cel_rules.append(cel_rule)
        return cel_rules

    def _validate_bundled_python_findings(
        self,
        findings: list[Finding],
    ) -> tuple[int, set[int], list[dict[str, Any]], list[dict[str, str]]]:
        """Validate manifest-owned Python finding identities without dropping them.

        Invalid findings remain in the scan result and carry a stable audit
        annotation.  Their object identities are returned so the caller can
        keep them outside the CEL activation and suppression path.
        """

        checked = 0
        invalid_ids: set[int] = set()
        errors: list[dict[str, Any]] = []
        analyzer_failures: list[dict[str, str]] = []
        for finding in findings:
            definition = self.rule_registry.get(finding.rule_id) if self.rule_registry is not None else None
            require_known = (finding.analyzer or "") in self._CLOSED_BUNDLED_PYTHON_ANALYZERS
            participates = bool(
                definition is not None and definition.pack_name == "core" and definition.source_type == "python"
            )
            if not participates and not require_known:
                continue
            checked += 1
            violations = self.rule_registry.validate_bundled_python_finding(
                finding,
                require_known=require_known,
            )
            if not violations:
                continue

            invalid_ids.add(id(finding))
            serialized = [violation.to_dict() for violation in violations]
            finding.metadata["rule_contract"] = {
                "status": "invalid",
                "schema_version": 2,
                "errors": serialized,
            }
            errors.extend(serialized)
            codes = ",".join(violation.code for violation in violations)
            analyzer_failures.append(
                {
                    "analyzer": finding.analyzer or "unknown",
                    "error": f"FindingContract:{finding.rule_id}:{codes}",
                }
            )
        return checked, invalid_ids, errors, analyzer_failures

    def _apply_cel_with_contract(
        self,
        skill: Skill,
        findings: list[Finding],
        invalid_ids: set[int],
    ) -> tuple[list[Finding], CelTelemetry]:
        """Apply CEL only to contract-valid facts and retain invalid facts open."""

        eligible = [finding for finding in findings if id(finding) not in invalid_ids]
        retained, telemetry = self.cel_gate.apply(skill, eligible)
        retained_ids = {id(finding) for finding in retained}
        invalid_present = [finding for finding in findings if id(finding) in invalid_ids]
        telemetry.retained += len(invalid_present)

        gate_mode = getattr(self.cel_gate, "mode", CelMode.OFF)
        gate_rules = getattr(self.cel_gate, "rules", {})
        if gate_mode is not CelMode.OFF:
            for finding in invalid_present:
                rule = gate_rules.get(finding.rule_id)
                if rule is None:
                    continue
                telemetry.fallbacks += 1
                telemetry.record_error(finding.rule_id, "FINDING_CONTRACT_INVALID")
                telemetry.record_decision(rule, "fallback")
                finding.metadata["cel"] = {
                    "decision": "fallback",
                    "reason": "FINDING_CONTRACT_INVALID",
                    "fact_schema": rule.fact_schema,
                    "expression_hash": rule.expression_hash,
                    "pack": rule.pack_name,
                    "rollout": rule.rollout.value,
                }

        return [finding for finding in findings if id(finding) in invalid_ids or id(finding) in retained_ids], telemetry

    def scan_skill(
        self,
        skill_directory: str | Path,
        *,
        lenient: bool = False,
        skill_file: str | None = None,
    ) -> ScanResult:
        """
        Scan a single skill package.

        Args:
            skill_directory: Path to skill directory
            lenient: Tolerate malformed YAML / missing fields in the skill.
                When True and ``SKILL.md`` is absent, the loader falls back to
                scanning ``.md`` files in the directory (non-Codex/Cursor formats).
            skill_file: Optional custom metadata filename (e.g. ``"README.md"``).

        Returns:
            ScanResult with findings

        Raises:
            SkillLoadError: If skill cannot be loaded (when not lenient)
        """
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)

        try:
            skill, load_telemetry = self._load_skill_for_scan(
                skill_directory,
                lenient=lenient,
                skill_file=skill_file,
            )
        except _SkillMetadataSizeRejection as rejection:
            return self._scan_load_rejection(skill_directory, rejection)
        return self._scan_single_skill(skill, skill_directory, load_telemetry=load_telemetry)

    @staticmethod
    def _manifest_error_code(error: SkillLoadError) -> str | None:
        """Classify strict manifest errors eligible for inert fallback."""

        message = str(error).lower()
        if "failed to parse yaml frontmatter" in message:
            return "MALFORMED_YAML_FRONTMATTER"
        if "missing required field" in message:
            return "MISSING_REQUIRED_MANIFEST_FIELD"
        return None

    def _load_skill_for_scan(
        self,
        skill_directory: Path,
        *,
        lenient: bool,
        skill_file: str | None,
    ) -> tuple[Skill, dict[str, Any] | None]:
        """Load one skill, recovering only bounded malformed metadata.

        Binary/oversized/invalid-UTF-8 files, missing metadata files, and path
        traversal remain hard failures.  Recovery never imports or executes
        package content; it reuses the loader's bounded inert text path.
        """

        metadata_path = skill_directory / (skill_file or "SKILL.md")
        if metadata_path.exists():
            try:
                resolved_root = skill_directory.resolve(strict=True)
                resolved_metadata = metadata_path.resolve(strict=True)
            except OSError as error:
                raise SkillLoadError("Skill metadata path could not be resolved safely") from error
            if metadata_path.is_symlink() or not resolved_metadata.is_relative_to(resolved_root):
                raise SkillLoadError("Skill metadata path must be a non-symlink file within the skill directory")
            if metadata_path.is_file():
                try:
                    size_bytes = metadata_path.stat(follow_symlinks=False).st_size
                except OSError as error:
                    raise SkillLoadError("Skill metadata size could not be inspected safely") from error
                limit_bytes = self.loader.max_file_size_bytes
                if size_bytes > limit_bytes:
                    raise _SkillMetadataSizeRejection(
                        metadata_path,
                        size_bytes=size_bytes,
                        limit_bytes=limit_bytes,
                    )
        elif skill_file:
            # Keep the loader's stable missing-file behavior for callers that
            # select an explicit metadata filename.
            return self.loader.load_skill(skill_directory, lenient=lenient, skill_file=skill_file), None

        if lenient:
            try:
                skill = self.loader.load_skill(skill_directory, lenient=True, skill_file=skill_file)
            except SkillLoadError as error:
                rejection = self._size_rejection_from_loader_error(error, metadata_path)
                if rejection is not None:
                    raise rejection from error
                raise
            return skill, None

        try:
            return self.loader.load_skill(skill_directory, lenient=False, skill_file=skill_file), None
        except SkillLoadError as strict_error:
            rejection = self._size_rejection_from_loader_error(strict_error, metadata_path)
            if rejection is not None:
                raise rejection from strict_error
            error_code = self._manifest_error_code(strict_error)
            if error_code is None or not metadata_path.exists() or not metadata_path.is_file():
                raise

            try:
                skill = self.loader.load_skill(skill_directory, lenient=True, skill_file=skill_file)
            except SkillLoadError as fallback_error:
                rejection = self._size_rejection_from_loader_error(fallback_error, metadata_path)
                if rejection is not None:
                    raise rejection from fallback_error
                # Preserve the original strict failure as the stable public
                # error; the fallback cannot turn binary/oversized content
                # into a successful scan.
                raise strict_error

            # No field from a rejected manifest is authoritative.  Retain only
            # a synthetic package identity; deterministic analyzers continue
            # over inert body/files without capability-based assumptions.
            skill.manifest = type(skill.manifest)(
                name=skill_directory.name,
                description="(manifest metadata unavailable)",
            )
            skill.manifest_complete = False
            load_telemetry: dict[str, Any] = {
                "fallback_used": True,
                "fallback_mode": "bounded_inert_raw_body",
                "strict_error_type": "SkillLoadError",
                "strict_error_code": error_code,
                "manifest_complete": False,
                "capability_facts_trusted": False,
                "projection_complete": False,
                "projection_error_code": "MANIFEST_METADATA_INCOMPLETE",
            }
            skill.load_metadata = dict(load_telemetry)
            return skill, load_telemetry

    @staticmethod
    def _size_rejection_from_loader_error(
        error: SkillLoadError,
        metadata_path: Path,
    ) -> _SkillMetadataSizeRejection | None:
        """Recover typed size proof from the loader's descriptor/bounded read.

        The scanner performs its own stat-only preflight, while the loader
        repeats the limit check on the opened file descriptor.  Preserving the
        typed cause closes the race where a manifest grows or is swapped after
        the first stat: the package still receives the same deterministic
        closed verdict and its bytes are never parsed.
        """

        cause = error.__cause__
        if not isinstance(cause, FileValidationError):
            return None
        size_bytes = cause.size_bytes
        limit_bytes = cause.limit_bytes
        if type(size_bytes) is not int or type(limit_bytes) is not int or limit_bytes <= 0 or size_bytes <= limit_bytes:
            return None
        return _SkillMetadataSizeRejection(
            metadata_path,
            size_bytes=size_bytes,
            limit_bytes=limit_bytes,
        )

    def _scan_load_rejection(
        self,
        skill_directory: Path,
        rejection: _SkillMetadataSizeRejection,
    ) -> ScanResult:
        """Return a closed security verdict without reading oversized content."""

        started = time.time()
        proof: dict[str, Any] = {
            "rejection_used": True,
            "rejection_mode": "hard_size_limit",
            "strict_error_type": "SkillLoadError",
            "strict_error_code": _LOAD_REJECTION_ERROR_CODE,
            "manifest_complete": False,
            "capability_facts_trusted": False,
            "content_scanned": False,
            "size_bytes": rejection.size_bytes,
            "limit_bytes": rejection.limit_bytes,
        }
        synthetic_skill = Skill(
            directory=skill_directory,
            manifest=SkillManifest(
                name=skill_directory.name,
                description="(package rejected before manifest content was read)",
            ),
            skill_md_path=rejection.path,
            instruction_body="",
            files=[],
            referenced_files=[],
            manifest_complete=False,
            load_metadata=dict(proof),
        )
        finding = Finding(
            id="SKILL_LOAD_REJECTED_LIMIT",
            rule_id="SKILL_LOAD_REJECTED_LIMIT",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.HIGH,
            title="Skill manifest exceeds the hard safety limit",
            description=(
                f"The selected skill manifest is {rejection.size_bytes} bytes, exceeding the "
                f"{rejection.limit_bytes}-byte hard loader limit. The package was blocked "
                "without reading or parsing its content."
            ),
            file_path=rejection.path.name,
            remediation="Reduce the skill manifest below the configured hard loader limit and rescan it.",
            analyzer="skill_loader",
            metadata=dict(proof),
        )

        checked, invalid_ids, contract_errors, _ = self._validate_bundled_python_findings([finding])
        findings, cel_telemetry = self._apply_cel_with_contract(
            synthetic_skill,
            [finding],
            invalid_ids,
        )
        policy_meta: dict[str, Any] = self._policy_fingerprint_metadata()
        policy_meta["cel"] = cel_telemetry.to_dict()
        policy_meta["rule_contract"] = {
            "status": "failed" if invalid_ids else "passed",
            "schema_version": 2,
            "checked": checked,
            "invalid_findings": len(invalid_ids),
            "errors": contract_errors[:100],
        }
        policy_meta["loader"] = dict(proof)
        self._annotate_findings_with_policy(findings, policy_meta)

        analyzability = AnalyzabilityReport(
            score=0.0,
            total_files=1,
            analyzed_files=0,
            unanalyzable_files=1,
            risk_level="HIGH",
        )
        return ScanResult(
            skill_name=skill_directory.name,
            skill_directory=str(skill_directory.absolute()),
            findings=findings,
            scan_duration_seconds=time.time() - started,
            analyzers_used=["skill_loader"],
            analyzers_failed=[],
            analyzability_score=analyzability.score,
            analyzability_details=analyzability.to_dict(),
            scan_metadata=policy_meta,
        )

    # ------------------------------------------------------------------
    # Shared single-skill scanning logic (used by both scan_skill and
    # scan_directory for identical behaviour).
    # ------------------------------------------------------------------

    def _scan_single_skill(
        self,
        skill: Skill,
        skill_directory: Path,
        *,
        load_telemetry: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Run one scan with skill-scoped logging context."""
        with scan_log_context(
            skill_name=skill.name,
            skill_path=str(skill_directory.resolve()),
        ):
            if load_telemetry is None:
                return self._scan_single_skill_with_context(skill, skill_directory)
            return self._scan_single_skill_with_context(
                skill,
                skill_directory,
                load_telemetry=load_telemetry,
            )

    def _scan_single_skill_with_context(
        self,
        skill: Skill,
        skill_directory: Path,
        *,
        load_telemetry: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Run the full analysis pipeline on a loaded skill.

        This is the shared implementation that both ``scan_skill`` and
        ``scan_directory`` delegate to.  It guarantees identical two-phase
        (non-LLM → LLM w/ enrichment) behaviour regardless of entry point.
        """
        start_time = time.time()

        # Pre-processing: Extract archives and add extracted files to skill
        extraction_result = self.content_extractor.extract_skill_archives(skill.files)
        if extraction_result.extracted_files:
            skill.files.extend(extraction_result.extracted_files)

        try:
            # Run all analyzers in two phases:
            # Phase 1: Non-LLM analyzers (static, pipeline, behavioral, etc.)
            # Phase 2: LLM analyzers (enriched with Phase 1 context)
            all_findings: list[Finding] = []
            if load_telemetry is not None:
                all_findings.append(
                    Finding(
                        id="SKILL_LOAD_FALLBACK_USED",
                        rule_id="SKILL_LOAD_FALLBACK_USED",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.INFO,
                        title="Strict manifest load failed; inert fallback scan used",
                        description=(
                            "SkillLoadError rejected malformed or missing manifest metadata. "
                            "The bounded package body was still scanned as inert content; "
                            "manifest capabilities were not trusted."
                        ),
                        file_path=Path(skill.skill_md_path).name,
                        remediation="Repair the YAML frontmatter and provide the required manifest fields.",
                        analyzer="skill_loader",
                        metadata=dict(load_telemetry),
                    )
                )
            # Include any archive extraction findings (zip bombs, path traversal, etc.)
            all_findings.extend(extraction_result.findings)
            analyzer_names: list[str] = []
            analyzers_failed: list[dict[str, str]] = []
            if load_telemetry is not None:
                analyzers_failed.append(
                    {
                        "analyzer": "skill_loader",
                        "error": ("SkillLoadError:" + str(load_telemetry["strict_error_code"])),
                    }
                )
            validated_binary_files: set[str] = set()
            llm_analyzers: list[BaseAnalyzer] = []
            unreferenced_scripts: list[str] = []
            llm_scan_meta: dict[str, Any] = {}
            llm_usage: dict[str, int] | None = None

            for analyzer in self.analyzers:
                # Defer LLM analyzers to Phase 2
                if analyzer.get_name() in ("llm_analyzer", "meta_analyzer"):
                    llm_analyzers.append(analyzer)
                    continue
                findings = analyzer.analyze(skill)
                all_findings.extend(findings)
                analyzer_names.append(analyzer.get_name())

                if hasattr(analyzer, "validated_binary_files"):
                    validated_binary_files.update(analyzer.validated_binary_files)

                # Collect unreferenced scripts from the static analyzer for
                # LLM enrichment (no longer emitted as standalone findings).
                if hasattr(analyzer, "get_unreferenced_scripts"):
                    unreferenced_scripts = analyzer.get_unreferenced_scripts()

            # Analyzability is a deterministic package-level analyzer.  Its
            # candidate findings must exist before CEL so contextual gates can
            # correlate opaque binaries with file role, permissions, and
            # references.  Creating these findings after the LLM phase would
            # make rules such as UNANALYZABLE_BINARY impossible to gate.
            analyzability = compute_analyzability(skill, policy=self.policy)
            all_findings.extend(self._analyzability_findings(analyzability))

            # Exact duplicates must be removed before the CEL decision layer.
            # Otherwise CEL telemetry counts decisions for candidates that the
            # final output normalizer later removes, breaking the invariant
            # that aggregate decisions are auditable on retained findings.
            # Same-issue, cross-analyzer collapsing remains a final-stage
            # operation because LLM/meta findings do not exist yet.
            all_findings = self._dedupe_exact_findings(all_findings)

            # Schema-v2 pack metadata is authoritative for every bundled
            # Python candidate. Contract-invalid findings remain visible, but
            # cannot enter CEL facts or be suppressed by a contextual gate.
            (
                contract_checked,
                contract_invalid_ids,
                contract_errors,
                contract_failures,
            ) = self._validate_bundled_python_findings(all_findings)
            analyzers_failed.extend(contract_failures)

            # Remove candidates that deterministic policy has already made
            # ineligible before CEL.  The same filters run again after the LLM
            # phase as a global safety net for findings added later.
            if validated_binary_files:
                all_findings = [
                    finding
                    for finding in all_findings
                    if not (finding.rule_id == "BINARY_FILE_DETECTED" and finding.file_path in validated_binary_files)
                ]
            if self.policy.disabled_rules:
                all_findings = [f for f in all_findings if f.rule_id not in self.policy.disabled_rules]

            # Phase 1.5: Bounded CEL decision layer.  It sees only concrete
            # deterministic candidates and runs before any LLM-based pass so
            # shadow/suppression decisions also shape enrichment context.
            all_findings, cel_telemetry = self._apply_cel_with_contract(
                skill,
                all_findings,
                contract_invalid_ids,
            )

            # Phase 1.6: Per-finding adjudicator (demote literal-regex FPs)
            #
            # Runs before the LLM analyzer so that demoted findings never
            # enter the LLM analyzer's ``static_findings_summary`` enrichment
            # context.  This naturally breaks the cross-analyzer confirmation
            # cascade where a wrong deterministic HIGH gets amplified into
            # LLM findings citing the same pattern hit.
            #
            # Demote-only: findings can only be lowered in severity, never
            # raised. LLM errors leave findings at their original severity,
            # so enabling this pass cannot introduce false negatives.
            adjudicator_audit: list[dict[str, Any]] = []
            adjudicator_usage = _empty_token_usage()
            # Fail-closed analyzability findings historically appeared after
            # this phase and therefore could not be LLM-demoted.  They now
            # exist before CEL, but must retain that safety property.
            adjudicable_findings = [finding for finding in all_findings if finding.analyzer != "analyzability"]
            if self.policy.adjudicator.enabled and adjudicable_findings:
                try:
                    from .analyzers.adjudicator import Adjudicator

                    adj = Adjudicator(
                        min_fp_confidence=self.policy.adjudicator.min_fp_confidence,
                    )
                    try:
                        if adj.is_available():
                            adj.adjudicate(adjudicable_findings, skill)
                            analyzer_names.append("adjudicator")
                            adjudicator_audit = [
                                {
                                    "rule_id": r.rule_id,
                                    "verdict": r.verdict,
                                    "confidence": r.confidence,
                                    "reason": r.reason,
                                    "demoted_to": r.demoted_to,
                                    "model_id": r.model_id,
                                }
                                for r in adj.audit
                            ]
                        else:
                            logger.debug(
                                "adjudicator enabled but no LLM model configured; "
                                "set SKILL_SCANNER_LLM_MODEL or "
                                "SKILL_SCANNER_ADJUDICATOR_LLM_MODEL to activate"
                            )
                    finally:
                        # Preserve billed usage even if a later adjudication
                        # step raises and findings remain fail-closed.
                        _add_token_usage(adjudicator_usage, adj.llm_usage)
                except Exception as exc:
                    logger.warning("Adjudication failed: %s", exc)

            # Phase 2: Run LLM analyzers with enrichment context from Phase 1
            if llm_analyzers:
                enrichment = self._build_enrichment_context(skill, all_findings, unreferenced_scripts)
                for analyzer in llm_analyzers:
                    if hasattr(analyzer, "set_enrichment_context") and enrichment:
                        # Build structured enrichment for the LLM
                        type_counts: dict[str, int] = {}
                        for sf in skill.files:
                            type_counts[sf.file_type] = type_counts.get(sf.file_type, 0) + 1
                        magic_mismatches = [
                            f.file_path for f in all_findings if f.rule_id and "MAGIC" in f.rule_id and f.file_path
                        ]
                        static_summaries = [
                            f"{f.rule_id}: {f.title}"
                            for f in all_findings
                            if f.severity in (Severity.CRITICAL, Severity.HIGH)
                        ][:10]
                        raw_allowed_tools = skill.manifest.allowed_tools
                        if isinstance(raw_allowed_tools, str):
                            normalized_allowed_tools = [raw_allowed_tools]
                        elif isinstance(raw_allowed_tools, list):
                            normalized_allowed_tools = [tool for tool in raw_allowed_tools if isinstance(tool, str)]
                        else:
                            normalized_allowed_tools = []
                        analyzer.set_enrichment_context(
                            file_inventory={
                                "total_files": len(skill.files),
                                "types": type_counts,
                                "unreferenced_scripts": unreferenced_scripts,
                            },
                            magic_mismatches=magic_mismatches if magic_mismatches else None,
                            static_findings_summary=static_summaries if static_summaries else None,
                            analyzability_score=analyzability.score,
                            deterministic_findings=all_findings,
                            manifest_capabilities=(
                                {
                                    "complete": True,
                                    "trusted": True,
                                    "allowed_tools": sorted(normalized_allowed_tools),
                                    "allowed_tools_declared": bool(normalized_allowed_tools),
                                    "compatibility_declared": bool(skill.manifest.compatibility),
                                }
                                if skill.manifest_complete
                                else {"complete": False, "trusted": False}
                            ),
                        )
                    findings = analyzer.analyze(skill)
                    (
                        llm_contract_checked,
                        llm_contract_invalid_ids,
                        llm_contract_errors,
                        llm_contract_failures,
                    ) = self._validate_bundled_python_findings(findings)
                    contract_checked += llm_contract_checked
                    contract_invalid_ids.update(llm_contract_invalid_ids)
                    contract_errors.extend(llm_contract_errors)
                    analyzers_failed.extend(llm_contract_failures)
                    all_findings.extend(findings)
                    analyzer_names.append(analyzer.get_name())

                    # Track analyzer failures for machine-readable output
                    if hasattr(analyzer, "last_error") and analyzer.last_error:
                        analyzers_failed.append({"analyzer": analyzer.get_name(), "error": analyzer.last_error})

                    # Capture skill-level LLM assessment for scan_metadata
                    if hasattr(analyzer, "last_overall_assessment"):
                        llm_scan_meta["llm_overall_assessment"] = analyzer.last_overall_assessment
                        llm_scan_meta["llm_primary_threats"] = getattr(analyzer, "last_primary_threats", [])

            # Aggregate token usage across all LLM analyzers that ran.
            aggregated_usage = _empty_token_usage()
            _add_token_usage(aggregated_usage, adjudicator_usage)
            for analyzer in llm_analyzers:
                if hasattr(analyzer, "llm_usage"):
                    _add_token_usage(aggregated_usage, analyzer.llm_usage)
            llm_usage = dict(aggregated_usage) if any(aggregated_usage.values()) else None  # type: ignore[arg-type]

            # Post-process findings: Suppress BINARY_FILE_DETECTED for VirusTotal-validated files
            if validated_binary_files:
                filtered_findings = []
                for finding in all_findings:
                    if finding.rule_id == "BINARY_FILE_DETECTED" and finding.file_path in validated_binary_files:
                        continue
                    filtered_findings.append(finding)
                all_findings = filtered_findings

            # Global safety net: enforce disabled_rules across ALL analyzers
            if self.policy.disabled_rules:
                all_findings = [f for f in all_findings if f.rule_id not in self.policy.disabled_rules]

            # Apply severity overrides from policy
            self._apply_severity_overrides(all_findings)

            # Normalize duplicate findings at final output stage (policy-controlled).
            all_findings = self._normalize_findings(all_findings)

            # Attach same-path rule co-occurrence metadata (policy-controlled).
            self._annotate_same_path_rule_cooccurrence(all_findings)

            # Attach policy fingerprint metadata for traceability (policy-controlled).
            policy_meta: dict[str, Any] = self._policy_fingerprint_metadata()
            policy_meta["cel"] = cel_telemetry.to_dict()
            policy_meta["rule_contract"] = {
                "status": "failed" if contract_invalid_ids else "passed",
                "schema_version": 2,
                "checked": contract_checked,
                "invalid_findings": len(contract_invalid_ids),
                "errors": contract_errors[:100],
            }
            if load_telemetry is not None:
                policy_meta["loader"] = dict(load_telemetry)
            if llm_scan_meta:
                policy_meta.update(llm_scan_meta)
            if adjudicator_audit:
                demoted = [a for a in adjudicator_audit if a.get("demoted_to")]
                policy_meta["adjudicator"] = {
                    "considered": len(adjudicator_audit),
                    "demoted": len(demoted),
                    "audit": adjudicator_audit,
                }
            self._annotate_findings_with_policy(all_findings, policy_meta)

        finally:
            # Always cleanup temporary extraction directories, even if an
            # analyzer raises an exception, to avoid leaking temp files.
            self.content_extractor.cleanup()

        scan_duration = time.time() - start_time

        result = ScanResult(
            skill_name=skill.name,
            skill_directory=str(skill_directory.absolute()),
            findings=all_findings,
            scan_duration_seconds=scan_duration,
            analyzers_used=analyzer_names,
            analyzers_failed=analyzers_failed,
            analyzability_score=analyzability.score,
            analyzability_details=analyzability.to_dict(),
            scan_metadata=policy_meta,
            llm_usage=llm_usage,
        )

        return result

    def _analyzability_findings(self, report: AnalyzabilityReport) -> list[Finding]:
        """Generate findings when analyzability score is below acceptable thresholds.

        Fail-closed: what the scanner cannot inspect should be flagged, not trusted.
        """
        findings: list[Finding] = []

        # Escalate unknown binaries from INFO to MEDIUM — skip inert
        # file types (images, fonts, databases) that are binary but benign.
        _unanalyzable_enabled = "UNANALYZABLE_BINARY" not in self.policy.disabled_rules
        _skip_inert = self.policy.file_classification.skip_inert_extensions
        _inert_exts = set(self.policy.file_classification.inert_extensions) if _skip_inert else set()
        _doc_indicators = set(self.policy.rule_scoping.doc_path_indicators)

        for fd in report.file_details:
            if not fd.is_analyzable and fd.skip_reason and "Binary file" in fd.skip_reason:
                if not _unanalyzable_enabled:
                    continue
                ext = Path(fd.relative_path).suffix.lower()
                # Skip inert extensions (images, fonts, etc.)
                if _skip_inert and ext in _inert_exts:
                    continue
                # Skip files in test/fixture/doc directories
                parts = Path(fd.relative_path).parts
                if any(p.lower() in _doc_indicators for p in parts):
                    continue
                findings.append(
                    Finding(
                        id=f"UNANALYZABLE_BINARY_{fd.relative_path}",
                        rule_id="UNANALYZABLE_BINARY",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Unanalyzable binary file",
                        description=(
                            f"Binary file '{fd.relative_path}' cannot be inspected by the scanner. "
                            f"Reason: {fd.skip_reason}. Binary files resist static analysis "
                            f"and may contain hidden functionality."
                        ),
                        file_path=fd.relative_path,
                        remediation=(
                            "Replace binary files with source code, or submit the binary "
                            "to VirusTotal for independent verification (--use-virustotal)."
                        ),
                        analyzer="analyzability",
                        metadata={
                            "skip_reason": fd.skip_reason,
                            "weight": fd.weight,
                            # Scanner-owned, bounded classification for the
                            # CEL projector. The decision layer must never
                            # infer binary role by reparsing the description
                            # or the (potentially sensitive) skip reason.
                            "semantic_facts": {
                                "evidence_kind": "file_analyzability",
                                "evidence_value_class": "opaque_binary",
                                "context_kind": "binary",
                                "signal_kind": "unanalyzable_binary",
                            },
                        },
                    )
                )

        # Overall analyzability score findings — check policy knob
        if "LOW_ANALYZABILITY" in self.policy.disabled_rules:
            return findings  # early return; UNANALYZABLE_BINARY already collected above

        if report.risk_level == "HIGH":
            # < medium_threshold (default 70%) — critically low analyzability
            findings.append(
                Finding(
                    id="LOW_ANALYZABILITY_CRITICAL",
                    rule_id="LOW_ANALYZABILITY",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.HIGH,
                    title="Critically low analyzability score",
                    description=(
                        f"Only {report.score:.0f}% of skill content could be analyzed. "
                        f"{report.unanalyzable_files} of {report.total_files} files are opaque "
                        f"to the scanner. The safety assessment has low confidence."
                    ),
                    remediation=(
                        "Replace opaque files (binaries, encrypted content) with "
                        "inspectable source code to improve scan confidence."
                    ),
                    analyzer="analyzability",
                    metadata={
                        "score": round(report.score, 1),
                        "unanalyzable_files": report.unanalyzable_files,
                        "total_files": report.total_files,
                        "risk_level": report.risk_level,
                    },
                )
            )
        elif report.risk_level == "MEDIUM":
            # Between medium and low thresholds (default 70-90%)
            findings.append(
                Finding(
                    id="LOW_ANALYZABILITY_MODERATE",
                    rule_id="LOW_ANALYZABILITY",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.MEDIUM,
                    title="Moderate analyzability score",
                    description=(
                        f"Only {report.score:.0f}% of skill content could be analyzed. "
                        f"{report.unanalyzable_files} of {report.total_files} files are opaque "
                        f"to the scanner. Some content could not be verified as safe."
                    ),
                    remediation=("Review opaque files and replace with inspectable formats where possible."),
                    analyzer="analyzability",
                    metadata={
                        "score": round(report.score, 1),
                        "unanalyzable_files": report.unanalyzable_files,
                        "total_files": report.total_files,
                        "risk_level": report.risk_level,
                    },
                )
            )

        return findings

    @staticmethod
    def _build_enrichment_context(
        skill: Skill,
        findings: list[Finding],
        unreferenced_scripts: list[str] | None = None,
    ) -> bool:
        """Check if there is meaningful enrichment context to pass to LLM analyzers."""
        has_critical_or_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        has_unreferenced = bool(unreferenced_scripts)
        has_magic_mismatch = any(f.rule_id and "MAGIC" in (f.rule_id or "") for f in findings)
        return bool(skill.files) or has_critical_or_high or has_unreferenced or has_magic_mismatch

    def _apply_severity_overrides(self, findings: list) -> None:
        """Apply severity overrides from policy ``severity_overrides``.

        Findings previously demoted by the adjudicator (marked with
        ``metadata['adjudication']['demoted_to']``) are exempt — the
        adjudicator's INFO verdict is load-bearing for downstream verdict
        computation and must not be re-raised by a per-rule override.
        """
        for finding in findings:
            if (finding.metadata or {}).get("adjudication", {}).get("demoted_to"):
                continue
            override = self.policy.get_severity_override(finding.rule_id)
            if override:
                try:
                    finding.severity = Severity(override)
                except (ValueError, KeyError):
                    logger.warning("Invalid severity override '%s' for rule %s", override, finding.rule_id)

    @staticmethod
    def _normalize_snippet(snippet: str | None) -> str:
        """Normalize snippets for stable dedupe keys."""
        if not snippet:
            return ""
        lowered = snippet.lower()
        collapsed = re.sub(r"\s+", " ", lowered).strip()
        return collapsed[:240]

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.SAFE: 0,
        }
        return order.get(severity, 0)

    def _analyzer_rank(self, name: str | None) -> int:
        """Policy-driven analyzer precedence for same-issue collapse."""
        if not name:
            return 0
        lower = name.lower()
        prefs = [p.lower() for p in self.policy.finding_output.same_issue_preferred_analyzers]
        for idx, token in enumerate(prefs):
            if token and token in lower:
                # Earlier entries in preference list should rank higher.
                return len(prefs) - idx
        return 0

    def _normalize_findings(self, findings: list[Finding]) -> list[Finding]:
        """Global final-stage finding de-duplication."""
        fo = self.policy.finding_output
        if not findings or (not fo.dedupe_exact_findings and not fo.dedupe_same_issue_per_location):
            return findings

        normalized = self._dedupe_exact_findings(findings)

        if not fo.dedupe_same_issue_per_location:
            return normalized

        grouped: dict[tuple[object, ...], list[Finding]] = {}
        passthrough: list[Finding] = []
        for f in normalized:
            file_key = (f.file_path or "").lower()
            line_key = int(f.line_number or 0)
            snippet_key = self._normalize_snippet(f.snippet)
            # Only collapse when we have meaningful location/surface context.
            has_location = bool(file_key) and (line_key > 0 or bool(snippet_key))
            if not has_location:
                passthrough.append(f)
                continue
            group_key = (file_key, line_key, snippet_key, f.category.value)
            grouped.setdefault(group_key, []).append(f)

        merged: list[Finding] = []
        for group in grouped.values():
            if len(group) == 1:
                merged.append(group[0])
                continue
            analyzers_in_group = {(f.analyzer or "").lower() for f in group if (f.analyzer or "").strip()}
            # Same-issue collapse is intended to remove overlap across analyzers.
            # If all findings come from one analyzer, keep them as separate signals.
            if len(analyzers_in_group) <= 1 and not fo.same_issue_collapse_within_analyzer:
                merged.extend(
                    sorted(
                        group,
                        key=lambda f: (
                            self._severity_rank(f.severity) * -1,
                            f.rule_id,
                        ),
                    )
                )
                continue
            cel_decisions = self._cel_decision_lineage(group)
            winner = max(
                group,
                key=lambda f: (
                    self._analyzer_rank(f.analyzer),
                    self._severity_rank(f.severity),
                    f.rule_id,
                ),
            )
            max_severity = max((f.severity for f in group), key=self._severity_rank)
            if self._severity_rank(max_severity) > self._severity_rank(winner.severity):
                winner.metadata["deduped_original_severity"] = winner.severity.value
                winner.severity = max_severity

            merged_rule_ids = sorted({f.rule_id for f in group if f.rule_id != winner.rule_id})
            merged_analyzers = sorted(
                {(f.analyzer or "") for f in group if (f.analyzer or "") != (winner.analyzer or "")}
            )

            # If preferred winner has no remediation, inherit the strongest
            # available remediation from merged findings.
            if not winner.remediation:
                fallback = max(
                    group,
                    key=lambda f: (
                        self._severity_rank(f.severity),
                        self._analyzer_rank(f.analyzer),
                        bool(f.remediation),
                    ),
                )
                if fallback.remediation:
                    winner.remediation = fallback.remediation

            if merged_rule_ids:
                winner.metadata["deduped_rule_ids"] = merged_rule_ids
            if merged_analyzers:
                winner.metadata["deduped_analyzers"] = merged_analyzers
            winner.metadata["deduped_count"] = len(group) - 1
            if cel_decisions:
                # Shadow mode must not change finding identities or
                # multiplicity. Preserve the ordinary OFF-mode winner while
                # attaching a bounded, counted lineage for every decided
                # candidate collapsed into it. Evaluators use this lineage
                # instead of inferring decisions from only the winning rule.
                winner.metadata["cel_decisions"] = cel_decisions
            merged.append(winner)

        # Preserve deterministic output order for stable benchmarks.
        final = merged + passthrough
        final.sort(
            key=lambda f: (
                (f.file_path or ""),
                int(f.line_number or 0),
                self._severity_rank(f.severity) * -1,
                f.rule_id,
            )
        )
        return final

    @staticmethod
    def _has_cel_decision(finding: Finding) -> bool:
        """Return whether a retained finding carries an auditable CEL result."""

        annotation = finding.metadata.get("cel")
        return isinstance(annotation, dict) and annotation.get("decision") in {
            "fallback",
            "keep",
            "would_suppress",
        }

    @staticmethod
    def _cel_decision_lineage(findings: list[Finding]) -> list[dict[str, object]]:
        """Return bounded counted CEL lineage for a merged finding group."""

        decisions: dict[tuple[str, ...], int] = {}
        for finding in findings:
            existing = finding.metadata.get("cel_decisions")
            if isinstance(existing, list):
                if len(existing) > 4_096:
                    raise ValueError("CEL decision lineage exceeds the bounded output contract")
                for entry in existing:
                    if not isinstance(entry, dict):
                        raise ValueError("CEL decision lineage contains an invalid entry")
                    decision = entry.get("decision")
                    count = entry.get("count")
                    values = (
                        entry.get("rule_id"),
                        decision,
                        entry.get("reason"),
                        entry.get("fact_schema"),
                        entry.get("expression_hash"),
                        entry.get("pack"),
                        entry.get("rollout"),
                    )
                    if (
                        decision not in {"fallback", "keep", "would_suppress"}
                        or any(not isinstance(value, str) or not value for value in values)
                        or isinstance(count, bool)
                        or not isinstance(count, int)
                        or count <= 0
                    ):
                        raise ValueError("CEL decision lineage contains an invalid entry")
                    key = cast(tuple[str, ...], values)
                    decisions[key] = decisions.get(key, 0) + count
                # Scanner-generated lineage already includes the selected
                # finding's singular annotation. Reading both would double
                # count it when exact and same-issue normalization compose.
                continue

            annotation = finding.metadata.get("cel")
            if not isinstance(annotation, dict):
                continue
            decision = annotation.get("decision")
            if decision not in {"fallback", "keep", "would_suppress"}:
                continue
            values = (
                finding.rule_id,
                decision,
                str(annotation.get("reason", "unspecified")),
                str(annotation.get("fact_schema", "unspecified")),
                str(annotation.get("expression_hash", "unspecified")),
                str(annotation.get("pack", "unspecified") or "unspecified"),
                str(annotation.get("rollout", "unspecified")),
            )
            decisions[values] = decisions.get(values, 0) + 1
        if len(decisions) > 4_096:
            raise ValueError("CEL decision lineage exceeds the bounded output contract")
        return [
            {
                "rule_id": values[0],
                "decision": values[1],
                "reason": values[2],
                "fact_schema": values[3],
                "expression_hash": values[4],
                "pack": values[5],
                "rollout": values[6],
                "count": count,
            }
            for values, count in sorted(decisions.items())
        ]

    def _dedupe_exact_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove byte-equivalent finding identities in stable input order.

        This narrow pass is safe before CEL because it never merges analyzers,
        rule IDs, severities, locations, or evidence surfaces.  Running the
        same helper again at the final output boundary also covers findings
        introduced by LLM/meta analyzers.
        """

        if not findings or not self.policy.finding_output.dedupe_exact_findings:
            return findings

        deduped: list[Finding] = []
        seen: dict[tuple[object, ...], int] = {}
        groups: dict[int, list[Finding]] = {}
        for finding in findings:
            exact_key = (
                finding.rule_id,
                finding.category.value,
                finding.severity.value,
                (finding.file_path or "").lower(),
                int(finding.line_number or 0),
                self._normalize_snippet(finding.snippet),
                (finding.analyzer or "").lower(),
            )
            existing_index = seen.get(exact_key)
            if existing_index is not None:
                groups[existing_index].append(finding)
                continue
            seen[exact_key] = len(deduped)
            groups[len(deduped)] = [finding]
            deduped.append(finding)
        for index, group in groups.items():
            if len(group) <= 1:
                continue
            cel_decisions = self._cel_decision_lineage(group)
            if cel_decisions:
                # Severity adjudication/overrides can make two candidates
                # exact duplicates only after CEL. Preserve the ordinary
                # first-winner identity while retaining every decision.
                deduped[index].metadata["cel_decisions"] = cel_decisions
        return deduped

    @staticmethod
    def _finding_rule_ids(finding: Finding) -> set[str]:
        """Rule IDs represented by a finding, including merged dedupe aliases."""
        rule_ids = {finding.rule_id}
        deduped = finding.metadata.get("deduped_rule_ids")
        if isinstance(deduped, list):
            for rid in deduped:
                if isinstance(rid, str) and rid:
                    rule_ids.add(rid)
        return rule_ids

    def _annotate_same_path_rule_cooccurrence(self, findings: list[Finding]) -> None:
        """Add metadata about other rules that triggered on the same file path."""
        if not self.policy.finding_output.annotate_same_path_rule_cooccurrence:
            return
        if not findings:
            return

        grouped: dict[str, list[Finding]] = {}
        for f in findings:
            path = (f.file_path or "").strip()
            if not path:
                continue
            grouped.setdefault(path.lower(), []).append(f)

        for group in grouped.values():
            if not group:
                continue
            path_rule_universe: set[str] = set()
            for f in group:
                path_rule_universe.update(self._finding_rule_ids(f))
            if len(path_rule_universe) <= 1:
                continue

            sorted_universe = sorted(path_rule_universe)
            for f in group:
                other_rules = sorted(path_rule_universe - self._finding_rule_ids(f))
                if not other_rules:
                    continue
                f.metadata["same_path_other_rule_ids"] = other_rules
                f.metadata["same_path_unique_rule_count"] = len(sorted_universe)
                f.metadata["same_path_findings_count"] = len(group)

    def _policy_fingerprint_metadata(self) -> dict[str, str]:
        """Build deterministic policy fingerprint metadata."""
        payload = self.policy._to_dict()
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "policy_name": self.policy.policy_name,
            "policy_version": self.policy.policy_version,
            "policy_preset_base": self.policy.preset_base,
            "policy_fingerprint_sha256": digest,
        }

    def _annotate_findings_with_policy(self, findings: list[Finding], policy_meta: dict[str, str]) -> None:
        """Attach scan-policy metadata to each finding (policy-controlled)."""
        if not self.policy.finding_output.attach_policy_fingerprint:
            return
        for f in findings:
            f.metadata.setdefault("scan_policy_name", policy_meta["policy_name"])
            f.metadata.setdefault("scan_policy_version", policy_meta["policy_version"])
            f.metadata.setdefault("scan_policy_preset_base", policy_meta["policy_preset_base"])
            f.metadata.setdefault("scan_policy_fingerprint_sha256", policy_meta["policy_fingerprint_sha256"])

    def scan_directory(
        self,
        skills_directory: str | Path,
        recursive: bool = False,
        check_overlap: bool = False,
        *,
        lenient: bool = False,
        skill_file: str | None = None,
    ) -> Report:
        """
        Scan all skill packages in a directory.

        Uses the same two-phase analysis pipeline as ``scan_skill`` via the
        shared ``_scan_single_skill`` helper, ensuring identical behaviour
        (enrichment context, severity overrides, disabled rules, etc.).

        Args:
            skills_directory: Directory containing skill packages
            recursive: If True, search recursively for SKILL.md files
            check_overlap: If True, check for description overlap between skills
            lenient: Tolerate malformed YAML / missing fields in skills.
                When True, directories containing ``.md`` files (but no
                ``SKILL.md``) are also discovered as candidate skills.
            skill_file: Optional custom metadata filename (e.g. ``"README.md"``).

        Returns:
            Report with results from all skills
        """
        if not isinstance(skills_directory, Path):
            skills_directory = Path(skills_directory)

        if not skills_directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {skills_directory}")

        skill_dirs = self._find_skill_directories(skills_directory, recursive, lenient=lenient, skill_file=skill_file)
        report = Report()

        # Keep track of loaded skills for cross-skill analysis
        loaded_skills: list[Skill] = []

        for skill_dir in skill_dirs:
            try:
                skill, load_telemetry = self._load_skill_for_scan(
                    skill_dir,
                    lenient=lenient,
                    skill_file=skill_file,
                )
                result = self._scan_single_skill(skill, skill_dir, load_telemetry=load_telemetry)
                report.add_scan_result(result)

                if check_overlap and skill.manifest_complete:
                    loaded_skills.append(skill)

            except _SkillMetadataSizeRejection as rejection:
                report.add_scan_result(self._scan_load_rejection(skill_dir, rejection))
                continue
            except SkillLoadError as e:
                logger.warning("Failed to load %s: %s", skill_dir, e)
                report.skills_skipped.append({"skill": str(skill_dir), "reason": str(e)})
                continue
            except Exception as e:
                logger.error("Unexpected error scanning %s: %s", skill_dir, e, exc_info=True)
                report.skills_skipped.append({"skill": str(skill_dir), "reason": str(e)})
                continue

        # Perform cross-skill analysis if requested
        overlap_findings: list[Finding] = []
        cross_findings: list[Finding] = []
        if check_overlap and len(loaded_skills) > 1:
            try:
                overlap_findings = self._check_description_overlap(loaded_skills)
            except Exception as e:
                logger.error("Cross-skill description overlap check failed: %s", e)

            try:
                from .analyzers.cross_skill_scanner import CrossSkillScanner

                cross_analyzer = CrossSkillScanner()
                cross_findings = cross_analyzer.analyze_skill_set(loaded_skills)
            except ImportError:
                pass
            except Exception as e:
                logger.error("Cross-skill pattern detection failed: %s", e)

        if overlap_findings or cross_findings:
            all_cross_findings = list(overlap_findings or []) + list(cross_findings or [])
            if all_cross_findings:
                # Cross-package findings are emitted outside the ordinary
                # per-skill pipeline, but bundled schema-v2 metadata remains
                # authoritative here too.  Retain violations fail-open and
                # attach the same stable audit record used by scan_skill().
                _, _, _, contract_failures = self._validate_bundled_python_findings(all_cross_findings)
                for failure in contract_failures:
                    logger.error(
                        "Cross-skill finding contract validation failed for %s: %s",
                        failure["analyzer"],
                        failure["error"],
                    )
                # Apply policy filters to cross-skill findings (mirrors _scan_single_skill lines 279-283)
                if self.policy.disabled_rules:
                    all_cross_findings = [f for f in all_cross_findings if f.rule_id not in self.policy.disabled_rules]
                self._apply_severity_overrides(all_cross_findings)
                report.add_cross_skill_findings(all_cross_findings)

        return report

    def _check_description_overlap(self, skills: list[Skill]) -> list[Finding]:
        """
        Check for description overlap between skills.

        Similar descriptions could cause trigger hijacking where one skill
        steals requests intended for another.

        Args:
            skills: List of loaded skills to compare

        Returns:
            List of findings for overlapping descriptions
        """
        findings = []

        for i, skill_a in enumerate(skills):
            for skill_b in skills[i + 1 :]:
                similarity = self._jaccard_similarity(skill_a.description, skill_b.description)

                if similarity > 0.7:
                    digest = hashlib.sha256((skill_a.name + skill_b.name).encode()).hexdigest()[:8]
                    findings.append(
                        Finding(
                            id=f"OVERLAP_{digest}",
                            rule_id="TRIGGER_OVERLAP_RISK",
                            category=ThreatCategory.SOCIAL_ENGINEERING,
                            severity=Severity.MEDIUM,
                            title="Skills have overlapping descriptions",
                            description=(
                                f"Skills '{skill_a.name}' and '{skill_b.name}' have {similarity:.0%} "
                                f"similar descriptions. This may cause confusion about which skill "
                                f"should handle a request, or enable trigger hijacking attacks."
                            ),
                            file_path=f"{skill_a.name}/SKILL.md",
                            remediation=(
                                "Make skill descriptions more distinct by clearly specifying "
                                "the unique capabilities, file types, or use cases for each skill."
                            ),
                            metadata={
                                "skill_a": skill_a.name,
                                "skill_b": skill_b.name,
                                "similarity": similarity,
                            },
                            analyzer="scanner",
                        )
                    )
                elif similarity > 0.5:
                    digest = hashlib.sha256((skill_a.name + skill_b.name).encode()).hexdigest()[:8]
                    findings.append(
                        Finding(
                            id=f"OVERLAP_WARN_{digest}",
                            rule_id="TRIGGER_OVERLAP_WARNING",
                            category=ThreatCategory.SOCIAL_ENGINEERING,
                            severity=Severity.LOW,
                            title="Skills have somewhat similar descriptions",
                            description=(
                                f"Skills '{skill_a.name}' and '{skill_b.name}' have {similarity:.0%} "
                                f"similar descriptions. Consider making descriptions more distinct."
                            ),
                            file_path=f"{skill_a.name}/SKILL.md",
                            remediation="Consider making skill descriptions more distinct",
                            metadata={
                                "skill_a": skill_a.name,
                                "skill_b": skill_b.name,
                                "similarity": similarity,
                            },
                            analyzer="scanner",
                        )
                    )

        return findings

    def _jaccard_similarity(self, text_a: str, text_b: str) -> float:
        """
        Calculate Jaccard similarity between two text strings.

        Args:
            text_a: First text
            text_b: Second text

        Returns:
            Similarity score from 0.0 to 1.0
        """
        tokens_a = set(re.findall(r"\b[a-zA-Z]+\b", str(text_a).lower()))
        tokens_b = set(re.findall(r"\b[a-zA-Z]+\b", str(text_b).lower()))

        # Remove common stop words (using module-level constant)
        tokens_a = tokens_a - _STOP_WORDS
        tokens_b = tokens_b - _STOP_WORDS

        if not tokens_a or not tokens_b:
            return 0.0

        intersection = len(tokens_a & tokens_b)
        union = len(tokens_a | tokens_b)

        return intersection / union if union > 0 else 0.0

    def _walk_skill_dirs(self, directory: Path) -> Iterator[Path]:
        """Yield *directory* and every subdirectory beneath it, descending
        into symlinked directories as well.

        ``Path.rglob`` / ``Path.glob("**")`` do not follow directory symlinks
        (and on Python < 3.13 there is no option to make them), so skills
        installed as symlinks are silently skipped during recursive discovery.
        This is the standard Claude Code layout, where ``~/.claude/skills/<name>``
        is a symlink to a real directory elsewhere (issue #116).  ``os.walk``
        with ``followlinks=True`` descends into them.

        Following symlinks is deliberately bounded so a security scan cannot be
        turned against the user (issue #116 review):

        * **Containment.** When the walk crosses a symlink whose real target is
          *outside* the scan root, that directory itself is still yielded (so a
          per-skill symlink such as ``~/.claude/skills/<name>`` -- which points
          directly at a leaf skill with its ``SKILL.md`` at depth 0 -- is
          discovered), but its children are not descended into. This stops a
          hostile bundle whose ``trap -> /`` (or ``-> ~``) symlink would
          otherwise make discovery crawl the entire filesystem.

          Limitation: because descent stops at the crossing, a symlink pointing
          at an external *collection* of skills (e.g. ``skills -> /ext/skillset``
          with skills nested at ``skillset/a``, ``skillset/group/b``) only has
          its top level evaluated; nested skills underneath are not discovered.
          This is not a regression -- ``rglob`` followed no symlinks at all -- and
          the standard #116 layout (one symlink per skill) is unaffected. To scan
          such a collection, point the scanner directly at the resolved directory.
        * **Cycle safety.** Resolved paths are tracked so symlink cycles and
          aliases are walked at most once.
        * **DoS backstop.** Discovery stops after ``_MAX_WALK_DIRS`` directories,
          logging the truncation. Note this bounds the *number of directories*
          walked, not the entry count within a single directory: ``os.walk``
          still materializes one directory's full listing at a time, so a symlink
          to a single directory with an enormous number of entries is not bounded
          by this cap.
        """
        try:
            scan_root = directory.resolve()
        except OSError:
            return
        visited: set[Path] = set()
        for root, dirs, _files in os.walk(directory, followlinks=True):
            if len(visited) >= self._MAX_WALK_DIRS:
                logger.warning(
                    "Skill discovery truncated at %d directories under %s "
                    "(possible symlink fan-out); some skills may be skipped.",
                    self._MAX_WALK_DIRS,
                    directory,
                )
                break
            root_path = Path(root)
            try:
                real = root_path.resolve()
            except OSError:
                # Symlink loop / unreadable entry: do not descend further.
                dirs[:] = []
                continue
            if real in visited:
                # Already walked this real directory (symlink cycle or alias).
                dirs[:] = []
                continue
            visited.add(real)
            yield root_path
            if not real.is_relative_to(scan_root):
                # Followed a symlink out of the scan root: evaluate this
                # directory as a skill, but do not wander into its external
                # siblings/children (containment, see docstring).
                dirs[:] = []

    def _find_skill_directories(
        self,
        directory: Path,
        recursive: bool,
        *,
        lenient: bool = False,
        skill_file: str | None = None,
    ) -> list[Path]:
        """
        Find all directories containing skill metadata files.

        When *lenient* is True and no ``SKILL.md`` (or *skill_file*) is found,
        directories containing at least one ``.md`` file are also treated as
        candidate skills.  This enables scanning non-Codex/Cursor formats such
        as Claude Code ``.claude/commands/*.md`` or flat markdown skill repos.

        Args:
            directory: Directory to search
            recursive: Search recursively
            lenient: Also discover directories with ``.md`` files (no ``SKILL.md``)
            skill_file: Custom metadata filename to look for instead of ``SKILL.md``

        Returns:
            List of skill directory paths
        """
        target_filename = skill_file or "SKILL.md"
        skill_dirs: list[Path] = []
        seen: set[Path] = set()

        # Phase 1: find directories with the target metadata file
        if recursive:
            for sub in self._walk_skill_dirs(directory):
                if (sub / target_filename).exists():
                    resolved = sub.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        skill_dirs.append(sub)
        else:
            for item in directory.iterdir():
                if item.is_dir():
                    md = item / target_filename
                    if md.exists():
                        resolved = item.resolve()
                        if resolved not in seen:
                            seen.add(resolved)
                            skill_dirs.append(item)

        # Phase 2 (lenient only): discover directories with .md files
        if lenient:
            if recursive:
                for sub in self._walk_skill_dirs(directory):
                    candidate = sub.resolve()
                    if candidate in seen:
                        continue
                    if any(sub.glob("*.md")):
                        seen.add(candidate)
                        skill_dirs.append(sub)
            else:
                for item in directory.iterdir():
                    if item.is_dir():
                        resolved = item.resolve()
                        if resolved in seen:
                            continue
                        if any(item.glob("*.md")):
                            seen.add(resolved)
                            skill_dirs.append(item)

        return skill_dirs

    def add_analyzer(self, analyzer: BaseAnalyzer):
        """Add an analyzer to the scanner."""
        self.analyzers.append(analyzer)

    def list_analyzers(self) -> list[str]:
        """Get names of all configured analyzers."""
        return [analyzer.get_name() for analyzer in self.analyzers]

    def close(self) -> None:
        """Release persistent decision-runtime resources."""

        self.cel_gate.close()

    def __enter__(self) -> SkillScanner:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def scan_skill(
    skill_directory: str | Path,
    analyzers: list[BaseAnalyzer] | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    """
    Convenience function to scan a single skill.

    Args:
        skill_directory: Path to skill directory
        analyzers: Optional list of analyzers
        policy: Optional scan policy. If omitted and analyzers are provided,
            the policy from the first analyzer is used when available.

    Returns:
        ScanResult
    """
    scanner_policy = policy
    if scanner_policy is None and analyzers:
        scanner_policy = getattr(analyzers[0], "policy", None)
    with SkillScanner(analyzers=analyzers, policy=scanner_policy) as scanner:
        return scanner.scan_skill(skill_directory)


def scan_directory(
    skills_directory: str | Path,
    recursive: bool = False,
    analyzers: list[BaseAnalyzer] | None = None,
    check_overlap: bool = False,
    policy: ScanPolicy | None = None,
) -> Report:
    """
    Convenience function to scan multiple skills.

    Args:
        skills_directory: Directory containing skills
        recursive: Search recursively
        analyzers: Optional list of analyzers
        check_overlap: If True, check for description overlap between skills
        policy: Optional scan policy. If omitted and analyzers are provided,
            the policy from the first analyzer is used when available.

    Returns:
        Report with all results
    """
    scanner_policy = policy
    if scanner_policy is None and analyzers:
        scanner_policy = getattr(analyzers[0], "policy", None)
    with SkillScanner(analyzers=analyzers, policy=scanner_policy) as scanner:
        return scanner.scan_directory(skills_directory, recursive=recursive, check_overlap=check_overlap)
