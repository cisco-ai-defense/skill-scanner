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
import re
import time
from pathlib import Path
from typing import Any

from .analyzability import AnalyzabilityReport, compute_analyzability
from .analyzer_factory import build_core_analyzers
from .analyzers.base import BaseAnalyzer
from .extractors.content_extractor import ContentExtractor
from .loader import SkillLoader, SkillLoadError
from .models import Finding, Report, ScanResult, Severity, Skill, ThreatCategory
from .scan_policy import ScanPolicy

logger = logging.getLogger(__name__)

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

    def __init__(
        self,
        analyzers: list[BaseAnalyzer] | None = None,
        use_virustotal: bool = False,
        virustotal_api_key: str | None = None,
        virustotal_upload_files: bool = False,
        policy: ScanPolicy | None = None,
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
        """
        self.policy = policy or ScanPolicy.default()

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

    def scan_skill(self, skill_directory: str | Path, *, lenient: bool = False) -> ScanResult:
        """
        Scan a single skill package.

        Args:
            skill_directory: Path to skill directory
            lenient: Tolerate malformed YAML / missing fields in the skill.

        Returns:
            ScanResult with findings

        Raises:
            SkillLoadError: If skill cannot be loaded (when not lenient)
        """
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)

        skill = self.loader.load_skill(skill_directory, lenient=lenient)
        return self._scan_single_skill(skill, skill_directory)

    # ------------------------------------------------------------------
    # Shared single-skill scanning logic (used by both scan_skill and
    # scan_directory for identical behaviour).
    # ------------------------------------------------------------------

    def _scan_single_skill(self, skill: Skill, skill_directory: Path) -> ScanResult:
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
            # Include any archive extraction findings (zip bombs, path traversal, etc.)
            all_findings.extend(extraction_result.findings)
            analyzer_names: list[str] = []
            analyzers_failed: list[dict[str, str]] = []
            validated_binary_files: set[str] = set()
            llm_analyzers: list[BaseAnalyzer] = []
            unreferenced_scripts: list[str] = []
            llm_scan_meta: dict[str, Any] = {}

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
                        analyzer.set_enrichment_context(
                            file_inventory={
                                "total_files": len(skill.files),
                                "types": type_counts,
                                "unreferenced_scripts": unreferenced_scripts,
                            },
                            magic_mismatches=magic_mismatches if magic_mismatches else None,
                            static_findings_summary=static_summaries if static_summaries else None,
                        )
                    findings = analyzer.analyze(skill)
                    all_findings.extend(findings)
                    analyzer_names.append(analyzer.get_name())

                    # Track analyzer failures for machine-readable output
                    if hasattr(analyzer, "last_error") and analyzer.last_error:
                        analyzers_failed.append({"analyzer": analyzer.get_name(), "error": analyzer.last_error})

                    # Capture skill-level LLM assessment for scan_metadata
                    if hasattr(analyzer, "last_overall_assessment"):
                        llm_scan_meta["llm_overall_assessment"] = analyzer.last_overall_assessment
                        llm_scan_meta["llm_primary_threats"] = getattr(analyzer, "last_primary_threats", [])

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

            # Compute analyzability score
            analyzability = compute_analyzability(skill, policy=self.policy)

            # Generate findings from low analyzability (fail-closed posture)
            all_findings.extend(self._analyzability_findings(analyzability))

            # Normalize duplicate findings at final output stage (policy-controlled).
            all_findings = self._normalize_findings(all_findings)

            # Attach same-path rule co-occurrence metadata (policy-controlled).
            self._annotate_same_path_rule_cooccurrence(all_findings)

            # Attach policy fingerprint metadata for traceability (policy-controlled).
            policy_meta = self._policy_fingerprint_metadata()
            if llm_scan_meta:
                policy_meta.update(llm_scan_meta)
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
                        metadata={"skip_reason": fd.skip_reason, "weight": fd.weight},
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
        return has_critical_or_high or has_unreferenced or has_magic_mismatch

    def _apply_severity_overrides(self, findings: list) -> None:
        """Apply severity overrides from policy ``severity_overrides``."""
        for finding in findings:
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

        normalized = list(findings)

        if fo.dedupe_exact_findings:
            deduped_exact: list[Finding] = []
            seen_exact: set[tuple[object, ...]] = set()
            for f in normalized:
                exact_key = (
                    f.rule_id,
                    f.category.value,
                    f.severity.value,
                    (f.file_path or "").lower(),
                    int(f.line_number or 0),
                    self._normalize_snippet(f.snippet),
                    (f.analyzer or "").lower(),
                )
                if exact_key in seen_exact:
                    continue
                seen_exact.add(exact_key)
                deduped_exact.append(f)
            normalized = deduped_exact

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

        Returns:
            Report with results from all skills
        """
        if not isinstance(skills_directory, Path):
            skills_directory = Path(skills_directory)

        if not skills_directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {skills_directory}")

        skill_dirs = self._find_skill_directories(skills_directory, recursive)
        report = Report()

        # Keep track of loaded skills for cross-skill analysis
        loaded_skills: list[Skill] = []

        for skill_dir in skill_dirs:
            try:
                skill = self.loader.load_skill(skill_dir, lenient=lenient)
                result = self._scan_single_skill(skill, skill_dir)
                report.add_scan_result(result)

                if check_overlap:
                    loaded_skills.append(skill)

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

    def _find_skill_directories(self, directory: Path, recursive: bool) -> list[Path]:
        """
        Find all directories containing SKILL.md files.

        Args:
            directory: Directory to search
            recursive: Search recursively

        Returns:
            List of skill directory paths
        """
        skill_dirs = []

        if recursive:
            for skill_md in directory.rglob("SKILL.md"):
                skill_dirs.append(skill_md.parent)
        else:
            for item in directory.iterdir():
                if item.is_dir():
                    skill_md = item / "SKILL.md"
                    if skill_md.exists():
                        skill_dirs.append(item)

        return skill_dirs

    def add_analyzer(self, analyzer: BaseAnalyzer):
        """Add an analyzer to the scanner."""
        self.analyzers.append(analyzer)

    def list_analyzers(self) -> list[str]:
        """Get names of all configured analyzers."""
        return [analyzer.get_name() for analyzer in self.analyzers]


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
    scanner = SkillScanner(analyzers=analyzers, policy=scanner_policy)
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
    scanner = SkillScanner(analyzers=analyzers, policy=scanner_policy)
    return scanner.scan_directory(skills_directory, recursive=recursive, check_overlap=check_overlap)
