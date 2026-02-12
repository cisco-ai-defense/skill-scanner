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

import logging
import re
import time
from pathlib import Path

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

        self.loader = SkillLoader()
        self.content_extractor = ContentExtractor()

    def scan_skill(self, skill_directory: Path) -> ScanResult:
        """
        Scan a single skill package.

        Args:
            skill_directory: Path to skill directory

        Returns:
            ScanResult with findings

        Raises:
            SkillLoadError: If skill cannot be loaded
        """
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)

        skill = self.loader.load_skill(skill_directory)
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

        # Run all analyzers in two phases:
        # Phase 1: Non-LLM analyzers (static, pipeline, behavioral, etc.)
        # Phase 2: LLM analyzers (enriched with Phase 1 context)
        all_findings: list[Finding] = []
        # Include any archive extraction findings (zip bombs, path traversal, etc.)
        all_findings.extend(extraction_result.findings)
        analyzer_names: list[str] = []
        validated_binary_files: set[str] = set()
        llm_analyzers: list[BaseAnalyzer] = []
        unreferenced_scripts: list[str] = []

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

        # Cleanup temporary extraction directories
        self.content_extractor.cleanup()

        scan_duration = time.time() - start_time

        result = ScanResult(
            skill_name=skill.name,
            skill_directory=str(skill_directory.absolute()),
            findings=all_findings,
            scan_duration_seconds=scan_duration,
            analyzers_used=analyzer_names,
            analyzability_score=analyzability.score,
            analyzability_details=analyzability.to_dict(),
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
                            "to VirusTotal for independent verification (--enable-virustotal)."
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

    def scan_directory(self, skills_directory: Path, recursive: bool = False, check_overlap: bool = False) -> Report:
        """
        Scan all skill packages in a directory.

        Uses the same two-phase analysis pipeline as ``scan_skill`` via the
        shared ``_scan_single_skill`` helper, ensuring identical behaviour
        (enrichment context, severity overrides, disabled rules, etc.).

        Args:
            skills_directory: Directory containing skill packages
            recursive: If True, search recursively for SKILL.md files
            check_overlap: If True, check for description overlap between skills

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
                skill = self.loader.load_skill(skill_dir)
                result = self._scan_single_skill(skill, skill_dir)
                report.add_scan_result(result)

                if check_overlap:
                    loaded_skills.append(skill)

            except SkillLoadError as e:
                logger.warning("Failed to scan %s: %s", skill_dir, e)
                continue

        # Perform cross-skill analysis if requested
        if check_overlap and len(loaded_skills) > 1:
            overlap_findings = self._check_description_overlap(loaded_skills)
            if overlap_findings and report.scan_results:
                report.scan_results[0].findings.extend(overlap_findings)

            # Full cross-skill attack pattern detection
            try:
                from .analyzers.cross_skill_scanner import CrossSkillScanner

                cross_analyzer = CrossSkillScanner()
                cross_findings = cross_analyzer.analyze_skill_set(loaded_skills)
                if cross_findings and report.scan_results:
                    report.scan_results[0].findings.extend(cross_findings)
            except ImportError:
                pass

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
                    findings.append(
                        Finding(
                            id=f"OVERLAP_{hash(skill_a.name + skill_b.name) & 0xFFFFFFFF:08x}",
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
                    findings.append(
                        Finding(
                            id=f"OVERLAP_WARN_{hash(skill_a.name + skill_b.name) & 0xFFFFFFFF:08x}",
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
        tokens_a = set(re.findall(r"\b[a-zA-Z]+\b", text_a.lower()))
        tokens_b = set(re.findall(r"\b[a-zA-Z]+\b", text_b.lower()))

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


def scan_skill(skill_directory: Path, analyzers: list[BaseAnalyzer] | None = None) -> ScanResult:
    """
    Convenience function to scan a single skill.

    Args:
        skill_directory: Path to skill directory
        analyzers: Optional list of analyzers

    Returns:
        ScanResult
    """
    scanner = SkillScanner(analyzers=analyzers)
    return scanner.scan_skill(skill_directory)


def scan_directory(
    skills_directory: Path,
    recursive: bool = False,
    analyzers: list[BaseAnalyzer] | None = None,
    check_overlap: bool = False,
) -> Report:
    """
    Convenience function to scan multiple skills.

    Args:
        skills_directory: Directory containing skills
        recursive: Search recursively
        analyzers: Optional list of analyzers
        check_overlap: If True, check for description overlap between skills

    Returns:
        Report with all results
    """
    scanner = SkillScanner(analyzers=analyzers)
    return scanner.scan_directory(skills_directory, recursive=recursive, check_overlap=check_overlap)
