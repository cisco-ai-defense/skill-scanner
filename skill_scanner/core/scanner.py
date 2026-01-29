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

from .analyzers.base import BaseAnalyzer
from .analyzers.static import StaticAnalyzer
from .analyzers.virustotal_analyzer import VirusTotalAnalyzer
from .loader import SkillLoader, SkillLoadError
from .models import Finding, Report, ScanResult, Severity, Skill, ThreatCategory

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
    ):
        """
        Initialize scanner with analyzers.

        Args:
            analyzers: List of analyzers to use. If None, uses default (static).
            use_virustotal: Whether to enable VirusTotal binary scanning
            virustotal_api_key: VirusTotal API key (required if use_virustotal=True)
            virustotal_upload_files: If True, upload unknown files to VT. If False (default),
                                    only check existing hashes
        """
        if analyzers is None:
            self.analyzers: list[BaseAnalyzer] = [StaticAnalyzer()]

            if use_virustotal and virustotal_api_key:
                vt_analyzer = VirusTotalAnalyzer(
                    api_key=virustotal_api_key, enabled=True, upload_files=virustotal_upload_files
                )
                self.analyzers.append(vt_analyzer)
        else:
            self.analyzers = analyzers

        self.loader = SkillLoader()

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

        start_time = time.time()

        # Load the skill
        skill = self.loader.load_skill(skill_directory)

        # Run all analyzers
        all_findings = []
        analyzer_names = []
        validated_binary_files = set()

        for analyzer in self.analyzers:
            findings = analyzer.analyze(skill)
            all_findings.extend(findings)
            analyzer_names.append(analyzer.get_name())

            if hasattr(analyzer, "validated_binary_files"):
                validated_binary_files.update(analyzer.validated_binary_files)

        # Post-process findings: Suppress BINARY_FILE_DETECTED for VirusTotal-validated files
        if validated_binary_files:
            filtered_findings = []
            for finding in all_findings:
                if finding.rule_id == "BINARY_FILE_DETECTED" and finding.file_path in validated_binary_files:
                    continue
                filtered_findings.append(finding)
            all_findings = filtered_findings

        scan_duration = time.time() - start_time

        result = ScanResult(
            skill_name=skill.name,
            skill_directory=str(skill_directory.absolute()),
            findings=all_findings,
            scan_duration_seconds=scan_duration,
            analyzers_used=analyzer_names,
        )

        return result

    def scan_directory(self, skills_directory: Path, recursive: bool = False, check_overlap: bool = False) -> Report:
        """
        Scan all skill packages in a directory.

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
                # Load skill once for both scanning and cross-skill analysis
                skill = self.loader.load_skill(skill_dir)

                # Run all analyzers on the already-loaded skill
                start_time = time.time()
                all_findings = []
                analyzer_names = []
                validated_binary_files = set()

                for analyzer in self.analyzers:
                    findings = analyzer.analyze(skill)
                    all_findings.extend(findings)
                    analyzer_names.append(analyzer.get_name())

                    if hasattr(analyzer, "validated_binary_files"):
                        validated_binary_files.update(analyzer.validated_binary_files)

                # Post-process findings
                if validated_binary_files:
                    all_findings = [
                        f
                        for f in all_findings
                        if not (f.rule_id == "BINARY_FILE_DETECTED" and f.file_path in validated_binary_files)
                    ]

                scan_duration = time.time() - start_time

                result = ScanResult(
                    skill_name=skill.name,
                    skill_directory=str(skill_dir.absolute()),
                    findings=all_findings,
                    scan_duration_seconds=scan_duration,
                    analyzers_used=analyzer_names,
                )

                report.add_scan_result(result)

                # Store skill for cross-skill analysis if needed
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
