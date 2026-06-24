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
SARIF format reporter for GitHub Code Scanning integration.

Implements SARIF 2.1.0 specification for security scan results.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import os
from pathlib import Path
from typing import Any

from ...core.models import Finding, Report, ScanResult, Severity


class SARIFReporter:
    """Generates SARIF 2.1.0 format reports for GitHub Code Scanning."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Map severity to SARIF levels
    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
        Severity.SAFE: "none",
    }

    def __init__(self, tool_name: str = "skill-scanner", tool_version: str = "1.0.0"):
        """
        Initialize SARIF reporter.

        Args:
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate_report(self, data: ScanResult | Report) -> str:
        """
        Generate SARIF report.

        Args:
            data: ScanResult or Report object

        Returns:
            SARIF JSON string
        """
        if isinstance(data, ScanResult):
            sarif = self._generate_from_scan_result(data)
        else:
            sarif = self._generate_from_report(data)

        return json.dumps(sarif, indent=2, default=str)

    def _generate_from_scan_result(self, result: ScanResult) -> dict[str, Any]:
        """Generate SARIF from a single ScanResult."""
        rules = self._extract_rules(result.findings)
        results = self._convert_findings(result.findings, result.skill_directory)

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": self._create_tool_component(rules),
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": result.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                    ],
                }
            ],
        }

    def _generate_from_report(self, report: Report) -> dict[str, Any]:
        """Generate SARIF from a Report with multiple scan results."""
        all_findings = []
        for scan_result in report.scan_results:
            all_findings.extend(scan_result.findings)
        all_findings.extend(report.cross_skill_findings)

        rules = self._extract_rules(all_findings)

        # Create results with proper artifact locations
        all_results = []
        for scan_result in report.scan_results:
            results = self._convert_findings(scan_result.findings, scan_result.skill_directory)
            all_results.extend(results)
        all_results.extend(self._convert_findings(report.cross_skill_findings))

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": self._create_tool_component(rules),
                    "results": all_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": report.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                    ],
                }
            ],
        }

    def _create_tool_component(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        """Create the tool component with rules."""
        return {
            "driver": {
                "name": self.tool_name,
                "version": self.tool_version,
                "informationUri": "https://github.com/cisco-ai-defense/skill-scanner",
                "rules": rules,
            }
        }

    def _extract_rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Extract unique rules from findings."""
        seen_rules: set[str] = set()
        rules = []

        for finding in findings:
            if finding.rule_id in seen_rules:
                continue
            seen_rules.add(finding.rule_id)

            rule = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("_", " ").title(),
                "shortDescription": {
                    "text": finding.title,
                },
                "fullDescription": {
                    "text": finding.description,
                },
                "defaultConfiguration": {
                    "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                },
                "properties": {
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "tags": [finding.category.value, "security"],
                },
            }

            if finding.remediation:
                rule["help"] = {
                    "text": finding.remediation,
                    "markdown": f"**Remediation**: {finding.remediation}",
                }

            rules.append(rule)

        return rules

    @staticmethod
    def _artifact_uri(finding: Finding, skill_directory: str | None) -> str:
        """Build the artifact URI for a finding, relative to the scan root.

        Finding.file_path is relative to the skill's own directory. GitHub Code
        Scanning resolves URIs against %SRCROOT% (the repository root), so when
        skills are discovered in subdirectories the skill path must be included
        for results to be tied to files in a PR. The scanner's working directory
        is taken as the scan root; when the skill directory lies outside it
        (or on a different drive), the skill-relative path is kept as before.
        """
        file_path = finding.file_path if finding.file_path else "SKILL.md"
        if not skill_directory or Path(file_path).is_absolute():
            return Path(file_path).as_posix()

        try:
            skill_rel = os.path.relpath(skill_directory, os.getcwd())
        except ValueError:
            # Windows: skill directory and CWD on different drives
            return Path(file_path).as_posix()

        if skill_rel == os.curdir:
            return Path(file_path).as_posix()
        if skill_rel == os.pardir or skill_rel.startswith(os.pardir + os.sep):
            # Skill directory is outside the scan root; a %SRCROOT%-relative
            # path cannot be formed, and ".." segments are invalid in SARIF.
            return Path(file_path).as_posix()

        return (Path(skill_rel) / file_path).as_posix()

    def _convert_findings(self, findings: list[Finding], skill_directory: str | None = None) -> list[dict[str, Any]]:
        """Convert findings to SARIF results."""
        results = []

        for finding in findings:
            result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": finding.description,
                },
                "properties": {
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    **({"remediation": finding.remediation} if finding.remediation else {}),
                },
            }

            artifact_uri = self._artifact_uri(finding, skill_directory)
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            }

            if finding.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line_number,
                }
                if finding.snippet:
                    location["physicalLocation"]["region"]["snippet"] = {
                        "text": finding.snippet,
                    }

            result["locations"] = [location]

            # Add fingerprint for deduplication
            result["fingerprints"] = {
                "primaryLocationLineHash": finding.id,
            }

            results.append(result)

        return results

    def save_report(self, data: ScanResult | Report, output_path: str):
        """
        Save SARIF report to file.

        Args:
            data: ScanResult or Report object
            output_path: Path to save file
        """
        report_json = self.generate_report(data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_json)
