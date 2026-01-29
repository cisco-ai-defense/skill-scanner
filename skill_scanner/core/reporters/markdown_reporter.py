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
Markdown format reporter for scan results.
"""

from ...core.models import Finding, Report, ScanResult, Severity


class MarkdownReporter:
    """Generates Markdown format reports."""

    def __init__(self, detailed: bool = True):
        """
        Initialize Markdown reporter.

        Args:
            detailed: If True, include full finding details
        """
        self.detailed = detailed

    def generate_report(self, data: ScanResult | Report) -> str:
        """
        Generate Markdown report.

        Args:
            data: ScanResult or Report object

        Returns:
            Markdown string
        """
        if isinstance(data, ScanResult):
            return self._generate_scan_result_report(data)
        else:
            return self._generate_multi_skill_report(data)

    def _generate_scan_result_report(self, result: ScanResult) -> str:
        """Generate report for a single skill scan."""
        lines = []

        # Header
        lines.append("# Agent Skill Security Scan Report")
        lines.append("")
        lines.append(f"**Skill:** {result.skill_name}")
        lines.append(f"**Directory:** {result.skill_directory}")
        lines.append(f"**Status:** {'[OK] SAFE' if result.is_safe else '[FAIL] ISSUES FOUND'}")
        lines.append(f"**Max Severity:** {result.max_severity.value}")
        lines.append(f"**Scan Duration:** {result.scan_duration_seconds:.2f}s")
        lines.append(f"**Timestamp:** {result.timestamp.isoformat()}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Findings:** {len(result.findings)}")
        lines.append(f"- **Critical:** {len(result.get_findings_by_severity(Severity.CRITICAL))}")
        lines.append(f"- **High:** {len(result.get_findings_by_severity(Severity.HIGH))}")
        lines.append(f"- **Medium:** {len(result.get_findings_by_severity(Severity.MEDIUM))}")
        lines.append(f"- **Low:** {len(result.get_findings_by_severity(Severity.LOW))}")
        lines.append(f"- **Info:** {len(result.get_findings_by_severity(Severity.INFO))}")
        lines.append("")

        # Findings
        if result.findings:
            lines.append("## Findings")
            lines.append("")

            # Group by severity
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                findings = result.get_findings_by_severity(severity)
                if findings:
                    lines.append(f"### {severity.value} Severity")
                    lines.append("")

                    for finding in findings:
                        lines.extend(self._format_finding(finding))
                        lines.append("")
        else:
            lines.append("## [OK] No Issues Found")
            lines.append("")
            lines.append("This skill passed all security checks.")
            lines.append("")

        # Analyzers used
        lines.append("## Analyzers")
        lines.append("")
        lines.append("The following analyzers were used:")
        lines.append("")
        for analyzer in result.analyzers_used:
            lines.append(f"- {analyzer}")
        lines.append("")

        return "\n".join(lines)

    def _generate_multi_skill_report(self, report: Report) -> str:
        """Generate report for multiple skills."""
        lines = []

        # Header
        lines.append("# Agent Skills Security Scan Report")
        lines.append("")
        lines.append(f"**Timestamp:** {report.timestamp.isoformat()}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Skills Scanned:** {report.total_skills_scanned}")
        lines.append(f"- **Safe Skills:** {report.safe_count}")
        lines.append(f"- **Total Findings:** {report.total_findings}")
        lines.append("")
        lines.append("### Findings by Severity")
        lines.append("")
        lines.append(f"- **Critical:** {report.critical_count}")
        lines.append(f"- **High:** {report.high_count}")
        lines.append(f"- **Medium:** {report.medium_count}")
        lines.append(f"- **Low:** {report.low_count}")
        lines.append(f"- **Info:** {report.info_count}")
        lines.append("")

        # Individual skill results
        lines.append("## Skill Results")
        lines.append("")

        for result in report.scan_results:
            status_icon = "[OK]" if result.is_safe else "[FAIL]"
            lines.append(f"### {status_icon} {result.skill_name}")
            lines.append("")
            lines.append(f"- **Max Severity:** {result.max_severity.value}")
            lines.append(f"- **Findings:** {len(result.findings)}")
            lines.append(f"- **Directory:** {result.skill_directory}")
            lines.append("")

            if self.detailed and result.findings:
                for finding in result.findings:
                    lines.extend(self._format_finding(finding, indent=1))
                    lines.append("")

        return "\n".join(lines)

    def _format_finding(self, finding: Finding, indent: int = 0) -> list:
        """Format a single finding as markdown lines."""
        lines = []
        indent_str = "  " * indent

        # Severity prefix
        severity_prefix = {
            Severity.CRITICAL: "[CRITICAL]",
            Severity.HIGH: "[HIGH]",
            Severity.MEDIUM: "[MEDIUM]",
            Severity.LOW: "[LOW]",
            Severity.INFO: "[INFO]",
        }
        prefix = severity_prefix.get(finding.severity, "[INFO]")

        lines.append(f"{indent_str}#### {prefix} {finding.title}")
        lines.append(f"{indent_str}")
        lines.append(f"{indent_str}**Severity:** {finding.severity.value}")
        lines.append(f"{indent_str}**Category:** {finding.category.value}")
        lines.append(f"{indent_str}**Rule ID:** {finding.rule_id}")

        if finding.file_path:
            location = f"{finding.file_path}"
            if finding.line_number:
                location += f":{finding.line_number}"
            lines.append(f"{indent_str}**Location:** {location}")

        lines.append(f"{indent_str}")
        lines.append(f"{indent_str}**Description:** {finding.description}")

        if self.detailed:
            if finding.snippet:
                lines.append(f"{indent_str}")
                lines.append(f"{indent_str}**Code Snippet:**")
                lines.append(f"{indent_str}```")
                lines.append(f"{indent_str}{finding.snippet}")
                lines.append(f"{indent_str}```")

            if finding.remediation:
                lines.append(f"{indent_str}")
                lines.append(f"{indent_str}**Remediation:** {finding.remediation}")

        return lines

    def save_report(self, data: ScanResult | Report, output_path: str):
        """
        Save Markdown report to file.

        Args:
            data: ScanResult or Report object
            output_path: Path to save file
        """
        report_md = self.generate_report(data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_md)
