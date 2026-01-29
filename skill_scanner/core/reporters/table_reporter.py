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
Table format reporter for scan results.
"""

from tabulate import tabulate

from ...core.models import Report, ScanResult, Severity


class TableReporter:
    """Generates table format reports."""

    def __init__(self, format_style: str = "grid", show_snippets: bool = False):
        """
        Initialize table reporter.

        Args:
            format_style: Table format (grid, simple, plain, etc.)
            show_snippets: If True, include code snippets after table
        """
        self.format_style = format_style
        self.show_snippets = show_snippets

    def generate_report(self, data: ScanResult | Report) -> str:
        """
        Generate table report.

        Args:
            data: ScanResult or Report object

        Returns:
            Table string
        """
        if isinstance(data, ScanResult):
            return self._generate_scan_result_report(data)
        else:
            return self._generate_multi_skill_report(data)

    def _generate_scan_result_report(self, result: ScanResult) -> str:
        """Generate table report for a single skill scan."""
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append(f"Agent Skill Security Scan: {result.skill_name}")
        lines.append("=" * 80)
        lines.append("")

        # Summary table
        summary_data = [
            ["Skill", result.skill_name],
            ["Status", "[OK] SAFE" if result.is_safe else "[FAIL] ISSUES FOUND"],
            ["Max Severity", result.max_severity.value],
            ["Total Findings", len(result.findings)],
            ["Scan Duration", f"{result.scan_duration_seconds:.2f}s"],
        ]
        lines.append(tabulate(summary_data, tablefmt=self.format_style))
        lines.append("")

        # Findings by severity
        if result.findings:
            severity_data = [
                ["Critical", len(result.get_findings_by_severity(Severity.CRITICAL))],
                ["High", len(result.get_findings_by_severity(Severity.HIGH))],
                ["Medium", len(result.get_findings_by_severity(Severity.MEDIUM))],
                ["Low", len(result.get_findings_by_severity(Severity.LOW))],
                ["Info", len(result.get_findings_by_severity(Severity.INFO))],
            ]
            lines.append("Findings by Severity:")
            lines.append(tabulate(severity_data, headers=["Severity", "Count"], tablefmt=self.format_style))
            lines.append("")

            # Detailed findings table
            lines.append("Detailed Findings:")
            findings_data = []
            for finding in result.findings:
                location = finding.file_path or "N/A"
                if finding.line_number:
                    location += f":{finding.line_number}"

                findings_data.append(
                    [
                        finding.severity.value,
                        finding.category.value,
                        finding.title[:40] + "..." if len(finding.title) > 40 else finding.title,
                        location[:30] + "..." if len(location) > 30 else location,
                    ]
                )

            lines.append(
                tabulate(
                    findings_data, headers=["Severity", "Category", "Title", "Location"], tablefmt=self.format_style
                )
            )

            # Add code snippets if requested
            if self.show_snippets:
                lines.append("")
                lines.append("=" * 80)
                lines.append("CODE EVIDENCE")
                lines.append("=" * 80)
                lines.append("")

                for i, finding in enumerate(result.findings, 1):
                    lines.append(f"Finding #{i}: {finding.title}")
                    lines.append(f"  Location: {finding.file_path}:{finding.line_number or 'N/A'}")
                    lines.append(f"  Severity: {finding.severity.value}")
                    if finding.snippet:
                        lines.append(f"  Code: {finding.snippet}")
                    if finding.remediation:
                        lines.append(f"  Fix: {finding.remediation}")
                    lines.append("")
        else:
            lines.append("[OK] No security issues found!")

        lines.append("")
        return "\n".join(lines)

    def _generate_multi_skill_report(self, report: Report) -> str:
        """Generate table report for multiple skills."""
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("Agent Skills Security Scan Report")
        lines.append("=" * 80)
        lines.append("")

        # Summary table
        summary_data = [
            ["Total Skills Scanned", report.total_skills_scanned],
            ["Safe Skills", report.safe_count],
            ["Total Findings", report.total_findings],
            ["Critical", report.critical_count],
            ["High", report.high_count],
            ["Medium", report.medium_count],
            ["Low", report.low_count],
            ["Info", report.info_count],
        ]
        lines.append(tabulate(summary_data, tablefmt=self.format_style))
        lines.append("")

        # Skills overview table
        lines.append("Skills Overview:")
        skills_data = []
        for result in report.scan_results:
            skills_data.append(
                [
                    result.skill_name,
                    "[OK] SAFE" if result.is_safe else "[FAIL] ISSUES",
                    result.max_severity.value,
                    len(result.findings),
                    len(result.get_findings_by_severity(Severity.CRITICAL)),
                    len(result.get_findings_by_severity(Severity.HIGH)),
                ]
            )

        lines.append(
            tabulate(
                skills_data,
                headers=["Skill", "Status", "Max Severity", "Total", "Critical", "High"],
                tablefmt=self.format_style,
            )
        )
        lines.append("")

        return "\n".join(lines)

    def save_report(self, data: ScanResult | Report, output_path: str):
        """
        Save table report to file.

        Args:
            data: ScanResult or Report object
            output_path: Path to save file
        """
        report_table = self.generate_report(data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_table)
