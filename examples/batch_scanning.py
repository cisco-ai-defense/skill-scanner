#!/usr/bin/env python3
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
Batch scanning example - scan multiple skills in a directory.

This example demonstrates:
1. Scanning multiple skills recursively
2. Aggregating results
3. Generating summary reports
4. Filtering by severity

Usage:
    python batch_scanning.py <skills_directory> [--recursive] [--use-behavioral] [--output=FILE]
"""

import argparse
from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.reporters.json_reporter import JSONReporter


def main():
    parser = argparse.ArgumentParser(description="Batch scan multiple skills")
    parser.add_argument("skills_directory", type=str, help="Path to directory containing skills")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan recursively")
    parser.add_argument("--use-behavioral", action="store_true", help="Enable behavioral analyzer")
    parser.add_argument("--output", type=str, help="Save report to file (JSON)")

    args = parser.parse_args()

    skills_dir = Path(args.skills_directory)
    if not skills_dir.exists():
        print(f"Error: Directory not found: {skills_dir}")
        return 1

    # Create scanner
    analyzers = [StaticAnalyzer()]
    if args.use_behavioral:
        analyzers.append(BehavioralAnalyzer(use_static_analysis=True))

    scanner = SkillScanner(analyzers=analyzers)

    print(f"Scanning skills in: {skills_dir}")
    print(f"Recursive: {args.recursive}")
    print(f"Analyzers: {', '.join(scanner.list_analyzers())}\n")

    # Scan directory
    try:
        report = scanner.scan_directory(skills_dir, recursive=args.recursive)

        # Print summary
        print(f"{'=' * 60}")
        print("Batch Scan Report")
        print(f"{'=' * 60}")
        print(f"Total Skills Scanned: {report.total_skills_scanned}")
        print(f"Safe Skills: {report.safe_count}")
        print(f"Unsafe Skills: {report.total_skills_scanned - report.safe_count}")
        print(f"Total Findings: {report.total_findings}")
        print("\nSeverity Breakdown:")
        if report.critical_count > 0:
            print(f"  CRITICAL: {report.critical_count}")
        if report.high_count > 0:
            print(f"  HIGH: {report.high_count}")
        if report.medium_count > 0:
            print(f"  MEDIUM: {report.medium_count}")
        if report.low_count > 0:
            print(f"  LOW: {report.low_count}")
        if report.info_count > 0:
            print(f"  INFO: {report.info_count}")

        # Print per-skill results
        print(f"\n{'=' * 60}")
        print("Per-Skill Results:")
        print(f"{'=' * 60}")
        for result in report.scan_results:
            status = "[SAFE]" if result.is_safe else "[UNSAFE]"
            print(f"{status} | {result.skill_name}")
            print(f"    Max Severity: {result.max_severity.value}")
            print(f"    Findings: {len(result.findings)}")
            if result.findings:
                for finding in result.findings[:3]:  # Show first 3
                    print(f"      - [{finding.severity.value}] {finding.title}")
                if len(result.findings) > 3:
                    print(f"      ... and {len(result.findings) - 3} more")
            print()

        # Save report
        if args.output:
            reporter = JSONReporter()
            json_output = reporter.generate_report(report)
            with open(args.output, "w") as f:
                f.write(json_output)
            print(f"[OK] Report saved to {args.output}")

        unsafe_count = report.total_skills_scanned - report.safe_count
        return 0 if unsafe_count == 0 else 1

    except Exception as e:
        print(f"Error scanning directory: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
