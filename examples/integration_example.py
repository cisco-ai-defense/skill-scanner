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
CI/CD Integration example - using Skill Scanner in automated pipelines.

This example demonstrates:
1. Exit codes for CI/CD integration
2. Filtering by severity for gating
3. Generating reports for artifacts
4. Batch scanning for multiple skills

Usage:
    # In CI/CD pipeline
    python integration_example.py <skills_directory> --fail-on-critical --output=report.json
"""

import argparse
import json
import sys
from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.reporters.json_reporter import JSONReporter


def main():
    parser = argparse.ArgumentParser(description="CI/CD Integration example")
    parser.add_argument("skills_directory", type=str, help="Path to skills directory")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan recursively")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with error if CRITICAL findings")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with error if HIGH findings")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with error if any findings")
    parser.add_argument("--output", type=str, help="Save report to file")
    parser.add_argument("--use-behavioral", action="store_true", help="Enable behavioral analyzer")

    args = parser.parse_args()

    skills_dir = Path(args.skills_directory)
    if not skills_dir.exists():
        print(f"Error: Directory not found: {skills_dir}", file=sys.stderr)
        return 1

    # Create scanner
    analyzers = [StaticAnalyzer()]
    if args.use_behavioral:
        analyzers.append(BehavioralAnalyzer(use_static_analysis=True))

    scanner = SkillScanner(analyzers=analyzers)

    print(f"Scanning skills in: {skills_dir}")
    print(f"Recursive: {args.recursive}")

    # Scan directory
    try:
        report = scanner.scan_directory(skills_dir, recursive=args.recursive)

        # Print summary
        print(f"\n{'=' * 60}")
        print("Scan Summary")
        print(f"{'=' * 60}")
        unsafe_count = report.total_skills_scanned - report.safe_count
        print(f"Total Skills: {report.total_skills_scanned}")
        print(f"Safe: {report.safe_count}")
        print(f"Unsafe: {unsafe_count}")
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

        # Save report
        if args.output:
            reporter = JSONReporter()
            json_output = reporter.generate_report(report)
            with open(args.output, "w") as f:
                f.write(json_output)
            print(f"\n[OK] Report saved to {args.output}")

        # Check exit conditions
        exit_code = 0

        if args.fail_on_findings and report.total_findings > 0:
            print(f"\n[FAILED] Found {report.total_findings} findings")
            exit_code = 1

        if args.fail_on_high and report.high_count > 0:
            print(f"\n[FAILED] Found {report.high_count} HIGH severity findings")
            exit_code = 1

        if args.fail_on_critical and report.critical_count > 0:
            print(f"\n[FAILED] Found {report.critical_count} CRITICAL severity findings")
            exit_code = 1

        if exit_code == 0:
            print("\n[OK] All checks passed!")

        return exit_code

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
