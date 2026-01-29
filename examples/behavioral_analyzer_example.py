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
Behavioral Analyzer example - detecting multi-file exfiltration chains.

This example demonstrates:
1. Using behavioral analyzer for dataflow analysis
2. Detecting cross-file data flows
3. Identifying taint sources and sinks

Usage:
    python behavioral_analyzer_example.py <skill_directory>
"""

import argparse
from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Behavioral Analyzer example")
    parser.add_argument("skill_directory", type=str, help="Path to skill directory")

    args = parser.parse_args()

    skill_path = Path(args.skill_directory)
    if not skill_path.exists():
        print(f"Error: Skill directory not found: {skill_path}")
        return 1

    print(f"{'=' * 60}")
    print("Behavioral Analyzer Example")
    print(f"{'=' * 60}")
    print(f"Skill: {skill_path}")
    print()

    # Scan with static analyzer only
    print("Step 1: Scanning with Static Analyzer...")
    static_scanner = SkillScanner(analyzers=[StaticAnalyzer()])
    static_result = static_scanner.scan_skill(skill_path)

    print(f"  Findings: {len(static_result.findings)}")
    print(f"  Max Severity: {static_result.max_severity.value}")
    print()

    # Scan with behavioral analyzer
    print("Step 2: Scanning with Behavioral Analyzer (dataflow analysis)...")
    behavioral_analyzer = BehavioralAnalyzer(use_static_analysis=True)
    behavioral_scanner = SkillScanner(analyzers=[behavioral_analyzer])
    behavioral_result = behavioral_scanner.scan_skill(skill_path)

    print(f"  Findings: {len(behavioral_result.findings)}")
    print(f"  Max Severity: {behavioral_result.max_severity.value}")
    print()

    # Scan with both
    print("Step 3: Scanning with Static + Behavioral Analyzers...")
    combined_scanner = SkillScanner(analyzers=[StaticAnalyzer(), BehavioralAnalyzer(use_static_analysis=True)])
    combined_result = combined_scanner.scan_skill(skill_path)

    print(f"  Findings: {len(combined_result.findings)}")
    print(f"  Max Severity: {combined_result.max_severity.value}")
    print()

    # Show behavioral-specific findings
    behavioral_findings = [f for f in combined_result.findings if "behavioral_analyzer" in f.analyzers]

    if behavioral_findings:
        print(f"{'=' * 60}")
        print(f"Behavioral Analyzer Findings ({len(behavioral_findings)}):")
        print(f"{'=' * 60}")
        for finding in behavioral_findings:
            print(f"\n  [{finding.severity.value}] {finding.title}")
            print(f"    Category: {finding.category.value}")
            if finding.description:
                print(f"    Description: {finding.description[:200]}...")
            if finding.location:
                print(f"    Location: {finding.location}")
    else:
        print("No behavioral-specific findings detected.")

    # Compare results
    print(f"\n{'=' * 60}")
    print("Comparison")
    print(f"{'=' * 60}")
    print(f"Static Analyzer:    {len(static_result.findings)} findings")
    print(f"Behavioral Analyzer: {len(behavioral_result.findings)} findings")
    print(f"Combined:          {len(combined_result.findings)} findings")

    if behavioral_findings:
        print(f"\n[WARNING] Behavioral analyzer detected {len(behavioral_findings)} additional findings")
        print("   that static analysis missed (multi-file flows, dataflow patterns)")

    return 0 if combined_result.is_safe else 1


if __name__ == "__main__":
    exit(main())
