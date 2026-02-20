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
Programmatic usage example - using Skill Scanner as a Python library.

This example demonstrates:
1. Creating custom scanner configurations
2. Accessing detailed scan results
3. Processing findings programmatically
4. Custom result filtering and analysis
"""

from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory


def analyze_findings(findings):
    """Analyze findings and group by category."""
    by_category = {}
    by_severity = {}

    for finding in findings:
        # Group by category
        category = finding.category.value
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(finding)

        # Group by severity
        severity = finding.severity.value
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    return by_category, by_severity


def main():
    # Example skill path (adjust to your test skill)
    skill_path = Path("evals/test_skills/safe/simple-formatter")

    if not skill_path.exists():
        print(f"Error: Skill not found: {skill_path}")
        print("Please update the skill_path variable to point to a valid skill.")
        return 1

    # Create scanner with multiple analyzers
    analyzers = [StaticAnalyzer(), BehavioralAnalyzer(use_static_analysis=True)]

    scanner = SkillScanner(analyzers=analyzers)

    print(f"Scanning skill: {skill_path}")
    print(f"Using analyzers: {', '.join(scanner.list_analyzers())}\n")

    # Scan the skill
    result = scanner.scan_skill(skill_path)

    # Access result properties
    print(f"{'=' * 60}")
    print("Scan Results")
    print(f"{'=' * 60}")
    print(f"Skill Name: {result.skill_name}")
    print(f"Is Safe: {result.is_safe}")
    print(f"Max Severity: {result.max_severity.value}")
    print(f"Total Findings: {len(result.findings)}")
    print(f"Scan Duration: {result.scan_duration_seconds:.2f}s")
    print(f"Analyzers Used: {', '.join(result.analyzers_used)}")

    # Analyze findings
    if result.findings:
        by_category, by_severity = analyze_findings(result.findings)

        print(f"\n{'=' * 60}")
        print("Findings by Category:")
        print(f"{'=' * 60}")
        for category, findings in by_category.items():
            print(f"  {category}: {len(findings)}")

        print(f"\n{'=' * 60}")
        print("Findings by Severity:")
        print(f"{'=' * 60}")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
            if severity in by_severity:
                print(f"  {severity}: {len(by_severity[severity])}")

        # Show critical/high findings
        critical_high = [f for f in result.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]

        if critical_high:
            print(f"\n{'=' * 60}")
            print("Critical/High Findings:")
            print(f"{'=' * 60}")
            for finding in critical_high:
                print(f"\n  [{finding.severity.value}] {finding.title}")
                print(f"    Category: {finding.category.value}")
                if finding.description:
                    print(f"    Description: {finding.description[:150]}...")
                if finding.location:
                    print(f"    Location: {finding.location}")

    # Check specific threat categories
    prompt_injection = [f for f in result.findings if f.category == ThreatCategory.PROMPT_INJECTION]

    if prompt_injection:
        print(f"\n[WARNING] Found {len(prompt_injection)} prompt injection findings!")

    return 0 if result.is_safe else 1


if __name__ == "__main__":
    exit(main())
