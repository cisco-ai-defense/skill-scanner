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
Advanced scanning example with multiple analyzers and custom configuration.

This example demonstrates:
1. Using multiple analyzers together
2. Custom analyzer configuration
3. Filtering results by severity
4. Saving results to different formats
5. Error handling

Usage:
    python advanced_scanning.py <skill_directory> [--use-llm] [--use-behavioral] [--use-virustotal] [--use-aidefense]
"""

import argparse
import json
from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.reporters.json_reporter import JSONReporter
from skill_scanner.core.reporters.markdown_reporter import MarkdownReporter

# Optional analyzers
try:
    from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

try:
    from skill_scanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False

try:
    from skill_scanner.core.analyzers.aidefense_analyzer import AIDefenseAnalyzer

    AIDEFENSE_AVAILABLE = True
except ImportError:
    AIDEFENSE_AVAILABLE = False


def create_scanner(use_llm=False, use_behavioral=False, use_virustotal=False, use_aidefense=False):
    """Create scanner with configured analyzers."""
    analyzers = [StaticAnalyzer()]

    if use_behavioral:
        analyzers.append(BehavioralAnalyzer(use_static_analysis=True))

    if use_llm and LLM_AVAILABLE:
        analyzers.append(LLMAnalyzer())

    if use_virustotal and VT_AVAILABLE:
        analyzers.append(VirusTotalAnalyzer())

    if use_aidefense and AIDEFENSE_AVAILABLE:
        analyzers.append(AIDefenseAnalyzer())

    return SkillScanner(analyzers=analyzers)


def filter_by_severity(findings, min_severity="MEDIUM"):
    """Filter findings by minimum severity."""
    severity_order = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_level = severity_order.get(min_severity.upper(), 2)

    return [f for f in findings if severity_order.get(f.severity.value, 0) >= min_level]


def main():
    parser = argparse.ArgumentParser(description="Advanced skill scanning example")
    parser.add_argument("skill_directory", type=str, help="Path to skill directory")
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM analyzer")
    parser.add_argument("--use-behavioral", action="store_true", help="Enable behavioral analyzer")
    parser.add_argument("--use-virustotal", action="store_true", help="Enable VirusTotal analyzer")
    parser.add_argument("--use-aidefense", action="store_true", help="Enable AI Defense analyzer")
    parser.add_argument("--min-severity", default="MEDIUM", help="Minimum severity to report")
    parser.add_argument("--output-json", type=str, help="Save results as JSON")
    parser.add_argument("--output-markdown", type=str, help="Save results as Markdown")

    args = parser.parse_args()

    skill_path = Path(args.skill_directory)
    if not skill_path.exists():
        print(f"Error: Skill directory not found: {skill_path}")
        return 1

    # Create scanner
    scanner = create_scanner(
        use_llm=args.use_llm,
        use_behavioral=args.use_behavioral,
        use_virustotal=args.use_virustotal,
        use_aidefense=args.use_aidefense,
    )

    print(f"Scanning skill: {skill_path}")
    print(f"Analyzers: {', '.join(scanner.list_analyzers())}")

    # Scan skill
    try:
        result = scanner.scan_skill(skill_path)

        # Filter findings
        filtered_findings = filter_by_severity(result.findings, args.min_severity)

        # Print summary
        print(f"\n{'=' * 60}")
        print(f"Scan Results: {result.skill_name}")
        print(f"{'=' * 60}")
        print(f"Status: {'[SAFE]' if result.is_safe else '[UNSAFE]'}")
        print(f"Max Severity: {result.max_severity.value}")
        print(f"Total Findings: {len(result.findings)}")
        print(f"Filtered Findings (min {args.min_severity}): {len(filtered_findings)}")
        print(f"Scan Duration: {result.scan_duration_seconds:.2f}s")

        if filtered_findings:
            print("\nFindings:")
            for finding in filtered_findings:
                print(f"  [{finding.severity.value}] {finding.title}")
                print(f"    Category: {finding.category.value}")
                if finding.description:
                    print(f"    Description: {finding.description[:100]}...")

        # Save outputs
        if args.output_json:
            reporter = JSONReporter()
            json_output = reporter.generate(result)
            with open(args.output_json, "w") as f:
                json.dump(json.loads(json_output), f, indent=2)
            print(f"\n[OK] Results saved to {args.output_json}")

        if args.output_markdown:
            reporter = MarkdownReporter()
            markdown_output = reporter.generate(result)
            with open(args.output_markdown, "w") as f:
                f.write(markdown_output)
            print(f"[OK] Results saved to {args.output_markdown}")

        return 0 if result.is_safe else 1

    except Exception as e:
        print(f"Error scanning skill: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
