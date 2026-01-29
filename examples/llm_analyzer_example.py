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
LLM Analyzer example - using semantic analysis for threat detection.

This example demonstrates:
1. Configuring LLM analyzer with different providers
2. Using LLM for intent verification
3. Comparing LLM vs static analysis results

Prerequisites:
    export SKILL_SCANNER_LLM_API_KEY="your_key"
    export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"  # or gpt-4o
    pip install cisco-ai-skill-scanner[llm]

Usage:
    python llm_analyzer_example.py <skill_directory>
"""

import argparse
import os
from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.static import StaticAnalyzer

try:
    from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer, LLMProvider

    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    print("Error: LLM analyzer not available. Install with: pip install cisco-ai-skill-scanner[llm]")


def main():
    if not LLM_AVAILABLE:
        return 1

    parser = argparse.ArgumentParser(description="LLM Analyzer example")
    parser.add_argument("skill_directory", type=str, help="Path to skill directory")

    args = parser.parse_args()

    skill_path = Path(args.skill_directory)
    if not skill_path.exists():
        print(f"Error: Skill directory not found: {skill_path}")
        return 1

    # Check for API key
    api_key = os.getenv("SKILL_SCANNER_LLM_API_KEY")
    if not api_key:
        print("Error: SKILL_SCANNER_LLM_API_KEY environment variable not set")
        return 1

    model = os.getenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")

    print(f"{'=' * 60}")
    print("LLM Analyzer Example")
    print(f"{'=' * 60}")
    print(f"Skill: {skill_path}")
    print(f"Model: {model}")
    print()

    # Scan with static analyzer only
    print("Step 1: Scanning with Static Analyzer only...")
    static_scanner = SkillScanner(analyzers=[StaticAnalyzer()])
    static_result = static_scanner.scan_skill(skill_path)

    print(f"  Findings: {len(static_result.findings)}")
    print(f"  Max Severity: {static_result.max_severity.value}")
    print()

    # Scan with LLM analyzer
    print("Step 2: Scanning with LLM Analyzer...")
    llm_analyzer = LLMAnalyzer(model=model, api_key=api_key)
    llm_scanner = SkillScanner(analyzers=[llm_analyzer])
    llm_result = llm_scanner.scan_skill(skill_path)

    print(f"  Findings: {len(llm_result.findings)}")
    print(f"  Max Severity: {llm_result.max_severity.value}")
    print()

    # Scan with both
    print("Step 3: Scanning with Static + LLM Analyzers...")
    combined_scanner = SkillScanner(analyzers=[StaticAnalyzer(), llm_analyzer])
    combined_result = combined_scanner.scan_skill(skill_path)

    print(f"  Findings: {len(combined_result.findings)}")
    print(f"  Max Severity: {combined_result.max_severity.value}")
    print()

    # Compare results
    print(f"{'=' * 60}")
    print("Comparison")
    print(f"{'=' * 60}")
    print(f"Static Analyzer:    {len(static_result.findings)} findings, {static_result.max_severity.value}")
    print(f"LLM Analyzer:      {len(llm_result.findings)} findings, {llm_result.max_severity.value}")
    print(f"Combined:          {len(combined_result.findings)} findings, {combined_result.max_severity.value}")
    print()

    # Show LLM-specific findings
    llm_findings = [f for f in combined_result.findings if "llm_analyzer" in f.analyzers]
    if llm_findings:
        print(f"LLM-Specific Findings ({len(llm_findings)}):")
        for finding in llm_findings:
            print(f"  [{finding.severity.value}] {finding.title}")
            if finding.description:
                print(f"    {finding.description[:150]}...")
            print()

    return 0 if combined_result.is_safe else 1


if __name__ == "__main__":
    exit(main())
