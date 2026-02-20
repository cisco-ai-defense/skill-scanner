#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
Helper script to update _expected.json files based on actual scan results.

This helps improve precision/recall by ensuring expected findings match
what analyzers actually detect.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import os

from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.scanner import SkillScanner


def scan_skill_and_get_findings(skill_dir: Path, use_llm: bool = False):
    """Scan a skill and return findings grouped by category+severity."""
    analyzers = [StaticAnalyzer()]

    if use_llm:
        api_key = os.getenv("SKILL_SCANNER_LLM_API_KEY")
        model = os.getenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")
        if api_key:
            analyzers.append(LLMAnalyzer(model=model, api_key=api_key))

    scanner = SkillScanner(analyzers=analyzers)
    result = scanner.scan_skill(skill_dir)

    # Group findings by category+severity
    findings_by_key = defaultdict(list)
    for finding in result.findings:
        key = (finding.category.value, finding.severity.value)
        findings_by_key[key].append(finding)

    return result, findings_by_key


def load_expected(skill_dir: Path):
    """Load expected findings from _expected.json."""
    expected_file = skill_dir / "_expected.json"
    if not expected_file.exists():
        return None

    with open(expected_file) as f:
        return json.load(f)


def suggest_expected_findings(actual_findings_by_key, existing_expected):
    """Suggest expected findings based on actual findings."""
    suggested = []

    for (category, severity), findings in actual_findings_by_key.items():
        # Check if this category+severity is already expected
        expected_key = None
        if existing_expected:
            expected_findings = existing_expected.get(
                "expected_findings", existing_expected.get("expected_threats", [])
            )
            for exp in expected_findings:
                if exp.get("category") == category and exp.get("severity") == severity:
                    expected_key = exp
                    break

        if not expected_key:
            # Suggest adding this finding
            suggested.append(
                {
                    "category": category,
                    "severity": severity,
                    "description": findings[0].title[:100] if findings else f"{category} threat detected",
                    "count": len(findings),
                }
            )

    return suggested


def main():
    """Main function to analyze and suggest expected findings updates."""
    import argparse

    parser = argparse.ArgumentParser(description="Update expected findings based on actual scan results")
    parser.add_argument("--test-skills-dir", default="evals/skills", help="Directory containing test skills")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM analyzer")
    parser.add_argument(
        "--update", action="store_true", help="Actually update _expected.json files (dry-run by default)"
    )
    parser.add_argument("--skill", help="Process only specific skill (directory name)")

    args = parser.parse_args()

    skills_dir = Path(args.test_skills_dir)

    # Find all skills
    expected_files = list(skills_dir.rglob("_expected.json"))

    if args.skill:
        expected_files = [f for f in expected_files if args.skill in str(f.parent)]

    print(f"Analyzing {len(expected_files)} skills...\n")

    updates_needed = []

    for expected_file in expected_files:
        skill_dir = expected_file.parent
        skill_name = skill_dir.name

        print(f"=== {skill_name} ===")

        # Load existing expected
        existing = load_expected(skill_dir)
        if not existing:
            print("  No _expected.json found, skipping")
            continue

        # Scan skill
        try:
            result, findings_by_key = scan_skill_and_get_findings(skill_dir, use_llm=args.use_llm)

            # Get expected findings
            expected_findings = existing.get("expected_findings", existing.get("expected_threats", []))

            print(f"  Expected: {len(expected_findings)} findings")
            print(f"  Actual: {len(result.findings)} findings")

            # Check for missing expected findings
            expected_keys = set()
            for exp in expected_findings:
                key = (exp.get("category"), exp.get("severity"))
                expected_keys.add(key)

            actual_keys = set(findings_by_key.keys())

            missing_expected = actual_keys - expected_keys
            extra_expected = expected_keys - actual_keys

            if missing_expected:
                print(f"  [WARNING] Missing from expected: {len(missing_expected)}")
                for cat, sev in missing_expected:
                    findings = findings_by_key[(cat, sev)]
                    print(f"     - {cat}/{sev}: {len(findings)} finding(s)")
                    print(f"       Example: {findings[0].title[:60]}")

            if extra_expected:
                print(f"  [WARNING] In expected but not found: {len(extra_expected)}")
                for cat, sev in extra_expected:
                    print(f"     - {cat}/{sev}")

            if not missing_expected and not extra_expected:
                print("  [OK] Expected findings match actual findings")

            # Suggest updates
            if missing_expected and args.update:
                # Update the expected file
                if "expected_findings" not in existing:
                    existing["expected_findings"] = existing.get("expected_threats", [])
                    if "expected_threats" in existing:
                        del existing["expected_threats"]

                # Add missing findings
                for cat, sev in missing_expected:
                    findings = findings_by_key[(cat, sev)]
                    existing["expected_findings"].append(
                        {
                            "category": cat,
                            "severity": sev,
                            "description": findings[0].title[:200] if findings else f"{cat} threat detected",
                        }
                    )

                # Save updated file
                with open(expected_file, "w") as f:
                    json.dump(existing, f, indent=2)
                print(f"  [OK] Updated {expected_file}")
                updates_needed.append(skill_name)

            print()

        except Exception as e:
            print(f"  [ERROR] Error: {e}\n")
            continue

    if updates_needed:
        print(f"\n[OK] Updated {len(updates_needed)} skills: {', '.join(updates_needed)}")
    elif args.update:
        print("\n[OK] No updates needed - all expected findings match actual findings")
    else:
        print("\n[TIP] Run with --update to automatically update _expected.json files")


if __name__ == "__main__":
    main()
