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
Collect per-skill findings for target rules to support false-positive analysis.
Outputs JSON with skills ranked by hits for each target rule.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner

TARGET_RULES = {
    "UNREFERENCED_SCRIPT",
    "UNANALYZABLE_BINARY",
    "GLOB_HIDDEN_FILE_TARGETING",
    "COMPOUND_FETCH_EXECUTE",
    "FIND_EXEC_PATTERN",
    "YARA_embedded_shebang_in_binary",
}


def find_skills(root: Path) -> list[Path]:
    skills = []
    for skill_md in root.rglob("SKILL.md"):
        skills.append(skill_md.parent)
    return sorted(set(skills))


def main():
    corpus = Path(__file__).parent.parent / ".local_benchmark" / "corpus"
    if not corpus.exists():
        print(f"Corpus not found: {corpus}")
        sys.exit(1)

    skills = find_skills(corpus)
    max_skills = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    if max_skills > 0:
        skills = skills[:max_skills]

    print(f"Scanning {len(skills)} skills...")
    policy = ScanPolicy.from_preset("balanced")
    scanner = SkillScanner(policy=policy)

    # skill_path -> rule_id -> list of (file_path, line, snippet)
    skill_findings: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    total_by_rule: dict[str, int] = defaultdict(int)
    skills_with_rule: dict[str, set[str]] = defaultdict(set)

    for i, skill_dir in enumerate(skills):
        try:
            result = scanner.scan_skill(skill_dir)
            try:
                rel = str(skill_dir.relative_to(corpus))
            except ValueError:
                rel = str(skill_dir)
            for f in result.findings:
                if f.rule_id in TARGET_RULES:
                    skill_findings[rel][f.rule_id].append(
                        {
                            "file": f.file_path or "",
                            "line": getattr(f, "line", None) or f.metadata.get("line"),
                            "snippet": (f.metadata.get("snippet") or f.description or "")[:200],
                            "description": (f.description or "")[:300],
                        }
                    )
                    total_by_rule[f.rule_id] += 1
                    skills_with_rule[f.rule_id].add(rel)
        except Exception as e:
            pass
        if (i + 1) % 100 == 0:
            print(f"  ... {i + 1}/{len(skills)}")

    # Rank skills by total target-rule hits
    skill_totals = []
    for skill, rules in skill_findings.items():
        count = sum(len(v) for v in rules.values())
        if count > 0:
            skill_totals.append((skill, count, {r: len(v) for r, v in rules.items()}))

    skill_totals.sort(key=lambda x: -x[1])

    out = {
        "summary": {
            "skills_scanned": len(skills),
            "skills_with_target_findings": len(skill_totals),
            "total_findings_by_rule": dict(total_by_rule),
            "skills_with_each_rule": {r: len(s) for r, s in skills_with_rule.items()},
        },
        "top_skills": skill_totals[:50],
        "sample_findings": {},
    }

    # Include first 3 findings per rule from top 15 skills for manual review
    for skill, _count, rule_counts in skill_totals[:15]:
        for rule in rule_counts:
            key = f"{skill}::{rule}"
            findings = skill_findings[skill][rule][:3]
            out["sample_findings"][key] = findings

    out_path = Path(__file__).parent.parent / ".local_benchmark" / "fp_analysis_collect.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"Wrote {out_path}")
    print("\nTop 20 skills by target-rule hits:")
    for skill, count, rules in skill_totals[:20]:
        print(f"  {count:4d}  {skill}")
        for r, c in sorted(rules.items(), key=lambda x: -x[1]):
            print(f"         {r}: {c}")


if __name__ == "__main__":
    main()
