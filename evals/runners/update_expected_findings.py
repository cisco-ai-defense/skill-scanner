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

"""Create scanner-observation reports for ground-truth attesters.

This tool deliberately cannot update ``_expected.json`` files. Scanner output
is useful diagnostic evidence, but making the system under test its own label
source would make the evaluation circular. Ground truth must instead carry a
scanner-independent public, Ollama, agent, or human attestation with bound
provenance and label-evidence hashes.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add repository root to path when invoked as a script.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.runners.finding_matcher import match_findings, validate_expectation_document
from skill_scanner.core.analyzer_factory import build_analyzers
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner


def _value(value: Any) -> Any:
    return getattr(value, "value", value)


def _finding_observation(finding: Any) -> dict[str, Any]:
    """Return canonical, non-labeling scanner evidence for one finding."""

    return {
        "rule_id": finding.rule_id,
        "category": _value(finding.category),
        "severity": _value(finding.severity),
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "evidence_id": finding.id,
        "analyzer": finding.analyzer,
        "title": finding.title,
    }


def _build_scanner(use_llm: bool) -> SkillScanner:
    policy = ScanPolicy.default()
    return SkillScanner(analyzers=build_analyzers(policy, use_llm=use_llm), policy=policy)


def observe_fixture(scanner: SkillScanner, expected_file: Path) -> dict[str, Any]:
    """Validate and scan one fixture without deriving or changing its labels."""

    fixture_dir = expected_file.parent
    observation: dict[str, Any] = {
        "fixture": fixture_dir.as_posix(),
        "expectation_file": expected_file.as_posix(),
        "attestation_status": "scanner_observation_only_not_label_evidence",
    }

    try:
        with expected_file.open(encoding="utf-8") as stream:
            document = json.load(stream)
        validated = validate_expectation_document(document, fixture_dir=fixture_dir)
        observation.update(
            {
                "skill_name": validated.skill_name,
                "expectation_schema_version": validated.schema_version,
                "evaluation_quality": validated.evaluation_quality,
                "expected_verdict": "safe" if validated.expected_safe else "unsafe",
                "expected_finding_count": len(validated.expected_findings),
            }
        )

        result = scanner.scan_skill(fixture_dir)
        analyzer_failures = getattr(result, "analyzers_failed", None) or []
        if analyzer_failures:
            raise RuntimeError(f"scanner reported analyzer failure(s): {analyzer_failures}")

        match = match_findings(validated.expected_findings, result.findings)
        observations = [_finding_observation(finding) for finding in result.findings]
        observation["scanner_observation"] = {
            "is_safe": result.is_safe,
            "max_severity": result.max_severity.value,
            "findings": observations,
            "matched_pairs": [list(pair) for pair in match.matched_pairs],
            "unmatched_expected_indices": list(match.unmatched_expected_indices),
            "unmatched_scanner_indices": list(match.unmatched_actual_indices),
        }
    except Exception as error:
        observation["error"] = str(error)

    return observation


def build_observation_report(
    test_skills_dir: Path,
    *,
    use_llm: bool = False,
    skill: str | None = None,
    scanner: SkillScanner | None = None,
) -> dict[str, Any]:
    """Build a reviewer report for every discovered expectation file."""

    expected_files = sorted(test_skills_dir.rglob("_expected.json"))
    if skill is not None:
        expected_files = [path for path in expected_files if path.parent.name == skill]

    active_scanner = scanner or _build_scanner(use_llm)
    observations = [observe_fixture(active_scanner, expected_file) for expected_file in expected_files]
    return {
        "schema_version": 1,
        "report_kind": "scanner_observation_only",
        "generated_at": datetime.now(UTC).isoformat(),
        "ground_truth_mutated": False,
        "attestation_policy": {
            "accepted_label_sources": [
                "agent_labeled",
                "human_reviewed",
                "independent_ollama",
                "public_labeled",
            ],
            "required_hashes": ["label_evidence_sha256", "label_provenance_sha256"],
            "scanner_output_is_ground_truth": False,
            "instructions": (
                "Attest the label from scanner-independent evidence; scanner findings are observations, not labels."
            ),
        },
        "fixture_count": len(observations),
        "error_count": sum("error" in observation for observation in observations),
        "observations": observations,
    }


def main() -> int:
    """Write an attester-only scanner observation report."""

    import argparse

    parser = argparse.ArgumentParser(description="Create an attester-only scanner observation report")
    parser.add_argument("--test-skills-dir", default="evals/skills", help="Directory containing evaluation skills")
    parser.add_argument("--output", required=True, help="Path for the observation report (never _expected.json)")
    parser.add_argument("--use-llm", action="store_true", help="Include the configured LLM analyzer")
    parser.add_argument("--skill", help="Process only an exact skill directory name")
    args = parser.parse_args()

    skills_dir = Path(args.test_skills_dir)
    if not skills_dir.is_dir():
        parser.error(f"evaluation directory does not exist: {skills_dir}")

    output = Path(args.output)
    if output.name == "_expected.json":
        parser.error("refusing to write an evaluation ground-truth file")
    if output.resolve().is_relative_to(skills_dir.resolve()):
        parser.error("observation reports must be written outside the evaluation fixture tree")

    report = build_observation_report(
        skills_dir,
        use_llm=args.use_llm,
        skill=args.skill,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")

    print(f"Wrote {report['fixture_count']} scanner observation(s) to {output}")
    if report["error_count"]:
        print(f"Observation report contains {report['error_count']} error(s)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
