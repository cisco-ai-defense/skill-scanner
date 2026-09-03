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

from __future__ import annotations

import json
from types import SimpleNamespace

from evals.runners.benchmark_runner import SkillBenchmarkRunner
from evals.runners.eval_runner import EvaluationRunner, _evaluation_provenance
from evals.runners.finding_matcher import match_findings


def _actual(
    rule_id: str,
    *,
    category: str = "command_injection",
    severity: str = "HIGH",
    file_path: str = "scripts/run.py",
    line_number: int = 7,
    evidence_id: str | None = None,
    analyzer: str = "static",
) -> dict:
    return {
        "id": evidence_id or f"{rule_id}:{line_number}",
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "file_path": file_path,
        "line_number": line_number,
        "analyzer": analyzer,
    }


def test_one_actual_cannot_satisfy_duplicate_expectations():
    expected = [
        {"category": "command_injection", "severity": "HIGH"},
        {"category": "command_injection", "severity": "HIGH"},
    ]

    result = match_findings(expected, [_actual("ONE")])

    assert result.matched_count == 1
    assert len(result.unmatched_expected_indices) == 1
    assert result.unmatched_actual_indices == ()


def test_specific_expectation_is_not_starved_by_legacy_wildcard():
    expected = [
        {"category": "command_injection", "severity": "HIGH"},
        {"rule_id": "EXACT", "category": "command_injection", "severity": "HIGH"},
    ]
    actual = [_actual("EXACT"), _actual("OTHER")]

    result = match_findings(expected, actual)

    assert result.matched_count == 2
    assert result.unmatched_expected_indices == ()
    assert result.unmatched_actual_indices == ()
    assert (1, 0) in result.matched_pairs


def test_complete_finding_identity_is_enforced():
    expected = [
        {
            "rule_id": "RULE",
            "category": "command_injection",
            "severity": "HIGH",
            "file_path": "./scripts/run.py",
            "line_number": 7,
            "evidence_id": "evidence-1",
            "analyzer": "STATIC",
        }
    ]

    match = match_findings(expected, [_actual("RULE", evidence_id="evidence-1")])
    mismatch = match_findings(expected, [_actual("RULE", line_number=8, evidence_id="evidence-1")])

    assert match.matched_count == 1
    assert mismatch.matched_count == 0


def test_unmatched_actual_is_false_positive_even_for_unsafe_skill():
    runner = object.__new__(EvaluationRunner)
    expected = {
        "expected_safe": False,
        "expected_findings": [{"rule_id": "EXPECTED", "category": "command_injection", "severity": "HIGH"}],
    }
    scan_result = SimpleNamespace(
        skill_name="unsafe",
        is_safe=False,
        findings=[_actual("EXPECTED"), _actual("EXTRA")],
    )

    result = runner._compare_results(expected, scan_result)

    assert result.matched_findings == 1
    assert result.false_positives == 1
    assert result.false_negatives == 0
    assert result.correct is False


def test_scan_error_remains_in_evaluation_denominator(tmp_path):
    skill_dir = tmp_path / "broken-skill"
    skill_dir.mkdir()
    (skill_dir / "_expected.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evaluation_quality": "legacy_degraded",
                "skill_name": "broken-skill",
                "expected_safe": False,
                "expected_findings": [{"rule_id": "EXPECTED", "category": "command_injection", "severity": "HIGH"}],
            }
        ),
        encoding="utf-8",
    )

    class BrokenScanner:
        def scan_skill(self, _skill_dir):
            raise RuntimeError("scanner failed")

    runner = object.__new__(EvaluationRunner)
    runner.test_skills_dir = tmp_path
    runner.scanner = BrokenScanner()
    runner.use_meta = False
    runner.meta_analyzer = None
    runner.evaluation_provenance = _evaluation_provenance(None, None)

    results = runner.run_evaluation()

    assert results["total_skills"] == 1
    assert results["metrics"]["errors"] == 1
    assert results["metrics"]["accuracy"] == 0
    assert results["metrics"]["false_negatives"] == 1


def test_benchmark_error_remains_in_denominator():
    runner = object.__new__(SkillBenchmarkRunner)
    runner.results = [
        {
            "expected_safe": True,
            "actual_safe": True,
            "matched_threats": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "correct": True,
        },
        {
            "expected_safe": False,
            "actual_safe": None,
            "matched_threats": 0,
            "false_positives": 0,
            "false_negatives": 1,
            "correct": False,
            "error": "scanner failed",
        },
    ]

    result = runner._calculate_benchmark_metrics(1.0)

    assert result.total_skills_evaluated == 2
    assert result.evaluation_errors == 1
    assert result.overall_accuracy == 0.5
    assert result.finding_false_negatives == 1
