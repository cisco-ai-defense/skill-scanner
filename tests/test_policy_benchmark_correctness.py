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

"""Correctness tests for the policy benchmark evaluation path."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from evals.runners.policy_benchmark import run_eval_benchmark


def _expected(*, name: str, safe: bool, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evaluation_quality": "legacy_degraded",
        "skill_name": name,
        "expected_safe": safe,
        "expected_findings": findings or [],
    }


def _write_case(
    root: Path,
    name: str,
    expectation: dict[str, Any] | str,
    *,
    include_skill: bool = True,
) -> Path:
    case_dir = root / name
    case_dir.mkdir()
    if include_skill:
        (case_dir / "SKILL.md").write_text(f"# {name}\n", encoding="utf-8")
    encoded = expectation if isinstance(expectation, str) else json.dumps(expectation)
    (case_dir / "_expected.json").write_text(encoded, encoding="utf-8")
    return case_dir


def _finding(rule_id: str) -> dict[str, Any]:
    return {
        "id": "evidence-1",
        "rule_id": rule_id,
        "category": "command_injection",
        "severity": "HIGH",
        "file_path": "SKILL.md",
        "line_number": 4,
        "analyzer": "static",
    }


def _expected_finding(rule_id: str) -> dict[str, Any]:
    finding = _finding(rule_id)
    finding["evidence_id"] = finding.pop("id")
    return finding


class _Scanner:
    def __init__(self, outcomes: dict[str, Any]) -> None:
        self.outcomes = outcomes
        self.calls: list[str] = []

    def scan_skill(self, skill_dir: Path) -> Any:
        self.calls.append(skill_dir.name)
        outcome = self.outcomes[skill_dir.name]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_policy_benchmark_uses_complete_one_to_one_finding_identity(tmp_path: Path) -> None:
    expected_finding = _expected_finding("EXPECTED_RULE")
    _write_case(
        tmp_path,
        "identity",
        _expected(name="identity", safe=False, findings=[expected_finding]),
    )
    scanner = _Scanner(
        {
            "identity": SimpleNamespace(
                is_safe=False,
                findings=[_finding("WRONG_RULE")],
                analyzers_failed=[],
            )
        }
    )

    result = run_eval_benchmark(scanner, tmp_path)

    # The category and severity agree, but the canonical rule identity does
    # not.  The old pair-counting implementation incorrectly called this a TP.
    assert result["finding_tp"] == 0
    assert result["finding_fp"] == 1
    assert result["finding_fn"] == 1
    assert result["strict_cases"] == 0
    assert result["legacy_degraded_cases"] == 1
    assert result["invalid_expectations"] == 0
    assert result["details"][0]["matched_findings"] == 0


def test_scan_errors_are_wrong_for_both_malicious_and_benign_labels(tmp_path: Path) -> None:
    _write_case(
        tmp_path,
        "malicious",
        _expected(name="malicious", safe=False, findings=[_expected_finding("EXPECTED_RULE")]),
    )
    _write_case(tmp_path, "benign", _expected(name="benign", safe=True))
    scanner = _Scanner(
        {
            "malicious": RuntimeError("malicious scan failed"),
            "benign": RuntimeError("benign scan failed"),
        }
    )

    result = run_eval_benchmark(scanner, tmp_path)

    assert result["total"] == 2
    assert result["errors"] == 2
    assert result["complete"] is False
    assert result["tp"] == 0
    assert result["tn"] == 0
    assert result["fn"] == 1
    assert result["fp"] == 1
    assert result["accuracy"] == 0.0
    assert result["finding_fn"] == 1


def test_missing_skill_remains_in_denominator_and_is_not_scanned(tmp_path: Path) -> None:
    _write_case(
        tmp_path,
        "missing",
        _expected(name="missing", safe=True),
        include_skill=False,
    )
    scanner = _Scanner({})

    result = run_eval_benchmark(scanner, tmp_path)

    assert result["total"] == 1
    assert result["errors"] == 1
    assert result["fp"] == 1
    assert result["accuracy"] == 0.0
    assert result["details"][0]["error_kind"] == "missing_skill"
    assert scanner.calls == []


def test_malformed_expectation_remains_in_accuracy_denominator(tmp_path: Path) -> None:
    _write_case(tmp_path, "malformed", "{ definitely not json")
    scanner = _Scanner({})

    result = run_eval_benchmark(scanner, tmp_path)

    assert result["total"] == 1
    assert result["errors"] == 1
    assert result["complete"] is False
    assert result["accuracy"] == 0.0
    assert result["tp"] == result["fp"] == result["tn"] == result["fn"] == 0
    assert result["invalid_expectations"] == 1
    assert result["legacy_degraded_cases"] == 0
    assert result["details"][0]["correct"] is False
    assert result["details"][0]["error_kind"] == "expectation"
    assert scanner.calls == []


def test_reported_analyzer_failure_discards_partial_success(tmp_path: Path) -> None:
    expected_finding = _expected_finding("EXPECTED_RULE")
    _write_case(
        tmp_path,
        "partial",
        _expected(name="partial", safe=False, findings=[expected_finding]),
    )
    scanner = _Scanner(
        {
            "partial": SimpleNamespace(
                is_safe=False,
                findings=[_finding("EXPECTED_RULE")],
                analyzers_failed=[{"analyzer": "llm", "error": "timed out"}],
            )
        }
    )

    result = run_eval_benchmark(scanner, tmp_path)

    assert result["total"] == 1
    assert result["errors"] == 1
    assert result["tp"] == 0
    assert result["fn"] == 1
    assert result["finding_tp"] == 0
    assert result["finding_fn"] == 1
    assert result["details"][0]["error_kind"] == "analyzer"
