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

"""Benchmark handling for the scanner's bounded manifest-loader recovery."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from evals.runners.benchmark_runner import SkillBenchmarkRunner
from evals.runners.finding_matcher import bind_label_attestation, fixture_sha256

_MALFORMED_METADATA = {
    "fallback_used": True,
    "fallback_mode": "bounded_inert_raw_body",
    "strict_error_type": "SkillLoadError",
    "strict_error_code": "MALFORMED_YAML_FRONTMATTER",
    "manifest_complete": False,
    "capability_facts_trusted": False,
    "projection_complete": False,
    "projection_error_code": "MANIFEST_METADATA_INCOMPLETE",
}


def _marker(metadata: dict | None = None) -> dict:
    return {
        "id": "SKILL_LOAD_FALLBACK_USED",
        "rule_id": "SKILL_LOAD_FALLBACK_USED",
        "category": "policy_violation",
        "severity": "INFO",
        "file_path": "SKILL.md",
        "analyzer": "skill_loader",
        "metadata": deepcopy(metadata if metadata is not None else _MALFORMED_METADATA),
    }


def _dangerous_finding() -> dict:
    return {
        "id": "dangerous-command",
        "rule_id": "DANGEROUS_COMMAND",
        "category": "command_injection",
        "severity": "HIGH",
        "file_path": "SKILL.md",
        "line_number": 8,
        "analyzer": "static",
        "metadata": {},
    }


def _scan_result(
    *,
    analyzer_failures: list[dict] | None = None,
    loader_metadata: dict | None = None,
) -> SimpleNamespace:
    findings = [_marker(), _dangerous_finding()]
    scan_metadata = {
        "cel": {"elapsed_ms": 0.0, "fallbacks": 0},
        "loader": deepcopy(loader_metadata if loader_metadata is not None else _MALFORMED_METADATA),
    }
    return SimpleNamespace(
        is_safe=False,
        findings=findings,
        max_severity=SimpleNamespace(value="HIGH"),
        analyzers_failed=(
            analyzer_failures
            if analyzer_failures is not None
            else [
                {
                    "analyzer": "skill_loader",
                    "error": "SkillLoadError:MALFORMED_YAML_FRONTMATTER",
                }
            ]
        ),
        scan_duration_seconds=0.01,
        scan_metadata=scan_metadata,
    )


def _write_strict_expectation(root: Path) -> tuple[Path, Path]:
    skill_dir = root / "bounded-loader-recovery"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# Scanner input\n", encoding="utf-8")
    expected_path = skill_dir / "_expected.json"
    document = {
        "schema_version": 2,
        "evaluation_quality": "strict",
        "case_id": "golden.bounded-loader-recovery-001",
        "skill_name": "bounded-loader-recovery",
        "package_label": "malicious",
        "expected_verdict": "unsafe",
        "expected_severity": "HIGH",
        "provenance": {
            "source": "first-party human review",
            "license": "Apache-2.0",
            "fixture_sha256": fixture_sha256(skill_dir),
            "label_source": "human_reviewed",
            "scanner_independent": True,
        },
        "expected_findings": [
            {
                "rule_id": "SKILL_LOAD_FALLBACK_USED",
                "category": "policy_violation",
                "severity": "INFO",
                "file_path": "SKILL.md",
                "evidence_id": "SKILL_LOAD_FALLBACK_USED",
                "analyzer": "skill_loader",
            },
            {
                "rule_id": "DANGEROUS_COMMAND",
                "category": "command_injection",
                "severity": "HIGH",
                "file_path": "SKILL.md",
                "line_number": 8,
                "analyzer": "static",
            },
        ],
    }
    bind_label_attestation(document)
    expected_path.write_text(
        json.dumps(document),
        encoding="utf-8",
    )
    return skill_dir, expected_path


def _evaluate(tmp_path: Path, scan_result: SimpleNamespace) -> tuple[dict, object]:
    skill_dir, expected_path = _write_strict_expectation(tmp_path)
    runner = object.__new__(SkillBenchmarkRunner)
    runner.results = []
    runner.scanner = SimpleNamespace(scan_skill=lambda _skill_path: scan_result)

    runner._evaluate_skill(skill_dir, expected_path)

    return runner.results[0], runner._calculate_benchmark_metrics(1.0)


def test_exact_bounded_loader_recovery_retains_findings_and_is_counted(tmp_path: Path) -> None:
    row, metrics = _evaluate(tmp_path, _scan_result())

    assert "error" not in row
    assert row["correct"] is True
    assert row["detected_threat_count"] == 2
    assert row["matched_threats"] == 2
    assert {pair["actual"]["rule_id"] for pair in row["matched_pairs"]} == {
        "DANGEROUS_COMMAND",
        "SKILL_LOAD_FALLBACK_USED",
    }
    assert row["recovered_scan_error"] is True
    assert row["loader_fallback_code"] == "MALFORMED_YAML_FRONTMATTER"
    assert metrics.total_skills_evaluated == 1
    assert metrics.finding_true_positives == 2
    assert metrics.overall_accuracy == 1.0
    assert metrics.evaluation_errors == 0
    assert metrics.loader_fallbacks == 1
    assert metrics.recovered_scan_errors == 1


def test_spoofed_loader_marker_identity_is_an_evaluation_error(tmp_path: Path) -> None:
    spoofed = _scan_result()
    spoofed.findings[0]["severity"] = "HIGH"
    row, metrics = _evaluate(tmp_path, spoofed)

    assert "error" in row
    assert row["recovered_scan_error"] is False
    assert row["loader_fallback_code"] is None
    assert metrics.evaluation_errors == 1
    assert metrics.loader_fallbacks == 0
    assert metrics.recovered_scan_errors == 0


def test_mismatched_loader_failure_and_metadata_remains_an_evaluation_error(
    tmp_path: Path,
) -> None:
    mismatched_metadata = {
        **_MALFORMED_METADATA,
        "strict_error_code": "MISSING_REQUIRED_MANIFEST_FIELD",
    }
    row, metrics = _evaluate(tmp_path, _scan_result(loader_metadata=mismatched_metadata))

    assert "scan_metadata.loader does not match the loader failure" in row["error"]
    assert row["recovered_scan_error"] is False
    assert row["loader_fallback_code"] is None
    assert metrics.evaluation_errors == 1
    assert metrics.loader_fallbacks == 0
    assert metrics.recovered_scan_errors == 0
