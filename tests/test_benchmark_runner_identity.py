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

import hashlib
import json
from types import SimpleNamespace

import pytest

from evals.runners.benchmark_runner import (
    SkillBenchmarkRunner,
    build_committed_golden_evidence,
)
from evals.runners.finding_matcher import (
    EvaluationExpectationError,
    bind_label_attestation,
    fixture_sha256,
)


def test_benchmark_runner_always_closes_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = SkillBenchmarkRunner.__new__(SkillBenchmarkRunner)
    closed: list[bool] = []
    runner.scanner = type("ClosingScanner", (), {"close": lambda self: closed.append(True)})()
    monkeypatch.setattr(runner, "_run_benchmark", lambda: "result")

    assert runner.run_benchmark() == "result"
    assert closed == [True]

    closed.clear()

    def fail() -> None:
        raise RuntimeError("benchmark failed")

    monkeypatch.setattr(runner, "_run_benchmark", fail)
    with pytest.raises(RuntimeError, match="benchmark failed"):
        runner.run_benchmark()
    assert closed == [True]


def _actual(
    rule_id: str,
    *,
    category: str = "command_injection",
    severity: str = "HIGH",
    file_path: str = "scripts/run.py",
    line_number: int = 7,
    evidence_id: str = "evidence-1",
    analyzer: str = "static",
) -> dict:
    return {
        "id": evidence_id,
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "file_path": file_path,
        "line_number": line_number,
        "analyzer": analyzer,
    }


def _scan_result(
    findings: list[dict],
    *,
    is_safe: bool = False,
    analyzer_failures=None,
    duration_seconds: float = 0.0,
    cel_elapsed_ms: float = 0.0,
    cel_fallbacks: int = 0,
):
    severity = "SAFE" if not findings else findings[0]["severity"]
    return SimpleNamespace(
        is_safe=is_safe,
        findings=findings,
        max_severity=SimpleNamespace(value=severity),
        analyzers_failed=analyzer_failures or [],
        scan_duration_seconds=duration_seconds,
        scan_metadata={"cel": {"elapsed_ms": cel_elapsed_ms, "fallbacks": cel_fallbacks}},
    )


def _runner() -> SkillBenchmarkRunner:
    runner = object.__new__(SkillBenchmarkRunner)
    runner.results = []
    return runner


def _write_strict_golden(
    root,
    directory: str,
    case_id: str,
    *,
    label_source: str = "human_reviewed",
):
    skill_dir = root / "evals" / "skills" / directory
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Harmless fixture\n", encoding="utf-8")
    expected_path = skill_dir / "_expected.json"
    document = {
        "schema_version": 2,
        "evaluation_quality": "strict",
        "case_id": case_id,
        "skill_name": directory,
        "package_label": "benign",
        "expected_verdict": "safe",
        "expected_severity": "SAFE",
        "provenance": {
            "source": "first-party human review",
            "license": "Apache-2.0",
            "fixture_sha256": fixture_sha256(skill_dir),
            "label_source": label_source,
            "scanner_independent": True,
        },
        "expected_findings": [],
    }
    bind_label_attestation(document)
    expected_path.write_text(
        json.dumps(document, indent=2) + "\n",
        encoding="utf-8",
    )
    return expected_path


def test_committed_golden_counts_each_attested_label_source(tmp_path) -> None:
    sources = ("public_labeled", "independent_ollama", "agent_labeled", "human_reviewed")
    for index, source in enumerate(sources):
        _write_strict_golden(
            tmp_path,
            f"fixture-{index}",
            f"golden.fixture-{index}",
            label_source=source,
        )

    evidence = build_committed_golden_evidence(
        tmp_path / "evals" / "skills",
        repository_root=tmp_path,
    )

    assert evidence["label_sources"] == {source: 1 for source in sources}


def test_committed_golden_evidence_is_sorted_deterministic_and_domain_separated(tmp_path):
    zeta = _write_strict_golden(tmp_path, "zeta", "golden.zeta-001")
    alpha = _write_strict_golden(tmp_path, "alpha", "golden.alpha-001")
    eval_dir = tmp_path / "evals" / "skills"

    first = build_committed_golden_evidence(eval_dir, repository_root=tmp_path)
    second = build_committed_golden_evidence(eval_dir, repository_root=tmp_path)
    entries = [
        {
            "case_id": "golden.alpha-001",
            "expectation_path": "evals/skills/alpha/_expected.json",
            "expectation_sha256": hashlib.sha256(alpha.read_bytes()).hexdigest(),
            "fixture_sha256": fixture_sha256(alpha.parent),
            "label_source": "human_reviewed",
            "label_provenance_sha256": json.loads(alpha.read_text())["provenance"]["label_provenance_sha256"],
            "label_evidence_sha256": json.loads(alpha.read_text())["provenance"]["label_evidence_sha256"],
            "package_label": "benign",
            "expected_verdict": "safe",
        },
        {
            "case_id": "golden.zeta-001",
            "expectation_path": "evals/skills/zeta/_expected.json",
            "expectation_sha256": hashlib.sha256(zeta.read_bytes()).hexdigest(),
            "fixture_sha256": fixture_sha256(zeta.parent),
            "label_source": "human_reviewed",
            "label_provenance_sha256": json.loads(zeta.read_text())["provenance"]["label_provenance_sha256"],
            "label_evidence_sha256": json.loads(zeta.read_text())["provenance"]["label_evidence_sha256"],
            "package_label": "benign",
            "expected_verdict": "safe",
        },
    ]
    canonical = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert first == second
    assert first == {
        "schema_version": 1,
        "strict_fixtures": 2,
        "legacy_degraded_fixtures": 0,
        "manifest_sha256": hashlib.sha256(b"skill-scanner-exact-golden-manifest-v1\0" + canonical).hexdigest(),
        "label_sources": {
            "public_labeled": 0,
            "independent_ollama": 0,
            "agent_labeled": 0,
            "human_reviewed": 2,
        },
        "scanner_derived_fixtures": 0,
        "sealed_hf_model_labeled_fixtures": 0,
    }


def test_committed_golden_evidence_rejects_duplicate_case_ids(tmp_path):
    _write_strict_golden(tmp_path, "one", "golden.duplicate-001")
    _write_strict_golden(tmp_path, "two", "golden.duplicate-001")

    with pytest.raises(ValueError, match="duplicate strict golden case_id"):
        build_committed_golden_evidence(
            tmp_path / "evals" / "skills",
            repository_root=tmp_path,
        )


def test_committed_golden_evidence_binds_expectation_and_fixture_hashes(tmp_path):
    expected_path = _write_strict_golden(tmp_path, "bound", "golden.bound-001")
    eval_dir = tmp_path / "evals" / "skills"
    original = build_committed_golden_evidence(eval_dir, repository_root=tmp_path)

    document = json.loads(expected_path.read_text(encoding="utf-8"))
    document["notes"] = "Independent human clarification."
    expected_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    label_mutation = build_committed_golden_evidence(eval_dir, repository_root=tmp_path)
    assert label_mutation["manifest_sha256"] != original["manifest_sha256"]

    (expected_path.parent / "SKILL.md").write_text("# Changed fixture\n", encoding="utf-8")
    with pytest.raises(EvaluationExpectationError, match="provenance.fixture_sha256"):
        build_committed_golden_evidence(eval_dir, repository_root=tmp_path)

    document["provenance"]["fixture_sha256"] = fixture_sha256(expected_path.parent)
    bind_label_attestation(document)
    expected_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    fixture_mutation = build_committed_golden_evidence(eval_dir, repository_root=tmp_path)
    assert fixture_mutation["manifest_sha256"] != label_mutation["manifest_sha256"]


def test_complete_identity_uses_strict_matching_and_counts_extra_actual_as_fp():
    expected = {
        "expected_safe": False,
        "expected_findings": [
            {
                "rule_id": "EXPECTED",
                "category": "command_injection",
                "severity": "HIGH",
                "file_path": "scripts/run.py",
                "evidence_id": "evidence-1",
                "analyzer": "static",
            }
        ],
    }

    result = _runner()._compare_results(
        expected,
        _scan_result([_actual("EXPECTED"), _actual("EXTRA", evidence_id="evidence-2")]),
        "unsafe",
    )

    assert result["matching_mode"] == "strict"
    assert result["matched_threats"] == 1
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 0
    assert result["correct"] is False
    assert result["matched_pairs"] == [
        {
            "expected": {
                "rule_id": "EXPECTED",
                "category": "command_injection",
                "severity": "HIGH",
                "file_path": "scripts/run.py",
                "evidence_id": "evidence-1",
                "analyzer": "static",
            },
            "actual": {
                "rule_id": "EXPECTED",
                "category": "command_injection",
                "severity": "HIGH",
                "file_path": "scripts/run.py",
                "line_number": 7,
                "evidence_id": "evidence-1",
                "analyzer": "static",
            },
        }
    ]
    assert result["unmatched_actual_findings"][0]["rule_id"] == "EXTRA"


def test_one_actual_finding_cannot_satisfy_repeated_legacy_expectations():
    expected = {
        "expected_safe": False,
        "expected_findings": [
            {"category": "command_injection", "severity": "HIGH"},
            {"category": "command_injection", "severity": "HIGH"},
        ],
    }

    result = _runner()._compare_results(expected, _scan_result([_actual("ONLY")]), "unsafe")

    assert result["matching_mode"] == "legacy_degraded"
    assert result["legacy_degraded_findings"] == 2
    assert result["matched_threats"] == 1
    assert result["false_negatives"] == 1


def test_identity_can_use_line_number_instead_of_evidence_id():
    expected = {
        "expected_safe": False,
        "expected_findings": [
            {
                "rule_id": "EXPECTED",
                "category": "command_injection",
                "severity": "HIGH",
                "file_path": "scripts/run.py",
                "line_number": 7,
                "analyzer": "static",
            }
        ],
    }

    result = _runner()._compare_results(expected, _scan_result([_actual("EXPECTED")]), "unsafe")

    assert result["matching_mode"] == "strict"
    assert result["correct"] is True


def test_discovery_keeps_missing_skill_fixture_in_denominator(tmp_path):
    missing_skill = tmp_path / "a-missing"
    valid_skill = tmp_path / "b-valid"
    missing_skill.mkdir()
    valid_skill.mkdir()
    (missing_skill / "_expected.json").write_text("{}", encoding="utf-8")
    (valid_skill / "_expected.json").write_text("{}", encoding="utf-8")
    (valid_skill / "SKILL.md").write_text("# valid", encoding="utf-8")

    runner = _runner()
    runner.eval_skills_dir = tmp_path

    assert runner._find_evaluation_skills() == [
        (missing_skill, missing_skill / "_expected.json"),
        (valid_skill, valid_skill / "_expected.json"),
    ]


def test_malformed_expectation_is_recorded_as_error_not_dropped(tmp_path):
    skill_dir = tmp_path / "malformed"
    skill_dir.mkdir()
    expected_file = skill_dir / "_expected.json"
    expected_file.write_text("[]", encoding="utf-8")

    runner = _runner()
    runner.scanner = SimpleNamespace()
    runner._evaluate_skill(skill_dir, expected_file)
    metrics = runner._calculate_benchmark_metrics(1.0)

    assert metrics.total_skills_evaluated == 1
    assert metrics.evaluation_errors == 1
    assert metrics.overall_accuracy == 0
    assert metrics.strict_identity_skills == 0
    assert runner.results[0]["matching_mode"] == "unavailable"
    assert "root must be a JSON object" in runner.results[0]["error"]


def test_partial_analyzer_failure_fails_fixture_and_preserves_expected_fn(tmp_path):
    skill_dir = tmp_path / "partial"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# partial", encoding="utf-8")
    expected_file = skill_dir / "_expected.json"
    expected_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evaluation_quality": "legacy_degraded",
                "skill_name": "partial",
                "expected_safe": False,
                "expected_findings": [
                    {
                        "rule_id": "EXPECTED",
                        "category": "command_injection",
                        "severity": "HIGH",
                        "file_path": "scripts/run.py",
                        "evidence_id": "evidence-1",
                        "analyzer": "static",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    class PartialScanner:
        def scan_skill(self, _skill_path):
            return _scan_result(
                [_actual("EXPECTED")],
                analyzer_failures=[{"analyzer": "yara", "error": "timed out"}],
            )

    runner = _runner()
    runner.scanner = PartialScanner()
    runner._evaluate_skill(skill_dir, expected_file)
    metrics = runner._calculate_benchmark_metrics(1.0)

    assert metrics.total_skills_evaluated == 1
    assert metrics.evaluation_errors == 1
    assert metrics.finding_false_negatives == 1
    assert runner.results[0]["correct"] is False


def test_scan_error_preserves_validated_benign_package_label(tmp_path) -> None:
    expected_path = _write_strict_golden(tmp_path, "benign-error", "golden.benign-error-001")

    class FailingScanner:
        def scan_skill(self, _skill_path):
            raise RuntimeError("deterministic scanner failure")

    runner = _runner()
    runner.scanner = FailingScanner()
    runner._evaluate_skill(expected_path.parent, expected_path)
    metrics = runner._calculate_benchmark_metrics(1.0)

    assert runner.results[0]["package_label"] == "benign"
    assert metrics.evaluation_errors == 1
    assert metrics.benign_actionable_false_positive_rate == 1.0


def test_aggregate_reports_legacy_degraded_matching_explicitly():
    runner = _runner()
    runner.results = [
        {
            "expected_safe": False,
            "matched_threats": 1,
            "false_positives": 0,
            "false_negatives": 0,
            "correct": True,
            "matching_mode": "strict",
            "legacy_degraded_findings": 0,
        },
        {
            "expected_safe": False,
            "matched_threats": 1,
            "false_positives": 0,
            "false_negatives": 0,
            "correct": True,
            "matching_mode": "legacy_degraded",
            "legacy_degraded_findings": 3,
        },
    ]

    result = runner._calculate_benchmark_metrics(1.0)

    assert result.strict_identity_skills == 1
    assert result.legacy_degraded_skills == 1
    assert result.legacy_degraded_findings == 3


def test_aggregate_reports_package_thresholds_and_per_category_finding_metrics():
    runner = _runner()
    malicious = runner._compare_results(
        {
            "expected_safe": False,
            "package_label": "malicious",
            "expected_findings": [
                {
                    "rule_id": "EXPECTED",
                    "category": "command_injection",
                    "severity": "HIGH",
                    "file_path": "scripts/run.py",
                    "evidence_id": "evidence-1",
                    "analyzer": "static",
                }
            ],
        },
        _scan_result(
            [_actual("EXPECTED")],
            duration_seconds=0.1,
            cel_elapsed_ms=2.0,
            cel_fallbacks=1,
        ),
        "malicious",
    )
    benign = runner._compare_results(
        {"expected_safe": True, "package_label": "benign", "expected_findings": []},
        _scan_result(
            [
                _actual(
                    "NOISY",
                    category="obfuscation",
                    severity="MEDIUM",
                    evidence_id="evidence-2",
                )
            ],
            is_safe=False,
            duration_seconds=0.2,
            cel_elapsed_ms=1.0,
        ),
        "benign",
    )
    runner.results = [malicious, benign]

    result = runner._calculate_benchmark_metrics(1.0)

    assert result.package_true_positives == 1
    assert result.package_true_negatives == 1
    assert result.package_false_positives == 0
    assert result.package_false_negatives == 0
    assert result.package_block_recall == 1.0
    assert result.package_signal_recall == 1.0
    assert result.package_macro_f1 == 1.0
    assert result.benign_actionable_false_positive_rate == 1.0
    categories = {metric.category: metric for metric in result.category_metrics}
    assert categories["command_injection"].true_positives == 1
    assert categories["command_injection"].recall == 1.0
    assert categories["obfuscation"].false_positives == 1
    assert categories["obfuscation"].precision == 0.0
    assert result.finding_macro_f1 == 0.5
    assert result.overall_f1 == pytest.approx(2 / 3)
    assert 0.0 < result.finding_precision_confidence_interval_95[0] < 0.5
    assert categories["command_injection"].precision_confidence_interval_95[1] == 1.0
    assert result.p95_scan_latency_ms == 200.0
    assert result.cel_time_ratio == pytest.approx(0.01)
    assert result.cel_fallbacks == 1


def test_package_severity_matrix_separates_signal_actionable_and_blocking() -> None:
    runner = _runner()
    results = []
    for label, expected_safe in (("malicious", False), ("benign", True)):
        for severity in ("LOW", "MEDIUM", "HIGH"):
            results.append(
                runner._compare_results(
                    {
                        "expected_safe": expected_safe,
                        "package_label": label,
                        "expected_findings": [],
                    },
                    _scan_result(
                        [
                            _actual(
                                f"{label}-{severity}",
                                severity=severity,
                                evidence_id=f"{label}-{severity}",
                            )
                        ],
                        is_safe=False,
                    ),
                    f"{label}-{severity}",
                )
            )
    runner.results = results

    result = runner._calculate_benchmark_metrics(1.0)

    assert (result.package_true_positives, result.package_false_negatives) == (1, 2)
    assert (result.package_true_negatives, result.package_false_positives) == (2, 1)
    assert result.package_block_recall == pytest.approx(1 / 3)
    assert result.package_signal_recall == 1.0
    assert result.benign_actionable_false_positive_rate == pytest.approx(2 / 3)


def test_benign_actionable_fpr_excludes_contextual_risk_packages() -> None:
    runner = _runner()
    contextual_expected = {
        "evaluation_quality": "strict",
        "expected_verdict": "safe",
        "package_label": "contextual_risk",
        "expected_findings": [
            {
                "rule_id": "CONTEXTUAL_SIGNAL",
                "category": "policy_violation",
                "severity": "MEDIUM",
                "file_path": "scripts/run.py",
                "evidence_id": "contextual-signal",
                "analyzer": "static",
            }
        ],
    }
    contextual = runner._compare_results(
        contextual_expected,
        _scan_result(
            [
                _actual(
                    "CONTEXTUAL_SIGNAL",
                    category="policy_violation",
                    severity="MEDIUM",
                    evidence_id="contextual-signal",
                )
            ],
            is_safe=True,
        ),
        "contextual",
    )
    benign_clean = runner._compare_results(
        {"expected_safe": True, "package_label": "benign", "expected_findings": []},
        _scan_result([], is_safe=True),
        "benign-clean",
    )
    benign_noisy = runner._compare_results(
        {"expected_safe": True, "package_label": "benign", "expected_findings": []},
        _scan_result(
            [_actual("BENIGN_NOISE", severity="MEDIUM", evidence_id="benign-noise")],
            is_safe=True,
        ),
        "benign-noisy",
    )
    runner.results = [contextual, benign_clean, benign_noisy]

    result = runner._calculate_benchmark_metrics(1.0)

    assert contextual["package_label"] == "contextual_risk"
    assert result.benign_packages == 2
    assert result.contextual_risk_packages == 1
    assert result.benign_actionable_false_positives == 1
    assert result.benign_actionable_false_positive_rate == 0.5
    lower, upper = result.benign_actionable_fpr_confidence_interval_95
    assert lower < 0.5 < upper
