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

import copy
from pathlib import Path

import pytest

from evals.runners import benchmark_comparison
from evals.runners.benchmark_comparison import (
    BenchmarkComparisonError,
    compare_benchmark_reports,
    compare_repeated_benchmark_reports,
    run_cel_mode_comparison,
)
from evals.runners.public_dataset_benchmark import compact_release_report
from skill_scanner.core.cel.models import CelMode

_RULE_FIXTURE_EVIDENCE = {
    "CEL_TEST": {
        "true_positive_fixture_ids": ["cel-test.true-positive"],
        "benign_near_miss_fixture_ids": ["cel-test.benign-near-miss"],
        "boundary_fixture_ids": ["cel-test.projection-boundary"],
    }
}


def _metrics(
    *,
    recall: float,
    signal_recall: float,
    macro_f1: float,
    benign_fpr: float,
    false_negative_ids: list[str],
    latency_ms: float,
    cel_ratio: float,
    fallbacks: int = 0,
    errors: int = 0,
) -> dict:
    return {
        "samples": 10,
        "malicious": 5,
        "benign": 5,
        "precision": recall,
        "recall": recall,
        "package_block_precision": recall,
        "package_block_recall": recall,
        "signal_recall": signal_recall,
        "macro_f1": macro_f1,
        "benign_actionable_fpr": benign_fpr,
        "critical_high_false_negatives": len(false_negative_ids),
        "critical_high_false_negative_ids": false_negative_ids,
        "p95_scan_latency_ms": latency_ms,
        "cel_time_ratio": cel_ratio,
        "cel_fallbacks": fallbacks,
        "loader_fallbacks": 0,
        "recovered_scan_errors": 0,
        "loader_fallback_sample_ids": [],
        "loader_rejections": 0,
        "loader_rejection_sample_ids": [],
        "scan_errors": errors,
        "confidence_intervals_95": {
            "package_block_precision": [0.5, 1.0],
            "package_block_recall": [0.5, 1.0],
            "signal_recall": [0.5, 1.0],
            "benign_actionable_fpr": [0.0, 0.5],
        },
    }


def _report(*, candidate: bool = False) -> dict:
    metrics = _metrics(
        recall=1.0 if candidate else 0.8,
        signal_recall=1.0,
        macro_f1=1.0 if candidate else 0.8,
        benign_fpr=0.0 if candidate else 0.2,
        false_negative_ids=[] if candidate else ["mal-5"],
        latency_ms=105.0 if candidate else 100.0,
        cel_ratio=0.04 if candidate else 0.0,
    )
    metrics["cel"] = {
        "modes": ["shadow" if candidate else "off"],
        "runtimes": ["cel-go"],
        "runtime_versions": ["v0.32.0;helper=2.0.0"],
        "fact_schemas": ["v1"],
        "expression_set_hashes": ["a" * 64],
        "evaluated": 5 if candidate else 0,
        "retained": 5 if candidate else 10,
        "would_suppress": 1 if candidate else 0,
        "suppressed": 0,
        "fallbacks": 0,
        "projection_incomplete": 0,
        "elapsed_ms": 40.0 if candidate else 0.0,
        "projection_ms": 10.0 if candidate else 0.0,
        "evaluation_ms": 20.0 if candidate else 0.0,
        "error_counts": {},
        "per_rule": (
            {
                "CEL_TEST": {
                    "keep": 1,
                    "would_suppress": 1,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": ["expression-hash"],
                    "packs": ["core"],
                    "rollouts": ["shadow"],
                }
            }
            if candidate
            else {}
        ),
        "would_suppress_sample_ids": ["benign-1"] if candidate else [],
        "suppressed_sample_ids": [],
        "fallback_sample_ids": [],
        "projection_incomplete_sample_ids": [],
    }
    track = {
        "name": "source-disjoint-core",
        "status": "passed",
        "detector_profile": "core_only",
        "protocol": "source_disjoint",
        "partition": "test",
        "population_sha256": "9" * 64,
        **copy.deepcopy(metrics),
        "per_source": {"SRC-A": copy.deepcopy(metrics)},
        "per_structural_family": {"FAM-A": copy.deepcopy(metrics)},
        "per_category": {"command_execution": copy.deepcopy(metrics)},
        "sample_outcomes": {
            "mal-1": {
                "label": "malicious",
                "blocked": True,
                "actionable": True,
                "signal": True,
                "scan_error": False,
                "findings": (
                    [
                        {
                            "rule_id": "CEL_TEST",
                            "category": "command_execution",
                            "severity": "HIGH",
                            "cel_decision": "keep",
                            "cel_decisions": [
                                {
                                    "rule_id": "CEL_TEST",
                                    "decision": "keep",
                                    "reason": "expression_true",
                                    "fact_schema": "v1",
                                    "expression_hash": "expression-hash",
                                    "pack": "core",
                                    "rollout": "shadow",
                                    "count": 1,
                                }
                            ],
                        },
                    ]
                    if candidate
                    else []
                ),
            },
            "benign-1": {
                "label": "benign",
                "blocked": False,
                "actionable": True,
                "signal": True,
                "scan_error": False,
                "findings": (
                    [
                        {
                            "rule_id": "CEL_TEST",
                            "category": "command_execution",
                            "severity": "MEDIUM",
                            "cel_decision": "would_suppress",
                            "cel_decisions": [
                                {
                                    "rule_id": "CEL_TEST",
                                    "decision": "would_suppress",
                                    "reason": "shadow_or_rule_rollout",
                                    "fact_schema": "v1",
                                    "expression_hash": "expression-hash",
                                    "pack": "core",
                                    "rollout": "shadow",
                                    "count": 1,
                                }
                            ],
                        }
                    ]
                    if candidate
                    else []
                ),
            },
        },
        "errors": [],
    }
    producer = {
        "scanner_version": "2.0.0",
        "source_revision": "test-revision",
        "build_sha256": "c" * 64,
        "policy_sha256": "d" * 64,
        "rules_sha256": "e" * 64,
    }
    stable_identity = {"snapshot_sha256": "b" * 64, **producer}
    return {
        "schema_version": 1,
        "status": "passed",
        "profile": "release",
        "cel_mode": "shadow" if candidate else "off",
        "evidence_identity": {
            "dataset_or_corpus_id": "example/benchmark",
            "snapshot_sha256": "b" * 64,
            "build_sha256": "c" * 64,
            "policy_sha256": "d" * 64,
            "rules_sha256": "e" * 64,
            "expression_set_hash": "f" * 64,
            "cel_mode": "shadow" if candidate else "off",
        },
        "producer": producer,
        "identity_verification": {
            "status": "passed",
            "drifted_fields": [],
            "start": copy.deepcopy(stable_identity),
            "end": copy.deepcopy(stable_identity),
            "errors": [],
        },
        "dataset": {
            "id": "example/benchmark",
            "revision": "a" * 40,
            "artifact_manifest_sha256": "b" * 64,
            "sample_metadata_manifest_sha256": "a" * 64,
            "blocking_eligible": True,
        },
        "tracks": {"source-disjoint-core": track},
        "summary": copy.deepcopy(metrics),
        "errors": [],
    }


def test_compares_population_locked_reports_across_all_group_dimensions() -> None:
    comparison = compare_benchmark_reports(_report(), _report(candidate=True))

    assert comparison["status"] == "passed"
    assert comparison["population_locked"] is True
    assert comparison["summary"]["metrics"]["package_block_recall"] == {
        "baseline": 0.8,
        "candidate": 1.0,
        "absolute_delta": pytest.approx(0.2),
        "relative_delta": pytest.approx(0.25),
        "preferred_direction": "higher",
        "outcome": "improved",
        "confidence_intervals_95": {
            "baseline": [0.5, 1.0],
            "candidate": [0.5, 1.0],
            "relation": "overlap",
        },
    }
    assert comparison["summary"]["critical_high_false_negative_ids"]["resolved"] == ["mal-5"]
    track = comparison["tracks"]["source-disjoint-core"]
    assert set(track["groups"]) == {
        "per_category",
        "per_source",
        "per_structural_family",
    }
    assert comparison["missing_group_dimensions"] == []


def test_rejects_population_or_dataset_drift() -> None:
    baseline = _report()
    candidate = _report(candidate=True)
    candidate["summary"]["samples"] = 11
    with pytest.raises(BenchmarkComparisonError, match="population differs"):
        compare_benchmark_reports(baseline, candidate)

    candidate = _report(candidate=True)
    candidate["dataset"]["revision"] = "c" * 40
    with pytest.raises(BenchmarkComparisonError, match="dataset identity differs"):
        compare_benchmark_reports(baseline, candidate)

    candidate = _report(candidate=True)
    candidate["dataset"]["sample_metadata_manifest_sha256"] = "9" * 64
    with pytest.raises(BenchmarkComparisonError, match="dataset identity differs"):
        compare_benchmark_reports(baseline, candidate)

    candidate = _report(candidate=True)
    candidate["tracks"]["source-disjoint-core"]["population_sha256"] = "8" * 64
    with pytest.raises(BenchmarkComparisonError, match="selected population identity differs"):
        compare_benchmark_reports(baseline, candidate)


def test_new_false_negative_and_excess_latency_fail_promotion() -> None:
    baseline = _report()
    candidate = _report(candidate=True)
    candidate["summary"]["critical_high_false_negative_ids"] = ["new-miss"]
    candidate["summary"]["critical_high_false_negatives"] = 1
    candidate["summary"]["p95_scan_latency_ms"] = 111.0

    comparison = compare_benchmark_reports(baseline, candidate)

    assert comparison["status"] == "failed"
    checks = comparison["summary"]["promotion"]["checks"]
    assert checks["no_new_critical_high_false_negatives"] is False
    assert checks["p95_latency_within_ten_percent"] is False


def test_old_report_recall_alias_and_missing_new_groups_are_explicit() -> None:
    baseline = _report()
    candidate = _report(candidate=True)
    baseline["summary"].pop("package_block_recall")
    baseline["summary"].pop("scan_errors")
    for track in baseline["tracks"].values():
        track.pop("package_block_recall")
        track.pop("scan_errors")
        track.pop("per_category")
        track.pop("per_structural_family")

    comparison = compare_benchmark_reports(baseline, candidate)

    assert comparison["summary"]["metrics"]["package_block_recall"]["baseline"] == 0.8
    assert comparison["missing_group_dimensions"] == [
        "source-disjoint-core.per_category",
        "source-disjoint-core.per_structural_family",
    ]
    assert comparison["status"] == "failed"


def test_runs_off_then_candidate_cel_mode_and_compares(monkeypatch, tmp_path: Path) -> None:
    calls: list[CelMode] = []

    def fake_run(_snapshot_dir: Path, *, cel_mode: CelMode, **_kwargs):
        calls.append(cel_mode)
        return _report(candidate=cel_mode is not CelMode.OFF)

    monkeypatch.setattr(benchmark_comparison, "run_public_benchmark", fake_run)

    result = run_cel_mode_comparison(tmp_path, candidate_mode=CelMode.SHADOW)

    assert calls == [CelMode.OFF, CelMode.SHADOW]
    assert result["comparison"]["status"] == "passed"


def test_refuses_off_as_candidate_mode(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkComparisonError, match="shadow or enforce"):
        run_cel_mode_comparison(tmp_path, candidate_mode=CelMode.OFF)


def test_subgroup_regression_is_blocking_even_when_summary_is_unchanged() -> None:
    baseline = _report()
    candidate = _report(candidate=True)
    category = candidate["tracks"]["source-disjoint-core"]["per_category"]["command_execution"]
    category["package_block_recall"] = 0.6
    category["recall"] = 0.6
    category["critical_high_false_negative_ids"] = ["category-miss"]
    category["critical_high_false_negatives"] = 1

    comparison = compare_benchmark_reports(baseline, candidate)

    assert comparison["summary"]["promotion"]["passed"] is True
    assert comparison["status"] == "failed"
    category_result = comparison["tracks"]["source-disjoint-core"]["groups"]["per_category"]["command_execution"]
    assert category_result["promotion"]["passed"] is False


def test_rejects_active_mode_without_qualified_runtime_evidence() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["cel"]["runtimes"] = ["unavailable"]

    with pytest.raises(BenchmarkComparisonError, match="qualified CEL runtime"):
        compare_benchmark_reports(_report(), candidate)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("runtimes", ["celpy"], "qualified CEL runtime"),
        ("runtime_versions", ["v0.32.0;helper=development"], "qualified CEL runtime"),
        ("expression_set_hashes", ["not-a-digest"], "expression generation hash"),
        ("evaluated", 0, "active CEL evaluation"),
    ],
)
def test_rejects_spoofed_or_inactive_cel_evidence(field: str, value: object, message: str) -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["cel"][field] = value

    with pytest.raises(BenchmarkComparisonError, match=message):
        compare_benchmark_reports(_report(), candidate)


def test_off_baseline_must_use_same_compiled_cel_go_generation() -> None:
    baseline = _report()
    baseline["summary"]["cel"]["runtimes"] = ["unavailable"]
    baseline["summary"]["cel"]["runtime_versions"] = ["not_loaded"]

    with pytest.raises(BenchmarkComparisonError, match="baseline report lacks a qualified CEL runtime"):
        compare_benchmark_reports(baseline, _report(candidate=True))

    baseline = _report()
    baseline["summary"]["cel"]["expression_set_hashes"] = ["b" * 64]
    with pytest.raises(BenchmarkComparisonError, match="same CEL expression generation hash"):
        compare_benchmark_reports(baseline, _report(candidate=True))


def test_off_baseline_cannot_report_cel_evaluation() -> None:
    baseline = _report()
    baseline["summary"]["cel"]["evaluated"] = 1

    with pytest.raises(BenchmarkComparisonError, match="off baseline reports active CEL"):
        compare_benchmark_reports(baseline, _report(candidate=True))


def test_active_cel_comparison_binds_bounded_loader_recovery_identity() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["loader_fallbacks"] = 1
    candidate["summary"]["recovered_scan_errors"] = 1
    candidate["summary"]["loader_fallback_sample_ids"] = ["source-disjoint-core:recovered-1"]

    comparison = compare_benchmark_reports(_report(), candidate)

    assert comparison["status"] == "failed"
    assert comparison["summary"]["loader_recovery"] == {
        "baseline": {
            "loader_fallbacks": 0,
            "recovered_scan_errors": 0,
            "sample_ids": [],
        },
        "candidate": {
            "loader_fallbacks": 1,
            "recovered_scan_errors": 1,
            "sample_ids": ["source-disjoint-core:recovered-1"],
        },
        "matches": False,
    }
    assert comparison["summary"]["promotion"]["checks"]["loader_recovery_identity"] is False


def test_comparison_rejects_incoherent_loader_recovery_counts() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["loader_fallbacks"] = 1

    with pytest.raises(BenchmarkComparisonError, match="loader recovery evidence is inconsistent"):
        compare_benchmark_reports(_report(), candidate)


def test_active_cel_comparison_binds_closed_loader_rejection_identity() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["loader_rejections"] = 1
    candidate["summary"]["loader_rejection_sample_ids"] = ["source-disjoint-core:rejected-1"]

    comparison = compare_benchmark_reports(_report(), candidate)

    assert comparison["status"] == "failed"
    assert comparison["summary"]["loader_rejection"]["matches"] is False
    assert comparison["summary"]["promotion"]["checks"]["loader_rejection_identity"] is False


def test_comparison_rejects_incoherent_loader_rejection_count() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["loader_rejections"] = 1

    with pytest.raises(
        BenchmarkComparisonError,
        match="closed loader rejection evidence is inconsistent",
    ):
        compare_benchmark_reports(_report(), candidate)


def test_active_comparison_rejects_incomplete_projection_even_without_fallback() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["cel"]["projection_incomplete"] = 1
    candidate["summary"]["cel"]["projection_incomplete_sample_ids"] = ["mal-1"]

    comparison = compare_benchmark_reports(_report(), candidate)

    assert comparison["status"] == "failed"
    assert comparison["summary"]["promotion"]["checks"]["zero_cel_fallbacks"] is True
    assert comparison["summary"]["promotion"]["checks"]["zero_cel_projection_incomplete"] is False


def test_helper_build_must_match_scanner_producer() -> None:
    candidate = _report(candidate=True)
    candidate["summary"]["cel"]["runtime_versions"] = ["v0.32.0;helper=other-build"]

    with pytest.raises(BenchmarkComparisonError, match="does not match scanner producer"):
        compare_benchmark_reports(_report(), candidate)


def test_active_comparison_binds_producer_to_evidence_and_baseline() -> None:
    candidate = _report(candidate=True)
    candidate["producer"]["source_revision"] = "different-revision"

    with pytest.raises(BenchmarkComparisonError, match="producer"):
        compare_benchmark_reports(_report(), candidate)

    candidate = _report(candidate=True)
    candidate["producer"]["rules_sha256"] = "0" * 64
    with pytest.raises(BenchmarkComparisonError, match="does not match evidence_identity"):
        compare_benchmark_reports(_report(), candidate)


def test_comparison_rejects_missing_or_drifted_post_run_identity() -> None:
    candidate = _report(candidate=True)
    candidate["identity_verification"]["end"]["build_sha256"] = "0" * 64

    with pytest.raises(BenchmarkComparisonError, match="start and end identities differ"):
        compare_benchmark_reports(_report(), candidate)

    candidate = _report(candidate=True)
    candidate.pop("identity_verification")
    with pytest.raises(BenchmarkComparisonError, match="identity_verification must be an object"):
        compare_benchmark_reports(_report(), candidate)


def test_rejects_failed_or_errorful_reports() -> None:
    candidate = _report(candidate=True)
    candidate["errors"] = [{"benchmark_id": "x", "error": "failed"}]

    with pytest.raises(BenchmarkComparisonError, match="errors must be an empty"):
        compare_benchmark_reports(_report(), candidate)


def test_five_run_stability_and_per_rule_promotion_evidence() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
        promoted_rule_ids=["CEL_TEST"],
    )

    assert result["status"] == "failed"
    assert result["same_evidence_identity"] is True
    assert result["same_producer_identity"] is True
    assert result["stable_output"] is True
    assert len(set(result["stability_fingerprints"])) == 1
    rule = result["rule_promotion_evidence"]["CEL_TEST"]
    assert rule["observed_targeted_benign_candidates"] == 1
    assert rule["observed_would_suppress_benign_candidates"] == 1
    assert rule["normalized_loss_evidence_status"] == "not_available"
    assert rule["normalized_loss_evidence_exact"] is False
    assert rule["relative_actionable_fp_reduction"] is None
    assert rule["passes_twenty_percent_reduction"] is False
    assert rule["has_true_positive_fixture"] is True
    assert rule["has_benign_near_miss_fixture"] is True
    assert rule["has_boundary_fixture"] is True
    assert rule["eligible_for_promotion"] is False


def test_compact_v3_rule_references_do_not_claim_normalized_loss() -> None:
    candidates = [compact_release_report(_report(candidate=True)) for _ in range(5)]

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
        promoted_rule_ids=["CEL_TEST"],
    )

    assert result["status"] == "failed"
    rule = result["rule_promotion_evidence"]["CEL_TEST"]
    assert rule["observed_would_suppress_benign_candidates"] == 1
    assert rule["normalized_loss_evidence_exact"] is False
    assert rule["eligible_for_promotion"] is False


def test_enforced_raw_suppression_with_surviving_same_issue_is_ineligible() -> None:
    candidates = []
    for _ in range(5):
        candidate = _report(candidate=True)
        candidate["cel_mode"] = "enforce"
        candidate["evidence_identity"]["cel_mode"] = "enforce"
        candidate["summary"]["cel"]["modes"] = ["enforce"]
        track = candidate["tracks"]["source-disjoint-core"]
        track["cel"]["modes"] = ["enforce"]
        track["cel"]["suppressed"] = 1
        track["cel"]["suppressed_sample_ids"] = ["benign-1"]
        track["cel"]["per_rule"]["CEL_TEST"].update(keep=2, suppressed=1, rollouts=["enforce"])
        for finding in track["sample_outcomes"]["mal-1"]["findings"]:
            for decision in finding["cel_decisions"]:
                decision["rollout"] = "enforce"
        benign = track["sample_outcomes"]["benign-1"]
        # The raw candidate is suppressed, but equivalent support for the
        # normalized issue survives.  Compact-v3 cannot bind the suppression
        # record to this final group, so it must not claim a resolved finding.
        benign["findings"] = [
            {
                "rule_id": "CEL_TEST",
                "category": "command_execution",
                "severity": "MEDIUM",
                "cel_decision": "keep",
                "cel_decisions": [
                    {
                        "rule_id": "CEL_TEST",
                        "decision": "keep",
                        "reason": "expression_true",
                        "fact_schema": "v1",
                        "expression_hash": "expression-hash",
                        "pack": "core",
                        "rollout": "enforce",
                        "count": 1,
                    }
                ],
            }
        ]
        benign["cel_suppressed"] = [
            {
                "rule_id": "CEL_TEST",
                "category": "command_execution",
                "severity": "MEDIUM",
                "analyzer": "static",
                "count": 1,
                "expression_hash": "expression-hash",
                "pack": "core",
                "rollout": "enforce",
            }
        ]
        for dimension in ("per_source", "per_structural_family", "per_category"):
            for group in track[dimension].values():
                group["cel"]["modes"] = ["enforce"]
        candidates.append(compact_release_report(candidate))

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
        promoted_rule_ids=["CEL_TEST"],
    )

    rule = result["rule_promotion_evidence"]["CEL_TEST"]
    assert result["status"] == "failed"
    assert rule["observed_targeted_benign_candidates"] == 2
    assert rule["observed_would_suppress_benign_candidates"] == 1
    assert rule["observed_would_suppress_malicious_high_critical_candidates"] == 0
    assert rule["normalized_loss_evidence_exact"] is False
    assert rule["relative_actionable_fp_reduction"] is None
    assert rule["eligible_for_promotion"] is False


def test_single_enforced_rule_computes_exact_bound_normalized_loss() -> None:
    candidates = []
    for _ in range(5):
        candidate = _report(candidate=True)
        candidate["cel_mode"] = "enforce"
        candidate["evidence_identity"]["cel_mode"] = "enforce"
        candidate["summary"]["cel"]["modes"] = ["enforce"]
        track = candidate["tracks"]["source-disjoint-core"]
        track["cel"].update(
            modes=["enforce"],
            suppressed=1,
            suppressed_sample_ids=["benign-1"],
        )
        track["cel"]["per_rule"]["CEL_TEST"].update(suppressed=1, rollouts=["enforce"])
        malicious = track["sample_outcomes"]["mal-1"]
        malicious["findings"][0]["cel_decisions"][0]["rollout"] = "enforce"
        benign = track["sample_outcomes"]["benign-1"]
        benign.update(actionable=False, signal=False, findings=[])
        benign["cel_suppressed"] = [
            {
                "rule_id": "CEL_TEST",
                "category": "command_execution",
                "severity": "MEDIUM",
                "analyzer": "static",
                "count": 1,
                "expression_hash": "expression-hash",
                "pack": "core",
                "rollout": "enforce",
            }
        ]
        for dimension in ("per_source", "per_structural_family", "per_category"):
            for group in track[dimension].values():
                group["cel"]["modes"] = ["enforce"]
        candidates.append(candidate)

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
        promoted_rule_ids=["CEL_TEST"],
    )

    rule = result["rule_promotion_evidence"]["CEL_TEST"]
    assert result["status"] == "passed"
    assert rule["normalized_loss_evidence_status"] == "computed_exact_sample_outcomes"
    assert rule["normalized_loss_evidence_exact"] is True
    assert rule["baseline_actionable_fp_sample_ids"] == ["source-disjoint-core:benign-1"]
    assert rule["candidate_actionable_fp_sample_ids"] == []
    assert rule["resolved_actionable_fp_sample_ids"] == ["source-disjoint-core:benign-1"]
    assert rule["relative_actionable_fp_reduction"] == 1.0
    assert rule["passes_twenty_percent_reduction"] is True
    assert rule["eligible_for_promotion"] is True
    assert len(rule["normalized_loss_population_sha256"]) == 64
    assert len(rule["normalized_loss_generation_sha256"]) == 64


def test_five_run_comparison_rejects_unstable_output_or_generation() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]
    candidates[4]["tracks"]["source-disjoint-core"]["sample_outcomes"]["benign-1"]["actionable"] = False

    unstable = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        require_rule_promotion_evidence=False,
    )

    assert unstable["status"] == "failed"
    assert unstable["stable_output"] is False

    candidates = [_report(candidate=True) for _ in range(5)]
    candidates[4]["evidence_identity"]["build_sha256"] = "1" * 64
    with pytest.raises(BenchmarkComparisonError, match="build_sha256"):
        compare_repeated_benchmark_reports(
            _report(),
            candidates,
            require_rule_promotion_evidence=False,
        )


def test_rule_without_twenty_percent_reduction_blocks_repeated_promotion() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]
    for candidate in candidates:
        track = candidate["tracks"]["source-disjoint-core"]
        finding = track["sample_outcomes"]["benign-1"]["findings"][0]
        finding["cel_decision"] = "keep"
        finding["cel_decisions"][0]["decision"] = "keep"
        finding["cel_decisions"][0]["reason"] = "expression_true"
        track["cel"]["would_suppress"] = 0
        track["cel"]["would_suppress_sample_ids"] = []
        track["cel"]["per_rule"]["CEL_TEST"].update(keep=2, would_suppress=0)

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
        promoted_rule_ids=["CEL_TEST"],
    )

    assert result["status"] == "failed"
    rule = result["rule_promotion_evidence"]["CEL_TEST"]
    assert rule["observed_would_suppress_benign_candidates"] == 0
    assert rule["relative_actionable_fp_reduction"] is None
    assert rule["eligible_for_promotion"] is False


def test_rule_promotion_requires_independent_fixture_coverage() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        promoted_rule_ids=["CEL_TEST"],
    )

    assert result["status"] == "failed"
    rule = result["rule_promotion_evidence"]["CEL_TEST"]
    assert rule["has_true_positive_fixture"] is False
    assert rule["has_benign_near_miss_fixture"] is False
    assert rule["has_boundary_fixture"] is False
    assert rule["eligible_for_promotion"] is False


def test_sample_cel_decisions_must_match_runtime_telemetry() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]
    candidates[0]["tracks"]["source-disjoint-core"]["sample_outcomes"]["mal-1"]["findings"][0]["cel_decision"] = (
        "fallback"
    )
    candidates[0]["tracks"]["source-disjoint-core"]["sample_outcomes"]["mal-1"]["findings"][0]["cel_decisions"][0][
        "decision"
    ] = "fallback"

    with pytest.raises(BenchmarkComparisonError, match="fallback outcomes disagree with telemetry"):
        compare_repeated_benchmark_reports(
            _report(),
            candidates,
            rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
            promoted_rule_ids=["CEL_TEST"],
        )


def test_promotion_evidence_is_restricted_to_explicit_rule_ids() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]
    for candidate in candidates:
        track = candidate["tracks"]["source-disjoint-core"]
        track["sample_outcomes"]["mal-1"]["findings"].append(
            {
                "rule_id": "CEL_SHADOW_ONLY",
                "category": "command_execution",
                "severity": "HIGH",
                "cel_decision": "keep",
                "cel_decisions": [
                    {
                        "rule_id": "CEL_SHADOW_ONLY",
                        "decision": "keep",
                        "reason": "expression_true",
                        "fact_schema": "v1",
                        "expression_hash": "2" * 64,
                        "pack": "core",
                        "rollout": "shadow",
                        "count": 1,
                    }
                ],
            }
        )
        track["cel"]["per_rule"]["CEL_SHADOW_ONLY"] = {
            "keep": 1,
            "would_suppress": 0,
            "fallback": 0,
            "suppressed": 0,
            "expression_hashes": ["2" * 64],
            "packs": ["core"],
            "rollouts": ["shadow"],
        }

    result = compare_repeated_benchmark_reports(
        _report(),
        candidates,
        rule_fixture_evidence=_RULE_FIXTURE_EVIDENCE,
        promoted_rule_ids=["CEL_TEST"],
    )

    assert result["status"] == "failed"
    assert set(result["rule_promotion_evidence"]) == {"CEL_TEST"}
    assert result["rule_promotion_evidence"]["CEL_TEST"]["normalized_loss_evidence_exact"] is False


def test_enforce_mode_rollouts_must_match_explicit_promotion_set() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]
    for candidate in candidates:
        candidate["cel_mode"] = "enforce"
        candidate["evidence_identity"]["cel_mode"] = "enforce"
        candidate["summary"]["cel"]["modes"] = ["enforce"]
        track = candidate["tracks"]["source-disjoint-core"]
        track["cel"]["modes"] = ["enforce"]
        for dimension in ("per_source", "per_structural_family", "per_category"):
            for group in track[dimension].values():
                group["cel"]["modes"] = ["enforce"]

    with pytest.raises(BenchmarkComparisonError, match="explicit promoted rule set"):
        compare_repeated_benchmark_reports(
            _report(),
            candidates,
            promoted_rule_ids=["CEL_TEST"],
            require_rule_promotion_evidence=False,
        )


def test_enforced_rule_cannot_retain_would_suppress_lineage() -> None:
    candidates = [_report(candidate=True) for _ in range(5)]
    for candidate in candidates:
        candidate["cel_mode"] = "enforce"
        candidate["evidence_identity"]["cel_mode"] = "enforce"
        candidate["summary"]["cel"]["modes"] = ["enforce"]
        track = candidate["tracks"]["source-disjoint-core"]
        track["cel"]["modes"] = ["enforce"]
        track["cel"]["per_rule"]["CEL_TEST"]["rollouts"] = ["enforce"]
        for outcome in track["sample_outcomes"].values():
            for finding in outcome["findings"]:
                for decision in finding["cel_decisions"]:
                    decision["rollout"] = "enforce"
        for dimension in ("per_source", "per_structural_family", "per_category"):
            for group in track[dimension].values():
                group["cel"]["modes"] = ["enforce"]

    with pytest.raises(BenchmarkComparisonError, match="retained false CEL decisions"):
        compare_repeated_benchmark_reports(
            _report(),
            candidates,
            promoted_rule_ids=["CEL_TEST"],
            require_rule_promotion_evidence=False,
        )
