# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

import pytest

from evals.runners import cel_promotion_audit
from evals.runners.benchmark_comparison import BenchmarkComparisonError
from evals.runners.cel_promotion_audit import (
    AUDIT_PROFILE,
    DEFAULT_EXPECTED_RULE_COUNT,
    TRACK_NAME,
    CelPromotionAuditError,
    _accumulate_sample_incidence,
    _blank_rule_accumulator,
    _detection_output_sha256,
    _finalize_rule_incidence,
    _generation_from_scanner,
    assemble_audit_summary,
    build_parser,
    compact_audit_report,
    main,
    select_joint_train_validation,
)
from evals.runners.public_dataset_benchmark import FrozenSample, FrozenSnapshot
from skill_scanner.core.cel.models import CelRollout, CelRule, expression_set_hash
from skill_scanner.core.models import Finding, Severity, ThreatCategory
from tests.test_benchmark_comparison import _report as _comparison_report


def _sample(
    benchmark_id: str,
    label: str,
    source_split: str,
    structural_split: str,
) -> FrozenSample:
    return FrozenSample(
        benchmark_id=benchmark_id,
        label=label,
        source_id=f"source-{benchmark_id}",
        structural_family_id=f"family-{benchmark_id}",
        category_ids=("benign" if label == "benign" else "command_execution",),
        relative_path=PurePosixPath(f"skills/{benchmark_id}"),
        splits={
            "source_disjoint": source_split,
            "m_structural_disjoint": structural_split,
        },
    )


def _snapshot(
    tmp_path: Path, samples: tuple[FrozenSample, ...], *, quarantined: tuple[str, ...] = ()
) -> FrozenSnapshot:
    return FrozenSnapshot(
        root=tmp_path,
        dataset={"id": "ProtectSkills/MaliciousSkillBench", "revision": "a" * 40},
        artifact_manifest_sha256="b" * 64,
        usable_artifact_manifest_sha256="c" * 64,
        quarantine_manifest_sha256="d" * 64 if quarantined else None,
        quarantined_sample_ids=quarantined,
        samples=samples,
    )


def _finding(rule_id: str, severity: Severity, lineage: list[dict[str, object]], *, deduped_count: int = 0) -> Finding:
    return Finding(
        id=f"{rule_id}-1",
        rule_id=rule_id,
        category=ThreatCategory.COMMAND_INJECTION,
        severity=severity,
        title="test",
        description="test",
        file_path="SKILL.md",
        line_number=1,
        analyzer="static",
        metadata={"cel_decisions": lineage, "deduped_count": deduped_count},
    )


def _plain_finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        id=f"{rule_id}-1",
        rule_id=rule_id,
        category=ThreatCategory.COMMAND_INJECTION,
        severity=severity,
        title="test",
        description="test",
        file_path="OTHER.md",
        line_number=2,
        analyzer="static",
    )


def _lineage(rule: CelRule, decision: str, *, count: int = 1) -> dict[str, object]:
    return {
        "rule_id": rule.rule_id,
        "decision": decision,
        "reason": "expression_true" if decision == "keep" else "shadow_or_rule_rollout",
        "fact_schema": rule.fact_schema,
        "expression_hash": rule.expression_hash,
        "pack": rule.pack_name,
        "rollout": rule.rollout.value,
        "count": count,
    }


def _compact_worker_report(*, shadow: bool, invocation: int) -> dict[str, Any]:
    """Adapt the comparator's contract fixture into one compact audit worker."""

    report = _comparison_report(candidate=shadow)
    candidate_template = _comparison_report(candidate=True)
    if not shadow:
        for scope, target in (
            (report["summary"], candidate_template["summary"]),
            (
                next(iter(report["tracks"].values())),
                next(iter(candidate_template["tracks"].values())),
            ),
        ):
            for field in (
                "precision",
                "recall",
                "package_block_precision",
                "package_block_recall",
                "signal_recall",
                "macro_f1",
                "benign_actionable_fpr",
                "critical_high_false_negatives",
                "critical_high_false_negative_ids",
                "confidence_intervals_95",
            ):
                scope[field] = copy.deepcopy(target[field])

    old_track = next(iter(report["tracks"].values()))
    old_track["name"] = TRACK_NAME
    old_track["detector_profile"] = "core_only"
    old_track["protocol"] = "joint_train_validation_v1"
    old_track["partition"] = "train_validation_intersection"
    old_track["per_source"] = {}
    old_track["per_structural_family"] = {}
    old_track["per_category"] = {}
    old_track["detection_output_sha256"] = "3" * 64

    expression_hash = "1" * 64
    identity = {
        "pack": "core",
        "rollout": "shadow",
        "fact_schema": "v1",
        "expression_hash": expression_hash,
    }
    decisions = (
        {"keep": 1, "would_suppress": 1, "fallback": 0}
        if shadow
        else {
            "keep": 0,
            "would_suppress": 0,
            "fallback": 0,
        }
    )
    promotion_accumulators = {"CEL_TEST": _blank_rule_accumulator(identity)}
    promotion_accumulators["CEL_TEST"]["benign"]["decisions"].update(decisions)
    empty_baseline: dict[str, dict[str, set[str]]] = {
        label: {field: set() for field in ("with_findings", "blocked", "actionable", "signal")}
        for label in ("benign", "malicious")
    }
    promotion_rule = _finalize_rule_incidence(
        promotion_accumulators,
        empty_baseline,
        {
            "cel": {
                "per_rule": {
                    "CEL_TEST": {
                        **decisions,
                        "suppressed": 0,
                        "expression_hashes": [expression_hash],
                        "packs": ["core"],
                        "rollouts": ["shadow"],
                    }
                },
                "error_counts": {},
            }
        },
    )["CEL_TEST"]
    old_track["promotion_audit"] = {
        "baseline_package_counts": {},
        "per_rule": {"CEL_TEST": promotion_rule},
        "malicious_blocking_candidate_attestation_requirements": (
            cel_promotion_audit._finalize_attestation_requirements({})
        ),
    }
    if shadow:
        old_track["cel"]["per_rule"]["CEL_TEST"]["expression_hashes"] = [expression_hash]
        report["summary"]["cel"]["per_rule"]["CEL_TEST"]["expression_hashes"] = [expression_hash]
        for outcome in old_track["sample_outcomes"].values():
            for finding in outcome["findings"]:
                for entry in finding["cel_decisions"]:
                    entry["expression_hash"] = expression_hash
    report["tracks"] = {TRACK_NAME: old_track}
    report["profile"] = AUDIT_PROFILE
    report["release_blocking"] = False
    report["producer"]["source_revision"] = "5" * 40
    report["identity_verification"]["start"]["source_revision"] = "5" * 40
    report["identity_verification"]["end"]["source_revision"] = "5" * 40
    report["worker_invocation_id"] = f"{invocation:032x}"
    report["audit_harness_sha256"] = cel_promotion_audit._audit_harness_sha256()
    report["dataset"]["usable_artifact_manifest_sha256"] = "c" * 64
    report["dataset"]["selection"] = {"population_sha256": "4" * 64}
    report["cel_generation"] = {
        "expected_rule_count": 1,
        "observed_rule_count": 1,
        "expression_set_hash": "a" * 64,
        "rules": {"CEL_TEST": identity},
    }
    report["limitations"] = []
    return compact_audit_report(report)


def _reports_with_malicious_blocking_candidate() -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any],
]:
    baseline_report = _compact_worker_report(shadow=False, invocation=1)
    candidate_reports = [_compact_worker_report(shadow=True, invocation=index) for index in range(2, 7)]
    identity = {
        "pack": "core",
        "rollout": "shadow",
        "fact_schema": "v1",
        "expression_hash": "1" * 64,
    }
    accumulators = {"CEL_TEST": _blank_rule_accumulator(identity)}
    baseline_packages: dict[str, dict[str, set[str]]] = {
        label: {field: set() for field in ("with_findings", "blocked", "actionable", "signal")}
        for label in ("benign", "malicious")
    }
    would_suppress = {
        "rule_id": "CEL_TEST",
        "decision": "would_suppress",
        "reason": "shadow_or_rule_rollout",
        "fact_schema": "v1",
        "expression_hash": "1" * 64,
        "pack": "core",
        "rollout": "shadow",
        "count": 1,
    }
    _accumulate_sample_incidence(
        accumulators,
        baseline_packages,
        _sample("benign-near-miss", "benign", "train", "validation"),
        SimpleNamespace(findings=[_finding("CEL_TEST", Severity.HIGH, [would_suppress])]),
    )
    requirements: dict[str, dict[str, Any]] = {}
    _accumulate_sample_incidence(
        accumulators,
        baseline_packages,
        _sample("malicious-with-independent-high", "malicious", "validation", "train"),
        SimpleNamespace(
            findings=[
                _finding("CEL_TEST", Severity.HIGH, [would_suppress]),
                _plain_finding("INDEPENDENT_HIGH", Severity.HIGH),
            ]
        ),
        attestation_requirements=requirements,
        sample_content_sha256="6" * 64,
    )
    telemetry = {
        "cel": {
            "per_rule": {
                "CEL_TEST": {
                    "keep": 0,
                    "would_suppress": 2,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": ["1" * 64],
                    "packs": ["core"],
                    "rollouts": ["shadow"],
                }
            },
            "error_counts": {},
        }
    }
    promotion = {
        "baseline_package_counts": {
            label: {field: len(values) for field, values in sorted(fields.items())}
            for label, fields in sorted(baseline_packages.items())
        },
        "per_rule": _finalize_rule_incidence(accumulators, baseline_packages, telemetry),
        "malicious_blocking_candidate_attestation_requirements": (
            cel_promotion_audit._finalize_attestation_requirements(requirements)
        ),
    }
    for report in candidate_reports:
        report["tracks"][TRACK_NAME]["promotion_audit"] = copy.deepcopy(promotion)
    return baseline_report, candidate_reports, promotion


def _attestation_reason(label: str) -> str:
    return {
        "benign_non_actionable": "benign_prose_term",
        "actionable": "active_privilege_operation",
        "ambiguous": "insufficient_context",
        "abstain": "provider_error",
    }[label]


def _candidate_attestation_bundle(
    report: dict[str, Any],
    promotion: dict[str, Any],
    *,
    accepted_label: str = "benign_non_actionable",
    second_pass_label: str | None = None,
    deterministic_label: str = "benign_non_actionable",
    label_source: str = "independent_ollama",
) -> dict[str, Any]:
    requirements = promotion["malicious_blocking_candidate_attestation_requirements"]
    binding = cel_promotion_audit._candidate_attestation_expected_binding(
        report,
        report["cel_generation"],
        requirements,
    )
    pass_contract = [{"pass_id": "pass-a", "seed": 101}, {"pass_id": "pass-b", "seed": 202}]
    provenance: dict[str, Any]
    if label_source == "independent_ollama":
        provenance = {
            "corpus_id": "synthetic-independent-corpus-v1",
            "report_sha256": "7" * 64,
            "scanner_outputs_used_as_labels": False,
        }
    else:
        provenance = {
            "agent_id": "independent-security-review-agent",
            "agent_definition_sha256": "7" * 64,
            "run_id": "synthetic-run-v1",
            "scanner_outputs_used_as_labels": False,
        }
    candidates: dict[str, Any] = {}
    global_counts = cel_promotion_audit._empty_attestation_counts()
    per_rule: dict[str, dict[str, int]] = {}
    labels = [accepted_label, second_pass_label or accepted_label]
    for candidate_id, requirement in sorted(requirements["candidates"].items()):
        passes = [
            {
                **contract,
                "label": label,
                "reason_code": _attestation_reason(label),
                "request_sha256": cel_promotion_audit._domain_sha256(
                    b"test-candidate-attestation-request-v1",
                    {"candidate_id": candidate_id, "pass_id": contract["pass_id"]},
                ),
                "response_sha256": cel_promotion_audit._domain_sha256(
                    b"test-candidate-attestation-response-v1",
                    {"candidate_id": candidate_id, "pass_id": contract["pass_id"], "label": label},
                ),
            }
            for contract, label in zip(pass_contract, labels, strict=True)
        ]
        agreement = labels[0] == labels[1]
        normalized_label = labels[0] if agreement else "abstain"
        candidates[candidate_id] = {
            **requirement,
            "deterministic": {
                "label": deterministic_label,
                "reason_code": _attestation_reason(deterministic_label),
            },
            "passes": passes,
            "accepted_label": normalized_label,
        }
        rule_counts = per_rule.setdefault(requirement["rule_id"], cel_promotion_audit._empty_attestation_counts())
        for counts in (global_counts, rule_counts):
            counts["candidate_count"] += 1
            if normalized_label != "abstain":
                counts["accepted"] += 1
            if normalized_label == "actionable":
                counts["actionable"] += 1
            elif normalized_label == "ambiguous":
                counts["ambiguous"] += 1
            elif normalized_label == "abstain":
                counts["abstained"] += 1
            if not agreement:
                counts["disagreements"] += 1
            if "provider_error" in {item["reason_code"] for item in passes}:
                counts["provider_errors"] += 1
    document = {
        "schema_version": 1,
        "purpose": "cel_malicious_blocking_candidate_attestations",
        "label_source": label_source,
        "binding": binding,
        "adjudicator": {
            "model_name": "qwen3.5:9b-mlx",
            "model_digest": "8" * 64,
            "rubric_sha256": "9" * 64,
            "prompt_sha256": "a" * 64,
            "options_sha256": "b" * 64,
            "provenance": provenance,
            "provenance_sha256": cel_promotion_audit._candidate_attestation_provenance_sha256(
                label_source,
                provenance,
            ),
            "deterministic_check_sha256": "c" * 64,
            "passes": pass_contract,
        },
        "candidates": candidates,
        "summary": {
            **global_counts,
            "per_rule": {rule_id: counts for rule_id, counts in sorted(per_rule.items())},
        },
        "evidence_sha256": "0" * 64,
    }
    document["evidence_sha256"] = cel_promotion_audit.candidate_attestation_bundle_sha256(document)
    return document


def test_joint_selection_is_intersection_and_accounts_for_quarantine(tmp_path: Path) -> None:
    samples = (
        _sample("train-train-quarantine", "benign", "train", "train"),
        _sample("train-validation", "malicious", "train", "validation"),
        _sample("validation-train", "benign", "validation", "train"),
        _sample("source-test", "malicious", "test", "train"),
        _sample("structural-test", "malicious", "train", "test"),
        _sample("excluded", "benign", "excluded", "validation"),
    )
    snapshot = _snapshot(tmp_path, samples, quarantined=("train-train-quarantine",))

    population = select_joint_train_validation(snapshot)

    assert [sample.benchmark_id for sample in population.samples] == ["train-validation", "validation-train"]
    assert population.declared_samples == 3
    assert population.usable_samples == 2
    assert population.malicious == 1
    assert population.benign == 1
    assert population.quarantined_samples == 1
    assert population.excluded_union_holdout == 3
    assert len(population.population_sha256) == 64


def test_joint_population_digest_is_order_independent(tmp_path: Path) -> None:
    samples = (
        _sample("a", "benign", "train", "validation"),
        _sample("b", "malicious", "validation", "train"),
    )
    forward = select_joint_train_validation(_snapshot(tmp_path, samples))
    reverse = select_joint_train_validation(_snapshot(tmp_path, tuple(reversed(samples))))

    assert forward.population_sha256 == reverse.population_sha256
    assert forward == reverse


def test_generation_is_derived_but_expected_count_is_fail_closed() -> None:
    rules = [
        CelRule("RULE_A", "f.projection.complete", pack_name="core"),
        CelRule(
            "RULE_B",
            "f.candidate.severity == 'HIGH'",
            rollout=CelRollout.SHADOW,
            pack_name="atr",
        ),
    ]
    scanner = SimpleNamespace(
        cel_gate=SimpleNamespace(
            rules={rule.rule_id: rule for rule in rules},
            expression_set_hash=expression_set_hash(rules),
        )
    )

    generation = _generation_from_scanner(scanner, expected_rule_count=2)

    assert generation["observed_rule_count"] == 2
    assert set(generation["rules"]) == {"RULE_A", "RULE_B"}
    with pytest.raises(CelPromotionAuditError, match="expected exactly 3"):
        _generation_from_scanner(scanner, expected_rule_count=3)


def test_per_rule_incidence_and_single_rule_counterfactual_are_label_separated() -> None:
    rule_a = CelRule("RULE_A", "f.projection.complete", pack_name="core")
    rule_b = CelRule("RULE_B", "f.projection.complete", pack_name="atr")
    identities = {
        rule.rule_id: {
            "pack": rule.pack_name,
            "rollout": rule.rollout.value,
            "fact_schema": rule.fact_schema,
            "expression_hash": rule.expression_hash,
        }
        for rule in (rule_a, rule_b)
    }
    accumulators = {rule_id: _blank_rule_accumulator(identity) for rule_id, identity in identities.items()}
    baseline: dict[str, dict[str, set[str]]] = {
        label: {field: set() for field in ("with_findings", "blocked", "actionable", "signal")}
        for label in ("benign", "malicious")
    }

    benign = _sample("benign", "benign", "train", "train")
    benign_result = SimpleNamespace(findings=[_finding("RULE_A", Severity.HIGH, [_lineage(rule_a, "would_suppress")])])
    _accumulate_sample_incidence(accumulators, baseline, benign, benign_result)

    malicious = _sample("malicious", "malicious", "train", "validation")
    # RULE_A's false candidate is merged with RULE_B's retained candidate, so
    # isolated enforcement of RULE_A must not remove the final HIGH finding.
    malicious_result = SimpleNamespace(
        findings=[
            _finding(
                "RULE_A",
                Severity.HIGH,
                [_lineage(rule_a, "would_suppress"), _lineage(rule_b, "keep")],
                deduped_count=1,
            )
        ]
    )
    _accumulate_sample_incidence(accumulators, baseline, malicious, malicious_result)
    track = {
        "cel": {
            "per_rule": {
                "RULE_A": {
                    "keep": 0,
                    "would_suppress": 2,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": [rule_a.expression_hash],
                    "packs": ["core"],
                    "rollouts": ["shadow"],
                },
                "RULE_B": {
                    "keep": 1,
                    "would_suppress": 0,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": [rule_b.expression_hash],
                    "packs": ["atr"],
                    "rollouts": ["shadow"],
                },
            },
            "error_counts": {},
        }
    }

    result = _finalize_rule_incidence(accumulators, baseline, track)

    benign_a = result["RULE_A"]["benign"]
    assert benign_a["candidate_findings"]["would_suppress"] == 1
    assert benign_a["counterfactual_single_rule_enforcement"]["blocked_packages"]["delta"] == -1
    assert benign_a["counterfactual_single_rule_enforcement"]["signal_packages"]["delta"] == -1
    assert (
        benign_a["counterfactual_single_rule_enforcement"]["relative_actionable_package_reduction_lower_bound"] == 1.0
    )
    assert benign_a["counterfactual_finding_classification"]["actionable"]["known_lost"]["count"] == 1
    assert benign_a["counterfactual_finding_classification"]["actionable"]["relative_targeted_loss_lower_bound"] == 1.0
    malicious_a = result["RULE_A"]["malicious"]
    assert malicious_a["counterfactual_single_rule_enforcement"]["blocked_packages"]["delta"] == 0
    assert malicious_a["counterfactual_single_rule_enforcement"]["blocked_packages"]["exact"] is False
    assert malicious_a["counterfactual_single_rule_enforcement"]["blocked_packages"]["delta_range"] == [-1, 0]
    assert malicious_a["counterfactual_single_rule_enforcement"]["signal_packages"]["delta"] == 0
    assert result["RULE_A"]["potentially_promotable_from_this_audit"] is False
    assert result["RULE_B"]["malicious"]["candidate_findings"]["keep"] == 1


def test_malicious_blocking_finding_loss_blocks_promotion_even_when_package_stays_blocked() -> None:
    rule = CelRule("RULE_A", "f.projection.complete", pack_name="core")
    identity = {
        "pack": rule.pack_name,
        "rollout": rule.rollout.value,
        "fact_schema": rule.fact_schema,
        "expression_hash": rule.expression_hash,
    }
    accumulators = {"RULE_A": _blank_rule_accumulator(identity)}
    baseline: dict[str, dict[str, set[str]]] = {
        label: {field: set() for field in ("with_findings", "blocked", "actionable", "signal")}
        for label in ("benign", "malicious")
    }
    benign = _sample("benign", "benign", "train", "train")
    _accumulate_sample_incidence(
        accumulators,
        baseline,
        benign,
        SimpleNamespace(findings=[_finding("RULE_A", Severity.HIGH, [_lineage(rule, "would_suppress")])]),
    )
    malicious = _sample("malicious", "malicious", "validation", "train")
    _accumulate_sample_incidence(
        accumulators,
        baseline,
        malicious,
        SimpleNamespace(
            findings=[
                _finding("RULE_A", Severity.HIGH, [_lineage(rule, "would_suppress")]),
                _plain_finding("INDEPENDENT_HIGH", Severity.HIGH),
            ]
        ),
    )
    track = {
        "cel": {
            "per_rule": {
                "RULE_A": {
                    "keep": 0,
                    "would_suppress": 2,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": [rule.expression_hash],
                    "packs": ["core"],
                    "rollouts": ["shadow"],
                }
            },
            "error_counts": {},
        }
    }

    finalized = _finalize_rule_incidence(accumulators, baseline, track)["RULE_A"]

    malicious_effect = finalized["malicious"]
    assert malicious_effect["counterfactual_single_rule_enforcement"]["blocked_packages"]["delta"] == 0
    blocking_findings = malicious_effect["counterfactual_finding_classification"]["blocking"]
    assert blocking_findings["known_lost"]["count"] == 1
    assert blocking_findings["indeterminate"]["count"] == 0
    assert finalized["potentially_promotable_from_this_audit"] is False


def test_non_cel_deduped_support_prevents_counterfactual_finding_loss() -> None:
    rule = CelRule("RULE_A", "f.projection.complete", pack_name="core")
    identity = {
        "pack": "core",
        "rollout": "shadow",
        "fact_schema": "v1",
        "expression_hash": rule.expression_hash,
    }
    accumulators = {"RULE_A": _blank_rule_accumulator(identity)}
    baseline: dict[str, dict[str, set[str]]] = {
        label: {field: set() for field in ("with_findings", "blocked", "actionable", "signal")}
        for label in ("benign", "malicious")
    }
    sample = _sample("benign", "benign", "train", "train")
    # Group size is two but only one member has CEL lineage.
    result = SimpleNamespace(
        findings=[_finding("RULE_A", Severity.HIGH, [_lineage(rule, "would_suppress")], deduped_count=1)]
    )
    _accumulate_sample_incidence(accumulators, baseline, sample, result)
    track = {
        "cel": {
            "per_rule": {
                "RULE_A": {
                    "keep": 0,
                    "would_suppress": 1,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": [rule.expression_hash],
                    "packs": ["core"],
                    "rollouts": ["shadow"],
                }
            },
            "error_counts": {},
        }
    }

    finalized = _finalize_rule_incidence(accumulators, baseline, track)

    assert finalized["RULE_A"]["benign"]["normalized_findings"]["counterfactual_lost"] == 0
    assert finalized["RULE_A"]["benign"]["counterfactual_single_rule_enforcement"]["blocked_packages"]["delta"] == 0


def test_detection_hash_ignores_only_cel_observation_fields() -> None:
    base: dict[str, Any] = {
        "sample": {
            "label": "benign",
            "blocked": True,
            "cel_suppressed": [],
            "findings": [
                {
                    "rule_id": "RULE_A",
                    "category": "command_injection",
                    "severity": "HIGH",
                    "cel_decision": None,
                    "cel_decisions": [],
                }
            ],
        }
    }
    shadow = {
        "sample": {
            **base["sample"],
            "findings": [
                {
                    **base["sample"]["findings"][0],
                    "cel_decision": "would_suppress",
                    "cel_decisions": [{"rule_id": "RULE_A", "decision": "would_suppress", "count": 1}],
                }
            ],
        }
    }

    assert _detection_output_sha256(base) == _detection_output_sha256(shadow)
    changed = {"sample": {**shadow["sample"], "blocked": False}}
    assert _detection_output_sha256(base) != _detection_output_sha256(changed)


def test_compaction_is_explicitly_non_release() -> None:
    report: dict[str, Any] = {
        "summary": {},
        "tracks": {
            "development": {
                "sample_outcomes": {},
                "per_source": {},
                "per_structural_family": {},
                "per_category": {},
            }
        },
    }

    compact = compact_audit_report(report)

    assert "release_evidence" not in compact
    assert compact["audit_evidence"]["format"] == "compact-v3"
    assert compact["audit_evidence"]["release_blocking"] is False


def test_cli_defaults_to_exact_current_rule_count_and_assembler_requires_five() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "worker",
            "--snapshot-dir",
            "/tmp/snapshot",
            "--dataset-id",
            "ProtectSkills/MaliciousSkillBench",
            "--dataset-lock",
            "/tmp/lock.json",
            "--cel-mode",
            "shadow",
            "--output",
            "/tmp/output.json",
        ]
    )
    assert DEFAULT_EXPECTED_RULE_COUNT == 8
    assert args.expected_rule_count == DEFAULT_EXPECTED_RULE_COUNT
    with pytest.raises(CelPromotionAuditError, match="exactly 5 shadow"):
        assemble_audit_summary({}, [{}, {}, {}, {}])


def test_compact_v3_off_plus_five_shadow_reports_assemble_successfully() -> None:
    baseline = _compact_worker_report(shadow=False, invocation=1)
    candidates = [_compact_worker_report(shadow=True, invocation=index) for index in range(2, 7)]

    summary = assemble_audit_summary(baseline, candidates, expected_rule_count=1)

    assert summary["status"] == "passed"
    assert summary["checks"]["five_stable_shadow_outputs"] is True
    assert summary["stability"]["worker_invocation_ids"] == [f"{index:032x}" for index in range(1, 7)]
    assert set(summary["per_rule"]) == {"CEL_TEST"}


def test_assembler_rejects_replayed_shadow_worker() -> None:
    baseline = _compact_worker_report(shadow=False, invocation=1)
    candidate = _compact_worker_report(shadow=True, invocation=2)

    with pytest.raises(CelPromotionAuditError, match="unique invocation"):
        assemble_audit_summary(baseline, [candidate] * 5, expected_rule_count=1)


def test_assembler_rejects_promotion_rule_set_different_from_generation() -> None:
    baseline = _compact_worker_report(shadow=False, invocation=1)
    candidates = [_compact_worker_report(shadow=True, invocation=index) for index in range(2, 7)]
    candidates[0]["cel_generation"]["rules"] = {"OTHER_RULE": candidates[0]["cel_generation"]["rules"]["CEL_TEST"]}

    with pytest.raises(CelPromotionAuditError, match="does not match the CEL generation"):
        assemble_audit_summary(baseline, candidates, expected_rule_count=1)


def test_audit_harness_hash_binds_imported_evaluator_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    original = cel_promotion_audit._audit_harness_sha256()
    monkeypatch.setattr(
        cel_promotion_audit,
        "_AUDIT_HARNESS_RELATIVE_PATHS",
        (*cel_promotion_audit._AUDIT_HARNESS_RELATIVE_PATHS, Path("pyproject.toml")),
    )

    assert cel_promotion_audit._audit_harness_sha256() != original


def test_cli_reports_comparator_contract_failure_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reports = [_compact_worker_report(shadow=False, invocation=1)]
    reports.extend(_compact_worker_report(shadow=True, invocation=index) for index in range(2, 7))
    paths: list[Path] = []
    for index, report in enumerate(reports):
        path = tmp_path / f"worker-{index}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        paths.append(path)

    def fail_comparison(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise BenchmarkComparisonError("synthetic comparator failure")

    monkeypatch.setattr(cel_promotion_audit, "compare_repeated_benchmark_reports", fail_comparison)
    arguments = [
        "assemble",
        "--baseline",
        str(paths[0]),
        "--expected-rule-count",
        "1",
        "--output",
        str(tmp_path / "summary.json"),
    ]
    for path in paths[1:]:
        arguments.extend(("--candidate", str(path)))

    assert main(arguments) == 1
    assert "synthetic comparator failure" in capsys.readouterr().err


def test_complete_independent_two_pass_benign_attestation_allows_development_promotion() -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(candidates[0], promotion)

    summary = assemble_audit_summary(
        baseline,
        candidates,
        expected_rule_count=1,
        candidate_attestations=bundle,
    )

    assert summary["status"] == "passed"
    assert summary["candidate_attestations"]["status"] == "complete"
    assert summary["candidate_attestations"]["expected_candidate_count"] == 1
    rule = summary["per_rule"]["CEL_TEST"]
    assert rule["potentially_promotable_from_this_audit"] is True
    assert rule["malicious_blocking_candidate_attestation"]["status"] == "complete_benign_non_actionable"
    assert rule["promotion_checks"]["zero_malicious_package_block_signal_loss"] is True


def test_rule_scoped_bundle_covers_every_declared_candidate_and_leaves_other_rules_unattested() -> None:
    _baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    original_requirements = promotion["malicious_blocking_candidate_attestation_requirements"]
    first_candidate = copy.deepcopy(next(iter(original_requirements["candidates"].values())))
    first_candidate["rule_id"] = "CEL_OTHER"
    first_candidate["expression_sha256"] = "2" * 64
    first_candidate["lineage_identity_sha256"] = "3" * 64
    first_candidate["candidate_identity_sha256"] = cel_promotion_audit._candidate_attestation_identity(first_candidate)
    all_candidates = {
        **original_requirements["candidates"],
        first_candidate["candidate_identity_sha256"]: first_candidate,
    }
    all_requirements = cel_promotion_audit._finalize_attestation_requirements(all_candidates)
    bundle = _candidate_attestation_bundle(candidates[0], promotion)

    scoped = cel_promotion_audit._scoped_attestation_requirements(bundle, all_requirements)
    assert scoped == cel_promotion_audit.scoped_candidate_attestation_requirements(
        all_requirements,
        ["CEL_TEST"],
    )
    expected_binding = cel_promotion_audit._candidate_attestation_expected_binding(
        candidates[0],
        candidates[0]["cel_generation"],
        scoped,
    )
    validation = cel_promotion_audit.validate_candidate_attestation_bundle(
        bundle,
        expected_binding=expected_binding,
        expected_requirements=scoped,
    )
    per_rule = copy.deepcopy(promotion["per_rule"])
    per_rule["CEL_OTHER"] = copy.deepcopy(per_rule["CEL_TEST"])
    per_rule["CEL_OTHER"]["identity"]["expression_hash"] = "2" * 64
    applied = cel_promotion_audit._apply_candidate_attestation_eligibility(
        per_rule,
        all_requirements,
        {**validation, "status": "complete_scoped"},
        aggregate_no_regression=True,
    )

    assert scoped["candidate_count"] == 1
    assert set(scoped["rule_expression_sha256"]) == {"CEL_TEST"}
    assert applied["CEL_TEST"]["potentially_promotable_from_this_audit"] is True
    assert applied["CEL_OTHER"]["potentially_promotable_from_this_audit"] is False
    assert applied["CEL_OTHER"]["malicious_blocking_candidate_attestation"]["status"] == "not_supplied"


def test_missing_attestation_is_nonfatal_but_disqualifies_affected_rule() -> None:
    baseline, candidates, _promotion = _reports_with_malicious_blocking_candidate()

    summary = assemble_audit_summary(baseline, candidates, expected_rule_count=1)

    assert summary["status"] == "passed"
    assert summary["candidate_attestations"]["status"] == "not_supplied"
    rule = summary["per_rule"]["CEL_TEST"]
    assert rule["potentially_promotable_from_this_audit"] is False
    assert rule["malicious_blocking_candidate_attestation"]["status"] == "not_supplied"


def test_aggregate_recall_or_macro_f1_regression_disqualifies_attested_rule() -> None:
    _baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    requirements = promotion["malicious_blocking_candidate_attestation_requirements"]
    bundle = _candidate_attestation_bundle(candidates[0], promotion)
    validation = cel_promotion_audit.validate_candidate_attestation_bundle(
        bundle,
        expected_binding=cel_promotion_audit.candidate_attestation_expected_binding(
            candidates[0],
            candidates[0]["cel_generation"],
            requirements,
        ),
        expected_requirements=requirements,
    )

    applied = cel_promotion_audit._apply_candidate_attestation_eligibility(
        promotion["per_rule"],
        requirements,
        validation,
        aggregate_no_regression=False,
    )

    assert applied["CEL_TEST"]["potentially_promotable_from_this_audit"] is False
    assert applied["CEL_TEST"]["promotion_checks"]["aggregate_recall_macro_f1_no_regression"] is False


def test_partial_attestation_bundle_is_rejected_even_when_rehashed() -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(candidates[0], promotion)
    bundle["candidates"].clear()
    bundle["evidence_sha256"] = cel_promotion_audit.candidate_attestation_bundle_sha256(bundle)

    with pytest.raises(CelPromotionAuditError, match="exact bounded candidate identity set"):
        assemble_audit_summary(
            baseline,
            candidates,
            expected_rule_count=1,
            candidate_attestations=bundle,
        )


def test_spoofed_scanner_agent_attestation_is_rejected_even_when_rehashed() -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(candidates[0], promotion, label_source="agent_labeled")
    provenance = bundle["adjudicator"]["provenance"]
    provenance["agent_id"] = "skill-scanner-labeler"
    bundle["adjudicator"]["provenance_sha256"] = cel_promotion_audit._candidate_attestation_provenance_sha256(
        "agent_labeled", provenance
    )
    bundle["evidence_sha256"] = cel_promotion_audit.candidate_attestation_bundle_sha256(bundle)

    with pytest.raises(CelPromotionAuditError, match="scanner-independent"):
        assemble_audit_summary(
            baseline,
            candidates,
            expected_rule_count=1,
            candidate_attestations=bundle,
        )


def test_tampered_sample_content_binding_is_rejected_even_when_bundle_is_rehashed() -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(candidates[0], promotion)
    candidate = next(iter(bundle["candidates"].values()))
    candidate["sample_content_sha256"] = "d" * 64
    bundle["evidence_sha256"] = cel_promotion_audit.candidate_attestation_bundle_sha256(bundle)

    with pytest.raises(CelPromotionAuditError, match="audited candidate identity"):
        assemble_audit_summary(
            baseline,
            candidates,
            expected_rule_count=1,
            candidate_attestations=bundle,
        )


@pytest.mark.parametrize("label", ["actionable", "ambiguous", "abstain"])
def test_nonbenign_or_abstaining_two_pass_attestation_disqualifies_rule(label: str) -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(candidates[0], promotion, accepted_label=label)

    summary = assemble_audit_summary(
        baseline,
        candidates,
        expected_rule_count=1,
        candidate_attestations=bundle,
    )

    rule = summary["per_rule"]["CEL_TEST"]
    assert rule["potentially_promotable_from_this_audit"] is False
    assert rule["malicious_blocking_candidate_attestation"]["status"] == "complete_disqualifying_labels"


def test_two_pass_disagreement_is_canonical_abstention_and_disqualifies_rule() -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(
        candidates[0],
        promotion,
        accepted_label="benign_non_actionable",
        second_pass_label="ambiguous",
    )

    summary = assemble_audit_summary(
        baseline,
        candidates,
        expected_rule_count=1,
        candidate_attestations=bundle,
    )

    attestation = summary["per_rule"]["CEL_TEST"]["malicious_blocking_candidate_attestation"]
    assert attestation["abstained"] == 1
    assert attestation["disagreements"] == 1
    assert summary["per_rule"]["CEL_TEST"]["potentially_promotable_from_this_audit"] is False


def test_ambiguous_deterministic_check_disqualifies_otherwise_benign_model_agreement() -> None:
    baseline, candidates, promotion = _reports_with_malicious_blocking_candidate()
    bundle = _candidate_attestation_bundle(
        candidates[0],
        promotion,
        deterministic_label="ambiguous",
    )

    summary = assemble_audit_summary(
        baseline,
        candidates,
        expected_rule_count=1,
        candidate_attestations=bundle,
    )

    attestation = summary["per_rule"]["CEL_TEST"]["malicious_blocking_candidate_attestation"]
    assert attestation["deterministic_disqualifying"] == 1
    assert summary["per_rule"]["CEL_TEST"]["potentially_promotable_from_this_audit"] is False


def test_json_reader_rejects_duplicate_attestation_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")

    with pytest.raises(CelPromotionAuditError, match="duplicate key"):
        cel_promotion_audit._read_json(
            path,
            max_bytes=cel_promotion_audit._MAX_ATTESTATION_BUNDLE_BYTES,
        )


def test_mixed_shadow_lineage_enumerates_only_false_candidates_with_exact_identity() -> None:
    sample = _sample("mixed-malicious", "malicious", "train", "validation")
    would_suppress = {
        "rule_id": "RULE_FALSE",
        "decision": "would_suppress",
        "reason": "shadow_or_rule_rollout",
        "fact_schema": "v1",
        "expression_hash": "1" * 64,
        "pack": "core",
        "rollout": "shadow",
        "count": 2,
    }
    retained = {
        "rule_id": "RULE_KEEP",
        "decision": "keep",
        "reason": "expression_true",
        "fact_schema": "v1",
        "expression_hash": "2" * 64,
        "pack": "core",
        "rollout": "shadow",
        "count": 1,
    }
    finding = _finding("RULE_FALSE", Severity.HIGH, [would_suppress, retained], deduped_count=2)

    requirements = cel_promotion_audit._malicious_blocking_candidate_requirements(
        sample,
        finding,
        0,
        [would_suppress, retained],
        sample_content_sha256="3" * 64,
    )

    assert [candidate["rule_id"] for candidate in requirements] == ["RULE_FALSE", "RULE_FALSE"]
    assert [candidate["lineage_ordinal"] for candidate in requirements] == [0, 1]
    assert len({candidate["candidate_identity_sha256"] for candidate in requirements}) == 2
