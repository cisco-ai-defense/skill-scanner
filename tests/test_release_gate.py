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
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evals.datasets.public_datasets import load_dataset_lock
from evals.runners import release_gate
from evals.runners.release_gate import (
    ReleaseGateError,
    main,
    stable_release_output_sha256,
)
from evals.runners.release_gate import (
    run_release_gate as _run_release_gate,
)

_ARTIFACT_DIGEST = "a" * 64
_PRIVATE_DIGEST = "b" * 64
_PUBLIC_REVISION = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
_BUILD_DIGEST = "c" * 64
_POLICY_DIGEST = "d" * 64
_RULES_DIGEST = "e" * 64
_EXPRESSION_DIGEST = "f" * 64
_GOLDEN_DIGEST = "1" * 64
_SOURCE_REVISION = "2" * 40
_CORE_TRACK = "core-only-source-disjoint"
_TRACK_EXPECTATIONS = {
    _CORE_TRACK: {
        "samples": 1384,
        "malicious": 839,
        "benign": 545,
        "population_sha256": "e77564f010fe55ee368af237fabc89b94ca308bd0b3a8c49f052716609f89399",
        "detector_profile": "core_only",
        "protocol": "source_disjoint",
    },
}


@pytest.fixture(autouse=True)
def _bind_synthetic_bundled_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep synthetic release evidence bound to one deterministic bundled generation."""

    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "shadow"}},
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _promoted_lock(tmp_path: Path) -> Path:
    manifest = copy.deepcopy(load_dataset_lock())
    dataset = next(entry for entry in manifest["datasets"] if entry["id"] == "ProtectSkills/MaliciousSkillBench")
    dataset["integrity"]["hashes_pending"] = False
    dataset["integrity"]["artifact_manifest_sha256"] = _ARTIFACT_DIGEST
    dataset["gating"]["blocking"] = True
    path = tmp_path / "datasets.lock.json"
    _write_json(path, manifest)
    return path


def _metrics(
    *,
    samples: int = 200,
    malicious: int = 100,
    benign: int = 100,
    cel_mode: str = "shadow",
) -> dict:
    active = cel_mode != "off"
    return {
        "samples": samples,
        "malicious": malicious,
        "benign": benign,
        "critical_high_false_negatives": 1,
        "critical_high_false_negative_ids": ["known-high-fn"],
        "recall": 0.90,
        "package_block_recall": 0.90,
        "signal_recall": 0.92,
        "macro_f1": 0.88,
        "benign_actionable_fpr": 0.04,
        "confidence_intervals_95": {
            "package_block_recall": [0.83, 0.94],
            "signal_recall": [0.85, 0.96],
            "benign_actionable_fpr": [0.02, 0.08],
        },
        "p95_scan_latency_ms": 100.0,
        "cel_time_ratio": 0.04 if active else 0.0,
        "cel_fallbacks": 0,
        "loader_fallbacks": 0,
        "recovered_scan_errors": 0,
        "loader_fallback_sample_ids": [],
        "loader_rejections": 0,
        "loader_rejection_sample_ids": [],
        "cel": {
            "modes": [cel_mode],
            "runtimes": ["cel-go"],
            "runtime_versions": ["v0.32.0;helper=2.0.0"],
            "fact_schemas": ["v1"],
            "expression_set_hashes": [_EXPRESSION_DIGEST],
            "evaluated": 10 if active else 0,
            "retained": 10 if active else 0,
            "would_suppress": 2 if active else 0,
            "suppressed": 0,
            "fallbacks": 0,
            "projection_incomplete": 0,
            "elapsed_ms": 4.0 if active else 0.0,
            "projection_ms": 1.0 if active else 0.0,
            "evaluation_ms": 2.0 if active else 0.0,
            "error_counts": {},
            "would_suppress_sample_ids": [],
            "suppressed_sample_ids": [],
            "fallback_sample_ids": [],
            "projection_incomplete_sample_ids": [],
            "per_rule": (
                {
                    "CEL_TEST": {
                        "keep": 8,
                        "would_suppress": 2,
                        "fallback": 0,
                        "suppressed": 0,
                        "expression_hashes": [_EXPRESSION_DIGEST],
                        "packs": ["core"],
                        "rollouts": ["shadow" if cel_mode == "shadow" else "enforce"],
                    }
                }
                if active
                else {}
            ),
        },
        "scan_errors": 0,
    }


def _combined_expression_hash() -> str:
    payload = json.dumps([_EXPRESSION_DIGEST], separators=(",", ":"))
    return hashlib.sha256(b"skill-scanner-benchmark-expression-generations-v1\0" + payload.encode()).hexdigest()


def _evidence_identity(dataset_or_corpus_id: str, snapshot_sha256: str, cel_mode: str) -> dict:
    return {
        "dataset_or_corpus_id": dataset_or_corpus_id,
        "snapshot_sha256": snapshot_sha256,
        "build_sha256": _BUILD_DIGEST,
        "policy_sha256": _POLICY_DIGEST,
        "rules_sha256": _RULES_DIGEST,
        "expression_set_hash": _combined_expression_hash(),
        "cel_mode": cel_mode,
    }


def _track_metrics(track_name: str, cel_mode: str) -> dict:
    expectation = _TRACK_EXPECTATIONS[track_name]
    metrics = _metrics(
        samples=expectation["samples"],
        malicious=expectation["malicious"],
        benign=expectation["benign"],
        cel_mode=cel_mode,
    )
    if cel_mode == "off":
        outcomes = {}
    else:
        outcomes = {
            **{
                f"{track_name}-keep-{index}": {
                    "label": "malicious",
                    "scan_error": False,
                    "recovered_scan_error": False,
                    "loader_fallback_code": None,
                    "loader_rejection_code": None,
                    "cel_suppressed": [],
                    "findings": [
                        {
                            "rule_id": "CEL_TEST",
                            "severity": "HIGH",
                            "cel_decision": "keep",
                            "cel_decisions": [{"rule_id": "CEL_TEST", "decision": "keep", "count": 1}],
                        }
                    ],
                }
                for index in range(8)
            },
            **{
                f"{track_name}-would-{index}": {
                    "label": "benign",
                    "scan_error": False,
                    "recovered_scan_error": False,
                    "loader_fallback_code": None,
                    "loader_rejection_code": None,
                    "cel_suppressed": [],
                    "findings": [
                        {
                            "rule_id": "CEL_TEST",
                            "severity": "HIGH",
                            "cel_decision": "would_suppress",
                            "cel_decisions": [{"rule_id": "CEL_TEST", "decision": "would_suppress", "count": 1}],
                        }
                    ],
                }
                for index in range(2)
            },
        }
        metrics["cel"]["would_suppress_sample_ids"] = [f"{track_name}-would-{index}" for index in range(2)]
    group_metrics = copy.deepcopy(metrics)
    group_metrics.update(
        {
            "sample_outcomes_count": metrics["samples"],
            "sample_outcomes_sha256": _ARTIFACT_DIGEST,
            "sample_outcomes_format": "digest-only-v1",
        }
    )
    return {
        "name": track_name,
        "detector_profile": expectation["detector_profile"],
        "protocol": expectation["protocol"],
        "partition": "test",
        "population_sha256": expectation["population_sha256"],
        "status": "passed",
        **copy.deepcopy(metrics),
        "sample_outcomes_count": metrics["samples"],
        "sample_outcomes_sha256": _ARTIFACT_DIGEST,
        "sample_outcomes_format": "cel-referenced-v3",
        "sample_outcomes": outcomes,
        "per_category": {"command_execution": copy.deepcopy(group_metrics)},
        "per_source": {"source-a": copy.deepcopy(group_metrics)},
        "per_structural_family": {"family-a": copy.deepcopy(group_metrics)},
    }


def _public_report(*, cel_mode: str = "shadow") -> dict:
    metrics = _metrics(cel_mode=cel_mode)
    producer = {
        "scanner_version": "2.0.0",
        "source_revision": "test-revision",
        "build_sha256": _BUILD_DIGEST,
        "policy_sha256": _POLICY_DIGEST,
        "rules_sha256": _RULES_DIGEST,
    }
    stable_identity = {"snapshot_sha256": _ARTIFACT_DIGEST, **producer}
    return {
        "schema_version": 1,
        "status": "passed",
        "profile": "release",
        "release_evidence": {
            "format": "compact-v3",
            "full_sample_outcomes_domain": "skill-scanner-release-sample-outcomes-v1",
            "cel_decision_identity": "track.cel.per_rule",
        },
        "cel_mode": cel_mode,
        "evidence_identity": _evidence_identity("ProtectSkills/MaliciousSkillBench", _ARTIFACT_DIGEST, cel_mode),
        "producer": producer,
        "identity_verification": {
            "status": "passed",
            "drifted_fields": [],
            "start": copy.deepcopy(stable_identity),
            "end": copy.deepcopy(stable_identity),
            "errors": [],
        },
        "dataset": {
            "id": "ProtectSkills/MaliciousSkillBench",
            "revision": _PUBLIC_REVISION,
            "artifact_manifest_sha256": _ARTIFACT_DIGEST,
            "blocking_eligible": True,
        },
        "summary": copy.deepcopy(metrics),
        "tracks": {_CORE_TRACK: _track_metrics(_CORE_TRACK, cel_mode)},
        "errors": [],
    }


def _private_report(*, cel_mode: str = "shadow", label_source: str = "agent_labeled") -> dict:
    report = _public_report(cel_mode=cel_mode)
    report.pop("dataset")
    corpus = {
        "id": "private-source-disjoint-v1",
        "snapshot_sha256": _PRIVATE_DIGEST,
        "source_disjoint": True,
        "holdout_fraction": 0.30,
        "samples": 200,
        "malicious_or_contextual": 100,
        "benign": 100,
        "label_attestation": {
            "schema_version": 1,
            "scanner_independent": True,
            "scanner_outputs_used_as_labels": False,
            "label_sources": {
                source: 200 if source == label_source else 0
                for source in release_gate._SCANNER_INDEPENDENT_LABEL_SOURCES
            },
            "label_provenance_sha256": "0" * 64,
            "label_evidence_sha256": "0" * 64,
        },
    }
    corpus["label_attestation"]["label_provenance_sha256"] = release_gate._private_label_provenance_sha256(corpus)
    corpus["label_attestation"]["label_evidence_sha256"] = release_gate._private_label_evidence_sha256(corpus)
    report["corpus"] = corpus
    report["evidence_identity"] = _evidence_identity("private-source-disjoint-v1", _PRIVATE_DIGEST, cel_mode)
    report["identity_verification"]["start"]["snapshot_sha256"] = _PRIVATE_DIGEST
    report["identity_verification"]["end"]["snapshot_sha256"] = _PRIVATE_DIGEST
    return report


def _repeated_runs(
    candidate: dict,
    count: int = 5,
    *,
    failed_index: int | None = None,
    evidence_identity: dict | None = None,
    golden_manifest_sha256: str = _GOLDEN_DIGEST,
    output_sha256: str | None = None,
) -> dict:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    identity = evidence_identity or candidate["evidence_identity"]
    stable_output = output_sha256 or stable_release_output_sha256(candidate)
    return {
        "schema_version": 1,
        "runs": [
            {
                "run_id": str(index + 1),
                "completed_at": (start + timedelta(days=index)).isoformat(),
                "status": "failed" if index == failed_index else "passed",
                "evidence_identity": copy.deepcopy(identity),
                "golden_manifest_sha256": golden_manifest_sha256,
                "output_sha256": stable_output,
            }
            for index in range(count)
        ],
    }


def _public_root(tmp_path: Path, *, golden: tuple[int, int] | None = (1, 0)) -> Path:
    root = tmp_path / "public"
    root.mkdir()
    candidate = _public_report()
    _write_json(root / "candidate.json", candidate)
    _write_json(root / "baseline.json", _public_report(cel_mode="off"))
    golden_digest = _GOLDEN_DIGEST
    strict, legacy = golden if golden is not None else (1, 0)
    golden_evidence = {
        "schema_version": 1,
        "strict_fixtures": strict,
        "legacy_degraded_fixtures": legacy,
        "manifest_sha256": _GOLDEN_DIGEST,
        "label_sources": {
            "public_labeled": strict,
            "independent_ollama": 0,
            "agent_labeled": 0,
            "human_reviewed": 0,
        },
        "scanner_derived_fixtures": 0,
        "sealed_hf_model_labeled_fixtures": 0,
    }
    if golden is not None:
        _write_json(root / "golden-corpus.json", golden_evidence)
        golden_digest = _GOLDEN_DIGEST
    _write_json(tmp_path / "current-committed-golden.json", golden_evidence)
    _write_json(root / "repeated-runs.json", _repeated_runs(candidate, golden_manifest_sha256=golden_digest))
    return root


def _bind_public_source_revision(public_root: Path, source_revision: str) -> None:
    for report_name in ("candidate.json", "baseline.json"):
        path = public_root / report_name
        report = json.loads(path.read_text(encoding="utf-8"))
        report["producer"]["source_revision"] = source_revision
        report["identity_verification"]["start"]["source_revision"] = source_revision
        report["identity_verification"]["end"]["source_revision"] = source_revision
        _write_json(path, report)


def _add_loader_recovery(
    report: dict,
    *,
    track_name: str = _CORE_TRACK,
    benchmark_id: str = "bounded-loader-recovery",
    code: str = "MALFORMED_YAML_FRONTMATTER",
) -> None:
    track = report["tracks"][track_name]
    track["loader_fallbacks"] += 1
    track["recovered_scan_errors"] += 1
    track["loader_fallback_sample_ids"].append(benchmark_id)
    track["loader_fallback_sample_ids"].sort()
    for dimension in ("per_category", "per_source", "per_structural_family"):
        for group in track[dimension].values():
            group["loader_fallbacks"] += 1
            group["recovered_scan_errors"] += 1
            group["loader_fallback_sample_ids"].append(benchmark_id)
            group["loader_fallback_sample_ids"].sort()
    track["sample_outcomes"][benchmark_id] = {
        "label": "malicious",
        "scan_error": False,
        "recovered_scan_error": True,
        "loader_fallback_code": code,
        "loader_rejection_code": None,
        "cel_suppressed": [],
        "findings": [
            {
                "rule_id": "SKILL_LOAD_FALLBACK_USED",
                "severity": "INFO",
                "cel_decision": None,
                "cel_decisions": [],
            }
        ],
    }
    summary_id = f"{track_name}:{benchmark_id}"
    report["summary"]["loader_fallbacks"] += 1
    report["summary"]["recovered_scan_errors"] += 1
    report["summary"]["loader_fallback_sample_ids"].append(summary_id)
    report["summary"]["loader_fallback_sample_ids"].sort()


def _add_loader_rejection(
    report: dict,
    *,
    track_name: str = _CORE_TRACK,
    benchmark_id: str = "closed-loader-rejection",
) -> None:
    track = report["tracks"][track_name]
    track["loader_rejections"] += 1
    track["loader_rejection_sample_ids"].append(benchmark_id)
    track["loader_rejection_sample_ids"].sort()
    for dimension in ("per_category", "per_source", "per_structural_family"):
        for group in track[dimension].values():
            group["loader_rejections"] += 1
            group["loader_rejection_sample_ids"].append(benchmark_id)
            group["loader_rejection_sample_ids"].sort()
    track["sample_outcomes"][benchmark_id] = {
        "label": "malicious",
        "scan_error": False,
        "recovered_scan_error": False,
        "loader_fallback_code": None,
        "loader_rejection_code": "SKILL_METADATA_SIZE_LIMIT_EXCEEDED",
        "cel_suppressed": [],
        "findings": [
            {
                "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
                "severity": "HIGH",
                "cel_decision": None,
                "cel_decisions": [],
            }
        ],
    }
    report["summary"]["loader_rejections"] += 1
    report["summary"]["loader_rejection_sample_ids"].append(f"{track_name}:{benchmark_id}")
    report["summary"]["loader_rejection_sample_ids"].sort()


def _refresh_repeated_runs(public_root: Path, candidate: dict) -> None:
    _write_json(
        public_root / "repeated-runs.json",
        _repeated_runs(candidate, golden_manifest_sha256=_GOLDEN_DIGEST),
    )


def run_release_gate(
    *,
    public_corpus: Path,
    dataset_lock: Path,
    private_corpus: Path | None = None,
) -> dict:
    return _run_release_gate(
        public_corpus=public_corpus,
        private_corpus=private_corpus,
        dataset_lock=dataset_lock,
        committed_golden=public_corpus.parent / "current-committed-golden.json",
    )


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir()
    _write_json(root / "candidate.json", _private_report())
    _write_json(root / "baseline.json", _private_report(cel_mode="off"))
    return root


def _fixture_provenance(label_source: str, fixture_id: str) -> dict:
    if label_source == "public_labeled":
        return {
            "dataset_id": "example/public-fixtures",
            "revision": "2" * 40,
            "split": "test",
            "sample_id": fixture_id,
            "source_artifact_sha256": "3" * 64,
            "labels_derived_from_scanner": False,
        }
    if label_source == "independent_ollama":
        return {
            "corpus_id": "example/unlabeled-fixtures",
            "report_sha256": "4" * 64,
            "case_id": fixture_id,
            "model_name": "qwen3:8b",
            "model_digest": "5" * 64,
            "rubric_sha256": "6" * 64,
            "prompt_sha256": "7" * 64,
            "passes": [{"pass_id": "pass-a", "seed": 101}, {"pass_id": "pass-b", "seed": 202}],
            "scanner_outputs_used_as_labels": False,
        }
    if label_source == "agent_labeled":
        return {
            "agent_id": "independent-safety-labeler",
            "agent_definition_sha256": "8" * 64,
            "run_id": f"run-{fixture_id}",
            "model_id": "local-meta-llama",
            "model_digest": "9" * 64,
            "rubric_sha256": "a" * 64,
            "prompt_sha256": "b" * 64,
            "scanner_outputs_used_as_labels": False,
        }
    if label_source == "human_reviewed":
        return {
            "reviewer_ids": ["reviewer-a", "reviewer-b"],
            "reviewed_at": "2026-08-01T00:00:00+00:00",
            "review_protocol_sha256": "c" * 64,
            "scanner_outputs_used_in_review": False,
        }
    raise AssertionError(f"unsupported test label source: {label_source}")


def _fixture_attestation(
    fixture_id: str,
    role: str,
    package_label: str,
    expected_verdict: str,
    *,
    label_source: str,
) -> dict:
    provenance = _fixture_provenance(label_source, fixture_id)
    attestation = {
        "fixture_id": fixture_id,
        "role": role,
        "label_source": label_source,
        "package_label": package_label,
        "expected_verdict": expected_verdict,
        "scanner_independent": True,
        "content_sha256": "d" * 64,
        "provenance": provenance,
        "provenance_sha256": release_gate._fixture_provenance_sha256(label_source, provenance),
    }
    attestation["evidence_sha256"] = release_gate._fixture_attestation_sha256(attestation)
    return attestation


def _attested_fixture_evidence(candidate: dict, *, label_source: str = "public_labeled") -> dict:
    fixture_roles = {
        "cel-test.tp": ("true_positive", "malicious", "unsafe"),
        "cel-test.near-miss": ("benign_near_miss", "benign", "safe"),
        "cel-test.boundary": ("boundary", "contextual_risk", "unsafe"),
    }
    document = {
        "schema_version": 2,
        "rules_sha256": _RULES_DIGEST,
        "expression_set_hash": candidate["evidence_identity"]["expression_set_hash"],
        "golden_manifest_sha256": _GOLDEN_DIGEST,
        "rules": {
            "CEL_TEST": {
                "true_positive_fixture_ids": ["cel-test.tp"],
                "benign_near_miss_fixture_ids": ["cel-test.near-miss"],
                "boundary_fixture_ids": ["cel-test.boundary"],
            }
        },
        "attestations": {
            fixture_id: _fixture_attestation(
                fixture_id,
                role,
                package_label,
                expected_verdict,
                label_source=label_source,
            )
            for fixture_id, (role, package_label, expected_verdict) in fixture_roles.items()
        },
    }
    document["evidence_sha256"] = release_gate._fixture_evidence_sha256(document)
    return document


def _rehash_fixture_attestation(document: dict, fixture_id: str) -> None:
    attestation = document["attestations"][fixture_id]
    attestation["provenance_sha256"] = release_gate._fixture_provenance_sha256(
        attestation["label_source"], attestation["provenance"]
    )
    attestation["evidence_sha256"] = release_gate._fixture_attestation_sha256(attestation)
    document["evidence_sha256"] = release_gate._fixture_evidence_sha256(document)


def _validate_fixture_document(document: dict, candidate: dict) -> dict:
    return release_gate._validate_attested_rule_fixtures(
        document,
        enforced_rule_ids={"CEL_TEST"},
        rules_sha256=_RULES_DIGEST,
        expression_set_hash=candidate["evidence_identity"]["expression_set_hash"],
        golden_manifest_sha256=_GOLDEN_DIGEST,
    )


@pytest.mark.parametrize(
    "label_source",
    ["public_labeled", "independent_ollama", "agent_labeled", "human_reviewed"],
)
def test_each_scanner_independent_fixture_attestation_source_is_accepted(label_source: str) -> None:
    candidate = _public_report(cel_mode="enforce")
    document = _attested_fixture_evidence(candidate, label_source=label_source)

    normalized = _validate_fixture_document(document, candidate)

    assert set(normalized) == {"CEL_TEST"}


@pytest.mark.parametrize(
    ("label_source", "scanner_field"),
    [
        ("public_labeled", "labels_derived_from_scanner"),
        ("independent_ollama", "scanner_outputs_used_as_labels"),
        ("agent_labeled", "scanner_outputs_used_as_labels"),
        ("human_reviewed", "scanner_outputs_used_in_review"),
    ],
)
def test_each_fixture_attestation_source_rejects_scanner_derived_labels(
    label_source: str,
    scanner_field: str,
) -> None:
    candidate = _public_report(cel_mode="enforce")
    document = _attested_fixture_evidence(candidate, label_source=label_source)
    document["attestations"]["cel-test.tp"]["provenance"][scanner_field] = True
    _rehash_fixture_attestation(document, "cel-test.tp")

    with pytest.raises(ReleaseGateError, match=f"{scanner_field} must be false"):
        _validate_fixture_document(document, candidate)


@pytest.mark.parametrize(
    ("label_source", "spoofed_source"),
    [
        ("public_labeled", "independent_ollama"),
        ("independent_ollama", "agent_labeled"),
        ("agent_labeled", "human_reviewed"),
        ("human_reviewed", "public_labeled"),
    ],
)
def test_fixture_attestation_rejects_type_spoofed_provenance(
    label_source: str,
    spoofed_source: str,
) -> None:
    candidate = _public_report(cel_mode="enforce")
    document = _attested_fixture_evidence(candidate, label_source=label_source)
    document["attestations"]["cel-test.tp"]["provenance"] = _fixture_provenance(spoofed_source, "cel-test.tp")
    _rehash_fixture_attestation(document, "cel-test.tp")

    with pytest.raises(ReleaseGateError, match="must contain exactly"):
        _validate_fixture_document(document, candidate)


def test_fixture_attestation_hashes_and_role_labels_are_recomputed_and_enforced() -> None:
    candidate = _public_report(cel_mode="enforce")
    document = _attested_fixture_evidence(candidate)
    document["attestations"]["cel-test.tp"]["provenance"]["sample_id"] = "changed"
    document["evidence_sha256"] = release_gate._fixture_evidence_sha256(document)
    with pytest.raises(ReleaseGateError, match="provenance_sha256 does not match"):
        _validate_fixture_document(document, candidate)

    document = _attested_fixture_evidence(candidate)
    document["attestations"]["cel-test.tp"]["content_sha256"] = "e" * 64
    document["evidence_sha256"] = release_gate._fixture_evidence_sha256(document)
    with pytest.raises(ReleaseGateError, match="evidence_sha256 does not match"):
        _validate_fixture_document(document, candidate)

    document = _attested_fixture_evidence(candidate)
    document["attestations"]["cel-test.tp"]["scanner_independent"] = False
    _rehash_fixture_attestation(document, "cel-test.tp")
    with pytest.raises(ReleaseGateError, match="scanner_independent must be true"):
        _validate_fixture_document(document, candidate)

    document = _attested_fixture_evidence(candidate)
    attestation = document["attestations"]["cel-test.tp"]
    attestation.update(package_label="benign", expected_verdict="safe")
    _rehash_fixture_attestation(document, "cel-test.tp")
    with pytest.raises(ReleaseGateError, match="true-positive fixtures must be malicious/unsafe"):
        _validate_fixture_document(document, candidate)

    document = _attested_fixture_evidence(candidate)
    attestation = document["attestations"]["cel-test.near-miss"]
    attestation.update(package_label="malicious", expected_verdict="unsafe")
    _rehash_fixture_attestation(document, "cel-test.near-miss")
    with pytest.raises(ReleaseGateError, match="benign near-miss fixtures must be benign/safe"):
        _validate_fixture_document(document, candidate)

    document = _attested_fixture_evidence(candidate)
    document["attestations"]["cel-test.boundary"]["content_sha256"] = "f" * 64
    attestation = document["attestations"]["cel-test.boundary"]
    attestation["evidence_sha256"] = release_gate._fixture_attestation_sha256(attestation)
    with pytest.raises(ReleaseGateError, match="does not match its canonical content"):
        _validate_fixture_document(document, candidate)


def test_agent_attestation_cannot_claim_the_scanner_as_an_independent_labeler() -> None:
    candidate = _public_report(cel_mode="enforce")
    document = _attested_fixture_evidence(candidate, label_source="agent_labeled")
    document["attestations"]["cel-test.tp"]["provenance"]["agent_id"] = "skill-scanner-labeler"
    _rehash_fixture_attestation(document, "cel-test.tp")

    with pytest.raises(ReleaseGateError, match="scanner-independent agent"):
        _validate_fixture_document(document, candidate)


def _repeated_comparison(candidate: dict, baseline: dict, fixtures: dict) -> dict:
    rule_fixtures = fixtures["rules"]["CEL_TEST"]
    evidence = {
        "malicious_support_sample_ids": [f"{_CORE_TRACK}:malicious-1"],
        "benign_near_miss_sample_ids": [f"{_CORE_TRACK}:benign-1"],
        **copy.deepcopy(rule_fixtures),
        "observed_targeted_benign_candidates": 5,
        "observed_would_suppress_benign_candidates": 1,
        "observed_would_suppress_malicious_high_critical_candidates": 0,
        "observed_would_suppress_malicious_high_critical_sample_ids": [],
        "normalized_loss_evidence_status": "not_supplied",
        "normalized_loss_evidence_exact": False,
        "relative_actionable_fp_reduction": None,
        "passes_twenty_percent_reduction": False,
        "has_malicious_support": True,
        "has_true_positive_fixture": True,
        "has_benign_near_miss_fixture": True,
        "has_boundary_fixture": True,
        "eligible_for_promotion": False,
    }
    comparison = {
        "status": "passed",
        "comparison_kind": "cel_activation",
        "baseline_cel_mode": "off",
        "candidate_cel_mode": "enforce",
        "population_locked": True,
        "missing_group_dimensions": [],
        "evidence_identity": {
            "baseline": copy.deepcopy(baseline["evidence_identity"]),
            "candidate": copy.deepcopy(candidate["evidence_identity"]),
            "changed_fields": ["cel_mode"],
        },
        "producer": {
            "baseline": copy.deepcopy(baseline["producer"]),
            "candidate": copy.deepcopy(candidate["producer"]),
            "changed_fields": [],
        },
    }
    return {
        "schema_version": 1,
        "status": "passed",
        "runs": 5,
        "same_evidence_identity": True,
        "same_producer_identity": True,
        "stable_output": True,
        "stability_fingerprints": ["8" * 64] * 5,
        "rule_promotion_evidence": {"CEL_TEST": evidence},
        "rule_promotion_evidence_required": True,
        "rule_promotion_passed": True,
        "comparisons": [copy.deepcopy(comparison) for _ in range(5)],
    }


def _configure_enforced_evidence(public_root: Path, *, include_promotion: bool = True) -> tuple[dict, dict]:
    candidate = _public_report(cel_mode="enforce")
    baseline = _public_report(cel_mode="off")
    _write_json(public_root / "candidate.json", candidate)
    _write_json(public_root / "baseline.json", baseline)
    _write_json(public_root / "repeated-runs.json", _repeated_runs(candidate))
    if include_promotion:
        fixtures = _attested_fixture_evidence(candidate)
        _write_json(public_root / "rule-fixture-evidence.json", fixtures)
        _write_json(public_root / "repeated-comparison.json", _repeated_comparison(candidate, baseline, fixtures))
    return candidate, baseline


def test_public_only_gate_passes_and_private_is_explicitly_disabled(tmp_path: Path) -> None:
    report = run_release_gate(
        public_corpus=_public_root(tmp_path),
        dataset_lock=_promoted_lock(tmp_path),
    )

    assert report["status"] == "passed"
    assert report["golden_corpus"]["verified_against_current_committed_manifest"] is True
    assert report["private"] == {
        "enabled": False,
        "blocking": False,
        "status": "not_supplied",
        "checks": [],
        "errors": [],
    }
    assert report["promotion_evidence"] == {
        "required_repeated_runs": 5,
        "clean_repeated_runs": 5,
        "clean_run_ids": ["1", "2", "3", "4", "5"],
        "normalized_output_sha256": stable_release_output_sha256(_public_report()),
        "complete_public_release_run_passed": True,
        "enforced_rule_ids": [],
        "rule_promotion_required": False,
        "rule_promotion_artifacts_passed": False,
        "attested_fixture_evidence_sha256": None,
    }
    assert report["waivers"] == {"accepted": False, "present": False}
    assert report["checks"]
    assert all(check["passed"] for check in report["checks"])


def test_shadow_only_generation_does_not_require_fake_promotion_evidence(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert not (public_root / "rule-fixture-evidence.json").exists()
    assert not (public_root / "repeated-comparison.json").exists()
    assert report["promotion_evidence"]["rule_promotion_required"] is False
    assert report["status"] == "passed"


def test_release_rejects_evidence_from_a_stale_bundled_rule_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": "9" * 64, "rollouts": {"CEL_TEST": "shadow"}},
    )

    with pytest.raises(ReleaseGateError, match="current bundled rule generation"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_enforced_rule_requires_attested_fixture_and_repeated_comparison_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    _configure_enforced_evidence(public_root, include_promotion=False)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "enforce"}},
    )

    with pytest.raises(ReleaseGateError, match="require rule-fixture-evidence.json"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_enforced_rule_rejects_raw_candidate_evidence_without_normalized_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    _configure_enforced_evidence(public_root)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "enforce"}},
    )

    with pytest.raises(ReleaseGateError, match="lack independently bound exact normalized-loss evidence"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_enforced_rule_rejects_forged_reduction_from_raw_candidate_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    _configure_enforced_evidence(public_root)
    comparison_path = public_root / "repeated-comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    rule = comparison["rule_promotion_evidence"]["CEL_TEST"]
    rule["relative_actionable_fp_reduction"] = 0.20
    rule["passes_twenty_percent_reduction"] = True
    rule["eligible_for_promotion"] = True
    _write_json(comparison_path, comparison)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "enforce"}},
    )

    with pytest.raises(ReleaseGateError, match="invalid normalized-loss contract"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_observed_malicious_high_critical_candidates_do_not_become_loss_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    _configure_enforced_evidence(public_root)
    comparison_path = public_root / "repeated-comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    rule = comparison["rule_promotion_evidence"]["CEL_TEST"]
    rule["observed_would_suppress_malicious_high_critical_candidates"] = 1
    rule["observed_would_suppress_malicious_high_critical_sample_ids"] = [f"{_CORE_TRACK}:malicious-1"]
    _write_json(comparison_path, comparison)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "enforce"}},
    )

    with pytest.raises(ReleaseGateError, match="lack independently bound exact normalized-loss evidence"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_enforced_rule_rejects_comparison_fixture_ids_that_disagree_with_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    _configure_enforced_evidence(public_root)
    comparison_path = public_root / "repeated-comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    comparison["rule_promotion_evidence"]["CEL_TEST"]["boundary_fixture_ids"] = ["cel-test.unreviewed-boundary"]
    _write_json(comparison_path, comparison)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "enforce"}},
    )

    with pytest.raises(ReleaseGateError, match="fixture IDs disagree"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_enforced_rule_rejects_comparison_generation_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = _public_root(tmp_path)
    _configure_enforced_evidence(public_root)
    comparison_path = public_root / "repeated-comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    comparison["comparisons"][3]["evidence_identity"]["candidate"]["expression_set_hash"] = "9" * 64
    _write_json(comparison_path, comparison)
    monkeypatch.setattr(
        release_gate,
        "_current_bundled_cel_generation",
        lambda: {"rules_sha256": _RULES_DIGEST, "rollouts": {"CEL_TEST": "enforce"}},
    )

    with pytest.raises(ReleaseGateError, match="does not bind the release generation"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_release_rejects_waiver_inputs_instead_of_bypassing_gates(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    _write_json(public_root / "promotion-waiver.json", {"reason": "skip promotion evidence"})

    with pytest.raises(ReleaseGateError, match="do not accept waivers"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_release_rejects_embedded_waiver_metadata(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate_path = public_root / "candidate.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate["waiver_reason"] = "skip a failed gate"
    _write_json(candidate_path, candidate)

    with pytest.raises(ReleaseGateError, match="waiver metadata"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_cli_reports_waiver_rejection_without_accepting_it(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    _write_json(public_root / "waiver.json", {"reason": "skip"})
    output = tmp_path / "release-result.json"

    exit_code = main(
        [
            "--public-corpus",
            str(public_root),
            "--committed-golden",
            str(tmp_path / "current-committed-golden.json"),
            "--dataset-lock",
            str(_promoted_lock(tmp_path)),
            "--expected-source-revision",
            _SOURCE_REVISION,
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == "failed"
    assert report["waivers"] == {"accepted": False, "present": True}


def test_release_commit_must_match_candidate_and_baseline_producer(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)

    with pytest.raises(ReleaseGateError, match="candidate producer source_revision does not match"):
        _run_release_gate(
            public_corpus=public_root,
            dataset_lock=_promoted_lock(tmp_path),
            committed_golden=tmp_path / "current-committed-golden.json",
            expected_source_revision=_SOURCE_REVISION,
        )

    _bind_public_source_revision(public_root, _SOURCE_REVISION)
    report = _run_release_gate(
        public_corpus=public_root,
        dataset_lock=_promoted_lock(tmp_path),
        committed_golden=tmp_path / "current-committed-golden.json",
        expected_source_revision=_SOURCE_REVISION,
    )

    assert report["status"] == "passed"
    assert report["public"]["source_revision"] == _SOURCE_REVISION


def test_supplied_private_holdout_is_optional_and_reported_separately(tmp_path: Path) -> None:
    private_root = _private_root(tmp_path)
    report = run_release_gate(
        public_corpus=_public_root(tmp_path),
        private_corpus=private_root,
        dataset_lock=_promoted_lock(tmp_path),
    )

    assert report["status"] == "passed"
    assert report["private"]["enabled"] is True
    assert report["private"]["blocking"] is False
    assert report["private"]["status"] == "passed"
    assert report["private"]["corpus_id"] == "private-source-disjoint-v1"
    assert report["private"]["checks"]
    assert all(not check["name"].startswith("private") for check in report["checks"])


def test_invalid_optional_private_evidence_never_changes_hard_release_result(tmp_path: Path) -> None:
    private_root = tmp_path / "broken-private"
    private_root.mkdir()
    (private_root / "unexpected.txt").write_text("invalid", encoding="utf-8")

    report = run_release_gate(
        public_corpus=_public_root(tmp_path),
        private_corpus=private_root,
        dataset_lock=_promoted_lock(tmp_path),
    )

    assert report["status"] == "passed"
    assert report["private"]["status"] == "failed"
    assert report["private"]["blocking"] is False
    assert report["private"]["errors"]


@pytest.mark.parametrize(
    ("field", "value", "expected_check"),
    [
        ("package_block_recall", 0.89, "public.summary.package_block_recall"),
        ("signal_recall", 0.91, "public.summary.signal_recall"),
        ("macro_f1", 0.87, "public.summary.macro_f1"),
        ("benign_actionable_fpr", 0.041, "public.summary.benign_actionable_fpr"),
        ("p95_scan_latency_ms", 110.01, "public.summary.p95_scan_latency_ms"),
        ("cel_time_ratio", 0.051, "public.summary.cel_time_ratio"),
        ("cel_fallbacks", 1, "public.summary.cel_fallbacks"),
        ("scan_errors", 1, "public.summary.scan_errors"),
    ],
)
def test_metric_regressions_fail_the_gate(tmp_path: Path, field: str, value: int | float, expected_check: str) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["summary"][field] = value
    if field == "package_block_recall":
        candidate["summary"]["recall"] = value
    if field == "scan_errors":
        track = candidate["tracks"][_CORE_TRACK]
        track["scan_errors"] = value
        track["sample_outcomes"]["fatal-scan-error"] = {
            "label": "benign",
            "scan_error": True,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [],
        }
    _write_json(public_root / "candidate.json", candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert report["status"] == "failed"
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert expected_check in failed


def test_exact_bounded_loader_recovery_remains_eligible_for_release(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    _add_loader_recovery(candidate)
    _add_loader_recovery(baseline)
    _write_json(public_root / "candidate.json", candidate)
    _write_json(public_root / "baseline.json", baseline)
    _refresh_repeated_runs(public_root, candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert report["status"] == "passed"
    recovery_checks = [check for check in report["checks"] if check["name"].endswith(".loader_fallback_identity")]
    assert recovery_checks
    assert all(check["passed"] for check in recovery_checks)


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        ("count", "compact CEL outcome counts disagree"),
        ("winner", "contradictory CEL winner"),
        ("identity_collision", "must bind one immutable expression"),
    ],
)
def test_compact_cel_lineage_spoofs_are_rejected(
    tmp_path: Path,
    mutation: str,
    error_match: str,
) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    outcome = candidate["tracks"][_CORE_TRACK]["sample_outcomes"][f"{_CORE_TRACK}-keep-0"]
    finding = outcome["findings"][0]
    if mutation == "count":
        finding["cel_decisions"][0]["count"] = 2
    elif mutation == "winner":
        finding["cel_decision"] = "fallback"
    else:
        candidate["tracks"][_CORE_TRACK]["cel"]["per_rule"]["CEL_TEST"]["expression_hashes"].append("0" * 64)
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match=error_match):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        ("missing_marker", "exactly 1 SKILL_LOAD_FALLBACK_USED marker"),
        ("duplicate_marker", "exactly 1 SKILL_LOAD_FALLBACK_USED marker"),
        ("contradictory_marker", "contradictory bounded-loader marker"),
        ("unknown_code", "invalid identity"),
    ],
)
def test_bounded_loader_recovery_spoofs_are_rejected(
    tmp_path: Path,
    mutation: str,
    error_match: str,
) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    _add_loader_recovery(candidate)
    outcome = candidate["tracks"][_CORE_TRACK]["sample_outcomes"]["bounded-loader-recovery"]
    if mutation == "missing_marker":
        outcome["findings"] = []
    elif mutation == "duplicate_marker":
        outcome["findings"].append(copy.deepcopy(outcome["findings"][0]))
    elif mutation == "contradictory_marker":
        outcome["findings"][0]["severity"] = "HIGH"
        outcome["findings"][0]["cel_decision"] = "keep"
    else:
        outcome["loader_fallback_code"] = "UNBOUNDED_RECOVERY"
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match=error_match):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_compact_suppression_without_severity_and_context_is_rejected(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    outcome = candidate["tracks"][_CORE_TRACK]["sample_outcomes"][f"{_CORE_TRACK}-keep-0"]
    outcome["cel_suppressed"] = [{"rule_id": "CEL_TEST", "count": 1}]
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match="cel_suppressed.*invalid fields"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_projection_incomplete_count_requires_sample_identity(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["summary"]["cel"]["projection_incomplete"] = 1
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match="projection_incomplete cannot exceed CEL fallbacks"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_candidate_and_baseline_must_recover_the_same_loader_samples(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    _add_loader_recovery(candidate, benchmark_id="candidate-recovery")
    _add_loader_recovery(baseline, benchmark_id="baseline-recovery")
    _write_json(public_root / "candidate.json", candidate)
    _write_json(public_root / "baseline.json", baseline)
    _refresh_repeated_runs(public_root, candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert report["status"] == "failed"
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "public.summary.loader_fallback_identity" in failed
    assert f"public.track.{_CORE_TRACK}.loader_fallback_identity" in failed


def test_exact_closed_loader_rejection_remains_eligible_for_release(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    _add_loader_rejection(candidate)
    _add_loader_rejection(baseline)
    _write_json(public_root / "candidate.json", candidate)
    _write_json(public_root / "baseline.json", baseline)
    _refresh_repeated_runs(public_root, candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert report["status"] == "passed"
    rejection_checks = [check for check in report["checks"] if check["name"].endswith(".loader_rejection_identity")]
    assert rejection_checks
    assert all(check["passed"] for check in rejection_checks)


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        ("missing_marker", "exactly 1 SKILL_LOAD_REJECTED_LIMIT marker"),
        ("duplicate_marker", "exactly 1 SKILL_LOAD_REJECTED_LIMIT marker"),
        ("contradictory_marker", "contradictory closed-loader rejection marker"),
        ("unknown_code", "invalid identity"),
    ],
)
def test_closed_loader_rejection_compact_spoofs_are_rejected(
    tmp_path: Path,
    mutation: str,
    error_match: str,
) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    _add_loader_rejection(candidate)
    outcome = candidate["tracks"][_CORE_TRACK]["sample_outcomes"]["closed-loader-rejection"]
    if mutation == "missing_marker":
        outcome["findings"] = []
    elif mutation == "duplicate_marker":
        outcome["findings"].append(copy.deepcopy(outcome["findings"][0]))
    elif mutation == "contradictory_marker":
        outcome["findings"][0]["severity"] = "INFO"
        outcome["findings"][0]["cel_decision"] = "keep"
    else:
        outcome["loader_rejection_code"] = "UNKNOWN_LIMIT"
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match=error_match):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_candidate_and_baseline_must_reject_the_same_loader_samples(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    _add_loader_rejection(candidate, benchmark_id="candidate-rejection")
    _add_loader_rejection(baseline, benchmark_id="baseline-rejection")
    _write_json(public_root / "candidate.json", candidate)
    _write_json(public_root / "baseline.json", baseline)
    _refresh_repeated_runs(public_root, candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert report["status"] == "failed"
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "public.summary.loader_rejection_identity" in failed
    assert f"public.track.{_CORE_TRACK}.loader_rejection_identity" in failed


def test_closed_loader_rejection_must_be_bound_to_subgroup_evidence(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    _add_loader_rejection(candidate)
    source = next(iter(candidate["tracks"][_CORE_TRACK]["per_source"].values()))
    source["loader_rejections"] = 0
    source["loader_rejection_sample_ids"] = []
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(
        ReleaseGateError,
        match="per_source closed loader rejection IDs do not equal the track evidence",
    ):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_fatal_baseline_scan_error_cannot_hide_behind_passed_status(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    baseline["summary"]["scan_errors"] = 1
    track = baseline["tracks"][_CORE_TRACK]
    track["scan_errors"] = 1
    track["sample_outcomes"]["fatal-baseline-error"] = {
        "label": "benign",
        "scan_error": True,
        "recovered_scan_error": False,
        "loader_fallback_code": None,
        "loader_rejection_code": None,
        "cel_suppressed": [],
        "findings": [],
    }
    _write_json(public_root / "baseline.json", baseline)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert report["status"] == "failed"
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "public.summary.scan_errors" in failed
    assert f"public.track.{_CORE_TRACK}.scan_errors" in failed


def test_stable_id_set_detects_new_critical_or_high_false_negative(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["summary"]["critical_high_false_negatives"] = 2
    candidate["summary"]["critical_high_false_negative_ids"].append("new-high-fn")
    _write_json(public_root / "candidate.json", candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    check = next(
        item for item in report["checks"] if item["name"] == "public.summary.no_new_critical_high_false_negatives"
    )

    assert report["status"] == "failed"
    assert check["passed"] is False
    assert "new-high-fn" in check["detail"]


def test_exactly_five_repeated_runs_must_be_clean_and_deterministic(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    _write_json(public_root / "repeated-runs.json", _repeated_runs(candidate, failed_index=0))

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    repeated = next(check for check in report["checks"] if check["name"] == "promotion.deterministic_repeated_runs")

    assert report["status"] == "failed"
    assert repeated["current"] == {"runs": 5, "clean_runs": 4}
    assert repeated["passed"] is False


def test_repeated_run_hash_ignores_only_timing_and_keeps_detection_outcomes() -> None:
    report = _public_report()
    baseline = stable_release_output_sha256(report)
    timing_only = copy.deepcopy(report)
    timing_only["summary"]["p95_scan_latency_ms"] = 999.0
    timing_only["summary"]["cel"]["elapsed_ms"] = 999.0
    timing_only["tracks"][_CORE_TRACK]["cel_time_ratio"] = 0.001
    assert stable_release_output_sha256(timing_only) == baseline

    changed = copy.deepcopy(report)
    changed["summary"]["signal_recall"] = 0.5
    assert stable_release_output_sha256(changed) != baseline


def test_repeated_runs_bind_exact_generation_and_normalized_output(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    repeated_runs = _repeated_runs(candidate)
    repeated_runs["runs"][-1]["evidence_identity"]["rules_sha256"] = "9" * 64
    repeated_runs["runs"][-2]["output_sha256"] = "8" * 64
    _write_json(public_root / "repeated-runs.json", repeated_runs)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    repeated = next(check for check in report["checks"] if check["name"] == "promotion.deterministic_repeated_runs")

    assert report["status"] == "failed"
    assert repeated["current"] == {"runs": 5, "clean_runs": 3}
    assert "rules_sha256" in repeated["detail"]
    assert "output_sha256" in repeated["detail"]


@pytest.mark.parametrize("candidate_mode", ["off", "invalid"])
def test_candidate_must_supply_active_cel_evidence(tmp_path: Path, candidate_mode: str) -> None:
    public_root = _public_root(tmp_path)
    candidate = _public_report(cel_mode="off")
    if candidate_mode == "invalid":
        candidate["cel_mode"] = "shadow"
        candidate["evidence_identity"]["cel_mode"] = "shadow"
    _write_json(public_root / "candidate.json", candidate)
    _write_json(
        public_root / "repeated-runs.json",
        _repeated_runs(candidate, evidence_identity=candidate["evidence_identity"]),
    )

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    check = next(item for item in report["checks"] if item["name"] == "public.cel.candidate_active")

    assert report["status"] == "failed"
    assert check["passed"] is False


def test_development_cel_helper_is_an_explicit_blocker(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["summary"]["cel"]["runtime_versions"] = ["v0.32.0;helper=development"]
    _write_json(public_root / "candidate.json", candidate)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    check = next(item for item in report["checks"] if item["name"] == "public.cel.qualified_runtime")

    assert report["status"] == "failed"
    assert check["passed"] is False
    assert "non-development release build" in check["detail"]


def test_missing_subgroups_block_release(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    for report_name in ("candidate.json", "baseline.json"):
        report = json.loads((public_root / report_name).read_text(encoding="utf-8"))
        report["tracks"][_CORE_TRACK].pop("per_source")
        _write_json(public_root / report_name, report)

    result = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    check = next(item for item in result["checks"] if item["name"] == f"public.track.{_CORE_TRACK}.groups.complete")

    assert result["status"] == "failed"
    assert check["passed"] is False
    assert "per_source" in check["detail"]


def test_subgroup_signal_recall_regression_blocks_release(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["tracks"][_CORE_TRACK]["per_structural_family"]["family-a"]["signal_recall"] = 0.80
    _write_json(public_root / "candidate.json", candidate)

    result = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    check = next(
        item
        for item in result["checks"]
        if item["name"] == f"public.track.{_CORE_TRACK}.per_structural_family.family-a.signal_recall"
    )

    assert result["status"] == "failed"
    assert check["passed"] is False


def test_zero_strict_goldens_are_an_explicit_release_blocker(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path, golden=(0, 15))

    result = run_release_gate(
        public_corpus=public_root,
        dataset_lock=_promoted_lock(tmp_path),
    )
    strict = next(item for item in result["checks"] if item["name"] == "golden_corpus.strict_fixtures")
    legacy = next(item for item in result["checks"] if item["name"] == "golden_corpus.no_legacy_degraded")

    assert result["status"] == "failed"
    assert strict["passed"] is False
    assert "never scanner output" in strict["detail"]
    assert legacy["passed"] is False


@pytest.mark.parametrize(
    ("field", "check_name"),
    [
        ("scanner_derived_fixtures", "golden_corpus.no_scanner_derived_labels"),
        ("sealed_hf_model_labeled_fixtures", "golden_corpus.no_sealed_hf_model_labels"),
    ],
)
def test_forbidden_golden_label_sources_block_release(tmp_path: Path, field: str, check_name: str) -> None:
    public_root = _public_root(tmp_path)
    path = public_root / "golden-corpus.json"
    golden = json.loads(path.read_text(encoding="utf-8"))
    golden[field] = 1
    _write_json(path, golden)
    _write_json(tmp_path / "current-committed-golden.json", golden)

    result = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    check = next(item for item in result["checks"] if item["name"] == check_name)

    assert result["status"] == "failed"
    assert check["passed"] is False


def test_agent_labeled_strict_golden_source_is_supported(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    path = public_root / "golden-corpus.json"
    golden = json.loads(path.read_text(encoding="utf-8"))
    golden["label_sources"]["public_labeled"] = 0
    golden["label_sources"]["agent_labeled"] = 1
    _write_json(path, golden)
    _write_json(tmp_path / "current-committed-golden.json", golden)

    result = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))

    assert result["status"] == "passed"
    assert result["golden_corpus"]["label_sources"]["agent_labeled"] == 1


def test_required_missing_golden_evidence_is_a_reported_blocker(tmp_path: Path) -> None:
    with pytest.raises(ReleaseGateError, match="mandatory bundled golden-corpus.json is missing"):
        run_release_gate(
            public_corpus=_public_root(tmp_path, golden=None),
            dataset_lock=_promoted_lock(tmp_path),
        )


def test_bundled_golden_must_match_current_committed_manifest(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    bundled_path = public_root / "golden-corpus.json"
    bundled = json.loads(bundled_path.read_text(encoding="utf-8"))
    bundled["manifest_sha256"] = "9" * 64
    _write_json(bundled_path, bundled)

    with pytest.raises(
        ReleaseGateError,
        match="does not match the current committed exact-golden manifest",
    ):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_current_committed_golden_is_mandatory_and_independent(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    current_golden = tmp_path / "current-committed-golden.json"
    current_golden.unlink()

    with pytest.raises(ReleaseGateError, match="current committed golden evidence is unavailable"):
        _run_release_gate(
            public_corpus=public_root,
            committed_golden=current_golden,
            dataset_lock=_promoted_lock(tmp_path),
        )

    with pytest.raises(ReleaseGateError, match="must be independent of the public artifact"):
        _run_release_gate(
            public_corpus=public_root,
            committed_golden=public_root / "golden-corpus.json",
            dataset_lock=_promoted_lock(tmp_path),
        )

    current_golden.hardlink_to(public_root / "golden-corpus.json")
    with pytest.raises(ReleaseGateError, match="must be independent of the public artifact"):
        _run_release_gate(
            public_corpus=public_root,
            committed_golden=current_golden,
            dataset_lock=_promoted_lock(tmp_path),
        )


def test_private_population_never_blocks_public_release_gate(tmp_path: Path) -> None:
    private_root = _private_root(tmp_path)
    for name in ("candidate.json", "baseline.json"):
        report = json.loads((private_root / name).read_text(encoding="utf-8"))
        report["corpus"].update(samples=199, malicious_or_contextual=99, benign=100)
        _write_json(private_root / name, report)

    result = run_release_gate(
        public_corpus=_public_root(tmp_path),
        private_corpus=private_root,
        dataset_lock=_promoted_lock(tmp_path),
    )

    assert result["status"] == "passed"
    assert result["private"]["blocking"] is False


@pytest.mark.parametrize("label_source", release_gate._SCANNER_INDEPENDENT_LABEL_SOURCES)
def test_private_corpus_accepts_each_scanner_independent_label_source(
    tmp_path: Path,
    label_source: str,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir()
    _write_json(private_root / "candidate.json", _private_report(label_source=label_source))
    _write_json(private_root / "baseline.json", _private_report(cel_mode="off", label_source=label_source))

    result = run_release_gate(
        public_corpus=_public_root(tmp_path),
        private_corpus=private_root,
        dataset_lock=_promoted_lock(tmp_path),
    )

    assert result["status"] == "passed"
    assert result["private"]["status"] == "passed"
    assert result["private"]["label_sources"][label_source] == 200
    assert len(result["private"]["label_provenance_sha256"]) == 64
    assert len(result["private"]["label_evidence_sha256"]) == 64


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda corpus: corpus["label_attestation"].update(scanner_independent=False),
            "scanner_independent must be true",
        ),
        (
            lambda corpus: corpus["label_attestation"].update(scanner_outputs_used_as_labels=True),
            "scanner_outputs_used_as_labels must be false",
        ),
        (
            lambda corpus: corpus["label_attestation"]["label_sources"].update(scanner_derived=1),
            "label_sources must contain exactly",
        ),
        (
            lambda corpus: corpus["label_attestation"].update(label_provenance_sha256="0" * 64),
            "label_provenance_sha256 does not match",
        ),
        (
            lambda corpus: corpus["label_attestation"].update(label_evidence_sha256="0" * 64),
            "label_evidence_sha256 does not match",
        ),
    ],
)
def test_private_corpus_rejects_scanner_derived_partial_or_tampered_attestation(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    private_root = _private_root(tmp_path)
    for report_name in ("candidate.json", "baseline.json"):
        path = private_root / report_name
        report = json.loads(path.read_text(encoding="utf-8"))
        mutation(report["corpus"])
        _write_json(path, report)

    result = run_release_gate(
        public_corpus=_public_root(tmp_path),
        private_corpus=private_root,
        dataset_lock=_promoted_lock(tmp_path),
    )

    assert result["status"] == "passed"
    assert result["private"]["status"] == "failed"
    assert message in result["private"]["errors"][0]


def test_artifact_symlink_is_rejected_before_reports_are_consumed(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    (public_root / "unsafe-link").symlink_to(public_root / "candidate.json")

    with pytest.raises(ReleaseGateError, match="symbolic link"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_public_report_must_bind_to_reviewed_dataset_lock(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["dataset"]["artifact_manifest_sha256"] = "c" * 64
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match="candidate and baseline dataset artifact_manifest_sha256 differ"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_jointly_shrunken_candidate_and_baseline_cannot_shrink_release_denominator(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    for report_name in ("candidate.json", "baseline.json"):
        report = json.loads((public_root / report_name).read_text(encoding="utf-8"))
        track = report["tracks"][_CORE_TRACK]
        track["samples"] -= 1
        track["benign"] -= 1
        track["sample_outcomes_count"] -= 1
        _write_json(public_root / report_name, report)

    with pytest.raises(ReleaseGateError, match=r"core-only-source-disjoint\.samples.*blocking dataset lock"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_joint_membership_swap_cannot_preserve_counts_and_pass(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    swapped_population = "9" * 64
    for report_name in ("candidate.json", "baseline.json"):
        report = json.loads((public_root / report_name).read_text(encoding="utf-8"))
        report["tracks"][_CORE_TRACK]["population_sha256"] = swapped_population
        _write_json(public_root / report_name, report)

    with pytest.raises(ReleaseGateError, match=r"core-only-source-disjoint\.population_sha256.*lock"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_candidate_and_baseline_population_digests_must_match_each_other(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["tracks"][_CORE_TRACK]["population_sha256"] = "9" * 64
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match="population_sha256 differs between candidate and baseline"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_release_report_must_contain_every_locked_blocking_track(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    for report_name in ("candidate.json", "baseline.json"):
        report = json.loads((public_root / report_name).read_text(encoding="utf-8"))
        unexpected = report["tracks"].pop(_CORE_TRACK)
        unexpected["name"] = "unexpected-track"
        report["tracks"]["unexpected-track"] = unexpected
        _write_json(public_root / report_name, report)

    with pytest.raises(ReleaseGateError, match="exactly the locked blocking tracks"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_off_baseline_must_prove_same_qualified_compiled_generation(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    baseline["summary"]["cel"]["runtimes"] = ["unavailable"]
    baseline["summary"]["cel"]["runtime_versions"] = ["not_loaded"]
    _write_json(public_root / "baseline.json", baseline)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    qualified = next(check for check in report["checks"] if check["name"] == "public.cel.qualified_runtime")

    assert report["status"] == "failed"
    assert qualified["passed"] is False
    assert "baseline" in qualified["detail"]


def test_off_baseline_cannot_report_evaluation_or_decisions(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    baseline = json.loads((public_root / "baseline.json").read_text(encoding="utf-8"))
    baseline["summary"]["cel"]["evaluated"] = 1
    _write_json(public_root / "baseline.json", baseline)

    report = run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))
    baseline_off = next(check for check in report["checks"] if check["name"] == "public.cel.baseline_off")

    assert report["status"] == "failed"
    assert baseline_off["passed"] is False
    assert baseline_off["current"]["nonzero_counters"] == {"evaluated": 1}


def test_release_rejects_report_with_mid_run_identity_drift(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    candidate = json.loads((public_root / "candidate.json").read_text(encoding="utf-8"))
    candidate["identity_verification"]["end"]["rules_sha256"] = "0" * 64
    _write_json(public_root / "candidate.json", candidate)

    with pytest.raises(ReleaseGateError, match="start and end identities differ"):
        run_release_gate(public_corpus=public_root, dataset_lock=_promoted_lock(tmp_path))


def test_cli_passes_without_private_corpus(tmp_path: Path) -> None:
    output = tmp_path / "release-result.json"
    public_root = _public_root(tmp_path)
    _bind_public_source_revision(public_root, _SOURCE_REVISION)
    exit_code = main(
        [
            "--public-corpus",
            str(public_root),
            "--committed-golden",
            str(tmp_path / "current-committed-golden.json"),
            "--dataset-lock",
            str(_promoted_lock(tmp_path)),
            "--expected-source-revision",
            _SOURCE_REVISION,
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["status"] == "passed"
    assert report["private"]["enabled"] is False
    assert report["promotion_evidence"]["complete_public_release_run_passed"] is True


def test_cli_refuses_to_write_output_inside_immutable_corpus(tmp_path: Path) -> None:
    public_root = _public_root(tmp_path)
    output = public_root / "release-result.json"

    exit_code = main(
        [
            "--public-corpus",
            str(public_root),
            "--committed-golden",
            str(tmp_path / "current-committed-golden.json"),
            "--dataset-lock",
            str(_promoted_lock(tmp_path)),
            "--expected-source-revision",
            _SOURCE_REVISION,
            "--output",
            str(output),
        ]
    )

    assert exit_code == 2
    assert not output.exists()
