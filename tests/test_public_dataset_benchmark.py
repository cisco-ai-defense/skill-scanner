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
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
import yaml

from evals.datasets.public_datasets import (
    artifact_manifest_sha256,
    load_dataset_lock,
    quarantine_manifest_sha256,
    sample_metadata_manifest_sha256,
)
from evals.runners import public_dataset_benchmark
from evals.runners.produce_release_evidence import _write_json_new
from evals.runners.public_dataset_benchmark import (
    MALICIOUS_SKILL_BENCH,
    FrozenSample,
    PublicBenchmarkError,
    _empty_counts,
    _finalize_counts,
    _record_sample,
    _validated_cel_telemetry,
    _validated_findings,
    _write_report,
    compact_release_report,
    load_frozen_snapshot,
    main,
    run_public_benchmark,
)
from evals.runners.release_gate import run_release_gate, stable_release_output_sha256
from skill_scanner.core.cel.models import CelMode
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _write_trusted_pack(
    path: Path,
    *,
    name: str = "local-eval-pack",
    rule_id: str = "LOCAL_EVAL_MARKER",
) -> Path:
    path.mkdir()
    manifest = {
        "schema_version": 2,
        "name": name,
        "version": "1.0",
        "description": "Inert trusted-pack benchmark fixture",
        "rules": {
            rule_id: {
                "source": "signature",
                "category": "command_injection",
                "severity": "HIGH",
                "knobs": {"enabled": True},
                "description": "Detect an inert local benchmark marker",
                "file_types": ["markdown"],
                "remediation": "Remove the inert marker",
                "cel": {
                    "fact_schema": "v1",
                    "rollout": "shadow",
                    "expression": f'f.candidate.rule_id == "{rule_id}"',
                },
            }
        },
    }
    signatures = [
        {
            "id": rule_id,
            "category": "command_injection",
            "severity": "HIGH",
            "patterns": ["LOCAL_EVAL_MARKER"],
            "exclude_patterns": [],
            "file_types": ["markdown"],
            "description": "Detect an inert local benchmark marker",
            "remediation": "Remove the inert marker",
        }
    ]
    (path / "pack.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    (path / "signatures.yaml").write_text(yaml.safe_dump(signatures, sort_keys=False), encoding="utf-8")
    return path


def test_core_profile_loads_the_authoritative_bundled_v2_pack() -> None:
    registry = public_dataset_benchmark._core_registry()

    assert set(registry.all_packs()) == {"core"}
    core = registry.all_packs()["core"]
    assert core.schema_version == 2
    assert core.validation_report is not None
    assert core.validation_report.schema_status == "v2"
    assert core.validation_report.validation_scope == "strict_bundled_v2"
    assert len(registry) > 0


def test_core_profile_scanner_does_not_construct_the_full_bundled_registry(monkeypatch) -> None:
    def reject_full_registry(*_args, **_kwargs):
        raise AssertionError("core-only evaluation attempted to load all bundled packs")

    monkeypatch.setattr(public_dataset_benchmark.PackLoader, "build_registry", reject_full_registry)
    scanner = public_dataset_benchmark._default_scanner_factory("core_only", CelMode.OFF)
    try:
        assert scanner.rule_registry is not None
        assert set(scanner.rule_registry.all_packs()) == {"core"}
    finally:
        scanner.close()


def _track_expectation(dataset: dict, track: dict, samples: list[dict]) -> dict:
    selected = [sample for sample in samples if sample["splits"][track["protocol"]] == track["partition"]]
    payload = {
        "dataset_id": dataset["id"],
        "revision": dataset["revision"],
        "track": {field: track[field] for field in ("name", "detector_profile", "protocol", "partition")},
        "samples": [
            {
                "benchmark_id": sample["benchmark_id"],
                "category_ids": sample.get("category_ids", [sample.get("category_id", "unclassified")]),
                "label": sample["label"],
                "path": sample["path"],
                "source_id": sample["source_id"],
                "structural_family_id": sample["structural_family_id"],
            }
            for sample in sorted(selected, key=lambda item: item["benchmark_id"])
        ],
    }
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "samples": len(selected),
        "malicious": sum(sample["label"] == "malicious" for sample in selected),
        "benign": sum(sample["label"] == "benign" for sample in selected),
        "population_sha256": digest,
    }


def _snapshot(tmp_path: Path, *, pinned: bool = True) -> tuple[Path, Path, str]:
    root = tmp_path / "snapshot"
    root.mkdir(parents=True)
    definitions = [
        ("mal-source", "malicious", "SRC-A", "FAM-A", "command_execution", "test", "train"),
        ("ben-source", "benign", "SRC-B", "FAM-B", "command_execution", "test", "train"),
        ("mal-struct", "malicious", "SRC-C", "FAM-C", "data_exfiltration", "train", "test"),
        ("ben-struct", "benign", "SRC-D", "FAM-D", "data_exfiltration", "train", "test"),
    ]
    samples = []
    artifacts = []
    for benchmark_id, label, source, family, category, source_split, structural_split in definitions:
        directory = root / "skills" / benchmark_id
        directory.mkdir(parents=True)
        content = f"---\nname: {benchmark_id}\ndescription: Frozen evaluation fixture for {benchmark_id}\n---\n"
        skill_file = directory / "SKILL.md"
        skill_file.write_text(content, encoding="utf-8")
        encoded = content.encode("utf-8")
        artifacts.append(
            {
                "path": f"skills/{benchmark_id}/SKILL.md",
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "size_bytes": len(encoded),
            }
        )
        samples.append(
            {
                "benchmark_id": benchmark_id,
                "exact_hash": hashlib.sha256(encoded).hexdigest(),
                "label": label,
                "normalized_hash": hashlib.sha256(encoded).hexdigest(),
                "provenance": "unit_test",
                "source_id": source,
                "source_ids": [source],
                "source_pointer": f"test://{source}",
                "structural_family_id": family,
                "text_origin_source_id": source,
                "category_id": category,
                "path": f"skills/{benchmark_id}",
                "splits": {
                    "source_disjoint": source_split,
                    "m_structural_disjoint": structural_split,
                },
            }
        )

    lock = copy.deepcopy(load_dataset_lock())
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == MALICIOUS_SKILL_BENCH)
    dataset["expected"]["row_counts"] = {
        "primary/train": 4,
        "splits/source_disjoint": 4,
        "splits/m_structural_disjoint": 4,
    }
    dataset["expected"]["track_expectations"] = {
        track["name"]: _track_expectation(dataset, track, samples) for track in dataset["gating"]["tracks"]
    }
    dataset["integrity"].pop("materialization", None)
    digest = artifact_manifest_sha256(MALICIOUS_SKILL_BENCH, artifacts, manifest=lock)
    dataset["integrity"]["hashes_pending"] = not pinned
    dataset["integrity"]["artifact_manifest_sha256"] = digest if pinned else None
    dataset["gating"]["blocking"] = pinned
    metadata_digest = sample_metadata_manifest_sha256(
        MALICIOUS_SKILL_BENCH,
        samples,
        artifact_manifest_sha256=digest,
        manifest=lock,
    )
    dataset["integrity"]["sample_metadata_manifest_sha256"] = metadata_digest
    lock_path = tmp_path / "public-datasets.lock.json"
    _write_json(lock_path, lock)

    _write_json(
        root / "benchmark-snapshot.json",
        {
            "schema_version": 2,
            "dataset_id": MALICIOUS_SKILL_BENCH,
            "revision": dataset["revision"],
            "artifact_manifest_sha256": digest,
            "sample_metadata_manifest_sha256": metadata_digest,
            "artifacts": artifacts,
            "samples": samples,
        },
    )
    return root, lock_path, digest


def _refresh_track_expectations(lock_path: Path, samples: list[dict]) -> None:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == MALICIOUS_SKILL_BENCH)
    dataset["expected"]["track_expectations"] = {
        track["name"]: _track_expectation(dataset, track, samples) for track in dataset["gating"]["tracks"]
    }
    _write_json(lock_path, lock)


def _refresh_sample_metadata_digest(root: Path, lock_path: Path) -> str:
    manifest_path = root / "benchmark-snapshot.json"
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == MALICIOUS_SKILL_BENCH)
    digest = sample_metadata_manifest_sha256(
        MALICIOUS_SKILL_BENCH,
        snapshot["samples"],
        artifact_manifest_sha256=snapshot["artifact_manifest_sha256"],
        manifest=lock,
    )
    dataset["integrity"]["sample_metadata_manifest_sha256"] = digest
    snapshot["sample_metadata_manifest_sha256"] = digest
    _write_json(lock_path, lock)
    _write_json(manifest_path, snapshot)
    return digest


def _add_quarantined_train_sample(root: Path, lock_path: Path) -> tuple[str, str]:
    manifest_path = root / "benchmark-snapshot.json"
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == MALICIOUS_SKILL_BENCH)
    content = b"---\nname: quarantined\ndescription: Declared but unavailable fixture\n---\n"
    artifact = {
        "path": "skills/quarantined/SKILL.md",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }
    sample = {
        "benchmark_id": "quarantined",
        "exact_hash": hashlib.sha256(content).hexdigest(),
        "label": "malicious",
        "normalized_hash": hashlib.sha256(content).hexdigest(),
        "provenance": "unit_test",
        "source_id": "SRC-Q",
        "source_ids": ["SRC-Q"],
        "source_pointer": "test://SRC-Q",
        "structural_family_id": "FAM-Q",
        "text_origin_source_id": "SRC-Q",
        "category_id": "command_execution",
        "path": "skills/quarantined",
        "splits": {"source_disjoint": "train", "m_structural_disjoint": "train"},
    }
    record = {
        "benchmark_id": sample["benchmark_id"],
        "error_code": "ENDPOINT_PROTECTION_QUARANTINE",
        "label": sample["label"],
        "path": artifact["path"],
        "sha256": artifact["sha256"],
        "size_bytes": artifact["size_bytes"],
        "source_id": sample["source_id"],
        "splits": sample["splits"],
        "structural_family_id": sample["structural_family_id"],
    }
    snapshot["artifacts"].append(artifact)
    snapshot["samples"].append(sample)
    for key in dataset["expected"]["row_counts"]:
        dataset["expected"]["row_counts"][key] = 5
    declared_digest = artifact_manifest_sha256(MALICIOUS_SKILL_BENCH, snapshot["artifacts"], manifest=lock)
    dataset["integrity"]["artifact_manifest_sha256"] = declared_digest
    usable_digest = artifact_manifest_sha256(MALICIOUS_SKILL_BENCH, snapshot["artifacts"][:-1], manifest=lock)
    quarantine_digest = quarantine_manifest_sha256(
        MALICIOUS_SKILL_BENCH,
        [record],
        declared_artifact_manifest_sha256=declared_digest,
        manifest=lock,
    )
    dataset["integrity"]["materialization"] = {
        "declared_artifact_count": 5,
        "usable_artifact_count": 4,
        "error_count": 1,
        "usable_artifact_manifest_sha256": usable_digest,
        "quarantine_manifest_sha256": quarantine_digest,
    }
    snapshot["artifact_manifest_sha256"] = declared_digest
    snapshot["quarantine"] = {"manifest_sha256": quarantine_digest, "records": [record]}
    _write_json(lock_path, lock)
    _write_json(manifest_path, snapshot)
    _refresh_sample_metadata_digest(root, lock_path)
    return usable_digest, quarantine_digest


class _RecordingScanner:
    def __init__(
        self,
        profile: str,
        calls: list[tuple[str, str]],
        mode: CelMode = CelMode.OFF,
    ):
        self.profile = profile
        self.calls = calls
        self.mode = mode

    def scan_skill(self, path: Path):
        self.calls.append((self.profile, path.name))
        severity = "HIGH" if path.name.startswith("mal-") else None
        findings = (
            []
            if severity is None
            else [
                {
                    "id": "RECORDING_FINDING",
                    "rule_id": "RECORDING_FINDING",
                    "category": "command_execution",
                    "severity": severity,
                    "file_path": "SKILL.md",
                    "analyzer": "static",
                }
            ]
        )
        per_rule = {}
        if severity is not None and self.mode is not CelMode.OFF:
            lineage = {
                "rule_id": "CEL_RECORDING",
                "decision": "keep",
                "reason": "expression_true",
                "fact_schema": "v1",
                "expression_hash": "c" * 64,
                "pack": "core",
                "rollout": "shadow",
                "count": 1,
            }
            findings[0].update(
                {
                    "rule_id": "CEL_RECORDING",
                    "metadata": {
                        "cel": {key: value for key, value in lineage.items() if key not in {"rule_id", "count"}},
                        "cel_decisions": [lineage],
                    },
                }
            )
            per_rule = {
                "CEL_RECORDING": {
                    "keep": 1,
                    "would_suppress": 0,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hash": "c" * 64,
                    "pack": "core",
                    "rollout": "shadow",
                }
            }
        return SimpleNamespace(
            findings=findings,
            analyzers_failed=[],
            scan_duration_seconds=0.1,
            scan_metadata={
                "cel": {
                    "mode": self.mode.value,
                    "runtime": "cel-go",
                    "runtime_version": "v0.32.0;helper=test-build",
                    "fact_schema": "v1",
                    "expression_set_hash": "a" * 64,
                    "evaluated": int(bool(per_rule)),
                    "retained": len(findings),
                    "would_suppress": 0,
                    "suppressed": 0,
                    "fallbacks": 0,
                    "projection_incomplete": 0,
                    "elapsed_ms": 2.0 if self.mode is not CelMode.OFF else 0.0,
                    "projection_ms": 0.5 if self.mode is not CelMode.OFF else 0.0,
                    "evaluation_ms": 0.5 if self.mode is not CelMode.OFF else 0.0,
                    "errors": [],
                    "per_rule": per_rule,
                }
            },
        )


def _loader_fallback_metadata(error_code: str = "MALFORMED_YAML_FRONTMATTER") -> dict[str, object]:
    return {
        "fallback_used": True,
        "fallback_mode": "bounded_inert_raw_body",
        "strict_error_type": "SkillLoadError",
        "strict_error_code": error_code,
        "manifest_complete": False,
        "capability_facts_trusted": False,
        "projection_complete": False,
        "projection_error_code": "MANIFEST_METADATA_INCOMPLETE",
    }


def _add_loader_fallback_proof(result: SimpleNamespace, error_code: str = "MALFORMED_YAML_FRONTMATTER") -> None:
    metadata = _loader_fallback_metadata(error_code)
    result.analyzers_failed = [
        {
            "analyzer": "skill_loader",
            "error": f"SkillLoadError:{error_code}",
        }
    ]
    result.scan_metadata["loader"] = dict(metadata)
    result.findings.append(
        {
            "id": "SKILL_LOAD_FALLBACK_USED",
            "rule_id": "SKILL_LOAD_FALLBACK_USED",
            "analyzer": "skill_loader",
            "category": "policy_violation",
            "severity": "INFO",
            "metadata": dict(metadata),
        }
    )
    result.scan_metadata["cel"]["retained"] = len(result.findings)


def _add_loader_rejection_proof(result: SimpleNamespace) -> None:
    metadata = {
        "rejection_used": True,
        "rejection_mode": "hard_size_limit",
        "strict_error_type": "SkillLoadError",
        "strict_error_code": "SKILL_METADATA_SIZE_LIMIT_EXCEEDED",
        "manifest_complete": False,
        "capability_facts_trusted": False,
        "content_scanned": False,
        "size_bytes": 21_002_040,
        "limit_bytes": 10 * 1024 * 1024,
    }
    result.analyzers_failed = []
    result.scan_metadata["loader"] = dict(metadata)
    result.findings = [
        {
            "id": "SKILL_LOAD_REJECTED_LIMIT",
            "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
            "analyzer": "skill_loader",
            "category": "policy_violation",
            "severity": "HIGH",
            "file_path": "SKILL.md",
            "metadata": dict(metadata),
        }
    ]
    result.scan_metadata["cel"]["evaluated"] = 0
    result.scan_metadata["cel"]["retained"] = 1


def test_runs_core_source_disjoint_and_full_pack_structural_tracks(tmp_path, monkeypatch):
    root, lock_path, digest = _snapshot(tmp_path)
    snapshot = json.loads((root / "benchmark-snapshot.json").read_text(encoding="utf-8"))
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr("evals.runners.public_dataset_benchmark.scanner_version", "test-build")

    def factory(profile: str, mode: CelMode):
        return _RecordingScanner(profile, calls, mode)

    baseline = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        profile="release",
        cel_mode=CelMode.OFF,
        scanner_factory=factory,
    )
    assert baseline["status"] == "passed"
    assert baseline["summary"]["scan_errors"] == 0
    assert baseline["summary"]["cel"]["runtime_versions"] == ["v0.32.0;helper=test-build"]
    assert baseline["summary"]["cel"]["evaluated"] == 0
    assert baseline["identity_verification"]["status"] == "passed"
    assert baseline["identity_verification"]["start"] == baseline["identity_verification"]["end"]
    calls.clear()
    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        profile="release",
        cel_mode=CelMode.SHADOW,
        scanner_factory=factory,
    )

    assert report["status"] == "passed"
    assert report["dataset"] == {
        "id": MALICIOUS_SKILL_BENCH,
        "revision": "d4b42ce5766a6e0359c987cf59c1007cb3795a90",
        "artifact_manifest_sha256": digest,
        "sample_metadata_manifest_sha256": snapshot["sample_metadata_manifest_sha256"],
        "usable_artifact_manifest_sha256": digest,
        "quarantine_manifest_sha256": None,
        "quarantined_sample_count": 0,
        "source_artifact_manifest_sha256": "3d64779dc972759ede61717ac5cc7f4e87289add8feabff1e83c4289094ce300",
        "blocking_eligible": True,
        "nonblocking_reason": None,
    }
    assert calls == [
        ("core_only", "mal-source"),
        ("core_only", "ben-source"),
    ]
    tracks = list(report["tracks"].values())
    assert [track["protocol"] for track in tracks] == [
        "source_disjoint",
    ]
    assert tracks[0]["per_source"]["SRC-A"]["malicious"] == 1
    assert tracks[0]["per_structural_family"]["FAM-A"]["malicious"] == 1
    assert tracks[0]["per_category"]["command_execution"]["samples"] == 2
    assert report["summary"]["recall"] == 1.0
    assert report["summary"]["package_block_recall"] == 1.0
    assert report["summary"]["signal_recall"] == 1.0
    assert report["summary"]["macro_f1"] == 1.0
    assert report["summary"]["benign_actionable_fpr"] == 0.0
    assert report["summary"]["critical_high_false_negative_ids"] == []
    assert report["summary"]["p95_scan_latency_ms"] == 100.0
    assert report["summary"]["cel_time_ratio"] == pytest.approx(0.02)
    interval = tracks[0]["confidence_intervals_95"]["recall"]
    assert 0.0 < interval[0] < interval[1] <= 1.0
    assert tracks[0]["confidence_intervals_95"]["package_block_recall"] == interval

    evidence = tmp_path / "release-evidence"
    evidence.mkdir()
    compact_report = compact_release_report(report)
    _write_json_new(evidence / "candidate.json", compact_report)
    _write_json_new(evidence / "baseline.json", compact_release_report(baseline))
    golden_digest = "1" * 64
    golden_evidence = {
        "schema_version": 1,
        "strict_fixtures": 1,
        "legacy_degraded_fixtures": 0,
        "manifest_sha256": golden_digest,
        "label_sources": {
            "public_labeled": 1,
            "independent_ollama": 0,
            "agent_labeled": 0,
            "human_reviewed": 0,
        },
        "scanner_derived_fixtures": 0,
        "sealed_hf_model_labeled_fixtures": 0,
    }
    _write_json(evidence / "golden-corpus.json", golden_evidence)
    committed_golden = tmp_path / "current-committed-golden.json"
    _write_json(committed_golden, golden_evidence)
    started = datetime(2026, 8, 1, tzinfo=UTC)
    _write_json(
        evidence / "repeated-runs.json",
        {
            "schema_version": 1,
            "runs": [
                {
                    "run_id": str(index),
                    "completed_at": (started + timedelta(days=index)).isoformat(),
                    "status": "passed",
                    "evidence_identity": report["evidence_identity"],
                    "golden_manifest_sha256": golden_digest,
                    "output_sha256": stable_release_output_sha256(compact_report),
                }
                for index in range(5)
            ],
        },
    )
    gate = run_release_gate(
        public_corpus=evidence,
        dataset_lock=lock_path,
        committed_golden=committed_golden,
    )
    assert gate["status"] == "passed"


def test_release_profile_rejects_pending_snapshot_hashes(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path, pinned=False)
    calls: list[tuple[str, str]] = []
    factory = lambda profile, mode: _RecordingScanner(profile, calls)

    with pytest.raises(PublicBenchmarkError, match="reviewed, lock-pinned"):
        run_public_benchmark(
            root,
            dataset_lock=lock_path,
            scanner_factory=factory,
        )
    assert calls == []


def test_benchmark_closes_each_track_scanner(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    closed: list[str] = []

    class ClosingScanner(_RecordingScanner):
        def close(self) -> None:
            closed.append(self.profile)

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: ClosingScanner(profile, [], mode),
    )

    assert report["status"] == "passed"
    assert closed == ["core_only"]


def test_locally_extended_configuration_is_separate_from_locked_profiles(tmp_path, monkeypatch):
    root, lock_path, _ = _snapshot(tmp_path)
    trusted_pack = _write_trusted_pack(tmp_path / "trusted-pack")
    base_calls: list[tuple[str, str]] = []
    local_calls: list[tuple[str, str]] = []
    monkeypatch.setattr("evals.runners.public_dataset_benchmark.scanner_version", "test-build")

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        cel_mode=CelMode.SHADOW,
        scanner_factory=lambda profile, mode: _RecordingScanner(profile, base_calls, mode),
        trusted_rule_packs=[trusted_pack],
        locally_extended_scanner_factory=(lambda profile, mode: _RecordingScanner(profile, local_calls, mode)),
    )

    assert report["status"] == "passed"
    assert [track["detector_profile"] for track in report["tracks"].values()] == [
        "core_only",
    ]
    assert base_calls == [
        ("core_only", "mal-source"),
        ("core_only", "ben-source"),
    ]
    assert report["summary"]["samples"] == 2

    extended = report["locally_extended"]
    assert extended["status"] == "passed"
    assert extended["release_blocking"] is False
    assert extended["base_configuration"] == "core_only"
    assert extended["summary"]["samples"] == 2
    assert local_calls == [
        ("locally_extended", "mal-source"),
        ("locally_extended", "ben-source"),
    ]
    local_track = extended["tracks"]["core-only-source-disjoint-locally-extended"]
    assert local_track["detector_profile"] == "locally_extended"
    assert local_track["population_reference_track"] == "core-only-source-disjoint"
    assert local_track["population_sha256"] == report["tracks"]["core-only-source-disjoint"]["population_sha256"]
    pack_identity = extended["trusted_rule_pack_set"]
    assert pack_identity["format"] == "trusted-rule-pack-set-v1"
    assert len(pack_identity["sha256"]) == 64
    assert pack_identity["packs"] == [
        {
            "name": "local-eval-pack",
            "version": "1.0",
            "sha256": pack_identity["packs"][0]["sha256"],
            "rule_count": 1,
            "cel_rule_count": 1,
        }
    ]
    assert str(trusted_pack) not in json.dumps(extended)
    assert extended["evidence_identity"]["trusted_rule_pack_set_sha256"] == pack_identity["sha256"]
    assert report["identity_verification"]["start"] == report["identity_verification"]["end"]

    compact = compact_release_report(report)
    compact_local_track = compact["locally_extended"]["tracks"]["core-only-source-disjoint-locally-extended"]
    assert compact_local_track["sample_outcomes_count"] == 2
    assert compact_local_track["sample_outcomes_format"] == "cel-referenced-v3"


def test_public_compact_writer_uses_canonical_json(tmp_path: Path) -> None:
    destination = tmp_path / "compact.json"
    report = {
        "release_evidence": {
            "format": "compact-v3",
            "full_sample_outcomes_domain": "skill-scanner-release-sample-outcomes-v1",
            "cel_decision_identity": "track.cel.per_rule",
        },
        "z": [2, 1],
        "a": {"value": True},
    }

    _write_report(destination, report)

    assert destination.read_bytes() == (
        b'{"a":{"value":true},"release_evidence":{"cel_decision_identity":"track.cel.per_rule",'
        b'"format":"compact-v3","full_sample_outcomes_domain":"skill-scanner-release-sample-outcomes-v1"},'
        b'"z":[2,1]}\n'
    )


def test_locally_extended_requires_valid_unique_disjoint_non_symlink_packs(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    trusted_pack = _write_trusted_pack(tmp_path / "trusted-pack")

    with pytest.raises(PublicBenchmarkError, match="does not exist"):
        run_public_benchmark(root, dataset_lock=lock_path, trusted_rule_packs=[tmp_path / "missing"])
    with pytest.raises(PublicBenchmarkError, match="duplicate trusted rule-pack path"):
        run_public_benchmark(root, dataset_lock=lock_path, trusted_rule_packs=[trusted_pack, trusted_pack])

    linked_pack = tmp_path / "linked-pack"
    linked_pack.symlink_to(trusted_pack, target_is_directory=True)
    with pytest.raises(PublicBenchmarkError, match="must not be a symbolic link"):
        run_public_benchmark(root, dataset_lock=lock_path, trusted_rule_packs=[linked_pack])

    parent_pack_root = tmp_path / "parent-pack"
    parent_pack = _write_trusted_pack(parent_pack_root)
    nested_root, nested_lock, _ = _snapshot(parent_pack_root)
    with pytest.raises(PublicBenchmarkError, match="must be disjoint"):
        run_public_benchmark(nested_root, dataset_lock=nested_lock, trusted_rule_packs=[parent_pack])


def test_trusted_pack_set_identity_is_path_independent_and_order_stable(tmp_path):
    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()
    second = _write_trusted_pack(
        tmp_path / "z-path",
        name="second-local-pack",
        rule_id="SECOND_LOCAL_MARKER",
    )
    first = _write_trusted_pack(
        tmp_path / "a-path",
        name="first-local-pack",
        rule_id="FIRST_LOCAL_MARKER",
    )

    forward = public_dataset_benchmark._trusted_pack_set(
        [first, second],
        snapshot_root=snapshot_root,
    )
    reverse = public_dataset_benchmark._trusted_pack_set(
        [second, first],
        snapshot_root=snapshot_root,
    )

    assert forward.identity == reverse.identity
    assert [pack["name"] for pack in forward.identity["packs"]] == [
        "first-local-pack",
        "second-local-pack",
    ]
    assert forward.paths == (first.resolve(), second.resolve())
    assert str(first) not in json.dumps(forward.identity)
    assert str(second) not in json.dumps(forward.identity)


def test_trusted_pack_set_rejects_non_directory_invalid_member_link_and_size_boundary(tmp_path, monkeypatch):
    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()
    non_directory = tmp_path / "pack.yaml"
    non_directory.write_text("schema_version: 2\n", encoding="utf-8")
    with pytest.raises(PublicBenchmarkError, match="must be a directory"):
        public_dataset_benchmark._trusted_pack_set([non_directory], snapshot_root=snapshot_root)

    invalid = _write_trusted_pack(tmp_path / "invalid-pack")
    manifest = invalid / "pack.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("schema_version: 2", "schema_version: 1"),
        encoding="utf-8",
    )
    with pytest.raises(PublicBenchmarkError, match="invalid trusted rule-pack set"):
        public_dataset_benchmark._trusted_pack_set([invalid], snapshot_root=snapshot_root)

    linked = _write_trusted_pack(
        tmp_path / "linked-member-pack",
        name="linked-member-pack",
        rule_id="LINKED_MEMBER_MARKER",
    )
    (linked / "ignored-link").symlink_to(linked / "pack.yaml")
    with pytest.raises(PublicBenchmarkError, match="contains a symbolic link"):
        public_dataset_benchmark._trusted_pack_set([linked], snapshot_root=snapshot_root)

    bounded = _write_trusted_pack(
        tmp_path / "bounded-pack",
        name="bounded-pack",
        rule_id="BOUNDED_MARKER",
    )
    monkeypatch.setattr(public_dataset_benchmark, "_MAX_TRUSTED_PACK_FILE_BYTES", 1)
    with pytest.raises(PublicBenchmarkError, match="file exceeds 1 bytes"):
        public_dataset_benchmark._trusted_pack_set([bounded], snapshot_root=snapshot_root)


def test_locally_extended_pack_drift_fails_without_shrinking_denominators(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    trusted_pack = _write_trusted_pack(tmp_path / "trusted-pack")
    changed = False

    class MutatingLocalScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            nonlocal changed
            result = super().scan_skill(path)
            if not changed:
                changed = True
                manifest = trusted_pack / "pack.yaml"
                manifest.write_text(
                    manifest.read_text(encoding="utf-8") + "\n# changed during scan\n", encoding="utf-8"
                )
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: _RecordingScanner(profile, [], mode),
        trusted_rule_packs=[trusted_pack],
        locally_extended_scanner_factory=lambda profile, mode: MutatingLocalScanner(profile, [], mode),
    )

    assert report["status"] == "failed"
    assert report["summary"]["samples"] == 2
    assert report["locally_extended"]["summary"]["samples"] == 2
    assert report["locally_extended"]["status"] == "failed"
    assert report["identity_verification"]["drifted_fields"] == ["trusted_rule_pack_set_sha256"]
    assert "trusted_rule_pack_set_sha256" in report["errors"][-1]["error"]


def test_locally_extended_default_factory_requires_explicit_packs():
    with pytest.raises(PublicBenchmarkError, match="requires trusted local rule packs"):
        public_dataset_benchmark._default_scanner_factory("locally_extended", CelMode.OFF)


def test_locally_extended_default_factory_loads_validated_pack(tmp_path):
    trusted_pack = _write_trusted_pack(tmp_path / "trusted-pack")

    scanner = public_dataset_benchmark._default_scanner_factory(
        "locally_extended",
        CelMode.OFF,
        trusted_rule_packs=[trusted_pack],
    )
    try:
        assert scanner.rule_registry is not None
        assert "local-eval-pack" in scanner.rule_registry.all_packs()
    finally:
        scanner.close()


def test_explicit_train_only_quarantine_preserves_blocking_track_denominators(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    usable_digest, quarantine_digest = _add_quarantined_train_sample(root, lock_path)
    calls: list[tuple[str, str]] = []

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        profile="release",
        scanner_factory=lambda profile, mode: _RecordingScanner(profile, calls, mode),
    )

    assert report["status"] == "passed"
    assert report["dataset"]["blocking_eligible"] is True
    assert report["dataset"]["usable_artifact_manifest_sha256"] == usable_digest
    assert report["dataset"]["quarantine_manifest_sha256"] == quarantine_digest
    assert report["dataset"]["quarantined_sample_count"] == 1
    assert {track["samples"] for track in report["tracks"].values()} == {2}
    assert all(call[1] != "quarantined" for call in calls)


def test_quarantined_member_cannot_belong_to_a_blocking_track(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    _add_quarantined_train_sample(root, lock_path)
    manifest_path = root / "benchmark-snapshot.json"
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == MALICIOUS_SKILL_BENCH)
    sample = next(sample for sample in snapshot["samples"] if sample["benchmark_id"] == "quarantined")
    record = snapshot["quarantine"]["records"][0]
    sample["splits"]["source_disjoint"] = "test"
    record["splits"]["source_disjoint"] = "test"
    digest = quarantine_manifest_sha256(
        MALICIOUS_SKILL_BENCH,
        [record],
        declared_artifact_manifest_sha256=snapshot["artifact_manifest_sha256"],
        manifest=lock,
    )
    snapshot["quarantine"]["manifest_sha256"] = digest
    dataset["integrity"]["materialization"]["quarantine_manifest_sha256"] = digest
    _write_json(manifest_path, snapshot)
    _write_json(lock_path, lock)
    _refresh_sample_metadata_digest(root, lock_path)

    with pytest.raises(PublicBenchmarkError, match="belongs to blocking track"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_same_count_track_membership_swap_fails_before_scanner_construction(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    manifest_path = root / "benchmark-snapshot.json"
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_id = {sample["benchmark_id"]: sample for sample in snapshot["samples"]}
    by_id["mal-source"]["splits"]["source_disjoint"] = "train"
    by_id["mal-struct"]["splits"]["source_disjoint"] = "test"
    _write_json(manifest_path, snapshot)
    constructed: list[str] = []

    def factory(profile: str, mode: CelMode):
        constructed.append(profile)
        return _RecordingScanner(profile, [], mode)

    with pytest.raises(PublicBenchmarkError, match="sample metadata manifest digest mismatch"):
        run_public_benchmark(root, dataset_lock=lock_path, scanner_factory=factory)
    assert constructed == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda samples: samples[0].update(label="benign"),
        lambda samples: samples[0].update(
            source_id="SRC-TAMPERED",
            source_ids=["SRC-TAMPERED"],
            text_origin_source_id="SRC-TAMPERED",
        ),
        lambda samples: samples[0].update(structural_family_id="FAM-TAMPERED"),
        lambda samples: samples[0].update(category_id="data_exfiltration"),
        lambda samples: samples[0]["splits"].update(m_structural_disjoint="validation"),
        lambda samples: samples[0].update(exact_hash="f" * 64),
        lambda samples: (
            samples[0].update(path="skills/ben-source"),
            samples[1].update(path="skills/mal-source"),
        ),
    ],
    ids=["label", "source", "family", "category", "non-gating-split", "exact-hash", "path"],
)
def test_sample_metadata_tampering_fails_against_independently_pinned_digest(tmp_path, mutation):
    root, lock_path, _ = _snapshot(tmp_path)
    manifest_path = root / "benchmark-snapshot.json"
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutation(snapshot["samples"])
    _write_json(manifest_path, snapshot)

    with pytest.raises(PublicBenchmarkError, match="sample metadata manifest digest mismatch"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_artifact_tampering_and_unmanaged_files_fail_closed(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    (root / "skills" / "mal-source" / "SKILL.md").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(PublicBenchmarkError, match="artifact inventory mismatch"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_snapshot_rejects_declared_package_files_and_executable_hooks(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path, pinned=False)
    hook = root / "skills" / "mal-source" / "setup.py"
    hook.write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")
    manifest_path = root / "benchmark-snapshot.json"
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    content = hook.read_bytes()
    snapshot["artifacts"].append(
        {
            "path": "skills/mal-source/setup.py",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
    )
    lock = load_dataset_lock(lock_path)
    snapshot["artifact_manifest_sha256"] = artifact_manifest_sha256(
        MALICIOUS_SKILL_BENCH,
        snapshot["artifacts"],
        manifest=lock,
    )
    _write_json(manifest_path, snapshot)
    _refresh_sample_metadata_digest(root, lock_path)

    with pytest.raises(PublicBenchmarkError, match="executable ingestion hooks"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_snapshot_validates_every_locked_split_manifest_row_count(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    lock = load_dataset_lock(lock_path)
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == MALICIOUS_SKILL_BENCH)
    dataset["expected"]["row_counts"]["splits/source_disjoint"] = 5
    _write_json(lock_path, lock)

    with pytest.raises(PublicBenchmarkError, match="source_disjoint split-manifest count drift"):
        load_frozen_snapshot(root, dataset_lock=lock_path)

    root, lock_path, _ = _snapshot(tmp_path / "second")
    (root / "unmanaged.txt").write_text("not in manifest", encoding="utf-8")
    with pytest.raises(PublicBenchmarkError, match="artifact inventory mismatch"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_snapshot_rejects_symlinks_without_following_them(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (root / "skills" / "mal-source" / "escape").symlink_to(outside)

    with pytest.raises(PublicBenchmarkError, match="symbolic link"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_snapshot_rejects_duplicate_json_keys(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    manifest_path = root / "benchmark-snapshot.json"
    original = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        original.replace('"schema_version": 2,', '"schema_version": 2, "schema_version": 2,'), encoding="utf-8"
    )

    with pytest.raises(PublicBenchmarkError, match="duplicate key"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_scan_errors_are_reported_and_fail_the_complete_benchmark(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class BrokenScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            if path.name == "mal-source":
                raise RuntimeError("deliberate scan failure")
            return super().scan_skill(path)

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: BrokenScanner(profile, []),
    )
    assert report["status"] == "failed"
    assert report["errors"] == [{"benchmark_id": "mal-source", "error": "deliberate scan failure"}]
    first_track = next(iter(report["tracks"].values()))
    assert first_track["samples"] == 2
    assert first_track["scan_errors"] == 1
    assert first_track["critical_high_false_negative_ids"] == ["mal-source"]


@pytest.mark.parametrize("severity", ["HGIH", None, 7, True])
def test_invalid_finding_severity_fails_conservatively_without_shrinking_denominators(tmp_path, severity):
    root, lock_path, _ = _snapshot(tmp_path)

    class InvalidSeverityScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "ben-source":
                result.findings = [{"rule_id": "BROKEN_SEVERITY", "severity": severity}]
                result.findings[0].update(
                    id="BROKEN_SEVERITY",
                    category="command_execution",
                    file_path="SKILL.md",
                    analyzer="static",
                )
                result.scan_metadata["cel"]["retained"] = 1
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: InvalidSeverityScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "failed"
    assert source_track["status"] == "failed"
    assert source_track["samples"] == 2
    assert source_track["malicious"] == source_track["benign"] == 1
    assert source_track["scan_errors"] == 1
    assert source_track["tp"] == source_track["fp"] == 1
    assert source_track["tn"] == source_track["fn"] == 0
    assert source_track["actionable_benign_false_positives"] == 1
    assert source_track["benign_actionable_fpr"] == 1.0
    assert report["errors"] == [
        {
            "benchmark_id": "ben-source",
            "error": "scanner returned invalid finding severity for ben-source at findings[0]",
        }
    ]


@pytest.mark.parametrize("findings", [None, "HIGH", {"severity": "HIGH"}])
def test_invalid_findings_collection_is_a_conservative_scan_error(tmp_path, findings):
    root, lock_path, _ = _snapshot(tmp_path)

    class InvalidFindingsScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "ben-source":
                result.findings = findings
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: InvalidFindingsScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "failed"
    assert source_track["samples"] == 2
    assert source_track["scan_errors"] == 1
    assert source_track["tp"] == source_track["fp"] == 1
    assert source_track["tn"] == source_track["fn"] == 0
    assert source_track["benign_actionable_fpr"] == 1.0
    assert report["errors"] == [
        {
            "benchmark_id": "ben-source",
            "error": "scanner returned invalid findings collection for ben-source",
        }
    ]


@pytest.mark.parametrize(
    ("mutation", "field"),
    [
        (lambda finding: finding.pop("id"), "id"),
        (lambda finding: finding.pop("rule_id"), "rule_id"),
        (lambda finding: finding.pop("category"), "category"),
        (lambda finding: finding.pop("analyzer"), "analyzer"),
        (lambda finding: finding.update(file_path="../escape"), "file_path"),
        (lambda finding: finding.update(line_number=0), "line_number"),
    ],
)
def test_metric_critical_finding_identity_is_validated(mutation, field: str) -> None:
    finding = {
        "id": "TEST_FINDING",
        "rule_id": "TEST_FINDING",
        "category": "command_execution",
        "severity": "HIGH",
        "file_path": "SKILL.md",
        "line_number": 1,
        "analyzer": "static",
    }
    mutation(finding)

    with pytest.raises(PublicBenchmarkError, match=field):
        _validated_findings(SimpleNamespace(findings=[finding]), "sample")


def test_analyzer_failures_preserve_both_class_denominators_conservatively(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class PartialScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name in {"mal-source", "ben-source"}:
                result.analyzers_failed = [{"analyzer": "static", "error": "partial scan"}]
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: PartialScanner(profile, []),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert source_track["status"] == "failed"
    assert source_track["samples"] == 2
    assert source_track["malicious"] == 1
    assert source_track["benign"] == 1
    assert source_track["scan_errors"] == 2
    assert source_track["fn"] == 1
    assert source_track["fp"] == 1
    assert source_track["tp"] == source_track["tn"] == 0
    assert source_track["accuracy"] == 0.0
    assert source_track["critical_high_false_negative_ids"] == ["mal-source"]


def test_bounded_loader_fallback_retains_findings_and_records_recovery(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class RecoveredLoaderScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                _add_loader_fallback_proof(result)
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: RecoveredLoaderScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "passed"
    assert source_track["samples"] == 2
    assert source_track["scan_errors"] == 0
    assert source_track["tp"] == 1
    assert source_track["loader_fallbacks"] == 1
    assert source_track["recovered_scan_errors"] == 1
    assert source_track["loader_fallback_sample_ids"] == ["mal-source"]
    assert source_track["per_source"]["SRC-A"]["loader_fallback_sample_ids"] == ["mal-source"]
    assert source_track["per_structural_family"]["FAM-A"]["loader_fallbacks"] == 1
    assert source_track["per_category"]["command_execution"]["recovered_scan_errors"] == 1

    outcome = source_track["sample_outcomes"]["mal-source"]
    assert outcome["scan_error"] is False
    assert outcome["recovered_scan_error"] is True
    assert outcome["loader_fallback_code"] == "MALFORMED_YAML_FRONTMATTER"
    assert outcome["loader_rejection_code"] is None
    assert {
        "rule_id": "SKILL_LOAD_FALLBACK_USED",
        "category": "policy_violation",
        "severity": "INFO",
        "cel_decision": None,
        "cel_decisions": [],
    } in outcome["findings"]

    summary = report["summary"]
    assert summary["loader_fallbacks"] == summary["recovered_scan_errors"] == 1
    assert summary["loader_fallback_sample_ids"] == [f"{source_track['name']}:mal-source"]

    compact = compact_release_report(report)
    compact_outcome = compact["tracks"][source_track["name"]]["sample_outcomes"]["mal-source"]
    assert compact_outcome["recovered_scan_error"] is True
    assert compact_outcome["loader_fallback_code"] == "MALFORMED_YAML_FRONTMATTER"
    assert {
        "rule_id": "SKILL_LOAD_FALLBACK_USED",
        "severity": "INFO",
        "cel_decision": None,
        "cel_decisions": [],
    } in compact_outcome["findings"]


def test_spoofed_loader_fallback_without_analyzer_failure_is_fatal(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class SpoofedLoaderScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                _add_loader_fallback_proof(result)
                result.analyzers_failed = []
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: SpoofedLoaderScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "failed"
    assert source_track["samples"] == 2
    assert source_track["scan_errors"] == 1
    assert source_track["loader_fallbacks"] == source_track["recovered_scan_errors"] == 0
    assert source_track["loader_fallback_sample_ids"] == []
    assert "exactly one analyzer failure" in source_track["errors"][0]["error"]
    assert source_track["sample_outcomes"]["mal-source"] == {
        "label": "malicious",
        "blocked": False,
        "actionable": False,
        "signal": False,
        "scan_error": True,
        "recovered_scan_error": False,
        "loader_fallback_code": None,
        "loader_rejection_code": None,
        "cel_suppressed": [],
        "findings": [],
    }


def test_closed_loader_rejection_is_counted_as_a_normal_high_finding(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class RejectedLoaderScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                _add_loader_rejection_proof(result)
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: RejectedLoaderScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "passed"
    assert source_track["scan_errors"] == 0
    assert source_track["tp"] == 1
    assert source_track["loader_rejections"] == 1
    assert source_track["loader_rejection_sample_ids"] == ["mal-source"]
    outcome = source_track["sample_outcomes"]["mal-source"]
    assert outcome["loader_rejection_code"] == "SKILL_METADATA_SIZE_LIMIT_EXCEEDED"
    assert outcome["loader_fallback_code"] is None
    assert outcome["recovered_scan_error"] is False
    assert outcome["findings"] == [
        {
            "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
            "category": "policy_violation",
            "severity": "HIGH",
            "cel_decision": None,
            "cel_decisions": [],
        }
    ]
    assert report["summary"]["loader_rejections"] == 1
    assert report["summary"]["loader_rejection_sample_ids"] == [f"{source_track['name']}:mal-source"]

    compact = compact_release_report(report)
    compact_outcome = compact["tracks"][source_track["name"]]["sample_outcomes"]["mal-source"]
    assert compact_outcome["loader_rejection_code"] == "SKILL_METADATA_SIZE_LIMIT_EXCEEDED"
    assert compact_outcome["findings"] == [
        {
            "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
            "severity": "HIGH",
            "cel_decision": None,
            "cel_decisions": [],
        }
    ]


def test_spoofed_closed_loader_rejection_is_a_fatal_scan_error(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class SpoofedRejectedLoaderScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                _add_loader_rejection_proof(result)
                result.scan_metadata["loader"]["content_scanned"] = True
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: SpoofedRejectedLoaderScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "failed"
    assert source_track["scan_errors"] == 1
    assert source_track["loader_rejections"] == 0
    assert source_track["loader_rejection_sample_ids"] == []
    assert source_track["sample_outcomes"]["mal-source"]["loader_rejection_code"] is None


def test_mismatched_loader_fallback_error_code_is_fatal(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class MismatchedLoaderScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                _add_loader_fallback_proof(result)
                result.scan_metadata["loader"]["strict_error_code"] = "MISSING_REQUIRED_MANIFEST_FIELD"
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: MismatchedLoaderScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert report["status"] == "failed"
    assert source_track["scan_errors"] == 1
    assert source_track["recovered_scan_errors"] == 0
    assert "scan_metadata.loader does not match" in source_track["errors"][0]["error"]


@pytest.mark.parametrize(
    ("field", "spoofed_value"),
    [
        ("id", "NOT_THE_LOADER_MARKER"),
        ("category", "malware"),
        ("severity", "HIGH"),
    ],
)
def test_spoofed_loader_fallback_marker_identity_is_fatal(tmp_path, field, spoofed_value):
    root, lock_path, _ = _snapshot(tmp_path)

    class SpoofedMarkerScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                _add_loader_fallback_proof(result)
                result.findings[-1][field] = spoofed_value
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: SpoofedMarkerScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert source_track["status"] == "failed"
    assert source_track["scan_errors"] == 1
    assert source_track["recovered_scan_errors"] == 0
    assert "invalid marker identity" in source_track["errors"][0]["error"]


def test_invalid_telemetry_counts_sample_once_as_a_scan_error(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class InvalidTelemetryScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            result = super().scan_skill(path)
            if path.name == "mal-source":
                result.scan_metadata = {"cel": {"elapsed_ms": 101.0, "fallbacks": 0}}
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: InvalidTelemetryScanner(profile, []),
    )

    first_track = next(iter(report["tracks"].values()))
    assert first_track["samples"] == 2
    assert first_track["malicious"] == 1
    assert first_track["scan_errors"] == 1
    assert first_track["fn"] == 1
    assert first_track["tp"] == 0


def test_reports_shadow_deltas_by_sample_and_rule(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)

    class ShadowScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            is_malicious = path.name.startswith("mal-")
            findings = []
            if is_malicious:
                findings = [
                    {
                        "id": "CEL_TEST",
                        "rule_id": "CEL_TEST",
                        "category": "command_execution",
                        "severity": "HIGH",
                        "file_path": "SKILL.md",
                        "analyzer": "static",
                        "metadata": {
                            "cel": {
                                "decision": "would_suppress",
                                "reason": "shadow_or_rule_rollout",
                                "fact_schema": "v1",
                                "expression_hash": "c" * 64,
                                "pack": "core",
                                "rollout": "shadow",
                            }
                        },
                    }
                ]
            return SimpleNamespace(
                findings=findings,
                analyzers_failed=[],
                scan_duration_seconds=0.1,
                scan_metadata={
                    "cel": {
                        "mode": "shadow",
                        "runtime": "cel-go",
                        "runtime_version": "v0.32.0;helper=test-build",
                        "fact_schema": "v1",
                        "expression_set_hash": "a" * 64,
                        "evaluated": int(is_malicious),
                        "retained": len(findings),
                        "would_suppress": int(is_malicious),
                        "suppressed": 0,
                        "fallbacks": 0,
                        "projection_incomplete": 0,
                        "elapsed_ms": 2.0,
                        "projection_ms": 0.5,
                        "evaluation_ms": 1.0,
                        "errors": [],
                        "per_rule": (
                            {
                                "CEL_TEST": {
                                    "keep": 0,
                                    "would_suppress": 1,
                                    "fallback": 0,
                                    "suppressed": 0,
                                    "expression_hash": "c" * 64,
                                    "pack": "core",
                                    "rollout": "shadow",
                                }
                            }
                            if is_malicious
                            else {}
                        ),
                    }
                },
            )

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        cel_mode=CelMode.SHADOW,
        scanner_factory=lambda profile, mode: ShadowScanner(profile, []),
    )

    cel = report["summary"]["cel"]
    assert cel["modes"] == ["shadow"]
    assert cel["evaluated"] == 1
    assert cel["would_suppress"] == 1
    assert cel["would_suppress_sample_ids"] == ["mal-source"]
    assert cel["per_rule"]["CEL_TEST"] == {
        "keep": 0,
        "would_suppress": 1,
        "fallback": 0,
        "suppressed": 0,
        "expression_hashes": ["c" * 64],
        "packs": ["core"],
        "rollouts": ["shadow"],
    }


def test_release_requires_category_group_for_every_sample(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    manifest_path = root / "benchmark-snapshot.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for sample in manifest["samples"]:
        sample.pop("category_id")
    _write_json(manifest_path, manifest)
    _refresh_sample_metadata_digest(root, lock_path)

    with pytest.raises(PublicBenchmarkError, match="requires category_id"):
        run_public_benchmark(
            root,
            dataset_lock=lock_path,
            profile="release",
            scanner_factory=lambda profile, mode: _RecordingScanner(profile, []),
        )


def test_multi_category_and_excluded_split_values_are_preserved(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    manifest_path = root / "benchmark-snapshot.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sample = manifest["samples"][0]
    sample.pop("category_id")
    sample["category_ids"] = ["command_execution", "data_exfiltration"]
    manifest["samples"][2]["splits"]["source_disjoint"] = "excluded"
    _write_json(manifest_path, manifest)
    _refresh_track_expectations(lock_path, manifest["samples"])
    _refresh_sample_metadata_digest(root, lock_path)

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: _RecordingScanner(profile, [], mode),
    )

    source_track = next(track for track in report["tracks"].values() if track["protocol"] == "source_disjoint")
    assert source_track["per_category"]["command_execution"]["samples"] == 2
    assert source_track["per_category"]["data_exfiltration"]["samples"] == 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["samples"][0]["category_ids"] = ["data_exfiltration", "command_execution"]
    _write_json(manifest_path, manifest)
    with pytest.raises(PublicBenchmarkError, match="sorted and duplicate-free"):
        load_frozen_snapshot(root, dataset_lock=lock_path)


def test_real_no_rule_scanner_normalizes_explicit_off_runtime_and_generation(tmp_path):
    skill_dir = tmp_path / "real-off"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: real-off\ndescription: Safe CEL-off telemetry regression fixture\n---\n",
        encoding="utf-8",
    )
    policy = ScanPolicy.default()
    policy.cel.mode = CelMode.OFF
    result = SkillScanner(analyzers=[], policy=policy, cel_rules=[]).scan_skill(skill_dir)
    raw_cel = result.scan_metadata["cel"]
    assert raw_cel["runtime"] == "unavailable"
    assert raw_cel["runtime_version"] == ""
    assert raw_cel["expression_set_hash"] == ""
    assert raw_cel["evaluated"] == 0

    sample = FrozenSample(
        benchmark_id="real-off",
        label="benign",
        source_id="test",
        structural_family_id="test",
        category_ids=("benign",),
        relative_path=PurePosixPath("real-off"),
        splits={},
    )
    telemetry = _validated_cel_telemetry(
        result,
        sample,
        result.scan_duration_seconds * 1_000,
    )

    assert telemetry["runtime_version"] == "not_loaded"
    assert len(telemetry["expression_set_hash"]) == 64
    assert telemetry["evaluated"] == 0

    raw_cel.update(
        {
            "runtime": "cel-go",
            "runtime_version": "v0.32.0;helper=test-build",
            "expression_set_hash": "a" * 64,
        }
    )
    compiled_off = _validated_cel_telemetry(result, sample, result.scan_duration_seconds * 1_000)
    assert compiled_off["runtime"] == "cel-go"
    assert compiled_off["runtime_version"] == "v0.32.0;helper=test-build"
    assert compiled_off["expression_set_hash"] == "a" * 64

    raw_cel["mode"] = "invented"
    with pytest.raises(PublicBenchmarkError, match="unsupported CEL mode"):
        _validated_cel_telemetry(result, sample, result.scan_duration_seconds * 1_000)


def _collapsed_lineage_result(*, reported_would_suppress: int = 2) -> tuple[SimpleNamespace, FrozenSample]:
    expression_hash = "a" * 64
    lineage = {
        "rule_id": "CEL_COLLAPSED",
        "decision": "would_suppress",
        "reason": "shadow_or_rule_rollout",
        "fact_schema": "v1",
        "expression_hash": expression_hash,
        "pack": "core",
        "rollout": "shadow",
        "count": 2,
    }
    result = SimpleNamespace(
        findings=[
            {
                "rule_id": "CEL_COLLAPSED",
                "severity": "HIGH",
                "metadata": {
                    "cel": {key: value for key, value in lineage.items() if key not in {"rule_id", "count"}},
                    "cel_decisions": [lineage],
                },
            }
        ],
        scan_duration_seconds=0.1,
        scan_metadata={
            "cel": {
                "mode": "shadow",
                "runtime": "cel-go",
                "runtime_version": "v0.32.0;helper=test-build",
                "fact_schema": "v1",
                "expression_set_hash": "b" * 64,
                "evaluated": reported_would_suppress,
                "retained": reported_would_suppress,
                "would_suppress": reported_would_suppress,
                "suppressed": 0,
                "fallbacks": 0,
                "projection_incomplete": 0,
                "elapsed_ms": 2.0,
                "projection_ms": 0.5,
                "evaluation_ms": 1.0,
                "errors": [],
                "per_rule": {
                    "CEL_COLLAPSED": {
                        "keep": 0,
                        "would_suppress": reported_would_suppress,
                        "fallback": 0,
                        "suppressed": 0,
                        "expression_hash": expression_hash,
                        "pack": "core",
                        "rollout": "shadow",
                    }
                },
            }
        },
    )
    sample = FrozenSample(
        benchmark_id="collapsed-lineage",
        label="benign",
        source_id="test",
        structural_family_id="test",
        category_ids=("benign",),
        relative_path=PurePosixPath("collapsed-lineage"),
        splits={},
    )
    return result, sample


def test_collapsed_cel_lineage_reconciles_candidate_multiplicity() -> None:
    result, sample = _collapsed_lineage_result()

    telemetry = _validated_cel_telemetry(result, sample, 100.0)

    assert telemetry["rule_decisions"] == [
        {
            "rule_id": "CEL_COLLAPSED",
            "decision": "would_suppress",
            "reason": "shadow_or_rule_rollout",
            "fact_schema": "v1",
            "expression_hash": "a" * 64,
            "pack": "core",
            "rollout": "shadow",
            "count": 2,
        }
    ]


def test_collapsed_cel_lineage_count_mismatch_fails_closed() -> None:
    result, sample = _collapsed_lineage_result(reported_would_suppress=3)

    with pytest.raises(PublicBenchmarkError, match="retained CEL lineage count disagrees"):
        _validated_cel_telemetry(result, sample, 100.0)


def test_active_cel_requires_authoritative_per_rule_telemetry() -> None:
    result, sample = _collapsed_lineage_result()
    result.scan_metadata["cel"].pop("per_rule")

    with pytest.raises(PublicBenchmarkError, match="omitted authoritative CEL per_rule telemetry"):
        _validated_cel_telemetry(result, sample, 100.0)


def _suppressed_candidate_result() -> tuple[SimpleNamespace, FrozenSample]:
    expression_hash = "d" * 64
    result = SimpleNamespace(
        findings=[],
        scan_duration_seconds=0.1,
        scan_metadata={
            "cel": {
                "mode": "enforce",
                "runtime": "cel-go",
                "runtime_version": "v0.32.0;helper=test-build",
                "fact_schema": "v1",
                "expression_set_hash": "e" * 64,
                "evaluated": 1,
                "retained": 0,
                "would_suppress": 1,
                "suppressed": 1,
                "fallbacks": 0,
                "projection_incomplete": 0,
                "elapsed_ms": 2.0,
                "projection_ms": 0.5,
                "evaluation_ms": 0.5,
                "errors": [],
                "per_rule": {
                    "CEL_SUPPRESSED": {
                        "keep": 0,
                        "would_suppress": 1,
                        "fallback": 0,
                        "suppressed": 1,
                        "expression_hash": expression_hash,
                        "pack": "core",
                        "rollout": "enforce",
                    }
                },
                "suppressed_candidates": [
                    {
                        "rule_id": "CEL_SUPPRESSED",
                        "category": "command_injection",
                        "severity": "HIGH",
                        "analyzer": "static",
                        "expression_hash": expression_hash,
                        "pack": "core",
                        "rollout": "enforce",
                        "count": 1,
                    }
                ],
            }
        },
    )
    sample = FrozenSample(
        benchmark_id="suppressed-benign",
        label="benign",
        source_id="test",
        structural_family_id="test",
        category_ids=("benign",),
        relative_path=PurePosixPath("suppressed-benign"),
        splits={},
    )
    return result, sample


def test_enforced_suppression_retains_actionable_context_through_compact_v3() -> None:
    result, sample = _suppressed_candidate_result()
    telemetry = _validated_cel_telemetry(result, sample, 100.0)

    assert telemetry["suppressed_decisions"] == result.scan_metadata["cel"]["suppressed_candidates"]

    counts = _empty_counts()
    _record_sample(counts, sample, result, expected_cel_mode=CelMode.ENFORCE)
    track = _finalize_counts(counts)
    compact = compact_release_report(
        {
            "summary": {"sample_outcomes": {}},
            "tracks": {
                "development": {
                    **track,
                    "per_source": {},
                    "per_structural_family": {},
                    "per_category": {},
                }
            },
        }
    )

    assert compact["tracks"]["development"]["sample_outcomes"][sample.benchmark_id]["cel_suppressed"] == [
        {
            "rule_id": "CEL_SUPPRESSED",
            "category": "command_injection",
            "severity": "HIGH",
            "analyzer": "static",
            "count": 1,
        }
    ]


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda candidate: candidate.update(count=2), "count disagrees"),
        (lambda candidate: candidate.update(severity="invented"), "invalid suppressed CEL candidate"),
        (lambda candidate: candidate.update(expression_hash="f" * 64), "identity disagrees"),
    ],
)
def test_suppressed_candidate_evidence_fails_closed_on_spoofing(mutation, error: str) -> None:
    result, sample = _suppressed_candidate_result()
    mutation(result.scan_metadata["cel"]["suppressed_candidates"][0])

    with pytest.raises(PublicBenchmarkError, match=error):
        _validated_cel_telemetry(result, sample, 100.0)


def test_requested_cel_mode_mismatch_fails_every_sample_without_shrinking_denominators(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        cel_mode=CelMode.SHADOW,
        scanner_factory=lambda profile, _mode: _RecordingScanner(profile, [], CelMode.OFF),
    )

    assert report["status"] == "failed"
    assert report["summary"]["samples"] == 2
    assert report["summary"]["scan_errors"] == 2
    assert all("does not match requested mode" in error["error"] for error in report["errors"])


def test_mid_run_producer_drift_fails_report_without_shrinking_denominators(tmp_path, monkeypatch):
    root, lock_path, _ = _snapshot(tmp_path)
    stable = {
        "scanner_version": "test",
        "source_revision": "revision",
        "build_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "rules_sha256": "c" * 64,
    }
    calls = 0

    def changing_components(_detector_profiles):
        nonlocal calls
        calls += 1
        components = dict(stable)
        if calls > 1:
            components["build_sha256"] = "d" * 64
        return components

    monkeypatch.setattr(public_dataset_benchmark, "_producer_components", changing_components)
    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: _RecordingScanner(profile, [], mode),
    )

    assert calls == 2
    assert report["status"] == "failed"
    assert report["summary"]["samples"] == 2
    assert report["summary"]["scan_errors"] == 0
    assert report["identity_verification"]["drifted_fields"] == ["build_sha256"]
    assert "build_sha256" in report["errors"][-1]["error"]
    assert report["evidence_identity"]["build_sha256"] == "a" * 64


def test_mid_run_snapshot_mutation_fails_post_run_inventory_validation(tmp_path):
    root, lock_path, _ = _snapshot(tmp_path)
    calls = 0

    class MutatingScanner(_RecordingScanner):
        def scan_skill(self, path: Path):
            nonlocal calls
            result = super().scan_skill(path)
            calls += 1
            if calls == 2:
                skill_file = path / "SKILL.md"
                skill_file.write_text(skill_file.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
            return result

    report = run_public_benchmark(
        root,
        dataset_lock=lock_path,
        scanner_factory=lambda profile, mode: MutatingScanner(profile, [], mode),
    )

    assert report["status"] == "failed"
    assert report["summary"]["samples"] == 2
    assert report["summary"]["scan_errors"] == 0
    assert report["identity_verification"]["drifted_fields"] == ["snapshot_artifact_inventory"]
    assert "artifact inventory mismatch" in report["errors"][-1]["error"]


def test_supplemental_profile_skips_nonblocking_data_and_still_rejects_links(tmp_path):
    supplemental = tmp_path / "supplemental"
    supplemental.mkdir()
    (supplemental / "authorized-data.json").write_text("[]\n", encoding="utf-8")

    report = run_public_benchmark(supplemental, profile="supplemental")
    assert report["status"] == "skipped"
    assert report["summary"] == {}

    (supplemental / "link").symlink_to(supplemental / "authorized-data.json")
    with pytest.raises(PublicBenchmarkError, match="symbolic link"):
        run_public_benchmark(supplemental, profile="supplemental")

    trusted_pack = _write_trusted_pack(tmp_path / "trusted-pack")
    with pytest.raises(PublicBenchmarkError, match="cannot load trusted local rule packs"):
        run_public_benchmark(
            supplemental,
            profile="supplemental",
            trusted_rule_packs=[trusted_pack],
        )


def test_missing_gated_supplemental_data_is_an_explicit_skip(tmp_path, capsys):
    missing = tmp_path / "missing-gated-snapshot"
    report = run_public_benchmark(
        missing,
        dataset_id="TrustAIRLab/HarmfulSkillBench",
        profile="supplemental",
    )

    assert report["status"] == "skipped"
    assert report["availability"] == "unavailable"
    assert report["dataset"]["blocking"] is False
    assert report["errors"] == []

    output = tmp_path / "supplemental-report.json"
    status = main(
        [
            "--snapshot-dir",
            str(missing),
            "--dataset-id",
            "TrustAIRLab/HarmfulSkillBench",
            "--profile",
            "supplemental",
            "--output",
            str(output),
        ]
    )
    assert status == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "skipped"
    assert "skipped" in capsys.readouterr().out


def test_supplemental_profile_rejects_broken_root_symlink(tmp_path):
    broken = tmp_path / "broken-supplemental"
    broken.symlink_to(tmp_path / "missing-target", target_is_directory=True)

    with pytest.raises(PublicBenchmarkError, match="non-symlink"):
        run_public_benchmark(broken, profile="supplemental")


def test_cli_rejects_writing_output_into_snapshot(tmp_path, capsys):
    root, lock_path, _ = _snapshot(tmp_path)
    status = main(
        [
            "--snapshot-dir",
            str(root),
            "--dataset-lock",
            str(lock_path),
            "--output",
            str(root / "report.json"),
        ]
    )
    assert status == 1
    assert "output must be outside" in capsys.readouterr().err


def test_cli_keeps_locally_extended_data_out_of_compact_release_evidence(tmp_path, capsys):
    root, lock_path, _ = _snapshot(tmp_path)
    trusted_pack = _write_trusted_pack(tmp_path / "trusted-pack")
    status = main(
        [
            "--snapshot-dir",
            str(root),
            "--dataset-lock",
            str(lock_path),
            "--trusted-rule-pack",
            str(trusted_pack),
            "--compact-release-evidence",
            "--output",
            str(tmp_path / "release.json"),
        ]
    )

    assert status == 1
    assert "must not include" in capsys.readouterr().err


def test_cli_does_not_follow_output_symlink(tmp_path, capsys):
    supplemental = tmp_path / "supplemental"
    supplemental.mkdir()
    (supplemental / "authorized-data.json").write_text("[]\n", encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text("do not replace\n", encoding="utf-8")
    output = tmp_path / "output.json"
    output.symlink_to(target)

    status = main(
        [
            "--snapshot-dir",
            str(supplemental),
            "--profile",
            "supplemental",
            "--output",
            str(output),
        ]
    )

    assert status == 1
    assert target.read_text(encoding="utf-8") == "do not replace\n"
    assert "symlink" in capsys.readouterr().err
