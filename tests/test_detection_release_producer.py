# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict

import pytest

from evals.datasets import materialize_malicious_skill_bench
from evals.datasets.materialize_malicious_skill_bench import (
    DATASET_ID,
    MaterializationError,
    _category_ids,
    _locked_split_protocols,
    _materialize_pinned_text,
    source_artifact_contract,
)
from evals.datasets.public_datasets import (
    artifact_manifest_sha256,
    load_dataset_lock,
    quarantine_manifest_sha256,
    sample_metadata_manifest_sha256,
)
from evals.runners.produce_release_evidence import (
    _write_json_new,
    active_release_mode,
)
from evals.runners.produce_release_evidence import (
    main as release_evidence_main,
)
from evals.runners.public_dataset_benchmark import compact_release_report
from skill_scanner.core.cel.models import CelMode


class _MaterializationFixture(TypedDict):
    label: str
    source_id: str
    structural_family_id: str
    content: str
    splits: dict[str, str]


def test_committed_malicious_skill_bench_source_contract_is_complete() -> None:
    lock, artifacts, profile = source_artifact_contract()

    assert profile["id"] == DATASET_ID
    assert profile["revision"] == "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
    assert profile["source_artifact_manifest_sha256"] == (
        "3d64779dc972759ede61717ac5cc7f4e87289add8feabff1e83c4289094ce300"
    )
    assert [artifact["path"] for artifact in artifacts] == [
        "primary.parquet",
        "metadata.parquet",
        "attack_taxonomy.parquet",
        "impact_taxonomy.parquet",
        "splits/random.parquet",
        "splits/source_balanced_random.parquet",
        "splits/m_structural_disjoint.parquet",
        "splits/source_disjoint.parquet",
        "package_manifest.csv",
        "schema.json",
    ]
    locked = next(dataset for dataset in lock["datasets"] if dataset["id"] == DATASET_ID)
    assert locked["integrity"]["hashes_pending"] is False
    assert locked["integrity"]["materialization"] == {
        "declared_artifact_count": 9740,
        "usable_artifact_count": 9737,
        "error_count": 3,
        "usable_artifact_manifest_sha256": "e1f54bfdfb8489b136601ab5cacdc0ae81802aa2ac3b37ebe0766afdf5cec79b",
        "quarantine_manifest_sha256": "6dcd44640fd28506eed470888272c52b43a8779988a8b8b0efda99f3d8c6ee79",
    }
    assert {track["protocol"] for track in locked["gating"]["tracks"]} == {"source_disjoint"}
    assert _locked_split_protocols(locked) == ("m_structural_disjoint", "source_disjoint")
    assert locked["integrity"]["sample_metadata_manifest_format"] == "sample-metadata-splits-v2"
    assert profile["materialization"]["sample_metadata_manifest_format"] == "sample-metadata-splits-v2"
    assert (
        profile["materialization"]["sample_metadata_manifest_sha256"]
        == locked["integrity"]["sample_metadata_manifest_sha256"]
        == "6a284d9a181ae07179f2cc3ff98f64f14787dadc1ebde6c0dd86e78f4f55bc7a"
    )


def test_fresh_materialization_emits_every_locked_split_protocol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = copy.deepcopy(load_dataset_lock())
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == DATASET_ID)
    dataset["gating"]["tracks"] = [
        track for track in dataset["gating"]["tracks"] if track["protocol"] == "source_disjoint"
    ]
    dataset["expected"]["row_counts"] = {
        "primary/train": 2,
        "splits/source_disjoint": 2,
        "splits/m_structural_disjoint": 2,
    }
    track = dataset["gating"]["tracks"][0]
    dataset["expected"]["track_expectations"] = {
        track["name"]: {
            "samples": 1,
            "malicious": 0,
            "benign": 1,
            "population_sha256": "0" * 64,
        }
    }

    rows: dict[str, _MaterializationFixture] = {
        "fixture-quarantined": {
            "label": "1",
            "source_id": "SRC-Q",
            "structural_family_id": "FAMILY-Q",
            "content": "---\nname: fixture-quarantined\ndescription: Inert quarantined fixture\n---\n",
            "splits": {"source_disjoint": "train", "m_structural_disjoint": "train"},
        },
        "fixture-visible": {
            "label": "0",
            "source_id": "SRC-V",
            "structural_family_id": "FAMILY-V",
            "content": "---\nname: fixture-visible\ndescription: Inert visible fixture\n---\n",
            "splits": {"source_disjoint": "test", "m_structural_disjoint": "validation"},
        },
    }
    artifacts_by_id = {
        benchmark_id: {
            "path": f"skills/{benchmark_id}/SKILL.md",
            "sha256": hashlib.sha256(row["content"].encode("utf-8")).hexdigest(),
            "size_bytes": len(row["content"].encode("utf-8")),
        }
        for benchmark_id, row in sorted(rows.items())
    }
    artifacts = list(artifacts_by_id.values())
    dataset["integrity"]["artifact_manifest_sha256"] = artifact_manifest_sha256(
        DATASET_ID,
        artifacts,
        manifest=lock,
    )
    usable_artifacts = [artifacts_by_id["fixture-visible"]]
    usable_digest = artifact_manifest_sha256(DATASET_ID, usable_artifacts, manifest=lock)
    quarantined_artifact = artifacts_by_id["fixture-quarantined"]
    quarantine_record = {
        "benchmark_id": "fixture-quarantined",
        "error_code": "ENDPOINT_PROTECTION_QUARANTINE",
        "label": "malicious",
        **quarantined_artifact,
        "source_id": "SRC-Q",
        "splits": dict(rows["fixture-quarantined"]["splits"]),
        "structural_family_id": "FAMILY-Q",
    }
    dataset["integrity"]["materialization"] = {
        "declared_artifact_count": 2,
        "usable_artifact_count": 1,
        "error_count": 1,
        "usable_artifact_manifest_sha256": usable_digest,
        "quarantine_manifest_sha256": "0" * 64,
    }
    quarantine_digest = quarantine_manifest_sha256(
        DATASET_ID,
        [quarantine_record],
        declared_artifact_manifest_sha256=dataset["integrity"]["artifact_manifest_sha256"],
        manifest=lock,
    )
    dataset["integrity"]["materialization"]["quarantine_manifest_sha256"] = quarantine_digest
    expected_samples = [
        {
            "benchmark_id": benchmark_id,
            "category_ids": ["benign"] if fixture["label"] == "0" else ["unclassified_malicious"],
            "exact_hash": hashlib.sha256(fixture["content"].encode()).hexdigest(),
            "label": "benign" if fixture["label"] == "0" else "malicious",
            "normalized_hash": hashlib.sha256(fixture["content"].encode()).hexdigest(),
            "path": f"skills/{benchmark_id}",
            "provenance": "unit_test",
            "source_id": fixture["source_id"],
            "source_ids": [fixture["source_id"]],
            "source_pointer": f"test://{fixture['source_id']}",
            "splits": dict(fixture["splits"]),
            "structural_family_id": fixture["structural_family_id"],
            "text_origin_source_id": fixture["source_id"],
        }
        for benchmark_id, fixture in sorted(rows.items())
    ]
    metadata_digest = sample_metadata_manifest_sha256(
        DATASET_ID,
        expected_samples,
        artifact_manifest_sha256=dataset["integrity"]["artifact_manifest_sha256"],
        manifest=lock,
    )
    dataset["integrity"]["sample_metadata_manifest_sha256"] = metadata_digest

    primary_fields = dataset["expected"]["schemas"]["primary"]["exact_fields"]
    primary_rows = []
    for benchmark_id, fixture in rows.items():
        row = dict.fromkeys(primary_fields)
        row.update(
            {
                "benchmark_id": benchmark_id,
                "label": fixture["label"],
                "skill_text": fixture["content"],
                "text_available": True,
                "source_id": fixture["source_id"],
                "source_ids": [fixture["source_id"]],
                "source_pointer": f"test://{fixture['source_id']}",
                "provenance": "unit_test",
                "exact_hash": hashlib.sha256(fixture["content"].encode()).hexdigest(),
                "normalized_hash": hashlib.sha256(fixture["content"].encode()).hexdigest(),
                "text_origin_source_id": fixture["source_id"],
                "structural_family_id": fixture["structural_family_id"],
                "attack_category_codes": [],
                "public_skill_text": None,
                "public_text_sha256": None,
                "original_text_withheld": False,
            }
        )
        primary_rows.append(row)

    class FakeTable:
        def __init__(self, fields: list[str], table_rows: list[dict[str, object]]) -> None:
            self.schema = SimpleNamespace(names=fields)
            self.num_rows = len(table_rows)
            self._rows = table_rows

        def to_pylist(self) -> list[dict[str, object]]:
            return copy.deepcopy(self._rows)

    split_fields = dataset["expected"]["schemas"]["split_manifest"]["exact_fields"]
    tables = {
        "primary.parquet": FakeTable(primary_fields, primary_rows),
        **{
            f"splits/{protocol}.parquet": FakeTable(
                split_fields,
                [
                    {
                        "benchmark_id": benchmark_id,
                        "label": fixture["label"],
                        "source_id": fixture["source_id"],
                        "split": fixture["splits"][protocol],
                    }
                    for benchmark_id, fixture in rows.items()
                ],
            )
            for protocol in ("source_disjoint", "m_structural_disjoint")
        },
    }
    source_root = tmp_path / "source"
    source_root.mkdir()
    observed_reads: list[str] = []

    def read_table(path: Path) -> FakeTable:
        relative = Path(path).relative_to(source_root).as_posix()
        observed_reads.append(relative)
        return tables[relative]

    profile_entry = {
        "materialization": {
            "quarantine_records": [quarantine_record],
            "sample_metadata_manifest_format": "sample-metadata-splits-v2",
            "sample_metadata_manifest_sha256": metadata_digest,
            "sample_metadata_grouping": copy.deepcopy(dataset["integrity"]["sample_metadata_grouping"]),
        }
    }
    monkeypatch.setattr(
        materialize_malicious_skill_bench,
        "source_artifact_contract",
        lambda **_kwargs: (lock, (), profile_entry),
    )
    monkeypatch.setattr(materialize_malicious_skill_bench, "validate_acquired_sources", lambda *_args: None)
    monkeypatch.setattr(materialize_malicious_skill_bench, "parquet", SimpleNamespace(read_table=read_table))

    lock_path = tmp_path / "public-datasets.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    output_root = tmp_path / "snapshot"
    summary = materialize_malicious_skill_bench.materialize_snapshot(
        source_root,
        output_root,
        dataset_lock=lock_path,
    )

    assert summary["declared_artifacts"] == 2
    assert summary["usable_artifacts"] == 1
    assert observed_reads == [
        "primary.parquet",
        "splits/m_structural_disjoint.parquet",
        "splits/source_disjoint.parquet",
    ]
    manifest = json.loads((output_root / "benchmark-snapshot.json").read_text(encoding="utf-8"))
    expected_protocols = {"m_structural_disjoint", "source_disjoint"}
    assert manifest["sample_metadata_manifest_sha256"] == metadata_digest
    assert all(set(sample["splits"]) == expected_protocols for sample in manifest["samples"])
    assert set(manifest["quarantine"]["records"][0]["splits"]) == expected_protocols


def test_category_projection_matches_locked_population_contract() -> None:
    assert _category_ids({"attack_category_codes": ["z", "a", "z"]}, "malicious") == ["a", "z"]
    assert _category_ids({"attack_category_codes": []}, "benign") == ["benign"]
    assert _category_ids({"attack_category_codes": []}, "malicious") == ["unclassified_malicious"]
    with pytest.raises(MaterializationError, match="must be an array"):
        _category_ids({"attack_category_codes": "command_execution"}, "malicious")


def test_pinned_text_adapter_is_inert_and_byte_preserving(tmp_path: Path) -> None:
    destination = tmp_path / "sample"
    content = "---\nname: control\ndescription: pinned\n---\n\x02"

    _materialize_pinned_text(destination, content)

    skill = destination / "SKILL.md"
    assert skill.read_bytes() == content.encode("utf-8")
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE(skill.stat().st_mode) == 0o600
    assert not (skill.stat().st_mode & 0o111)
    with pytest.raises(MaterializationError, match="NUL"):
        _materialize_pinned_text(tmp_path / "nul", "bad\x00text")


def test_compact_release_report_retains_only_cel_and_recovered_outcomes() -> None:
    outcomes = {
        "plain": {
            "label": "benign",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [{"rule_id": "PLAIN", "severity": "LOW", "cel_decision": None, "category": "x"}],
        },
        "cel": {
            "label": "malicious",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [
                {
                    "rule_id": "CEL_RULE",
                    "severity": "HIGH",
                    "cel_decision": "keep",
                    "cel_decisions": [
                        {
                            "rule_id": "CEL_RULE",
                            "decision": "keep",
                            "reason": "expression_true",
                            "fact_schema": "v1",
                            "expression_hash": "a" * 64,
                            "pack": "core",
                            "rollout": "shadow",
                            "count": 1,
                        }
                    ],
                    "category": "x",
                }
            ],
        },
        "recovered": {
            "label": "malicious",
            "scan_error": False,
            "recovered_scan_error": True,
            "loader_fallback_code": "INVALID_FRONTMATTER",
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [
                {
                    "rule_id": "SKILL_LOAD_FALLBACK_USED",
                    "severity": "INFO",
                    "cel_decision": None,
                    "cel_decisions": [],
                    "category": "policy_violation",
                }
            ],
        },
        "rejected": {
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
                    "category": "policy_violation",
                }
            ],
        },
    }
    group = {"samples": 1, "sample_outcomes": {"plain": outcomes["plain"]}}
    report = {
        "summary": {},
        "tracks": {
            "track": {
                "samples": 4,
                "sample_outcomes": outcomes,
                "per_source": {"source": dict(group)},
                "per_structural_family": {"family": dict(group)},
                "per_category": {"category": dict(group)},
            }
        },
    }

    compact = compact_release_report(report)
    track = compact["tracks"]["track"]
    assert compact["release_evidence"] == {
        "format": "compact-v3",
        "full_sample_outcomes_domain": "skill-scanner-release-sample-outcomes-v1",
        "cel_decision_identity": "track.cel.per_rule",
    }
    assert track["sample_outcomes_count"] == 4
    assert len(track["sample_outcomes_sha256"]) == 64
    assert set(track["sample_outcomes"]) == {"cel", "recovered", "rejected"}
    assert track["sample_outcomes"]["cel"]["findings"] == [
        {
            "rule_id": "CEL_RULE",
            "severity": "HIGH",
            "cel_decision": "keep",
            "cel_decisions": [{"rule_id": "CEL_RULE", "decision": "keep", "count": 1}],
        }
    ]
    assert track["sample_outcomes"]["recovered"]["loader_fallback_code"] == "INVALID_FRONTMATTER"
    assert track["sample_outcomes"]["recovered"]["findings"] == [
        {
            "rule_id": "SKILL_LOAD_FALLBACK_USED",
            "severity": "INFO",
            "cel_decision": None,
            "cel_decisions": [],
        }
    ]
    assert track["sample_outcomes"]["rejected"]["loader_rejection_code"] == ("SKILL_METADATA_SIZE_LIMIT_EXCEEDED")
    assert track["sample_outcomes"]["rejected"]["findings"] == [
        {
            "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
            "severity": "HIGH",
            "cel_decision": None,
            "cel_decisions": [],
        }
    ]
    expected_outcome_fields = {
        "label",
        "scan_error",
        "recovered_scan_error",
        "loader_fallback_code",
        "loader_rejection_code",
        "cel_suppressed",
        "findings",
    }
    assert all(set(outcome) == expected_outcome_fields for outcome in track["sample_outcomes"].values())
    for dimension in ("per_source", "per_structural_family", "per_category"):
        compact_group = next(iter(track[dimension].values()))
        assert "sample_outcomes" not in compact_group
        assert compact_group["sample_outcomes_format"] == "digest-only-v1"


def test_active_release_mode_tracks_bundled_rollouts() -> None:
    mode, enforced = active_release_mode()
    assert mode in {CelMode.SHADOW, CelMode.ENFORCE}
    assert (mode is CelMode.ENFORCE) is bool(enforced)


def test_compact_v3_bounds_representative_repeated_lineage() -> None:
    samples = 1_948
    findings_per_sample = 15
    lineage = {
        "rule_id": "CEL_RULE_WITH_LONG_STABLE_IDENTIFIER",
        "decision": "would_suppress",
        "reason": "shadow_or_rule_rollout",
        "fact_schema": "v1",
        "expression_hash": "a" * 64,
        "pack": "promptguard",
        "rollout": "shadow",
        "count": 1,
    }
    finding = {
        "rule_id": lineage["rule_id"],
        "severity": "HIGH",
        "cel_decision": "would_suppress",
        "cel_decisions": [lineage],
    }
    outcomes = {
        f"sample-{index:04d}": {
            "label": "benign",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [finding] * findings_per_sample,
        }
        for index in range(samples)
    }
    report = {
        "summary": {},
        "tracks": {
            "representative": {
                "samples": samples,
                "sample_outcomes": outcomes,
                "per_source": {},
                "per_structural_family": {},
                "per_category": {},
            }
        },
    }
    verbose_size = len((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    compact = compact_release_report(report)
    canonical = (json.dumps(compact, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")

    assert verbose_size > 16 * 1024 * 1024
    assert len(canonical) < 16 * 1024 * 1024
    assert len(canonical) < verbose_size // 2
    decision = compact["tracks"]["representative"]["sample_outcomes"]["sample-0000"]["findings"][0]
    assert decision["cel_decisions"] == [
        {
            "rule_id": "CEL_RULE_WITH_LONG_STABLE_IDENTIFIER",
            "decision": "would_suppress",
            "count": 1,
        }
    ]


def test_release_evidence_writer_uses_canonical_json(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.json"

    _write_json_new(destination, {"z": [2, 1], "a": {"value": True}})

    assert destination.read_bytes() == b'{"a":{"value":true},"z":[2,1]}\n'


def test_release_evidence_cli_requires_attested_fixture_naming(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        release_evidence_main(["assemble", "--help"])

    help_text = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--attested-rule-fixtures" in help_text
    assert "--reviewed-rule-fixtures" not in help_text
