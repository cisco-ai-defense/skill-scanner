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

"""The corpora a pull-request check may acquire, and what it may never write.

MaliciousSkillBench forbids selecting anything on its frozen test members, so the pull-request
check scans train/validation only. These tests pin that the lock allows no more than that, and that
the development-split writer validates the whole pinned population and then writes no test member.
"""

from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evals.datasets import materialize_malicious_skill_bench
from evals.datasets.materialize_malicious_skill_bench import DATASET_ID, development_split_ids
from evals.datasets.public_datasets import (
    DatasetLockError,
    artifact_manifest_sha256,
    load_dataset_lock,
    pull_request_acquisition,
    quarantine_manifest_sha256,
    sample_metadata_manifest_sha256,
)
from evals.lib.cross_tool import CleanCorpus


def _write_lock(tmp_path: Path, manifest: dict[str, Any]) -> Path:
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class TestLockAllowance:
    def test_only_the_two_public_datasets_allow_pull_request_acquisition(self) -> None:
        manifest = load_dataset_lock()
        allowed = {d["id"] for d in manifest["datasets"] if "pull_request_acquisition" in d}
        assert allowed == {"ProtectSkills/MaliciousSkillBench", "OpenClaw/clawhub-security-signals"}
        assert manifest["safety_defaults"]["network_fetch_in_pull_requests"] is False

    def test_the_benchmark_allowance_is_train_and_validation_with_the_network_denied(self) -> None:
        allowance = pull_request_acquisition(DATASET_ID)
        assert allowance["partitions"] == ["train", "validation"]
        assert allowance["scan_network"] == "denied"

    def test_the_real_skill_allowance_is_one_validation_file(self) -> None:
        allowance = pull_request_acquisition("OpenClaw/clawhub-security-signals")
        assert allowance["files"] == ["data/validation.jsonl"]
        assert allowance["partitions"] == ["validation"]

    @pytest.mark.parametrize("partition", ["test", "excluded", "eval_holdout"])
    def test_a_frozen_or_held_out_partition_is_refused(self, tmp_path: Path, partition: str) -> None:
        manifest = copy.deepcopy(load_dataset_lock())
        entry = next(d for d in manifest["datasets"] if d["id"] == DATASET_ID)
        entry["pull_request_acquisition"]["partitions"] = ["train", partition]
        with pytest.raises(DatasetLockError, match="only train and validation"):
            load_dataset_lock(_write_lock(tmp_path, manifest))

    def test_a_scan_with_network_is_refused(self, tmp_path: Path) -> None:
        manifest = copy.deepcopy(load_dataset_lock())
        entry = next(d for d in manifest["datasets"] if d["id"] == DATASET_ID)
        entry["pull_request_acquisition"]["scan_network"] = "allowed"
        with pytest.raises(DatasetLockError, match="network denied"):
            load_dataset_lock(_write_lock(tmp_path, manifest))

    def test_a_gated_or_manual_dataset_cannot_be_acquired_in_a_pull_request(self, tmp_path: Path) -> None:
        manifest = copy.deepcopy(load_dataset_lock())
        entry = next(d for d in manifest["datasets"] if d["id"] == "TrustAIRLab/HarmfulSkillBench")
        entry["pull_request_acquisition"] = {
            "purpose": "detection_impact_real_skill_sample",
            "files": ["data.jsonl"],
            "partitions": ["validation"],
            "scan_network": "denied",
        }
        with pytest.raises(DatasetLockError, match="only public, automatically downloadable"):
            load_dataset_lock(_write_lock(tmp_path, manifest))

    def test_a_dataset_without_an_allowance_reports_that(self) -> None:
        with pytest.raises(DatasetLockError, match="does not allow pull-request acquisition"):
            pull_request_acquisition("Miaow-Lab/OpenSkillRisk")


class TestDevelopmentSelection:
    def test_every_protocol_must_be_train_or_validation(self) -> None:
        samples = [
            {"benchmark_id": "a", "splits": {"source_disjoint": "train", "m_structural_disjoint": "validation"}},
            {"benchmark_id": "b", "splits": {"source_disjoint": "test", "m_structural_disjoint": "train"}},
            {"benchmark_id": "c", "splits": {"source_disjoint": "validation", "m_structural_disjoint": "excluded"}},
            {"benchmark_id": "d", "splits": {}},
        ]
        assert development_split_ids(samples, ["train", "validation"]) == ["a"]


def _synthetic_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: dict[str, dict[str, Any]], quarantined: str
) -> Path:
    """A pinned population the materializer can validate end to end, without Parquet or a download."""

    lock = copy.deepcopy(load_dataset_lock())
    dataset = next(dataset for dataset in lock["datasets"] if dataset["id"] == DATASET_ID)
    dataset["gating"]["tracks"] = [
        track for track in dataset["gating"]["tracks"] if track["protocol"] == "source_disjoint"
    ]
    dataset["expected"]["row_counts"] = {
        "primary/train": len(rows),
        "splits/source_disjoint": len(rows),
        "splits/m_structural_disjoint": len(rows),
    }
    track = dataset["gating"]["tracks"][0]
    dataset["expected"]["track_expectations"] = {
        track["name"]: {"samples": 1, "malicious": 0, "benign": 1, "population_sha256": "0" * 64}
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
    dataset["integrity"]["artifact_manifest_sha256"] = artifact_manifest_sha256(DATASET_ID, artifacts, manifest=lock)
    usable = [artifact for benchmark_id, artifact in sorted(artifacts_by_id.items()) if benchmark_id != quarantined]
    quarantine_record = {
        "benchmark_id": quarantined,
        "error_code": "ENDPOINT_PROTECTION_QUARANTINE",
        "label": "malicious" if rows[quarantined]["label"] == "1" else "benign",
        **artifacts_by_id[quarantined],
        "source_id": rows[quarantined]["source_id"],
        "splits": dict(rows[quarantined]["splits"]),
        "structural_family_id": rows[quarantined]["structural_family_id"],
    }
    dataset["integrity"]["materialization"] = {
        "declared_artifact_count": len(rows),
        "usable_artifact_count": len(rows) - 1,
        "error_count": 1,
        "usable_artifact_manifest_sha256": artifact_manifest_sha256(DATASET_ID, usable, manifest=lock),
        "quarantine_manifest_sha256": "0" * 64,
    }
    dataset["integrity"]["materialization"]["quarantine_manifest_sha256"] = quarantine_manifest_sha256(
        DATASET_ID,
        [quarantine_record],
        declared_artifact_manifest_sha256=dataset["integrity"]["artifact_manifest_sha256"],
        manifest=lock,
    )
    samples = [
        {
            "benchmark_id": benchmark_id,
            "category_ids": ["benign"] if row["label"] == "0" else ["unclassified_malicious"],
            "exact_hash": hashlib.sha256(row["content"].encode()).hexdigest(),
            "label": "benign" if row["label"] == "0" else "malicious",
            "normalized_hash": hashlib.sha256(row["content"].encode()).hexdigest(),
            "path": f"skills/{benchmark_id}",
            "provenance": "unit_test",
            "source_id": row["source_id"],
            "source_ids": [row["source_id"]],
            "source_pointer": f"test://{row['source_id']}",
            "splits": dict(row["splits"]),
            "structural_family_id": row["structural_family_id"],
            "text_origin_source_id": row["source_id"],
        }
        for benchmark_id, row in sorted(rows.items())
    ]
    dataset["integrity"]["sample_metadata_manifest_sha256"] = sample_metadata_manifest_sha256(
        DATASET_ID, samples, artifact_manifest_sha256=dataset["integrity"]["artifact_manifest_sha256"], manifest=lock
    )

    primary_fields = dataset["expected"]["schemas"]["primary"]["exact_fields"]
    primary_rows = []
    for benchmark_id, row in rows.items():
        record = dict.fromkeys(primary_fields)
        record.update(
            {
                "benchmark_id": benchmark_id,
                "label": row["label"],
                "skill_text": row["content"],
                "text_available": True,
                "source_id": row["source_id"],
                "source_ids": [row["source_id"]],
                "source_pointer": f"test://{row['source_id']}",
                "provenance": "unit_test",
                "exact_hash": hashlib.sha256(row["content"].encode()).hexdigest(),
                "normalized_hash": hashlib.sha256(row["content"].encode()).hexdigest(),
                "text_origin_source_id": row["source_id"],
                "structural_family_id": row["structural_family_id"],
                "attack_category_codes": [],
                "public_skill_text": None,
                "public_text_sha256": None,
                "original_text_withheld": False,
            }
        )
        primary_rows.append(record)

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
                        "label": row["label"],
                        "source_id": row["source_id"],
                        "split": row["splits"][protocol],
                    }
                    for benchmark_id, row in rows.items()
                ],
            )
            for protocol in ("source_disjoint", "m_structural_disjoint")
        },
    }
    source_root = tmp_path / "source"
    source_root.mkdir()
    profile_entry = {
        "materialization": {
            "quarantine_records": [quarantine_record],
            "sample_metadata_manifest_format": "sample-metadata-splits-v2",
            "sample_metadata_manifest_sha256": dataset["integrity"]["sample_metadata_manifest_sha256"],
            "sample_metadata_grouping": copy.deepcopy(dataset["integrity"]["sample_metadata_grouping"]),
        }
    }
    monkeypatch.setattr(
        materialize_malicious_skill_bench, "source_artifact_contract", lambda **_kwargs: (lock, (), profile_entry)
    )
    monkeypatch.setattr(materialize_malicious_skill_bench, "validate_acquired_sources", lambda *_args: None)
    monkeypatch.setattr(
        materialize_malicious_skill_bench,
        "parquet",
        SimpleNamespace(read_table=lambda path: tables[Path(path).relative_to(source_root).as_posix()]),
    )
    lock_path = tmp_path / "public-datasets.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    return lock_path


def _row(label: str, source_disjoint: str, structural: str, name: str) -> dict[str, Any]:
    return {
        "label": label,
        "source_id": f"SRC-{name}",
        "structural_family_id": f"FAMILY-{name}",
        "content": f"---\nname: {name}\ndescription: Inert fixture {name}\n---\n",
        "splits": {"source_disjoint": source_disjoint, "m_structural_disjoint": structural},
    }


def test_the_development_split_writes_no_test_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = {
        "dev-malicious": _row("1", "train", "validation", "dm"),
        "dev-benign": _row("0", "validation", "train", "db"),
        "test-member": _row("1", "test", "train", "tm"),
        "quarantined": _row("1", "train", "train", "q"),
    }
    lock_path = _synthetic_source(tmp_path, monkeypatch, rows, quarantined="quarantined")
    clean_root = tmp_path / "clean"
    summary = materialize_malicious_skill_bench.materialize_development_split(
        tmp_path / "source", clean_root, dataset_lock=lock_path
    )

    assert summary["records"] == 2
    assert summary["label_counts"] == {"benign": 1, "malicious": 1}
    assert summary["excluded_by_partition"] == 1
    assert summary["quarantined_in_selection"] == 1
    written = sorted(path.name for path in (clean_root / "msb-trainval").iterdir())
    assert written == ["dev-benign", "dev-malicious"]
    # The frozen test member never reaches disk, in the corpus or anywhere under the clean root.
    assert not any("test-member" in str(path) for path in clean_root.rglob("*"))
    corpus = CleanCorpus.load(clean_root, "msb-trainval")
    assert {record.record_id: record.label for record in corpus.records} == {
        "dev-benign": "benign",
        "dev-malicious": "malicious",
    }
    skill = clean_root / "msb-trainval" / "dev-malicious" / "SKILL.md"
    assert stat.S_IMODE(skill.stat().st_mode) == 0o600
    labels = json.loads((clean_root / "msb-trainval.labels.json").read_text(encoding="utf-8"))
    assert labels["selection"] == "every split protocol in ['train', 'validation']"


class TestRealSkillSample:
    def test_the_sample_is_fixed_and_independent_of_file_order(self) -> None:
        from evals.datasets.clawhub_security_signals import sample_row_ids

        ids = [f"row-{i}" for i in range(500)]
        first = sample_row_ids(ids, revision="r1", size=50)
        assert first == sample_row_ids(list(reversed(ids)), revision="r1", size=50)
        assert len(first) == 50 and len(set(first)) == 50
        # A new pinned revision draws a new sample rather than silently keeping the old one.
        assert first != sample_row_ids(ids, revision="r2", size=50)

    def _snapshot(self, tmp_path: Path, split: str) -> Any:
        from evals.datasets.clawhub_security_signals import ClawhubSecuritySignalsSnapshot, ClawhubSplitContract

        contract = ClawhubSplitContract(
            name=split,
            relative_path=Path(f"data/{split}.jsonl"),
            rows=3,
            size_bytes=0,
            sha256="0" * 64,
            silver_label_counts={},
        )
        return ClawhubSecuritySignalsSnapshot(
            root=tmp_path,
            revision="0" * 40,
            schema=(),
            raw_contract_sha256="0" * 64,
            raw_artifact_manifest_sha256="0" * 64,
            repository_artifact_manifest_pinned=True,
            splits=(contract,),
            lock_manifest=load_dataset_lock(),
        )

    def test_the_sample_is_label_free_and_writes_only_portable_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evals.datasets import clawhub_security_signals as clawhub

        def rows(_snapshot: Any) -> Any:
            for index in range(3):
                yield clawhub.ClawhubRowRecord(
                    split="validation",
                    line_number=index + 1,
                    row_id=f"owner/skill-{index}",
                    row={
                        "skill_md_content": f"---\nname: skill-{index}\n---\nDo a thing.\n",
                        "skill_bundle_content": [
                            {"path": "scripts/run.sh", "content": "echo hello\n"},
                            {"path": "../escape.sh", "content": "echo no\n"},
                            {"path": "/etc/passwd", "content": "no\n"},
                        ],
                        "clawscan_verdict": "malicious",
                    },
                    silver_verdict="malicious",
                    provenance={},
                    grouping={},
                    ingestion_error=None,
                )

        monkeypatch.setattr(clawhub, "iter_clawhub_security_signal_rows", rows)
        summary = clawhub.materialize_flag_rate_sample(
            self._snapshot(tmp_path, "validation"), tmp_path / "clean", size=2
        )
        assert summary["records"] == 2
        corpus = CleanCorpus.load(tmp_path / "clean", "clawhub-sample")
        # The silver verdict never becomes a label.
        assert all(record.label is None for record in corpus.records)
        for record in corpus.records:
            assert record.record_id.startswith("c_") and "owner" not in record.record_id
            written = sorted(
                p.relative_to(record.directory).as_posix() for p in record.directory.rglob("*") if p.is_file()
            )
            assert written == ["SKILL.md", "scripts/run.sh"]
        assert not any("escape" in str(p) for p in (tmp_path / "clean").rglob("*"))

    def test_a_split_outside_the_allowance_is_refused(self, tmp_path: Path) -> None:
        from evals.datasets import clawhub_security_signals as clawhub

        with pytest.raises(clawhub.ClawhubSecuritySignalsError, match="may sample only"):
            clawhub.materialize_flag_rate_sample(self._snapshot(tmp_path, "test"), tmp_path / "clean")
