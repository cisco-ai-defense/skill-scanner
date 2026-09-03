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
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.datasets.clawhub_security_signals import (
    DATASET_ID,
    RAW_CONTRACT_FILE,
    SPLIT_ORDER,
    ClawhubSecuritySignalsError,
    iter_clawhub_security_signal_rows,
    load_clawhub_security_signals_snapshot,
)
from evals.datasets.public_datasets import artifact_manifest_sha256, get_locked_dataset, load_dataset_lock
from evals.runners.clawhub_security_signals_benchmark import (
    _build_static_scanner,
    main,
    run_clawhub_security_signals_benchmark,
)

REVISION = "69dcbd323c155312fb000ec89ea0b1efdf6a5757"


def test_repository_raw_snapshot_lock_matches_reviewed_profile_and_dataset_lock() -> None:
    raw_contract = json.loads(RAW_CONTRACT_FILE.read_text(encoding="utf-8"))
    profile_path = RAW_CONTRACT_FILE.with_name("public-datasets.profile.json")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile_entry = next(item for item in profile["datasets"] if item["id"] == DATASET_ID)
    manifest = load_dataset_lock()
    dataset = get_locked_dataset(DATASET_ID, manifest)

    assert raw_contract["revision"] == dataset["revision"] == REVISION
    assert raw_contract["schema"] == dataset["expected"]["schemas"]["default"]["exact_fields"]
    artifacts = []
    for split in SPLIT_ORDER:
        locked_split = raw_contract["splits"][split]
        inspected_split = profile_entry["splits"][split]
        assert locked_split == {
            "path": f"data/{split}.jsonl",
            "rows": inspected_split["rows"],
            "silver_label_counts": inspected_split["labels"],
            "size_bytes": inspected_split["size_bytes"],
            "sha256": inspected_split["sha256"],
        }
        artifacts.append(
            {
                "path": locked_split["path"],
                "sha256": locked_split["sha256"],
                "size_bytes": locked_split["size_bytes"],
            }
        )
    assert raw_contract["artifact_manifest_sha256"] == artifact_manifest_sha256(
        DATASET_ID,
        artifacts,
        manifest=manifest,
    )


def _row(
    row_id: str,
    *,
    split: str = "test",
    verdict: str = "clean",
    content: str = "---\nname: fixture\ndescription: inert fixture\n---\n",
) -> dict:
    fields = get_locked_dataset(DATASET_ID, load_dataset_lock())["expected"]["schemas"]["default"]["exact_fields"]
    row = {field: None for field in fields}
    row.update(
        {
            "id": row_id,
            "skill_slug": f"fixture-owner/{row_id}",
            "skill_version": "1.0.0",
            "skill_md_content": content,
            "skill_bundle_content": [],
            "clawscan_verdict": verdict,
            "clawscan_confidence": "high",
            "clawscan_model": "fixture-model",
            "clawscan_summary": "fixture summary",
            "static_status": "clean",
            "static_finding_count": 0,
            "static_reason_codes": [],
            "virustotal_status": "clean",
            "virustotal_malicious_count": 0,
            "virustotal_suspicious_count": 0,
            "virustotal_harmless_count": 1,
            "virustotal_undetected_count": 0,
            "skillspector_status": "clean",
            "skillspector_score": 0.0,
            "skillspector_severity": None,
            "skillspector_issue_count": 0,
            "skillspector_issue_codes": [],
            "skillspector_issue_categories": [],
            "clawscan_context": {},
            "split": split,
        }
    )
    return row


def _encoded_rows(rows: list[dict] | bytes) -> bytes:
    if isinstance(rows, bytes):
        return rows
    return b"".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
        for row in rows
    )


def _write_snapshot_contract(
    tmp_path: Path,
    *,
    selected_rows: list[dict] | bytes,
    selected_split: str = "test",
) -> tuple[Path, Path, Path]:
    root = tmp_path / "snapshot"
    data = root / "data"
    data.mkdir(parents=True)
    selected_content = _encoded_rows(selected_rows)
    (data / f"{selected_split}.jsonl").write_bytes(selected_content)

    lock = copy.deepcopy(load_dataset_lock())
    locked = next(item for item in lock["datasets"] if item["id"] == DATASET_ID)
    raw_contract = json.loads(RAW_CONTRACT_FILE.read_text(encoding="utf-8"))

    split_contents: dict[str, bytes] = {}
    split_rows: dict[str, list[dict] | bytes] = {}
    for split in SPLIT_ORDER:
        if split == selected_split:
            rows = selected_rows
        else:
            rows = [_row(f"unselected-{split}", split=split)]
        split_rows[split] = rows
        split_contents[split] = _encoded_rows(rows)
        row_count = split_contents[split].count(b"\n")
        locked["expected"]["row_counts"][f"default/{split}"] = row_count
        labels = {"clean": 0, "suspicious": 0, "malicious": 0}
        if isinstance(rows, list):
            for row in rows:
                verdict = row.get("clawscan_verdict")
                if verdict in labels:
                    labels[verdict] += 1
        else:
            # A deliberately malformed locked row still occupies the silver
            # population. The benchmark must retain it as an ingestion error.
            labels["clean"] = row_count
        raw_contract["splits"][split] = {
            "path": f"data/{split}.jsonl",
            "rows": row_count,
            "silver_label_counts": labels,
            "size_bytes": len(split_contents[split]),
            "sha256": hashlib.sha256(split_contents[split]).hexdigest(),
        }

    aggregate = {"clean": 0, "suspicious": 0, "malicious": 0}
    for split in SPLIT_ORDER:
        for verdict, count in raw_contract["splits"][split]["silver_label_counts"].items():
            aggregate[verdict] += count
    raw_contract["quality"]["total_rows"] = sum(raw_contract["splits"][split]["rows"] for split in SPLIT_ORDER)
    raw_contract["quality"]["silver_label_counts"] = aggregate
    raw_contract["quality"]["unique_ids_within_splits"] = True
    raw_contract["quality"]["bundle_hash_and_size_mismatches"] = 0
    raw_contract["quality"]["unsafe_bundle_paths"] = 0
    artifacts = [
        {
            "path": raw_contract["splits"][split]["path"],
            "sha256": raw_contract["splits"][split]["sha256"],
            "size_bytes": raw_contract["splits"][split]["size_bytes"],
        }
        for split in SPLIT_ORDER
    ]
    raw_contract["artifact_manifest_sha256"] = artifact_manifest_sha256(DATASET_ID, artifacts, manifest=lock)

    lock_path = tmp_path / "datasets.lock.json"
    contract_path = tmp_path / "clawhub.raw.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    contract_path.write_text(json.dumps(raw_contract), encoding="utf-8")
    return root, lock_path, contract_path


def _load(root: Path, lock: Path, raw_contract: Path, *, split: str = "test"):
    return load_clawhub_security_signals_snapshot(
        root,
        revision=REVISION,
        splits=(split,),
        dataset_lock=lock,
        raw_contract=raw_contract,
    )


class _StaticScanner:
    def scan_skill(self, skill_directory: Path):
        content = (skill_directory / "SKILL.md").read_text(encoding="utf-8")
        if "scan-error" in content:
            raise RuntimeError("deliberate scanner failure")
        actionable = "actionable" in content
        findings = []
        if actionable:
            findings.append(SimpleNamespace(rule_id="FIXTURE_ACTIONABLE", severity="HIGH", analyzer="static"))
        failures = ["fixture_partial"] if "analyzer-failure" in content else []
        return SimpleNamespace(findings=findings, analyzers_failed=failures)


def test_loads_only_pinned_raw_jsonl_and_yields_provenance(tmp_path: Path) -> None:
    root, lock, profile = _write_snapshot_contract(
        tmp_path,
        selected_rows=[_row("clean-one"), _row("malicious-one", verdict="malicious")],
    )

    snapshot = _load(root, lock, profile)
    records = list(iter_clawhub_security_signal_rows(snapshot))

    assert snapshot.population == 2
    assert len(snapshot.raw_contract_sha256) == 64
    assert [record.row_id for record in records] == ["clean-one", "malicious-one"]
    assert all(record.ingestion_error is None for record in records)
    assert records[0].provenance == {
        "dataset_id": DATASET_ID,
        "revision": REVISION,
        "split": "test",
        "split_sha256": snapshot.splits[0].sha256,
        "row_id": "clean-one",
    }
    assert set(records[0].grouping) == {
        "repository_group_sha256",
        "exact_content_sha256",
        "normalized_content_sha256",
        "structural_family_sha256",
    }
    assert all(len(value) == 64 for value in records[0].grouping.values())


@pytest.mark.parametrize("mutation", ["bytes", "size", "count", "schema", "revision", "contract_hash"])
def test_rejects_revision_schema_count_size_and_hash_drift(tmp_path: Path, mutation: str) -> None:
    root, lock, profile = _write_snapshot_contract(tmp_path, selected_rows=[_row("one")])
    revision = REVISION
    if mutation == "bytes":
        path = root / "data" / "test.jsonl"
        content = bytearray(path.read_bytes())
        content[0] = ord("[")
        path.write_bytes(content)
    elif mutation == "size":
        (root / "data" / "test.jsonl").write_bytes(b"{}\n")
    elif mutation == "count":
        manifest = json.loads(lock.read_text())
        dataset = next(item for item in manifest["datasets"] if item["id"] == DATASET_ID)
        dataset["expected"]["row_counts"]["default/test"] = 2
        lock.write_text(json.dumps(manifest))
    elif mutation == "schema":
        payload = json.loads(profile.read_text())
        payload["schema"].append("unexpected")
        profile.write_text(json.dumps(payload))
    elif mutation == "revision":
        revision = "0" * 40
    else:
        payload = json.loads(profile.read_text())
        payload["splits"]["test"]["sha256"] = "0" * 64
        profile.write_text(json.dumps(payload))

    with pytest.raises(ClawhubSecuritySignalsError):
        load_clawhub_security_signals_snapshot(
            root,
            revision=revision,
            splits=("test",),
            dataset_lock=lock,
            raw_contract=profile,
        )


def test_rejects_symlinks_executable_members_and_unexpected_file_types(tmp_path: Path) -> None:
    root, lock, profile = _write_snapshot_contract(tmp_path, selected_rows=[_row("one")])
    raw = root / "data" / "test.jsonl"
    raw.chmod(0o700)
    with pytest.raises(ClawhubSecuritySignalsError, match="executable"):
        _load(root, lock, profile)
    raw.chmod(0o600)

    (root / "data" / "unexpected.parquet").write_bytes(b"stale")
    with pytest.raises(ClawhubSecuritySignalsError, match="unexpected"):
        _load(root, lock, profile)
    (root / "data" / "unexpected.parquet").unlink()

    target = tmp_path / "target.jsonl"
    target.write_bytes(raw.read_bytes())
    raw.unlink()
    raw.symlink_to(target)
    with pytest.raises(ClawhubSecuritySignalsError, match="non-symlink"):
        _load(root, lock, profile)


def test_custom_raw_contract_requires_explicit_dataset_lock(tmp_path: Path) -> None:
    root, _lock, raw_contract = _write_snapshot_contract(tmp_path, selected_rows=[_row("one")])

    with pytest.raises(ClawhubSecuritySignalsError, match="matching dataset lock"):
        load_clawhub_security_signals_snapshot(
            root,
            revision=REVISION,
            splits=("test",),
            raw_contract=raw_contract,
        )


def test_malformed_and_schema_invalid_rows_stay_in_denominator(tmp_path: Path) -> None:
    root, lock, profile = _write_snapshot_contract(tmp_path, selected_rows=b"{not-json}\n")
    snapshot = _load(root, lock, profile)
    report = run_clawhub_security_signals_benchmark(snapshot, scanner=_StaticScanner())

    assert report["population_denominator"] == report["processed_rows"] == 1
    assert report["errors"]["counts"] == {"ingestion:INVALID_JSON": 1}
    assert report["drift"]["by_silver_verdict"]["unknown"]["population"] == 1
    assert report["release_blocking"] is False
    assert report["release_decision"] == "not_applicable"


def test_duplicate_id_is_not_dropped_from_denominator(tmp_path: Path) -> None:
    root, lock, profile = _write_snapshot_contract(
        tmp_path,
        selected_rows=[_row("same"), _row("same")],
    )
    report = run_clawhub_security_signals_benchmark(_load(root, lock, profile), scanner=_StaticScanner())

    assert report["population_denominator"] == report["processed_rows"] == 2
    assert report["errors"]["counts"] == {"ingestion:ROW_SCHEMA_INVALID": 1}
    assert report["drift"]["by_silver_verdict"]["clean"]["scan_completed"] == 1


def test_materialization_and_scan_errors_stay_in_denominator(tmp_path: Path) -> None:
    unsafe = _row("unsafe")
    content = "print('inert')\n"
    unsafe["skill_bundle_content"] = [
        {
            "path": "../escape.py",
            "content": content,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "sizeBytes": len(content.encode()),
        }
    ]
    root, lock, profile = _write_snapshot_contract(
        tmp_path,
        selected_rows=[unsafe, _row("scan", content="scan-error")],
    )
    report = run_clawhub_security_signals_benchmark(_load(root, lock, profile), scanner=_StaticScanner())

    assert report["population_denominator"] == report["processed_rows"] == 2
    assert sum(report["errors"]["counts"].values()) == 2
    assert any(key.startswith("materialization:") for key in report["errors"]["counts"])
    assert report["errors"]["counts"]["scan:RuntimeError"] == 1


def test_reports_silver_disagreement_without_accuracy_claims_or_sample_text(tmp_path: Path) -> None:
    secret_marker = "DO-NOT-PERSIST-RAW-SAMPLE"
    root, lock, profile = _write_snapshot_contract(
        tmp_path,
        selected_rows=[
            _row("clean-actionable", content=f"actionable {secret_marker}"),
            _row("suspicious-gap", verdict="suspicious"),
            _row("malicious-hit", verdict="malicious", content="actionable analyzer-failure"),
        ],
    )
    report = run_clawhub_security_signals_benchmark(
        _load(root, lock, profile),
        scanner=_StaticScanner(),
        max_candidate_records=10,
    )

    assert report["label_scope"] == "scanner_derived_silver_signals_not_ground_truth"
    assert report["authoritative_metrics_eligible"] is False
    assert report["false_positive_mining"]["silver_clean_actionable_candidates"] == 1
    assert report["false_positive_mining"]["candidate_rate_over_silver_clean"] == 1.0
    assert report["disagreement"]["review_gap_candidates"]["count"] == 1
    assert report["analyzer_failure_samples"] == 1
    assert secret_marker not in json.dumps(report)

    def keys(value):
        if isinstance(value, dict):
            return set(value) | {key for item in value.values() for key in keys(item)}
        if isinstance(value, list):
            return {key for item in value for key in keys(item)}
        return set()

    assert not {"precision", "recall", "f1", "false_positive_rate"} & keys(report)


def test_candidate_and_error_records_are_bounded(tmp_path: Path) -> None:
    root, lock, profile = _write_snapshot_contract(
        tmp_path,
        selected_rows=[_row(f"row-{index}", content="actionable") for index in range(3)],
    )
    report = run_clawhub_security_signals_benchmark(
        _load(root, lock, profile),
        scanner=_StaticScanner(),
        max_candidate_records=1,
    )

    mining = report["false_positive_mining"]
    assert mining["silver_clean_actionable_candidates"] == 3
    assert len(mining["records"]) == 1
    assert mining["records_truncated"] is True


def test_malformed_scanner_result_is_retained_as_scan_error(tmp_path: Path) -> None:
    class BrokenResult:
        @property
        def findings(self):
            raise RuntimeError("broken result object")

    class BrokenScanner:
        def scan_skill(self, _skill_directory: Path):
            return BrokenResult()

    root, lock, raw_contract = _write_snapshot_contract(tmp_path, selected_rows=[_row("one")])
    report = run_clawhub_security_signals_benchmark(
        _load(root, lock, raw_contract),
        scanner=BrokenScanner(),
    )

    assert report["population_denominator"] == report["processed_rows"] == 1
    assert report["errors"]["counts"] == {"scan:INVALID_RESULT_RuntimeError": 1}


def test_cli_missing_snapshot_is_a_nonblocking_skip_without_building_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(**_kwargs):
        raise AssertionError("scanner must not be constructed for an unavailable supplemental snapshot")

    monkeypatch.setattr("evals.runners.clawhub_security_signals_benchmark._build_static_scanner", forbidden)
    output = tmp_path / "report.json"

    assert main(["--snapshot", str(tmp_path / "missing"), "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["status"] == "skipped"
    assert report["supplemental"] is True
    assert report["release_decision"] == "not_applicable"


def test_cli_refuses_to_overwrite_snapshot_input(tmp_path: Path) -> None:
    root, _lock, _raw_contract = _write_snapshot_contract(tmp_path, selected_rows=[_row("one")])

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--snapshot",
                str(root),
                "--output",
                str(root / "data" / "test.jsonl"),
            ]
        )

    assert exc_info.value.code == 2


def test_materialized_files_are_never_executable(tmp_path: Path) -> None:
    observed_modes: list[int] = []

    class ModeScanner:
        def scan_skill(self, skill_directory: Path):
            observed_modes.append(stat.S_IMODE((skill_directory / "SKILL.md").stat().st_mode))
            return SimpleNamespace(findings=[], analyzers_failed=[])

    root, lock, profile = _write_snapshot_contract(tmp_path, selected_rows=[_row("one")])
    run_clawhub_security_signals_benchmark(_load(root, lock, profile), scanner=ModeScanner())

    assert observed_modes == [0o600]


def test_real_core_scanner_runs_offline_snapshot_in_cel_shadow_mode(tmp_path: Path) -> None:
    root, lock, raw_contract = _write_snapshot_contract(tmp_path, selected_rows=[_row("real-core")])
    scanner = _build_static_scanner(detector_profile="core_only", cel_mode="shadow")

    report = run_clawhub_security_signals_benchmark(
        _load(root, lock, raw_contract),
        scanner=scanner,
        max_candidate_records=1,
    )

    assert report["population_denominator"] == report["processed_rows"] == 1
    assert report["errors"]["total"] == 0
    assert report["cel"]["samples_with_metadata"] == 1
    assert report["cel"]["samples_without_metadata"] == 0
    assert report["cel"]["invalid_metadata_samples"] == 0
    assert report["cel"]["identity_values"]["mode"] == ["shadow"]
    assert report["cel"]["identity_values"]["runtime"] == ["cel-go"]
