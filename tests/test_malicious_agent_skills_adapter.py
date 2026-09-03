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
import csv
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

import evals.datasets.malicious_agent_skills_bench as masb_adapter
import evals.datasets.public_datasets as public_datasets
from evals.datasets.malicious_agent_skills_bench import (
    DATASET_ID,
    MALICIOUS_SKILLS_FILE,
    SKILLS_DATASET_FILE,
    SNAPSHOT_MANIFEST,
    MaliciousAgentSkillsError,
    load_malicious_agent_skills_snapshot,
)
from evals.datasets.public_datasets import artifact_manifest_sha256, get_locked_dataset, load_dataset_lock
from evals.datasets.quarantined_text import TextTreePolicy, inspect_text_package, inventory_text_tree
from evals.runners.malicious_agent_skills_benchmark import (
    SandboxConfirmedPackage,
    build_malicious_agent_taxonomy_report,
    run_malicious_agent_confirmed_recall,
)

_CSV_POLICY = TextTreePolicy(
    allowed_suffixes=frozenset({".csv"}),
    allowed_basenames=frozenset(),
    max_files=2,
    max_file_bytes=32 * 1024 * 1024,
    max_total_bytes=48 * 1024 * 1024,
)


def _revision() -> str:
    return str(get_locked_dataset(DATASET_ID, load_dataset_lock())["revision"])


def _write_csv(path: Path, header, rows) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def _write_manifest(root: Path) -> None:
    inventory = inventory_text_tree(root, policy=_CSV_POLICY, excluded_paths=(PurePosixPath(SNAPSHOT_MANIFEST),))
    artifacts = [artifact.manifest_entry() for artifact in inventory]
    manifest = {
        "schema_version": 1,
        "dataset_id": DATASET_ID,
        "revision": _revision(),
        "artifact_manifest_sha256": artifact_manifest_sha256(DATASET_ID, artifacts),
        "artifacts": artifacts,
    }
    (root / SNAPSHOT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")


@pytest.fixture
def small_contract(monkeypatch):
    dataset = copy.deepcopy(dict(get_locked_dataset(DATASET_ID, load_dataset_lock())))
    dataset["integrity"]["artifact_manifest_sha256"] = None
    dataset["integrity"]["hashes_pending"] = True
    dataset["expected"]["row_counts"] = {"skills_dataset/train": 4, "malicious_skills/train": 2}
    monkeypatch.setattr(masb_adapter, "get_locked_dataset", lambda dataset_id, manifest=None: dataset)
    monkeypatch.setattr(public_datasets, "get_locked_dataset", lambda dataset_id, manifest=None: dataset)
    monkeypatch.setattr(masb_adapter, "EXPECTED_SKILLS_ROWS", 4)
    monkeypatch.setattr(masb_adapter, "EXPECTED_MALICIOUS_ROWS", 2)
    monkeypatch.setattr(
        masb_adapter,
        "EXPECTED_LABEL_COUNTS",
        {"safe": 1, "suspicious": 1, "malicious": 2},
    )
    monkeypatch.setattr(masb_adapter, "EXPECTED_PATTERN_INSTANCES", 3)
    monkeypatch.setattr(
        masb_adapter,
        "EXPECTED_SEVERITY_COUNTS",
        {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
    )


def _snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "masb"
    root.mkdir(parents=True)
    _write_csv(
        root / SKILLS_DATASET_FILE,
        ["source", "repo", "skill_name", "classification", "url"],
        [
            ["github", "safe/repo", "safe-skill", "safe", "https://github.com/safe/repo/tree/main/safe"],
            ["github", "review/repo", "review-skill", "suspicious", "https://github.com/review/repo"],
            ["github", "bad/one", "bad-one", "malicious", "https://github.com/bad/one/tree/main/skill"],
            ["clawhub", "bad/two", "bad-two", "malicious", "https://example.test/bad/two"],
        ],
    )
    _write_csv(
        root / MALICIOUS_SKILLS_FILE,
        ["source", "repo", "skill_name", "classification", "Pattern", "Severity"],
        [
            [
                "github",
                "bad/one",
                "bad-one",
                "malicious",
                "Data Exfiltration; Remote Code Execution",
                "CRITICAL; HIGH",
            ],
            ["clawhub", "bad/two", "bad-two", "malicious", "Privilege Escalation", "MEDIUM"],
        ],
    )
    _write_manifest(root)
    return root


def test_taxonomy_is_strictly_malicious_and_explicitly_deoverlapped(tmp_path: Path, small_contract) -> None:
    snapshot = load_malicious_agent_skills_snapshot(_snapshot(tmp_path), revision=_revision())
    excluded = snapshot.malicious_cases[0]
    report = build_malicious_agent_taxonomy_report(
        snapshot,
        malicious_skill_bench_overlap_keys={excluded.overlap_keys[0]},
    )

    assert snapshot.skills_population == 4
    assert snapshot.label_counts == {"malicious": 2, "safe": 1, "suspicious": 1}
    assert len(snapshot.malicious_cases) == 2
    assert not hasattr(snapshot, "safe_cases")
    assert report["safe_rows_used_as_benign"] == 0
    assert report["benign_denominator"] == 0
    assert report["benign_gold_eligible"] is False
    assert report["malicious_skill_bench_deoverlap"] == {
        "status": "applied",
        "excluded_cases": 1,
        "double_counted_cases": 0,
        "eligible_cases": 1,
    }
    assert report["authoritative_metrics_eligible"] is False
    assert sum(report["per_pattern_instance_count"].values()) == sum(
        len(case.patterns) for case in snapshot.malicious_cases if case.case_id != excluded.case_id
    )


def test_dynamic_pattern_text_is_rejected_without_execution(tmp_path: Path, small_contract) -> None:
    root = _snapshot(tmp_path)
    marker = tmp_path / "executed"
    rows = list(csv.reader((root / MALICIOUS_SKILLS_FILE).read_text(encoding="utf-8").splitlines()))
    rows[1][4] = f"__import__('pathlib').Path({str(marker)!r}).write_text('executed'); Remote Code Execution"
    _write_csv(root / MALICIOUS_SKILLS_FILE, rows[0], rows[1:])
    _write_manifest(root)

    with pytest.raises(MaliciousAgentSkillsError, match="unknown taxonomy label"):
        load_malicious_agent_skills_snapshot(root)
    assert not marker.exists()


def test_exact_url_redactions_are_metadata_only_and_never_shared_overlap_keys(tmp_path: Path, small_contract) -> None:
    root = _snapshot(tmp_path)
    rows = list(csv.reader((root / SKILLS_DATASET_FILE).read_text(encoding="utf-8").splitlines()))
    rows[3][4] = "[REDACTED]"
    rows[4][4] = "[REDACTED]"
    _write_csv(root / SKILLS_DATASET_FILE, rows[0], rows[1:])
    _write_manifest(root)

    snapshot = load_malicious_agent_skills_snapshot(root)

    assert all(case.url is None for case in snapshot.malicious_cases)
    assert all(len(case.overlap_keys) == 3 for case in snapshot.malicious_cases)
    assert set(snapshot.malicious_cases[0].overlap_keys).isdisjoint(snapshot.malicious_cases[1].overlap_keys)


def test_unknown_url_placeholder_is_rejected(tmp_path: Path, small_contract) -> None:
    root = _snapshot(tmp_path)
    rows = list(csv.reader((root / SKILLS_DATASET_FILE).read_text(encoding="utf-8").splitlines()))
    rows[1][4] = "[UNKNOWN_REDACTION]"
    _write_csv(root / SKILLS_DATASET_FILE, rows[0], rows[1:])
    _write_manifest(root)

    with pytest.raises(MaliciousAgentSkillsError, match="absolute HTTP\\(S\\) URL"):
        load_malicious_agent_skills_snapshot(root)


def test_reviewed_identity_whitespace_is_canonicalized(tmp_path: Path, small_contract) -> None:
    root = _snapshot(tmp_path)
    rows = list(csv.reader((root / SKILLS_DATASET_FILE).read_text(encoding="utf-8").splitlines()))
    rows[1][2] = f"{rows[1][2]} "
    _write_csv(root / SKILLS_DATASET_FILE, rows[0], rows[1:])
    _write_manifest(root)

    snapshot = load_malicious_agent_skills_snapshot(root)

    assert snapshot.skills_population == 4


def test_locked_schema_drift_is_rejected(tmp_path: Path, small_contract, monkeypatch) -> None:
    dataset = copy.deepcopy(dict(get_locked_dataset(DATASET_ID, load_dataset_lock())))
    dataset["integrity"]["artifact_manifest_sha256"] = None
    dataset["integrity"]["hashes_pending"] = True
    dataset["expected"]["row_counts"] = {"skills_dataset/train": 4, "malicious_skills/train": 2}
    dataset["expected"]["schemas"]["skills_dataset"]["exact_fields"].append("unexpected")
    monkeypatch.setattr(masb_adapter, "get_locked_dataset", lambda dataset_id, manifest=None: dataset)

    with pytest.raises(MaliciousAgentSkillsError, match="locked CSV schemas"):
        load_malicious_agent_skills_snapshot(_snapshot(tmp_path))


def test_post_processing_report_cannot_pollute_snapshot_input(tmp_path: Path, small_contract) -> None:
    root = _snapshot(tmp_path)
    (root / "taxonomy-report.json").write_text("{}", encoding="utf-8")

    with pytest.raises(MaliciousAgentSkillsError, match="text allowlist"):
        load_malicious_agent_skills_snapshot(root)


@pytest.mark.parametrize("mutation", ["schema", "symlink", "executable", "unexpected"])
def test_rejects_schema_drift_and_unsafe_tree_entries(tmp_path: Path, small_contract, mutation: str) -> None:
    root = _snapshot(tmp_path)
    if mutation == "schema":
        rows = list(csv.reader((root / SKILLS_DATASET_FILE).read_text(encoding="utf-8").splitlines()))
        rows[0].append("unexpected")
        for row in rows[1:]:
            row.append("value")
        _write_csv(root / SKILLS_DATASET_FILE, rows[0], rows[1:])
        _write_manifest(root)
    elif mutation == "symlink":
        (root / "linked.csv").symlink_to(root / SKILLS_DATASET_FILE)
    elif mutation == "executable":
        path = root / MALICIOUS_SKILLS_FILE
        path.chmod(path.stat().st_mode | 0o111)
    else:
        (root / "dataset_hook.py").write_text("raise RuntimeError('must never run')", encoding="utf-8")

    with pytest.raises(MaliciousAgentSkillsError, match="schema drift|symbolic|executable|allowlist"):
        load_malicious_agent_skills_snapshot(root)


def test_confirmed_recall_uses_only_explicit_positive_packages_and_keeps_errors(tmp_path: Path, small_contract) -> None:
    snapshot = load_malicious_agent_skills_snapshot(_snapshot(tmp_path))
    records = []
    for index, case in enumerate(snapshot.malicious_cases):
        package = tmp_path / "confirmed" / str(index)
        package.mkdir(parents=True)
        (package / "SKILL.md").write_text(
            f"---\nname: confirmed-{index}\ndescription: inert\n---\nStatic malicious fixture {index}.\n",
            encoding="utf-8",
        )
        identity = inspect_text_package(package)
        records.append(
            SandboxConfirmedPackage(
                case_id=case.case_id,
                package_directory=package,
                content_sha256=identity.content_sha256,
                normalized_content_sha256=identity.normalized_content_sha256,
                confirmation_kind="sandbox_behavior_confirmed",
                confirmation_sha256=f"{index + 1:064x}",
            )
        )

    class Scanner:
        def __init__(self):
            self.paths: list[Path] = []

        def scan_skill(self, skill_directory: Path):
            self.paths.append(skill_directory)
            if skill_directory.name == "1":
                raise RuntimeError("bounded failure")
            return SimpleNamespace(findings=[SimpleNamespace(severity="CRITICAL")], analyzers_failed=[])

    scanner = Scanner()
    report = run_malicious_agent_confirmed_recall(
        snapshot,
        confirmed_packages=records,
        malicious_skill_bench_overlap_keys=set(),
        scanner=scanner,
    )

    assert report["positive_population"] == 2
    assert report["actionable_detected"] == 1
    assert report["positive_recall"] == 0.5
    assert report["errors"] == 1
    assert report["safe_rows_used_as_benign"] == 0
    assert report["double_counted_cases"] == 0
    assert report["sample_execution"] is False
    assert len(scanner.paths) == 2

    overlap_scanner = Scanner()
    overlap_report = run_malicious_agent_confirmed_recall(
        snapshot,
        confirmed_packages=records,
        malicious_skill_bench_overlap_keys={snapshot.malicious_cases[0].overlap_keys[0]},
        scanner=overlap_scanner,
    )
    assert overlap_report["overlap_excluded_confirmed"] == 1
    assert overlap_report["positive_population"] == 1
    assert len(overlap_scanner.paths) == 1


def test_confirmation_contract_and_content_drift_fail_closed(tmp_path: Path, small_contract) -> None:
    snapshot = load_malicious_agent_skills_snapshot(_snapshot(tmp_path))
    case = snapshot.malicious_cases[0]
    package = tmp_path / "confirmed"
    package.mkdir()
    skill = package / "SKILL.md"
    skill.write_text("inert text", encoding="utf-8")
    identity = inspect_text_package(package)
    record = SandboxConfirmedPackage(
        case_id=case.case_id,
        package_directory=package,
        content_sha256=identity.content_sha256,
        normalized_content_sha256=identity.normalized_content_sha256,
        confirmation_kind="sandbox_behavior_confirmed",
        confirmation_sha256="a" * 64,
    )
    skill.write_text("changed text", encoding="utf-8")
    report = run_malicious_agent_confirmed_recall(
        snapshot,
        confirmed_packages=[record],
        malicious_skill_bench_overlap_keys=set(),
        scanner=SimpleNamespace(scan_skill=lambda _: (_ for _ in ()).throw(AssertionError("must not scan"))),
    )
    assert report["positive_population"] == 1
    assert report["errors"] == 1
    assert report["outcomes"][0]["error_code"] == "PACKAGE_CONTENT_HASH_DRIFT"

    invalid = SandboxConfirmedPackage(
        **{**record.__dict__, "confirmation_kind": "self_reported"},
    )
    with pytest.raises(MaliciousAgentSkillsError, match="confirmation_kind"):
        run_malicious_agent_confirmed_recall(
            snapshot,
            confirmed_packages=[invalid],
            malicious_skill_bench_overlap_keys=set(),
            scanner=SimpleNamespace(scan_skill=lambda _: None),
        )
