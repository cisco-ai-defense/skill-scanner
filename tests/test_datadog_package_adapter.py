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

import json
import os
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from evals.datasets.datadog_malicious_packages import (
    DATASET_ID,
    SNAPSHOT_MANIFEST,
    DataDogSnapshotError,
    datadog_population_sha256,
    load_datadog_package_snapshot,
)
from evals.datasets.public_datasets import artifact_manifest_sha256, get_locked_dataset, load_dataset_lock
from evals.datasets.quarantined_text import inventory_text_tree, package_identity
from evals.runners.datadog_package_benchmark import run_datadog_package_recall


def _revision() -> str:
    return str(get_locked_dataset(DATASET_ID, load_dataset_lock())["revision"])


def _metadata(sample_id: str, path: str, *, identity) -> dict[str, str]:
    return {
        "sample_id": sample_id,
        "ecosystem": "npm",
        "package_name": f"package-{sample_id}",
        "package_version": "1.0.0",
        "source_id": "datadog",
        "repository_id": f"repository-{sample_id}",
        "actor_campaign_id": "campaign-a",
        "structural_family_id": "family-a",
        "lexical_template_id": "template-a",
        "path": path,
        "content_sha256": identity.content_sha256,
        "normalized_content_sha256": identity.normalized_content_sha256,
    }


def _quarantine(sample_id: str = "quarantined") -> dict[str, str]:
    return {
        "sample_id": sample_id,
        "ecosystem": "pypi",
        "package_name": f"package-{sample_id}",
        "package_version": "2.0.0",
        "source_id": "datadog",
        "repository_id": "repository-q",
        "actor_campaign_id": "campaign-q",
        "structural_family_id": "family-q",
        "lexical_template_id": "template-q",
        "error_code": "BINARY_ONLY_PACKAGE",
    }


def _write_manifest(root: Path, samples, quarantine=()) -> None:
    inventory = inventory_text_tree(root, excluded_paths=(PurePosixPath(SNAPSHOT_MANIFEST),))
    artifacts = [artifact.manifest_entry() for artifact in inventory]
    manifest = {
        "schema_version": 1,
        "dataset_id": DATASET_ID,
        "revision": _revision(),
        "artifact_manifest_sha256": artifact_manifest_sha256(DATASET_ID, artifacts),
        "artifacts": artifacts,
        "population_sha256": datadog_population_sha256(samples, quarantine, revision=_revision()),
        "samples": samples,
        "quarantine": list(quarantine),
    }
    (root / SNAPSHOT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")


def _snapshot(tmp_path: Path, *, marker: Path | None = None):
    root = tmp_path / "datadog"
    first = root / "packages" / "a"
    duplicate = root / "packages" / "b"
    failing = root / "packages" / "c"
    first.mkdir(parents=True)
    duplicate.mkdir(parents=True)
    failing.mkdir(parents=True)
    payload = "---\nname: package-a\ndescription: inert\n---\nRun a suspicious command.\n"
    (first / "SKILL.md").write_text(payload, encoding="utf-8")
    # A trailing-space/newline-only mutation has the same normalized identity.
    (duplicate / "SKILL.md").write_text(payload.replace("command.", "command.  ") + "\n", encoding="utf-8")
    marker_code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n" if marker else "x = 1\n"
    (failing / "setup.py").write_text(marker_code, encoding="utf-8")

    inventory = inventory_text_tree(root)
    samples = []
    for sample_id in ("a", "b", "c"):
        prefix = PurePosixPath("packages") / sample_id
        identity = package_identity(
            tuple(artifact for artifact in inventory if artifact.path.is_relative_to(prefix)),
            prefix=prefix,
        )
        samples.append(_metadata(sample_id, prefix.as_posix(), identity=identity))
    _write_manifest(root, samples, [_quarantine()])
    return root


def test_text_only_runner_deduplicates_and_keeps_errors_in_denominator(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    root = _snapshot(tmp_path, marker=marker)
    snapshot = load_datadog_package_snapshot(root, revision=_revision())

    class Scanner:
        def __init__(self):
            self.paths: list[Path] = []

        def scan_skill(self, skill_directory: Path):
            self.paths.append(skill_directory)
            if skill_directory.name == "c":
                raise RuntimeError("bounded failure")
            return SimpleNamespace(findings=[SimpleNamespace(severity="HIGH")], analyzers_failed=[])

    scanner = Scanner()
    report = run_datadog_package_recall(snapshot, scanner=scanner)

    assert not marker.exists()
    assert len(snapshot.packages) == 3
    assert snapshot.normalized_duplicate_of == {"b": "a"}
    assert report["declared_positive_population"] == 4
    assert report["positive_population"] == 3
    assert report["actionable_detected"] == 1
    assert report["positive_recall"] == pytest.approx(1 / 3)
    assert report["errors"] == 2
    assert report["benign_gold_eligible"] is False
    assert report["authoritative_metrics_eligible"] is False
    assert report["sample_execution"] is False
    assert {path.name for path in scanner.paths} == {"a", "c"}
    assert report["grouping"]["per_ecosystem"]["pypi"]["errors"] == 1


@pytest.mark.parametrize("mutation", ["symlink", "archive", "binary", "executable"])
def test_snapshot_rejects_unsafe_members(tmp_path: Path, mutation: str) -> None:
    root = _snapshot(tmp_path)
    if mutation == "symlink":
        (root / "packages" / "a" / "escape.md").symlink_to(root / "packages" / "c" / "setup.py")
    elif mutation == "archive":
        (root / "packages" / "a" / "payload.zip").write_bytes(b"PK\x03\x04payload")
    elif mutation == "binary":
        (root / "packages" / "a" / "payload.txt").write_bytes(b"prefix\x00suffix")
    else:
        path = root / "packages" / "a" / "SKILL.md"
        path.chmod(path.stat().st_mode | 0o111)

    with pytest.raises(DataDogSnapshotError, match="symbolic|archive|NUL|executable"):
        load_datadog_package_snapshot(root)


def test_snapshot_rejects_traversal_and_population_or_artifact_drift(tmp_path: Path) -> None:
    root = _snapshot(tmp_path)
    manifest_path = root / SNAPSHOT_MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["samples"][0]["path"] = "packages/../escape"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(DataDogSnapshotError, match="portable relative path"):
        load_datadog_package_snapshot(root)

    root = _snapshot(tmp_path / "population")
    manifest_path = root / SNAPSHOT_MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["population_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(DataDogSnapshotError, match="population manifest digest mismatch"):
        load_datadog_package_snapshot(root)

    root = _snapshot(tmp_path / "artifact")
    (root / "packages" / "a" / "SKILL.md").write_text("changed", encoding="utf-8")
    with pytest.raises(DataDogSnapshotError, match="artifact inventory"):
        load_datadog_package_snapshot(root)


def test_revision_is_pinned_and_manifest_cannot_be_executable(tmp_path: Path) -> None:
    root = _snapshot(tmp_path)
    with pytest.raises(DataDogSnapshotError, match="revision drift"):
        load_datadog_package_snapshot(root, revision="0" * 40)

    manifest_path = root / SNAPSHOT_MANIFEST
    os.chmod(manifest_path, manifest_path.stat().st_mode | 0o111)
    with pytest.raises(DataDogSnapshotError, match="executable-mode"):
        load_datadog_package_snapshot(root)
