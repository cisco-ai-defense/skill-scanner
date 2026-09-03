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

"""Evaluate a frozen, already-materialized public skill corpus.

This runner intentionally has no acquisition code.  It accepts a local
``benchmark-snapshot.json`` plus skill directories, verifies the complete file
inventory against the repository's pinned dataset contract, and runs only the
static scanner.  It never imports, executes, or follows links from a sample.

Snapshot layout (schema version 1)::

    snapshot/
      benchmark-snapshot.json
      skills/<benchmark id>/SKILL.md

The manifest contains ``dataset_id``, ``revision``,
``artifact_manifest_sha256``, ``artifacts`` and ``samples``. ``artifacts`` is
the canonical declared ``path-sha256-size-v1`` inventory. An optional,
lock-pinned ``quarantine`` object accounts for exact unavailable members only
when each member is outside every blocking track; the usable on-disk inventory
must otherwise match exactly. Each sample has exactly these fields::

    {
      "benchmark_id": "MSB-...",
      "label": "malicious" | "benign",
      "source_id": "SRC001",
      "structural_family_id": "...",
      "category_ids": ["command_execution", "data_exfiltration"],
      "path": "skills/MSB-...",
      "splits": {
        "source_disjoint": "train" | "validation" | "test" | "excluded",
        "m_structural_disjoint": "train" | "validation" | "test" | "excluded"
      }
    }

Acquisition is a separate, trusted workflow.  Pull-request and release scan
jobs consume only this validated local representation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

# Permit direct execution from the repository checkout.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.datasets.public_datasets import (  # noqa: E402
    DatasetLockError,
    DatasetSchemaError,
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    validate_artifact_manifest,
    validate_quarantine_manifest,
)
from evals.runners.loader_fallback import (  # noqa: E402
    LoaderClosedRejection,
    LoaderFallbackRecovery,
    recognize_loader_disposition,
)
from skill_scanner import __version__ as scanner_version  # noqa: E402
from skill_scanner.core.analyzer_factory import build_core_analyzers  # noqa: E402
from skill_scanner.core.cel.go_runtime import CEL_GO_VERSION  # noqa: E402
from skill_scanner.core.cel.models import CelMode  # noqa: E402
from skill_scanner.core.rule_registry import PackLoader, RuleRegistry  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402
from skill_scanner.data import DATA_DIR, list_available_packs, resolve_rule_packs  # noqa: E402

SNAPSHOT_MANIFEST = "benchmark-snapshot.json"
SNAPSHOT_SCHEMA_VERSION = 1
MALICIOUS_SKILL_BENCH = "ProtectSkills/MaliciousSkillBench"
_SNAPSHOT_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "revision",
        "artifact_manifest_sha256",
        "artifacts",
        "samples",
    }
)
_SNAPSHOT_OPTIONAL_FIELDS = frozenset({"quarantine"})
_QUARANTINE_FIELDS = frozenset({"manifest_sha256", "records"})
_SAMPLE_REQUIRED_FIELDS = frozenset({"benchmark_id", "label", "source_id", "structural_family_id", "path", "splits"})
_SAMPLE_OPTIONAL_FIELDS = frozenset({"category_id", "category_ids"})
_ARTIFACT_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_LABELS = frozenset({"malicious", "benign"})
_PARTITIONS = frozenset({"train", "validation", "test", "excluded"})
_ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
_BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_SIGNAL_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_ALL_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"})
_MAX_INVENTORY_FILES = 100_000
_MAX_INVENTORY_BYTES = 2 * 1024 * 1024 * 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_METADATA_STRING_BYTES = 4_096
_MAX_COMPACT_RELEASE_REPORT_BYTES = 16 * 1024 * 1024
_MAX_TRUSTED_PACK_FILES = 4_096
_MAX_TRUSTED_PACK_FILE_BYTES = 32 * 1024 * 1024
_MAX_TRUSTED_PACK_BYTES = 128 * 1024 * 1024
_EMPTY_EXPRESSION_SET_HASH = hashlib.sha256(b"skill-scanner-cel-expression-set-v1\0").hexdigest()


class PublicBenchmarkError(ValueError):
    """Raised when a frozen public benchmark cannot be trusted or evaluated."""


class _Scanner(Protocol):
    def scan_skill(self, skill_directory: Path): ...


@dataclass(frozen=True)
class FrozenSample:
    benchmark_id: str
    label: str
    source_id: str
    structural_family_id: str
    category_ids: tuple[str, ...]
    relative_path: PurePosixPath
    splits: Mapping[str, str]


@dataclass(frozen=True)
class FrozenSnapshot:
    root: Path
    dataset: Mapping[str, Any]
    artifact_manifest_sha256: str
    usable_artifact_manifest_sha256: str
    quarantine_manifest_sha256: str | None
    quarantined_sample_ids: tuple[str, ...]
    samples: tuple[FrozenSample, ...]


@dataclass(frozen=True)
class TrustedPackSet:
    """Validated, path-independent identity for local benchmark extensions."""

    paths: tuple[Path, ...]
    identity: Mapping[str, Any]


def _require_exact_fields(value: Any, expected: frozenset[str], location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicBenchmarkError(f"{location} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise PublicBenchmarkError(f"{location} has invalid fields (missing={missing}, unexpected={unexpected})")
    return value


def _require_sample_fields(value: Any, location: str) -> Mapping[str, Any]:
    """Validate a sample while permitting the schema-v1 category extension.

    Early frozen snapshots did not retain the upstream category grouping.  We
    continue to read those snapshots as ``unclassified`` so historical runs
    remain comparable, while newer materializers can provide ``category_id``
    for the mandatory per-category report.
    """

    if not isinstance(value, Mapping):
        raise PublicBenchmarkError(f"{location} must be an object")
    actual = set(value)
    missing = sorted(_SAMPLE_REQUIRED_FIELDS - actual)
    unexpected = sorted(actual - _SAMPLE_REQUIRED_FIELDS - _SAMPLE_OPTIONAL_FIELDS)
    if missing or unexpected:
        raise PublicBenchmarkError(f"{location} has invalid fields (missing={missing}, unexpected={unexpected})")
    return value


def _require_snapshot_fields(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicBenchmarkError("snapshot manifest must be an object")
    actual = set(value)
    missing = sorted(_SNAPSHOT_REQUIRED_FIELDS - actual)
    unexpected = sorted(actual - _SNAPSHOT_REQUIRED_FIELDS - _SNAPSHOT_OPTIONAL_FIELDS)
    if missing or unexpected:
        raise PublicBenchmarkError(f"snapshot manifest has invalid fields (missing={missing}, unexpected={unexpected})")
    return value


def _require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PublicBenchmarkError(f"{location} must be a non-empty NUL-free string")
    if len(value.encode("utf-8")) > _MAX_METADATA_STRING_BYTES:
        raise PublicBenchmarkError(f"{location} exceeds the {_MAX_METADATA_STRING_BYTES}-byte metadata limit")
    return value


def _relative_path(raw: Any, location: str) -> PurePosixPath:
    value = _require_string(raw, location)
    if "\\" in value or value.startswith("/") or len(value.encode("utf-8")) > 1_024:
        raise PublicBenchmarkError(f"{location} must be a normalized portable relative path")
    parts = value.split("/")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in parts):
        raise PublicBenchmarkError(f"{location} must be a normalized portable relative path")
    if any(":" in part or part.endswith((" ", ".")) for part in parts):
        raise PublicBenchmarkError(f"{location} is not portable across supported platforms")
    return path


def _regular_file_inventory(root: Path) -> list[dict[str, Any]]:
    """Hash the complete snapshot inventory without following symbolic links."""

    if root.is_symlink() or not root.is_dir():
        raise PublicBenchmarkError("snapshot root must be an existing non-symlink directory")

    inventory: list[dict[str, Any]] = []
    total_bytes = 0
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names.sort()
        file_names.sort()
        for name in [*directory_names, *file_names]:
            member = current / name
            member_stat = member.lstat()
            if stat.S_ISLNK(member_stat.st_mode):
                raise PublicBenchmarkError(f"snapshot contains a symbolic link: {member.relative_to(root)}")
            if name in directory_names and not stat.S_ISDIR(member_stat.st_mode):
                raise PublicBenchmarkError(f"snapshot contains a non-directory tree entry: {member}")
            if name in file_names and not stat.S_ISREG(member_stat.st_mode):
                raise PublicBenchmarkError(f"snapshot contains a non-regular file: {member}")

        for name in file_names:
            member = current / name
            relative = member.relative_to(root).as_posix()
            if relative == SNAPSHOT_MANIFEST:
                continue
            member_stat = member.stat(follow_symlinks=False)
            if member_stat.st_size > _MAX_FILE_BYTES:
                raise PublicBenchmarkError(f"snapshot file exceeds {_MAX_FILE_BYTES} bytes: {relative}")
            total_bytes += member_stat.st_size
            if total_bytes > _MAX_INVENTORY_BYTES:
                raise PublicBenchmarkError(f"snapshot exceeds the {_MAX_INVENTORY_BYTES}-byte aggregate safety limit")
            if len(inventory) >= _MAX_INVENTORY_FILES:
                raise PublicBenchmarkError(f"snapshot exceeds the {_MAX_INVENTORY_FILES}-file safety limit")
            digest = hashlib.sha256()
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(member, flags)
            with os.fdopen(descriptor, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            inventory.append({"path": relative, "sha256": digest.hexdigest(), "size_bytes": member_stat.st_size})

    inventory.sort(key=lambda item: item["path"])
    if not inventory:
        raise PublicBenchmarkError("snapshot contains no materialized sample files")
    return inventory


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicBenchmarkError(f"snapshot JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise PublicBenchmarkError(f"snapshot JSON contains non-finite number {value}")


def _read_snapshot_manifest(path: Path) -> Mapping[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicBenchmarkError(f"cannot open snapshot manifest: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise PublicBenchmarkError("snapshot manifest must be a regular file")
        if file_stat.st_size > _MAX_MANIFEST_BYTES:
            raise PublicBenchmarkError(f"snapshot manifest exceeds the {_MAX_MANIFEST_BYTES}-byte safety limit")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            try:
                value = json.load(
                    handle,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite_number,
                )
            except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
                raise PublicBenchmarkError(f"invalid snapshot manifest: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, Mapping):
        raise PublicBenchmarkError("snapshot manifest root must be an object")
    return value


def _validate_declared_artifacts(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence) or not raw:
        raise PublicBenchmarkError("snapshot artifacts must be a non-empty array")
    artifacts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        artifact = _require_exact_fields(value, _ARTIFACT_FIELDS, f"artifacts[{index}]")
        path = _relative_path(artifact["path"], f"artifacts[{index}].path").as_posix()
        if path == SNAPSHOT_MANIFEST or path in seen:
            raise PublicBenchmarkError(f"duplicate or reserved artifact path: {path}")
        seen.add(path)
        digest = artifact["sha256"]
        size = artifact["size_bytes"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise PublicBenchmarkError(f"artifacts[{index}].sha256 must be lowercase SHA-256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PublicBenchmarkError(f"artifacts[{index}].size_bytes must be a non-negative integer")
        artifacts.append({"path": path, "sha256": digest, "size_bytes": size})
    return sorted(artifacts, key=lambda item: item["path"])


def _validate_quarantine(
    raw: Any,
    *,
    dataset: Mapping[str, Any],
    lock: Mapping[str, Any],
    declared_digest: str,
    declared: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Mapping[str, Any]], str | None]:
    materialization = dataset["integrity"].get("materialization")
    if materialization is None:
        if raw is not None:
            raise PublicBenchmarkError("snapshot declares quarantine records but the dataset lock does not")
        return {}, None
    if raw is None:
        raise PublicBenchmarkError("snapshot is missing the quarantine manifest pinned in the dataset lock")
    quarantine = _require_exact_fields(raw, _QUARANTINE_FIELDS, "quarantine")
    digest = _require_string(quarantine["manifest_sha256"], "quarantine.manifest_sha256")
    records = quarantine["records"]
    try:
        validate_quarantine_manifest(
            str(dataset["id"]),
            records,
            declared_artifact_manifest_sha256=declared_digest,
            manifest_sha256=digest,
            manifest=lock,
        )
    except (DatasetLockError, DatasetSchemaError) as exc:
        raise PublicBenchmarkError(str(exc)) from exc

    declared_by_path = {str(item["path"]): item for item in declared}
    by_path: dict[str, Mapping[str, Any]] = {}
    assert isinstance(records, Sequence) and not isinstance(records, (str, bytes))
    for index, record in enumerate(records):
        assert isinstance(record, Mapping)
        path = str(record["path"])
        declared_artifact = declared_by_path.get(path)
        if declared_artifact is None:
            raise PublicBenchmarkError(f"quarantine record {index} is not present in the declared artifact manifest")
        if record["sha256"] != declared_artifact["sha256"] or record["size_bytes"] != declared_artifact["size_bytes"]:
            raise PublicBenchmarkError(f"quarantine record {index} disagrees with declared artifact metadata")
        by_path[path] = record
    return by_path, digest


def _track_protocols(dataset: Mapping[str, Any]) -> tuple[str, ...]:
    tracks = dataset["gating"]["tracks"]
    protocols = tuple(track["protocol"] for track in tracks)
    if not protocols or len(protocols) != len(set(protocols)):
        raise PublicBenchmarkError("dataset lock must declare unique benchmark protocols")
    return protocols


def _validate_samples(
    raw: Any,
    dataset: Mapping[str, Any],
    root: Path,
    quarantined_by_path: Mapping[str, Mapping[str, Any]],
) -> tuple[FrozenSample, ...]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence) or not raw:
        raise PublicBenchmarkError("snapshot samples must be a non-empty array")

    protocols = _track_protocols(dataset)
    locked_row_counts = dataset.get("expected", {}).get("row_counts", {})
    expected_split_fields = {
        key.removeprefix("splits/")
        for key in locked_row_counts
        if isinstance(key, str) and key.startswith("splits/") and key.removeprefix("splits/")
    }
    if not set(protocols) <= expected_split_fields:
        raise PublicBenchmarkError("dataset lock is missing a row count for a blocking split protocol")
    expected_population = locked_row_counts.get("primary/train")
    if expected_population is not None and len(raw) != expected_population:
        raise PublicBenchmarkError(f"snapshot sample-count drift (expected {expected_population}, received {len(raw)})")
    for protocol in sorted(expected_split_fields):
        expected_split_rows = locked_row_counts.get(f"splits/{protocol}")
        if expected_split_rows is None:
            raise PublicBenchmarkError(f"dataset lock has no row count for split manifest {protocol}")
        if len(raw) != expected_split_rows:
            raise PublicBenchmarkError(
                f"snapshot {protocol} split-manifest count drift (expected {expected_split_rows}, received {len(raw)})"
            )

    samples: list[FrozenSample] = []
    identifiers: set[str] = set()
    paths: set[str] = set()
    for index, value in enumerate(raw):
        sample = _require_sample_fields(value, f"samples[{index}]")
        benchmark_id = _require_string(sample["benchmark_id"], f"samples[{index}].benchmark_id")
        if benchmark_id in identifiers:
            raise PublicBenchmarkError(f"duplicate benchmark_id: {benchmark_id}")
        identifiers.add(benchmark_id)

        label = sample["label"]
        if not isinstance(label, str) or label not in _LABELS:
            raise PublicBenchmarkError(f"samples[{index}].label must be one of {sorted(_LABELS)}")
        source_id = _require_string(sample["source_id"], f"samples[{index}].source_id")
        family = _require_string(sample["structural_family_id"], f"samples[{index}].structural_family_id")
        if "category_id" in sample and "category_ids" in sample:
            raise PublicBenchmarkError(f"samples[{index}] must not provide both category_id and category_ids")
        raw_categories = sample.get("category_ids")
        if raw_categories is not None:
            if (
                isinstance(raw_categories, (str, bytes))
                or not isinstance(raw_categories, Sequence)
                or not raw_categories
            ):
                raise PublicBenchmarkError(f"samples[{index}].category_ids must be a non-empty array")
            categories = tuple(
                _require_string(value, f"samples[{index}].category_ids[{category_index}]")
                for category_index, value in enumerate(raw_categories)
            )
            if tuple(sorted(set(categories))) != categories:
                raise PublicBenchmarkError(f"samples[{index}].category_ids must be sorted and duplicate-free")
        else:
            categories = (
                _require_string(
                    sample.get("category_id", "unclassified"),
                    f"samples[{index}].category_id",
                ),
            )
        relative = _relative_path(sample["path"], f"samples[{index}].path")
        if relative.as_posix() in paths:
            raise PublicBenchmarkError(f"multiple samples share path: {relative}")
        paths.add(relative.as_posix())

        splits = sample["splits"]
        if not isinstance(splits, Mapping) or set(splits) != expected_split_fields:
            raise PublicBenchmarkError(f"samples[{index}].splits must contain exactly {sorted(expected_split_fields)}")
        if any(not isinstance(partition, str) or partition not in _PARTITIONS for partition in splits.values()):
            raise PublicBenchmarkError(f"samples[{index}].splits contains an unsupported partition")

        materialized = root.joinpath(*relative.parts)
        skill_file = materialized / "SKILL.md"
        artifact_path = f"{relative.as_posix()}/SKILL.md"
        quarantine_record = quarantined_by_path.get(artifact_path)
        if quarantine_record is None:
            if materialized.is_symlink() or not materialized.is_dir():
                raise PublicBenchmarkError(f"sample path is not a materialized directory: {relative}")
            if skill_file.is_symlink() or not skill_file.is_file():
                raise PublicBenchmarkError(f"sample is missing a regular SKILL.md: {relative}")
        else:
            if skill_file.exists() or skill_file.is_symlink():
                raise PublicBenchmarkError(f"quarantined sample unexpectedly has a SKILL.md: {relative}")
            expected_record = {
                "benchmark_id": benchmark_id,
                "label": label,
                "source_id": source_id,
                "structural_family_id": family,
                "splits": dict(splits),
            }
            if any(quarantine_record[field] != value for field, value in expected_record.items()):
                raise PublicBenchmarkError(f"quarantine metadata disagrees with sample {benchmark_id}")
            for track in dataset["gating"]["tracks"]:
                if splits[track["protocol"]] == track["partition"]:
                    raise PublicBenchmarkError(
                        f"quarantined sample {benchmark_id} belongs to blocking track {track['name']}"
                    )
        samples.append(
            FrozenSample(
                benchmark_id=benchmark_id,
                label=label,
                source_id=source_id,
                structural_family_id=family,
                category_ids=categories,
                relative_path=relative,
                splits=dict(splits),
            )
        )
    matched_quarantine_paths = {f"{sample.relative_path.as_posix()}/SKILL.md" for sample in samples}
    unmatched = sorted(set(quarantined_by_path) - matched_quarantine_paths)
    if unmatched:
        raise PublicBenchmarkError(f"quarantine records do not map to snapshot samples: {unmatched[:10]}")
    return tuple(samples)


def load_frozen_snapshot(
    snapshot_dir: Path,
    *,
    dataset_id: str | None = None,
    dataset_lock: Path | None = None,
) -> FrozenSnapshot:
    """Load and fully validate one local, pre-materialized snapshot."""

    root = Path(snapshot_dir)
    if root.is_symlink() or not root.is_dir():
        raise PublicBenchmarkError("snapshot directory must be an existing non-symlink directory")
    root = root.resolve(strict=True)
    manifest_path = root / SNAPSHOT_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise PublicBenchmarkError(f"snapshot is missing regular {SNAPSHOT_MANIFEST}")
    payload = _read_snapshot_manifest(manifest_path)
    manifest = _require_snapshot_fields(payload)
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise PublicBenchmarkError(f"unsupported snapshot schema_version: {manifest['schema_version']!r}")

    manifest_dataset_id = _require_string(manifest["dataset_id"], "dataset_id")
    if dataset_id is not None and manifest_dataset_id != dataset_id:
        raise PublicBenchmarkError(f"snapshot dataset mismatch (expected {dataset_id}, received {manifest_dataset_id})")
    lock = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
    dataset = get_locked_dataset(manifest_dataset_id, lock)
    if manifest["revision"] != dataset["revision"]:
        raise PublicBenchmarkError(
            f"dataset revision drift (expected {dataset['revision']}, received {manifest['revision']})"
        )
    if manifest_dataset_id != MALICIOUS_SKILL_BENCH:
        raise PublicBenchmarkError(f"no approved classification adapter for {manifest_dataset_id}")

    declared = _validate_declared_artifacts(manifest["artifacts"])
    digest = _require_string(manifest["artifact_manifest_sha256"], "artifact_manifest_sha256")
    try:
        validate_artifact_manifest(
            manifest_dataset_id,
            declared,
            manifest_sha256=digest,
            manifest=lock,
        )
    except (DatasetLockError, DatasetSchemaError) as exc:
        raise PublicBenchmarkError(str(exc)) from exc

    quarantined_by_path, quarantine_digest = _validate_quarantine(
        manifest.get("quarantine"),
        dataset=dataset,
        lock=lock,
        declared_digest=digest,
        declared=declared,
    )
    expected_usable = [item for item in declared if item["path"] not in quarantined_by_path]
    actual = _regular_file_inventory(root)
    if expected_usable != actual:
        declared_by_path = {item["path"]: item for item in expected_usable}
        actual_by_path = {item["path"]: item for item in actual}
        missing = sorted(set(declared_by_path) - set(actual_by_path))
        unexpected = sorted(set(actual_by_path) - set(declared_by_path))
        changed = sorted(
            path
            for path in set(declared_by_path) & set(actual_by_path)
            if declared_by_path[path] != actual_by_path[path]
        )
        raise PublicBenchmarkError(
            "snapshot artifact inventory mismatch "
            f"(missing={missing[:10]}, unexpected={unexpected[:10]}, changed={changed[:10]})"
        )
    usable_digest = artifact_manifest_sha256(manifest_dataset_id, actual, manifest=lock)
    materialization = dataset["integrity"].get("materialization")
    if materialization is not None:
        if len(declared) != materialization["declared_artifact_count"]:
            raise PublicBenchmarkError(
                "snapshot declared artifact-count drift "
                f"(expected {materialization['declared_artifact_count']}, received {len(declared)})"
            )
        if len(actual) != materialization["usable_artifact_count"]:
            raise PublicBenchmarkError(
                "snapshot usable artifact-count drift "
                f"(expected {materialization['usable_artifact_count']}, received {len(actual)})"
            )
        if usable_digest != materialization["usable_artifact_manifest_sha256"]:
            raise PublicBenchmarkError("snapshot usable artifact manifest does not match the dataset lock")

    samples = _validate_samples(manifest["samples"], dataset, root, quarantined_by_path)
    artifact_paths = {item["path"] for item in declared}
    expected_artifact_paths = {f"{sample.relative_path.as_posix()}/SKILL.md" for sample in samples}
    if artifact_paths != expected_artifact_paths:
        missing = sorted(expected_artifact_paths - artifact_paths)
        unexpected = sorted(artifact_paths - expected_artifact_paths)
        raise PublicBenchmarkError(
            "classification snapshot must contain exactly one inert SKILL.md per sample; "
            "unexpected package files or executable ingestion hooks are forbidden "
            f"(missing={missing[:10]}, unexpected={unexpected[:10]})"
        )

    return FrozenSnapshot(
        root=root,
        dataset=dataset,
        artifact_manifest_sha256=digest,
        usable_artifact_manifest_sha256=usable_digest,
        quarantine_manifest_sha256=quarantine_digest,
        quarantined_sample_ids=tuple(sorted(str(record["benchmark_id"]) for record in quarantined_by_path.values())),
        samples=samples,
    )


def _core_registry() -> RuleRegistry:
    loader = PackLoader()
    registry = RuleRegistry()
    registry.register_pack(loader.load_bundled_pack(DATA_DIR / "packs" / "core"))
    return registry


def _hash_tree(root: Path, *, namespace: bytes) -> str:
    """Hash a trusted installed source/data tree with path framing."""

    digest = hashlib.sha256(namespace + b"\0")
    members = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    for path in sorted(members, key=lambda member: member.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _trusted_pack_tree_sha256(root: Path) -> str:
    """Hash one validated trusted pack without following filesystem links."""

    digest = hashlib.sha256(b"skill-scanner-trusted-rule-pack-tree-v1\0")
    file_count = 0
    total_bytes = 0
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        for name in [*directory_names, *file_names]:
            member = current / name
            member_stat = member.lstat()
            if stat.S_ISLNK(member_stat.st_mode):
                raise PublicBenchmarkError(f"trusted rule pack contains a symbolic link: {member.relative_to(root)}")
            if name in directory_names and not stat.S_ISDIR(member_stat.st_mode):
                raise PublicBenchmarkError(f"trusted rule pack contains a non-directory tree entry: {member}")
            if name in file_names and not stat.S_ISREG(member_stat.st_mode):
                raise PublicBenchmarkError(f"trusted rule pack contains a non-regular file: {member}")

        for name in sorted(file_names):
            member = current / name
            member_stat = member.lstat()
            if member_stat.st_size > _MAX_TRUSTED_PACK_FILE_BYTES:
                raise PublicBenchmarkError(
                    f"trusted rule-pack file exceeds {_MAX_TRUSTED_PACK_FILE_BYTES} bytes: {member.relative_to(root)}"
                )
            file_count += 1
            total_bytes += member_stat.st_size
            if file_count > _MAX_TRUSTED_PACK_FILES:
                raise PublicBenchmarkError(f"trusted rule pack exceeds the {_MAX_TRUSTED_PACK_FILES}-file safety limit")
            if total_bytes > _MAX_TRUSTED_PACK_BYTES:
                raise PublicBenchmarkError(
                    f"trusted rule pack exceeds the {_MAX_TRUSTED_PACK_BYTES}-byte aggregate safety limit"
                )

            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(member, flags)
            try:
                opened_stat = os.fstat(descriptor)
                if not stat.S_ISREG(opened_stat.st_mode):
                    raise PublicBenchmarkError(f"trusted rule-pack member is not a regular file: {member}")
                if (opened_stat.st_dev, opened_stat.st_ino, opened_stat.st_size) != (
                    member_stat.st_dev,
                    member_stat.st_ino,
                    member_stat.st_size,
                ):
                    raise PublicBenchmarkError(f"trusted rule-pack member changed while opening: {member}")
                file_digest = hashlib.sha256()
                bytes_read = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    file_digest.update(chunk)
                if bytes_read != member_stat.st_size:
                    raise PublicBenchmarkError(f"trusted rule-pack member changed while hashing: {member}")
            finally:
                os.close(descriptor)

            relative = member.relative_to(root).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(member_stat.st_size.to_bytes(8, "big"))
            digest.update(file_digest.digest())

    if file_count == 0:
        raise PublicBenchmarkError("trusted rule pack contains no files")
    return digest.hexdigest()


def _trusted_pack_set(
    raw_paths: Sequence[Path | str],
    *,
    snapshot_root: Path,
) -> TrustedPackSet:
    """Validate local packs and return a stable content identity.

    Local absolute paths are intentionally excluded from the report. The pack
    name/version plus a path-independent content digest are sufficient to bind
    the locally extended scanner generation without leaking host layout.
    """

    if isinstance(raw_paths, (str, bytes)) or not raw_paths:
        raise PublicBenchmarkError("locally extended evaluation requires at least one trusted rule pack")
    resolved_paths: list[Path] = []
    seen_paths: set[Path] = set()
    for index, raw_path in enumerate(raw_paths):
        try:
            requested = Path(raw_path).expanduser()
        except TypeError as exc:
            raise PublicBenchmarkError(f"trusted_rule_packs[{index}] must be a filesystem path") from exc
        if requested.is_symlink():
            raise PublicBenchmarkError(f"trusted_rule_packs[{index}] must not be a symbolic link")
        try:
            resolved = requested.resolve(strict=True)
        except OSError as exc:
            raise PublicBenchmarkError(f"trusted_rule_packs[{index}] does not exist: {requested}") from exc
        if not resolved.is_dir():
            raise PublicBenchmarkError(f"trusted_rule_packs[{index}] must be a directory")
        if resolved in seen_paths:
            raise PublicBenchmarkError(f"duplicate trusted rule-pack path: {requested}")
        if (
            resolved == snapshot_root
            or resolved.is_relative_to(snapshot_root)
            or snapshot_root.is_relative_to(resolved)
        ):
            raise PublicBenchmarkError("trusted rule packs and the immutable dataset snapshot must be disjoint")
        seen_paths.add(resolved)
        resolved_paths.append(resolved)

    loader = PackLoader()
    try:
        local_packs = [loader.load_trusted_pack(path) for path in resolved_paths]
        # This second validation is intentional: it catches duplicate IDs and
        # names across local packs and collisions with the bundled generation.
        loader.build_registry(trusted_dirs=list(resolved_paths))
    except (FileNotFoundError, OSError, TypeError, ValueError) as exc:
        raise PublicBenchmarkError(f"invalid trusted rule-pack set: {exc}") from exc

    records: list[tuple[dict[str, Any], Path]] = []
    for pack, path in zip(local_packs, resolved_paths, strict=True):
        tree_sha256 = _trusted_pack_tree_sha256(path)
        record = {
            "name": pack.name,
            "version": pack.version,
            "sha256": tree_sha256,
            "rule_count": len(pack.rules),
            "cel_rule_count": sum(definition.cel is not None for definition in pack.rules.values()),
        }
        records.append((record, path))
    records.sort(key=lambda item: (item[0]["name"], item[0]["sha256"]))
    report_records = [record for record, _path in records]
    encoded = json.dumps(report_records, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    set_sha256 = hashlib.sha256(b"skill-scanner-trusted-rule-pack-set-v1\0" + encoded).hexdigest()
    return TrustedPackSet(
        paths=tuple(path for _record, path in records),
        identity={
            "format": "trusted-rule-pack-set-v1",
            "sha256": set_sha256,
            "packs": report_records,
        },
    )


def _policy_identity_sha256() -> str:
    policy = ScanPolicy.default()
    # CEL mode is represented independently in evidence_identity.  Normalize
    # it here so OFF and SHADOW/ENFORCE runs prove every other policy knob is
    # identical.
    policy.cel.mode = CelMode.OFF
    payload = json.dumps(policy._to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _combined_expression_hash(tracks: Sequence[Mapping[str, Any]]) -> str:
    generations = sorted({generation for track in tracks for generation in track["cel"]["expression_set_hashes"]})
    payload = json.dumps(generations, separators=(",", ":"))
    return hashlib.sha256(b"skill-scanner-benchmark-expression-generations-v1\0" + payload.encode("utf-8")).hexdigest()


def _producer_components(detector_profiles: Sequence[str] = ("core_only",)) -> dict[str, str]:
    profiles = frozenset(detector_profiles)
    if not profiles or not profiles <= {"core_only", "full_packs", "locally_extended"}:
        raise PublicBenchmarkError("producer identity received an unsupported detector profile set")
    package_root = Path(__file__).resolve().parents[2] / "skill_scanner"
    rules_root = DATA_DIR / "packs" / "core" if profiles == {"core_only"} else DATA_DIR / "packs"
    return {
        "scanner_version": scanner_version,
        "source_revision": os.environ.get("SKILL_SCANNER_SOURCE_REVISION")
        or os.environ.get("GITHUB_SHA")
        or "unrecorded",
        "build_sha256": _hash_tree(package_root, namespace=b"skill-scanner-installed-build-v1"),
        "policy_sha256": _policy_identity_sha256(),
        "rules_sha256": _hash_tree(rules_root, namespace=b"skill-scanner-bundled-rules-v1"),
    }


def _evidence_identity(
    snapshot: FrozenSnapshot,
    tracks: Sequence[Mapping[str, Any]],
    mode: CelMode,
    producer: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    identity = {
        "dataset_or_corpus_id": str(snapshot.dataset["id"]),
        "snapshot_sha256": snapshot.artifact_manifest_sha256,
        "build_sha256": producer["build_sha256"],
        "policy_sha256": producer["policy_sha256"],
        "rules_sha256": producer["rules_sha256"],
        "expression_set_hash": _combined_expression_hash(tracks),
        "cel_mode": mode.value,
    }
    return identity, dict(producer)


def _default_scanner_factory(
    detector_profile: str,
    cel_mode: CelMode,
    *,
    trusted_rule_packs: Sequence[Path] = (),
) -> _Scanner:
    policy = ScanPolicy.default()
    policy.cel.mode = cel_mode
    if detector_profile == "core_only":
        if trusted_rule_packs:
            raise PublicBenchmarkError("core_only must not load trusted local rule packs")
        extra_rule_dirs = None
        registry = _core_registry()
    elif detector_profile == "full_packs":
        if trusted_rule_packs:
            raise PublicBenchmarkError("full_packs must not load trusted local rule packs")
        pack_names = list_available_packs()
        extra_rule_dirs = resolve_rule_packs(pack_names)
        registry = PackLoader().build_registry()
    elif detector_profile == "locally_extended":
        if not trusted_rule_packs:
            raise PublicBenchmarkError("locally_extended requires trusted local rule packs")
        pack_names = list_available_packs()
        extra_rule_dirs = resolve_rule_packs(pack_names)
        registry = PackLoader().build_registry(trusted_dirs=list(trusted_rule_packs))
    else:
        raise PublicBenchmarkError(f"unsupported detector profile: {detector_profile}")
    analyzers = build_core_analyzers(
        policy,
        extra_rules_dirs=extra_rule_dirs,
        trusted_pack_dirs=list(trusted_rule_packs) or None,
    )
    return SkillScanner(analyzers=analyzers, policy=policy, rule_registry=registry)


def _severity_name(finding: Any) -> str:
    severity = finding.get("severity") if isinstance(finding, Mapping) else getattr(finding, "severity", None)
    value = getattr(severity, "value", severity)
    return str(value).upper()


def _safe_divide(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _binary_metrics(tp: int, tn: int, fp: int, fn: int) -> dict[str, float]:
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    benign_precision = _safe_divide(tn, tn + fn)
    benign_recall = _safe_divide(tn, tn + fp)
    benign_f1 = _safe_divide(2 * benign_precision * benign_recall, benign_precision + benign_recall)
    defined_class_f1 = []
    if tp + fn:
        defined_class_f1.append(f1)
    if tn + fp:
        defined_class_f1.append(benign_f1)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "macro_f1": _safe_divide(sum(defined_class_f1), len(defined_class_f1)),
        "macro_f1_defined_classes": len(defined_class_f1),
        "accuracy": _safe_divide(tp + tn, tp + tn + fp + fn),
    }


def _p95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def _wilson_interval(successes: int, total: int) -> list[float]:
    """Return a two-sided 95% Wilson score interval for one proportion."""

    if total <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + (z * z / total)
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((proportion * (1 - proportion) / total) + (z * z / (4 * total * total))) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _empty_counts() -> dict[str, Any]:
    return {
        "samples": 0,
        "malicious": 0,
        "benign": 0,
        "tp": 0,
        "tn": 0,
        "fp": 0,
        "fn": 0,
        "signal_tp": 0,
        "signal_fn": 0,
        "actionable_benign_false_positives": 0,
        "critical_high_false_negative_ids": [],
        "scan_latencies_ms": [],
        "total_scan_ms": 0.0,
        "total_cel_ms": 0.0,
        "cel_fallbacks": 0,
        "loader_fallbacks": 0,
        "recovered_scan_errors": 0,
        "loader_fallback_sample_ids": [],
        "loader_rejections": 0,
        "loader_rejection_sample_ids": [],
        "scan_errors": 0,
        "cel_evaluated": 0,
        "cel_retained": 0,
        "cel_would_suppress": 0,
        "cel_suppressed": 0,
        "cel_projection_incomplete": 0,
        "total_cel_projection_ms": 0.0,
        "total_cel_evaluation_ms": 0.0,
        "cel_modes": set(),
        "cel_runtimes": set(),
        "cel_runtime_versions": set(),
        "cel_fact_schemas": set(),
        "cel_expression_set_hashes": set(),
        "cel_error_counts": {},
        "cel_rule_decisions": {},
        "cel_would_suppress_sample_ids": [],
        "cel_suppressed_sample_ids": [],
        "cel_fallback_sample_ids": [],
        "cel_projection_incomplete_sample_ids": [],
        "sample_outcomes": {},
    }


def _finding_metadata(finding: Any) -> Mapping[str, Any]:
    metadata = finding.get("metadata", {}) if isinstance(finding, Mapping) else getattr(finding, "metadata", {})
    return metadata if isinstance(metadata, Mapping) else {}


def _finding_rule_id(finding: Any) -> str:
    value = finding.get("rule_id") if isinstance(finding, Mapping) else getattr(finding, "rule_id", None)
    return value if isinstance(value, str) and value else "unidentified"


def _finding_cel_lineage(
    finding: Any,
    benchmark_id: str,
) -> list[dict[str, Any]]:
    """Read one bounded CEL decision lineage from a normalized finding."""

    metadata = _finding_metadata(finding)
    raw_lineage = metadata.get("cel_decisions")
    singular = metadata.get("cel")
    if raw_lineage is None:
        if singular is None:
            return []
        if not isinstance(singular, Mapping):
            raise PublicBenchmarkError(f"scanner returned invalid finding CEL annotation for {benchmark_id}")
        raw_lineage = [
            {
                "rule_id": _finding_rule_id(finding),
                "decision": singular.get("decision"),
                "reason": singular.get("reason", "unspecified"),
                "fact_schema": singular.get("fact_schema", "unspecified"),
                "expression_hash": singular.get("expression_hash", "unspecified"),
                "pack": singular.get("pack", "unspecified") or "unspecified",
                "rollout": singular.get("rollout", "unspecified"),
                "count": 1,
            }
        ]
        require_exact_fields = False
    else:
        require_exact_fields = True
    if isinstance(raw_lineage, (str, bytes)) or not isinstance(raw_lineage, Sequence):
        raise PublicBenchmarkError(f"scanner returned invalid finding CEL lineage for {benchmark_id}")
    if not raw_lineage:
        raise PublicBenchmarkError(f"scanner returned empty finding CEL lineage for {benchmark_id}")
    if len(raw_lineage) > 4_096:
        raise PublicBenchmarkError(f"scanner returned oversized finding CEL lineage for {benchmark_id}")

    fields = {
        "rule_id",
        "decision",
        "reason",
        "fact_schema",
        "expression_hash",
        "pack",
        "rollout",
        "count",
    }
    decisions: list[dict[str, Any]] = []
    keys: list[tuple[str, str, str, str, str, str, str]] = []
    for index, raw in enumerate(raw_lineage):
        if not isinstance(raw, Mapping):
            raise PublicBenchmarkError(f"scanner returned invalid finding CEL lineage[{index}] for {benchmark_id}")
        if require_exact_fields and set(raw) != fields:
            raise PublicBenchmarkError(
                f"scanner returned invalid finding CEL lineage[{index}] fields for {benchmark_id}"
            )
        rule_id = raw.get("rule_id")
        decision = raw.get("decision")
        reason = raw.get("reason", "unspecified")
        fact_schema = raw.get("fact_schema", "unspecified")
        expression_hash = raw.get("expression_hash", "unspecified")
        pack = raw.get("pack", "unspecified") or "unspecified"
        rollout = raw.get("rollout", "unspecified")
        count = raw.get("count", 1)
        if decision not in {"keep", "would_suppress", "fallback"}:
            raise PublicBenchmarkError(f"scanner returned invalid finding CEL decision for {benchmark_id}")
        string_values = (rule_id, decision, reason, fact_schema, expression_hash, pack, rollout)
        if any(not isinstance(value, str) or not value for value in string_values):
            raise PublicBenchmarkError(f"scanner returned invalid finding CEL identity for {benchmark_id}")
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise PublicBenchmarkError(f"scanner returned invalid finding CEL lineage count for {benchmark_id}")
        key = cast(tuple[str, str, str, str, str, str, str], string_values)
        keys.append(key)
        decisions.append(
            {
                "rule_id": rule_id,
                "decision": decision,
                "reason": reason,
                "fact_schema": fact_schema,
                "expression_hash": expression_hash,
                "pack": pack,
                "rollout": rollout,
                "count": count,
            }
        )
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise PublicBenchmarkError(f"scanner returned unsorted or duplicate finding CEL lineage for {benchmark_id}")
    if singular is not None and require_exact_fields:
        if not isinstance(singular, Mapping):
            raise PublicBenchmarkError(f"scanner returned invalid finding CEL annotation for {benchmark_id}")
        singular_key = (
            _finding_rule_id(finding),
            singular.get("decision"),
            singular.get("reason", "unspecified"),
            singular.get("fact_schema", "unspecified"),
            singular.get("expression_hash", "unspecified"),
            singular.get("pack", "unspecified") or "unspecified",
            singular.get("rollout", "unspecified"),
        )
        if singular_key not in keys:
            raise PublicBenchmarkError(f"scanner finding CEL winner is absent from lineage for {benchmark_id}")
    return decisions


def _validated_cel_telemetry(result: Any, sample: FrozenSample, duration_ms: float) -> dict[str, Any]:
    metadata = getattr(result, "scan_metadata", None) or {}
    cel = metadata.get("cel", {}) if isinstance(metadata, Mapping) else {}
    if not isinstance(cel, Mapping):
        raise PublicBenchmarkError(f"scanner returned invalid CEL telemetry for {sample.benchmark_id}")

    integer_fields = (
        "evaluated",
        "retained",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
    )
    integers: dict[str, int] = {}
    for field in integer_fields:
        value = cel.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PublicBenchmarkError(f"scanner returned invalid CEL {field} count for {sample.benchmark_id}")
        integers[field] = value
    if integers["projection_incomplete"] > integers["fallbacks"]:
        raise PublicBenchmarkError(f"scanner CEL projection_incomplete exceeds fallbacks for {sample.benchmark_id}")

    timing_fields = ("elapsed_ms", "projection_ms", "evaluation_ms")
    timings: dict[str, float] = {}
    for field in timing_fields:
        value = cel.get(field, 0.0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise PublicBenchmarkError(f"scanner returned invalid CEL {field} for {sample.benchmark_id}")
        timings[field] = float(value)
    if timings["elapsed_ms"] > duration_ms + 1e-9:
        raise PublicBenchmarkError(f"scanner CEL duration exceeds total scan duration for {sample.benchmark_id}")
    if timings["projection_ms"] + timings["evaluation_ms"] > timings["elapsed_ms"] + 0.002:
        raise PublicBenchmarkError(f"scanner CEL phase durations exceed CEL elapsed time for {sample.benchmark_id}")

    identities: dict[str, str] = {}
    for field, default in (
        ("mode", "unspecified"),
        ("runtime", "unspecified"),
        ("fact_schema", "unspecified"),
    ):
        value = cel.get(field, default)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_METADATA_STRING_BYTES:
            raise PublicBenchmarkError(f"scanner returned invalid CEL {field} for {sample.benchmark_id}")
        identities[field] = value
    runtime_version = cel.get("runtime_version", "unspecified")
    raw_expression_hash = cel.get("expression_set_hash", "")
    mode = identities["mode"]
    runtime = identities["runtime"]
    runtime_prefix = f"{CEL_GO_VERSION};helper="

    def require_cel_go_identity() -> None:
        if runtime != "cel-go":
            raise PublicBenchmarkError(
                f"scanner returned a non-authoritative active CEL runtime for {sample.benchmark_id}"
            )
        if (
            not isinstance(runtime_version, str)
            or not runtime_version.startswith(runtime_prefix)
            or not runtime_version.removeprefix(runtime_prefix)
            or len(runtime_version.removeprefix(runtime_prefix).encode("utf-8")) > 128
            or "\x00" in runtime_version
        ):
            raise PublicBenchmarkError(f"scanner returned invalid cel-go runtime_version for {sample.benchmark_id}")

    if mode == CelMode.OFF.value:
        for field in (
            "evaluated",
            "would_suppress",
            "suppressed",
            "fallbacks",
            "projection_incomplete",
        ):
            if integers[field] != 0:
                raise PublicBenchmarkError(f"scanner returned nonzero CEL {field} while off for {sample.benchmark_id}")
        if runtime == "unavailable":
            if runtime_version not in {"", "not_loaded"}:
                raise PublicBenchmarkError(
                    f"scanner returned inconsistent unloaded CEL metadata while off for {sample.benchmark_id}"
                )
            runtime_version = "not_loaded"
            if raw_expression_hash == "":
                raw_expression_hash = _EMPTY_EXPRESSION_SET_HASH
        else:
            require_cel_go_identity()
    elif mode in {CelMode.SHADOW.value, CelMode.ENFORCE.value}:
        require_cel_go_identity()
        expression_hash = raw_expression_hash
        if len(expression_hash) != 64 or any(character not in "0123456789abcdef" for character in expression_hash):
            raise PublicBenchmarkError(
                f"scanner returned invalid active CEL expression generation for {sample.benchmark_id}"
            )
    else:
        raise PublicBenchmarkError(f"scanner returned unsupported CEL mode for {sample.benchmark_id}: {mode}")
    if (
        not isinstance(raw_expression_hash, str)
        or len(raw_expression_hash) != 64
        or any(character not in "0123456789abcdef" for character in raw_expression_hash)
    ):
        raise PublicBenchmarkError(f"scanner returned invalid CEL expression_set_hash for {sample.benchmark_id}")
    identities["expression_set_hash"] = raw_expression_hash
    if (
        not isinstance(runtime_version, str)
        or not runtime_version
        or len(runtime_version.encode("utf-8")) > _MAX_METADATA_STRING_BYTES
    ):
        raise PublicBenchmarkError(f"scanner returned invalid CEL runtime_version for {sample.benchmark_id}")
    identities["runtime_version"] = runtime_version

    raw_errors = cel.get("errors", [])
    if isinstance(raw_errors, (str, bytes)) or not isinstance(raw_errors, Sequence):
        raise PublicBenchmarkError(f"scanner returned invalid CEL errors for {sample.benchmark_id}")
    errors: list[tuple[str, str]] = []
    for index, raw_error in enumerate(raw_errors):
        if not isinstance(raw_error, Mapping):
            raise PublicBenchmarkError(f"scanner returned invalid CEL errors[{index}] for {sample.benchmark_id}")
        rule_id = raw_error.get("rule_id")
        code = raw_error.get("code")
        if not isinstance(rule_id, str) or not rule_id or not isinstance(code, str) or not code:
            raise PublicBenchmarkError(f"scanner returned invalid CEL errors[{index}] for {sample.benchmark_id}")
        errors.append((rule_id, code))

    rule_decisions: list[dict[str, Any]] = []
    for finding in list(getattr(result, "findings", []) or []):
        rule_decisions.extend(_finding_cel_lineage(finding, sample.benchmark_id))

    authoritative_per_rule: dict[str, dict[str, Any]] | None = None
    if mode in {CelMode.SHADOW.value, CelMode.ENFORCE.value} and "per_rule" not in cel:
        raise PublicBenchmarkError(f"scanner omitted authoritative CEL per_rule telemetry for {sample.benchmark_id}")
    if "per_rule" in cel:
        raw_per_rule = cel["per_rule"]
        if not isinstance(raw_per_rule, Mapping):
            raise PublicBenchmarkError(f"scanner returned invalid CEL per_rule telemetry for {sample.benchmark_id}")
        authoritative_per_rule = {}
        expected_fields = {
            "keep",
            "would_suppress",
            "fallback",
            "suppressed",
            "expression_hash",
            "pack",
            "rollout",
        }
        for rule_id, raw_rule in raw_per_rule.items():
            if not isinstance(rule_id, str) or not rule_id or not isinstance(raw_rule, Mapping):
                raise PublicBenchmarkError(f"scanner returned invalid CEL per_rule entry for {sample.benchmark_id}")
            if set(raw_rule) != expected_fields:
                raise PublicBenchmarkError(
                    f"scanner returned invalid CEL per_rule fields for {sample.benchmark_id}:{rule_id}"
                )
            decision_counts: dict[str, int] = {}
            for decision in ("keep", "would_suppress", "fallback", "suppressed"):
                value = raw_rule[decision]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise PublicBenchmarkError(
                        f"scanner returned invalid CEL per_rule {decision} for {sample.benchmark_id}:{rule_id}"
                    )
                decision_counts[decision] = value
            expression_hash = raw_rule["expression_hash"]
            pack = raw_rule["pack"]
            rollout = raw_rule["rollout"]
            if (
                not isinstance(expression_hash, str)
                or len(expression_hash) != 64
                or any(character not in "0123456789abcdef" for character in expression_hash)
                or not isinstance(pack, str)
                or not pack
                or rollout not in {"shadow", "enforce"}
            ):
                raise PublicBenchmarkError(
                    f"scanner returned invalid CEL per_rule identity for {sample.benchmark_id}:{rule_id}"
                )
            if decision_counts["suppressed"] > decision_counts["would_suppress"]:
                raise PublicBenchmarkError(
                    f"scanner returned contradictory CEL suppression counts for {sample.benchmark_id}:{rule_id}"
                )
            authoritative_per_rule[rule_id] = {
                **decision_counts,
                "expression_hash": expression_hash,
                "pack": pack,
                "rollout": rollout,
            }

        for decision, total_field in (
            ("would_suppress", "would_suppress"),
            ("fallback", "fallbacks"),
            ("suppressed", "suppressed"),
        ):
            total = sum(rule[decision] for rule in authoritative_per_rule.values())
            if total != integers[total_field]:
                raise PublicBenchmarkError(
                    f"scanner CEL {total_field} disagrees with per_rule telemetry for {sample.benchmark_id}"
                )

        resolved_evaluations = sum(rule["keep"] + rule["would_suppress"] for rule in authoritative_per_rule.values())
        if not resolved_evaluations <= integers["evaluated"] <= resolved_evaluations + integers["fallbacks"]:
            raise PublicBenchmarkError(
                f"scanner CEL evaluated count disagrees with per_rule telemetry for {sample.benchmark_id}"
            )
        minimum_retained = sum(
            rule["keep"] + rule["fallback"] + rule["would_suppress"] - rule["suppressed"]
            for rule in authoritative_per_rule.values()
        )
        if integers["retained"] < minimum_retained:
            raise PublicBenchmarkError(
                f"scanner CEL retained count disagrees with per_rule telemetry for {sample.benchmark_id}"
            )

        lineage_counts: dict[tuple[str, str], int] = {}
        for entry in rule_decisions:
            rule_id = entry["rule_id"]
            decision = entry["decision"]
            rule = authoritative_per_rule.get(rule_id)
            if rule is None:
                raise PublicBenchmarkError(
                    f"scanner finding CEL lineage has no per_rule telemetry for {sample.benchmark_id}:{rule_id}"
                )
            if (
                entry["fact_schema"] != identities["fact_schema"]
                or entry["expression_hash"] != rule["expression_hash"]
                or entry["pack"] != rule["pack"]
                or entry["rollout"] != rule["rollout"]
            ):
                raise PublicBenchmarkError(
                    f"scanner finding CEL lineage identity disagrees for {sample.benchmark_id}:{rule_id}"
                )
            key = (rule_id, decision)
            lineage_counts[key] = lineage_counts.get(key, 0) + entry["count"]
        for rule_id, rule in authoritative_per_rule.items():
            expected_retained = {
                "keep": rule["keep"],
                "fallback": rule["fallback"],
                "would_suppress": rule["would_suppress"] - rule["suppressed"],
            }
            for decision, expected_count in expected_retained.items():
                if lineage_counts.get((rule_id, decision), 0) != expected_count:
                    raise PublicBenchmarkError(
                        f"scanner retained CEL lineage count disagrees for {sample.benchmark_id}:{rule_id}:{decision}"
                    )

    raw_suppressed = cel.get("suppressed_candidates", [])
    if isinstance(raw_suppressed, (str, bytes)) or not isinstance(raw_suppressed, Sequence):
        raise PublicBenchmarkError(f"scanner returned invalid suppressed CEL candidates for {sample.benchmark_id}")
    if len(raw_suppressed) > 4_096:
        raise PublicBenchmarkError(f"scanner returned oversized suppressed CEL candidates for {sample.benchmark_id}")
    suppressed_decisions: list[dict[str, Any]] = []
    suppressed_keys: list[tuple[str, str, str, str, str, str, str]] = []
    suppressed_by_rule: dict[str, int] = {}
    suppressed_fields = {
        "rule_id",
        "category",
        "severity",
        "analyzer",
        "expression_hash",
        "pack",
        "rollout",
        "count",
    }
    for index, raw in enumerate(raw_suppressed):
        if not isinstance(raw, Mapping) or set(raw) != suppressed_fields:
            raise PublicBenchmarkError(
                f"scanner returned invalid suppressed CEL candidate[{index}] fields for {sample.benchmark_id}"
            )
        rule_id = raw.get("rule_id")
        category = raw.get("category")
        severity = raw.get("severity")
        analyzer = raw.get("analyzer")
        expression_hash = raw.get("expression_hash")
        pack = raw.get("pack")
        rollout = raw.get("rollout")
        count = raw.get("count")
        string_values = (rule_id, category, severity, analyzer, expression_hash, pack, rollout)
        if (
            any(
                not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_METADATA_STRING_BYTES
                for value in string_values
            )
            or severity not in _ALL_SEVERITIES
            or not isinstance(expression_hash, str)
            or len(expression_hash) != 64
            or any(character not in "0123456789abcdef" for character in expression_hash)
            or rollout not in {"shadow", "enforce"}
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count <= 0
        ):
            raise PublicBenchmarkError(
                f"scanner returned invalid suppressed CEL candidate[{index}] identity for {sample.benchmark_id}"
            )
        if authoritative_per_rule is None or rule_id not in authoritative_per_rule:
            raise PublicBenchmarkError(
                f"scanner suppressed CEL candidate has no per_rule identity for {sample.benchmark_id}:{rule_id}"
            )
        rule_identity = authoritative_per_rule[rule_id]
        if (
            expression_hash != rule_identity["expression_hash"]
            or pack != rule_identity["pack"]
            or rollout != rule_identity["rollout"]
        ):
            raise PublicBenchmarkError(
                f"scanner suppressed CEL candidate identity disagrees for {sample.benchmark_id}:{rule_id}"
            )
        suppressed_key = cast(tuple[str, str, str, str, str, str, str], string_values)
        suppressed_keys.append(suppressed_key)
        suppressed_by_rule[rule_id] = suppressed_by_rule.get(rule_id, 0) + count
        suppressed_decisions.append(
            {
                "rule_id": rule_id,
                "category": category,
                "severity": severity,
                "analyzer": analyzer,
                "expression_hash": expression_hash,
                "pack": pack,
                "rollout": rollout,
                "count": count,
            }
        )
    if suppressed_keys != sorted(suppressed_keys) or len(suppressed_keys) != len(set(suppressed_keys)):
        raise PublicBenchmarkError(
            f"scanner returned unsorted or duplicate suppressed CEL candidates for {sample.benchmark_id}"
        )
    if sum(suppressed_by_rule.values()) != integers["suppressed"]:
        raise PublicBenchmarkError(f"scanner suppressed CEL candidate count disagrees for {sample.benchmark_id}")
    if authoritative_per_rule is not None and any(
        rule["suppressed"] != suppressed_by_rule.get(rule_id, 0) for rule_id, rule in authoritative_per_rule.items()
    ):
        raise PublicBenchmarkError(f"scanner suppressed CEL per_rule evidence disagrees for {sample.benchmark_id}")

    return {
        **integers,
        **timings,
        **identities,
        "errors": errors,
        "rule_decisions": rule_decisions,
        "suppressed_decisions": suppressed_decisions,
    }


def _record_sample(
    counts: dict[str, Any],
    sample: FrozenSample,
    result: Any,
    *,
    expected_cel_mode: CelMode,
    loader_recovery: LoaderFallbackRecovery | None = None,
    loader_rejection: LoaderClosedRejection | None = None,
) -> None:
    if loader_recovery is not None and loader_rejection is not None:
        raise PublicBenchmarkError("loader recovery and closed rejection are mutually exclusive")
    findings = list(getattr(result, "findings", []) or [])
    severities = {_severity_name(finding) for finding in findings}
    blocked = bool(severities & _BLOCKING_SEVERITIES)
    actionable = bool(severities & _ACTIONABLE_SEVERITIES)
    signal = bool(severities & _SIGNAL_SEVERITIES)

    # Validate every fallible scanner-supplied value before mutating counts.
    # Otherwise a malformed telemetry value could first count a successful
    # classification and then be counted again as a conservative scan error.
    duration_ms = float(getattr(result, "scan_duration_seconds", 0.0) or 0.0) * 1_000
    if not math.isfinite(duration_ms) or duration_ms < 0:
        raise PublicBenchmarkError(f"scanner returned invalid latency for {sample.benchmark_id}")
    cel = _validated_cel_telemetry(result, sample, duration_ms)
    if cel["mode"] != expected_cel_mode.value:
        raise PublicBenchmarkError(
            f"scanner CEL mode {cel['mode']!r} does not match requested mode {expected_cel_mode.value!r} "
            f"for {sample.benchmark_id}"
        )

    finding_outcomes = []
    for finding in findings:
        annotation = _finding_metadata(finding).get("cel")
        decision = annotation.get("decision") if isinstance(annotation, Mapping) else None
        lineage = _finding_cel_lineage(finding, sample.benchmark_id)
        category = finding.get("category") if isinstance(finding, Mapping) else getattr(finding, "category", None)
        category = getattr(category, "value", category)
        finding_outcomes.append(
            {
                "rule_id": _finding_rule_id(finding),
                "category": str(category) if category is not None else "unclassified",
                "severity": _severity_name(finding),
                "cel_decision": decision,
                "cel_decisions": lineage,
            }
        )

    counts["samples"] += 1
    counts[sample.label] += 1
    if sample.label == "malicious":
        if signal:
            counts["signal_tp"] += 1
        else:
            counts["signal_fn"] += 1
        if blocked:
            counts["tp"] += 1
        else:
            counts["fn"] += 1
            counts["critical_high_false_negative_ids"].append(sample.benchmark_id)
    elif blocked:
        counts["fp"] += 1
    else:
        counts["tn"] += 1
    if sample.label == "benign" and actionable:
        counts["actionable_benign_false_positives"] += 1

    counts["scan_latencies_ms"].append(duration_ms)
    counts["total_scan_ms"] += duration_ms
    if loader_recovery is not None:
        counts["loader_fallbacks"] += 1
        counts["recovered_scan_errors"] += 1
        counts["loader_fallback_sample_ids"].append(sample.benchmark_id)
    if loader_rejection is not None:
        counts["loader_rejections"] += 1
        counts["loader_rejection_sample_ids"].append(sample.benchmark_id)
    counts["total_cel_ms"] += cel["elapsed_ms"]
    counts["total_cel_projection_ms"] += cel["projection_ms"]
    counts["total_cel_evaluation_ms"] += cel["evaluation_ms"]
    for field in (
        "evaluated",
        "retained",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
    ):
        counts[f"cel_{field}"] += cel[field]
    for field, target in (
        ("mode", "cel_modes"),
        ("runtime", "cel_runtimes"),
        ("runtime_version", "cel_runtime_versions"),
        ("fact_schema", "cel_fact_schemas"),
        ("expression_set_hash", "cel_expression_set_hashes"),
    ):
        counts[target].add(cel[field])
    for rule_id, code in cel["errors"]:
        key = f"{rule_id}:{code}"
        counts["cel_error_counts"][key] = counts["cel_error_counts"].get(key, 0) + 1
    for entry in cel["rule_decisions"]:
        rule_id = entry["rule_id"]
        decision = entry["decision"]
        rule = counts["cel_rule_decisions"].setdefault(
            rule_id,
            {
                "keep": 0,
                "would_suppress": 0,
                "fallback": 0,
                "suppressed": 0,
                "expression_hashes": set(),
                "packs": set(),
                "rollouts": set(),
            },
        )
        rule[decision] += entry["count"]
        rule["expression_hashes"].add(entry["expression_hash"])
        rule["packs"].add(entry["pack"])
        rule["rollouts"].add(entry["rollout"])
    for entry in cel["suppressed_decisions"]:
        rule_id = entry["rule_id"]
        rule = counts["cel_rule_decisions"].setdefault(
            rule_id,
            {
                "keep": 0,
                "would_suppress": 0,
                "fallback": 0,
                "suppressed": 0,
                "expression_hashes": set(),
                "packs": set(),
                "rollouts": set(),
            },
        )
        # ``would_suppress`` is the attempted false-decision population.  In
        # enforce mode a subset of those candidates are removed, so a compact
        # suppressed record contributes to both counters.  The retained
        # lineage above contains only ``would_suppress - suppressed``.
        rule["would_suppress"] += entry["count"]
        rule["suppressed"] += entry["count"]
        rule["expression_hashes"].add(entry["expression_hash"])
        rule["packs"].add(entry["pack"])
        rule["rollouts"].add(entry["rollout"])
    for count_field, ids_field in (
        ("would_suppress", "cel_would_suppress_sample_ids"),
        ("suppressed", "cel_suppressed_sample_ids"),
        ("fallbacks", "cel_fallback_sample_ids"),
        ("projection_incomplete", "cel_projection_incomplete_sample_ids"),
    ):
        if cel[count_field]:
            counts[ids_field].append(sample.benchmark_id)
    counts["sample_outcomes"][sample.benchmark_id] = {
        "label": sample.label,
        "blocked": blocked,
        "actionable": actionable,
        "signal": signal,
        "scan_error": False,
        "recovered_scan_error": loader_recovery is not None,
        "loader_fallback_code": loader_recovery.error_code if loader_recovery is not None else None,
        "loader_rejection_code": loader_rejection.error_code if loader_rejection is not None else None,
        "cel_suppressed": cel["suppressed_decisions"],
        "findings": sorted(
            finding_outcomes,
            key=lambda item: (
                item["rule_id"],
                item["category"],
                item["severity"],
                str(item["cel_decision"]),
            ),
        ),
    }


def _record_scan_error(counts: dict[str, Any], sample: FrozenSample) -> None:
    """Keep failed scans in every denominator using conservative outcomes."""

    counts["samples"] += 1
    counts[sample.label] += 1
    counts["scan_errors"] += 1
    if sample.label == "malicious":
        counts["fn"] += 1
        counts["signal_fn"] += 1
        counts["critical_high_false_negative_ids"].append(sample.benchmark_id)
    else:
        counts["fp"] += 1
        counts["actionable_benign_false_positives"] += 1
    counts["sample_outcomes"][sample.benchmark_id] = {
        "label": sample.label,
        "blocked": sample.label == "benign",
        "actionable": sample.label == "benign",
        "signal": False,
        "scan_error": True,
        "recovered_scan_error": False,
        "loader_fallback_code": None,
        "loader_rejection_code": None,
        "cel_suppressed": [],
        "findings": [],
    }


def _finalize_counts(counts: Mapping[str, Any]) -> dict[str, Any]:
    loader_fallback_sample_ids = sorted(set(counts["loader_fallback_sample_ids"]))
    if counts["loader_fallbacks"] != counts["recovered_scan_errors"] or counts["loader_fallbacks"] != len(
        loader_fallback_sample_ids
    ):
        raise PublicBenchmarkError("loader fallback recovery counters are inconsistent")
    loader_rejection_sample_ids = sorted(set(counts["loader_rejection_sample_ids"]))
    if counts["loader_rejections"] != len(loader_rejection_sample_ids):
        raise PublicBenchmarkError("closed loader rejection counters are inconsistent")
    metrics = _binary_metrics(counts["tp"], counts["tn"], counts["fp"], counts["fn"])
    block_precision_total = counts["tp"] + counts["fp"]
    rule_decisions = {
        rule_id: {
            "keep": rule["keep"],
            "would_suppress": rule["would_suppress"],
            "fallback": rule["fallback"],
            "suppressed": rule["suppressed"],
            "expression_hashes": sorted(rule["expression_hashes"]),
            "packs": sorted(rule["packs"]),
            "rollouts": sorted(rule["rollouts"]),
        }
        for rule_id, rule in sorted(counts["cel_rule_decisions"].items())
    }
    return {
        "samples": counts["samples"],
        "malicious": counts["malicious"],
        "benign": counts["benign"],
        "tp": counts["tp"],
        "tn": counts["tn"],
        "fp": counts["fp"],
        "fn": counts["fn"],
        "blocked_malicious": counts["tp"],
        "signaled_malicious": counts["signal_tp"],
        "actionable_benign_false_positives": counts["actionable_benign_false_positives"],
        **metrics,
        # Keep the original precision/recall names for report compatibility,
        # but make the package-level classification semantics explicit.
        "package_block_precision": metrics["precision"],
        "package_block_recall": metrics["recall"],
        "signal_recall": _safe_divide(counts["signal_tp"], counts["signal_tp"] + counts["signal_fn"]),
        "benign_actionable_fpr": _safe_divide(counts["actionable_benign_false_positives"], counts["benign"]),
        "confidence_intervals_95": {
            "package_block_precision": _wilson_interval(counts["tp"], block_precision_total),
            "package_block_recall": _wilson_interval(counts["tp"], counts["malicious"]),
            "recall": _wilson_interval(counts["tp"], counts["malicious"]),
            "signal_recall": _wilson_interval(counts["signal_tp"], counts["malicious"]),
            "benign_actionable_fpr": _wilson_interval(counts["actionable_benign_false_positives"], counts["benign"]),
            "accuracy": _wilson_interval(counts["tp"] + counts["tn"], counts["samples"]),
        },
        "critical_high_false_negatives": len(counts["critical_high_false_negative_ids"]),
        "critical_high_false_negative_ids": sorted(counts["critical_high_false_negative_ids"]),
        "p95_scan_latency_ms": _p95(counts["scan_latencies_ms"]),
        "cel_time_ratio": _safe_divide(counts["total_cel_ms"], counts["total_scan_ms"]),
        "cel_fallbacks": counts["cel_fallbacks"],
        "loader_fallbacks": counts["loader_fallbacks"],
        "recovered_scan_errors": counts["recovered_scan_errors"],
        "loader_fallback_sample_ids": loader_fallback_sample_ids,
        "loader_rejections": counts["loader_rejections"],
        "loader_rejection_sample_ids": loader_rejection_sample_ids,
        "cel": {
            "modes": sorted(counts["cel_modes"]),
            "runtimes": sorted(counts["cel_runtimes"]),
            "runtime_versions": sorted(counts["cel_runtime_versions"]),
            "fact_schemas": sorted(counts["cel_fact_schemas"]),
            "expression_set_hashes": sorted(counts["cel_expression_set_hashes"]),
            "evaluated": counts["cel_evaluated"],
            "retained": counts["cel_retained"],
            "would_suppress": counts["cel_would_suppress"],
            "suppressed": counts["cel_suppressed"],
            "fallbacks": counts["cel_fallbacks"],
            "projection_incomplete": counts["cel_projection_incomplete"],
            "elapsed_ms": counts["total_cel_ms"],
            "projection_ms": counts["total_cel_projection_ms"],
            "evaluation_ms": counts["total_cel_evaluation_ms"],
            "error_counts": dict(sorted(counts["cel_error_counts"].items())),
            "per_rule": rule_decisions,
            "would_suppress_sample_ids": sorted(set(counts["cel_would_suppress_sample_ids"])),
            "suppressed_sample_ids": sorted(set(counts["cel_suppressed_sample_ids"])),
            "fallback_sample_ids": sorted(set(counts["cel_fallback_sample_ids"])),
            "projection_incomplete_sample_ids": sorted(set(counts["cel_projection_incomplete_sample_ids"])),
        },
        "scan_errors": counts["scan_errors"],
        "latency_samples": len(counts["scan_latencies_ms"]),
        "sample_outcomes": {
            benchmark_id: outcome for benchmark_id, outcome in sorted(counts["sample_outcomes"].items())
        },
    }


def _run_track(
    snapshot: FrozenSnapshot,
    track: Mapping[str, Any],
    *,
    scanner_factory: Callable[[str, CelMode], _Scanner],
    cel_mode: CelMode,
    population_reference_track: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    selected = [sample for sample in snapshot.samples if sample.splits.get(track["protocol"]) == track["partition"]]
    if not selected:
        raise PublicBenchmarkError(f"track {track['name']} has no selected samples")
    reference_track = population_reference_track or track
    expectation = snapshot.dataset.get("expected", {}).get("track_expectations", {}).get(reference_track["name"])
    if not isinstance(expectation, Mapping):
        raise PublicBenchmarkError(
            f"track {track['name']} has no locked population expectation via {reference_track['name']}"
        )
    label_counts = {label: sum(sample.label == label for sample in selected) for label in _LABELS}
    population_payload = {
        "dataset_id": str(snapshot.dataset["id"]),
        "revision": str(snapshot.dataset["revision"]),
        "track": {
            field: str(reference_track[field]) for field in ("name", "detector_profile", "protocol", "partition")
        },
        "samples": [
            {
                "benchmark_id": sample.benchmark_id,
                "category_ids": list(sample.category_ids),
                "label": sample.label,
                "path": sample.relative_path.as_posix(),
                "source_id": sample.source_id,
                "structural_family_id": sample.structural_family_id,
            }
            for sample in sorted(selected, key=lambda item: item.benchmark_id)
        ],
    }
    population_sha256 = hashlib.sha256(
        json.dumps(
            population_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    actual_population = {
        "samples": len(selected),
        "malicious": label_counts["malicious"],
        "benign": label_counts["benign"],
        "population_sha256": population_sha256,
    }
    if actual_population != dict(expectation):
        raise PublicBenchmarkError(
            f"track {track['name']} population drift (expected {dict(expectation)}, received {actual_population})"
        )
    if {sample.label for sample in selected} != _LABELS:
        raise PublicBenchmarkError(f"track {track['name']} must include malicious and benign controls")

    scanner = scanner_factory(track["detector_profile"], cel_mode)
    counts = _empty_counts()
    source_counts: dict[str, dict[str, Any]] = {}
    family_counts: dict[str, dict[str, Any]] = {}
    category_counts: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    try:
        for sample in selected:
            sample_path = snapshot.root.joinpath(*sample.relative_path.parts)
            try:
                result = scanner.scan_skill(sample_path)
                loader_disposition = recognize_loader_disposition(result)
                _record_sample(
                    counts,
                    sample,
                    result,
                    expected_cel_mode=cel_mode,
                    loader_recovery=loader_disposition.recovery,
                    loader_rejection=loader_disposition.rejection,
                )
                per_source = source_counts.setdefault(sample.source_id, _empty_counts())
                _record_sample(
                    per_source,
                    sample,
                    result,
                    expected_cel_mode=cel_mode,
                    loader_recovery=loader_disposition.recovery,
                    loader_rejection=loader_disposition.rejection,
                )
                per_family = family_counts.setdefault(sample.structural_family_id, _empty_counts())
                _record_sample(
                    per_family,
                    sample,
                    result,
                    expected_cel_mode=cel_mode,
                    loader_recovery=loader_disposition.recovery,
                    loader_rejection=loader_disposition.rejection,
                )
                for category_id in sample.category_ids:
                    per_category = category_counts.setdefault(category_id, _empty_counts())
                    _record_sample(
                        per_category,
                        sample,
                        result,
                        expected_cel_mode=cel_mode,
                        loader_recovery=loader_disposition.recovery,
                        loader_rejection=loader_disposition.rejection,
                    )
            except Exception as exc:  # scanner failures are data, but fail the complete run
                errors.append({"benchmark_id": sample.benchmark_id, "error": str(exc)})
                _record_scan_error(counts, sample)
                per_source = source_counts.setdefault(sample.source_id, _empty_counts())
                _record_scan_error(per_source, sample)
                per_family = family_counts.setdefault(sample.structural_family_id, _empty_counts())
                _record_scan_error(per_family, sample)
                for category_id in sample.category_ids:
                    per_category = category_counts.setdefault(category_id, _empty_counts())
                    _record_scan_error(per_category, sample)
    finally:
        close = getattr(scanner, "close", None)
        if callable(close):
            try:
                close()
            except Exception as exc:
                errors.append({"benchmark_id": "__scanner_close__", "error": str(exc)})

    finalized = _finalize_counts(counts)
    report = {
        "name": track["name"],
        "detector_profile": track["detector_profile"],
        "protocol": track["protocol"],
        "partition": track["partition"],
        "population_sha256": population_sha256,
        "status": "passed" if not errors and finalized["samples"] == len(selected) else "failed",
        **finalized,
        "per_source": {
            source_id: _finalize_counts(per_source) for source_id, per_source in sorted(source_counts.items())
        },
        "per_structural_family": {
            family_id: _finalize_counts(per_family) for family_id, per_family in sorted(family_counts.items())
        },
        "per_category": {
            category_id: _finalize_counts(per_category) for category_id, per_category in sorted(category_counts.items())
        },
        "errors": errors,
    }
    if population_reference_track is not None:
        report["population_reference_track"] = reference_track["name"]
    return report


def _merge_track_cel_telemetry(tracks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    identity_fields = (
        "modes",
        "runtimes",
        "runtime_versions",
        "fact_schemas",
        "expression_set_hashes",
    )
    count_fields = (
        "evaluated",
        "retained",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
        "elapsed_ms",
        "projection_ms",
        "evaluation_ms",
    )
    sample_fields = (
        "would_suppress_sample_ids",
        "suppressed_sample_ids",
        "fallback_sample_ids",
        "projection_incomplete_sample_ids",
    )
    merged: dict[str, Any] = {
        **{field: set() for field in identity_fields},
        **{field: 0 for field in count_fields},
        **{field: set() for field in sample_fields},
        "error_counts": {},
        "per_rule": {},
    }
    for track in tracks:
        cel = _mapping_or_error(track.get("cel"), "track CEL telemetry")
        for field in identity_fields:
            merged[field].update(cel[field])
        for field in count_fields:
            merged[field] += cel[field]
        for field in sample_fields:
            merged[field].update(cel[field])
        for key, count in cel["error_counts"].items():
            merged["error_counts"][key] = merged["error_counts"].get(key, 0) + count
        for rule_id, rule in cel["per_rule"].items():
            target = merged["per_rule"].setdefault(
                rule_id,
                {
                    "keep": 0,
                    "would_suppress": 0,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": set(),
                    "packs": set(),
                    "rollouts": set(),
                },
            )
            for decision in ("keep", "would_suppress", "fallback", "suppressed"):
                target[decision] += rule[decision]
            for field in ("expression_hashes", "packs", "rollouts"):
                target[field].update(rule[field])
    return {
        **{field: sorted(merged[field]) for field in identity_fields},
        **{field: merged[field] for field in count_fields},
        **{field: sorted(merged[field]) for field in sample_fields},
        "error_counts": dict(sorted(merged["error_counts"].items())),
        "per_rule": {
            rule_id: {
                "keep": rule["keep"],
                "would_suppress": rule["would_suppress"],
                "fallback": rule["fallback"],
                "suppressed": rule["suppressed"],
                "expression_hashes": sorted(rule["expression_hashes"]),
                "packs": sorted(rule["packs"]),
                "rollouts": sorted(rule["rollouts"]),
            }
            for rule_id, rule in sorted(merged["per_rule"].items())
        },
    }


def _mapping_or_error(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicBenchmarkError(f"{location} must be an object")
    return value


def _summary(tracks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    false_negative_ids = sorted(
        {benchmark_id for track in tracks for benchmark_id in track["critical_high_false_negative_ids"]}
    )
    block_track = min(tracks, key=lambda track: track["package_block_recall"])
    signal_track = min(tracks, key=lambda track: track["signal_recall"])
    fpr_track = max(tracks, key=lambda track: track["benign_actionable_fpr"])
    loader_fallbacks = sum(track["loader_fallbacks"] for track in tracks)
    loader_fallback_sample_ids = sorted(
        {f"{track['name']}:{benchmark_id}" for track in tracks for benchmark_id in track["loader_fallback_sample_ids"]}
    )
    if loader_fallbacks != len(loader_fallback_sample_ids):
        raise PublicBenchmarkError("summary loader fallback recovery counters are inconsistent")
    loader_rejections = sum(track["loader_rejections"] for track in tracks)
    loader_rejection_sample_ids = sorted(
        {f"{track['name']}:{benchmark_id}" for track in tracks for benchmark_id in track["loader_rejection_sample_ids"]}
    )
    if loader_rejections != len(loader_rejection_sample_ids):
        raise PublicBenchmarkError("summary closed loader rejection counters are inconsistent")
    return {
        "tracks": len(tracks),
        "samples": sum(track["samples"] for track in tracks),
        "malicious": sum(track["malicious"] for track in tracks),
        "benign": sum(track["benign"] for track in tracks),
        "critical_high_false_negatives": len(false_negative_ids),
        "critical_high_false_negative_ids": false_negative_ids,
        "recall": block_track["recall"],
        "package_block_recall": block_track["package_block_recall"],
        "signal_recall": min(track["signal_recall"] for track in tracks),
        "macro_f1": min(track["macro_f1"] for track in tracks),
        "benign_actionable_fpr": max(track["benign_actionable_fpr"] for track in tracks),
        "p95_scan_latency_ms": max(track["p95_scan_latency_ms"] for track in tracks),
        "cel_time_ratio": max(track["cel_time_ratio"] for track in tracks),
        "cel_fallbacks": sum(track["cel_fallbacks"] for track in tracks),
        "loader_fallbacks": loader_fallbacks,
        "recovered_scan_errors": sum(track["recovered_scan_errors"] for track in tracks),
        "loader_fallback_sample_ids": loader_fallback_sample_ids,
        "loader_rejections": loader_rejections,
        "loader_rejection_sample_ids": loader_rejection_sample_ids,
        "cel": _merge_track_cel_telemetry(tracks),
        "scan_errors": sum(track["scan_errors"] for track in tracks),
        "confidence_intervals_95": {
            "package_block_recall": block_track["confidence_intervals_95"]["package_block_recall"],
            "recall": block_track["confidence_intervals_95"]["recall"],
            "signal_recall": signal_track["confidence_intervals_95"]["signal_recall"],
            "benign_actionable_fpr": fpr_track["confidence_intervals_95"]["benign_actionable_fpr"],
        },
    }


def _supplemental_skip(
    snapshot_dir: Path,
    dataset_id: str | None,
    dataset_lock: Path | None,
) -> dict[str, Any]:
    # Even a skipped artifact is traversed defensively so a symlink/device is
    # never silently accepted by the evaluation workflow.
    dataset: Mapping[str, Any] | None = None
    if dataset_id is not None:
        lock = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
        dataset = get_locked_dataset(dataset_id, lock)

    root = Path(snapshot_dir)
    if root.is_symlink():
        raise PublicBenchmarkError("supplemental snapshot root must be an existing non-symlink directory")
    if not root.exists():
        availability = "unavailable"
    elif not root.is_dir():
        raise PublicBenchmarkError("supplemental snapshot root must be an existing non-symlink directory")
    else:
        availability = "present_not_evaluated"
        entries = 0
        total_bytes = 0
        for current_root, directory_names, file_names in os.walk(root, followlinks=False):
            current = Path(current_root)
            for name in [*directory_names, *file_names]:
                entries += 1
                if entries > _MAX_INVENTORY_FILES:
                    raise PublicBenchmarkError("supplemental snapshot exceeds the file safety limit")
                mode = (current / name).lstat().st_mode
                if stat.S_ISLNK(mode):
                    raise PublicBenchmarkError("supplemental snapshot contains a symbolic link")
                if name in directory_names and not stat.S_ISDIR(mode):
                    raise PublicBenchmarkError("supplemental snapshot contains a non-directory tree entry")
                if name in file_names:
                    if not stat.S_ISREG(mode):
                        raise PublicBenchmarkError("supplemental snapshot contains a non-regular file")
                    total_bytes += (current / name).lstat().st_size
                    if total_bytes > _MAX_INVENTORY_BYTES:
                        raise PublicBenchmarkError("supplemental snapshot exceeds the aggregate safety limit")

    dataset_report: dict[str, Any] = {"id": dataset_id or "unspecified"}
    if dataset is not None:
        dataset_report.update(
            {
                "revision": dataset["revision"],
                "blocking": dataset["gating"]["blocking"],
                "source_artifact_manifest_sha256": dataset["integrity"].get("source_artifact_manifest_sha256"),
            }
        )
    return {
        "schema_version": 1,
        "status": "skipped",
        "profile": "supplemental",
        "dataset": dataset_report,
        "tracks": [],
        "summary": {},
        "errors": [],
        "availability": availability,
        "skip_reason": (
            "supplemental and gated corpora are non-blocking; missing credentials or data are a skip, "
            "and no approved static classification adapter is configured"
        ),
    }


def run_public_benchmark(
    snapshot_dir: Path,
    *,
    dataset_id: str | None = None,
    dataset_lock: Path | None = None,
    profile: str = "release",
    cel_mode: CelMode | str = CelMode.OFF,
    scanner_factory: Callable[[str, CelMode], _Scanner] = _default_scanner_factory,
    trusted_rule_packs: Sequence[Path | str] = (),
    locally_extended_scanner_factory: Callable[[str, CelMode], _Scanner] | None = None,
) -> dict[str, Any]:
    """Run locked public tracks and an optional, separate local extension."""

    if profile == "supplemental":
        if trusted_rule_packs or locally_extended_scanner_factory is not None:
            raise PublicBenchmarkError("supplemental skip reports cannot load trusted local rule packs")
        return _supplemental_skip(snapshot_dir, dataset_id, dataset_lock)
    if profile != "release":
        raise PublicBenchmarkError(f"unsupported benchmark profile: {profile}")
    if locally_extended_scanner_factory is not None and not trusted_rule_packs:
        raise PublicBenchmarkError("locally_extended_scanner_factory requires trusted_rule_packs")
    mode = CelMode(cel_mode)
    snapshot = load_frozen_snapshot(
        snapshot_dir,
        dataset_id=dataset_id,
        dataset_lock=dataset_lock,
    )
    trusted_pack_set = (
        _trusted_pack_set(trusted_rule_packs, snapshot_root=snapshot.root.resolve(strict=True))
        if trusted_rule_packs
        else None
    )
    dataset = snapshot.dataset
    locked_track_definitions = list(dataset["gating"]["tracks"])
    detector_profiles = tuple(str(track["detector_profile"]) for track in locked_track_definitions)
    start_producer = _producer_components(detector_profiles)
    blocking_eligible = bool(
        dataset["gating"]["blocking"]
        and not dataset["integrity"]["hashes_pending"]
        and dataset["integrity"]["artifact_manifest_sha256"] == snapshot.artifact_manifest_sha256
    )
    if dataset["integrity"]["hashes_pending"]:
        blocking_reason = "complete materialized snapshot manifest is pending review"
    elif not dataset["gating"]["blocking"]:
        blocking_reason = "dataset lock marks this corpus non-blocking"
    elif dataset["integrity"]["artifact_manifest_sha256"] != snapshot.artifact_manifest_sha256:
        blocking_reason = "materialized snapshot digest does not match the dataset lock"
    else:
        blocking_reason = None
    if profile == "release" and not blocking_eligible:
        raise PublicBenchmarkError("release profile requires a reviewed, lock-pinned artifact digest and blocking=true")
    if profile == "release" and any("unclassified" in sample.category_ids for sample in snapshot.samples):
        raise PublicBenchmarkError("release profile requires category_id for every benchmark sample")

    tracks = [
        _run_track(
            snapshot,
            track,
            scanner_factory=scanner_factory,
            cel_mode=mode,
        )
        for track in locked_track_definitions
    ]
    errors = [error for track in tracks for error in track["errors"]]
    locally_extended_tracks: list[dict[str, Any]] = []
    locally_extended_errors: list[dict[str, str]] = []
    if trusted_pack_set is not None:
        source_tracks = [track for track in locked_track_definitions if track["detector_profile"] == "core_only"]
        if not source_tracks:
            raise PublicBenchmarkError("locally extended evaluation requires a locked core_only reference track")
        local_factory: Callable[[str, CelMode], _Scanner]
        if locally_extended_scanner_factory is None:

            def default_local_factory(detector_profile: str, requested_mode: CelMode) -> _Scanner:
                return _default_scanner_factory(
                    detector_profile,
                    requested_mode,
                    trusted_rule_packs=trusted_pack_set.paths,
                )

            local_factory = default_local_factory
        else:
            local_factory = locally_extended_scanner_factory
        for source_track in source_tracks:
            local_track = {
                "name": f"{source_track['name']}-locally-extended",
                "detector_profile": "locally_extended",
                "protocol": source_track["protocol"],
                "partition": source_track["partition"],
            }
            local_report = _run_track(
                snapshot,
                local_track,
                scanner_factory=local_factory,
                cel_mode=mode,
                population_reference_track=source_track,
            )
            locally_extended_tracks.append(local_report)
            locally_extended_errors.extend(local_report["errors"])
        errors.extend(locally_extended_errors)
    identity_errors: list[str] = []
    drifted_fields: set[str] = set()
    end_snapshot: FrozenSnapshot | None = None
    try:
        end_snapshot = load_frozen_snapshot(
            snapshot_dir,
            dataset_id=dataset_id,
            dataset_lock=dataset_lock,
        )
    except Exception as exc:
        drifted_fields.add("snapshot_artifact_inventory")
        identity_errors.append(f"snapshot post-run validation failed: {exc}")
    else:
        if end_snapshot.artifact_manifest_sha256 != snapshot.artifact_manifest_sha256:
            drifted_fields.add("snapshot_sha256")
        if end_snapshot.dataset != snapshot.dataset:
            drifted_fields.add("dataset_lock")
        if end_snapshot.samples != snapshot.samples:
            drifted_fields.add("snapshot_manifest")

    end_producer: dict[str, str] | None = None
    try:
        end_producer = _producer_components(detector_profiles)
    except Exception as exc:
        drifted_fields.add("producer_identity")
        identity_errors.append(f"producer post-run validation failed: {exc}")
    else:
        for field, start_value in start_producer.items():
            if end_producer[field] != start_value:
                drifted_fields.add(field)

    end_trusted_pack_set: TrustedPackSet | None = None
    if trusted_pack_set is not None:
        try:
            end_trusted_pack_set = _trusted_pack_set(
                trusted_pack_set.paths,
                snapshot_root=snapshot.root.resolve(strict=True),
            )
        except Exception as exc:
            drifted_fields.add("trusted_rule_pack_set_sha256")
            identity_errors.append(f"trusted rule-pack post-run validation failed: {exc}")
        else:
            if end_trusted_pack_set.identity != trusted_pack_set.identity:
                drifted_fields.add("trusted_rule_pack_set_sha256")

    if drifted_fields:
        detail = f"benchmark identity changed during scan: {', '.join(sorted(drifted_fields))}"
        identity_errors.insert(0, detail)
        errors.append({"benchmark_id": "__benchmark_identity__", "error": "; ".join(identity_errors)})
    all_tracks = [*tracks, *locally_extended_tracks]
    status = "passed" if all(track["status"] == "passed" for track in all_tracks) and not drifted_fields else "failed"
    evidence_identity, producer = _evidence_identity(snapshot, tracks, mode, start_producer)
    locally_extended: dict[str, Any]
    if trusted_pack_set is None:
        locally_extended = {
            "status": "not_configured",
            "release_blocking": False,
            "tracks": {},
            "summary": {},
            "errors": [],
        }
    else:
        local_identity, local_producer = _evidence_identity(
            snapshot,
            locally_extended_tracks,
            mode,
            start_producer,
        )
        local_identity["trusted_rule_pack_set_sha256"] = trusted_pack_set.identity["sha256"]
        local_producer["trusted_rule_pack_set_sha256"] = trusted_pack_set.identity["sha256"]
        locally_extended = {
            "status": (
                "passed"
                if all(track["status"] == "passed" for track in locally_extended_tracks) and not drifted_fields
                else "failed"
            ),
            "release_blocking": False,
            "base_configuration": "core_only",
            "trusted_rule_pack_set": trusted_pack_set.identity,
            "evidence_identity": local_identity,
            "producer": local_producer,
            "tracks": {track["name"]: track for track in locally_extended_tracks},
            "summary": _summary(locally_extended_tracks),
            "errors": [
                *locally_extended_errors,
                *(
                    []
                    if not drifted_fields
                    else [{"benchmark_id": "__benchmark_identity__", "error": "; ".join(identity_errors)}]
                ),
            ],
        }
    return {
        "schema_version": 1,
        "status": status,
        "profile": profile,
        "cel_mode": mode.value,
        "evidence_identity": evidence_identity,
        "producer": producer,
        "identity_verification": {
            "status": "passed" if not drifted_fields else "failed",
            "drifted_fields": sorted(drifted_fields),
            "start": {
                "snapshot_sha256": snapshot.artifact_manifest_sha256,
                **start_producer,
                **(
                    {}
                    if trusted_pack_set is None
                    else {"trusted_rule_pack_set_sha256": trusted_pack_set.identity["sha256"]}
                ),
            },
            "end": (
                None
                if end_snapshot is None or end_producer is None
                else {
                    "snapshot_sha256": end_snapshot.artifact_manifest_sha256,
                    **end_producer,
                    **(
                        {}
                        if end_trusted_pack_set is None
                        else {"trusted_rule_pack_set_sha256": end_trusted_pack_set.identity["sha256"]}
                    ),
                }
            ),
            "errors": identity_errors,
        },
        "dataset": {
            "id": dataset["id"],
            "revision": dataset["revision"],
            "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
            "usable_artifact_manifest_sha256": snapshot.usable_artifact_manifest_sha256,
            "quarantine_manifest_sha256": snapshot.quarantine_manifest_sha256,
            "quarantined_sample_count": len(snapshot.quarantined_sample_ids),
            "source_artifact_manifest_sha256": dataset["integrity"].get("source_artifact_manifest_sha256"),
            "blocking_eligible": blocking_eligible,
            "nonblocking_reason": blocking_reason,
        },
        "tracks": {track["name"]: track for track in tracks},
        "summary": _summary(tracks),
        "locally_extended": locally_extended,
        "errors": errors,
    }


def _outcomes_sha256(outcomes: Mapping[str, Any]) -> str:
    encoded = json.dumps(outcomes, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"skill-scanner-release-sample-outcomes-v1\0" + encoded).hexdigest()


def compact_release_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return bounded release evidence without duplicating sample outcomes.

    Full benchmark reports repeat each outcome in the track, source, family,
    and category scopes and can exceed 40 MiB. Release gates need aggregate
    metrics for every scope and per-rule CEL decisions, not every non-CEL
    finding copied four times. The compact form retains a domain-separated
    digest/count for every removed outcome map and keeps the minimal annotated
    track outcomes needed to verify CEL promotion telemetry.
    """

    compact: dict[str, Any] = json.loads(json.dumps(report, ensure_ascii=False))

    def replace_scope_outcomes(scope: dict[str, Any], *, retain_cel: bool) -> None:
        raw = scope.pop("sample_outcomes", None)
        if raw is None:
            return
        if not isinstance(raw, Mapping):
            raise PublicBenchmarkError("sample_outcomes must be an object before release compaction")
        scope["sample_outcomes_count"] = len(raw)
        scope["sample_outcomes_sha256"] = _outcomes_sha256(raw)
        scope["sample_outcomes_format"] = "cel-referenced-v3" if retain_cel else "digest-only-v1"
        if not retain_cel:
            return
        annotated: dict[str, Any] = {}
        for benchmark_id, value in sorted(raw.items()):
            if not isinstance(benchmark_id, str) or not isinstance(value, Mapping):
                raise PublicBenchmarkError("sample_outcomes contains an invalid entry")
            findings = value.get("findings", [])
            if not isinstance(findings, list):
                raise PublicBenchmarkError("sample_outcomes findings must be an array")
            cel_findings = []
            recovered = value.get("recovered_scan_error") is True
            rejected = value.get("loader_rejection_code") is not None
            suppressed = value.get("cel_suppressed", [])
            if not isinstance(suppressed, list):
                raise PublicBenchmarkError("sample_outcomes cel_suppressed must be an array")
            compact_suppressed = []
            for entry in suppressed:
                if not isinstance(entry, Mapping) or set(entry) != {
                    "rule_id",
                    "category",
                    "severity",
                    "analyzer",
                    "count",
                    "expression_hash",
                    "pack",
                    "rollout",
                }:
                    raise PublicBenchmarkError("sample_outcomes contains invalid suppressed CEL evidence")
                compact_suppressed.append(
                    {
                        "rule_id": entry["rule_id"],
                        "category": entry["category"],
                        "severity": entry["severity"],
                        "analyzer": entry["analyzer"],
                        "count": entry["count"],
                    }
                )
            for finding in findings:
                if not isinstance(finding, Mapping):
                    raise PublicBenchmarkError("sample_outcomes contains an invalid finding")
                decision = finding.get("cel_decision")
                lineage = finding.get("cel_decisions", [])
                if not isinstance(lineage, list):
                    raise PublicBenchmarkError("sample_outcomes finding cel_decisions must be an array")
                compact_lineage_counts: dict[tuple[str, str], int] = {}
                for entry in lineage:
                    if not isinstance(entry, Mapping) or set(entry) != {
                        "rule_id",
                        "decision",
                        "reason",
                        "fact_schema",
                        "expression_hash",
                        "pack",
                        "rollout",
                        "count",
                    }:
                        raise PublicBenchmarkError("sample_outcomes contains invalid CEL lineage evidence")
                    rule_id = entry["rule_id"]
                    lineage_decision = entry["decision"]
                    count = entry["count"]
                    if (
                        not isinstance(rule_id, str)
                        or not rule_id
                        or lineage_decision not in {"keep", "would_suppress", "fallback"}
                        or isinstance(count, bool)
                        or not isinstance(count, int)
                        or count <= 0
                    ):
                        raise PublicBenchmarkError("sample_outcomes contains invalid CEL lineage identity")
                    key = (rule_id, lineage_decision)
                    compact_lineage_counts[key] = compact_lineage_counts.get(key, 0) + count
                compact_lineage = [
                    {"rule_id": rule_id, "decision": lineage_decision, "count": count}
                    for (rule_id, lineage_decision), count in sorted(compact_lineage_counts.items())
                ]
                is_loader_marker = recovered and finding.get("rule_id") == "SKILL_LOAD_FALLBACK_USED"
                is_rejection_marker = rejected and finding.get("rule_id") == "SKILL_LOAD_REJECTED_LIMIT"
                if not compact_lineage and decision is None and not is_loader_marker and not is_rejection_marker:
                    continue
                cel_findings.append(
                    {
                        "rule_id": finding.get("rule_id"),
                        "severity": finding.get("severity"),
                        "cel_decision": decision,
                        "cel_decisions": compact_lineage,
                    }
                )
            if cel_findings or compact_suppressed or value.get("scan_error") is True or recovered or rejected:
                annotated[benchmark_id] = {
                    "label": value.get("label"),
                    "scan_error": value.get("scan_error") is True,
                    "recovered_scan_error": value.get("recovered_scan_error") is True,
                    "loader_fallback_code": value.get("loader_fallback_code"),
                    "loader_rejection_code": value.get("loader_rejection_code"),
                    "cel_suppressed": compact_suppressed,
                    "findings": cel_findings,
                }
        scope["sample_outcomes"] = annotated

    summary = compact.get("summary")
    if isinstance(summary, dict):
        replace_scope_outcomes(summary, retain_cel=False)

    def compact_tracks(raw_tracks: Any, *, location: str) -> None:
        if not isinstance(raw_tracks, Mapping):
            raise PublicBenchmarkError(f"{location} tracks must be an object")
        for track in raw_tracks.values():
            if not isinstance(track, dict):
                raise PublicBenchmarkError(f"{location} contains an invalid track")
            replace_scope_outcomes(track, retain_cel=True)
            for dimension in ("per_source", "per_structural_family", "per_category"):
                groups = track.get(dimension, {})
                if not isinstance(groups, Mapping):
                    raise PublicBenchmarkError(f"{location} {dimension} must be an object")
                for group in groups.values():
                    if not isinstance(group, dict):
                        raise PublicBenchmarkError(f"{location} {dimension} contains an invalid group")
                    replace_scope_outcomes(group, retain_cel=False)

    compact_tracks(compact.get("tracks"), location="release report")
    locally_extended = compact.get("locally_extended")
    if isinstance(locally_extended, dict) and locally_extended.get("status") != "not_configured":
        local_summary = locally_extended.get("summary")
        if not isinstance(local_summary, dict):
            raise PublicBenchmarkError("locally extended summary must be an object")
        replace_scope_outcomes(local_summary, retain_cel=False)
        compact_tracks(locally_extended.get("tracks"), location="locally extended report")
    compact["release_evidence"] = {
        "format": "compact-v3",
        "full_sample_outcomes_domain": "skill-scanner-release-sample-outcomes-v1",
        "cel_decision_identity": "track.cel.per_rule",
    }
    return compact


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        output_mode = destination.lstat().st_mode
        if stat.S_ISLNK(output_mode) or not stat.S_ISREG(output_mode):
            raise PublicBenchmarkError(f"output must not be a symlink or non-regular file: {destination}")

    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(temporary, flags, 0o600)
    complete = False
    try:
        release_evidence = report.get("release_evidence")
        if isinstance(release_evidence, Mapping) and release_evidence.get("format") == "compact-v3":
            payload = (json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode(
                "utf-8"
            )
        else:
            payload = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write while emitting public benchmark report")
            remaining = remaining[written:]
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete:
            temporary.unlink(missing_ok=True)
    os.replace(temporary, destination)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a pinned, pre-materialized public dataset snapshot (offline only)"
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--dataset-id")
    parser.add_argument("--dataset-lock", type=Path, default=None)
    parser.add_argument("--profile", choices=("release", "supplemental"), default="release")
    parser.add_argument("--cel-mode", choices=tuple(mode.value for mode in CelMode), default="off")
    parser.add_argument(
        "--trusted-rule-pack",
        action="append",
        type=Path,
        default=[],
        help=(
            "administrator-approved local schema-v2 pack; repeat to emit a separate, "
            "non-blocking locally_extended configuration"
        ),
    )
    parser.add_argument(
        "--compact-release-evidence",
        action="store_true",
        help="emit bounded canonical release evidence instead of the duplicated full diagnostic report",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        snapshot_root = args.snapshot_dir.resolve(strict=args.profile != "supplemental")
        output = args.output.resolve(strict=False)
        if output == snapshot_root or output.is_relative_to(snapshot_root):
            raise PublicBenchmarkError("output must be outside the immutable snapshot root")
        if args.compact_release_evidence and args.trusted_rule_pack:
            raise PublicBenchmarkError(
                "compact mandatory release evidence must not include the non-blocking locally_extended configuration"
            )
        report = run_public_benchmark(
            args.snapshot_dir,
            dataset_id=args.dataset_id,
            dataset_lock=args.dataset_lock,
            profile=args.profile,
            cel_mode=args.cel_mode,
            trusted_rule_packs=args.trusted_rule_pack,
        )
        if args.compact_release_evidence:
            if args.profile != "release":
                raise PublicBenchmarkError("compact release evidence requires --profile release")
            report = compact_release_report(report)
            encoded_size = len(
                (json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            )
            if encoded_size > _MAX_COMPACT_RELEASE_REPORT_BYTES:
                raise PublicBenchmarkError(
                    f"compact release evidence exceeds the {_MAX_COMPACT_RELEASE_REPORT_BYTES}-byte safety limit"
                )
        _write_report(args.output, report)
    except Exception as exc:
        print(f"public dataset benchmark failed: {exc}", file=sys.stderr)
        return 1

    if report["status"] == "failed":
        print(f"public dataset benchmark recorded {len(report['errors'])} scan error(s)", file=sys.stderr)
        return 1
    if report["status"] == "skipped":
        print(f"public dataset benchmark skipped: {report['skip_reason']}")
    else:
        print(
            f"public dataset benchmark passed: {report['summary']['samples']} track-samples, "
            f"blocking_eligible={report['dataset']['blocking_eligible']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
