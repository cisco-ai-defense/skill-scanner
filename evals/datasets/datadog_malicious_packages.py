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

"""Offline, text-only adapter for DataDog malicious-package snapshots.

This is a consumer for a *derived* snapshot, not an acquisition utility.  A
separate quarantined job must fetch the pinned upstream revision, discard all
archives and binary members, and write the exact manifest documented by this
module.  This adapter never downloads, extracts, imports, compiles, or executes
sample content.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from evals.datasets.public_datasets import (
    DatasetLockError,
    DatasetSchemaError,
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    validate_artifact_manifest,
)
from evals.datasets.quarantined_text import (
    PACKAGE_TEXT_POLICY,
    QuarantinedTextError,
    TextArtifact,
    inventory_text_tree,
    package_identity,
    read_regular_json,
    require_exact_fields,
    require_portable_relative_path,
    require_sequence,
    require_sha256,
    require_string,
    validate_declared_artifacts,
)

DATASET_ID = "DataDog/malicious-software-packages-dataset"
SNAPSHOT_MANIFEST = "datadog-package-snapshot.json"
SNAPSHOT_SCHEMA_VERSION = 1

_ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "revision",
        "artifact_manifest_sha256",
        "artifacts",
        "population_sha256",
        "samples",
        "quarantine",
    }
)
_SAMPLE_FIELDS = frozenset(
    {
        "sample_id",
        "ecosystem",
        "package_name",
        "package_version",
        "source_id",
        "repository_id",
        "actor_campaign_id",
        "structural_family_id",
        "lexical_template_id",
        "path",
        "content_sha256",
        "normalized_content_sha256",
    }
)
_QUARANTINE_FIELDS = frozenset(
    {
        "sample_id",
        "ecosystem",
        "package_name",
        "package_version",
        "source_id",
        "repository_id",
        "actor_campaign_id",
        "structural_family_id",
        "lexical_template_id",
        "error_code",
    }
)
_SLUG_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_ERROR_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_MAX_SAMPLES = 500_000


class DataDogSnapshotError(ValueError):
    """Raised when a derived DataDog snapshot is unsafe or drifts."""


@dataclass(frozen=True)
class DataDogPackage:
    """One validated malicious, text-only package."""

    sample_id: str
    ecosystem: str
    package_name: str
    package_version: str
    source_id: str
    repository_id: str
    actor_campaign_id: str
    structural_family_id: str
    lexical_template_id: str
    relative_path: PurePosixPath
    package_directory: Path
    content_sha256: str
    normalized_content_sha256: str


@dataclass(frozen=True)
class DataDogQuarantinedPackage:
    """A positive sample that remains in the denominator but cannot be scanned."""

    sample_id: str
    ecosystem: str
    package_name: str
    package_version: str
    source_id: str
    repository_id: str
    actor_campaign_id: str
    structural_family_id: str
    lexical_template_id: str
    error_code: str


@dataclass(frozen=True)
class DataDogPackageSnapshot:
    """Validated derived snapshot and immutable provenance."""

    root: Path
    revision: str
    artifact_manifest_sha256: str
    population_sha256: str
    artifact_manifest_pinned: bool
    packages: tuple[DataDogPackage, ...]
    quarantine: tuple[DataDogQuarantinedPackage, ...]
    exact_duplicate_of: Mapping[str, str]
    normalized_duplicate_of: Mapping[str, str]

    @property
    def evaluation_packages(self) -> tuple[DataDogPackage, ...]:
        """Return one deterministic representative per exact-content group."""

        return tuple(package for package in self.packages if package.sample_id not in self.normalized_duplicate_of)


def _stable_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _metadata(value: Any, location: str, *, max_bytes: int = 1_024) -> str:
    try:
        return require_string(value, location, max_bytes=max_bytes)
    except QuarantinedTextError as exc:
        raise DataDogSnapshotError(str(exc)) from exc


def _slug(value: Any, location: str) -> str:
    result = _metadata(value, location, max_bytes=64)
    if not _SLUG_RE.fullmatch(result):
        raise DataDogSnapshotError(f"{location} must be a lowercase ecosystem slug")
    return result


def _canonical_sample_record(raw: Any, index: int) -> dict[str, str]:
    try:
        value = require_exact_fields(raw, _SAMPLE_FIELDS, f"samples[{index}]")
        path = require_portable_relative_path(value["path"], f"samples[{index}].path")
        content_sha256 = require_sha256(value["content_sha256"], f"samples[{index}].content_sha256")
        normalized_sha256 = require_sha256(
            value["normalized_content_sha256"], f"samples[{index}].normalized_content_sha256"
        )
    except QuarantinedTextError as exc:
        raise DataDogSnapshotError(str(exc)) from exc
    if len(path.parts) < 2 or path.parts[0] != "packages":
        raise DataDogSnapshotError(f"samples[{index}].path must be beneath packages/")
    return {
        "sample_id": _metadata(value["sample_id"], f"samples[{index}].sample_id", max_bytes=256),
        "ecosystem": _slug(value["ecosystem"], f"samples[{index}].ecosystem"),
        "package_name": _metadata(value["package_name"], f"samples[{index}].package_name"),
        "package_version": _metadata(value["package_version"], f"samples[{index}].package_version", max_bytes=256),
        "source_id": _metadata(value["source_id"], f"samples[{index}].source_id", max_bytes=256),
        "repository_id": _metadata(value["repository_id"], f"samples[{index}].repository_id"),
        "actor_campaign_id": _metadata(value["actor_campaign_id"], f"samples[{index}].actor_campaign_id"),
        "structural_family_id": _metadata(value["structural_family_id"], f"samples[{index}].structural_family_id"),
        "lexical_template_id": _metadata(value["lexical_template_id"], f"samples[{index}].lexical_template_id"),
        "path": path.as_posix(),
        "content_sha256": content_sha256,
        "normalized_content_sha256": normalized_sha256,
    }


def _canonical_quarantine_record(raw: Any, index: int) -> dict[str, str]:
    try:
        value = require_exact_fields(raw, _QUARANTINE_FIELDS, f"quarantine[{index}]")
    except QuarantinedTextError as exc:
        raise DataDogSnapshotError(str(exc)) from exc
    error_code = _metadata(value["error_code"], f"quarantine[{index}].error_code", max_bytes=128)
    if not _ERROR_RE.fullmatch(error_code):
        raise DataDogSnapshotError(f"quarantine[{index}].error_code must be a stable uppercase code")
    return {
        "sample_id": _metadata(value["sample_id"], f"quarantine[{index}].sample_id", max_bytes=256),
        "ecosystem": _slug(value["ecosystem"], f"quarantine[{index}].ecosystem"),
        "package_name": _metadata(value["package_name"], f"quarantine[{index}].package_name"),
        "package_version": _metadata(value["package_version"], f"quarantine[{index}].package_version", max_bytes=256),
        "source_id": _metadata(value["source_id"], f"quarantine[{index}].source_id", max_bytes=256),
        "repository_id": _metadata(value["repository_id"], f"quarantine[{index}].repository_id"),
        "actor_campaign_id": _metadata(value["actor_campaign_id"], f"quarantine[{index}].actor_campaign_id"),
        "structural_family_id": _metadata(value["structural_family_id"], f"quarantine[{index}].structural_family_id"),
        "lexical_template_id": _metadata(value["lexical_template_id"], f"quarantine[{index}].lexical_template_id"),
        "error_code": error_code,
    }


def datadog_population_sha256(
    samples: object,
    quarantine: object,
    *,
    revision: str | None = None,
) -> str:
    """Return the path/content-free denominator identity for a derived snapshot."""

    try:
        sample_values = require_sequence(samples, "samples")
        quarantine_values = require_sequence(quarantine, "quarantine", allow_empty=True)
    except QuarantinedTextError as exc:
        raise DataDogSnapshotError(str(exc)) from exc
    canonical_samples = [_canonical_sample_record(value, index) for index, value in enumerate(sample_values)]
    canonical_quarantine = [_canonical_quarantine_record(value, index) for index, value in enumerate(quarantine_values)]
    canonical_samples.sort(key=lambda item: (_stable_key(item["sample_id"]), item["sample_id"]))
    canonical_quarantine.sort(key=lambda item: (_stable_key(item["sample_id"]), item["sample_id"]))
    payload = {
        "dataset_id": DATASET_ID,
        "format": "datadog-positive-population-v1",
        "quarantine": canonical_quarantine,
        "revision": revision or str(get_locked_dataset(DATASET_ID, load_dataset_lock())["revision"]),
        "samples": canonical_samples,
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _validate_unique_identity(samples: Sequence[Mapping[str, str]], quarantine: Sequence[Mapping[str, str]]) -> None:
    seen_ids: dict[str, str] = {}
    seen_paths: list[PurePosixPath] = []
    for record in [*samples, *quarantine]:
        sample_id = record["sample_id"]
        key = _stable_key(sample_id)
        if key in seen_ids:
            raise DataDogSnapshotError(f"duplicate or normalization-colliding sample identifier: {sample_id}")
        seen_ids[key] = sample_id
    for record in samples:
        path = PurePosixPath(record["path"])
        for existing in seen_paths:
            if path == existing or path.is_relative_to(existing) or existing.is_relative_to(path):
                raise DataDogSnapshotError(
                    f"package paths must be disjoint and non-nested: {existing.as_posix()} and {path.as_posix()}"
                )
        seen_paths.append(path)


def _artifact_subset(artifacts: Sequence[TextArtifact], prefix: PurePosixPath) -> tuple[TextArtifact, ...]:
    result: list[TextArtifact] = []
    for artifact in artifacts:
        try:
            artifact.path.relative_to(prefix)
        except ValueError:
            continue
        result.append(artifact)
    return tuple(result)


def load_datadog_package_snapshot(
    root: Path,
    *,
    revision: str | None = None,
) -> DataDogPackageSnapshot:
    """Load and validate a complete, already-materialized DataDog snapshot."""

    root = Path(root)
    manifest_path = root / SNAPSHOT_MANIFEST
    try:
        manifest = require_exact_fields(read_regular_json(manifest_path), _ROOT_FIELDS, "snapshot manifest")
    except QuarantinedTextError as exc:
        raise DataDogSnapshotError(str(exc)) from exc
    if manifest["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise DataDogSnapshotError(f"unsupported snapshot schema version: {manifest['schema_version']!r}")
    if manifest["dataset_id"] != DATASET_ID:
        raise DataDogSnapshotError(f"snapshot dataset_id must be {DATASET_ID!r}")

    try:
        dataset = get_locked_dataset(DATASET_ID, load_dataset_lock())
    except (DatasetLockError, DatasetSchemaError) as exc:
        raise DataDogSnapshotError(f"cannot load locked DataDog identity: {exc}") from exc
    locked_revision = str(dataset["revision"])
    manifest_revision = _metadata(manifest["revision"], "snapshot revision", max_bytes=40)
    if manifest_revision != locked_revision or (revision is not None and revision != manifest_revision):
        raise DataDogSnapshotError(
            f"revision drift (expected {locked_revision}, received {revision or manifest_revision})"
        )

    raw_samples = require_sequence(manifest["samples"], "samples")
    raw_quarantine = require_sequence(manifest["quarantine"], "quarantine", allow_empty=True)
    if len(raw_samples) + len(raw_quarantine) > _MAX_SAMPLES:
        raise DataDogSnapshotError(f"snapshot exceeds the {_MAX_SAMPLES}-sample limit")
    samples = [_canonical_sample_record(value, index) for index, value in enumerate(raw_samples)]
    quarantine = [_canonical_quarantine_record(value, index) for index, value in enumerate(raw_quarantine)]
    _validate_unique_identity(samples, quarantine)

    try:
        inventory = inventory_text_tree(
            root,
            policy=PACKAGE_TEXT_POLICY,
            excluded_paths=(PurePosixPath(SNAPSHOT_MANIFEST),),
        )
        declared = validate_declared_artifacts(manifest["artifacts"], actual=inventory)
        declared_digest = require_sha256(manifest["artifact_manifest_sha256"], "artifact_manifest_sha256")
        actual_digest = artifact_manifest_sha256(DATASET_ID, declared)
        validate_artifact_manifest(DATASET_ID, declared, manifest_sha256=declared_digest)
    except (QuarantinedTextError, DatasetLockError, DatasetSchemaError) as exc:
        raise DataDogSnapshotError(f"invalid text artifact inventory: {exc}") from exc
    if actual_digest != declared_digest:  # validate_artifact_manifest already checks; keep the invariant explicit.
        raise DataDogSnapshotError("artifact manifest digest mismatch")

    owned_artifacts: set[PurePosixPath] = set()
    packages: list[DataDogPackage] = []
    for index, sample in enumerate(samples):
        relative_path = PurePosixPath(sample["path"])
        package_artifacts = _artifact_subset(inventory, relative_path)
        try:
            identity = package_identity(package_artifacts, prefix=relative_path)
        except QuarantinedTextError as exc:
            raise DataDogSnapshotError(f"samples[{index}] has an invalid package tree: {exc}") from exc
        if identity.content_sha256 != sample["content_sha256"]:
            raise DataDogSnapshotError(f"samples[{index}] exact content hash drift")
        if identity.normalized_content_sha256 != sample["normalized_content_sha256"]:
            raise DataDogSnapshotError(f"samples[{index}] normalized content hash drift")
        owned_artifacts.update(artifact.path for artifact in package_artifacts)
        packages.append(
            DataDogPackage(
                sample_id=sample["sample_id"],
                ecosystem=sample["ecosystem"],
                package_name=sample["package_name"],
                package_version=sample["package_version"],
                source_id=sample["source_id"],
                repository_id=sample["repository_id"],
                actor_campaign_id=sample["actor_campaign_id"],
                structural_family_id=sample["structural_family_id"],
                lexical_template_id=sample["lexical_template_id"],
                relative_path=relative_path,
                package_directory=root.joinpath(*relative_path.parts),
                content_sha256=sample["content_sha256"],
                normalized_content_sha256=sample["normalized_content_sha256"],
            )
        )
    unowned = sorted(artifact.path.as_posix() for artifact in inventory if artifact.path not in owned_artifacts)
    if unowned:
        raise DataDogSnapshotError(f"artifact inventory contains files outside declared packages: {unowned[:3]}")

    expected_population_digest = datadog_population_sha256(samples, quarantine, revision=manifest_revision)
    try:
        declared_population_digest = require_sha256(manifest["population_sha256"], "population_sha256")
    except QuarantinedTextError as exc:
        raise DataDogSnapshotError(str(exc)) from exc
    if expected_population_digest != declared_population_digest:
        raise DataDogSnapshotError("population manifest digest mismatch")

    packages.sort(key=lambda package: (_stable_key(package.sample_id), package.sample_id))
    exact_duplicate_of: dict[str, str] = {}
    canonical_by_content: dict[str, str] = {}
    normalized_duplicate_of: dict[str, str] = {}
    canonical_by_normalized_content: dict[str, str] = {}
    for package in packages:
        canonical = canonical_by_content.setdefault(package.content_sha256, package.sample_id)
        if canonical != package.sample_id:
            exact_duplicate_of[package.sample_id] = canonical
        normalized_canonical = canonical_by_normalized_content.setdefault(
            package.normalized_content_sha256, package.sample_id
        )
        if normalized_canonical != package.sample_id:
            normalized_duplicate_of[package.sample_id] = normalized_canonical
    quarantine_objects = tuple(
        DataDogQuarantinedPackage(**record)
        for record in sorted(quarantine, key=lambda item: (_stable_key(item["sample_id"]), item["sample_id"]))
    )
    return DataDogPackageSnapshot(
        root=root,
        revision=manifest_revision,
        artifact_manifest_sha256=declared_digest,
        population_sha256=declared_population_digest,
        artifact_manifest_pinned=not bool(dataset["integrity"]["hashes_pending"]),
        packages=tuple(packages),
        quarantine=quarantine_objects,
        exact_duplicate_of=exact_duplicate_of,
        normalized_duplicate_of=normalized_duplicate_of,
    )
