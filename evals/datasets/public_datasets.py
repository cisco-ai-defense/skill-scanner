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

"""Offline validation and safe materialization for locked public datasets.

This module deliberately has no HTTP client, archive extraction, import, or
execution path. Callers must fetch an approved pinned artifact elsewhere and
pass decoded rows in memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, cast

LOCK_FILE = Path(__file__).with_name("public-datasets.lock.json")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_BUNDLE_FIELDS = frozenset({"path", "content", "sha256", "sizeBytes"})
_ARTIFACT_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_QUARANTINE_RECORD_FIELDS = frozenset(
    {
        "benchmark_id",
        "path",
        "label",
        "source_id",
        "structural_family_id",
        "splits",
        "sha256",
        "size_bytes",
        "error_code",
    }
)
_LOCK_FIELDS = frozenset({"manifest_version", "updated_at", "safety_defaults", "datasets"})
_SAFETY_FIELDS = frozenset(
    {"execute_samples", "follow_embedded_links", "network_fetch_in_pull_requests", "materialized_file_mode"}
)
_DATASET_REQUIRED_FIELDS = frozenset(
    {
        "id",
        "provider",
        "revision",
        "integrity",
        "access",
        "license",
        "download_policy",
        "approved_uses",
        "prohibited_uses",
        "gating",
    }
)
_DATASET_FIELDS = _DATASET_REQUIRED_FIELDS | {"known_issues", "expected"}
_LICENSE_FIELDS = frozenset({"spdx", "code_spdx", "scope"})
_INTEGRITY_REQUIRED_FIELDS = frozenset(
    {
        "repository_commit",
        "artifact_manifest_algorithm",
        "artifact_manifest_format",
        "artifact_manifest_required",
        "artifact_manifest_sha256",
        "hashes_pending",
    }
)
_INTEGRITY_FIELDS = _INTEGRITY_REQUIRED_FIELDS | {"source_artifact_manifest_sha256", "materialization"}
_MATERIALIZATION_FIELDS = frozenset(
    {
        "declared_artifact_count",
        "usable_artifact_count",
        "error_count",
        "usable_artifact_manifest_sha256",
        "quarantine_manifest_sha256",
    }
)
_GATING_FIELDS = frozenset({"blocking", "tracks"})
_TRACK_FIELDS = frozenset({"name", "detector_profile", "protocol", "partition"})
_EXPECTED_FIELDS = frozenset({"row_counts", "schemas", "track_expectations"})
_TRACK_EXPECTATION_FIELDS = frozenset({"samples", "malicious", "benign", "population_sha256"})
_SCHEMA_FIELDS = frozenset({"exact_fields", "bundle_exact_fields"})
_PROVIDERS = frozenset({"github", "huggingface"})
_ACCESS_VALUES = frozenset({"public", "public_sanitized", "gated_manual", "gated_auto"})
_DOWNLOAD_POLICIES = frozenset(
    {
        "manual_authorized_environment_only",
        "manual_research_only",
        "metadata_only",
        "scheduled_or_manual",
        "prohibited",
        "scheduled_or_release_only",
        "scheduled_quarantine_only",
    }
)
_DETECTOR_PROFILES = frozenset({"core_only", "full_packs"})
_TRACK_PARTITIONS = frozenset({"train", "validation", "test", "excluded"})
_MAX_BUNDLE_FILES = 4_096
# The pinned MaliciousSkillBench corpus contains a reviewed 21,002,040-character
# SKILL.md hard negative. Keep enough headroom for its UTF-8 representation while
# retaining finite per-file and per-sample allocation bounds.
_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024
_MAX_PATH_BYTES = 1_024
_MAX_LOCK_BYTES = 4 * 1024 * 1024
_UNSAFE_TEXT_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_BLOCKED_BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".a",
        ".apk",
        ".ar",
        ".bin",
        ".bz2",
        ".cab",
        ".class",
        ".com",
        ".deb",
        ".dex",
        ".dll",
        ".dmg",
        ".doc",
        ".docm",
        ".docx",
        ".dylib",
        ".elf",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".iso",
        ".jar",
        ".jpeg",
        ".jpg",
        ".lib",
        ".lz",
        ".lz4",
        ".lzma",
        ".msi",
        ".o",
        ".pdb",
        ".pdf",
        ".png",
        ".pyc",
        ".rar",
        ".rpm",
        ".scr",
        ".so",
        ".sys",
        ".tar",
        ".tbz",
        ".tgz",
        ".tiff",
        ".wasm",
        ".whl",
        ".xls",
        ".xlsm",
        ".xlsx",
        ".xz",
        ".zip",
        ".zst",
    }
)

LOCKED_DATASET_IDS = frozenset(
    {
        "ProtectSkills/MaliciousSkillBench",
        "Miaow-Lab/OpenSkillRisk",
        "TrustAIRLab/HarmfulSkillBench",
        "ProtectSkills/MaliciousAgentSkillsBench",
        "OpenClaw/clawhub-security-signals",
        "LLM-LAT/harmful-dataset",
        "DataDog/malicious-software-packages-dataset",
        "uiuc-kang-lab/InjecAgent",
        "SoheilKhodayari/in_page_prompt_injection_pub",
        "InjecGuard/InjecGuard",
    }
)


class DatasetLockError(ValueError):
    """Raised when the dataset lock or supplied snapshot metadata is invalid."""


class DatasetSchemaError(ValueError):
    """Raised when a dataset row differs from its locked schema."""


class UnsafeSampleError(ValueError):
    """Raised when sample materialization would be unsafe or ambiguous."""


def load_dataset_lock(path: Path = LOCK_FILE) -> dict[str, Any]:
    """Load and validate the repository's dataset lock without network access."""

    path = Path(path)
    if path.is_symlink():
        raise DatasetLockError("dataset lock must be a regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DatasetLockError(f"cannot open dataset lock as a regular non-symlink file: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise DatasetLockError("dataset lock must be a regular file")
        if file_stat.st_size > _MAX_LOCK_BYTES:
            raise DatasetLockError(f"dataset lock exceeds the {_MAX_LOCK_BYTES}-byte safety limit")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            try:
                manifest = json.load(
                    handle,
                    object_pairs_hook=_reject_duplicate_lock_keys,
                    parse_constant=_reject_nonfinite_lock_number,
                )
            except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
                raise DatasetLockError(f"invalid dataset lock JSON: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _validate_lock(manifest)
    return cast(dict[str, Any], manifest)


def _reject_duplicate_lock_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetLockError(f"dataset lock contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_lock_number(value: str) -> None:
    raise DatasetLockError(f"dataset lock contains non-finite number {value}")


def _require_object_shape(
    value: Any,
    *,
    location: str,
    required: frozenset[str],
    allowed: frozenset[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DatasetLockError(f"{location} must be an object")
    keys = set(value)
    missing = sorted(required - keys)
    unexpected = sorted(keys - allowed)
    if missing or unexpected:
        raise DatasetLockError(f"{location} has invalid fields (missing={missing}, unexpected={unexpected})")
    return value


def _require_unique_strings(value: Any, *, location: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise DatasetLockError(f"{location} must be a{' possibly empty' if allow_empty else ' non-empty'} list")
    if not all(isinstance(item, str) and item for item in value) or len(value) != len(set(value)):
        raise DatasetLockError(f"{location} must contain unique non-empty strings")
    return value


def _validate_lock(manifest: Any) -> None:
    manifest = _require_object_shape(
        manifest,
        location="dataset lock",
        required=_LOCK_FIELDS,
        allowed=_LOCK_FIELDS,
    )
    if manifest.get("manifest_version") != 1:
        raise DatasetLockError("unsupported dataset lock manifest_version")
    if not isinstance(manifest.get("updated_at"), str) or not _DATE_RE.fullmatch(manifest["updated_at"]):
        raise DatasetLockError("dataset lock updated_at must use YYYY-MM-DD")

    safety_defaults = _require_object_shape(
        manifest.get("safety_defaults"),
        location="safety_defaults",
        required=_SAFETY_FIELDS,
        allowed=_SAFETY_FIELDS,
    )
    if safety_defaults.get("execute_samples") is not False:
        raise DatasetLockError("dataset lock must forbid sample execution")
    if safety_defaults.get("follow_embedded_links") is not False:
        raise DatasetLockError("dataset lock must forbid following embedded links")
    if safety_defaults.get("network_fetch_in_pull_requests") is not False:
        raise DatasetLockError("dataset lock must forbid pull-request network fetches")
    if safety_defaults.get("materialized_file_mode") != "0600":
        raise DatasetLockError("dataset lock materialized_file_mode must be 0600")

    datasets = manifest.get("datasets")
    if not isinstance(datasets, list) or not datasets:
        raise DatasetLockError("dataset lock must contain a non-empty datasets list")

    seen_ids: set[str] = set()
    for index, dataset in enumerate(datasets):
        dataset = _require_object_shape(
            dataset,
            location=f"datasets[{index}]",
            required=_DATASET_REQUIRED_FIELDS,
            allowed=_DATASET_FIELDS,
        )
        dataset_id = dataset.get("id")
        if not isinstance(dataset_id, str) or not dataset_id:
            raise DatasetLockError(f"datasets[{index}].id must be a non-empty string")
        if dataset_id in seen_ids:
            raise DatasetLockError(f"duplicate dataset id: {dataset_id}")
        seen_ids.add(dataset_id)

        if dataset.get("provider") not in _PROVIDERS:
            raise DatasetLockError(f"{dataset_id}: provider must be one of {sorted(_PROVIDERS)}")
        if dataset.get("access") not in _ACCESS_VALUES:
            raise DatasetLockError(f"{dataset_id}: access must be one of {sorted(_ACCESS_VALUES)}")
        if dataset.get("download_policy") not in _DOWNLOAD_POLICIES:
            raise DatasetLockError(f"{dataset_id}: download_policy must be one of {sorted(_DOWNLOAD_POLICIES)}")

        revision = dataset.get("revision")
        if not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
            raise DatasetLockError(f"{dataset_id}: revision must be a full lowercase 40-character commit SHA")
        integrity = _require_object_shape(
            dataset.get("integrity"),
            location=f"{dataset_id}.integrity",
            required=_INTEGRITY_REQUIRED_FIELDS,
            allowed=_INTEGRITY_FIELDS,
        )
        if integrity.get("repository_commit") != revision:
            raise DatasetLockError(f"{dataset_id}: integrity.repository_commit must match revision")
        if integrity.get("artifact_manifest_algorithm") != "sha256":
            raise DatasetLockError(f"{dataset_id}: artifact manifest algorithm must be sha256")
        if integrity.get("artifact_manifest_format") != "path-sha256-size-v1":
            raise DatasetLockError(f"{dataset_id}: unsupported artifact manifest format")
        if integrity.get("artifact_manifest_required") is not True:
            raise DatasetLockError(f"{dataset_id}: artifact manifest must be required")
        hashes_pending = integrity.get("hashes_pending")
        locked_manifest_digest = integrity.get("artifact_manifest_sha256")
        if not isinstance(hashes_pending, bool):
            raise DatasetLockError(f"{dataset_id}: integrity.hashes_pending must be boolean")
        if hashes_pending:
            if locked_manifest_digest is not None:
                raise DatasetLockError(f"{dataset_id}: pending artifact hashes must not declare a manifest digest")
        elif not isinstance(locked_manifest_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", locked_manifest_digest):
            raise DatasetLockError(f"{dataset_id}: pinned artifact hashes require a lowercase SHA-256 manifest digest")
        source_manifest_digest = integrity.get("source_artifact_manifest_sha256")
        if source_manifest_digest is not None and (
            not isinstance(source_manifest_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", source_manifest_digest)
        ):
            raise DatasetLockError(
                f"{dataset_id}: source_artifact_manifest_sha256 must be a lowercase SHA-256 when present"
            )
        materialization = integrity.get("materialization")
        if materialization is not None:
            materialization = _require_object_shape(
                materialization,
                location=f"{dataset_id}.integrity.materialization",
                required=_MATERIALIZATION_FIELDS,
                allowed=_MATERIALIZATION_FIELDS,
            )
            declared_count = materialization.get("declared_artifact_count")
            usable_count = materialization.get("usable_artifact_count")
            error_count = materialization.get("error_count")
            for field, count in (
                ("declared_artifact_count", declared_count),
                ("usable_artifact_count", usable_count),
                ("error_count", error_count),
            ):
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise DatasetLockError(
                        f"{dataset_id}: integrity.materialization.{field} must be a non-negative integer"
                    )
            declared_count = cast(int, declared_count)
            usable_count = cast(int, usable_count)
            error_count = cast(int, error_count)
            if declared_count == 0 or usable_count + error_count != declared_count:
                raise DatasetLockError(
                    f"{dataset_id}: materialization usable_artifact_count + error_count must equal "
                    "declared_artifact_count"
                )
            for field in ("usable_artifact_manifest_sha256", "quarantine_manifest_sha256"):
                digest = materialization.get(field)
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise DatasetLockError(
                        f"{dataset_id}: integrity.materialization.{field} must be a lowercase SHA-256"
                    )
            if hashes_pending:
                raise DatasetLockError(f"{dataset_id}: materialization metadata requires pinned artifact hashes")
        approved_uses = _require_unique_strings(
            dataset.get("approved_uses"), location=f"{dataset_id}.approved_uses", allow_empty=True
        )
        prohibited_uses = _require_unique_strings(
            dataset.get("prohibited_uses"), location=f"{dataset_id}.prohibited_uses"
        )
        if "execute_samples" not in prohibited_uses:
            raise DatasetLockError(f"{dataset_id}: prohibited_uses must include execute_samples")
        if dataset.get("download_policy") == "prohibited" and approved_uses:
            raise DatasetLockError(f"{dataset_id}: prohibited datasets may not declare approved uses")

        license_info = _require_object_shape(
            dataset.get("license"),
            location=f"{dataset_id}.license",
            required=frozenset({"spdx", "scope"}),
            allowed=_LICENSE_FIELDS,
        )
        if license_info.get("spdx") is not None and (
            not isinstance(license_info["spdx"], str) or not license_info["spdx"]
        ):
            raise DatasetLockError(f"{dataset_id}: license.spdx must be a non-empty string or null")
        if "code_spdx" in license_info and (
            not isinstance(license_info["code_spdx"], str) or not license_info["code_spdx"]
        ):
            raise DatasetLockError(f"{dataset_id}: license.code_spdx must be a non-empty string")
        if not isinstance(license_info.get("scope"), str) or not license_info["scope"]:
            raise DatasetLockError(f"{dataset_id}: license.scope must be a non-empty string")

        gating = _require_object_shape(
            dataset.get("gating"),
            location=f"{dataset_id}.gating",
            required=_GATING_FIELDS,
            allowed=_GATING_FIELDS,
        )
        if not isinstance(gating.get("blocking"), bool):
            raise DatasetLockError(f"{dataset_id}: gating.blocking must be boolean")
        if not isinstance(gating.get("tracks"), list):
            raise DatasetLockError(f"{dataset_id}: gating.tracks must be a list")
        if hashes_pending and gating["blocking"]:
            raise DatasetLockError(f"{dataset_id}: datasets with pending artifact hashes cannot block")
        track_names: set[str] = set()
        track_protocols: set[str] = set()
        for track_index, track in enumerate(gating["tracks"]):
            track = _require_object_shape(
                track,
                location=f"{dataset_id}.gating.tracks[{track_index}]",
                required=_TRACK_FIELDS,
                allowed=_TRACK_FIELDS,
            )
            if not all(isinstance(track[field], str) and track[field] for field in _TRACK_FIELDS):
                raise DatasetLockError(f"{dataset_id}: every gating track value must be a non-empty string")
            if track["name"] in track_names or track["protocol"] in track_protocols:
                raise DatasetLockError(f"{dataset_id}: gating track names and protocols must be unique")
            track_names.add(track["name"])
            track_protocols.add(track["protocol"])
            if track["detector_profile"] not in _DETECTOR_PROFILES:
                raise DatasetLockError(f"{dataset_id}: detector_profile must be one of {sorted(_DETECTOR_PROFILES)}")
            if track["partition"] not in _TRACK_PARTITIONS:
                raise DatasetLockError(f"{dataset_id}: track partition must be one of {sorted(_TRACK_PARTITIONS)}")

        known_issues = dataset.get("known_issues")
        if known_issues is not None:
            _require_unique_strings(known_issues, location=f"{dataset_id}.known_issues")

        expected = dataset.get("expected", {})
        expected = _require_object_shape(
            expected,
            location=f"{dataset_id}.expected",
            required=frozenset(),
            allowed=_EXPECTED_FIELDS,
        )
        row_counts = expected.get("row_counts", {})
        if not isinstance(row_counts, Mapping):
            raise DatasetLockError(f"{dataset_id}: expected.row_counts must be an object")
        for partition, row_count in row_counts.items():
            if (
                not isinstance(partition, str)
                or partition.count("/") != 1
                or not all(partition_part for partition_part in partition.split("/"))
            ):
                raise DatasetLockError(f"{dataset_id}: row-count keys must use config/split")
            if isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0:
                raise DatasetLockError(f"{dataset_id}/{partition}: row count must be a non-negative integer")

        track_expectations = expected.get("track_expectations", {})
        if not isinstance(track_expectations, Mapping):
            raise DatasetLockError(f"{dataset_id}: expected.track_expectations must be an object")
        for track_name, raw_expectation in track_expectations.items():
            if not isinstance(track_name, str) or not track_name:
                raise DatasetLockError(f"{dataset_id}: track-expectation keys must be non-empty strings")
            expectation = _require_object_shape(
                raw_expectation,
                location=f"{dataset_id}.expected.track_expectations.{track_name}",
                required=_TRACK_EXPECTATION_FIELDS,
                allowed=_TRACK_EXPECTATION_FIELDS,
            )
            for field in ("samples", "malicious", "benign"):
                count = expectation.get(field)
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise DatasetLockError(f"{dataset_id}/{track_name}: {field} must be a non-negative integer")
            if (
                expectation["samples"] <= 0
                or expectation["malicious"] + expectation["benign"] != expectation["samples"]
            ):
                raise DatasetLockError(
                    f"{dataset_id}/{track_name}: malicious + benign must equal a positive samples count"
                )
            population_digest = expectation.get("population_sha256")
            if not isinstance(population_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", population_digest):
                raise DatasetLockError(f"{dataset_id}/{track_name}: population_sha256 must be a lowercase SHA-256")

        schemas = expected.get("schemas", {})
        if not isinstance(schemas, Mapping):
            raise DatasetLockError(f"{dataset_id}: expected.schemas must be an object")
        for schema_name, schema in schemas.items():
            if not isinstance(schema_name, str) or not schema_name:
                raise DatasetLockError(f"{dataset_id}: schema names must be non-empty strings")
            schema = _require_object_shape(
                schema,
                location=f"{dataset_id}/{schema_name}",
                required=frozenset({"exact_fields"}),
                allowed=_SCHEMA_FIELDS,
            )
            _require_unique_strings(schema.get("exact_fields"), location=f"{dataset_id}/{schema_name}.exact_fields")
            if "bundle_exact_fields" in schema:
                _require_unique_strings(
                    schema["bundle_exact_fields"],
                    location=f"{dataset_id}/{schema_name}.bundle_exact_fields",
                )

        if gating["tracks"]:
            required_row_counts = {"primary/train"} | {f"splits/{track['protocol']}" for track in gating["tracks"]}
            missing_row_counts = sorted(required_row_counts - set(row_counts))
            if missing_row_counts:
                raise DatasetLockError(
                    f"{dataset_id}: benchmark tracks are missing locked row counts: {missing_row_counts}"
                )
            missing_schemas = sorted({"primary", "split_manifest"} - set(schemas))
            if missing_schemas:
                raise DatasetLockError(f"{dataset_id}: benchmark tracks are missing locked schemas: {missing_schemas}")
            expected_track_names = {track["name"] for track in gating["tracks"]}
            if set(track_expectations) != expected_track_names:
                raise DatasetLockError(
                    f"{dataset_id}: expected.track_expectations must contain exactly {sorted(expected_track_names)}"
                )

    missing_datasets = sorted(LOCKED_DATASET_IDS - seen_ids)
    if missing_datasets:
        raise DatasetLockError(f"dataset lock is missing approved entries: {missing_datasets}")
    unexpected_datasets = sorted(seen_ids - LOCKED_DATASET_IDS)
    if unexpected_datasets:
        raise DatasetLockError(f"dataset lock contains unapproved entries: {unexpected_datasets}")
    blocking_datasets = {dataset["id"] for dataset in datasets if dataset["gating"]["blocking"]}
    if blocking_datasets - {"ProtectSkills/MaliciousSkillBench"}:
        raise DatasetLockError("only MaliciousSkillBench may be a blocking public dataset")


def get_locked_dataset(dataset_id: str, manifest: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    """Return one locked dataset entry or raise for an unknown identifier."""

    loaded: Mapping[str, Any]
    if manifest is None:
        loaded = load_dataset_lock()
    else:
        _validate_lock(manifest)
        loaded = manifest
    for dataset in loaded["datasets"]:
        if dataset["id"] == dataset_id:
            return cast(Mapping[str, Any], dataset)
    raise DatasetLockError(f"dataset is not approved in the lock: {dataset_id}")


def validate_snapshot_metadata(
    dataset_id: str,
    *,
    revision: str,
    config: str,
    split: str,
    fields: Sequence[str] | None = None,
    schema_name: str | None = None,
    row_count: int | None = None,
    manifest: Mapping[str, Any] | None = None,
) -> None:
    """Validate caller-supplied Hub metadata against the pinned contract."""

    dataset = get_locked_dataset(dataset_id, manifest)
    if revision != dataset["revision"]:
        raise DatasetLockError(f"{dataset_id}: revision drift (expected {dataset['revision']}, received {revision})")
    if not isinstance(config, str) or not config or "/" in config:
        raise DatasetSchemaError(f"{dataset_id}: config must be a non-empty path-free string")
    if not isinstance(split, str) or not split or "/" in split:
        raise DatasetSchemaError(f"{dataset_id}: split must be a non-empty path-free string")
    if row_count is not None and (isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0):
        raise DatasetSchemaError(f"{dataset_id}: row_count must be a non-negative integer")
    if fields is not None:
        if (
            isinstance(fields, (str, bytes))
            or not isinstance(fields, Sequence)
            or not all(isinstance(field, str) and field for field in fields)
            or len(fields) != len(set(fields))
        ):
            raise DatasetSchemaError(f"{dataset_id}: fields must contain unique non-empty strings")

    expected = dataset.get("expected", {})
    partition = f"{config}/{split}"
    locked_row_counts = expected.get("row_counts", {})
    if not locked_row_counts:
        raise DatasetSchemaError(f"{dataset_id}: no locked row counts are available for ingestion")
    if partition not in locked_row_counts:
        raise DatasetSchemaError(f"{dataset_id}: no locked partition named {partition}")
    expected_rows = locked_row_counts.get(partition)
    if expected_rows is not None:
        if row_count is None:
            raise DatasetSchemaError(f"{dataset_id}/{partition}: locked row count must be supplied")
        if row_count != expected_rows:
            raise DatasetSchemaError(
                f"{dataset_id}/{partition}: row-count drift (expected {expected_rows}, received {row_count})"
            )

    selected_schema = schema_name or config
    locked_schemas = expected.get("schemas", {})
    if not locked_schemas:
        raise DatasetSchemaError(f"{dataset_id}: no locked schemas are available for ingestion")
    schema = locked_schemas.get(selected_schema)
    if schema is not None and fields is None:
        raise DatasetSchemaError(f"{dataset_id}/{selected_schema}: locked schema fields must be supplied")
    if fields is not None:
        if schema is None:
            raise DatasetSchemaError(f"{dataset_id}: no locked schema named {selected_schema}")
        _require_exact_fields(dataset_id, selected_schema, fields, schema["exact_fields"])


def validate_locked_row(
    dataset_id: str,
    schema_name: str,
    row: Mapping[str, Any],
    manifest: Mapping[str, Any] | None = None,
) -> None:
    """Reject missing or additional fields relative to the locked row schema."""

    if not isinstance(row, Mapping):
        raise DatasetSchemaError(f"{dataset_id}/{schema_name}: row must be an object")
    dataset = get_locked_dataset(dataset_id, manifest)
    schema = dataset.get("expected", {}).get("schemas", {}).get(schema_name)
    if schema is None:
        raise DatasetSchemaError(f"{dataset_id}: no locked schema named {schema_name}")
    _require_exact_fields(dataset_id, schema_name, row.keys(), schema["exact_fields"])

    if "bundle_exact_fields" in schema:
        bundle = row.get("skill_bundle_content")
        if not isinstance(bundle, list):
            raise DatasetSchemaError(f"{dataset_id}/{schema_name}: skill_bundle_content must be a list")
        for index, entry in enumerate(bundle):
            if not isinstance(entry, Mapping):
                raise DatasetSchemaError(f"{dataset_id}/{schema_name}: skill_bundle_content[{index}] must be an object")
            _require_exact_fields(
                dataset_id,
                f"{schema_name}.skill_bundle_content[{index}]",
                entry.keys(),
                schema["bundle_exact_fields"],
            )


def _require_exact_fields(
    dataset_id: str,
    schema_name: str,
    actual_fields: Sequence[str] | Any,
    expected_fields: Sequence[str],
) -> None:
    actual = set(actual_fields)
    expected = set(expected_fields)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details = []
    if missing:
        details.append(f"missing={missing}")
    if unexpected:
        details.append(f"unexpected={unexpected}")
    raise DatasetSchemaError(f"{dataset_id}/{schema_name}: schema drift ({', '.join(details)})")


def _validated_relative_path(
    raw_path: Any,
    *,
    allow_root_skill: bool = False,
    allow_binary: bool = False,
) -> PurePosixPath:
    if not isinstance(raw_path, str) or not raw_path:
        raise UnsafeSampleError("bundle path must be a non-empty string")
    if "\x00" in raw_path or "\\" in raw_path or _DRIVE_PATH_RE.match(raw_path):
        raise UnsafeSampleError(f"unsafe or platform-ambiguous bundle path: {raw_path!r}")
    try:
        encoded_path = raw_path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UnsafeSampleError("bundle path must be valid UTF-8") from exc
    if len(encoded_path) > _MAX_PATH_BYTES:
        raise UnsafeSampleError(f"bundle path exceeds {_MAX_PATH_BYTES} UTF-8 bytes")
    raw_parts = raw_path.split("/")
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in ("", ".", "..") for part in raw_parts):
        raise UnsafeSampleError(f"bundle path must be a normalized relative path: {raw_path!r}")
    if any(any(ord(character) < 32 or ord(character) == 127 for character in part) for part in raw_parts):
        raise UnsafeSampleError(f"bundle path contains control characters: {raw_path!r}")
    if any(len(part.encode("utf-8")) > 255 for part in raw_parts):
        raise UnsafeSampleError("bundle path contains a component longer than 255 UTF-8 bytes")
    if any(part.endswith((" ", ".")) or ":" in part for part in raw_parts):
        raise UnsafeSampleError(f"bundle path is not portable across supported platforms: {raw_path!r}")
    if any(part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES for part in raw_parts):
        raise UnsafeSampleError(f"bundle path uses a reserved platform name: {raw_path!r}")
    if not allow_root_skill and path.as_posix().casefold() == "skill.md":
        raise UnsafeSampleError("bundle content may not replace SKILL.md")
    if not allow_binary and path.suffix.casefold() in _BLOCKED_BINARY_SUFFIXES:
        raise UnsafeSampleError(f"bundle path has an unexpected binary or archive type: {raw_path!r}")
    return path


def _path_collision_key(path: PurePosixPath) -> str:
    return unicodedata.normalize("NFKC", path.as_posix()).casefold()


def artifact_manifest_sha256(
    dataset_id: str,
    artifacts: object,
    *,
    manifest: Mapping[str, Any] | None = None,
) -> str:
    """Return the canonical digest for an acquisition-produced file manifest.

    The function never opens artifact paths. Acquisition code supplies the
    already-computed hashes; the pinned commit remains the identity anchor.
    """

    dataset = get_locked_dataset(dataset_id, manifest)
    if isinstance(artifacts, (str, bytes)) or not isinstance(artifacts, Sequence) or not artifacts:
        raise DatasetSchemaError("artifact manifest must contain at least one file")

    canonical_artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, Mapping) or set(artifact) != _ARTIFACT_FIELDS:
            raise DatasetSchemaError(f"artifact manifest entry {index} has unexpected fields")
        path = _validated_relative_path(
            artifact["path"],
            allow_root_skill=True,
            allow_binary=True,
        )
        collision_key = _path_collision_key(path)
        if collision_key in seen_paths:
            raise DatasetSchemaError(f"duplicate or normalization-colliding artifact path: {path}")
        seen_paths.add(collision_key)

        digest = artifact["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DatasetSchemaError(f"artifact manifest entry {index} has an invalid SHA-256")
        size = artifact["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise DatasetSchemaError(f"artifact manifest entry {index} has an invalid size_bytes")
        canonical_artifacts.append({"path": path.as_posix(), "sha256": digest, "size_bytes": size})

    canonical_artifacts.sort(key=lambda item: _path_collision_key(PurePosixPath(item["path"])))
    canonical_payload = {
        "dataset_id": dataset_id,
        "format": dataset["integrity"]["artifact_manifest_format"],
        "revision": dataset["revision"],
        "artifacts": canonical_artifacts,
    }
    encoded = json.dumps(
        canonical_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def quarantine_manifest_sha256(
    dataset_id: str,
    records: object,
    *,
    declared_artifact_manifest_sha256: str,
    manifest: Mapping[str, Any] | None = None,
) -> str:
    """Return a canonical digest for explicitly unavailable snapshot members.

    Quarantine records contain identity and declared file metadata only. They
    never contain sample text, and they remain part of the declared artifact
    manifest and dataset denominator.
    """

    dataset = get_locked_dataset(dataset_id, manifest)
    if not isinstance(declared_artifact_manifest_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", declared_artifact_manifest_sha256
    ):
        raise DatasetSchemaError("declared artifact manifest digest must be a lowercase SHA-256")
    locked_digest = dataset["integrity"]["artifact_manifest_sha256"]
    if locked_digest is not None and declared_artifact_manifest_sha256 != locked_digest:
        raise DatasetSchemaError(f"{dataset_id}: quarantine manifest refers to an unpinned artifact manifest")
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence) or not records:
        raise DatasetSchemaError("quarantine manifest must contain at least one record")

    # Quarantine evidence covers every pinned source split, including
    # supplemental protocols that are intentionally absent from release gates.
    # Do not let narrowing the blocking track set invalidate those immutable
    # source-artifact records.
    protocols = {track["protocol"] for track in dataset["gating"]["tracks"]}
    row_counts = dataset.get("expected", {}).get("row_counts", {})
    if isinstance(row_counts, Mapping):
        protocols.update(
            key.removeprefix("splits/")
            for key in row_counts
            if isinstance(key, str) and key.startswith("splits/") and key.removeprefix("splits/")
        )
    canonical_records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, raw_record in enumerate(records):
        if not isinstance(raw_record, Mapping) or set(raw_record) != _QUARANTINE_RECORD_FIELDS:
            raise DatasetSchemaError(f"quarantine manifest record {index} has unexpected fields")
        record = dict(raw_record)
        benchmark_id = record["benchmark_id"]
        if not isinstance(benchmark_id, str) or not benchmark_id or "\x00" in benchmark_id:
            raise DatasetSchemaError(f"quarantine manifest record {index} has an invalid benchmark_id")
        if benchmark_id in seen_ids:
            raise DatasetSchemaError(f"duplicate quarantined benchmark_id: {benchmark_id}")
        seen_ids.add(benchmark_id)

        path = _validated_relative_path(record["path"], allow_root_skill=True, allow_binary=True).as_posix()
        collision_key = _path_collision_key(PurePosixPath(path))
        if collision_key in seen_paths:
            raise DatasetSchemaError(f"duplicate or normalization-colliding quarantined path: {path}")
        seen_paths.add(collision_key)
        if not path.endswith("/SKILL.md"):
            raise DatasetSchemaError(f"quarantined classification artifact must be SKILL.md: {path}")

        label = record["label"]
        if label not in {"malicious", "benign"}:
            raise DatasetSchemaError(f"quarantine manifest record {index} has an invalid label")
        for field in ("source_id", "structural_family_id", "error_code"):
            value = record[field]
            if not isinstance(value, str) or not value or "\x00" in value:
                raise DatasetSchemaError(f"quarantine manifest record {index} has an invalid {field}")

        splits = record["splits"]
        if not isinstance(splits, Mapping) or set(splits) != protocols:
            raise DatasetSchemaError(
                f"quarantine manifest record {index} splits must contain exactly {sorted(protocols)}"
            )
        if any(not isinstance(partition, str) or partition not in _TRACK_PARTITIONS for partition in splits.values()):
            raise DatasetSchemaError(f"quarantine manifest record {index} has an invalid split partition")

        digest = record["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DatasetSchemaError(f"quarantine manifest record {index} has an invalid SHA-256")
        size = record["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise DatasetSchemaError(f"quarantine manifest record {index} has an invalid size_bytes")

        canonical_records.append(
            {
                "benchmark_id": benchmark_id,
                "error_code": record["error_code"],
                "label": label,
                "path": path,
                "sha256": digest,
                "size_bytes": size,
                "source_id": record["source_id"],
                "splits": dict(sorted(splits.items())),
                "structural_family_id": record["structural_family_id"],
            }
        )

    canonical_records.sort(key=lambda item: (_path_collision_key(PurePosixPath(item["path"])), item["path"]))
    payload = {
        "dataset_id": dataset_id,
        "declared_artifact_manifest_sha256": declared_artifact_manifest_sha256,
        "format": "quarantine-manifest-v1",
        "records": canonical_records,
        "revision": dataset["revision"],
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_quarantine_manifest(
    dataset_id: str,
    records: object,
    *,
    declared_artifact_manifest_sha256: str,
    manifest_sha256: str,
    manifest: Mapping[str, Any] | None = None,
) -> str:
    """Validate quarantine metadata against the counts and digest in the lock."""

    dataset = get_locked_dataset(dataset_id, manifest)
    materialization = dataset["integrity"].get("materialization")
    if not isinstance(materialization, Mapping):
        raise DatasetSchemaError(f"{dataset_id}: no materialization metadata is pinned")
    locked_quarantine_digest = materialization["quarantine_manifest_sha256"]
    if manifest_sha256 != locked_quarantine_digest:
        raise DatasetSchemaError(f"{dataset_id}: quarantine manifest does not match the digest pinned in the lock")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise DatasetSchemaError("quarantine manifest records must be a sequence")
    if len(records) != materialization["error_count"]:
        raise DatasetSchemaError(
            f"{dataset_id}: quarantine record count drift "
            f"(expected {materialization['error_count']}, received {len(records)})"
        )
    actual_digest = quarantine_manifest_sha256(
        dataset_id,
        records,
        declared_artifact_manifest_sha256=declared_artifact_manifest_sha256,
        manifest=manifest,
    )
    if actual_digest != manifest_sha256:
        raise DatasetSchemaError(
            f"{dataset_id}: quarantine manifest digest mismatch (expected {manifest_sha256}, received {actual_digest})"
        )
    return actual_digest


def validate_artifact_manifest(
    dataset_id: str,
    artifacts: object,
    *,
    manifest_sha256: str,
    manifest: Mapping[str, Any] | None = None,
) -> str:
    """Validate file metadata against an independently persisted manifest digest."""

    if not isinstance(manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise DatasetSchemaError("artifact manifest digest must be a lowercase SHA-256")
    dataset = get_locked_dataset(dataset_id, manifest)
    locked_digest = dataset["integrity"]["artifact_manifest_sha256"]
    if locked_digest is not None and manifest_sha256 != locked_digest:
        raise DatasetSchemaError(
            f"{dataset_id}: artifact manifest does not match the digest pinned in the dataset lock"
        )
    actual_digest = artifact_manifest_sha256(dataset_id, artifacts, manifest=manifest)
    if actual_digest != manifest_sha256:
        raise DatasetSchemaError(
            f"{dataset_id}: artifact manifest digest mismatch (expected {manifest_sha256}, received {actual_digest})"
        )
    return actual_digest


def validate_source_artifact_manifest(
    dataset_id: str,
    artifacts: object,
    *,
    manifest: Mapping[str, Any] | None = None,
) -> str:
    """Validate upstream acquisition inputs against their separate pinned digest.

    Source artifacts (for example Parquet and schema files) are provenance for
    materialization.  Their digest does not stand in for the derived snapshot
    digest used by release evidence.
    """

    dataset = get_locked_dataset(dataset_id, manifest)
    locked_digest = dataset["integrity"].get("source_artifact_manifest_sha256")
    if locked_digest is None:
        raise DatasetSchemaError(f"{dataset_id}: no source artifact manifest is pinned")
    actual_digest = artifact_manifest_sha256(dataset_id, artifacts, manifest=manifest)
    if actual_digest != locked_digest:
        raise DatasetSchemaError(
            f"{dataset_id}: source artifact manifest does not match the digest pinned in the dataset lock"
        )
    return actual_digest


def _validate_bundle_files(
    bundle_files: object,
) -> tuple[list[tuple[PurePosixPath, str]], int]:
    if isinstance(bundle_files, (str, bytes)) or not isinstance(bundle_files, Sequence):
        raise DatasetSchemaError("bundle_files must be a sequence of file objects")
    if len(bundle_files) > _MAX_BUNDLE_FILES:
        raise DatasetSchemaError(f"bundle exceeds the {_MAX_BUNDLE_FILES}-file safety limit")
    typed_bundle_files = cast(Sequence[Mapping[str, Any]], bundle_files)

    validated: list[tuple[PurePosixPath, str]] = []
    seen_casefolded: set[str] = set()
    path_parts: list[tuple[str, ...]] = []
    total_bytes = 0

    for index, entry in enumerate(typed_bundle_files):
        if not isinstance(entry, Mapping):
            raise DatasetSchemaError(f"bundle[{index}] must be an object")
        if any(key in entry for key in ("symlink", "is_symlink", "link_target")) or entry.get("type") == "symlink":
            raise UnsafeSampleError(f"bundle[{index}] describes a symlink")
        if set(entry) != _BUNDLE_FIELDS:
            missing = sorted(_BUNDLE_FIELDS - set(entry))
            unexpected = sorted(set(entry) - _BUNDLE_FIELDS)
            raise DatasetSchemaError(f"bundle[{index}] schema drift (missing={missing}, unexpected={unexpected})")

        path = _validated_relative_path(entry["path"])
        casefolded = _path_collision_key(path)
        if casefolded in seen_casefolded:
            raise UnsafeSampleError(f"duplicate or case-colliding bundle path: {path}")
        seen_casefolded.add(casefolded)

        content = entry["content"]
        if not isinstance(content, str):
            raise DatasetSchemaError(f"bundle[{index}].content must be text")
        if "\x00" in content:
            raise DatasetSchemaError(f"bundle[{index}].content contains a binary NUL byte")
        if _UNSAFE_TEXT_CONTROL_RE.search(content):
            raise DatasetSchemaError(f"bundle[{index}].content contains non-text control bytes")
        try:
            encoded = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DatasetSchemaError(f"bundle[{index}].content must be valid UTF-8") from exc
        if len(encoded) > _MAX_FILE_BYTES:
            raise DatasetSchemaError(f"bundle[{index}] exceeds the {_MAX_FILE_BYTES}-byte file limit")
        total_bytes += len(encoded)
        if total_bytes > _MAX_TOTAL_BYTES:
            raise DatasetSchemaError(f"bundle exceeds the {_MAX_TOTAL_BYTES}-byte aggregate limit")
        if isinstance(entry["sizeBytes"], bool) or not isinstance(entry["sizeBytes"], int):
            raise DatasetSchemaError(f"bundle[{index}].sizeBytes must be an integer")
        if entry["sizeBytes"] != len(encoded):
            raise DatasetSchemaError(f"bundle[{index}] sizeBytes does not match UTF-8 content")
        digest = hashlib.sha256(encoded).hexdigest()
        if not isinstance(entry["sha256"], str) or entry["sha256"].lower() != digest:
            raise DatasetSchemaError(f"bundle[{index}] sha256 does not match content")

        validated.append((path, content))
        path_parts.append(tuple(unicodedata.normalize("NFKC", part).casefold() for part in path.parts))

    for index, parts in enumerate(path_parts):
        for other_index, other_parts in enumerate(path_parts):
            if index == other_index:
                continue
            if len(parts) < len(other_parts) and other_parts[: len(parts)] == parts:
                raise UnsafeSampleError(f"bundle path is both a file and a parent directory: {validated[index][0]}")
    return validated, total_bytes


def _write_new_text(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def _ensure_no_symlink_ancestors(path: Path) -> None:
    current = path.absolute().parent
    while True:
        if current.is_symlink():
            raise UnsafeSampleError(f"destination ancestor must not be a symlink: {current}")
        if current.parent == current:
            return
        current = current.parent


def _remove_partial_destination(destination: Path) -> None:
    if destination.is_symlink():
        destination.unlink(missing_ok=True)
    elif destination.exists():
        shutil.rmtree(destination)


def materialize_skill_files(
    *,
    skill_md_content: str,
    bundle_files: Sequence[Mapping[str, Any]],
    destination: Path,
) -> Path:
    """Materialize text-only files into a new non-executable directory.

    All input is validated before the destination is created. Existing paths,
    symlinks, absolute/traversing paths, duplicate paths, binary content, and
    hash/size mismatches are rejected.
    """

    if not isinstance(skill_md_content, str) or not skill_md_content:
        raise DatasetSchemaError("skill_md_content must be non-empty text")
    if "\x00" in skill_md_content:
        raise DatasetSchemaError("skill_md_content contains a binary NUL byte")
    if _UNSAFE_TEXT_CONTROL_RE.search(skill_md_content):
        raise DatasetSchemaError("skill_md_content contains non-text control bytes")
    try:
        skill_md_bytes = skill_md_content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DatasetSchemaError("skill_md_content must be valid UTF-8") from exc
    if len(skill_md_bytes) > _MAX_FILE_BYTES:
        raise DatasetSchemaError(f"skill_md_content exceeds the {_MAX_FILE_BYTES}-byte file limit")
    validated_files, bundle_bytes = _validate_bundle_files(bundle_files)
    if len(skill_md_bytes) + bundle_bytes > _MAX_TOTAL_BYTES:
        raise DatasetSchemaError(f"sample exceeds the {_MAX_TOTAL_BYTES}-byte aggregate limit")

    destination = Path(destination)
    if destination.is_symlink() or destination.exists():
        raise UnsafeSampleError(f"destination must be a new non-symlink path: {destination}")
    if not destination.parent.is_dir():
        raise UnsafeSampleError(f"destination parent must already exist: {destination.parent}")
    _ensure_no_symlink_ancestors(destination)

    destination.mkdir(mode=0o700)
    try:
        _write_new_text(destination / "SKILL.md", skill_md_content)
        for relative_path, content in validated_files:
            output_path = destination.joinpath(*relative_path.parts)
            output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_new_text(output_path, content)
    except BaseException:
        _remove_partial_destination(destination)
        raise
    return destination.resolve(strict=True)


def materialize_locked_skill_row(
    dataset_id: str,
    row: Mapping[str, Any],
    destination: Path,
    manifest: Mapping[str, Any] | None = None,
) -> Path:
    """Materialize a supported locked row for static scanning only."""

    if dataset_id == "OpenClaw/clawhub-security-signals":
        validate_locked_row(dataset_id, "default", row, manifest)
        return materialize_skill_files(
            skill_md_content=row["skill_md_content"],
            bundle_files=row["skill_bundle_content"],
            destination=destination,
        )

    if dataset_id == "ProtectSkills/MaliciousSkillBench":
        validate_locked_row(dataset_id, "primary", row, manifest)
        for field in ("text_available", "text_redacted", "original_text_withheld"):
            if type(row[field]) is not bool:
                raise DatasetSchemaError(f"MaliciousSkillBench {field} must be boolean")
        skill_text = row["skill_text"] if row["skill_text"] is not None else row["public_skill_text"]
        if not isinstance(skill_text, str) or not skill_text:
            raise DatasetSchemaError("MaliciousSkillBench row has no public-readable skill text")
        if row["text_available"] != (row["skill_text"] is not None):
            raise DatasetSchemaError("MaliciousSkillBench text_available disagrees with skill_text")
        if row["original_text_withheld"] and row["skill_text"] is not None:
            raise DatasetSchemaError("withheld original must not be present as skill_text")
        if row["public_skill_text"] is not None:
            if not isinstance(row["public_skill_text"], str) or not row["public_skill_text"]:
                raise DatasetSchemaError("MaliciousSkillBench public_skill_text must be non-empty text when present")
            public_digest = hashlib.sha256(row["public_skill_text"].encode("utf-8")).hexdigest()
            if row["public_text_sha256"] != public_digest:
                raise DatasetSchemaError("MaliciousSkillBench public_text_sha256 does not match public text")
        elif row["public_text_sha256"] is not None:
            raise DatasetSchemaError("MaliciousSkillBench public_text_sha256 must be null without public text")
        return materialize_skill_files(
            skill_md_content=skill_text,
            bundle_files=[],
            destination=destination,
        )

    raise DatasetLockError(f"dataset has no approved static materializer: {dataset_id}")
