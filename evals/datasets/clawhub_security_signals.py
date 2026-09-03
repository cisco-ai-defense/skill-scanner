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

"""Offline adapter for the pinned ClawHub security-signals JSONL snapshot.

The upstream verdicts are automated, silver-standard signals.  This adapter
therefore exposes them for drift and disagreement analysis only.  It has no
download, archive, import, execution, or network path.

Only raw ``data/<split>.jsonl`` files are accepted.  The stale Hugging Face
Parquet conversion is intentionally unsupported.  Each selected raw file is
bound to the repository dataset lock (revision, schema, and row count) and to
a narrow raw-snapshot lock (path, byte size, SHA-256, and silver-label counts).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, cast

from evals.datasets.public_datasets import (
    DatasetLockError,
    DatasetSchemaError,
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    validate_locked_row,
)

DATASET_ID = "OpenClaw/clawhub-security-signals"
RAW_CONTRACT_FILE = Path(__file__).with_name("clawhub-security-signals.raw.lock.json")
SPLIT_ORDER = ("train", "validation", "test", "eval_holdout")

_CONTRACT_FIELDS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "revision",
        "config",
        "raw_format",
        "artifact_manifest_sha256",
        "schema",
        "splits",
        "quality",
        "safety",
        "use_policy",
    }
)
_SPLIT_FIELDS = frozenset({"path", "rows", "silver_label_counts", "size_bytes", "sha256"})
_QUALITY_FIELDS = frozenset(
    {
        "total_rows",
        "silver_label_counts",
        "unique_ids_within_splits",
        "bundle_hash_and_size_mismatches",
        "unsafe_bundle_paths",
    }
)
_SAFETY_FIELDS = frozenset({"sample_code_executed", "network_allowed", "raw_content_persisted_in_repository"})
_USE_POLICY_FIELDS = frozenset({"label_standard", "release_blocking", "precision_or_fpr_eligible"})
_VERDICTS = frozenset({"clean", "suspicious", "malicious"})
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RAW_CONTRACT_BYTES = 4 * 1024 * 1024
_MAX_SPLIT_BYTES = 1024 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 128 * 1024 * 1024
_MAX_ROWS_PER_SPLIT = 1_000_000
_MAX_ID_BYTES = 1_024
_READ_CHUNK_BYTES = 1024 * 1024


class ClawhubSecuritySignalsError(ValueError):
    """Raised when a local raw snapshot is unsafe or differs from its pins."""


@dataclass(frozen=True)
class ClawhubSplitContract:
    """Immutable identity and population contract for one raw JSONL split."""

    name: str
    relative_path: Path
    rows: int
    size_bytes: int
    sha256: str
    silver_label_counts: Mapping[str, int]


@dataclass(frozen=True)
class ClawhubSecuritySignalsSnapshot:
    """Validated metadata for selected local split files."""

    root: Path
    revision: str
    schema: tuple[str, ...]
    raw_contract_sha256: str
    raw_artifact_manifest_sha256: str
    repository_artifact_manifest_pinned: bool
    splits: tuple[ClawhubSplitContract, ...]
    lock_manifest: Mapping[str, Any] = field(repr=False, compare=False)

    @property
    def population(self) -> int:
        return sum(split.rows for split in self.splits)


@dataclass(frozen=True)
class ClawhubRowRecord:
    """One physical JSONL row, including rows that cannot be ingested."""

    split: str
    line_number: int
    row_id: str
    row: Mapping[str, Any] | None
    silver_verdict: str | None
    provenance: Mapping[str, str]
    grouping: Mapping[str, str]
    ingestion_error: str | None


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ClawhubSecuritySignalsError(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _reject_nonfinite_number(value: str) -> None:
    raise ClawhubSecuritySignalsError(f"JSON contains non-finite number {value}")


def _read_regular_bytes(path: Path, *, limit: int, label: str) -> bytes:
    if path.is_symlink():
        raise ClawhubSecuritySignalsError(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ClawhubSecuritySignalsError(f"cannot safely open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ClawhubSecuritySignalsError(f"{label} must be a regular file")
        if opened.st_size > limit:
            raise ClawhubSecuritySignalsError(f"{label} exceeds the {limit}-byte limit")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(limit + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > limit:
        raise ClawhubSecuritySignalsError(f"{label} exceeds the {limit}-byte limit")
    return content


def _load_raw_contract(path: Path) -> Mapping[str, Any]:
    raw = _read_regular_bytes(path, limit=_MAX_RAW_CONTRACT_BYTES, label="ClawHub raw-snapshot lock")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ClawhubSecuritySignalsError(f"invalid ClawHub raw-snapshot lock JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock must be an object")
    if set(value) != _CONTRACT_FIELDS:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock schema drift")
    safety = value.get("safety")
    if not isinstance(safety, Mapping) or set(safety) != _SAFETY_FIELDS:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot safety contract drift")
    if any(
        safety.get(field) is not False
        for field in ("sample_code_executed", "network_allowed", "raw_content_persisted_in_repository")
    ):
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock must prohibit execution, network, and persistence")
    use_policy = value.get("use_policy")
    if not isinstance(use_policy, Mapping) or set(use_policy) != _USE_POLICY_FIELDS:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot use-policy schema drift")
    if use_policy != {
        "label_standard": "scanner_derived_silver",
        "release_blocking": False,
        "precision_or_fpr_eligible": False,
    }:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock must remain silver and non-blocking")
    return cast(Mapping[str, Any], value)


def _positive_int(value: Any, location: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ClawhubSecuritySignalsError(f"{location} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ClawhubSecuritySignalsError(f"{location} exceeds the {maximum} safety limit")
    return cast(int, value)


def _validate_dataset_policy(dataset: Mapping[str, Any]) -> None:
    if dataset.get("gating", {}).get("blocking") is not False:
        raise ClawhubSecuritySignalsError("ClawHub security signals must remain supplemental and non-blocking")
    if dataset.get("access") != "public" or dataset.get("download_policy") != "scheduled_or_manual":
        raise ClawhubSecuritySignalsError("ClawHub dataset access/download policy drift")
    if set(dataset.get("approved_uses", ())) != {
        "silver_label_drift",
        "scanner_disagreement_mining",
        "human_review_sampling",
    }:
        raise ClawhubSecuritySignalsError("ClawHub approved-use policy drift")
    prohibited = set(dataset.get("prohibited_uses", ()))
    if not {"blocking_accuracy_gate", "treat_clawscan_verdict_as_ground_truth", "execute_samples"} <= prohibited:
        raise ClawhubSecuritySignalsError("ClawHub prohibited-use policy drift")


def _raw_contracts(
    raw_contract: Mapping[str, Any],
    dataset: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> tuple[tuple[str, ...], tuple[ClawhubSplitContract, ...], str]:
    if (
        raw_contract.get("schema_version") != 1
        or raw_contract.get("dataset_id") != DATASET_ID
        or raw_contract.get("revision") != dataset["revision"]
        or raw_contract.get("config") != "default"
        or raw_contract.get("raw_format") != "jsonl-v1"
    ):
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock identity drift")

    locked_fields = dataset.get("expected", {}).get("schemas", {}).get("default", {}).get("exact_fields")
    schema = raw_contract.get("schema")
    if not isinstance(schema, list) or schema != locked_fields or not all(isinstance(item, str) for item in schema):
        raise ClawhubSecuritySignalsError("ClawHub raw schema differs from the dataset lock")

    raw_splits = raw_contract.get("splits")
    if not isinstance(raw_splits, Mapping) or set(raw_splits) != set(SPLIT_ORDER):
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock must pin exactly the four raw splits")
    expected_rows = dataset.get("expected", {}).get("row_counts", {})
    contracts: list[ClawhubSplitContract] = []
    aggregate_labels = {verdict: 0 for verdict in sorted(_VERDICTS)}
    total_size = 0
    for split in SPLIT_ORDER:
        raw = raw_splits[split]
        if not isinstance(raw, Mapping) or set(raw) != _SPLIT_FIELDS:
            raise ClawhubSecuritySignalsError(f"ClawHub {split} raw-split contract schema drift")
        relative_path = raw["path"]
        if relative_path != f"data/{split}.jsonl":
            raise ClawhubSecuritySignalsError(f"ClawHub {split} raw path differs from the approved JSONL path")
        rows = _positive_int(raw["rows"], f"ClawHub {split}.rows", maximum=_MAX_ROWS_PER_SPLIT)
        if rows != expected_rows.get(f"default/{split}"):
            raise ClawhubSecuritySignalsError(f"ClawHub {split} row count differs from the dataset lock")
        size_bytes = _positive_int(raw["size_bytes"], f"ClawHub {split}.size_bytes", maximum=_MAX_SPLIT_BYTES)
        total_size += size_bytes
        digest = raw["sha256"]
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise ClawhubSecuritySignalsError(f"ClawHub {split}.sha256 must be a lowercase SHA-256")
        labels = raw["silver_label_counts"]
        if not isinstance(labels, Mapping) or set(labels) != _VERDICTS:
            raise ClawhubSecuritySignalsError(f"ClawHub {split} must pin all silver-label counts")
        normalized_labels: dict[str, int] = {}
        for verdict in sorted(_VERDICTS):
            count = labels[verdict]
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ClawhubSecuritySignalsError(f"ClawHub {split}.{verdict} count must be non-negative")
            normalized_labels[verdict] = count
            aggregate_labels[verdict] += count
        if sum(normalized_labels.values()) != rows:
            raise ClawhubSecuritySignalsError(f"ClawHub {split} silver-label counts do not sum to its rows")
        contracts.append(
            ClawhubSplitContract(
                name=split,
                relative_path=Path(cast(str, relative_path)),
                rows=rows,
                size_bytes=size_bytes,
                sha256=digest,
                silver_label_counts=normalized_labels,
            )
        )
    if total_size > _MAX_SNAPSHOT_BYTES:
        raise ClawhubSecuritySignalsError("ClawHub raw snapshot exceeds the aggregate byte limit")

    quality = raw_contract.get("quality")
    if not isinstance(quality, Mapping) or set(quality) != _QUALITY_FIELDS:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot quality contract drift")
    if quality.get("total_rows") != sum(contract.rows for contract in contracts):
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot total-row count drift")
    if quality.get("silver_label_counts") != aggregate_labels:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot aggregate silver-label count drift")
    if quality.get("unique_ids_within_splits") is not True:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock no longer proves unique split-local row IDs")
    if quality.get("bundle_hash_and_size_mismatches") != 0 or quality.get("unsafe_bundle_paths") != 0:
        raise ClawhubSecuritySignalsError("ClawHub raw-snapshot lock reports unsafe or inconsistent bundles")

    artifacts = [
        {"path": item.relative_path.as_posix(), "sha256": item.sha256, "size_bytes": item.size_bytes}
        for item in contracts
    ]
    expected_artifact_manifest = raw_contract.get("artifact_manifest_sha256")
    if not isinstance(expected_artifact_manifest, str) or not _DIGEST_RE.fullmatch(expected_artifact_manifest):
        raise ClawhubSecuritySignalsError("ClawHub raw artifact manifest must be a lowercase SHA-256")
    if artifact_manifest_sha256(DATASET_ID, artifacts, manifest=manifest) != expected_artifact_manifest:
        raise ClawhubSecuritySignalsError("ClawHub raw artifact manifest digest drift")

    encoded = json.dumps(raw_contract, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return tuple(schema), tuple(contracts), hashlib.sha256(encoded).hexdigest()


def _validate_data_tree(root: Path, selected: Sequence[ClawhubSplitContract]) -> None:
    data = root / "data"
    if data.is_symlink() or not data.is_dir():
        raise ClawhubSecuritySignalsError("snapshot must contain a real non-symlink data directory")
    allowed_names = {f"{split}.jsonl" for split in SPLIT_ORDER}
    try:
        entries = list(os.scandir(data))
    except OSError as exc:
        raise ClawhubSecuritySignalsError(f"cannot safely inspect snapshot data directory: {exc}") from exc
    for entry in entries:
        if entry.name not in allowed_names:
            raise ClawhubSecuritySignalsError(f"unexpected raw snapshot member: data/{entry.name}")
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise ClawhubSecuritySignalsError(
                f"raw snapshot member must be a regular non-symlink file: data/{entry.name}"
            )
    present = {entry.name for entry in entries}
    for contract in selected:
        if contract.relative_path.name not in present:
            raise ClawhubSecuritySignalsError(f"raw snapshot is missing {contract.relative_path.as_posix()}")


def _open_split(path: Path, contract: ClawhubSplitContract) -> BinaryIO:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ClawhubSecuritySignalsError(f"cannot safely open {contract.relative_path.as_posix()}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ClawhubSecuritySignalsError(f"{contract.relative_path.as_posix()} is not a regular file")
        if opened.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise ClawhubSecuritySignalsError(f"{contract.relative_path.as_posix()} must not be executable")
        if opened.st_size != contract.size_bytes:
            raise ClawhubSecuritySignalsError(
                f"{contract.name} byte-size drift (expected {contract.size_bytes}, received {opened.st_size})"
            )
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _verify_open_split(handle: BinaryIO, contract: ClawhubSplitContract) -> None:
    handle.seek(0)
    digest = hashlib.sha256()
    row_count = 0
    current_line_bytes = 0
    last_byte = b""
    while True:
        chunk = handle.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
        last_byte = chunk[-1:]
        pieces = chunk.split(b"\n")
        if len(pieces) == 1:
            current_line_bytes += len(chunk)
        else:
            current_line_bytes += len(pieces[0])
            if current_line_bytes > _MAX_JSONL_LINE_BYTES:
                raise ClawhubSecuritySignalsError(f"{contract.name} contains an oversized JSONL row")
            row_count += len(pieces) - 1
            current_line_bytes = len(pieces[-1])
        if current_line_bytes > _MAX_JSONL_LINE_BYTES:
            raise ClawhubSecuritySignalsError(f"{contract.name} contains an oversized JSONL row")
    if current_line_bytes or (contract.size_bytes and last_byte != b"\n"):
        row_count += 1
    if digest.hexdigest() != contract.sha256:
        raise ClawhubSecuritySignalsError(f"{contract.name} SHA-256 differs from the pinned raw split")
    if row_count != contract.rows:
        raise ClawhubSecuritySignalsError(
            f"{contract.name} physical-row drift (expected {contract.rows}, received {row_count})"
        )
    handle.seek(0)


def load_clawhub_security_signals_snapshot(
    root: Path,
    *,
    revision: str,
    splits: Sequence[str] = SPLIT_ORDER,
    dataset_lock: Path | None = None,
    raw_contract: Path | None = None,
) -> ClawhubSecuritySignalsSnapshot:
    """Load an already-acquired raw snapshot and bind it to reviewed pins."""

    supplied_root = Path(root)
    if supplied_root.is_symlink():
        raise ClawhubSecuritySignalsError("snapshot root must not be a symbolic link")
    try:
        resolved_root = supplied_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ClawhubSecuritySignalsError(f"snapshot root is unavailable: {exc}") from exc
    if not resolved_root.is_dir():
        raise ClawhubSecuritySignalsError("snapshot root must be a directory")
    if raw_contract is not None and dataset_lock is None:
        raise ClawhubSecuritySignalsError("a custom raw contract requires an explicit matching dataset lock")

    manifest = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
    dataset = get_locked_dataset(DATASET_ID, manifest)
    _validate_dataset_policy(dataset)
    if revision != dataset["revision"] or revision != dataset["integrity"]["repository_commit"]:
        raise ClawhubSecuritySignalsError(
            f"snapshot revision drift (expected {dataset['revision']}, received {revision})"
        )

    contract_payload = _load_raw_contract(raw_contract or RAW_CONTRACT_FILE)
    schema, all_contracts, contract_digest = _raw_contracts(contract_payload, dataset, manifest)
    if isinstance(splits, (str, bytes)) or not splits:
        raise ClawhubSecuritySignalsError("splits must be a non-empty sequence")
    if not all(isinstance(split, str) for split in splits) or len(splits) != len(set(splits)):
        raise ClawhubSecuritySignalsError("splits must contain unique string names")
    unknown = sorted(set(splits) - set(SPLIT_ORDER))
    if unknown:
        raise ClawhubSecuritySignalsError(f"unknown raw ClawHub splits: {unknown}")
    selected_names = set(splits)
    selected = tuple(contract for contract in all_contracts if contract.name in selected_names)
    _validate_data_tree(resolved_root, selected)

    # Hash and count every selected split before exposing any sample row.  The
    # iterator repeats this verification on the same open descriptor used for
    # decoding, closing the ordinary path-replacement race.
    for contract in selected:
        with _open_split(resolved_root / contract.relative_path, contract) as handle:
            _verify_open_split(handle, contract)

    return ClawhubSecuritySignalsSnapshot(
        root=resolved_root,
        revision=revision,
        schema=schema,
        raw_contract_sha256=contract_digest,
        raw_artifact_manifest_sha256=cast(str, contract_payload["artifact_manifest_sha256"]),
        repository_artifact_manifest_pinned=not bool(dataset["integrity"]["hashes_pending"]),
        splits=selected,
        lock_manifest=manifest,
    )


def _error_record(
    snapshot: ClawhubSecuritySignalsSnapshot,
    contract: ClawhubSplitContract,
    line_number: int,
    code: str,
) -> ClawhubRowRecord:
    row_id = f"invalid:{contract.name}:{line_number}"
    return ClawhubRowRecord(
        split=contract.name,
        line_number=line_number,
        row_id=row_id,
        row=None,
        silver_verdict=None,
        provenance={
            "dataset_id": DATASET_ID,
            "revision": snapshot.revision,
            "split": contract.name,
            "split_sha256": contract.sha256,
            "line": str(line_number),
        },
        grouping={},
        ingestion_error=code,
    )


def _bounded_identifier(value: Any, location: str, *, max_bytes: int = _MAX_ID_BYTES) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DatasetSchemaError(f"{location} must be a non-empty NUL-free string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DatasetSchemaError(f"{location} must be valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise DatasetSchemaError(f"{location} exceeds {max_bytes} UTF-8 bytes")
    return value


def _nullable_bounded_string(
    value: Any,
    location: str,
    *,
    allowed: frozenset[str] | None = None,
    max_bytes: int = _MAX_ID_BYTES,
) -> None:
    if value is None:
        return
    text = _bounded_identifier(value, location, max_bytes=max_bytes)
    if allowed is not None and text.casefold() not in allowed:
        raise DatasetSchemaError(f"{location} contains an unknown enum value")


def _nullable_nonnegative_integer(value: Any, location: str) -> None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
        raise DatasetSchemaError(f"{location} must be a non-negative integer or null")


def _bounded_string_list(value: Any, location: str) -> None:
    if value is None:
        return
    if not isinstance(value, list) or len(value) > 4_096:
        raise DatasetSchemaError(f"{location} must be a bounded string list or null")
    for index, item in enumerate(value):
        _bounded_identifier(item, f"{location}[{index}]")


def _validate_context(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping) or not set(value) <= {"static", "virustotal", "skillspector"}:
        raise DatasetSchemaError("row.clawscan_context has unexpected fields")
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, UnicodeError, ValueError, RecursionError) as exc:
        raise DatasetSchemaError("row.clawscan_context is not bounded JSON data") from exc
    if len(encoded) > 1024 * 1024:
        raise DatasetSchemaError("row.clawscan_context exceeds the 1 MiB discarded-context limit")


def _validate_used_row_values(row: Mapping[str, Any], contract: ClawhubSplitContract) -> tuple[str, str]:
    row_id = _bounded_identifier(row.get("id"), "row.id")
    _bounded_identifier(row.get("skill_slug"), "row.skill_slug")
    _bounded_identifier(row.get("skill_version"), "row.skill_version")
    if row.get("split") != contract.name:
        raise DatasetSchemaError("row.split differs from containing raw split")
    verdict = row.get("clawscan_verdict")
    if verdict not in _VERDICTS:
        raise DatasetSchemaError("row.clawscan_verdict is outside the locked silver-label enum")
    skill_text = row.get("skill_md_content")
    bundle = row.get("skill_bundle_content")
    if not isinstance(skill_text, str) or not skill_text or not isinstance(bundle, list) or len(bundle) > 4_096:
        raise DatasetSchemaError("row skill content fields have invalid types")

    _nullable_bounded_string(
        row.get("clawscan_confidence"), "row.clawscan_confidence", allowed=frozenset({"low", "medium", "high"})
    )
    _nullable_bounded_string(row.get("clawscan_model"), "row.clawscan_model")
    _nullable_bounded_string(row.get("clawscan_summary"), "row.clawscan_summary", max_bytes=64 * 1024)
    _nullable_bounded_string(
        row.get("static_status"),
        "row.static_status",
        allowed=frozenset({"clean", "suspicious", "malicious", "stale", "error"}),
    )
    _nullable_bounded_string(
        row.get("virustotal_status"),
        "row.virustotal_status",
        allowed=frozenset({"clean", "suspicious", "malicious", "stale", "error"}),
    )
    _nullable_bounded_string(
        row.get("skillspector_status"),
        "row.skillspector_status",
        allowed=frozenset({"clean", "suspicious", "malicious", "stale", "error"}),
    )
    _nullable_bounded_string(
        row.get("skillspector_severity"),
        "row.skillspector_severity",
        allowed=frozenset({"critical", "high", "medium", "low", "info"}),
    )
    for field_name in (
        "static_finding_count",
        "virustotal_malicious_count",
        "virustotal_suspicious_count",
        "virustotal_harmless_count",
        "virustotal_undetected_count",
        "skillspector_issue_count",
    ):
        _nullable_nonnegative_integer(row.get(field_name), f"row.{field_name}")
    score = row.get("skillspector_score")
    if score is not None and (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 100
    ):
        raise DatasetSchemaError("row.skillspector_score must be a finite 0..100 number or null")
    for field_name in (
        "static_reason_codes",
        "skillspector_issue_codes",
        "skillspector_issue_categories",
    ):
        _bounded_string_list(row.get(field_name), f"row.{field_name}")
    _validate_context(row.get("clawscan_context"))
    return row_id, cast(str, verdict)


def _grouping(row: Mapping[str, Any]) -> dict[str, str]:
    skill_text = cast(str, row["skill_md_content"])
    slug = cast(str, row["skill_slug"])
    bundle = cast(Sequence[Mapping[str, Any]], row["skill_bundle_content"])
    owner = slug.partition("/")[0] or slug
    normalized_text = " ".join(skill_text.casefold().split())
    path_shape = sorted(
        f"{Path(cast(str, entry['path'])).suffix.casefold()}:{len(cast(str, entry['content']).encode('utf-8')) // 256}"
        for entry in bundle
    )
    family_payload = json.dumps(path_shape, separators=(",", ":")).encode("utf-8")
    return {
        "repository_group_sha256": hashlib.sha256(b"clawhub-owner-v1\0" + owner.encode("utf-8")).hexdigest(),
        "exact_content_sha256": hashlib.sha256(skill_text.encode("utf-8")).hexdigest(),
        "normalized_content_sha256": hashlib.sha256(normalized_text.encode("utf-8")).hexdigest(),
        "structural_family_sha256": hashlib.sha256(b"clawhub-structure-v1\0" + family_payload).hexdigest(),
    }


def _parse_row(
    raw_line: bytes,
    *,
    snapshot: ClawhubSecuritySignalsSnapshot,
    contract: ClawhubSplitContract,
    line_number: int,
    seen_ids: set[str],
) -> ClawhubRowRecord:
    try:
        row = json.loads(
            raw_line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ClawhubSecuritySignalsError):
        return _error_record(snapshot, contract, line_number, "INVALID_JSON")
    if not isinstance(row, Mapping):
        return _error_record(snapshot, contract, line_number, "ROW_NOT_OBJECT")
    try:
        validate_locked_row(DATASET_ID, "default", row, snapshot.lock_manifest)
        row_id, verdict = _validate_used_row_values(row, contract)
        if row_id in seen_ids:
            raise DatasetSchemaError("row.id is duplicated across selected splits")
        seen_ids.add(row_id)
        grouping = _grouping(row)
    except (DatasetLockError, DatasetSchemaError, TypeError, UnicodeError, ValueError):
        return _error_record(snapshot, contract, line_number, "ROW_SCHEMA_INVALID")
    provenance = {
        "dataset_id": DATASET_ID,
        "revision": snapshot.revision,
        "split": contract.name,
        "split_sha256": contract.sha256,
        "row_id": row_id,
    }
    return ClawhubRowRecord(
        split=contract.name,
        line_number=line_number,
        row_id=row_id,
        row=cast(Mapping[str, Any], row),
        silver_verdict=verdict,
        provenance=provenance,
        grouping=grouping,
        ingestion_error=None,
    )


def iter_clawhub_security_signal_rows(
    snapshot: ClawhubSecuritySignalsSnapshot,
) -> Iterator[ClawhubRowRecord]:
    """Yield every physical row; malformed rows remain explicit outcomes."""

    seen_ids: set[str] = set()
    for contract in snapshot.splits:
        path = snapshot.root / contract.relative_path
        with _open_split(path, contract) as handle:
            _verify_open_split(handle, contract)
            physical_rows = 0
            observed_labels = {verdict: 0 for verdict in sorted(_VERDICTS)}
            for line_number, raw_line in enumerate(handle, start=1):
                physical_rows += 1
                if len(raw_line) > _MAX_JSONL_LINE_BYTES:
                    # This was already rejected during split verification; keep
                    # the branch as a local invariant if the iterator changes.
                    raise ClawhubSecuritySignalsError(f"{contract.name} row exceeds the JSONL line limit")
                record = _parse_row(
                    raw_line,
                    snapshot=snapshot,
                    contract=contract,
                    line_number=line_number,
                    seen_ids=seen_ids,
                )
                if record.silver_verdict is not None:
                    observed_labels[record.silver_verdict] += 1
                yield record
            if physical_rows != contract.rows:  # pragma: no cover - verified same descriptor
                raise ClawhubSecuritySignalsError(f"{contract.name} row count changed while iterating")
            valid_count = sum(observed_labels.values())
            if valid_count == contract.rows and observed_labels != dict(contract.silver_label_counts):
                raise ClawhubSecuritySignalsError(f"{contract.name} silver-label distribution differs from its pin")
            # Re-hash the same descriptor after consumers finish each yielded
            # row. If another process changed the file during a long scan, the
            # runner aborts instead of publishing evidence under the old pin.
            _verify_open_split(handle, contract)
