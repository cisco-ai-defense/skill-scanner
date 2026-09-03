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

"""Materialize the locked MaliciousSkillBench release snapshot.

This is deliberately an acquisition adapter, not a Hugging Face dataset
loader. It opens only the ten files listed in the committed inspection profile,
requires their byte hashes to match the dataset lock, decodes the pinned
Parquet tables as data, and emits one non-executable ``SKILL.md`` per usable
row. It never imports repository code, follows source pointers, opens package
archives, or executes a sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

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
    validate_snapshot_metadata,
    validate_source_artifact_manifest,
)
from evals.runners.public_dataset_benchmark import (  # noqa: E402
    SNAPSHOT_MANIFEST,
    SNAPSHOT_SCHEMA_VERSION,
    load_frozen_snapshot,
)

try:
    import pyarrow.parquet as parquet
except ImportError:  # pragma: no cover - the non-materializing contract API remains usable
    parquet = None


DATASET_ID = "ProtectSkills/MaliciousSkillBench"
PROFILE_FILE = Path(__file__).with_name("public-datasets.profile.json")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_SKILL_BYTES = 32 * 1024 * 1024
_PARTITIONS = frozenset({"train", "validation", "test", "excluded"})


class MaterializationError(ValueError):
    """Raised when locked acquisition inputs cannot produce the snapshot."""


def _strict_json(path: Path, *, label: str) -> Mapping[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise MaterializationError(f"{label} must be a regular non-symlink file")
    file_stat = path.stat(follow_symlinks=False)
    if file_stat.st_size > _MAX_JSON_BYTES:
        raise MaterializationError(f"{label} exceeds the {_MAX_JSON_BYTES}-byte safety limit")

    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MaterializationError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MaterializationError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise MaterializationError(f"{label} root must be an object")
    return value


def _profile_dataset(profile_path: Path, lock: Mapping[str, Any]) -> Mapping[str, Any]:
    profile = _strict_json(profile_path, label="dataset profile")
    datasets = profile.get("datasets")
    if isinstance(datasets, (str, bytes)) or not isinstance(datasets, Sequence):
        raise MaterializationError("dataset profile datasets must be an array")
    matches = [entry for entry in datasets if isinstance(entry, Mapping) and entry.get("id") == DATASET_ID]
    if len(matches) != 1:
        raise MaterializationError(f"dataset profile must contain exactly one {DATASET_ID} entry")
    entry = matches[0]
    locked = get_locked_dataset(DATASET_ID, lock)
    if entry.get("revision") != locked["revision"] or entry.get("revision_verified") is not True:
        raise MaterializationError("dataset profile revision is not the verified locked revision")
    if entry.get("source_artifact_manifest_sha256") != locked["integrity"].get("source_artifact_manifest_sha256"):
        raise MaterializationError("dataset profile source-artifact identity differs from the lock")
    return entry


def source_artifact_contract(
    *,
    profile_path: Path = PROFILE_FILE,
    dataset_lock: Path | None = None,
) -> tuple[Mapping[str, Any], tuple[dict[str, Any], ...], Mapping[str, Any]]:
    """Return the validated lock, ordered source inventory, and profile entry."""

    lock = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
    entry = _profile_dataset(profile_path, lock)
    raw_artifacts = entry.get("source_artifacts")
    if isinstance(raw_artifacts, (str, bytes)) or not isinstance(raw_artifacts, Sequence) or not raw_artifacts:
        raise MaterializationError("dataset profile source_artifacts must be a non-empty array")

    artifacts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_artifacts):
        if not isinstance(raw, Mapping) or set(raw) != _SOURCE_FIELDS:
            raise MaterializationError(f"source_artifacts[{index}] has unexpected fields")
        path = raw["path"]
        digest = raw["sha256"]
        size = raw["size_bytes"]
        if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
            raise MaterializationError(f"source_artifacts[{index}].path is not a portable relative path")
        parsed = PurePosixPath(path)
        if any(part in ("", ".", "..") for part in path.split("/")) or parsed.as_posix() != path:
            raise MaterializationError(f"source_artifacts[{index}].path is not normalized")
        if path in seen:
            raise MaterializationError(f"duplicate source artifact path: {path}")
        seen.add(path)
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise MaterializationError(f"source_artifacts[{index}].sha256 is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise MaterializationError(f"source_artifacts[{index}].size_bytes is invalid")
        artifacts.append({"path": path, "sha256": digest, "size_bytes": size})

    validate_source_artifact_manifest(DATASET_ID, artifacts, manifest=lock)
    return lock, tuple(artifacts), entry


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_acquired_sources(root: Path, artifacts: Sequence[Mapping[str, Any]], lock: Mapping[str, Any]) -> None:
    """Require every pinned source file and reject additional non-cache inputs."""

    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise MaterializationError("source directory must be an existing non-symlink directory")
    root = root.resolve(strict=True)
    expected = {str(item["path"]): item for item in artifacts}
    observed: set[str] = set()
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        relative_root = current.relative_to(root)
        if relative_root.parts[:2] == (".cache", "huggingface"):
            directory_names[:] = []
            continue
        for name in [*directory_names, *file_names]:
            member = current / name
            mode = member.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise MaterializationError(f"source directory contains a symbolic link: {member.relative_to(root)}")
            if name in directory_names and not stat.S_ISDIR(mode):
                raise MaterializationError(f"source directory contains a non-directory tree entry: {member}")
            if name in file_names and not stat.S_ISREG(mode):
                raise MaterializationError(f"source directory contains a non-regular file: {member}")
        for name in file_names:
            member = current / name
            relative = member.relative_to(root).as_posix()
            if relative.startswith(".cache/huggingface/"):
                continue
            observed.add(relative)
            pinned = expected.get(relative)
            if pinned is None:
                raise MaterializationError(f"source directory contains an unpinned input: {relative}")
            size = member.stat(follow_symlinks=False).st_size
            if size != pinned["size_bytes"]:
                raise MaterializationError(f"source artifact size mismatch: {relative}")
            if _sha256_file(member) != pinned["sha256"]:
                raise MaterializationError(f"source artifact SHA-256 mismatch: {relative}")
    missing = sorted(set(expected) - observed)
    if missing:
        raise MaterializationError(f"source directory is missing pinned inputs: {missing}")
    validate_source_artifact_manifest(DATASET_ID, list(artifacts), manifest=lock)


def _label(raw: Any) -> str:
    if raw == "1":
        return "malicious"
    if raw == "0":
        return "benign"
    raise MaterializationError(f"unsupported MaliciousSkillBench label: {raw!r}")


def _category_ids(row: Mapping[str, Any], label: str) -> list[str]:
    raw = row.get("attack_category_codes")
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise MaterializationError("attack_category_codes must be an array")
    if any(not isinstance(value, str) or not value or "\x00" in value for value in raw):
        raise MaterializationError("attack_category_codes contains an invalid category")
    categories = sorted(set(raw))
    if categories:
        return categories
    return ["benign" if label == "benign" else "unclassified_malicious"]


def _split_rows(
    source_root: Path,
    protocol: str,
    *,
    revision: str,
    expected_ids: set[str],
    primary_identity: Mapping[str, tuple[str, str]],
    lock: Mapping[str, Any],
) -> dict[str, str]:
    if parquet is None:  # pragma: no cover - exercised by the producer environment
        raise MaterializationError("install the locked datasets dependency group: uv sync --frozen --group datasets")
    table = parquet.read_table(source_root / "splits" / f"{protocol}.parquet")
    validate_snapshot_metadata(
        DATASET_ID,
        revision=revision,
        config="splits",
        split=protocol,
        fields=table.schema.names,
        schema_name="split_manifest",
        row_count=table.num_rows,
        manifest=lock,
    )
    result: dict[str, str] = {}
    for index, row in enumerate(table.to_pylist()):
        benchmark_id = row["benchmark_id"]
        if not isinstance(benchmark_id, str) or benchmark_id not in expected_ids or benchmark_id in result:
            raise MaterializationError(f"{protocol} row {index} has an unknown or duplicate benchmark_id")
        label, source_id = primary_identity[benchmark_id]
        if _label(row["label"]) != label or row["source_id"] != source_id:
            raise MaterializationError(f"{protocol} row {index} disagrees with primary identity")
        partition = row["split"]
        if partition not in _PARTITIONS:
            raise MaterializationError(f"{protocol} row {index} has unsupported split {partition!r}")
        result[benchmark_id] = partition
    if set(result) != expected_ids:
        raise MaterializationError(f"{protocol} split membership differs from the primary table")
    return result


def _quarantine_records(entry: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    materialization = entry.get("materialization")
    if not isinstance(materialization, Mapping):
        raise MaterializationError("dataset profile lacks materialization metadata")
    records = materialization.get("quarantine_records")
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise MaterializationError("dataset profile quarantine_records must be an array")
    if not all(isinstance(record, Mapping) for record in records):
        raise MaterializationError("dataset profile contains an invalid quarantine record")
    return tuple(dict(record) for record in records)


def _write_json_new(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def _materialize_pinned_text(destination: Path, content: str) -> None:
    """Write one exact, hash-pinned UTF-8 sample with non-executable modes.

    Five locked rows contain Unicode/C0 control code points (one is the 21 MB
    hard negative). Replacing or dropping those bytes would change the reviewed
    artifact manifest and benchmark population. This narrower adapter therefore
    preserves valid UTF-8 exactly after the complete upstream file manifest has
    been authenticated. NUL remains forbidden; no content is logged or run.
    """

    if "\x00" in content:
        raise MaterializationError("pinned skill text contains a NUL byte")
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MaterializationError("pinned skill text is not valid UTF-8") from exc
    if not encoded or len(encoded) > _MAX_SKILL_BYTES:
        raise MaterializationError(f"pinned skill text must contain 1..{_MAX_SKILL_BYTES} UTF-8 bytes")
    destination.mkdir(mode=0o700)
    try:
        descriptor = os.open(
            destination / "SKILL.md",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        shutil.rmtree(destination)
        raise


def materialize_snapshot(
    source_root: Path,
    output_root: Path,
    *,
    profile_path: Path = PROFILE_FILE,
    dataset_lock: Path | None = None,
) -> Mapping[str, Any]:
    """Validate pinned inputs and write the complete inert classification snapshot."""

    if parquet is None:  # pragma: no cover - exercised by the producer environment
        raise MaterializationError("install the locked datasets dependency group: uv sync --frozen --group datasets")
    lock, source_artifacts, profile_entry = source_artifact_contract(
        profile_path=profile_path,
        dataset_lock=dataset_lock,
    )
    validate_acquired_sources(source_root, source_artifacts, lock)
    source_root = Path(source_root).resolve(strict=True)
    dataset = get_locked_dataset(DATASET_ID, lock)
    revision = str(dataset["revision"])
    if _REVISION_RE.fullmatch(revision) is None:
        raise MaterializationError("locked dataset revision is invalid")

    primary_table = parquet.read_table(source_root / "primary.parquet")
    validate_snapshot_metadata(
        DATASET_ID,
        revision=revision,
        config="primary",
        split="train",
        fields=primary_table.schema.names,
        row_count=primary_table.num_rows,
        manifest=lock,
    )
    primary_rows = primary_table.to_pylist()
    by_id: dict[str, Mapping[str, Any]] = {}
    identities: dict[str, tuple[str, str]] = {}
    for index, row in enumerate(primary_rows):
        benchmark_id = row["benchmark_id"]
        if not isinstance(benchmark_id, str) or not benchmark_id or benchmark_id in by_id:
            raise MaterializationError(f"primary row {index} has an invalid or duplicate benchmark_id")
        if "/" in benchmark_id or "\\" in benchmark_id or benchmark_id in {".", ".."}:
            raise MaterializationError(f"primary row {index} has an unsafe benchmark_id")
        label = _label(row["label"])
        source_id = row["source_id"]
        if not isinstance(source_id, str) or not source_id or "\x00" in source_id:
            raise MaterializationError(f"primary row {index} has an invalid source_id")
        by_id[benchmark_id] = row
        identities[benchmark_id] = (label, source_id)

    protocols = tuple(track["protocol"] for track in dataset["gating"]["tracks"])
    splits = {
        protocol: _split_rows(
            source_root,
            protocol,
            revision=revision,
            expected_ids=set(by_id),
            primary_identity=identities,
            lock=lock,
        )
        for protocol in protocols
    }

    quarantine = _quarantine_records(profile_entry)
    quarantine_by_id = {record["benchmark_id"]: record for record in quarantine}
    if len(quarantine_by_id) != len(quarantine):
        raise MaterializationError("dataset profile contains duplicate quarantine identities")

    output_root = Path(output_root)
    if output_root.exists() or output_root.is_symlink():
        raise MaterializationError("output directory must be a new non-symlink path")
    if not output_root.parent.is_dir() or output_root.parent.is_symlink():
        raise MaterializationError("output directory parent must be an existing non-symlink directory")
    # Resolve only the existing parent. This keeps the leaf creation exclusive
    # while normalizing platform aliases such as macOS /tmp -> /private/tmp.
    output_root = output_root.parent.resolve(strict=True) / output_root.name
    output_root.mkdir(mode=0o700)
    (output_root / "skills").mkdir(mode=0o700)

    artifacts: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    try:
        for benchmark_id in sorted(by_id):
            row = by_id[benchmark_id]
            label, source_id = identities[benchmark_id]
            family = row["structural_family_id"]
            if family is None and label == "benign":
                family = "UNASSIGNED_BENIGN"
            if not isinstance(family, str) or not family or "\x00" in family:
                raise MaterializationError(f"{benchmark_id} has an invalid structural_family_id")
            categories = _category_ids(row, label)
            selected_text = row["skill_text"] if row["skill_text"] is not None else row["public_skill_text"]
            if not isinstance(selected_text, str) or not selected_text:
                raise MaterializationError(f"{benchmark_id} has no public-readable skill text")
            if row["text_available"] is not (row["skill_text"] is not None):
                raise MaterializationError(f"{benchmark_id} text_available disagrees with skill_text")
            if row["original_text_withheld"] and row["skill_text"] is not None:
                raise MaterializationError(f"{benchmark_id} exposes an original marked withheld")
            if row["public_skill_text"] is not None:
                public_digest = hashlib.sha256(row["public_skill_text"].encode("utf-8")).hexdigest()
                if row["public_text_sha256"] != public_digest:
                    raise MaterializationError(f"{benchmark_id} public text digest mismatch")
            elif row["public_text_sha256"] is not None:
                raise MaterializationError(f"{benchmark_id} has a public digest without public text")

            content = selected_text.encode("utf-8")
            artifact = {
                "path": f"skills/{benchmark_id}/SKILL.md",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
            artifacts.append(artifact)
            sample_splits = {protocol: splits[protocol][benchmark_id] for protocol in protocols}
            sample = {
                "benchmark_id": benchmark_id,
                "category_ids": categories,
                "label": label,
                "path": f"skills/{benchmark_id}",
                "source_id": source_id,
                "splits": sample_splits,
                "structural_family_id": family,
            }
            samples.append(sample)

            quarantined = quarantine_by_id.get(benchmark_id)
            if quarantined is not None:
                for field, expected in (
                    ("path", artifact["path"]),
                    ("sha256", artifact["sha256"]),
                    ("size_bytes", artifact["size_bytes"]),
                    ("label", label),
                    ("source_id", source_id),
                    ("structural_family_id", family),
                    ("splits", sample_splits),
                ):
                    if quarantined[field] != expected:
                        raise MaterializationError(f"{benchmark_id} quarantine {field} disagrees with source data")
                continue

            _materialize_pinned_text(output_root / "skills" / benchmark_id, selected_text)

        declared_digest = artifact_manifest_sha256(DATASET_ID, artifacts, manifest=lock)
        validate_artifact_manifest(
            DATASET_ID,
            artifacts,
            manifest_sha256=declared_digest,
            manifest=lock,
        )
        quarantine_digest = dataset["integrity"]["materialization"]["quarantine_manifest_sha256"]
        validate_quarantine_manifest(
            DATASET_ID,
            quarantine,
            declared_artifact_manifest_sha256=declared_digest,
            manifest_sha256=quarantine_digest,
            manifest=lock,
        )
        manifest = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "dataset_id": DATASET_ID,
            "revision": revision,
            "artifact_manifest_sha256": declared_digest,
            "artifacts": artifacts,
            "samples": samples,
            "quarantine": {"manifest_sha256": quarantine_digest, "records": list(quarantine)},
        }
        _write_json_new(output_root / SNAPSHOT_MANIFEST, manifest)
        snapshot = load_frozen_snapshot(output_root, dataset_id=DATASET_ID, dataset_lock=dataset_lock)
    except BaseException:
        shutil.rmtree(output_root)
        raise

    return {
        "dataset_id": DATASET_ID,
        "revision": revision,
        "source_artifact_manifest_sha256": dataset["integrity"]["source_artifact_manifest_sha256"],
        "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
        "usable_artifact_manifest_sha256": snapshot.usable_artifact_manifest_sha256,
        "declared_artifacts": len(artifacts),
        "usable_artifacts": len(artifacts) - len(quarantine),
        "quarantined_artifacts": len(quarantine),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the locked, inert MaliciousSkillBench release snapshot")
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--dataset-lock", type=Path, default=None)
    parser.add_argument("--dataset-profile", type=Path, default=PROFILE_FILE)
    parser.add_argument(
        "--print-source-paths",
        action="store_true",
        help="print the validated lock-pinned Hugging Face paths and exit",
    )
    args = parser.parse_args(argv)
    try:
        if args.print_source_paths:
            if args.source_dir is not None or args.output_dir is not None:
                raise MaterializationError("--print-source-paths cannot be combined with materialization paths")
            _, artifacts, _ = source_artifact_contract(
                profile_path=args.dataset_profile,
                dataset_lock=args.dataset_lock,
            )
            for artifact in artifacts:
                print(artifact["path"])
            return 0
        if args.source_dir is None or args.output_dir is None:
            raise MaterializationError("--source-dir and --output-dir are required")
        summary = materialize_snapshot(
            args.source_dir,
            args.output_dir,
            profile_path=args.dataset_profile,
            dataset_lock=args.dataset_lock,
        )
    except (DatasetLockError, DatasetSchemaError, MaterializationError, OSError) as exc:
        print(f"MaliciousSkillBench materialization failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
