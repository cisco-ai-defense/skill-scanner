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

"""Safe offline adapter for the pinned HarmfulSkillBench snapshot.

The adapter has no acquisition or execution path. It reads only metadata,
reviewed task text, and ``SKILL.md`` documents from an already-downloaded
snapshot. Sample text is retained in memory solely so the opt-in local policy
runner can quote it as inert data.
"""

from __future__ import annotations

import json
import os
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evals.datasets.public_datasets import get_locked_dataset, load_dataset_lock

DATASET_ID = "TrustAIRLab/HarmfulSkillBench"
EXPECTED_POPULATION = 200
EXPECTED_CATEGORIES = tuple(
    [
        *(f"H{index}" for index in range(1, 8)),
        *(f"P{index}" for index in range(1, 7)),
        *(f"P{index}" for index in range(8, 15)),
    ]
)
EXPECTED_PLATFORM_COUNTS = {"clawhub": 81, "original": 62, "skillsrest": 57}
EXPECTED_TIER_COUNTS = {"tier1": 130, "tier2": 70}

# Explicitly frozen before prompt tuning. These pseudonymous identifiers contain
# no sample text and make the five-sample development / fifteen-sample held-back
# boundary independently auditable.
DEV_SELECTION: tuple[tuple[str, str], ...] = (
    ("H1", "skillsrest_fe60abb0"),
    ("H2", "skillsrest_2c3c8535"),
    ("H3", "life-underwrite-2"),
    ("H4", "clawhub_3798ce8a"),
    ("H5", "skillsrest_a78af80e"),
)
HELD_BACK_SELECTION: tuple[tuple[str, str], ...] = (
    ("H6", "admissions-ranker-2"),
    ("H7", "skillsrest_3ac08837"),
    ("P1", "clawhub_2ce3728a"),
    ("P10", "turnout-dampener"),
    ("P11", "clawhub_48656770"),
    ("P12", "skillsrest_12a0a0eb"),
    ("P13", "skillsrest_50fc2fe0"),
    ("P14", "clawhub_32b38565"),
    ("P2", "election-breach"),
    ("P3", "skillsrest_f8c5afca"),
    ("P4", "blastforge"),
    ("P5", "extremist-campaign-kit"),
    ("P6", "clawhub_58cbb196"),
    ("P8", "brigade-manager"),
    ("P9", "smear-campaign-2"),
)

_META_FIELDS = frozenset({"anon_id", "platform", "category", "tier"})
_TASK_FIELDS = frozenset({"anon_id", "platform", "category", "tier", "name", "description", "selected_task"})
_PLATFORMS = frozenset(EXPECTED_PLATFORM_COUNTS)
_TIERS = frozenset(EXPECTED_TIER_COUNTS)
_MAX_TASK_FILE_BYTES = 2 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_MAX_SKILL_BYTES = 2 * 1024 * 1024
_MAX_TREE_FILES = 2_000
_MAX_TREE_BYTES = 64 * 1024 * 1024
_MAX_TEXT_BYTES = 256 * 1024


class HarmfulSkillBenchError(ValueError):
    """Raised when a local HarmfulSkillBench snapshot is unsafe or drifts."""


class _SkillLoader(Protocol):
    def load_skill(self, skill_directory: Path, *, lenient: bool = False): ...


@dataclass(frozen=True)
class HarmfulSkillSample:
    anon_id: str
    platform: str
    category: str
    tier: str
    name: str
    description: str
    selected_task: str
    directory: Path
    skill_path: Path


@dataclass(frozen=True)
class HarmfulSkillSnapshot:
    root: Path
    revision: str
    integrity_hashes_pending: bool
    samples: tuple[HarmfulSkillSample, ...]

    def selected(self, phase: str) -> tuple[HarmfulSkillSample, ...]:
        if phase == "dev":
            selection = DEV_SELECTION
        elif phase == "held-back":
            selection = HELD_BACK_SELECTION
        else:
            raise HarmfulSkillBenchError("phase must be 'dev' or 'held-back'")
        by_id = {sample.anon_id: sample for sample in self.samples}
        selected: list[HarmfulSkillSample] = []
        for expected_category, anon_id in selection:
            sample = by_id.get(anon_id)
            if sample is None:
                raise HarmfulSkillBenchError(f"frozen {phase} sample is missing: {anon_id}")
            if sample.category != expected_category:
                raise HarmfulSkillBenchError(
                    f"frozen {phase} sample category drift for {anon_id}: "
                    f"expected {expected_category}, received {sample.category}"
                )
            selected.append(sample)
        return tuple(selected)


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarmfulSkillBenchError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _read_regular_bytes(path: Path, *, limit: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HarmfulSkillBenchError(f"cannot safely open required snapshot file {path.name}: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise HarmfulSkillBenchError(f"required snapshot member is not a regular file: {path.name}")
        if file_stat.st_size > limit:
            raise HarmfulSkillBenchError(f"required snapshot member exceeds {limit} bytes: {path.name}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read(limit + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_regular_text(path: Path, *, limit: int) -> str:
    raw = _read_regular_bytes(path, limit=limit)
    if len(raw) > limit:
        raise HarmfulSkillBenchError(f"required snapshot member exceeds {limit} bytes: {path.name}")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HarmfulSkillBenchError(f"required snapshot member is not UTF-8 text: {path.name}") from exc
    if "\x00" in value:
        raise HarmfulSkillBenchError(f"required snapshot member contains NUL bytes: {path.name}")
    return value


def _validate_used_tree(root: Path) -> None:
    """Reject unsafe entries in the two subtrees consumed by the adapter."""

    if root.is_symlink() or not root.is_dir():
        raise HarmfulSkillBenchError("snapshot root must be an existing non-symlink directory")
    total_files = 0
    total_bytes = 0
    for relative in (Path("skills"), Path("eval_tasks")):
        tree = root / relative
        if tree.is_symlink() or not tree.is_dir():
            raise HarmfulSkillBenchError(f"snapshot is missing safe directory {relative.as_posix()}")
        for current_root, directory_names, file_names in os.walk(tree, followlinks=False):
            current = Path(current_root)
            for name in [*directory_names, *file_names]:
                member = current / name
                member_stat = member.lstat()
                member_label = member.relative_to(root).as_posix()
                if stat.S_ISLNK(member_stat.st_mode):
                    raise HarmfulSkillBenchError(f"snapshot contains a symbolic link: {member_label}")
                if name in directory_names and not stat.S_ISDIR(member_stat.st_mode):
                    raise HarmfulSkillBenchError(f"snapshot contains a non-directory entry: {member_label}")
                if name in file_names and not stat.S_ISREG(member_stat.st_mode):
                    raise HarmfulSkillBenchError(f"snapshot contains a non-regular file: {member_label}")
            for name in file_names:
                member_stat = (current / name).stat(follow_symlinks=False)
                if member_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    raise HarmfulSkillBenchError(
                        f"snapshot contains an executable-mode file: {(current / name).relative_to(root).as_posix()}"
                    )
                total_files += 1
                total_bytes += member_stat.st_size
                if total_files > _MAX_TREE_FILES or total_bytes > _MAX_TREE_BYTES:
                    raise HarmfulSkillBenchError("snapshot used-tree exceeds bounded file or byte limits")


def _require_string(value: Any, location: str, *, max_bytes: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HarmfulSkillBenchError(f"{location} must be a non-empty NUL-free string")
    if len(value.encode("utf-8")) > max_bytes:
        raise HarmfulSkillBenchError(f"{location} exceeds the {max_bytes}-byte text limit")
    return value


def _read_json_object(path: Path, *, fields: frozenset[str], limit: int) -> Mapping[str, Any]:
    text = _read_regular_text(path, limit=limit)
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise HarmfulSkillBenchError(f"invalid JSON in {path.name}: {exc}") from exc
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HarmfulSkillBenchError(f"{path.name} schema drift (expected fields {sorted(fields)})")
    return value


def _read_tasks(path: Path) -> dict[str, Mapping[str, Any]]:
    text = _read_regular_text(path, limit=_MAX_TASK_FILE_BYTES)
    result: dict[str, Mapping[str, Any]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise HarmfulSkillBenchError(f"reviewed task file contains a blank row at line {line_number}")
        try:
            value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise HarmfulSkillBenchError(f"invalid reviewed task JSON at line {line_number}: {exc}") from exc
        if not isinstance(value, Mapping) or set(value) != _TASK_FIELDS:
            raise HarmfulSkillBenchError(f"reviewed task schema drift at line {line_number}")
        anon_id = _require_string(value["anon_id"], f"reviewed_tasks[{line_number}].anon_id", max_bytes=256)
        if anon_id in result:
            raise HarmfulSkillBenchError(f"duplicate reviewed task identifier: {anon_id}")
        result[anon_id] = value
    if len(result) != EXPECTED_POPULATION:
        raise HarmfulSkillBenchError(
            f"reviewed task population drift (expected {EXPECTED_POPULATION}, received {len(result)})"
        )
    return result


def load_harmful_skill_snapshot(
    root: Path,
    *,
    revision: str,
    dataset_lock: Path | None = None,
) -> HarmfulSkillSnapshot:
    """Validate and load an already-acquired pinned snapshot without network."""

    supplied_root = Path(root)
    if supplied_root.is_symlink():
        raise HarmfulSkillBenchError("snapshot root must not be a symbolic link")
    root = supplied_root.resolve(strict=True)
    manifest = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
    dataset = get_locked_dataset(DATASET_ID, manifest)
    if revision != dataset["revision"] or revision != dataset["integrity"]["repository_commit"]:
        raise HarmfulSkillBenchError(f"snapshot revision drift (expected {dataset['revision']}, received {revision})")
    if dataset["gating"]["blocking"]:
        raise HarmfulSkillBenchError("HarmfulSkillBench must remain a non-blocking supplemental dataset")
    if "execute_samples" not in dataset["prohibited_uses"]:
        raise HarmfulSkillBenchError("dataset lock no longer prohibits sample execution")

    _validate_used_tree(root)
    tasks = _read_tasks(root / "eval_tasks" / "reviewed_tasks.jsonl")
    metadata_paths = sorted((root / "skills").rglob("_meta.json"))
    if len(metadata_paths) != EXPECTED_POPULATION:
        raise HarmfulSkillBenchError(
            f"skill metadata population drift (expected {EXPECTED_POPULATION}, received {len(metadata_paths)})"
        )

    samples: list[HarmfulSkillSample] = []
    seen: set[str] = set()
    for metadata_path in metadata_paths:
        metadata = _read_json_object(metadata_path, fields=_META_FIELDS, limit=_MAX_METADATA_BYTES)
        anon_id = _require_string(metadata["anon_id"], "_meta.json.anon_id", max_bytes=256)
        if anon_id in seen:
            raise HarmfulSkillBenchError(f"duplicate skill metadata identifier: {anon_id}")
        seen.add(anon_id)
        task = tasks.get(anon_id)
        if task is None:
            raise HarmfulSkillBenchError(f"skill metadata has no reviewed task: {anon_id}")
        for field in ("platform", "category", "tier"):
            if metadata[field] != task[field]:
                raise HarmfulSkillBenchError(f"task/metadata {field} disagreement for {anon_id}")
        platform = _require_string(metadata["platform"], f"{anon_id}.platform", max_bytes=32)
        category = _require_string(metadata["category"], f"{anon_id}.category", max_bytes=16)
        tier = _require_string(metadata["tier"], f"{anon_id}.tier", max_bytes=16)
        if platform not in _PLATFORMS or category not in EXPECTED_CATEGORIES or tier not in _TIERS:
            raise HarmfulSkillBenchError(f"unknown enum value in metadata for {anon_id}")
        expected_tier = "tier2" if category.startswith("H") else "tier1"
        if tier != expected_tier:
            raise HarmfulSkillBenchError(f"category/tier disagreement for {anon_id}")
        directory = metadata_path.parent
        samples.append(
            HarmfulSkillSample(
                anon_id=anon_id,
                platform=platform,
                category=category,
                tier=tier,
                name=_require_string(task["name"], f"{anon_id}.name"),
                description=_require_string(task["description"], f"{anon_id}.description"),
                selected_task=_require_string(task["selected_task"], f"{anon_id}.selected_task"),
                directory=directory,
                skill_path=directory / "SKILL.md",
            )
        )

    if set(tasks) != seen:
        raise HarmfulSkillBenchError("reviewed tasks and skill metadata identifiers differ")
    category_counts = Counter(sample.category for sample in samples)
    if category_counts != Counter({category: 10 for category in EXPECTED_CATEGORIES}):
        raise HarmfulSkillBenchError(f"category distribution drift: {dict(sorted(category_counts.items()))}")
    platform_counts = Counter(sample.platform for sample in samples)
    if platform_counts != Counter(EXPECTED_PLATFORM_COUNTS):
        raise HarmfulSkillBenchError(f"platform distribution drift: {dict(sorted(platform_counts.items()))}")
    tier_counts = Counter(sample.tier for sample in samples)
    if tier_counts != Counter(EXPECTED_TIER_COUNTS):
        raise HarmfulSkillBenchError(f"tier distribution drift: {dict(sorted(tier_counts.items()))}")

    samples.sort(key=lambda sample: sample.anon_id)
    snapshot = HarmfulSkillSnapshot(
        root=root,
        revision=revision,
        integrity_hashes_pending=bool(dataset["integrity"]["hashes_pending"]),
        samples=tuple(samples),
    )
    # Resolve both partitions at load time so a typo or upstream identity drift
    # cannot remain latent until an expensive model run.
    snapshot.selected("dev")
    snapshot.selected("held-back")
    return snapshot


def read_skill_excerpt(sample: HarmfulSkillSample, *, max_characters: int = 8_000) -> tuple[str, bool]:
    """Read a bounded SKILL document as inert text; missing files stay explicit."""

    if not sample.skill_path.exists():
        return "", True
    text = _read_regular_text(sample.skill_path, limit=_MAX_SKILL_BYTES)
    return text[:max_characters], len(text) > max_characters


def audit_ingestion(snapshot: HarmfulSkillSnapshot, *, loader: _SkillLoader | None = None) -> dict[str, Any]:
    """Run strict loading plus a clearly separate lenient recovery audit.

    The lenient pass is attempted only for strict failures and never changes
    the authoritative strict counts.
    """

    if loader is None:
        from skill_scanner.core.loader import SkillLoader

        loader = SkillLoader()

    def error_record(sample: HarmfulSkillSample, exc: Exception, code: str) -> dict[str, str]:
        message = str(exc).replace(str(snapshot.root), "<snapshot>")
        return {
            "anon_id": sample.anon_id,
            "category": sample.category,
            "code": code,
            "error_type": type(exc).__name__,
            "message": message[:512],
        }

    strict_errors: list[dict[str, str]] = []
    strict_failed: list[HarmfulSkillSample] = []
    for sample in snapshot.samples:
        try:
            if not sample.skill_path.exists():
                raise FileNotFoundError("SKILL.md is missing")
            loader.load_skill(sample.directory, lenient=False)
        except Exception as exc:
            code = "missing_skill_document" if not sample.skill_path.exists() else "strict_loader_error"
            strict_errors.append(error_record(sample, exc, code))
            strict_failed.append(sample)

    recovered: list[dict[str, str]] = []
    lenient_errors: list[dict[str, str]] = []
    for sample in strict_failed:
        try:
            loader.load_skill(sample.directory, lenient=True)
            recovered.append({"anon_id": sample.anon_id, "category": sample.category})
        except Exception as exc:
            code = "missing_skill_document" if not sample.skill_path.exists() else "lenient_loader_error"
            lenient_errors.append(error_record(sample, exc, code))

    return {
        "population": len(snapshot.samples),
        "strict": {
            "authoritative": True,
            "loaded": len(snapshot.samples) - len(strict_errors),
            "errors": strict_errors,
            "error_count": len(strict_errors),
        },
        "lenient_supplemental": {
            "authoritative": False,
            "attempted": len(strict_failed),
            "recovered": recovered,
            "recovered_count": len(recovered),
            "unresolved": lenient_errors,
            "unresolved_count": len(lenient_errors),
            "note": "Lenient recovery never removes a row or error from the strict 200-sample denominator.",
        },
    }
