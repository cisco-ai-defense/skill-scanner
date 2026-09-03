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

"""Safe offline adapters for three GitHub prompt-injection corpora.

The adapters consume deliberately narrow, pre-acquired snapshots.  They have
no acquisition, archive extraction, import, execution, or network path.  Every
accepted source file is byte-pinned to the repository revision recorded below,
and the complete input tree must contain exactly the allowlisted files.

The repository-wide dataset lock pins the reviewed source-file manifests.  A
matching manifest makes the input immutable, but not authoritative: all three
corpora remain supplemental and nonblocking, and NotInject is not package-level
benign ground truth.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

from evals.datasets.public_datasets import (
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    materialize_skill_files,
    validate_artifact_manifest,
)

INJECAGENT_DATASET_ID: Final = "uiuc-kang-lab/InjecAgent"
IN_PAGE_DATASET_ID: Final = "SoheilKhodayari/in_page_prompt_injection_pub"
NOTINJECT_DATASET_ID: Final = "InjecGuard/InjecGuard"

INJECAGENT_REVISION: Final = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
IN_PAGE_REVISION: Final = "0a04d1762cf60957f954f16a6cb9525ab32d6bca"
NOTINJECT_REVISION: Final = "cb1531f36bffb38b6493438217b36cda8875da8a"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SAMPLE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]")
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_MAX_PATH_BYTES = 1_024
_MAX_TEXT_BYTES = 512 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_ITEMS = 100_000
_ADAPTER_SCHEMA_VERSION: Final = "github-prompt-injection-v1"

_INJECAGENT_FIELDS: Final = frozenset(
    {
        "Attacker Tools",
        "Modifed",  # Upstream spelling is part of the pinned schema.
        "Attacker Instruction",
        "Expected Achievements",
        "Attack Type",
        "User Tool",
        "User Instruction",
        "Tool Parameters",
        "Tool Response Template",
        "Thought",
        "Tool Response",
    }
)
_INJECAGENT_ATTACK_TYPES: Final = frozenset(
    {"Data Security Harm", "Financial Harm", "Physical Harm", "Financial Data", "Others", "Physical Data"}
)

IN_PAGE_FIELDS: Final = (
    "row",
    "data_source",
    "tranco_ranking",
    "crux_ranking",
    "chrome_topics",
    "jsonl_file",
    "jsonl_index",
    "inclusion",
    "text",
    "prompt",
    "origin",
    "ID",
    "url",
    "pattern",
    "fp",
    "position",
    "display_none",
    "background_color",
    "color_css",
    "font_size",
    "color_prop",
    "font_prop",
    "json_ld",
    "lang_tld",
    "lang_html",
    "cc_tld",
    "asn",
    "asn_org",
    "AI Bot Identification (human verification)",
    "Content & Reputation Manipulation|Citation Forcing",
    "Content & Reputation Manipulation|Content / Product Promotion",
    "Content & Reputation Manipulation|Personal Job Candidate Promotion",
    "Content & Reputation Manipulation|Positive Review Forcing",
    "Content & Reputation Manipulation|SEO / Backlink Injection",
    "Data Exfiltration|Leak System Prompt",
    "Data Exfiltration|Leak Secret",
    "Data Protection|social_media_bots",
    "Data Protection|non_personal_pages",
    "Data Protection|personal_pages",
    "General Instruction Manipulation",
    "System Disruption / Degradation|Command Injection",
    "System Disruption / Degradation|Constraint Removal",
    "System Disruption / Degradation|Garbage Injection (Corruption)",
    "System Disruption / Degradation|Model Self-Modification",
    "honeypot",
    "normalized",
    "lexical_cluster",
    "embedding_cluster",
    "mnli_task_override",
    "mnli_conditional_logic_trigger",
    "mnli_authority_pressure",
    "mnli_role_playing",
    "mnli_identity_rewrite",
    "mnli_jailbreak_mode",
    "mnli_content_injection",
    "mnli_forced_output_format",
    "user_interactions",
    "third_party_platform_hosted",
    "first_party_content",
    "agents_DS",
    "agents_SE",
    "agents_CS",
    "agents_HR",
    "agents_TE",
)

_IN_PAGE_TAXONOMY_FIELDS: Final = frozenset(IN_PAGE_FIELDS[28:45])
_IN_PAGE_BINARY_FIELDS: Final = frozenset(IN_PAGE_FIELDS[48:])
_NOTINJECT_FIELDS: Final = frozenset({"prompt", "word_list", "category"})
_PROJECTION_FIELDS: Final = frozenset(
    {
        "dataset_id",
        "sample_id",
        "source_id",
        "repository_group_id",
        "structural_family_id",
        "lexical_template_id",
        "benchmark_labels",
        "split",
        "parent_sample_id",
        "split_inherited_from",
        "dedup_parent_id",
        "dedup_relation",
        "content_sha256",
        "normalized_content_sha256",
        "lexical_template_sha256",
        "control_content_sha256",
        "trigger_count",
    }
)
_SOURCE_SCHEMA_FIELDS: Final = {
    INJECAGENT_DATASET_ID: ("injecagent_case", _INJECAGENT_FIELDS),
    IN_PAGE_DATASET_ID: ("dataset_tp", frozenset(IN_PAGE_FIELDS)),
    NOTINJECT_DATASET_ID: ("notinject", _NOTINJECT_FIELDS),
}
_REQUIRED_APPROVED_USES: Final = {
    INJECAGENT_DATASET_ID: frozenset(
        {
            "supplemental_inert_indirect_prompt_injection_fixtures",
            "supplemental_positive_indirect_injection_signal_recall",
            "supplemental_base_control_differential_signal_recall",
        }
    ),
    IN_PAGE_DATASET_ID: frozenset(
        {
            "supplemental_inert_indirect_prompt_injection_fixtures",
            "supplemental_positive_indirect_injection_signal_recall",
        }
    ),
    NOTINJECT_DATASET_ID: frozenset({"diagnostic_flagged_rate", "hard_negative_mining"}),
}
_REQUIRED_PROHIBITED_USES: Final = {
    INJECAGENT_DATASET_ID: frozenset(
        {
            "blocking_package_accuracy_gate",
            "package_block_recall_denominator",
            "release_authoritative_metric",
            "execute_agent_tools",
            "contact_external_services",
            "execute_samples",
        }
    ),
    IN_PAGE_DATASET_ID: frozenset(
        {
            "blocking_package_accuracy_gate",
            "package_block_recall_denominator",
            "release_authoritative_metric",
            "network_enabled_analysis",
            "execute_samples",
        }
    ),
    NOTINJECT_DATASET_ID: frozenset(
        {
            "blocking_package_accuracy_gate",
            "package_level_benign_fpr_denominator",
            "release_authoritative_metric",
            "treat_as_package_level_benign_ground_truth",
            "execute_samples",
        }
    ),
}


class GitHubPromptInjectionError(ValueError):
    """Raised when a snapshot is unsafe or differs from its pinned contract."""


@dataclass(frozen=True)
class ArtifactSpec:
    """One byte-pinned file in an offline snapshot."""

    path: str
    sha256: str
    size_bytes: int
    row_count: int


@dataclass(frozen=True)
class SnapshotContract:
    """Closed file inventory for one reviewed repository revision."""

    dataset_id: str
    revision: str
    kind: str
    artifacts: tuple[ArtifactSpec, ...]


@dataclass(frozen=True)
class PromptInjectionSample:
    """Content plus source-disjoint and deduplication identities."""

    dataset_id: str
    sample_id: str
    source_id: str
    repository_group_id: str
    structural_family_id: str
    lexical_template_id: str
    benchmark_labels: tuple[str, ...]
    split: str
    parent_sample_id: str | None
    split_inherited_from: str
    dedup_parent_id: str
    dedup_relation: str
    content_sha256: str
    normalized_content_sha256: str
    lexical_template_sha256: str
    control_content_sha256: str | None
    trigger_count: int
    payload: str
    control_payload: str | None


@dataclass(frozen=True)
class GitHubPromptInjectionSnapshot:
    """Validated, byte-pinned supplemental snapshot."""

    root: Path
    dataset_id: str
    revision: str
    kind: str
    adapter_schema_version: str
    dataset_lock_path: Path | None
    lock_entry_sha256: str
    access: str
    license_spdx: str
    license_code_spdx: str | None
    download_policy: str
    lock_hashes_pending: bool
    observed_artifact_manifest_sha256: str
    artifacts: tuple[ArtifactSpec, ...]
    samples: tuple[PromptInjectionSample, ...]


_CONTRACTS: dict[str, SnapshotContract] = {
    INJECAGENT_DATASET_ID: SnapshotContract(
        dataset_id=INJECAGENT_DATASET_ID,
        revision=INJECAGENT_REVISION,
        kind="injecagent_positive",
        artifacts=(
            ArtifactSpec(
                "data/test_cases_dh_base.json",
                "0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305",
                672_918,
                510,
            ),
            ArtifactSpec(
                "data/test_cases_dh_enhanced.json",
                "885602716b72c18af80695ce6c2e1f242fa03163bc90b0788b0c5e4ab6216d50",
                721_878,
                510,
            ),
            ArtifactSpec(
                "data/test_cases_ds_base.json",
                "4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9",
                765_370,
                544,
            ),
            ArtifactSpec(
                "data/test_cases_ds_enhanced.json",
                "7bc510868df032511053fc40e8470e68a041fb7148d055112093594bf73ab0ce",
                817_594,
                544,
            ),
        ),
    ),
    IN_PAGE_DATASET_ID: SnapshotContract(
        dataset_id=IN_PAGE_DATASET_ID,
        revision=IN_PAGE_REVISION,
        kind="in_page_positive",
        artifacts=(
            ArtifactSpec(
                "data/dataset_tp.csv",
                "aa4cae8559f6b6b7a3a35075a12958933c7f194b3801fe80b32f8c54b28d43c7",
                17_955_335,
                15_387,
            ),
        ),
    ),
    NOTINJECT_DATASET_ID: SnapshotContract(
        dataset_id=NOTINJECT_DATASET_ID,
        revision=NOTINJECT_REVISION,
        kind="notinject_hard_negative",
        artifacts=(
            ArtifactSpec(
                "datasets/NotInject_one.json",
                "69b535596d95102424e9c5946944feb4f2d596687eb8213f2ecad75478e5ffdd",
                26_117,
                113,
            ),
            ArtifactSpec(
                "datasets/NotInject_two.json",
                "6043d94e75b48d8e7682d25dc79eaf45359e1e561ce520e3b8fd5625a91060c6",
                29_902,
                113,
            ),
            ArtifactSpec(
                "datasets/NotInject_three.json",
                "ef01eff0d761d2e34571b3fdbcec08c30cd93efe8d0e1a2eb5c2baeb1873b070",
                35_765,
                113,
            ),
        ),
    ),
}


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GitHubPromptInjectionError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise GitHubPromptInjectionError(f"JSON contains non-finite number {value}")


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\x00" in value or "\\" in value or _DRIVE_RE.match(value):
        raise GitHubPromptInjectionError(f"unsafe or ambiguous snapshot path: {value!r}")
    if len(value.encode("utf-8")) > _MAX_PATH_BYTES:
        raise GitHubPromptInjectionError("snapshot path exceeds the byte limit")
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts):
        raise GitHubPromptInjectionError(f"snapshot path must be normalized and relative: {value!r}")
    return path


def _validate_tree(root: Path, contract: SnapshotContract) -> None:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise GitHubPromptInjectionError(f"snapshot root is unavailable: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise GitHubPromptInjectionError("snapshot root must be an existing non-symlink directory")

    allowed_files = {_safe_relative_path(artifact.path).as_posix() for artifact in contract.artifacts}
    allowed_directories = {
        parent.as_posix()
        for artifact in contract.artifacts
        for parent in _safe_relative_path(artifact.path).parents
        if parent != PurePosixPath(".")
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    entry_count = 0
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        for name in [*directory_names, *file_names]:
            entry_count += 1
            if entry_count > len(allowed_files) + len(allowed_directories):
                raise GitHubPromptInjectionError("snapshot contains paths outside the closed allowlist")
            member = current / name
            relative = member.relative_to(root).as_posix()
            _safe_relative_path(relative)
            try:
                member_stat = member.lstat()
            except OSError as exc:
                raise GitHubPromptInjectionError(f"cannot inspect snapshot member {relative}: {exc}") from exc
            if stat.S_ISLNK(member_stat.st_mode):
                raise GitHubPromptInjectionError(f"snapshot contains a symbolic link: {relative}")
            if name in directory_names:
                if not stat.S_ISDIR(member_stat.st_mode):
                    raise GitHubPromptInjectionError(f"snapshot contains a non-directory tree entry: {relative}")
                if relative not in allowed_directories:
                    raise GitHubPromptInjectionError(f"snapshot contains an unexpected directory: {relative}")
                observed_directories.add(relative)
                continue
            if not stat.S_ISREG(member_stat.st_mode):
                raise GitHubPromptInjectionError(f"snapshot contains a device or non-regular file: {relative}")
            if member_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                raise GitHubPromptInjectionError(f"snapshot contains an executable-mode file: {relative}")
            if relative not in allowed_files:
                raise GitHubPromptInjectionError(
                    f"snapshot contains an unexpected, binary, executable, or archive path: {relative}"
                )
            observed_files.add(relative)

    if observed_files != allowed_files or observed_directories != allowed_directories:
        missing = sorted((allowed_files - observed_files) | (allowed_directories - observed_directories))
        raise GitHubPromptInjectionError(f"snapshot is missing required allowlisted paths: {missing}")


def _read_verified_bytes(root: Path, artifact: ArtifactSpec) -> bytes:
    parts = _safe_relative_path(artifact.path).parts
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW

    file_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK

    root_descriptor = -1
    directory_descriptor = -1
    descriptor = -1
    try:
        root_descriptor = os.open(root, directory_flags)
        directory_descriptor = root_descriptor
        for component in parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            if directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
    except OSError as exc:
        if directory_descriptor >= 0 and directory_descriptor != root_descriptor:
            os.close(directory_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise GitHubPromptInjectionError(f"cannot safely open {artifact.path}: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise GitHubPromptInjectionError(f"snapshot member is not a regular file: {artifact.path}")
        if file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise GitHubPromptInjectionError(f"snapshot member is executable: {artifact.path}")
        if file_stat.st_size != artifact.size_bytes:
            raise GitHubPromptInjectionError(
                f"snapshot size drift for {artifact.path}: expected {artifact.size_bytes}, received {file_stat.st_size}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(artifact.size_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_descriptor >= 0 and directory_descriptor != root_descriptor:
            os.close(directory_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
    if len(raw) != artifact.size_bytes:
        raise GitHubPromptInjectionError(f"snapshot changed while reading {artifact.path}")
    digest = hashlib.sha256(raw).hexdigest()
    if not _HEX64_RE.fullmatch(artifact.sha256) or digest != artifact.sha256:
        raise GitHubPromptInjectionError(f"snapshot SHA-256 drift for {artifact.path}")
    return raw


def _decode_utf8(raw: bytes, location: str) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubPromptInjectionError(f"{location} is not UTF-8 text") from exc
    if "\x00" in value:
        raise GitHubPromptInjectionError(f"{location} contains a binary NUL byte")
    return value


def _bounded_json(raw: bytes, location: str) -> Any:
    text = _decode_utf8(raw, location)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except (json.JSONDecodeError, UnicodeError, MemoryError, RecursionError) as exc:
        raise GitHubPromptInjectionError(f"invalid JSON in {location}: {exc}") from exc

    item_count = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        item_count += 1
        if item_count > _MAX_JSON_ITEMS:
            raise GitHubPromptInjectionError(f"{location} exceeds the JSON item limit")
        if depth > _MAX_JSON_DEPTH:
            raise GitHubPromptInjectionError(f"{location} exceeds the JSON depth limit")
        if isinstance(item, Mapping):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _text(
    value: Any,
    location: str,
    *,
    allow_empty: bool = False,
    allow_controls: bool = False,
    max_bytes: int = _MAX_TEXT_BYTES,
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise GitHubPromptInjectionError(
            f"{location} must be a{' possibly empty' if allow_empty else ' non-empty'} string"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise GitHubPromptInjectionError(f"{location} must be valid UTF-8") from exc
    if len(encoded) > max_bytes or (not allow_controls and _CONTROL_RE.search(value)):
        raise GitHubPromptInjectionError(f"{location} contains unsafe controls or exceeds the text limit")
    return value


def _canonical_hash(*values: object) -> str:
    encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalized_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _normalized_hash(value: str) -> str:
    return hashlib.sha256(_normalized_text(value).encode("utf-8")).hexdigest()


def _lexical_template_hash(value: str) -> str:
    template = re.sub(r"\d+", "<number>", _normalized_text(value))
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def _validate_sample_projection(sample: PromptInjectionSample, *, dataset_id: str) -> None:
    if sample.dataset_id != dataset_id:
        raise GitHubPromptInjectionError("sample dataset identity does not match its snapshot")
    identifiers = {
        "sample_id": sample.sample_id,
        "dedup_parent_id": sample.dedup_parent_id,
        "split_inherited_from": sample.split_inherited_from,
    }
    if sample.parent_sample_id is not None:
        identifiers["parent_sample_id"] = sample.parent_sample_id
    for name, value in identifiers.items():
        if not _SAFE_SAMPLE_ID_RE.fullmatch(value):
            raise GitHubPromptInjectionError(f"sample {name} is not a safe bounded identity")
    if sample.dedup_relation not in {"canonical", "exact_duplicate", "normalized_duplicate"}:
        raise GitHubPromptInjectionError("sample dedup relation is invalid")
    if sample.split != "supplemental" or sample.trigger_count < 0:
        raise GitHubPromptInjectionError("sample split or trigger count is invalid")
    for value in (
        sample.content_sha256,
        sample.normalized_content_sha256,
        sample.lexical_template_sha256,
    ):
        if not _HEX64_RE.fullmatch(value):
            raise GitHubPromptInjectionError("sample content identity is invalid")
    if sample.control_content_sha256 is not None and not _HEX64_RE.fullmatch(sample.control_content_sha256):
        raise GitHubPromptInjectionError("sample control content identity is invalid")
    if (sample.control_payload is None) != (sample.control_content_sha256 is None):
        raise GitHubPromptInjectionError("sample control payload identity is incomplete")
    if hashlib.sha256(sample.payload.encode("utf-8")).hexdigest() != sample.content_sha256:
        raise GitHubPromptInjectionError("sample payload content identity drift")
    if _normalized_hash(sample.payload) != sample.normalized_content_sha256:
        raise GitHubPromptInjectionError("sample normalized content identity drift")
    if _lexical_template_hash(sample.payload) != sample.lexical_template_sha256:
        raise GitHubPromptInjectionError("sample lexical template identity drift")
    if sample.control_payload is not None:
        control_digest = hashlib.sha256(sample.control_payload.encode("utf-8")).hexdigest()
        if control_digest != sample.control_content_sha256:
            raise GitHubPromptInjectionError("sample control content identity drift")


def _finalize_dedup(samples: Sequence[PromptInjectionSample]) -> tuple[PromptInjectionSample, ...]:
    exact_parents: dict[str, str] = {}
    normalized_parents: dict[str, str] = {}
    finalized: list[PromptInjectionSample] = []
    for sample in samples:
        if sample.content_sha256 in exact_parents:
            dedup_parent = exact_parents[sample.content_sha256]
            relation = "exact_duplicate"
        elif sample.normalized_content_sha256 in normalized_parents:
            dedup_parent = normalized_parents[sample.normalized_content_sha256]
            relation = "normalized_duplicate"
            exact_parents[sample.content_sha256] = dedup_parent
        else:
            dedup_parent = sample.sample_id
            relation = "canonical"
            exact_parents[sample.content_sha256] = sample.sample_id
            normalized_parents[sample.normalized_content_sha256] = sample.sample_id
        inherited_from = sample.parent_sample_id or dedup_parent
        finalized.append(
            replace(
                sample,
                dedup_parent_id=dedup_parent,
                dedup_relation=relation,
                split_inherited_from=inherited_from,
            )
        )
    identities = [sample.sample_id for sample in finalized]
    if len(identities) != len(set(identities)):
        raise GitHubPromptInjectionError("snapshot contains duplicate sample identities")
    return tuple(finalized)


def _load_locked_contract(
    contract: SnapshotContract,
    revision: str,
    dataset_lock: Path | None,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    lock = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
    dataset = get_locked_dataset(contract.dataset_id, lock)
    if revision != contract.revision or dataset.get("revision") != contract.revision:
        raise GitHubPromptInjectionError(
            f"{contract.dataset_id}: revision drift (expected {contract.revision}, received {revision})"
        )
    if dataset.get("provider") != "github":
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: provider must remain github")
    gating = dataset.get("gating")
    if not isinstance(gating, Mapping) or gating.get("blocking") is not False:
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: supplemental corpus must remain nonblocking")
    prohibited = dataset.get("prohibited_uses")
    if not isinstance(prohibited, list) or "execute_samples" not in prohibited:
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: lock must prohibit sample execution")
    approved = dataset.get("approved_uses")
    if not isinstance(approved, list) or not _REQUIRED_APPROVED_USES[contract.dataset_id].issubset(approved):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: supplemental approved-use policy drift")
    if not _REQUIRED_PROHIBITED_USES[contract.dataset_id].issubset(prohibited):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: supplemental prohibited-use policy drift")
    integrity = dataset.get("integrity")
    if not isinstance(integrity, Mapping) or not isinstance(integrity.get("hashes_pending"), bool):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: lock integrity policy is invalid")
    if integrity["hashes_pending"] is not False or not isinstance(integrity.get("artifact_manifest_sha256"), str):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: immutable supplemental manifest is not pinned")
    access = dataset.get("access")
    license_metadata = dataset.get("license")
    download_policy = dataset.get("download_policy")
    if (
        not isinstance(access, str)
        or not isinstance(download_policy, str)
        or not isinstance(license_metadata, Mapping)
        or not isinstance(license_metadata.get("spdx"), str)
    ):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: provenance policy is incomplete")
    expected = dataset.get("expected")
    if not isinstance(expected, Mapping):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: expected schema/count contract is missing")
    row_counts = expected.get("row_counts")
    expected_rows = _contract_row_counts(contract)
    if row_counts != expected_rows:
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: locked row-count protocol drift")
    schemas = expected.get("schemas")
    schema_name, source_fields = _SOURCE_SCHEMA_FIELDS[contract.dataset_id]
    if not isinstance(schemas, Mapping) or set(schemas) != {schema_name, "evaluation_projection"}:
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: locked schema protocol drift")
    source_schema = schemas[schema_name]
    projection_schema = schemas["evaluation_projection"]
    if (
        not isinstance(source_schema, Mapping)
        or set(source_schema.get("exact_fields", ())) != source_fields
        or not isinstance(projection_schema, Mapping)
        or set(projection_schema.get("exact_fields", ())) != _PROJECTION_FIELDS
    ):
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: locked exact-field protocol drift")
    return lock, dataset


def _contract_row_counts(contract: SnapshotContract) -> dict[str, int]:
    for artifact in contract.artifacts:
        _safe_relative_path(artifact.path)
    if contract.dataset_id == INJECAGENT_DATASET_ID:
        names = {
            "data/test_cases_dh_base.json": "base/direct_harm",
            "data/test_cases_ds_base.json": "base/data_stealing",
            "data/test_cases_dh_enhanced.json": "enhanced/direct_harm",
            "data/test_cases_ds_enhanced.json": "enhanced/data_stealing",
        }
    elif contract.dataset_id == IN_PAGE_DATASET_ID:
        names = {"data/dataset_tp.csv": "sanitized/dataset_tp"}
    else:
        names = {
            "datasets/NotInject_one.json": "notinject/one",
            "datasets/NotInject_two.json": "notinject/two",
            "datasets/NotInject_three.json": "notinject/three",
        }
    if set(names) != {artifact.path for artifact in contract.artifacts}:
        raise GitHubPromptInjectionError(f"{contract.dataset_id}: adapter artifact protocol drift")
    return {names[artifact.path]: artifact.row_count for artifact in contract.artifacts}


def _snapshot(
    *,
    root: Path,
    contract: SnapshotContract,
    lock: Mapping[str, Any],
    dataset: Mapping[str, Any],
    dataset_lock: Path | None,
    samples: Sequence[PromptInjectionSample],
) -> GitHubPromptInjectionSnapshot:
    observed_manifest = artifact_manifest_sha256(
        contract.dataset_id,
        [{"path": item.path, "sha256": item.sha256, "size_bytes": item.size_bytes} for item in contract.artifacts],
        manifest=lock,
    )
    validate_artifact_manifest(
        contract.dataset_id,
        [{"path": item.path, "sha256": item.sha256, "size_bytes": item.size_bytes} for item in contract.artifacts],
        manifest_sha256=observed_manifest,
        manifest=lock,
    )
    finalized_samples = _finalize_dedup(samples)
    for sample in finalized_samples:
        _validate_sample_projection(sample, dataset_id=contract.dataset_id)
    license_metadata = cast(Mapping[str, Any], dataset["license"])
    lock_entry_sha256 = hashlib.sha256(
        json.dumps(dataset, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return GitHubPromptInjectionSnapshot(
        root=root.resolve(strict=True),
        dataset_id=contract.dataset_id,
        revision=contract.revision,
        kind=contract.kind,
        adapter_schema_version=_ADAPTER_SCHEMA_VERSION,
        dataset_lock_path=dataset_lock.resolve(strict=True) if dataset_lock is not None else None,
        lock_entry_sha256=lock_entry_sha256,
        access=cast(str, dataset["access"]),
        license_spdx=cast(str, license_metadata["spdx"]),
        license_code_spdx=cast(str | None, license_metadata.get("code_spdx")),
        download_policy=cast(str, dataset["download_policy"]),
        lock_hashes_pending=bool(dataset["integrity"]["hashes_pending"]),
        observed_artifact_manifest_sha256=observed_manifest,
        artifacts=contract.artifacts,
        samples=finalized_samples,
    )


def _validated_injecagent_rows(raw: bytes, artifact: ArtifactSpec) -> list[Mapping[str, Any]]:
    parsed = _bounded_json(raw, artifact.path)
    if not isinstance(parsed, list) or len(parsed) != artifact.row_count:
        received = len(parsed) if isinstance(parsed, list) else "non-list"
        raise GitHubPromptInjectionError(
            f"{artifact.path}: row-count drift (expected {artifact.row_count}, received {received})"
        )
    rows: list[Mapping[str, Any]] = []
    for index, row in enumerate(parsed):
        location = f"{artifact.path}[{index}]"
        if not isinstance(row, Mapping) or set(row) != _INJECAGENT_FIELDS:
            actual = set(row) if isinstance(row, Mapping) else set()
            raise GitHubPromptInjectionError(
                f"{location}: schema drift (missing={sorted(_INJECAGENT_FIELDS - actual)}, "
                f"unexpected={sorted(actual - _INJECAGENT_FIELDS)})"
            )
        tools = row["Attacker Tools"]
        if (
            not isinstance(tools, list)
            or not 1 <= len(tools) <= 16
            or len(tools) != len(set(tools))
            or not all(isinstance(tool, str) and tool for tool in tools)
        ):
            raise GitHubPromptInjectionError(f"{location}.Attacker Tools must contain unique tool names")
        for tool_index, tool in enumerate(tools):
            _text(tool, f"{location}.Attacker Tools[{tool_index}]", max_bytes=1_024)
        modified = row["Modifed"]
        if isinstance(modified, bool) or not isinstance(modified, int) or modified not in {0, 1}:
            raise GitHubPromptInjectionError(f"{location}.Modifed must be 0 or 1")
        for field in _INJECAGENT_FIELDS - {"Attacker Tools", "Modifed"}:
            _text(row[field], f"{location}.{field}")
        if row["Attack Type"] not in _INJECAGENT_ATTACK_TYPES:
            raise GitHubPromptInjectionError(f"{location}.Attack Type is outside the pinned taxonomy")
        rows.append(row)
    return rows


def load_injecagent_snapshot(
    root: Path,
    *,
    revision: str,
    dataset_lock: Path | None = None,
) -> GitHubPromptInjectionSnapshot:
    """Load only the paired base/enhanced InjecAgent JSON fixtures."""

    contract = _CONTRACTS[INJECAGENT_DATASET_ID]
    lock, dataset = _load_locked_contract(contract, revision, dataset_lock)
    root = Path(root)
    _validate_tree(root, contract)
    by_path = {artifact.path: artifact for artifact in contract.artifacts}
    samples: list[PromptInjectionSample] = []
    for attack_class in ("dh", "ds"):
        base_artifact = by_path[f"data/test_cases_{attack_class}_base.json"]
        enhanced_artifact = by_path[f"data/test_cases_{attack_class}_enhanced.json"]
        base_rows = _validated_injecagent_rows(_read_verified_bytes(root, base_artifact), base_artifact)
        enhanced_rows = _validated_injecagent_rows(_read_verified_bytes(root, enhanced_artifact), enhanced_artifact)
        for index, (base, enhanced) in enumerate(zip(base_rows, enhanced_rows, strict=True)):
            for field in _INJECAGENT_FIELDS - {"Tool Response"}:
                if base[field] != enhanced[field]:
                    raise GitHubPromptInjectionError(
                        f"InjecAgent {attack_class}[{index}] base/enhanced provenance drift in {field}"
                    )
            if base["Tool Response"] == enhanced["Tool Response"]:
                raise GitHubPromptInjectionError(
                    f"InjecAgent {attack_class}[{index}] enhanced response does not differ from its base parent"
                )
            payload = str(enhanced["Tool Response"])
            control_payload = str(base["Tool Response"])
            content_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            parent_id = f"injecagent-{attack_class}-base-{index:04d}-{_canonical_hash(base)[:16]}"
            sample_id = f"injecagent-{attack_class}-enhanced-{index:04d}-{_canonical_hash(enhanced)[:16]}"
            labels = (str(enhanced["Attack Type"]),)
            samples.append(
                PromptInjectionSample(
                    dataset_id=contract.dataset_id,
                    sample_id=sample_id,
                    source_id=f"injecagent:{attack_class}",
                    repository_group_id=f"{contract.dataset_id}@{contract.revision}",
                    structural_family_id=(
                        "injecagent-carrier-"
                        + _canonical_hash(
                            attack_class,
                            enhanced["User Tool"],
                            enhanced["Tool Response Template"],
                        )[:20]
                    ),
                    lexical_template_id=(
                        "injecagent-instruction-" + _lexical_template_hash(str(enhanced["Attacker Instruction"]))[:20]
                    ),
                    benchmark_labels=labels,
                    split="supplemental",
                    parent_sample_id=parent_id,
                    split_inherited_from=parent_id,
                    dedup_parent_id=sample_id,
                    dedup_relation="canonical",
                    content_sha256=content_sha,
                    normalized_content_sha256=_normalized_hash(payload),
                    lexical_template_sha256=_lexical_template_hash(payload),
                    control_content_sha256=hashlib.sha256(control_payload.encode("utf-8")).hexdigest(),
                    trigger_count=0,
                    payload=payload,
                    control_payload=control_payload,
                )
            )
    return _snapshot(
        root=root,
        contract=contract,
        lock=lock,
        dataset=dataset,
        dataset_lock=dataset_lock,
        samples=samples,
    )


def _in_page_labels(row: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(sorted(field for field in _IN_PAGE_TAXONOMY_FIELDS if row[field] == "1.0"))


def _validated_in_page_rows(raw: bytes, artifact: ArtifactSpec) -> list[Mapping[str, str]]:
    text = _decode_utf8(raw, artifact.path)
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if tuple(reader.fieldnames or ()) != IN_PAGE_FIELDS:
            raise GitHubPromptInjectionError("data/dataset_tp.csv: exact CSV header schema drift")
        rows = cast(list[dict[str, str]], list(reader))
    except (csv.Error, UnicodeError) as exc:
        raise GitHubPromptInjectionError(f"invalid CSV in {artifact.path}: {exc}") from exc
    if len(rows) != artifact.row_count:
        raise GitHubPromptInjectionError(
            f"{artifact.path}: row-count drift (expected {artifact.row_count}, received {len(rows)})"
        )
    seen_rows: set[int] = set()
    seen_ids: set[int] = set()
    for index, row in enumerate(rows):
        location = f"{artifact.path}[{index}]"
        if set(row) != set(IN_PAGE_FIELDS) or any(value is None for value in row.values()):
            raise GitHubPromptInjectionError(f"{location}: CSV row schema drift")
        for field, value in row.items():
            # Three byte-pinned upstream context fields contain DEL (0x7f).
            # That context is validated but never retained or materialized;
            # the actual prompt remains subject to the strict text policy.
            _text(
                value,
                f"{location}.{field}",
                allow_empty=True,
                allow_controls=field == "text",
            )
        try:
            row_id = int(row["row"])
            injection_id = int(row["ID"])
            lexical_cluster = int(row["lexical_cluster"])
            embedding_cluster = int(row["embedding_cluster"])
        except ValueError as exc:
            raise GitHubPromptInjectionError(f"{location}: numeric identity field is invalid") from exc
        if row_id < 0 or injection_id <= 0 or lexical_cluster < 0 or embedding_cluster < -1:
            raise GitHubPromptInjectionError(f"{location}: numeric identity field is out of range")
        if row_id in seen_rows or injection_id in seen_ids:
            raise GitHubPromptInjectionError(f"{location}: duplicate row or injection identity")
        seen_rows.add(row_id)
        seen_ids.add(injection_id)
        if row["fp"] != "0":
            raise GitHubPromptInjectionError(f"{location}: dataset_tp row must retain fp=0")
        if row["data_source"] not in {"commoncrawl", "censys", "shodan"}:
            raise GitHubPromptInjectionError(f"{location}: unexpected data_source")
        if row["position"] not in {"http_body", "http_header", "site_level"}:
            raise GitHubPromptInjectionError(f"{location}: unexpected injection position")
        if not row["prompt"] or not row["normalized"]:
            raise GitHubPromptInjectionError(f"{location}: prompt and normalized text must be non-empty")
        for field in _IN_PAGE_TAXONOMY_FIELDS:
            if row[field] not in {"", "0.0", "1.0"}:
                raise GitHubPromptInjectionError(f"{location}.{field}: expected a tri-state label")
        for field in _IN_PAGE_BINARY_FIELDS:
            if row[field] not in {"0", "1"}:
                raise GitHubPromptInjectionError(f"{location}.{field}: expected a binary label")
    return [cast(Mapping[str, str], row) for row in rows]


def load_in_page_snapshot(
    root: Path,
    *,
    revision: str,
    dataset_lock: Path | None = None,
) -> GitHubPromptInjectionSnapshot:
    """Load the sanitized, validated true-positive in-page prompt subset."""

    contract = _CONTRACTS[IN_PAGE_DATASET_ID]
    lock, dataset = _load_locked_contract(contract, revision, dataset_lock)
    root = Path(root)
    _validate_tree(root, contract)
    artifact = contract.artifacts[0]
    rows = _validated_in_page_rows(_read_verified_bytes(root, artifact), artifact)
    samples: list[PromptInjectionSample] = []
    for row in rows:
        payload = row["prompt"]
        sample_id = f"in-page-tp-{int(row['ID']):05d}"
        labels = _in_page_labels(row) or ("validated_in_page_prompt_injection",)
        samples.append(
            PromptInjectionSample(
                dataset_id=contract.dataset_id,
                sample_id=sample_id,
                source_id=f"in-page:{row['data_source']}",
                repository_group_id=f"{contract.dataset_id}@{contract.revision}",
                structural_family_id=f"in-page-{row['position']}-embedding-{row['embedding_cluster']}",
                lexical_template_id=f"in-page-lexical-{row['lexical_cluster']}",
                benchmark_labels=labels,
                split="supplemental",
                parent_sample_id=f"in-page-raw-{int(row['ID']):05d}",
                split_inherited_from=f"in-page-raw-{int(row['ID']):05d}",
                dedup_parent_id=sample_id,
                dedup_relation="canonical",
                content_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                normalized_content_sha256=_normalized_hash(payload),
                lexical_template_sha256=_lexical_template_hash(payload),
                control_content_sha256=None,
                trigger_count=0,
                payload=payload,
                control_payload=None,
            )
        )
    return _snapshot(
        root=root,
        contract=contract,
        lock=lock,
        dataset=dataset,
        dataset_lock=dataset_lock,
        samples=samples,
    )


def _validated_notinject_rows(raw: bytes, artifact: ArtifactSpec, trigger_count: int) -> list[Mapping[str, Any]]:
    parsed = _bounded_json(raw, artifact.path)
    if not isinstance(parsed, list) or len(parsed) != artifact.row_count:
        received = len(parsed) if isinstance(parsed, list) else "non-list"
        raise GitHubPromptInjectionError(
            f"{artifact.path}: row-count drift (expected {artifact.row_count}, received {received})"
        )
    rows: list[Mapping[str, Any]] = []
    for index, row in enumerate(parsed):
        location = f"{artifact.path}[{index}]"
        if not isinstance(row, Mapping) or set(row) != _NOTINJECT_FIELDS:
            actual = set(row) if isinstance(row, Mapping) else set()
            raise GitHubPromptInjectionError(
                f"{location}: schema drift (missing={sorted(_NOTINJECT_FIELDS - actual)}, "
                f"unexpected={sorted(actual - _NOTINJECT_FIELDS)})"
            )
        prompt = _text(row["prompt"], f"{location}.prompt")
        category = _text(row["category"], f"{location}.category", max_bytes=256)
        if category not in {"Common Queries", "Technique Queries", "Virtual Creation", "Multilingual"}:
            raise GitHubPromptInjectionError(f"{location}.category is outside the NotInject taxonomy")
        words = row["word_list"]
        if (
            not isinstance(words, list)
            or len(words) != trigger_count
            or len(words) != len(set(words))
            or not all(isinstance(word, str) and word for word in words)
        ):
            raise GitHubPromptInjectionError(
                f"{location}.word_list must contain exactly {trigger_count} unique trigger words"
            )
        for word_index, word in enumerate(words):
            _text(word, f"{location}.word_list[{word_index}]", max_bytes=256)
        rows.append({"prompt": prompt, "category": category, "word_list": tuple(words)})
    return rows


def load_notinject_snapshot(
    root: Path,
    *,
    revision: str,
    dataset_lock: Path | None = None,
) -> GitHubPromptInjectionSnapshot:
    """Load NotInject strictly as a diagnostic hard-negative corpus."""

    contract = _CONTRACTS[NOTINJECT_DATASET_ID]
    lock, dataset = _load_locked_contract(contract, revision, dataset_lock)
    root = Path(root)
    _validate_tree(root, contract)
    counts_by_name = {"one": 1, "two": 2, "three": 3}
    samples: list[PromptInjectionSample] = []
    for artifact in contract.artifacts:
        subset = PurePosixPath(artifact.path).stem.removeprefix("NotInject_")
        trigger_count = counts_by_name.get(subset)
        if trigger_count is None:
            raise GitHubPromptInjectionError(f"unexpected NotInject subset: {subset}")
        rows = _validated_notinject_rows(_read_verified_bytes(root, artifact), artifact, trigger_count)
        for index, row in enumerate(rows):
            payload = str(row["prompt"])
            sample_id = f"notinject-{subset}-{_canonical_hash(subset, index, payload)[:24]}"
            samples.append(
                PromptInjectionSample(
                    dataset_id=contract.dataset_id,
                    sample_id=sample_id,
                    source_id=f"notinject:{subset}",
                    repository_group_id=f"{contract.dataset_id}@{contract.revision}",
                    structural_family_id=(
                        "notinject-"
                        + re.sub(r"[^a-z]+", "-", str(row["category"]).casefold()).strip("-")
                        + f"-{trigger_count}"
                    ),
                    lexical_template_id=f"notinject-generated-{subset}-{index:03d}",
                    benchmark_labels=(str(row["category"]),),
                    split="supplemental",
                    parent_sample_id=None,
                    split_inherited_from=sample_id,
                    dedup_parent_id=sample_id,
                    dedup_relation="canonical",
                    content_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    normalized_content_sha256=_normalized_hash(payload),
                    lexical_template_sha256=_lexical_template_hash(payload),
                    control_content_sha256=None,
                    trigger_count=trigger_count,
                    payload=payload,
                    control_payload=None,
                )
            )
    return _snapshot(
        root=root,
        contract=contract,
        lock=lock,
        dataset=dataset,
        dataset_lock=dataset_lock,
        samples=samples,
    )


def revalidate_snapshot(snapshot: GitHubPromptInjectionSnapshot) -> None:
    """Rebuild and compare the complete source-derived projection before a run."""

    contract = _CONTRACTS.get(snapshot.dataset_id)
    if (
        contract is None
        or contract.revision != snapshot.revision
        or contract.artifacts != snapshot.artifacts
        or snapshot.adapter_schema_version != _ADAPTER_SCHEMA_VERSION
    ):
        raise GitHubPromptInjectionError("snapshot contract identity changed after ingestion")
    loaders = {
        INJECAGENT_DATASET_ID: load_injecagent_snapshot,
        IN_PAGE_DATASET_ID: load_in_page_snapshot,
        NOTINJECT_DATASET_ID: load_notinject_snapshot,
    }
    rebuilt = loaders[snapshot.dataset_id](
        snapshot.root,
        revision=snapshot.revision,
        dataset_lock=snapshot.dataset_lock_path,
    )
    if rebuilt != snapshot:
        raise GitHubPromptInjectionError("snapshot projection or locked provenance changed after ingestion")


def materialize_inert_wrapper(
    sample: PromptInjectionSample,
    destination: Path,
    *,
    control: bool = False,
) -> Path:
    """Create a text-only SKILL.md wrapper without interpreting the payload."""

    _validate_sample_projection(sample, dataset_id=sample.dataset_id)
    if not _SAFE_SAMPLE_ID_RE.fullmatch(sample.sample_id):
        raise GitHubPromptInjectionError("sample identity cannot be used as a materialization path")
    if control and sample.control_payload is None:
        raise GitHubPromptInjectionError("sample has no paired control payload")
    payload = sample.control_payload if control else sample.payload
    expected_sha = sample.control_content_sha256 if control else sample.content_sha256
    if payload is None or expected_sha is None:
        raise GitHubPromptInjectionError("sample payload identity is incomplete")
    payload_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if payload_sha != expected_sha:
        raise GitHubPromptInjectionError(f"sample content identity drift: {sample.sample_id}")
    wrapper_name = f"{sample.sample_id}{'-control' if control else ''}"
    if not _SAFE_SAMPLE_ID_RE.fullmatch(wrapper_name):
        raise GitHubPromptInjectionError("sample wrapper identity exceeds the safe path bound")
    quoted_payload = "\n".join(f"> {line}" if line else ">" for line in payload.splitlines())
    if not quoted_payload:
        raise GitHubPromptInjectionError(f"sample payload is empty: {sample.sample_id}")
    wrapper = (
        "---\n"
        f"name: {wrapper_name}\n"
        'description: "Inert quoted-source evaluation fixture"\n'
        "---\n\n"
        "# Quoted source fixture\n\n"
        "The block below is preserved source text for static classification.\n\n"
        f"{quoted_payload}\n"
    )
    return materialize_skill_files(skill_md_content=wrapper, bundle_files=[], destination=destination)


__all__ = [
    "INJECAGENT_DATASET_ID",
    "INJECAGENT_REVISION",
    "IN_PAGE_DATASET_ID",
    "IN_PAGE_FIELDS",
    "IN_PAGE_REVISION",
    "NOTINJECT_DATASET_ID",
    "NOTINJECT_REVISION",
    "GitHubPromptInjectionError",
    "GitHubPromptInjectionSnapshot",
    "PromptInjectionSample",
    "load_in_page_snapshot",
    "load_injecagent_snapshot",
    "load_notinject_snapshot",
    "materialize_inert_wrapper",
    "revalidate_snapshot",
]
