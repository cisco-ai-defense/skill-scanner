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

"""Offline release gates for frozen detection benchmark reports.

The runner deliberately consumes reports that were already produced from
frozen, pre-materialized corpora.  It has no download, archive extraction,
sample execution, scanner invocation, or embedded-path loading behavior.

Artifact contract::

    public-corpus/
      candidate.json
      baseline.json
      repeated-runs.json              # five frozen-build deterministic runs
      golden-corpus.json              # frozen evidence's exact-golden identity
      rule-fixture-evidence.json       # required once a bundled rule is enforced
      repeated-comparison.json         # required once a bundled rule is enforced

    current-golden-corpus.json        # produced from this checkout; separate input

    private-corpus/                  # optional, supplemental, never blocking
      candidate.json
      baseline.json

``candidate.json`` and ``baseline.json`` use the version-one public benchmark
report contract. The public candidate is one complete release-profile corpus
run. ``repeated-runs.json`` binds five clean runs to the same frozen corpus,
build, policy, rules, CEL generation, exact-golden manifest, and normalized
detection-output hash. The separately supplied current golden manifest must
match the public artifact's bundled manifest exactly, preventing stale or
subset evidence from satisfying the gate. Private reports use the same metric contract plus a
``corpus`` object documenting ``id``, ``snapshot_sha256``, ``source_disjoint``,
``holdout_fraction``, ``samples``, ``malicious_or_contextual``, ``benign``, and
a hash-bound scanner-independent four-source label attestation. Optional private
evidence is reported independently and never changes the hard public release
result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypeGuard

# Permit direct execution from the repository checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evals.datasets.public_datasets import DatasetLockError, get_locked_dataset, load_dataset_lock
from evals.runners.benchmark_comparison import (
    normalized_loss_generation_sha256,
    normalized_loss_population_sha256,
)
from skill_scanner.core.cel import qualification as cel_qualification
from skill_scanner.core.cel.models import CelMode
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.data import DATA_DIR

SCHEMA_VERSION = 1
PRIMARY_PUBLIC_DATASET = "ProtectSkills/MaliciousSkillBench"
REQUIRED_REPEATED_RUNS = 5
MAX_CEL_TIME_RATIO = 0.05
MAX_LATENCY_REGRESSION = 0.10
# Compact release reports retain complete aggregate/group metrics, full outcome
# digests, and CEL-annotated sample evidence. The 16 MiB ceiling accepts that
# canonical form while continuing to reject the 40+ MiB duplicated diagnostic
# reports produced by an un-compacted benchmark run.
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_ENTRIES = 250_000
_EPSILON = 1e-12
_HEX_SHA256 = frozenset("0123456789abcdef")
_FINDING_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"})
_GROUP_DIMENSIONS = ("per_category", "per_source", "per_structural_family")
_LOADER_FALLBACK_RULE_ID = "SKILL_LOAD_FALLBACK_USED"
_LOADER_REJECTION_RULE_ID = "SKILL_LOAD_REJECTED_LIMIT"
_LOADER_REJECTION_CODE = "SKILL_METADATA_SIZE_LIMIT_EXCEEDED"
_RECOGNIZED_LOADER_FALLBACK_CODES = frozenset(
    {
        "MALFORMED_YAML_FRONTMATTER",
        "MISSING_REQUIRED_MANIFEST_FIELD",
    }
)
_RULE_FIXTURE_FIELDS = frozenset(
    {
        "true_positive_fixture_ids",
        "benign_near_miss_fixture_ids",
        "boundary_fixture_ids",
    }
)
_RULE_FIXTURE_EVIDENCE_SCHEMA_VERSION = 2
_RULE_FIXTURE_LABEL_SOURCES = frozenset({"public_labeled", "independent_ollama", "agent_labeled", "human_reviewed"})
_SCANNER_INDEPENDENT_LABEL_SOURCES = (
    "public_labeled",
    "independent_ollama",
    "agent_labeled",
    "human_reviewed",
)
_PRIVATE_CORPUS_FIELDS = frozenset(
    {
        "id",
        "snapshot_sha256",
        "source_disjoint",
        "holdout_fraction",
        "samples",
        "malicious_or_contextual",
        "benign",
        "label_attestation",
    }
)
_PRIVATE_LABEL_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "scanner_independent",
        "scanner_outputs_used_as_labels",
        "label_sources",
        "label_provenance_sha256",
        "label_evidence_sha256",
    }
)
_RULE_FIXTURE_ROLE_BY_FIELD = {
    "true_positive_fixture_ids": "true_positive",
    "benign_near_miss_fixture_ids": "benign_near_miss",
    "boundary_fixture_ids": "boundary",
}
_RULE_FIXTURE_ATTESTATION_FIELDS = frozenset(
    {
        "fixture_id",
        "role",
        "label_source",
        "package_label",
        "expected_verdict",
        "scanner_independent",
        "content_sha256",
        "provenance",
        "provenance_sha256",
        "evidence_sha256",
    }
)
_RULE_FIXTURE_PROVENANCE_FIELDS = {
    "public_labeled": frozenset(
        {
            "dataset_id",
            "revision",
            "split",
            "sample_id",
            "source_artifact_sha256",
            "labels_derived_from_scanner",
        }
    ),
    "independent_ollama": frozenset(
        {
            "corpus_id",
            "report_sha256",
            "case_id",
            "model_name",
            "model_digest",
            "rubric_sha256",
            "prompt_sha256",
            "passes",
            "scanner_outputs_used_as_labels",
        }
    ),
    "agent_labeled": frozenset(
        {
            "agent_id",
            "agent_definition_sha256",
            "run_id",
            "model_id",
            "model_digest",
            "rubric_sha256",
            "prompt_sha256",
            "scanner_outputs_used_as_labels",
        }
    ),
    "human_reviewed": frozenset(
        {
            "reviewer_ids",
            "reviewed_at",
            "review_protocol_sha256",
            "scanner_outputs_used_in_review",
        }
    ),
}
_MAX_RULE_FIXTURE_ATTESTATIONS = 16_384
_MAX_RULE_FIXTURE_STRING_BYTES = 1_024
_EVIDENCE_IDENTITY_FIELDS = frozenset(
    {
        "dataset_or_corpus_id",
        "snapshot_sha256",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
        "expression_set_hash",
        "cel_mode",
    }
)
_PRODUCER_FIELDS = frozenset(
    {
        "scanner_version",
        "source_revision",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
    }
)
_SUMMARY_FIELDS = frozenset(
    {
        "samples",
        "malicious",
        "benign",
        "critical_high_false_negatives",
        "critical_high_false_negative_ids",
        "recall",
        "package_block_recall",
        "signal_recall",
        "macro_f1",
        "benign_actionable_fpr",
        "confidence_intervals_95",
        "p95_scan_latency_ms",
        "cel_time_ratio",
        "cel_fallbacks",
        "loader_fallbacks",
        "recovered_scan_errors",
        "loader_fallback_sample_ids",
        "loader_rejections",
        "loader_rejection_sample_ids",
        "cel",
        "scan_errors",
    }
)


class ReleaseGateError(ValueError):
    """Raised when frozen gate evidence is missing, unsafe, or malformed."""


@dataclass(frozen=True)
class GateCheck:
    """One auditable release-gate decision."""

    name: str
    passed: bool
    requirement: str
    current: Any = None
    baseline: Any = None
    detail: str | None = None


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> TypeGuard[int | float]:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _sha256(value: Any, *, location: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in _HEX_SHA256 for character in value):
        raise ReleaseGateError(f"{location} must be a lowercase SHA-256 digest")
    return value


def _safe_component(name: str, *, location: str) -> str:
    if not name or name in {".", ".."}:
        raise ReleaseGateError(f"{location} contains an empty or relative path component")
    if name != unicodedata.normalize("NFC", name):
        raise ReleaseGateError(f"{location} contains a non-NFC path component: {name!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ReleaseGateError(f"{location} contains a control character")
    if "/" in name or "\\" in name or len(name.encode("utf-8")) > 1_024:
        raise ReleaseGateError(f"{location} contains an unsafe path component: {name!r}")
    return unicodedata.normalize("NFKC", name).casefold()


def _validate_local_root(path: Path, *, label: str) -> Path:
    """Validate an artifact tree without following any link or opening samples."""

    try:
        root_stat = path.lstat()
    except OSError as exc:
        raise ReleaseGateError(f"{label} root is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ReleaseGateError(f"{label} root must be a real directory, not a symlink: {path}")

    root = path.resolve(strict=True)
    stack = [root]
    entries = 0
    while stack:
        directory = stack.pop()
        normalized_names: dict[str, str] = {}
        try:
            directory_entries = list(os.scandir(directory))
        except OSError as exc:
            raise ReleaseGateError(f"cannot inspect {label} artifact directory {directory}: {exc}") from exc

        for entry in directory_entries:
            entries += 1
            if entries > MAX_ARTIFACT_ENTRIES:
                raise ReleaseGateError(f"{label} artifact exceeds the {MAX_ARTIFACT_ENTRIES} entry safety limit")
            normalized = _safe_component(entry.name, location=label)
            previous = normalized_names.setdefault(normalized, entry.name)
            if previous != entry.name:
                raise ReleaseGateError(
                    f"{label} artifact contains normalization-colliding paths: {previous!r} and {entry.name!r}"
                )

            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReleaseGateError(f"cannot stat {label} artifact entry {entry.path}: {exc}") from exc
            if entry.is_symlink():
                raise ReleaseGateError(f"{label} artifact contains a symbolic link: {entry.path}")
            if stat.S_ISDIR(entry_stat.st_mode):
                stack.append(Path(entry.path))
            elif stat.S_ISREG(entry_stat.st_mode):
                if entry_stat.st_mode & 0o111:
                    raise ReleaseGateError(f"{label} artifact contains an executable file: {entry.path}")
            else:
                raise ReleaseGateError(f"{label} artifact contains a non-regular filesystem entry: {entry.path}")

    if entries == 0:
        raise ReleaseGateError(f"{label} artifact is empty")
    return root


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseGateError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise ReleaseGateError(f"JSON contains non-finite number {value}")


def _read_json(path: Path, *, label: str) -> Mapping[str, Any]:
    """Read one bounded regular JSON file without following a final symlink."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseGateError(f"cannot open {label}: {path}: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ReleaseGateError(f"{label} must be a regular file: {path}")
        if file_stat.st_size > MAX_JSON_BYTES:
            raise ReleaseGateError(f"{label} exceeds the {MAX_JSON_BYTES}-byte JSON limit")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            try:
                value = json.load(
                    handle,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite_number,
                )
            except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
                raise ReleaseGateError(f"{label} is not valid bounded UTF-8 JSON: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, Mapping):
        raise ReleaseGateError(f"{label} JSON root must be an object")
    return value


def _validate_regular_input(path: Path, *, label: str) -> None:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise ReleaseGateError(f"{label} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ReleaseGateError(f"{label} must be a real regular file, not a symlink: {path}")
    if file_stat.st_size > MAX_JSON_BYTES:
        raise ReleaseGateError(f"{label} exceeds the {MAX_JSON_BYTES}-byte JSON limit")


def _hash_tree(root: Path, *, namespace: bytes) -> str:
    """Hash the immutable bundled rules exactly like the benchmark producer."""

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


def _current_bundled_cel_generation() -> dict[str, Any]:
    """Return the release-blocking core rule digest and CEL rollouts."""

    try:
        packs = [PackLoader().load_bundled_pack(DATA_DIR / "packs" / "core")]
    except Exception as exc:
        raise ReleaseGateError(f"current bundled CEL generation is invalid: {exc}") from exc
    rollouts: dict[str, str] = {}
    for pack in packs:
        for rule_id, definition in pack.rules.items():
            if definition.cel is None:
                continue
            if rule_id in rollouts:
                raise ReleaseGateError(f"current bundled CEL generation has duplicate rule ID {rule_id!r}")
            rollouts[rule_id] = definition.cel.rollout.value
    return {
        "rules_sha256": _hash_tree(
            DATA_DIR / "packs" / "core",
            namespace=b"skill-scanner-bundled-rules-v1",
        ),
        "rollouts": dict(sorted(rollouts.items())),
    }


def _reject_waiver_inputs(root: Path, *, label: str) -> None:
    """Waivers are audit records, never a release-gate bypass mechanism."""

    for path in root.rglob("*"):
        if any("waiver" in part.casefold() for part in path.relative_to(root).parts):
            raise ReleaseGateError(f"{label} contains waiver input; release gates do not accept waivers")


def _reject_waiver_metadata(value: Any, *, location: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and "waiver" in key.casefold():
                raise ReleaseGateError(f"{location} contains waiver metadata; release gates do not accept waivers")
            _reject_waiver_metadata(item, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_waiver_metadata(item, location=f"{location}[{index}]")


def _unique_strings(value: Any, *, location: str, allow_empty: bool = True) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, list):
        raise ReleaseGateError(f"{location} must be an array")
    if not allow_empty and not value:
        raise ReleaseGateError(f"{location} must not be empty")
    if any(not isinstance(item, str) or not item for item in value) or len(value) != len(set(value)):
        raise ReleaseGateError(f"{location} must contain unique non-empty strings")
    return tuple(value)


def _validate_interval(value: Any, *, location: str) -> tuple[float, float]:
    if isinstance(value, (str, bytes)) or not isinstance(value, list) or len(value) != 2:
        raise ReleaseGateError(f"{location} must be a two-item array")
    lower, upper = value
    if not _is_number(lower) or not _is_number(upper) or not 0.0 <= float(lower) <= float(upper) <= 1.0:
        raise ReleaseGateError(f"{location} must be a finite interval within [0, 1]")
    return float(lower), float(upper)


def _validate_cel_telemetry(value: Any, *, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseGateError(f"{location} must be an object")
    for field in (
        "modes",
        "runtimes",
        "runtime_versions",
        "fact_schemas",
        "expression_set_hashes",
    ):
        _unique_strings(value.get(field), location=f"{location}.{field}")
    for field in (
        "evaluated",
        "retained",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
    ):
        count = value.get(field)
        if not _is_int(count) or count < 0:
            raise ReleaseGateError(f"{location}.{field} must be a non-negative integer")
    for field in ("elapsed_ms", "projection_ms", "evaluation_ms"):
        duration = value.get(field)
        if not _is_number(duration) or float(duration) < 0:
            raise ReleaseGateError(f"{location}.{field} must be a non-negative finite number")

    error_counts = value.get("error_counts")
    if not isinstance(error_counts, Mapping):
        raise ReleaseGateError(f"{location}.error_counts must be an object")
    for code, count in error_counts.items():
        if not isinstance(code, str) or not code or not _is_int(count) or count < 0:
            raise ReleaseGateError(f"{location}.error_counts must map non-empty error codes to non-negative integers")

    per_rule = value.get("per_rule")
    if not isinstance(per_rule, Mapping):
        raise ReleaseGateError(f"{location}.per_rule must be an object")
    for rule_id, rule in per_rule.items():
        if not isinstance(rule_id, str) or not rule_id or not isinstance(rule, Mapping):
            raise ReleaseGateError(f"{location}.per_rule must contain named rule objects")
        for field in ("keep", "would_suppress", "fallback", "suppressed"):
            count = rule.get(field)
            if not _is_int(count) or count < 0:
                raise ReleaseGateError(f"{location}.per_rule.{rule_id}.{field} must be a non-negative integer")
        expression_hashes = _unique_strings(
            rule.get("expression_hashes"),
            location=f"{location}.per_rule.{rule_id}.expression_hashes",
            allow_empty=False,
        )
        for index, expression_hash in enumerate(expression_hashes):
            _sha256(
                expression_hash,
                location=f"{location}.per_rule.{rule_id}.expression_hashes[{index}]",
            )
        packs = _unique_strings(
            rule.get("packs"),
            location=f"{location}.per_rule.{rule_id}.packs",
            allow_empty=False,
        )
        rollouts = _unique_strings(
            rule.get("rollouts"),
            location=f"{location}.per_rule.{rule_id}.rollouts",
            allow_empty=False,
        )
        if any(rollout not in {"shadow", "enforce"} for rollout in rollouts):
            raise ReleaseGateError(f"{location}.per_rule.{rule_id}.rollouts must contain only shadow/enforce")
        if len(expression_hashes) != 1 or len(packs) != 1 or len(rollouts) != 1:
            raise ReleaseGateError(
                f"{location}.per_rule.{rule_id} must bind one immutable expression, pack, and rollout"
            )
        if rule["suppressed"] > rule["would_suppress"]:
            raise ReleaseGateError(f"{location}.per_rule.{rule_id} has contradictory suppression counts")
    for decision, aggregate_field in (
        ("would_suppress", "would_suppress"),
        ("fallback", "fallbacks"),
        ("suppressed", "suppressed"),
    ):
        if sum(rule[decision] for rule in per_rule.values()) != value[aggregate_field]:
            raise ReleaseGateError(f"{location}.{aggregate_field} disagrees with per-rule telemetry")
    if value["projection_incomplete"] > value["fallbacks"]:
        raise ReleaseGateError(f"{location}.projection_incomplete cannot exceed CEL fallbacks")
    if set(value["modes"]) != {"off"}:
        resolved_evaluations = sum(rule["keep"] + rule["would_suppress"] for rule in per_rule.values())
        if not resolved_evaluations <= value["evaluated"] <= resolved_evaluations + value["fallbacks"]:
            raise ReleaseGateError(f"{location}.evaluated disagrees with per-rule telemetry")
        minimum_retained = sum(
            rule["keep"] + rule["fallback"] + rule["would_suppress"] - rule["suppressed"] for rule in per_rule.values()
        )
        if value["retained"] < minimum_retained:
            raise ReleaseGateError(f"{location}.retained disagrees with per-rule telemetry")
    projection_ids = _unique_strings(
        value.get("projection_incomplete_sample_ids"),
        location=f"{location}.projection_incomplete_sample_ids",
    )
    if bool(projection_ids) is not bool(value["projection_incomplete"]):
        raise ReleaseGateError(f"{location}.projection_incomplete sample identity is inconsistent")
    return value


def _validate_evidence_identity(value: Any, *, location: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ReleaseGateError(f"{location} must be an object")
    missing = sorted(_EVIDENCE_IDENTITY_FIELDS - set(value))
    unknown = sorted(set(value) - _EVIDENCE_IDENTITY_FIELDS)
    if missing or unknown:
        raise ReleaseGateError(f"{location} fields differ from the v1 contract: missing={missing}, unknown={unknown}")
    identity = dict(value)
    dataset_or_corpus_id = identity["dataset_or_corpus_id"]
    if not isinstance(dataset_or_corpus_id, str) or not dataset_or_corpus_id:
        raise ReleaseGateError(f"{location}.dataset_or_corpus_id must be a non-empty string")
    for field in (
        "snapshot_sha256",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
        "expression_set_hash",
    ):
        _sha256(identity[field], location=f"{location}.{field}")
    if identity["cel_mode"] not in {mode.value for mode in CelMode}:
        raise ReleaseGateError(f"{location}.cel_mode must be off, shadow, or enforce")
    return identity


def _combined_expression_hash(expression_hashes: Sequence[str]) -> str:
    payload = json.dumps(sorted(expression_hashes), separators=(",", ":"))
    return hashlib.sha256(b"skill-scanner-benchmark-expression-generations-v1\0" + payload.encode("utf-8")).hexdigest()


def _validate_summary(value: Any, *, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseGateError(f"{location} must be an object")
    missing = sorted(_SUMMARY_FIELDS - set(value))
    if missing:
        raise ReleaseGateError(f"{location} is missing required fields: {missing}")

    for field in (
        "samples",
        "malicious",
        "benign",
        "critical_high_false_negatives",
        "cel_fallbacks",
        "loader_fallbacks",
        "recovered_scan_errors",
        "loader_rejections",
        "scan_errors",
    ):
        number = value[field]
        if not _is_int(number) or number < 0:
            raise ReleaseGateError(f"{location}.{field} must be a non-negative integer")
    if value["samples"] <= 0:
        raise ReleaseGateError(f"{location}.samples must be positive")
    if value["malicious"] + value["benign"] > value["samples"]:
        raise ReleaseGateError(f"{location} class counts exceed samples")
    if value["loader_fallbacks"] != value["recovered_scan_errors"]:
        raise ReleaseGateError(f"{location}.loader_fallbacks must equal recovered_scan_errors")
    if value["scan_errors"] + value["recovered_scan_errors"] > value["samples"]:
        raise ReleaseGateError(f"{location} fatal and recovered scan errors exceed samples")

    loader_fallback_ids = _unique_strings(
        value["loader_fallback_sample_ids"],
        location=f"{location}.loader_fallback_sample_ids",
    )
    if list(loader_fallback_ids) != sorted(loader_fallback_ids):
        raise ReleaseGateError(f"{location}.loader_fallback_sample_ids must be sorted")
    if len(loader_fallback_ids) != value["loader_fallbacks"]:
        raise ReleaseGateError(f"{location}.loader_fallback_sample_ids must identify every recovered scan error")

    for field in (
        "recall",
        "package_block_recall",
        "signal_recall",
        "macro_f1",
        "benign_actionable_fpr",
        "cel_time_ratio",
    ):
        number = value[field]
        if not _is_number(number) or not 0.0 <= float(number) <= 1.0:
            raise ReleaseGateError(f"{location}.{field} must be a finite number between zero and one")
    latency = value["p95_scan_latency_ms"]
    if not _is_number(latency) or float(latency) < 0:
        raise ReleaseGateError(f"{location}.p95_scan_latency_ms must be a non-negative finite number")

    false_negative_ids = value["critical_high_false_negative_ids"]
    if (
        not isinstance(false_negative_ids, list)
        or any(not isinstance(identity, str) or not identity for identity in false_negative_ids)
        or len(false_negative_ids) != len(set(false_negative_ids))
    ):
        raise ReleaseGateError(f"{location}.critical_high_false_negative_ids must contain unique non-empty strings")
    if len(false_negative_ids) != value["critical_high_false_negatives"]:
        raise ReleaseGateError(f"{location}.critical_high_false_negatives must equal the number of stable IDs")
    if abs(float(value["recall"]) - float(value["package_block_recall"])) > _EPSILON:
        raise ReleaseGateError(f"{location}.recall must equal package_block_recall")

    intervals = value["confidence_intervals_95"]
    if not isinstance(intervals, Mapping):
        raise ReleaseGateError(f"{location}.confidence_intervals_95 must be an object")
    for metric in ("package_block_recall", "signal_recall", "benign_actionable_fpr"):
        _validate_interval(
            intervals.get(metric),
            location=f"{location}.confidence_intervals_95.{metric}",
        )
    loader_rejection_ids = _unique_strings(
        value["loader_rejection_sample_ids"],
        location=f"{location}.loader_rejection_sample_ids",
    )
    if list(loader_rejection_ids) != sorted(loader_rejection_ids):
        raise ReleaseGateError(f"{location}.loader_rejection_sample_ids must be sorted")
    if len(loader_rejection_ids) != value["loader_rejections"]:
        raise ReleaseGateError(f"{location}.loader_rejection_sample_ids must identify every closed rejection")
    _validate_cel_telemetry(value["cel"], location=f"{location}.cel")
    return value


def _validate_producer(
    value: Any,
    evidence: Mapping[str, str],
    *,
    location: str,
) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or set(value) != _PRODUCER_FIELDS:
        raise ReleaseGateError(f"{location} must contain exactly {sorted(_PRODUCER_FIELDS)}")
    for field in ("scanner_version", "source_revision"):
        if not isinstance(value[field], str) or not value[field]:
            raise ReleaseGateError(f"{location}.{field} must be a non-empty string")
    for field in ("build_sha256", "policy_sha256", "rules_sha256"):
        digest = _sha256(value[field], location=f"{location}.{field}")
        if digest != evidence[field]:
            raise ReleaseGateError(f"{location}.{field} does not match evidence_identity.{field}")
    return value


def _validate_identity_verification(
    value: Any,
    evidence: Mapping[str, str],
    producer: Mapping[str, str],
    *,
    location: str,
) -> None:
    if not isinstance(value, Mapping):
        raise ReleaseGateError(f"{location} must be an object")
    if value.get("status") != "passed":
        raise ReleaseGateError(f"{location}.status must be 'passed'")
    if value.get("drifted_fields") != [] or value.get("errors") != []:
        raise ReleaseGateError(f"{location} must not contain drift or errors")
    start = value.get("start")
    end = value.get("end")
    expected = {"snapshot_sha256", *_PRODUCER_FIELDS}
    if not isinstance(start, Mapping) or set(start) != expected:
        raise ReleaseGateError(f"{location}.start must contain exactly {sorted(expected)}")
    if not isinstance(end, Mapping) or set(end) != expected:
        raise ReleaseGateError(f"{location}.end must contain exactly {sorted(expected)}")
    if start != end:
        raise ReleaseGateError(f"{location} start and end identities differ")
    if _sha256(start["snapshot_sha256"], location=f"{location}.start.snapshot_sha256") != evidence["snapshot_sha256"]:
        raise ReleaseGateError(f"{location} snapshot does not match evidence_identity")
    for field in _PRODUCER_FIELDS:
        if start[field] != producer[field]:
            raise ReleaseGateError(f"{location}.{field} does not match producer")


def _validate_compact_outcomes(
    value: Mapping[str, Any],
    *,
    location: str,
    retain_cel: bool,
    expected_count: int,
) -> None:
    count = value.get("sample_outcomes_count")
    if not _is_int(count) or count != expected_count:
        raise ReleaseGateError(f"{location}.sample_outcomes_count must equal samples")
    _sha256(value.get("sample_outcomes_sha256"), location=f"{location}.sample_outcomes_sha256")
    expected_format = "cel-referenced-v3" if retain_cel else "digest-only-v1"
    if value.get("sample_outcomes_format") != expected_format:
        raise ReleaseGateError(f"{location}.sample_outcomes_format must be {expected_format!r}")
    if not retain_cel:
        if "sample_outcomes" in value:
            raise ReleaseGateError(f"{location} duplicates digest-only sample outcomes")
        return

    outcomes = value.get("sample_outcomes")
    if not isinstance(outcomes, Mapping) or len(outcomes) > expected_count:
        raise ReleaseGateError(f"{location}.sample_outcomes must be a bounded object")
    decisions: dict[str, dict[str, int]] = {}
    decision_samples: dict[str, set[str]] = {
        "would_suppress": set(),
        "fallback": set(),
        "suppressed": set(),
    }
    recovered_loader_samples: set[str] = set()
    rejected_loader_samples: set[str] = set()
    for benchmark_id, outcome in outcomes.items():
        if not isinstance(benchmark_id, str) or not benchmark_id or not isinstance(outcome, Mapping):
            raise ReleaseGateError(f"{location}.sample_outcomes contains an invalid entry")
        if set(outcome) != {
            "label",
            "scan_error",
            "recovered_scan_error",
            "loader_fallback_code",
            "loader_rejection_code",
            "cel_suppressed",
            "findings",
        }:
            raise ReleaseGateError(f"{location}.sample_outcomes.{benchmark_id} has invalid fields")
        if (
            outcome["label"] not in {"malicious", "benign"}
            or type(outcome["scan_error"]) is not bool
            or type(outcome["recovered_scan_error"]) is not bool
            or (
                outcome["loader_fallback_code"] is not None
                and (not isinstance(outcome["loader_fallback_code"], str) or not outcome["loader_fallback_code"])
            )
            or (outcome["scan_error"] is True and outcome["recovered_scan_error"] is True)
            or (
                outcome["loader_rejection_code"] is not None
                and outcome["loader_rejection_code"] != _LOADER_REJECTION_CODE
            )
            or (outcome["scan_error"] is True and outcome["loader_rejection_code"] is not None)
            or (outcome["recovered_scan_error"] is True and outcome["loader_rejection_code"] is not None)
            or (outcome["recovered_scan_error"] is False and outcome["loader_fallback_code"] is not None)
            or (
                outcome["recovered_scan_error"] is True
                and outcome["loader_fallback_code"] not in _RECOGNIZED_LOADER_FALLBACK_CODES
            )
        ):
            raise ReleaseGateError(f"{location}.sample_outcomes.{benchmark_id} has invalid identity")
        if outcome["recovered_scan_error"]:
            recovered_loader_samples.add(benchmark_id)
        if outcome["loader_rejection_code"] is not None:
            rejected_loader_samples.add(benchmark_id)
        suppressed_entries = outcome["cel_suppressed"]
        if not isinstance(suppressed_entries, list) or len(suppressed_entries) > 4_096:
            raise ReleaseGateError(f"{location}.sample_outcomes.{benchmark_id}.cel_suppressed is invalid")
        suppressed_keys: list[tuple[str, str, str, str]] = []
        for index, entry in enumerate(suppressed_entries):
            if not isinstance(entry, Mapping) or set(entry) != {
                "rule_id",
                "category",
                "severity",
                "analyzer",
                "count",
            }:
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.cel_suppressed[{index}] has invalid fields"
                )
            rule_id = entry["rule_id"]
            category = entry["category"]
            severity = entry["severity"]
            analyzer = entry["analyzer"]
            count = entry["count"]
            if (
                not isinstance(rule_id, str)
                or not rule_id
                or not isinstance(category, str)
                or not category
                or not isinstance(severity, str)
                or severity not in _FINDING_SEVERITIES
                or not isinstance(analyzer, str)
                or not analyzer
                or not _is_int(count)
                or count <= 0
            ):
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.cel_suppressed[{index}] has invalid identity"
                )
            suppressed_keys.append((rule_id, category, severity, analyzer))
            counts = decisions.setdefault(
                rule_id,
                {"keep": 0, "would_suppress": 0, "fallback": 0, "suppressed": 0},
            )
            counts["would_suppress"] += count
            counts["suppressed"] += count
            decision_samples["would_suppress"].add(benchmark_id)
            decision_samples["suppressed"].add(benchmark_id)
        if suppressed_keys != sorted(suppressed_keys) or len(suppressed_keys) != len(set(suppressed_keys)):
            raise ReleaseGateError(
                f"{location}.sample_outcomes.{benchmark_id}.cel_suppressed must be sorted and unique"
            )
        findings = outcome["findings"]
        if not isinstance(findings, list):
            raise ReleaseGateError(f"{location}.sample_outcomes.{benchmark_id}.findings must be an array")
        if (
            not findings
            and not suppressed_entries
            and outcome["scan_error"] is not True
            and outcome["recovered_scan_error"] is not True
            and outcome["loader_rejection_code"] is None
        ):
            raise ReleaseGateError(f"{location}.sample_outcomes.{benchmark_id} contains no retained evidence")
        loader_marker_count = 0
        rejection_marker_count = 0
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping) or set(finding) != {
                "rule_id",
                "severity",
                "cel_decision",
                "cel_decisions",
            }:
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}] has invalid fields"
                )
            rule_id = finding["rule_id"]
            severity = finding["severity"]
            decision = finding["cel_decision"]
            lineage = finding["cel_decisions"]
            if (
                not isinstance(rule_id, str)
                or not rule_id
                or severity
                not in {
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                    "INFO",
                }
            ):
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}] has invalid rule identity"
                )
            if not isinstance(lineage, list) or len(lineage) > 4_096:
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}].cel_decisions is invalid"
                )
            is_loader_marker = (
                outcome["recovered_scan_error"] is True
                and rule_id == _LOADER_FALLBACK_RULE_ID
                and severity == "INFO"
                and decision is None
                and not lineage
            )
            is_rejection_marker = (
                outcome["loader_rejection_code"] == _LOADER_REJECTION_CODE
                and rule_id == _LOADER_REJECTION_RULE_ID
                and severity == "HIGH"
                and decision is None
                and not lineage
            )
            if rule_id == _LOADER_FALLBACK_RULE_ID and not is_loader_marker:
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}] "
                    "contains a contradictory bounded-loader marker"
                )
            if rule_id == _LOADER_REJECTION_RULE_ID and not is_rejection_marker:
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}] "
                    "contains a contradictory closed-loader rejection marker"
                )
            if is_loader_marker:
                loader_marker_count += 1
                continue
            if is_rejection_marker:
                rejection_marker_count += 1
                continue
            if not lineage:
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}] has no CEL lineage"
                )
            lineage_keys: list[tuple[str, str]] = []
            singular_present = False
            for lineage_index, entry in enumerate(lineage):
                if not isinstance(entry, Mapping) or set(entry) != {"rule_id", "decision", "count"}:
                    raise ReleaseGateError(
                        f"{location}.sample_outcomes.{benchmark_id}.findings[{index}]."
                        f"cel_decisions[{lineage_index}] has invalid fields"
                    )
                lineage_rule_id = entry["rule_id"]
                lineage_decision = entry["decision"]
                count = entry["count"]
                if (
                    not isinstance(lineage_rule_id, str)
                    or not lineage_rule_id
                    or lineage_decision not in {"keep", "would_suppress", "fallback"}
                    or not _is_int(count)
                    or count <= 0
                ):
                    raise ReleaseGateError(
                        f"{location}.sample_outcomes.{benchmark_id}.findings[{index}]."
                        f"cel_decisions[{lineage_index}] has invalid identity"
                    )
                key = (lineage_rule_id, lineage_decision)
                lineage_keys.append(key)
                singular_present = singular_present or (
                    decision is not None and lineage_rule_id == rule_id and lineage_decision == decision
                )
                counts = decisions.setdefault(
                    lineage_rule_id,
                    {"keep": 0, "would_suppress": 0, "fallback": 0, "suppressed": 0},
                )
                counts[lineage_decision] += count
                if lineage_decision in decision_samples:
                    decision_samples[lineage_decision].add(benchmark_id)
            if lineage_keys != sorted(lineage_keys) or len(lineage_keys) != len(set(lineage_keys)):
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}]."
                    "cel_decisions must be sorted and unique"
                )
            if decision is not None and (
                decision not in {"keep", "would_suppress", "fallback"} or not singular_present
            ):
                raise ReleaseGateError(
                    f"{location}.sample_outcomes.{benchmark_id}.findings[{index}] has contradictory CEL winner"
                )
        expected_marker_count = 1 if outcome["recovered_scan_error"] else 0
        if loader_marker_count != expected_marker_count:
            raise ReleaseGateError(
                f"{location}.sample_outcomes.{benchmark_id} must contain exactly "
                f"{expected_marker_count} {_LOADER_FALLBACK_RULE_ID} marker(s)"
            )
        expected_rejection_markers = 1 if outcome["loader_rejection_code"] is not None else 0
        if rejection_marker_count != expected_rejection_markers:
            raise ReleaseGateError(
                f"{location}.sample_outcomes.{benchmark_id} must contain exactly "
                f"{expected_rejection_markers} {_LOADER_REJECTION_RULE_ID} marker(s)"
            )

    cel = value["cel"]
    reported_rules = cel["per_rule"]
    if set(reported_rules) != set(decisions):
        raise ReleaseGateError(f"{location} compact CEL outcomes disagree with per-rule telemetry")
    for rule_id, counts in decisions.items():
        if any(reported_rules[rule_id][decision] != count for decision, count in counts.items()):
            raise ReleaseGateError(f"{location} compact CEL outcome counts disagree for {rule_id!r}")
    for decision, telemetry_field in (
        ("would_suppress", "would_suppress_sample_ids"),
        ("fallback", "fallback_sample_ids"),
        ("suppressed", "suppressed_sample_ids"),
    ):
        reported_ids = _unique_strings(cel.get(telemetry_field), location=f"{location}.cel.{telemetry_field}")
        if set(reported_ids) != decision_samples[decision]:
            raise ReleaseGateError(f"{location} compact outcomes disagree with {telemetry_field}")
    reported_loader_ids = _unique_strings(
        value["loader_fallback_sample_ids"],
        location=f"{location}.loader_fallback_sample_ids",
    )
    if set(reported_loader_ids) != recovered_loader_samples:
        raise ReleaseGateError(f"{location} compact outcomes disagree with loader_fallback_sample_ids")
    reported_rejection_ids = _unique_strings(
        value["loader_rejection_sample_ids"],
        location=f"{location}.loader_rejection_sample_ids",
    )
    if set(reported_rejection_ids) != rejected_loader_samples:
        raise ReleaseGateError(f"{location} compact outcomes disagree with loader_rejection_sample_ids")


def _validate_report(value: Mapping[str, Any], *, location: str) -> Mapping[str, Any]:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseGateError(f"{location} uses an unsupported schema_version")
    if not isinstance(value.get("status"), str) or not value["status"]:
        raise ReleaseGateError(f"{location}.status must be a non-empty string")
    if not isinstance(value.get("profile"), str) or not value["profile"]:
        raise ReleaseGateError(f"{location}.profile must be a non-empty string")
    if value.get("cel_mode") not in {mode.value for mode in CelMode}:
        raise ReleaseGateError(f"{location}.cel_mode must be off, shadow, or enforce")
    release_evidence = value.get("release_evidence")
    if release_evidence != {
        "format": "compact-v3",
        "full_sample_outcomes_domain": "skill-scanner-release-sample-outcomes-v1",
        "cel_decision_identity": "track.cel.per_rule",
    }:
        raise ReleaseGateError(f"{location} must use compact-v3 canonical release evidence")
    evidence = _validate_evidence_identity(value.get("evidence_identity"), location=f"{location}.evidence_identity")
    producer = _validate_producer(value.get("producer"), evidence, location=f"{location}.producer")
    _validate_identity_verification(
        value.get("identity_verification"),
        evidence,
        producer,
        location=f"{location}.identity_verification",
    )
    errors = value.get("errors")
    if not isinstance(errors, list):
        raise ReleaseGateError(f"{location}.errors must be an array")
    _validate_summary(value.get("summary"), location=f"{location}.summary")

    raw_tracks = value.get("tracks")
    if isinstance(raw_tracks, Mapping):
        track_items = list(raw_tracks.items())
    elif isinstance(raw_tracks, list):
        track_items = [
            (track.get("name"), track) if isinstance(track, Mapping) else (None, track) for track in raw_tracks
        ]
    else:
        track_items = []
    if not track_items:
        raise ReleaseGateError(f"{location}.tracks must be a non-empty object or array")

    tracks: dict[str, Mapping[str, Any]] = {}
    for track_name, track in track_items:
        if not isinstance(track_name, str) or not track_name or not isinstance(track, Mapping):
            raise ReleaseGateError(f"{location}.tracks must contain named track objects")
        if track_name in tracks:
            raise ReleaseGateError(f"{location}.tracks contains duplicate track name {track_name!r}")
        if track.get("status") != "passed":
            raise ReleaseGateError(f"{location}.tracks.{track_name}.status must be 'passed'")
        _validate_summary(track, location=f"{location}.tracks.{track_name}")
        _validate_compact_outcomes(
            track,
            location=f"{location}.tracks.{track_name}",
            retain_cel=True,
            expected_count=track["samples"],
        )
        normalized_track = dict(track)
        for dimension in _GROUP_DIMENSIONS:
            raw_groups = track.get(dimension)
            if raw_groups is None:
                normalized_track[dimension] = {}
                continue
            if not isinstance(raw_groups, Mapping):
                raise ReleaseGateError(f"{location}.tracks.{track_name}.{dimension} must be an object")
            groups: dict[str, Mapping[str, Any]] = {}
            for group_name, group in raw_groups.items():
                if not isinstance(group_name, str) or not group_name or not isinstance(group, Mapping):
                    raise ReleaseGateError(
                        f"{location}.tracks.{track_name}.{dimension} must contain named metric objects"
                    )
                _validate_summary(
                    group,
                    location=f"{location}.tracks.{track_name}.{dimension}.{group_name}",
                )
                _validate_compact_outcomes(
                    group,
                    location=f"{location}.tracks.{track_name}.{dimension}.{group_name}",
                    retain_cel=False,
                    expected_count=group["samples"],
                )
                groups[group_name] = group
            normalized_track[dimension] = groups
        for count_field, ids_field, label in (
            ("loader_fallbacks", "loader_fallback_sample_ids", "bounded-loader recovery"),
            ("loader_rejections", "loader_rejection_sample_ids", "closed loader rejection"),
        ):
            track_ids = set(track[ids_field])
            for dimension in _GROUP_DIMENSIONS:
                groups = normalized_track[dimension]
                group_ids = {benchmark_id for group in groups.values() for benchmark_id in group[ids_field]}
                if group_ids != track_ids:
                    raise ReleaseGateError(
                        f"{location}.tracks.{track_name}.{dimension} {label} IDs do not equal the track evidence"
                    )
                if (
                    dimension != "per_category"
                    and sum(group[count_field] for group in groups.values()) != track[count_field]
                ):
                    raise ReleaseGateError(
                        f"{location}.tracks.{track_name}.{dimension} {label} count does not equal the track evidence"
                    )
        tracks[track_name] = normalized_track
    summary = value["summary"]
    expected_loader_ids = sorted(
        f"{track_name}:{benchmark_id}"
        for track_name, track in tracks.items()
        for benchmark_id in track["loader_fallback_sample_ids"]
    )
    expected_rejection_ids = sorted(
        f"{track_name}:{benchmark_id}"
        for track_name, track in tracks.items()
        for benchmark_id in track["loader_rejection_sample_ids"]
    )
    track_loader_fallbacks = sum(track["loader_fallbacks"] for track in tracks.values())
    track_recovered_errors = sum(track["recovered_scan_errors"] for track in tracks.values())
    track_loader_rejections = sum(track["loader_rejections"] for track in tracks.values())
    track_scan_errors = sum(track["scan_errors"] for track in tracks.values())
    if (
        summary["loader_fallbacks"] != track_loader_fallbacks
        or summary["recovered_scan_errors"] != track_recovered_errors
        or summary["loader_fallback_sample_ids"] != expected_loader_ids
    ):
        raise ReleaseGateError(f"{location}.summary bounded-loader recovery does not equal the track evidence")
    if summary["scan_errors"] != track_scan_errors:
        raise ReleaseGateError(f"{location}.summary scan_errors does not equal the track evidence")
    if (
        summary["loader_rejections"] != track_loader_rejections
        or summary["loader_rejection_sample_ids"] != expected_rejection_ids
    ):
        raise ReleaseGateError(f"{location}.summary closed loader rejection does not equal the track evidence")
    normalized = dict(value)
    normalized["tracks"] = tracks
    return normalized


def _public_identity(report: Mapping[str, Any], *, location: str) -> Mapping[str, Any]:
    dataset = report.get("dataset")
    if not isinstance(dataset, Mapping):
        raise ReleaseGateError(f"{location}.dataset must be an object")
    if not isinstance(dataset.get("id"), str) or not dataset["id"]:
        raise ReleaseGateError(f"{location}.dataset.id must be a non-empty string")
    revision = dataset.get("revision")
    if (
        not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in _HEX_SHA256 for character in revision)
    ):
        raise ReleaseGateError(f"{location}.dataset.revision must be a full lowercase commit SHA")
    _sha256(dataset.get("artifact_manifest_sha256"), location=f"{location}.dataset.artifact_manifest_sha256")
    _sha256(
        dataset.get("sample_metadata_manifest_sha256"),
        location=f"{location}.dataset.sample_metadata_manifest_sha256",
    )
    if not isinstance(dataset.get("blocking_eligible"), bool):
        raise ReleaseGateError(f"{location}.dataset.blocking_eligible must be boolean")
    return dataset


def _private_label_provenance_sha256(corpus: Mapping[str, Any]) -> str:
    attestation = corpus["label_attestation"]
    payload = {
        "corpus_id": corpus["id"],
        "holdout_fraction": corpus["holdout_fraction"],
        "label_sources": attestation["label_sources"],
        "scanner_independent": attestation["scanner_independent"],
        "scanner_outputs_used_as_labels": attestation["scanner_outputs_used_as_labels"],
        "snapshot_sha256": corpus["snapshot_sha256"],
        "source_disjoint": corpus["source_disjoint"],
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"skill-scanner-private-label-provenance-v1\0" + encoded).hexdigest()


def _private_label_evidence_sha256(corpus: Mapping[str, Any]) -> str:
    attestation = corpus["label_attestation"]
    payload = {
        "benign": corpus["benign"],
        "corpus_id": corpus["id"],
        "label_sources": attestation["label_sources"],
        "malicious_or_contextual": corpus["malicious_or_contextual"],
        "samples": corpus["samples"],
        "snapshot_sha256": corpus["snapshot_sha256"],
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"skill-scanner-private-label-evidence-v1\0" + encoded).hexdigest()


def _validate_private_label_attestation(corpus: Mapping[str, Any], *, location: str) -> None:
    attestation = corpus.get("label_attestation")
    attestation_location = f"{location}.corpus.label_attestation"
    if not isinstance(attestation, Mapping) or set(attestation) != _PRIVATE_LABEL_ATTESTATION_FIELDS:
        raise ReleaseGateError(f"{attestation_location} does not match the strict v1 contract")
    if attestation.get("schema_version") != 1:
        raise ReleaseGateError(f"{attestation_location}.schema_version must be 1")
    if attestation.get("scanner_independent") is not True:
        raise ReleaseGateError(f"{attestation_location}.scanner_independent must be true")
    if attestation.get("scanner_outputs_used_as_labels") is not False:
        raise ReleaseGateError(f"{attestation_location}.scanner_outputs_used_as_labels must be false")
    label_sources = attestation.get("label_sources")
    if not isinstance(label_sources, Mapping) or set(label_sources) != set(_SCANNER_INDEPENDENT_LABEL_SOURCES):
        raise ReleaseGateError(
            f"{attestation_location}.label_sources must contain exactly {list(_SCANNER_INDEPENDENT_LABEL_SOURCES)}"
        )
    for label_source, count in label_sources.items():
        if not _is_int(count) or count < 0:
            raise ReleaseGateError(f"{attestation_location}.label_sources.{label_source} must be non-negative")
    if sum(label_sources.values()) != corpus["samples"]:
        raise ReleaseGateError(f"{attestation_location}.label_sources must account for every private sample")
    provenance_hash = _sha256(
        attestation.get("label_provenance_sha256"),
        location=f"{attestation_location}.label_provenance_sha256",
    )
    if provenance_hash != _private_label_provenance_sha256(corpus):
        raise ReleaseGateError(f"{attestation_location}.label_provenance_sha256 does not match its evidence")
    evidence_hash = _sha256(
        attestation.get("label_evidence_sha256"),
        location=f"{attestation_location}.label_evidence_sha256",
    )
    if evidence_hash != _private_label_evidence_sha256(corpus):
        raise ReleaseGateError(f"{attestation_location}.label_evidence_sha256 does not match its evidence")


def _private_identity(report: Mapping[str, Any], *, location: str) -> Mapping[str, Any]:
    corpus = report.get("corpus")
    if not isinstance(corpus, Mapping):
        raise ReleaseGateError(f"{location}.corpus must be an object")
    if set(corpus) != _PRIVATE_CORPUS_FIELDS:
        raise ReleaseGateError(f"{location}.corpus does not match the strict scanner-independent label contract")
    corpus_id = corpus.get("id")
    if not isinstance(corpus_id, str) or not corpus_id:
        raise ReleaseGateError(f"{location}.corpus.id must be a non-empty string")
    _sha256(corpus.get("snapshot_sha256"), location=f"{location}.corpus.snapshot_sha256")
    if corpus.get("source_disjoint") is not True:
        raise ReleaseGateError(f"{location}.corpus.source_disjoint must be true")
    holdout_fraction = corpus.get("holdout_fraction")
    if not _is_number(holdout_fraction) or not 0.3 <= float(holdout_fraction) <= 1.0:
        raise ReleaseGateError(f"{location}.corpus.holdout_fraction must be at least 0.30")
    for field in ("samples", "malicious_or_contextual", "benign"):
        count = corpus.get(field)
        if not _is_int(count) or count < 0:
            raise ReleaseGateError(f"{location}.corpus.{field} must be a non-negative integer")
    if corpus["malicious_or_contextual"] + corpus["benign"] != corpus["samples"]:
        raise ReleaseGateError(f"{location}.corpus class counts must account for every sample")
    _validate_private_label_attestation(corpus, location=location)
    return corpus


def _same_report_population(current: Mapping[str, Any], baseline: Mapping[str, Any], *, location: str) -> None:
    if current["profile"] != baseline["profile"]:
        raise ReleaseGateError(f"{location} candidate and baseline profiles differ")
    current_tracks = set(current["tracks"])
    baseline_tracks = set(baseline["tracks"])
    if current_tracks != baseline_tracks:
        raise ReleaseGateError(
            f"{location} candidate and baseline track sets differ: "
            f"candidate={sorted(current_tracks)}, baseline={sorted(baseline_tracks)}"
        )
    for scope, current_metrics, baseline_metrics in [
        ("summary", current["summary"], baseline["summary"]),
        *[(f"tracks.{track}", current["tracks"][track], baseline["tracks"][track]) for track in sorted(current_tracks)],
    ]:
        for field in ("samples", "malicious", "benign"):
            if current_metrics[field] != baseline_metrics[field]:
                raise ReleaseGateError(f"{location}.{scope}.{field} differs between candidate and baseline")
    for track_name in sorted(current_tracks):
        current_track = current["tracks"][track_name]
        baseline_track = baseline["tracks"][track_name]
        current_population = _sha256(
            current_track.get("population_sha256"),
            location=f"{location}.candidate.tracks.{track_name}.population_sha256",
        )
        baseline_population = _sha256(
            baseline_track.get("population_sha256"),
            location=f"{location}.baseline.tracks.{track_name}.population_sha256",
        )
        if current_population != baseline_population:
            raise ReleaseGateError(
                f"{location}.tracks.{track_name}.population_sha256 differs between candidate and baseline"
            )
        for dimension in _GROUP_DIMENSIONS:
            current_groups = current_track[dimension]
            baseline_groups = baseline_track[dimension]
            if set(current_groups) != set(baseline_groups):
                raise ReleaseGateError(
                    f"{location}.tracks.{track_name}.{dimension} group sets differ between candidate and baseline"
                )
            for group_name in sorted(current_groups):
                for field in ("samples", "malicious", "benign"):
                    if current_groups[group_name][field] != baseline_groups[group_name][field]:
                        raise ReleaseGateError(
                            f"{location}.tracks.{track_name}.{dimension}.{group_name}.{field} "
                            "differs between candidate and baseline"
                        )


def _validate_locked_track_populations(
    report: Mapping[str, Any],
    locked_dataset: Mapping[str, Any],
    *,
    location: str,
) -> None:
    """Bind every release track to the lock's absolute population identity."""

    locked_tracks = {track["name"]: track for track in locked_dataset["gating"]["tracks"]}
    expectations = locked_dataset.get("expected", {}).get("track_expectations")
    if not isinstance(expectations, Mapping) or set(expectations) != set(locked_tracks):
        raise ReleaseGateError("blocking dataset lock has incomplete track expectations")
    report_tracks = report["tracks"]
    if set(report_tracks) != set(locked_tracks):
        raise ReleaseGateError(
            f"{location}.tracks must contain exactly the locked blocking tracks {sorted(locked_tracks)}"
        )

    for track_name in sorted(locked_tracks):
        track = report_tracks[track_name]
        locked_track = locked_tracks[track_name]
        expectation = expectations[track_name]
        for field in ("name", "detector_profile", "protocol", "partition"):
            expected = track_name if field == "name" else locked_track[field]
            if track.get(field) != expected:
                raise ReleaseGateError(
                    f"{location}.tracks.{track_name}.{field} does not match the blocking dataset lock"
                )
        for field in ("samples", "malicious", "benign"):
            if track[field] != expectation[field]:
                raise ReleaseGateError(
                    f"{location}.tracks.{track_name}.{field} does not match the blocking dataset lock "
                    f"(expected {expectation[field]}, received {track[field]})"
                )
        population_sha256 = _sha256(
            track.get("population_sha256"),
            location=f"{location}.tracks.{track_name}.population_sha256",
        )
        if population_sha256 != expectation["population_sha256"]:
            raise ReleaseGateError(
                f"{location}.tracks.{track_name}.population_sha256 does not match the blocking dataset lock"
            )


def _append_check(
    checks: list[GateCheck],
    *,
    name: str,
    passed: bool,
    requirement: str,
    current: Any = None,
    baseline: Any = None,
    detail: str | None = None,
) -> None:
    checks.append(
        GateCheck(
            name=name,
            passed=passed,
            requirement=requirement,
            current=current,
            baseline=baseline,
            detail=detail,
        )
    )


def _validate_controlled_generation(
    current_report: Mapping[str, Any],
    baseline_report: Mapping[str, Any],
    *,
    location: str,
) -> tuple[Mapping[str, str], Mapping[str, str]]:
    current = _validate_evidence_identity(
        current_report["evidence_identity"], location=f"{location}.candidate.evidence_identity"
    )
    baseline = _validate_evidence_identity(
        baseline_report["evidence_identity"], location=f"{location}.baseline.evidence_identity"
    )
    for field in _EVIDENCE_IDENTITY_FIELDS - {"cel_mode"}:
        if current[field] != baseline[field]:
            raise ReleaseGateError(f"{location} candidate and baseline evidence_identity.{field} differ")
    if current["cel_mode"] != current_report["cel_mode"]:
        raise ReleaseGateError(f"{location} candidate CEL mode disagrees with its evidence identity")
    if baseline["cel_mode"] != baseline_report["cel_mode"]:
        raise ReleaseGateError(f"{location} baseline CEL mode disagrees with its evidence identity")

    for report_label, report, identity in (
        ("candidate", current_report, current),
        ("baseline", baseline_report, baseline),
    ):
        expression_hashes = _unique_strings(
            report["summary"]["cel"]["expression_set_hashes"],
            location=f"{location}.{report_label}.summary.cel.expression_set_hashes",
            allow_empty=False,
        )
        for index, expression_hash in enumerate(expression_hashes):
            _sha256(
                expression_hash,
                location=(f"{location}.{report_label}.summary.cel.expression_set_hashes[{index}]"),
            )
        if identity["expression_set_hash"] != _combined_expression_hash(expression_hashes):
            raise ReleaseGateError(
                f"{location} {report_label} evidence identity does not bind its CEL expression generation"
            )
    return current, baseline


def _append_cel_evidence_checks(
    current_report: Mapping[str, Any],
    baseline_report: Mapping[str, Any],
    *,
    prefix: str,
    checks: list[GateCheck],
) -> None:
    current_mode = current_report["cel_mode"]
    baseline_mode = baseline_report["cel_mode"]
    current_cel = current_report["summary"]["cel"]
    baseline_cel = baseline_report["summary"]["cel"]
    current_modes = set(current_cel["modes"])
    baseline_modes = set(baseline_cel["modes"])
    off_counter_fields = (
        "evaluated",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
        "elapsed_ms",
        "projection_ms",
        "evaluation_ms",
    )
    nonzero_off_counters = {field: baseline_cel[field] for field in off_counter_fields if baseline_cel[field] != 0}
    _append_check(
        checks,
        name=f"{prefix}.cel.baseline_off",
        passed=(
            baseline_mode == CelMode.OFF.value and baseline_modes == {CelMode.OFF.value} and not nonzero_off_counters
        ),
        requirement="baseline compiles CEL but performs no CEL evaluation or decision",
        current={
            "report_mode": baseline_mode,
            "telemetry_modes": sorted(baseline_modes),
            "nonzero_counters": nonzero_off_counters,
        },
    )
    _append_check(
        checks,
        name=f"{prefix}.cel.candidate_active",
        passed=(
            current_mode in {CelMode.SHADOW.value, CelMode.ENFORCE.value}
            and current_modes == {current_mode}
            and current_cel["evaluated"] > 0
        ),
        requirement="candidate runs CEL in shadow/enforce and evaluates at least one candidate",
        current={
            "report_mode": current_mode,
            "telemetry_modes": sorted(current_modes),
            "evaluated": current_cel["evaluated"],
        },
    )

    current_runtimes = set(current_cel["runtimes"])
    current_versions = set(current_cel["runtime_versions"])
    baseline_runtimes = set(baseline_cel["runtimes"])
    baseline_versions = set(baseline_cel["runtime_versions"])
    qualification_errors: list[str] = []
    for report_label, runtimes, versions, report in (
        ("candidate", current_runtimes, current_versions, current_report),
        ("baseline", baseline_runtimes, baseline_versions, baseline_report),
    ):
        if len(runtimes) != 1 or len(versions) != 1:
            qualification_errors.append(f"{report_label} must report exactly one runtime and version")
            continue
        error = cel_qualification.qualification_error(
            next(iter(runtimes)),
            next(iter(versions)),
            expected_helper_version=report["producer"]["scanner_version"],
        )
        if error is not None:
            qualification_errors.append(f"{report_label}: {error}")
    if current_versions != baseline_versions:
        qualification_errors.append("candidate and off baseline used different helper builds")
    _append_check(
        checks,
        name=f"{prefix}.cel.qualified_runtime",
        passed=not qualification_errors,
        requirement=(
            "candidate and off baseline use the exact qualified cel-go engine and the release helper "
            "matching their scanner producer"
        ),
        current={"runtimes": sorted(current_runtimes), "versions": sorted(current_versions)},
        baseline={"runtimes": sorted(baseline_runtimes), "versions": sorted(baseline_versions)},
        detail="; ".join(qualification_errors) if qualification_errors else None,
    )

    fact_schemas = set(current_cel["fact_schemas"])
    baseline_fact_schemas = set(baseline_cel["fact_schemas"])
    expression_hashes = tuple(current_cel["expression_set_hashes"])
    baseline_expression_hashes = tuple(baseline_cel["expression_set_hashes"])
    _append_check(
        checks,
        name=f"{prefix}.cel.fact_schema_v1",
        passed=fact_schemas == {"v1"} and baseline_fact_schemas == {"v1"},
        requirement="candidate and off baseline telemetry use exactly ScanFacts schema v1",
        current=sorted(fact_schemas),
        baseline=sorted(baseline_fact_schemas),
    )
    per_track_generations_match = all(
        len(current_report["tracks"][track_name]["cel"]["expression_set_hashes"]) == 1
        and current_report["tracks"][track_name]["cel"]["expression_set_hashes"]
        == baseline_report["tracks"][track_name]["cel"]["expression_set_hashes"]
        for track_name in current_report["tracks"]
    )
    _append_check(
        checks,
        name=f"{prefix}.cel.expression_generation",
        passed=(
            bool(expression_hashes) and expression_hashes == baseline_expression_hashes and per_track_generations_match
        ),
        requirement=(
            "candidate and off baseline bind the same non-empty expression generation, with one hash per track"
        ),
        current=list(expression_hashes),
        baseline=list(baseline_expression_hashes),
    )


def _append_group_completeness_checks(report: Mapping[str, Any], *, prefix: str, checks: list[GateCheck]) -> None:
    for track_name, track in sorted(report["tracks"].items()):
        missing = [dimension for dimension in _GROUP_DIMENSIONS if not track[dimension]]
        _append_check(
            checks,
            name=f"{prefix}.track.{track_name}.groups.complete",
            passed=not missing,
            requirement="category, source, and structural-family subgroup metrics are all present",
            current={dimension: len(track[dimension]) for dimension in _GROUP_DIMENSIONS},
            detail=f"missing or empty dimensions: {missing}" if missing else None,
        )


def _compare_metrics(
    current_report: Mapping[str, Any],
    baseline_report: Mapping[str, Any],
    *,
    prefix: str,
    checks: list[GateCheck],
) -> None:
    scopes = [
        ("summary", current_report["summary"], baseline_report["summary"]),
        *[
            (
                f"track.{track_name}",
                current_report["tracks"][track_name],
                baseline_report["tracks"][track_name],
            )
            for track_name in sorted(current_report["tracks"])
        ],
    ]
    for track_name in sorted(current_report["tracks"]):
        current_track = current_report["tracks"][track_name]
        baseline_track = baseline_report["tracks"][track_name]
        for dimension in _GROUP_DIMENSIONS:
            scopes.extend(
                (
                    f"track.{track_name}.{dimension}.{group_name}",
                    current_track[dimension][group_name],
                    baseline_track[dimension][group_name],
                )
                for group_name in sorted(current_track[dimension])
            )
    for scope_name, current, baseline in scopes:
        name = f"{prefix}.{scope_name}"
        new_false_negatives = sorted(
            set(current["critical_high_false_negative_ids"]) - set(baseline["critical_high_false_negative_ids"])
        )
        if new_false_negatives and prefix == "private":
            false_negative_detail = f"{len(new_false_negatives)} new private stable identity/identities"
        elif new_false_negatives:
            false_negative_detail = f"new identities: {new_false_negatives}"
        else:
            false_negative_detail = None
        _append_check(
            checks,
            name=f"{name}.no_new_critical_high_false_negatives",
            passed=not new_false_negatives,
            requirement="candidate introduces no new stable CRITICAL/HIGH false-negative identities",
            current=current["critical_high_false_negatives"],
            baseline=baseline["critical_high_false_negatives"],
            detail=false_negative_detail,
        )
        _append_check(
            checks,
            name=f"{name}.recall",
            passed=float(current["recall"]) + _EPSILON >= float(baseline["recall"]),
            requirement="recall does not regress",
            current=current["recall"],
            baseline=baseline["recall"],
        )
        _append_check(
            checks,
            name=f"{name}.package_block_recall",
            passed=(float(current["package_block_recall"]) + _EPSILON >= float(baseline["package_block_recall"])),
            requirement="package block recall does not regress",
            current=current["package_block_recall"],
            baseline=baseline["package_block_recall"],
        )
        _append_check(
            checks,
            name=f"{name}.signal_recall",
            passed=float(current["signal_recall"]) + _EPSILON >= float(baseline["signal_recall"]),
            requirement="signal recall does not regress",
            current=current["signal_recall"],
            baseline=baseline["signal_recall"],
        )
        _append_check(
            checks,
            name=f"{name}.macro_f1",
            passed=float(current["macro_f1"]) + _EPSILON >= float(baseline["macro_f1"]),
            requirement="macro-F1 does not regress",
            current=current["macro_f1"],
            baseline=baseline["macro_f1"],
        )
        _append_check(
            checks,
            name=f"{name}.benign_actionable_fpr",
            passed=float(current["benign_actionable_fpr"]) <= float(baseline["benign_actionable_fpr"]) + _EPSILON,
            requirement="benign actionable false-positive rate does not increase",
            current=current["benign_actionable_fpr"],
            baseline=baseline["benign_actionable_fpr"],
        )
        loader_fallback_identity_matches = (
            current["loader_fallbacks"] == baseline["loader_fallbacks"]
            and current["recovered_scan_errors"] == baseline["recovered_scan_errors"]
            and current["loader_fallback_sample_ids"] == baseline["loader_fallback_sample_ids"]
        )
        _append_check(
            checks,
            name=f"{name}.loader_fallback_identity",
            passed=loader_fallback_identity_matches,
            requirement=(
                "candidate and baseline recover the exact same strictly validated bounded-loader fallback samples"
            ),
            current={
                "loader_fallbacks": current["loader_fallbacks"],
                "recovered_scan_errors": current["recovered_scan_errors"],
                "sample_ids": current["loader_fallback_sample_ids"],
            },
            baseline={
                "loader_fallbacks": baseline["loader_fallbacks"],
                "recovered_scan_errors": baseline["recovered_scan_errors"],
                "sample_ids": baseline["loader_fallback_sample_ids"],
            },
        )
        loader_rejection_identity_matches = (
            current["loader_rejections"] == baseline["loader_rejections"]
            and current["loader_rejection_sample_ids"] == baseline["loader_rejection_sample_ids"]
        )
        _append_check(
            checks,
            name=f"{name}.loader_rejection_identity",
            passed=loader_rejection_identity_matches,
            requirement=("candidate and baseline emit the same strictly validated closed-loader rejections"),
            current={
                "loader_rejections": current["loader_rejections"],
                "sample_ids": current["loader_rejection_sample_ids"],
            },
            baseline={
                "loader_rejections": baseline["loader_rejections"],
                "sample_ids": baseline["loader_rejection_sample_ids"],
            },
        )
        maximum_latency = float(baseline["p95_scan_latency_ms"]) * (1.0 + MAX_LATENCY_REGRESSION)
        _append_check(
            checks,
            name=f"{name}.p95_scan_latency_ms",
            passed=float(current["p95_scan_latency_ms"]) <= maximum_latency + _EPSILON,
            requirement="p95 scan latency regresses by no more than 10%",
            current=current["p95_scan_latency_ms"],
            baseline=baseline["p95_scan_latency_ms"],
            detail=f"maximum allowed: {maximum_latency}",
        )
        _append_check(
            checks,
            name=f"{name}.cel_time_ratio",
            passed=float(current["cel_time_ratio"]) <= MAX_CEL_TIME_RATIO + _EPSILON,
            requirement="CEL time is no more than 5% of total scan time",
            current=current["cel_time_ratio"],
            baseline=baseline["cel_time_ratio"],
        )
        _append_check(
            checks,
            name=f"{name}.cel_fallbacks",
            passed=current["cel_fallbacks"] == 0 and baseline["cel_fallbacks"] == 0,
            requirement="candidate and baseline mandatory release corpora have zero CEL/projection fallbacks",
            current=current["cel_fallbacks"],
            baseline=baseline["cel_fallbacks"],
        )
        current_projection_incomplete = current["cel"]["projection_incomplete"]
        baseline_projection_incomplete = baseline["cel"]["projection_incomplete"]
        _append_check(
            checks,
            name=f"{name}.cel_projection_incomplete",
            passed=current_projection_incomplete == 0 and baseline_projection_incomplete == 0,
            requirement="candidate and baseline mandatory release corpora have zero incomplete CEL projections",
            current=current_projection_incomplete,
            baseline=baseline_projection_incomplete,
        )
        _append_check(
            checks,
            name=f"{name}.scan_errors",
            passed=current["scan_errors"] == 0 and baseline["scan_errors"] == 0,
            requirement="candidate and baseline mandatory release corpora have zero fatal scanner errors",
            current=current["scan_errors"],
            baseline=baseline["scan_errors"],
        )


def stable_release_output_sha256(report: Mapping[str, Any]) -> str:
    """Hash detection outcomes while excluding measured wall-clock timing."""

    volatile_fields = {
        "p95_scan_latency_ms",
        "cel_time_ratio",
        "elapsed_ms",
        "projection_ms",
        "evaluation_ms",
        "latency_samples",
    }

    def normalized(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: normalized(item) for key, item in sorted(value.items()) if key not in volatile_fields}
        if isinstance(value, list):
            return [normalized(item) for item in value]
        return value

    payload = {
        "summary": normalized(report.get("summary")),
        "tracks": normalized(report.get("tracks")),
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(b"skill-scanner-release-output-v1\0" + serialized.encode("utf-8")).hexdigest()


def _validate_repeated_runs(
    value: Mapping[str, Any],
    *,
    expected_identity: Mapping[str, str],
    expected_golden_manifest_sha256: str,
    expected_output_sha256: str,
) -> tuple[int, list[str], list[str]]:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseGateError("repeated-runs.json uses an unsupported schema_version")
    runs = value.get("runs")
    if not isinstance(runs, list):
        raise ReleaseGateError("repeated-runs.json.runs must be an array")

    previous_time: datetime | None = None
    seen_run_ids: set[str] = set()
    clean_run_ids: list[str] = []
    mismatches: list[str] = []
    for index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}] must be an object")
        expected_fields = {
            "run_id",
            "completed_at",
            "status",
            "evidence_identity",
            "golden_manifest_sha256",
            "output_sha256",
        }
        if set(run) != expected_fields:
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}] must contain exactly {sorted(expected_fields)}")
        run_id = run.get("run_id")
        if not isinstance(run_id, (str, int)) or isinstance(run_id, bool) or not str(run_id):
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}].run_id is invalid")
        normalized_id = str(run_id)
        if normalized_id in seen_run_ids:
            raise ReleaseGateError(f"repeated-runs.json contains duplicate run_id {normalized_id!r}")
        seen_run_ids.add(normalized_id)
        completed_at = run.get("completed_at")
        if not isinstance(completed_at, str):
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}].completed_at must be RFC3339")
        try:
            completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}].completed_at must be RFC3339") from exc
        if completed.tzinfo is None:
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}].completed_at must include a timezone")
        if previous_time is not None and completed <= previous_time:
            raise ReleaseGateError("repeated runs must be strictly chronological")
        previous_time = completed
        if run.get("status") not in {"passed", "failed"}:
            raise ReleaseGateError(f"repeated-runs.json.runs[{index}].status must be 'passed' or 'failed'")
        identity = _validate_evidence_identity(
            run.get("evidence_identity"),
            location=f"repeated-runs.json.runs[{index}].evidence_identity",
        )
        golden_manifest = _sha256(
            run.get("golden_manifest_sha256"),
            location=f"repeated-runs.json.runs[{index}].golden_manifest_sha256",
        )
        output_sha256 = _sha256(
            run.get("output_sha256"),
            location=f"repeated-runs.json.runs[{index}].output_sha256",
        )
        mismatched_fields = sorted(
            field for field in _EVIDENCE_IDENTITY_FIELDS if identity[field] != expected_identity[field]
        )
        if golden_manifest != expected_golden_manifest_sha256:
            mismatched_fields.append("golden_manifest_sha256")
        if output_sha256 != expected_output_sha256:
            mismatched_fields.append("output_sha256")
        if run["status"] != "passed":
            mismatched_fields.append("status")
        if mismatched_fields:
            mismatches.append(f"run {normalized_id}: {', '.join(sorted(mismatched_fields))}")
        else:
            clean_run_ids.append(normalized_id)
    return len(clean_run_ids), clean_run_ids, mismatches


def _load_evidence(root: Path, *, label: str, include_history: bool) -> dict[str, Any]:
    candidate = _validate_report(
        _read_json(root / "candidate.json", label=f"{label} candidate report"),
        location=f"{label}.candidate",
    )
    baseline = _validate_report(
        _read_json(root / "baseline.json", label=f"{label} baseline report"),
        location=f"{label}.baseline",
    )
    _same_report_population(candidate, baseline, location=label)
    evidence: dict[str, Any] = {"candidate": candidate, "baseline": baseline}
    if include_history:
        evidence["repeated_runs"] = _read_json(root / "repeated-runs.json", label="public repeated runs")
    return evidence


def _validate_golden_corpus(value: Mapping[str, Any], *, location: str) -> Mapping[str, Any]:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseGateError(f"{location} uses an unsupported schema_version")
    expected_fields = {
        "schema_version",
        "strict_fixtures",
        "legacy_degraded_fixtures",
        "manifest_sha256",
        "label_sources",
        "scanner_derived_fixtures",
        "sealed_hf_model_labeled_fixtures",
    }
    if set(value) != expected_fields:
        raise ReleaseGateError(f"{location} must contain exactly {sorted(expected_fields)}")
    for field in (
        "strict_fixtures",
        "legacy_degraded_fixtures",
        "scanner_derived_fixtures",
        "sealed_hf_model_labeled_fixtures",
    ):
        count = value.get(field)
        if not _is_int(count) or count < 0:
            raise ReleaseGateError(f"{location}.{field} must be a non-negative integer")
    label_sources = value.get("label_sources")
    expected_sources = {"public_labeled", "independent_ollama", "agent_labeled", "human_reviewed"}
    if not isinstance(label_sources, Mapping) or set(label_sources) != expected_sources:
        raise ReleaseGateError(f"{location}.label_sources must contain exactly {sorted(expected_sources)}")
    for source, count in label_sources.items():
        if not _is_int(count) or count < 0:
            raise ReleaseGateError(f"{location}.label_sources.{source} must be a non-negative integer")
    if sum(label_sources.values()) != value["strict_fixtures"]:
        raise ReleaseGateError(f"{location} label-source counts must equal strict_fixtures")
    _sha256(value.get("manifest_sha256"), location=f"{location}.manifest_sha256")
    return value


def _load_golden_corpus(public_root: Path, committed_golden: Path) -> Mapping[str, Any]:
    bundled_path = public_root / "golden-corpus.json"
    if not bundled_path.exists():
        raise ReleaseGateError("mandatory bundled golden-corpus.json is missing")
    bundled = _validate_golden_corpus(
        _read_json(bundled_path, label="bundled golden corpus evidence"),
        location="bundled golden-corpus.json",
    )

    _validate_regular_input(committed_golden, label="current committed golden evidence")
    resolved_committed = committed_golden.resolve(strict=True)
    if (
        resolved_committed == bundled_path.resolve(strict=True)
        or os.path.samefile(resolved_committed, bundled_path)
        or public_root in resolved_committed.parents
    ):
        raise ReleaseGateError("current committed golden evidence must be independent of the public artifact")
    current = _validate_golden_corpus(
        _read_json(resolved_committed, label="current committed golden evidence"),
        location="current committed golden-corpus.json",
    )
    if bundled != current:
        differing = sorted(field for field in bundled if bundled[field] != current[field])
        raise ReleaseGateError(
            "bundled public evidence does not match the current committed exact-golden manifest "
            f"(differing fields: {differing})"
        )
    return current


def _fixture_evidence_sha256(value: Mapping[str, Any]) -> str:
    payload = {key: value[key] for key in sorted(value) if key != "evidence_sha256"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"skill-scanner-attested-rule-fixture-evidence-v2\0" + encoded).hexdigest()


def _fixture_provenance_sha256(label_source: str, provenance: Mapping[str, Any]) -> str:
    encoded = json.dumps(provenance, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    domain = f"skill-scanner-rule-fixture-provenance-v1:{label_source}\0".encode()
    return hashlib.sha256(domain + encoded).hexdigest()


def _fixture_attestation_sha256(value: Mapping[str, Any]) -> str:
    payload = {key: value[key] for key in sorted(value) if key != "evidence_sha256"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"skill-scanner-rule-fixture-attestation-v1\0" + encoded).hexdigest()


def _bounded_fixture_string(value: Any, *, location: str, maximum: int = _MAX_RULE_FIXTURE_STRING_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseGateError(f"{location} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise ReleaseGateError(f"{location} exceeds its {maximum}-byte bound")
    return value


def _fixture_sha256(value: Any, *, location: str) -> str:
    return _sha256(value, location=location)


def _validate_fixture_provenance(
    value: Any,
    *,
    label_source: str,
    location: str,
) -> Mapping[str, Any]:
    expected_fields = _RULE_FIXTURE_PROVENANCE_FIELDS[label_source]
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ReleaseGateError(f"{location} must contain exactly {sorted(expected_fields)}")

    if label_source == "public_labeled":
        _bounded_fixture_string(value.get("dataset_id"), location=f"{location}.dataset_id")
        revision = _bounded_fixture_string(value.get("revision"), location=f"{location}.revision", maximum=64)
        if len(revision) not in {40, 64} or any(character not in _HEX_SHA256 for character in revision):
            raise ReleaseGateError(f"{location}.revision must be an immutable lowercase 40- or 64-hex revision")
        _bounded_fixture_string(value.get("split"), location=f"{location}.split", maximum=128)
        _bounded_fixture_string(value.get("sample_id"), location=f"{location}.sample_id")
        _fixture_sha256(value.get("source_artifact_sha256"), location=f"{location}.source_artifact_sha256")
        if value.get("labels_derived_from_scanner") is not False:
            raise ReleaseGateError(f"{location}.labels_derived_from_scanner must be false")
    elif label_source == "independent_ollama":
        for field in ("corpus_id", "case_id", "model_name"):
            _bounded_fixture_string(value.get(field), location=f"{location}.{field}")
        for field in ("report_sha256", "model_digest", "rubric_sha256", "prompt_sha256"):
            _fixture_sha256(value.get(field), location=f"{location}.{field}")
        raw_passes = value.get("passes")
        if not isinstance(raw_passes, list) or len(raw_passes) != 2:
            raise ReleaseGateError(f"{location}.passes must contain exactly two independent passes")
        pass_ids: list[str] = []
        seeds: list[int] = []
        for index, raw_pass in enumerate(raw_passes):
            pass_location = f"{location}.passes[{index}]"
            if not isinstance(raw_pass, Mapping) or set(raw_pass) != {"pass_id", "seed"}:
                raise ReleaseGateError(f"{pass_location} must contain exactly pass_id and seed")
            pass_ids.append(
                _bounded_fixture_string(raw_pass.get("pass_id"), location=f"{pass_location}.pass_id", maximum=128)
            )
            seed = raw_pass.get("seed")
            if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
                raise ReleaseGateError(f"{pass_location}.seed must be a bounded integer")
            seeds.append(seed)
        if len(set(pass_ids)) != 2 or len(set(seeds)) != 2 or pass_ids != sorted(pass_ids):
            raise ReleaseGateError(f"{location}.passes must have distinct seeds and sorted distinct pass IDs")
        if value.get("scanner_outputs_used_as_labels") is not False:
            raise ReleaseGateError(f"{location}.scanner_outputs_used_as_labels must be false")
    elif label_source == "agent_labeled":
        for field in ("agent_id", "run_id", "model_id"):
            _bounded_fixture_string(value.get(field), location=f"{location}.{field}")
        for field in (
            "agent_definition_sha256",
            "model_digest",
            "rubric_sha256",
            "prompt_sha256",
        ):
            _fixture_sha256(value.get(field), location=f"{location}.{field}")
        if value.get("scanner_outputs_used_as_labels") is not False:
            raise ReleaseGateError(f"{location}.scanner_outputs_used_as_labels must be false")
        agent_id = str(value["agent_id"]).casefold().replace("_", "-")
        if "skill-scanner" in agent_id:
            raise ReleaseGateError(f"{location}.agent_id must identify a scanner-independent agent")
    else:
        reviewers = _unique_strings(
            value.get("reviewer_ids"),
            location=f"{location}.reviewer_ids",
            allow_empty=False,
        )
        if not 2 <= len(reviewers) <= 8 or list(reviewers) != sorted(reviewers):
            raise ReleaseGateError(f"{location}.reviewer_ids must contain 2-8 sorted distinct reviewers")
        for index, reviewer in enumerate(reviewers):
            _bounded_fixture_string(reviewer, location=f"{location}.reviewer_ids[{index}]", maximum=256)
        reviewed_at = _bounded_fixture_string(value.get("reviewed_at"), location=f"{location}.reviewed_at", maximum=128)
        try:
            reviewed_timestamp = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReleaseGateError(f"{location}.reviewed_at must be RFC3339") from exc
        if reviewed_timestamp.tzinfo is None:
            raise ReleaseGateError(f"{location}.reviewed_at must include a timezone")
        _fixture_sha256(value.get("review_protocol_sha256"), location=f"{location}.review_protocol_sha256")
        if value.get("scanner_outputs_used_in_review") is not False:
            raise ReleaseGateError(f"{location}.scanner_outputs_used_in_review must be false")
    return value


def _validate_attested_rule_fixtures(
    value: Mapping[str, Any],
    *,
    enforced_rule_ids: set[str],
    rules_sha256: str,
    expression_set_hash: str,
    golden_manifest_sha256: str,
) -> Mapping[str, Mapping[str, Any]]:
    expected_fields = {
        "schema_version",
        "rules_sha256",
        "expression_set_hash",
        "golden_manifest_sha256",
        "rules",
        "attestations",
        "evidence_sha256",
    }
    if set(value) != expected_fields or value.get("schema_version") != _RULE_FIXTURE_EVIDENCE_SCHEMA_VERSION:
        raise ReleaseGateError("rule-fixture-evidence.json does not match the v2 attested-evidence contract")
    for field, expected in (
        ("rules_sha256", rules_sha256),
        ("expression_set_hash", expression_set_hash),
        ("golden_manifest_sha256", golden_manifest_sha256),
    ):
        received = _sha256(value.get(field), location=f"rule-fixture-evidence.json.{field}")
        if received != expected:
            raise ReleaseGateError(f"rule-fixture-evidence.json.{field} does not match release evidence")
    rules = value.get("rules")
    if not isinstance(rules, Mapping) or set(rules) != enforced_rule_ids:
        raise ReleaseGateError(
            "rule-fixture-evidence.json.rules must contain exactly the enforced bundled CEL rule IDs"
        )
    normalized: dict[str, Mapping[str, Any]] = {}
    fixture_roles: dict[str, str] = {}
    for rule_id in sorted(enforced_rule_ids):
        rule = rules[rule_id]
        if not isinstance(rule, Mapping) or set(rule) != _RULE_FIXTURE_FIELDS:
            raise ReleaseGateError(
                f"rule-fixture-evidence.json.rules.{rule_id} must contain exactly {sorted(_RULE_FIXTURE_FIELDS)}"
            )
        role_ids: dict[str, tuple[str, ...]] = {}
        for role in sorted(_RULE_FIXTURE_FIELDS):
            fixture_ids = _unique_strings(
                rule.get(role),
                location=f"rule-fixture-evidence.json.rules.{rule_id}.{role}",
                allow_empty=False,
            )
            if list(fixture_ids) != sorted(fixture_ids):
                raise ReleaseGateError(f"rule-fixture-evidence.json.rules.{rule_id}.{role} must be sorted")
            role_ids[role] = fixture_ids
            expected_role = _RULE_FIXTURE_ROLE_BY_FIELD[role]
            for fixture_id in fixture_ids:
                _bounded_fixture_string(
                    fixture_id,
                    location=f"rule-fixture-evidence.json.rules.{rule_id}.{role}",
                )
                previous_role = fixture_roles.setdefault(fixture_id, expected_role)
                if previous_role != expected_role:
                    raise ReleaseGateError(
                        f"rule-fixture-evidence.json fixture {fixture_id!r} is assigned conflicting roles"
                    )
        flattened = [fixture_id for fixture_ids in role_ids.values() for fixture_id in fixture_ids]
        if len(flattened) != len(set(flattened)):
            raise ReleaseGateError(
                f"rule-fixture-evidence.json.rules.{rule_id} must use distinct fixtures for each role"
            )
        normalized[rule_id] = rule

    attestations = value.get("attestations")
    if (
        not isinstance(attestations, Mapping)
        or set(attestations) != set(fixture_roles)
        or not 1 <= len(attestations) <= _MAX_RULE_FIXTURE_ATTESTATIONS
    ):
        raise ReleaseGateError(
            "rule-fixture-evidence.json.attestations must cover exactly the bounded referenced fixture IDs"
        )
    for fixture_id, raw_attestation in sorted(attestations.items()):
        location = f"rule-fixture-evidence.json.attestations.{fixture_id}"
        if not isinstance(raw_attestation, Mapping) or set(raw_attestation) != _RULE_FIXTURE_ATTESTATION_FIELDS:
            raise ReleaseGateError(f"{location} must contain exactly {sorted(_RULE_FIXTURE_ATTESTATION_FIELDS)}")
        if raw_attestation.get("fixture_id") != fixture_id:
            raise ReleaseGateError(f"{location}.fixture_id must match its attestation key")
        if raw_attestation.get("role") != fixture_roles[fixture_id]:
            raise ReleaseGateError(f"{location}.role does not match the referenced fixture role")
        label_source = raw_attestation.get("label_source")
        if label_source not in _RULE_FIXTURE_LABEL_SOURCES:
            raise ReleaseGateError(f"{location}.label_source must be one of {sorted(_RULE_FIXTURE_LABEL_SOURCES)}")
        package_label = raw_attestation.get("package_label")
        expected_verdict = raw_attestation.get("expected_verdict")
        if (package_label, expected_verdict) not in {
            ("malicious", "unsafe"),
            ("contextual_risk", "unsafe"),
            ("benign", "safe"),
        }:
            raise ReleaseGateError(f"{location} has an inconsistent package_label/expected_verdict pair")
        if fixture_roles[fixture_id] == "true_positive" and (
            package_label != "malicious" or expected_verdict != "unsafe"
        ):
            raise ReleaseGateError(f"{location} true-positive fixtures must be malicious/unsafe")
        if fixture_roles[fixture_id] == "benign_near_miss" and (
            package_label != "benign" or expected_verdict != "safe"
        ):
            raise ReleaseGateError(f"{location} benign near-miss fixtures must be benign/safe")
        if raw_attestation.get("scanner_independent") is not True:
            raise ReleaseGateError(f"{location}.scanner_independent must be true")
        _fixture_sha256(raw_attestation.get("content_sha256"), location=f"{location}.content_sha256")
        provenance = _validate_fixture_provenance(
            raw_attestation.get("provenance"),
            label_source=str(label_source),
            location=f"{location}.provenance",
        )
        provenance_sha256 = _fixture_sha256(
            raw_attestation.get("provenance_sha256"), location=f"{location}.provenance_sha256"
        )
        if provenance_sha256 != _fixture_provenance_sha256(str(label_source), provenance):
            raise ReleaseGateError(f"{location}.provenance_sha256 does not match canonical provenance")
        evidence_sha256 = _fixture_sha256(
            raw_attestation.get("evidence_sha256"), location=f"{location}.evidence_sha256"
        )
        if evidence_sha256 != _fixture_attestation_sha256(raw_attestation):
            raise ReleaseGateError(f"{location}.evidence_sha256 does not match canonical attestation evidence")

    evidence_sha256 = _sha256(
        value.get("evidence_sha256"),
        location="rule-fixture-evidence.json.evidence_sha256",
    )
    if evidence_sha256 != _fixture_evidence_sha256(value):
        raise ReleaseGateError("rule-fixture-evidence.json.evidence_sha256 does not match its canonical content")
    return normalized


def _validate_repeated_comparison_artifact(
    value: Mapping[str, Any],
    *,
    enforced_rule_ids: set[str],
    fixture_rules: Mapping[str, Mapping[str, Any]],
    candidate_identity: Mapping[str, str],
    baseline_identity: Mapping[str, str],
    candidate_producer: Mapping[str, str],
    baseline_producer: Mapping[str, str],
) -> Mapping[str, Any]:
    expected_fields = {
        "schema_version",
        "status",
        "runs",
        "same_evidence_identity",
        "same_producer_identity",
        "stable_output",
        "stability_fingerprints",
        "rule_promotion_evidence",
        "rule_promotion_evidence_required",
        "rule_promotion_passed",
        "comparisons",
    }
    if set(value) != expected_fields or value.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseGateError("repeated-comparison.json does not match the v1 comparison contract")
    if (
        value.get("status") != "passed"
        or value.get("runs") != REQUIRED_REPEATED_RUNS
        or value.get("same_evidence_identity") is not True
        or value.get("same_producer_identity") is not True
        or value.get("stable_output") is not True
        or value.get("rule_promotion_evidence_required") is not True
        or value.get("rule_promotion_passed") is not True
    ):
        raise ReleaseGateError("repeated-comparison.json does not prove a passing five-run promotion comparison")
    fingerprints = value.get("stability_fingerprints")
    if not isinstance(fingerprints, list) or len(fingerprints) != REQUIRED_REPEATED_RUNS:
        raise ReleaseGateError("repeated-comparison.json must contain exactly five stability fingerprints")
    normalized_fingerprints = [
        _sha256(fingerprint, location=f"repeated-comparison.json.stability_fingerprints[{index}]")
        for index, fingerprint in enumerate(fingerprints)
    ]
    if len(set(normalized_fingerprints)) != 1:
        raise ReleaseGateError("repeated-comparison.json stability fingerprints are not identical")

    rule_evidence = value.get("rule_promotion_evidence")
    if not isinstance(rule_evidence, Mapping) or set(rule_evidence) != enforced_rule_ids:
        raise ReleaseGateError(
            "repeated-comparison.json rule promotion evidence must cover exactly the enforced bundled rules"
        )
    rule_fields = {
        "malicious_support_sample_ids",
        "benign_near_miss_sample_ids",
        "true_positive_fixture_ids",
        "benign_near_miss_fixture_ids",
        "boundary_fixture_ids",
        "observed_targeted_benign_candidates",
        "observed_would_suppress_benign_candidates",
        "observed_would_suppress_malicious_high_critical_candidates",
        "observed_would_suppress_malicious_high_critical_sample_ids",
        "normalized_loss_evidence_status",
        "normalized_loss_evidence_exact",
        "normalized_loss_population_sha256",
        "normalized_loss_generation_sha256",
        "baseline_actionable_fp_sample_ids",
        "candidate_actionable_fp_sample_ids",
        "resolved_actionable_fp_sample_ids",
        "malicious_block_loss_sample_ids",
        "relative_actionable_fp_reduction",
        "passes_twenty_percent_reduction",
        "has_malicious_support",
        "has_true_positive_fixture",
        "has_benign_near_miss_fixture",
        "has_boundary_fixture",
        "eligible_for_promotion",
    }
    for rule_id in sorted(enforced_rule_ids):
        evidence = rule_evidence[rule_id]
        if not isinstance(evidence, Mapping) or set(evidence) != rule_fields:
            raise ReleaseGateError(
                f"repeated-comparison.json.rule_promotion_evidence.{rule_id} has an invalid contract"
            )
        for role in _RULE_FIXTURE_FIELDS:
            fixture_ids = _unique_strings(
                evidence.get(role),
                location=f"repeated-comparison.json.rule_promotion_evidence.{rule_id}.{role}",
                allow_empty=False,
            )
            if list(fixture_ids) != list(fixture_rules[rule_id][role]):
                raise ReleaseGateError(f"repeated-comparison.json fixture IDs disagree for enforced rule {rule_id!r}")
        for field in (
            "malicious_support_sample_ids",
            "benign_near_miss_sample_ids",
            "observed_would_suppress_malicious_high_critical_sample_ids",
        ):
            _unique_strings(
                evidence.get(field),
                location=f"repeated-comparison.json.rule_promotion_evidence.{rule_id}.{field}",
            )
        targeted = evidence.get("observed_targeted_benign_candidates")
        suppressed = evidence.get("observed_would_suppress_benign_candidates")
        if not _is_int(targeted) or not _is_int(suppressed) or targeted <= 0 or suppressed < 0 or suppressed > targeted:
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} has invalid observed candidate counts"
            )
        malicious_high_critical = evidence.get("observed_would_suppress_malicious_high_critical_candidates")
        malicious_high_critical_ids = evidence["observed_would_suppress_malicious_high_critical_sample_ids"]
        if (
            not _is_int(malicious_high_critical)
            or malicious_high_critical < 0
            or len(malicious_high_critical_ids) > malicious_high_critical
            or bool(malicious_high_critical_ids) is not bool(malicious_high_critical)
        ):
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} has invalid observed malicious "
                "HIGH/CRITICAL candidate evidence"
            )
        exact_list_fields = (
            "baseline_actionable_fp_sample_ids",
            "candidate_actionable_fp_sample_ids",
            "resolved_actionable_fp_sample_ids",
            "malicious_block_loss_sample_ids",
        )
        exact_lists = {
            field: list(
                _unique_strings(
                    evidence.get(field),
                    location=f"repeated-comparison.json.rule_promotion_evidence.{rule_id}.{field}",
                )
            )
            for field in exact_list_fields
        }
        targeted_ids = list(evidence["benign_near_miss_sample_ids"])
        baseline_actionable = exact_lists["baseline_actionable_fp_sample_ids"]
        candidate_actionable = exact_lists["candidate_actionable_fp_sample_ids"]
        resolved_actionable = exact_lists["resolved_actionable_fp_sample_ids"]
        malicious_support = list(evidence["malicious_support_sample_ids"])
        malicious_block_loss = exact_lists["malicious_block_loss_sample_ids"]
        if (
            not set(baseline_actionable) <= set(targeted_ids)
            or not set(candidate_actionable) <= set(targeted_ids)
            or resolved_actionable != sorted(set(baseline_actionable) - set(candidate_actionable))
            or not set(malicious_block_loss) <= set(malicious_support)
        ):
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} has an invalid normalized-loss contract"
            )
        relative_reduction = evidence.get("relative_actionable_fp_reduction")
        expected_reduction = (
            (len(baseline_actionable) - len(candidate_actionable)) / len(baseline_actionable)
            if baseline_actionable
            else None
        )
        if (
            evidence.get("normalized_loss_evidence_status") != "computed_exact_sample_outcomes"
            or evidence.get("normalized_loss_evidence_exact") is not True
            or isinstance(relative_reduction, bool)
            or not isinstance(relative_reduction, (int, float))
            or expected_reduction is None
            or not math.isfinite(float(relative_reduction))
            or abs(float(relative_reduction) - expected_reduction) > _EPSILON
            or evidence.get("passes_twenty_percent_reduction")
            is not (expected_reduction + _EPSILON >= 0.20 and not malicious_block_loss)
            or evidence.get("eligible_for_promotion") is not True
        ):
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} lacks valid exact normalized-loss evidence"
            )
        expected_population_digest = normalized_loss_population_sha256(
            rule_id=rule_id,
            targeted_benign_sample_ids=targeted_ids,
            baseline_actionable_sample_ids=baseline_actionable,
            candidate_actionable_sample_ids=candidate_actionable,
            resolved_actionable_sample_ids=resolved_actionable,
            malicious_support_sample_ids=malicious_support,
            malicious_block_loss_sample_ids=malicious_block_loss,
        )
        if (
            _sha256(
                evidence.get("normalized_loss_population_sha256"),
                location=f"repeated-comparison.json.rule_promotion_evidence.{rule_id}.normalized_loss_population_sha256",
            )
            != expected_population_digest
        ):
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} normalized-loss population hash disagrees"
            )
        expected_generation_digest = normalized_loss_generation_sha256(
            baseline_identity,
            candidate_identity,
        )
        if (
            _sha256(
                evidence.get("normalized_loss_generation_sha256"),
                location=f"repeated-comparison.json.rule_promotion_evidence.{rule_id}.normalized_loss_generation_sha256",
            )
            != expected_generation_digest
        ):
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} normalized-loss generation hash disagrees"
            )
        expected_booleans = {
            "has_malicious_support": bool(evidence["malicious_support_sample_ids"]),
            "has_true_positive_fixture": True,
            "has_benign_near_miss_fixture": True,
            "has_boundary_fixture": True,
        }
        if any(evidence.get(field) is not expected for field, expected in expected_booleans.items()):
            raise ReleaseGateError(
                f"repeated-comparison.json enforced rule {rule_id!r} does not satisfy promotion requirements"
            )

    comparisons = value.get("comparisons")
    if not isinstance(comparisons, list) or len(comparisons) != REQUIRED_REPEATED_RUNS:
        raise ReleaseGateError("repeated-comparison.json must contain exactly five comparisons")
    for index, comparison in enumerate(comparisons):
        if not isinstance(comparison, Mapping) or comparison.get("status") != "passed":
            raise ReleaseGateError(f"repeated-comparison.json.comparisons[{index}] did not pass")
        if (
            comparison.get("comparison_kind") != "cel_activation"
            or comparison.get("baseline_cel_mode") != CelMode.OFF.value
            or comparison.get("candidate_cel_mode") != CelMode.ENFORCE.value
            or comparison.get("population_locked") is not True
            or comparison.get("missing_group_dimensions") != []
        ):
            raise ReleaseGateError(
                f"repeated-comparison.json.comparisons[{index}] is not a complete enforced CEL comparison"
            )
        identities = comparison.get("evidence_identity")
        if not isinstance(identities, Mapping):
            raise ReleaseGateError(f"repeated-comparison.json.comparisons[{index}] lacks evidence identity")
        if identities.get("candidate") != candidate_identity or identities.get("baseline") != baseline_identity:
            raise ReleaseGateError(
                f"repeated-comparison.json.comparisons[{index}] does not bind the release generation"
            )
        if identities.get("changed_fields") != ["cel_mode"]:
            raise ReleaseGateError(f"repeated-comparison.json.comparisons[{index}] changes fields other than CEL mode")
        producers = comparison.get("producer")
        if not isinstance(producers, Mapping):
            raise ReleaseGateError(f"repeated-comparison.json.comparisons[{index}] lacks producer identity")
        if producers.get("candidate") != candidate_producer or producers.get("baseline") != baseline_producer:
            raise ReleaseGateError(f"repeated-comparison.json.comparisons[{index}] does not bind the release producer")
        if producers.get("changed_fields") != []:
            raise ReleaseGateError(f"repeated-comparison.json.comparisons[{index}] changes producer identity")
    return value


def _evaluate_optional_private(
    private_root: Path,
    *,
    public_generation: Mapping[str, str],
    public_baseline_generation: Mapping[str, str],
) -> dict[str, Any]:
    """Evaluate optional private evidence without affecting hard release gates."""

    private = _load_evidence(private_root, label="private", include_history=False)
    _reject_waiver_metadata(private, location="private evidence")
    candidate = private["candidate"]
    baseline = private["baseline"]
    candidate_identity = _private_identity(candidate, location="private.candidate")
    baseline_identity = _private_identity(baseline, location="private.baseline")
    for field in (
        "id",
        "snapshot_sha256",
        "source_disjoint",
        "holdout_fraction",
        "samples",
        "malicious_or_contextual",
        "benign",
        "label_attestation",
    ):
        if candidate_identity[field] != baseline_identity[field]:
            raise ReleaseGateError(f"private candidate and baseline corpus {field} differ")
    candidate_generation, baseline_generation = _validate_controlled_generation(
        candidate,
        baseline,
        location="private",
    )
    for report_label, corpus, generation in (
        ("candidate", candidate_identity, candidate_generation),
        ("baseline", baseline_identity, baseline_generation),
    ):
        if generation["dataset_or_corpus_id"] != corpus["id"]:
            raise ReleaseGateError(f"private {report_label} evidence identity does not bind the corpus ID")
        if generation["snapshot_sha256"] != corpus["snapshot_sha256"]:
            raise ReleaseGateError(f"private {report_label} evidence identity does not bind the corpus snapshot")
    for field in {"build_sha256", "policy_sha256", "rules_sha256", "expression_set_hash", "cel_mode"}:
        if candidate_generation[field] != public_generation[field]:
            raise ReleaseGateError(f"public and private candidate evidence_identity.{field} differ")
        if baseline_generation[field] != public_baseline_generation[field]:
            raise ReleaseGateError(f"public and private baseline evidence_identity.{field} differ")

    checks: list[GateCheck] = []
    for report_label, report in (("private candidate", candidate), ("private baseline", baseline)):
        _append_check(
            checks,
            name=f"{report_label.replace(' ', '.')}.complete",
            passed=report["status"] == "passed" and not report["errors"],
            requirement="optional private benchmark completed without evaluation or ingestion errors",
            current={"status": report["status"], "errors": report["errors"]},
        )
    _append_check(
        checks,
        name="private.candidate.release_profile",
        passed=candidate["profile"] == "release",
        requirement="optional private candidate evidence is a release-profile run",
        current=candidate["profile"],
    )
    _append_cel_evidence_checks(candidate, baseline, prefix="private", checks=checks)
    _append_group_completeness_checks(candidate, prefix="private", checks=checks)
    _compare_metrics(candidate, baseline, prefix="private", checks=checks)
    return {
        "enabled": True,
        "blocking": False,
        "status": "passed" if all(check.passed for check in checks) else "failed",
        "corpus_id": candidate_identity["id"],
        "snapshot_sha256": candidate_identity["snapshot_sha256"],
        "label_sources": dict(candidate_identity["label_attestation"]["label_sources"]),
        "label_provenance_sha256": candidate_identity["label_attestation"]["label_provenance_sha256"],
        "label_evidence_sha256": candidate_identity["label_attestation"]["label_evidence_sha256"],
        "checks": [asdict(check) for check in checks],
        "errors": [],
    }


def run_release_gate(
    *,
    public_corpus: Path,
    dataset_lock: Path,
    committed_golden: Path,
    private_corpus: Path | None = None,
    expected_source_revision: str | None = None,
) -> dict[str, Any]:
    """Validate frozen evidence and return a complete release-gate report."""

    if expected_source_revision is not None and (
        len(expected_source_revision) != 40
        or any(character not in _HEX_SHA256 for character in expected_source_revision)
    ):
        raise ReleaseGateError("expected source revision must be a full lowercase Git commit SHA")

    public_root = _validate_local_root(public_corpus, label="public corpus")
    _reject_waiver_inputs(public_root, label="public corpus")
    private_root: Path | None = None
    private_preflight_error: str | None = None
    if private_corpus is not None:
        try:
            private_root = _validate_local_root(private_corpus, label="private corpus")
            if (
                public_root == private_root
                or public_root in private_root.parents
                or private_root in public_root.parents
            ):
                raise ReleaseGateError("public and private corpus roots must be separate, non-nested artifacts")
        except ReleaseGateError as exc:
            private_preflight_error = str(exc)
            private_root = None
    if private_root is not None:
        _reject_waiver_inputs(private_root, label="private corpus")
        for report_name in ("candidate.json", "baseline.json"):
            try:
                report = _read_json(private_root / report_name, label=f"private {report_name}")
            except ReleaseGateError:
                # Optional private evidence remains non-blocking when it is absent or
                # malformed. A valid document that asks for a waiver is still a hard
                # release rejection below.
                continue
            _reject_waiver_metadata(report, location=f"private {report_name}")
    golden = _load_golden_corpus(public_root, committed_golden)

    _validate_regular_input(dataset_lock, label="dataset lock")
    _read_json(dataset_lock, label="dataset lock")
    try:
        lock_manifest = load_dataset_lock(dataset_lock)
    except (OSError, json.JSONDecodeError, DatasetLockError) as exc:
        raise ReleaseGateError(f"dataset lock is invalid: {exc}") from exc

    public = _load_evidence(public_root, label="public", include_history=True)
    _reject_waiver_metadata(public, location="public evidence")
    public_candidate = public["candidate"]
    public_baseline = public["baseline"]
    candidate_identity = _public_identity(public_candidate, location="public.candidate")
    baseline_identity = _public_identity(public_baseline, location="public.baseline")
    for field in ("id", "revision", "artifact_manifest_sha256", "sample_metadata_manifest_sha256"):
        if candidate_identity[field] != baseline_identity[field]:
            raise ReleaseGateError(f"public candidate and baseline dataset {field} differ")
    if candidate_identity["id"] != PRIMARY_PUBLIC_DATASET:
        raise ReleaseGateError(f"public release gate requires {PRIMARY_PUBLIC_DATASET}, got {candidate_identity['id']}")
    public_generation, public_baseline_generation = _validate_controlled_generation(
        public_candidate,
        public_baseline,
        location="public",
    )
    bundled_generation = _current_bundled_cel_generation()
    if public_generation["rules_sha256"] != bundled_generation["rules_sha256"]:
        raise ReleaseGateError("public release evidence does not match the current bundled rule generation")
    enforced_rule_ids = {rule_id for rule_id, rollout in bundled_generation["rollouts"].items() if rollout == "enforce"}
    if expected_source_revision is not None:
        for report_label, report in (("candidate", public_candidate), ("baseline", public_baseline)):
            actual_revision = report["producer"]["source_revision"]
            if actual_revision != expected_source_revision:
                raise ReleaseGateError(
                    f"public {report_label} producer source_revision does not match the release commit "
                    f"(expected {expected_source_revision}, received {actual_revision})"
                )
    for report_label, dataset, generation in (
        ("candidate", candidate_identity, public_generation),
        ("baseline", baseline_identity, public_baseline_generation),
    ):
        if generation["dataset_or_corpus_id"] != dataset["id"]:
            raise ReleaseGateError(f"public {report_label} evidence identity does not bind the dataset ID")
        if generation["snapshot_sha256"] != dataset["artifact_manifest_sha256"]:
            raise ReleaseGateError(f"public {report_label} evidence identity does not bind the dataset snapshot")

    locked_dataset = get_locked_dataset(candidate_identity["id"], lock_manifest)
    locked_integrity = locked_dataset["integrity"]
    if candidate_identity["revision"] != locked_dataset["revision"]:
        raise ReleaseGateError("public report revision does not match the dataset lock")
    if locked_integrity["hashes_pending"] is not False or locked_dataset["gating"]["blocking"] is not True:
        raise ReleaseGateError("public dataset lock is not reviewed and blocking-eligible")
    if candidate_identity["artifact_manifest_sha256"] != locked_integrity["artifact_manifest_sha256"]:
        raise ReleaseGateError("public report artifact manifest does not match the dataset lock")
    if candidate_identity["sample_metadata_manifest_sha256"] != locked_integrity["sample_metadata_manifest_sha256"]:
        raise ReleaseGateError("public report sample metadata manifest does not match the dataset lock")
    _validate_locked_track_populations(
        public_candidate,
        locked_dataset,
        location="public.candidate",
    )
    _validate_locked_track_populations(
        public_baseline,
        locked_dataset,
        location="public.baseline",
    )

    checks: list[GateCheck] = []
    for report_label, report in (
        ("public candidate", public_candidate),
        ("public baseline", public_baseline),
    ):
        _append_check(
            checks,
            name=f"{report_label.replace(' ', '.')}.complete",
            passed=report["status"] == "passed" and not report["errors"],
            requirement="benchmark report completed without evaluation or ingestion errors",
            current={"status": report["status"], "errors": report["errors"]},
        )
    _append_check(
        checks,
        name="public.candidate.release_profile",
        passed=public_candidate["profile"] == "release",
        requirement="candidate evidence is a full release-profile run",
        current=public_candidate["profile"],
    )
    _append_check(
        checks,
        name="public.dataset.blocking_eligible",
        passed=candidate_identity["blocking_eligible"] is True,
        requirement="producer marked the pinned public snapshot blocking-eligible",
        current=candidate_identity["blocking_eligible"],
    )
    _append_cel_evidence_checks(
        public_candidate,
        public_baseline,
        prefix="public",
        checks=checks,
    )
    _append_group_completeness_checks(public_candidate, prefix="public", checks=checks)
    _compare_metrics(public_candidate, public_baseline, prefix="public", checks=checks)

    rule_promotion_required = bool(enforced_rule_ids)
    rule_promotion_artifacts_passed = False
    attested_fixture_evidence_sha256: str | None = None
    if rule_promotion_required:
        if public_candidate["cel_mode"] != CelMode.ENFORCE.value:
            raise ReleaseGateError("enforced bundled CEL rules require a cel_mode=enforce release benchmark")
        candidate_rule_telemetry = public_candidate["summary"]["cel"]["per_rule"]
        for rule_id in sorted(enforced_rule_ids):
            rule_telemetry = candidate_rule_telemetry.get(rule_id)
            if not isinstance(rule_telemetry, Mapping) or set(rule_telemetry.get("rollouts", [])) != {"enforce"}:
                raise ReleaseGateError(
                    f"release benchmark lacks enforced rollout telemetry for bundled CEL rule {rule_id!r}"
                )
        fixture_path = public_root / "rule-fixture-evidence.json"
        comparison_path = public_root / "repeated-comparison.json"
        if not fixture_path.exists() or not comparison_path.exists():
            raise ReleaseGateError(
                "enforced bundled CEL rules require rule-fixture-evidence.json and repeated-comparison.json"
            )
        fixture_document = _read_json(fixture_path, label="attested rule fixture evidence")
        _reject_waiver_metadata(fixture_document, location="rule-fixture-evidence.json")
        fixture_rules = _validate_attested_rule_fixtures(
            fixture_document,
            enforced_rule_ids=enforced_rule_ids,
            rules_sha256=public_generation["rules_sha256"],
            expression_set_hash=public_generation["expression_set_hash"],
            golden_manifest_sha256=golden["manifest_sha256"],
        )
        comparison_document = _read_json(comparison_path, label="repeated CEL comparison")
        _reject_waiver_metadata(comparison_document, location="repeated-comparison.json")
        _validate_repeated_comparison_artifact(
            comparison_document,
            enforced_rule_ids=enforced_rule_ids,
            fixture_rules=fixture_rules,
            candidate_identity=public_generation,
            baseline_identity=public_baseline_generation,
            candidate_producer=public_candidate["producer"],
            baseline_producer=public_baseline["producer"],
        )
        rule_promotion_artifacts_passed = True
        attested_fixture_evidence_sha256 = fixture_document["evidence_sha256"]
    _append_check(
        checks,
        name="promotion.enforced_rule_evidence",
        passed=not rule_promotion_required or rule_promotion_artifacts_passed,
        requirement=(
            "every enforced bundled CEL rule has scanner-independent, source-attested "
            "TP/near-miss/boundary fixtures plus exact normalized-loss evidence"
        ),
        current={
            "required": rule_promotion_required,
            "enforced_rule_ids": sorted(enforced_rule_ids),
            "artifacts_passed": rule_promotion_artifacts_passed,
        },
    )

    golden_manifest_sha256 = golden["manifest_sha256"]
    candidate_output_sha256 = stable_release_output_sha256(public_candidate)
    clean_repeated_runs, clean_run_ids, repeated_mismatches = _validate_repeated_runs(
        public["repeated_runs"],
        expected_identity=public_generation,
        expected_golden_manifest_sha256=golden_manifest_sha256,
        expected_output_sha256=candidate_output_sha256,
    )
    repeated_run_count = len(public["repeated_runs"]["runs"])
    _append_check(
        checks,
        name="promotion.deterministic_repeated_runs",
        passed=(repeated_run_count == REQUIRED_REPEATED_RUNS and clean_repeated_runs == REQUIRED_REPEATED_RUNS),
        requirement=(
            f"exactly {REQUIRED_REPEATED_RUNS} clean runs share the frozen corpus, build, policy, rules, "
            "CEL generation, exact-golden manifest, and normalized output"
        ),
        current={"runs": repeated_run_count, "clean_runs": clean_repeated_runs},
        detail="; ".join(repeated_mismatches) if repeated_mismatches else None,
    )

    golden_summary: dict[str, Any] = {
        "enabled": True,
        "required": True,
        "verified_against_current_committed_manifest": True,
        "strict_fixtures": golden["strict_fixtures"],
        "legacy_degraded_fixtures": golden["legacy_degraded_fixtures"],
        "manifest_sha256": golden["manifest_sha256"],
        "label_sources": dict(golden["label_sources"]),
        "scanner_derived_fixtures": golden["scanner_derived_fixtures"],
        "sealed_hf_model_labeled_fixtures": golden["sealed_hf_model_labeled_fixtures"],
    }
    _append_check(
        checks,
        name="golden_corpus.strict_fixtures",
        passed=golden["strict_fixtures"] > 0,
        requirement="committed exact golden corpus contains at least one strict fixture",
        current=golden["strict_fixtures"],
        detail=(
            "zero strict fixtures remains a release blocker; labels must come from public ground truth, "
            "independent review, or the frozen Ollama labeling protocol, never scanner output"
            if golden["strict_fixtures"] == 0
            else None
        ),
    )
    _append_check(
        checks,
        name="golden_corpus.no_legacy_degraded",
        passed=golden["legacy_degraded_fixtures"] == 0,
        requirement="mandatory committed exact golden corpus contains no degraded category-only fixtures",
        current=golden["legacy_degraded_fixtures"],
    )
    _append_check(
        checks,
        name="golden_corpus.no_scanner_derived_labels",
        passed=golden["scanner_derived_fixtures"] == 0,
        requirement="scanner outputs are never used as golden labels",
        current=golden["scanner_derived_fixtures"],
    )
    _append_check(
        checks,
        name="golden_corpus.no_sealed_hf_model_labels",
        passed=golden["sealed_hf_model_labeled_fixtures"] == 0,
        requirement="Ollama-labeled cases never contaminate sealed Hugging Face labeled test metrics",
        current=golden["sealed_hf_model_labeled_fixtures"],
    )

    private_summary: dict[str, Any] = {
        "enabled": private_corpus is not None,
        "blocking": False,
        "status": "failed" if private_preflight_error is not None else "not_supplied",
        "checks": [],
        "errors": [private_preflight_error] if private_preflight_error is not None else [],
    }
    if private_root is not None:
        try:
            private_summary = _evaluate_optional_private(
                private_root,
                public_generation=public_generation,
                public_baseline_generation=public_baseline_generation,
            )
        except ReleaseGateError as exc:
            private_summary.update(status="failed", errors=[str(exc)])

    passed = all(check.passed for check in checks)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if passed else "failed",
        "public": {
            "dataset_id": candidate_identity["id"],
            "revision": candidate_identity["revision"],
            "artifact_manifest_sha256": candidate_identity["artifact_manifest_sha256"],
            "sample_metadata_manifest_sha256": candidate_identity["sample_metadata_manifest_sha256"],
            "source_revision": public_candidate["producer"]["source_revision"],
        },
        "private": private_summary,
        "golden_corpus": golden_summary,
        "promotion_evidence": {
            "required_repeated_runs": REQUIRED_REPEATED_RUNS,
            "clean_repeated_runs": clean_repeated_runs,
            "clean_run_ids": clean_run_ids,
            "normalized_output_sha256": candidate_output_sha256,
            "complete_public_release_run_passed": passed,
            "enforced_rule_ids": sorted(enforced_rule_ids),
            "rule_promotion_required": rule_promotion_required,
            "rule_promotion_artifacts_passed": rule_promotion_artifacts_passed,
            "attested_fixture_evidence_sha256": attested_fixture_evidence_sha256,
        },
        "waivers": {"accepted": False, "present": False},
        "checks": [asdict(check) for check in checks],
        "errors": [],
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise ReleaseGateError(f"output must not be a symlink or non-regular file: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(temporary, flags, 0o600)
    try:
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write while emitting release-gate report")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _validate_output_location(
    output: Path,
    *,
    public_corpus: Path,
    private_corpus: Path | None,
    dataset_lock: Path,
    committed_golden: Path,
) -> None:
    """Keep generated output outside every immutable evidence input."""

    resolved_output = output.resolve(strict=False)
    for label, input_root in (
        ("public corpus", public_corpus),
        ("private corpus", private_corpus),
    ):
        if input_root is None:
            continue
        resolved_root = input_root.resolve(strict=False)
        if resolved_output == resolved_root or resolved_output.is_relative_to(resolved_root):
            raise ReleaseGateError(f"output must be outside the immutable {label} root")
    if resolved_output == dataset_lock.resolve(strict=False):
        raise ReleaseGateError("output must not overwrite the dataset lock")
    if resolved_output == committed_golden.resolve(strict=False):
        raise ReleaseGateError("output must not overwrite current committed golden evidence")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply offline release gates to frozen candidate and baseline reports."
    )
    parser.add_argument("--public-corpus", type=Path, required=True)
    parser.add_argument("--committed-golden", type=Path, required=True)
    parser.add_argument("--private-corpus", type=Path, help="Optional nonblocking supplemental evidence")
    parser.add_argument("--dataset-lock", type=Path, required=True)
    parser.add_argument(
        "--expected-source-revision",
        required=True,
        help="Exact 40-character release commit SHA that produced candidate and baseline evidence",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _validate_output_location(
            args.output,
            public_corpus=args.public_corpus,
            private_corpus=args.private_corpus,
            dataset_lock=args.dataset_lock,
            committed_golden=args.committed_golden,
        )
    except (ReleaseGateError, OSError) as exc:
        print(f"release gate rejected unsafe output: {exc}", file=sys.stderr)
        return 2

    try:
        report = run_release_gate(
            public_corpus=args.public_corpus,
            private_corpus=args.private_corpus,
            dataset_lock=args.dataset_lock,
            committed_golden=args.committed_golden,
            expected_source_revision=args.expected_source_revision,
        )
        exit_code = 0 if report["status"] == "passed" else 1
    except (ReleaseGateError, OSError, KeyError, TypeError) as exc:
        waiver_present = "waiver" in str(exc).casefold()
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
            "release_source_revision": args.expected_source_revision,
            "public": None,
            "private": {"enabled": args.private_corpus is not None, "blocking": False},
            "golden_corpus": {"enabled": False, "required": True},
            "promotion_evidence": {
                "required_repeated_runs": REQUIRED_REPEATED_RUNS,
                "clean_repeated_runs": 0,
                "clean_run_ids": [],
                "normalized_output_sha256": None,
                "complete_public_release_run_passed": False,
                "enforced_rule_ids": [],
                "rule_promotion_required": False,
                "rule_promotion_artifacts_passed": False,
                "attested_fixture_evidence_sha256": None,
            },
            "waivers": {"accepted": False, "present": waiver_present},
            "checks": [],
            "errors": [str(exc)],
        }
        exit_code = 2

    try:
        _write_report(args.output, report)
    except (ReleaseGateError, OSError) as exc:
        print(f"release gate could not write its report: {exc}", file=sys.stderr)
        return 2

    if exit_code:
        print(f"release gates failed; see {args.output}", file=sys.stderr)
    else:
        print(f"release gates passed; report written to {args.output}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
