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

"""Strict metadata-only adapter for MaliciousAgentSkillsBench.

Only the two upstream CSV data files are consumed.  Dataset hooks, linked
repositories, URLs, package archives, Python modules, and sample code are never
loaded.  The 94k ``safe`` labels are retained only as a provenance count: this
module deliberately exposes no benign examples or precision denominator.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import unicodedata
from collections import Counter
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from evals.datasets.public_datasets import (
    DatasetLockError,
    DatasetSchemaError,
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    validate_artifact_manifest,
)
from evals.datasets.quarantined_text import (
    QuarantinedTextError,
    TextTreePolicy,
    inventory_text_tree,
    read_regular_json,
    read_regular_text,
    require_exact_fields,
    require_sha256,
    require_string,
    validate_declared_artifacts,
)

DATASET_ID = "ProtectSkills/MaliciousAgentSkillsBench"
SNAPSHOT_MANIFEST = "malicious-agent-skills-snapshot.json"
SNAPSHOT_SCHEMA_VERSION = 1
SKILLS_DATASET_FILE = "skills_dataset.csv"
MALICIOUS_SKILLS_FILE = "malicious_skills.csv"

EXPECTED_SKILLS_ROWS = 98_380
EXPECTED_MALICIOUS_ROWS = 157
EXPECTED_LABEL_COUNTS = {"safe": 94_093, "suspicious": 4_130, "malicious": 157}
EXPECTED_PATTERN_INSTANCES = 632
EXPECTED_SEVERITY_COUNTS = {"CRITICAL": 252, "HIGH": 202, "MEDIUM": 176, "LOW": 2}
EXPECTED_PATTERNS = frozenset(
    {
        "Behavior Manipulation",
        "Code Obfuscation",
        "Command Injection",
        "Context Leakage",
        "Data Exfiltration",
        "Excessive Permissions",
        "External Transmission",
        "File System Scan",
        "Hardcoded Tokens",
        "Hidden Instructions",
        "Instruction Override",
        "Network sniffing / Credential theft",
        "Privilege Escalation",
        "Remote Code Execution",
    }
)

_ROOT_FIELDS = frozenset({"schema_version", "dataset_id", "revision", "artifact_manifest_sha256", "artifacts"})
_SKILLS_FIELDS = ("source", "repo", "skill_name", "classification", "url")
_MALICIOUS_FIELDS = ("source", "repo", "skill_name", "classification", "Pattern", "Severity")
_LABELS = frozenset(EXPECTED_LABEL_COUNTS)
_SEVERITIES = frozenset(EXPECTED_SEVERITY_COUNTS)
_REDACTED_URL_VALUES = frozenset({"", "[REDACTED]", "[REDACTED:repo_contains_malicious]"})
_CSV_POLICY = TextTreePolicy(
    allowed_suffixes=frozenset({".csv"}),
    allowed_basenames=frozenset(),
    max_files=2,
    max_file_bytes=32 * 1024 * 1024,
    max_total_bytes=48 * 1024 * 1024,
)
_MAX_FIELD_BYTES = 256 * 1024
_MAX_LIST_ITEMS = 1_024


class MaliciousAgentSkillsError(ValueError):
    """Raised when the pinned metadata snapshot is unsafe or drifts."""


@dataclass(frozen=True)
class MaliciousAgentCase:
    """One confirmed-malicious metadata case; it contains no package content."""

    case_id: str
    source_id: str
    repository_id: str
    skill_name: str
    url: str | None
    patterns: tuple[str, ...]
    severities: tuple[str, ...]
    structural_family_id: str
    actor_campaign_id: str
    lexical_template_id: str
    overlap_keys: tuple[str, ...]


@dataclass(frozen=True)
class MaliciousAgentSkillsSnapshot:
    """Validated metadata projection with safe rows reduced to counts only."""

    root: Path
    revision: str
    artifact_manifest_sha256: str
    artifact_manifest_pinned: bool
    skills_population: int
    label_counts: Mapping[str, int]
    duplicate_metadata_rows: int
    malicious_cases: tuple[MaliciousAgentCase, ...]

    def nonoverlapping_cases(
        self, malicious_skill_bench_overlap_keys: Collection[str]
    ) -> tuple[MaliciousAgentCase, ...]:
        """Exclude every case sharing any caller-supplied MSB overlap key."""

        overlap = frozenset(malicious_skill_bench_overlap_keys)
        return tuple(case for case in self.malicious_cases if overlap.isdisjoint(case.overlap_keys))


def _stable_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _bounded_metadata(value: Any, location: str, *, max_bytes: int = 4_096) -> str:
    try:
        return require_string(value, location, max_bytes=max_bytes)
    except QuarantinedTextError as exc:
        raise MaliciousAgentSkillsError(str(exc)) from exc


def _identity(source: str, repository: str, skill_name: str) -> tuple[str, str, str]:
    return (_stable_text(source), _stable_text(repository), _stable_text(skill_name))


def _identity_name(value: Any, location: str) -> str:
    """Normalize reviewed surrounding whitespace before building a metadata identity."""

    normalized = value.strip() if isinstance(value, str) else value
    return _bounded_metadata(normalized, location)


def _tagged_hash(tag: str, *values: str) -> str:
    encoded = json.dumps([tag, *values], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return f"{tag}:{hashlib.sha256(encoded).hexdigest()}"


def _canonical_url(value: Any, location: str) -> str | None:
    if value == "":
        return None
    raw = _bounded_metadata(value, location, max_bytes=8_192)
    if raw in _REDACTED_URL_VALUES:
        return None
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise MaliciousAgentSkillsError(f"{location} is not a valid HTTP(S) URL") from exc
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise MaliciousAgentSkillsError(f"{location} must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise MaliciousAgentSkillsError(f"{location} may not contain credentials")
    hostname = parsed.hostname.casefold()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = (parsed.scheme.casefold() == "http" and port == 80) or (
        parsed.scheme.casefold() == "https" and port == 443
    )
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit(SplitResult(parsed.scheme.casefold(), netloc, path, parsed.query, ""))


def _read_csv_rows(path: Path, expected_header: tuple[str, ...], *, max_rows: int) -> list[tuple[str, ...]]:
    try:
        text = read_regular_text(path, max_bytes=_CSV_POLICY.max_file_bytes)
    except QuarantinedTextError as exc:
        raise MaliciousAgentSkillsError(str(exc)) from exc
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except (StopIteration, csv.Error) as exc:
        raise MaliciousAgentSkillsError(f"{path.name} is missing a valid CSV header") from exc
    if tuple(header) != expected_header:
        raise MaliciousAgentSkillsError(
            f"{path.name} schema drift (expected {list(expected_header)}, received {header})"
        )
    rows: list[tuple[str, ...]] = []
    try:
        for line_number, row in enumerate(reader, start=2):
            if len(row) != len(expected_header):
                raise MaliciousAgentSkillsError(f"{path.name} row {line_number} has {len(row)} fields")
            if len(rows) >= max_rows:
                raise MaliciousAgentSkillsError(f"{path.name} exceeds the locked row-count bound")
            for column, value in zip(expected_header, row, strict=True):
                if len(value.encode("utf-8")) > _MAX_FIELD_BYTES or "\x00" in value:
                    raise MaliciousAgentSkillsError(f"{path.name} row {line_number}.{column} exceeds field bounds")
            rows.append(tuple(row))
    except csv.Error as exc:
        raise MaliciousAgentSkillsError(f"invalid CSV syntax in {path.name}: {exc}") from exc
    return rows


def _semicolon_string_list(value: str, location: str) -> tuple[str, ...]:
    raw = _bounded_metadata(value, location, max_bytes=_MAX_FIELD_BYTES)
    values = tuple(part.strip() for part in raw.split(";"))
    if not values or len(values) > _MAX_LIST_ITEMS or any(not part for part in values):
        raise MaliciousAgentSkillsError(f"{location} must be a non-empty bounded semicolon-delimited list")
    return tuple(_bounded_metadata(part, f"{location}[{index}]") for index, part in enumerate(values))


def _case_id(identity: tuple[str, str, str]) -> str:
    return _tagged_hash("masb-case-v1", *identity)


def _case_from_row(
    row: tuple[str, ...],
    *,
    index: int,
    main_malicious: Mapping[tuple[str, str, str], str | None],
) -> tuple[tuple[str, str, str], MaliciousAgentCase]:
    source = _bounded_metadata(row[0], f"malicious_skills[{index}].source")
    repository = _bounded_metadata(row[1], f"malicious_skills[{index}].repo")
    skill_name = _identity_name(row[2], f"malicious_skills[{index}].skill_name")
    if row[3] != "malicious":
        raise MaliciousAgentSkillsError(f"malicious_skills[{index}].classification must be 'malicious'")
    identity = _identity(source, repository, skill_name)
    if identity not in main_malicious:
        raise MaliciousAgentSkillsError(f"malicious_skills[{index}] is absent from the main malicious population")
    url = main_malicious[identity]
    patterns = _semicolon_string_list(row[4], f"malicious_skills[{index}].Pattern")
    severities = tuple(value.upper() for value in _semicolon_string_list(row[5], f"malicious_skills[{index}].Severity"))
    if len(patterns) != len(severities):
        raise MaliciousAgentSkillsError(f"malicious_skills[{index}] pattern/severity lists are not aligned")
    if any(value not in EXPECTED_PATTERNS for value in patterns):
        raise MaliciousAgentSkillsError(f"malicious_skills[{index}] contains an unknown taxonomy label")
    if any(value not in _SEVERITIES for value in severities):
        raise MaliciousAgentSkillsError(f"malicious_skills[{index}] contains an unknown severity")
    pattern_family = _tagged_hash("masb-pattern-family-v1", *sorted({_stable_text(value) for value in patterns}))
    case_identifier = _case_id(identity)
    overlap_keys = {
        case_identifier,
        _tagged_hash("identity", *identity),
        _tagged_hash("repository", identity[0], identity[1]),
    }
    if url is not None:
        overlap_keys.add(_tagged_hash("url", _stable_text(url)))
    return identity, MaliciousAgentCase(
        case_id=case_identifier,
        source_id=source,
        repository_id=repository,
        skill_name=skill_name,
        url=url,
        patterns=patterns,
        severities=severities,
        structural_family_id=pattern_family,
        actor_campaign_id="not_available",
        lexical_template_id="not_available",
        overlap_keys=tuple(sorted(overlap_keys)),
    )


def load_malicious_agent_skills_snapshot(root: Path, *, revision: str | None = None) -> MaliciousAgentSkillsSnapshot:
    """Load the exact pinned CSV projection without resolving linked packages."""

    root = Path(root)
    try:
        manifest = require_exact_fields(read_regular_json(root / SNAPSHOT_MANIFEST), _ROOT_FIELDS, "snapshot manifest")
    except QuarantinedTextError as exc:
        raise MaliciousAgentSkillsError(str(exc)) from exc
    if manifest["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise MaliciousAgentSkillsError(f"unsupported snapshot schema version: {manifest['schema_version']!r}")
    if manifest["dataset_id"] != DATASET_ID:
        raise MaliciousAgentSkillsError(f"snapshot dataset_id must be {DATASET_ID!r}")
    try:
        dataset = get_locked_dataset(DATASET_ID, load_dataset_lock())
    except (DatasetLockError, DatasetSchemaError) as exc:
        raise MaliciousAgentSkillsError(f"cannot load locked MaliciousAgentSkillsBench identity: {exc}") from exc
    locked_revision = str(dataset["revision"])
    manifest_revision = _bounded_metadata(manifest["revision"], "snapshot revision", max_bytes=40)
    if manifest_revision != locked_revision or (revision is not None and revision != manifest_revision):
        raise MaliciousAgentSkillsError(
            f"revision drift (expected {locked_revision}, received {revision or manifest_revision})"
        )
    locked_counts = dataset.get("expected", {}).get("row_counts", {})
    if locked_counts.get("skills_dataset/train") != EXPECTED_SKILLS_ROWS:
        raise MaliciousAgentSkillsError("locked skills_dataset row count disagrees with the reviewed adapter contract")
    if locked_counts.get("malicious_skills/train") != EXPECTED_MALICIOUS_ROWS:
        raise MaliciousAgentSkillsError(
            "locked malicious_skills row count disagrees with the reviewed adapter contract"
        )
    expected_schemas = {
        "skills_dataset": {"exact_fields": list(_SKILLS_FIELDS)},
        "malicious_skills": {"exact_fields": list(_MALICIOUS_FIELDS)},
    }
    if dataset.get("expected", {}).get("schemas") != expected_schemas:
        raise MaliciousAgentSkillsError("locked CSV schemas disagree with the reviewed adapter contract")

    try:
        inventory = inventory_text_tree(
            root,
            policy=_CSV_POLICY,
            excluded_paths=(PurePosixPath(SNAPSHOT_MANIFEST),),
        )
        declared = validate_declared_artifacts(manifest["artifacts"], actual=inventory)
        if {entry["path"] for entry in declared} != {SKILLS_DATASET_FILE, MALICIOUS_SKILLS_FILE}:
            raise QuarantinedTextError("snapshot must contain exactly the two reviewed CSV data files")
        declared_digest = require_sha256(manifest["artifact_manifest_sha256"], "artifact_manifest_sha256")
        actual_digest = artifact_manifest_sha256(DATASET_ID, declared)
        validate_artifact_manifest(DATASET_ID, declared, manifest_sha256=declared_digest)
    except (QuarantinedTextError, DatasetLockError, DatasetSchemaError) as exc:
        raise MaliciousAgentSkillsError(f"invalid CSV artifact inventory: {exc}") from exc
    if actual_digest != declared_digest:
        raise MaliciousAgentSkillsError("artifact manifest digest mismatch")

    skills_rows = _read_csv_rows(root / SKILLS_DATASET_FILE, _SKILLS_FIELDS, max_rows=EXPECTED_SKILLS_ROWS)
    malicious_rows = _read_csv_rows(root / MALICIOUS_SKILLS_FILE, _MALICIOUS_FIELDS, max_rows=EXPECTED_MALICIOUS_ROWS)
    if len(skills_rows) != EXPECTED_SKILLS_ROWS:
        raise MaliciousAgentSkillsError(
            f"skills_dataset row-count drift (expected {EXPECTED_SKILLS_ROWS}, received {len(skills_rows)})"
        )
    if len(malicious_rows) != EXPECTED_MALICIOUS_ROWS:
        raise MaliciousAgentSkillsError(
            f"malicious_skills row-count drift (expected {EXPECTED_MALICIOUS_ROWS}, received {len(malicious_rows)})"
        )

    label_counts: Counter[str] = Counter()
    identities: dict[tuple[str, str, str], tuple[str, str | None]] = {}
    main_malicious: dict[tuple[str, str, str], str | None] = {}
    duplicate_rows = 0
    for index, row in enumerate(skills_rows):
        source = _bounded_metadata(row[0], f"skills_dataset[{index}].source")
        repository = _bounded_metadata(row[1], f"skills_dataset[{index}].repo")
        skill_name = _identity_name(row[2], f"skills_dataset[{index}].skill_name")
        classification = row[3]
        if classification not in _LABELS:
            raise MaliciousAgentSkillsError(f"skills_dataset[{index}].classification is unknown")
        url = _canonical_url(row[4], f"skills_dataset[{index}].url")
        identity = _identity(source, repository, skill_name)
        existing = identities.get(identity)
        if existing is not None:
            duplicate_rows += 1
            if existing != (classification, url):
                raise MaliciousAgentSkillsError(f"skills_dataset[{index}] conflicts with a duplicate identity")
        else:
            identities[identity] = (classification, url)
        label_counts[classification] += 1
        if classification == "malicious":
            if identity in main_malicious:
                raise MaliciousAgentSkillsError("main malicious population contains a duplicate skill identity")
            main_malicious[identity] = url
    if dict(label_counts) != EXPECTED_LABEL_COUNTS:
        raise MaliciousAgentSkillsError(
            f"classification-count drift (expected {EXPECTED_LABEL_COUNTS}, received {dict(label_counts)})"
        )

    cases: list[MaliciousAgentCase] = []
    case_identities: set[tuple[str, str, str]] = set()
    for index, row in enumerate(malicious_rows):
        identity, case = _case_from_row(row, index=index, main_malicious=main_malicious)
        if identity in case_identities:
            raise MaliciousAgentSkillsError("malicious case metadata contains a duplicate skill identity")
        case_identities.add(identity)
        cases.append(case)
    if case_identities != set(main_malicious):
        raise MaliciousAgentSkillsError("malicious case metadata does not exactly cover the main malicious population")
    pattern_instances = sum(len(case.patterns) for case in cases)
    if pattern_instances != EXPECTED_PATTERN_INSTANCES:
        raise MaliciousAgentSkillsError(
            f"pattern-instance drift (expected {EXPECTED_PATTERN_INSTANCES}, received {pattern_instances})"
        )
    severity_counts = Counter(severity for case in cases for severity in case.severities)
    if dict(severity_counts) != EXPECTED_SEVERITY_COUNTS:
        raise MaliciousAgentSkillsError(
            f"severity-instance drift (expected {EXPECTED_SEVERITY_COUNTS}, received {dict(severity_counts)})"
        )
    cases.sort(key=lambda case: case.case_id)
    return MaliciousAgentSkillsSnapshot(
        root=root,
        revision=manifest_revision,
        artifact_manifest_sha256=declared_digest,
        artifact_manifest_pinned=not bool(dataset["integrity"]["hashes_pending"]),
        skills_population=len(skills_rows),
        label_counts=dict(sorted(label_counts.items())),
        duplicate_metadata_rows=duplicate_rows,
        malicious_cases=tuple(cases),
    )
