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

"""Bounded validation primitives for quarantined text-only snapshots.

The functions in this module are intentionally boring.  They do not fetch,
extract, import, compile, or execute anything.  They walk an already-created
directory without following links, accept only an explicit filename allowlist,
and retain only hashes and sizes after validating UTF-8 text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
_BINARY_MAGICS: tuple[bytes, ...] = (
    b"\x7fELF",
    b"MZ",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"\xca\xfe\xba\xbe",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"SQLite format 3\x00",
)


class QuarantinedTextError(ValueError):
    """Raised when an offline snapshot member is unsafe or ambiguous."""


@dataclass(frozen=True)
class TextTreePolicy:
    """Finite allowlist and allocation bounds for one text tree."""

    allowed_suffixes: frozenset[str]
    allowed_basenames: frozenset[str]
    max_files: int = 100_000
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_path_bytes: int = 1_024


@dataclass(frozen=True)
class TextArtifact:
    """Content-free identity for one validated text artifact."""

    path: PurePosixPath
    sha256: str
    normalized_sha256: str
    size_bytes: int

    def manifest_entry(self) -> dict[str, Any]:
        return {"path": self.path.as_posix(), "sha256": self.sha256, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class TextPackageIdentity:
    """Path-independent exact and normalized identity for a text package."""

    content_sha256: str
    normalized_content_sha256: str
    artifacts: tuple[TextArtifact, ...]


PACKAGE_TEXT_POLICY = TextTreePolicy(
    allowed_suffixes=frozenset(
        {
            ".bash",
            ".bat",
            ".c",
            ".cc",
            ".cfg",
            ".cjs",
            ".conf",
            ".cpp",
            ".cs",
            ".css",
            ".csv",
            ".env",
            ".fish",
            ".fs",
            ".fsx",
            ".go",
            ".h",
            ".hpp",
            ".htm",
            ".html",
            ".ini",
            ".java",
            ".js",
            ".json",
            ".jsonl",
            ".jsx",
            ".kt",
            ".kts",
            ".lua",
            ".md",
            ".mjs",
            ".php",
            ".pl",
            ".pm",
            ".properties",
            ".ps1",
            ".py",
            ".pyi",
            ".pyx",
            ".r",
            ".rb",
            ".rst",
            ".rs",
            ".scala",
            ".scss",
            ".sh",
            ".sql",
            ".swift",
            ".toml",
            ".ts",
            ".tsv",
            ".tsx",
            ".txt",
            ".vb",
            ".xml",
            ".yaml",
            ".yml",
            ".zsh",
        }
    ),
    allowed_basenames=frozenset(
        {
            ".dockerignore",
            ".env",
            ".gitattributes",
            ".gitignore",
            ".npmignore",
            "authors",
            "changelog",
            "copying",
            "dockerfile",
            "gemfile",
            "license",
            "makefile",
            "notice",
            "procfile",
            "rakefile",
            "readme",
        }
    ),
)


def require_sha256(value: Any, location: str) -> str:
    """Return a lowercase SHA-256 or fail with a stable location."""

    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise QuarantinedTextError(f"{location} must be a lowercase SHA-256")
    return value


def require_portable_relative_path(value: Any, location: str, *, max_bytes: int = 1_024) -> PurePosixPath:
    """Validate one normalized, cross-platform relative path."""

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value or _DRIVE_PATH_RE.match(value):
        raise QuarantinedTextError(f"{location} must be a normalized portable relative path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise QuarantinedTextError(f"{location} must be valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise QuarantinedTextError(f"{location} exceeds the {max_bytes}-byte path limit")
    parts = value.split("/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in parts):
        raise QuarantinedTextError(f"{location} must be a normalized portable relative path")
    if any(len(part.encode("utf-8")) > 255 for part in parts):
        raise QuarantinedTextError(f"{location} contains a component longer than 255 UTF-8 bytes")
    if any(part.endswith((" ", ".")) or ":" in part for part in parts):
        raise QuarantinedTextError(f"{location} is not portable across supported platforms")
    if any(part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES for part in parts):
        raise QuarantinedTextError(f"{location} contains a reserved platform name")
    if any(any(ord(character) < 32 or ord(character) == 127 for character in part) for part in parts):
        raise QuarantinedTextError(f"{location} contains control characters")
    return path


def _collision_key(path: PurePosixPath) -> str:
    return unicodedata.normalize("NFKC", path.as_posix()).casefold()


def read_regular_json(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> Mapping[str, Any]:
    """Read a bounded JSON object without following a symbolic link."""

    raw = _read_regular_bytes(path, max_bytes=max_bytes, require_text=True, reject_executable=True)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_number,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise QuarantinedTextError(f"invalid JSON in {path.name}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise QuarantinedTextError(f"{path.name} must contain a JSON object")
    return value


def read_regular_text(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> str:
    """Read bounded UTF-8 text without following links or accepting executable mode."""

    return _read_regular_bytes(
        path,
        max_bytes=max_bytes,
        require_text=True,
        reject_executable=True,
    ).decode("utf-8")


def _reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QuarantinedTextError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json_number(value: str) -> None:
    raise QuarantinedTextError(f"JSON contains non-finite number {value}")


def _read_regular_bytes(
    path: Path,
    *,
    max_bytes: int,
    require_text: bool,
    reject_executable: bool,
) -> bytes:
    if path.is_symlink():
        raise QuarantinedTextError(f"symbolic links are forbidden: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise QuarantinedTextError(f"cannot safely open snapshot member {path.name}: {exc}") from exc
    try:
        member_stat = os.fstat(descriptor)
        if not stat.S_ISREG(member_stat.st_mode):
            raise QuarantinedTextError(f"snapshot member is not a regular file: {path.name}")
        if reject_executable and member_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise QuarantinedTextError(f"executable-mode snapshot files are forbidden: {path.name}")
        if member_stat.st_size > max_bytes:
            raise QuarantinedTextError(f"snapshot member exceeds the {max_bytes}-byte limit: {path.name}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > max_bytes:
        raise QuarantinedTextError(f"snapshot member exceeds the {max_bytes}-byte limit: {path.name}")
    if require_text:
        _validated_text(raw, path.name)
    return raw


def _validated_text(raw: bytes, location: str) -> str:
    if any(raw.startswith(magic) for magic in _BINARY_MAGICS):
        raise QuarantinedTextError(f"binary or archive content is forbidden: {location}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QuarantinedTextError(f"snapshot text is not valid UTF-8: {location}") from exc
    if "\x00" in text:
        raise QuarantinedTextError(f"binary NUL content is forbidden: {location}")
    if any(unicodedata.category(character) == "Cc" and character not in "\t\r\n" for character in text):
        raise QuarantinedTextError(f"non-text control content is forbidden: {location}")
    return text


def _allowed_text_path(path: PurePosixPath, policy: TextTreePolicy) -> bool:
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    if suffix in policy.allowed_suffixes:
        return True
    if name in policy.allowed_basenames:
        return True
    # Common license/readme names may carry suffix-like qualifiers such as
    # LICENSE-APACHE or README.development.
    return any(name.startswith(f"{prefix}-") for prefix in policy.allowed_basenames)


def _normalized_text_bytes(raw: bytes) -> bytes:
    text = unicodedata.normalize("NFKC", raw.decode("utf-8")).replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n")
    if normalized:
        normalized += "\n"
    return normalized.encode("utf-8")


def inventory_text_tree(
    root: Path,
    *,
    policy: TextTreePolicy = PACKAGE_TEXT_POLICY,
    excluded_paths: Iterable[PurePosixPath] = (),
) -> tuple[TextArtifact, ...]:
    """Return the complete validated text inventory beneath ``root``.

    Every encountered entry is checked, including ignored manifest paths.
    Exclusions may name regular, non-executable files only.
    """

    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise QuarantinedTextError("snapshot root must be an existing non-symlink directory")
    exclusions = {_collision_key(path): path for path in excluded_paths}
    artifacts: list[TextArtifact] = []
    seen_paths: set[str] = set()
    total_bytes = 0

    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names.sort()
        file_names.sort()
        for name in [*directory_names, *file_names]:
            member = current / name
            relative = require_portable_relative_path(
                member.relative_to(root).as_posix(),
                "snapshot member path",
                max_bytes=policy.max_path_bytes,
            )
            member_stat = member.lstat()
            if stat.S_ISLNK(member_stat.st_mode):
                raise QuarantinedTextError(f"symbolic links are forbidden: {relative.as_posix()}")
            if name in directory_names and not stat.S_ISDIR(member_stat.st_mode):
                raise QuarantinedTextError(f"snapshot tree entry is not a directory: {relative.as_posix()}")
            if name in file_names and not stat.S_ISREG(member_stat.st_mode):
                raise QuarantinedTextError(f"snapshot tree entry is not a regular file: {relative.as_posix()}")

        for name in file_names:
            member = current / name
            relative = require_portable_relative_path(
                member.relative_to(root).as_posix(),
                "snapshot file path",
                max_bytes=policy.max_path_bytes,
            )
            collision_key = _collision_key(relative)
            if collision_key in seen_paths:
                raise QuarantinedTextError(f"case or Unicode-normalization path collision: {relative.as_posix()}")
            seen_paths.add(collision_key)
            raw = _read_regular_bytes(
                member,
                max_bytes=policy.max_file_bytes,
                require_text=True,
                reject_executable=True,
            )
            if collision_key in exclusions:
                continue
            if not _allowed_text_path(relative, policy):
                raise QuarantinedTextError(f"file type is outside the text allowlist: {relative.as_posix()}")
            total_bytes += len(raw)
            if total_bytes > policy.max_total_bytes:
                raise QuarantinedTextError(f"snapshot exceeds the {policy.max_total_bytes}-byte aggregate limit")
            if len(artifacts) >= policy.max_files:
                raise QuarantinedTextError(f"snapshot exceeds the {policy.max_files}-file limit")
            artifacts.append(
                TextArtifact(
                    path=relative,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    normalized_sha256=hashlib.sha256(_normalized_text_bytes(raw)).hexdigest(),
                    size_bytes=len(raw),
                )
            )

    artifacts.sort(key=lambda artifact: (_collision_key(artifact.path), artifact.path.as_posix()))
    return tuple(artifacts)


def package_identity(
    artifacts: Sequence[TextArtifact],
    *,
    prefix: PurePosixPath | None = None,
) -> TextPackageIdentity:
    """Compute exact and conservative normalized identities for a subtree."""

    rebased: list[TextArtifact] = []
    for artifact in artifacts:
        path = artifact.path
        if prefix is not None:
            try:
                path = path.relative_to(prefix)
            except ValueError as exc:
                raise QuarantinedTextError(
                    f"artifact {artifact.path.as_posix()} is outside package prefix {prefix.as_posix()}"
                ) from exc
        rebased.append(
            TextArtifact(
                path=path,
                sha256=artifact.sha256,
                normalized_sha256=artifact.normalized_sha256,
                size_bytes=artifact.size_bytes,
            )
        )
    if not rebased:
        raise QuarantinedTextError("a materialized text package must contain at least one file")
    rebased.sort(key=lambda artifact: (_collision_key(artifact.path), artifact.path.as_posix()))
    exact_payload = [artifact.manifest_entry() for artifact in rebased]
    normalized_payload = [
        {"path": artifact.path.as_posix(), "sha256": artifact.normalized_sha256} for artifact in rebased
    ]
    exact = hashlib.sha256(
        json.dumps(exact_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    normalized = hashlib.sha256(
        json.dumps(normalized_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return TextPackageIdentity(
        content_sha256=exact,
        normalized_content_sha256=normalized,
        artifacts=tuple(rebased),
    )


def inspect_text_package(
    package_root: Path,
    *,
    policy: TextTreePolicy = PACKAGE_TEXT_POLICY,
) -> TextPackageIdentity:
    """Revalidate one standalone package immediately before a static scan."""

    return package_identity(inventory_text_tree(package_root, policy=policy))


def require_exact_fields(value: Any, fields: frozenset[str], location: str) -> Mapping[str, Any]:
    """Require an object with exactly ``fields``."""

    if not isinstance(value, Mapping):
        raise QuarantinedTextError(f"{location} must be an object")
    actual = set(value)
    if actual != fields:
        raise QuarantinedTextError(
            f"{location} schema drift (missing={sorted(fields - actual)}, unexpected={sorted(actual - fields)})"
        )
    return value


def require_sequence(value: Any, location: str, *, allow_empty: bool = False) -> Sequence[Any]:
    """Require a bounded-array-shaped value (bounds remain caller-specific)."""

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or (not value and not allow_empty):
        qualifier = "possibly-empty" if allow_empty else "non-empty"
        raise QuarantinedTextError(f"{location} must be a {qualifier} array")
    return cast(Sequence[Any], value)


def require_string(value: Any, location: str, *, max_bytes: int = 4_096) -> str:
    """Require normalized bounded metadata, never sample content."""

    if not isinstance(value, str) or not value or "\x00" in value or value != value.strip():
        raise QuarantinedTextError(f"{location} must be a non-empty normalized string")
    if "\n" in value or "\r" in value or len(value.encode("utf-8")) > max_bytes:
        raise QuarantinedTextError(f"{location} must be bounded single-line text")
    return value


def validate_declared_artifacts(
    raw_artifacts: Any,
    *,
    actual: Sequence[TextArtifact],
) -> tuple[dict[str, Any], ...]:
    """Compare a manifest inventory to the complete on-disk inventory."""

    values = require_sequence(raw_artifacts, "artifacts")
    declared: list[dict[str, Any]] = []
    seen: set[str] = set()
    fields = frozenset({"path", "sha256", "size_bytes"})
    for index, value in enumerate(values):
        artifact = require_exact_fields(value, fields, f"artifacts[{index}]")
        path = require_portable_relative_path(artifact["path"], f"artifacts[{index}].path")
        key = _collision_key(path)
        if key in seen:
            raise QuarantinedTextError(f"duplicate or normalization-colliding artifact path: {path.as_posix()}")
        seen.add(key)
        digest = require_sha256(artifact["sha256"], f"artifacts[{index}].sha256")
        size = artifact["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise QuarantinedTextError(f"artifacts[{index}].size_bytes must be a non-negative integer")
        declared.append({"path": path.as_posix(), "sha256": digest, "size_bytes": size})
    declared.sort(key=lambda artifact: _collision_key(PurePosixPath(artifact["path"])))
    observed = [artifact.manifest_entry() for artifact in actual]
    if declared != observed:
        raise QuarantinedTextError("declared artifact inventory does not match the complete text snapshot")
    return tuple(declared)
