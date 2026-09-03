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

"""Provenance-locked discovery of first-party bundled agent skills.

This module inventories already-installed, inert skill packages.  It never
downloads, imports, executes, copies, or redistributes vendor content.  A
source is eligible only through one of four closed selectors:

* a reserved first-party bundle root (for example Codex ``.system``);
* Codex plugin manifests whose declared author exactly matches the vendor; or
* an Anthropic marketplace record whose declared author exactly matches; or
* every local record in a revision-locked Anthropic-owned repository.

The lock stores hashes and counts, not raw vendor content.  Any package or file
change therefore requires an explicit lock refresh before it can influence the
goodware benchmark.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

PROFILE_VERSION = 1
LOCK_VERSION = 1
LOCK_FILE = Path(__file__).with_name("official-bundled-skills.lock.json")
PROFILE_FILE = Path(__file__).with_name("official-bundled-skills.profile.json")

_MAX_PROFILE_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_PACKAGE_FILES = 8_192
_MAX_PACKAGE_BYTES = 256 * 1024 * 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_PACKAGES = 2_048
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
_SELECTOR_KINDS = frozenset(
    {
        "recursive_first_party",
        "codex_plugin_author",
        "anthropic_marketplace_author",
        "anthropic_owned_marketplace_all_local",
    }
)


class OfficialBundleError(ValueError):
    """Raised when installed goodware provenance cannot be proven."""


@dataclass(frozen=True)
class OfficialPackage:
    source_id: str
    vendor: str
    tool: str
    relative_path: str
    absolute_path: Path
    tree_sha256: str
    skill_sha256: str
    file_count: int
    total_bytes: int
    version: str
    license: str
    provenance_manifest: str | None

    @property
    def package_id(self) -> str:
        return f"{self.source_id}:{self.relative_path}"

    def lock_record(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "relative_path": self.relative_path,
            "tree_sha256": self.tree_sha256,
            "skill_sha256": self.skill_sha256,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "version": self.version,
            "license": self.license,
            "provenance_manifest": self.provenance_manifest,
        }


@dataclass(frozen=True)
class OfficialSource:
    source_id: str
    vendor: str
    tool: str
    source_group: str
    root: Path
    root_locator: str
    selector: Mapping[str, Any]
    provenance: Mapping[str, Any]
    packages: tuple[OfficialPackage, ...]
    inventory_sha256: str
    file_count: int
    total_bytes: int

    def lock_record(self) -> dict[str, Any]:
        return {
            "id": self.source_id,
            "vendor": self.vendor,
            "tool": self.tool,
            "source_group": self.source_group,
            "root_locator": self.root_locator,
            "selector": dict(self.selector),
            "provenance": dict(self.provenance),
            "expected": {
                "package_count": len(self.packages),
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
                "inventory_sha256": self.inventory_sha256,
            },
        }


def _reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OfficialBundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, *, max_bytes: int = _MAX_PROFILE_BYTES) -> Any:
    if path.is_symlink() or not path.is_file():
        raise OfficialBundleError(f"expected a regular non-symlink JSON file: {path}")
    file_stat = path.stat(follow_symlinks=False)
    if file_stat.st_size > max_bytes:
        raise OfficialBundleError(f"JSON file exceeds {max_bytes} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OfficialBundleError(f"invalid JSON at {path}: {exc}") from exc


def _exact_mapping(value: Any, fields: frozenset[str], location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OfficialBundleError(f"{location} must be an object")
    if set(value) != fields:
        raise OfficialBundleError(
            f"{location} fields differ (missing={sorted(fields - set(value))}, "
            f"unexpected={sorted(set(value) - fields)})"
        )
    return value


def _string(value: Any, location: str, *, max_bytes: int = 4_096) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise OfficialBundleError(f"{location} must be a non-empty NUL-free string")
    if len(value.encode("utf-8")) > max_bytes:
        raise OfficialBundleError(f"{location} exceeds {max_bytes} bytes")
    return value


def _portable_relative(value: Any, location: str) -> PurePosixPath:
    raw = _string(value, location, max_bytes=1_024)
    if raw.startswith("/") or "\\" in raw:
        raise OfficialBundleError(f"{location} must be a portable relative path")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise OfficialBundleError(f"{location} must be a normalized relative path")
    return path


def _resolve_root(locator: str, observed_root: str) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(locator)))
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exc:
        raise OfficialBundleError(f"source root is unavailable: {expanded}") from exc
    if expanded.is_symlink() or not resolved.is_dir():
        raise OfficialBundleError(f"source root must be a non-symlink directory: {expanded}")
    if str(resolved) != observed_root:
        raise OfficialBundleError(
            f"source root changed: locator {locator!r} resolves to {resolved}, expected {observed_root}"
        )
    return resolved


def load_profile(path: Path = PROFILE_FILE) -> list[dict[str, Any]]:
    raw = _exact_mapping(
        _load_json(path),
        frozenset({"profile_version", "observed_at", "purpose", "safety", "sources"}),
        "profile",
    )
    if raw["profile_version"] != PROFILE_VERSION:
        raise OfficialBundleError(f"unsupported profile_version: {raw['profile_version']!r}")
    _string(raw["observed_at"], "profile.observed_at")
    _string(raw["purpose"], "profile.purpose")
    safety = _exact_mapping(
        raw["safety"],
        frozenset({"content_executed", "content_copied", "network_acquisition", "vendor_allowlists"}),
        "profile.safety",
    )
    if safety != {
        "content_executed": False,
        "content_copied": False,
        "network_acquisition": False,
        "vendor_allowlists": False,
    }:
        raise OfficialBundleError("profile safety contract must remain fully inert and vendor-neutral")
    sources = raw["sources"]
    if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence) or not sources:
        raise OfficialBundleError("profile.sources must be a non-empty array")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    fields = frozenset(
        {
            "id",
            "vendor",
            "tool",
            "source_group",
            "root_locator",
            "observed_root",
            "selector",
            "provenance",
        }
    )
    for index, value in enumerate(sources):
        source = dict(_exact_mapping(value, fields, f"profile.sources[{index}]"))
        source_id = _string(source["id"], f"profile.sources[{index}].id", max_bytes=128)
        if not _SOURCE_ID_RE.fullmatch(source_id) or source_id in seen:
            raise OfficialBundleError(f"invalid or duplicate source id: {source_id!r}")
        seen.add(source_id)
        for field in ("vendor", "tool", "source_group", "root_locator", "observed_root"):
            _string(source[field], f"profile.sources[{index}].{field}")
        selector = source["selector"]
        if not isinstance(selector, Mapping) or selector.get("kind") not in _SELECTOR_KINDS:
            raise OfficialBundleError(f"profile.sources[{index}].selector has an unsupported kind")
        if not isinstance(source["provenance"], Mapping):
            raise OfficialBundleError(f"profile.sources[{index}].provenance must be an object")
        source["root"] = _resolve_root(source["root_locator"], source["observed_root"])
        result.append(source)
    return result


def _safe_json_manifest(path: Path) -> Mapping[str, Any]:
    value = _load_json(path, max_bytes=_MAX_MANIFEST_BYTES)
    if not isinstance(value, Mapping):
        raise OfficialBundleError(f"manifest must be an object: {path}")
    return value


def _walk_skill_manifests(root: Path) -> list[Path]:
    manifests: list[Path] = []
    for current_raw, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_raw)
        retained: list[str] = []
        for name in sorted(directory_names):
            child = current / name
            child_stat = child.lstat()
            if stat.S_ISLNK(child_stat.st_mode):
                continue
            if not stat.S_ISDIR(child_stat.st_mode):
                raise OfficialBundleError(f"non-directory tree entry while discovering skills: {child}")
            retained.append(name)
        directory_names[:] = retained
        if "SKILL.md" in file_names:
            candidate = current / "SKILL.md"
            if candidate.is_symlink() or not candidate.is_file():
                raise OfficialBundleError(f"SKILL.md must be a regular non-symlink file: {candidate}")
            manifests.append(candidate)
    return sorted(manifests)


def _within(root: Path, relative: Any, location: str) -> Path:
    rel = _portable_relative(relative, location)
    candidate = root.joinpath(*rel.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise OfficialBundleError(f"{location} does not exist: {candidate}") from exc
    if candidate.is_symlink() or not resolved.is_relative_to(root):
        raise OfficialBundleError(f"{location} escapes or aliases its source root")
    return resolved


def _plugin_skill_roots(root: Path, author: str) -> list[tuple[Path, Mapping[str, Any], str]]:
    selected: list[tuple[Path, Mapping[str, Any], str]] = []
    # Installed caches are ``plugin/version/.codex-plugin`` while the signed
    # desktop application is ``plugins/plugin/.codex-plugin``.  Recursive
    # discovery supports both layouts; the author check remains mandatory.
    for manifest_path in sorted(root.rglob(".codex-plugin/plugin.json")):
        # Cache convenience aliases such as ``chrome/latest`` are symlinks.
        # The concrete immutable version directory is inventoried instead.
        plugin_root = manifest_path.parent.parent
        if plugin_root.is_symlink():
            continue
        manifest = _safe_json_manifest(manifest_path)
        declared_author = manifest.get("author")
        if not isinstance(declared_author, Mapping) or declared_author.get("name") != author:
            continue
        skills = manifest.get("skills")
        if not isinstance(skills, str) or not skills:
            continue
        skill_root = _within(plugin_root, skills, f"{manifest_path}.skills")
        if not skill_root.is_dir():
            raise OfficialBundleError(f"declared skills root is not a directory: {skill_root}")
        selected.append((skill_root, manifest, manifest_path.relative_to(root).as_posix()))
    if not selected:
        raise OfficialBundleError(f"no {author!r}-authored Codex plugin skills found under {root}")
    return selected


def _anthropic_skill_roots(
    root: Path,
    author: str,
    marketplace_relative_path: str,
) -> list[tuple[Path, Mapping[str, Any], str]]:
    marketplace_path = _within(root, marketplace_relative_path, "selector.marketplace_relative_path")
    marketplace = _safe_json_manifest(marketplace_path)
    owner = marketplace.get("owner")
    if not isinstance(owner, Mapping) or owner.get("name") != author:
        raise OfficialBundleError("Anthropic marketplace owner does not match the required first-party author")
    records = marketplace.get("plugins")
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise OfficialBundleError("Anthropic marketplace plugins must be an array")
    selected: list[tuple[Path, Mapping[str, Any], str]] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise OfficialBundleError(f"marketplace.plugins[{index}] must be an object")
        declared_author = record.get("author")
        if not isinstance(declared_author, Mapping) or declared_author.get("name") != author:
            continue
        source = record.get("source")
        if not isinstance(source, str) or not source.startswith("./"):
            continue
        plugin_root = _within(root, source[2:], f"marketplace.plugins[{index}].source")
        if not plugin_root.is_dir():
            raise OfficialBundleError(f"first-party marketplace source is not a directory: {plugin_root}")
        selected.append((plugin_root, record, marketplace_path.relative_to(root).as_posix()))
    if not selected:
        raise OfficialBundleError(f"no local {author!r}-authored marketplace plugins found under {root}")
    return selected


def _anthropic_owned_skill_roots(
    root: Path,
    owner_name: str,
    marketplace_relative_path: str,
) -> list[tuple[Path, Mapping[str, Any], str]]:
    """Select local plugins from a repository wholly owned by Anthropic.

    This selector is intentionally distinct from the mixed official
    marketplace selector above. It may be used only for a provenance-locked
    repository whose marketplace owner is Anthropic; remote plugin records
    remain excluded.
    """

    marketplace_path = _within(root, marketplace_relative_path, "selector.marketplace_relative_path")
    marketplace = _safe_json_manifest(marketplace_path)
    owner = marketplace.get("owner")
    if not isinstance(owner, Mapping) or owner.get("name") != owner_name:
        raise OfficialBundleError("owned marketplace does not match the required first-party owner")
    records = marketplace.get("plugins")
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise OfficialBundleError("owned marketplace plugins must be an array")
    selected: list[tuple[Path, Mapping[str, Any], str]] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise OfficialBundleError(f"marketplace.plugins[{index}] must be an object")
        source = record.get("source")
        if not isinstance(source, str) or not source.startswith("./"):
            continue
        plugin_root = _within(root, source[2:], f"marketplace.plugins[{index}].source")
        if not plugin_root.is_dir():
            raise OfficialBundleError(f"first-party marketplace source is not a directory: {plugin_root}")
        selected.append((plugin_root, record, marketplace_path.relative_to(root).as_posix()))
    if not selected:
        raise OfficialBundleError(f"no local plugins found in {owner_name!r}-owned marketplace under {root}")
    return selected


def _license_from_files(package_root: Path) -> str:
    candidates = sorted(
        path for path in package_root.iterdir() if path.is_file() and path.name.lower().startswith("license")
    )
    for path in candidates:
        if path.stat(follow_symlinks=False).st_size > 1024 * 1024:
            continue
        try:
            prefix = path.read_text(encoding="utf-8")[:8_192].lower()
        except (OSError, UnicodeError):
            continue
        if "apache license" in prefix and "version 2.0" in prefix:
            return "Apache-2.0"
        if "mit license" in prefix or "permission is hereby granted, free of charge" in prefix:
            return "MIT"
    return "not-declared-in-package"


def _hash_package(package_root: Path) -> tuple[str, str, int, int]:
    digest = hashlib.sha256(b"skill-scanner-official-bundled-package-v1\0")
    file_count = 0
    total_bytes = 0
    skill_sha256 = ""
    for current_raw, directory_names, file_names in os.walk(package_root, followlinks=False):
        current = Path(current_raw)
        directory_names.sort()
        file_names.sort()
        for name in [*directory_names, *file_names]:
            path = current / name
            entry_stat = path.lstat()
            if stat.S_ISLNK(entry_stat.st_mode):
                raise OfficialBundleError(f"official skill package contains a symlink: {path}")
            expected_type = stat.S_ISDIR if name in directory_names else stat.S_ISREG
            if not expected_type(entry_stat.st_mode):
                raise OfficialBundleError(f"official skill package contains a special entry: {path}")
        for name in file_names:
            path = current / name
            entry_stat = path.lstat()
            if entry_stat.st_size > _MAX_FILE_BYTES:
                raise OfficialBundleError(f"official skill file exceeds {_MAX_FILE_BYTES} bytes: {path}")
            file_count += 1
            total_bytes += entry_stat.st_size
            if file_count > _MAX_PACKAGE_FILES or total_bytes > _MAX_PACKAGE_BYTES:
                raise OfficialBundleError(f"official skill package exceeds bounded inventory limits: {package_root}")
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino, opened.st_size) != (
                    entry_stat.st_dev,
                    entry_stat.st_ino,
                    entry_stat.st_size,
                ):
                    raise OfficialBundleError(f"official skill file changed while opening: {path}")
                file_digest = hashlib.sha256()
                read_bytes = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    file_digest.update(chunk)
                if read_bytes != entry_stat.st_size:
                    raise OfficialBundleError(f"official skill file changed while hashing: {path}")
            finally:
                os.close(descriptor)
            relative = path.relative_to(package_root).as_posix()
            relative_bytes = relative.encode("utf-8")
            digest.update(len(relative_bytes).to_bytes(4, "big"))
            digest.update(relative_bytes)
            digest.update(entry_stat.st_size.to_bytes(8, "big"))
            digest.update(file_digest.digest())
            if relative == "SKILL.md":
                skill_sha256 = file_digest.hexdigest()
    if not skill_sha256:
        raise OfficialBundleError(f"official skill package is missing SKILL.md: {package_root}")
    return digest.hexdigest(), skill_sha256, file_count, total_bytes


def _manifest_version_license(metadata: Mapping[str, Any], fallback_license: str) -> tuple[str, str]:
    raw_version = metadata.get("version")
    version = raw_version if isinstance(raw_version, str) and raw_version else "not-declared"
    raw_license = metadata.get("license")
    license_name = raw_license if isinstance(raw_license, str) and raw_license else fallback_license
    return version, license_name


def inventory_profile(path: Path = PROFILE_FILE) -> tuple[OfficialSource, ...]:
    sources: list[OfficialSource] = []
    for source in load_profile(path):
        root = source["root"]
        selector = source["selector"]
        selector_kind = selector["kind"]
        roots: list[tuple[Path, Mapping[str, Any], str | None]]
        if selector_kind == "recursive_first_party":
            if set(selector) != {"kind"}:
                raise OfficialBundleError(f"{source['id']} recursive selector has unknown fields")
            roots = [(root, {}, None)]
        elif selector_kind == "codex_plugin_author":
            if set(selector) != {"kind", "author"}:
                raise OfficialBundleError(f"{source['id']} Codex selector has unknown fields")
            author = _string(selector["author"], f"{source['id']}.selector.author")
            roots = list(_plugin_skill_roots(root, author))
        elif selector_kind == "anthropic_marketplace_author":
            if set(selector) != {"kind", "author", "marketplace_relative_path"}:
                raise OfficialBundleError(f"{source['id']} Anthropic selector has unknown fields")
            author = _string(selector["author"], f"{source['id']}.selector.author")
            marketplace_relative = _string(
                selector["marketplace_relative_path"],
                f"{source['id']}.selector.marketplace_relative_path",
            )
            roots = list(_anthropic_skill_roots(root, author, marketplace_relative))
        else:
            if set(selector) != {"kind", "owner", "marketplace_relative_path"}:
                raise OfficialBundleError(f"{source['id']} owned Anthropic selector has unknown fields")
            owner = _string(selector["owner"], f"{source['id']}.selector.owner")
            marketplace_relative = _string(
                selector["marketplace_relative_path"],
                f"{source['id']}.selector.marketplace_relative_path",
            )
            roots = list(_anthropic_owned_skill_roots(root, owner, marketplace_relative))

        package_metadata: dict[Path, tuple[Mapping[str, Any], str | None]] = {}
        for skill_root, metadata, provenance_manifest in roots:
            for manifest in _walk_skill_manifests(skill_root):
                package_root = manifest.parent
                previous = package_metadata.get(package_root)
                if previous is not None and previous != (metadata, provenance_manifest):
                    raise OfficialBundleError(f"official package selected by conflicting provenance: {package_root}")
                package_metadata[package_root] = (metadata, provenance_manifest)
        if not package_metadata or len(package_metadata) > _MAX_PACKAGES:
            raise OfficialBundleError(f"{source['id']} selected an invalid package count: {len(package_metadata)}")

        packages: list[OfficialPackage] = []
        for package_root, (metadata, provenance_manifest) in sorted(
            package_metadata.items(), key=lambda item: item[0].relative_to(root).as_posix()
        ):
            tree_sha256, skill_sha256, file_count, total_bytes = _hash_package(package_root)
            fallback_license = _license_from_files(package_root)
            version, license_name = _manifest_version_license(metadata, fallback_license)
            packages.append(
                OfficialPackage(
                    source_id=source["id"],
                    vendor=source["vendor"],
                    tool=source["tool"],
                    relative_path=package_root.relative_to(root).as_posix(),
                    absolute_path=package_root,
                    tree_sha256=tree_sha256,
                    skill_sha256=skill_sha256,
                    file_count=file_count,
                    total_bytes=total_bytes,
                    version=version,
                    license=license_name,
                    provenance_manifest=provenance_manifest,
                )
            )

        package_records = [package.lock_record() for package in packages]
        encoded = json.dumps(package_records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        inventory_sha256 = hashlib.sha256(b"skill-scanner-official-bundled-source-v1\0" + encoded).hexdigest()
        sources.append(
            OfficialSource(
                source_id=source["id"],
                vendor=source["vendor"],
                tool=source["tool"],
                source_group=source["source_group"],
                root=root,
                root_locator=source["root_locator"],
                selector=dict(selector),
                provenance=dict(source["provenance"]),
                packages=tuple(packages),
                inventory_sha256=inventory_sha256,
                file_count=sum(package.file_count for package in packages),
                total_bytes=sum(package.total_bytes for package in packages),
            )
        )
    return tuple(sources)


def build_lock(profile_path: Path = PROFILE_FILE) -> dict[str, Any]:
    return {
        "lock_version": LOCK_VERSION,
        "corpus_id": "official-bundled-agent-skills-goodware",
        "label": "benign-hard-negative",
        "usage": "non-gating first-party false-positive audit; never a malicious-recall denominator",
        "sources": [source.lock_record() for source in inventory_profile(profile_path)],
    }


def load_and_verify_lock(
    lock_path: Path = LOCK_FILE,
    profile_path: Path = PROFILE_FILE,
) -> tuple[OfficialSource, ...]:
    lock = _exact_mapping(
        _load_json(lock_path, max_bytes=8 * 1024 * 1024),
        frozenset({"lock_version", "corpus_id", "label", "usage", "sources"}),
        "lock",
    )
    if lock["lock_version"] != LOCK_VERSION:
        raise OfficialBundleError(f"unsupported lock_version: {lock['lock_version']!r}")
    if lock["corpus_id"] != "official-bundled-agent-skills-goodware" or lock["label"] != "benign-hard-negative":
        raise OfficialBundleError("official bundle lock has the wrong corpus identity")
    _string(lock["usage"], "lock.usage")
    observed = inventory_profile(profile_path)
    expected_sources = lock["sources"]
    if isinstance(expected_sources, (str, bytes)) or not isinstance(expected_sources, Sequence):
        raise OfficialBundleError("lock.sources must be an array")
    actual_records = [source.lock_record() for source in observed]
    if list(expected_sources) != actual_records:
        expected_ids = [record.get("id") for record in expected_sources if isinstance(record, Mapping)]
        actual_ids = [record["id"] for record in actual_records]
        raise OfficialBundleError(
            "installed official bundle differs from the immutable lock "
            f"(expected_sources={expected_ids}, actual_sources={actual_ids}); refresh requires review"
        )
    for source in observed:
        if not _SHA256_RE.fullmatch(source.inventory_sha256):
            raise OfficialBundleError(f"invalid computed inventory hash for {source.source_id}")
    return observed


__all__ = [
    "LOCK_FILE",
    "PROFILE_FILE",
    "OfficialBundleError",
    "OfficialPackage",
    "OfficialSource",
    "build_lock",
    "inventory_profile",
    "load_and_verify_lock",
    "load_profile",
]
