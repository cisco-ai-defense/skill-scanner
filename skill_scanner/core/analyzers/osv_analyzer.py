# Copyright 2026 Cisco Systems, Inc.
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

"""OSV dependency vulnerability analyzer.

Checks a skill's exactly resolved dependencies against the free, open
`OSV.dev <https://osv.dev>`_ vulnerability database. Opt-in (like the
VirusTotal analyzer), requires no API key, and fails open on network errors so
it never blocks a scan.

Collected sources:

* **PyPI** -- dependencies pinned to an exact version (``package==1.2.3``) in a
  requirements file, ``pyproject.toml``, ``setup.cfg``, ``setup.py``, a
  ``Pipfile`` or manifest metadata. An open range (``package>=1``) has no single
  version to look up, and that risk is already surfaced by the
  unpinned-dependency static check.
* **npm** -- dependencies declared at an exact version in a ``package.json``.
  A range (``^4.17.0``) names no single release, so the unpinned-dependency
  static check carries that signal instead.  Lockfiles are not read, matching
  how Python dependencies are collected.

Each query carries its own ecosystem, so ecosystems are looked up together.
Queries are deduplicated, chunked and capped to stay proportionate.
"""

from __future__ import annotations

import ast
import configparser
import logging
import re
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from ..models import Finding, Severity, ThreatCategory
from .base import BaseAnalyzer
from .dependencies import NPM_ECOSYSTEM, ResolvedDependency
from .npm_manifest import entries_from_package_json, exact_version, is_npm_manifest

if TYPE_CHECKING:
    from ..models import Skill
    from ..scan_policy import ScanPolicy

logger = logging.getLogger(__name__)

# name[extras]==version  (exact pins only; markers/comments stripped beforehand)
_PINNED_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.\-+!]*)\s*$"
)


def _first_line_containing(content: str, needle: str) -> int | None:
    """Best-effort 1-based line number of the first line containing ``needle``."""
    if not needle:
        return None
    for index, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _safe_toml(content: str) -> dict | None:
    """Parse TOML, returning ``None`` when content is malformed."""
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return None


def _entries_from_pyproject(path: str, content: str) -> list[tuple[str, int | None, str]]:
    """PEP 621 ``[project]`` dependencies and optional-dependencies."""
    data = _safe_toml(content)
    project = data.get("project") if isinstance(data, dict) else None
    if not isinstance(project, dict):
        return []
    specs: list[str] = []
    deps = project.get("dependencies")
    if isinstance(deps, list):
        specs.extend(str(dep) for dep in deps)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                specs.extend(str(dep) for dep in group)
    return [(path, _first_line_containing(content, spec), spec) for spec in specs]


def _entries_from_setup_cfg(path: str, content: str) -> list[tuple[str, int | None, str]]:
    """``[options] install_requires`` and ``[options.extras_require]``."""
    parser = configparser.ConfigParser()
    try:
        parser.read_string(content)
    except configparser.Error:
        return []
    blocks: list[str] = []
    if parser.has_option("options", "install_requires"):
        blocks.append(parser.get("options", "install_requires"))
    if parser.has_section("options.extras_require"):
        blocks.extend(value for _, value in parser.items("options.extras_require"))

    entries: list[tuple[str, int | None, str]] = []
    for block in blocks:
        for piece in block.replace(",", "\n").splitlines():
            spec = piece.strip()
            if spec:
                entries.append((path, _first_line_containing(content, spec), spec))
    return entries


def _entries_from_setup_py(path: str, content: str) -> list[tuple[str, int | None, str]]:
    """String literals inside ``install_requires=[...]`` in setup.py."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    entries: list[tuple[str, int | None, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.keyword) and node.arg == "install_requires"):
            continue
        for literal in ast.walk(node.value):
            if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                entries.append((path, getattr(literal, "lineno", None), literal.value))
    return entries


def _pipfile_requirement(name: str, spec: Any) -> str | None:
    """Convert a Pipfile entry into a requirement string, or None to skip."""
    if isinstance(spec, str):
        version = spec.strip()
        return name if version in ("", "*") else f"{name}{version}"
    if isinstance(spec, dict):
        # git/path/url references are pinned to a specific artifact.
        if any(key in spec for key in ("git", "path", "file", "url")):
            return None
        version = str(spec.get("version", "")).strip()
        return name if version in ("", "*") else f"{name}{version}"
    return None


def _vulns_per_dependency(payload: object, count: int) -> list[list[dict]]:
    """Extract one advisory list per queried dependency from an OSV response.

    The response comes from an external service, so its shape is validated rather
    than trusted: a malformed body raises ``ValueError``, which the caller already
    treats as a failed chunk and fails open on.
    """
    if not isinstance(payload, dict):
        raise ValueError("OSV response body is not a JSON object")
    results = payload.get("results", [])
    if not isinstance(results, list):
        raise ValueError("OSV response 'results' is not a list")

    extracted: list[list[dict]] = []
    for index in range(count):
        entry = results[index] if index < len(results) else None
        vulns = entry.get("vulns") if isinstance(entry, dict) else None
        extracted.append([v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else [])
    return extracted


def _positive_bound(value: object, default: int, name: str) -> int:
    """Return ``value`` when it is a positive integer, else the default for ``None``.

    A silently accepted zero or negative bound is worse than an error: a negative
    chunk size yields no query chunks at all, and a negative cap truncates from
    the wrong end.
    """
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer, got {value!r}")
    return value


def _coordinates(dependency: ResolvedDependency) -> str:
    """Render a dependency the way its ecosystem writes it."""
    separator = "@" if dependency.ecosystem == NPM_ECOSYSTEM else "=="
    return f"{dependency.name}{separator}{dependency.version}"


def _entries_from_pipfile(path: str, content: str) -> list[tuple[str, int | None, str]]:
    """``[packages]`` and ``[dev-packages]`` sections of a Pipfile (TOML)."""
    data = _safe_toml(content)
    if not isinstance(data, dict):
        return []
    entries: list[tuple[str, int | None, str]] = []
    for section in ("packages", "dev-packages"):
        packages = data.get(section)
        if not isinstance(packages, dict):
            continue
        for name, spec in packages.items():
            requirement = _pipfile_requirement(name, spec)
            if requirement is not None:
                entries.append((path, _first_line_containing(content, name), requirement))
    return entries


class OSVAnalyzer(BaseAnalyzer):
    """Query resolved dependencies against the OSV.dev vulnerability database."""

    QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

    #: Queries per ``querybatch`` request, kept inside OSV's pagination threshold.
    QUERY_CHUNK_SIZE = 200

    #: Lookups per skill; a scan should not become a full dependency audit.
    MAX_DEPENDENCIES = 1000

    def __init__(
        self,
        enabled: bool = True,
        ecosystem: str = "PyPI",
        timeout: float = 10.0,
        policy: ScanPolicy | None = None,
        chunk_size: int | None = None,
        max_dependencies: int | None = None,
    ):
        super().__init__("osv_analyzer", policy=policy)
        self.enabled = enabled
        self.ecosystem = ecosystem
        self.timeout = timeout
        self.chunk_size = _positive_bound(chunk_size, self.QUERY_CHUNK_SIZE, "chunk_size")
        self.max_dependencies = _positive_bound(max_dependencies, self.MAX_DEPENDENCIES, "max_dependencies")
        self._client = httpx.Client(timeout=timeout)

    def analyze(self, skill: Skill) -> list[Finding]:
        if not self.enabled:
            return []

        dependencies = self._collect_pinned_dependencies(skill)
        if not dependencies:
            return []

        vuln_lists = self._query_osv(dependencies)

        findings: list[Finding] = []
        for dependency, vulns in zip(dependencies, vuln_lists, strict=False):
            if not vulns:
                continue
            findings.append(self._create_finding(dependency, vulns))
        return findings

    def _collect_pinned_dependencies(self, skill: Skill) -> list[ResolvedDependency]:
        """Return every dependency resolved to an exact version.

        PyPI sources: ``requirements*.txt``, ``pyproject.toml`` (``[project]``
        dependencies and optional-dependencies), ``setup.cfg``, ``setup.py``
        (``install_requires``), ``Pipfile``, and a manifest ``metadata``
        ``dependencies`` list; only exact ``==`` pins qualify.  npm source:
        ``package.json``; only specs naming one exact release qualify.

        One release is often declared twice, so results are deduplicated on
        ecosystem, name and version.
        """
        collected: list[ResolvedDependency] = []
        for source, line_number, raw in self._iter_requirement_strings(skill):
            parsed = self._parse_pinned(raw)
            if parsed is not None:
                collected.append(ResolvedDependency(self.ecosystem, parsed[0], parsed[1], source, line_number))
        collected.extend(self._iter_npm_dependencies(skill))

        seen: set[tuple[str, str, str]] = set()
        deduplicated: list[ResolvedDependency] = []
        for dependency in collected:
            key = (dependency.ecosystem, dependency.name, dependency.version)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(dependency)

        if len(deduplicated) > self.max_dependencies:
            logger.warning(
                "Skill declares %d resolved dependencies; querying the first %d",
                len(deduplicated),
                self.max_dependencies,
            )
            del deduplicated[self.max_dependencies :]
        return deduplicated

    @staticmethod
    def _iter_npm_dependencies(skill: Skill) -> list[ResolvedDependency]:
        """Exactly pinned npm dependencies from every ``package.json`` in the skill."""
        collected: list[ResolvedDependency] = []
        for skill_file in skill.files:
            if not is_npm_manifest(skill_file.relative_path):
                continue
            for entry in entries_from_package_json(skill_file.relative_path, skill_file.read_content()):
                version = exact_version(entry.spec)
                if version is None:
                    continue
                collected.append(
                    ResolvedDependency(
                        ecosystem=NPM_ECOSYSTEM,
                        name=entry.name,
                        version=version,
                        source=entry.source,
                        line_number=entry.line_number,
                        dev=entry.dev,
                    )
                )
        return collected

    @staticmethod
    def _iter_requirement_strings(skill: Skill) -> list[tuple[str, int | None, str]]:
        """Gather ``(source_path, line_number, requirement_string)`` from every
        dependency-declaring file in the skill plus manifest metadata."""
        entries: list[tuple[str, int | None, str]] = []
        for skill_file in skill.files:
            file_name = Path(skill_file.relative_path).name.lower()
            path = skill_file.relative_path
            if file_name.startswith("requirements") and file_name.endswith(".txt"):
                for line_number, raw in enumerate(skill_file.read_content().splitlines(), start=1):
                    entries.append((path, line_number, raw))
            elif file_name == "pyproject.toml":
                entries.extend(_entries_from_pyproject(path, skill_file.read_content()))
            elif file_name == "setup.cfg":
                entries.extend(_entries_from_setup_cfg(path, skill_file.read_content()))
            elif file_name == "setup.py":
                entries.extend(_entries_from_setup_py(path, skill_file.read_content()))
            elif file_name == "pipfile":
                entries.extend(_entries_from_pipfile(path, skill_file.read_content()))

        metadata = skill.manifest.metadata
        if isinstance(metadata, dict):
            declared = metadata.get("dependencies")
            if isinstance(declared, list):
                for declared_dep in declared:
                    # Manifest metadata is sourced from the package's
                    # instruction file.  Findings and CEL facts use stable,
                    # package-relative paths rather than absolute host paths.
                    entries.append(("SKILL.md", None, str(declared_dep)))
        return entries

    @staticmethod
    def _parse_pinned(raw: str) -> tuple[str, str] | None:
        """Extract ``(name, version)`` from an exactly pinned requirement line."""
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            return None
        line = line.split(";", 1)[0].strip()
        # Drop trailing pip hash options that may share the line.
        line = line.split("--hash", 1)[0].strip()
        match = _PINNED_RE.match(line)
        if not match:
            return None
        return match.group("name"), match.group("version")

    def _query_osv(self, dependencies: list[ResolvedDependency]) -> list[list[dict]]:
        """Query in chunks, returning one vulnerability list per dependency.

        Chunks fail open independently, so a transient error costs that chunk's
        coverage rather than the whole scan.
        """
        vuln_lists: list[list[dict]] = []
        for start in range(0, len(dependencies), self.chunk_size):
            chunk = dependencies[start : start + self.chunk_size]
            try:
                vuln_lists.extend(self._query_osv_batch(chunk))
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("OSV query failed for %d dependencies, skipping them: %s", len(chunk), exc)
                vuln_lists.extend([] for _ in chunk)
        return vuln_lists

    def _query_osv_batch(self, dependencies: list[ResolvedDependency]) -> list[list[dict]]:
        """Query OSV querybatch; return a per-package list of vulnerability dicts."""
        if not dependencies:
            return []
        payload = {
            "queries": [
                {
                    "package": {"ecosystem": dependency.ecosystem, "name": dependency.name},
                    "version": dependency.version,
                }
                for dependency in dependencies
            ]
        }
        response = self._client.post(self.QUERYBATCH_URL, json=payload)
        response.raise_for_status()
        return _vulns_per_dependency(response.json(), len(dependencies))

    def _create_finding(self, dependency: ResolvedDependency, vulns: list[dict]) -> Finding:
        vuln_ids = [vuln_id for v in vulns if isinstance((vuln_id := v.get("id")), str) and vuln_id]
        references = [f"https://osv.dev/vulnerability/{vuln_id}" for vuln_id in vuln_ids]
        ids_display = ", ".join(vuln_ids) if vuln_ids else "unknown"
        coordinates = _coordinates(dependency)
        return Finding(
            # One name and version can exist on both PyPI and npm, unrelated.
            id=f"OSV_{dependency.ecosystem}_{dependency.name}_{dependency.version}",
            rule_id="SUPPLY_CHAIN_KNOWN_VULNERABILITY",
            category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
            severity=Severity.HIGH,
            title=f"Known vulnerability in dependency {coordinates}",
            description=(
                f"Dependency '{coordinates}' has {len(vuln_ids)} known "
                f"vulnerability advisory(ies) in the OSV database: {ids_display}."
            ),
            file_path=dependency.source,
            line_number=dependency.line_number,
            snippet=coordinates,
            remediation="Upgrade to a patched version listed in the referenced OSV advisories.",
            analyzer="osv",
            metadata={
                "package": dependency.name,
                "version": dependency.version,
                "ecosystem": dependency.ecosystem,
                "dev": dependency.dev,
                "vulnerability_ids": vuln_ids,
                "references": references,
                "semantic_facts": {
                    "evidence_kind": "dependency_advisory",
                    "context_kind": "manifest" if dependency.source == "SKILL.md" else "dependency_file",
                    "evidence_value_class": "known_vulnerable_dependency",
                    "evidence_count": len(vuln_ids),
                    "signal_kind": "known_vulnerability",
                    "signals": [],
                },
            },
        )
