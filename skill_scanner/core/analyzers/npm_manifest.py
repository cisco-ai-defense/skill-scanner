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

"""npm manifest (``package.json``) dependency parsing.

The npm counterpart of ``requirements.txt``: what a package *declares*, read for
the same two purposes.  :func:`exact_version` finds releases an advisory database
can be queried for; :func:`classify_spec` judges whether a spec is pinned at all.
Lockfiles are not read, matching how Python dependencies are collected, so
transitive dependencies are out of scope either way.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

#: Manifest basename recognized as an npm dependency declaration.
NPM_MANIFEST_NAME = "package.json"

#: Directory holding installed packages rather than declared ones.
_INSTALL_DIR = "node_modules"

#: Sections read, and whether they are development-only.  ``peerDependencies`` is
#: excluded (the consumer installs those, not this package) and
#: ``bundleDependencies`` carries no versions.
_DEPENDENCY_SECTIONS = (
    ("dependencies", False),
    ("devDependencies", True),
    ("optionalDependencies", False),
)

# An exact release: strict semver, optionally v-prefixed.
_EXACT_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]*)?)$")

# Partially bound (``1.x``, ``1.2.*``): constrained, still free to move.
_WILDCARD_RE = re.compile(r"^v?\d+(?:\.\d+)?\.[xX*]$")

# ``"aliased": "npm:real-pkg@1.2.3"`` installs ``real-pkg`` under another name.
_ALIAS_RE = re.compile(r"^npm:(?P<name>@[^/@]+/[^@]+|[^@]+)@(?P<spec>.+)$")

# Specs that bind to a particular artifact rather than a registry range.
_ARTIFACT_PREFIXES = (
    "file:",
    "link:",
    "portal:",
    "patch:",
    "workspace:",
    "git:",
    "git+",
    "github:",
    "gitlab:",
    "bitbucket:",
)


class DeclaredDependency(NamedTuple):
    """One dependency as declared in a manifest, with its raw version spec."""

    source: str
    line_number: int | None
    name: str
    spec: str
    dev: bool = False


def is_vendored(relative_path: str) -> bool:
    """True for a path inside an installed dependency tree.

    Content under ``node_modules/`` belongs to an installed package, not to the
    author: its declarations are not theirs to pin, and its lockfiles say nothing
    about what this package declares.
    """
    return _INSTALL_DIR in Path(relative_path).parts


def is_npm_manifest(relative_path: str) -> bool:
    """True for a ``package.json`` the package itself declares."""
    if Path(relative_path).name.lower() != NPM_MANIFEST_NAME:
        return False
    return not is_vendored(relative_path)


def _first_line_containing(content: str, needle: str) -> int | None:
    """Best-effort 1-based line number of the first line containing ``needle``."""
    if not needle:
        return None
    for index, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _normalized_range(spec: object) -> str | None:
    """Return a comparable range, or ``None`` when there is nothing to judge.

    Artifact references (paths, git, tarballs, workspace protocols) are already
    bound, so -- like a Python URL requirement -- they are neither pinned nor not.
    """
    if not isinstance(spec, str):
        return None
    value = spec.strip()
    if "://" in value or value.startswith(_ARTIFACT_PREFIXES):
        return None
    # ``owner/repo`` and ``owner/repo#ref`` are GitHub shorthands.
    if "/" in value:
        return None
    # npm allows a redundant equals sign on an exact version.
    if value.startswith("="):
        value = value[1:].strip()
    return value


def exact_version(spec: object) -> str | None:
    """Return the version when ``spec`` names exactly one release, else ``None``."""
    value = _normalized_range(spec)
    if value is None:
        return None
    match = _EXACT_RE.match(value)
    return match.group(1) if match else None


def classify_spec(spec: object) -> str | None:
    """Classify a version spec as ``pinned``, ``wildcard`` or ``unpinned``.

    Returns ``None`` for specs that name an artifact rather than a range, which
    the unpinned-dependency check ignores.
    """
    value = _normalized_range(spec)
    if value is None:
        return None
    if _EXACT_RE.match(value):
        return "pinned"
    if _WILDCARD_RE.match(value):
        return "wildcard"
    return "unpinned"


def entries_from_package_json(path: str, content: str) -> list[DeclaredDependency]:
    """Dependencies declared in a ``package.json``, with aliases resolved."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    # npm resolves a duplicate name to the optionalDependencies spec, so the
    # entry in dependencies is not the one that gets installed.
    optional = data.get("optionalDependencies")
    overridden = set(optional) if isinstance(optional, dict) else set()

    entries: list[DeclaredDependency] = []
    for section, is_dev in _DEPENDENCY_SECTIONS:
        declared = data.get(section)
        if not isinstance(declared, dict):
            continue
        for key, spec in declared.items():
            if not isinstance(key, str) or not key or not isinstance(spec, str):
                continue
            if section == "dependencies" and key in overridden:
                continue
            name, resolved_spec = key, spec
            alias = _ALIAS_RE.match(spec.strip())
            if alias is not None:
                name, resolved_spec = alias.group("name"), alias.group("spec")
            entries.append(
                DeclaredDependency(
                    source=path,
                    # Locate by key: the alias, for aliased installs.
                    line_number=_first_line_containing(content, f'"{key}"'),
                    name=name,
                    spec=resolved_spec,
                    dev=is_dev,
                )
            )
    return entries
