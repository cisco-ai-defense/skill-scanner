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

"""Resolve changed repository paths to the skill packages they affect."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path


def _resolve_path(path: Path) -> Path:
    """Resolve a path without requiring the final entry to exist."""
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        # ``absolute()`` leaves ``..`` segments intact, which can make a
        # lexical containment check accept a path that escapes the repository.
        return Path(os.path.abspath(path))


def _nearest_skill_root(start: Path, skill_file: str, stop: Path | None) -> Path | None:
    """Walk upward from *start* and return the nearest skill root."""
    candidate = start
    while True:
        if stop is not None and (candidate == stop or not candidate.is_relative_to(stop)):
            return None
        if (candidate / skill_file).is_file():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


def resolve_affected_skills(
    changed_files: Iterable[str | Path],
    *,
    repo_root: str | Path | None = None,
    skill_roots: Iterable[str | Path] = (),
    skill_file: str = "SKILL.md",
) -> set[Path]:
    """Map changed file paths to their nearest containing skill directories.

    Paths may be absolute or relative to *repo_root*. When *repo_root* is
    provided, paths outside that repository are ignored so an untrusted file
    argument cannot make the hook scan arbitrary directories. Missing paths
    are supported, allowing deleted files to map to a still-existing skill.

    *skill_roots* provides compatibility with configured skill collections.
    Each root is used as a fallback for the common ``<root>/<skill>/...``
    layout; the nearest parent containing *skill_file* always wins.
    """
    if not skill_file or Path(skill_file).name != skill_file:
        raise ValueError("skill_file must be a filename, not a path")

    base = _resolve_path(Path(repo_root) if repo_root is not None else Path.cwd())
    bounded = repo_root is not None

    configured_roots: list[Path] = []
    for root in skill_roots:
        root_path = Path(root)
        if not root_path.is_absolute():
            root_path = base / root_path
        root_path = _resolve_path(root_path)
        if bounded and not root_path.is_relative_to(base):
            continue
        configured_roots.append(root_path)

    affected: set[Path] = set()
    for changed_file in changed_files:
        raw_value = str(changed_file)
        if not raw_value:
            continue

        changed_path = Path(raw_value)
        if not changed_path.is_absolute():
            changed_path = base / changed_path
        changed_path = _resolve_path(changed_path)

        if bounded and not changed_path.is_relative_to(base):
            continue

        nearest = _nearest_skill_root(changed_path.parent, skill_file, base if bounded else None)
        if nearest is not None:
            affected.add(nearest)
            continue

        # Preserve the configured ``<skills-root>/<skill>/...`` lookup used by
        # the original hook. This is mainly useful for callers that provide a
        # path before its leaf file has been materialized.
        for configured_root in configured_roots:
            try:
                relative = changed_path.relative_to(configured_root)
            except ValueError:
                continue
            if not relative.parts:
                continue
            skill_root = configured_root / relative.parts[0]
            if (skill_root / skill_file).is_file():
                affected.add(skill_root)
                break

    return affected
