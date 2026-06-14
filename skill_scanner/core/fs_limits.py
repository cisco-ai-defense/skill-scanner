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

"""Bounded filesystem traversal helpers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path


def iter_directory_bounded(
    directory: Path,
    *,
    max_entries_visited: int | None = None,
    entries_visited: int = 0,
) -> Iterator[tuple[os.DirEntry[str], int]]:
    """Yield direct directory entries while enforcing a cumulative visit limit."""
    with os.scandir(directory) as entries:
        for entry in entries:
            entries_visited += 1
            if max_entries_visited is not None and entries_visited > max_entries_visited:
                raise ValueError(f"Directory traversal exceeds {max_entries_visited} filesystem entries")
            yield entry, entries_visited


def walk_directory_bounded(
    directory: Path,
    *,
    max_entries_visited: int | None = None,
) -> Iterator[tuple[Path, list[str], list[str]]]:
    """Yield ``(root, dirs, files)`` while enforcing an entry-by-entry limit."""
    stack = [directory]
    entries_visited = 0

    while stack:
        current = stack.pop()
        dirs: list[str] = []
        files: list[str] = []

        try:
            for entry, next_entries_visited in iter_directory_bounded(
                current,
                max_entries_visited=max_entries_visited,
                entries_visited=entries_visited,
            ):
                entries_visited = next_entries_visited
                try:
                    if entry.is_dir(follow_symlinks=False):
                        dirs.append(entry.name)
                    else:
                        files.append(entry.name)
                except OSError:
                    files.append(entry.name)
        except OSError:
            continue

        yield current, dirs, files

        for dirname in reversed(dirs):
            stack.append(current / dirname)
