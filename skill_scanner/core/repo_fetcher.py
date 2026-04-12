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

"""Repository fetching utilities for Skill Scanner.

Provides helpers to resolve GitHub repository references and clone them
into temporary directories for scanning.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from skill_scanner.core.exceptions import RepoFetchError

_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def resolve_repo_url(repo: str) -> str:
    """Resolve a repository reference to a full GitHub URL.

    Accepts:
    - A full GitHub URL (``https://github.com/owner/repo`` or with ``.git`` suffix)
    - An ``owner/repo`` shorthand, which is expanded to ``https://github.com/owner/repo``

    Args:
        repo: Repository URL or ``owner/repo`` shorthand.

    Returns:
        A full ``https://`` GitHub URL.

    Raises:
        RepoFetchError: If *repo* does not match a recognised format.
    """
    if repo.startswith("http"):
        return repo

    if _SHORTHAND_RE.match(repo):
        return f"https://github.com/{repo}"

    raise RepoFetchError(
        f"Invalid repository reference {repo!r}. "
        "Expected a full GitHub URL (https://github.com/owner/repo) "
        "or an owner/repo shorthand."
    )


@contextmanager
def clone_repo(url: str, timeout: int = 120) -> Iterator[Path]:
    """Clone a Git repository into a temporary directory.

    A context manager that performs a shallow clone of *url* and yields the
    path to the cloned tree.  The temporary directory is always removed on
    exit, regardless of whether an exception occurred.

    Args:
        url: Repository URL to clone.
        timeout: Maximum seconds to wait for ``git clone`` to complete.

    Yields:
        :class:`pathlib.Path` pointing at the root of the cloned repository.

    Raises:
        RepoFetchError: If ``git`` is not found on PATH, or if the clone
            command exits with a non-zero return code.
    """
    tmpdir = tempfile.mkdtemp(prefix="skill_scanner_repo_")
    try:
        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", url, tmpdir],
                capture_output=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise RepoFetchError(
                "git not found on PATH. Please install git and ensure it is available in your PATH."
            )

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace").strip()
            raise RepoFetchError(
                f"git clone failed for {url!r} (exit code {result.returncode}): {stderr}"
            )

        yield Path(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
