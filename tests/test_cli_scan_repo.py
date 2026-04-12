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

"""
CLI-level tests for the ``scan-repo`` command.

Uses a patched clone_repo that yields a real local skills directory so that
the scan can run end-to-end without network access.

Invokes ``scan_repo_command`` in-process (rather than via subprocess) so that
``unittest.mock.patch`` can replace ``clone_repo`` before the lazy import
inside ``scan_repo_command`` resolves it.
"""

from __future__ import annotations

import io
import sys
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.core.exceptions import RepoFetchError

# Real local skills directory used as the fake cloned tree
_TEST_SKILLS_DIR = Path(__file__).parent.parent / "evals" / "test_skills"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def _fake_clone_test_skills(url: str, **kwargs):
    """Fake clone_repo that yields the real test_skills directory."""
    yield _TEST_SKILLS_DIR


@contextmanager
def _fake_clone_raises(url: str, **kwargs):
    """Fake clone_repo that immediately raises RepoFetchError."""
    raise RepoFetchError("clone failed")
    yield  # pragma: no cover – makes this a generator so @contextmanager is happy


def _invoke_scan_repo(repo_arg: str) -> tuple[str, str, int]:
    """Invoke scan_repo_command in-process, return (stdout, stderr, exit_code)."""
    from skill_scanner.cli.cli import build_parser, scan_repo_command

    parser = build_parser()
    args = parser.parse_args(["scan-repo", repo_arg])

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        exit_code = scan_repo_command(args)

    return stdout_buf.getvalue(), stderr_buf.getvalue(), exit_code


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScanRepoCommand:
    """CLI tests for ``scan-repo``."""

    def test_scan_repo_shorthand(self):
        """scan-repo owner/repo with patched clone exits 0 and produces output."""
        with patch("skill_scanner.core.repo_fetcher.clone_repo", _fake_clone_test_skills):
            stdout, stderr, code = _invoke_scan_repo("owner/repo")

        assert code == 0, (
            f"Expected exit 0, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
        )
        # Scan should have produced some output (status messages or skill names)
        combined = stdout + stderr
        assert combined.strip(), "Expected some output from the scan"

    def test_scan_repo_full_url(self):
        """scan-repo with a full URL also exits 0 and produces output."""
        with patch("skill_scanner.core.repo_fetcher.clone_repo", _fake_clone_test_skills):
            stdout, stderr, code = _invoke_scan_repo("https://github.com/owner/repo")

        assert code == 0, (
            f"Expected exit 0, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
        )
        combined = stdout + stderr
        assert combined.strip(), "Expected some output from the scan"

    def test_scan_repo_invalid_repo(self):
        """scan-repo with an invalid reference exits 1 and stderr contains an error."""
        # No patch needed — resolve_repo_url raises RepoFetchError before clone is called
        stdout, stderr, code = _invoke_scan_repo("not-valid")

        assert code == 1, (
            f"Expected exit 1 for invalid repo, got {code}.\nstderr: {stderr}"
        )
        assert stderr.strip(), "Expected an error message on stderr"

    def test_scan_repo_clone_failure(self):
        """When clone_repo raises RepoFetchError, scan-repo exits 1."""
        with patch("skill_scanner.core.repo_fetcher.clone_repo", _fake_clone_raises):
            stdout, stderr, code = _invoke_scan_repo("owner/repo")

        assert code == 1, (
            f"Expected exit 1 on clone failure, got {code}.\nstderr: {stderr}"
        )
