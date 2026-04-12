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
Unit tests for skill_scanner/core/repo_fetcher.py.

Covers resolve_repo_url URL normalisation and clone_repo context-manager
behaviour (success, failure, git-not-found, and cleanup).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from skill_scanner.core.exceptions import RepoFetchError
from skill_scanner.core.repo_fetcher import clone_repo, resolve_repo_url

# ---------------------------------------------------------------------------
# resolve_repo_url
# ---------------------------------------------------------------------------


class TestResolveRepoUrl:
    """Tests for resolve_repo_url."""

    def test_full_github_url_returned_as_is(self):
        url = "https://github.com/owner/repo"
        assert resolve_repo_url(url) == url

    def test_full_github_url_with_git_suffix_returned_as_is(self):
        url = "https://github.com/owner/repo.git"
        assert resolve_repo_url(url) == url

    def test_shorthand_expanded_to_github_url(self):
        assert resolve_repo_url("owner/repo") == "https://github.com/owner/repo"

    def test_no_slash_raises_repo_fetch_error(self):
        with pytest.raises(RepoFetchError):
            resolve_repo_url("not-a-repo")

    def test_non_github_http_url_returned_as_is(self):
        url = "https://other.com/owner/repo"
        assert resolve_repo_url(url) == url


# ---------------------------------------------------------------------------
# clone_repo
# ---------------------------------------------------------------------------


class TestCloneRepo:
    """Tests for clone_repo context manager."""

    def test_successful_clone_yields_path(self, tmp_path: Path):
        """When git clone exits 0, the context manager yields a Path that exists."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("skill_scanner.core.repo_fetcher.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("skill_scanner.core.repo_fetcher.subprocess.run", return_value=mock_result),
            patch("skill_scanner.core.repo_fetcher.shutil.rmtree") as mock_rmtree,
        ):
            with clone_repo("https://github.com/owner/repo") as cloned_path:
                assert isinstance(cloned_path, Path)
                assert cloned_path == tmp_path

            # Cleanup must always be called
            mock_rmtree.assert_called_once_with(str(tmp_path), ignore_errors=True)

    def test_clone_failure_raises_repo_fetch_error(self, tmp_path: Path):
        """When git clone returns non-zero, RepoFetchError is raised with stderr."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"repository not found"

        with (
            patch("skill_scanner.core.repo_fetcher.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("skill_scanner.core.repo_fetcher.subprocess.run", return_value=mock_result),
            patch("skill_scanner.core.repo_fetcher.shutil.rmtree"),
        ):
            with pytest.raises(RepoFetchError) as exc_info:
                with clone_repo("https://github.com/owner/repo"):
                    pass  # should not reach here

        assert "repository not found" in str(exc_info.value)

    def test_git_not_on_path_raises_repo_fetch_error(self, tmp_path: Path):
        """When git is not found (FileNotFoundError), RepoFetchError mentioning PATH is raised."""
        with (
            patch("skill_scanner.core.repo_fetcher.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("skill_scanner.core.repo_fetcher.subprocess.run", side_effect=FileNotFoundError),
            patch("skill_scanner.core.repo_fetcher.shutil.rmtree"),
        ):
            with pytest.raises(RepoFetchError) as exc_info:
                with clone_repo("https://github.com/owner/repo"):
                    pass

        assert "PATH" in str(exc_info.value)

    def test_cleanup_runs_even_on_clone_failure(self, tmp_path: Path):
        """shutil.rmtree is called even when clone fails."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"some error"

        with (
            patch("skill_scanner.core.repo_fetcher.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("skill_scanner.core.repo_fetcher.subprocess.run", return_value=mock_result),
            patch("shutil.rmtree") as mock_rmtree,
        ):
            with pytest.raises(RepoFetchError):
                with clone_repo("https://github.com/owner/repo"):
                    pass

        mock_rmtree.assert_called()

    def test_cleanup_runs_even_on_git_not_found(self, tmp_path: Path):
        """shutil.rmtree is called even when FileNotFoundError is raised by git."""
        with (
            patch("skill_scanner.core.repo_fetcher.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("skill_scanner.core.repo_fetcher.subprocess.run", side_effect=FileNotFoundError),
            patch("skill_scanner.core.repo_fetcher.shutil.rmtree") as mock_rmtree,
        ):
            with pytest.raises(RepoFetchError):
                with clone_repo("https://github.com/owner/repo"):
                    pass

        mock_rmtree.assert_called_once_with(str(tmp_path), ignore_errors=True)
