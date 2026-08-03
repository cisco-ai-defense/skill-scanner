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

"""Tests for incremental pre-commit skill resolution."""

from __future__ import annotations

import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from skill_scanner.core.changed_skills import resolve_affected_skills
from skill_scanner.hooks.pre_commit import get_ref_changed_files, get_staged_files, main


def _make_skill(skill_dir: Path) -> Path:
    """Create a minimal skill directory for resolver tests."""
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: test skill\n---\n# Test\n",
        encoding="utf-8",
    )
    return skill_dir


class TestResolveAffectedSkills:
    """Cover repository-bounded changed-path resolution."""

    def test_resolves_relative_deleted_file(self, tmp_path):
        """Deleted relative paths resolve through their surviving parents."""
        repo_root = tmp_path / "repo"
        skill_dir = _make_skill(repo_root / ".claude" / "skills" / "alpha")

        result = resolve_affected_skills(
            [".claude/skills/alpha/scripts/deleted.py"],
            repo_root=repo_root,
            skill_roots=(".claude/skills",),
        )

        assert result == {skill_dir.resolve()}

    def test_nearest_nested_skill_wins(self, tmp_path):
        """The nearest nested skill takes precedence over its outer skill."""
        repo_root = tmp_path / "repo"
        _make_skill(repo_root / "skills" / "outer")
        inner = _make_skill(repo_root / "skills" / "outer" / "nested")

        result = resolve_affected_skills(
            ["skills/outer/nested/scripts/run.py"],
            repo_root=repo_root,
            skill_roots=("skills",),
        )

        assert result == {inner.resolve()}

    def test_deduplicates_files_and_supports_spaces(self, tmp_path):
        """Multiple paths with spaces resolve to one affected skill."""
        repo_root = tmp_path / "repo"
        skill_dir = _make_skill(repo_root / "skills" / " skill with spaces ")

        result = resolve_affected_skills(
            [
                "skills/ skill with spaces /SKILL.md",
                "skills/ skill with spaces /scripts/run.py",
            ],
            repo_root=repo_root,
            skill_roots=("skills",),
        )

        assert result == {skill_dir.resolve()}

    def test_ignores_absolute_path_outside_repo(self, tmp_path):
        """Absolute paths outside the repository boundary are ignored."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside = _make_skill(tmp_path / "outside")

        result = resolve_affected_skills(
            [outside / "scripts" / "run.py"],
            repo_root=repo_root,
        )

        assert result == set()

    def test_ignores_relative_path_traversal_outside_repo(self, tmp_path):
        """Relative traversal cannot escape the repository boundary."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        _make_skill(tmp_path / "outside")

        result = resolve_affected_skills(
            ["../outside/scripts/run.py"],
            repo_root=repo_root,
        )

        assert result == set()

    def test_ignores_configured_root_outside_repo(self, tmp_path):
        """Configured skill roots outside the repository are ignored."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside = _make_skill(tmp_path / "outside" / "alpha")

        result = resolve_affected_skills(
            [repo_root / "unrelated" / "file.py"],
            repo_root=repo_root,
            skill_roots=(outside.parent,),
        )

        assert result == set()

    def test_rejects_skill_file_paths(self):
        """The metadata marker must be a filename rather than a path."""
        with pytest.raises(ValueError, match="filename"):
            resolve_affected_skills([], skill_file="metadata/SKILL.md")

    def test_repo_root_is_an_exclusive_search_boundary(self, tmp_path):
        """A marker at the repository root cannot become an affected skill."""
        repo_root = _make_skill(tmp_path / "repo")

        result = resolve_affected_skills(
            ["scripts/run.py"],
            repo_root=repo_root,
        )

        assert result == set()


class TestStagedFileDiscovery:
    """Cover Git-based changed-path discovery."""

    def test_includes_deleted_paths(self):
        """The staged fallback asks Git to include deleted paths."""
        completed = CompletedProcess(
            args=[],
            returncode=0,
            stdout="skills/alpha/deleted.py\0",
            stderr="",
        )

        with patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=completed) as run:
            assert get_staged_files() == ["skills/alpha/deleted.py"]

        assert run.call_args.args[0] == [
            "git",
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMRTD",
        ]

    def test_ref_diff_uses_a_separate_deletion_query(self):
        """CI ref discovery obtains deleted paths through an explicit Git diff."""
        non_deleted = CompletedProcess(
            args=[],
            returncode=0,
            stdout="skills/alpha/changed.py\0",
            stderr="",
        )
        deleted = CompletedProcess(
            args=[],
            returncode=0,
            stdout="skills/alpha/deleted.py\0install\0",
            stderr="",
        )

        with patch(
            "skill_scanner.hooks.pre_commit.subprocess.run",
            side_effect=[non_deleted, deleted],
        ) as run:
            assert get_ref_changed_files("base", "head") == [
                "skills/alpha/changed.py",
                "skills/alpha/deleted.py",
                "install",
            ]

        assert run.call_args_list[0].args[0] == [
            "git",
            "diff",
            "--diff-filter=ACMRT",
            "--name-only",
            "-z",
            "base...head",
        ]
        assert run.call_args_list[1].args[0] == [
            "git",
            "diff",
            "--diff-filter=D",
            "--name-only",
            "-z",
            "base...head",
        ]

    def test_preserves_unusual_path_characters(self):
        """NUL-delimited output preserves whitespace and backslashes verbatim."""
        completed = CompletedProcess(
            args=[],
            returncode=0,
            stdout="skills/tab\tname/SKILL.md\0skills/back\\slash/SKILL.md\0",
            stderr="",
        )

        with patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=completed):
            assert get_staged_files() == [
                "skills/tab\tname/SKILL.md",
                "skills/back\\slash/SKILL.md",
            ]

    def test_ref_diff_propagates_git_failure(self):
        """Invalid CI refs cannot be mistaken for an empty change set."""
        with (
            patch(
                "skill_scanner.hooks.pre_commit.subprocess.run",
                side_effect=subprocess.CalledProcessError(128, ["git", "diff"], stderr="bad revision"),
            ),
            pytest.raises(subprocess.CalledProcessError),
        ):
            get_ref_changed_files("missing", "head")


class TestPreCommitIncrementalFiles:
    """Cover pre-commit argument routing and changed-file selection."""

    def test_precommit_filenames_bypass_staged_diff(self, tmp_path, monkeypatch):
        """Explicit filenames remain supported without reading the staged diff."""
        repo_root = tmp_path / "repo"
        skill_dir = _make_skill(repo_root / ".claude" / "skills" / "alpha")
        monkeypatch.chdir(repo_root)

        rev_parse = CompletedProcess(
            args=["git", "rev-parse", "--show-toplevel"],
            returncode=0,
            stdout=f"{repo_root}\n",
            stderr="",
        )
        clean_result = {
            "skill_name": "alpha",
            "skill_directory": str(skill_dir),
            "findings": [],
        }

        with (
            patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=rev_parse),
            patch(
                "skill_scanner.hooks.pre_commit.get_staged_files",
                side_effect=AssertionError("staged diff must not run when filenames are provided"),
            ),
            patch("skill_scanner.hooks.pre_commit.scan_skill", return_value=clean_result) as scan,
        ):
            exit_code = main(
                [
                    ".claude/skills/alpha/SKILL.md",
                    ".claude/skills/alpha/scripts/run.py",
                ]
            )

        assert exit_code == 0
        scan.assert_called_once()
        assert scan.call_args.args[0] == skill_dir.resolve()

    def test_no_filenames_keeps_staged_fallback(self, tmp_path, monkeypatch):
        """Direct invocation without filenames retains staged discovery."""
        repo_root = tmp_path / "repo"
        skill_dir = _make_skill(repo_root / ".claude" / "skills" / "alpha")
        monkeypatch.chdir(repo_root)

        rev_parse = CompletedProcess(
            args=["git", "rev-parse", "--show-toplevel"],
            returncode=0,
            stdout=f"{repo_root}\n",
            stderr="",
        )
        clean_result = {
            "skill_name": "alpha",
            "skill_directory": str(skill_dir),
            "findings": [],
        }

        with (
            patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=rev_parse),
            patch(
                "skill_scanner.hooks.pre_commit.get_staged_files",
                return_value=[".claude/skills/alpha/scripts/run.py"],
            ) as staged,
            patch("skill_scanner.hooks.pre_commit.scan_skill", return_value=clean_result) as scan,
        ):
            exit_code = main([])

        assert exit_code == 0
        staged.assert_called_once_with()
        scan.assert_called_once()

    def test_install_flag_remains_supported(self):
        """The explicit install flag routes to hook installation."""
        with patch("skill_scanner.hooks.pre_commit.install_hook", return_value=0) as install:
            assert main(["--install"]) == 0
        install.assert_called_once_with()

    def test_install_filename_is_not_a_subcommand(self, tmp_path, monkeypatch):
        """A changed path named install goes through normal skill resolution."""
        monkeypatch.chdir(tmp_path)
        rev_parse = CompletedProcess(
            args=["git", "rev-parse", "--show-toplevel"],
            returncode=0,
            stdout=f"{tmp_path}\n",
            stderr="",
        )

        with (
            patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=rev_parse),
            patch("skill_scanner.hooks.pre_commit.install_hook") as install,
            patch("skill_scanner.hooks.pre_commit.get_affected_skills", return_value=set()) as affected,
        ):
            assert main(["install"]) == 0

        install.assert_not_called()
        affected.assert_called_once_with(["install"], ".claude/skills", repo_root=tmp_path)

    def test_ci_refs_use_internal_changed_file_discovery(self, tmp_path, monkeypatch):
        """CI ref environment variables select internal changed-path discovery."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PRE_COMMIT_FROM_REF", "base")
        monkeypatch.setenv("PRE_COMMIT_TO_REF", "head")
        rev_parse = CompletedProcess(
            args=["git", "rev-parse", "--show-toplevel"],
            returncode=0,
            stdout=f"{tmp_path}\n",
            stderr="",
        )

        with (
            patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=rev_parse),
            patch(
                "skill_scanner.hooks.pre_commit.get_ref_changed_files",
                return_value=["skills/alpha/deleted.py", "install"],
            ) as changed,
            patch("skill_scanner.hooks.pre_commit.get_staged_files") as staged,
            patch("skill_scanner.hooks.pre_commit.get_affected_skills", return_value=set()) as affected,
        ):
            assert main([]) == 0

        changed.assert_called_once_with("base", "head")
        staged.assert_not_called()
        affected.assert_called_once_with(
            ["skills/alpha/deleted.py", "install"],
            ".claude/skills",
            repo_root=tmp_path,
        )

    def test_legacy_all_filename_cannot_trigger_full_scan(self, tmp_path, monkeypatch):
        """A path token named --all remains a filename after the option boundary."""
        monkeypatch.chdir(tmp_path)
        rev_parse = CompletedProcess(
            args=["git", "rev-parse", "--show-toplevel"],
            returncode=0,
            stdout=f"{tmp_path}\n",
            stderr="",
        )

        with (
            patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=rev_parse),
            patch("skill_scanner.hooks.pre_commit.get_affected_skills", return_value=set()) as affected,
        ):
            assert main(["--", "--all"]) == 0

        affected.assert_called_once_with(["--all"], ".claude/skills", repo_root=tmp_path)

    def test_scan_all_option_scans_every_configured_skill(self, tmp_path, monkeypatch):
        """The renamed scan-all option selects every configured skill."""
        skill_dir = _make_skill(tmp_path / ".claude" / "skills" / "alpha")
        monkeypatch.chdir(tmp_path)
        rev_parse = CompletedProcess(
            args=["git", "rev-parse", "--show-toplevel"],
            returncode=0,
            stdout=f"{tmp_path}\n",
            stderr="",
        )
        clean_result = {
            "skill_name": "alpha",
            "skill_directory": str(skill_dir),
            "findings": [],
        }

        with (
            patch("skill_scanner.hooks.pre_commit.subprocess.run", return_value=rev_parse),
            patch("skill_scanner.hooks.pre_commit.scan_skill", return_value=clean_result) as scan,
        ):
            assert main(["--scan-all"]) == 0

        scan.assert_called_once()
        assert scan.call_args.args[0] == skill_dir
