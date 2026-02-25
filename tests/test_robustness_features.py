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
Tests for robustness features:
- Lenient loading mode (malformed YAML, missing fields)
- Report.skills_skipped tracking
- Pre-commit hook git-diff improvements
- Multi-skill summary with skipped skills
"""

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.core.exceptions import SkillLoadError
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Finding, Report, ScanResult, Severity, ThreatCategory

# ============================================================================
# Helpers
# ============================================================================


def _write_skill_md(skill_dir: Path, content: str) -> None:
    """Write a SKILL.md file inside *skill_dir*."""
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(textwrap.dedent(content), encoding="utf-8")


# ============================================================================
# Lenient loader tests
# ============================================================================


class TestLenientLoader:
    """Tests for SkillLoader lenient mode."""

    def test_missing_name_strict_raises(self, tmp_path):
        _write_skill_md(
            tmp_path / "bad-skill",
            """\
            ---
            description: Some skill
            ---
            # Body
            """,
        )
        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="missing required field: name"):
            loader.load_skill(tmp_path / "bad-skill")

    def test_missing_name_lenient_uses_dirname(self, tmp_path):
        _write_skill_md(
            tmp_path / "my-dir",
            """\
            ---
            description: Some skill
            ---
            # Body
            """,
        )
        loader = SkillLoader()
        skill = loader.load_skill(tmp_path / "my-dir", lenient=True)
        assert skill.name == "my-dir"

    def test_missing_description_strict_raises(self, tmp_path):
        _write_skill_md(
            tmp_path / "bad-skill",
            """\
            ---
            name: my-skill
            ---
            # Body
            """,
        )
        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="missing required field: description"):
            loader.load_skill(tmp_path / "bad-skill")

    def test_missing_description_lenient_uses_placeholder(self, tmp_path):
        _write_skill_md(
            tmp_path / "no-desc",
            """\
            ---
            name: my-skill
            ---
            # Body
            """,
        )
        loader = SkillLoader()
        skill = loader.load_skill(tmp_path / "no-desc", lenient=True)
        assert skill.name == "my-skill"
        assert skill.description == "(no description)"

    def test_both_fields_missing_lenient(self, tmp_path):
        _write_skill_md(
            tmp_path / "empty-front",
            """\
            ---
            license: MIT
            ---
            Some instructions
            """,
        )
        loader = SkillLoader()
        skill = loader.load_skill(tmp_path / "empty-front", lenient=True)
        assert skill.name == "empty-front"
        assert skill.description == "(no description)"
        assert skill.instruction_body.strip() == "Some instructions"

    def test_bad_yaml_strict_raises(self, tmp_path):
        skill_dir = tmp_path / "bad-yaml"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: [broken\n---\nbody\n",
            encoding="utf-8",
        )
        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="frontmatter"):
            loader.load_skill(skill_dir)

    def test_bad_yaml_lenient_returns_raw_body(self, tmp_path):
        skill_dir = tmp_path / "bad-yaml"
        skill_dir.mkdir()
        raw = "---\nname: [broken\n---\nbody text\n"
        (skill_dir / "SKILL.md").write_text(raw, encoding="utf-8")
        loader = SkillLoader()
        skill = loader.load_skill(skill_dir, lenient=True)
        assert skill.name == "bad-yaml"
        assert "body text" in skill.instruction_body or "body text" in raw

    def test_dict_description_coerced_to_string(self, tmp_path):
        _write_skill_md(
            tmp_path / "dict-desc",
            """\
            ---
            name: multi-lang
            description:
              en: English description
              fr: Description en francais
            ---
            # Body
            """,
        )
        loader = SkillLoader()
        skill = loader.load_skill(tmp_path / "dict-desc")
        assert isinstance(skill.description, str)
        assert "English" in skill.description or "en" in skill.description

    def test_dict_name_coerced_to_string(self, tmp_path):
        _write_skill_md(
            tmp_path / "dict-name",
            """\
            ---
            name:
              full: My Skill
              short: ms
            description: A skill
            ---
            # Body
            """,
        )
        loader = SkillLoader()
        skill = loader.load_skill(tmp_path / "dict-name")
        assert isinstance(skill.name, str)

    def test_no_skill_md_still_raises_in_lenient(self, tmp_path):
        """Even in lenient mode, a missing SKILL.md is fatal."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        loader = SkillLoader()
        with pytest.raises(SkillLoadError, match="SKILL.md not found"):
            loader.load_skill(empty_dir, lenient=True)


# ============================================================================
# Report.skills_skipped tests
# ============================================================================


class TestReportSkillsSkipped:
    def test_empty_report_has_no_skipped(self):
        report = Report()
        assert report.skills_skipped == []

    def test_skills_skipped_appears_in_to_dict(self):
        report = Report()
        report.skills_skipped.append({"skill": "/tmp/bad", "reason": "missing name"})
        d = report.to_dict()
        assert "skills_skipped" in d["summary"]
        assert len(d["summary"]["skills_skipped"]) == 1
        assert d["summary"]["skills_skipped"][0]["skill"] == "/tmp/bad"

    def test_skills_skipped_absent_when_empty(self):
        report = Report()
        d = report.to_dict()
        assert "skills_skipped" not in d["summary"]

    def test_add_scan_result_still_works(self):
        report = Report()
        result = ScanResult(
            skill_name="good",
            skill_directory="/tmp/good",
            findings=[
                Finding(
                    id="f1",
                    rule_id="R1",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=Severity.HIGH,
                    title="Test",
                    description="desc",
                )
            ],
        )
        report.add_scan_result(result)
        report.skills_skipped.append({"skill": "/tmp/bad", "reason": "parse error"})

        assert report.total_skills_scanned == 1
        assert report.total_findings == 1
        assert len(report.skills_skipped) == 1


# ============================================================================
# Multi-skill summary with skipped skills
# ============================================================================


class TestMultiSkillSummary:
    def test_summary_includes_skipped_count(self):
        from skill_scanner.cli.cli import _generate_multi_skill_summary

        report = Report()
        report.add_scan_result(ScanResult(skill_name="good", skill_directory="/tmp/good"))
        report.skills_skipped.append({"skill": "/tmp/bad", "reason": "missing name"})

        summary = _generate_multi_skill_summary(report)
        assert "Skills Skipped: 1" in summary
        assert "Skipped Skills:" in summary
        assert "/tmp/bad" in summary

    def test_summary_omits_skipped_when_none(self):
        from skill_scanner.cli.cli import _generate_multi_skill_summary

        report = Report()
        report.add_scan_result(ScanResult(skill_name="good", skill_directory="/tmp/good"))

        summary = _generate_multi_skill_summary(report)
        assert "Skipped" not in summary


# ============================================================================
# Scanner scan_directory tracks skipped skills
# ============================================================================


class TestScanDirectorySkipped:
    def test_malformed_skill_tracked_in_skipped(self, tmp_path):
        good_dir = tmp_path / "good-skill"
        _write_skill_md(
            good_dir,
            """\
            ---
            name: good
            description: A good skill
            ---
            # Hello
            """,
        )

        bad_dir = tmp_path / "bad-skill"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text(
            "---\nlicense: MIT\n---\nbody\n",
            encoding="utf-8",
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner()
        report = scanner.scan_directory(tmp_path)

        assert report.total_skills_scanned == 1
        assert len(report.skills_skipped) == 1
        assert "bad-skill" in report.skills_skipped[0]["skill"]

    def test_malformed_skill_loaded_in_lenient(self, tmp_path):
        good_dir = tmp_path / "good-skill"
        _write_skill_md(
            good_dir,
            """\
            ---
            name: good
            description: A good skill
            ---
            # Hello
            """,
        )

        bad_dir = tmp_path / "bad-skill"
        _write_skill_md(
            bad_dir,
            """\
            ---
            license: MIT
            ---
            body
            """,
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner()
        report = scanner.scan_directory(tmp_path, lenient=True)

        assert report.total_skills_scanned == 2
        assert len(report.skills_skipped) == 0


# ============================================================================
# Pre-commit hook: get_affected_skills improvements
# ============================================================================


class TestPrecommitGetAffectedSkills:
    def test_detects_skill_under_configured_path(self, tmp_path):
        from skill_scanner.hooks.pre_commit import get_affected_skills

        skills_root = tmp_path / ".cursor" / "skills" / "my-skill"
        _write_skill_md(
            skills_root,
            """\
            ---
            name: my-skill
            description: test
            ---
            # body
            """,
        )

        staged = [".cursor/skills/my-skill/scripts/run.py"]
        with patch("pathlib.Path.exists", return_value=True):
            result = get_affected_skills(staged, ".cursor/skills")
        assert len(result) >= 1

    def test_detects_skill_by_walking_up(self, tmp_path):
        from skill_scanner.hooks.pre_commit import get_affected_skills

        skill_dir = tmp_path / "custom" / "my-skill"
        _write_skill_md(
            skill_dir,
            """\
            ---
            name: my-skill
            description: test
            ---
            # body
            """,
        )

        staged = [str(skill_dir / "scripts" / "run.py")]
        result = get_affected_skills(staged, ".claude/skills")
        skill_paths = [str(p) for p in result]
        assert any("my-skill" in p for p in skill_paths)

    def test_empty_staged_returns_nothing(self):
        from skill_scanner.hooks.pre_commit import get_affected_skills

        result = get_affected_skills([], ".cursor/skills")
        assert result == set()

    def test_file_outside_skills_ignored(self, tmp_path):
        from skill_scanner.hooks.pre_commit import get_affected_skills

        staged = ["README.md", "src/main.py"]
        result = get_affected_skills(staged, ".cursor/skills")
        assert result == set()


# ============================================================================
# CLI --lenient flag registration
# ============================================================================


class TestCLILenientFlag:
    def test_lenient_flag_registered_on_scan(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp/skill", "--lenient"])
        assert args.lenient is True

    def test_lenient_flag_registered_on_scan_all(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan-all", "/tmp/skills", "--lenient"])
        assert args.lenient is True

    def test_lenient_defaults_to_false(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp/skill"])
        assert args.lenient is False
