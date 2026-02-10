# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for fail-closed analyzability scoring (Feature #10)."""

from pathlib import Path

import pytest

from skill_scanner.core.analyzability import compute_analyzability
from skill_scanner.core.models import Skill, SkillFile, SkillManifest


def _make_skill(tmp_path: Path, files: dict[str, tuple[str, str | None]]) -> Skill:
    """Create a skill with specified files.

    files: dict of relative_path -> (file_type, content_or_None_for_binary)
    """
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir(exist_ok=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text("---\nname: test\ndescription: Test\n---\n\n# Test\n")

    skill_files = []
    for rel_path, (file_type, content) in files.items():
        fp = skill_dir / rel_path
        fp.parent.mkdir(parents=True, exist_ok=True)
        if content is not None:
            fp.write_text(content)
            size = len(content.encode())
        else:
            fp.write_bytes(b"\x00" * 100)
            size = 100

        skill_files.append(
            SkillFile(
                path=fp,
                relative_path=rel_path,
                file_type=file_type,
                content=content,
                size_bytes=size,
            )
        )

    return Skill(
        directory=skill_dir,
        manifest=SkillManifest(name="test", description="Test"),
        skill_md_path=skill_md,
        instruction_body="# Test",
        files=skill_files,
    )


class TestAnalyzabilityScoring:
    """Test analyzability score computation."""

    def test_all_text_files_100_percent(self, tmp_path):
        """All text files should give 100% score."""
        skill = _make_skill(
            tmp_path,
            {
                "scripts/main.py": ("python", "print('hello')"),
                "scripts/setup.sh": ("bash", "echo hello"),
                "README.md": ("markdown", "# Readme"),
            },
        )
        report = compute_analyzability(skill)
        assert report.score == 100.0
        assert report.risk_level == "LOW"

    def test_binary_files_reduce_score(self, tmp_path):
        """Binary files should reduce score."""
        skill = _make_skill(
            tmp_path,
            {
                "scripts/main.py": ("python", "print('hello')"),
                "data/blob.bin": ("binary", None),
            },
        )
        report = compute_analyzability(skill)
        assert report.score < 100.0
        assert report.unanalyzable_files >= 1

    def test_inert_files_dont_reduce_score(self, tmp_path):
        """Image/font files are considered analyzable (inert)."""
        skill = _make_skill(
            tmp_path,
            {
                "scripts/main.py": ("python", "print('hello')"),
            },
        )
        # Add a PNG file
        png_path = skill.directory / "logo.png"
        png_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        skill.files.append(
            SkillFile(
                path=png_path,
                relative_path="logo.png",
                file_type="binary",
                size_bytes=108,
            )
        )

        report = compute_analyzability(skill)
        assert report.score == 100.0

    def test_empty_skill_100_percent(self, tmp_path):
        """Skill with no files should be 100%."""
        skill = _make_skill(tmp_path, {})
        report = compute_analyzability(skill)
        assert report.score == 100.0

    def test_risk_levels(self, tmp_path):
        """Test that risk levels are assigned correctly."""
        # All analyzable -> LOW
        skill = _make_skill(
            tmp_path,
            {
                "main.py": ("python", "x=1"),
            },
        )
        report = compute_analyzability(skill)
        assert report.risk_level == "LOW"

    def test_report_to_dict(self, tmp_path):
        """to_dict should contain expected fields."""
        skill = _make_skill(
            tmp_path,
            {
                "main.py": ("python", "x=1"),
                "blob.bin": ("binary", None),
            },
        )
        report = compute_analyzability(skill)
        d = report.to_dict()
        assert "score" in d
        assert "total_files" in d
        assert "risk_level" in d
        assert "unanalyzable_file_list" in d
