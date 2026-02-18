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

"""Tests for the strict Agent Skills directory validator."""

import pytest

from skill_scanner.core.exceptions import SkillValidationError
from skill_scanner.core.strict_structure import (
    SkillValidator,
    ValidationErrorCode,
    ValidationResult,
    validate_skill,
    validate_skill_or_raise,
)

MINIMAL_FRONTMATTER = """\
---
name: "{name}"
description: "A test skill"
---
# Instructions
"""


def _write_skill_md(skill_dir, name=None, content=None):
    """Helper to write a SKILL.md with valid frontmatter."""
    if name is None:
        name = skill_dir.name
    if content is None:
        content = MINIMAL_FRONTMATTER.format(name=name)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")


def _make_valid_skill(tmp_path, name="my-skill"):
    """Create a minimal valid skill directory."""
    skill_dir = tmp_path / name
    skill_dir.mkdir()
    _write_skill_md(skill_dir)
    return skill_dir


# ---------------------------------------------------------------------------
# Directory checks
# ---------------------------------------------------------------------------


class TestDirectoryChecks:
    def test_nonexistent_directory(self, tmp_path):
        result = SkillValidator().validate(tmp_path / "nope")
        # Returns early, no errors (directory doesn't exist)
        assert result.is_valid

    def test_not_a_directory(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hi")
        result = SkillValidator().validate(f)
        assert result.is_valid  # returns early

    def test_valid_minimal_skill(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid

    def test_valid_with_all_subdirs(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        for sub in ("scripts", "references", "assets"):
            (skill_dir / sub).mkdir()
            (skill_dir / sub / "file.py").write_text("# ok")
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid


# ---------------------------------------------------------------------------
# Structure checks
# ---------------------------------------------------------------------------


class TestStructureChecks:
    def test_disallowed_top_level_dir(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "lib").mkdir()
        (skill_dir / "lib" / "util.py").write_text("# bad")
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.DISALLOWED_DIRECTORY in codes

    def test_nested_subdirs_within_allowed_pass(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        nested = skill_dir / "scripts" / "utils"
        nested.mkdir(parents=True)
        (nested / "helper.py").write_text("# fine")
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid

    def test_disallowed_extension(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "malware.exe").write_text("bad")
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.DISALLOWED_FILE_EXTENSION in codes

    def test_hidden_file_rejected(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / ".secret").write_text("hidden")
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.HIDDEN_FILE in codes

    def test_hidden_dir_rejected(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        hidden = skill_dir / ".hidden"
        hidden.mkdir()
        (hidden / "file.py").write_text("# sneaky")
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.HIDDEN_FILE in codes

    def test_symlink_file_rejected(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        target = tmp_path / "outside.md"
        target.write_text("external")
        (skill_dir / "link.md").symlink_to(target)
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.SYMLINK in codes

    def test_symlink_dir_rejected(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        target_dir = tmp_path / "external"
        target_dir.mkdir()
        (target_dir / "secret.py").write_text("# secret")
        (skill_dir / "scripts").symlink_to(target_dir)
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.SYMLINK in codes

    def test_root_level_allowed_extensions(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "helper.py").write_text("# ok")
        (skill_dir / "run.sh").write_text("#!/bin/bash")
        (skill_dir / "config.json").write_text("{}")
        (skill_dir / "settings.yaml").write_text("key: val")
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid


# ---------------------------------------------------------------------------
# Encoding checks
# ---------------------------------------------------------------------------


class TestEncodingChecks:
    def test_valid_utf8_passes(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "notes.md").write_text("Hello 🌍", encoding="utf-8")
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid

    def test_latin1_rejected(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "bad.md").write_bytes(b"caf\xe9")  # latin-1 é
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.FILE_NOT_UTF8 in codes

    def test_null_bytes_rejected(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "binary.py").write_bytes(b"print('hi')\x00\x00")
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.BINARY_CONTENT in codes

    def test_empty_file_passes(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        (skill_dir / "empty.md").write_text("")
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid


# ---------------------------------------------------------------------------
# SKILL.md presence
# ---------------------------------------------------------------------------


class TestSkillMdPresence:
    def test_missing_skill_md(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.MISSING_SKILL_MD in codes

    def test_wrong_case_skill_md(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "skill.md").write_text("---\nname: my-skill\ndescription: x\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.MISSING_SKILL_MD in codes


# ---------------------------------------------------------------------------
# Frontmatter validation
# ---------------------------------------------------------------------------


class TestFrontmatterValidation:
    def test_missing_name(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\ndescription: hi\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.MISSING_REQUIRED_FIELD in codes

    def test_missing_description(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: my-skill\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.MISSING_REQUIRED_FIELD in codes

    def test_name_too_long(self, tmp_path):
        skill_dir = tmp_path / "a"
        skill_dir.mkdir()
        long_name = "a" * 65
        (skill_dir / "SKILL.md").write_text(f"---\nname: {long_name}\ndescription: hi\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.NAME_LENGTH_OUT_OF_RANGE in codes

    def test_name_uppercase_rejected(self, tmp_path):
        skill_dir = tmp_path / "MySkill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: MySkill\ndescription: hi\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.NAME_INVALID_FORMAT in codes

    def test_name_consecutive_hyphens_rejected(self, tmp_path):
        skill_dir = tmp_path / "my--skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: my--skill\ndescription: hi\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.NAME_INVALID_FORMAT in codes

    def test_name_leading_hyphen_rejected(self, tmp_path):
        skill_dir = tmp_path / "-bad"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text('---\nname: "-bad"\ndescription: hi\n---\n')
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.NAME_INVALID_FORMAT in codes

    def test_name_dir_mismatch(self, tmp_path):
        skill_dir = tmp_path / "actual-dir"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: other-name\ndescription: hi\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.NAME_DIR_MISMATCH in codes

    def test_single_char_name_valid(self, tmp_path):
        skill_dir = tmp_path / "x"
        skill_dir.mkdir()
        _write_skill_md(skill_dir, name="x")
        result = SkillValidator().validate(skill_dir)
        assert result.is_valid

    def test_description_whitespace_only(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text('---\nname: my-skill\ndescription: "   "\n---\n')
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.DESCRIPTION_EMPTY in codes

    def test_description_too_long(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        long_desc = "x" * 1025
        (skill_dir / "SKILL.md").write_text(f'---\nname: my-skill\ndescription: "{long_desc}"\n---\n')
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.DESCRIPTION_TOO_LONG in codes

    def test_compatibility_too_long(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        long_compat = "x" * 501
        (skill_dir / "SKILL.md").write_text(
            f'---\nname: my-skill\ndescription: ok\ncompatibility: "{long_compat}"\n---\n'
        )
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.COMPATIBILITY_TOO_LONG in codes

    def test_metadata_not_dict(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: my-skill\ndescription: ok\nmetadata: not-a-dict\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.FRONTMATTER_PARSE_ERROR in codes

    def test_malformed_yaml(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\n: :\n  - {\n---\n")
        result = SkillValidator().validate(skill_dir)
        codes = [e.code for e in result.errors]
        assert ValidationErrorCode.FRONTMATTER_PARSE_ERROR in codes


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_multiple_errors_accumulated(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        # No SKILL.md, hidden file, bad extension
        (skill_dir / ".hidden").write_text("x")
        (skill_dir / "bad.exe").write_text("x")
        result = SkillValidator().validate(skill_dir)
        assert not result.is_valid
        assert len(result.errors) >= 3  # hidden + extension + missing SKILL.md

    def test_to_dict_serialization(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        result = SkillValidator().validate(skill_dir)
        d = result.to_dict()
        assert d["is_valid"] is True
        assert d["errors"] == []
        assert "skill_directory" in d

    def test_to_dict_with_errors(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        result = SkillValidator().validate(skill_dir)
        d = result.to_dict()
        assert d["is_valid"] is False
        assert len(d["errors"]) > 0
        assert "code" in d["errors"][0]
        assert "message" in d["errors"][0]

    def test_convenience_validate_skill(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        result = validate_skill(skill_dir)
        assert isinstance(result, ValidationResult)
        assert result.is_valid

    def test_convenience_validate_skill_or_raise_valid(self, tmp_path):
        skill_dir = _make_valid_skill(tmp_path)
        result = validate_skill_or_raise(skill_dir)
        assert result.is_valid

    def test_convenience_validate_skill_or_raise_invalid(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        with pytest.raises(SkillValidationError, match="validation failed"):
            validate_skill_or_raise(skill_dir)
