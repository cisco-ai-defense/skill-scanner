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
Unit tests for skill loader.
"""

from pathlib import Path

import pytest

from skill_scanner.core.loader import SkillLoader, SkillLoadError


@pytest.fixture
def example_skills_dir():
    """Get path to example skills directory."""
    return Path(__file__).parent.parent / "evals" / "test_skills"


@pytest.fixture
def loader():
    """Create a skill loader instance."""
    return SkillLoader()


def test_load_safe_calculator(loader, example_skills_dir):
    """Test loading the safe formatter skill."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    assert skill.name == "simple-formatter"
    assert "format" in skill.description.lower()
    assert skill.manifest.license == "MIT"
    assert len(skill.files) > 0

    # Check that Python file was discovered
    python_files = [f for f in skill.files if f.file_type == "python"]
    assert len(python_files) > 0


def test_load_malicious_skill(loader, example_skills_dir):
    """Test loading a malicious skill (should load without error)."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    assert skill.name == "data-exfiltrator"
    assert len(skill.files) > 0


def test_load_nonexistent_skill(loader, tmp_path):
    """Test loading a non-existent skill directory."""
    with pytest.raises(SkillLoadError):
        loader.load_skill(tmp_path / "nonexistent")


def test_load_directory_without_skill_md(loader, tmp_path):
    """Test loading a directory without SKILL.md."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    with pytest.raises(SkillLoadError):
        loader.load_skill(empty_dir)


def test_skill_file_discovery(loader, example_skills_dir):
    """Test that skill files are properly discovered."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    # Should have SKILL.md and formatter.py
    assert len(skill.files) >= 2

    # Check file types are correctly identified
    file_types = [f.file_type for f in skill.files]
    assert "markdown" in file_types
    assert "python" in file_types


def test_manifest_parsing(loader, example_skills_dir):
    """Test YAML frontmatter parsing."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    assert skill.manifest.name == "simple-formatter"
    assert skill.manifest.description is not None
    assert skill.manifest.license == "MIT"
    assert skill.manifest.allowed_tools is not None
    assert isinstance(skill.manifest.allowed_tools, list)


def test_allowed_tools_comma_separated_string_is_split(loader, tmp_path):
    """Agent skill docs often show allowed-tools as a comma-separated string."""
    skill_dir = tmp_path / "comma-tools-skill"
    skill_dir.mkdir()

    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: comma-tools-skill\n"
        "description: Test skill for allowed-tools parsing.\n"
        "allowed-tools: Read, Grep, Glob\n"
        "---\n"
        "\n"
        "# Comma Tools Skill\n",
        encoding="utf-8",
    )

    skill = loader.load_skill(skill_dir)
    assert skill.manifest.allowed_tools == ["Read", "Grep", "Glob"]


def test_instruction_body_extraction(loader, example_skills_dir):
    """Test extraction of instruction body."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    # Instruction body should contain the content after frontmatter
    assert len(skill.instruction_body) > 0
    assert "Formatter" in skill.instruction_body or "format" in skill.instruction_body.lower()


def test_skill_discovery_under_dot_claude_directory(loader, tmp_path):
    """
    Project skills may live under `.claude/skills/<skill>/` or similar hidden directories.
    Ensure our loader discovers files even when parent dirs are hidden.
    """
    skill_dir = tmp_path / ".claude" / "skills" / "my-skill"
    skill_dir.mkdir(parents=True)

    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: my-skill\n"
        "description: A test skill that proves file discovery works under .claude.\n"
        "allowed-tools: [Read]\n"
        "---\n"
        "\n"
        "# My Skill\n"
        "\n"
        "See [helper.py](helper.py).\n",
        encoding="utf-8",
    )
    (skill_dir / "helper.py").write_text("print('hello')\n", encoding="utf-8")

    skill = loader.load_skill(skill_dir)

    # Must discover SKILL.md + helper.py even under hidden parent dir
    rel_paths = sorted([f.relative_path for f in skill.files])
    assert "SKILL.md" in rel_paths
    assert "helper.py" in rel_paths


def test_codex_skills_metadata_short_description(loader, tmp_path):
    """Test Codex Skills format with metadata.short-description."""
    skill_dir = tmp_path / "codex-skill"
    skill_dir.mkdir()

    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: codex-skill\n"
        "description: Description that helps Codex select the skill\n"
        "metadata:\n"
        "  short-description: Optional user-facing description\n"
        "license: MIT\n"
        "---\n"
        "\n"
        "# Codex Skill\n"
        "\n"
        "This is a Codex Skills format skill.\n",
        encoding="utf-8",
    )

    skill = loader.load_skill(skill_dir)

    # Verify basic fields
    assert skill.manifest.name == "codex-skill"
    assert skill.manifest.description == "Description that helps Codex select the skill"
    assert skill.manifest.license == "MIT"

    # Verify metadata.short-description is accessible
    assert skill.manifest.metadata is not None
    assert skill.manifest.metadata.get("short-description") == "Optional user-facing description"
    assert skill.manifest.short_description == "Optional user-facing description"


def test_codex_skills_directory_structure(loader, tmp_path):
    """Test that Codex Skills directories (scripts/, references/, assets/) are discovered."""
    skill_dir = tmp_path / "codex-structured-skill"
    skill_dir.mkdir()

    # Create SKILL.md
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: structured-skill\n"
        "description: A skill with Codex Skills directory structure\n"
        "---\n"
        "\n"
        "# Structured Skill\n",
        encoding="utf-8",
    )

    # Create scripts/ directory
    (skill_dir / "scripts").mkdir()
    (skill_dir / "scripts" / "main.py").write_text("print('hello')\n", encoding="utf-8")

    # Create references/ directory
    (skill_dir / "references").mkdir()
    (skill_dir / "references" / "data.json").write_text('{"key": "value"}\n', encoding="utf-8")

    # Create assets/ directory
    (skill_dir / "assets").mkdir()
    (skill_dir / "assets" / "template.txt").write_text("Template content\n", encoding="utf-8")

    skill = loader.load_skill(skill_dir)

    # Verify all files are discovered
    rel_paths = {f.relative_path for f in skill.files}
    assert "SKILL.md" in rel_paths
    assert "scripts/main.py" in rel_paths
    assert "references/data.json" in rel_paths
    assert "assets/template.txt" in rel_paths

    # Verify file types
    file_types = {f.relative_path: f.file_type for f in skill.files}
    assert file_types["scripts/main.py"] == "python"
    assert file_types["references/data.json"] == "other"
    assert file_types["assets/template.txt"] == "other"
