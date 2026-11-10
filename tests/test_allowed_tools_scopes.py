# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Scoped tool declarations must not become false allowed-tools violations."""

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Skill, SkillFile, SkillManifest
from skill_scanner.data.packs.core.python.allowed_tools_checks import check_allowed_tools_violations, declares_bash_tool


@pytest.mark.parametrize(
    ("allowed_tools", "expect_violation"),
    [
        (["Bash"], False),
        (["Read", "Bash(scripts/cli:*)"], False),
        (["bash(scripts/cli:*)"], False),
        (["Read"], True),
        (["Bash()"], True),
        (["NotBash(scripts/cli:*)"], True),
        (["Bash(scripts/cli:*)extra"], True),
        (["Bash((scripts/cli:*))"], True),
        (["Bash(scripts/cli\\):*)"], True),
        (["Bash(scripts/cli:*)\nWrite"], True),
        (["Bash(\x00)"], True),
        (["Bash(scripts/cli\x1b:*)"], True),
        (["Bash(scripts/cli\x7f:*)"], True),
        (['Bash("echo a,b")'], False),
    ],
)
def test_bash_declaration_in_active_and_extracted_checks(
    tmp_path: Path, allowed_tools: list[str], expect_violation: bool
) -> None:
    skill = Skill(
        directory=tmp_path,
        manifest=SkillManifest(name="tool-test", description="Test tool declaration", allowed_tools=allowed_tools),
        skill_md_path=tmp_path / "SKILL.md",
        instruction_body="Run the included script.",
        files=[
            SkillFile(
                path=tmp_path / "scripts" / "cli.sh",
                relative_path="scripts/cli.sh",
                file_type="bash",
                content="echo ready\n",
            )
        ],
    )

    active = StaticAnalyzer()._check_allowed_tools_violations(skill)
    extracted = check_allowed_tools_violations(skill)
    for findings in (active, extracted):
        assert ("ALLOWED_TOOLS_BASH_VIOLATION" in {finding.rule_id for finding in findings}) is expect_violation


@pytest.mark.parametrize(
    ("tool_name", "rule_id", "file_type", "content"),
    [
        ("Read", "ALLOWED_TOOLS_READ_VIOLATION", "python", 'open("data.txt", "r")\n'),
        ("Write", "ALLOWED_TOOLS_WRITE_VIOLATION", "python", 'open("data.txt", "w")\n'),
        ("Grep", "ALLOWED_TOOLS_GREP_VIOLATION", "python", 're.search("x", "y")\n'),
        ("Glob", "ALLOWED_TOOLS_GLOB_VIOLATION", "python", 'glob.glob("*.txt")\n'),
    ],
)
def test_other_scoped_declarations_do_not_suppress_existing_checks(
    tmp_path: Path, tool_name: str, rule_id: str, file_type: str, content: str
) -> None:
    skill = Skill(
        directory=tmp_path,
        manifest=SkillManifest(
            name="tool-test", description="Test scoped tool declaration", allowed_tools=[f"{tool_name}(scripts/cli:*)"]
        ),
        skill_md_path=tmp_path / "SKILL.md",
        instruction_body="Run the included script.",
        files=[SkillFile(tmp_path / "scripts" / "cli", "scripts/cli", file_type, content)],
    )

    assert rule_id in {finding.rule_id for finding in StaticAnalyzer()._check_allowed_tools_violations(skill)}
    assert rule_id in {finding.rule_id for finding in check_allowed_tools_violations(skill)}


def test_scalar_allowed_tools_keeps_commas_inside_scopes() -> None:
    manifest = SkillManifest(
        name="tool-test",
        description="Test scalar tool list",
        allowed_tools="Bash(scripts/cli --arg a,b), Read",
    )

    assert manifest.allowed_tools == ["Bash(scripts/cli --arg a,b)", "Read"]
    assert declares_bash_tool(manifest.allowed_tools)


def test_space_separated_tools_keep_scoped_command_together() -> None:
    manifest = SkillManifest(
        name="tool-test",
        description="Test space-separated tool list",
        allowed_tools="Read Bash(scripts/cli --arg a,b) Grep",
    )

    assert manifest.allowed_tools == ["Read", "Bash(scripts/cli --arg a,b)", "Grep"]
