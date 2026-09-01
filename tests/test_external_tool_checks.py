# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Direct regression tests for extracted external-tool checks."""

from pathlib import Path

import pytest

from skill_scanner.core.models import Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.data.packs.core.python.external_tool_checks import check_homoglyph_attacks


def _script_skill(content: str, file_type: str) -> Skill:
    suffix = ".py" if file_type == "python" else ".sh"
    path = Path(f"/nonexistent/issue-165/script{suffix}")
    return Skill(
        directory=path.parent,
        manifest=SkillManifest(name="issue-165", description="Regression fixture"),
        skill_md_path=path.parent / "SKILL.md",
        instruction_body="# Issue 165 regression fixture",
        files=[
            SkillFile(
                path=path,
                relative_path=path.name,
                file_type=file_type,
                content=content,
                size_bytes=len(content.encode()),
            )
        ],
    )


def _homoglyph_findings(content: str, file_type: str):
    findings = check_homoglyph_attacks(_script_skill(content, file_type), ScanPolicy.default())
    return [finding for finding in findings if finding.rule_id == "HOMOGLYPH_ATTACK"]


@pytest.mark.parametrize(
    ("file_type", "content"),
    [
        (
            "python",
            "COLUMNS = [\n"
            '    ("calendar_uid", "TEXT"),  # идентификатор календаря в своём источнике\n'
            '    ("calendar_account", "TEXT"),  # аккаунт Outlook (у Apple пуст)\n'
            '    ("event_uid", "TEXT"),  # UID из iCalendar; общий для всей серии\n'
            '    ("recurrence_id", "TEXT"),  # RECURRENCE-ID вхождения; переживает перенос\n'
            '    ("all_day", "INTEGER"),  # NULL = неизвестно, 0/1 = знание\n'
            "]\n",
        ),
        (
            "bash",
            'one=("value")  # описание первого значения\n'
            'two=("value")  # описание второго значения\n'
            'three=("value")  # описание третьего значения\n'
            'four=("value")  # описание четвёртого значения\n'
            'five=("value")  # описание пятого значения\n',
        ),
    ],
)
def test_trailing_comments_do_not_trigger_modular_homoglyph_check(file_type: str, content: str) -> None:
    assert not _homoglyph_findings(content, file_type)


@pytest.mark.parametrize("file_type", ["python", "bash"])
def test_quoted_hash_does_not_hide_spoofed_identifier(file_type: str) -> None:
    """A quoted hash stays code while the genuine trailing comment is removed."""
    cyrillic_a = "\u0430"
    if file_type == "python":
        content = "".join(
            f'marker = "# value"; p{cyrillic_a}yload_{index} = read_input()  # обычный комментарий\n'
            for index in range(5)
        )
    else:
        content = "".join(
            f'echo "# value"; p{cyrillic_a}yload_{index}=input  # обычный комментарий\n' for index in range(5)
        )

    assert _homoglyph_findings(content, file_type)


def test_ansi_c_hash_does_not_hide_spoofed_identifier() -> None:
    """ANSI-C escaped quotes keep literal hashes inside the quoted token."""
    cyrillic_a = "\u0430"
    content = "".join(
        f"label=$'can\\'t # literal'; p{cyrillic_a}yload_{index}=input  # комментарий\n" for index in range(5)
    )

    assert _homoglyph_findings(content, "bash")


def test_multiline_bash_quote_hash_does_not_hide_spoofed_identifier() -> None:
    """Bash quote state is shared across physical lines in modular checks."""
    cyrillic_a = "\u0430"
    content = "".join(
        f'message_{index}="first line\n# literal"; p{cyrillic_a}yload_{index}=input  # комментарий\n'
        for index in range(5)
    )

    assert _homoglyph_findings(content, "bash")
