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

"""
Static pattern analyzer for detecting security vulnerabilities.
"""

import ast
import configparser
import hashlib
import logging
import pickletools
import re
import tomllib
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ...config.yara_modes import YaraModeConfig
from ...core.models import Finding, Severity, Skill, SkillFile, ThreatCategory
from ...core.rules.active_dynamic_execution import check_active_dynamic_execution
from ...core.rules.active_html_injection import check_active_hidden_html
from ...core.rules.active_remote_execution import check_active_remote_execution
from ...core.rules.active_semantic_directives import check_active_semantic_directives
from ...core.rules.core_signature_precision import refine_core_signature_findings
from ...core.rules.ooxml_relationships import (
    INCONCLUSIVE_MACRO_ANALYSIS,
    VBA_MACRO,
    XLM_MACRO,
    classify_oleid_macro_indicator,
)
from ...core.rules.patterns import (
    SIGNATURE_CONTEXT_KINDS,
    SIGNATURE_POLARITIES,
    RuleLoader,
    SecurityRule,
    SignatureScanContext,
)
from ...core.rules.unicode_smuggling import check_unicode_smuggling
from ...core.rules.yara_behavior_context import classify_yara_behavior_context
from ...core.rules.yara_scanner import YaraScanner
from ...core.scan_policy import ScanPolicy
from ...core.static_analysis.comment_stripping import comment_stripped_lines
from ...core.static_analysis.python_shell_semantics import find_python_shell_candidates
from ...core.static_analysis.url_classifier import classify_url, extract_urls
from ...data import DATA_DIR
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


# Pre-compiled regex patterns for file operation checks
_READ_PATTERNS = [
    re.compile(r"open\([^)]+['\"]r['\"]"),
    re.compile(r"\.read\("),
    re.compile(r"\.readline\("),
    re.compile(r"\.readlines\("),
    re.compile(r"Path\([^)]+\)\.read_text"),
    re.compile(r"Path\([^)]+\)\.read_bytes"),
    re.compile(r"with\s+open\([^)]+['\"]r"),
]

_WRITE_PATTERNS = [
    re.compile(r"open\([^)]+['\"]w['\"]"),
    re.compile(r"\.write\("),
    re.compile(r"\.writelines\("),
    re.compile(r"pathlib\.Path\([^)]+\)\.write"),
    re.compile(r"with\s+open\([^)]+['\"]w"),
]

_GREP_PATTERNS = [
    re.compile(r"re\.search\("),
    re.compile(r"re\.findall\("),
    re.compile(r"re\.match\("),
    re.compile(r"re\.finditer\("),
    re.compile(r"re\.sub\("),
    re.compile(r"grep"),
]

_GLOB_PATTERNS = [
    re.compile(r"glob\.glob\("),
    re.compile(r"glob\.iglob\("),
    re.compile(r"Path\([^)]*\)\.glob\("),
    re.compile(r"\.glob\("),
    re.compile(r"\.rglob\("),
    re.compile(r"fnmatch\."),
]
_SENSITIVE_PATH_LITERAL_RE = re.compile(
    r"(?i)(?:\.aws[/\\]credentials|\.ssh[/\\](?:id_[a-z0-9_]+|authorized_keys)|"
    r"\.(?:npmrc|gitconfig|gnupg|netrc|pgpass)|(?:^|[/\\])credentials?(?:[/\\]|$)|"
    r"(?:^|[/\\])secrets?(?:[/\\]|$))"
)
_OBFUSCATED_INSTRUCTION_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (
        re.compile(
            r"(?is)(?P<override_action>ignore)(?P<override_separator_one>\s+)"
            r"(?:(?P<override_all>all)(?P<override_separator_all>\s+))?"
            r"(?P<override_precedence>previous|prior|earlier)(?P<override_separator_two>\s+)"
            r"(?P<override_target>instructions?)"
        ),
        (
            "override_action",
            "override_separator_one",
            "override_all",
            "override_separator_all",
            "override_precedence",
            "override_separator_two",
            "override_target",
        ),
    ),
    (
        re.compile(
            r"(?is)(?P<mode_subject>you)(?P<mode_separator_one>\s+)"
            r"(?P<mode_state>are\s+now\s+in)(?P<mode_separator_two>\s+)"
            r"(?P<mode_name>developer|debug|unrestricted|admin)(?P<mode_separator_three>\s+)"
            r"(?P<mode_target>mode)"
        ),
        (
            "mode_subject",
            "mode_separator_one",
            "mode_state",
            "mode_separator_two",
            "mode_name",
            "mode_separator_three",
            "mode_target",
        ),
    ),
    (
        re.compile(
            r"(?is)(?P<access_action>read|collect|capture|harvest|exfiltrate).{0,160}"
            r"(?P<access_target>credentials?|tokens?|api\s*keys?|ssh|environment(?:\s+variables?)?|dotfiles?)"
        ),
        ("access_action", "access_target"),
    ),
    (
        re.compile(r"(?is)(?P<exfil_action>exfiltrate).{0,160}(?P<exfil_url>https?://)"),
        ("exfil_action", "exfil_url"),
    ),
    (
        re.compile(
            r"(?is)(?P<transfer_action>post|send|transmit).{0,160}"
            r"(?P<transfer_object>(?:(?:the\s+)?(?:collected|captured|harvested|retrieved|stolen|"
            r"sensitive|secret)\s+(?:data|information|credentials?|tokens?|api\s*keys?|"
            r"environment(?:\s+variables?)?)|credentials?|tokens?|api\s*keys?)).{0,160}"
            r"(?P<transfer_url>https?://)"
        ),
        ("transfer_action", "transfer_object", "transfer_url"),
    ),
)

_UNICODE_MAX_FILE_SOURCE_CHARS = 10 * 1024 * 1024
_UNICODE_MAX_FILE_WORK_UNITS = 2 * 1024 * 1024
_UNICODE_MAX_PACKAGE_WORK_UNITS = 8 * 1024 * 1024
_UNICODE_DECODE_CHUNK_CHARS = 64 * 1024
_UNICODE_DECODE_OVERLAP_CHARS = 512
_UNICODE_MAX_NFKC_EXPANSION = 4
_UNICODE_MAX_OUTPUT_FACTOR = 4
_UNICODE_MAX_MARKDOWN_LINES = 32_768
_UNICODE_MAX_FENCED_BLOCKS = 512
_UNICODE_MAX_MARKDOWN_REGIONS = 4_096
_UNICODE_HTML_COMMENT_SENTINEL = "\U000f0000"

_UNICODE_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_UNICODE_HEADING_RE = re.compile(r"^ {0,3}(?P<marks>#{1,6})[ \t]+(?P<title>.+?)\s*#*\s*$")
_UNICODE_SETEXT_RE = re.compile(r"^ {0,3}(?P<marks>=+|-+)[ \t]*$")
_UNICODE_BOLD_HEADING_RE = re.compile(r"^ {0,3}\*\*(?P<title>[^*\n]{1,128}?)\*\*\s*:?[ \t]*$")
_UNICODE_BLOCKQUOTE_RE = re.compile(r"^ {0,3}>")
_UNICODE_EXAMPLE_SECTION_RE = re.compile(
    r"\b(?:demos?|documentation|examples?|reference|samples?|testing|tutorials?)\b",
    re.IGNORECASE,
)
_UNICODE_NEGATIVE_SECTION_RE = re.compile(
    r"\b(?:anti[- ]?patterns?|bad|dangerous|do not use|insecure|mitigations?|negative|"
    r"prohibited|safety guidance|unsafe|what not to do)\b",
    re.IGNORECASE,
)
_UNICODE_INLINE_EXAMPLE_RE = re.compile(
    r"\b(?:e\.g\.|for example|for instance|illustrat(?:e|ion)|sample (?:code|payload|usage)|"
    r"test(?:ing)? (?:that )?(?:the )?scanner detects|test string|negative example|"
    r"(?:documentation|tests?|examples?|samples?)\s+(?:may\s+)?(?:quote|show|contain|use|detects?))\b",
    re.IGNORECASE,
)
_UNICODE_LABEL_EXAMPLE_RE = re.compile(
    r"^\s*(?:(?:[-*+]\s+)|(?:\d+[.)]\s+))?"
    r"(?:example(?:\s+payload)?|sample(?:\s+payload)?|test\s+case)\s*:",
    re.IGNORECASE,
)
_UNICODE_PROHIBITION_START_RE = re.compile(
    r"^\s*(?:(?:[-*+]\s+)|(?:\d+[.)]\s+))?"
    r"(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|forbid(?:den)?|prohibit(?:ed)?)\b",
    re.IGNORECASE,
)
_UNICODE_CONTRASTIVE_RE = re.compile(
    r"(?:[;!?]|&&|\|\||\b(?:but|except|however|instead|then|unless)\b)",
    re.IGNORECASE,
)
_UNICODE_NEGATIVE_FENCE_LEAD_RE = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|forbid(?:den)?|prohibit(?:ed)?)\b"
    r".{0,120}\b(?:code|commands?|examples?|following|scripts?|payload)\b",
    re.IGNORECASE,
)
_UNICODE_EXAMPLE_FENCE_LEAD_RE = re.compile(
    r"\b(?:example|illustration|sample|test)\b.{0,80}\b(?:code|commands?|following|scripts?|payload)\b",
    re.IGNORECASE,
)
_UNICODE_EXECUTABLE_FENCE_LANGUAGES = frozenset(
    {
        "bash",
        "cjs",
        "javascript",
        "js",
        "mjs",
        "node",
        "nodejs",
        "powershell",
        "ps1",
        "pwsh",
        "py",
        "python",
        "python3",
        "sh",
        "shell",
        "ts",
        "typescript",
        "zsh",
    }
)
_UNICODE_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


@dataclass(frozen=True, slots=True)
class _DecodedUnicodeText:
    """Decoded text with source provenance for every emitted character."""

    text: str
    encodings: frozenset[str]
    transformation_kinds: tuple[str | None, ...]
    source_offsets: tuple[int, ...]
    deleted_transformations: tuple["_DeletedUnicodeTransformation", ...]
    complete: bool


@dataclass(frozen=True, slots=True)
class _DeletedUnicodeTransformation:
    """A removed codepoint anchored to a boundary in decoded output."""

    kind: str
    source_offset: int
    output_offset: int


@dataclass(frozen=True, slots=True)
class _UnicodeScanRegion:
    """One source-contiguous active region with a physical starting line."""

    content: str
    start_line: int
    context_kind: str
    synthetic_elisions: frozenset[int] = frozenset()


def _unicode_section_kind(title: str) -> str:
    if _UNICODE_NEGATIVE_SECTION_RE.search(title):
        return "negative"
    if _UNICODE_EXAMPLE_SECTION_RE.search(title):
        return "example"
    return "active"


def _unicode_fence_language(tail: str) -> str:
    value = tail.strip()
    if not value:
        return ""
    token = value.split(maxsplit=1)[0].strip().lower()
    if token.startswith("{.") and token.endswith("}"):
        return token[2:-1]
    return token


def _unicode_fence_lead_is_inert(lead: str) -> bool:
    """Return whether an explicit example/prohibition lead owns a fence."""
    cues = [
        match
        for pattern in (_UNICODE_NEGATIVE_FENCE_LEAD_RE, _UNICODE_EXAMPLE_FENCE_LEAD_RE)
        if (match := pattern.search(lead)) is not None
    ]
    if not cues:
        return False
    cue = max(cues, key=lambda match: match.start())
    return _UNICODE_CONTRASTIVE_RE.search(lead, cue.start()) is None


def _unicode_mask_html_comments(line: str, *, inside_comment: bool) -> tuple[str, bool, frozenset[int]]:
    """Elide Markdown HTML-comment spans without changing source offsets.

    A default-ignorable placeholder is removed by the Unicode projector. That
    preserves source provenance while joining visible text split by a comment.
    """
    masked = list(line)
    placeholder = _UNICODE_HTML_COMMENT_SENTINEL
    elisions: set[int] = set()
    cursor = 0
    if not inside_comment and (line.startswith("    ") or line.startswith("\t")):
        return line, False, frozenset()

    def opener_is_literal(start: int) -> bool:
        backslashes = 0
        backslash_cursor = start - 1
        while backslash_cursor >= 0 and line[backslash_cursor] == "\\":
            backslashes += 1
            backslash_cursor -= 1
        if backslashes % 2:
            return True

        delimiter = 0
        code_cursor = 0
        while code_cursor < start:
            if line[code_cursor] != "`":
                code_cursor += 1
                continue
            run_end = code_cursor + 1
            while run_end < start and line[run_end] == "`":
                run_end += 1
            run_length = run_end - code_cursor
            if delimiter == 0:
                delimiter = run_length
            elif run_length == delimiter:
                delimiter = 0
            code_cursor = run_end
        return delimiter != 0

    while cursor < len(line):
        if inside_comment:
            end = line.find("-->", cursor)
            if end < 0:
                masked[cursor:] = placeholder * (len(line) - cursor)
                elisions.update(range(cursor, len(line)))
                return "".join(masked), True, frozenset(elisions)
            masked[cursor : end + 3] = placeholder * (end + 3 - cursor)
            elisions.update(range(cursor, end + 3))
            cursor = end + 3
            inside_comment = False
            continue

        start = line.find("<!--", cursor)
        if start < 0:
            break
        if opener_is_literal(start):
            cursor = start + 4
            continue
        end = line.find("-->", start + 4)
        if end < 0:
            masked[start:] = placeholder * (len(line) - start)
            elisions.update(range(start, len(line)))
            return "".join(masked), True, frozenset(elisions)
        masked[start : end + 3] = placeholder * (end + 3 - start)
        elisions.update(range(start, end + 3))
        cursor = end + 3
    return "".join(masked), inside_comment, frozenset(elisions)


def _unicode_blockquote_opens_lazy_paragraph(line: str) -> bool:
    """Approximate CommonMark lazy continuation only for quoted paragraphs."""
    marker = _UNICODE_BLOCKQUOTE_RE.match(line)
    if marker is None:
        return False
    body = line[marker.end() :].lstrip(" \t")
    if not body:
        return False
    return not (
        _UNICODE_HEADING_RE.match(body)
        or _UNICODE_FENCE_RE.match(body)
        or _UNICODE_SETEXT_RE.match(body)
        or _UNICODE_BLOCKQUOTE_RE.match(body)
    )


def _unicode_markdown_regions(content: str, *, line_offset: int = 0) -> list[_UnicodeScanRegion] | None:
    """Return bounded active prose and operational code-fence regions.

    Example/reference/negative heading subtrees, blockquotes, and inert fences
    are omitted. Parsing completes before any region is returned so a document
    that exceeds a structural bound cannot produce a partial HIGH result.
    """
    if len(content) > _UNICODE_MAX_FILE_SOURCE_CHARS:
        return None
    lines = content.split("\n")
    if len(lines) > _UNICODE_MAX_MARKDOWN_LINES:
        return None
    if lines and lines[0] == "---":
        closing_frontmatter = next(
            (index for index, line in enumerate(lines[1:257], start=1) if line in {"---", "..."}),
            None,
        )
        if closing_frontmatter is not None and any(
            re.match(r"^[A-Za-z0-9_-]{1,64}[ \t]*:", line) is not None for line in lines[1:closing_frontmatter]
        ):
            # Preserve physical line numbering while excluding a complete,
            # mapping-shaped YAML frontmatter block. An unclosed or ambiguous
            # delimiter remains active fail-open.
            lines[: closing_frontmatter + 1] = [""] * (closing_frontmatter + 1)

    regions: list[_UnicodeScanRegion] = []
    paragraph: list[str] = []
    paragraph_elisions: set[int] = set()
    paragraph_char_length = 0
    paragraph_start = 1
    heading_stack: list[tuple[int, str]] = []
    bold_section: str | None = None
    previous_nonempty = ""
    lazy_blockquote = False
    html_comment = False
    fence_character: str | None = None
    fence_length = 0
    fence_language = ""
    fence_section = "active"
    fence_start = 0
    fence_lines: list[str] = []
    fence_candidates = 0

    def current_section() -> str:
        if bold_section is not None:
            return bold_section
        return heading_stack[-1][1] if heading_stack else "active"

    def append_region(
        region_content: str,
        start_line: int,
        context_kind: str,
        synthetic_elisions: frozenset[int] = frozenset(),
    ) -> bool:
        if not region_content:
            return True
        if len(regions) >= _UNICODE_MAX_MARKDOWN_REGIONS:
            return False
        regions.append(
            _UnicodeScanRegion(
                region_content,
                line_offset + start_line,
                context_kind,
                synthetic_elisions,
            )
        )
        return True

    def finish_paragraph() -> bool:
        nonlocal paragraph, paragraph_char_length, paragraph_elisions
        ok = True
        if paragraph and current_section() == "active":
            ok = append_region(
                "\n".join(paragraph),
                paragraph_start,
                "active_instruction",
                frozenset(paragraph_elisions),
            )
        paragraph = []
        paragraph_elisions = set()
        paragraph_char_length = 0
        return ok

    def append_paragraph_line(value: str, elisions: frozenset[int]) -> None:
        nonlocal paragraph_char_length
        base = paragraph_char_length + (1 if paragraph else 0)
        paragraph.append(value)
        paragraph_elisions.update(base + offset for offset in elisions)
        paragraph_char_length = base + len(value)

    def finish_fence(*, malformed: bool = False) -> bool:
        nonlocal fence_lines
        ok = True
        if (fence_section == "active" or malformed) and fence_lines:
            ok = append_region("\n".join(fence_lines), fence_start + 1, "code")
        fence_lines = []
        return ok

    def enter_heading(level: int, title: str) -> None:
        nonlocal bold_section
        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        inherited = heading_stack[-1][1] if heading_stack else "active"
        direct = _unicode_section_kind(title)
        heading_stack.append((level, direct if direct != "active" else inherited))
        bold_section = None

    index = 0
    while index < len(lines):
        line_number = index + 1
        line = lines[index]
        structural_line = line[:-1] if line.endswith("\r") else line

        if fence_character is not None:
            fence_match = _UNICODE_FENCE_RE.match(structural_line)
            if fence_match is not None:
                marker = fence_match.group("marker")
                if (
                    marker[0] == fence_character
                    and len(marker) >= fence_length
                    and not fence_match.group("tail").strip(" \t\r")
                ):
                    if not finish_fence():
                        return None
                    fence_character = None
                    fence_length = 0
                    fence_language = ""
                    previous_nonempty = line
                    index += 1
                    continue
            fence_lines.append(line)
            index += 1
            continue

        structural_line, html_comment, line_elisions = _unicode_mask_html_comments(
            structural_line, inside_comment=html_comment
        )

        # Quoted headings/fences are inert and must not mutate parser state.
        if _UNICODE_BLOCKQUOTE_RE.match(structural_line):
            if not finish_paragraph():
                return None
            lazy_blockquote = _unicode_blockquote_opens_lazy_paragraph(structural_line)
            previous_nonempty = line
            index += 1
            continue

        fence_match = _UNICODE_FENCE_RE.match(structural_line)
        heading_match = _UNICODE_HEADING_RE.match(structural_line)
        bold_heading_match = _UNICODE_BOLD_HEADING_RE.match(structural_line)
        setext_match = (
            _UNICODE_SETEXT_RE.match(lines[index + 1].removesuffix("\r"))
            if index + 1 < len(lines) and structural_line.strip()
            else None
        )

        if lazy_blockquote:
            if not structural_line.strip():
                lazy_blockquote = False
                previous_nonempty = ""
                index += 1
                continue
            # A block construct interrupts CommonMark lazy quote continuation.
            if fence_match is None and heading_match is None and bold_heading_match is None and setext_match is None:
                index += 1
                continue
            lazy_blockquote = False

        if heading_match is not None:
            if not finish_paragraph():
                return None
            enter_heading(len(heading_match.group("marks")), heading_match.group("title"))
            if current_section() == "active" and not append_region(
                structural_line, line_number, "active_instruction", line_elisions
            ):
                return None
            previous_nonempty = line
            index += 1
            continue
        if setext_match is not None:
            if not finish_paragraph():
                return None
            enter_heading(1 if setext_match.group("marks")[0] == "=" else 2, structural_line.strip())
            if current_section() == "active" and not append_region(
                structural_line, line_number, "active_instruction", line_elisions
            ):
                return None
            previous_nonempty = line
            index += 2
            continue
        if bold_heading_match is not None:
            if not finish_paragraph():
                return None
            inherited = heading_stack[-1][1] if heading_stack else "active"
            direct = _unicode_section_kind(bold_heading_match.group("title"))
            bold_section = direct if direct != "active" else inherited
            if current_section() == "active" and not append_region(
                structural_line, line_number, "active_instruction", line_elisions
            ):
                return None
            previous_nonempty = line
            index += 1
            continue

        if fence_match is not None:
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            # Backticks in a backtick info string are invalid. Treat that
            # malformed line as active prose rather than opening a fence.
            if marker[0] != "`" or "`" not in tail:
                if not finish_paragraph():
                    return None
                fence_candidates += 1
                if fence_candidates > _UNICODE_MAX_FENCED_BLOCKS:
                    return None
                fence_character = marker[0]
                fence_length = len(marker)
                fence_language = _unicode_fence_language(tail)
                fence_section = current_section()
                if fence_section == "active" and _unicode_fence_lead_is_inert(previous_nonempty):
                    fence_section = "negative"
                fence_start = line_number
                fence_lines = []
                previous_nonempty = line
                index += 1
                continue

        if not structural_line.strip():
            # Preserve active paragraph continuity across blank lines. Decoded
            # whitespace is canonicalized later, so an attacker cannot split a
            # required token sequence with an arbitrary blank run.
            if paragraph and current_section() == "active":
                append_paragraph_line(structural_line, line_elisions)
            else:
                if not finish_paragraph():
                    return None
                paragraph_start = line_number + 1
            previous_nonempty = ""
            index += 1
            continue
        if not paragraph:
            paragraph_start = line_number
        append_paragraph_line(structural_line, line_elisions)
        previous_nonempty = structural_line
        index += 1

    if fence_character is not None:
        # An unclosed fence is malformed, so retain its content fail-open even
        # when an example-like lead would suppress a properly closed fixture.
        if not finish_fence(malformed=True):
            return None
    elif not finish_paragraph():
        return None
    return regions


def _unicode_bounded_chunks(region: _UnicodeScanRegion) -> Iterator[tuple[str, int]]:
    """Yield bounded source slabs and their offsets within a region."""
    content = region.content
    if len(content) <= _UNICODE_DECODE_CHUNK_CHARS:
        yield content, 0
        return

    cursor = 0
    while cursor < len(content):
        end = min(len(content), cursor + _UNICODE_DECODE_CHUNK_CHARS)
        yield content[cursor:end], cursor
        cursor = end


def _unicode_collapse_whitespace(
    text: str,
    kinds: tuple[str | None, ...],
    source_offsets: tuple[int, ...],
    deleted: tuple[_DeletedUnicodeTransformation, ...],
) -> tuple[
    str,
    tuple[str | None, ...],
    tuple[int, ...],
    tuple[_DeletedUnicodeTransformation, ...],
]:
    """Collapse Unicode whitespace runs while retaining aligned provenance."""
    if not text or len(kinds) != len(text) or len(source_offsets) != len(text):
        return text, kinds, source_offsets, deleted

    output: list[str] = []
    output_kinds: list[str | None] = []
    output_sources: list[int] = []
    boundary_map = [0] * (len(text) + 1)
    cursor = 0
    while cursor < len(text):
        boundary_map[cursor] = len(output)
        if not text[cursor].isspace():
            output.append(text[cursor])
            output_kinds.append(kinds[cursor])
            output_sources.append(source_offsets[cursor])
            cursor += 1
            boundary_map[cursor] = len(output)
            continue

        end = cursor + 1
        while end < len(text) and text[end].isspace():
            end += 1
        transformed = next((index for index in range(cursor, end) if kinds[index] is not None), cursor)
        output.append(" ")
        output_kinds.append(kinds[transformed])
        output_sources.append(source_offsets[transformed])
        for boundary in range(cursor + 1, end + 1):
            boundary_map[boundary] = len(output)
        cursor = end

    remapped_deleted = tuple(
        _DeletedUnicodeTransformation(
            item.kind,
            item.source_offset,
            boundary_map[min(max(item.output_offset, 0), len(text))],
        )
        for item in deleted
    )
    return "".join(output), tuple(output_kinds), tuple(output_sources), remapped_deleted


def _unicode_match_is_inert_context(content: str, source_start: int, source_end: int) -> bool:
    """Classify only the local clause leading into a decoded match."""
    prefix_start = max(0, source_start - 1_024)
    prefix = content[prefix_start:source_start]
    # A newline normally ends local scope. Carry exactly one explicit lead
    # ending in a colon so ``For example:\n...`` and ``Never follow:\n...``
    # remain inert without allowing distant prose to suppress a finding.
    last_newline = prefix.rfind("\n")
    if last_newline >= 0:
        previous_line = prefix[:last_newline].rsplit("\n", 1)[-1]
        current_line = prefix[last_newline + 1 :]
        carries_cue = previous_line.rstrip().endswith(":") and (
            _UNICODE_INLINE_EXAMPLE_RE.search(previous_line) is not None
            or _UNICODE_LABEL_EXAMPLE_RE.search(previous_line) is not None
            or _UNICODE_PROHIBITION_START_RE.search(previous_line) is not None
        )
        prefix = f"{previous_line}\n{current_line}" if carries_cue else current_line

    # A completed sentence ends the scope of an earlier cue. A colon
    # deliberately does not: ``Never follow this string: ...``.
    boundaries = list(re.finditer(r"[.!?][\"')\]]{0,2}[ \t]+", prefix))
    if boundaries:
        prefix = prefix[boundaries[-1].end() :]

    examples = [
        match
        for pattern in (_UNICODE_INLINE_EXAMPLE_RE, _UNICODE_LABEL_EXAMPLE_RE)
        if (match := pattern.search(prefix)) is not None
    ]
    example = max(examples, key=lambda candidate: candidate.start()) if examples else None
    prohibition = _UNICODE_PROHIBITION_START_RE.search(prefix)
    if example is None and prohibition is None:
        return False

    cue: re.Match[str]
    cue_is_prohibition: bool
    if example is not None and (prohibition is None or example.start() > prohibition.start()):
        cue = example
        cue_is_prohibition = False
    else:
        assert prohibition is not None
        cue = prohibition
        cue_is_prohibition = True
    if _UNICODE_CONTRASTIVE_RE.search(prefix, cue.end()) is not None:
        return False

    if cue_is_prohibition:
        tail = content[source_end : min(len(content), source_end + 512)]
        tail_boundary = re.search(r"[.]?[\"')\]]?[ \t]*(?:\n|$)", tail)
        if tail_boundary is not None:
            tail = tail[: tail_boundary.start()]
        if _UNICODE_CONTRASTIVE_RE.search(tail) is not None:
            return False
    return True


def _unicode_code_match_is_inert_context(content: str, source_start: int, source_end: int) -> bool:
    """Apply example/prohibition scope only inside an actual code comment."""
    line_start = content.rfind("\n", 0, source_start) + 1
    line_end = content.find("\n", source_end)
    if line_end < 0:
        line_end = len(content)
    line = content[line_start:line_end]

    line_comment = re.match(r"^[ \t]*(?P<marker>//+|\#+)[ \t]*", line)
    if line_comment is not None and source_start >= line_start + line_comment.end():
        comment_start = line_start + line_comment.end()
        comment_content = content[comment_start:line_end]
        relative_start = source_start - comment_start
        relative_end = source_end - comment_start

        # Carry one immediately preceding comment-only cue ending in a colon.
        previous_end = max(0, line_start - 1)
        previous_start = content.rfind("\n", 0, previous_end) + 1
        previous = content[previous_start:previous_end]
        previous_comment = re.match(r"^[ \t]*(?://+|\#+)[ \t]*(?P<body>.*)$", previous)
        if previous_comment is not None and previous_comment.group("body").rstrip().endswith(":"):
            lead = previous_comment.group("body")
            comment_content = f"{lead}\n{comment_content}"
            relative_start += len(lead) + 1
            relative_end += len(lead) + 1
        return _unicode_match_is_inert_context(comment_content, relative_start, relative_end)

    # Recognize a block comment only when its opener is line-leading. This
    # avoids treating comment-looking string literals as syntax while still
    # supporting ordinary multi-line documentation comments.
    prefix = content[:source_start]
    block_start = prefix.rfind("/*")
    block_end_before = prefix.rfind("*/")
    if block_start <= block_end_before:
        return False
    block_line_start = content.rfind("\n", 0, block_start) + 1
    if content[block_line_start:block_start].strip(" \t"):
        return False
    closing = content.find("*/", block_start + 2)
    if closing < 0 or source_end > closing:
        return False
    comment_start = block_start + 2
    comment_end = closing
    comment_content = content[comment_start:comment_end]
    return _unicode_match_is_inert_context(
        comment_content,
        source_start - comment_start,
        source_end - comment_start,
    )


def _unicode_slab_has_projection(text: str) -> bool:
    """Return whether a slab needs dense decoded provenance."""
    return any(_unicode_scalar_projection(character) is not None for character in set(text) if not character.isascii())


@lru_cache(maxsize=4_096)
def _bounded_ascii_nfkc(character: str) -> str | None:
    """Return a small wholly-ASCII compatibility form, if one exists."""
    normalized = unicodedata.normalize("NFKC", character)
    if (
        normalized == character
        or not normalized
        or len(normalized) > _UNICODE_MAX_NFKC_EXPANSION
        or not normalized.isascii()
    ):
        return None
    return normalized


@lru_cache(maxsize=4_096)
def _ascii_confusable(character: str) -> str | None:
    """Resolve one non-ASCII scalar through the packaged confusables table."""
    try:
        from confusable_homoglyphs import confusables  # type: ignore[import-untyped]
    except ImportError:
        return None
    entries: Any = confusables.confusables_data.get(character, ())
    for entry in entries:
        glyph = entry.get("c", "")
        # Multi-scalar skeletons are intentionally rejected: they can amplify
        # output and do not provide a single auditable source position.
        if isinstance(glyph, str) and len(glyph) == 1 and glyph.isascii() and (glyph.isalnum() or glyph in {":", "/"}):
            # Several uppercase I/Iota lookalikes have a lowercase-L skeleton
            # in the upstream table. Preserve source case for ASCII anchors.
            if glyph == "l" and character.isupper():
                return "I"
            return glyph
    return None


@lru_cache(maxsize=4_096)
def _unicode_scalar_projection(character: str) -> tuple[str, str] | None:
    """Return one bounded decoded scalar and its transformation class."""
    if character.isascii():
        return None

    codepoint = ord(character)
    if character == _UNICODE_HTML_COMMENT_SENTINEL:
        return "", "default-ignorable"
    # Decode the supported supplementary-selector carrier before applying the
    # Default_Ignorable property, which also contains this codepoint range.
    if 0xE0100 <= codepoint <= 0xE017E:
        value = codepoint - 0xE0100
        if value == 10 or 0x20 <= value <= 0x7E:
            return chr(value), "variation-selectors-supplement"
    if any(start <= codepoint <= end for start, end in _UNICODE_DEFAULT_IGNORABLE_RANGES):
        return "", "default-ignorable"
    # A combining mark inserted into an ASCII anchor breaks the raw signature.
    # It is only actionable later when fixed-span causality and raw non-match
    # are both proven, so ordinary marked multilingual prose remains inert.
    if unicodedata.category(character) in {"Mn", "Mc", "Me"}:
        return "", "combining-mark"
    if character.isspace():
        return " ", "unicode-whitespace"
    if 0x2800 <= codepoint <= 0x28FF:
        value = codepoint - 0x2800
        if value == 10 or 0x20 <= value <= 0x7E:
            return chr(value), "braille-offset"

    confusable = _ascii_confusable(character)
    normalized = _bounded_ascii_nfkc(character)
    if confusable is not None and confusable != normalized:
        return confusable, "unicode-confusable"
    if normalized is not None:
        return normalized, "unicode-normalization"
    if confusable is not None:
        return confusable, "unicode-confusable"
    return None


_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--)")
_NEGATED_EXFILTRATION_RE = re.compile(
    r"\b(?:do\s+not|don't|never|avoid|prevent|block|reject|refus(?:e|es|ed|ing)|rather\s+than)\b"
    r"[^\n]{0,100}\b(?:exfiltrat(?:e|es|ed|ing|ion)|siphon(?:s|ed|ing)?)\b",
    re.IGNORECASE,
)
_NEGATABLE_EXFIL_IDENTIFIERS = {"$explicit_exfil", "$leak_param", "$credential_theft_actions"}


def _constant_truth_value(node: ast.expr) -> bool | None:
    """Evaluate side-effect-free literal conditions, or return ``None``.

    This deliberately handles only syntax whose value can be established
    without executing user-controlled code. It keeps unreachable exits such
    as ``if False: break`` from disguising an infinite loop.
    """
    try:
        return bool(ast.literal_eval(node))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        pass

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _constant_truth_value(node.operand)
        return None if operand is None else not operand

    if isinstance(node, ast.BoolOp):
        values = [_constant_truth_value(value) for value in node.values]
        if isinstance(node.op, ast.And):
            if False in values:
                return False
            return True if all(value is True for value in values) else None
        if isinstance(node.op, ast.Or):
            if True in values:
                return True
            return False if all(value is False for value in values) else None

    if isinstance(node, ast.Compare):
        try:
            operands = [ast.literal_eval(node.left), *(ast.literal_eval(item) for item in node.comparators)]
            comparisons: list[bool] = []
            for left, operator_node, right in zip(operands[:-1], node.ops, operands[1:], strict=True):
                if isinstance(operator_node, ast.Eq):
                    comparisons.append(left == right)
                elif isinstance(operator_node, ast.NotEq):
                    comparisons.append(left != right)
                elif isinstance(operator_node, ast.Lt):
                    comparisons.append(left < right)
                elif isinstance(operator_node, ast.LtE):
                    comparisons.append(left <= right)
                elif isinstance(operator_node, ast.Gt):
                    comparisons.append(left > right)
                elif isinstance(operator_node, ast.GtE):
                    comparisons.append(left >= right)
                elif isinstance(operator_node, ast.Is):
                    comparisons.append(left is right)
                elif isinstance(operator_node, ast.IsNot):
                    comparisons.append(left is not right)
                elif isinstance(operator_node, ast.In):
                    comparisons.append(left in right)
                elif isinstance(operator_node, ast.NotIn):
                    comparisons.append(left not in right)
                else:
                    return None
            return all(comparisons)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None

    return None


class _LoopExitVisitor:
    """Find potentially reachable exits belonging to one enclosing loop."""

    def block_has_exit(self, statements: list[ast.stmt], *, nested_loop_depth: int = 0) -> bool:
        """Return whether a reachable path through *statements* exits the loop."""
        has_exit, _ = self._block_flow(statements, nested_loop_depth=nested_loop_depth)
        return has_exit

    def _block_flow(self, statements: list[ast.stmt], *, nested_loop_depth: int) -> tuple[bool, bool]:
        has_exit = False
        falls_through = True
        for statement in statements:
            if not falls_through:
                break
            statement_exit, falls_through = self._statement_flow(
                statement,
                nested_loop_depth=nested_loop_depth,
            )
            has_exit = has_exit or statement_exit
        return has_exit, falls_through

    def _statement_flow(self, node: ast.stmt, *, nested_loop_depth: int) -> tuple[bool, bool]:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False, True
        if isinstance(node, (ast.Return, ast.Raise)):
            return True, False
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "sys"
            and node.value.func.attr == "exit"
        ):
            return True, False
        if isinstance(node, ast.Break):
            return nested_loop_depth == 0, False
        if isinstance(node, ast.Continue):
            return False, False

        if isinstance(node, ast.If):
            truth_value = _constant_truth_value(node.test)
            if truth_value is True:
                return self._block_flow(node.body, nested_loop_depth=nested_loop_depth)
            if truth_value is False:
                return self._block_flow(node.orelse, nested_loop_depth=nested_loop_depth)

            body_exit, body_falls_through = self._block_flow(
                node.body,
                nested_loop_depth=nested_loop_depth,
            )
            if node.orelse:
                else_exit, else_falls_through = self._block_flow(
                    node.orelse,
                    nested_loop_depth=nested_loop_depth,
                )
            else:
                else_exit, else_falls_through = False, True
            return body_exit or else_exit, body_falls_through or else_falls_through

        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            if isinstance(node, ast.While) and _constant_truth_value(node.test) is False:
                return self._block_flow(node.orelse, nested_loop_depth=nested_loop_depth)
            body_exit, _ = self._block_flow(node.body, nested_loop_depth=nested_loop_depth + 1)
            else_exit, _ = self._block_flow(node.orelse, nested_loop_depth=nested_loop_depth)
            # A nested loop may complete or break, so the enclosing block can
            # continue even when one path through its body does not.
            return body_exit or else_exit, True

        if isinstance(node, (ast.With, ast.AsyncWith)):
            return self._block_flow(node.body, nested_loop_depth=nested_loop_depth)

        if isinstance(node, (ast.Try, ast.TryStar)):
            protected_blocks = [node.body, node.orelse, *(handler.body for handler in node.handlers)]
            protected_exit = any(
                self._block_flow(block, nested_loop_depth=nested_loop_depth)[0] for block in protected_blocks if block
            )
            if not node.finalbody:
                return protected_exit, True

            final_exit, final_falls_through = self._block_flow(
                node.finalbody,
                nested_loop_depth=nested_loop_depth,
            )
            if not final_falls_through:
                # An unconditional continue/exit in finally overrides control
                # flow from the protected block.
                return final_exit, False
            return protected_exit or final_exit, True

        if isinstance(node, ast.Match):
            case_flows = [
                self._block_flow(case.body, nested_loop_depth=nested_loop_depth)
                for case in node.cases
                if case.guard is None or _constant_truth_value(case.guard) is not False
            ]
            return any(flow[0] for flow in case_flows), True

        return False, True


_SKILL_NAME_PATTERN = re.compile(r"[a-z0-9-]+")
_MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^\)]+)\)")
_PYTHON_IMPORT_PATTERN = re.compile(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", re.MULTILINE)
_BASH_SOURCE_PATTERN = re.compile(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))")
_RM_TARGET_PATTERN = re.compile(r"rm\s+-r[^;]*?\s+([^\s;]+)")
_DEFAULT_SAFE_CLEANUP_DIRS = {
    "dist",
    "build",
    "tmp",
    "temp",
    ".tmp",
    ".temp",
    "bundle.html",
    "bundle.js",
    "bundle.css",
    "node_modules",
    ".next",
    ".nuxt",
    ".cache",
}
_DEFAULT_PLACEHOLDER_MARKERS = {
    "your-",
    "your_",
    "your ",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "replace",
    "changeme",
    "change_me",
    "<your",
    "<insert",
}


def _is_path_traversal(ref_path: str) -> bool:
    """Check if a reference path contains traversal sequences or is absolute."""
    return ".." in ref_path or ref_path.startswith("/")


def _is_within_directory(path: Path, directory: Path) -> bool:
    """Check if a resolved path stays within the given directory."""
    try:
        resolved_path = path.resolve()
        resolved_directory = directory.resolve()
        return resolved_path.is_relative_to(resolved_directory)
    except (ValueError, OSError):
        return False


def _redact_secret(text: str) -> str:
    """Redact a matched secret, preserving a short prefix for identification.

    Returns a version like ``AKIA****`` or ``sk_live_****`` so the type of
    secret is still recognisable in the report without exposing the full value.
    """
    if not text:
        return text
    _KNOWN_PREFIXES = {
        "AKIA": 4,
        "AGPA": 4,
        "AIDA": 4,
        "AROA": 4,
        "AIPA": 4,
        "ANPA": 4,
        "ANVA": 4,
        "ASIA": 4,
        "AIza": 4,
    }
    for prefix, length in _KNOWN_PREFIXES.items():
        if text.startswith(prefix):
            return text[:length] + "****"
    _TOKEN_PREFIXES = ("sk_live_", "pk_live_", "sk_test_", "pk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_")
    for prefix in _TOKEN_PREFIXES:
        if text.startswith(prefix):
            return prefix + "****"
    if text.startswith("eyJ"):
        return "eyJ****"
    _PK_MARKER_BEGIN = "-----BEGIN"
    _PK_MARKER_TYPE = "PRIVATE KEY"
    if _PK_MARKER_BEGIN in text and _PK_MARKER_TYPE in text:
        return f"{_PK_MARKER_BEGIN} {_PK_MARKER_TYPE}----- [REDACTED]"
    if len(text) <= 8:
        return text[:2] + "****"
    return text[:4] + "****"


_OOXML_CONTAINER_ROOTS = {
    ".docx": "word",
    ".docm": "word",
    ".pptx": "ppt",
    ".pptm": "ppt",
    ".xlsx": "xl",
    ".xlsm": "xl",
}
_OOXML_INERT_MEDIA_EXTENSIONS = frozenset(
    {
        ".bmp",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".png",
        ".tif",
        ".tiff",
        ".webp",
    }
)
_OOXML_INERT_FONT_EXTENSIONS = frozenset(
    {
        ".eot",
        ".fntdata",
        ".odttf",
        ".otf",
        ".ttf",
        ".woff",
        ".woff2",
    }
)


def _ooxml_member_identity(skill_file: SkillFile) -> tuple[str, str] | None:
    """Return a validated ``(container root, member path)`` extraction identity.

    ``extracted_from`` is populated only by the bounded archive extractor.  A
    matching virtual-path prefix and an exact OOXML extension are required so
    a filename or vendor label alone can never opt a file out of detection.
    """

    source = skill_file.extracted_from
    if not source:
        return None
    container_root = _OOXML_CONTAINER_ROOTS.get(Path(source).suffix.lower())
    if container_root is None:
        return None

    prefix = f"{source}!/"
    if not skill_file.relative_path.startswith(prefix):
        return None
    member_path = skill_file.relative_path[len(prefix) :]
    if not member_path or "\\" in member_path or member_path.startswith("/"):
        return None
    parts = member_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    return container_root, "/".join(parts).lower()


def _is_inert_ooxml_unicode_asset(skill_file: SkillFile) -> bool:
    """Identify binary OOXML media/font roles where Unicode bytes are inert.

    YARA scans raw bytes, so ordinary compressed images and font tables can
    coincidentally contain valid UTF-8 encodings for tag-block, bidi, or
    separator characters.  Only a binary member with extractor provenance,
    the container's expected root, a precise media/font role, and a known
    inert extension is suppressible.  SVG, macros, OLE, relationships, and
    unknown members deliberately fail open.
    """

    if skill_file.file_type != "binary":
        return False
    identity = _ooxml_member_identity(skill_file)
    if identity is None:
        return False
    container_root, member_path = identity
    parts = member_path.split("/")
    if len(parts) < 3 or parts[0] != container_root:
        return False

    extension = Path(parts[-1]).suffix.lower()
    if parts[1] == "media":
        return extension in _OOXML_INERT_MEDIA_EXTENSIONS
    if parts[1] == "fonts":
        return extension in _OOXML_INERT_FONT_EXTENSIONS
    return False


def _is_extracted_ooxml_text(skill_file: SkillFile) -> bool:
    """Return whether a readable member came from bounded OOXML extraction."""

    return skill_file.file_type != "binary" and _ooxml_member_identity(skill_file) is not None


def _semantic_metadata(
    *,
    rule_id: str,
    file_path: str,
    evidence_kind: str,
    context_kind: str,
    signal_kind: str,
    value_class: str,
    evidence_value_class: str | None = None,
    evidence_count: int | None = None,
    candidate_command: dict[str, Any] | None = None,
    candidate_flow: dict[str, Any] | None = None,
    extra_signals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build bounded, structured facts for the semantic projector.

    Static analyzers own this classification: the CEL projection layer must not
    infer it by reparsing finding snippets or descriptions.
    """
    semantic_facts: dict[str, Any] = {
        "evidence_kind": evidence_kind,
        "context_kind": context_kind,
        "signals": [
            {
                "rule_id": rule_id,
                "kind": signal_kind,
                "file_path": file_path,
                "value_class": value_class,
            }
        ],
    }
    if evidence_value_class is not None:
        semantic_facts["evidence_value_class"] = evidence_value_class
    if evidence_count is not None:
        semantic_facts["evidence_count"] = evidence_count
    if candidate_command is not None:
        semantic_facts["candidate_command"] = candidate_command
        semantic_facts["commands"] = [candidate_command]
    if candidate_flow is not None:
        semantic_facts["candidate_flow"] = candidate_flow
        semantic_facts["flows"] = [candidate_flow]
    if extra_signals:
        semantic_facts["signals"].extend(extra_signals)
    return {"semantic_facts": semantic_facts}


_YARA_SEMANTIC_EVIDENCE_KINDS = frozenset(
    {
        "binary_signature",
        "command_pipeline",
        "correlated_behavior",
    }
)
_YARA_SEMANTIC_CONTEXT_KINDS = frozenset(
    {
        "active_instruction",
        "binary",
        "code",
        "example",
        "prohibition",
    }
)
_YARA_SEMANTIC_SIGNAL_KINDS = frozenset({"compound_flow", "embedded_shebang", "taint_flow"})
_YARA_SEMANTIC_SOURCE_SINK_CLASSES = frozenset(
    {
        "archive",
        "credential_file",
        "external_network",
        "network",
        "obfuscation",
        "process_execution",
        "resource_consumption",
        "scheduler",
    }
)
_YARA_SEMANTIC_TRANSFORMS = frozenset({"decode", "extraction", "pipe"})
_YARA_SEMANTIC_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _embedded_shebang_offset_facts(offset: Any) -> tuple[str, int]:
    """Return a bounded, candidate-local offset classification.

    The YARA implementation only retains shebangs after byte 64.  Direct unit
    callers and malformed custom results can still omit or corrupt the offset,
    so those cases remain explicitly unclassified for fail-open CEL handling.
    The scalar count never exceeds the global 4,096 fact bound.
    """

    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 65:
        return "unclassified", 0
    if offset < 4_096:
        return "embedded_shebang_offset_65_4095", offset
    return "embedded_shebang_offset_4096_plus", 4_096


def _yara_candidate_string_matches(match: dict[str, Any], meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the bounded string evidence used to construct findings.

    Behavior-chain rules use several supporting strings to prove one
    correlated rule/file candidate.  Emitting a finding for every supporting
    primitive inflates counts and gives CEL duplicate activations.  The
    explicit ``rule_file`` scope therefore selects one deterministic anchor;
    ordinary and byte-offset-sensitive YARA rules retain per-string findings.
    """

    strings = match.get("strings")
    if not isinstance(strings, list):
        return []
    candidates = [value for value in strings if isinstance(value, dict)]
    if meta.get("finding_scope") != "rule_file" or not candidates:
        return candidates

    def stable_position(value: dict[str, Any]) -> tuple[int, int, str]:
        offset = value.get("offset")
        line_number = value.get("line_number")
        return (
            offset if isinstance(offset, int) and not isinstance(offset, bool) and offset >= 0 else 2**63 - 1,
            line_number
            if isinstance(line_number, int) and not isinstance(line_number, bool) and line_number >= 0
            else 2**31 - 1,
            str(value.get("identifier", "")),
        )

    return [min(candidates, key=stable_position)]


def _yara_semantic_metadata(
    *,
    rule_name: str,
    meta: dict[str, Any],
    file_path: str,
    match_offset: Any,
    context_kind_override: str | None = None,
) -> dict[str, Any]:
    """Translate trusted, normalized YARA metadata into bounded CEL facts.

    This function never reparses source snippets.  Unknown or malformed source
    metadata is ignored rather than exposing an arbitrary YARA map to CEL.
    """

    rule_id = f"YARA_{rule_name}"
    if rule_name == "embedded_shebang_in_binary":
        offset_value_class, evidence_count = _embedded_shebang_offset_facts(match_offset)
        result = _semantic_metadata(
            rule_id=rule_id,
            file_path=file_path,
            evidence_kind="binary_signature",
            context_kind="binary",
            signal_kind="embedded_shebang",
            value_class=offset_value_class,
            evidence_value_class=offset_value_class,
            evidence_count=evidence_count,
        )
        result["yara_byte_offset_class"] = offset_value_class
        result["yara_byte_offset_bounded"] = evidence_count
        return result

    evidence_kind = meta.get("evidence_kind")
    context_kind = context_kind_override or meta.get("context_kind")
    signal_kind = meta.get("signal_kind")
    value_class = meta.get("value_class")
    source_class = meta.get("source_class")
    sink_class = meta.get("sink_class")
    transforms_raw = meta.get("transforms", "")
    if not (
        isinstance(evidence_kind, str)
        and evidence_kind in _YARA_SEMANTIC_EVIDENCE_KINDS
        and isinstance(context_kind, str)
        and context_kind in _YARA_SEMANTIC_CONTEXT_KINDS
        and isinstance(signal_kind, str)
        and signal_kind in _YARA_SEMANTIC_SIGNAL_KINDS
        and isinstance(value_class, str)
        and _YARA_SEMANTIC_TOKEN_RE.fullmatch(value_class)
        and isinstance(source_class, str)
        and source_class in _YARA_SEMANTIC_SOURCE_SINK_CLASSES
        and isinstance(sink_class, str)
        and sink_class in _YARA_SEMANTIC_SOURCE_SINK_CLASSES
        and isinstance(transforms_raw, str)
    ):
        return {}

    transforms = [value.strip() for value in transforms_raw.split(",") if value.strip()]
    if any(value not in _YARA_SEMANTIC_TRANSFORMS for value in transforms):
        return {}

    candidate_flow = {
        "source_class": source_class,
        "sink_class": sink_class,
        "transforms": transforms,
        "cross_file": False,
        "source_path": file_path,
        "sink_path": file_path,
    }
    return _semantic_metadata(
        rule_id=rule_id,
        file_path=file_path,
        evidence_kind=evidence_kind,
        context_kind=context_kind,
        signal_kind=signal_kind,
        value_class=value_class,
        evidence_value_class=value_class,
        evidence_count=1,
        candidate_flow=candidate_flow,
    )


class StaticAnalyzer(BaseAnalyzer):
    """Static pattern-based security analyzer."""

    def __init__(
        self,
        rules_file: Path | None = None,
        use_yara: bool = True,
        yara_mode: YaraModeConfig | str | None = None,
        custom_yara_rules_path: str | Path | None = None,
        disabled_rules: set[str] | None = None,
        policy: ScanPolicy | None = None,
        extra_rules_dirs: list[Path] | None = None,
        trusted_pack_dirs: list[Path] | None = None,
    ):
        """
        Initialize static analyzer.

        Args:
            rules_file: Optional custom YAML rules file
            use_yara: Whether to use YARA scanning (default: True)
            yara_mode: YARA detection mode - can be:
                - YaraModeConfig instance
                - Mode name string: "strict", "balanced", "permissive"
                - None for default (balanced)
            custom_yara_rules_path: Path to directory containing custom YARA rules
                (.yara files). If provided, uses these instead of built-in rules.
            disabled_rules: Set of rule names to disable. Rules can be YARA rule
                names (e.g., "YARA_script_injection") or static rule IDs
                (e.g., "COMMAND_INJECTION_EVAL").
            policy: Scan policy for org-specific allowlists and rule scoping.
                If None, loads built-in defaults.
            extra_rules_dirs: Additional signature rule directories from
                community/external packs to load alongside the core rules.
            trusted_pack_dirs: Administrator-approved v2 rule pack directories.
        """
        super().__init__("static_analyzer", policy=policy)

        # Unreferenced scripts are computed during _check_file_inventory()
        # and exposed to the scanner for LLM enrichment context (not as
        # standalone findings).
        self._unreferenced_scripts: list[str] = []

        self.rule_loader = RuleLoader(
            rules_file,
            extra_rules_dirs=extra_rules_dirs,
            trusted_pack_dirs=trusted_pack_dirs,
        )
        self.rule_loader.load_rules()

        # Configure YARA mode.
        # When no explicit yara_mode is supplied, derive it from the policy's
        # ``preset_base`` so that ``--policy strict`` (or a custom policy
        # generated from the strict preset) automatically gets strict YARA
        # post-filtering.  ``preset_base`` is a stable field that survives
        # policy-name customisation (e.g. "acme-corp"), unlike
        # ``policy_name`` which is a user-facing display name.
        if yara_mode is None:
            preset = getattr(self.policy, "preset_base", "balanced")
            _PRESET_TO_YARA = {"strict": "strict", "permissive": "permissive"}
            mode_name = _PRESET_TO_YARA.get(preset, "balanced")
            self.yara_mode = YaraModeConfig.from_mode_name(mode_name)
        elif isinstance(yara_mode, str):
            self.yara_mode = YaraModeConfig.from_mode_name(yara_mode)
        else:
            self.yara_mode = yara_mode

        # Store disabled rules (merge CLI + mode + policy)
        self.disabled_rules = set(disabled_rules or set())
        self.disabled_rules.update(self.yara_mode.disabled_rules)
        self.disabled_rules.update(self.policy.disabled_rules)

        # Store custom YARA rules path
        self.custom_yara_rules_path = Path(custom_yara_rules_path) if custom_yara_rules_path else None

        self.use_yara = use_yara
        self.yara_scanner = None
        if use_yara:
            trusted_yara_dirs: list[Path] = []
            trusted_yara_metadata: dict[str, dict[str, Any]] = {}
            if self.custom_yara_rules_path is None:
                # Bundled schema-v2 metadata is authoritative at runtime too,
                # not only during startup validation. Load only the core pack:
                # core-only scans must not depend on unrelated bundled packs.
                from ...core.rule_registry import PackLoader

                core_pack = PackLoader().load_bundled_pack(DATA_DIR / "packs" / "core")
                for definition in core_pack.rules.values():
                    if definition.source_type != "yara":
                        continue
                    bundled_metadata: dict[str, Any] = {
                        "category": definition.category,
                        "severity": definition.default_severity,
                    }
                    if definition.description:
                        bundled_metadata["description"] = definition.description
                    trusted_yara_metadata[definition.id.removeprefix("YARA_")] = bundled_metadata
            if trusted_pack_dirs:
                # RuleLoader validates trusted signature implementations.  Load
                # the same explicit packs here to obtain their validated YARA
                # directories for the runtime generation.  Validation remains
                # fail-fast and no discovery of untrusted directories occurs.
                from ...core.rule_registry import PackLoader

                pack_loader = PackLoader()
                for pack_dir in trusted_pack_dirs:
                    pack = pack_loader.load_trusted_pack(pack_dir)
                    trusted_yara_dirs.extend(pack.yara_dirs)
                    for definition in pack.rules.values():
                        if definition.source_type != "yara":
                            continue
                        local_metadata: dict[str, Any] = {
                            "category": definition.category,
                            "severity": definition.default_severity,
                        }
                        if definition.description:
                            local_metadata["description"] = definition.description
                        trusted_yara_metadata[definition.id.removeprefix("YARA_")] = local_metadata

            try:
                max_scan_bytes = self.policy.file_limits.max_yara_scan_file_size_bytes
                # Use custom rules path if provided
                if self.custom_yara_rules_path:
                    self.yara_scanner = YaraScanner(
                        rules_dir=self.custom_yara_rules_path,
                        additional_rules_dirs=trusted_yara_dirs,
                        metadata_overrides=trusted_yara_metadata,
                        max_scan_file_size=max_scan_bytes,
                    )
                    logger.info("Using custom YARA rules from: %s", self.custom_yara_rules_path)
                else:
                    self.yara_scanner = YaraScanner(
                        additional_rules_dirs=trusted_yara_dirs,
                        metadata_overrides=trusted_yara_metadata,
                        max_scan_file_size=max_scan_bytes,
                    )
            except Exception as e:
                if trusted_yara_dirs or self.custom_yara_rules_path is None:
                    # A trusted pack participates in one atomic runtime
                    # generation, and the bundled rules are trusted release
                    # artifacts.  Compilation or identity failures must abort
                    # startup rather than silently disabling all YARA rules.
                    raise
                logger.warning("Could not load YARA scanner: %s", e)
                self.yara_scanner = None

    def _is_rule_enabled(self, rule_name: str) -> bool:
        """
        Check if a rule is enabled.

        A rule is enabled if:
        1. It's enabled in the current YARA mode
        2. It's not in the explicitly disabled rules set
        3. It's not in the policy's disabled_rules set

        Args:
            rule_name: Name of the rule to check (e.g., "YARA_script_injection")

        Returns:
            True if the rule is enabled, False otherwise
        """
        # Check mode-based enable/disable first
        if not self.yara_mode.is_rule_enabled(rule_name):
            return False

        # Check if explicitly disabled via policy or constructor
        if rule_name in self.disabled_rules:
            return False

        base_name = rule_name.replace("YARA_", "") if rule_name.startswith("YARA_") else rule_name
        if base_name in self.disabled_rules:
            return False

        return True

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using static pattern matching.

        Performs multi-pass scanning:
        1. Manifest validation
        2. Instruction body scanning (SKILL.md)
        3. Script/code scanning
        4. Consistency checks
        5. Dependency pinning checks
        6. Reference file scanning

        Args:
            skill: Skill to analyze

        Returns:
            List of security findings
        """
        findings = []
        self._unreferenced_scripts = []  # reset per-scan enrichment state

        manifest_complete = bool(getattr(skill, "manifest_complete", True))
        if manifest_complete:
            findings.extend(self._check_manifest(skill))
        findings.extend(self._scan_instruction_body(skill))
        findings.extend(check_active_dynamic_execution(skill))
        findings.extend(check_active_hidden_html(skill))
        findings.extend(check_active_remote_execution(skill))
        findings.extend(check_active_semantic_directives(skill))
        findings.extend(check_unicode_smuggling(skill))
        findings.extend(self._scan_scripts(skill))
        findings.extend(self._check_dynamic_sensitive_file_access(skill))
        if manifest_complete:
            findings.extend(self._check_consistency(skill))
        findings.extend(self._check_dependency_pinning(skill))
        findings.extend(self._scan_config_files(skill))
        findings.extend(self._scan_referenced_files(skill))
        findings.extend(self._check_binary_files(skill))
        findings.extend(self._check_hidden_files(skill))
        findings.extend(self._check_ascii_smuggling(skill))
        findings.extend(self._check_unicode_obfuscated_instructions(skill))
        findings.extend(self._check_file_inventory(skill))
        findings.extend(self._check_pdf_documents(skill))
        findings.extend(self._check_office_documents(skill))
        findings.extend(self._check_homoglyph_attacks(skill))

        if self.yara_scanner:
            findings.extend(self._yara_scan(skill))

        findings.extend(self._scan_asset_files(skill))

        # Filter out disabled rules (both explicitly disabled and via enabled=false knob)
        findings = [f for f in findings if self._is_rule_enabled(f.rule_id)]

        # Filter out well-known test/placeholder credentials
        findings = [f for f in findings if not self._is_known_test_credential(f)]

        # Collapse duplicate findings emitted by overlapping scan phases
        # (e.g., script scan + recursive reference scan on the same file/line).
        if self.policy.rule_scoping.dedupe_duplicate_findings:
            findings = self._dedupe_findings(findings)

        self._annotate_unreferenced_script_context(findings)

        # Broad primitive signatures are useful candidate extractors, but a
        # local file operation or structured process launch is not, by itself,
        # the external/shell sink named by the rule.  Apply package-local,
        # provenance-neutral data-flow and file-role refinement only after the
        # inventory has established referenced versus concealed code.
        findings = refine_core_signature_findings(
            skill,
            findings,
            unreferenced_scripts=set(self._unreferenced_scripts),
        )
        return findings

    def _annotate_unreferenced_script_context(self, findings: list[Finding]) -> None:
        """Attach unreferenced-script context to existing findings in place.

        Unreferenced scripts intentionally remain enrichment context rather
        than standalone findings.  Adding a structured signal to findings that
        already exist on the same file lets CEL correlate that context without
        changing finding counts, severities, or scan verdicts.
        """
        unreferenced = {Path(path).as_posix() for path in self._unreferenced_scripts}
        if not unreferenced:
            return

        for finding in findings:
            file_path = Path(finding.file_path or "").as_posix()
            if file_path not in unreferenced:
                continue

            semantic = finding.metadata.setdefault("semantic_facts", {})
            if not isinstance(semantic, dict):
                continue
            semantic.setdefault("evidence_kind", "pattern_match")
            semantic.setdefault("context_kind", "code")
            signals = semantic.setdefault("signals", [])
            if not isinstance(signals, list):
                continue
            suffix_kind = {
                ".js": "javascript",
                ".mjs": "javascript",
                ".py": "python",
                ".sh": "bash",
                ".ts": "typescript",
            }.get(Path(file_path).suffix.lower(), "other")
            signal = {
                "rule_id": finding.rule_id,
                "kind": "unreferenced_executable",
                "file_path": file_path,
                "value_class": suffix_kind,
            }
            if signal not in signals:
                signals.append(signal)

    def get_unreferenced_scripts(self) -> list[str]:
        """Return unreferenced script paths computed during the last ``analyze()`` call.

        These are scripts present in the skill package that are not mentioned
        in SKILL.md.  They are stored as enrichment context for the LLM
        analyzer rather than emitted as standalone findings.
        """
        return list(self._unreferenced_scripts)

    def _is_known_test_credential(self, finding: Finding) -> bool:
        """Check if a finding matches a well-known test/placeholder credential (from policy)."""
        if finding.category != ThreatCategory.HARDCODED_SECRETS:
            return False
        snippet = finding.snippet or ""
        for cred in self.policy.credentials.known_test_values:
            if cred in snippet:
                return True
        return False

    def _is_doc_file(self, rel_path: str) -> bool:
        """Check if a file is in a documentation directory or is an educational file.

        Uses ``doc_path_indicators`` and ``doc_filename_patterns`` from the
        active scan policy to determine if a given relative path belongs to a
        documentation or example area (e.g. ``docs/``, ``examples/``).
        """
        path_obj = Path(rel_path)
        parts = path_obj.parts
        doc_indicators = self.policy.rule_scoping.doc_path_indicators
        if any(p.lower() in doc_indicators for p in parts):
            return True
        doc_re = self.policy._compiled_doc_filename_re
        if doc_re and doc_re.search(path_obj.stem):
            return True
        return False

    def _check_manifest(self, skill: Skill) -> list[Finding]:
        """Validate skill manifest for security issues."""
        findings = []
        manifest = skill.manifest

        max_name_length = self.policy.file_limits.max_name_length
        if len(manifest.name) > max_name_length or not _SKILL_NAME_PATTERN.fullmatch(manifest.name or ""):
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_INVALID_NAME", "manifest"),
                    rule_id="MANIFEST_INVALID_NAME",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Skill name does not follow agent skills naming rules",
                    description=(
                        f"Skill name '{manifest.name}' is invalid. Agent skills require lowercase letters, numbers, "
                        f"and hyphens only, with a maximum length of {max_name_length} characters."
                    ),
                    file_path="SKILL.md",
                    remediation="Rename the skill to match `[a-z0-9-]{1,64}` (e.g., 'pdf-processing')",
                    analyzer="static",
                )
            )

        max_desc_length = self.policy.file_limits.max_description_length
        if len(manifest.description or "") > max_desc_length:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_DESCRIPTION_TOO_LONG", "manifest"),
                    rule_id="MANIFEST_DESCRIPTION_TOO_LONG",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Skill description exceeds agent skills length limit",
                    description=(
                        f"Skill description is {len(manifest.description)} characters; Agent skills limit the "
                        f"`description` field to {max_desc_length} characters."
                    ),
                    file_path="SKILL.md",
                    remediation=f"Shorten the description to {max_desc_length} characters or fewer while keeping it specific",
                    analyzer="static",
                )
            )

        min_desc_length = self.policy.file_limits.min_description_length
        if len(manifest.description or "") < min_desc_length:
            findings.append(
                Finding(
                    id=self._generate_finding_id("SOCIAL_ENG_VAGUE_DESCRIPTION", "manifest"),
                    rule_id="SOCIAL_ENG_VAGUE_DESCRIPTION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.LOW,
                    title="Vague skill description",
                    description=f"Skill description is too short ({len(manifest.description)} chars). Provide detailed explanation.",
                    file_path="SKILL.md",
                    remediation="Provide a clear, detailed description of what the skill does and when to use it",
                    analyzer="static",
                )
            )

        description_lower = manifest.description.lower()
        name_lower = manifest.name.lower()
        is_anthropic_mentioned = "anthropic" in name_lower or "anthropic" in description_lower

        if is_anthropic_mentioned:
            legitimate_patterns = ["apply", "brand", "guidelines", "colors", "typography", "style"]
            is_legitimate = any(pattern in description_lower for pattern in legitimate_patterns)

            if not is_legitimate:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("SOCIAL_ENG_ANTHROPIC_IMPERSONATION", "manifest"),
                        rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.MEDIUM,
                        title="Potential Anthropic brand impersonation",
                        description="Skill name or description contains 'Anthropic', suggesting official affiliation",
                        file_path="SKILL.md",
                        remediation="Do not impersonate official skills or use unauthorized branding",
                        analyzer="static",
                    )
                )

        if "claude official" in manifest.name.lower() or "claude official" in manifest.description.lower():
            findings.append(
                Finding(
                    id=self._generate_finding_id("SOCIAL_ENG_CLAUDE_OFFICIAL", "manifest"),
                    rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.HIGH,
                    title="Claims to be official skill",
                    description="Skill claims to be an 'official' skill",
                    file_path="SKILL.md",
                    remediation="Remove 'official' claims unless properly authorized",
                    analyzer="static",
                )
            )

        if not manifest.license:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_MISSING_LICENSE", "manifest"),
                    rule_id="MANIFEST_MISSING_LICENSE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Skill does not specify a license",
                    description="Skill manifest does not include a 'license' field. Specifying a license helps users understand usage terms.",
                    file_path="SKILL.md",
                    remediation="Add 'license' field to SKILL.md frontmatter (e.g., MIT, Apache-2.0)",
                    analyzer="static",
                )
            )

        return findings

    def _scan_instruction_body(self, skill: Skill) -> list[Finding]:
        """Scan SKILL.md instruction body for prompt injection patterns."""
        findings = []

        markdown_rules = self.rule_loader.get_rules_for_file_type("markdown")
        scan_context = SignatureScanContext(skill.instruction_body)

        for rule in markdown_rules:
            matches = rule.scan_content(
                skill.instruction_body,
                "SKILL.md",
                scan_context=scan_context,
            )
            for match in matches:
                physical_match = dict(match)
                line_number = physical_match.get("line_number")
                if isinstance(line_number, int):
                    physical_match["line_number"] = line_number + skill.instruction_body_line_offset
                findings.append(self._create_finding_from_match(rule, physical_match))

        return findings

    def _scan_scripts(self, skill: Skill) -> list[Finding]:
        """Scan all script files (Python, Bash) for vulnerabilities."""
        findings = []
        skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)

        for skill_file in skill.files:
            if skill_file.file_type not in ("python", "bash", "javascript", "typescript"):
                continue

            rules = self.rule_loader.get_rules_for_file_type(skill_file.file_type)

            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._is_doc_file(skill_file.relative_path)
            scan_context = SignatureScanContext(content)
            python_shell_candidates = None

            for rule in rules:
                # Skip rules scoped out of documentation files
                if is_doc and rule.id in skip_in_docs:
                    continue
                matches = rule.scan_content(
                    content,
                    skill_file.relative_path,
                    scan_context=scan_context,
                )
                if (
                    rule.id == "COMMAND_INJECTION_SHELL_TRUE"
                    and skill_file.file_type == "python"
                    and self._is_rule_enabled(rule.id)
                ):
                    if python_shell_candidates is None:
                        python_shell_candidates = find_python_shell_candidates(content)
                    for candidate in python_shell_candidates:
                        line = scan_context.lines[candidate.line_number - 1]
                        if any(pattern.search(line) for pattern in rule.compiled_exclude_patterns):
                            continue
                        leading_space = len(line) - len(line.lstrip())
                        relative_start = max(0, candidate.start_column - leading_space)
                        relative_end = min(len(line.strip()), candidate.end_column - leading_space)
                        equivalent_spans = (
                            (candidate.line_number, candidate.start_column, candidate.end_column),
                            *getattr(candidate, "equivalent_regex_spans", ()),
                        )

                        def overlaps_semantic_evidence(match: dict[str, Any]) -> bool:
                            match_line_number = match.get("line_number")
                            match_start = match.get("match_start")
                            match_end = match.get("match_end")
                            if (
                                match.get("pattern_index") is None
                                or not isinstance(match_line_number, int)
                                or not isinstance(match_start, int)
                                or not isinstance(match_end, int)
                                or not 1 <= match_line_number <= len(scan_context.lines)
                            ):
                                return False
                            match_line = scan_context.lines[match_line_number - 1]
                            match_leading_space = len(match_line) - len(match_line.lstrip())
                            absolute_start = match_start + match_leading_space
                            absolute_end = match_end + match_leading_space
                            return any(
                                span_line == match_line_number
                                and span_start < absolute_end
                                and absolute_start < span_end
                                for span_line, span_start, span_end in equivalent_spans
                            )

                        # Syntax-aware evidence wins over an equivalent broad
                        # regex, including a raw regex hit inside a Python -c
                        # payload whose displayed anchor is the outer call.
                        matches = [match for match in matches if not overlaps_semantic_evidence(match)]
                        context_kind, polarity = scan_context.classify_match(
                            candidate.line_number - 1,
                            skill_file.relative_path,
                            match_start=candidate.start_column,
                            match_end=candidate.end_column,
                            additional_active_match=any(pattern.search(line) for pattern in rule.compiled_patterns),
                        )
                        matches.append(
                            {
                                "line_number": candidate.line_number,
                                "line_content": line.strip(),
                                "pattern_index": None,
                                "match_start": relative_start,
                                "match_end": relative_end,
                                "matched_pattern": candidate.matched_pattern,
                                "matched_text": candidate.evidence,
                                "file_path": skill_file.relative_path,
                                "context_kind": context_kind,
                                "polarity": polarity,
                            }
                        )
                for match in matches:
                    if rule.id == "RESOURCE_ABUSE_INFINITE_LOOP" and skill_file.file_type == "python":
                        if self._python_loop_has_exit(content, match["line_number"]):
                            continue
                    findings.append(self._create_finding_from_match(rule, match))

        return findings

    @staticmethod
    def _python_loop_has_exit(content: str, loop_line_num: int) -> bool:
        """Return whether the matched constant loop has an exit in its body.

        Regex context cannot reliably associate ``return`` or ``break`` with a
        particular loop.  The Python AST lets us suppress bounded ``while
        True``/``while 1`` loops without borrowing exits from a later block or
        a nested function.  A break belonging to a nested loop is likewise not
        an exit from the matched outer loop.
        """
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return False

        for node in ast.walk(tree):
            if not isinstance(node, ast.While) or node.lineno != loop_line_num:
                continue
            if not isinstance(node.test, ast.Constant) or node.test.value not in (True, 1):
                continue

            return _LoopExitVisitor().block_has_exit(node.body)

        return False

    def _check_consistency(self, skill: Skill) -> list[Finding]:
        """Check for inconsistencies between manifest and actual behavior."""
        findings = []

        network_usage_path = self._skill_network_usage_path(skill)
        uses_network = network_usage_path is not None
        declared_network = self._manifest_declares_network(skill)

        # Findings use package-relative paths so downstream consumers (notably
        # the bounded CEL fact projector) never receive host-specific absolute
        # paths for manifest-level evidence.
        skillmd = "SKILL.md"

        if uses_network and not declared_network:
            findings.append(
                Finding(
                    id=self._generate_finding_id("TOOL_MISMATCH_NETWORK", skill.name),
                    rule_id="TOOL_ABUSE_UNDECLARED_NETWORK",
                    category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                    severity=Severity.MEDIUM,
                    title="Undeclared network usage",
                    description="Skill code uses network libraries but doesn't declare network requirement",
                    file_path=skillmd,
                    remediation="Declare network usage in compatibility field or remove network calls",
                    analyzer="static",
                    metadata=_semantic_metadata(
                        rule_id="TOOL_ABUSE_UNDECLARED_NETWORK",
                        file_path="SKILL.md",
                        evidence_kind="capability_mismatch",
                        context_kind="manifest",
                        signal_kind="undeclared_network",
                        value_class="external_network",
                        candidate_flow={
                            "source_class": "skill_code",
                            "sink_class": "external_network",
                            "transforms": [],
                            "cross_file": False,
                            "source_path": network_usage_path or skillmd,
                            "sink_path": network_usage_path or skillmd,
                        },
                    ),
                )
            )

        findings.extend(self._check_allowed_tools_violations(skill))

        if self._check_description_mismatch(skill):
            findings.append(
                Finding(
                    id=self._generate_finding_id("DESC_BEHAVIOR_MISMATCH", skill.name),
                    rule_id="SOCIAL_ENG_MISLEADING_DESC",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.MEDIUM,
                    title="Potential description-behavior mismatch",
                    description="Skill performs actions not reflected in its description",
                    file_path="SKILL.md",
                    remediation="Ensure description accurately reflects all skill capabilities",
                    analyzer="static",
                )
            )

        return findings

    @staticmethod
    def _attribute_path(node: ast.AST) -> str | None:
        """Return a dotted attribute path for a simple AST expression."""
        parts: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _check_dynamic_sensitive_file_access(self, skill: Skill) -> list[Finding]:
        """Detect glob/open flows that enumerate credential files indirectly.

        Regex signatures cannot connect a sensitive path literal in an
        ``os.path.join`` list to a later ``glob.glob(pattern)`` or ``open(path)``.
        This conservative AST check only reports a file when the same lexical scope
        contains both a credential-like path literal and a glob operation.
        """
        findings: list[Finding] = []

        for sf in skill.get_scripts():
            if sf.file_type != "python":
                continue
            content = sf.read_content()
            try:
                tree = ast.parse(content, filename=sf.relative_path)
            except (SyntaxError, ValueError):
                continue

            def _owned_nodes(scope: ast.AST) -> list[ast.AST]:
                """Return nodes owned by one scope, excluding nested scopes."""
                owned: list[ast.AST] = []
                stack = list(ast.iter_child_nodes(scope))
                while stack:
                    node = stack.pop()
                    owned.append(node)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                        continue
                    stack.extend(ast.iter_child_nodes(node))
                return owned

            scope_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            scopes: list[ast.AST] = [tree, *(node for node in ast.walk(tree) if isinstance(node, scope_types))]
            for scope in scopes:
                scope_nodes = _owned_nodes(scope)
                has_sensitive_literal = any(
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and _SENSITIVE_PATH_LITERAL_RE.search(node.value)
                    for node in scope_nodes
                )
                if not has_sensitive_literal:
                    continue

                for node in scope_nodes:
                    if not isinstance(node, ast.Call):
                        continue
                    call_path = self._attribute_path(node.func)
                    attribute_name = node.func.attr if isinstance(node.func, ast.Attribute) else None
                    is_glob_call = call_path in {
                        "glob.glob",
                        "glob.iglob",
                        "pathlib.Path.glob",
                        "pathlib.Path.rglob",
                        "Path.glob",
                        "Path.rglob",
                    } or attribute_name in {"glob", "iglob", "rglob"}
                    if not is_glob_call:
                        continue
                    line = getattr(node, "lineno", 1)
                    findings.append(
                        Finding(
                            id=self._generate_finding_id(
                                "DATA_EXFIL_SENSITIVE_FILE_GLOB", f"{sf.relative_path}:{line}"
                            ),
                            rule_id="DATA_EXFIL_SENSITIVE_FILE_GLOB",
                            category=ThreatCategory.DATA_EXFILTRATION,
                            severity=Severity.HIGH,
                            title="Dynamic enumeration of sensitive files",
                            description=(
                                f"{sf.relative_path}:{line} enumerates files with a glob operation in a scope "
                                "that also constructs credential-like paths. Dynamic path construction can hide "
                                "credential harvesting from literal-pattern checks."
                            ),
                            file_path=sf.relative_path,
                            line_number=line,
                            snippet=ast.get_source_segment(content, node),
                            remediation="Do not enumerate credential or configuration files from a skill; use explicit, non-sensitive inputs.",
                            analyzer="static",
                            metadata={"detection_method": "ast_sensitive_path_and_glob"},
                        )
                    )
                    break

        return findings

    # Lockfiles whose presence means dependency versions are already resolved/frozen.
    _LOCKFILE_NAMES = {"uv.lock", "poetry.lock", "pipfile.lock", "requirements.lock"}

    # name[extras] followed by an optional version specifier.
    _REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
    _SPECIFIER_RE = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*(.+)$")

    @staticmethod
    def _classify_requirement(raw: str) -> tuple[str, str] | None:
        """Classify a single requirement line.

        Returns ``(package_name, status)`` where ``status`` is one of
        ``"pinned"`` (has an exact ``==`` version), ``"wildcard"`` (``==1.*``
        style range pin), or ``"unpinned"`` (bare name or open range such as
        ``>=``).  Returns ``None`` for lines that are not package requirements
        (blank, comments, pip options like ``-r``/``--hash``, or direct
        URL/VCS references which are already pinned to a specific artifact).
        """
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            return None
        # Drop PEP 508 environment markers (e.g. "; python_version < '3.11'").
        line = line.split(";", 1)[0].strip()
        # Direct URL / VCS / local-file references are pinned to an artifact.
        if "://" in line or line.startswith("git+") or " @ " in line:
            return None

        match = StaticAnalyzer._REQUIREMENT_RE.match(line)
        if not match:
            return None
        name = match.group(1)
        spec = match.group(2).strip()
        if not spec:
            return (name, "unpinned")

        has_exact = False
        has_wildcard_pin = False
        for part in (p.strip() for p in spec.split(",") if p.strip()):
            op_match = StaticAnalyzer._SPECIFIER_RE.match(part)
            if not op_match:
                continue
            operator, version = op_match.group(1), op_match.group(2).strip()
            if operator in ("==", "==="):
                if "*" in version:
                    has_wildcard_pin = True
                else:
                    has_exact = True
        if has_exact:
            return (name, "pinned")
        if has_wildcard_pin:
            return (name, "wildcard")
        return (name, "unpinned")

    @staticmethod
    def _first_line_containing(content: str, needle: str) -> int | None:
        """Best-effort 1-based line number of the first line containing ``needle``."""
        if not needle:
            return None
        for index, line in enumerate(content.splitlines(), start=1):
            if needle in line:
                return index
        return None

    @staticmethod
    def _safe_toml(content: str) -> dict | None:
        """Parse TOML, returning None when malformed."""
        try:
            return tomllib.loads(content)
        except Exception:  # noqa: BLE001 - malformed manifest, treat as no data
            return None

    def _entries_from_pyproject(self, path: str, content: str) -> list[tuple[str, int | None, str]]:
        """PEP 621 ``[project]`` dependencies and optional-dependencies."""
        data = self._safe_toml(content)
        project = data.get("project") if isinstance(data, dict) else None
        if not isinstance(project, dict):
            return []
        specs: list[str] = []
        deps = project.get("dependencies")
        if isinstance(deps, list):
            specs.extend(str(dep) for dep in deps)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    specs.extend(str(dep) for dep in group)
        return [(path, self._first_line_containing(content, spec), spec) for spec in specs]

    def _entries_from_setup_cfg(self, path: str, content: str) -> list[tuple[str, int | None, str]]:
        """``[options] install_requires`` and ``[options.extras_require]``."""
        parser = configparser.ConfigParser()
        try:
            parser.read_string(content)
        except configparser.Error:
            return []
        blocks: list[str] = []
        if parser.has_option("options", "install_requires"):
            blocks.append(parser.get("options", "install_requires"))
        if parser.has_section("options.extras_require"):
            blocks.extend(value for _, value in parser.items("options.extras_require"))

        entries: list[tuple[str, int | None, str]] = []
        for block in blocks:
            for piece in block.replace(",", "\n").splitlines():
                spec = piece.strip()
                if spec:
                    entries.append((path, self._first_line_containing(content, spec), spec))
        return entries

    def _entries_from_setup_py(self, path: str, content: str) -> list[tuple[str, int | None, str]]:
        """String literals inside ``install_requires=[...]`` in setup.py."""
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return []
        entries: list[tuple[str, int | None, str]] = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.keyword) and node.arg == "install_requires"):
                continue
            for literal in ast.walk(node.value):
                if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                    line_number = getattr(literal, "lineno", None)
                    entries.append((path, line_number, literal.value))
        return entries

    @staticmethod
    def _pipfile_requirement(name: str, spec: Any) -> str | None:
        """Convert a Pipfile entry into a requirement string, or None to skip."""
        if isinstance(spec, str):
            version = spec.strip()
            return name if version in ("", "*") else f"{name}{version}"
        if isinstance(spec, dict):
            # git/path/url references are pinned to a specific artifact.
            if any(key in spec for key in ("git", "path", "file", "url")):
                return None
            version = str(spec.get("version", "")).strip()
            return name if version in ("", "*") else f"{name}{version}"
        return None

    def _entries_from_pipfile(self, path: str, content: str) -> list[tuple[str, int | None, str]]:
        """``[packages]`` and ``[dev-packages]`` sections of a Pipfile (TOML)."""
        data = self._safe_toml(content)
        if not isinstance(data, dict):
            return []
        entries: list[tuple[str, int | None, str]] = []
        for section in ("packages", "dev-packages"):
            packages = data.get(section)
            if not isinstance(packages, dict):
                continue
            for name, spec in packages.items():
                requirement = self._pipfile_requirement(name, spec)
                if requirement is not None:
                    entries.append((path, self._first_line_containing(content, name), requirement))
        return entries

    def _collect_requirement_entries(self, skill: Skill) -> list[tuple[str, int | None, str]]:
        """Gather ``(source_path, line_number, requirement_string)`` from every
        dependency-declaring file in the skill plus manifest metadata."""
        entries: list[tuple[str, int | None, str]] = []
        for skill_file in skill.files:
            file_name = Path(skill_file.relative_path).name.lower()
            path = skill_file.relative_path
            if file_name.startswith("requirements") and file_name.endswith(".txt"):
                for line_number, raw in enumerate(skill_file.read_content().splitlines(), start=1):
                    entries.append((path, line_number, raw))
            elif file_name == "pyproject.toml":
                entries.extend(self._entries_from_pyproject(path, skill_file.read_content()))
            elif file_name == "setup.cfg":
                entries.extend(self._entries_from_setup_cfg(path, skill_file.read_content()))
            elif file_name == "setup.py":
                entries.extend(self._entries_from_setup_py(path, skill_file.read_content()))
            elif file_name == "pipfile":
                entries.extend(self._entries_from_pipfile(path, skill_file.read_content()))

        metadata = skill.manifest.metadata
        if isinstance(metadata, dict):
            declared = metadata.get("dependencies")
            if isinstance(declared, list):
                for declared_dep in declared:
                    # Manifest metadata belongs to the package's canonical
                    # instruction file.  Keep the finding path package-relative
                    # instead of leaking the loader's host-specific absolute
                    # checkout path into downstream typed facts.
                    entries.append(("SKILL.md", None, str(declared_dep)))
        return entries

    def _check_dependency_pinning(self, skill: Skill) -> list[Finding]:
        """Flag dependencies declared without an exact pinned version.

        Skill packages are end-user applications, so unpinned dependencies
        (``requests>=2`` or a bare ``requests``) let a later, potentially
        compromised release be pulled in at install time -- a supply-chain
        risk.  This differs from library pinning policy: libraries
        intentionally use ranges, so if a lockfile is present the versions are
        already frozen and we do not flag.

        Sources checked: ``requirements*.txt``, ``pyproject.toml``
        (``[project]`` dependencies and optional-dependencies), ``setup.cfg``,
        ``setup.py`` (``install_requires``), ``Pipfile``, and a
        ``dependencies`` list under manifest ``metadata``.
        """
        findings: list[Finding] = []

        # A lockfile freezes the resolved versions, so ranges are intentional.
        if any(Path(f.relative_path).name.lower() in self._LOCKFILE_NAMES for f in skill.files):
            return findings

        for source_label, line_number, raw in self._collect_requirement_entries(skill):
            classified = self._classify_requirement(raw)
            if classified is None:
                continue
            package_name, status = classified
            if status == "pinned":
                continue

            severity = Severity.LOW if status == "wildcard" else Severity.MEDIUM
            if status == "wildcard":
                detail = f"'{package_name}' is pinned to a wildcard version range"
            else:
                detail = f"'{package_name}' has no pinned (==) version"
            findings.append(
                Finding(
                    id=self._generate_finding_id(
                        "SUPPLY_CHAIN_UNPINNED_DEPENDENCY", f"{source_label}:{line_number}:{package_name}"
                    ),
                    rule_id="SUPPLY_CHAIN_UNPINNED_DEPENDENCY",
                    category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                    severity=severity,
                    title="Unpinned dependency",
                    description=(
                        f"Dependency {detail}. Unpinned dependencies in a skill package allow a later, "
                        f"potentially malicious release to be installed automatically (supply-chain risk)."
                    ),
                    file_path=source_label,
                    line_number=line_number,
                    snippet=raw.strip() or None,
                    remediation="Pin the dependency to an exact version (e.g. 'package==1.2.3').",
                    analyzer="static",
                    metadata={
                        "semantic_facts": {
                            "evidence_kind": "dependency_declaration",
                            "context_kind": "manifest" if source_label == "SKILL.md" else "dependency_file",
                            "evidence_value_class": f"{status}_dependency",
                            "evidence_count": 1,
                            "signal_kind": "unpinned_dependency",
                            "signals": [],
                        }
                    },
                )
            )

        return findings

    # Basenames (without extension) treated as configuration files.
    _CONFIG_FILE_STEMS = {"config", "settings"}

    def _is_config_file(self, relative_path: str) -> bool:
        """Return True for config files (config.*/settings.* YAML/JSON, any TOML)."""
        name = Path(relative_path).name.lower()
        suffix = Path(name).suffix
        if suffix == ".toml":
            return True
        if suffix in (".yaml", ".yml", ".json"):
            return Path(name).stem in self._CONFIG_FILE_STEMS
        return False

    def _scan_config_files(self, skill: Skill) -> list[Finding]:
        """Classify URLs found in config files using the shared URL classifier.

        Config files (e.g. ``config.yaml``) are typed ``other`` and never
        reach the Python AST URL classifier, so a tunnel/proxy endpoint hidden
        in a config value would otherwise go unnoticed. URLs are extracted from
        the raw text so endpoints in comments are covered too.
        """
        findings: list[Finding] = []
        for skill_file in skill.files:
            if not self._is_config_file(skill_file.relative_path):
                continue
            content = skill_file.read_content()
            if not content:
                continue
            for url in extract_urls(content):
                if classify_url(url) != "suspicious":
                    continue
                display_url = self._redact_url_for_finding(url)
                findings.append(
                    Finding(
                        id=self._generate_finding_id(
                            "CONFIG_SUSPICIOUS_URL", f"{skill_file.relative_path}:{display_url}"
                        ),
                        rule_id="CONFIG_SUSPICIOUS_URL",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        title="Suspicious URL in configuration file",
                        description=(
                            f"Configuration file references '{display_url}', which is on a known "
                            f"suspicious/tunnel domain that may route data to an attacker-controlled endpoint."
                        ),
                        file_path=skill_file.relative_path,
                        line_number=self._find_line_number(content, url),
                        snippet=display_url,
                        remediation=(
                            "Verify the endpoint is legitimate and documented; "
                            "remove tunnel/proxy or exfiltration URLs from configuration."
                        ),
                        analyzer="static",
                        metadata={"url": display_url},
                    )
                )
        return findings

    @staticmethod
    def _find_line_number(content: str, needle: str) -> int | None:
        """Best-effort 1-based line number of the first line containing ``needle``."""
        for index, line in enumerate(content.splitlines(), start=1):
            if needle in line:
                return index
        return None

    @staticmethod
    def _redact_url_for_finding(url: str) -> str:
        """Remove credentials, query values, and fragments from report URLs."""
        try:
            parts = urlsplit(url)
            hostname = parts.hostname or ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = f"[{hostname}]"
            port = parts.port
        except ValueError:
            return "<redacted-url>"

        if port is not None:
            hostname = f"{hostname}:{port}"
        netloc = f"<redacted>@{hostname}" if parts.username is not None else hostname
        query = "<redacted>" if parts.query else ""
        fragment = "<redacted>" if parts.fragment else ""
        return urlunsplit((parts.scheme, netloc, parts.path, query, fragment))

    def _scan_referenced_files(self, skill: Skill) -> list[Finding]:
        """Scan files referenced in instruction body with recursive scanning."""
        max_depth = self.policy.file_limits.max_reference_depth
        findings = []
        findings.extend(self._scan_references_recursive(skill, skill.referenced_files, max_depth=max_depth))
        return findings

    def _scan_references_recursive(
        self,
        skill: Skill,
        references: list[str],
        max_depth: int = 5,
        current_depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[Finding]:
        """
        Recursively scan referenced files up to a maximum depth.

        This detects lazy-loaded content that might contain malicious patterns
        hidden in nested references.

        Args:
            skill: The skill being analyzed
            references: List of file paths to scan
            max_depth: Maximum recursion depth
            current_depth: Current depth in recursion
            visited: Set of already-visited files to prevent cycles

        Returns:
            List of findings from all referenced files
        """
        findings = []

        if visited is None:
            visited = set()

        if current_depth > max_depth:
            if references:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("LAZY_LOAD_DEEP", str(current_depth)),
                        rule_id="LAZY_LOAD_DEEP_NESTING",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Deeply nested file references detected",
                        description=(
                            f"Skill has file references nested more than {max_depth} levels deep. "
                            f"This could be an attempt to hide malicious content in files that are "
                            f"only loaded under specific conditions."
                        ),
                        file_path="SKILL.md",
                        remediation="Flatten the reference structure or ensure all nested files are safe",
                        analyzer="static",
                    )
                )
            return findings

        for ref_file_path in references:
            if _is_path_traversal(ref_file_path):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("PATH_TRAVERSAL", ref_file_path),
                        rule_id="PATH_TRAVERSAL_ATTEMPT",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        title="Path traversal attempt in file reference",
                        description=(
                            f"Reference '{ref_file_path}' attempts to escape the skill directory. "
                            f"This is a path traversal attack that could read sensitive files "
                            f"from the host system."
                        ),
                        file_path="SKILL.md",
                        remediation="Remove path traversal sequences from file references",
                        analyzer="static",
                    )
                )
                continue

            full_path = skill.directory / ref_file_path
            if not full_path.exists():
                alt_paths = [
                    skill.directory / "references" / ref_file_path,
                    skill.directory / "assets" / ref_file_path,
                    skill.directory / "templates" / ref_file_path,
                    skill.directory / "scripts" / ref_file_path,
                ]
                for alt in alt_paths:
                    if alt.exists():
                        full_path = alt
                        break

            if not full_path.exists():
                continue

            if not _is_within_directory(full_path, skill.directory):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("PATH_TRAVERSAL_RESOLVED", ref_file_path),
                        rule_id="PATH_TRAVERSAL_ATTEMPT",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        title="File reference resolves outside skill directory",
                        description=(
                            f"Reference '{ref_file_path}' resolves to a path outside the skill "
                            f"directory. This could be a path traversal attack."
                        ),
                        file_path="SKILL.md",
                        remediation="Ensure all file references point to files within the skill directory",
                        analyzer="static",
                    )
                )
                continue

            dedupe_reference_aliases = self.policy.rule_scoping.dedupe_reference_aliases
            # De-duplicate aliases to the same physical file (e.g.
            # "cover_art_generator.py" and "scripts/cover_art_generator.py").
            if dedupe_reference_aliases:
                try:
                    visited_key = str(full_path.resolve())
                except OSError:
                    visited_key = str(full_path)
            else:
                visited_key = ref_file_path
            if visited_key in visited:
                continue
            visited.add(visited_key)

            # Prefer the canonical skill-relative path for reporting.
            display_path = ref_file_path
            if dedupe_reference_aliases:
                try:
                    resolved_full = full_path.resolve()
                    for sf in skill.files:
                        try:
                            if sf.path.resolve() == resolved_full:
                                display_path = sf.relative_path
                                break
                        except OSError:
                            continue
                except OSError:
                    pass

            try:
                with open(full_path, encoding="utf-8") as f:
                    content = f.read()

                suffix = full_path.suffix.lower()
                if suffix in (".md", ".markdown"):
                    rules = self.rule_loader.get_rules_for_file_type("markdown")
                elif suffix == ".py":
                    rules = self.rule_loader.get_rules_for_file_type("python")
                elif suffix in (".sh", ".bash"):
                    rules = self.rule_loader.get_rules_for_file_type("bash")
                elif suffix in (".js", ".mjs", ".cjs"):
                    rules = self.rule_loader.get_rules_for_file_type("javascript")
                elif suffix in (".ts", ".tsx"):
                    rules = self.rule_loader.get_rules_for_file_type("typescript")
                else:
                    rules = []

                skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)
                is_doc = self._is_doc_file(display_path)
                scan_context = SignatureScanContext(content)

                for rule in rules:
                    # Skip rules scoped out of documentation files
                    if is_doc and rule.id in skip_in_docs:
                        continue
                    matches = rule.scan_content(
                        content,
                        display_path,
                        scan_context=scan_context,
                    )
                    for match in matches:
                        finding = self._create_finding_from_match(rule, match)
                        finding.metadata["reference_depth"] = current_depth
                        findings.append(finding)

                nested_refs = self._extract_references_from_content(full_path, content)
                if nested_refs:
                    findings.extend(
                        self._scan_references_recursive(skill, nested_refs, max_depth, current_depth + 1, visited)
                    )

            except Exception as e:
                logger.debug("Failed to scan reference %s: %s", full_path, e)

        return findings

    def _extract_references_from_content(self, file_path: Path, content: str) -> list[str]:
        """
        Extract file references from content based on file type.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of referenced file paths
        """
        references = []
        suffix = file_path.suffix.lower()

        if suffix in (".md", ".markdown"):
            markdown_links = _MARKDOWN_LINK_PATTERN.findall(content)
            for _, link in markdown_links:
                if not link.startswith(("http://", "https://", "ftp://", "#")):
                    if not _is_path_traversal(link):
                        references.append(link)

        elif suffix == ".py":
            import_patterns = _PYTHON_IMPORT_PATTERN.findall(content)
            for imp in import_patterns:
                if imp and not _is_path_traversal(imp):
                    references.append(f"{imp}.py")

        elif suffix in (".sh", ".bash"):
            source_patterns = _BASH_SOURCE_PATTERN.findall(content)
            for src in source_patterns:
                if not _is_path_traversal(src):
                    references.append(src)

        return references

    def _check_binary_files(self, skill: Skill) -> list[Finding]:
        """Check for binary files in skill package with tiered asset classification and magic byte validation."""
        from ..file_magic import check_extension_mismatch

        findings = []

        # Extension classifications from policy (org-customisable)
        INERT_EXTENSIONS = self.policy.file_classification.inert_extensions
        STRUCTURED_EXTENSIONS = self.policy.file_classification.structured_extensions
        ARCHIVE_EXTENSIONS = self.policy.file_classification.archive_extensions
        allow_script_shebang_text_extensions = self.policy.file_classification.allow_script_shebang_text_extensions
        shebang_compatible_extensions = self.policy.file_classification.script_shebang_extensions or None

        min_confidence = self.policy.analysis_thresholds.min_confidence_pct / 100.0
        for skill_file in skill.files:
            file_path_obj = Path(skill_file.relative_path)
            ext = file_path_obj.suffix.lower()
            if file_path_obj.name.endswith(".tar.gz"):
                ext = ".tar.gz"

            # Run file magic mismatch check on ALL files with known extensions
            # (regardless of whether they're classified as binary)
            if skill_file.path.exists():
                mismatch = check_extension_mismatch(
                    skill_file.path,
                    min_confidence=min_confidence,
                    allow_script_shebang_text_extensions=allow_script_shebang_text_extensions,
                    shebang_compatible_extensions=shebang_compatible_extensions,
                )
                if mismatch:
                    mismatch_severity, mismatch_desc, magic_match = mismatch
                    severity_map = {
                        "CRITICAL": Severity.CRITICAL,
                        "HIGH": Severity.HIGH,
                        "MEDIUM": Severity.MEDIUM,
                    }
                    findings.append(
                        Finding(
                            id=self._generate_finding_id("FILE_MAGIC_MISMATCH", skill_file.relative_path),
                            rule_id="FILE_MAGIC_MISMATCH",
                            category=ThreatCategory.OBFUSCATION,
                            severity=severity_map.get(mismatch_severity, Severity.MEDIUM),
                            title="File extension does not match actual content type",
                            description=mismatch_desc,
                            file_path=skill_file.relative_path,
                            remediation="Rename the file to match its actual content type, or remove it if it appears malicious.",
                            analyzer="static",
                            metadata={
                                "actual_type": magic_match.content_type,
                                "actual_family": magic_match.content_family,
                                "claimed_extension": ext,
                                "confidence_score": magic_match.score,
                                **_semantic_metadata(
                                    rule_id="FILE_MAGIC_MISMATCH",
                                    file_path=skill_file.relative_path,
                                    evidence_kind="file_magic",
                                    context_kind="binary",
                                    signal_kind="file_magic_mismatch",
                                    # CEL receives only the bounded behavioral
                                    # class; the exact MIME family remains in
                                    # ordinary finding metadata above.
                                    value_class="binary",
                                ),
                            },
                        )
                    )

            # Only check further if the file is classified as binary
            if skill_file.file_type != "binary":
                continue

            if ext in {".pkl", ".pickle"}:
                findings.append(self._pickle_finding(skill_file))
                continue

            if ext in INERT_EXTENSIONS:
                continue

            if ext in STRUCTURED_EXTENSIONS:
                # SVGs will be scanned by multimodal analyzer for embedded scripts
                # Just note their presence for now
                continue

            if ext in ARCHIVE_EXTENSIONS:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ARCHIVE_FILE_DETECTED", skill_file.relative_path),
                        rule_id="ARCHIVE_FILE_DETECTED",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Archive file detected in skill package",
                        description=(
                            f"Archive file found: {skill_file.relative_path}. "
                            f"Archives can contain hidden executables, scripts, or other malicious content "
                            f"that is not visible without extraction."
                        ),
                        file_path=skill_file.relative_path,
                        remediation="Extract archive contents and include files directly, or document the archive's purpose.",
                        analyzer="static",
                        metadata=_semantic_metadata(
                            rule_id="ARCHIVE_FILE_DETECTED",
                            file_path=skill_file.relative_path,
                            evidence_kind="file_inventory",
                            context_kind="binary",
                            signal_kind="archive_binary",
                            value_class="archive",
                        ),
                    )
                )
                continue

            # Unknown binary file - informational only
            findings.append(
                Finding(
                    id=self._generate_finding_id("BINARY_FILE_DETECTED", skill_file.relative_path),
                    rule_id="BINARY_FILE_DETECTED",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Binary file detected in skill package",
                    description=f"Binary file found: {skill_file.relative_path}. "
                    f"Binary files cannot be inspected by static analysis. "
                    f"Consider using Python or Bash scripts for transparency.",
                    file_path=skill_file.relative_path,
                    remediation="Review binary file necessity. Replace with auditable scripts if possible.",
                    analyzer="static",
                    metadata=_semantic_metadata(
                        rule_id="BINARY_FILE_DETECTED",
                        file_path=skill_file.relative_path,
                        evidence_kind="file_inventory",
                        context_kind="binary",
                        signal_kind="unanalyzable_binary",
                        # Raw extensions are open-ended and must not cross the
                        # closed semantic-fact boundary.
                        value_class="binary",
                    ),
                )
            )

        return findings

    def _pickle_finding(self, skill_file) -> Finding:
        """Report serialized Python objects as executable, untrusted content.

        Pickle is not a data-only format: loading a pickle can invoke arbitrary
        callables encoded by the producer.  Inspect opcodes with ``pickletools``
        (which never unpickles the object) to distinguish an ordinary serialized
        object from one that visibly references a code-execution primitive.
        Even a syntactically valid pickle remains HIGH because static analysis
        cannot make loading attacker-controlled pickle data safe.
        """
        dangerous_globals: list[str] = []
        executable_opcodes: list[str] = []
        parse_error: str | None = None
        inspection_skipped_reason: str | None = None
        inspection_limit = max(0, self.policy.file_limits.max_loader_file_size_bytes)

        def _record_global(module: str, name: str) -> None:
            reference = f"{module} {name}"
            if module in {"builtins", "os", "posix", "nt", "subprocess", "commands"} or name in {
                "eval",
                "exec",
                "system",
                "popen",
                "spawn",
                "Popen",
            }:
                dangerous_globals.append(reference)

        if skill_file.size_bytes > inspection_limit:
            inspection_skipped_reason = "size-limit"
        else:
            try:
                # Bound the actual read as well as checking the loader's size
                # metadata, so a file replacement race cannot exhaust memory.
                with skill_file.path.open("rb") as handle:
                    payload = handle.read(inspection_limit + 1)
                if len(payload) > inspection_limit:
                    inspection_skipped_reason = "size-limit"
                else:
                    stack: list[object] = []
                    memo: dict[int, object] = {}
                    next_memo_index = 0
                    mark = object()
                    string_opcodes = {
                        "STRING",
                        "BINSTRING",
                        "SHORT_BINSTRING",
                        "UNICODE",
                        "BINUNICODE",
                        "SHORT_BINUNICODE",
                        "BINUNICODE8",
                    }

                    for opcode, argument, _ in pickletools.genops(payload):
                        opcode_name = opcode.name
                        if opcode_name in string_opcodes:
                            if isinstance(argument, bytes):
                                stack.append(argument.decode("utf-8", errors="replace"))
                            else:
                                stack.append(argument if isinstance(argument, str) else None)
                        elif opcode_name == "MEMOIZE":
                            memo[next_memo_index] = stack[-1] if stack else None
                            next_memo_index += 1
                        elif opcode_name in {"PUT", "BINPUT", "LONG_BINPUT"}:
                            if argument is not None:
                                memo[int(argument)] = stack[-1] if stack else None
                        elif opcode_name in {"GET", "BINGET", "LONG_BINGET"}:
                            stack.append(memo.get(int(argument)) if argument is not None else None)
                        elif opcode_name == "GLOBAL" and isinstance(argument, str):
                            module, _, name = argument.partition(" ")
                            _record_global(module, name)
                            stack.append(None)
                        elif opcode_name == "STACK_GLOBAL":
                            executable_opcodes.append(opcode_name)
                            stack_name = stack.pop() if stack else None
                            stack_module = stack.pop() if stack else None
                            if isinstance(stack_module, str) and isinstance(stack_name, str):
                                _record_global(stack_module, stack_name)
                            stack.append(None)
                        elif opcode_name == "REDUCE":
                            executable_opcodes.append(opcode_name)
                            if stack:
                                stack.pop()
                            if stack:
                                stack.pop()
                            stack.append(None)
                        elif opcode_name == "MARK":
                            stack.append(mark)
                        elif opcode_name == "POP":
                            if stack:
                                stack.pop()
                        elif opcode_name == "POP_MARK":
                            while stack and stack.pop() is not mark:
                                pass
                        elif opcode_name == "DUP" and stack:
                            stack.append(stack[-1])
            except Exception as exc:  # noqa: BLE001 - malformed untrusted bytes must not abort a scan
                parse_error = type(exc).__name__

        suspicious = bool(dangerous_globals)
        details = ""
        if dangerous_globals:
            details = f" Detected executable pickle opcode references: {', '.join(sorted(set(dangerous_globals)))}."
        elif inspection_skipped_reason:
            details = (
                f" Opcode inspection was skipped because the file exceeds the {inspection_limit}-byte "
                "inspection limit; the file must still be treated as untrusted."
            )
        elif parse_error:
            details = f" Opcode inspection failed ({parse_error}); the file must still be treated as untrusted."

        metadata: dict[str, object] = {
            "opcode_inspection": "pickletools.genops",
            "dangerous_opcodes": dangerous_globals,
            "observed_executable_opcodes": sorted(set(executable_opcodes)),
            "inspection_limit_bytes": inspection_limit,
        }
        if inspection_skipped_reason:
            metadata["inspection_skipped_reason"] = inspection_skipped_reason
        if parse_error:
            metadata["parse_error"] = parse_error

        return Finding(
            id=self._generate_finding_id("PICKLE_FILE_DETECTED", skill_file.relative_path),
            rule_id="PICKLE_FILE_DETECTED",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.CRITICAL if suspicious else Severity.HIGH,
            title="Executable Python pickle detected",
            description=(
                f"Pickle file found: {skill_file.relative_path}. Python pickle loading can execute "
                f"arbitrary code supplied by the file producer; do not load it from an untrusted skill."
                f"{details}"
            ),
            file_path=skill_file.relative_path,
            remediation="Remove pickle files from skills. Use a non-executable data format such as JSON instead.",
            analyzer="static",
            metadata=metadata,
        )

    def _check_hidden_files(self, skill: Skill) -> list[Finding]:
        """Check for hidden files (dotfiles) and __pycache__ in skill package."""
        findings = []

        # Code extensions from policy (org-customisable)
        CODE_EXTENSIONS = self.policy.file_classification.code_extensions

        # Use policy-defined allowlists (org-customisable)
        benign_dotfiles = self.policy.hidden_files.benign_dotfiles
        benign_dotdirs = self.policy.hidden_files.benign_dotdirs

        # Track pycache directories already flagged (consolidate to one finding per dir)
        flagged_pycache_dirs: set[str] = set()

        for skill_file in skill.files:
            rel_path = skill_file.relative_path
            path_obj = Path(rel_path)

            if skill_file.is_pycache:
                # Consolidate: one finding per __pycache__ directory, not per file
                pycache_dir = str(path_obj.parent)
                if pycache_dir in flagged_pycache_dirs:
                    continue
                flagged_pycache_dirs.add(pycache_dir)

                # Count how many .pyc files are in this directory
                pyc_count = sum(
                    1 for sf in skill.files if sf.is_pycache and str(Path(sf.relative_path).parent) == pycache_dir
                )

                findings.append(
                    Finding(
                        id=self._generate_finding_id("PYCACHE_FILES_DETECTED", pycache_dir),
                        rule_id="PYCACHE_FILES_DETECTED",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.LOW,
                        title="Python bytecode cache directory detected",
                        description=(
                            f"__pycache__ directory found at {pycache_dir}/ "
                            f"containing {pyc_count} bytecode file(s). "
                            f"Pre-compiled bytecode should not be distributed in skill packages."
                        ),
                        file_path=pycache_dir,
                        remediation="Remove __pycache__ directories from skill packages. Ship source code only.",
                        analyzer="static",
                    )
                )
            elif skill_file.is_hidden:
                ext = path_obj.suffix.lower()
                parts = path_obj.parts
                filename = path_obj.name

                # Skip known benign dotfiles (from policy)
                if filename.lower() in benign_dotfiles:
                    continue

                # Skip files inside known benign hidden directories (from policy)
                hidden_parts = [p for p in parts if p.startswith(".") and p != "."]
                if any(p.lower() in benign_dotdirs for p in hidden_parts):
                    continue

                if ext in CODE_EXTENSIONS or skill_file.file_type in {
                    "python",
                    "bash",
                    "javascript",
                    "typescript",
                }:
                    findings.append(
                        Finding(
                            id=self._generate_finding_id("HIDDEN_EXECUTABLE_SCRIPT", rel_path),
                            rule_id="HIDDEN_EXECUTABLE_SCRIPT",
                            category=ThreatCategory.OBFUSCATION,
                            severity=Severity.HIGH,
                            title="Hidden executable script detected",
                            description=(
                                f"Hidden script file found: {rel_path}. "
                                f"Hidden files (dotfiles) are often used to conceal malicious code "
                                f"from casual inspection."
                            ),
                            file_path=rel_path,
                            remediation="Move script to a visible location or remove if not needed.",
                            analyzer="static",
                            metadata=_semantic_metadata(
                                rule_id="HIDDEN_EXECUTABLE_SCRIPT",
                                file_path=rel_path,
                                evidence_kind="file_inventory",
                                context_kind="code",
                                signal_kind="hidden_executable",
                                value_class=skill_file.file_type or ext or "script",
                            ),
                        )
                    )
                else:
                    # Unknown hidden data/config file
                    findings.append(
                        Finding(
                            id=self._generate_finding_id("HIDDEN_DATA_FILE", rel_path),
                            rule_id="HIDDEN_DATA_FILE",
                            category=ThreatCategory.OBFUSCATION,
                            severity=Severity.LOW,
                            title="Hidden data file detected",
                            description=(
                                f"Hidden file found: {rel_path}. "
                                f"Hidden files may contain concealed configuration or data "
                                f"that should be reviewed."
                            ),
                            file_path=rel_path,
                            remediation="Move file to a visible location or document its purpose.",
                            analyzer="static",
                            metadata=_semantic_metadata(
                                rule_id="HIDDEN_DATA_FILE",
                                file_path=rel_path,
                                evidence_kind="file_inventory",
                                context_kind="package",
                                signal_kind="hidden_file",
                                value_class=skill_file.file_type or ext or "data",
                            ),
                        )
                    )

        return findings

    # ------------------------------------------------------------------ #
    # ASCII Smuggling / Unicode Tag Block detection                        #
    # ------------------------------------------------------------------ #

    # Unicode Tag Block: U+E0000 (TAG NULL) through U+E007F (TAG DELETE).
    # U+E0020–U+E007E map 1-to-1 to printable ASCII.  No legitimate use
    # for these codepoints exists in skill files.
    _TAG_BLOCK_START = 0xE0000
    _TAG_BLOCK_END = 0xE007F
    _TAG_PRINTABLE_START = 0xE0020
    _TAG_PRINTABLE_END = 0xE007E
    _TAG_BOUNDARY_CODEPOINTS = frozenset([0xE0000, 0xE0001, 0xE007F])

    @staticmethod
    def _decode_tag_chars(tag_codepoints: list[int]) -> str:
        """Decode Tag Block codepoints back to their ASCII equivalents."""
        decoded: list[str] = []
        for cp in tag_codepoints:
            ascii_cp = cp - 0xE0000
            if 0x20 <= ascii_cp <= 0x7E:
                decoded.append(chr(ascii_cp))
            elif ascii_cp == 0x01:
                decoded.append("<SOT>")
            elif ascii_cp == 0x7F:
                decoded.append("<EOT>")
            else:
                decoded.append("?")
        return "".join(decoded)

    def _check_ascii_smuggling(self, skill: Skill) -> list[Finding]:
        """Detect ASCII smuggling via Unicode Tag Block characters (U+E0000–U+E007F).

        ASCII smuggling encodes each printable ASCII character as its invisible
        Tag Block counterpart and embeds the result inside skill files.  The
        payload is invisible in editors and terminals but is decoded by LLMs,
        enabling hidden prompt-injection instructions.

        Reference: https://embracethered.com/blog/posts/2026/scary-agent-skills/
        """
        findings: list[Finding] = []

        for skill_file in skill.files:
            if skill_file.content is None:
                continue

            content: str = skill_file.content
            tag_chars: list[int] = []
            first_line: int = 1
            first_line_located = False

            for line_no, line in enumerate(content.split("\n"), start=1):
                for ch in line:
                    cp = ord(ch)
                    if self._TAG_BLOCK_START <= cp <= self._TAG_BLOCK_END:
                        tag_chars.append(cp)
                        if not first_line_located:
                            first_line = line_no
                            first_line_located = True

            if not tag_chars:
                continue

            decoded = self._decode_tag_chars(tag_chars)
            preview = decoded[:120] + ("…" if len(decoded) > 120 else "")
            printable_count = sum(1 for cp in tag_chars if self._TAG_PRINTABLE_START <= cp <= self._TAG_PRINTABLE_END)
            boundary_count = sum(1 for cp in tag_chars if cp in self._TAG_BOUNDARY_CODEPOINTS)

            findings.append(
                Finding(
                    id=self._generate_finding_id("ASCII_SMUGGLING_TAG_BLOCK", skill_file.relative_path),
                    rule_id="ASCII_SMUGGLING_TAG_BLOCK",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="ASCII smuggling via Unicode Tag Block detected",
                    description=(
                        f"ASCII smuggling detected in '{skill_file.relative_path}': "
                        f"{len(tag_chars)} Unicode Tag Block character(s) found "
                        f"({printable_count} printable, {boundary_count} boundary marker(s)). "
                        f"First occurrence at line {first_line}. "
                        f"Decoded hidden payload (first 120 chars): «{preview}». "
                        "Tag Block characters (U+E0000–U+E007F) are invisible in editors "
                        "but are decoded by LLMs, enabling hidden prompt-injection payloads "
                        "inside otherwise-legitimate skill files."
                    ),
                    file_path=skill_file.relative_path,
                    line_number=first_line,
                    remediation=(
                        "Remove all Unicode Tag Block characters (U+E0000–U+E007F) "
                        "from the file. "
                        "You can strip them with: "
                        'python3 -c "'
                        "import sys; t=open(sys.argv[1]).read(); "
                        "open(sys.argv[1],'w').write("
                        "''.join(c for c in t if not(0xE0000<=ord(c)<=0xE007F)))\" <file>. "
                        "Or use the 'aid' tool: https://github.com/wunderwuzzi23/aid"
                    ),
                    analyzer="static",
                )
            )

        return findings

    @staticmethod
    def _socket_target_is_local(node: ast.AST | None) -> bool:
        """Return whether a socket call target is explicitly local-only."""
        if isinstance(node, (ast.Tuple, ast.List)) and node.elts:
            node = node.elts[0]

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.strip().lower().rstrip(".") in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

        if isinstance(node, ast.Call):
            return not node.args and StaticAnalyzer._attribute_path(node.func) == "socket.gethostname"

        return False

    def _socket_call_can_contact_remote(self, node: ast.Call) -> bool:
        """Classify one supported socket call using its own target argument."""
        call_path = self._attribute_path(node.func)
        if (
            call_path is None
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
            and isinstance(node.func.value, ast.Call)
            and self._attribute_path(node.func.value.func) == "socket.socket"
        ):
            call_path = "socket.socket.connect"

        target_apis = {
            "socket.connect",
            "socket.socket.connect",
            "socket.create_connection",
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.getnameinfo",
            "socket.getfqdn",
        }
        if call_path not in target_apis:
            return False

        # getfqdn() without an argument resolves the current host only.
        if call_path == "socket.getfqdn" and not node.args:
            return False

        target = node.args[0] if node.args else None
        return not self._socket_target_is_local(target)

    def _content_uses_external_socket_api(self, content: str) -> bool:
        """Return whether any individual socket call can contact a remote host."""
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            # Preserve conservative detection for malformed or partial Python.
            return bool(
                re.search(
                    r"socket\.(?:connect|create_connection|getaddrinfo|gethostbyname(?:_ex)?|getnameinfo|getfqdn)\s*\(",
                    content,
                )
                or re.search(r"socket\.socket\s*\([^)]*\)\.connect\s*\(", content)
            )

        return any(self._socket_call_can_contact_remote(node) for node in ast.walk(tree) if isinstance(node, ast.Call))

    @staticmethod
    def _decode_obfuscated_unicode_with_provenance(text: str) -> _DecodedUnicodeText:
        """Decode one bounded scalar chunk with exact source provenance.

        Every source scalar emits at most four ASCII scalars, aggregate output
        is capped at four times the input, and removed default-ignorables retain a
        boundary anchor. Returning ``complete=False`` never exposes a decoded
        prefix to the detector.
        """
        if len(text) > _UNICODE_DECODE_CHUNK_CHARS:
            return _DecodedUnicodeText("", frozenset(), (), (), (), False)
        if text.isascii():
            # No supported Unicode representation can occur in ASCII-only
            # text, so avoid allocating per-character provenance for the
            # overwhelmingly common case.
            return _DecodedUnicodeText(text, frozenset(), (), (), (), True)

        # Resolve each distinct non-ASCII scalar once before allocating dense
        # provenance. Irrelevant compatibility characters such as U+FDFA then
        # take the fast path even when repeated throughout a large slab.
        projections = {
            character: _unicode_scalar_projection(character) for character in set(text) if not character.isascii()
        }
        if not any(projection is not None for projection in projections.values()):
            return _DecodedUnicodeText(text, frozenset(), (), (), (), True)

        decoded: list[str] = []
        transformation_kinds: list[str | None] = []
        source_offsets: list[int] = []
        deleted_transformations: list[_DeletedUnicodeTransformation] = []
        encodings: set[str] = set()
        output_limit = len(text) * _UNICODE_MAX_OUTPUT_FACTOR

        for source_offset, source_char in enumerate(text):
            projection = None if source_char.isascii() else projections[source_char]
            if projection is None:
                emitted = source_char
                transformation_kind = None
            else:
                emitted, transformation_kind = projection

            if transformation_kind is not None and not emitted:
                # Collapse an arbitrarily long run at one output boundary to
                # one auditable source location per class; one deleted scalar
                # is sufficient only after fixed-token causality is proven.
                if not deleted_transformations or (
                    deleted_transformations[-1].kind,
                    deleted_transformations[-1].output_offset,
                ) != (transformation_kind, len(decoded)):
                    deleted_transformations.append(
                        _DeletedUnicodeTransformation(transformation_kind, source_offset, len(decoded))
                    )
                encodings.add(transformation_kind)
                continue

            # Every accepted normalization is independently capped at four
            # ASCII scalars, so the 4x aggregate limit is order-independent.
            if len(decoded) + len(emitted) > output_limit:
                return _DecodedUnicodeText("", frozenset(), (), (), (), False)
            decoded.extend(emitted)
            transformation_kinds.extend([transformation_kind] * len(emitted))
            source_offsets.extend([source_offset] * len(emitted))
            if transformation_kind is not None:
                encodings.add(transformation_kind)

        return _DecodedUnicodeText(
            text="".join(decoded),
            encodings=frozenset(encodings),
            transformation_kinds=tuple(transformation_kinds),
            source_offsets=tuple(source_offsets),
            deleted_transformations=tuple(deleted_transformations),
            complete=True,
        )

    @staticmethod
    def _decode_obfuscated_unicode(text: str) -> tuple[str, set[str]]:
        """Decode one bounded Unicode chunk, preserving legacy return types."""
        decoded = StaticAnalyzer._decode_obfuscated_unicode_with_provenance(text)
        if not decoded.complete:
            return text, set()
        return decoded.text, set(decoded.encodings)

    def _check_unicode_obfuscated_instructions(self, skill: Skill) -> list[Finding]:
        """Detect high-signal prompt injections hidden behind Unicode variants.

        Detection runs over bounded decoded slabs with a rolling decoded-output
        overlap, so default-ignorables cannot split a signature across source
        chunk boundaries. Only transformations inside fixed signature tokens or
        delimiters are causal; typography in wildcard gaps is ignored.
        """
        findings: list[Finding] = []
        package_work_units = 0
        package_budget_exhausted = False
        eligible_types = {"markdown", "python", "bash", "javascript", "typescript"}
        referenced = {Path(path).as_posix() for path in skill.referenced_files}
        synthetic_source_count = int(skill.load_metadata.get("synthetic_instruction_source_count", 0))

        def file_priority(skill_file: SkillFile) -> tuple[int, str]:
            is_primary = skill_file.path == skill.skill_md_path
            if is_primary:
                priority = 0
            elif skill_file.relative_path in referenced and skill_file.file_type != "markdown":
                priority = 1
            elif skill_file.file_type != "markdown":
                priority = 2
            else:
                priority = 3
            return priority, skill_file.relative_path

        for sf in sorted(skill.files, key=file_priority):
            if sf.file_type not in eligible_types:
                continue
            is_synthetic_multi_markdown = synthetic_source_count > 1
            is_primary_instructions = sf.path == skill.skill_md_path and not is_synthetic_multi_markdown
            if is_primary_instructions:
                content = skill.instruction_body
            elif sf.content is not None:
                content = sf.content
            else:
                continue
            if not content or content.isascii():
                continue
            # CommonMark treats CRLF and bare CR as line endings. Normalize
            # them before bounded region parsing so physical line attribution
            # matches LF input without invoking splitlines()'s broader Unicode
            # separator semantics.
            content = content.replace("\r\n", "\n").replace("\r", "\n")

            if sf.file_type == "markdown":
                regions = _unicode_markdown_regions(
                    content,
                    line_offset=max(0, skill.instruction_body_line_offset) if is_primary_instructions else 0,
                )
                if regions is None:
                    # Structural bounds disable precision suppression, not the
                    # extractor. Raw streaming remains bounded per slab.
                    regions = [
                        _UnicodeScanRegion(
                            content,
                            1 + (max(0, skill.instruction_body_line_offset) if is_primary_instructions else 0),
                            "active_instruction",
                        )
                    ]
            else:
                regions = [_UnicodeScanRegion(content, 1, "code")]

            selected: tuple[str, set[str], set[int], int, _UnicodeScanRegion] | None = None
            file_work_units = 0
            analysis_incomplete = False
            for region in regions:
                carry_text = ""
                carry_kinds: tuple[str | None, ...] = ()
                carry_source_offsets: tuple[int, ...] = ()
                carry_deleted: tuple[_DeletedUnicodeTransformation, ...] = ()

                for source_slab, slab_offset in _unicode_bounded_chunks(region):
                    carry_has_projection = any(kind is not None for kind in carry_kinds) or bool(carry_deleted)
                    if source_slab.isascii() and not carry_has_projection:
                        # CPython's bounded ASCII predicate establishes that no
                        # scalar in this slab can create Unicode provenance. It
                        # keeps large ASCII prefixes cheap while retaining tail
                        # coverage at the loader limit.
                        tail_start = max(0, len(source_slab) - _UNICODE_DECODE_OVERLAP_CHARS)
                        carry_text = source_slab[tail_start:]
                        carry_kinds = (None,) * len(carry_text)
                        carry_source_offsets = tuple(
                            slab_offset + offset for offset in range(tail_start, len(source_slab))
                        )
                        carry_deleted = ()
                        continue

                    # Charge every inspected non-ASCII source scalar before the
                    # projection fast path. Dense irrelevant Unicode therefore
                    # cannot bypass the declared file/package work contract.
                    source_work_units = len(source_slab)
                    if (
                        file_work_units + source_work_units > _UNICODE_MAX_FILE_WORK_UNITS
                        or package_work_units + source_work_units > _UNICODE_MAX_PACKAGE_WORK_UNITS
                    ):
                        analysis_incomplete = True
                        package_budget_exhausted = (
                            package_work_units + source_work_units > _UNICODE_MAX_PACKAGE_WORK_UNITS
                        )
                        break
                    file_work_units += source_work_units
                    package_work_units += source_work_units

                    slab_has_projection = _unicode_slab_has_projection(source_slab)
                    if not slab_has_projection and not carry_has_projection:
                        # No transformed scalar can be causal in this slab. Keep
                        # only the decoded-space overlap needed by a future slab,
                        # without allocating dense provenance for the prefix.
                        tail_start = max(0, len(source_slab) - _UNICODE_DECODE_OVERLAP_CHARS)
                        carry_text = source_slab[tail_start:]
                        carry_kinds = (None,) * len(carry_text)
                        carry_source_offsets = tuple(
                            slab_offset + offset for offset in range(tail_start, len(source_slab))
                        )
                        carry_deleted = ()
                        continue

                    decoded = self._decode_obfuscated_unicode_with_provenance(source_slab)
                    if not decoded.complete:
                        # The chunk helper guarantees this today. Keep the
                        # guard fail-closed against partial decoded prefixes.
                        carry_text = ""
                        carry_kinds = ()
                        carry_source_offsets = ()
                        carry_deleted = ()
                        continue

                    # Charge actual bounded decoded output, not a 4x reserve
                    # against every ASCII scalar in a mixed slab. One rejected
                    # 64-KiB slab is the fixed maximum uncharged operation.
                    slab_work_units = len(decoded.text) + len(carry_text)
                    if (
                        file_work_units + slab_work_units > _UNICODE_MAX_FILE_WORK_UNITS
                        or package_work_units + slab_work_units > _UNICODE_MAX_PACKAGE_WORK_UNITS
                    ):
                        analysis_incomplete = True
                        package_budget_exhausted = (
                            package_work_units + slab_work_units > _UNICODE_MAX_PACKAGE_WORK_UNITS
                        )
                        break
                    file_work_units += slab_work_units
                    package_work_units += slab_work_units

                    if len(decoded.source_offsets) == len(decoded.text):
                        current_kinds = decoded.transformation_kinds
                        current_source_offsets = tuple(slab_offset + offset for offset in decoded.source_offsets)
                    elif (
                        not decoded.source_offsets
                        and not decoded.transformation_kinds
                        and not decoded.deleted_transformations
                        and len(decoded.text) == len(source_slab)
                    ):
                        # ASCII and no-op Unicode slabs intentionally skip dense
                        # identity provenance in the decoder fast path. Restore
                        # that invariant only inside the bounded streaming scan.
                        current_kinds = (None,) * len(decoded.text)
                        current_source_offsets = tuple(slab_offset + offset for offset in range(len(decoded.text)))
                    else:
                        # A complete projection must align every emitted scalar.
                        carry_text = ""
                        carry_kinds = ()
                        carry_source_offsets = ()
                        carry_deleted = ()
                        continue
                    current_deleted = tuple(
                        _DeletedUnicodeTransformation(
                            (
                                "html-comment-elision"
                                if slab_offset + item.source_offset in region.synthetic_elisions
                                else item.kind
                            ),
                            slab_offset + item.source_offset,
                            len(carry_text) + item.output_offset,
                        )
                        for item in decoded.deleted_transformations
                    )
                    combined_text = carry_text + decoded.text
                    combined_kinds = carry_kinds + current_kinds
                    combined_source_offsets = carry_source_offsets + current_source_offsets
                    combined_deleted = carry_deleted + current_deleted
                    (
                        combined_text,
                        combined_kinds,
                        combined_source_offsets,
                        combined_deleted,
                    ) = _unicode_collapse_whitespace(
                        combined_text,
                        combined_kinds,
                        combined_source_offsets,
                        combined_deleted,
                    )

                    if selected is None and (any(kind is not None for kind in combined_kinds) or combined_deleted):
                        chunk_candidate: tuple[int, str, set[str], set[int], int, _UnicodeScanRegion] | None = None
                        for pattern, fixed_groups in _OBFUSCATED_INSTRUCTION_PATTERNS:
                            for match in pattern.finditer(combined_text):
                                fixed_spans = [match.span(group_name) for group_name in fixed_groups]
                                matched_positions: dict[str, set[int]] = {}
                                for output_offset in range(match.start(), match.end()):
                                    if not any(start <= output_offset < end for start, end in fixed_spans):
                                        continue
                                    kind = combined_kinds[output_offset]
                                    if kind is not None:
                                        matched_positions.setdefault(kind, set()).add(
                                            combined_source_offsets[output_offset]
                                        )
                                for deleted in combined_deleted:
                                    boundary = deleted.output_offset
                                    left_is_fixed = any(start <= boundary - 1 < end for start, end in fixed_spans)
                                    right_is_fixed = any(start <= boundary < end for start, end in fixed_spans)
                                    if match.start() < boundary < match.end() and left_is_fixed and right_is_fixed:
                                        matched_positions.setdefault(deleted.kind, set()).add(deleted.source_offset)

                                qualifying_encodings = {
                                    kind
                                    for kind, positions in matched_positions.items()
                                    if positions and kind != "html-comment-elision"
                                }
                                if not qualifying_encodings:
                                    continue

                                match_source_offsets = combined_source_offsets[match.start() : match.end()]
                                if not match_source_offsets:
                                    continue
                                source_start = min(match_source_offsets)
                                source_end = max(match_source_offsets) + 1
                                if (
                                    region.context_kind == "active_instruction"
                                    and _unicode_match_is_inert_context(region.content, source_start, source_end)
                                ) or (
                                    region.context_kind == "code"
                                    and _unicode_code_match_is_inert_context(region.content, source_start, source_end)
                                ):
                                    continue

                                transformed_source_offsets = set().union(
                                    *(matched_positions[kind] for kind in qualifying_encodings)
                                )
                                candidate = (
                                    match.start(),
                                    " ".join(match.group().split())[:160],
                                    qualifying_encodings,
                                    transformed_source_offsets,
                                    source_start,
                                    region,
                                )
                                if chunk_candidate is None or candidate[0] < chunk_candidate[0]:
                                    chunk_candidate = candidate
                                break
                        if chunk_candidate is not None:
                            _, preview, encodings, source_offsets, match_source_start, candidate_region = (
                                chunk_candidate
                            )
                            selected = (preview, encodings, source_offsets, match_source_start, candidate_region)

                    tail_start = max(0, len(combined_text) - _UNICODE_DECODE_OVERLAP_CHARS)
                    carry_text = combined_text[tail_start:]
                    carry_kinds = combined_kinds[tail_start:]
                    carry_source_offsets = combined_source_offsets[tail_start:]
                    carry_deleted = tuple(
                        _DeletedUnicodeTransformation(
                            item.kind,
                            item.source_offset,
                            item.output_offset - tail_start,
                        )
                        for item in combined_deleted
                        if item.output_offset >= tail_start
                    )
                    if selected is not None:
                        break
                if selected is not None or analysis_incomplete:
                    break

            if selected is None:
                if analysis_incomplete:
                    findings.append(
                        Finding(
                            id=self._generate_finding_id("UNICODE_ANALYSIS_INCOMPLETE", sf.relative_path),
                            rule_id="UNICODE_ANALYSIS_INCOMPLETE",
                            category=ThreatCategory.POLICY_VIOLATION,
                            severity=Severity.INFO,
                            title="Unicode instruction analysis incomplete",
                            description=(
                                f"Unicode projection for {sf.relative_path} exceeded a deterministic bounded-work "
                                "limit. Earlier findings remain valid, but the absence of another Unicode finding "
                                "does not establish safety for the uninspected remainder."
                            ),
                            file_path=sf.relative_path,
                            line_number=None,
                            remediation=(
                                "Reduce or remove dense Unicode compatibility/confusable content and rescan the "
                                "complete package."
                            ),
                            analyzer="static",
                            metadata={
                                "analysis_incomplete": True,
                                "reason": "unicode-work-limit",
                                "error_code": (
                                    "UNICODE_PACKAGE_WORK_LIMIT_EXCEEDED"
                                    if package_budget_exhausted
                                    else "UNICODE_FILE_WORK_LIMIT_EXCEEDED"
                                ),
                                "work_model": "unicode_projection_v1",
                                "file_work_units": file_work_units,
                                "file_work_limit": _UNICODE_MAX_FILE_WORK_UNITS,
                                "package_work_units": package_work_units,
                                "package_work_limit": _UNICODE_MAX_PACKAGE_WORK_UNITS,
                            },
                        )
                    )
                if package_budget_exhausted:
                    break
                continue

            preview, selected_encodings, selected_source_offsets, match_source_start, selected_region = selected
            first_transformed_source_offset = min(selected_source_offsets)
            first_line = selected_region.start_line + selected_region.content.count("\n", 0, match_source_start)
            first_transformed_line = selected_region.start_line + selected_region.content.count(
                "\n", 0, first_transformed_source_offset
            )
            findings.append(
                Finding(
                    id=self._generate_finding_id("UNICODE_OBFUSCATED_INSTRUCTION", sf.relative_path),
                    rule_id="UNICODE_OBFUSCATED_INSTRUCTION",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    title="Obfuscated prompt-injection instructions detected",
                    description=(
                        f"Unicode-obfuscated instructions were detected in {sf.relative_path} using "
                        f"{', '.join(sorted(selected_encodings))}. Recovered text includes a high-risk instruction or "
                        f"data-access pattern: {preview}"
                    ),
                    file_path=sf.relative_path,
                    line_number=first_line,
                    remediation="Remove the obfuscated Unicode content and review the skill for prompt-injection and data-exfiltration behavior.",
                    analyzer="static",
                    metadata={
                        "encodings": sorted(selected_encodings),
                        "decoded_preview": preview,
                        "matched_transformed_codepoint_count": len(selected_source_offsets),
                        "context_kind": selected_region.context_kind,
                        "first_transformed_line": first_transformed_line,
                    },
                )
            )
        return findings

    def _skill_network_usage_path(self, skill: Skill) -> str | None:
        """Return the first package-relative script with external network behavior."""
        external_network_indicators = [
            "import requests",
            "from requests import",
            "import urllib.request",
            "from urllib.request import",
            "import http.client",
            "import httpx",
            "import aiohttp",
        ]

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()

            if any(indicator in content for indicator in external_network_indicators):
                return skill_file.relative_path

            if "import socket" in content and self._content_uses_external_socket_api(content):
                return skill_file.relative_path

        return None

    def _skill_uses_network(self, skill: Skill) -> bool:
        """Check if skill code uses network libraries for EXTERNAL communication."""
        return self._skill_network_usage_path(skill) is not None

    def _manifest_declares_network(self, skill: Skill) -> bool:
        """Check if manifest declares network usage."""
        if skill.manifest.compatibility:
            compatibility_lower = str(skill.manifest.compatibility).lower()
            return "network" in compatibility_lower or "internet" in compatibility_lower
        return False

    def _check_description_mismatch(self, skill: Skill) -> bool:
        """Check for description/behavior mismatch (basic heuristic)."""
        description = skill.description.lower()

        simple_keywords = ["calculator", "format", "template", "style", "lint"]
        if any(keyword in description for keyword in simple_keywords):
            if self._skill_uses_network(skill):
                return True

        return False

    def _check_allowed_tools_violations(self, skill: Skill) -> list[Finding]:
        """Check if code behavior violates allowed-tools restrictions."""
        findings: list[Finding] = []

        if not skill.manifest.allowed_tools:
            return findings

        allowed_tools_lower = [tool.lower() for tool in skill.manifest.allowed_tools]
        # Capability mismatches are manifest findings.  Keep their location
        # stable and package-relative rather than leaking the checkout path.
        skillmd = "SKILL.md"

        if "read" not in allowed_tools_lower:
            if self._code_reads_files(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_READ_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_READ_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.MEDIUM,
                        title="Code reads files but Read tool not in allowed-tools",
                        description=(
                            f"Skill restricts tools to {skill.manifest.allowed_tools} but bundled scripts appear to "
                            f"read files from the filesystem."
                        ),
                        file_path=skillmd,
                        remediation="Add 'Read' to allowed-tools or remove file reading operations from scripts",
                        analyzer="static",
                        metadata=_semantic_metadata(
                            rule_id="ALLOWED_TOOLS_READ_VIOLATION",
                            file_path="SKILL.md",
                            evidence_kind="capability_mismatch",
                            context_kind="manifest",
                            signal_kind="undeclared_tool",
                            value_class="read",
                            candidate_command={
                                "executable": "Read",
                                "argument_classes": [],
                                "downloads": False,
                                "executes": False,
                                "destructive": False,
                                "privilege_change": False,
                                "source_class": "skill_code",
                                "sink_class": "filesystem_read",
                                "file_path": "",
                            },
                        ),
                    )
                )

        if "write" not in allowed_tools_lower:
            if self._code_writes_files(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_WRITE_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_WRITE_VIOLATION",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Skill declares no Write tool but bundled scripts write files",
                        description=(
                            f"Skill restricts tools to {skill.manifest.allowed_tools} but bundled scripts appear to "
                            f"write to the filesystem, which conflicts with a read-only tool declaration."
                        ),
                        file_path=skillmd,
                        remediation="Either add 'Write' to allowed-tools (if intentional) or remove filesystem writes from scripts",
                        analyzer="static",
                        metadata=_semantic_metadata(
                            rule_id="ALLOWED_TOOLS_WRITE_VIOLATION",
                            file_path="SKILL.md",
                            evidence_kind="capability_mismatch",
                            context_kind="manifest",
                            signal_kind="undeclared_tool",
                            value_class="write",
                            candidate_command={
                                "executable": "Write",
                                "argument_classes": [],
                                "downloads": False,
                                "executes": False,
                                "destructive": False,
                                "privilege_change": False,
                                "source_class": "skill_code",
                                "sink_class": "filesystem_write",
                                "file_path": "",
                            },
                        ),
                    )
                )

        if "bash" not in allowed_tools_lower:
            if self._code_executes_bash(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_BASH_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_BASH_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.HIGH,
                        title="Code executes bash but Bash tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code executes bash commands",
                        file_path=skillmd,
                        remediation="Add 'Bash' to allowed-tools or remove bash execution from code",
                        analyzer="static",
                        metadata=_semantic_metadata(
                            rule_id="ALLOWED_TOOLS_BASH_VIOLATION",
                            file_path="SKILL.md",
                            evidence_kind="capability_mismatch",
                            context_kind="manifest",
                            signal_kind="undeclared_tool",
                            value_class="bash",
                            candidate_command={
                                "executable": "Bash",
                                "argument_classes": [],
                                "downloads": False,
                                "executes": True,
                                "destructive": False,
                                "privilege_change": False,
                                "source_class": "skill_code",
                                "sink_class": "process_execution",
                                "file_path": "",
                            },
                        ),
                    )
                )

        # Note: ALLOWED_TOOLS_PYTHON_VIOLATION removed - too many false positives
        # Many skills include Python helper scripts that are NOT invoked directly by the agent
        # (e.g., build scripts, test files, utilities). The allowed-tools list controls what
        # the AGENT can use, not what helper scripts exist in the repo.
        # If direct Python execution is a concern, COMMAND_INJECTION_EVAL catches actual risks.

        if "grep" not in allowed_tools_lower:
            if self._code_uses_grep(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_GREP_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_GREP_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.LOW,
                        title="Code uses search/grep patterns but Grep tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses regex search patterns",
                        file_path=skillmd,
                        remediation="Add 'Grep' to allowed-tools or remove regex search operations",
                        analyzer="static",
                        metadata=_semantic_metadata(
                            rule_id="ALLOWED_TOOLS_GREP_VIOLATION",
                            file_path="SKILL.md",
                            evidence_kind="capability_mismatch",
                            context_kind="manifest",
                            signal_kind="undeclared_tool",
                            value_class="grep",
                            candidate_command={
                                "executable": "Grep",
                                "argument_classes": [],
                                "downloads": False,
                                "executes": False,
                                "destructive": False,
                                "privilege_change": False,
                                "source_class": "skill_code",
                                "sink_class": "content_search",
                                "file_path": "",
                            },
                        ),
                    )
                )

        if "glob" not in allowed_tools_lower:
            if self._code_uses_glob(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_GLOB_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_GLOB_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.LOW,
                        title="Code uses glob/file patterns but Glob tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses glob patterns",
                        file_path=skillmd,
                        remediation="Add 'Glob' to allowed-tools or remove glob operations",
                        analyzer="static",
                        metadata=_semantic_metadata(
                            rule_id="ALLOWED_TOOLS_GLOB_VIOLATION",
                            file_path="SKILL.md",
                            evidence_kind="capability_mismatch",
                            context_kind="manifest",
                            signal_kind="undeclared_tool",
                            value_class="glob",
                            candidate_command={
                                "executable": "Glob",
                                "argument_classes": [],
                                "downloads": False,
                                "executes": False,
                                "destructive": False,
                                "privilege_change": False,
                                "source_class": "skill_code",
                                "sink_class": "filesystem_enumeration",
                                "file_path": "",
                            },
                        ),
                    )
                )

        network_usage_path = self._code_network_usage_path(skill)
        if network_usage_path is not None:
            findings.append(
                Finding(
                    id=self._generate_finding_id("ALLOWED_TOOLS_NETWORK_USAGE", skill.name),
                    rule_id="ALLOWED_TOOLS_NETWORK_USAGE",
                    category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                    severity=Severity.MEDIUM,
                    title="Code makes network requests",
                    description=(
                        "Skill code makes network requests. While not controlled by allowed-tools, "
                        "network access should be documented and justified in the skill description."
                    ),
                    file_path=skillmd,
                    remediation="Document network usage in skill description or remove network operations if not needed",
                    analyzer="static",
                    metadata=_semantic_metadata(
                        rule_id="ALLOWED_TOOLS_NETWORK_USAGE",
                        file_path="SKILL.md",
                        evidence_kind="capability_mismatch",
                        context_kind="manifest",
                        signal_kind="undocumented_network",
                        value_class="external_network",
                        candidate_flow={
                            "source_class": "skill_code",
                            "sink_class": "external_network",
                            "transforms": [],
                            "cross_file": False,
                            "source_path": network_usage_path,
                            "sink_path": network_usage_path,
                        },
                    ),
                )
            )

        return findings

    def _code_reads_files(self, skill: Skill) -> bool:
        """Check if code contains file reading operations."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _READ_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_writes_files(self, skill: Skill) -> bool:
        """Check if code contains file writing operations."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _WRITE_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_executes_bash(self, skill: Skill) -> bool:
        """Check if code executes bash/shell commands."""
        bash_indicators = [
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_output",
            "os.system",
            "os.popen",
            "commands.getoutput",
            "shell=True",
        ]

        has_bash_scripts = any(f.file_type == "bash" for f in skill.files)
        if has_bash_scripts:
            return True

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if any(indicator in content for indicator in bash_indicators):
                return True
        return False

    def _code_uses_grep(self, skill: Skill) -> bool:
        """Check if code uses regex search/grep patterns."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _GREP_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_uses_glob(self, skill: Skill) -> bool:
        """Check if code uses glob/file pattern matching."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _GLOB_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_network_usage_path(self, skill: Skill) -> str | None:
        """Return the first package-relative script that makes a network request."""
        network_indicators = [
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "urllib.request",
            "urllib.urlopen",
            "http.client",
            "httpx.",
            "aiohttp.",
        ]

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if any(indicator in content for indicator in network_indicators) or self._content_uses_external_socket_api(
                content
            ):
                return skill_file.relative_path
        return None

    def _code_uses_network(self, skill: Skill) -> bool:
        """Check if code makes network requests."""
        return self._code_network_usage_path(skill) is not None

    def _scan_asset_files(self, skill: Skill) -> list[Finding]:
        """Scan files in assets/, templates/, and references/ directories for injection patterns."""
        findings = []

        ASSET_DIRS = ["assets", "templates", "references", "data"]

        ASSET_PATTERNS = [
            (
                re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.HIGH,
                "Prompt injection pattern in asset file",
            ),
            (
                re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.HIGH,
                "Prompt override pattern in asset file",
            ),
            (
                re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Role reassignment pattern in asset file",
            ),
            (
                re.compile(r"à\s+partir\s+de\s+maintenant", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "French role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"a\s+partir\s+de\s+ahora", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Spanish role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"a\s+partir\s+de\s+agora", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Portuguese role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"ab\s+jetzt", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "German role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"da\s+ora\s+in\s+poi", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Italian role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"bundan\s+sonra", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Turkish role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"from\s+now\s+on", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "English role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"https?://[^\s]+\.(tk|ml|ga|cf|gq)/", re.IGNORECASE),
                "ASSET_SUSPICIOUS_URL",
                Severity.MEDIUM,
                "Suspicious free domain URL in asset",
            ),
        ]

        for skill_file in skill.files:
            path_parts = skill_file.relative_path.split("/")

            is_asset_file = (
                (len(path_parts) > 1 and path_parts[0] in ASSET_DIRS)
                or skill_file.relative_path.endswith((".template", ".tmpl", ".tpl"))
                or (
                    skill_file.file_type == "other"
                    and skill_file.relative_path.endswith(
                        (
                            ".txt",
                            ".json",
                            ".yaml",
                            ".yml",
                            ".html",
                            ".css",
                            ".svg",
                            ".xml",
                            ".xsd",
                        )
                    )
                )
            )

            if not is_asset_file:
                continue

            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._is_doc_file(skill_file.relative_path)

            for pattern, rule_id, severity, description in ASSET_PATTERNS:
                matches = list(pattern.finditer(content))

                for match in matches:
                    line_number = content[: match.start()].count("\n") + 1
                    line_content = content.split("\n")[line_number - 1] if content else ""

                    if (
                        rule_id == "ASSET_PROMPT_INJECTION"
                        and is_doc
                        and self.policy.rule_scoping.asset_prompt_injection_skip_in_docs
                    ):
                        continue

                    findings.append(
                        Finding(
                            id=self._generate_finding_id(rule_id, f"{skill_file.relative_path}:{line_number}"),
                            rule_id=rule_id,
                            category=ThreatCategory.PROMPT_INJECTION
                            if "PROMPT" in rule_id
                            else ThreatCategory.COMMAND_INJECTION
                            if "CODE" in rule_id or "SCRIPT" in rule_id
                            else ThreatCategory.OBFUSCATION
                            if "BASE64" in rule_id
                            else ThreatCategory.POLICY_VIOLATION,
                            severity=severity,
                            title=description,
                            description=f"Pattern '{match.group()[:50]}...' detected in asset file",
                            file_path=skill_file.relative_path,
                            line_number=line_number,
                            snippet=line_content[:100],
                            remediation="Review the asset file and remove any malicious or unnecessary dynamic patterns",
                            analyzer="static",
                        )
                    )

        return findings

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        """Drop exact duplicate findings while preserving order."""
        deduped: list[Finding] = []
        seen: set[tuple[Any, ...]] = set()
        for f in findings:
            key = (
                f.rule_id,
                f.file_path or "",
                int(f.line_number or 0),
                f.snippet or "",
                f.metadata.get("matched_pattern"),
                f.metadata.get("matched_text"),
                f.metadata.get("signature_match_start"),
                f.metadata.get("signature_match_end"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    def _create_finding_from_match(self, rule: SecurityRule, match: dict[str, Any]) -> Finding:
        """Create a Finding object from a rule match, aligned with AITech taxonomy."""
        threat_mapping = None
        try:
            threat_name = rule.category.value.upper().replace("_", " ")
            threat_mapping = ThreatMapping.get_threat_mapping("static", threat_name)
        except (ValueError, AttributeError):
            pass

        matched_text = match.get("matched_text", "N/A")
        snippet = match.get("line_content")

        if rule.category == ThreatCategory.HARDCODED_SECRETS:
            redacted = _redact_secret(matched_text)
            if snippet and matched_text in snippet:
                snippet = snippet.replace(matched_text, redacted)
            matched_text = redacted

        file_path = str(match.get("file_path") or "")
        context_value = match.get("context_kind")
        context_kind = (
            context_value if isinstance(context_value, str) and context_value in SIGNATURE_CONTEXT_KINDS else "unknown"
        )
        polarity_value = match.get("polarity")
        polarity = (
            polarity_value if isinstance(polarity_value, str) and polarity_value in SIGNATURE_POLARITIES else "unknown"
        )
        evidence_kind = "signature_pattern"
        evidence_value_class: str | None = None
        evidence_count: int | None = None
        candidate_command: dict[str, Any] | None = None
        candidate_flow: dict[str, Any] | None = None
        extra_signals: list[dict[str, Any]] = []
        candidate_evidence_metadata = (
            {
                "evidence_value_class": evidence_value_class,
                "evidence_count": evidence_count,
            }
            if evidence_value_class is not None and evidence_count is not None
            else {}
        )
        pattern_index_value = match.get("pattern_index")
        signature_pattern_index = (
            pattern_index_value
            if isinstance(pattern_index_value, int)
            and not isinstance(pattern_index_value, bool)
            and pattern_index_value >= 0
            else None
        )
        match_start_value = match.get("match_start")
        match_end_value = match.get("match_end")
        signature_match_start = (
            match_start_value
            if isinstance(match_start_value, int) and not isinstance(match_start_value, bool) and match_start_value >= 0
            else None
        )
        signature_match_end = (
            match_end_value
            if isinstance(match_end_value, int)
            and not isinstance(match_end_value, bool)
            and signature_match_start is not None
            and match_end_value >= signature_match_start
            else None
        )
        matched_pattern_value = match.get("matched_pattern")
        signature_pattern_sha256 = (
            hashlib.sha256(matched_pattern_value.encode("utf-8")).hexdigest()
            if isinstance(matched_pattern_value, str)
            else None
        )

        occurrence = (
            f"{match.get('file_path', 'unknown')}:{match.get('line_number', 0)}:"
            f"{signature_match_start}:{signature_match_end}"
        )
        return Finding(
            id=self._generate_finding_id(rule.id, occurrence),
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            title=rule.description,
            description=f"Pattern detected: {matched_text}",
            file_path=file_path,
            line_number=match.get("line_number"),
            snippet=snippet,
            remediation=rule.remediation,
            analyzer="static",
            metadata={
                "matched_pattern": match.get("matched_pattern"),
                "matched_text": matched_text,
                "signature_pattern_index": signature_pattern_index,
                "signature_match_start": signature_match_start,
                "signature_match_end": signature_match_end,
                "signature_pattern_sha256": signature_pattern_sha256,
                "aitech": threat_mapping.get("aitech") if threat_mapping else None,
                "aitech_name": threat_mapping.get("aitech_name") if threat_mapping else None,
                "scanner_category": threat_mapping.get("scanner_category") if threat_mapping else None,
                "signature_context": context_kind,
                "signature_polarity": polarity,
                **candidate_evidence_metadata,
                "source_category": rule.source_category,
                "category_normalization": rule.category_resolution,
                **_semantic_metadata(
                    rule_id=rule.id,
                    file_path=file_path,
                    evidence_kind=evidence_kind,
                    context_kind=context_kind,
                    signal_kind="signature_polarity",
                    value_class=polarity,
                    evidence_value_class=evidence_value_class,
                    evidence_count=evidence_count,
                    candidate_command=candidate_command,
                    candidate_flow=candidate_flow,
                    extra_signals=extra_signals,
                ),
            },
        )

    def _generate_finding_id(self, rule_id: str, context: str) -> str:
        """Generate a unique finding ID."""
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"

    def _yara_scan(self, skill: Skill) -> list[Finding]:
        """Scan ALL skill files with YARA rules (full-tree scan).

        Scans:
        - SKILL.md instruction body
        - All text-readable files (scripts, markdown, configs, etc.)
        - Binary files are scanned by YARA directly on disk if the scanner supports it
        """
        if self.yara_scanner is None:
            return []

        findings: list[Finding] = []

        # Scan SKILL.md instruction body
        yara_matches = self.yara_scanner.scan_content(skill.instruction_body, "SKILL.md")
        for match in yara_matches:
            rule_name = match.get("rule_name", "")
            if not self._is_rule_enabled(rule_name):
                continue
            # embedded_shebang_in_binary only applies to binary files, not text
            if rule_name == "embedded_shebang_in_binary":
                continue
            findings.extend(self._create_findings_from_yara_match(match, skill))

        # Use policy-defined rule scoping (org-customisable)
        _SKILLMD_AND_SCRIPTS_ONLY = self.policy.rule_scoping.skillmd_and_scripts_only
        _SCRIPT_ONLY_YARA_RULES = self.policy.rule_scoping.skip_in_docs
        _CODE_ONLY_YARA_RULES = self.policy.rule_scoping.code_only

        def _is_skillmd_or_script(skill_file) -> bool:
            """Check if this is SKILL.md or an executable script."""
            return (
                skill_file.relative_path == "SKILL.md"
                or skill_file.file_type in ("python", "bash")
                or Path(skill_file.relative_path).suffix.lower() in {".py", ".sh", ".bash", ".rb", ".pl", ".js", ".ts"}
            )

        # Track which files have been scanned
        scanned_files = {"SKILL.md"}
        # Scan ALL files, not just scripts
        for skill_file in skill.files:
            if skill_file.relative_path in scanned_files:
                continue
            scanned_files.add(skill_file.relative_path)

            if skill_file.file_type == "binary":
                # For binary files, scan with YARA directly on disk.
                # scan_file() handles both text and binary: it tries UTF-8
                # first, then falls back to YARA's native filepath matcher.
                if skill_file.path.exists():
                    # Determine if this binary has an inert extension (images,
                    # fonts, databases) — used to suppress noisy shebang rule.
                    _ext = skill_file.path.suffix.lower()
                    _inert_exts = set(self.policy.file_classification.inert_extensions)
                    _is_inert = _ext in _inert_exts
                    _skip_shebang_inert = self.policy.file_classification.skip_inert_extensions
                    try:
                        yara_matches = self.yara_scanner.scan_file(
                            skill_file.path,
                            display_path=skill_file.relative_path,
                        )
                        for match in yara_matches:
                            rule_name = match.get("rule_name", "")
                            if not self._is_rule_enabled(rule_name):
                                continue
                            # Raw OOXML ZIP bytes and inert embedded media/font
                            # bytes are not a Unicode text channel.  Suppress
                            # only when the bounded extractor supplied exact
                            # provenance; unopened containers and every other
                            # member fail open.  Readable OOXML members are
                            # scanned below so active document text is retained.
                            if rule_name == "prompt_injection_unicode_steganography" and _is_inert_ooxml_unicode_asset(
                                skill_file
                            ):
                                continue
                            # Skip shebang-in-binary for inert file types (images,
                            # fonts, databases) — shebang-like bytes are coincidental.
                            if rule_name == "embedded_shebang_in_binary" and _is_inert and _skip_shebang_inert:
                                continue
                            findings.extend(self._create_findings_from_yara_match(match, skill))
                    except Exception as e:
                        logger.debug("YARA binary scan failed for %s: %s", skill_file.relative_path, e)
                continue

            # For text files, read content and scan
            content = skill_file.read_content()
            if content:
                is_doc = self._is_doc_file(skill_file.relative_path)

                yara_matches = self.yara_scanner.scan_content(content, skill_file.relative_path)
                for match in yara_matches:
                    rule_name = match.get("rule_name", "")
                    if not self._is_rule_enabled(rule_name):
                        continue

                    # Most restrictive: only SKILL.md and scripts
                    if rule_name in _SKILLMD_AND_SCRIPTS_ONLY:
                        if not _is_skillmd_or_script(skill_file):
                            continue

                    # Skip script-specific YARA rules for documentation files
                    if is_doc and rule_name in _SCRIPT_ONLY_YARA_RULES:
                        continue

                    # Skip code-only YARA rules for non-script files (markdown, configs)
                    is_non_script = skill_file.file_type not in ("python", "bash")
                    if is_non_script and rule_name in _CODE_ONLY_YARA_RULES:
                        # Hidden Unicode remains actionable in readable OOXML
                        # members, including document/slide/sheet content,
                        # relationships, and unknown parts.  These files have
                        # bounded extraction provenance and must not inherit the
                        # generic config/document skip used by other code rules.
                        if not (
                            rule_name == "prompt_injection_unicode_steganography"
                            and _is_extracted_ooxml_text(skill_file)
                        ):
                            # Exception: SKILL.md is already scanned above
                            continue

                    # embedded_shebang_in_binary is only meaningful for binary files;
                    # text files (markdown, scripts) legitimately contain shebangs in
                    # code blocks, examples, and documentation.
                    if rule_name == "embedded_shebang_in_binary":
                        continue  # text files always skip; binary files handled above

                    findings.extend(self._create_findings_from_yara_match(match, skill, content))

        # Post-filter: apply policy zero-width steganography thresholds
        # The YARA rule has built-in thresholds (50 with decode, 200 alone).
        # The policy allows raising these thresholds (more permissive) to reduce FPs.
        zw_threshold_decode = self.policy.analysis_thresholds.zerowidth_threshold_with_decode
        zw_threshold_alone = self.policy.analysis_thresholds.zerowidth_threshold_alone

        if zw_threshold_decode != 50 or zw_threshold_alone != 200:
            # Only run this expensive check if policy overrides the default thresholds
            steg_files: set[str] = set()
            for f in findings:
                if f.rule_id == "YARA_prompt_injection_unicode_steganography" and f.file_path:
                    steg_files.add(f.file_path)

            if steg_files:
                _ZW_CHARS = frozenset("\u200b\u200c\u200d")
                _DECODE_PATTERNS = ("atob", "unescape", "fromCharCode", "base64", "decode")
                suppressed_files: set[str] = set()

                for rel_path in steg_files:
                    sf = next((s for s in skill.files if s.relative_path == rel_path), None)
                    if sf is None:
                        continue
                    content = sf.read_content()
                    if not content:
                        continue
                    zw_count = sum(1 for ch in content if ch in _ZW_CHARS)
                    has_decode = any(pat in content for pat in _DECODE_PATTERNS)
                    threshold = zw_threshold_decode if has_decode else zw_threshold_alone
                    if zw_count <= threshold:
                        suppressed_files.add(rel_path)

                if suppressed_files:
                    findings = [
                        f
                        for f in findings
                        if not (
                            f.rule_id == "YARA_prompt_injection_unicode_steganography"
                            and f.file_path in suppressed_files
                        )
                    ]

        return findings

    # ------------------------------------------------------------------
    # OSS-powered document & homoglyph scanners
    # ------------------------------------------------------------------

    def _check_pdf_documents(self, skill: Skill) -> list[Finding]:
        """Scan PDF files using pdfid for structural analysis of suspicious elements.

        Uses Didier Stevens' pdfid library to detect /JS, /JavaScript,
        /OpenAction, /AA, /Launch and other markers that indicate embedded
        executable content inside PDF documents.
        """
        if "PDF_STRUCTURAL_THREAT" in self.policy.disabled_rules:
            return []

        try:
            from pdfid import pdfid as pdfid_mod  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("pdfid not installed – skipping structural PDF scan")
            return []

        findings: list[Finding] = []

        # Suspicious PDF keywords and their severity mapping
        suspicious_keywords: dict[str, tuple[Severity, str]] = {
            "/JS": (Severity.CRITICAL, "Embedded JavaScript code"),
            "/JavaScript": (Severity.CRITICAL, "JavaScript action dictionary"),
            "/OpenAction": (Severity.HIGH, "Auto-execute action on open"),
            "/AA": (Severity.HIGH, "Additional actions (auto-trigger)"),
            "/Launch": (Severity.CRITICAL, "Launch external application"),
            "/EmbeddedFile": (Severity.MEDIUM, "Embedded file attachment"),
            "/RichMedia": (Severity.MEDIUM, "Rich media (Flash/video) content"),
            "/XFA": (Severity.MEDIUM, "XFA form (can contain scripts)"),
            "/AcroForm": (Severity.LOW, "Interactive form fields"),
        }

        for sf in skill.files:
            # Target PDF files by extension or content family
            is_pdf = sf.path.suffix.lower() == ".pdf" or (
                sf.file_type in ("binary", "other")
                and sf.path.exists()
                and sf.path.stat().st_size > 4
                and sf.path.read_bytes()[:5] == b"%PDF-"
            )
            if not is_pdf or not sf.path.exists():
                continue

            try:
                # pdfid returns a xml.dom.minidom Document; parse keyword counts
                xml_doc = pdfid_mod.PDFiD(str(sf.path), disarm=False)
                if xml_doc is None:
                    continue

                # Check that pdfid considers this a valid PDF
                pdfid_elem = xml_doc.getElementsByTagName("PDFiD")
                if pdfid_elem and pdfid_elem[0].getAttribute("IsPDF") != "True":
                    continue

                # Extract keyword counts from the minidom XML structure
                detected: list[tuple[str, int, Severity, str]] = []
                for keyword_elem in xml_doc.getElementsByTagName("Keyword"):
                    name = keyword_elem.getAttribute("Name")
                    count = int(keyword_elem.getAttribute("Count") or "0")
                    if count > 0 and name in suspicious_keywords:
                        severity, desc = suspicious_keywords[name]
                        detected.append((name, count, severity, desc))

                if not detected:
                    continue

                # Use highest severity among all detected keywords
                _SEV_ORDER = {
                    Severity.CRITICAL: 5,
                    Severity.HIGH: 4,
                    Severity.MEDIUM: 3,
                    Severity.LOW: 2,
                    Severity.INFO: 1,
                }
                max_severity = max(detected, key=lambda d: _SEV_ORDER.get(d[2], 0))[2]
                keyword_summary = ", ".join(f"{name} ({count}x)" for name, count, _, _ in detected)
                detail_lines = "\n".join(
                    f"  - {name}: {desc} (found {count} occurrence(s))" for name, count, _, desc in detected
                )

                findings.append(
                    Finding(
                        id=self._generate_finding_id("PDF_STRUCTURAL_THREAT", sf.relative_path),
                        rule_id="PDF_STRUCTURAL_THREAT",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=max_severity,
                        title="PDF contains suspicious structural elements",
                        description=(
                            f"Structural analysis of '{sf.relative_path}' detected "
                            f"suspicious PDF keywords: {keyword_summary}.\n{detail_lines}\n"
                            f"These elements can execute code when the PDF is opened."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove JavaScript actions and auto-execute triggers from PDF files. "
                            "PDF files in skill packages should contain only static content."
                        ),
                        analyzer="static",
                        metadata={
                            "detected_keywords": {name: count for name, count, _, _ in detected},
                            "analysis_method": "pdfid_structural",
                        },
                    )
                )

            except Exception as e:
                logger.debug("pdfid analysis failed for %s: %s", sf.relative_path, e)

        return findings

    def _check_office_documents(self, skill: Skill) -> list[Finding]:
        """Scan Office documents for VBA macros and suspicious OLE indicators.

        Uses oletools (oleid) to detect macros, auto-executable triggers,
        embedded OLE objects, and encrypted content in Office files.
        """
        if "OFFICE_DOCUMENT_THREAT" in self.policy.disabled_rules:
            return []

        try:
            from oletools.oleid import OleID  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("oletools not installed – skipping Office document scan")
            return []

        findings: list[Finding] = []

        # Office file extensions
        office_extensions = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".odt",
            ".ods",
            ".odp",
        }

        for sf in skill.files:
            ext = sf.path.suffix.lower()
            if ext not in office_extensions or not sf.path.exists():
                continue

            try:
                oid = OleID(str(sf.path))
                indicators = oid.check()

                has_macros = False
                macro_analysis_incomplete = False
                is_encrypted = False
                suspicious_indicators: list[str] = []

                for indicator in indicators:
                    ind_id = getattr(indicator, "id", "")
                    ind_value = getattr(indicator, "value", None)
                    ind_name = getattr(indicator, "name", str(indicator))

                    macro_kind = classify_oleid_macro_indicator(ind_id, ind_value)
                    if macro_kind == VBA_MACRO:
                        has_macros = True
                        suspicious_indicators.append(f"VBA macros detected: {ind_value}")
                    elif macro_kind == XLM_MACRO:
                        has_macros = True
                        suspicious_indicators.append(f"XLM/Excel4 macros detected: {ind_value}")
                    elif macro_kind == INCONCLUSIVE_MACRO_ANALYSIS:
                        macro_analysis_incomplete = True
                        suspicious_indicators.append(f"Macro analysis was inconclusive: {ind_id}")
                    elif ind_id == "encrypted" and ind_value:
                        is_encrypted = True
                        suspicious_indicators.append(f"Document is encrypted: {ind_value}")
                    elif ind_id == "flash" and ind_value:
                        suspicious_indicators.append(f"Embedded Flash content: {ind_value}")
                    elif ind_id == "ObjectPool" and ind_value:
                        suspicious_indicators.append(f"Embedded OLE objects: {ind_value}")
                    elif ind_id == "ext_rels" and ind_value:
                        suspicious_indicators.append(f"External relationships: {ind_value}")

                if not suspicious_indicators:
                    continue

                # Determine severity
                if has_macros:
                    severity = Severity.CRITICAL
                    title = "Office document contains VBA macros"
                elif is_encrypted or macro_analysis_incomplete:
                    severity = Severity.HIGH
                    title = (
                        "Office macro analysis was incomplete"
                        if macro_analysis_incomplete
                        else "Office document is encrypted (resists analysis)"
                    )
                else:
                    severity = Severity.MEDIUM
                    title = "Office document contains suspicious indicators"

                findings.append(
                    Finding(
                        id=self._generate_finding_id("OFFICE_DOCUMENT_THREAT", sf.relative_path),
                        rule_id="OFFICE_DOCUMENT_THREAT",
                        category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                        severity=severity,
                        title=title,
                        description=(
                            f"Analysis of '{sf.relative_path}' detected:\n"
                            + "\n".join(f"  - {s}" for s in suspicious_indicators)
                            + "\nMalicious macros in Office documents can execute code "
                            "when the agent processes the file."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove VBA macros from Office documents. Use plain text, "
                            "Markdown, or macro-free formats (.docx, .xlsx) instead."
                        ),
                        analyzer="static",
                        metadata={
                            "has_macros": has_macros,
                            "is_encrypted": is_encrypted,
                            "indicators": suspicious_indicators,
                            "analysis_method": "oletools_oleid",
                        },
                    )
                )

            except Exception as e:
                logger.debug("oleid analysis failed for %s: %s", sf.relative_path, e)

        return findings

    def _check_homoglyph_attacks(self, skill: Skill) -> list[Finding]:
        """Detect Unicode homoglyph attacks in code files.

        Uses the confusable-homoglyphs library (backed by Unicode Consortium's
        confusables.txt) to identify characters that look identical to ASCII
        but are from different scripts (e.g., Cyrillic 'a' vs Latin 'a').
        """
        try:
            from confusable_homoglyphs import confusables
        except ImportError:
            logger.debug("confusable-homoglyphs not installed – skipping homoglyph check")
            return []

        findings: list[Finding] = []

        # Only scan executable code files where homoglyphs can evade pattern
        # matching.  Markdown is excluded because legitimate multilingual prose
        # (CJK, Cyrillic, Arabic mixed with Latin) triggers massive FPs.
        code_file_types = {"python", "bash"}

        # Code-like tokens that suggest a line is an identifier / expression,
        # not natural-language prose (used for additional filtering).
        _CODE_TOKEN_RE = re.compile(r"[=\(\)\[\]\{\};]|import |def |class |if |for |while |return |print\(")
        _MATH_OPERATOR_RE = re.compile(r"[=+\-*/×÷≤≥≈≠∑∏√]")
        _STRING_LITERAL_RE = re.compile(r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')")
        _GREEK_CHAR_RE = re.compile(r"[\u0370-\u03FF\u1F00-\u1FFF]")
        filter_math_context = self.policy.analysis_thresholds.homoglyph_filter_math_context
        low_risk_confusable_aliases = {
            alias.upper() for alias in self.policy.analysis_thresholds.homoglyph_math_aliases
        }

        for sf in skill.files:
            if sf.file_type not in code_file_types:
                continue

            content = sf.read_content()
            if not content:
                continue

            # Check each line for mixed-script homoglyphs
            dangerous_lines: list[tuple[int, str, list[dict]]] = []
            in_triple_quote_block = False
            triple_quote_delim = ""
            original_lines = content.split("\n")
            analysis_lines = comment_stripped_lines(content, sf.file_type)

            for line_num, (line, analysis_line) in enumerate(zip(original_lines, analysis_lines, strict=True), 1):
                # Skip comments and empty lines
                stripped = analysis_line.strip()
                if not stripped or stripped.startswith("//"):
                    continue

                # When benign-context filtering is enabled, skip Python docstring
                # blocks to avoid flagging multilingual documentation text.
                if filter_math_context and sf.file_type == "python":
                    if in_triple_quote_block:
                        if triple_quote_delim and triple_quote_delim in analysis_line:
                            in_triple_quote_block = False
                            triple_quote_delim = ""
                        continue
                    if '"""' in analysis_line or "'''" in analysis_line:
                        delim = '"""' if '"""' in analysis_line else "'''"
                        if analysis_line.count(delim) % 2 == 1:
                            in_triple_quote_block = True
                            triple_quote_delim = delim
                        continue

                # Only check lines that contain non-ASCII characters
                if stripped.isascii():
                    continue

                # Skip localized user-facing strings when all non-ASCII chars are
                # confined to string literals (common in i18n output text).
                if filter_math_context:
                    outside_literals = _STRING_LITERAL_RE.sub("", stripped)
                    if all(ord(ch) < 128 for ch in outside_literals):
                        continue

                # Heuristic: in code files, only flag lines that look like code
                # (have operators, parens, etc.) — skip i18n strings
                if not _CODE_TOKEN_RE.search(stripped):
                    continue

                # Check for confusable characters
                result = confusables.is_dangerous(stripped, preferred_aliases=["LATIN"])
                if result:
                    # Reduce FPs from scientific formulas that legitimately use
                    # math symbols / Greek letters (e.g. "Q = π × r^4 ...").
                    # These lines are code-like but not identifier spoofing.
                    if filter_math_context:
                        confusable_info = confusables.is_confusable(stripped, preferred_aliases=["LATIN"]) or []
                        aliases = {
                            str(entry.get("alias", "")).upper()
                            for entry in confusable_info
                            if isinstance(entry, dict) and entry.get("alias")
                        }
                        if (
                            aliases
                            and aliases.issubset(low_risk_confusable_aliases)
                            and (_MATH_OPERATOR_RE.search(stripped) or _GREEK_CHAR_RE.search(stripped))
                        ):
                            continue
                    dangerous_lines.append((line_num, line.strip(), result))

            # Require multiple dangerous lines to reduce single-line i18n FPs.
            # A genuine homoglyph attack typically uses confusables across
            # several identifiers / expressions.
            min_dangerous_lines = self.policy.analysis_thresholds.min_dangerous_lines
            if len(dangerous_lines) < min_dangerous_lines:
                continue

            # Report the first few dangerous lines (avoid noise)
            reported = dangerous_lines[:5]
            line_details = "\n".join(f"  - Line {ln}: {text[:80]}" for ln, text, _ in reported)
            extra = ""
            if len(dangerous_lines) > 5:
                extra = f"\n  ... and {len(dangerous_lines) - 5} more lines"

            findings.append(
                Finding(
                    id=self._generate_finding_id("HOMOGLYPH_ATTACK", sf.relative_path),
                    rule_id="HOMOGLYPH_ATTACK",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Unicode homoglyph characters detected in code",
                    description=(
                        f"File '{sf.relative_path}' contains characters from mixed Unicode "
                        f"scripts that are visually identical to ASCII letters. "
                        f"This technique can bypass pattern-matching security rules.\n"
                        f"{line_details}{extra}"
                    ),
                    file_path=sf.relative_path,
                    line_number=reported[0][0],
                    remediation=(
                        "Replace all non-ASCII lookalike characters with their ASCII "
                        "equivalents. All code should use standard Latin characters."
                    ),
                    analyzer="static",
                    metadata={
                        "affected_lines": len(dangerous_lines),
                        "analysis_method": "confusable_homoglyphs",
                        **_semantic_metadata(
                            rule_id="HOMOGLYPH_ATTACK",
                            file_path=sf.relative_path,
                            evidence_kind="unicode_confusable",
                            context_kind="code",
                            signal_kind="unicode_homoglyph",
                            value_class="mixed_script",
                        ),
                    },
                )
            )

        return findings

    def _check_file_inventory(self, skill: Skill) -> list[Finding]:
        """Analyze the file inventory of the skill package for anomalies."""
        findings: list[Finding] = []

        if not skill.files:
            return findings

        # Count file types
        type_counts: dict[str, int] = {}
        ext_counts: dict[str, int] = {}
        total_size = 0
        largest_file = None
        largest_size = 0

        for sf in skill.files:
            file_type = sf.file_type
            type_counts[file_type] = type_counts.get(file_type, 0) + 1

            ext = sf.path.suffix.lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

            total_size += sf.size_bytes
            if sf.size_bytes > largest_size:
                largest_size = sf.size_bytes
                largest_file = sf

        # Check for excessive file count (possible resource waste)
        max_file_count = self.policy.file_limits.max_file_count
        if len(skill.files) > max_file_count:
            findings.append(
                Finding(
                    id=self._generate_finding_id("EXCESSIVE_FILE_COUNT", str(len(skill.files))),
                    rule_id="EXCESSIVE_FILE_COUNT",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Skill package contains many files",
                    description=(
                        f"Skill package contains {len(skill.files)} files. "
                        f"Large file counts increase attack surface and may indicate "
                        f"bundled dependencies or unnecessary content."
                    ),
                    file_path=".",
                    remediation="Review file inventory and remove unnecessary files.",
                    analyzer="static",
                    metadata={
                        "file_count": len(skill.files),
                        "type_breakdown": type_counts,
                    },
                )
            )

        # Check for oversized individual files
        max_file_size = self.policy.file_limits.max_file_size_bytes
        if largest_file and largest_size > max_file_size:
            findings.append(
                Finding(
                    id=self._generate_finding_id("OVERSIZED_FILE", largest_file.relative_path),
                    rule_id="OVERSIZED_FILE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Oversized file in skill package",
                    description=(
                        f"File {largest_file.relative_path} is {largest_size / 1024 / 1024:.1f}MB. "
                        f"Large files in skill packages may contain hidden content or serve as "
                        f"a vector for resource abuse."
                    ),
                    file_path=largest_file.relative_path,
                    remediation="Review large files and consider hosting externally.",
                    analyzer="static",
                )
            )

        # Check for unreferenced script files (hidden functionality)
        code_extensions = self.policy.file_classification.code_extensions

        # Build the set of referenced file names (from SKILL.md)
        referenced_lower = {r.lower() for r in skill.referenced_files}

        # Expand references transitively: scripts imported by referenced scripts
        # are considered indirectly referenced (not hidden functionality)
        _import_re = re.compile(r"^(?:from\s+\.?(\w[\w.]*)\s+import|import\s+\.?(\w[\w.]*))", re.MULTILINE)
        _source_re = re.compile(r"(?:source|\.)\s+[\"']?([A-Za-z0-9_\-./]+\.(?:sh|bash))[\"']?")
        expanded_refs: set[str] = set(referenced_lower)
        for sf in skill.files:
            if sf.relative_path.lower() not in referenced_lower:
                fn = Path(sf.relative_path).name.lower()
                if fn not in referenced_lower and fn not in skill.instruction_body.lower():
                    continue  # this file itself isn't referenced
            content = sf.read_content()
            if not content:
                continue
            # Python: from X import Y → X.py is transitively referenced
            if sf.file_type == "python":
                for m in _import_re.finditer(content):
                    mod = (m.group(1) or m.group(2) or "").replace(".", "/")
                    if mod:
                        expanded_refs.add(f"{mod}.py")
                        expanded_refs.add(mod.split("/")[-1] + ".py")
            # Bash: source X.sh → X.sh is transitively referenced
            elif sf.file_type == "bash":
                for m in _source_re.finditer(content):
                    expanded_refs.add(m.group(1).lower())
                    expanded_refs.add(Path(m.group(1)).name.lower())

        # Well-known filenames that are almost never referenced in SKILL.md
        # but serve standard structural roles in Python/JS projects
        _BENIGN_FILENAMES = {
            "__init__.py",
            "__main__.py",
            "conftest.py",
            "setup.py",
            "setup.cfg",
            "manage.py",
            "wsgi.py",
            "asgi.py",
            "fabfile.py",
            "noxfile.py",
            "tasks.py",
            "makefile",
            "rakefile",
            "gulpfile.js",
            "gruntfile.js",
            "webpack.config.js",
            "tsconfig.json",
            "jest.config.js",
            "babel.config.js",
            ".eslintrc.js",
            "vite.config.js",
        }
        # Patterns for test files that are structural, not hidden functionality
        _TEST_FILE_RE = re.compile(r"^(?:test_|tests_).*\.py$|^.*_test\.py$|^conftest\.py$", re.IGNORECASE)

        for sf in skill.files:
            if (
                sf.file_type in ("python", "bash", "javascript", "typescript")
                or sf.path.suffix.lower() in code_extensions
            ):
                rel = sf.relative_path
                # Skip SKILL.md itself
                if rel.lower() == "skill.md":
                    continue
                filename = Path(rel).name
                filename_lower = filename.lower()

                # Skip well-known structural files (not hidden functionality)
                if filename_lower in _BENIGN_FILENAMES:
                    continue

                # Skip test files (test infrastructure, not hidden functionality)
                if _TEST_FILE_RE.match(filename):
                    continue

                # Check if referenced in SKILL.md (directly or transitively)
                is_referenced = (
                    rel.lower() in expanded_refs
                    or filename_lower in expanded_refs
                    or any(ref in rel.lower() for ref in expanded_refs if ref)
                    or filename_lower in skill.instruction_body.lower()
                )
                if not is_referenced:
                    # Store for LLM enrichment context instead of emitting
                    # a standalone finding (too noisy — ~95% FP in corpus).
                    self._unreferenced_scripts.append(rel)

        # Check for archives that contain executable scripts
        for sf in skill.files:
            if sf.extracted_from and sf.file_type in ("python", "bash"):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ARCHIVE_CONTAINS_EXECUTABLE", sf.relative_path),
                        rule_id="ARCHIVE_CONTAINS_EXECUTABLE",
                        category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                        severity=Severity.HIGH,
                        title="Archive contains executable script",
                        description=(
                            f"Executable script '{sf.relative_path}' was extracted from "
                            f"archive '{sf.extracted_from}'. Archives can be used to conceal "
                            f"malicious scripts from casual inspection."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove executable scripts from archives. "
                            "Include scripts directly in the skill package for transparency."
                        ),
                        analyzer="static",
                        metadata={
                            "extracted_from": sf.extracted_from,
                            "file_type": sf.file_type,
                            **_semantic_metadata(
                                rule_id="ARCHIVE_CONTAINS_EXECUTABLE",
                                file_path=sf.relative_path,
                                evidence_kind="archive_inventory",
                                context_kind="code",
                                signal_kind="archived_executable",
                                value_class=sf.file_type,
                            ),
                        },
                    )
                )

        return findings

    def _create_findings_from_yara_match(
        self, match: dict[str, Any], skill: Skill, file_content: str | None = None
    ) -> list[Finding]:
        """Convert YARA match to Finding objects."""
        findings = []

        rule_name = match["rule_name"]
        namespace = match["namespace"]
        file_path = match["file_path"]
        meta = match["meta"].get("meta", {})

        category, severity = self._map_yara_rule_to_threat(rule_name, meta)
        context_kind_override = classify_yara_behavior_context(
            rule_name,
            match.get("strings"),
            file_path,
        )

        from ..command_safety import evaluate_command

        safe_cleanup_dirs = self.policy.system_cleanup.safe_rm_targets or _DEFAULT_SAFE_CLEANUP_DIRS
        placeholder_markers = self.policy.credentials.placeholder_markers or _DEFAULT_PLACEHOLDER_MARKERS

        for string_match in _yara_candidate_string_matches(match, meta):
            # Skip exclusion patterns (these are used in YARA conditions but shouldn't create findings)
            string_identifier = string_match.get("identifier", "")
            if string_identifier.startswith("$documentation") or string_identifier.startswith("$safe"):
                continue

            if (
                rule_name in {"credential_harvesting_generic", "tool_chaining_abuse_generic"}
                and string_identifier in _NEGATABLE_EXFIL_IDENTIFIERS
                and self._is_negated_exfiltration_comment(string_match.get("line_content", ""))
            ):
                continue

            if rule_name == "code_execution_generic":
                line_content = string_match.get("line_content", "").lower()
                matched_data = string_match.get("matched_data", "").lower()

                # Use context-aware command safety evaluation
                # Try to extract a command from the matched content
                cmd_to_eval = matched_data.strip() or line_content.strip()
                verdict = evaluate_command(cmd_to_eval, policy=self.policy)
                if verdict.should_suppress_yara:
                    continue

            if rule_name == "system_manipulation_generic":
                line_content = string_match.get("line_content", "").lower()
                matched_data = string_match.get("matched_data", "").lower()

                # Reuse context-aware command safety policy for benign
                # maintenance/admin commands that are non-executable in context.
                cmd_to_eval = matched_data.strip() or line_content.strip()
                verdict = evaluate_command(cmd_to_eval, policy=self.policy)
                if verdict.should_suppress_yara:
                    continue

                rm_source = line_content if ("rm -rf" in line_content or "rm -r" in line_content) else matched_data
                if "rm -rf" in rm_source or "rm -r" in rm_source:
                    rm_targets = _RM_TARGET_PATTERN.findall(rm_source)
                    if rm_targets:
                        all_safe = all(
                            any(safe_dir in target for safe_dir in safe_cleanup_dirs) for target in rm_targets
                        )
                        if all_safe:
                            continue

            # Credential harvesting post-filters (controlled by mode)
            if rule_name == "credential_harvesting_generic":
                if self.yara_mode.credential_harvesting.filter_placeholder_patterns:
                    line_content = string_match.get("line_content", "")
                    matched_data = string_match.get("matched_data", "")
                    combined = f"{line_content} {matched_data}".lower()

                    if any(marker in combined for marker in placeholder_markers):
                        continue

                    if "export " in combined and "=" in combined:
                        _, value = combined.split("=", 1)
                        if any(marker in value for marker in placeholder_markers):
                            continue

            # Tool chaining post-filters (controlled by mode + policy pipeline)
            if rule_name == "tool_chaining_abuse_generic":
                line_content = string_match.get("line_content", "")
                lower_line = line_content.lower()
                exfil_raw = ",".join(self.policy.pipeline.exfil_hints)
                exfil_hints = tuple(h.strip() for h in exfil_raw.split(","))

                if self.yara_mode.tool_chaining.filter_generic_http_verbs:
                    if (
                        "get" in lower_line
                        and "post" in lower_line
                        and not any(hint in lower_line for hint in exfil_hints)
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_api_documentation:
                    api_raw = ",".join(self.policy.pipeline.api_doc_tokens)
                    api_doc_tokens = tuple(t.strip() for t in api_raw.split(","))
                    if any(token in line_content for token in api_doc_tokens) and not any(
                        hint in lower_line for hint in exfil_hints
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_email_field_mentions:
                    if "by email" in lower_line or "email address" in lower_line or "email field" in lower_line:
                        continue

            # Unicode steganography post-filters
            if rule_name == "prompt_injection_unicode_steganography":
                _steg_rule_id = "YARA_prompt_injection_unicode_steganography"
                line_content = string_match.get("line_content", "")
                matched_data = string_match.get("matched_data", "")
                has_ascii_letters = any("A" <= char <= "Z" or "a" <= char <= "z" for char in line_content)

                # $tag_block matches Unicode Tag Block bytes (U+E0000-U+E007F) used
                # for ASCII smuggling.  These codepoints have no legitimate use in
                # skill files, so we must never suppress them regardless of line
                # length, i18n markers, or script context.  Skip all FP filters for
                # this specific pattern.
                if string_identifier != "$tag_block":
                    # Filter short matches in non-Latin context (likely legitimate i18n)
                    short_match_max = self.policy.analysis_thresholds.short_match_max_chars
                    if len(matched_data) <= short_match_max and not has_ascii_letters:
                        continue

                    # Filter if context suggests legitimate internationalization
                    i18n_markers = ("i18n", "locale", "translation", "lang=", "charset", "utf-8", "encoding")
                    if any(marker in line_content.lower() for marker in i18n_markers):
                        continue

                    # Filter Cyrillic, CJK, Arabic, Hebrew text (legitimate non-Latin content)
                    # These are indicated by presence of those scripts without zero-width chars
                    cyrillic_cjk_pattern = any(
                        ("\u0400" <= char <= "\u04ff")  # Cyrillic
                        or ("\u4e00" <= char <= "\u9fff")  # CJK Unified
                        or ("\u0600" <= char <= "\u06ff")  # Arabic
                        or ("\u0590" <= char <= "\u05ff")  # Hebrew
                        for char in line_content
                    )
                    # If the line has legitimate non-Latin text but matched only a
                    # few zero-width chars, skip.
                    cyrillic_cjk_min = self.policy.analysis_thresholds.cyrillic_cjk_min_chars
                    if cyrillic_cjk_pattern and len(matched_data) < cyrillic_cjk_min:
                        continue

            finding_id = self._generate_finding_id(f"YARA_{rule_name}", f"{file_path}:{string_match['line_number']}")

            description = meta.get("description", f"YARA rule {rule_name} matched")
            threat_type = meta.get("threat_type", "SECURITY THREAT")

            findings.append(
                Finding(
                    id=finding_id,
                    rule_id=f"YARA_{rule_name}",
                    category=category,
                    severity=severity,
                    title=f"{threat_type} detected by YARA",
                    description=f"{description}: {string_match['matched_data'][:100]}",
                    file_path=file_path,
                    line_number=string_match["line_number"],
                    snippet=string_match["line_content"],
                    remediation=f"Review and remove {threat_type.lower()} pattern",
                    analyzer="static",
                    metadata={
                        "yara_rule": rule_name,
                        "yara_namespace": namespace,
                        "matched_string": string_match["identifier"],
                        "threat_type": threat_type,
                        **_yara_semantic_metadata(
                            rule_name=rule_name,
                            meta=meta,
                            file_path=file_path or "",
                            match_offset=string_match.get("offset"),
                            context_kind_override=context_kind_override,
                        ),
                    },
                )
            )

        return findings

    @staticmethod
    def _is_negated_exfiltration_comment(line: str) -> bool:
        """Recognize a refusal/negation local to an exfiltration comment."""
        return bool(_COMMENT_LINE_RE.search(line) and _NEGATED_EXFILTRATION_RE.search(line))

    def _map_yara_rule_to_threat(self, rule_name: str, meta: dict[str, Any]) -> tuple:
        """Map YARA rule to ThreatCategory and Severity."""
        # Schema-v2 trusted packs make the manifest authoritative.  The YARA
        # scanner injects these normalized fields after compilation; prefer
        # them over legacy threat labels embedded in source files.
        category_value = meta.get("category")
        severity_value = meta.get("severity")
        if isinstance(category_value, str) and isinstance(severity_value, str):
            try:
                return ThreatCategory(category_value), Severity(severity_value.upper())
            except ValueError:
                # Bundled legacy rules continue through the historical mapping
                # below.  Trusted values were validated before compilation, so
                # this path is only defensive for direct/custom scanner use.
                pass

        threat_type = meta.get("threat_type", "").upper()
        classification = meta.get("classification", "harmful")

        category_map = {
            "PROMPT INJECTION": ThreatCategory.PROMPT_INJECTION,
            "JAILBREAK": ThreatCategory.PROMPT_INJECTION,  # AITech-2.1: Jailbreak maps to prompt injection
            "INJECTION ATTACK": ThreatCategory.COMMAND_INJECTION,
            "COMMAND INJECTION": ThreatCategory.COMMAND_INJECTION,
            "CREDENTIAL HARVESTING": ThreatCategory.HARDCODED_SECRETS,
            "DATA EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "SYSTEM MANIPULATION": ThreatCategory.UNAUTHORIZED_TOOL_USE,
            "CODE EXECUTION": ThreatCategory.COMMAND_INJECTION,
            "SQL INJECTION": ThreatCategory.COMMAND_INJECTION,
            "SKILL DISCOVERY ABUSE": ThreatCategory.SKILL_DISCOVERY_ABUSE,
            "TRANSITIVE TRUST ABUSE": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
            "AUTONOMY ABUSE": ThreatCategory.AUTONOMY_ABUSE,
            "TOOL CHAINING ABUSE": ThreatCategory.TOOL_CHAINING_ABUSE,
            "UNICODE STEGANOGRAPHY": ThreatCategory.UNICODE_STEGANOGRAPHY,
        }

        category = category_map.get(threat_type, ThreatCategory.POLICY_VIOLATION)

        if classification == "harmful":
            if "INJECTION" in threat_type or "CREDENTIAL" in threat_type:
                severity = Severity.CRITICAL
            elif "EXFILTRATION" in threat_type or "MANIPULATION" in threat_type or threat_type == "JAILBREAK":
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return category, severity
