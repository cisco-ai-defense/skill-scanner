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

"""Bounded semantic detection of active remote-acquire-and-execute instructions.

Pipeline and correlation analyzers own executable shell/code data flow.  This
rule covers a different surface: an operative SKILL.md instruction that
explicitly coordinates acquiring remote content with executing it.  It uses
Markdown structure and a closed token grammar; it never joins table cells,
paragraphs, examples, or code fences merely because two keywords coexist.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from ..models import Finding, Severity, Skill, ThreatCategory

RULE_ID = "ACTIVE_REMOTE_ACQUIRE_EXECUTE"

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_LINES = 32_768
MAX_STATEMENTS = 4_096
MAX_STATEMENT_CHARS = 4_096
MAX_TOKENS = 256
MAX_TOKEN_CHARS = 128
MAX_PAIR_DISTANCE = 24
MAX_DETECTIONS = 64

_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^ {0,3}(?P<marker>#{1,6})(?:[ \t]+(?P<title>.*?)[ \t]*#*[ \t]*|[ \t]*)$")
_BOLD_HEADING_RE = re.compile(r"^ {0,3}\*\*(?P<title>[^*\n]{1,128}?)\*\*\s*:?[ \t]*$")
_LIST_RE = re.compile(r"^ {0,3}(?:(?:[-*+]\s+)|(?:\d{1,4}[.)]\s+))(?P<body>.*)$")
_SETEXT_RE = re.compile(r"^ {0,3}(?P<underline>=+|-+)[ \t]*$")
_BLOCKQUOTE_RE = re.compile(r"^ {0,3}>")
_NEGATIVE_SECTION_RE = re.compile(
    r"^(?:anti[- ]?patterns?|bad\b|dangerous\b|do not use\b|insecure\b|negative\b|"
    r"prohibited\b|unsafe\b|what not to do\b)",
    re.IGNORECASE,
)
_EXAMPLE_SECTION_RE = re.compile(
    r"^(?:(?:common|usage|worked)\s+)?(?:demos?|documentation|examples?|references?|samples?|testing)\b",
    re.IGNORECASE,
)
_ARTIFACT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\."
    r"(?:bat|bin|cmd|com|exe|jar|js|mjs|pl|ps1|py|rb|sh)(?![A-Za-z0-9_.-])"
)
_ACQUIRE_PREFILTER_RE = re.compile(
    r"\b(?:download|downloaded|downloading|downloads|fetch|fetched|fetches|fetching|"
    r"retrieve|retrieved|retrieves|retrieving)\b",
    re.IGNORECASE,
)
_EXECUTE_PREFILTER_RE = re.compile(
    r"\b(?:execute|executed|executes|executing|invoke|invoked|invokes|invoking|"
    r"launch|launched|launches|launching|ran|run|running|runs|start|started|starting|starts)\b",
    re.IGNORECASE,
)

_ACQUIRE_WORDS = frozenset(
    {
        "download",
        "downloaded",
        "downloading",
        "downloads",
        "fetch",
        "fetched",
        "fetches",
        "fetching",
        "retrieve",
        "retrieved",
        "retrieves",
        "retrieving",
    }
)
_EXECUTE_WORDS = frozenset(
    {
        "execute",
        "executed",
        "executes",
        "executing",
        "invoke",
        "invoked",
        "invokes",
        "invoking",
        "launch",
        "launched",
        "launches",
        "launching",
        "ran",
        "run",
        "running",
        "runs",
        "start",
        "started",
        "starting",
        "starts",
    }
)
_CONNECTORS = frozenset({"and", "then"})
_CLAUSE_STOPS = frozenset({".", "!", "?", ";", "|"})
_NEGATIONS = frozenset({"avoid", "block", "never", "no", "not", "prevent", "refuse", "without"})
_URL_PREFIXES = ("http://", "https://", "ftp://", "www.")
_PRONOUNS = frozenset({"it", "them", "that", "this"})
_AUTH_ACTIONS = frozenset(
    {
        "approval",
        "approve",
        "approved",
        "approves",
        "confirmation",
        "confirm",
        "confirmed",
        "confirms",
        "consent",
        "consented",
        "consents",
    }
)
_AUTH_PRECONDITIONS = frozenset({"after", "if", "only", "unless", "with"})
_USER_WORDS = frozenset({"user", "user's", "users", "users'"})
_OBJECT_FILLERS = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "at",
        "automatically",
        "before",
        "by",
        "directly",
        "for",
        "from",
        "immediately",
        "in",
        "install",
        "installed",
        "installing",
        "into",
        "locally",
        "of",
        "on",
        "or",
        "the",
        "then",
        "through",
        "to",
        "using",
        "validate",
        "validated",
        "validating",
        "validates",
        "via",
        "with",
    }
)
_GENERIC_EXECUTED_ARTIFACTS = frozenset(
    {
        "binary",
        "binaries",
        "code",
        "executable",
        "file",
        "installer",
        "payload",
        "program",
        "script",
    }
)
_EXTRACTION_ACTIONS = frozenset(
    {"decompress", "decompressed", "decompresses", "extract", "extracted", "extracts", "unpack", "unpacked"}
)


@dataclass(frozen=True, slots=True)
class _Statement:
    text: str
    line_number: int
    shape: Literal["heading", "list_item", "paragraph", "table_cell"]
    block_id: int


@dataclass(frozen=True, slots=True)
class _Token:
    value: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class RemoteAcquireExecution:
    """One structurally bounded acquire-to-execute instruction."""

    acquisition: str
    execution: str
    line_number: int
    snippet: str
    statement_shape: str
    binding_kind: Literal["coordinated_action", "resolved_pronoun"]


def _section_kind(title: str) -> Literal["active", "example", "negative"]:
    normalized = " ".join(title.casefold().strip().split())
    while normalized and not normalized[0].isalnum():
        normalized = normalized[1:].lstrip()
    if _NEGATIVE_SECTION_RE.search(normalized):
        return "negative"
    if _EXAMPLE_SECTION_RE.search(normalized):
        return "example"
    return "active"


def _without_html_comments(line: str, in_comment: bool) -> tuple[str, bool]:
    """Remove HTML comments without exposing their hidden instruction text."""

    visible: list[str] = []
    offset = 0
    while offset < len(line):
        if in_comment:
            closing = line.find("-->", offset)
            if closing < 0:
                return "".join(visible), True
            offset = closing + 3
            in_comment = False
            continue
        opening = line.find("<!--", offset)
        if opening < 0:
            visible.append(line[offset:])
            break
        visible.append(line[offset:opening])
        offset = opening + 4
        in_comment = True
    return "".join(visible), in_comment


def _table_cells(line: str) -> list[str]:
    """Split a Markdown table row without joining independent cells."""

    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == "|":
            cell = "".join(current).strip()
            if cell:
                cells.append(cell)
            current = []
        else:
            current.append(character)
    cell = "".join(current).strip()
    if cell:
        cells.append(cell)
    return cells


def _markdown_statements(content: str) -> list[_Statement]:
    """Return active logical statements from bounded CommonMark structure."""

    lines = content.splitlines()
    if len(lines) > MAX_DOCUMENT_LINES:
        lines = lines[:MAX_DOCUMENT_LINES]

    statements: list[_Statement] = []
    paragraph: list[str] = []
    paragraph_line = 1
    inert_heading_level: int | None = None
    current_atx_level = 0
    fence_character: str | None = None
    fence_length = 0
    html_comment = False
    block_id = 0

    def is_active() -> bool:
        return inert_heading_level is None

    def append(text: str, line_number: int, shape: Literal["heading", "list_item", "paragraph", "table_cell"]):
        normalized = " ".join(text.split())
        if not normalized or len(normalized) > MAX_STATEMENT_CHARS or len(statements) >= MAX_STATEMENTS:
            return
        statements.append(_Statement(normalized, line_number, shape, block_id))

    def finish_paragraph() -> None:
        nonlocal paragraph
        if paragraph and is_active():
            append(" ".join(paragraph), paragraph_line, "paragraph")
        paragraph = []

    def apply_heading(title: str, level: int, line_number: int, *, atx: bool) -> None:
        nonlocal current_atx_level, inert_heading_level
        heading_kind = _section_kind(title)
        if inert_heading_level is None or level <= inert_heading_level:
            inert_heading_level = level if heading_kind != "active" else None
        if atx:
            current_atx_level = level
        if is_active() and title:
            append(title, line_number, "heading")

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line
        fence_match = _FENCE_RE.match(line)
        if fence_character is not None:
            if fence_match is not None:
                marker = fence_match.group("marker")
                if (
                    marker[0] == fence_character
                    and len(marker) >= fence_length
                    and not fence_match.group("tail").strip(" \t\r")
                ):
                    fence_character = None
                    fence_length = 0
            continue

        line, html_comment = _without_html_comments(line, html_comment)
        # A fence marker hidden in a multi-line HTML comment is not Markdown
        # structure.  Recompute against the visible text before opening one.
        fence_match = _FENCE_RE.match(line)
        if _BLOCKQUOTE_RE.match(line):
            finish_paragraph()
            block_id += 1
            continue

        heading = _HEADING_RE.match(line)
        bold_heading = _BOLD_HEADING_RE.match(line)
        if heading is not None or bold_heading is not None:
            finish_paragraph()
            block_id += 1
            matched_heading = heading or bold_heading
            assert matched_heading is not None
            title = matched_heading.group("title") or ""
            if heading is not None:
                level = len(heading.group("marker"))
            else:
                # Bold labels are pseudo-headings one level below the current
                # ATX heading.  A sibling bold label may close an inert bold
                # subtree, but cannot escape an inert ATX ancestor.
                level = min(7, current_atx_level + 1)
            apply_heading(title, level, line_number, atx=heading is not None)
            continue

        if fence_match is not None:
            finish_paragraph()
            block_id += 1
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            if marker[0] != "`" or "`" not in tail:
                fence_character = marker[0]
                fence_length = len(marker)
            continue

        if not line.strip():
            finish_paragraph()
            block_id += 1
            continue

        setext = _SETEXT_RE.match(line)
        if setext is not None and paragraph:
            title = " ".join(paragraph)
            title_line = paragraph_line
            paragraph = []
            block_id += 1
            apply_heading(
                title,
                1 if setext.group("underline")[0] == "=" else 2,
                title_line,
                atx=True,
            )
            continue
        if not is_active():
            # Retain ordinary text just long enough to recognize a following
            # Setext heading that may close an inert subtree.
            if not paragraph:
                paragraph_line = line_number
            paragraph.append(line)
            continue

        list_match = _LIST_RE.match(line)
        if list_match is not None:
            finish_paragraph()
            append(list_match.group("body"), line_number, "list_item")
            continue

        # A pipe-delimited row is a set of independent semantic cells.  This
        # prevents `download failed | resolve, then run ...` from becoming a
        # fabricated source-to-sink chain.
        if "|" in line:
            finish_paragraph()
            for cell in _table_cells(line):
                append(cell, line_number, "table_cell")
            continue

        if not paragraph:
            paragraph_line = line_number
        paragraph.append(line)

    finish_paragraph()
    return statements


def _tokens(text: str) -> list[_Token]:
    """Lex a bounded natural-language statement while treating URLs as atoms."""

    result: list[_Token] = []
    index = 0
    length = len(text)
    while index < length and len(result) < MAX_TOKENS:
        folded_tail = text[index : index + 8].casefold()
        prefix = next((value for value in _URL_PREFIXES if folded_tail.startswith(value)), None)
        if prefix is not None:
            end = index + len(prefix)
            while end < length and not text[end].isspace() and text[end] not in "<>)]}":
                end += 1
            result.append(_Token("<url>", index, end))
            index = end
            continue

        character = text[index]
        if character.isalpha():
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "_-'"):
                if end - index >= MAX_TOKEN_CHARS:
                    break
                end += 1
            result.append(_Token(text[index:end].casefold().strip("'"), index, end))
            index = end
            continue
        if character == "." and index > 0 and index + 1 < length:
            previous = text[index - 1]
            following = text[index + 1]
            if (previous.isalnum() or previous in "_-/\\") and (following.isalnum() or following in "_-/\\"):
                index += 1
                continue
        if character in ".!?;|,:()":
            result.append(_Token(character, index, index + 1))
        index += 1
    return result


def _authorization_near(text: str, start: int, end: int) -> bool:
    tokens = _tokens(text)
    values = [token.value for token in tokens]
    acquire_index = next((index for index, token in enumerate(tokens) if token.start == start), 0)
    execute_index = next(
        (index for index, token in enumerate(tokens) if token.end == end),
        min(len(tokens), acquire_index + MAX_PAIR_DISTANCE),
    )

    # Suppress only an explicit, temporally ordered user authorization gate.
    # Mere mentions of optional behavior, consent denied/absent, or a request
    # for confirmation after execution must not hide an active flow.
    for user_index, value in enumerate(values):
        if value not in _USER_WORDS:
            continue
        relation_start = max(0, user_index - 5)
        relation_end = min(len(values), user_index + 6)
        relation = values[relation_start:relation_end]
        if "without" in relation:
            continue
        auth_indexes = [relation_start + offset for offset, related in enumerate(relation) if related in _AUTH_ACTIONS]
        for auth_index in auth_indexes:
            boundary_start = min(auth_index, acquire_index)
            boundary_end = max(auth_index, execute_index)
            if any(token.value in _CLAUSE_STOPS for token in tokens[boundary_start:boundary_end]):
                continue
            left = min(user_index, auth_index)
            cue_start = max(0, left - 3)
            cue = set(values[cue_start : left + 1])
            if not cue & _AUTH_PRECONDITIONS:
                continue
            # `before user confirmation, execute` explicitly reverses the
            # safety ordering even if a different precondition word is near.
            if "before" in values[cue_start : user_index + 1]:
                continue
            if auth_index <= execute_index + 6:
                return True

    # A following sentence may establish a concrete UI protocol.  Keep this
    # intentionally narrow: ask -> approval noun -> before -> execution verb.
    for ask_index in range(execute_index + 1, len(values)):
        if values[ask_index] != "ask":
            continue
        following_auth_index = next(
            (
                index
                for index in range(ask_index + 1, min(len(values), ask_index + 7))
                if values[index] in {"approval", "confirmation", "consent"}
            ),
            None,
        )
        if following_auth_index is None:
            continue
        before_index = next(
            (
                index
                for index in range(following_auth_index + 1, min(len(values), following_auth_index + 7))
                if values[index] == "before"
            ),
            None,
        )
        if before_index is None:
            continue
        if any(value in _EXECUTE_WORDS for value in values[before_index + 1 : before_index + 7]):
            return True
    return False


def _object_words(tokens: list[_Token]) -> set[str]:
    return {
        token.value
        for token in tokens
        if token.value[0:1].isalpha()
        and token.value not in _OBJECT_FILLERS
        and token.value not in _ACQUIRE_WORDS
        and token.value not in _EXECUTE_WORDS
        and token.value not in _PRONOUNS
    }


def _action_is_negated(tokens: list[_Token], action_index: int) -> bool:
    """Return whether a nearby modifier negates this action itself."""

    lower = max(0, action_index - 6)
    segment: list[str] = []
    for token in tokens[lower:action_index]:
        if token.value in _CLAUSE_STOPS or token.value in _CONNECTORS:
            segment = []
            continue
        segment.append(token.value)
    if set(segment) & (_NEGATIONS - {"without"}):
        return True
    if "without" not in segment:
        return False
    without_index = len(segment) - 1 - segment[::-1].index("without")
    # `without [first/ever] downloading` negates the action.  In contrast,
    # `without user consent, download` and `without verification, download`
    # describe unsafe context and must remain detectable.
    return all(value in {"actually", "directly", "ever", "first"} for value in segment[without_index + 1 :])


def _direct_object_binding(
    tokens: list[_Token],
    acquire_index: int,
    connector_index: int,
    execute_index: int,
) -> bool:
    before = tokens[acquire_index + 1 : connector_index]
    after: list[_Token] = []
    for token in tokens[execute_index + 1 :]:
        if token.value in _CLAUSE_STOPS or token.value in _CONNECTORS:
            break
        after.append(token)

    before_objects = _object_words(before)
    after_objects = _object_words(after)
    after_values = {token.value for token in after}
    interval_values = {token.value for token in tokens[acquire_index + 1 : execute_index]}

    # `download and execute X` / `downloads, installs, and executes X` shares
    # the postposed direct object by grammar rather than keyword proximity.
    if not before_objects:
        return True
    # `download X and execute it` or elliptical `download X and execute` binds
    # the sink to the acquisition object.
    if after_values & _PRONOUNS or not after_objects:
        return True
    # Exact noun reuse is a bounded same-statement value binding.
    if before_objects & after_objects:
        return True
    # Archive acquisition followed by extraction and execution of an explicit
    # runtime artifact is one continuous delivery chain.
    if (
        "<url>" in {token.value for token in tokens}
        and interval_values & _EXTRACTION_ACTIONS
        and after_objects <= _GENERIC_EXECUTED_ARTIFACTS
    ):
        return True
    return False


def _coordinated_pair(statement: _Statement) -> tuple[_Token, _Token, bool] | None:
    if _ACQUIRE_PREFILTER_RE.search(statement.text) is None or _EXECUTE_PREFILTER_RE.search(statement.text) is None:
        return None
    tokens = _tokens(statement.text)
    for acquire_index, acquire in enumerate(tokens):
        if acquire.value not in _ACQUIRE_WORDS:
            continue
        if _action_is_negated(tokens, acquire_index):
            continue
        connector_index: int | None = None
        upper = min(len(tokens), acquire_index + MAX_PAIR_DISTANCE + 1)
        for execute_index in range(acquire_index + 1, upper):
            token = tokens[execute_index]
            if token.value in _CLAUSE_STOPS:
                break
            if token.value in _CONNECTORS:
                connector_index = execute_index
                continue
            if token.value not in _EXECUTE_WORDS:
                continue
            if connector_index is None or _action_is_negated(tokens, execute_index):
                continue
            if _authorization_near(statement.text, acquire.start, token.end):
                continue
            if not _direct_object_binding(tokens, acquire_index, connector_index, execute_index):
                continue
            between = [item.value for item in tokens if acquire.end <= item.start < token.start]
            following = [item.value for item in tokens if item.start >= token.end][:4]
            pronoun_only = bool(set(between) & _PRONOUNS and set(following) & _PRONOUNS)
            return acquire, token, pronoun_only
    return None


def _has_named_artifact_context(statements: list[_Statement], index: int) -> bool:
    current = statements[index]
    if current.shape != "list_item":
        return False
    start = max(0, index - 3)
    for prior in statements[start:index]:
        if (
            prior.shape != "list_item"
            or prior.block_id != current.block_id
            or current.line_number - prior.line_number > 3
        ):
            continue
        if _ARTIFACT_RE.search(prior.text) and any(token.value in _ACQUIRE_WORDS for token in _tokens(prior.text)):
            return True
    return False


def find_active_remote_execution(skill: Skill) -> list[RemoteAcquireExecution]:
    """Return bounded acquire/execute pairs from active SKILL.md instructions."""

    content = skill.instruction_body
    if not content or len(content.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        return []
    if _ACQUIRE_PREFILTER_RE.search(content) is None or _EXECUTE_PREFILTER_RE.search(content) is None:
        return []
    detections: list[RemoteAcquireExecution] = []
    seen: set[tuple[int, str, str]] = set()
    statements = _markdown_statements(content)
    for index, statement in enumerate(statements):
        pair = _coordinated_pair(statement)
        if pair is None:
            continue
        acquire, execute, pronoun_only = pair
        if pronoun_only and not _has_named_artifact_context(statements, index):
            continue
        binding_kind: Literal["coordinated_action", "resolved_pronoun"] = (
            "resolved_pronoun" if pronoun_only else "coordinated_action"
        )
        identity = (statement.line_number, acquire.value, execute.value)
        if identity in seen:
            continue
        seen.add(identity)
        detections.append(
            RemoteAcquireExecution(
                acquisition=acquire.value,
                execution=execute.value,
                line_number=statement.line_number,
                snippet=statement.text[:200],
                statement_shape=statement.shape,
                binding_kind=binding_kind,
            )
        )
        if len(detections) >= MAX_DETECTIONS:
            break
    return detections


def check_active_remote_execution(skill: Skill) -> list[Finding]:
    """Emit one high-confidence finding for explicit remote execution intent."""

    detections = find_active_remote_execution(skill)
    if not detections:
        return []
    first = detections[0]
    physical_line = first.line_number + max(0, skill.instruction_body_line_offset)
    identity = f"{RULE_ID}:SKILL.md:{physical_line}:{first.acquisition}:{first.execution}"
    finding_id = f"{RULE_ID}_{hashlib.sha256(identity.encode()).hexdigest()[:10]}"
    flow = {
        "source_class": "network",
        "sink_class": "execution",
        "transforms": [],
        "cross_file": False,
        "source_path": "SKILL.md",
        "sink_path": "SKILL.md",
    }
    semantic_facts = {
        "evidence_kind": "correlated_behavior",
        "context_kind": "active_instruction",
        "evidence_value_class": "untrusted_fetch_execute",
        "evidence_count": len(detections),
        "signal_kind": "compound_flow",
        "flows": [flow],
        "candidate_flow": flow,
    }
    return [
        Finding(
            id=finding_id,
            rule_id="ACTIVE_REMOTE_ACQUIRE_EXECUTE",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="Active instruction acquires and executes remote content",
            description=(
                "SKILL.md contains an operative statement that explicitly coordinates remote content acquisition "
                "with execution."
            ),
            file_path="SKILL.md",
            line_number=physical_line,
            snippet=first.snippet,
            remediation=(
                "Remove remote execution, or require a locally pinned artifact whose digest or signature is verified "
                "before a fixed allowlisted invocation."
            ),
            analyzer="static",
            metadata={
                "analysis_basis": "bounded_commonmark_statement_grammar",
                "acquisition_verbs": sorted({item.acquisition for item in detections}),
                "execution_verbs": sorted({item.execution for item in detections}),
                "statement_shapes": sorted({item.statement_shape for item in detections}),
                "binding_kinds": sorted({item.binding_kind for item in detections}),
                "semantic_facts": semantic_facts,
            },
        )
    ]


__all__ = [
    "RULE_ID",
    "RemoteAcquireExecution",
    "check_active_remote_execution",
    "find_active_remote_execution",
]
