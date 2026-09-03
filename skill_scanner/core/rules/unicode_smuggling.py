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

"""Bounded detection of hidden Unicode controls beside active intent.

The bundled YARA rule remains the broad byte-pattern detector.  This module
adds a separate, high-confidence signal for smaller zero-width sequences only
when an analyzer-owned CommonMark walk proves that they occur beside an active
override or execution instruction.  Source text is never normalised in place,
decoded, or executed, and raw candidate text never enters semantic metadata.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from ..models import Finding, Severity, Skill, ThreatCategory

RULE_ID = "UNICODE_SMUGGLING_ACTIVE_INTENT"

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_LINES = 32_768
MAX_FENCED_BLOCKS = 512
MAX_REGION_CHARS = 256 * 1024
MAX_INTENT_MATCHES = 4_096
MAX_FINDINGS = 64
MAX_EVIDENCE_COUNT = 4_096
NEARBY_DISTANCE_CHARS = 200

# Three controls are enough to establish a deliberate sequence, but a HIGH
# finding also requires either a contiguous run or at least one percent of the
# bounded candidate window.  Neither condition is independently actionable.
MIN_HIDDEN_COUNT = 3
MIN_MAX_RUN = 2
MIN_DENSITY_BPS = 100

_ZERO_WIDTH_CLASSES = {
    "\u200b": "zero_width_space",
    "\u200c": "zero_width_joiner",
    "\u200d": "zero_width_joiner",
    "\u2060": "word_joiner",
    "\ufeff": "word_joiner",
}
_HIDDEN_CHARACTERS = frozenset(_ZERO_WIDTH_CLASSES)

_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_EXAMPLE_SECTION_RE = re.compile(
    r"\b(?:demos?|documentation|examples?|reference|samples?|testing|tutorials?)\b",
    re.IGNORECASE,
)
_NEGATIVE_SECTION_RE = re.compile(
    r"\b(?:anti[- ]?patterns?|bad|dangerous|do not use|insecure|negative|prohibited|safety|unsafe|"
    r"what not to do)\b",
    re.IGNORECASE,
)
_INLINE_EXAMPLE_RE = re.compile(
    r"\b(?:e\.g\.|for example|for instance|illustrat(?:e|ion)|sample (?:code|usage)|such as)\b",
    re.IGNORECASE,
)
_PROHIBITION_START_RE = re.compile(
    r"^\s*(?:(?:[-*+]\s+)|(?:\d+[.)]\s+))?"
    r"(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|forbid(?:den)?|prohibit(?:ed)?)\b",
    re.IGNORECASE,
)
_CONTRASTIVE_RE = re.compile(
    r"(?:[;!?]|&&|\|\||\b(?:but|except|however|instead|then|unless)\b)",
    re.IGNORECASE,
)
_NEGATIVE_FENCE_LEAD_RE = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|forbid(?:den)?|prohibit(?:ed)?)\b"
    r".{0,120}\b(?:code|commands?|examples?|following|scripts?)\b",
    re.IGNORECASE,
)
_EXAMPLE_FENCE_LEAD_RE = re.compile(
    r"\b(?:example|illustration|sample)\b.{0,80}\b(?:code|commands?|following|scripts?)\b",
    re.IGNORECASE,
)

_OVERRIDE_VERB = r"(?:bypass|disregard|forget|ignore|override|replace|supersede)"
_CONTROL_TARGET = (
    r"(?:developer\s+(?:instructions?|messages?)|guardrails?|instructions?|polic(?:y|ies)|"
    r"previous\s+(?:context|directions?|instructions?|prompts?|rules?)|prior\s+(?:directions?|instructions?|"
    r"prompts?|rules?)|safety\s+(?:controls?|polic(?:y|ies)|rules?)|system\s+(?:instructions?|messages?|prompts?)|"
    r"constraints?)"
)
_EXECUTE_VERB = r"(?:call|eval|exec|execute|invoke|launch|run|spawn)"
_EXECUTE_TARGET = r"(?:code|commands?|payloads?|programs?|scripts?|shell|tools?)"
_INTENT_GAP = r"[\s\S]{0,80}?"
_OVERRIDE_INTENT_RE = re.compile(
    rf"\b(?:{_OVERRIDE_VERB}{_INTENT_GAP}{_CONTROL_TARGET}|{_CONTROL_TARGET}{_INTENT_GAP}{_OVERRIDE_VERB})\b",
    re.IGNORECASE,
)
_EXECUTE_INTENT_RE = re.compile(
    rf"\b(?:{_EXECUTE_VERB}{_INTENT_GAP}{_EXECUTE_TARGET}|{_EXECUTE_TARGET}{_INTENT_GAP}{_EXECUTE_VERB})\b",
    re.IGNORECASE,
)

ContextKind = Literal["active_instruction", "code"]
IntentClass = Literal["override_instruction", "execute_command"]
SectionKind = Literal["active", "example", "negative"]


@dataclass(frozen=True, slots=True)
class _MarkdownRegion:
    content: str
    start_line: int
    context_kind: ContextKind


@dataclass(frozen=True, slots=True)
class UnicodeSmugglingCandidate:
    """A bounded classification with no source or decoded payload text."""

    line_number: int
    context_kind: ContextKind
    character_class: str
    count: int
    density_bps: int
    max_run: int
    intent_class: IntentClass
    distance_chars: int


def _section_kind(title: str) -> SectionKind:
    if _NEGATIVE_SECTION_RE.search(title):
        return "negative"
    if _EXAMPLE_SECTION_RE.search(title):
        return "example"
    return "active"


def _visible_projection(text: str) -> str:
    return "".join(character for character in text if character not in _HIDDEN_CHARACTERS)


def _is_inert_instruction(line: str) -> bool:
    visible = _visible_projection(line)
    if _INLINE_EXAMPLE_RE.search(visible):
        return True
    prohibition = _PROHIBITION_START_RE.search(visible)
    if prohibition is None:
        return False
    return _CONTRASTIVE_RE.search(visible, prohibition.end()) is None


def _markdown_regions(content: str) -> list[_MarkdownRegion]:
    """Return complete, active CommonMark regions within fixed limits.

    Ordinary example/negative sections and complete prohibitions are omitted.
    A prohibition or example lead immediately before a fence is propagated to
    that fence.  An unclosed fence is discarded rather than partially scanned.
    """

    lines = content.splitlines()
    if len(lines) > MAX_DOCUMENT_LINES:
        return []

    regions: list[_MarkdownRegion] = []
    instruction_lines: list[str] = []
    instruction_start = 1
    current_section: SectionKind = "active"
    previous_nonempty = ""
    fence_character: str | None = None
    fence_length = 0
    fence_start = 0
    fence_section: SectionKind = "active"
    fence_lines: list[str] = []
    fence_candidates = 0

    def append_region(region_content: str, start_line: int, context_kind: ContextKind) -> None:
        if not region_content or len(region_content) > MAX_REGION_CHARS:
            return
        regions.append(_MarkdownRegion(region_content, start_line, context_kind))

    def flush_instructions() -> None:
        nonlocal instruction_lines
        if instruction_lines:
            append_region("\n".join(instruction_lines), instruction_start, "active_instruction")
            instruction_lines = []

    for line_number, line in enumerate(lines, start=1):
        fence_match = _FENCE_RE.match(line)
        if fence_character is not None:
            if fence_match is not None:
                marker = fence_match.group("marker")
                tail = fence_match.group("tail")
                if marker[0] == fence_character and len(marker) >= fence_length and not tail.strip(" \t\r"):
                    if fence_section == "active":
                        append_region("\n".join(fence_lines), fence_start + 1, "code")
                    fence_character = None
                    fence_length = 0
                    fence_lines = []
                    previous_nonempty = line
                    continue
            fence_lines.append(line)
            continue

        heading = _HEADING_RE.match(line)
        if heading is not None:
            flush_instructions()
            current_section = _section_kind(heading.group("title"))
            previous_nonempty = line
            continue

        if fence_match is not None:
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            # Backticks are forbidden in a backtick info string.  Ambiguous
            # candidates are not treated as either code or active prose.
            if marker[0] != "`" or "`" not in tail:
                flush_instructions()
                fence_candidates += 1
                if fence_candidates > MAX_FENCED_BLOCKS:
                    return []
                fence_character = marker[0]
                fence_length = len(marker)
                fence_start = line_number
                fence_lines = []
                if current_section != "active":
                    fence_section = current_section
                elif _NEGATIVE_FENCE_LEAD_RE.search(_visible_projection(previous_nonempty)):
                    fence_section = "negative"
                elif _EXAMPLE_FENCE_LEAD_RE.search(_visible_projection(previous_nonempty)):
                    fence_section = "example"
                else:
                    fence_section = "active"
                continue

        if current_section == "active" and not _is_inert_instruction(line):
            if not instruction_lines:
                instruction_start = line_number
            instruction_lines.append(line)
        else:
            flush_instructions()
        if line.strip():
            previous_nonempty = line

    flush_instructions()
    # CommonMark accepts an unclosed fence, but it is ambiguous for this HIGH
    # signal.  Its accumulated body is intentionally not appended.
    return regions


def _hidden_positions(region: str) -> list[int]:
    positions: list[int] = []
    for index, character in enumerate(region):
        if character not in _HIDDEN_CHARACTERS:
            continue
        # A single leading BOM is an encoding marker rather than content.
        if character == "\ufeff" and index == 0:
            continue
        positions.append(index)
        if len(positions) > MAX_EVIDENCE_COUNT:
            return []
    return positions


def _project_visible(region: str) -> tuple[str, list[int]]:
    characters: list[str] = []
    raw_positions: list[int] = []
    for index, character in enumerate(region):
        if character in _HIDDEN_CHARACTERS and not (character == "\ufeff" and index == 0):
            continue
        characters.append(character)
        raw_positions.append(index)
    return "".join(characters), raw_positions


def _intent_matches(visible: str) -> list[tuple[int, int, IntentClass]]:
    matches: list[tuple[int, int, IntentClass]] = []
    patterns: tuple[tuple[re.Pattern[str], IntentClass], ...] = (
        (_OVERRIDE_INTENT_RE, "override_instruction"),
        (_EXECUTE_INTENT_RE, "execute_command"),
    )
    for pattern, intent_class in patterns:
        for match in pattern.finditer(visible):
            matches.append((match.start(), match.end(), intent_class))
            if len(matches) > MAX_INTENT_MATCHES:
                return []
    return sorted(matches, key=lambda item: (item[0], item[1], item[2]))


def _distance(position: int, start: int, end: int) -> int:
    if position < start:
        return start - position
    if position >= end:
        return position - end + 1
    return 0


def _max_hidden_run(region: str, start: int, end: int) -> int:
    maximum = 0
    current = 0
    for character in region[start:end]:
        if character in _HIDDEN_CHARACTERS:
            current += 1
            maximum = max(maximum, current)
        else:
            current = 0
    return maximum


def _character_class(region: str, positions: list[int]) -> str:
    classes = {_ZERO_WIDTH_CLASSES[region[position]] for position in positions}
    if len(classes) == 1:
        return next(iter(classes))
    return "mixed_zero_width"


def _line_number(region: str, position: int, start_line: int) -> int:
    return start_line + region.count("\n", 0, position)


def _region_candidates(region: _MarkdownRegion) -> list[UnicodeSmugglingCandidate]:
    hidden_positions = _hidden_positions(region.content)
    if len(hidden_positions) < MIN_HIDDEN_COUNT:
        return []
    visible, raw_positions = _project_visible(region.content)
    if not raw_positions:
        return []
    intent_matches = _intent_matches(visible)
    if not intent_matches:
        return []

    candidates: list[UnicodeSmugglingCandidate] = []
    seen: set[tuple[int, IntentClass, str]] = set()
    for visible_start, visible_end, intent_class in intent_matches:
        raw_start = raw_positions[min(visible_start, len(raw_positions) - 1)]
        raw_end = raw_positions[min(max(visible_start, visible_end - 1), len(raw_positions) - 1)] + 1
        nearby = [
            position
            for position in hidden_positions
            if _distance(position, raw_start, raw_end) <= NEARBY_DISTANCE_CHARS
        ]
        if not nearby:
            continue

        window_start = max(0, raw_start - NEARBY_DISTANCE_CHARS)
        window_end = min(len(region.content), raw_end + NEARBY_DISTANCE_CHARS)
        # Preserve a contiguous control run that crosses the exact proximity
        # boundary by one or two scalars.  The nearest member still has to be
        # within the bound; unrelated dispersed controls remain outside.
        while window_start > 0 and region.content[window_start - 1] in _HIDDEN_CHARACTERS:
            window_start -= 1
        while window_end < len(region.content) and region.content[window_end] in _HIDDEN_CHARACTERS:
            window_end += 1
        window_positions = [position for position in hidden_positions if window_start <= position < window_end]
        count = len(window_positions)
        max_run = _max_hidden_run(region.content, window_start, window_end)
        density_bps = min(10_000, (10_000 * count) // max(1, window_end - window_start))
        if count < MIN_HIDDEN_COUNT or (max_run < MIN_MAX_RUN and density_bps < MIN_DENSITY_BPS):
            continue

        anchor = window_positions[0]
        character_class = _character_class(region.content, window_positions)
        identity = (anchor, intent_class, character_class)
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append(
            UnicodeSmugglingCandidate(
                line_number=_line_number(region.content, anchor, region.start_line),
                context_kind=region.context_kind,
                character_class=character_class,
                count=count,
                density_bps=density_bps,
                max_run=max_run,
                intent_class=intent_class,
                distance_chars=min(_distance(position, raw_start, raw_end) for position in window_positions),
            )
        )
        if len(candidates) >= MAX_FINDINGS:
            break
    return candidates


def find_unicode_smuggling_candidates(skill: Skill) -> list[UnicodeSmugglingCandidate]:
    """Return deterministic, normalized candidates from active SKILL.md text."""

    content = skill.instruction_body
    if not content or len(content.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        return []

    candidates: list[UnicodeSmugglingCandidate] = []
    for region in _markdown_regions(content):
        candidates.extend(_region_candidates(region))
        if len(candidates) >= MAX_FINDINGS:
            break
    return sorted(
        candidates[:MAX_FINDINGS],
        key=lambda item: (
            item.line_number,
            item.intent_class,
            item.character_class,
            item.context_kind,
            item.count,
            item.max_run,
            item.density_bps,
        ),
    )


def check_unicode_smuggling(skill: Skill) -> list[Finding]:
    """Emit HIGH findings only for hidden controls plus active local intent."""

    findings: list[Finding] = []
    for candidate in find_unicode_smuggling_candidates(skill):
        physical_line = candidate.line_number + max(0, skill.instruction_body_line_offset)
        identity = (
            f"{RULE_ID}:SKILL.md:{physical_line}:{candidate.context_kind}:{candidate.character_class}:"
            f"{candidate.intent_class}:{candidate.count}:{candidate.max_run}:{candidate.density_bps}"
        )
        finding_id = f"{RULE_ID}_{hashlib.sha256(identity.encode()).hexdigest()[:10]}"
        evidence_value_class = (
            "mixed_zero_width_active_intent"
            if candidate.character_class == "mixed_zero_width"
            else "zero_width_active_intent"
        )
        semantic_facts = {
            "evidence_kind": "unicode_smuggling",
            "context_kind": candidate.context_kind,
            "evidence_value_class": evidence_value_class,
            "evidence_count": candidate.count,
        }
        findings.append(
            Finding(
                id=finding_id,
                rule_id="UNICODE_SMUGGLING_ACTIVE_INTENT",
                category=ThreatCategory.UNICODE_STEGANOGRAPHY,
                severity=Severity.HIGH,
                title="Hidden Unicode controls accompany an active instruction",
                description=(
                    "SKILL.md contains a bounded sequence of hidden Unicode controls beside an active override or "
                    "execution instruction."
                ),
                file_path="SKILL.md",
                line_number=physical_line,
                snippet="[hidden Unicode controls near active intent]",
                remediation=(
                    "Remove hidden formatting controls and express any legitimate instruction with visible text. "
                    "Keep non-operative demonstrations in an explicit example section."
                ),
                analyzer="static",
                metadata={
                    "analysis_basis": "bounded_commonmark_unicode_intent",
                    "unicode_metrics": {
                        "count": candidate.count,
                        "density_bps": candidate.density_bps,
                        "max_run": candidate.max_run,
                        "character_class": candidate.character_class,
                        "nearby_intent": candidate.intent_class,
                        "distance_chars": candidate.distance_chars,
                    },
                    "semantic_facts": semantic_facts,
                },
            )
        )
    return findings


__all__ = [
    "RULE_ID",
    "UnicodeSmugglingCandidate",
    "check_unicode_smuggling",
    "find_unicode_smuggling_candidates",
]
