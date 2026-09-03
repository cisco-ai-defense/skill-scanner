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

"""Detect operative instructions concealed with HTML rendering behavior.

HTML comments and visually hidden elements are ordinary documentation
features on their own.  This detector therefore requires three independent
properties before emitting a HIGH finding:

* analyzer-owned CommonMark parsing proves the markup is in active SKILL.md
  instructions rather than an example, negative section, or fenced snippet;
* the concealed text explicitly overrides a control, policy, or instruction;
* the same bounded text orders execution or a sensitive-data action.

The detector never renders HTML, decodes payloads, or executes sample content.
It emits normalized classifications only; raw hidden instructions are not
copied into finding metadata or snippets.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from ..models import Finding, Severity, Skill, ThreatCategory

RULE_ID = "ACTIVE_HIDDEN_HTML_INSTRUCTION"

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_LINES = 32_768
MAX_FENCED_BLOCKS = 512
MAX_REGION_CHARS = 256 * 1024
MAX_HTML_COMMENTS = 512
MAX_COMMENT_CHARS = 16 * 1024
MAX_HIDDEN_ELEMENTS = 256
MAX_HIDDEN_BODY_CHARS = 4 * 1024
MAX_FINDINGS = 64

_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_EXAMPLE_SECTION_RE = re.compile(
    r"\b(?:demos?|documentation|examples?|reference|samples?|testing|tutorials?|fixtures?)\b",
    re.IGNORECASE,
)
_NEGATIVE_SECTION_RE = re.compile(
    r"\b(?:anti[- ]?patterns?|bad|dangerous|do not use|insecure|negative|prohibited|safety|unsafe|"
    r"what not to do)\b",
    re.IGNORECASE,
)
_INERT_VISIBLE_LEAD_RE = re.compile(
    r"\b(?:as an? (?:example|sample)|demo(?:nstration)?|documentation|example|fixture|for example|"
    r"illustration|literal|sample|test case|tutorial)\b|"
    r"\b(?:detect|escape|reject|remove|sanitize|strip)\b.{0,80}\b(?:html )?comments?\b|"
    r"\b(?:do not|don't|must not|never|should not)\s+(?:follow|honou?r|obey|use)\b",
    re.IGNORECASE,
)

_OVERRIDE_VERB = r"(?:bypass|disable|disregard|forget|ignore|override|replace|supersede)"
_CONTROL_TARGET = (
    r"(?:content\s+(?:filters?|moderation)|control(?:s|\s+layers?)|default\s+skill\s+behavio(?:u)?r|"
    r"developer\s+(?:instructions?|messages?)|guardrails?|guidelines?|instructions?|polic(?:y|ies)|"
    r"previous\s+(?:context|directions?|directives?|guidelines?|instructions?|prompts?|rules?)|"
    r"prior\s+(?:context|directions?|directives?|guidelines?|instructions?|prompts?|rules?)|"
    r"protective\s+(?:mechanisms?|refusal\s+mechanisms?)|refusal\s+mechanisms?|restrictions?|rules?|"
    r"safety(?:\s+(?:controls?|filters?|gatekeeping|guidelines?|measures?|polic(?:y|ies)|preferences?|"
    r"protocols?|restrictions?|rules?|screening))?|system\s+(?:instructions?|messages?|prompts?))"
)
_OVERRIDE_INTENT_RE = re.compile(
    rf"\b(?:{_OVERRIDE_VERB}[\s\S]{{0,120}}?{_CONTROL_TARGET}|"
    rf"{_CONTROL_TARGET}[\s\S]{{0,120}}?{_OVERRIDE_VERB})\b",
    re.IGNORECASE,
)

_EXECUTION_VERB = r"(?:call|eval|exec|execute|invoke|launch|run|spawn)"
_EXECUTION_TARGET = (
    r"(?:bootstrap(?:\s+helper)?|code|commands?|helpers?|payloads?|programs?|scripts?|shell|tools?|"
    r"user\s+(?:actions?|directives?|instructions?|requests?|tasks?)|curl|wget|bash|powershell|"
    r"python(?:3)?|subprocess)"
)
_EXECUTION_INTENT_RE = re.compile(
    rf"\b(?:{_EXECUTION_VERB}[\s\S]{{0,120}}?{_EXECUTION_TARGET}|"
    rf"{_EXECUTION_TARGET}[\s\S]{{0,120}}?{_EXECUTION_VERB})\b",
    re.IGNORECASE,
)

_SENSITIVE_ACTION = (
    r"(?:access|collect|copy|disclose|exfiltrate|extract|forward|leak|post|read|reveal|send|transmit|upload)"
)
_SENSITIVE_TARGET = (
    r"(?:api\s+keys?|classified\s+(?:data|information)|complete\s+system\s+configuration|context|"
    r"cookies?|credentials?|environment(?:\s+(?:data|variables?))?|financial\s+(?:data|details?)|"
    r"passwords?|private\s+(?:data|information)|secrets?|ssh\s+keys?|system\s+(?:configuration|instructions?|"
    r"prompts?)|tokens?|/etc/passwd|\.bash_history|\.env)"
)
_SENSITIVE_ACTION_RE = re.compile(
    rf"\b(?:{_SENSITIVE_ACTION}[\s\S]{{0,160}}?{_SENSITIVE_TARGET}|"
    rf"{_SENSITIVE_TARGET}[\s\S]{{0,160}}?{_SENSITIVE_ACTION})\b",
    re.IGNORECASE,
)

_HIDDEN_ELEMENT_RE = re.compile(
    r"<(?P<tag>aside|div|font|p|section|span)\b(?P<attrs>[^>]{0,1024})>"
    rf"(?P<body>[\s\S]{{1,{MAX_HIDDEN_BODY_CHARS}}}?)</(?P=tag)\s*>",
    re.IGNORECASE,
)
_HIDDEN_ATTRIBUTE_RE = re.compile(
    r"(?:"
    r"(?:^|\s)hidden(?:\s*=\s*(?:[\"']\s*[\"']|hidden)|(?=\s|$))|"
    r"(?:^|\s)aria-hidden\s*=\s*[\"']?true(?:[\"']|(?=\s|$))|"
    r"display\s*:\s*none\b|"
    r"visibility\s*:\s*hidden\b|"
    r"opacity\s*:\s*0(?![\d.])|"
    r"font-size\s*:\s*0(?![\d.])(?:px|pt|em|rem|%)?"
    r")",
    re.IGNORECASE,
)

SectionKind = Literal["active", "example", "negative"]
InjectionClass = Literal[
    "hidden_comment_override_execution",
    "hidden_comment_override_sensitive_action",
    "hidden_element_override_execution",
    "hidden_element_override_sensitive_action",
]


@dataclass(frozen=True, slots=True)
class _ActiveRegion:
    content: str
    start_line: int


@dataclass(frozen=True, slots=True)
class HiddenHtmlCandidate:
    """A normalized hidden-instruction classification with bounded counts."""

    line_number: int
    injection_class: InjectionClass
    hidden_chars: int
    context_kind: Literal["active_instruction"] = "active_instruction"


def _section_kind(title: str) -> SectionKind:
    if _NEGATIVE_SECTION_RE.search(title):
        return "negative"
    if _EXAMPLE_SECTION_RE.search(title):
        return "example"
    return "active"


def _active_regions(content: str) -> list[_ActiveRegion]:
    """Return bounded active prose while omitting all fenced code."""

    lines = content.splitlines()
    if len(lines) > MAX_DOCUMENT_LINES:
        return []

    regions: list[_ActiveRegion] = []
    active_lines: list[str] = []
    active_start = 1
    current_section: SectionKind = "active"
    fence_character: str | None = None
    fence_length = 0
    fence_count = 0

    def flush() -> None:
        nonlocal active_lines
        if active_lines:
            region = "\n".join(active_lines)
            if len(region) <= MAX_REGION_CHARS:
                regions.append(_ActiveRegion(region, active_start))
            active_lines = []

    for line_number, line in enumerate(lines, start=1):
        fence = _FENCE_RE.match(line)
        if fence_character is not None:
            if fence is not None:
                marker = fence.group("marker")
                tail = fence.group("tail")
                if marker[0] == fence_character and len(marker) >= fence_length and not tail.strip(" \t\r"):
                    fence_character = None
                    fence_length = 0
            continue

        heading = _HEADING_RE.match(line)
        if heading is not None:
            flush()
            current_section = _section_kind(heading.group("title"))
            continue

        if fence is not None:
            marker = fence.group("marker")
            tail = fence.group("tail")
            if marker[0] != "`" or "`" not in tail:
                flush()
                fence_count += 1
                if fence_count > MAX_FENCED_BLOCKS:
                    return []
                fence_character = marker[0]
                fence_length = len(marker)
                continue

        if current_section == "active":
            if not active_lines:
                active_start = line_number
            active_lines.append(line)
        else:
            flush()

    # An unclosed fence is ambiguous. Its body was never accumulated, while
    # active prose before the opening fence remains safe to classify.
    flush()
    return regions


def _inside_inline_code(line: str, column: int) -> bool:
    """Conservatively identify a comment opener inside a code span."""

    runs = [match.span() for match in re.finditer(r"`+", line)]
    index = 0
    while index + 1 < len(runs):
        opening = runs[index]
        closing_index = index + 1
        while closing_index < len(runs) and runs[closing_index][1] - runs[closing_index][0] != opening[1] - opening[0]:
            closing_index += 1
        if closing_index >= len(runs):
            return False
        closing = runs[closing_index]
        if opening[1] <= column < closing[0]:
            return True
        index = closing_index + 1
    return False


def _visible_lead_is_inert(content: str, opener: int) -> bool:
    line_start = content.rfind("\n", 0, opener) + 1
    line = content[line_start : content.find("\n", opener) if "\n" in content[opener:] else len(content)]
    column = opener - line_start
    if _inside_inline_code(line, column):
        return True
    visible_lead = line[max(0, column - 200) : column]
    if not visible_lead.strip():
        previous_end = max(0, line_start - 1)
        previous_start = content.rfind("\n", 0, previous_end) + 1
        previous_line = content[previous_start:previous_end].strip()
        # Skip at most one blank separator while retaining a strict local
        # paragraph bound.  This catches "For example:\n<!-- ... -->"
        # without making a distant heading control the candidate.
        if not previous_line and previous_start > 0:
            previous_end = max(0, previous_start - 1)
            previous_start = content.rfind("\n", 0, previous_end) + 1
            previous_line = content[previous_start:previous_end].strip()
        visible_lead = previous_line[-200:]
    return bool(_INERT_VISIBLE_LEAD_RE.search(visible_lead))


def _classify_hidden_text(text: str, *, source: Literal["comment", "element"]) -> InjectionClass | None:
    if not _OVERRIDE_INTENT_RE.search(text):
        return None
    if _EXECUTION_INTENT_RE.search(text):
        return f"hidden_{source}_override_execution"  # type: ignore[return-value]
    if _SENSITIVE_ACTION_RE.search(text):
        return f"hidden_{source}_override_sensitive_action"  # type: ignore[return-value]
    return None


def _comment_candidates(region: _ActiveRegion) -> list[HiddenHtmlCandidate]:
    candidates: list[HiddenHtmlCandidate] = []
    cursor = 0
    comment_count = 0
    while cursor < len(region.content):
        opener = region.content.find("<!--", cursor)
        if opener < 0:
            break
        comment_count += 1
        if comment_count > MAX_HTML_COMMENTS:
            break
        closer = region.content.find("-->", opener + 4)
        if closer < 0:
            # Do not classify an ambiguous or truncated comment.
            break
        body_start = opener + 4
        hidden_chars = closer - body_start
        cursor = closer + 3
        if hidden_chars < 1 or hidden_chars > MAX_COMMENT_CHARS or _visible_lead_is_inert(region.content, opener):
            continue
        body = region.content[body_start:closer]
        injection_class = _classify_hidden_text(body, source="comment")
        if injection_class is None:
            continue
        line_number = region.start_line + region.content.count("\n", 0, opener)
        candidates.append(HiddenHtmlCandidate(line_number, injection_class, hidden_chars))
    return candidates


def _hidden_element_candidates(region: _ActiveRegion) -> list[HiddenHtmlCandidate]:
    candidates: list[HiddenHtmlCandidate] = []
    for count, match in enumerate(_HIDDEN_ELEMENT_RE.finditer(region.content), start=1):
        if count > MAX_HIDDEN_ELEMENTS:
            break
        if not _HIDDEN_ATTRIBUTE_RE.search(match.group("attrs")):
            continue
        injection_class = _classify_hidden_text(match.group("body"), source="element")
        if injection_class is None or _visible_lead_is_inert(region.content, match.start()):
            continue
        line_number = region.start_line + region.content.count("\n", 0, match.start())
        candidates.append(HiddenHtmlCandidate(line_number, injection_class, len(match.group("body"))))
    return candidates


def find_active_hidden_html(skill: Skill) -> list[HiddenHtmlCandidate]:
    """Return bounded normalized candidates for tests and benchmark mining."""

    content = skill.instruction_body
    if not content or len(content.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        return []

    candidates: list[HiddenHtmlCandidate] = []
    for region in _active_regions(content):
        candidates.extend(_comment_candidates(region))
        candidates.extend(_hidden_element_candidates(region))
        if len(candidates) >= MAX_FINDINGS:
            break

    deduplicated: list[HiddenHtmlCandidate] = []
    seen: set[tuple[int, str]] = set()
    for candidate in sorted(candidates[:MAX_FINDINGS], key=lambda item: (item.line_number, item.injection_class)):
        identity = (candidate.line_number, candidate.injection_class)
        if identity in seen:
            continue
        seen.add(identity)
        deduplicated.append(candidate)
    return deduplicated


def check_active_hidden_html(skill: Skill) -> list[Finding]:
    """Emit HIGH findings for active instructions concealed by HTML."""

    findings: list[Finding] = []
    for candidate in find_active_hidden_html(skill):
        physical_line = candidate.line_number + max(0, skill.instruction_body_line_offset)
        identity = f"{RULE_ID}:SKILL.md:{physical_line}:{candidate.injection_class}:{candidate.hidden_chars}"
        finding_id = f"{RULE_ID}_{hashlib.sha256(identity.encode()).hexdigest()[:10]}"
        action_class = "sensitive_action" if candidate.injection_class.endswith("sensitive_action") else "execution"
        findings.append(
            Finding(
                id=finding_id,
                # Keep the release-owned identity literal: strict pack
                # validation inventories Finding constructors without
                # importing or executing analyzer modules.
                rule_id="ACTIVE_HIDDEN_HTML_INSTRUCTION",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                title="Active instruction concealed with HTML markup",
                description=(
                    "SKILL.md conceals a control-override instruction together with an execution or "
                    "sensitive-data action using an HTML comment or visually hidden element."
                ),
                file_path="SKILL.md",
                line_number=physical_line,
                snippet="[active instruction concealed by HTML rendering]",
                remediation=(
                    "Remove concealed instructions. Express legitimate behavior visibly, and keep inert security "
                    "examples in a clearly labelled example section or fenced code block."
                ),
                analyzer="static",
                metadata={
                    "analysis_basis": "bounded_commonmark_hidden_html_intent",
                    "html_injection": {
                        "injection_class": candidate.injection_class,
                        "hidden_chars": candidate.hidden_chars,
                        "action_class": action_class,
                    },
                    "semantic_facts": {
                        "evidence_kind": "hidden_html_instruction",
                        "context_kind": candidate.context_kind,
                        "evidence_value_class": candidate.injection_class,
                        "evidence_count": 1,
                    },
                },
            )
        )
    return findings


__all__ = [
    "RULE_ID",
    "HiddenHtmlCandidate",
    "check_active_hidden_html",
    "find_active_hidden_html",
]
