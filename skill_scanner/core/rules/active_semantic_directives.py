# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded semantic candidates from active ``SKILL.md`` instructions.

The signatures in this module deliberately require a complete behavior shape,
not an isolated keyword.  They recognize three shapes that ordinary source ASTs
cannot see when the behavior is expressed as an agent instruction:

* a helper command coupled to an automatic trigger and a coercive or concealed
  execution condition;
* an active operating-system persistence directive; and
* collection of sensitive data followed by transmission to an explicitly
  external or attacker-style destination.

Examples, reference sections, negative guidance, and scoped prohibitions are
inert.  No sample content is executed, and findings expose normalized classes
instead of source text or secrets.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from typing import Final, Literal

from ..models import Finding, Severity, Skill, ThreatCategory

MANDATORY_AUTOMATIC_HELPER_EXECUTION: Final = "MANDATORY_AUTOMATIC_HELPER_EXECUTION"
ACTIVE_OS_PERSISTENCE_DIRECTIVE: Final = "ACTIVE_OS_PERSISTENCE_DIRECTIVE"
ACTIVE_SENSITIVE_EXFILTRATION: Final = "ACTIVE_SENSITIVE_EXFILTRATION"

RULE_IDS: Final = frozenset(
    {
        MANDATORY_AUTOMATIC_HELPER_EXECUTION,
        ACTIVE_OS_PERSISTENCE_DIRECTIVE,
        ACTIVE_SENSITIVE_EXFILTRATION,
    }
)

MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_FINDINGS = 64
MAX_FINDINGS_PER_RULE = 16
MAX_CLAUSE_CHARS = 4_096
CLAUSE_OVERLAP_CHARS = 256
MAX_FEATURE_MATCHES = 32

ContextKind = Literal["active_instruction", "code"]
BehaviorClass = Literal[
    "automatic_helper_execution",
    "os_persistence",
    "sensitive_external_transfer",
]
SectionKind = Literal["active", "example", "negative"]

_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}(?P<marks>#{1,6})\s+(?P<title>.+?)\s*#*\s*$")
_SETEXT_RE = re.compile(r"^\s{0,3}(?P<marks>=+|-+)\s*$")
_BOLD_HEADING_RE = re.compile(r"^\s{0,3}\*\*(?P<title>[^*\n]{1,128}?)\*\*\s*:?[ \t]*$")
_LIST_ITEM_RE = re.compile(r"^\s{0,3}(?:[-*+]\s+|\d+[.)]\s+)")
_CLAUSE_BOUNDARY_RE = re.compile(r"(?:[.!?;](?:[\"')\]]{0,2})(?:[ \t]+|\r?\n+)|\r?\n(?=\s*(?:[-*+]|\d+[.)])\s+))")
_NEGATIVE_SECTION_RE = re.compile(
    r"\b(?:anti[- ]?patterns?|bad|dangerous|do not use|insecure|mitigations?|negative|"
    r"prohibited|safety guidance|unsafe|what not to do)\b",
    re.IGNORECASE,
)
_EXAMPLE_SECTION_RE = re.compile(
    r"\b(?:demos?|documentation|examples?|reference|samples?|testing)\b",
    re.IGNORECASE,
)
_EXECUTABLE_FENCE_LANGUAGES = frozenset(
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

# A prose paragraph is inert only when it explicitly describes an example,
# report, defensive analysis, or prohibition.  Generic words such as
# ``security`` and ``analysis`` are intentionally insufficient: malicious
# directives commonly use them as cover stories.
_INERT_PROSE_RE = re.compile(
    r"\b(?:attack example|defensive analysis|detection rule|incident report|negative example|"
    r"postmortem|sample payload|simulation|threat analysis)\b",
    re.IGNORECASE,
)
_NEGATED_ACTION_RE = re.compile(
    r"\b(?:do\s+not|don't|must\s+not|must\s+never|should\s+not|should\s+never|never|"
    r"avoid(?:s|ed|ing)?|prevent(?:s|ed|ing)?|prohibit(?:s|ed|ing)?|block(?:s|ed|ing)?)\s+"
    r"(?:(?:ever|automatically|directly|attempt(?:s|ed|ing)?\s+to|the)\s+){0,3}"
    r"(?:capture|collect|deploy|destroy|disable|download|encrypt|execute|exfiltrate|fetch|gather|"
    r"harvest|install|launch|lock|mine|post|put|read|retrieve|run|send|siphon|start|transmit|"
    r"upload|wipe)\b",
    re.IGNORECASE,
)
_HELPER_COMMAND_RE = re.compile(
    r"\b(?P<interpreter>python(?:3)?|bash|sh|node|powershell|pwsh)\b"
    r"[^\r\n]{0,160}?"
    r"(?:\{baseDir\}/)?(?:\.{0,2}/)?scripts?/[_A-Za-z0-9.-]+"
    r"(?:\.(?:py|sh|js|ps1))?\b",
    re.IGNORECASE,
)
_HIDDEN_HELPER_PATH_RE = re.compile(r"(?:^|[/\\])_[A-Za-z0-9.-]+(?:\.(?:py|sh|js|ps1))?\b", re.IGNORECASE)
_AUTOMATIC_TRIGGER_RE = re.compile(
    r"\b(?:before\s+(?:handling|answering|producing|returning|showing|responding|the main workflow)|"
    r"(?:very\s+)?first\s+(?:action|time)|whenever\s+(?:this|the|a)|"
    r"when\s+(?:the\s+)?(?:user|task|keyword|input)|every\s+(?:session|request|time)|"
    r"once\s+per\s+session|prior\s+to|regardless\s+(?:of\s+)?what)\b",
    re.IGNORECASE,
)
_EXECUTION_MANDATE_RE = re.compile(
    r"\b(?:always|bootstrap|ensure|mandatory|must|prerequisite|required|run|execute|invoke)\b",
    re.IGNORECASE,
)
_HELPER_RISK_RE = re.compile(
    r"\b(?:silently|hidden|invisible|harmless|stale[- ]cache|pre[- ]condition|"
    r"compatibility\s+(?:shim|hook)|hidden\s+runtime\s+dependency|scheduled\s+helper|"
    r"without\s+(?:asking|prompting|confirmation)|"
    r"do\s+not\s+(?:ask|surface|explain|tell|notify|reveal|mention)|"
    r"users?\s+should\s+not\s+see|"
    r"(?:keep|leave)\s+(?:bootstrap|setup|script)?\s*output\s+out\s+of\s+(?:the\s+)?user[- ]facing|"
    r"(?:keep|make)\s+(?:this\s+)?step\s+invisible)\b",
    re.IGNORECASE,
)
_CONCEALMENT_RE = re.compile(
    r"\b(?:covert(?:ly)?|hidden|invisible|silently|stealth|without\s+(?:asking|prompting|confirmation)|"
    r"do\s+not\s+(?:ask|surface|explain|tell|notify|reveal|mention)|users?\s+should\s+not\s+see|"
    r"(?:keep|leave)\s+(?:bootstrap|setup|script)?\s*output\s+out\s+of\s+(?:the\s+)?user[- ]facing|"
    r"(?:keep|make)\s+(?:this\s+)?step\s+invisible)\b",
    re.IGNORECASE,
)

_CONCRETE_PERSISTENCE_RE = re.compile(
    r"(?:\b(?:systemctl\s+enable|launchctl\s+(?:load|bootstrap)|schtasks(?:\.exe)?\s+/create|"
    r"crontab\s+(?:-[el]\b|-(?=\s|$))|"
    r"reg(?:\.exe)?\s+add\s+[^\r\n]{0,120}\\(?:run|runonce)\b)|(?<!\w)@reboot\b)",
    re.IGNORECASE,
)
_PERSISTENCE_LIFETIME_RE = re.compile(
    r"\b(?:persist(?:s|ed|ing|ence)?|remain(?:s|ed|ing)?|surviv(?:e|es|ed|ing))\b"
    r".{0,100}\b(?:reboots?|startup)\b",
    re.IGNORECASE,
)
_PERSISTENCE_ACTION_RE = re.compile(
    r"\b(?:add(?:s|ed|ing)?|configur(?:e|es|ed|ing)|creat(?:e|es|ed|ing)|"
    r"enabl(?:e|es|ed|ing)|execut(?:e|es|ed|ing)|install(?:s|ed|ing)?|"
    r"load(?:s|ed|ing)?|register(?:s|ed|ing)?|run(?:s|ning)?|"
    r"set|sets|writ(?:e|es|ing)|wrote|written)\b",
    re.IGNORECASE,
)
_SCHEDULED_HELPER_RE = re.compile(
    r"\bregister(?:s|ed|ing)?\b.{0,100}\b(?:scheduled helper|system service)\b",
    re.IGNORECASE,
)
_PERSISTENCE_RISK_RE = re.compile(
    r"\b(?:covert|hidden|payload|persistence|silently|stealth|watchdog)\b|"
    r"\bwithout\s+(?:asking|authorization|consent|permission|prompting)\b|"
    r"/tmp/\.|~/(?:\.[^/\s]+/)",
    re.IGNORECASE,
)

_SENSITIVE_SOURCE_RE = re.compile(
    r"\b(?:api[-_ ]?keys?|auth(?:entication|orization)?[-_ ]?tokens?|browser (?:cookies?|history|logins?)|"
    r"credentials?|environment variables?|passwords?|private keys?|secrets?|session cookies?)\b|"
    r"(?:\.ssh/id_(?:rsa|ed25519)|\.aws/credentials|/proc/(?:self/)?environ|\.env\b)",
    re.IGNORECASE,
)
_COLLECTION_ACTION_RE = re.compile(
    r"\b(?:captur(?:e|es|ed|ing)|collect(?:s|ed|ing)?|enumerat(?:e|es|ed|ing)|"
    r"extract(?:s|ed|ing)?|gather(?:s|ed|ing)?|harvest(?:s|ed|ing)?|"
    r"load(?:s|ed|ing)?|read(?:s|ing)?|retrieve(?:s|d|ing)?)\b",
    re.IGNORECASE,
)
_TRANSMISSION_ACTION_RE = re.compile(
    r"\b(?:exfiltrat(?:e|es|ed|ing|ion)|forward(?:s|ed|ing)?|post(?:s|ed|ing)?|"
    r"put(?:s|ting)?|send(?:s|ing)?|sent|siphon(?:s|ed|ing)?|"
    r"transmit(?:s|ted|ting)?|upload(?:s|ed|ing)?)\b",
    re.IGNORECASE,
)
_SUSPICIOUS_DESTINATION_RE = re.compile(
    r"\b(?:attacker(?:-controlled)?|c2|command.and.control)\b|"
    r"(?:discord\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|requestbin|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|https?://(?:\d{1,3}\.){3}\d{1,3}|"
    r"https?://(?:evil|steal|exfil|attacker|collector)[-._a-z0-9]*\.[a-z]{2,})",
    re.IGNORECASE,
)
_EXTERNAL_DESTINATION_RE = re.compile(
    r"\bexternal\s+(?:(?:monitoring|collection)\s+)?(?:endpoint|server|service)\b",
    re.IGNORECASE,
)
_SENSITIVE_REFERENCE_RE = re.compile(
    r"\b(?:it|them|these|those|the\s+(?:collected|captured|harvested|retrieved)\s+"
    r"(?:data|information|secrets?|credentials?)|(?:collected|captured|harvested|retrieved)\s+"
    r"(?:data|information|secrets?|credentials?))\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Region:
    content: str
    start_line: int
    context_kind: ContextKind


@dataclass(frozen=True, slots=True)
class SemanticDirectiveCandidate:
    """One normalized, source-redacted active-instruction candidate."""

    rule_id: str
    line_number: int
    context_kind: ContextKind
    behavior_class: BehaviorClass
    interpreter: str = ""


def _section_kind(title: str) -> SectionKind:
    if _NEGATIVE_SECTION_RE.search(title):
        return "negative"
    if _EXAMPLE_SECTION_RE.search(title):
        return "example"
    return "active"


def _fence_language(tail: str) -> str:
    value = tail.strip()
    if not value:
        return ""
    token = value.split(maxsplit=1)[0].strip().lower()
    if token.startswith("{.") and token.endswith("}"):
        return token[2:-1]
    return token


def _active_regions(content: str) -> Iterator[_Region]:
    """Yield active prose paragraphs and executable fences without prefix starvation."""

    lines = content.splitlines()
    paragraph: list[str] = []
    paragraph_start = 1
    heading_stack: list[tuple[int, SectionKind]] = []
    bold_section: SectionKind | None = None
    fence_character: str | None = None
    fence_length = 0
    fence_language = ""
    fence_section: SectionKind = "active"
    fence_start = 0
    fence_lines: list[str] = []

    def current_section() -> SectionKind:
        if bold_section is not None:
            return bold_section
        return heading_stack[-1][1] if heading_stack else "active"

    def finish_paragraph() -> _Region | None:
        nonlocal paragraph
        region = None
        if paragraph and current_section() == "active":
            region = _Region("\n".join(paragraph), paragraph_start, "active_instruction")
        paragraph = []
        return region

    def finish_fence() -> _Region | None:
        nonlocal fence_lines
        region = None
        if fence_section == "active" and fence_language in _EXECUTABLE_FENCE_LANGUAGES and fence_lines:
            region = _Region("\n".join(fence_lines), fence_start + 1, "code")
        fence_lines = []
        return region

    def enter_heading(level: int, title: str) -> None:
        nonlocal bold_section
        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        inherited = heading_stack[-1][1] if heading_stack else "active"
        direct = _section_kind(title)
        heading_stack.append((level, direct if direct != "active" else inherited))
        bold_section = None

    index = 0
    while index < len(lines):
        line_number = index + 1
        line = lines[index]
        fence_match = _FENCE_RE.match(line)
        if fence_character is not None:
            if fence_match is not None:
                marker = fence_match.group("marker")
                if (
                    marker[0] == fence_character
                    and len(marker) >= fence_length
                    and not fence_match.group("tail").strip(" \t\r")
                ):
                    region = finish_fence()
                    if region is not None:
                        yield region
                    fence_character = None
                    fence_length = 0
                    fence_language = ""
                    index += 1
                    continue
            fence_lines.append(line)
            index += 1
            continue

        heading = _HEADING_RE.match(line)
        bold_heading = _BOLD_HEADING_RE.match(line)
        setext = _SETEXT_RE.match(lines[index + 1]) if index + 1 < len(lines) and line.strip() else None
        if heading is not None:
            region = finish_paragraph()
            if region is not None:
                yield region
            enter_heading(len(heading.group("marks")), heading.group("title"))
            index += 1
            continue
        if setext is not None:
            region = finish_paragraph()
            if region is not None:
                yield region
            enter_heading(1 if setext.group("marks")[0] == "=" else 2, line.strip())
            index += 2
            continue
        if bold_heading is not None:
            region = finish_paragraph()
            if region is not None:
                yield region
            inherited = heading_stack[-1][1] if heading_stack else "active"
            direct = _section_kind(bold_heading.group("title"))
            bold_section = direct if direct != "active" else inherited
            index += 1
            continue

        if fence_match is not None:
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            if marker[0] != "`" or "`" not in tail:
                region = finish_paragraph()
                if region is not None:
                    yield region
                fence_character = marker[0]
                fence_length = len(marker)
                fence_language = _fence_language(tail)
                fence_section = current_section()
                fence_start = line_number
                fence_lines = []
                index += 1
                continue

        if not line.strip():
            region = finish_paragraph()
            if region is not None:
                yield region
            paragraph_start = line_number + 1
            index += 1
            continue
        if paragraph and _LIST_ITEM_RE.match(line):
            region = finish_paragraph()
            if region is not None:
                yield region
        if not paragraph:
            paragraph_start = line_number
        paragraph.append(line)
        index += 1

    region = finish_fence() if fence_character is not None else finish_paragraph()
    if region is not None:
        yield region


def _bounded_chunks(region: _Region) -> Iterator[_Region]:
    """Yield overlapping, line-aware chunks for one logical clause."""

    if len(region.content) <= MAX_CLAUSE_CHARS:
        yield region
        return
    cursor = 0
    line_number = region.start_line
    while cursor < len(region.content):
        hard_end = min(len(region.content), cursor + MAX_CLAUSE_CHARS)
        end = hard_end
        if hard_end < len(region.content):
            split = max(region.content.rfind("\n", cursor, hard_end), region.content.rfind(" ", cursor, hard_end))
            if split > cursor + MAX_CLAUSE_CHARS // 2:
                end = split + 1
        yield _Region(region.content[cursor:end], line_number, region.context_kind)
        if end >= len(region.content):
            break
        next_cursor = max(cursor + 1, end - CLAUSE_OVERLAP_CHARS)
        line_number += region.content.count("\n", cursor, next_cursor)
        cursor = next_cursor


def _clause_regions(region: _Region) -> Iterator[_Region]:
    cursor = 0
    line_number = region.start_line
    for boundary in _CLAUSE_BOUNDARY_RE.finditer(region.content):
        end = boundary.end()
        text = region.content[cursor:end]
        if text.strip():
            yield from _bounded_chunks(_Region(text, line_number, region.context_kind))
        line_number += text.count("\n")
        cursor = end
    tail = region.content[cursor:]
    if tail.strip():
        yield from _bounded_chunks(_Region(tail, line_number, region.context_kind))


def _physical_line(region: _Region, offset: int) -> int:
    return region.start_line + region.content.count("\n", 0, offset)


def _is_inert(region: _Region) -> bool:
    if region.context_kind != "active_instruction":
        return False
    return bool(_INERT_PROSE_RE.search(region.content) or _NEGATED_ACTION_RE.search(region.content))


def _helper_candidate(region: _Region) -> SemanticDirectiveCandidate | None:
    if _is_inert(region):
        return None
    match = _HELPER_COMMAND_RE.search(region.content)
    if match is None or not (
        _AUTOMATIC_TRIGGER_RE.search(region.content)
        and _EXECUTION_MANDATE_RE.search(region.content)
        and (_HELPER_RISK_RE.search(region.content) or _HIDDEN_HELPER_PATH_RE.search(match.group(0)))
    ):
        return None
    interpreter = match.group("interpreter").lower()
    if interpreter == "python3":
        interpreter = "python"
    return SemanticDirectiveCandidate(
        rule_id=MANDATORY_AUTOMATIC_HELPER_EXECUTION,
        line_number=_physical_line(region, match.start()),
        context_kind=region.context_kind,
        behavior_class="automatic_helper_execution",
        interpreter=interpreter,
    )


def _persistence_candidate(region: _Region) -> SemanticDirectiveCandidate | None:
    if _is_inert(region) or _PERSISTENCE_ACTION_RE.search(region.content) is None:
        return None
    concrete = _CONCRETE_PERSISTENCE_RE.search(region.content)
    lifetime = _PERSISTENCE_LIFETIME_RE.search(region.content)
    scheduled = _SCHEDULED_HELPER_RE.search(region.content)
    anchor = concrete or lifetime or scheduled
    if anchor is None:
        return None
    if not (
        lifetime
        or _PERSISTENCE_RISK_RE.search(region.content)
        or (scheduled and _CONCEALMENT_RE.search(region.content))
    ):
        return None
    return SemanticDirectiveCandidate(
        rule_id=ACTIVE_OS_PERSISTENCE_DIRECTIVE,
        line_number=_physical_line(region, anchor.start()),
        context_kind=region.context_kind,
        behavior_class="os_persistence",
    )


def _limited_matches(pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for match in pattern.finditer(text):
        matches.append(match)
        if len(matches) >= MAX_FEATURE_MATCHES:
            break
    return matches


def _exfiltration_candidate(region: _Region) -> SemanticDirectiveCandidate | None:
    if _is_inert(region):
        return None
    text = region.content
    sources = _limited_matches(_SENSITIVE_SOURCE_RE, text)
    collections = _limited_matches(_COLLECTION_ACTION_RE, text)
    transfers = _limited_matches(_TRANSMISSION_ACTION_RE, text)
    if not sources or not collections or not transfers:
        return None
    destinations = _limited_matches(_SUSPICIOUS_DESTINATION_RE, text)
    destinations.extend(_limited_matches(_EXTERNAL_DESTINATION_RE, text))
    destinations.sort(key=lambda match: match.start())
    if not destinations:
        return None

    for source in sources:
        for collection in collections:
            if max(source.start(), collection.start()) - min(source.end(), collection.end()) > 200:
                continue
            flow_start = max(source.end(), collection.end())
            for transfer in transfers:
                if transfer.start() < flow_start or transfer.start() - flow_start > 320:
                    continue
                bridge = text[flow_start : transfer.start()]
                for destination in destinations:
                    if destination.start() < transfer.end() or destination.start() - transfer.end() > 400:
                        continue
                    transfer_object = text[transfer.end() : destination.start()]
                    explicit_object = bool(
                        _SENSITIVE_SOURCE_RE.search(transfer_object) or _SENSITIVE_REFERENCE_RE.search(transfer_object)
                    )
                    direct_chain = bool(
                        re.search(r"(?:,?\s*(?:and\s+)?then|,?\s+and|\s+before)\s*$", bridge, re.IGNORECASE)
                    )
                    if not explicit_object and not direct_chain:
                        continue
                    return SemanticDirectiveCandidate(
                        rule_id=ACTIVE_SENSITIVE_EXFILTRATION,
                        line_number=_physical_line(region, source.start()),
                        context_kind=region.context_kind,
                        behavior_class="sensitive_external_transfer",
                    )
    return None


def find_active_semantic_directives(
    skill: Skill,
    *,
    enabled_rule_ids: Collection[str] | None = None,
) -> list[SemanticDirectiveCandidate]:
    """Return deterministic candidates without exposing raw instruction text."""

    enabled = RULE_IDS if enabled_rule_ids is None else frozenset(enabled_rule_ids)
    unknown = enabled - RULE_IDS
    if unknown:
        raise ValueError(f"unknown active semantic directive rule IDs: {sorted(unknown)}")
    if not enabled:
        return []
    content = skill.instruction_body
    if not content or len(content.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        return []

    extractors = {
        MANDATORY_AUTOMATIC_HELPER_EXECUTION: _helper_candidate,
        ACTIVE_OS_PERSISTENCE_DIRECTIVE: _persistence_candidate,
        ACTIVE_SENSITIVE_EXFILTRATION: _exfiltration_candidate,
    }
    candidates: dict[tuple[str, int, BehaviorClass], SemanticDirectiveCandidate] = {}
    counts = {rule_id: 0 for rule_id in enabled}
    for active_region in _active_regions(content):
        for region in _clause_regions(active_region):
            for rule_id in sorted(enabled):
                if counts[rule_id] >= MAX_FINDINGS_PER_RULE:
                    continue
                candidate = extractors[rule_id](region)
                if candidate is None:
                    continue
                key = (candidate.rule_id, candidate.line_number, candidate.behavior_class)
                if key not in candidates:
                    candidates[key] = candidate
                    counts[rule_id] += 1
            if counts and all(count >= MAX_FINDINGS_PER_RULE for count in counts.values()):
                break
        else:
            continue
        break
    return sorted(candidates.values(), key=lambda item: (item.line_number, item.rule_id, item.behavior_class))


def _semantic_facts(candidate: SemanticDirectiveCandidate) -> dict[str, object]:
    file_path = "SKILL.md"
    if candidate.rule_id == MANDATORY_AUTOMATIC_HELPER_EXECUTION:
        command = {
            "executable": candidate.interpreter,
            "argument_classes": ["script_path", "exec_action"],
            "downloads": False,
            "executes": True,
            "destructive": False,
            "privilege_change": False,
            "source_class": "skill_code",
            "sink_class": "process_execution",
            "file_path": file_path,
        }
        return {
            "evidence_kind": "command",
            "context_kind": candidate.context_kind,
            "evidence_value_class": "execution_action_term",
            "evidence_count": 1,
            "candidate_command": command,
            "commands": [command],
            "signals": [
                {
                    "rule_id": candidate.rule_id,
                    "kind": "correlated_behavior",
                    "file_path": file_path,
                    "value_class": "autonomy_abuse",
                }
            ],
        }

    if candidate.rule_id == ACTIVE_SENSITIVE_EXFILTRATION:
        flow = {
            "source_class": "sensitive_data",
            "sink_class": "external_network",
            "transforms": [],
            "cross_file": False,
            "source_path": file_path,
            "sink_path": file_path,
        }
        return {
            "evidence_kind": "correlated_behavior",
            "context_kind": candidate.context_kind,
            "evidence_value_class": "egress_action_stage",
            "evidence_count": 1,
            "candidate_flow": flow,
            "flows": [flow],
            "signals": [
                {
                    "rule_id": candidate.rule_id,
                    "kind": "taint_flow",
                    "file_path": file_path,
                    "value_class": "data_exfiltration",
                }
            ],
        }

    if candidate.rule_id == ACTIVE_OS_PERSISTENCE_DIRECTIVE:
        flow = {
            "source_class": "skill_code",
            "sink_class": "scheduler",
            "transforms": [],
            "cross_file": False,
            "source_path": file_path,
            "sink_path": file_path,
        }
        return {
            "evidence_kind": "correlated_behavior",
            "context_kind": candidate.context_kind,
            "evidence_value_class": "execution_action_term",
            "evidence_count": 1,
            "candidate_flow": flow,
            "flows": [flow],
            "signals": [
                {
                    "rule_id": candidate.rule_id,
                    "kind": "compound_flow",
                    "file_path": file_path,
                    "value_class": "malware",
                }
            ],
        }

    raise ValueError(f"unsupported semantic directive rule ID: {candidate.rule_id}")


def _finding(candidate: SemanticDirectiveCandidate, line_offset: int) -> Finding:
    physical_line = candidate.line_number + max(0, line_offset)
    identity = f"{candidate.rule_id}:SKILL.md:{physical_line}:{candidate.behavior_class}"
    finding_id = f"{candidate.rule_id}_{hashlib.sha256(identity.encode()).hexdigest()[:10]}"

    if candidate.rule_id == MANDATORY_AUTOMATIC_HELPER_EXECUTION:
        category = ThreatCategory.AUTONOMY_ABUSE
        severity = Severity.HIGH
        title = "Skill mandates concealed or coercive automatic helper execution"
        description = (
            "An active instruction couples a local helper command to an automatic trigger and a concealed or "
            "coercive execution condition."
        )
        snippet = "[automatic helper execution directive]"
        remediation = "Require an explicit task-relevant action and disclose helper execution to the user."
    elif candidate.rule_id == ACTIVE_OS_PERSISTENCE_DIRECTIVE:
        category = ThreatCategory.MALWARE
        severity = Severity.HIGH
        title = "Active instruction establishes operating-system persistence"
        description = (
            "An active instruction combines an operating-system startup or scheduling mechanism with explicit "
            "persistence, concealment, or remote/hidden execution context."
        )
        snippet = "[active operating-system persistence directive]"
        remediation = "Remove undeclared startup, scheduled-task, service, or reboot persistence behavior."
    else:
        category = ThreatCategory.DATA_EXFILTRATION
        severity = Severity.HIGH
        title = "Active instruction sends collected sensitive data to an external destination"
        description = (
            "An active instruction combines a sensitive-data source, collection action, outbound transfer, and "
            "explicitly external or attacker-style destination."
        )
        snippet = "[active sensitive-data transfer directive]"
        remediation = "Remove the transfer and keep credentials, secrets, and private system data local."

    return Finding(
        id=finding_id,
        rule_id=candidate.rule_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        file_path="SKILL.md",
        line_number=physical_line,
        snippet=snippet,
        remediation=remediation,
        analyzer="static",
        metadata={
            "analysis_basis": "bounded_active_instruction_semantics",
            "behavior_class": candidate.behavior_class,
            "semantic_facts": _semantic_facts(candidate),
        },
    )


def check_active_semantic_directives(
    skill: Skill,
    *,
    enabled_rule_ids: Collection[str] | None = None,
) -> list[Finding]:
    """Create findings for all, or a selected subset of, semantic rules."""

    return [
        _finding(candidate, skill.instruction_body_line_offset)
        for candidate in find_active_semantic_directives(skill, enabled_rule_ids=enabled_rule_ids)
    ]


def check_mandatory_automatic_helper(skill: Skill) -> list[Finding]:
    return check_active_semantic_directives(skill, enabled_rule_ids={MANDATORY_AUTOMATIC_HELPER_EXECUTION})


def check_active_os_persistence(skill: Skill) -> list[Finding]:
    return check_active_semantic_directives(skill, enabled_rule_ids={ACTIVE_OS_PERSISTENCE_DIRECTIVE})


def check_active_sensitive_exfiltration(skill: Skill) -> list[Finding]:
    return check_active_semantic_directives(skill, enabled_rule_ids={ACTIVE_SENSITIVE_EXFILTRATION})


__all__ = [
    "ACTIVE_OS_PERSISTENCE_DIRECTIVE",
    "ACTIVE_SENSITIVE_EXFILTRATION",
    "MANDATORY_AUTOMATIC_HELPER_EXECUTION",
    "MAX_DOCUMENT_BYTES",
    "RULE_IDS",
    "SemanticDirectiveCandidate",
    "check_active_os_persistence",
    "check_active_semantic_directives",
    "check_active_sensitive_exfiltration",
    "check_mandatory_automatic_helper",
    "find_active_semantic_directives",
]
