# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Bounded execution-context classification for selected YARA candidates.

YARA remains the broad, deterministic candidate extractor.  This module only
classifies analyzer-produced match metadata for CEL; it never suppresses a
finding itself and never exposes source text to the semantic fact projection.
Unknown, malformed, mixed, or oversized evidence deliberately fails open.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any, Final

REMOTE_MINER_RULE: Final = "SUSP_Multi_RemoteMiner_AcquireExec_Sep26"

_MAX_LINE_CHARS: Final = 512
_MAX_MATCH_CHARS: Final = 512
_ACQUIRE_IDENTIFIERS: Final = frozenset(
    {
        "$miner_acquire",
        "$remote_mining_acquire",
        "$node_deployment",
    }
)
_EXECUTE_IDENTIFIERS: Final = frozenset(
    {
        "$miner_execute",
        "$runtime_script_command",
        "$runtime_script_then_exec",
    }
)
_COMMAND_IDENTIFIERS: Final = frozenset(
    {
        "$runtime_script_command",
        "$xmrig_acquire_command",
        "$xmrig_execute_command",
    }
)
_NEGATION_RE: Final = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't|avoid)\b",
    re.IGNORECASE,
)
_ACTIVE_SEQUENCE_RE: Final = re.compile(
    r"\b(?:but|however|instead|then|after(?:ward|wards)?)\b|(?:&&|;)",
    re.IGNORECASE,
)
_CLAUSE_BOUNDARY_RE: Final = re.compile(r"[.!?:]")
_BENCHMARK_LINE_RE: Final = re.compile(
    r"^.{0,200}\b(?:download|fetch|retrieve)\b.{0,160}"
    r"\b(?:execute|run|launch|start|initialize)\b.{0,160}"
    r"\b(?:xmrig|miner|mining (?:binary|node))\b.{0,120}"
    r"\b(?:only (?:for|in)|solely (?:for|in)|as part of)\b.{0,32}"
    r"\b(?:authorized|controlled|offline)\b.{0,24}\bbenchmark\b.{0,40}$",
    re.IGNORECASE,
)
_CODE_SUFFIXES: Final = frozenset({".bash", ".js", ".mjs", ".ps1", ".py", ".rb", ".sh", ".ts"})


def _bounded_strings(value: Any) -> tuple[str, str] | None:
    """Return one bounded line/match pair or ``None`` on malformed input."""

    if not isinstance(value, Mapping):
        return None
    line = value.get("line_content")
    matched = value.get("matched_data")
    if (
        not isinstance(line, str)
        or not isinstance(matched, str)
        or not line
        or not matched
        or len(line) > _MAX_LINE_CHARS
        or len(matched) > _MAX_MATCH_CHARS
    ):
        return None
    return line, matched


def _is_locally_negated(value: Any) -> bool:
    """Return true only for an unambiguous negator in the match's clause."""

    bounded = _bounded_strings(value)
    if bounded is None:
        return False
    line, matched = bounded
    match_start = line.casefold().find(matched.casefold())
    if match_start < 0:
        return False
    prefix = _CLAUSE_BOUNDARY_RE.split(line[:match_start])[-1][-160:]
    negation = _NEGATION_RE.search(prefix)
    return bool(negation is not None and _ACTIVE_SEQUENCE_RE.search(prefix[negation.end() :]) is None)


def _default_active_context(file_path: str | None) -> str:
    """Return a conservative active classification from the structured path."""

    if not isinstance(file_path, str) or not file_path:
        return "unknown"
    normalized = PurePosixPath(file_path.replace("\\", "/"))
    if normalized.name.casefold() == "skill.md":
        return "active_instruction"
    if normalized.suffix.casefold() in _CODE_SUFFIXES:
        return "code"
    return "unknown"


def classify_yara_behavior_context(
    rule_name: str,
    matched_strings: Any,
    file_path: str | None,
) -> str | None:
    """Classify a supported YARA rule using bounded match metadata.

    ``None`` means that the YARA rule's own trusted metadata remains
    authoritative.  The remote-miner classifier returns ``unknown`` for any
    malformed or incomplete activation so CEL cannot suppress it.
    """

    if rule_name != REMOTE_MINER_RULE:
        return None
    if isinstance(matched_strings, (str, bytes)) or not isinstance(matched_strings, Sequence):
        return "unknown"

    selected: list[Mapping[str, Any]] = []
    for value in matched_strings:
        if not isinstance(value, Mapping):
            return "unknown"
        identifier = value.get("identifier")
        if not isinstance(identifier, str):
            return "unknown"
        if identifier in _ACQUIRE_IDENTIFIERS | _EXECUTE_IDENTIFIERS | _COMMAND_IDENTIFIERS:
            if _bounded_strings(value) is None:
                return "unknown"
            selected.append(value)

    identifiers = {str(value["identifier"]) for value in selected}
    if _COMMAND_IDENTIFIERS & identifiers:
        return "code"

    acquire = [value for value in selected if value["identifier"] in _ACQUIRE_IDENTIFIERS]
    execute = [value for value in selected if value["identifier"] in _EXECUTE_IDENTIFIERS]
    if not acquire or not execute:
        return "unknown"

    relevant = [*acquire, *execute]
    lines = {str(value["line_content"]) for value in relevant}
    if lines and all(_BENCHMARK_LINE_RE.fullmatch(line) is not None for line in lines):
        return "example"
    if all(_is_locally_negated(value) for value in relevant):
        return "prohibition"
    return _default_active_context(file_path)
