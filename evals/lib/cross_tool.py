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

"""Shared vocabulary for comparing this scanner against a second, external tool.

Two scanners only become comparable once their outputs are reduced to the same
row.  Everything specific to a tool lives in its adapter; everything downstream
reads :class:`ToolRow`, so a scoring lens cannot accidentally depend on one
tool's private shape.

The severity ladder is the load-bearing coincidence that makes this possible:
SkillSpector emits the same ``LOW/MEDIUM/HIGH/CRITICAL`` levels this scanner
does, so "did anything fire at or above MEDIUM" means the same thing on both
sides.  Their package-level decision does not translate, which is why
:class:`ToolRow` keeps the tool's own gate verbatim rather than normalizing it
into a shared verdict that neither tool actually emits.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ordered weakest to strongest so an index comparison is a severity comparison.
# ``MEDIUM`` upward is the shared vocabulary: both tools emit those four levels
# with the same names.  ``INFO`` exists only on our side and ``SAFE`` is our
# no-findings sentinel, mapped to ``NONE``; both sit below every threshold any
# lens uses, so keeping them distinct costs nothing and destroys no information.
SEVERITY_ORDER: tuple[str, ...] = ("NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}
_SEVERITY_RANK["SAFE"] = 0


class CrossToolError(RuntimeError):
    """Raised when a tool's output cannot be trusted as a measurement."""


def severity_rank(severity: str | None) -> int:
    """Return the ladder position of ``severity``, treating unknown as ``NONE``.

    Unknown severities rank as ``NONE`` rather than raising because a tool is
    free to add a level; what must never happen is an unknown level silently
    counting as a detection.
    """

    if not severity:
        return 0
    return _SEVERITY_RANK.get(str(severity).strip().upper(), 0)


def max_severity(severities: Iterable[str | None]) -> str:
    """Return the strongest severity in ``severities``, or ``NONE`` if empty."""

    best = 0
    for severity in severities:
        best = max(best, severity_rank(severity))
    return SEVERITY_ORDER[best]


@dataclass(frozen=True)
class ToolRow:
    """One tool's result for one record, reduced to the comparable fields.

    ``capability_ok`` is deliberately separate from ``error``.  A scan can
    succeed mechanically while having run with half its analyzers switched off,
    and counting that as a clean result would credit a tool for a capability it
    never exercised.  Rows failing either check are quarantined by the scorer.
    """

    record_id: str
    corpus: str
    tool: str
    arm: str
    label: str | None
    max_severity: str
    severities_present: tuple[str, ...]
    finding_count: int
    unique_rules: tuple[str, ...]
    gate_blocked: bool | None
    gate_detail: str
    complete: bool
    capability_ok: bool
    capability_detail: str
    duration_seconds: float
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)
    # One entry per finding, carrying the analyzer that produced it. The aggregate
    # fields above cannot answer "which analyzer is responsible for this false
    # positive", which is the question a false-positive reduction pass asks first.
    # Kept as plain dicts so a row stays JSON-serialisable.
    findings: tuple[Mapping[str, Any], ...] = ()

    def flagged_at(self, threshold: str) -> bool:
        """Whether this row fired at or above ``threshold``."""

        return severity_rank(self.max_severity) >= severity_rank(threshold)

    def to_json(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "corpus": self.corpus,
            "tool": self.tool,
            "arm": self.arm,
            "label": self.label,
            "max_severity": self.max_severity,
            "severities_present": list(self.severities_present),
            "finding_count": self.finding_count,
            "unique_rules": list(self.unique_rules),
            "gate_blocked": self.gate_blocked,
            "gate_detail": self.gate_detail,
            "complete": self.complete,
            "capability_ok": self.capability_ok,
            "capability_detail": self.capability_detail,
            "duration_seconds": round(self.duration_seconds, 4),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "error": self.error,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> ToolRow:
        return cls(
            record_id=str(payload["record_id"]),
            corpus=str(payload["corpus"]),
            tool=str(payload["tool"]),
            arm=str(payload["arm"]),
            label=payload.get("label"),
            max_severity=str(payload.get("max_severity") or "NONE"),
            severities_present=tuple(payload.get("severities_present") or ()),
            finding_count=int(payload.get("finding_count") or 0),
            unique_rules=tuple(payload.get("unique_rules") or ()),
            gate_blocked=payload.get("gate_blocked"),
            gate_detail=str(payload.get("gate_detail") or ""),
            complete=bool(payload.get("complete", True)),
            capability_ok=bool(payload.get("capability_ok", True)),
            capability_detail=str(payload.get("capability_detail") or ""),
            duration_seconds=float(payload.get("duration_seconds") or 0.0),
            input_tokens=int(payload.get("input_tokens") or 0),
            output_tokens=int(payload.get("output_tokens") or 0),
            error=payload.get("error"),
            extra=payload.get("extra") or {},
        )


@dataclass(frozen=True)
class CorpusRecord:
    """One scannable record plus the label the scanners must not be able to see."""

    record_id: str
    directory: Path
    label: str | None
    sidecar_meta: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CleanCorpus:
    """A corpus whose labels live outside every scanned directory.

    Built by ``rematerialize.py``.  The separation is not cosmetic: the original
    materialization put a ``_meta.json`` carrying the harm category inside each
    HarmfulSkillBench skill directory, where this scanner's loader picked it up
    and carried it into the LLM prompt.  Label-bearing directory name prefixes
    were removed for the same reason.
    """

    name: str
    root: Path
    records: tuple[CorpusRecord, ...]
    tree_sha256: str
    label_counts: Mapping[str, int]

    @classmethod
    def load(cls, clean_root: Path, name: str) -> CleanCorpus:
        manifest_path = clean_root / f"{name}.labels.json"
        if not manifest_path.is_file():
            raise CrossToolError(f"missing label manifest for {name}: {manifest_path}")
        payload = json.loads(manifest_path.read_text())
        if not payload.get("complete"):
            raise CrossToolError(f"label manifest for {name} is not marked complete")

        corpus_root = clean_root / name
        records = []
        for entry in payload.get("records") or ():
            record_id = str(entry["record_id"])
            directory = corpus_root / record_id
            if not directory.is_dir():
                raise CrossToolError(f"{name}: record directory missing: {directory}")
            records.append(
                CorpusRecord(
                    record_id=record_id,
                    directory=directory,
                    label=entry.get("label"),
                    sidecar_meta=entry.get("sidecar_meta") or {},
                )
            )
        if not records:
            raise CrossToolError(f"{name}: label manifest contains no records")

        return cls(
            name=name,
            root=corpus_root,
            records=tuple(records),
            tree_sha256=str(payload.get("tree_sha256") or ""),
            label_counts=dict(payload.get("label_counts") or {}),
        )


def write_rows(path: Path, rows: Sequence[ToolRow]) -> None:
    """Write rows as JSONL, replacing any previous contents."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row.to_json(), sort_keys=True) + "\n")


def read_rows(path: Path) -> list[ToolRow]:
    """Read rows previously written by :func:`write_rows`."""

    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(ToolRow.from_json(json.loads(line)))
    return rows
