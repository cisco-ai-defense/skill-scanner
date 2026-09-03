# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Data contracts for CEL compilation, decisions, and telemetry."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CelMode(str, Enum):
    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


class CelRollout(str, Enum):
    SHADOW = "shadow"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class CelRule:
    rule_id: str
    expression: str
    fact_schema: str = "v1"
    rollout: CelRollout = CelRollout.SHADOW
    pack_name: str = "unknown"

    @property
    def expression_hash(self) -> str:
        return hashlib.sha256(self.expression.encode("utf-8")).hexdigest()


def expression_set_hash(rules: Iterable[CelRule]) -> str:
    """Hash an exact, order-independent CEL source generation.

    The hash deliberately uses the trusted source expression rather than the
    native compiler's serialization. Compiler output is an implementation
    detail and may vary across otherwise compatible wheels or platforms. The
    length framing also prevents ambiguous concatenation of rule IDs and
    expressions.
    """

    ordered = sorted(rules, key=lambda rule: rule.rule_id)
    if not ordered:
        return ""

    digest = hashlib.sha256(b"skill-scanner-cel-expression-set-v1\0")
    for rule in ordered:
        for value in (rule.rule_id, rule.fact_schema, rule.expression):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


@dataclass(frozen=True)
class CelDecision:
    keep: bool
    evaluated: bool
    would_suppress: bool = False
    suppressed: bool = False
    fallback: bool = False
    reason: str = ""
    elapsed_ms: float = 0.0


@dataclass
class CelTelemetry:
    mode: CelMode
    fact_schema: str = "v1"
    runtime: str = "unavailable"
    runtime_version: str = ""
    expression_set_hash: str = ""
    evaluated: int = 0
    retained: int = 0
    would_suppress: int = 0
    suppressed: int = 0
    fallbacks: int = 0
    projection_incomplete: int = 0
    elapsed_ms: float = 0.0
    projection_ms: float = 0.0
    evaluation_ms: float = 0.0
    errors: list[dict[str, str]] = field(default_factory=list)
    per_rule: dict[str, dict[str, Any]] = field(default_factory=dict)
    _suppressed_candidate_counts: dict[tuple[str, str, str, str, str, str, str], int] = field(
        default_factory=dict,
        repr=False,
    )

    def record_error(self, rule_id: str, code: str) -> None:
        if len(self.errors) < 100:
            self.errors.append({"rule_id": rule_id, "code": code})

    def record_decision(self, rule: CelRule, decision: str) -> None:
        """Record authoritative per-rule counts and immutable identity."""

        if decision not in {"keep", "would_suppress", "fallback", "suppressed"}:
            raise ValueError(f"unsupported CEL telemetry decision: {decision}")
        entry = self.per_rule.setdefault(
            rule.rule_id,
            {
                "keep": 0,
                "would_suppress": 0,
                "fallback": 0,
                "suppressed": 0,
                "expression_hash": rule.expression_hash,
                "pack": rule.pack_name,
                "rollout": rule.rollout.value,
            },
        )
        identity = (entry["expression_hash"], entry["pack"], entry["rollout"])
        expected = (rule.expression_hash, rule.pack_name, rule.rollout.value)
        if identity != expected:
            raise ValueError(f"conflicting CEL telemetry identity for rule {rule.rule_id}")
        entry[decision] = int(entry[decision]) + 1

    def record_suppressed_candidate(
        self,
        rule: CelRule,
        *,
        category: str,
        severity: str,
        analyzer: str,
    ) -> None:
        """Retain bounded normalized context for an enforced suppression.

        A suppressed finding is absent from the final finding list, so the
        aggregate ``per_rule`` counters alone cannot prove whether a release
        removed an actionable benign near miss or a malicious HIGH/CRITICAL
        signal.  Keep only reviewed classifications and immutable CEL
        identity; source text and arbitrary finding metadata are deliberately
        excluded.
        """

        values = (
            rule.rule_id,
            category,
            severity,
            analyzer,
            rule.expression_hash,
            rule.pack_name,
            rule.rollout.value,
        )
        if any(not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4_096 for value in values):
            raise ValueError("suppressed CEL candidate has an invalid normalized identity")
        if values not in self._suppressed_candidate_counts and len(self._suppressed_candidate_counts) >= 4_096:
            raise ValueError("suppressed CEL candidate evidence exceeds the bounded output contract")
        self._suppressed_candidate_counts[values] = self._suppressed_candidate_counts.get(values, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "runtime": self.runtime,
            "runtime_version": self.runtime_version,
            "fact_schema": self.fact_schema,
            "expression_set_hash": self.expression_set_hash,
            "evaluated": self.evaluated,
            "retained": self.retained,
            "would_suppress": self.would_suppress,
            "suppressed": self.suppressed,
            "fallbacks": self.fallbacks,
            "projection_incomplete": self.projection_incomplete,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "projection_ms": round(self.projection_ms, 3),
            "evaluation_ms": round(self.evaluation_ms, 3),
            "errors": list(self.errors),
            "per_rule": {rule_id: dict(values) for rule_id, values in sorted(self.per_rule.items())},
            "suppressed_candidates": [
                {
                    "rule_id": values[0],
                    "category": values[1],
                    "severity": values[2],
                    "analyzer": values[3],
                    "expression_hash": values[4],
                    "pack": values[5],
                    "rollout": values[6],
                    "count": count,
                }
                for values, count in sorted(self._suppressed_candidate_counts.items())
            ],
        }
