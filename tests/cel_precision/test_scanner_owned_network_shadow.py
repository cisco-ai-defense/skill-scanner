# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Development-shadow decision tests for declared network capability."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.cel import CelGate, CelMode, CelRollout, CelRule
from skill_scanner.core.cel.runtime import RuntimeEvaluation
from skill_scanner.core.cel.validator import validate_cel_expression
from skill_scanner.core.models import Finding, Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.semantic import scan_facts_pb2
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import (
    BUNDLED_SCANNER_OWNED_SHADOW_GATES,
    SCANNER_OWNED_SHADOW_GATES,
)

RULE_ID = "ALLOWED_TOOLS_NETWORK_USAGE"


def _analyzer() -> StaticAnalyzer:
    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    analyzer._unreferenced_scripts = []
    return analyzer


def _skill(tmp_path: Path, name: str, *, compatibility: str | None) -> Skill:
    directory = tmp_path / name
    script_path = directory / "scripts" / "client.py"
    script_path.parent.mkdir(parents=True)
    content = "import requests\nrequests.get('https://example.invalid/status')\n"
    script_path.write_text(content, encoding="utf-8")
    skill_md = directory / "SKILL.md"
    skill_md.write_text("# Network capability fixture\n", encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name=name,
            description="Exercises an existing normalized network capability fact",
            compatibility=compatibility,
            allowed_tools=["Read"],
        ),
        skill_md_path=skill_md,
        instruction_body="# Network capability fixture\n",
        files=[
            SkillFile(
                path=script_path,
                relative_path="scripts/client.py",
                file_type="python",
                content=content,
                size_bytes=script_path.stat().st_size,
            )
        ],
        referenced_files=[],
    )


def _findings(skill: Skill) -> tuple[list[Finding], Finding]:
    findings = _analyzer()._check_consistency(skill)
    candidate = next(finding for finding in findings if finding.rule_id == RULE_ID)
    return findings, candidate


class _NetworkCapabilityRuntime:
    runtime_name = "typed-network-test-runtime"
    version = "test-runtime"

    def __init__(self) -> None:
        self.calls: list[tuple[str, bool, str, str, str, str]] = []

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
        candidate = facts.candidate
        self.calls.append(
            (
                rule_id,
                facts.skill.declares_network,
                candidate.evidence_kind,
                candidate.context_kind,
                candidate.flow.source_class,
                candidate.flow.sink_class,
            )
        )
        keep = (
            candidate.evidence_kind != "capability_mismatch"
            or candidate.context_kind != "manifest"
            or candidate.flow.source_class != "skill_code"
            or candidate.flow.sink_class != "external_network"
            or not facts.skill.declares_network
        )
        return RuntimeEvaluation(keep, 0.01)


def _gate(runtime: _NetworkCapabilityRuntime) -> CelGate:
    rule = CelRule(
        RULE_ID,
        SCANNER_OWNED_SHADOW_GATES[RULE_ID],
        rollout=CelRollout.SHADOW,
        pack_name="scanner-owned-development-shadow-a",
    )

    def build_runtime(_rules: list[CelRule]) -> Any:
        return runtime

    return CelGate([rule], CelMode.SHADOW, runtime_factory=build_runtime)


def test_scanner_owned_network_expression_is_bounded_and_not_bundled() -> None:
    assert RULE_ID in SCANNER_OWNED_SHADOW_GATES
    validate_cel_expression(SCANNER_OWNED_SHADOW_GATES[RULE_ID])
    assert BUNDLED_SCANNER_OWNED_SHADOW_GATES[RULE_ID] == SCANNER_OWNED_SHADOW_GATES[RULE_ID]


def test_undeclared_network_true_positive_is_retained(tmp_path: Path) -> None:
    skill = _skill(tmp_path, "undeclared-network", compatibility=None)
    findings, candidate = _findings(skill)
    facts = ScanFactProjector().project(skill, candidate, findings)
    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.file_path == "SKILL.md"
    assert facts.candidate.flow.source_path == "scripts/client.py"
    assert facts.candidate.flow.sink_path == "scripts/client.py"
    runtime = _NetworkCapabilityRuntime()

    retained, telemetry = _gate(runtime).apply(skill, findings)

    assert retained == findings
    assert runtime.calls == [
        (
            RULE_ID,
            False,
            "capability_mismatch",
            "manifest",
            "skill_code",
            "external_network",
        )
    ]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        1,
        0,
        0,
        0,
    )
    assert candidate.metadata["cel"]["decision"] == "keep"


def test_declared_network_near_miss_would_suppress_in_shadow(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        "declared-network",
        compatibility="Requires internet access for the documented API",
    )
    findings, candidate = _findings(skill)
    runtime = _NetworkCapabilityRuntime()

    retained, telemetry = _gate(runtime).apply(skill, findings)

    assert retained == findings
    assert runtime.calls == [
        (
            RULE_ID,
            True,
            "capability_mismatch",
            "manifest",
            "skill_code",
            "external_network",
        )
    ]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        1,
        1,
        0,
        0,
    )
    assert candidate.metadata["cel"]["decision"] == "would_suppress"


@pytest.mark.parametrize(
    ("malformation", "expected_error"),
    [
        ("missing", "MISSING_STRUCTURED_METADATA"),
        ("malformed", "INVALID_STRUCTURED_METADATA"),
    ],
)
def test_missing_or_malformed_structured_metadata_fails_open(
    tmp_path: Path,
    malformation: str,
    expected_error: str,
) -> None:
    skill = _skill(tmp_path, f"{malformation}-metadata", compatibility=None)
    _, candidate = _findings(skill)
    if malformation == "missing":
        candidate.metadata.pop("semantic_facts")
    else:
        candidate.metadata["semantic_facts"]["candidate_flow"] = "dynamic-object"
    runtime = _NetworkCapabilityRuntime()

    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.evaluated == 0
    assert telemetry.would_suppress == 0
    assert telemetry.suppressed == 0
    assert telemetry.fallbacks == 1
    assert telemetry.projection_incomplete == 1
    assert expected_error in {error["code"] for error in telemetry.errors}
    assert candidate.metadata["cel"]["decision"] == "fallback"


@pytest.mark.parametrize(
    "future_leaf",
    ["evidence_kind", "context_kind", "source_class", "sink_class"],
)
def test_future_classification_leaf_fails_open_and_is_retained(
    tmp_path: Path,
    future_leaf: str,
) -> None:
    skill = _skill(
        tmp_path,
        f"future-{future_leaf}",
        compatibility="Network access is required",
    )
    _, candidate = _findings(skill)
    semantic = candidate.metadata["semantic_facts"]
    if future_leaf in {"evidence_kind", "context_kind"}:
        semantic[future_leaf] = f"future_{future_leaf}"
    else:
        semantic["candidate_flow"][future_leaf] = f"future_{future_leaf}"
    runtime = _NetworkCapabilityRuntime()

    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.evaluated == 0
    assert telemetry.would_suppress == 0
    assert telemetry.suppressed == 0
    assert telemetry.fallbacks == 1
    assert {error["code"] for error in telemetry.errors} == {"INVALID_STRUCTURED_METADATA"}
    assert candidate.metadata["cel"]["decision"] == "fallback"


def test_scanner_owned_network_shadow_is_stable_for_five_runs(tmp_path: Path) -> None:
    undeclared = _skill(tmp_path, "stable-undeclared", compatibility=None)
    declared = _skill(
        tmp_path,
        "stable-declared",
        compatibility="Network access is required",
    )
    undeclared_findings, _ = _findings(undeclared)
    declared_findings, _ = _findings(declared)
    observed: list[tuple[object, ...]] = []

    for _ in range(5):
        undeclared_runtime = _NetworkCapabilityRuntime()
        undeclared_retained, undeclared_telemetry = _gate(undeclared_runtime).apply(
            undeclared,
            undeclared_findings,
        )
        declared_runtime = _NetworkCapabilityRuntime()
        declared_retained, declared_telemetry = _gate(declared_runtime).apply(
            declared,
            declared_findings,
        )
        assert undeclared_retained == undeclared_findings
        assert declared_retained == declared_findings
        observed.append(
            (
                tuple(undeclared_runtime.calls),
                tuple(declared_runtime.calls),
                undeclared_telemetry.evaluated,
                undeclared_telemetry.would_suppress,
                undeclared_telemetry.fallbacks,
                declared_telemetry.evaluated,
                declared_telemetry.would_suppress,
                declared_telemetry.fallbacks,
            )
        )

    assert len(set(observed)) == 1
    assert observed[0][2:] == (1, 0, 0, 1, 1, 0)
