# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Production-shadow decisions for remote-miner YARA candidates."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.static import _yara_semantic_metadata
from skill_scanner.core.cel import CelGate, CelMode, CelRollout
from skill_scanner.core.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.rules.yara_behavior_context import REMOTE_MINER_RULE
from skill_scanner.core.semantic.projector import ScanFactProjector

RULE_ID = f"YARA_{REMOTE_MINER_RULE}"
_YARA_META = {
    "evidence_kind": "correlated_behavior",
    "context_kind": "code",
    "signal_kind": "compound_flow",
    "value_class": "remote_miner_acquire_execute",
    "source_class": "external_network",
    "sink_class": "resource_consumption",
    "transforms": "",
}


def _skill_and_candidate(tmp_path: Path, name: str, context_kind: str) -> tuple[Skill, Finding]:
    directory = tmp_path / name
    directory.mkdir()
    skill_md = directory / "SKILL.md"
    content = "# Remote miner context fixture\n"
    skill_md.write_text(content, encoding="utf-8")
    skill = Skill(
        directory=directory,
        manifest=SkillManifest(name=name, description="Exercises normalized YARA context"),
        skill_md_path=skill_md,
        instruction_body=content,
        files=[
            SkillFile(
                path=skill_md,
                relative_path="SKILL.md",
                file_type="markdown",
                content=content,
                size_bytes=len(content.encode()),
            )
        ],
    )
    metadata = _yara_semantic_metadata(
        rule_name=REMOTE_MINER_RULE,
        meta=dict(_YARA_META),
        file_path="SKILL.md",
        match_offset=0,
        context_kind_override=context_kind,
    )
    candidate = Finding(
        id=f"{RULE_ID}_{name}",
        rule_id=RULE_ID,
        category=ThreatCategory.RESOURCE_ABUSE,
        severity=Severity.HIGH,
        title="Remote miner acquisition and execution",
        description="Normalized test candidate",
        file_path="SKILL.md",
        line_number=1,
        analyzer="static",
        metadata=metadata,
    )
    return skill, candidate


def _gate() -> CelGate:
    definition = PackLoader().build_registry().get(RULE_ID)
    assert definition is not None
    assert definition.cel is not None
    assert definition.cel.rollout is CelRollout.SHADOW
    return CelGate([definition.cel], CelMode.SHADOW)


@pytest.mark.parametrize(
    ("context_kind", "decision"),
    [
        ("active_instruction", "keep"),
        ("code", "keep"),
        ("example", "would_suppress"),
        ("prohibition", "would_suppress"),
    ],
)
def test_normalized_remote_miner_context_projects_and_evaluates(
    tmp_path: Path,
    context_kind: str,
    decision: str,
) -> None:
    skill, candidate = _skill_and_candidate(tmp_path, f"remote-miner-{context_kind}", context_kind)
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.evidence_kind == "correlated_behavior"
    assert facts.candidate.evidence_value_class == "remote_miner_acquire_execute"
    assert facts.candidate.context_kind == context_kind

    gate = _gate()
    try:
        retained, telemetry = gate.apply(skill, [candidate])
    finally:
        gate.close()

    assert retained == [candidate]
    assert telemetry.evaluated == 1
    assert telemetry.fallbacks == 0
    assert candidate.metadata["cel"]["decision"] == decision
    assert telemetry.would_suppress == (decision == "would_suppress")


def test_unknown_context_and_projection_boundary_fail_open(tmp_path: Path) -> None:
    skill, unknown = _skill_and_candidate(tmp_path, "remote-miner-unknown", "unknown")
    assert "semantic_facts" not in unknown.metadata

    gate = _gate()
    try:
        retained, telemetry = gate.apply(skill, [unknown])
    finally:
        gate.close()

    assert retained == [unknown]
    assert telemetry.evaluated == 0
    assert telemetry.fallbacks == 1
    assert {error["code"] for error in telemetry.errors} == {"MISSING_STRUCTURED_METADATA"}

    skill, boundary = _skill_and_candidate(tmp_path, "remote-miner-boundary", "active_instruction")
    boundary.metadata["semantic_facts"]["evidence_count"] = 4_097
    gate = _gate()
    try:
        retained, telemetry = gate.apply(skill, [boundary])
    finally:
        gate.close()

    assert retained == [boundary]
    assert telemetry.evaluated == 0
    assert telemetry.fallbacks == 1
    assert "CANDIDATE_EVIDENCE_COUNT_LIMIT" in {error["code"] for error in telemetry.errors}


def test_remote_miner_native_shadow_is_stable_across_five_fresh_helpers(tmp_path: Path) -> None:
    observed: list[tuple[int, int, int, str]] = []

    for repetition in range(5):
        skill, candidate = _skill_and_candidate(
            tmp_path,
            f"remote-miner-stable-{repetition}",
            "prohibition",
        )
        gate = _gate()
        try:
            retained, telemetry = gate.apply(skill, [candidate])
        finally:
            gate.close()

        assert retained == [candidate]
        observed.append(
            (
                telemetry.evaluated,
                telemetry.would_suppress,
                telemetry.fallbacks,
                candidate.metadata["cel"]["decision"],
            )
        )

    assert len(set(observed)) == 1
    assert observed[0] == (1, 1, 0, "would_suppress")
