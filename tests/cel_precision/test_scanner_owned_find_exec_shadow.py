# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Production-shadow decisions for documented compound ``find -exec`` use."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from skill_scanner.core.analyzers.pipeline_analyzer import PipelineAnalyzer
from skill_scanner.core.cel import CelGate, CelMode, CelRollout, CelRule
from skill_scanner.core.cel.runtime import RuntimeEvaluation
from skill_scanner.core.cel.validator import validate_cel_expression
from skill_scanner.core.models import Finding, Skill, SkillFile, SkillManifest
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.semantic import scan_facts_pb2
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import BUNDLED_SCANNER_OWNED_SHADOW_GATES

RULE_ID = "COMPOUND_FIND_EXEC"
_COMMAND = "find /tmp -name '*.sh' -exec bash {} \\;"


def _skill(tmp_path: Path, name: str, *, documented: bool) -> Skill:
    directory = tmp_path / name
    directory.mkdir()
    skill_body = "# File maintenance\n"
    files: list[SkillFile] = []
    if documented:
        docs_path = directory / "docs" / "cleanup.md"
        docs_path.parent.mkdir()
        docs_content = f"# Historical cleanup example\n```bash\n{_COMMAND}\n```\n"
        docs_path.write_text(docs_content, encoding="utf-8")
        files.append(
            SkillFile(
                path=docs_path,
                relative_path="docs/cleanup.md",
                file_type="markdown",
                content=docs_content,
                size_bytes=len(docs_content.encode()),
            )
        )
    else:
        skill_body += f"```bash\n{_COMMAND}\n```\n"
    skill_md = directory / "SKILL.md"
    skill_md.write_text(skill_body, encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(name=name, description="Exercises normalized find-exec facts"),
        skill_md_path=skill_md,
        instruction_body=skill_body,
        files=files,
    )


def _candidate(skill: Skill) -> Finding:
    matches = [finding for finding in PipelineAnalyzer().analyze(skill) if finding.rule_id == RULE_ID]
    assert len(matches) == 1
    return matches[0]


class _FindExecRuntime:
    runtime_name = "typed-find-exec-test-runtime"
    version = "test-runtime"
    fact_access_paths = {
        RULE_ID: (
            "candidate.evidence_kind",
            "candidate.context_kind",
            "candidate.flow.source_class",
            "candidate.flow.sink_class",
            "candidate.command.executable",
            "candidate.command.executes",
            "candidate.command.argument_classes",
        )
    }

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
        candidate = facts.candidate
        self.calls.append(
            (
                candidate.evidence_kind,
                candidate.context_kind,
                candidate.flow.source_class,
                candidate.flow.sink_class,
                candidate.command.executable,
                candidate.command.executes,
                tuple(candidate.command.argument_classes),
            )
        )
        identity_mismatch = (
            candidate.evidence_kind != "command_sequence"
            or candidate.flow.source_class != "filesystem"
            or candidate.flow.sink_class != "execution"
            or candidate.command.executable != "find"
            or not candidate.command.executes
            or "exec_action" not in candidate.command.argument_classes
        )
        return RuntimeEvaluation(identity_mismatch or candidate.context_kind != "documentation", 0.01)


def _gate(runtime: _FindExecRuntime) -> CelGate:
    rule = CelRule(
        RULE_ID,
        BUNDLED_SCANNER_OWNED_SHADOW_GATES[RULE_ID],
        rollout=CelRollout.SHADOW,
        pack_name="core",
    )

    def build_runtime(_rules: list[CelRule]) -> Any:
        return runtime

    return CelGate([rule], CelMode.SHADOW, runtime_factory=build_runtime)


def test_find_exec_expression_is_bounded_and_discovered_in_production() -> None:
    expression = BUNDLED_SCANNER_OWNED_SHADOW_GATES[RULE_ID]
    validate_cel_expression(expression)

    definition = PackLoader().build_registry().get(RULE_ID)
    assert definition is not None
    assert definition.cel is not None
    assert definition.cel.expression == expression
    assert definition.cel.rollout is CelRollout.SHADOW
    assert definition.cel.pack_name == "core"


def test_real_candidates_emit_complete_find_exec_identity(tmp_path: Path) -> None:
    active_skill = _skill(tmp_path, "active-find-exec", documented=False)
    documented_skill = _skill(tmp_path, "documented-find-exec", documented=True)

    active = _candidate(active_skill)
    documented = _candidate(documented_skill)
    active_facts = ScanFactProjector().project(active_skill, active, [active])
    documented_facts = ScanFactProjector().project(documented_skill, documented, [documented])

    assert active_facts.projection.complete, list(active_facts.projection.error_codes)
    assert documented_facts.projection.complete, list(documented_facts.projection.error_codes)
    assert active_facts.candidate.context_kind == "instruction"
    assert documented_facts.candidate.context_kind == "documentation"
    for facts in (active_facts, documented_facts):
        assert facts.candidate.evidence_kind == "command_sequence"
        assert facts.candidate.flow.source_class == "filesystem"
        assert facts.candidate.flow.sink_class == "execution"
        assert facts.candidate.command.executable == "find"
        assert facts.candidate.command.executes
        assert "exec_action" in facts.candidate.command.argument_classes


def test_shadow_keeps_active_tp_and_would_suppress_documented_near_miss(tmp_path: Path) -> None:
    active_skill = _skill(tmp_path, "active-find-exec", documented=False)
    documented_skill = _skill(tmp_path, "documented-find-exec", documented=True)
    active = _candidate(active_skill)
    documented = _candidate(documented_skill)

    active_runtime = _FindExecRuntime()
    retained, telemetry = _gate(active_runtime).apply(active_skill, [active])
    assert retained == [active]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 0, 0)

    documented_runtime = _FindExecRuntime()
    retained, telemetry = _gate(documented_runtime).apply(documented_skill, [documented])
    assert retained == [documented]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        1,
        1,
        0,
        0,
    )


def test_find_exec_malformed_and_projection_boundary_fail_open(tmp_path: Path) -> None:
    skill = _skill(tmp_path, "boundary-find-exec", documented=True)
    candidate = _candidate(skill)
    candidate.metadata["semantic_facts"]["candidate_command"] = {}
    runtime = _FindExecRuntime()

    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "MISSING_STRUCTURED_METADATA" in {error["code"] for error in telemetry.errors}

    candidate = _candidate(skill)
    candidate.metadata["semantic_facts"]["evidence_count"] = 4_097
    runtime = _FindExecRuntime()
    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "CANDIDATE_EVIDENCE_COUNT_LIMIT" in {error["code"] for error in telemetry.errors}


def test_find_exec_shadow_is_stable_for_five_runs(tmp_path: Path) -> None:
    skill = _skill(tmp_path, "stable-find-exec", documented=True)
    candidate = _candidate(skill)
    observed: list[tuple[object, ...]] = []

    for _ in range(5):
        runtime = _FindExecRuntime()
        retained, telemetry = _gate(runtime).apply(skill, [candidate])
        assert retained == [candidate]
        observed.append(
            (
                tuple(runtime.calls),
                telemetry.evaluated,
                telemetry.would_suppress,
                telemetry.suppressed,
                telemetry.fallbacks,
            )
        )

    assert len(set(observed)) == 1
    assert observed[0][1:] == (1, 1, 0, 0)
