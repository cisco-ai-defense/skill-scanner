# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Development-shadow decisions for hidden script role/reference context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

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

RULE_ID = "HIDDEN_EXECUTABLE_SCRIPT"


def _analyzer() -> StaticAnalyzer:
    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    analyzer._unreferenced_scripts = []
    return analyzer


def _skill(tmp_path: Path) -> Skill:
    directory = tmp_path / "hidden-script-skill"
    script_dir = directory / "scripts"
    script_dir.mkdir(parents=True)
    file_specs = {
        "scripts/.payload.py": ("print('active executable')\n", 0o755),
        "scripts/.helper.py": ("def helper(): return 1\n", 0o644),
        "scripts/.referenced.py": ("def referenced(): return 2\n", 0o644),
    }
    files: list[SkillFile] = []
    for relative_path, (content, mode) in file_specs.items():
        path = directory / relative_path
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        files.append(
            SkillFile(
                path=path,
                relative_path=relative_path,
                file_type="python",
                content=content,
                size_bytes=path.stat().st_size,
            )
        )
    skill_md = directory / "SKILL.md"
    skill_md.write_text("Run scripts/.referenced.py when explicitly requested.\n", encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name="hidden-script-skill",
            description="Exercises hidden script role and reference facts",
        ),
        skill_md_path=skill_md,
        instruction_body="Run scripts/.referenced.py when explicitly requested.\n",
        files=files,
        referenced_files=["scripts/.referenced.py"],
    )


def _findings(skill: Skill) -> list[Finding]:
    return [finding for finding in _analyzer()._check_hidden_files(skill) if finding.rule_id == RULE_ID]


class _HiddenExecutableRuntime:
    runtime_name = "typed-hidden-executable-test-runtime"
    version = "test-runtime"
    fact_access_paths = {
        RULE_ID: (
            "candidate.evidence_kind",
            "candidate.context_kind",
            "candidate.file.hidden",
            "candidate.file.executable",
            "candidate.file.referenced",
            "candidate.file.role",
            "candidate.cooccurring_rule_ids",
        )
    }

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
        candidate = facts.candidate
        file_fact = candidate.file
        self.calls.append(
            (
                candidate.file_path,
                candidate.evidence_kind,
                candidate.context_kind,
                file_fact.role,
                file_fact.hidden,
                file_fact.executable,
                file_fact.referenced,
            )
        )
        identity_mismatch = (
            candidate.evidence_kind != "file_inventory" or candidate.context_kind != "code" or not file_fact.hidden
        )
        actionable = (
            file_fact.executable
            or (file_fact.referenced and file_fact.role not in {"asset", "documentation", "test_or_example"})
            or any(cooccurring != "BINARY_FILE_DETECTED" for cooccurring in candidate.cooccurring_rule_ids)
        )
        return RuntimeEvaluation(identity_mismatch or actionable, 0.01)


def _gate(runtime: _HiddenExecutableRuntime) -> CelGate:
    rule = CelRule(
        RULE_ID,
        SCANNER_OWNED_SHADOW_GATES[RULE_ID],
        rollout=CelRollout.SHADOW,
        pack_name="scanner-owned-development-shadow-a",
    )

    def build_runtime(_rules: list[CelRule]) -> Any:
        return runtime

    return CelGate([rule], CelMode.SHADOW, runtime_factory=build_runtime)


def test_hidden_executable_expression_is_bounded_and_bundled_for_shadow() -> None:
    validate_cel_expression(SCANNER_OWNED_SHADOW_GATES[RULE_ID])
    assert BUNDLED_SCANNER_OWNED_SHADOW_GATES[RULE_ID] == SCANNER_OWNED_SHADOW_GATES[RULE_ID]


def test_hidden_candidates_project_actual_permissions_and_references(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)

    assert [finding.file_path for finding in findings] == [
        "scripts/.payload.py",
        "scripts/.helper.py",
        "scripts/.referenced.py",
    ]
    projected = [ScanFactProjector().project(skill, finding, findings) for finding in findings]
    assert all(facts.projection.complete for facts in projected)
    assert [facts.candidate.file.executable for facts in projected] == [True, False, False]
    assert [facts.candidate.file.referenced for facts in projected] == [False, False, True]
    assert {facts.candidate.file.role for facts in projected} == {"code"}


def test_shadow_keeps_executable_and_referenced_but_filters_plain_near_miss(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)
    runtime = _HiddenExecutableRuntime()

    retained, telemetry = _gate(runtime).apply(skill, findings)

    assert retained == findings
    assert [call[0] for call in runtime.calls] == [
        "scripts/.payload.py",
        "scripts/.helper.py",
        "scripts/.referenced.py",
    ]
    assert [call[5:] for call in runtime.calls] == [(True, False), (False, False), (False, True)]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        3,
        1,
        0,
        0,
    )


def test_future_context_and_projection_boundary_fail_open(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    candidate = _findings(skill)[1]
    candidate.metadata["semantic_facts"]["context_kind"] = "future_hidden_context"
    runtime = _HiddenExecutableRuntime()

    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "INVALID_STRUCTURED_METADATA" in {error["code"] for error in telemetry.errors}

    candidate.metadata["semantic_facts"]["context_kind"] = "code"
    candidate.metadata["semantic_facts"]["evidence_count"] = 4_097
    runtime = _HiddenExecutableRuntime()
    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "CANDIDATE_EVIDENCE_COUNT_LIMIT" in {error["code"] for error in telemetry.errors}


def test_hidden_executable_shadow_is_stable_for_five_runs(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)
    observed: list[tuple[object, ...]] = []

    for _ in range(5):
        runtime = _HiddenExecutableRuntime()
        retained, telemetry = _gate(runtime).apply(skill, findings)
        assert retained == findings
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
    assert observed[0][1:] == (3, 1, 0, 0)
