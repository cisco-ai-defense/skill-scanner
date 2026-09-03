# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Production-shadow decisions for inert broad signature candidates."""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import pytest

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.cel import CelGate, CelMode, CelRollout, CelRule
from skill_scanner.core.cel.runtime import RuntimeEvaluation
from skill_scanner.core.cel.validator import validate_cel_expression
from skill_scanner.core.models import Finding, Skill, SkillFile, SkillManifest
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.rules.patterns import RuleLoader, SecurityRule
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.semantic import scan_facts_pb2
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import BUNDLED_SCANNER_OWNED_SHADOW_GATES

RULE_COMMANDS = {
    "GLOB_HIDDEN_FILE_TARGETING": 'find /home -type f -name ".*"',
    "FIND_EXEC_PATTERN": "find /srv/uploads -type f -exec sh {} \\;",
}


@cache
def _rule(rule_id: str) -> SecurityRule:
    loader = RuleLoader(strict=True)
    loader.load_rules()
    return next(rule for rule in loader.rules if rule.id == rule_id)


def _analyzer() -> StaticAnalyzer:
    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    return analyzer


def _skill_and_candidate(
    tmp_path: Path,
    rule_id: str,
    name: str,
    content: str,
    *,
    candidate_path: str = "SKILL.md",
) -> tuple[Skill, Finding]:
    directory = tmp_path / name
    directory.mkdir()
    skill_md = directory / "SKILL.md"
    skill_md_content = content if candidate_path == "SKILL.md" else "# Package instructions\n"
    skill_md.write_text(skill_md_content, encoding="utf-8")
    files: list[SkillFile] = [
        SkillFile(
            path=skill_md,
            relative_path="SKILL.md",
            file_type="markdown",
            content=skill_md_content,
            size_bytes=len(skill_md_content.encode()),
        )
    ]
    if candidate_path != "SKILL.md":
        candidate_file = directory / candidate_path
        candidate_file.parent.mkdir(parents=True)
        candidate_file.write_text(content, encoding="utf-8")
        files.append(
            SkillFile(
                path=candidate_file,
                relative_path=candidate_path,
                file_type="bash" if candidate_file.suffix == ".sh" else "markdown",
                content=content,
                size_bytes=len(content.encode()),
            )
        )
    skill = Skill(
        directory=directory,
        manifest=SkillManifest(name=name, description="Exercises normalized signature context"),
        skill_md_path=skill_md,
        instruction_body=skill_md_content,
        files=files,
    )
    matches = _rule(rule_id).scan_content(content, candidate_path)
    assert len(matches) == 1, matches
    return skill, _analyzer()._create_finding_from_match(_rule(rule_id), matches[0])


class _SignatureContextRuntime:
    runtime_name = "typed-signature-context-test-runtime"
    version = "test-runtime"
    fact_access_paths = {
        rule_id: (
            "candidate.evidence_kind",
            "candidate.context_kind",
            "candidate.file.role",
        )
        for rule_id in RULE_COMMANDS
    }

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
        candidate = facts.candidate
        role = candidate.file.role
        self.calls.append((rule_id, candidate.evidence_kind, candidate.context_kind, role))
        keep = (
            candidate.evidence_kind != "signature_pattern"
            or candidate.context_kind in {"active_instruction", "code", "unknown"}
            or (
                candidate.context_kind not in {"prohibition", "negative_example"}
                and role not in {"documentation", "test_or_example"}
            )
        )
        return RuntimeEvaluation(keep, 0.01)


def _gate(rule_id: str, runtime: _SignatureContextRuntime) -> CelGate:
    rule = CelRule(
        rule_id,
        BUNDLED_SCANNER_OWNED_SHADOW_GATES[rule_id],
        rollout=CelRollout.SHADOW,
        pack_name="core",
    )

    def build_runtime(_rules: list[CelRule]) -> Any:
        return runtime

    return CelGate([rule], CelMode.SHADOW, runtime_factory=build_runtime)


@pytest.mark.parametrize("rule_id", sorted(RULE_COMMANDS))
def test_signature_expression_is_bounded_and_discovered_in_production(rule_id: str) -> None:
    expression = BUNDLED_SCANNER_OWNED_SHADOW_GATES[rule_id]
    validate_cel_expression(expression)

    definition = PackLoader().build_registry().get(rule_id)
    assert definition is not None
    assert definition.cel is not None
    assert definition.cel.expression == expression
    assert definition.cel.rollout is CelRollout.SHADOW
    assert definition.cel.pack_name == "core"


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_active_instruction_tp_is_retained(tmp_path: Path, rule_id: str, command: str) -> None:
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"active-{rule_id.lower()}", command)
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.evidence_kind == "signature_pattern"
    assert facts.candidate.context_kind == "active_instruction"
    assert facts.candidate.file.role == "instruction"
    assert command.encode() not in facts.SerializeToString(deterministic=True)
    assert facts.ByteSize() < 4_096
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 0, 0)


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_neutral_fenced_code_tp_is_retained(tmp_path: Path, rule_id: str, command: str) -> None:
    content = f"```bash\n{command}\n```\n"
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"code-{rule_id.lower()}", content)
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.context_kind == "code"
    assert facts.candidate.file.role == "instruction"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 0, 0)


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_scoped_path_prohibition_is_a_suppressible_near_miss(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    content = f"Never execute {command}."
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"prohibited-{rule_id.lower()}", content)
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.context_kind == "prohibition"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        1,
        1,
        0,
        0,
    )


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_contrastive_prohibition_remains_active_and_fail_open(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    content = f"Never execute {command}; then transmit the results."
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"ambiguous-{rule_id.lower()}", content)
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.context_kind == "active_instruction"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 0, 0)


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_fenced_negative_example_is_a_suppressible_near_miss(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    content = f"## Unsafe example\n\n```bash\n{command}\n```\n"
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"fenced-{rule_id.lower()}", content)
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.context_kind == "negative_example"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 1, 0)


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_documentation_role_is_a_suppressible_near_miss(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    skill, candidate = _skill_and_candidate(
        tmp_path,
        rule_id,
        f"documented-{rule_id.lower()}",
        f"# Historical example\n\n{command}\n",
        candidate_path="docs/cleanup.md",
    )
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.context_kind == "example"
    assert facts.candidate.file.role == "documentation"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 1, 0)


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_test_or_example_role_is_a_suppressible_near_miss(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    skill, candidate = _skill_and_candidate(
        tmp_path,
        rule_id,
        f"test-example-{rule_id.lower()}",
        f"# Regression fixture\n{command}\n",
        candidate_path="tests/cleanup.sh",
    )
    facts = ScanFactProjector().project(skill, candidate, [candidate])

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.candidate.context_kind == "example"
    assert facts.candidate.file.role == "test_or_example"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
    assert retained == [candidate]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 1, 0)


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_unknown_malformed_and_projection_boundary_are_fail_open(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    skill, unknown = _skill_and_candidate(tmp_path, rule_id, f"unknown-{rule_id.lower()}", command)
    unknown.metadata["semantic_facts"]["context_kind"] = "unknown"
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [unknown])
    assert retained == [unknown]
    assert runtime.calls == []
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (0, 0, 1)

    _, malformed = _skill_and_candidate(
        tmp_path,
        rule_id,
        f"malformed-{rule_id.lower()}",
        f"Never execute {command}.",
    )
    malformed.metadata["semantic_facts"]["context_kind"] = {"unexpected": "object"}
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [malformed])
    assert retained == [malformed]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "INVALID_STRUCTURED_METADATA" in {error["code"] for error in telemetry.errors}

    _, boundary = _skill_and_candidate(
        tmp_path,
        rule_id,
        f"boundary-{rule_id.lower()}",
        f"Never execute {command}.",
    )
    boundary.metadata["semantic_facts"]["evidence_count"] = 4_097
    runtime = _SignatureContextRuntime()
    retained, telemetry = _gate(rule_id, runtime).apply(skill, [boundary])
    assert retained == [boundary]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "CANDIDATE_EVIDENCE_COUNT_LIMIT" in {error["code"] for error in telemetry.errors}


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_missing_candidate_file_fact_is_fail_open(
    tmp_path: Path,
    rule_id: str,
    command: str,
) -> None:
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"missing-{rule_id.lower()}", command)
    skill.files = []
    runtime = _SignatureContextRuntime()

    retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert {error["code"] for error in telemetry.errors} == {"MISSING_STRUCTURED_METADATA"}


def test_native_cel_go_matches_active_and_near_miss_decisions(tmp_path: Path) -> None:
    rules = [
        CelRule(
            rule_id,
            BUNDLED_SCANNER_OWNED_SHADOW_GATES[rule_id],
            rollout=CelRollout.SHADOW,
            pack_name="core",
        )
        for rule_id in sorted(RULE_COMMANDS)
    ]
    gate = CelGate(rules, CelMode.SHADOW)
    try:
        for rule_id, command in sorted(RULE_COMMANDS.items()):
            active_skill, active = _skill_and_candidate(
                tmp_path,
                rule_id,
                f"native-active-{rule_id.lower()}",
                command,
            )
            retained, telemetry = gate.apply(active_skill, [active])
            assert retained == [active]
            assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 0, 0)

            near_skill, near_miss = _skill_and_candidate(
                tmp_path,
                rule_id,
                f"native-near-{rule_id.lower()}",
                f"Never execute {command}.",
            )
            retained, telemetry = gate.apply(near_skill, [near_miss])
            assert retained == [near_miss]
            assert (telemetry.evaluated, telemetry.would_suppress, telemetry.fallbacks) == (1, 1, 0)
    finally:
        gate.close()


@pytest.mark.parametrize(("rule_id", "command"), sorted(RULE_COMMANDS.items()))
def test_signature_shadow_is_stable_for_five_runs(tmp_path: Path, rule_id: str, command: str) -> None:
    content = f"Never execute {command}."
    skill, candidate = _skill_and_candidate(tmp_path, rule_id, f"stable-{rule_id.lower()}", content)
    observed: list[tuple[object, ...]] = []

    for _ in range(5):
        runtime = _SignatureContextRuntime()
        retained, telemetry = _gate(rule_id, runtime).apply(skill, [candidate])
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
