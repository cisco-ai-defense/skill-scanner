# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Development-shadow decisions for scanner-owned opaque-binary candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from skill_scanner.core.analyzability import compute_analyzability
from skill_scanner.core.cel import CelGate, CelMode, CelRollout, CelRule
from skill_scanner.core.cel.runtime import RuntimeEvaluation
from skill_scanner.core.cel.validator import validate_cel_expression
from skill_scanner.core.models import Finding, Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner
from skill_scanner.core.semantic import scan_facts_pb2
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import (
    BUNDLED_SCANNER_OWNED_SHADOW_GATES,
    SCANNER_OWNED_SHADOW_GATES,
)

RULE_ID = "UNANALYZABLE_BINARY"


def _skill(tmp_path: Path) -> Skill:
    directory = tmp_path / "opaque-binary-skill"
    executable_path = directory / "scripts" / "payload.bin"
    asset_path = directory / "assets" / "weights.bin"
    executable_path.parent.mkdir(parents=True)
    asset_path.parent.mkdir(parents=True)
    executable_path.write_bytes(b"\x7fELF\x00scanner-owned-fixture")
    asset_path.write_bytes(b"\x00\x01inert-model-fixture")
    executable_path.chmod(0o755)
    asset_path.chmod(0o644)
    skill_md = directory / "SKILL.md"
    skill_md.write_text("# Opaque binary fixture\n", encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name="opaque-binary-skill",
            description="Exercises bounded scanner-owned analyzability facts",
        ),
        skill_md_path=skill_md,
        instruction_body="# Opaque binary fixture\n",
        files=[
            SkillFile(
                path=executable_path,
                relative_path="scripts/payload.bin",
                file_type="binary",
                size_bytes=executable_path.stat().st_size,
            ),
            SkillFile(
                path=asset_path,
                relative_path="assets/weights.bin",
                file_type="binary",
                size_bytes=asset_path.stat().st_size,
            ),
        ],
        referenced_files=[],
    )


def _findings(skill: Skill) -> list[Finding]:
    scanner = SkillScanner.__new__(SkillScanner)
    scanner.policy = ScanPolicy.default()
    return [
        finding
        for finding in scanner._analyzability_findings(compute_analyzability(skill, policy=scanner.policy))
        if finding.rule_id == RULE_ID
    ]


class _OpaqueBinaryRuntime:
    runtime_name = "typed-opaque-binary-test-runtime"
    version = "test-runtime"
    fact_access_paths = {
        RULE_ID: (
            "candidate.evidence_kind",
            "candidate.evidence_value_class",
            "candidate.context_kind",
            "candidate.file.analyzable",
            "candidate.file.hidden",
            "candidate.file.executable",
            "candidate.file.magic_mismatch",
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
                rule_id,
                candidate.file_path,
                candidate.evidence_kind,
                candidate.evidence_value_class,
                candidate.context_kind,
                file_fact.role,
                file_fact.analyzable,
                file_fact.hidden,
                file_fact.executable,
                file_fact.referenced,
            )
        )
        identity_mismatch = (
            candidate.evidence_kind != "file_analyzability"
            or candidate.evidence_value_class != "opaque_binary"
            or candidate.context_kind != "binary"
        )
        actionable = not file_fact.analyzable and (
            file_fact.hidden
            or file_fact.executable
            or file_fact.magic_mismatch
            or "FILE_MAGIC_MISMATCH" in candidate.cooccurring_rule_ids
            or (file_fact.referenced and file_fact.role not in {"asset", "documentation", "test_or_example"})
            or any(rule.startswith("YARA_") for rule in candidate.cooccurring_rule_ids)
        )
        return RuntimeEvaluation(identity_mismatch or actionable, 0.01)


def _gate(runtime: _OpaqueBinaryRuntime) -> CelGate:
    rule = CelRule(
        RULE_ID,
        SCANNER_OWNED_SHADOW_GATES[RULE_ID],
        rollout=CelRollout.SHADOW,
        pack_name="scanner-owned-development-shadow-a",
    )

    def build_runtime(_rules: list[CelRule]) -> Any:
        return runtime

    return CelGate([rule], CelMode.SHADOW, runtime_factory=build_runtime)


def test_unanalyzable_binary_expression_is_bounded_and_not_bundled() -> None:
    validate_cel_expression(SCANNER_OWNED_SHADOW_GATES[RULE_ID])
    assert BUNDLED_SCANNER_OWNED_SHADOW_GATES[RULE_ID] == SCANNER_OWNED_SHADOW_GATES[RULE_ID]


def test_scanner_emits_complete_candidate_local_binary_facts(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)

    assert [finding.file_path for finding in findings] == [
        "scripts/payload.bin",
        "assets/weights.bin",
    ]
    for finding in findings:
        facts = ScanFactProjector().project(skill, finding, findings)
        assert facts.projection.complete, list(facts.projection.error_codes)
        assert facts.candidate.evidence_kind == "file_analyzability"
        assert facts.candidate.evidence_value_class == "opaque_binary"
        assert facts.candidate.context_kind == "binary"
        assert not facts.candidate.file.analyzable


def test_shadow_keeps_executable_and_would_suppress_inert_asset(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)
    runtime = _OpaqueBinaryRuntime()

    retained, telemetry = _gate(runtime).apply(skill, findings)

    assert retained == findings
    assert [call[1] for call in runtime.calls] == ["scripts/payload.bin", "assets/weights.bin"]
    assert runtime.calls[0][7:] == (False, True, False)
    assert runtime.calls[1][5:] == ("asset", False, False, False, False)
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        2,
        1,
        0,
        0,
    )
    assert findings[0].metadata["cel"]["decision"] == "keep"
    assert findings[1].metadata["cel"]["decision"] == "would_suppress"


def test_future_classification_retains_and_oversized_metadata_fails_open(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)
    candidate = findings[1]
    candidate.metadata["semantic_facts"]["evidence_value_class"] = "future_opaque_binary_class"
    runtime = _OpaqueBinaryRuntime()

    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.evaluated == 0
    assert telemetry.fallbacks == 1
    assert {error["code"] for error in telemetry.errors} == {"INVALID_STRUCTURED_METADATA"}
    assert candidate.metadata["cel"]["decision"] == "fallback"

    candidate.metadata["semantic_facts"]["evidence_value_class"] = "opaque_binary"
    candidate.metadata["semantic_facts"]["evidence_count"] = 4_097
    runtime = _OpaqueBinaryRuntime()
    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "CANDIDATE_EVIDENCE_COUNT_LIMIT" in {error["code"] for error in telemetry.errors}


def test_scanner_owned_binary_shadow_is_stable_for_five_runs(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = _findings(skill)
    observed: list[tuple[object, ...]] = []

    for _ in range(5):
        runtime = _OpaqueBinaryRuntime()
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
    assert observed[0][1:] == (2, 1, 0, 0)
