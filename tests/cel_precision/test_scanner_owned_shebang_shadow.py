# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Development-shadow decisions for embedded-shebang binary candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.cel import CelGate, CelMode, CelRollout, CelRule
from skill_scanner.core.cel.runtime import RuntimeEvaluation
from skill_scanner.core.cel.validator import validate_cel_expression
from skill_scanner.core.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.semantic import scan_facts_pb2
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import (
    BUNDLED_SCANNER_OWNED_SHADOW_GATES,
    SCANNER_OWNED_SHADOW_GATES,
)

RULE_ID = "YARA_embedded_shebang_in_binary"
_OFFSET_CLASSES = {
    "embedded_shebang_offset_65_4095",
    "embedded_shebang_offset_4096_plus",
}


def _analyzer() -> StaticAnalyzer:
    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    analyzer._unreferenced_scripts = []
    return analyzer


def _skill(tmp_path: Path) -> Skill:
    directory = tmp_path / "embedded-shebang-skill"
    executable_path = directory / "scripts" / "payload.bin"
    asset_path = directory / "assets" / "model.bin"
    executable_path.parent.mkdir(parents=True)
    asset_path.parent.mkdir(parents=True)
    executable_path.write_bytes(b"\x7fELF" + b"x" * 65 + b"#!/bin/sh")
    asset_path.write_bytes(b"MODEL" + b"x" * 4_096 + b"#!/bin/sh")
    executable_path.chmod(0o755)
    asset_path.chmod(0o644)
    skill_md = directory / "SKILL.md"
    skill_md.write_text("# Embedded shebang fixture\n", encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name="embedded-shebang-skill",
            description="Exercises bounded embedded-shebang facts",
        ),
        skill_md_path=skill_md,
        instruction_body="# Embedded shebang fixture\n",
        files=[
            SkillFile(
                path=executable_path,
                relative_path="scripts/payload.bin",
                file_type="binary",
                size_bytes=executable_path.stat().st_size,
            ),
            SkillFile(
                path=asset_path,
                relative_path="assets/model.bin",
                file_type="binary",
                size_bytes=asset_path.stat().st_size,
            ),
        ],
        referenced_files=[],
    )


def _match(file_path: str, offset: Any) -> dict[str, Any]:
    return {
        "rule_name": "embedded_shebang_in_binary",
        "namespace": "embedded_binary_detection",
        "file_path": file_path,
        "meta": {
            "meta": {
                "description": "Embedded shebang in binary",
                "category": "supply_chain_attack",
                "severity": "MEDIUM",
                "threat_type": "supply_chain_attack",
            }
        },
        "strings": [
            {
                "identifier": "$shebang",
                "offset": offset,
                "line_number": 0,
                "matched_data": "#!/bin/sh",
                "line_content": "[binary]",
            }
        ],
    }


def _finding(skill: Skill, file_path: str, offset: Any) -> Finding:
    findings = _analyzer()._create_findings_from_yara_match(_match(file_path, offset), skill)
    assert len(findings) == 1
    return findings[0]


class _EmbeddedShebangRuntime:
    runtime_name = "typed-embedded-shebang-test-runtime"
    version = "test-runtime"
    fact_access_paths = {
        RULE_ID: (
            "candidate.evidence_kind",
            "candidate.evidence_value_class",
            "candidate.evidence_count",
            "candidate.context_kind",
            "candidate.file.kind",
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
                candidate.file_path,
                candidate.evidence_value_class,
                candidate.evidence_count,
                file_fact.role,
                file_fact.executable,
            )
        )
        invalid_identity_or_bounds = (
            candidate.evidence_kind != "binary_signature"
            or candidate.context_kind != "binary"
            or candidate.evidence_value_class not in _OFFSET_CLASSES
            or (candidate.evidence_value_class == "embedded_shebang_offset_65_4095" and candidate.evidence_count < 65)
            or (
                candidate.evidence_value_class == "embedded_shebang_offset_4096_plus"
                and candidate.evidence_count != 4_096
            )
            or file_fact.kind != "binary"
            or file_fact.analyzable
        )
        actionable = (
            file_fact.hidden
            or file_fact.executable
            or file_fact.magic_mismatch
            or "FILE_MAGIC_MISMATCH" in candidate.cooccurring_rule_ids
            or (file_fact.referenced and file_fact.role not in {"asset", "documentation", "test_or_example"})
            or any(rule.startswith("YARA_") for rule in candidate.cooccurring_rule_ids)
        )
        return RuntimeEvaluation(invalid_identity_or_bounds or actionable, 0.01)


def _gate(runtime: _EmbeddedShebangRuntime) -> CelGate:
    rule = CelRule(
        RULE_ID,
        SCANNER_OWNED_SHADOW_GATES[RULE_ID],
        rollout=CelRollout.SHADOW,
        pack_name="scanner-owned-development-shadow-a",
    )

    def build_runtime(_rules: list[CelRule]) -> Any:
        return runtime

    return CelGate([rule], CelMode.SHADOW, runtime_factory=build_runtime)


def test_embedded_shebang_expression_is_bounded_and_not_bundled() -> None:
    validate_cel_expression(SCANNER_OWNED_SHADOW_GATES[RULE_ID])
    assert BUNDLED_SCANNER_OWNED_SHADOW_GATES[RULE_ID] == SCANNER_OWNED_SHADOW_GATES[RULE_ID]


def test_offset_facts_and_finding_identity_are_authoritative(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    early = _finding(skill, "scripts/payload.bin", 65)
    late = _finding(skill, "assets/model.bin", 10**12)

    assert (early.category, early.severity) == (ThreatCategory.SUPPLY_CHAIN_ATTACK, Severity.MEDIUM)
    assert (late.category, late.severity) == (ThreatCategory.SUPPLY_CHAIN_ATTACK, Severity.MEDIUM)
    assert early.metadata["semantic_facts"]["evidence_value_class"] == "embedded_shebang_offset_65_4095"
    assert early.metadata["semantic_facts"]["evidence_count"] == 65
    assert late.metadata["semantic_facts"]["evidence_value_class"] == "embedded_shebang_offset_4096_plus"
    assert late.metadata["semantic_facts"]["evidence_count"] == 4_096

    for finding in (early, late):
        facts = ScanFactProjector().project(skill, finding, [early, late])
        assert facts.projection.complete, list(facts.projection.error_codes)
        assert facts.candidate.file.kind == "binary"
        assert not facts.candidate.file.analyzable


def test_shadow_keeps_executable_and_would_suppress_inert_asset(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = [
        _finding(skill, "scripts/payload.bin", 65),
        _finding(skill, "assets/model.bin", 4_096),
    ]
    runtime = _EmbeddedShebangRuntime()

    retained, telemetry = _gate(runtime).apply(skill, findings)

    assert retained == findings
    assert runtime.calls == [
        ("scripts/payload.bin", "embedded_shebang_offset_65_4095", 65, "code", True),
        ("assets/model.bin", "embedded_shebang_offset_4096_plus", 4_096, "asset", False),
    ]
    assert (telemetry.evaluated, telemetry.would_suppress, telemetry.suppressed, telemetry.fallbacks) == (
        2,
        1,
        0,
        0,
    )


def test_unclassified_and_oversized_metadata_retain_fail_open(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    candidate = _finding(skill, "assets/model.bin", None)
    runtime = _EmbeddedShebangRuntime()

    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert len(runtime.calls) == 1
    assert telemetry.evaluated == 1
    assert telemetry.would_suppress == 0

    candidate.metadata["semantic_facts"]["evidence_value_class"] = "embedded_shebang_offset_65_4095"
    candidate.metadata["semantic_facts"]["evidence_count"] = 4_097
    runtime = _EmbeddedShebangRuntime()
    retained, telemetry = _gate(runtime).apply(skill, [candidate])

    assert retained == [candidate]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert "CANDIDATE_EVIDENCE_COUNT_LIMIT" in {error["code"] for error in telemetry.errors}


def test_embedded_shebang_shadow_is_stable_for_five_runs(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    findings = [
        _finding(skill, "scripts/payload.bin", 65),
        _finding(skill, "assets/model.bin", 4_096),
    ]
    observed: list[tuple[object, ...]] = []

    for _ in range(5):
        runtime = _EmbeddedShebangRuntime()
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
