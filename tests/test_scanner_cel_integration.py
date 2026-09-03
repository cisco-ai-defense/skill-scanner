# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Scanner-level integration tests for the bounded CEL decision phase."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

import skill_scanner.core.scanner as scanner_module
from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.cel import CelGoRuntime, CelMode, CelRollout, CelRule, CelTelemetry
from skill_scanner.core.cel.runtime import CelRuntimeUnavailable
from skill_scanner.core.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory
from skill_scanner.core.rule_registry import RuleDefinition, RuleRegistry
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner


def _skill(tmp_path: Path) -> Skill:
    body = "# Test skill\n\nSafe instructions.\n"
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(body, encoding="utf-8")
    return Skill(
        directory=tmp_path,
        manifest=SkillManifest(name="cel-integration", description="CEL integration test skill"),
        skill_md_path=skill_md,
        instruction_body=body,
        files=[
            SkillFile(
                path=skill_md,
                relative_path="SKILL.md",
                file_type="markdown",
                content=body,
                size_bytes=len(body.encode("utf-8")),
            )
        ],
    )


def _finding(rule_id: str, *, analyzer: str) -> Finding:
    return Finding(
        id=f"{rule_id}-1",
        rule_id=rule_id,
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        title="Test candidate",
        description="Test candidate",
        file_path="SKILL.md",
        line_number=1,
        snippet="danger()",
        analyzer=analyzer,
    )


class _StubAnalyzer(BaseAnalyzer):
    def __init__(self, name: str, finding: Finding, events: list[str]) -> None:
        super().__init__(name, policy=ScanPolicy())
        self.finding = finding
        self.events = events

    def analyze(self, _skill: Skill) -> list[Finding]:
        self.events.append(self.name)
        return [self.finding]


def test_cel_runs_between_deterministic_and_llm_and_emits_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    deterministic = _finding("CEL_RULE", analyzer="static")
    llm = _finding("LLM_RULE", analyzer="llm")
    rule = CelRule("CEL_RULE", "f.candidate.context_kind == 'code'", rollout=CelRollout.ENFORCE)
    captured: dict[str, object] = {}

    class RecordingGate:
        def __init__(self, rules: list[CelRule], mode: CelMode) -> None:
            captured["rules"] = rules
            captured["mode"] = mode

        def apply(self, _skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
            events.append("cel_gate")
            assert [finding.rule_id for finding in findings] == ["CEL_RULE"]
            telemetry = CelTelemetry(
                mode=CelMode.ENFORCE,
                runtime="cel-go",
                runtime_version="test",
                expression_set_hash="set-hash",
                evaluated=1,
                would_suppress=1,
                suppressed=1,
            )
            return [], telemetry

    monkeypatch.setattr(scanner_module, "CelGate", RecordingGate)
    policy = ScanPolicy()
    policy.cel.mode = CelMode.ENFORCE
    scanner = SkillScanner(
        analyzers=[
            _StubAnalyzer("static_analyzer", deterministic, events),
            _StubAnalyzer("llm_analyzer", llm, events),
        ],
        policy=policy,
        cel_rules=[rule],
    )

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert events == ["static_analyzer", "cel_gate", "llm_analyzer"]
    assert [finding.rule_id for finding in result.findings] == ["LLM_RULE"]
    assert captured == {"rules": [rule], "mode": CelMode.ENFORCE}
    assert result.scan_metadata is not None
    assert result.scan_metadata["cel"] == {
        "mode": "enforce",
        "runtime": "cel-go",
        "runtime_version": "test",
        "fact_schema": "v1",
        "expression_set_hash": "set-hash",
        "evaluated": 1,
        "retained": 0,
        "would_suppress": 1,
        "suppressed": 1,
        "fallbacks": 0,
        "projection_incomplete": 0,
        "elapsed_ms": 0.0,
        "projection_ms": 0.0,
        "evaluation_ms": 0.0,
        "errors": [],
        "per_rule": {},
        "suppressed_candidates": [],
    }


def test_cel_fail_open_candidate_remains_in_scan_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = _finding("CEL_RULE", analyzer="static")

    class FailingOpenGate:
        def __init__(self, _rules: list[CelRule], _mode: CelMode) -> None:
            pass

        def apply(self, _skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
            findings[0].metadata["cel"] = {
                "decision": "fallback",
                "reason": "EVALUATION_ERROR",
            }
            telemetry = CelTelemetry(mode=CelMode.ENFORCE, retained=1, fallbacks=1)
            telemetry.record_error("CEL_RULE", "EVALUATION_ERROR")
            return findings, telemetry

    monkeypatch.setattr(scanner_module, "CelGate", FailingOpenGate)
    policy = ScanPolicy()
    policy.cel.mode = CelMode.ENFORCE
    scanner = SkillScanner(
        analyzers=[_StubAnalyzer("static_analyzer", candidate, [])],
        policy=policy,
        cel_rules=[CelRule("CEL_RULE", "f.projection.complete", rollout=CelRollout.ENFORCE)],
    )

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert [finding.rule_id for finding in result.findings] == ["CEL_RULE"]
    assert result.findings[0].metadata["cel"]["decision"] == "fallback"
    assert result.scan_metadata is not None
    assert result.scan_metadata["cel"]["fallbacks"] == 1
    assert result.scan_metadata["cel"]["errors"] == [{"rule_id": "CEL_RULE", "code": "EVALUATION_ERROR"}]


@pytest.mark.parametrize(
    ("decision", "reason", "would_suppress", "fallbacks"),
    [
        ("would_suppress", "shadow_or_rule_rollout", 1, 0),
        ("fallback", "INVALID_STRUCTURED_METADATA", 0, 1),
    ],
)
def test_exact_deterministic_duplicates_are_removed_before_cel_telemetry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    decision: str,
    reason: str,
    would_suppress: int,
    fallbacks: int,
) -> None:
    first = _finding("CEL_RULE", analyzer="static")
    duplicate = _finding("CEL_RULE", analyzer="static")
    duplicate.id = "CEL_RULE-duplicate-object"

    class DuplicateAnalyzer(BaseAnalyzer):
        def __init__(self) -> None:
            super().__init__("static_analyzer", policy=ScanPolicy())

        def analyze(self, _skill: Skill) -> list[Finding]:
            return [first, duplicate]

    class RecordingGate:
        def __init__(self, _rules: list[CelRule], _mode: CelMode) -> None:
            pass

        def apply(self, _skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
            assert findings == [first]
            first.metadata["cel"] = {"decision": decision, "reason": reason}
            telemetry = CelTelemetry(
                mode=CelMode.SHADOW,
                retained=1,
                evaluated=0 if fallbacks else 1,
                would_suppress=would_suppress,
                fallbacks=fallbacks,
                projection_incomplete=fallbacks,
            )
            if fallbacks:
                telemetry.record_error("CEL_RULE", reason)
            return findings, telemetry

    monkeypatch.setattr(scanner_module, "CelGate", RecordingGate)
    policy = ScanPolicy()
    policy.cel.mode = CelMode.SHADOW
    scanner = SkillScanner(
        analyzers=[DuplicateAnalyzer()],
        policy=policy,
        cel_rules=[CelRule("CEL_RULE", "f.projection.complete")],
    )

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert result.findings == [first]
    assert result.scan_metadata is not None
    cel = result.scan_metadata["cel"]
    assert cel["would_suppress"] == would_suppress
    assert cel["fallbacks"] == fallbacks
    assert sum(finding.metadata.get("cel", {}).get("decision") == decision for finding in result.findings) == 1


def test_same_issue_normalization_preserves_off_identity_and_cel_lineage() -> None:
    policy = ScanPolicy()
    policy.finding_output.dedupe_same_issue_per_location = True
    policy.finding_output.same_issue_collapse_within_analyzer = True
    scanner = SkillScanner(analyzers=[], policy=policy, cel_rules=[])
    first = _finding("CEL_RULE_A", analyzer="static")
    second = _finding("CEL_RULE_B", analyzer="pipeline")
    undecided = _finding("OTHER_RULE", analyzer="llm")
    first.metadata["cel"] = {"decision": "would_suppress", "reason": "shadow_or_rule_rollout"}
    second.metadata["cel"] = {"decision": "fallback", "reason": "INVALID_STRUCTURED_METADATA"}
    shadow_input = [undecided, first, second]
    off_input = deepcopy(shadow_input)
    for finding in off_input:
        finding.metadata.pop("cel", None)

    normalized_off = scanner._normalize_findings(off_input)
    normalized_shadow = scanner._normalize_findings(shadow_input)

    identity = lambda finding: (
        finding.rule_id,
        finding.analyzer,
        finding.category,
        finding.severity,
        finding.file_path,
        finding.line_number,
        finding.snippet,
    )
    assert [identity(finding) for finding in normalized_shadow] == [identity(finding) for finding in normalized_off]
    assert len(normalized_shadow) == 1
    expected_lineage = [
        {
            "rule_id": "CEL_RULE_A",
            "decision": "would_suppress",
            "reason": "shadow_or_rule_rollout",
            "fact_schema": "unspecified",
            "expression_hash": "unspecified",
            "pack": "unspecified",
            "rollout": "unspecified",
            "count": 1,
        },
        {
            "rule_id": "CEL_RULE_B",
            "decision": "fallback",
            "reason": "INVALID_STRUCTURED_METADATA",
            "fact_schema": "unspecified",
            "expression_hash": "unspecified",
            "pack": "unspecified",
            "rollout": "unspecified",
            "count": 1,
        },
    ]
    assert normalized_shadow[0].metadata["cel_decisions"] == expected_lineage
    assert scanner._cel_decision_lineage(normalized_shadow) == expected_lineage


def test_final_exact_dedupe_preserves_post_cel_severity_collapse_lineage() -> None:
    policy = ScanPolicy()
    scanner = SkillScanner(analyzers=[], policy=policy, cel_rules=[])
    rule = CelRule("CEL_RULE", "f.projection.complete", pack_name="core")
    first = _finding(rule.rule_id, analyzer="static")
    second = _finding(rule.rule_id, analyzer="static")
    second.id = "CEL_RULE-second"
    second.severity = Severity.MEDIUM

    # The candidates are distinct before CEL, so both receive a decision.
    assert scanner._dedupe_exact_findings([first, second]) == [first, second]
    annotation = {
        "decision": "would_suppress",
        "reason": "shadow_or_rule_rollout",
        "fact_schema": rule.fact_schema,
        "expression_hash": rule.expression_hash,
        "pack": rule.pack_name,
        "rollout": rule.rollout.value,
    }
    first.metadata["cel"] = dict(annotation)
    second.metadata["cel"] = dict(annotation)
    telemetry = CelTelemetry(mode=CelMode.SHADOW, would_suppress=2)
    telemetry.record_decision(rule, "would_suppress")
    telemetry.record_decision(rule, "would_suppress")

    # A later severity override makes them exact duplicates. OFF and SHADOW
    # still select the same first winner; SHADOW retains both decisions as one
    # counted lineage entry that reconciles with authoritative telemetry.
    second.severity = Severity.HIGH
    off_input = deepcopy([first, second])
    for finding in off_input:
        finding.metadata.clear()
    normalized_off = scanner._normalize_findings(off_input)
    normalized_shadow = scanner._normalize_findings([first, second])

    assert [(finding.rule_id, finding.id) for finding in normalized_shadow] == [
        (finding.rule_id, finding.id) for finding in normalized_off
    ]
    expected_lineage = [
        {
            "rule_id": rule.rule_id,
            "decision": "would_suppress",
            "reason": "shadow_or_rule_rollout",
            "fact_schema": rule.fact_schema,
            "expression_hash": rule.expression_hash,
            "pack": rule.pack_name,
            "rollout": rule.rollout.value,
            "count": 2,
        }
    ]
    assert normalized_shadow[0].metadata["cel_decisions"] == expected_lineage
    assert scanner._cel_decision_lineage(normalized_shadow) == expected_lineage
    assert telemetry.to_dict()["per_rule"][rule.rule_id]["would_suppress"] == 2


def test_analyzability_candidates_are_created_before_cel_and_llm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    opaque_candidate = _finding("UNANALYZABLE_BINARY", analyzer="analyzability")
    opaque_candidate.category = ThreatCategory.POLICY_VIOLATION
    opaque_candidate.severity = Severity.MEDIUM
    opaque_candidate.file_path = "opaque.bin"
    opaque_candidate.snippet = None
    llm = _finding("LLM_RULE", analyzer="llm")

    class RecordingGate:
        def __init__(self, _rules: list[CelRule], _mode: CelMode) -> None:
            pass

        def apply(self, _skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
            events.append("cel_gate")
            assert [finding.rule_id for finding in findings] == ["UNANALYZABLE_BINARY"]
            return findings, CelTelemetry(mode=CelMode.SHADOW, retained=1)

    monkeypatch.setattr(scanner_module, "CelGate", RecordingGate)
    monkeypatch.setattr(
        SkillScanner,
        "_analyzability_findings",
        lambda _self, _report: [opaque_candidate],
    )
    policy = ScanPolicy()
    policy.cel.mode = CelMode.SHADOW
    scanner = SkillScanner(
        analyzers=[_StubAnalyzer("llm_analyzer", llm, events)],
        policy=policy,
        cel_rules=[CelRule("UNANALYZABLE_BINARY", "f.projection.complete")],
    )

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert events == ["cel_gate", "llm_analyzer"]
    assert {finding.rule_id for finding in result.findings} == {
        "UNANALYZABLE_BINARY",
        "LLM_RULE",
    }


def test_disabled_deterministic_candidates_do_not_reach_cel_or_llm_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    disabled = _finding("CEL_RULE", analyzer="static")
    llm = _finding("LLM_RULE", analyzer="llm")

    class RecordingGate:
        def __init__(self, _rules: list[CelRule], _mode: CelMode) -> None:
            pass

        def apply(self, _skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
            events.append("cel_gate")
            assert findings == []
            return findings, CelTelemetry(mode=CelMode.SHADOW)

    monkeypatch.setattr(scanner_module, "CelGate", RecordingGate)
    policy = ScanPolicy()
    policy.cel.mode = CelMode.SHADOW
    policy.disabled_rules.add("CEL_RULE")
    scanner = SkillScanner(
        analyzers=[
            _StubAnalyzer("static_analyzer", disabled, events),
            _StubAnalyzer("llm_analyzer", llm, events),
        ],
        policy=policy,
        cel_rules=[CelRule("CEL_RULE", "f.projection.complete")],
    )

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert events == ["static_analyzer", "cel_gate", "llm_analyzer"]
    assert [finding.rule_id for finding in result.findings] == ["LLM_RULE"]
    assert result.scan_metadata is not None
    assert result.scan_metadata["cel"]["evaluated"] == 0


def test_analyzability_findings_remain_ineligible_for_llm_demotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from skill_scanner.core.analyzers.adjudicator import Adjudicator

    deterministic = _finding("STATIC_RULE", analyzer="static")
    opaque_candidate = _finding("UNANALYZABLE_BINARY", analyzer="analyzability")
    opaque_candidate.category = ThreatCategory.POLICY_VIOLATION
    opaque_candidate.severity = Severity.MEDIUM
    opaque_candidate.file_path = "opaque.bin"
    opaque_candidate.snippet = None
    adjudicated_rule_ids: list[str] = []

    class RecordingGate:
        def __init__(self, _rules: list[CelRule], _mode: CelMode) -> None:
            pass

        def apply(self, _skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
            return findings, CelTelemetry(mode=CelMode.OFF, retained=len(findings))

    monkeypatch.setattr(scanner_module, "CelGate", RecordingGate)
    monkeypatch.setattr(
        SkillScanner,
        "_analyzability_findings",
        lambda _self, _report: [opaque_candidate],
    )
    monkeypatch.setattr(Adjudicator, "is_available", lambda _self: True)
    monkeypatch.setattr(
        Adjudicator,
        "adjudicate",
        lambda _self, findings, _skill: adjudicated_rule_ids.extend(finding.rule_id for finding in findings),
    )
    policy = ScanPolicy()
    policy.adjudicator.enabled = True
    scanner = SkillScanner(
        analyzers=[_StubAnalyzer("static_analyzer", deterministic, [])],
        policy=policy,
    )

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert adjudicated_rule_ids == ["STATIC_RULE"]
    opaque_result = next(finding for finding in result.findings if finding.rule_id == "UNANALYZABLE_BINARY")
    assert opaque_result.severity is Severity.MEDIUM
    assert "adjudication" not in opaque_result.metadata


def test_explicit_cel_rules_override_registry_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    registry_rule = CelRule("REGISTRY_RULE", "f.projection.complete")
    explicit_rule = CelRule("EXPLICIT_RULE", "f.projection.complete")
    registry = RuleRegistry()
    registry.register(
        RuleDefinition(
            id="REGISTRY_RULE",
            source_type="python",
            pack_name="test",
            cel=registry_rule,
        )
    )
    captured: list[list[CelRule]] = []

    class RecordingGate:
        def __init__(self, rules: list[CelRule], _mode: CelMode) -> None:
            captured.append(rules)

    monkeypatch.setattr(scanner_module, "CelGate", RecordingGate)
    SkillScanner(analyzers=[], policy=ScanPolicy(), rule_registry=registry)
    SkillScanner(analyzers=[], policy=ScanPolicy(), rule_registry=registry, cel_rules=[explicit_rule])

    assert captured == [[registry_rule], [explicit_rule]]


def test_direct_scanner_construction_validates_bundled_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = RuleRegistry()
    calls = 0

    def build_registry(_self: object) -> RuleRegistry:
        nonlocal calls
        calls += 1
        return registry

    monkeypatch.setattr("skill_scanner.core.rule_registry.PackLoader.build_registry", build_registry)

    scanner = SkillScanner(analyzers=[], policy=ScanPolicy())

    assert calls == 1
    assert scanner.rule_registry is registry


def test_explicit_registry_skips_default_bundled_registry_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = RuleRegistry()

    def unexpected_build(_self: object) -> RuleRegistry:
        pytest.fail("explicit validated registry must be used without rebuilding")

    monkeypatch.setattr("skill_scanner.core.rule_registry.PackLoader.build_registry", unexpected_build)

    scanner = SkillScanner(analyzers=[], policy=ScanPolicy(), rule_registry=registry)

    assert scanner.rule_registry is registry


def test_active_cel_mode_propagates_missing_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_self: CelGoRuntime, _rules: list[CelRule], **_kwargs: object) -> None:
        raise CelRuntimeUnavailable("official cel-go helper is unavailable")

    monkeypatch.setattr(CelGoRuntime, "__init__", unavailable)
    policy = ScanPolicy()
    policy.cel.mode = CelMode.SHADOW

    with pytest.raises(CelRuntimeUnavailable, match="official cel-go helper"):
        SkillScanner(
            analyzers=[],
            policy=policy,
            cel_rules=[CelRule("CEL_RULE", "f.projection.complete")],
        )


def test_off_mode_emits_authoritatively_validated_cel_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "skill_scanner.core.cel.gate.validate_cel_go_generation",
        lambda _rules: "v0.32.0;helper=test",
    )
    scanner = SkillScanner(analyzers=[], policy=ScanPolicy())

    result = scanner._scan_single_skill(_skill(tmp_path), tmp_path)

    assert result.scan_metadata is not None
    assert result.scan_metadata["cel"]["mode"] == "off"
    assert result.scan_metadata["cel"]["runtime"] == "cel-go"
    assert result.scan_metadata["cel"]["runtime_version"] == "v0.32.0;helper=test"
    assert result.scan_metadata["cel"]["evaluated"] == 0
