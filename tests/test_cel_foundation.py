# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the bounded CEL validator, runtime, and decision gate."""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import pytest

from skill_scanner.core.cel import (
    CelExpressionLimits,
    CelGate,
    CelMode,
    CelRollout,
    CelRule,
    CelValidationError,
    validate_cel_expression,
)
from skill_scanner.core.cel.gate import (
    _UNKEYABLE,
    _candidate_projection_cache_key,
    _freeze_projection_scalar,
    _projection_key_plan,
)
from skill_scanner.core.cel.models import expression_set_hash
from skill_scanner.core.cel.runtime import RuntimeEvaluation
from skill_scanner.core.models import Finding, Severity, Skill, ThreatCategory
from skill_scanner.core.semantic import ScanFactProjector, scan_facts_pb2
from skill_scanner.core.semantic.projector import PreparedScanFacts


@pytest.mark.parametrize(
    "expression",
    [
        'f.candidate.context_kind != "documentation"',
        '"HIGH_RISK" in f.candidate.cooccurring_rule_ids',
        "has(f.candidate.file) && f.candidate.file.hidden",
        "f.skill.files.exists(x, x.hidden && x.executable)",
        ('f.skill.files.exists(x, f.skill.files.all(y, x.path != y.path || y.role == "documentation"))'),
        'f.candidate.file.path.startsWith("scripts/") || f.candidate.file.path.endsWith(".sh")',
        'f.candidate.file.path.contains("hidden") && f.candidate.file.path.matches("^[a-z./]+$")',
        "f.skill.file_count > 0u && f.candidate.line <= 42u",
        "f.skill.total_bytes >= 0u",
        "f.skill.files.exists(x, x.archive_depth > 0u)",
        'f.skill.name < "z"',
        'f.skill.name.matches("^\\\\d{1,4}$")',
        'f.skill.name.matches("a\\\\{1001\\\\}")',
        'f.skill.name.matches("[{1001}]")',
        "has((f.candidate.file))",
        r'f.skill.name.contains("\?")',
    ],
)
def test_validator_accepts_the_documented_typed_subset(expression: str) -> None:
    validate_cel_expression(expression)


@pytest.mark.parametrize(
    ("expression", "message"),
    [
        ("", "non-empty"),
        ("true", "typed root variable"),
        ("other.candidate.file.hidden", "typed root variable"),
        ("f.skill.file_count + 1 > 2", "unsupported CEL token"),
        ("f.skill.files[0].hidden", "unsupported CEL token"),
        ("dangerous(f)", "function 'dangerous' is not permitted"),
        ("f.skill.name.lowerAscii()", "method 'lowerAscii' is not permitted"),
        ("f.skill.name.matches(f.candidate.rule_id)", "requires a literal string argument"),
        ("f.skill.name == {'name': 'value'}", "unsupported CEL token"),
        ("f.skill.files.exists(x, x.hidden", "unbalanced CEL parentheses"),
        ("f.skill.files.exists(x y, x.hidden)", "must bind one identifier"),
        ("f.skill.files.exists(x, x.hidden) && undeclared", "undeclared top-level identifier"),
        ("f.candidate.no_such_field == true", "undefined protobuf field 'no_such_field'"),
        ("f.candidate.file.no_such_field == true", "undefined protobuf field 'no_such_field'"),
        ("f.skill.name", "must return bool"),
        ("f.skill.file_count", "must return bool"),
        ("f.skill.file_count > 0", "incompatible types uint and int"),
        ("f.skill.files.exists(x, x.path)", "exists predicate requires bool"),
        ("f.skill.files.exists(x, x.hidden) && x.hidden", "undeclared top-level identifier 'x'"),
        ('f.candidate.file.hidden.contains("x")', "requires a string receiver"),
        ("f.candidate.rule_id in f.skill.files", "incompatible element types"),
        ('f.skill.name.matches("(")', "invalid CEL regex literal"),
        ('f.skill.name.matches("foo(?=bar)")', "RE2-unsupported lookaround"),
        ('f.skill.name.matches("foo(?!bar)")', "RE2-unsupported lookaround"),
        ('f.skill.name.matches("(?<=foo)bar")', "RE2-unsupported lookaround"),
        ('f.skill.name.matches("(foo)\\\\1")', "RE2-unsupported backreference"),
        ('f.skill.name.matches("a++")', "RE2-unsupported possessive quantifier"),
        (r'f.skill.name == "\q"', "invalid CEL string escape"),
        (r'f.skill.name.contains("\/")', "invalid CEL string escape"),
        ('f.skill.name == "\\uD800"', "invalid CEL"),
        ('f.skill.name == "\\U00110000"', "invalid CEL"),
        ("f.projection.complete /* block comment */", "unsupported CEL token"),
        ("f.projection.complete\u00a0&& true", "unsupported CEL token"),
        (
            "f.skill.files.exists(true, f.projection.complete)",
            "reserved name",
        ),
        (
            "f.skill.files.exists(has, f.projection.complete)",
            "reserved name",
        ),
        ("f.skill.file_count == ١u", "unsupported CEL token"),
        ("f.skill.file_count == 18446744073709551616u", "exceeds uint64 range"),
        ("f.candidate.line == 9223372036854775808", "exceeds int64 range"),
        ('f.skill.name.matches("(?a)a")', "RE2-unsupported group extension"),
        ('f.skill.name.matches("(?x)a")', "RE2-unsupported group extension"),
        ('f.skill.name.matches("a{1001}")', "repetition exceeds RE2 limit"),
        ('f.skill.name.matches("\\\\Z")', "outside the supported RE2 subset"),
        ('f.skill.name.matches("\\\\u0041")', "outside the supported RE2 subset"),
        ('f.skill.name.matches("[a&&b]")', "invalid CEL regex literal"),
        (
            "f.skill.files.exists(f, f.hidden)",
            "cannot shadow the typed root variable",
        ),
    ],
)
def test_validator_rejects_features_outside_the_bounded_subset(expression: str, message: str) -> None:
    with pytest.raises(CelValidationError, match=message):
        validate_cel_expression(expression)


def test_validator_enforces_each_configurable_limit() -> None:
    with pytest.raises(CelValidationError, match="exceeds 16 KiB"):
        validate_cel_expression("f.skill.name", CelExpressionLimits(max_expression_bytes=1))

    with pytest.raises(CelValidationError, match="token/AST budget"):
        validate_cel_expression('f.skill.name == "x"', CelExpressionLimits(max_tokens=3))

    with pytest.raises(CelValidationError, match="AST node budget"):
        validate_cel_expression(
            "f.projection.complete",
            CelExpressionLimits(max_ast_nodes=2),
        )

    with pytest.raises(CelValidationError, match="nesting exceeds 64"):
        validate_cel_expression("((f.skill.file_count > 0))", CelExpressionLimits(max_depth=1))

    nested_comprehension = "f.skill.files.exists(x, f.skill.files.all(y, x.path != y.path))"
    with pytest.raises(CelValidationError, match="comprehension nesting exceeds two"):
        validate_cel_expression(
            nested_comprehension,
            CelExpressionLimits(max_comprehension_depth=1),
        )

    with pytest.raises(CelValidationError, match="regex exceeds 512 characters"):
        validate_cel_expression(
            'f.skill.name.matches("abcd")',
            CelExpressionLimits(max_literal_regex_chars=3),
        )


def test_validator_rejects_deep_unary_and_boolean_asts_without_recursing() -> None:
    with pytest.raises(CelValidationError, match="AST depth exceeds 64"):
        validate_cel_expression("!" * 65 + "f.projection.complete")

    terms = ["f.projection.complete"] * 65
    with pytest.raises(CelValidationError, match="AST depth exceeds 64"):
        validate_cel_expression(" && ".join(terms))


def test_validator_wraps_unpaired_surrogate_as_a_validation_error() -> None:
    with pytest.raises(CelValidationError, match="invalid Unicode code point"):
        validate_cel_expression('f.skill.name == "\ud800"')


def test_validator_rejects_huge_integer_without_python_int_conversion() -> None:
    expression = "f.skill.total_bytes == " + "9" * 5_000 + "u"

    with pytest.raises(CelValidationError, match="exceeds uint64 range"):
        validate_cel_expression(expression)


def _finding(rule_id: str = "TEST_RULE") -> Finding:
    return Finding(
        id=f"{rule_id}:1",
        rule_id=rule_id,
        category=ThreatCategory.MALWARE,
        severity=Severity.HIGH,
        title="Candidate",
        description="A concrete deterministic candidate",
        file_path="scripts/run.sh",
        line_number=1,
        snippet="never expose this snippet to CEL",
        analyzer="static",
        metadata={
            "semantic_facts": {
                "evidence_kind": "pattern_match",
                "context_kind": "code",
            }
        },
    )


@dataclass
class _RuntimePlan:
    results: dict[str, RuntimeEvaluation]
    version: str = "test-runtime"
    runtime_name: str = "test-runtime"
    expression_set_hash: str = "runtime-expression-set-hash"
    fact_access_paths: dict[str, tuple[str, ...]] | None = None

    def __post_init__(self) -> None:
        self.calls: list[str] = []

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
        assert facts.schema_version == "v1"
        self.calls.append(rule_id)
        return self.results[rule_id]


def _runtime_factory(plan: _RuntimePlan) -> Callable[[list[CelRule]], Any]:
    def build(rules: list[CelRule]) -> _RuntimePlan:
        assert set(plan.results) == {rule.rule_id for rule in rules}
        return plan

    return build


@pytest.mark.parametrize(
    ("mode", "rollout", "expect_suppressed"),
    [
        (CelMode.SHADOW, CelRollout.SHADOW, False),
        (CelMode.SHADOW, CelRollout.ENFORCE, False),
        (CelMode.ENFORCE, CelRollout.SHADOW, False),
        (CelMode.ENFORCE, CelRollout.ENFORCE, True),
    ],
)
def test_false_decision_requires_both_enforce_switches(
    make_skill: Any,
    mode: CelMode,
    rollout: CelRollout,
    expect_suppressed: bool,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    rule = CelRule(finding.rule_id, "f.candidate.file.executable", rollout=rollout, pack_name="test")
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.25)})
    gate = CelGate([rule], mode, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == ([] if expect_suppressed else [finding])
    assert telemetry.evaluated == 1
    assert telemetry.would_suppress == 1
    assert telemetry.suppressed == int(expect_suppressed)
    assert telemetry.retained == int(not expect_suppressed)
    assert telemetry.elapsed_ms > 0
    assert telemetry.projection_ms > 0
    assert telemetry.evaluation_ms == 1.25
    assert telemetry.elapsed_ms >= telemetry.projection_ms
    assert telemetry.runtime == "test-runtime"
    assert telemetry.runtime_version == "test-runtime"
    assert telemetry.expression_set_hash == expression_set_hash([rule])
    assert telemetry.per_rule == {
        finding.rule_id: {
            "keep": 0,
            "would_suppress": 1,
            "fallback": 0,
            "suppressed": int(expect_suppressed),
            "expression_hash": rule.expression_hash,
            "pack": "test",
            "rollout": rollout.value,
        }
    }
    assert telemetry.to_dict()["suppressed_candidates"] == (
        [
            {
                "rule_id": finding.rule_id,
                "category": "malware",
                "severity": "HIGH",
                "analyzer": "static",
                "expression_hash": rule.expression_hash,
                "pack": "test",
                "rollout": "enforce",
                "count": 1,
            }
        ]
        if expect_suppressed
        else []
    )
    assert runtime.calls == [finding.rule_id]
    if not expect_suppressed:
        assert finding.metadata["cel"] == {
            "decision": "would_suppress",
            "reason": "shadow_or_rule_rollout",
            "fact_schema": "v1",
            "expression_hash": rule.expression_hash,
            "pack": "test",
            "rollout": rollout.value,
        }


def test_true_decision_retains_and_annotates_candidate(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    rule = CelRule(finding.rule_id, "f.candidate.file.executable", rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(True, 0.5)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert telemetry.retained == 1
    assert telemetry.would_suppress == 0
    assert telemetry.suppressed == 0
    assert telemetry.fallbacks == 0
    assert telemetry.per_rule[finding.rule_id]["keep"] == 1
    assert finding.metadata["cel"]["decision"] == "keep"
    assert finding.metadata["cel"]["reason"] == "expression_true"


@pytest.mark.parametrize("error_code", ["EVALUATION_ERROR", "NON_BOOLEAN_RESULT", "CIRCUIT_OPEN"])
def test_runtime_error_non_boolean_and_circuit_open_all_fail_open(
    make_skill: Any,
    error_code: str,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    rule = CelRule(finding.rule_id, "f.candidate.file.executable", rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(None, 2.0, error_code)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert telemetry.evaluated == 1
    assert telemetry.retained == 1
    assert telemetry.suppressed == 0
    assert telemetry.fallbacks == 1
    assert telemetry.errors == [{"rule_id": finding.rule_id, "code": error_code}]
    assert telemetry.per_rule[finding.rule_id]["fallback"] == 1
    assert finding.metadata["cel"]["decision"] == "fallback"
    assert finding.metadata["cel"]["reason"] == error_code


class _IncompleteProjector:
    def prepare(self, skill: Skill, findings: list[Finding]) -> object:
        return object()

    def project_candidate(
        self,
        prepared: object,
        candidate: Finding,
    ) -> scan_facts_pb2.ScanFacts:
        facts = scan_facts_pb2.ScanFacts(schema_version="v1")
        facts.candidate.rule_id = candidate.rule_id
        facts.projection.complete = False
        facts.projection.error_codes.extend(["FILE_FACT_LIMIT", "ACTIVATION_SIZE_LIMIT"])
        return facts


def test_incomplete_projection_fails_open_without_evaluation(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    rule = CelRule(finding.rule_id, "f.candidate.file.executable", rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate(
        [rule],
        CelMode.ENFORCE,
        projector=_IncompleteProjector(),  # type: ignore[arg-type]
        runtime_factory=_runtime_factory(runtime),
    )

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.evaluated == 0
    assert telemetry.retained == 1
    assert telemetry.projection_incomplete == 1
    assert telemetry.fallbacks == 1
    assert telemetry.errors == [
        {"rule_id": finding.rule_id, "code": "FILE_FACT_LIMIT"},
        {"rule_id": finding.rule_id, "code": "ACTIVATION_SIZE_LIMIT"},
    ]
    assert finding.metadata["cel"]["decision"] == "fallback"


def test_missing_structured_candidate_metadata_fails_open_without_evaluation(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    finding.metadata.clear()
    rule = CelRule(finding.rule_id, "f.candidate.file.executable", rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.evaluated == 0
    assert telemetry.fallbacks == 1
    assert telemetry.projection_incomplete == 1
    assert telemetry.errors == [{"rule_id": finding.rule_id, "code": "MISSING_STRUCTURED_METADATA"}]
    assert finding.metadata["cel"]["decision"] == "fallback"
    assert finding.metadata["cel"]["reason"] == "MISSING_STRUCTURED_METADATA"


@pytest.mark.parametrize(
    ("metadata_key", "expression"),
    [
        ("candidate_command", "f.candidate.command.downloads"),
        ("candidate_url", "f.candidate.url.trusted_installer"),
        ("candidate_flow", 'f.candidate.flow.source_class == "network"'),
    ],
)
def test_empty_candidate_message_fails_open_before_false_defaults_can_suppress(
    make_skill: Any,
    metadata_key: str,
    expression: str,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    finding.metadata["semantic_facts"][metadata_key] = {}
    rule = CelRule(finding.rule_id, expression, rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.suppressed == 0
    assert telemetry.errors[0]["code"] == "MISSING_STRUCTURED_METADATA"


def test_comprehension_alias_empty_classification_fails_open(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    finding.metadata["semantic_facts"]["commands"] = [
        {
            "executable": "echo",
            "argument_classes": [],
            "downloads": False,
            "executes": False,
            "destructive": False,
            "privilege_change": False,
            "source_class": "",
            "sink_class": "command_action",
            "file_path": "scripts/run.sh",
        }
    ]
    rule = CelRule(
        finding.rule_id,
        'f.skill.commands.exists(c, c.source_class == "secret")',
        rollout=CelRollout.ENFORCE,
    )
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.suppressed == 0
    assert telemetry.errors == [{"rule_id": finding.rule_id, "code": "MISSING_STRUCTURED_METADATA"}]


def test_gate_uses_compiler_fact_access_paths_for_alias_leaf_completeness(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    finding.metadata["semantic_facts"]["commands"] = [
        {
            "executable": "echo",
            "argument_classes": [],
            "downloads": False,
            "executes": False,
            "destructive": False,
            "privilege_change": False,
            "source_class": "command_action",
            "sink_class": "",
            "file_path": "scripts/run.sh",
        }
    ]
    rule = CelRule(
        finding.rule_id,
        'f.skill.commands.exists(c, c.source_class == "sensitive_data")',
        rollout=CelRollout.ENFORCE,
    )
    runtime = _RuntimePlan(
        {finding.rule_id: RuntimeEvaluation(False, 1.0)},
        fact_access_paths={
            finding.rule_id: (
                "skill.commands",
                "skill.commands.sink_class",
                "skill.commands.source_class",
            )
        },
    )
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.suppressed == 0
    assert telemetry.errors == [{"rule_id": finding.rule_id, "code": "MISSING_STRUCTURED_METADATA"}]


def test_package_collection_may_come_from_a_peer_deterministic_finding(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    candidate = _finding("CANDIDATE")
    peer = _finding("PEER")
    peer.metadata["semantic_facts"]["flows"] = [
        {
            "source_class": "network",
            "sink_class": "execution",
            "transforms": [],
            "cross_file": False,
            "source_path": "scripts/run.sh",
            "sink_path": "scripts/run.sh",
        }
    ]
    rule = CelRule(
        candidate.rule_id,
        'f.skill.flows.exists(flow, flow.source_class == "network")',
        rollout=CelRollout.ENFORCE,
    )
    runtime = _RuntimePlan(
        {candidate.rule_id: RuntimeEvaluation(False, 1.0)},
        fact_access_paths={
            candidate.rule_id: (
                "skill.flows",
                "skill.flows.source_class",
            )
        },
    )
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [candidate, peer])

    assert retained == [peer]
    assert runtime.calls == [candidate.rule_id]
    assert telemetry.suppressed == 1
    assert telemetry.fallbacks == 0


def test_unrecognized_candidate_classification_fails_open(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    finding.metadata["semantic_facts"]["context_kind"] = "typo"
    rule = CelRule(
        finding.rule_id,
        'f.candidate.context_kind == "code"',
        rollout=CelRollout.ENFORCE,
    )
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.suppressed == 0
    assert telemetry.errors == [{"rule_id": finding.rule_id, "code": "INVALID_STRUCTURED_METADATA"}]


def test_normalized_file_analyzability_evidence_is_eligible_for_evaluation(make_skill: Any) -> None:
    skill = make_skill({"opaque.bin": b"\x00\x01"})
    finding = _finding()
    finding.metadata["semantic_facts"]["evidence_kind"] = "file_analyzability"
    rule = CelRule(
        finding.rule_id,
        'f.candidate.evidence_kind == "other"',
        rollout=CelRollout.ENFORCE,
    )
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate([rule], CelMode.ENFORCE, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == []
    assert runtime.calls == [finding.rule_id]
    assert telemetry.suppressed == 1
    assert telemetry.fallbacks == 0


def test_unrelated_invalid_package_signal_does_not_poison_candidate_only_gate(make_skill: Any) -> None:
    """A malformed peer collection may only invalidate rules that read it."""

    skill = make_skill({"assets/audio.mp3": b"\x00\x01inert-audio-fixture"})
    candidate = _finding("UNANALYZABLE_BINARY")
    candidate.file_path = "assets/audio.mp3"
    candidate.metadata["semantic_facts"] = {
        "evidence_kind": "file_analyzability",
        "evidence_value_class": "opaque_binary",
        "context_kind": "binary",
        "signal_kind": "unanalyzable_binary",
    }
    unrelated = _finding("BINARY_FILE_DETECTED")
    unrelated.file_path = "assets/audio.mp3"
    unrelated.metadata["semantic_facts"] = {
        "evidence_kind": "binary_signature",
        "context_kind": "binary",
        "signals": [
            {
                "rule_id": "BINARY_FILE_DETECTED",
                "kind": "finding",
                "file_path": "assets/audio.mp3",
                # Reproduces the pre-normalization static-analyzer shape.
                "value_class": ".mp3",
            }
        ],
    }
    required_paths = (
        "candidate.context_kind",
        "candidate.cooccurring_rule_ids",
        "candidate.evidence_kind",
        "candidate.evidence_value_class",
        "candidate.file.analyzable",
        "candidate.file.executable",
        "candidate.file.hidden",
        "candidate.file.magic_mismatch",
        "candidate.file.referenced",
        "candidate.file.role",
    )
    rule = CelRule(candidate.rule_id, 'f.candidate.evidence_kind == "file_analyzability"')
    runtime = _RuntimePlan(
        {candidate.rule_id: RuntimeEvaluation(True, 0.1)},
        fact_access_paths={candidate.rule_id: required_paths},
    )
    gate = CelGate([rule], CelMode.SHADOW, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [candidate, unrelated])

    assert retained == [candidate, unrelated]
    assert runtime.calls == [candidate.rule_id]
    assert telemetry.evaluated == 1
    assert telemetry.fallbacks == 0

    projector = ScanFactProjector()
    prepared = projector.prepare(skill, [candidate, unrelated])
    assert not prepared.base.projection.complete
    assert list(prepared.base.projection.error_codes) == ["INVALID_STRUCTURED_METADATA"]
    selected = projector.project_candidate_for_paths(prepared, candidate, required_paths)
    assert selected.projection.complete, list(selected.projection.error_codes)
    signal_dependent = projector.project_candidate_for_paths(
        prepared,
        candidate,
        ("candidate.context_kind", "candidate.evidence_kind", "skill.signals.value_class"),
    )
    assert not signal_dependent.projection.complete
    assert list(signal_dependent.projection.error_codes) == ["INVALID_STRUCTURED_METADATA"]


class _InconsistentProjector(_IncompleteProjector):
    def __init__(
        self,
        *,
        schema_version: str = "v1",
        error_codes: tuple[str, ...] = (),
        truncated: bool = False,
    ) -> None:
        self.schema_version = schema_version
        self.error_codes = error_codes
        self.truncated = truncated

    def project_candidate(
        self,
        prepared: object,
        candidate: Finding,
    ) -> scan_facts_pb2.ScanFacts:
        facts = scan_facts_pb2.ScanFacts(schema_version=self.schema_version)
        facts.projection.complete = True
        facts.projection.error_codes.extend(self.error_codes)
        facts.projection.truncated = self.truncated
        facts.candidate.rule_id = candidate.rule_id
        return facts


@pytest.mark.parametrize(
    ("projector", "expected_code"),
    [
        (_InconsistentProjector(schema_version="v2"), "FACT_SCHEMA_MISMATCH"),
        (_InconsistentProjector(error_codes=("STRING_SIZE_LIMIT",)), "STRING_SIZE_LIMIT"),
        (_InconsistentProjector(truncated=True), "PROJECTION_INCOMPLETE"),
    ],
)
def test_schema_mismatch_or_inconsistent_projection_status_fails_open(
    make_skill: Any,
    projector: _InconsistentProjector,
    expected_code: str,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    rule = CelRule(finding.rule_id, "f.projection.complete", rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate(
        [rule],
        CelMode.ENFORCE,
        projector=projector,  # type: ignore[arg-type]
        runtime_factory=_runtime_factory(runtime),
    )

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert telemetry.errors[0]["code"] == expected_code


@pytest.mark.parametrize(
    ("facts_factory", "expected_code"),
    [
        (lambda _candidate: None, "PROJECTION_TYPE_ERROR"),
        (
            lambda _candidate: scan_facts_pb2.ScanFacts(
                schema_version="v1",
                projection=scan_facts_pb2.ProjectionStatus(complete=True),
            ),
            "CANDIDATE_RULE_MISMATCH",
        ),
        (
            lambda candidate: scan_facts_pb2.ScanFacts(
                schema_version="v1",
                skill=scan_facts_pb2.SkillFacts(name="x" * (2 * 1_024 * 1_024)),
                candidate=scan_facts_pb2.CandidateFacts(rule_id=candidate.rule_id),
                projection=scan_facts_pb2.ProjectionStatus(complete=True),
            ),
            "ACTIVATION_SIZE_LIMIT",
        ),
    ],
)
def test_malformed_or_suppression_unsafe_activation_fails_open(
    make_skill: Any,
    facts_factory: Callable[[Finding], object],
    expected_code: str,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()

    class BoundaryProjector:
        def prepare(self, _skill: Skill, _findings: list[Finding]) -> object:
            return object()

        def project_candidate(self, _prepared: object, candidate: Finding) -> object:
            return facts_factory(candidate)

    rule = CelRule(finding.rule_id, "f.projection.complete", rollout=CelRollout.ENFORCE)
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(False, 1.0)})
    gate = CelGate(
        [rule],
        CelMode.ENFORCE,
        projector=BoundaryProjector(),  # type: ignore[arg-type]
        runtime_factory=_runtime_factory(runtime),
    )

    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert runtime.calls == []
    assert telemetry.fallbacks == 1
    assert telemetry.errors[0]["code"] == expected_code


def test_off_mode_authoritatively_validates_without_evaluating_or_mutating_findings(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    original_metadata = {
        key: dict(value) if isinstance(value, dict) else value for key, value in finding.metadata.items()
    }
    rule = CelRule(finding.rule_id, "f.candidate.file.executable")

    validations: list[list[CelRule]] = []

    class ValidationRuntime:
        runtime_name = "test-runtime"
        version = "test-version"

        def close(self) -> None:
            return None

    def validation_runtime(rules: list[CelRule]) -> Any:
        validations.append(rules)
        return ValidationRuntime()

    gate = CelGate([rule], CelMode.OFF, runtime_factory=validation_runtime)
    retained, telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert finding.metadata == original_metadata
    assert telemetry.to_dict() == {
        "mode": "off",
        "runtime": "test-runtime",
        "runtime_version": "test-version",
        "fact_schema": "v1",
        "expression_set_hash": gate.expression_set_hash,
        "evaluated": 0,
        "retained": 1,
        "would_suppress": 0,
        "suppressed": 0,
        "fallbacks": 0,
        "projection_incomplete": 0,
        "elapsed_ms": 0.0,
        "projection_ms": 0.0,
        "evaluation_ms": 0.0,
        "errors": [],
        "per_rule": {},
        "suppressed_candidates": [],
    }
    assert validations == [[rule]]


def test_nonmatching_findings_bypass_runtime_but_count_as_retained(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    matching = _finding("MATCHING")
    other = _finding("OTHER")
    rule = CelRule("MATCHING", "f.candidate.file.executable")
    runtime = _RuntimePlan({"MATCHING": RuntimeEvaluation(True, 0.1)})
    gate = CelGate([rule], CelMode.SHADOW, runtime_factory=_runtime_factory(runtime))

    retained, telemetry = gate.apply(skill, [other, matching])

    assert retained == [other, matching]
    assert runtime.calls == ["MATCHING"]
    assert telemetry.evaluated == 1
    assert telemetry.retained == 2
    assert "cel" not in other.metadata


def test_nonmatching_findings_do_not_build_package_projection(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    projector = _CountingProjector()
    runtime = _RuntimePlan({"MATCHING": RuntimeEvaluation(True, 0.1)})
    gate = CelGate(
        [CelRule("MATCHING", "f.projection.complete")],
        CelMode.SHADOW,
        projector=projector,
        runtime_factory=_runtime_factory(runtime),
    )

    retained, telemetry = gate.apply(skill, [_finding("OTHER")])

    assert [finding.rule_id for finding in retained] == ["OTHER"]
    assert telemetry.retained == 1
    assert projector.prepare_calls == 0
    assert projector.candidate_calls == 0


def test_gate_fails_open_on_unexpected_runtime_exception_and_non_boolean(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    first = _finding("RAISES")
    second = _finding("NON_BOOL")

    class BrokenRuntime:
        version = "test-runtime"
        expression_set_hash = "test-hash"

        def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
            if rule_id == "RAISES":
                raise RuntimeError("unexpected adapter failure")
            return RuntimeEvaluation("truthy", 0.2)  # type: ignore[arg-type]

    gate = CelGate(
        [
            CelRule("RAISES", "f.projection.complete", rollout=CelRollout.ENFORCE),
            CelRule("NON_BOOL", "f.projection.complete", rollout=CelRollout.ENFORCE),
        ],
        CelMode.ENFORCE,
        runtime_factory=lambda _rules: BrokenRuntime(),
    )

    retained, telemetry = gate.apply(skill, [first, second])

    assert retained == [first, second]
    assert telemetry.fallbacks == 2
    assert telemetry.suppressed == 0
    assert {error["code"] for error in telemetry.errors} == {
        "EVALUATION_ERROR",
        "NON_BOOLEAN_RESULT",
    }


def test_annotation_replaces_malformed_preexisting_cel_metadata(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    finding = _finding()
    finding.metadata["cel"] = "untrusted analyzer value"
    rule = CelRule(finding.rule_id, "f.projection.complete")
    runtime = _RuntimePlan({finding.rule_id: RuntimeEvaluation(True, 0.1)})
    gate = CelGate([rule], CelMode.SHADOW, runtime_factory=_runtime_factory(runtime))

    retained, _telemetry = gate.apply(skill, [finding])

    assert retained == [finding]
    assert finding.metadata["cel"]["decision"] == "keep"


class _CountingProjector(ScanFactProjector):
    def __init__(self) -> None:
        super().__init__()
        self.prepare_calls = 0
        self.candidate_calls = 0

    def prepare(
        self,
        skill: Skill,
        findings: Iterable[Finding],
        *,
        required_paths: Iterable[str] | None = None,
    ) -> PreparedScanFacts:
        self.prepare_calls += 1
        return super().prepare(skill, findings, required_paths=required_paths)

    def project_candidate(self, prepared: PreparedScanFacts, candidate: Finding) -> scan_facts_pb2.ScanFacts:
        self.candidate_calls += 1
        return super().project_candidate(prepared, candidate)


def test_gate_prepares_package_facts_once_and_times_the_whole_layer(
    make_skill: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    first = _finding("FIRST")
    second = _finding("SECOND")
    rules = [
        CelRule("FIRST", "f.candidate.file.hidden"),
        CelRule("SECOND", "f.candidate.file.executable"),
    ]
    runtime = _RuntimePlan(
        {
            "FIRST": RuntimeEvaluation(True, 5.0),
            "SECOND": RuntimeEvaluation(True, 7.0),
        }
    )
    projector = _CountingProjector()
    ticks = iter([0.0, 0.1, 0.3, 0.4, 0.7, 0.7, 0.8, 1.2, 1.2, 2.0])
    monkeypatch.setattr("skill_scanner.core.cel.gate.time.perf_counter", lambda: next(ticks))
    gate = CelGate(
        rules,
        CelMode.SHADOW,
        projector=projector,
        runtime_factory=_runtime_factory(runtime),
    )

    retained, telemetry = gate.apply(skill, [first, second])

    assert retained == [first, second]
    assert projector.prepare_calls == 1
    assert projector.candidate_calls == 2
    assert telemetry.elapsed_ms == pytest.approx(2_000.0)
    assert telemetry.projection_ms == pytest.approx(600.0)
    assert telemetry.evaluation_ms == pytest.approx(12.0)
    assert telemetry.to_dict()["projection_ms"] == 600.0
    assert telemetry.to_dict()["evaluation_ms"] == 12.0


def test_batch_gate_evaluates_identical_typed_activations_once(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    findings = [_finding("RULE"), _finding("RULE")]

    class _BatchRuntime:
        version = "batch-test"
        runtime_name = "batch-test"
        max_batch_items = 4096
        fact_access_paths = {
            "RULE": ("candidate.context_kind", "candidate.evidence_kind"),
        }

        def __init__(self) -> None:
            self.calls: list[list[tuple[str, scan_facts_pb2.ScanFacts]]] = []

        def evaluate(self, _rule_id: str, _facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
            raise AssertionError("batch runtime should not use scalar evaluation")

        def evaluate_batch(
            self,
            evaluations: list[tuple[str, scan_facts_pb2.ScanFacts]],
        ) -> list[RuntimeEvaluation]:
            self.calls.append(evaluations)
            return [RuntimeEvaluation(True, 1.0) for _ in evaluations]

    runtime = _BatchRuntime()
    gate = CelGate(
        [CelRule("RULE", 'f.candidate.context_kind == "code"')],
        CelMode.SHADOW,
        runtime_factory=lambda _rules: runtime,
    )

    retained, telemetry = gate.apply(skill, findings)

    assert retained == findings
    assert [len(call) for call in runtime.calls] == [1]
    assert telemetry.evaluated == 2
    assert telemetry.evaluation_ms == 1.0
    assert telemetry.fallbacks == 0


def test_projection_scalar_cache_key_preserves_types_and_bounds() -> None:
    frozen = [_freeze_projection_scalar(value) for value in (None, False, 0, "0")]

    assert len(set(frozen)) == 4
    assert _freeze_projection_scalar("x" * 4_097) is _UNKEYABLE
    assert _freeze_projection_scalar("é" * 2_049) is _UNKEYABLE
    assert _freeze_projection_scalar([]) is _UNKEYABLE

    paths = ("candidate.context_kind", "candidate.evidence_count", "candidate.evidence_kind")
    keys = []
    for value in (None, False, 0, "0"):
        finding = _finding("RULE")
        finding.metadata["semantic_facts"]["evidence_count"] = value
        keys.append(_candidate_projection_cache_key(finding, paths))
    assert None not in keys
    assert len(set(keys)) == 4

    oversized = _finding("RULE")
    oversized.metadata["semantic_facts"]["context_kind"] = "x" * 4_097
    assert _candidate_projection_cache_key(oversized, paths) is None
    nonscalar = _finding("RULE")
    nonscalar.metadata["semantic_facts"]["evidence_count"] = []
    assert _candidate_projection_cache_key(nonscalar, paths) is None


def test_projection_cache_rebuilds_a_mismatched_selector_plan() -> None:
    old_paths = ("candidate.context_kind", "candidate.evidence_kind")
    new_paths = (*old_paths, "candidate.evidence_value_class")
    stale_plan = _projection_key_plan(old_paths)
    first = _finding("RULE")
    second = _finding("RULE")
    first.metadata["semantic_facts"]["evidence_value_class"] = "execution_action_term"
    second.metadata["semantic_facts"]["evidence_value_class"] = "regional_indicator_payload"

    first_key = _candidate_projection_cache_key(first, new_paths, plan=stale_plan)
    second_key = _candidate_projection_cache_key(second, new_paths, plan=stale_plan)

    assert first_key is not None
    assert second_key is not None
    assert first_key != second_key


def test_cached_scalar_projection_matches_uncached_facts_and_decisions(
    make_skill: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\nexit 0\n"})
    source_findings = [_finding("RULE"), _finding("RULE")]

    class _CaptureBatchRuntime:
        version = "cache-equivalence-test"
        runtime_name = "cache-equivalence-test"
        max_batch_items = 4_096
        fact_access_paths = {
            "RULE": ("candidate.context_kind", "candidate.evidence_kind"),
        }

        def __init__(self) -> None:
            self.activations: list[bytes] = []

        def evaluate(self, _rule_id: str, _facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
            raise AssertionError("cache equivalence must use the batch adapter")

        def evaluate_batch(
            self,
            evaluations: list[tuple[str, scan_facts_pb2.ScanFacts]],
        ) -> list[RuntimeEvaluation]:
            self.activations.extend(facts.SerializeToString(deterministic=True) for _rule_id, facts in evaluations)
            return [RuntimeEvaluation(True, 0.01) for _rule_id, _facts in evaluations]

    rule = CelRule("RULE", 'f.candidate.context_kind == "code"')
    cached_runtime = _CaptureBatchRuntime()
    cached_findings = copy.deepcopy(source_findings)
    cached_retained, cached_telemetry = CelGate(
        [rule],
        CelMode.SHADOW,
        runtime_factory=lambda _rules: cached_runtime,
    ).apply(skill, cached_findings)

    monkeypatch.setattr(
        "skill_scanner.core.cel.gate._candidate_projection_cache_key",
        lambda _finding, _paths, *, plan=None: None,
    )
    uncached_runtime = _CaptureBatchRuntime()
    uncached_findings = copy.deepcopy(source_findings)
    uncached_retained, uncached_telemetry = CelGate(
        [rule],
        CelMode.SHADOW,
        runtime_factory=lambda _rules: uncached_runtime,
    ).apply(skill, uncached_findings)

    assert cached_retained == cached_findings
    assert uncached_retained == uncached_findings
    assert cached_runtime.activations == uncached_runtime.activations
    assert len(cached_runtime.activations) == 1
    assert (
        cached_telemetry.evaluated,
        cached_telemetry.retained,
        cached_telemetry.would_suppress,
        cached_telemetry.suppressed,
        cached_telemetry.fallbacks,
    ) == (
        uncached_telemetry.evaluated,
        uncached_telemetry.retained,
        uncached_telemetry.would_suppress,
        uncached_telemetry.suppressed,
        uncached_telemetry.fallbacks,
    )


def test_expression_set_hash_is_stable_across_rule_order_and_sensitive_to_content() -> None:
    first = CelRule("A", "f.candidate.file.hidden")
    second = CelRule("B", "f.candidate.file.executable")

    factory = lambda _rules: _RuntimePlan({})
    hash_ab = CelGate([first, second], CelMode.OFF, runtime_factory=factory).expression_set_hash
    hash_ba = CelGate([second, first], CelMode.OFF, runtime_factory=factory).expression_set_hash
    changed = CelGate(
        [first, CelRule("B", "!f.candidate.file.executable")],
        CelMode.OFF,
        runtime_factory=factory,
    ).expression_set_hash

    assert hash_ab == hash_ba
    assert hash_ab != changed
    assert len(hash_ab) == 64

    assert hash_ab == expression_set_hash([first, second])
    assert hash_ab != expression_set_hash([CelRule("A", first.expression, fact_schema="v2"), second])


def test_duplicate_rule_ids_fail_before_runtime_construction() -> None:
    duplicate = [
        CelRule("DUP", "f.candidate.file.hidden"),
        CelRule("DUP", "f.candidate.file.executable"),
    ]
    with pytest.raises(ValueError, match="duplicate CEL rule IDs"):
        CelGate(duplicate, CelMode.OFF)


def test_gate_rule_generation_is_immutable() -> None:
    gate = CelGate(
        [CelRule("RULE", "f.projection.complete")],
        CelMode.OFF,
        runtime_factory=lambda _rules: _RuntimePlan({}),
    )

    assert isinstance(gate.rules, MappingProxyType)
    with pytest.raises(TypeError):
        gate.rules["RULE"] = CelRule("RULE", "!f.projection.complete")  # type: ignore[index]


def test_off_mode_still_validates_rule_types_and_fact_schema() -> None:
    with pytest.raises(CelValidationError, match="undefined protobuf field"):
        CelGate([CelRule("BAD_PATH", "f.candidate.missing == true")], CelMode.OFF)

    with pytest.raises(ValueError, match="unsupported CEL fact schema"):
        CelGate(
            [CelRule("BAD_SCHEMA", "f.projection.complete", fact_schema="v2")],
            CelMode.OFF,
        )
