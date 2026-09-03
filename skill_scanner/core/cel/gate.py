# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Fail-open CEL decision gate over concrete deterministic findings."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from ..models import Finding, Skill
from ..semantic import scan_facts_pb2
from ..semantic.projector import ScanFactProjector
from ..semantic.vocabulary import classification_values
from .go_runtime import CEL_GO_VERSION, CelGoRuntime, validate_cel_go_generation
from .models import CelMode, CelRollout, CelRule, CelTelemetry, expression_set_hash
from .runtime import RuntimeEvaluation
from .validator import validate_cel_expression

_FACT_PATH_RE = re.compile(r"\bf((?:\.[A-Za-z_][A-Za-z0-9_]*)+)\b")
_COMPREHENSION_RE = re.compile(
    r"\bf\.skill\.(files|commands|urls|flows|reference_edges|signals)\.(?:exists|all)"
    r"\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
)
_CANDIDATE_SCALAR_METADATA = {
    "candidate.evidence_kind": "evidence_kind",
    "candidate.context_kind": "context_kind",
    "candidate.evidence_value_class": "evidence_value_class",
    "candidate.evidence_count": "evidence_count",
}
_CANDIDATE_MESSAGE_METADATA = {
    "candidate.command": "candidate_command",
    "candidate.url": "candidate_url",
    "candidate.flow": "candidate_flow",
}
_SKILL_SEMANTIC_METADATA = {
    "skill.commands": "commands",
    "skill.urls": "urls",
    "skill.flows": "flows",
    "skill.reference_edges": "reference_edges",
    "skill.signals": "signals",
}
_UNKEYABLE = object()


class _CelRuntime(Protocol):
    version: str

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation: ...


@dataclass(frozen=True)
class _PendingEvaluation:
    index: int
    finding: Finding
    rule: CelRule
    facts: scan_facts_pb2.ScanFacts
    activation_key: tuple[object, ...] | None = None


@dataclass(frozen=True)
class _ProjectionKeyPlan:
    """Precomputed selectors for the bounded candidate projection key."""

    paths: tuple[str, ...]
    nested_metadata_keys: tuple[str, ...]
    reads_evidence_value_class: bool
    reads_magic_signals: bool
    reads_line: bool


class CelGate:
    """Apply immutable, precompiled CEL rules to matching candidates."""

    def __init__(
        self,
        rules: list[CelRule],
        mode: CelMode | str,
        *,
        projector: ScanFactProjector | None = None,
        runtime_factory: Callable[[list[CelRule]], _CelRuntime] | None = None,
    ) -> None:
        uses_default_runtime = runtime_factory is None
        if runtime_factory is None:

            def default_factory(generation: list[CelRule]) -> _CelRuntime:
                return CelGoRuntime(generation)

            factory: Callable[[list[CelRule]], _CelRuntime] = default_factory
        else:
            factory = runtime_factory
        self.mode = CelMode(mode)
        for rule in rules:
            if rule.fact_schema != "v1":
                raise ValueError(f"unsupported CEL fact schema {rule.fact_schema!r} for rule {rule.rule_id!r}")
            validate_cel_expression(rule.expression)
        rules_by_id = {rule.rule_id: rule for rule in rules}
        if len(rules_by_id) != len(rules):
            raise ValueError("duplicate CEL rule IDs")
        self.rules = MappingProxyType(rules_by_id)
        self.projector = projector or ScanFactProjector()
        self.runtime: _CelRuntime | None = None
        self.validated_runtime_name = ""
        self.validated_runtime_version = ""
        self._fact_access_paths: Mapping[str, tuple[str, ...]] = MappingProxyType({})
        self._projection_key_plans: Mapping[str, _ProjectionKeyPlan] = MappingProxyType({})

        self.expression_set_hash = expression_set_hash(rules)

        if self.mode is CelMode.OFF and rules:
            if uses_default_runtime:
                self.validated_runtime_name = CelGoRuntime.runtime_name
                self.validated_runtime_version = validate_cel_go_generation(rules)
            else:
                validator_runtime = factory(rules)
                self.validated_runtime_name = str(getattr(validator_runtime, "runtime_name", "custom"))
                self.validated_runtime_version = str(getattr(validator_runtime, "version", "unknown"))
                close = getattr(validator_runtime, "close", None)
                if callable(close):
                    close()
        elif self.mode is not CelMode.OFF and rules:
            self.runtime = factory(rules)
            self.validated_runtime_name = str(getattr(self.runtime, "runtime_name", "custom"))
            self.validated_runtime_version = str(getattr(self.runtime, "version", CEL_GO_VERSION))
            compiled_paths = getattr(self.runtime, "fact_access_paths", None)
            if isinstance(compiled_paths, Mapping):
                self._fact_access_paths = MappingProxyType(
                    {rule_id: tuple(paths) for rule_id, paths in compiled_paths.items()}
                )
            elif uses_default_runtime:
                self.close()
                raise ValueError("cel-go runtime did not return compiler-derived fact-access paths")
            self._projection_key_plans = MappingProxyType(
                {rule_id: _projection_key_plan(paths) for rule_id, paths in self._fact_access_paths.items()}
            )

    def apply(self, skill: Skill, findings: list[Finding]) -> tuple[list[Finding], CelTelemetry]:
        telemetry = CelTelemetry(mode=self.mode, expression_set_hash=self.expression_set_hash)
        if self.runtime is not None:
            telemetry.runtime = str(getattr(self.runtime, "runtime_name", "unknown"))
            telemetry.runtime_version = str(getattr(self.runtime, "version", "unknown"))
        elif self.validated_runtime_name:
            telemetry.runtime = self.validated_runtime_name
            telemetry.runtime_version = self.validated_runtime_version

        if self.mode is CelMode.OFF or not self.rules:
            telemetry.retained = len(findings)
            return findings, telemetry

        # A package with no candidate for any CEL-gated rule does not need a
        # potentially expensive package projection.
        if not any(finding.rule_id in self.rules for finding in findings):
            telemetry.retained = len(findings)
            return findings, telemetry

        layer_started = time.perf_counter()
        retained_by_index: dict[int, Finding] = {}
        pending: list[_PendingEvaluation] = []
        projection_started = time.perf_counter()
        try:
            selected_paths = {
                path
                for finding in findings
                if finding.rule_id in self.rules
                for path in self._fact_access_paths.get(finding.rule_id, ())
            }
            # Only the built-in projector advertises this keyword contract.
            # Preserve compatibility with small custom/fake projectors whose
            # two-argument prepare method predates checked-AST access masks.
            if self.projector.__class__.prepare is ScanFactProjector.prepare and selected_paths:
                prepared = self.projector.prepare(skill, findings, required_paths=selected_paths)
            else:
                prepared = self.projector.prepare(skill, findings)
        except Exception:
            telemetry.projection_ms = (time.perf_counter() - projection_started) * 1_000
            for finding in findings:
                rule = self.rules.get(finding.rule_id)
                if rule is not None:
                    telemetry.fallbacks += 1
                    telemetry.projection_incomplete += 1
                    telemetry.record_error(finding.rule_id, "PROJECTION_ERROR")
                    telemetry.record_decision(rule, "fallback")
                    self._annotate(finding, rule, "fallback", "PROJECTION_ERROR")
            telemetry.retained = len(findings)
            telemetry.elapsed_ms = (time.perf_counter() - layer_started) * 1_000
            return findings, telemetry
        telemetry.projection_ms += (time.perf_counter() - projection_started) * 1_000
        projection_cache: dict[
            tuple[object, ...],
            tuple[scan_facts_pb2.ScanFacts, tuple[str, ...]],
        ] = {}
        for index, finding in enumerate(findings):
            rule = self.rules.get(finding.rule_id)
            if rule is None:
                retained_by_index[index] = finding
                telemetry.retained += 1
                continue

            projection_started = time.perf_counter()
            try:
                required_paths = self._fact_access_paths.get(rule.rule_id)
                masked_project = getattr(self.projector, "project_candidate_for_paths", None)
                cache_key: tuple[object, ...] | None = None
                if required_paths is not None and callable(masked_project):
                    cache_key = _candidate_projection_cache_key(
                        finding,
                        required_paths,
                        plan=self._projection_key_plans.get(rule.rule_id),
                    )
                    cached = projection_cache.get(cache_key) if cache_key is not None else None
                    if cached is None:
                        facts = masked_project(prepared, finding, required_paths)
                        projection_errors = self._projection_error_codes(
                            facts,
                            finding,
                            rule,
                            required_paths,
                        )
                        if cache_key is not None:
                            projection_cache[cache_key] = (facts, tuple(projection_errors))
                    else:
                        facts, cached_errors = cached
                        projection_errors = list(cached_errors)
                else:
                    facts = self.projector.project_candidate(prepared, finding)
                    projection_errors = self._projection_error_codes(
                        facts,
                        finding,
                        rule,
                        required_paths,
                    )
            except Exception:
                telemetry.projection_ms += (time.perf_counter() - projection_started) * 1_000
                retained_by_index[index] = finding
                telemetry.retained += 1
                telemetry.fallbacks += 1
                telemetry.projection_incomplete += 1
                telemetry.record_error(finding.rule_id, "PROJECTION_ERROR")
                telemetry.record_decision(rule, "fallback")
                self._annotate(finding, rule, "fallback", "PROJECTION_ERROR")
                continue
            telemetry.projection_ms += (time.perf_counter() - projection_started) * 1_000
            if projection_errors:
                retained_by_index[index] = finding
                telemetry.retained += 1
                telemetry.fallbacks += 1
                telemetry.projection_incomplete += 1
                codes = projection_errors or ["PROJECTION_INCOMPLETE"]
                for code in codes:
                    telemetry.record_error(finding.rule_id, code)
                telemetry.record_decision(rule, "fallback")
                self._annotate(finding, rule, "fallback", codes[0])
                continue

            pending.append(_PendingEvaluation(index, finding, rule, facts, cache_key))

        for item, result in zip(pending, self._evaluate_pending(pending), strict=True):
            finding = item.finding
            rule = item.rule
            telemetry.evaluated += 1
            telemetry.evaluation_ms += result.elapsed_ms
            if not isinstance(result.value, bool):
                error_code = result.error_code or "NON_BOOLEAN_RESULT"
                retained_by_index[item.index] = finding
                telemetry.retained += 1
                telemetry.fallbacks += 1
                telemetry.record_error(finding.rule_id, error_code)
                telemetry.record_decision(rule, "fallback")
                self._annotate(finding, rule, "fallback", error_code)
                continue

            if result.value:
                retained_by_index[item.index] = finding
                telemetry.retained += 1
                telemetry.record_decision(rule, "keep")
                self._annotate(finding, rule, "keep", "expression_true")
                continue

            telemetry.would_suppress += 1
            telemetry.record_decision(rule, "would_suppress")
            should_suppress = self.mode is CelMode.ENFORCE and rule.rollout is CelRollout.ENFORCE
            if should_suppress:
                telemetry.record_suppressed_candidate(
                    rule,
                    category=finding.category.value,
                    severity=finding.severity.value,
                    analyzer=finding.analyzer or "unknown",
                )
                telemetry.suppressed += 1
                telemetry.record_decision(rule, "suppressed")
                continue
            retained_by_index[item.index] = finding
            telemetry.retained += 1
            self._annotate(finding, rule, "would_suppress", "shadow_or_rule_rollout")

        telemetry.elapsed_ms = (time.perf_counter() - layer_started) * 1_000
        retained = [retained_by_index[index] for index in range(len(findings)) if index in retained_by_index]
        return retained, telemetry

    def _evaluate_pending(self, pending: list[_PendingEvaluation]) -> list[RuntimeEvaluation]:
        """Evaluate a bounded candidate batch, failing open as one unit."""

        if not pending:
            return []
        assert self.runtime is not None
        batch_evaluate = getattr(self.runtime, "evaluate_batch", None)
        if not callable(batch_evaluate):
            results: list[RuntimeEvaluation] = []
            for item in pending:
                started = time.perf_counter()
                try:
                    results.append(self.runtime.evaluate(item.finding.rule_id, item.facts))
                except Exception:
                    results.append(
                        RuntimeEvaluation(
                            None,
                            (time.perf_counter() - started) * 1_000,
                            "EVALUATION_ERROR",
                        )
                    )
            return results

        # CEL is pure and the masked typed activation is the complete input.
        # Broad extractors can produce thousands of candidates whose relevant
        # normalized facts are byte-identical; evaluate each unique activation
        # once and fan the immutable decision back out in input order.
        unique: list[_PendingEvaluation] = []
        unique_by_activation: dict[tuple[object, ...], int] = {}
        expanded_indexes: list[int] = []
        first_use: set[int] = set()
        for item in pending:
            if item.activation_key is not None:
                key: tuple[object, ...] = (
                    "projected",
                    item.finding.rule_id,
                    item.activation_key,
                )
            else:
                activation = item.facts.SerializeToString(deterministic=True)
                key = ("serialized", item.finding.rule_id, activation)
            unique_index = unique_by_activation.get(key)
            if unique_index is None:
                unique_index = len(unique)
                unique_by_activation[key] = unique_index
                unique.append(item)
            expanded_indexes.append(unique_index)

        max_batch_items = getattr(self.runtime, "max_batch_items", 1)
        if isinstance(max_batch_items, bool) or not isinstance(max_batch_items, int) or max_batch_items <= 0:
            max_batch_items = 1
        unique_results: list[RuntimeEvaluation] = []
        for start in range(0, len(unique), max_batch_items):
            chunk = unique[start : start + max_batch_items]
            started = time.perf_counter()
            try:
                chunk_results = batch_evaluate([(item.finding.rule_id, item.facts) for item in chunk])
                if not isinstance(chunk_results, list) or len(chunk_results) != len(chunk):
                    raise ValueError("CEL batch result cardinality mismatch")
                if any(not isinstance(result, RuntimeEvaluation) for result in chunk_results):
                    raise TypeError("CEL batch returned an invalid result")
            except Exception:
                elapsed_each = (time.perf_counter() - started) * 1_000 / len(chunk)
                chunk_results = [RuntimeEvaluation(None, elapsed_each, "EVALUATION_ERROR") for _ in chunk]
            unique_results.extend(chunk_results)

        results = []
        for unique_index in expanded_indexes:
            result = unique_results[unique_index]
            if unique_index in first_use:
                results.append(RuntimeEvaluation(result.value, 0.0, result.error_code))
            else:
                first_use.add(unique_index)
                results.append(result)
        return results

    def close(self) -> None:
        """Release the persistent runtime helper, when active."""

        if self.runtime is None:
            return
        close = getattr(self.runtime, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> CelGate:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    @staticmethod
    def _projection_error_codes(
        facts: object,
        finding: Finding,
        rule: CelRule,
        required_paths: Iterable[str] | None = None,
    ) -> list[str]:
        """Validate suppression-critical activation invariants.

        The projector is trusted scanner code, but this boundary remains
        fail-open so a projector regression cannot evaluate a rule against the
        wrong candidate, schema, or an activation above the documented cap.
        """

        if not isinstance(facts, scan_facts_pb2.ScanFacts):
            return ["PROJECTION_TYPE_ERROR"]

        codes: list[str] = []
        if facts.schema_version != rule.fact_schema:
            codes.append("FACT_SCHEMA_MISMATCH")
        codes.extend(str(code) for code in facts.projection.error_codes if code)
        if facts.candidate.rule_id != finding.rule_id:
            codes.append("CANDIDATE_RULE_MISMATCH")
        if facts.ByteSize() > 2 * 1_024 * 1_024:
            codes.append("ACTIVATION_SIZE_LIMIT")
        if not codes and _missing_required_structured_fact(
            rule.expression,
            facts,
            finding,
            required_paths=required_paths,
        ):
            codes.append("MISSING_STRUCTURED_METADATA")
        # ``truncated`` is an independent, suppression-critical signal. Keep
        # the existing stable projector error codes when present, and use the
        # established generic incomplete code only for an inconsistent status.
        if (facts.projection.truncated or not facts.projection.complete) and not codes:
            codes.append("PROJECTION_INCOMPLETE")

        # Preserve first-seen diagnostic order while avoiding duplicate error
        # telemetry when both the projector and boundary detect the same cap.
        return list(dict.fromkeys(codes))

    @staticmethod
    def _annotate(finding: Finding, rule: CelRule, decision: str, reason: str) -> None:
        existing = finding.metadata.get("cel")
        annotation = existing if isinstance(existing, dict) else {}
        annotation.update(
            {
                "decision": decision,
                "reason": reason,
                "fact_schema": rule.fact_schema,
                "expression_hash": rule.expression_hash,
                "pack": rule.pack_name,
                "rollout": rule.rollout.value,
            }
        )
        finding.metadata["cel"] = annotation


def _candidate_projection_cache_key(
    finding: Finding,
    required_paths: Iterable[str],
    *,
    plan: _ProjectionKeyPlan | None = None,
) -> tuple[object, ...] | None:
    """Return a bounded key for byte-identical masked candidate projections.

    Only fields consumed by ``project_candidate_for_paths`` participate. Any
    malformed, oversized, or exotic Python value disables caching for that
    candidate so the normal projector remains the authoritative fail-open
    validator.
    """

    # cel-go returns one immutable, sorted tuple per rule.  Preserve that tuple
    # rather than rebuilding a set and sorting it for every broad-extractor
    # candidate.  Non-runtime callers still receive a canonical path tuple.
    paths = required_paths if isinstance(required_paths, tuple) else tuple(sorted(set(required_paths)))
    selectors = plan if plan is not None and plan.paths == paths else _projection_key_plan(paths)
    metadata = finding.metadata if isinstance(finding.metadata, dict) else None
    semantic = metadata.get("semantic_facts") if metadata is not None else None
    if not isinstance(semantic, dict):
        return None

    selected: list[tuple[str, object]] = [
        ("evidence_kind", semantic.get("evidence_kind")),
        ("context_kind", semantic.get("context_kind")),
        ("evidence_count", semantic.get("evidence_count", 0)),
    ]
    if selectors.reads_evidence_value_class:
        selected.append(("evidence_value_class", semantic.get("evidence_value_class")))
    for metadata_key in selectors.nested_metadata_keys:
        selected.append((metadata_key, semantic.get(metadata_key)))
    if selectors.reads_magic_signals:
        selected.append(("signals", semantic.get("signals", [])))

    if not selectors.nested_metadata_keys and not selectors.reads_magic_signals:
        # The high-volume built-in gates read only bounded scalar
        # classifications.  Freezing a temporary mapping recursively for each
        # candidate dominated their projection cost, even though there are
        # usually only a handful of distinct normalized activations.  Preserve
        # the same type-tagged key semantics with a direct bounded scalar path.
        frozen_items: list[tuple[str, object]] = []
        for name, value in selected:
            frozen_value = _freeze_projection_scalar(value)
            if frozen_value is _UNKEYABLE:
                return None
            frozen_items.append((name, frozen_value))
        frozen: object = ("mapping", tuple(frozen_items))
    else:
        frozen = _freeze_projection_key(dict(selected), budget=[256], depth=0)
        if frozen is _UNKEYABLE:
            return None
    line = finding.line_number if selectors.reads_line else None
    return (
        finding.rule_id,
        finding.analyzer,
        finding.category.value,
        finding.severity.value,
        finding.file_path,
        line,
        paths,
        frozen,
    )


def _projection_key_plan(paths: tuple[str, ...]) -> _ProjectionKeyPlan:
    """Compile repeated path-prefix checks once per immutable CEL rule."""

    nested_metadata_keys = tuple(
        metadata_key
        for prefix, metadata_key in _CANDIDATE_MESSAGE_METADATA.items()
        if any(path == prefix or path.startswith(prefix + ".") for path in paths)
    )
    return _ProjectionKeyPlan(
        paths=paths,
        nested_metadata_keys=nested_metadata_keys,
        reads_evidence_value_class="candidate.evidence_value_class" in paths,
        reads_magic_signals="candidate.file.magic_mismatch" in paths,
        reads_line="candidate.line" in paths,
    )


def _freeze_projection_scalar(value: object) -> object:
    """Freeze one bounded scalar using the recursive key's exact type tags."""

    if value is None or isinstance(value, bool | int):
        return (type(value).__name__, value)
    if isinstance(value, str):
        # Normalized classifications are tiny ASCII tokens.  Avoid allocating
        # an encoded copy on that hot path while retaining the exact UTF-8
        # byte bound for longer or non-ASCII values.
        if len(value) <= 256 and value.isascii():
            return ("str", value)
        if len(value.encode("utf-8")) <= 4 * 1_024:
            return ("str", value)
    return _UNKEYABLE


def _freeze_projection_key(value: object, *, budget: list[int], depth: int) -> object:
    """Freeze a small JSON-like structure without traversing unbounded input."""

    if depth > 8 or budget[0] <= 0:
        return _UNKEYABLE
    budget[0] -= 1
    if value is None or isinstance(value, bool | int):
        return (type(value).__name__, value)
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 4 * 1_024:
            return _UNKEYABLE
        return ("str", value)
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            return _UNKEYABLE
        frozen_items = tuple(_freeze_projection_key(item, budget=budget, depth=depth + 1) for item in value)
        return _UNKEYABLE if _UNKEYABLE in frozen_items else ("sequence", frozen_items)
    if isinstance(value, dict):
        if len(value) > 64 or any(not isinstance(key, str) for key in value):
            return _UNKEYABLE
        mapping_items: list[tuple[str, object]] = []
        for key in sorted(value):
            frozen = _freeze_projection_key(value[key], budget=budget, depth=depth + 1)
            if frozen is _UNKEYABLE:
                return _UNKEYABLE
            mapping_items.append((key, frozen))
        return ("mapping", tuple(mapping_items))
    return _UNKEYABLE


def _missing_required_structured_fact(
    expression: str,
    facts: scan_facts_pb2.ScanFacts,
    finding: Finding,
    *,
    required_paths: Iterable[str] | None = None,
) -> bool:
    """Reject protobuf defaults when a rule reads an optional analyzer fact.

    The expression subset has no dynamic indexing or construction, so direct
    ``f`` selections are sufficient to derive this conservative contract.
    Expressions may still use presence guards; treating absence as incomplete
    is intentionally fail-open and therefore cannot remove a finding.
    """

    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    semantic = metadata.get("semantic_facts")
    if not isinstance(semantic, dict):
        return True
    if required_paths is None:
        paths = {match.group(1).lstrip(".") for match in _FACT_PATH_RE.finditer(expression)}
        # This branch supports small fake runtimes in unit tests. Production
        # cel-go supplies an alias-aware map from its checked AST.
        for comprehension in _COMPREHENSION_RE.finditer(expression):
            collection, alias = comprehension.groups()
            for match in re.finditer(
                rf"\b{re.escape(alias)}\.([A-Za-z_][A-Za-z0-9_]*)\b",
                expression,
            ):
                paths.add(f"skill.{collection}.{match.group(1)}")
    else:
        paths = set(required_paths)

    for path_prefix, metadata_key in _CANDIDATE_SCALAR_METADATA.items():
        if any(path == path_prefix or path.startswith(path_prefix + ".") for path in paths):
            if metadata_key not in semantic:
                return True
            value = semantic[metadata_key]
            if isinstance(value, str) and value in {"", "unknown"}:
                return True
            leaf = path_prefix.rsplit(".", 1)[-1]
            if not _classification_value_allowed("candidate", leaf, value):
                return True

    for path_prefix, metadata_key in _CANDIDATE_MESSAGE_METADATA.items():
        if any(path == path_prefix or path.startswith(path_prefix + ".") for path in paths):
            protobuf_field = path_prefix.rsplit(".", 1)[-1]
            nested = semantic.get(metadata_key)
            if not isinstance(nested, dict) or not facts.candidate.HasField(protobuf_field):
                return True
            for path in paths:
                if not path.startswith(path_prefix + "."):
                    continue
                leaf = path.removeprefix(path_prefix + ".").split(".", 1)[0]
                if leaf not in nested:
                    return True
                value = nested[leaf]
                if isinstance(value, str) and value in {"", "unknown"}:
                    return True
                if leaf in {"source_class", "sink_class"} and value in {"", "none"}:
                    return True
                if not _classification_value_allowed(protobuf_field, leaf, value):
                    return True

    if any(path == "candidate.file" or path.startswith("candidate.file.") for path in paths):
        if not facts.candidate.HasField("file"):
            return True
        for path in paths:
            if not path.startswith("candidate.file."):
                continue
            leaf = path.removeprefix("candidate.file.").split(".", 1)[0]
            if leaf not in facts.candidate.file.DESCRIPTOR.fields_by_name:
                return True
            value = getattr(facts.candidate.file, leaf)
            if isinstance(value, str) and value in {"", "unknown"}:
                return True
            if not _classification_value_allowed("file", leaf, value):
                return True

    for path_prefix, metadata_key in _SKILL_SEMANTIC_METADATA.items():
        if not any(path == path_prefix or path.startswith(path_prefix + ".") for path in paths):
            continue
        protobuf_field = path_prefix.rsplit(".", 1)[-1]
        items = getattr(facts.skill, protobuf_field)
        # Package facts are contributed by every deterministic finding, not
        # necessarily by the gated candidate.  The projector validates each
        # contributing structure; an empty aggregate remains fail-open because
        # it cannot distinguish true absence from unavailable analyzer facts.
        if not items:
            return True

        leaves = {
            path.removeprefix(path_prefix + ".").split(".", 1)[0]
            for path in paths
            if path.startswith(path_prefix + ".")
        }
        for item in items:
            descriptor_fields = item.DESCRIPTOR.fields_by_name
            for leaf in leaves:
                if leaf not in descriptor_fields:
                    return True
                value = getattr(item, leaf)
                if isinstance(value, str) and value in {"", "unknown"}:
                    return True
                if leaf in {"source_class", "sink_class"} and value == "none":
                    return True
                if not _classification_value_allowed(protobuf_field, leaf, value):
                    return True

    file_paths = {
        path.removeprefix("skill.files.").split(".", 1)[0] for path in paths if path.startswith("skill.files.")
    }
    for item in facts.skill.files:
        for leaf in file_paths:
            if leaf not in item.DESCRIPTOR.fields_by_name:
                return True
            value = getattr(item, leaf)
            if isinstance(value, str) and value in {"", "unknown"}:
                return True
            if not _classification_value_allowed("files", leaf, value):
                return True

    return False


def _classification_value_allowed(container: str, leaf: str, value: object) -> bool:
    """Validate only closed, normalized classification leaves read by CEL."""

    allowed = classification_values(container, leaf)
    if allowed is None:
        # Paths, hostnames, executable/tool names, counts, and Booleans are
        # intentionally open normalized fields and are bounded by projector.
        return True
    if isinstance(value, str):
        return value.lower() in allowed
    if isinstance(value, str | bytes):
        return False
    if hasattr(value, "__iter__"):
        return all(isinstance(item, str) and item.lower() in allowed for item in value)
    return False
