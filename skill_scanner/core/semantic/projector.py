# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Bounded projection from scanner models into the CEL protobuf contract.

The projector intentionally consumes analyzer-produced structured metadata.  It
never reparses finding snippets or package source text, which keeps policy
evaluation separate from detection and avoids placing secrets in CEL inputs.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from google.protobuf.descriptor import FieldDescriptor

from ..models import Finding, Skill, SkillFile
from . import scan_facts_pb2
from .vocabulary import (
    ARGUMENT_CLASSES,
    CONTEXT_KINDS,
    DIRECTIONS,
    DOMAIN_CLASSES,
    EVIDENCE_KINDS,
    EVIDENCE_VALUE_CLASSES,
    HTTP_METHODS,
    REFERENCE_KINDS,
    SIGNAL_KINDS,
    SIGNAL_VALUE_CLASSES,
    SOURCE_SINK_CLASSES,
    TRANSFORMS,
)

FACT_SCHEMA_VERSION = "v1"

# These stable projection errors mean a hard projector bound shortened or
# omitted typed facts. Other projection errors are incomplete, but not
# truncated (for example malformed or missing analyzer metadata).
_TRUNCATION_ERROR_CODES = frozenset(
    {
        "ACTIVATION_SIZE_LIMIT",
        "CANDIDATE_EVIDENCE_COUNT_LIMIT",
        "FILE_FACT_LIMIT",
        "REPEATED_FIELD_LIMIT",
        "SEMANTIC_FACT_LIMIT",
        "STRING_SIZE_LIMIT",
    }
)


@dataclass(frozen=True)
class FactLimits:
    """Hard limits for one CEL activation."""

    max_files: int = 1_024
    max_semantic_items: int = 4_096
    max_repeated_items: int = 4_096
    max_string_bytes: int = 4 * 1_024
    max_activation_bytes: int = 2 * 1_024 * 1_024


@dataclass(frozen=True)
class PreparedScanFacts:
    """Package-level facts cached once for every CEL-gated candidate."""

    base: scan_facts_pb2.ScanFacts
    file_by_path: dict[str, scan_facts_pb2.FileFact]
    rules_by_path: dict[str, tuple[str, ...]]
    skill_error_codes_by_field: dict[str, tuple[str, ...]] = field(default_factory=dict)
    file_error_codes_by_path: dict[str, tuple[str, ...]] = field(default_factory=dict)
    reference_error_codes: tuple[str, ...] = ()
    cooccurrence_error_codes_by_path: dict[str, tuple[str, ...]] = field(default_factory=dict)
    masked_bases: dict[tuple[str, ...], scan_facts_pb2.ScanFacts] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )


class ScanFactProjector:
    """Create one bounded :class:`ScanFacts` activation per finding."""

    def __init__(self, limits: FactLimits | None = None) -> None:
        self.limits = limits or FactLimits()

    def project(self, skill: Skill, candidate: Finding, findings: Iterable[Finding]) -> scan_facts_pb2.ScanFacts:
        prepared = self.prepare(skill, findings)
        return self.project_candidate(prepared, candidate)

    def prepare(
        self,
        skill: Skill,
        findings: Iterable[Finding],
        *,
        required_paths: Iterable[str] | None = None,
    ) -> PreparedScanFacts:
        """Project invariant package/context facts once per scan.

        When cel-go supplies a checked-AST access mask, package collections
        outside that mask are neither materialized nor allowed to contaminate
        the activation's completeness. Candidate-local fields are populated
        later by :meth:`project_candidate_for_paths`.
        """

        errors: set[str] = set()
        facts = scan_facts_pb2.ScanFacts(schema_version=FACT_SCHEMA_VERSION)
        facts.projection.complete = True
        selected_paths = None if required_paths is None else tuple(sorted(set(required_paths)))
        selected_skill_fields: set[str] | None
        if selected_paths is None or "skill" in selected_paths:
            selected_skill_fields = None
        else:
            selected_skill_fields = {
                path.split(".", 2)[1]
                for path in selected_paths
                if path.startswith("skill.") and len(path.split(".", 2)) >= 2
            }

        def include_skill(field_name: str) -> bool:
            return selected_skill_fields is None or field_name in selected_skill_fields

        reads_candidate_file = selected_paths is None or any(
            path == "candidate.file" or path.startswith("candidate.file.") for path in selected_paths
        )
        reads_cooccurrence = selected_paths is None or "candidate.cooccurring_rule_ids" in selected_paths

        skill_errors: dict[str, set[str]] = {
            name: set()
            for name in (
                "name",
                "has_description",
                "declared_tools",
                "declares_network",
                "file_count",
                "total_bytes",
                "files",
                "commands",
                "urls",
                "flows",
                "reference_edges",
                "signals",
            )
        }
        if include_skill("name"):
            facts.skill.name = self._text(skill.name, skill_errors["name"])
        manifest_complete = bool(getattr(skill, "manifest_complete", True))
        if not manifest_complete:
            # Synthetic values keep content analyzers operational but are not
            # authoritative absence/allowance facts.  Mark every activation
            # incomplete so CEL fails open rather than suppressing a finding
            # based on an invalid manifest.
            for field_name in ("has_description", "declared_tools", "declares_network"):
                skill_errors[field_name].add("MANIFEST_METADATA_INCOMPLETE")
        if include_skill("has_description"):
            facts.skill.has_description = manifest_complete and bool(skill.description)
        declared_tools = (
            skill.manifest.allowed_tools if manifest_complete and isinstance(skill.manifest.allowed_tools, list) else []
        )
        if include_skill("declared_tools"):
            facts.skill.declared_tools.extend(self._texts(declared_tools, skill_errors["declared_tools"]))
        if include_skill("declares_network"):
            facts.skill.declares_network = manifest_complete and self._manifest_declares_network(skill)
        if include_skill("file_count"):
            facts.skill.file_count = min(len(skill.files), 2**32 - 1)
        if include_skill("total_bytes"):
            facts.skill.total_bytes = min(sum(max(0, f.size_bytes) for f in skill.files), 2**64 - 1)

        reference_errors: set[str] = set()
        referenced = {self._normalise_path(path, reference_errors) for path in skill.referenced_files}
        referenced.discard("")
        file_by_path: dict[str, scan_facts_pb2.FileFact] = {}
        file_errors_by_path: dict[str, set[str]] = {}
        project_files = include_skill("files") or reads_candidate_file
        for index, skill_file in enumerate(skill.files if project_files else ()):
            if index >= self.limits.max_files:
                skill_errors["files"].add("FILE_FACT_LIMIT")
                break
            file_errors: set[str] = set()
            file_fact = self._file_fact(skill_file, referenced, file_errors)
            if include_skill("files"):
                facts.skill.files.add().CopyFrom(file_fact)
            if file_fact.path in file_by_path:
                file_errors.add("DUPLICATE_NORMALIZED_PATH")
            file_by_path[file_fact.path] = file_fact
            file_errors_by_path.setdefault(file_fact.path, set()).update(file_errors)
            skill_errors["files"].update(file_errors)

        for index, target in enumerate(sorted(referenced) if include_skill("reference_edges") else ()):
            if index >= self.limits.max_semantic_items:
                skill_errors["reference_edges"].add("SEMANTIC_FACT_LIMIT")
                break
            edge = facts.skill.reference_edges.add()
            edge.source_path = "SKILL.md"
            edge.target_path = self._text(target, skill_errors["reference_edges"])
            edge.kind = "instruction_reference"

        all_findings = list(findings)
        semantic_fields = (
            None
            if selected_skill_fields is None
            else selected_skill_fields & {"commands", "urls", "flows", "reference_edges", "signals"}
        )
        self._populate_structured_facts(
            facts,
            all_findings,
            skill_errors,
            selected_fields=semantic_fields,
        )

        rules_by_path_mutable: dict[str, set[str]] = {}
        cooccurrence_errors: dict[str, set[str]] = {}
        for finding in all_findings if reads_cooccurrence else ():
            path_errors: set[str] = set()
            path = self._normalise_path(finding.file_path or "", path_errors)
            errors.update(path_errors)
            # An empty path is not a shared location.  Grouping every pathless
            # finding into the same bucket would manufacture package-wide
            # "same file" co-occurrence that analyzers never reported.
            if not path:
                continue
            bucket = rules_by_path_mutable.setdefault(path, set())
            if len(bucket) < self.limits.max_repeated_items:
                bucket.add(finding.rule_id)
            else:
                errors.add("REPEATED_FIELD_LIMIT")
                cooccurrence_errors.setdefault(path, set()).add("REPEATED_FIELD_LIMIT")

        for field_errors in skill_errors.values():
            errors.update(field_errors)
        errors.update(reference_errors)

        self._finalise(facts, errors)
        return PreparedScanFacts(
            base=facts,
            file_by_path=file_by_path,
            rules_by_path={path: tuple(sorted(values)) for path, values in rules_by_path_mutable.items()},
            skill_error_codes_by_field={name: tuple(sorted(values)) for name, values in skill_errors.items() if values},
            file_error_codes_by_path={
                path: tuple(sorted(values)) for path, values in file_errors_by_path.items() if values
            },
            reference_error_codes=tuple(sorted(reference_errors)),
            cooccurrence_error_codes_by_path={
                path: tuple(sorted(values)) for path, values in cooccurrence_errors.items() if values
            },
        )

    def project_candidate(self, prepared: PreparedScanFacts, candidate: Finding) -> scan_facts_pb2.ScanFacts:
        """Add candidate-specific facts to a cached package projection."""

        return self._project_candidate_from_base(prepared, candidate, prepared.base)

    def project_candidate_for_paths(
        self,
        prepared: PreparedScanFacts,
        candidate: Finding,
        required_paths: Iterable[str],
    ) -> scan_facts_pb2.ScanFacts:
        """Project only package fields referenced by one checked CEL rule.

        The cel-go compiler provides the authoritative access paths.  Caching
        this bounded base per path set avoids copying and serializing thousands
        of unrelated package signals for candidate-only gates while retaining
        the same fail-open projection status and candidate validation.
        """

        key = tuple(sorted(set(required_paths)))
        base = prepared.masked_bases.get(key)
        if base is None:
            base = self._masked_base(prepared, key)
            prepared.masked_bases[key] = base
        return self._project_candidate_from_base(prepared, candidate, base, required_paths=key)

    def _project_candidate_from_base(
        self,
        prepared: PreparedScanFacts,
        candidate: Finding,
        base: scan_facts_pb2.ScanFacts,
        *,
        required_paths: tuple[str, ...] | None = None,
    ) -> scan_facts_pb2.ScanFacts:
        """Add candidate-specific facts to a selected immutable package base."""

        facts = scan_facts_pb2.ScanFacts()
        facts.CopyFrom(base)
        errors = set(facts.projection.error_codes)
        path = self._normalise_path(candidate.file_path or "", errors)
        same_path_rules = (
            [rule_id for rule_id in prepared.rules_by_path.get(path, ()) if rule_id != candidate.rule_id]
            if path
            else []
        )
        if required_paths is None:
            self._populate_candidate(facts, candidate, prepared.file_by_path, same_path_rules, errors)
        else:
            self._populate_candidate_for_paths(
                facts,
                candidate,
                prepared.file_by_path,
                same_path_rules,
                required_paths,
                errors,
            )
            required = set(required_paths)
            if any(value == "candidate.file" or value.startswith("candidate.file.") for value in required):
                errors.update(prepared.file_error_codes_by_path.get(path, ()))
                if "candidate.file.referenced" in required:
                    errors.update(prepared.reference_error_codes)
            if "candidate.cooccurring_rule_ids" in required:
                errors.update(prepared.cooccurrence_error_codes_by_path.get(path, ()))
        self._finalise(facts, errors)
        return facts

    def _masked_base(
        self,
        prepared: PreparedScanFacts,
        required_paths: tuple[str, ...],
    ) -> scan_facts_pb2.ScanFacts:
        """Return a package base containing only compiler-referenced fields."""

        base = prepared.base
        masked = scan_facts_pb2.ScanFacts(schema_version=base.schema_version)
        masked.projection.complete = True
        # The helper requires each top-level typed message to be present even
        # when an expression does not read any of its fields.
        masked.skill.SetInParent()

        if "skill" in required_paths:
            masked.skill.CopyFrom(base.skill)
            selected_errors = {code for values in prepared.skill_error_codes_by_field.values() for code in values}
            selected_errors.update(prepared.reference_error_codes)
        else:
            top_level_fields = {
                path.split(".", 2)[1]
                for path in required_paths
                if path.startswith("skill.") and len(path.split(".", 2)) >= 2
            }
            for name in sorted(top_level_fields):
                descriptor = base.skill.DESCRIPTOR.fields_by_name.get(name)
                if descriptor is None:
                    # Compiler-derived paths are checked against the canonical
                    # descriptor, so this is defensive and fail-open.
                    masked.projection.complete = False
                    if "INVALID_STRUCTURED_METADATA" not in masked.projection.error_codes:
                        masked.projection.error_codes.append("INVALID_STRUCTURED_METADATA")
                    continue
                source = getattr(base.skill, name)
                target = getattr(masked.skill, name)
                if descriptor.label == FieldDescriptor.LABEL_REPEATED:
                    target.extend(source)
                elif descriptor.message_type is not None:
                    target.CopyFrom(source)
                else:
                    setattr(masked.skill, name, source)
            selected_errors = {
                code for name in top_level_fields for code in prepared.skill_error_codes_by_field.get(name, ())
            }
            if "reference_edges" in top_level_fields or any(
                path == "skill.files.referenced" or path.startswith("skill.files.referenced.")
                for path in required_paths
            ):
                selected_errors.update(prepared.reference_error_codes)

        self._finalise(masked, selected_errors)
        return masked

    def _populate_candidate_for_paths(
        self,
        facts: scan_facts_pb2.ScanFacts,
        finding: Finding,
        file_by_path: dict[str, scan_facts_pb2.FileFact],
        same_path_rules: list[str],
        required_paths: tuple[str, ...],
        errors: set[str],
    ) -> None:
        """Populate the identity plus compiler-referenced candidate fields."""

        paths = set(required_paths)

        def reads(prefix: str) -> bool:
            return any(path == prefix or path.startswith(prefix + ".") for path in paths)

        candidate = facts.candidate
        candidate.rule_id = self._text(finding.rule_id, errors)
        if reads("candidate.analyzer"):
            candidate.analyzer = self._text(finding.analyzer or "unknown", errors)
        if reads("candidate.category"):
            candidate.category = self._text(finding.category.value, errors)
        if reads("candidate.severity"):
            candidate.severity = self._text(finding.severity.value, errors)

        candidate_path = self._normalise_path(finding.file_path or "", errors)
        if reads("candidate.file_path") or reads("candidate.file"):
            candidate.file_path = self._text(candidate_path, errors)
        if reads("candidate.line"):
            candidate.line = max(0, min(finding.line_number or 0, 2**32 - 1))

        # Every gated candidate retains the base structured-evidence contract,
        # even when a particular expression reads only one of these fields.
        semantic = self._semantic_metadata(finding, errors, required=True)
        self._require_structured_keys(semantic, {"evidence_kind", "context_kind"}, errors)
        candidate.evidence_kind = self._classification(
            semantic.get("evidence_kind"), EVIDENCE_KINDS, errors, required=False
        )
        candidate.context_kind = self._classification(
            semantic.get("context_kind"), CONTEXT_KINDS, errors, required=False
        )
        if reads("candidate.evidence_value_class"):
            candidate.evidence_value_class = self._classification(
                semantic.get("evidence_value_class"),
                EVIDENCE_VALUE_CLASSES,
                errors,
                required=False,
            )
        evidence_count = semantic.get("evidence_count", 0)
        if isinstance(evidence_count, bool) or not isinstance(evidence_count, int) or evidence_count < 0:
            errors.add("INVALID_STRUCTURED_METADATA")
        elif evidence_count > self.limits.max_repeated_items:
            candidate.evidence_count = self.limits.max_repeated_items
            errors.add("CANDIDATE_EVIDENCE_COUNT_LIMIT")
        else:
            candidate.evidence_count = evidence_count

        if reads("candidate.cooccurring_rule_ids"):
            candidate.cooccurring_rule_ids.extend(self._texts(same_path_rules, errors))
        if reads("candidate.file"):
            file_fact = file_by_path.get(candidate_path)
            if file_fact is not None:
                candidate.file.CopyFrom(file_fact)
            if reads("candidate.file.magic_mismatch") and candidate.HasField("file"):
                signals = semantic.get("signals", [])
                if isinstance(signals, list):
                    candidate.file.magic_mismatch = any(
                        isinstance(signal, dict) and signal.get("kind") == "file_magic_mismatch" for signal in signals
                    )
                elif signals is not None:
                    errors.add("INVALID_STRUCTURED_METADATA")

        for prefix, metadata_key, destination, builder, masked_builder in (
            (
                "candidate.command",
                "candidate_command",
                candidate.command,
                self._command_fact,
                self._command_fact_for_leaves,
            ),
            (
                "candidate.url",
                "candidate_url",
                candidate.url,
                self._url_fact,
                self._url_fact_for_leaves,
            ),
            (
                "candidate.flow",
                "candidate_flow",
                candidate.flow,
                self._flow_fact,
                self._flow_fact_for_leaves,
            ),
        ):
            if not reads(prefix):
                continue
            value = semantic.get(metadata_key)
            if isinstance(value, dict):
                if prefix in paths:
                    destination.CopyFrom(builder(value, errors))
                else:
                    leaves = {
                        path.removeprefix(prefix + ".").split(".", 1)[0]
                        for path in paths
                        if path.startswith(prefix + ".")
                    }
                    destination.CopyFrom(masked_builder(value, leaves, errors))
            elif value is not None:
                errors.add("INVALID_STRUCTURED_METADATA")

    def _command_fact_for_leaves(
        self,
        value: dict[str, Any],
        leaves: set[str],
        errors: set[str],
    ) -> scan_facts_pb2.CommandFact:
        """Project only checked-AST-selected command fields."""

        self._require_structured_keys(value, leaves, errors)
        fact = scan_facts_pb2.CommandFact()
        if "executable" in leaves:
            fact.executable = self._text(value.get("executable", ""), errors)
        if "argument_classes" in leaves:
            fact.argument_classes.extend(
                self._classifications(value.get("argument_classes", []), ARGUMENT_CLASSES, errors)
            )
        for leaf in ("downloads", "executes", "destructive", "privilege_change"):
            if leaf in leaves:
                setattr(fact, leaf, self._structured_bool(value, leaf, errors))
        if "source_class" in leaves:
            fact.source_class = self._classification(
                value.get("source_class"),
                SOURCE_SINK_CLASSES,
                errors,
                required=False,
                empty_value="none",
            )
        if "sink_class" in leaves:
            fact.sink_class = self._classification(
                value.get("sink_class"),
                SOURCE_SINK_CLASSES,
                errors,
                required=False,
                empty_value="none",
            )
        if "file_path" in leaves:
            fact.file_path = self._text(self._normalise_path(value.get("file_path", ""), errors), errors)
        return fact

    def _url_fact_for_leaves(
        self,
        value: dict[str, Any],
        leaves: set[str],
        errors: set[str],
    ) -> scan_facts_pb2.UrlFact:
        """Project only checked-AST-selected URL fields."""

        self._require_structured_keys(value, leaves, errors)
        fact = scan_facts_pb2.UrlFact()
        for leaf in ("scheme", "host"):
            if leaf in leaves:
                setattr(fact, leaf, self._text(value.get(leaf, ""), errors))
        if "domain_class" in leaves:
            fact.domain_class = self._classification(value.get("domain_class"), DOMAIN_CLASSES, errors, required=False)
        if "trusted_installer" in leaves:
            fact.trusted_installer = self._structured_bool(value, "trusted_installer", errors)
        if "method" in leaves:
            fact.method = self._classification(value.get("method"), HTTP_METHODS, errors, required=False)
        if "direction" in leaves:
            fact.direction = self._classification(value.get("direction"), DIRECTIONS, errors, required=False)
        if "file_path" in leaves:
            fact.file_path = self._text(self._normalise_path(value.get("file_path", ""), errors), errors)
        return fact

    def _flow_fact_for_leaves(
        self,
        value: dict[str, Any],
        leaves: set[str],
        errors: set[str],
    ) -> scan_facts_pb2.FlowFact:
        """Project only checked-AST-selected flow fields."""

        self._require_structured_keys(value, leaves, errors)
        fact = scan_facts_pb2.FlowFact()
        for leaf in ("source_class", "sink_class"):
            if leaf in leaves:
                setattr(
                    fact,
                    leaf,
                    self._classification(
                        value.get(leaf),
                        SOURCE_SINK_CLASSES,
                        errors,
                        required=False,
                        empty_value="none",
                    ),
                )
        if "transforms" in leaves:
            fact.transforms.extend(self._classifications(value.get("transforms", []), TRANSFORMS, errors))
        if "cross_file" in leaves:
            fact.cross_file = self._structured_bool(value, "cross_file", errors)
        for leaf in ("source_path", "sink_path"):
            if leaf in leaves:
                setattr(fact, leaf, self._text(self._normalise_path(value.get(leaf, ""), errors), errors))
        return fact

    def _finalise(self, facts: scan_facts_pb2.ScanFacts, errors: set[str]) -> None:
        del facts.projection.error_codes[:]

        # A malformed supplied structure is the more precise diagnosis.  Do
        # not also report fields missing *within* that malformed value; both
        # are fail-open, and one canonical code keeps telemetry deterministic.
        if "INVALID_STRUCTURED_METADATA" in errors:
            errors.discard("MISSING_STRUCTURED_METADATA")

        facts.projection.truncated = bool(errors & _TRUNCATION_ERROR_CODES)
        if errors:
            facts.projection.complete = False
            facts.projection.error_codes.extend(sorted(errors))
        else:
            facts.projection.complete = True

        serialized_size = self._set_final_serialized_size(facts)
        if serialized_size > self.limits.max_activation_bytes:
            facts.projection.complete = False
            facts.projection.truncated = True
            if "ACTIVATION_SIZE_LIMIT" not in facts.projection.error_codes:
                facts.projection.error_codes.append("ACTIVATION_SIZE_LIMIT")
            self._set_final_serialized_size(facts)

    @staticmethod
    def _set_final_serialized_size(facts: scan_facts_pb2.ScanFacts) -> int:
        """Set the self-describing byte count until protobuf varint size stabilises."""

        for _ in range(8):
            size = int(facts.ByteSize())
            if facts.projection.serialized_bytes == size:
                return size
            facts.projection.serialized_bytes = size
        # A uint64 varint can cross only finitely many width boundaries; this
        # final assignment is defensive for unusual protobuf implementations.
        size = int(facts.ByteSize())
        facts.projection.serialized_bytes = size
        return int(facts.ByteSize())

    def _populate_candidate(
        self,
        facts: scan_facts_pb2.ScanFacts,
        finding: Finding,
        file_by_path: dict[str, scan_facts_pb2.FileFact],
        same_path_rules: list[str],
        errors: set[str],
    ) -> None:
        candidate = facts.candidate
        candidate.rule_id = self._text(finding.rule_id, errors)
        candidate.analyzer = self._text(finding.analyzer or "unknown", errors)
        candidate.category = self._text(finding.category.value, errors)
        candidate.severity = self._text(finding.severity.value, errors)
        candidate.file_path = self._text(self._normalise_path(finding.file_path or "", errors), errors)
        candidate.line = max(0, min(finding.line_number or 0, 2**32 - 1))

        # A CEL-gated candidate must carry analyzer-produced structured facts.
        # Falling back to protobuf scalar defaults here could turn an absent
        # classification into a false expression and suppress the finding.
        semantic = self._semantic_metadata(finding, errors, required=True)
        self._require_structured_keys(semantic, {"evidence_kind", "context_kind"}, errors)
        candidate.evidence_kind = self._classification(
            semantic.get("evidence_kind"), EVIDENCE_KINDS, errors, required=False
        )
        candidate.evidence_value_class = self._classification(
            semantic.get("evidence_value_class"),
            EVIDENCE_VALUE_CLASSES,
            errors,
            required=False,
        )
        evidence_count = semantic.get("evidence_count", 0)
        if isinstance(evidence_count, bool) or not isinstance(evidence_count, int) or evidence_count < 0:
            errors.add("INVALID_STRUCTURED_METADATA")
        elif evidence_count > self.limits.max_repeated_items:
            candidate.evidence_count = self.limits.max_repeated_items
            errors.add("CANDIDATE_EVIDENCE_COUNT_LIMIT")
        else:
            candidate.evidence_count = evidence_count
        candidate.context_kind = self._classification(
            semantic.get("context_kind"), CONTEXT_KINDS, errors, required=False
        )
        candidate.cooccurring_rule_ids.extend(self._texts(same_path_rules, errors))

        if candidate.file_path and candidate.file_path in file_by_path:
            candidate.file.CopyFrom(file_by_path[candidate.file_path])
        signals = semantic.get("signals", [])
        if isinstance(signals, list):
            magic_mismatch = False
            for signal in signals:
                if not isinstance(signal, dict):
                    errors.add("INVALID_STRUCTURED_METADATA")
                    continue
                magic_mismatch = magic_mismatch or signal.get("kind") == "file_magic_mismatch"
            # Merely accessing/assigning a field on a protobuf submessage can
            # mark it present.  Preserve `has(f.candidate.file) == false` when
            # the package projection has no matching file fact.
            if magic_mismatch and candidate.HasField("file"):
                candidate.file.magic_mismatch = True
        elif signals is not None:
            errors.add("INVALID_STRUCTURED_METADATA")
        self._copy_structured_candidate(candidate, semantic, errors)

    def _populate_structured_facts(
        self,
        facts: scan_facts_pb2.ScanFacts,
        findings: list[Finding],
        errors_by_field: dict[str, set[str]],
        *,
        selected_fields: set[str] | None = None,
    ) -> None:
        count = len(facts.skill.reference_edges)
        seen: set[tuple[str, str]] = set()
        semantic_fields = ("commands", "urls", "flows", "reference_edges", "signals")

        for finding in findings:
            signal_errors = errors_by_field["signals"]
            signal_key = (finding.rule_id, finding.file_path or "")
            if (selected_fields is None or "signals" in selected_fields) and signal_key not in seen:
                if count >= self.limits.max_semantic_items:
                    for field_name in semantic_fields:
                        errors_by_field[field_name].add("SEMANTIC_FACT_LIMIT")
                    return
                seen.add(signal_key)
                signal = facts.skill.signals.add()
                signal.rule_id = self._text(finding.rule_id, signal_errors)
                signal.kind = self._classification(
                    self._semantic_metadata(finding, signal_errors).get("signal_kind", "finding"),
                    SIGNAL_KINDS,
                    signal_errors,
                )
                signal.file_path = self._text(
                    self._normalise_path(finding.file_path or "", signal_errors), signal_errors
                )
                signal.value_class = self._classification(
                    finding.category.value,
                    SIGNAL_VALUE_CLASSES,
                    signal_errors,
                )
                count += 1

            for key, destination, builder in (
                ("commands", facts.skill.commands, self._command_fact),
                ("urls", facts.skill.urls, self._url_fact),
                ("flows", facts.skill.flows, self._flow_fact),
                ("reference_edges", facts.skill.reference_edges, self._reference_edge),
                ("signals", facts.skill.signals, self._signal_fact),
            ):
                if selected_fields is not None and key not in selected_fields:
                    continue
                field_errors = errors_by_field[key]
                semantic = self._semantic_metadata(finding, field_errors)
                values = semantic.get(key, [])
                if not isinstance(values, list):
                    field_errors.add("INVALID_STRUCTURED_METADATA")
                    continue
                for value in values:
                    if count >= self.limits.max_semantic_items:
                        for field_name in semantic_fields:
                            errors_by_field[field_name].add("SEMANTIC_FACT_LIMIT")
                        return
                    if not isinstance(value, dict):
                        field_errors.add("INVALID_STRUCTURED_METADATA")
                        continue
                    destination.add().CopyFrom(builder(value, field_errors))
                    count += 1

    def _copy_structured_candidate(
        self, candidate: scan_facts_pb2.CandidateFacts, semantic: dict[str, Any], errors: set[str]
    ) -> None:
        value = semantic.get("candidate_command")
        if isinstance(value, dict):
            candidate.command.CopyFrom(self._command_fact(value, errors))
        elif value is not None:
            errors.add("INVALID_STRUCTURED_METADATA")
        value = semantic.get("candidate_url")
        if isinstance(value, dict):
            candidate.url.CopyFrom(self._url_fact(value, errors))
        elif value is not None:
            errors.add("INVALID_STRUCTURED_METADATA")
        value = semantic.get("candidate_flow")
        if isinstance(value, dict):
            candidate.flow.CopyFrom(self._flow_fact(value, errors))
        elif value is not None:
            errors.add("INVALID_STRUCTURED_METADATA")

    @staticmethod
    def _semantic_metadata(
        finding: Finding,
        errors: set[str] | None = None,
        *,
        required: bool = False,
    ) -> dict[str, Any]:
        # Treat runtime input as untrusted even though the model annotation is
        # a dict; callers may deserialize malformed external finding data.
        metadata: object = finding.metadata
        if not isinstance(metadata, dict):
            if errors is not None:
                errors.add("INVALID_STRUCTURED_METADATA")
            return {}
        if "semantic_facts" not in metadata:
            if required and errors is not None:
                errors.add("MISSING_STRUCTURED_METADATA")
            return {}
        value = metadata["semantic_facts"]
        if isinstance(value, dict):
            return value
        if errors is not None:
            errors.add("INVALID_STRUCTURED_METADATA")
        return {}

    def _file_fact(self, skill_file: SkillFile, referenced: set[str], errors: set[str]) -> scan_facts_pb2.FileFact:
        path = self._normalise_path(skill_file.relative_path, errors)
        executable = False
        try:
            executable = bool(skill_file.path.stat().st_mode & 0o111)
        except OSError:
            errors.add("FILE_STAT_ERROR")
        suffix = PurePosixPath(path).suffix.lower()
        return scan_facts_pb2.FileFact(
            path=self._text(path, errors),
            extension=self._text(suffix, errors),
            kind=self._text(skill_file.file_type or "unknown", errors),
            role=self._text(self._file_role(path), errors),
            size_bytes=max(0, min(skill_file.size_bytes, 2**64 - 1)),
            hidden=skill_file.is_hidden,
            executable=executable,
            referenced=path in referenced or Path(path).name == "SKILL.md",
            analyzable=skill_file.file_type not in {"binary", "unknown"},
            archive_depth=max(0, min(skill_file.archive_depth, 2**32 - 1)),
        )

    def _command_fact(self, value: dict[str, Any], errors: set[str]) -> scan_facts_pb2.CommandFact:
        self._require_structured_keys(
            value,
            {
                "executable",
                "argument_classes",
                "downloads",
                "executes",
                "destructive",
                "privilege_change",
                "source_class",
                "sink_class",
                "file_path",
            },
            errors,
        )
        return scan_facts_pb2.CommandFact(
            executable=self._text(value.get("executable", ""), errors),
            argument_classes=self._classifications(value.get("argument_classes", []), ARGUMENT_CLASSES, errors),
            downloads=self._structured_bool(value, "downloads", errors),
            executes=self._structured_bool(value, "executes", errors),
            destructive=self._structured_bool(value, "destructive", errors),
            privilege_change=self._structured_bool(value, "privilege_change", errors),
            source_class=self._classification(
                value.get("source_class"),
                SOURCE_SINK_CLASSES,
                errors,
                required=False,
                empty_value="none",
            ),
            sink_class=self._classification(
                value.get("sink_class"),
                SOURCE_SINK_CLASSES,
                errors,
                required=False,
                empty_value="none",
            ),
            file_path=self._text(self._normalise_path(value.get("file_path", ""), errors), errors),
        )

    def _url_fact(self, value: dict[str, Any], errors: set[str]) -> scan_facts_pb2.UrlFact:
        self._require_structured_keys(
            value,
            {"scheme", "host", "domain_class", "trusted_installer", "method", "direction", "file_path"},
            errors,
        )
        return scan_facts_pb2.UrlFact(
            scheme=self._text(value.get("scheme", ""), errors),
            host=self._text(value.get("host", ""), errors),
            domain_class=self._classification(value.get("domain_class"), DOMAIN_CLASSES, errors, required=False),
            trusted_installer=self._structured_bool(value, "trusted_installer", errors),
            method=self._classification(value.get("method"), HTTP_METHODS, errors, required=False),
            direction=self._classification(value.get("direction"), DIRECTIONS, errors, required=False),
            file_path=self._text(self._normalise_path(value.get("file_path", ""), errors), errors),
        )

    def _flow_fact(self, value: dict[str, Any], errors: set[str]) -> scan_facts_pb2.FlowFact:
        self._require_structured_keys(
            value,
            {"source_class", "sink_class", "transforms", "cross_file", "source_path", "sink_path"},
            errors,
        )
        return scan_facts_pb2.FlowFact(
            source_class=self._classification(
                value.get("source_class"),
                SOURCE_SINK_CLASSES,
                errors,
                required=False,
                empty_value="none",
            ),
            sink_class=self._classification(
                value.get("sink_class"),
                SOURCE_SINK_CLASSES,
                errors,
                required=False,
                empty_value="none",
            ),
            transforms=self._classifications(value.get("transforms", []), TRANSFORMS, errors),
            cross_file=self._structured_bool(value, "cross_file", errors),
            source_path=self._text(self._normalise_path(value.get("source_path", ""), errors), errors),
            sink_path=self._text(self._normalise_path(value.get("sink_path", ""), errors), errors),
        )

    def _reference_edge(self, value: dict[str, Any], errors: set[str]) -> scan_facts_pb2.ReferenceEdge:
        self._require_structured_keys(value, {"source_path", "target_path", "kind"}, errors)
        return scan_facts_pb2.ReferenceEdge(
            source_path=self._text(self._normalise_path(value.get("source_path", ""), errors), errors),
            target_path=self._text(self._normalise_path(value.get("target_path", ""), errors), errors),
            kind=self._classification(value.get("kind"), REFERENCE_KINDS, errors, required=False),
        )

    def _signal_fact(self, value: dict[str, Any], errors: set[str]) -> scan_facts_pb2.SignalFact:
        self._require_structured_keys(value, {"rule_id", "kind", "file_path", "value_class"}, errors)
        return scan_facts_pb2.SignalFact(
            rule_id=self._text(value.get("rule_id", ""), errors),
            kind=self._classification(value.get("kind"), SIGNAL_KINDS, errors, required=False),
            file_path=self._text(self._normalise_path(value.get("file_path", ""), errors), errors),
            value_class=self._classification(
                value.get("value_class"),
                SIGNAL_VALUE_CLASSES | EVIDENCE_VALUE_CLASSES,
                errors,
                required=False,
            ),
        )

    def _texts(self, values: Any, errors: set[str]) -> list[str]:
        if not isinstance(values, (list, tuple)):
            if values not in (None, ""):
                errors.add("INVALID_STRUCTURED_METADATA")
            return []
        result: list[str] = []
        for index, value in enumerate(values):
            if index >= self.limits.max_repeated_items:
                errors.add("REPEATED_FIELD_LIMIT")
                break
            result.append(self._text(value, errors))
        return result

    def _classifications(
        self,
        values: Any,
        allowed: frozenset[str],
        errors: set[str],
    ) -> list[str]:
        if not isinstance(values, (list, tuple)):
            errors.add("INVALID_STRUCTURED_METADATA")
            return []
        result: list[str] = []
        for index, value in enumerate(values):
            if index >= self.limits.max_repeated_items:
                errors.add("REPEATED_FIELD_LIMIT")
                break
            result.append(self._classification(value, allowed, errors))
        return result

    @staticmethod
    def _classification(
        value: Any,
        allowed: frozenset[str],
        errors: set[str],
        *,
        required: bool = True,
        empty_value: str | None = None,
    ) -> str:
        if value is None:
            if required:
                errors.add("INVALID_STRUCTURED_METADATA")
            return "unknown"
        if value == "":
            if empty_value is not None:
                return empty_value
            errors.add("INVALID_STRUCTURED_METADATA")
            return "unknown"
        if not isinstance(value, str):
            errors.add("INVALID_STRUCTURED_METADATA")
            return "unknown"
        normalized = value.lower()
        if normalized not in allowed:
            errors.add("INVALID_STRUCTURED_METADATA")
            return "unknown"
        return normalized

    @staticmethod
    def _require_structured_keys(value: dict[str, Any], required: set[str], errors: set[str]) -> None:
        if not required.issubset(value):
            errors.add("MISSING_STRUCTURED_METADATA")

    @staticmethod
    def _structured_bool(value: dict[str, Any], field: str, errors: set[str]) -> bool:
        """Return an analyzer Boolean without Python truthiness coercion.

        Omitted optional Boolean classifications retain the protobuf default.
        If a producer supplies the field, however, only an actual ``bool`` is
        accepted; strings and integers are untrusted structured metadata and
        force the projection to fail open.
        """

        if field not in value:
            return False
        result = value[field]
        if not isinstance(result, bool):
            errors.add("INVALID_STRUCTURED_METADATA")
            return False
        return result

    def _text(self, value: Any, errors: set[str]) -> str:
        if not isinstance(value, str):
            errors.add("INVALID_STRUCTURED_METADATA")
            return ""
        text = value
        encoded = text.encode("utf-8")
        if len(encoded) <= self.limits.max_string_bytes:
            return text
        errors.add("STRING_SIZE_LIMIT")
        return encoded[: self.limits.max_string_bytes].decode("utf-8", errors="ignore")

    @staticmethod
    def _normalise_path(value: Any, errors: set[str] | None = None) -> str:
        if not isinstance(value, (str, os.PathLike)):
            if errors is not None:
                errors.add("INVALID_PATH")
            return ""
        raw = str(value).replace("\\", "/")
        while raw.startswith("./"):
            raw = raw[2:]
        if not raw:
            return ""
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts:
            if errors is not None:
                errors.add("INVALID_PATH")
            return ""
        return path.as_posix()

    @staticmethod
    def _file_role(path: str) -> str:
        lowered = PurePosixPath(path.lower())
        parts = set(lowered.parts)
        if lowered.name == "skill.md":
            return "instruction"
        if parts & {"test", "tests", "examples", "example", "fixtures"}:
            return "test_or_example"
        if "scripts" in parts:
            return "code"
        if parts & {"references", "docs", "documentation"}:
            return "documentation"
        if "assets" in parts:
            return "asset"
        return "package"

    @staticmethod
    def _is_network_tool(tool: str) -> bool:
        lowered = tool.lower()
        return any(token in lowered for token in ("network", "http", "web", "fetch", "curl", "wget"))

    @staticmethod
    def _manifest_declares_network(skill: Skill) -> bool:
        """Normalize both capability text and explicitly allowed network tools."""

        compatibility = skill.manifest.compatibility
        if compatibility:
            lowered = str(compatibility).lower()
            if "network" in lowered or "internet" in lowered:
                return True
        allowed_tools = skill.manifest.allowed_tools
        return isinstance(allowed_tools, list) and any(
            isinstance(tool, str) and ScanFactProjector._is_network_tool(tool) for tool in allowed_tools
        )
