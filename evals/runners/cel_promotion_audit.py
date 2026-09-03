# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Run a leakage-free, non-release CEL shadow promotion audit.

This runner deliberately evaluates only rows that are development data in
*both* MaliciousSkillBench protocols.  A row is eligible when each of
``source_disjoint`` and ``m_structural_disjoint`` is ``train`` or
``validation``.  A test/excluded membership in either protocol excludes the
row, so the audit cannot accidentally tune against either sealed holdout.

The audit is diagnostic and can never stand in for release evidence.  It runs
one CEL-OFF baseline and exactly five independent CEL-SHADOW workers, records
the explicitly required bundled CEL generation (including zero-hit rules), and emits bounded
candidate-incidence and counterfactual final-finding summaries before the
worker reports are compacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

# Permit direct execution from the repository checkout.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.runners.benchmark_comparison import (  # noqa: E402
    BenchmarkComparisonError,
    compare_repeated_benchmark_reports,
)
from evals.runners.loader_fallback import recognize_loader_disposition  # noqa: E402
from evals.runners.public_dataset_benchmark import (  # noqa: E402
    FrozenSample,
    FrozenSnapshot,
    PublicBenchmarkError,
    _default_scanner_factory,
    _empty_counts,
    _evidence_identity,
    _finalize_counts,
    _finding_cel_lineage,
    _finding_metadata,
    _hash_tree,
    _producer_components,
    _record_sample,
    _record_scan_error,
    _severity_name,
    _summary,
    compact_release_report,
    load_frozen_snapshot,
)
from skill_scanner.core.cel.models import CelMode, CelRule  # noqa: E402

SELECTION_POLICY = "joint_train_validation_v1"
AUDIT_PROFILE = "development_promotion_audit"
TRACK_NAME = "core-only-joint-train-validation"
DEFAULT_EXPECTED_RULE_COUNT = 8
REQUIRED_SHADOW_RUNS = 5
_DEVELOPMENT_PARTITIONS = frozenset({"train", "validation"})
_REQUIRED_PROTOCOLS = ("source_disjoint", "m_structural_disjoint")
_BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
_SIGNAL_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_MAX_WORKER_REPORT_BYTES = 32 * 1024 * 1024
_MAX_SUMMARY_BYTES = 2 * 1024 * 1024
_MAX_ATTESTATION_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 128
_SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_WORKER_INVOCATION_RE = re.compile(r"^[0-9a-f]{32}$")
_AUDIT_HARNESS_RELATIVE_PATHS = (
    Path("evals/datasets/public_datasets.py"),
    Path("evals/runners/benchmark_comparison.py"),
    Path("evals/runners/cel_promotion_audit.py"),
    Path("evals/runners/loader_fallback.py"),
    Path("evals/runners/public_dataset_benchmark.py"),
)
_ATTESTATION_PURPOSE = "cel_malicious_blocking_candidate_attestations"
_ATTESTATION_LABEL_SOURCES = frozenset({"independent_ollama", "agent_labeled"})
_ATTESTATION_LABELS = frozenset({"benign_non_actionable", "actionable", "ambiguous", "abstain"})
_ATTESTATION_REASON_CODES = frozenset(
    {
        "benign_prose_term",
        "benign_policy_taxonomy",
        "benign_prohibition",
        "active_privilege_operation",
        "active_egress_operation",
        "insufficient_context",
        "provider_error",
    }
)
_ATTESTATION_REASON_BY_LABEL = {
    "benign_non_actionable": frozenset({"benign_prose_term", "benign_policy_taxonomy", "benign_prohibition"}),
    "actionable": frozenset({"active_privilege_operation", "active_egress_operation"}),
    "ambiguous": frozenset({"insufficient_context"}),
    "abstain": frozenset({"provider_error"}),
}
_ATTESTATION_BINDING_FIELDS = frozenset(
    {
        "dataset_id",
        "dataset_revision",
        "snapshot_sha256",
        "sample_metadata_manifest_sha256",
        "usable_snapshot_sha256",
        "population_sha256",
        "membership_sha256",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
        "source_revision",
        "expression_set_sha256",
        "rule_expression_sha256",
        "candidate_set_sha256",
        "expected_candidate_count",
    }
)
_ATTESTATION_ADJUDICATOR_FIELDS = frozenset(
    {
        "model_name",
        "model_digest",
        "rubric_sha256",
        "prompt_sha256",
        "options_sha256",
        "provenance",
        "provenance_sha256",
        "deterministic_check_sha256",
        "passes",
    }
)
_ATTESTATION_CANDIDATE_FIELDS = frozenset(
    {
        "candidate_identity_sha256",
        "normalized_finding_identity_sha256",
        "sample_id",
        "sample_id_sha256",
        "sample_content_sha256",
        "source_evidence_sha256",
        "rule_id",
        "severity",
        "category",
        "analyzer",
        "file_path_sha256",
        "line_number",
        "evidence_value_class",
        "context_kind",
        "expression_sha256",
        "lineage_identity_sha256",
        "lineage_ordinal",
        "lineage_count",
        "deterministic",
        "passes",
        "accepted_label",
    }
)
_ATTESTATION_CANDIDATE_BINDING_FIELDS = _ATTESTATION_CANDIDATE_FIELDS - {
    "deterministic",
    "passes",
    "accepted_label",
}
_ATTESTATION_SUMMARY_FIELDS = frozenset(
    {
        "candidate_count",
        "per_rule",
        "accepted",
        "actionable",
        "ambiguous",
        "abstained",
        "disagreements",
        "provider_errors",
    }
)


class CelPromotionAuditError(ValueError):
    """Raised when development promotion evidence is incomplete or unsafe."""


class _Scanner(Protocol):
    cel_gate: Any

    def scan_skill(self, skill_directory: Path): ...


@dataclass(frozen=True)
class DevelopmentPopulation:
    """One immutable joint train/validation population contract."""

    samples: tuple[FrozenSample, ...]
    declared_samples: int
    declared_malicious: int
    declared_benign: int
    usable_samples: int
    malicious: int
    benign: int
    quarantined_samples: int
    quarantined_sample_ids: tuple[str, ...]
    excluded_union_holdout: int
    population_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "selection_policy": SELECTION_POLICY,
            "protocols": list(_REQUIRED_PROTOCOLS),
            "included_partitions": sorted(_DEVELOPMENT_PARTITIONS),
            "declared_samples": self.declared_samples,
            "declared_malicious": self.declared_malicious,
            "declared_benign": self.declared_benign,
            "usable_samples": self.usable_samples,
            "malicious": self.malicious,
            "benign": self.benign,
            "quarantined_samples": self.quarantined_samples,
            "quarantined_sample_ids_sha256": _identifier_set_sha256(
                self.quarantined_sample_ids,
                namespace=b"skill-scanner-cel-promotion-quarantine-v1",
            ),
            "excluded_union_holdout": self.excluded_union_holdout,
            "population_sha256": self.population_sha256,
        }


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _audit_harness_sha256() -> str:
    """Bind the audit and every non-scanner evaluator dependency it calls."""

    repository_root = Path(__file__).resolve(strict=True).parents[2]
    digest = hashlib.sha256(b"skill-scanner-cel-promotion-audit-harness-v1\0")
    for relative_path in _AUDIT_HARNESS_RELATIVE_PATHS:
        dependency = (repository_root / relative_path).resolve(strict=True)
        if not dependency.is_relative_to(repository_root) or not dependency.is_file():
            raise CelPromotionAuditError(f"audit harness dependency is invalid: {relative_path}")
        digest.update(relative_path.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256_file(dependency).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _identifier_set_sha256(values: Sequence[str] | set[str], *, namespace: bytes) -> str:
    encoded = _canonical_bytes(sorted(set(values)))
    return hashlib.sha256(namespace + b"\0" + encoded).hexdigest()


def _domain_sha256(namespace: bytes, value: Any) -> str:
    return hashlib.sha256(namespace + b"\0" + _canonical_bytes(value)).hexdigest()


def _sample_id_sha256(sample_id: str) -> str:
    return hashlib.sha256(b"skill-scanner-cel-candidate-sample-id-v1\0" + sample_id.encode()).hexdigest()


def _sample_content_sha256(sample_path: Path) -> str:
    """Hash one already-validated inert package tree without scanner output."""

    return _hash_tree(
        Path(sample_path),
        namespace=b"skill-scanner-cel-candidate-sample-content-v1",
    )


def _lineage_identity_sha256(lineage: Mapping[str, Any]) -> str:
    payload = {
        field: lineage[field]
        for field in (
            "rule_id",
            "decision",
            "reason",
            "fact_schema",
            "expression_hash",
            "pack",
            "rollout",
        )
    }
    return _domain_sha256(b"skill-scanner-cel-candidate-lineage-v1", payload)


def _candidate_attestation_identity(candidate: Mapping[str, Any]) -> str:
    payload = {
        field: candidate[field]
        for field in (
            "normalized_finding_identity_sha256",
            "sample_id_sha256",
            "sample_content_sha256",
            "rule_id",
            "lineage_identity_sha256",
            "lineage_ordinal",
        )
    }
    return _domain_sha256(b"skill-scanner-cel-candidate-attestation-v1", payload)


def _candidate_set_sha256(candidate_ids: Sequence[str] | set[str]) -> str:
    return _identifier_set_sha256(
        candidate_ids,
        namespace=b"skill-scanner-cel-malicious-blocking-candidate-set-v1",
    )


def _candidate_attestation_provenance_sha256(
    label_source: str,
    provenance: Mapping[str, Any],
) -> str:
    return _domain_sha256(
        f"skill-scanner-cel-candidate-attestation-provenance-v1:{label_source}".encode(),
        provenance,
    )


def _candidate_attestation_bundle_sha256(value: Mapping[str, Any]) -> str:
    payload = {key: value[key] for key in sorted(value) if key != "evidence_sha256"}
    return _domain_sha256(b"skill-scanner-cel-candidate-attestation-bundle-v1", payload)


def candidate_attestation_bundle_sha256(value: Mapping[str, Any]) -> str:
    """Return the canonical domain-separated hash for a schema-v1 bundle."""

    return _candidate_attestation_bundle_sha256(value)


def select_joint_train_validation(snapshot: FrozenSnapshot) -> DevelopmentPopulation:
    """Select rows that are non-holdout in both locked split protocols."""

    sample_ids = {sample.benchmark_id for sample in snapshot.samples}
    quarantined_ids = set(snapshot.quarantined_sample_ids)
    if not quarantined_ids <= sample_ids:
        raise CelPromotionAuditError("snapshot quarantine contains an unknown sample ID")

    declared: list[FrozenSample] = []
    excluded: list[FrozenSample] = []
    for sample in snapshot.samples:
        if set(sample.splits) != set(_REQUIRED_PROTOCOLS):
            raise CelPromotionAuditError(
                f"sample {sample.benchmark_id!r} must contain exactly the two development split protocols"
            )
        eligible = all(sample.splits[protocol] in _DEVELOPMENT_PARTITIONS for protocol in _REQUIRED_PROTOCOLS)
        (declared if eligible else excluded).append(sample)

    selected_quarantine = tuple(
        sorted(sample.benchmark_id for sample in declared if sample.benchmark_id in quarantined_ids)
    )
    usable = tuple(
        sorted(
            (sample for sample in declared if sample.benchmark_id not in quarantined_ids),
            key=lambda item: item.benchmark_id,
        )
    )
    if not usable:
        raise CelPromotionAuditError("joint train/validation population is empty")
    labels = {sample.label for sample in usable}
    if labels != {"malicious", "benign"}:
        raise CelPromotionAuditError("joint train/validation population must contain malicious and benign controls")

    payload = {
        "dataset_id": str(snapshot.dataset["id"]),
        "revision": str(snapshot.dataset["revision"]),
        "selection_policy": SELECTION_POLICY,
        "protocols": list(_REQUIRED_PROTOCOLS),
        "included_partitions": sorted(_DEVELOPMENT_PARTITIONS),
        "declared_samples": [
            {
                "benchmark_id": sample.benchmark_id,
                "category_ids": list(sample.category_ids),
                "label": sample.label,
                "path": sample.relative_path.as_posix(),
                "source_id": sample.source_id,
                "structural_family_id": sample.structural_family_id,
                "splits": {protocol: sample.splits[protocol] for protocol in _REQUIRED_PROTOCOLS},
                "quarantined": sample.benchmark_id in quarantined_ids,
            }
            for sample in sorted(declared, key=lambda item: item.benchmark_id)
        ],
    }
    population_sha256 = hashlib.sha256(
        b"skill-scanner-cel-promotion-population-v1\0" + _canonical_bytes(payload)
    ).hexdigest()
    return DevelopmentPopulation(
        samples=usable,
        declared_samples=len(declared),
        declared_malicious=sum(sample.label == "malicious" for sample in declared),
        declared_benign=sum(sample.label == "benign" for sample in declared),
        usable_samples=len(usable),
        malicious=sum(sample.label == "malicious" for sample in usable),
        benign=sum(sample.label == "benign" for sample in usable),
        quarantined_samples=len(selected_quarantine),
        quarantined_sample_ids=selected_quarantine,
        excluded_union_holdout=len(excluded),
        population_sha256=population_sha256,
    )


def _generation_from_scanner(scanner: _Scanner, *, expected_rule_count: int) -> dict[str, Any]:
    if isinstance(expected_rule_count, bool) or expected_rule_count <= 0:
        raise CelPromotionAuditError("expected_rule_count must be a positive integer")
    gate = getattr(scanner, "cel_gate", None)
    raw_rules = getattr(gate, "rules", None)
    if not isinstance(raw_rules, Mapping):
        raise CelPromotionAuditError("scanner does not expose its immutable CEL generation")
    rules: dict[str, dict[str, str]] = {}
    for rule_id, raw_rule in sorted(raw_rules.items()):
        if not isinstance(rule_id, str) or not rule_id or not isinstance(raw_rule, CelRule):
            raise CelPromotionAuditError("scanner CEL generation contains an invalid rule")
        if raw_rule.rule_id != rule_id:
            raise CelPromotionAuditError(f"scanner CEL generation identity mismatch for {rule_id!r}")
        rules[rule_id] = {
            "pack": raw_rule.pack_name,
            "rollout": raw_rule.rollout.value,
            "fact_schema": raw_rule.fact_schema,
            "expression_hash": raw_rule.expression_hash,
        }
    if len(rules) != expected_rule_count:
        raise CelPromotionAuditError(
            f"bundled CEL generation has {len(rules)} rules; expected exactly {expected_rule_count}"
        )
    expression_set_hash = getattr(gate, "expression_set_hash", None)
    if (
        not isinstance(expression_set_hash, str)
        or len(expression_set_hash) != 64
        or any(character not in "0123456789abcdef" for character in expression_set_hash)
    ):
        raise CelPromotionAuditError("scanner CEL generation lacks one valid expression-set hash")
    return {
        "expected_rule_count": expected_rule_count,
        "observed_rule_count": len(rules),
        "expression_set_hash": expression_set_hash,
        "rules": rules,
    }


def _validated_report_generation(
    report: Mapping[str, Any],
    *,
    location: str,
    expected_rule_count: int,
) -> tuple[Mapping[str, Any], frozenset[str]]:
    generation = report.get("cel_generation")
    if not isinstance(generation, Mapping):
        raise CelPromotionAuditError(f"{location} lacks a CEL generation")
    if (
        generation.get("expected_rule_count") != expected_rule_count
        or generation.get("observed_rule_count") != expected_rule_count
    ):
        raise CelPromotionAuditError(f"{location} does not prove exactly {expected_rule_count} CEL rules")
    expression_set_hash = generation.get("expression_set_hash")
    if (
        not isinstance(expression_set_hash, str)
        or len(expression_set_hash) != 64
        or any(character not in "0123456789abcdef" for character in expression_set_hash)
    ):
        raise CelPromotionAuditError(f"{location} has an invalid CEL expression-set hash")
    rules = generation.get("rules")
    if not isinstance(rules, Mapping) or len(rules) != expected_rule_count:
        raise CelPromotionAuditError(f"{location} CEL rule identity set is incomplete")
    rule_ids: set[str] = set()
    expected_identity_fields = {"pack", "rollout", "fact_schema", "expression_hash"}
    for rule_id, raw_identity in rules.items():
        if not isinstance(rule_id, str) or not rule_id or not isinstance(raw_identity, Mapping):
            raise CelPromotionAuditError(f"{location} contains an invalid CEL rule identity")
        if set(raw_identity) != expected_identity_fields:
            raise CelPromotionAuditError(f"{location} CEL rule {rule_id!r} has invalid identity fields")
        pack = raw_identity.get("pack")
        rollout = raw_identity.get("rollout")
        fact_schema = raw_identity.get("fact_schema")
        expression_hash = raw_identity.get("expression_hash")
        if (
            not isinstance(pack, str)
            or not pack
            or rollout not in {"shadow", "enforce"}
            or fact_schema != "v1"
            or not isinstance(expression_hash, str)
            or len(expression_hash) != 64
            or any(character not in "0123456789abcdef" for character in expression_hash)
        ):
            raise CelPromotionAuditError(f"{location} CEL rule {rule_id!r} has an invalid identity")
        rule_ids.add(rule_id)
    return generation, frozenset(rule_ids)


def _validated_promotion_incidence(
    report: Mapping[str, Any],
    generation: Mapping[str, Any],
    rule_ids: frozenset[str],
    *,
    location: str,
) -> Mapping[str, Any]:
    tracks = report.get("tracks")
    if not isinstance(tracks, Mapping):
        raise CelPromotionAuditError(f"{location} lacks audit tracks")
    track = tracks.get(TRACK_NAME)
    if not isinstance(track, Mapping):
        raise CelPromotionAuditError(f"{location} lacks the promotion track")
    promotion = track.get("promotion_audit")
    if not isinstance(promotion, Mapping):
        raise CelPromotionAuditError(f"{location} lacks promotion incidence")
    per_rule = promotion.get("per_rule")
    if not isinstance(per_rule, Mapping) or set(per_rule) != set(rule_ids):
        raise CelPromotionAuditError(f"{location} promotion incidence does not match the CEL generation")
    generation_rules = cast(Mapping[str, Mapping[str, Any]], generation["rules"])
    expected_rule_fields = {
        "identity",
        "coverage_status",
        "decisions",
        "error_counts",
        "benign",
        "malicious",
        "potentially_promotable_from_this_audit",
    }
    for rule_id, raw_rule in per_rule.items():
        if not isinstance(raw_rule, Mapping) or set(raw_rule) != expected_rule_fields:
            raise CelPromotionAuditError(f"{location} promotion entry is invalid for {rule_id!r}")
        if raw_rule.get("identity") != generation_rules[rule_id]:
            raise CelPromotionAuditError(f"{location} promotion identity disagrees for {rule_id!r}")
        coverage = raw_rule.get("coverage_status")
        decisions = raw_rule.get("decisions")
        errors = raw_rule.get("error_counts")
        if (
            coverage not in {"evaluated", "no_candidates"}
            or not isinstance(decisions, Mapping)
            or set(decisions) != {"keep", "would_suppress", "fallback"}
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in decisions.values())
            or not isinstance(errors, Mapping)
            or not isinstance(raw_rule.get("benign"), Mapping)
            or not isinstance(raw_rule.get("malicious"), Mapping)
            or not isinstance(raw_rule.get("potentially_promotable_from_this_audit"), bool)
        ):
            raise CelPromotionAuditError(f"{location} promotion metrics are invalid for {rule_id!r}")
    return promotion


def _blank_label_accumulator() -> dict[str, Any]:
    return {
        "decisions": {"keep": 0, "would_suppress": 0, "fallback": 0},
        "normalized_findings_touched": 0,
        "would_suppress_findings_touched": 0,
        "blocking_findings_touched": 0,
        "would_suppress_blocking_findings_touched": 0,
        "actionable_findings_touched": 0,
        "would_suppress_actionable_findings_touched": 0,
        "signal_findings_touched": 0,
        "would_suppress_signal_findings_touched": 0,
        "lost_normalized_findings": 0,
        "severity_indeterminate_findings": 0,
        "lost_normalized_finding_ids": set(),
        "severity_indeterminate_finding_ids": set(),
        "would_suppress_blocking_finding_ids": set(),
        "would_suppress_actionable_finding_ids": set(),
        "would_suppress_signal_finding_ids": set(),
        "lost_blocking_finding_ids": set(),
        "lost_actionable_finding_ids": set(),
        "lost_signal_finding_ids": set(),
        "blocking_finding_indeterminate_ids": set(),
        "actionable_finding_indeterminate_ids": set(),
        "signal_finding_indeterminate_ids": set(),
        "packages_evaluated": set(),
        "packages_would_suppress": set(),
        "packages_fallback": set(),
        "packages_with_finding_loss": set(),
        "packages_with_severity_indeterminacy": set(),
        "packages_with_all_findings_lost": set(),
        "blocking_packages_touched": set(),
        "would_suppress_blocking_packages_touched": set(),
        "blocking_package_losses": set(),
        "blocking_package_indeterminate": set(),
        "actionable_packages_touched": set(),
        "would_suppress_actionable_packages_touched": set(),
        "actionable_package_losses": set(),
        "actionable_package_indeterminate": set(),
        "signal_packages_touched": set(),
        "would_suppress_signal_packages_touched": set(),
        "signal_package_losses": set(),
        "signal_package_indeterminate": set(),
    }


def _blank_rule_accumulator(identity: Mapping[str, str]) -> dict[str, Any]:
    return {
        "identity": dict(identity),
        "benign": _blank_label_accumulator(),
        "malicious": _blank_label_accumulator(),
    }


def _classification(severities: Sequence[str]) -> dict[str, bool]:
    values = set(severities)
    return {
        "with_findings": bool(severities),
        "blocked": bool(values & _BLOCKING_SEVERITIES),
        "actionable": bool(values & _ACTIONABLE_SEVERITIES),
        "signal": bool(values & _SIGNAL_SEVERITIES),
    }


def _finding_value(finding: Any, field: str, default: Any = None) -> Any:
    return finding.get(field, default) if isinstance(finding, Mapping) else getattr(finding, field, default)


def _normalized_finding_evidence_id(sample: FrozenSample, finding: Any, finding_index: int) -> str:
    """Return a private, stable identity for one final normalized finding."""

    category = _finding_value(finding, "category")
    category = getattr(category, "value", category)
    metadata = _finding_metadata(finding)
    payload = {
        "benchmark_id": sample.benchmark_id,
        "finding_index": finding_index,
        "rule_id": str(_finding_value(finding, "rule_id", "unidentified")),
        "category": str(category) if category is not None else "unclassified",
        "severity": _severity_name(finding),
        "file_path": str(_finding_value(finding, "file_path", "") or ""),
        "line_number": int(_finding_value(finding, "line_number", 0) or 0),
        "evidence_id": str(metadata.get("evidence_id", "") or ""),
        "analyzer": str(_finding_value(finding, "analyzer", "") or ""),
    }
    return hashlib.sha256(
        b"skill-scanner-cel-promotion-normalized-finding-v1\0" + _canonical_bytes(payload)
    ).hexdigest()


def _bounded_candidate_class(value: Any) -> str:
    if isinstance(value, str) and value and len(value.encode("utf-8")) <= 256:
        return value
    return "unspecified"


def _malicious_blocking_candidate_requirements(
    sample: FrozenSample,
    finding: Any,
    finding_index: int,
    lineage: Sequence[Mapping[str, Any]],
    *,
    sample_content_sha256: str,
) -> list[dict[str, Any]]:
    if sample.label != "malicious" or _severity_name(finding) not in _BLOCKING_SEVERITIES:
        return []
    normalized_identity = _normalized_finding_evidence_id(sample, finding, finding_index)
    metadata = _finding_metadata(finding)
    category = _finding_value(finding, "category")
    category = getattr(category, "value", category)
    sample_id_hash = _sample_id_sha256(sample.benchmark_id)
    source_evidence = str(_finding_value(finding, "snippet", "") or "")
    file_path = str(_finding_value(finding, "file_path", "") or "")
    requirements: list[dict[str, Any]] = []
    for entry in lineage:
        if entry["decision"] != "would_suppress":
            continue
        lineage_identity = _lineage_identity_sha256(entry)
        lineage_count = cast(int, entry["count"])
        for ordinal in range(lineage_count):
            candidate: dict[str, Any] = {
                "normalized_finding_identity_sha256": normalized_identity,
                "sample_id": sample.benchmark_id,
                "sample_id_sha256": sample_id_hash,
                "sample_content_sha256": sample_content_sha256,
                "source_evidence_sha256": _domain_sha256(
                    b"skill-scanner-cel-candidate-source-evidence-v1",
                    source_evidence,
                ),
                "rule_id": cast(str, entry["rule_id"]),
                "severity": _severity_name(finding),
                "category": str(category) if category is not None else "unclassified",
                "analyzer": str(_finding_value(finding, "analyzer", "") or "unidentified"),
                "file_path_sha256": _domain_sha256(
                    b"skill-scanner-cel-candidate-file-path-v1",
                    file_path,
                ),
                "line_number": int(_finding_value(finding, "line_number", 0) or 0),
                "evidence_value_class": _bounded_candidate_class(metadata.get("evidence_value_class")),
                "context_kind": _bounded_candidate_class(metadata.get("context_kind")),
                "expression_sha256": cast(str, entry["expression_hash"]),
                "lineage_identity_sha256": lineage_identity,
                "lineage_ordinal": ordinal,
                "lineage_count": lineage_count,
            }
            candidate["candidate_identity_sha256"] = _candidate_attestation_identity(candidate)
            requirements.append(candidate)
    return requirements


def _accumulate_sample_incidence(
    accumulators: Mapping[str, dict[str, Any]],
    baseline_packages: Mapping[str, dict[str, set[str]]],
    sample: FrozenSample,
    result: Any,
    *,
    attestation_requirements: dict[str, dict[str, Any]] | None = None,
    sample_content_sha256: str | None = None,
) -> None:
    findings = list(getattr(result, "findings", []) or [])
    severities = [_severity_name(finding) for finding in findings]
    baseline = _classification(severities)
    for field, value in baseline.items():
        if value:
            baseline_packages[sample.label][field].add(sample.benchmark_id)

    touched_by_rule: dict[str, set[int]] = {}
    would_by_rule: dict[str, set[int]] = {}
    fallback_by_rule: dict[str, set[int]] = {}
    lost_by_rule: dict[str, set[int]] = {}
    severity_indeterminate_by_rule: dict[str, set[int]] = {}
    for finding_index, finding in enumerate(findings):
        finding_evidence_id = _normalized_finding_evidence_id(sample, finding, finding_index)
        lineage = _finding_cel_lineage(finding, sample.benchmark_id)
        if not lineage:
            continue
        if attestation_requirements is not None:
            if sample_content_sha256 is None:
                raise CelPromotionAuditError("candidate attestation projection lacks the sample content hash")
            for requirement in _malicious_blocking_candidate_requirements(
                sample,
                finding,
                finding_index,
                lineage,
                sample_content_sha256=sample_content_sha256,
            ):
                candidate_id = cast(str, requirement["candidate_identity_sha256"])
                if candidate_id in attestation_requirements:
                    raise CelPromotionAuditError(
                        f"duplicate malicious blocking candidate identity for {sample.benchmark_id}"
                    )
                attestation_requirements[candidate_id] = requirement
        lineage_count = sum(cast(int, entry["count"]) for entry in lineage)
        deduped_count = _finding_metadata(finding).get("deduped_count", 0)
        if isinstance(deduped_count, bool) or not isinstance(deduped_count, int) or deduped_count < 0:
            raise CelPromotionAuditError(f"finding for {sample.benchmark_id} has an invalid deduped_count")
        # Same-issue normalization records its complete group size. Exact
        # post-CEL dedupe records complete CEL multiplicity in lineage. If the
        # former is larger, an undecided/non-CEL support keeps the finding.
        has_non_cel_support = 1 + deduped_count > lineage_count
        entries_by_rule: dict[str, list[Mapping[str, Any]]] = {}
        for entry in lineage:
            rule_id = cast(str, entry["rule_id"])
            if rule_id not in accumulators:
                raise CelPromotionAuditError(
                    f"sample {sample.benchmark_id} reports CEL decision for unknown rule {rule_id!r}"
                )
            entries_by_rule.setdefault(rule_id, []).append(entry)
            decision = cast(str, entry["decision"])
            count = cast(int, entry["count"])
            accumulators[rule_id][sample.label]["decisions"][decision] += count

        severity = _severity_name(finding)
        for rule_id, entries in entries_by_rule.items():
            label_acc = accumulators[rule_id][sample.label]
            touched_by_rule.setdefault(rule_id, set()).add(finding_index)
            label_acc["normalized_findings_touched"] += 1
            has_would = any(entry["decision"] == "would_suppress" for entry in entries)
            has_fallback = any(entry["decision"] == "fallback" for entry in entries)
            if has_would:
                would_by_rule.setdefault(rule_id, set()).add(finding_index)
                label_acc["would_suppress_findings_touched"] += 1
            if has_fallback:
                fallback_by_rule.setdefault(rule_id, set()).add(finding_index)
            if severity in _BLOCKING_SEVERITIES:
                label_acc["blocking_findings_touched"] += 1
                if has_would:
                    label_acc["would_suppress_blocking_findings_touched"] += 1
                    label_acc["would_suppress_blocking_finding_ids"].add(finding_evidence_id)
            if severity in _ACTIONABLE_SEVERITIES:
                label_acc["actionable_findings_touched"] += 1
                if has_would:
                    label_acc["would_suppress_actionable_findings_touched"] += 1
                    label_acc["would_suppress_actionable_finding_ids"].add(finding_evidence_id)
            if severity in _SIGNAL_SEVERITIES:
                label_acc["signal_findings_touched"] += 1
                if has_would:
                    label_acc["would_suppress_signal_findings_touched"] += 1
                    label_acc["would_suppress_signal_finding_ids"].add(finding_evidence_id)

            # Enforce only this one rule. Every non-target decision and every
            # undecided member of a normalized group remains as support.
            removable = (
                not has_non_cel_support
                and bool(entries)
                and len(entries) == len(lineage)
                and all(entry["decision"] == "would_suppress" for entry in entries)
            )
            if removable:
                lost_by_rule.setdefault(rule_id, set()).add(finding_index)
                label_acc["lost_normalized_finding_ids"].add(finding_evidence_id)
                if severity in _BLOCKING_SEVERITIES:
                    label_acc["lost_blocking_finding_ids"].add(finding_evidence_id)
                if severity in _ACTIONABLE_SEVERITIES:
                    label_acc["lost_actionable_finding_ids"].add(finding_evidence_id)
                if severity in _SIGNAL_SEVERITIES:
                    label_acc["lost_signal_finding_ids"].add(finding_evidence_id)
            elif has_would:
                # The finding survives isolated enforcement because another
                # candidate supports the normalized issue, but the retained
                # candidate severities are not carried in CEL lineage. Its
                # post-enforcement severity is therefore bounded, not exact.
                severity_indeterminate_by_rule.setdefault(rule_id, set()).add(finding_index)
                label_acc["severity_indeterminate_finding_ids"].add(finding_evidence_id)
                if severity in _BLOCKING_SEVERITIES:
                    label_acc["blocking_finding_indeterminate_ids"].add(finding_evidence_id)
                if severity in _ACTIONABLE_SEVERITIES:
                    label_acc["actionable_finding_indeterminate_ids"].add(finding_evidence_id)
                if severity in _SIGNAL_SEVERITIES:
                    label_acc["signal_finding_indeterminate_ids"].add(finding_evidence_id)

    for rule_id, finding_indexes in touched_by_rule.items():
        label_acc = accumulators[rule_id][sample.label]
        label_acc["packages_evaluated"].add(sample.benchmark_id)
        if rule_id in would_by_rule:
            label_acc["packages_would_suppress"].add(sample.benchmark_id)
        if rule_id in fallback_by_rule:
            label_acc["packages_fallback"].add(sample.benchmark_id)
        touched_severities = [severities[index] for index in finding_indexes]
        if set(touched_severities) & _BLOCKING_SEVERITIES:
            label_acc["blocking_packages_touched"].add(sample.benchmark_id)
        if set(touched_severities) & _ACTIONABLE_SEVERITIES:
            label_acc["actionable_packages_touched"].add(sample.benchmark_id)
        if set(touched_severities) & _SIGNAL_SEVERITIES:
            label_acc["signal_packages_touched"].add(sample.benchmark_id)
        would_indexes = would_by_rule.get(rule_id, set())
        would_severities = [severities[index] for index in would_indexes]
        if set(would_severities) & _BLOCKING_SEVERITIES:
            label_acc["would_suppress_blocking_packages_touched"].add(sample.benchmark_id)
        if set(would_severities) & _ACTIONABLE_SEVERITIES:
            label_acc["would_suppress_actionable_packages_touched"].add(sample.benchmark_id)
        if set(would_severities) & _SIGNAL_SEVERITIES:
            label_acc["would_suppress_signal_packages_touched"].add(sample.benchmark_id)

        lost_indexes = lost_by_rule.get(rule_id, set())
        indeterminate_indexes = severity_indeterminate_by_rule.get(rule_id, set())
        if indeterminate_indexes:
            label_acc["severity_indeterminate_findings"] += len(indeterminate_indexes)
            label_acc["packages_with_severity_indeterminacy"].add(sample.benchmark_id)
        if not lost_indexes and not indeterminate_indexes:
            continue
        if lost_indexes:
            label_acc["lost_normalized_findings"] += len(lost_indexes)
            label_acc["packages_with_finding_loss"].add(sample.benchmark_id)
        remaining = [severity for index, severity in enumerate(severities) if index not in lost_indexes]
        after = _classification(remaining)
        worst_case_remaining = [
            severity
            for index, severity in enumerate(severities)
            if index not in lost_indexes and index not in indeterminate_indexes
        ]
        worst_case_after = _classification(worst_case_remaining)
        if baseline["with_findings"] and not after["with_findings"]:
            label_acc["packages_with_all_findings_lost"].add(sample.benchmark_id)
        if baseline["blocked"] and not after["blocked"]:
            label_acc["blocking_package_losses"].add(sample.benchmark_id)
        elif baseline["blocked"] and not worst_case_after["blocked"]:
            label_acc["blocking_package_indeterminate"].add(sample.benchmark_id)
        if baseline["actionable"] and not after["actionable"]:
            label_acc["actionable_package_losses"].add(sample.benchmark_id)
        elif baseline["actionable"] and not worst_case_after["actionable"]:
            label_acc["actionable_package_indeterminate"].add(sample.benchmark_id)
        if baseline["signal"] and not after["signal"]:
            label_acc["signal_package_losses"].add(sample.benchmark_id)
        elif baseline["signal"] and not worst_case_after["signal"]:
            label_acc["signal_package_indeterminate"].add(sample.benchmark_id)


def _set_evidence(
    values: set[str],
    *,
    namespace: str,
    identity_field: str = "sample_ids_sha256",
) -> dict[str, Any]:
    return {
        "count": len(values),
        identity_field: _identifier_set_sha256(
            values,
            namespace=f"skill-scanner-cel-promotion-{namespace}-v1".encode(),
        ),
    }


def _finalize_label_incidence(
    raw: Mapping[str, Any],
    baseline: Mapping[str, set[str]],
    *,
    namespace: str,
) -> dict[str, Any]:
    decisions = dict(raw["decisions"])
    would = int(decisions["would_suppress"])
    targeted_actionable_packages = cast(set[str], raw["would_suppress_actionable_packages_touched"])
    resolved_actionable_packages = cast(set[str], raw["actionable_package_losses"])
    package_reduction_lower_bound = (
        len(resolved_actionable_packages) / len(targeted_actionable_packages) if targeted_actionable_packages else 0.0
    )

    def classification_delta(
        field: str,
        losses_field: str,
        indeterminate_field: str | None = None,
    ) -> dict[str, Any]:
        before = len(baseline[field])
        losses = cast(set[str], raw[losses_field])
        indeterminate = set() if indeterminate_field is None else cast(set[str], raw[indeterminate_field])
        lower_delta = -(len(losses) + len(indeterminate))
        upper_delta = -len(losses)
        return {
            "before": before,
            "after": before - len(losses),
            "delta": upper_delta,
            "exact": not indeterminate,
            "after_range": [before + lower_delta, before + upper_delta],
            "delta_range": [lower_delta, upper_delta],
            "losses": _set_evidence(losses, namespace=f"{namespace}-{losses_field}"),
            "indeterminate": _set_evidence(
                indeterminate,
                namespace=f"{namespace}-{indeterminate_field or 'no-indeterminate'}",
            ),
        }

    def finding_classification_effect(classification: str) -> dict[str, Any]:
        targeted = cast(set[str], raw[f"would_suppress_{classification}_finding_ids"])
        known_lost = cast(set[str], raw[f"lost_{classification}_finding_ids"])
        indeterminate = cast(set[str], raw[f"{classification}_finding_indeterminate_ids"])
        reduction_lower_bound = len(known_lost) / len(targeted) if targeted else 0.0
        return {
            "targeted_would_suppress": _set_evidence(
                targeted,
                namespace=f"{namespace}-{classification}-finding-targeted",
                identity_field="finding_ids_sha256",
            ),
            "known_lost": _set_evidence(
                known_lost,
                namespace=f"{namespace}-{classification}-finding-known-lost",
                identity_field="finding_ids_sha256",
            ),
            "indeterminate": _set_evidence(
                indeterminate,
                namespace=f"{namespace}-{classification}-finding-indeterminate",
                identity_field="finding_ids_sha256",
            ),
            "exact": not indeterminate,
            "relative_targeted_loss_lower_bound": reduction_lower_bound,
        }

    return {
        "candidate_findings": {
            **decisions,
            "total_decisions": sum(decisions.values()),
            "observed_shadow_delta": 0,
            "would_suppress_delta": -would,
        },
        "normalized_findings": {
            "touched": raw["normalized_findings_touched"],
            "would_suppress_touched": raw["would_suppress_findings_touched"],
            "blocking_touched": raw["blocking_findings_touched"],
            "would_suppress_blocking_touched": raw["would_suppress_blocking_findings_touched"],
            "actionable_touched": raw["actionable_findings_touched"],
            "would_suppress_actionable_touched": raw["would_suppress_actionable_findings_touched"],
            "signal_touched": raw["signal_findings_touched"],
            "would_suppress_signal_touched": raw["would_suppress_signal_findings_touched"],
            "counterfactual_lost": raw["lost_normalized_findings"],
            "counterfactual_severity_indeterminate": raw["severity_indeterminate_findings"],
            "counterfactual_lost_evidence": _set_evidence(
                raw["lost_normalized_finding_ids"],
                namespace=f"{namespace}-normalized-finding-known-lost",
                identity_field="finding_ids_sha256",
            ),
            "counterfactual_severity_indeterminate_evidence": _set_evidence(
                raw["severity_indeterminate_finding_ids"],
                namespace=f"{namespace}-normalized-finding-indeterminate",
                identity_field="finding_ids_sha256",
            ),
        },
        "counterfactual_finding_classification": {
            classification: finding_classification_effect(classification)
            for classification in ("blocking", "actionable", "signal")
        },
        "candidate_package_incidence": {
            "evaluated": _set_evidence(raw["packages_evaluated"], namespace=f"{namespace}-evaluated"),
            "would_suppress": _set_evidence(raw["packages_would_suppress"], namespace=f"{namespace}-would-suppress"),
            "fallback": _set_evidence(raw["packages_fallback"], namespace=f"{namespace}-fallback"),
            "blocking_touched": _set_evidence(
                raw["blocking_packages_touched"], namespace=f"{namespace}-blocking-touched"
            ),
            "would_suppress_blocking_touched": _set_evidence(
                raw["would_suppress_blocking_packages_touched"],
                namespace=f"{namespace}-would-blocking",
            ),
            "signal_touched": _set_evidence(raw["signal_packages_touched"], namespace=f"{namespace}-signal-touched"),
            "would_suppress_signal_touched": _set_evidence(
                raw["would_suppress_signal_packages_touched"],
                namespace=f"{namespace}-would-signal",
            ),
            "packages_with_finding_loss": _set_evidence(
                raw["packages_with_finding_loss"], namespace=f"{namespace}-finding-loss"
            ),
            "packages_with_severity_indeterminacy": _set_evidence(
                raw["packages_with_severity_indeterminacy"],
                namespace=f"{namespace}-severity-indeterminate",
            ),
        },
        "counterfactual_single_rule_enforcement": {
            "packages_with_findings": classification_delta("with_findings", "packages_with_all_findings_lost"),
            "blocked_packages": classification_delta(
                "blocked", "blocking_package_losses", "blocking_package_indeterminate"
            ),
            "actionable_packages": classification_delta(
                "actionable", "actionable_package_losses", "actionable_package_indeterminate"
            ),
            "signal_packages": classification_delta("signal", "signal_package_losses", "signal_package_indeterminate"),
            "targeted_benign_actionable_packages": len(targeted_actionable_packages),
            "resolved_benign_actionable_packages_lower_bound": len(resolved_actionable_packages),
            "relative_actionable_package_reduction_lower_bound": package_reduction_lower_bound,
        },
    }


def _finalize_rule_incidence(
    accumulators: Mapping[str, Mapping[str, Any]],
    baseline_packages: Mapping[str, Mapping[str, set[str]]],
    track: Mapping[str, Any],
) -> dict[str, Any]:
    cel = track.get("cel")
    if not isinstance(cel, Mapping):
        raise CelPromotionAuditError("promotion track lacks CEL telemetry")
    raw_per_rule = cel.get("per_rule")
    if not isinstance(raw_per_rule, Mapping):
        raise CelPromotionAuditError("promotion track lacks authoritative CEL per_rule telemetry")
    unexpected = sorted(set(raw_per_rule) - set(accumulators))
    if unexpected:
        raise CelPromotionAuditError(f"promotion telemetry contains unexpected CEL rules: {unexpected}")

    error_counts_by_rule: dict[str, dict[str, int]] = {rule_id: {} for rule_id in accumulators}
    raw_errors = cel.get("error_counts")
    if not isinstance(raw_errors, Mapping):
        raise CelPromotionAuditError("promotion track CEL error_counts must be an object")
    for key, count in raw_errors.items():
        if not isinstance(key, str) or ":" not in key or isinstance(count, bool) or not isinstance(count, int):
            raise CelPromotionAuditError("promotion track contains an invalid CEL error count")
        rule_id, code = key.split(":", 1)
        if rule_id not in error_counts_by_rule or not code:
            raise CelPromotionAuditError("promotion track CEL error references an unknown rule")
        error_counts_by_rule[rule_id][code] = count

    finalized: dict[str, Any] = {}
    for rule_id, raw in sorted(accumulators.items()):
        aggregate_decisions = {
            decision: sum(int(raw[label]["decisions"][decision]) for label in ("benign", "malicious"))
            for decision in ("keep", "would_suppress", "fallback")
        }
        reported = raw_per_rule.get(rule_id)
        if reported is None:
            if any(aggregate_decisions.values()):
                raise CelPromotionAuditError(f"CEL lineage for {rule_id!r} lacks aggregate telemetry")
        else:
            if not isinstance(reported, Mapping):
                raise CelPromotionAuditError(f"CEL per_rule entry for {rule_id!r} is invalid")
            if any(reported.get(decision) != count for decision, count in aggregate_decisions.items()):
                raise CelPromotionAuditError(f"CEL per_rule decisions disagree for {rule_id!r}")
            identity = raw["identity"]
            if (
                reported.get("expression_hashes") != [identity["expression_hash"]]
                or reported.get("packs") != [identity["pack"]]
                or reported.get("rollouts") != [identity["rollout"]]
            ):
                raise CelPromotionAuditError(f"CEL per_rule identity disagrees for {rule_id!r}")
        benign = _finalize_label_incidence(raw["benign"], baseline_packages["benign"], namespace=f"{rule_id}-benign")
        malicious = _finalize_label_incidence(
            raw["malicious"], baseline_packages["malicious"], namespace=f"{rule_id}-malicious"
        )
        coverage = aggregate_decisions["keep"] + aggregate_decisions["would_suppress"]
        malicious_losses = malicious["counterfactual_single_rule_enforcement"]
        malicious_blocking_finding_effect = malicious["counterfactual_finding_classification"]["blocking"]
        benign_effect = benign["counterfactual_single_rule_enforcement"]
        potentially_promotable = (
            coverage > 0
            and aggregate_decisions["fallback"] == 0
            and not error_counts_by_rule[rule_id]
            and malicious_blocking_finding_effect["known_lost"]["count"] == 0
            and malicious_blocking_finding_effect["indeterminate"]["count"] == 0
            and malicious_blocking_finding_effect["exact"] is True
            and malicious_losses["blocked_packages"]["delta"] == 0
            and malicious_losses["blocked_packages"]["exact"] is True
            and malicious_losses["signal_packages"]["delta"] == 0
            and malicious_losses["signal_packages"]["exact"] is True
            and benign_effect["targeted_benign_actionable_packages"] > 0
            and benign_effect["relative_actionable_package_reduction_lower_bound"] >= 0.20
        )
        finalized[rule_id] = {
            "identity": dict(raw["identity"]),
            "coverage_status": "evaluated" if coverage else "no_candidates",
            "decisions": aggregate_decisions,
            "error_counts": dict(sorted(error_counts_by_rule[rule_id].items())),
            "benign": benign,
            "malicious": malicious,
            "potentially_promotable_from_this_audit": potentially_promotable,
        }
    return finalized


def _finalize_attestation_requirements(
    requirements: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if len(requirements) > 16_384:
        raise CelPromotionAuditError("candidate attestation requirements exceed the 16,384-candidate bound")
    sample_ids: set[str] = set()
    by_rule: dict[str, list[str]] = {}
    rule_expressions: dict[str, str] = {}
    candidates: dict[str, dict[str, Any]] = {}
    for candidate_id, raw_candidate in sorted(requirements.items()):
        if raw_candidate.get("candidate_identity_sha256") != candidate_id:
            raise CelPromotionAuditError("candidate attestation requirement identity mismatch")
        candidate = dict(raw_candidate)
        sample_ids.add(cast(str, candidate["sample_id"]))
        rule_id = cast(str, candidate["rule_id"])
        expression_hash = cast(str, candidate["expression_sha256"])
        previous_expression = rule_expressions.setdefault(rule_id, expression_hash)
        if previous_expression != expression_hash:
            raise CelPromotionAuditError(f"candidate rule {rule_id!r} has multiple expression identities")
        by_rule.setdefault(rule_id, []).append(candidate_id)
        candidates[candidate_id] = candidate
    return {
        "candidate_count": len(candidates),
        "candidate_set_sha256": _candidate_set_sha256(set(candidates)),
        "membership_sha256": _identifier_set_sha256(
            sample_ids,
            namespace=b"skill-scanner-cel-malicious-blocking-candidate-membership-v1",
        ),
        "rule_expression_sha256": dict(sorted(rule_expressions.items())),
        "by_rule": {
            rule_id: {
                "candidate_count": len(candidate_ids),
                "candidate_set_sha256": _candidate_set_sha256(set(candidate_ids)),
                "candidate_identity_sha256": sorted(candidate_ids),
            }
            for rule_id, candidate_ids in sorted(by_rule.items())
        },
        "candidates": candidates,
    }


def _attestation_sha256(value: Any, *, location: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CelPromotionAuditError(f"{location} must be a lowercase SHA-256 digest")
    return value


def _attestation_string(value: Any, *, location: str, maximum: int = 1_024) -> str:
    if not isinstance(value, str) or not value:
        raise CelPromotionAuditError(f"{location} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise CelPromotionAuditError(f"{location} exceeds its {maximum}-byte bound")
    return value


def _attestation_mapping(value: Any, fields: frozenset[str], *, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CelPromotionAuditError(f"{location} must contain exactly {sorted(fields)}")
    return value


def _validate_attestation_label_reason(label: Any, reason: Any, *, location: str) -> tuple[str, str]:
    if label not in _ATTESTATION_LABELS:
        raise CelPromotionAuditError(f"{location}.label must be one of {sorted(_ATTESTATION_LABELS)}")
    normalized_label = cast(str, label)
    if reason not in _ATTESTATION_REASON_CODES or reason not in _ATTESTATION_REASON_BY_LABEL[normalized_label]:
        raise CelPromotionAuditError(f"{location}.reason_code is inconsistent with its label")
    return normalized_label, cast(str, reason)


def _candidate_attestation_expected_binding(
    report: Mapping[str, Any],
    generation: Mapping[str, Any],
    requirements: Mapping[str, Any],
) -> dict[str, Any]:
    dataset = cast(Mapping[str, Any], report["dataset"])
    selection = cast(Mapping[str, Any], dataset["selection"])
    producer = cast(Mapping[str, Any], report["producer"])
    binding = {
        "dataset_id": dataset.get("id"),
        "dataset_revision": dataset.get("revision"),
        "snapshot_sha256": dataset.get("artifact_manifest_sha256"),
        "sample_metadata_manifest_sha256": dataset.get("sample_metadata_manifest_sha256"),
        "usable_snapshot_sha256": dataset.get("usable_artifact_manifest_sha256"),
        "population_sha256": selection.get("population_sha256"),
        "membership_sha256": requirements.get("membership_sha256"),
        "build_sha256": producer.get("build_sha256"),
        "policy_sha256": producer.get("policy_sha256"),
        "rules_sha256": producer.get("rules_sha256"),
        "source_revision": producer.get("source_revision"),
        "expression_set_sha256": generation.get("expression_set_hash"),
        "rule_expression_sha256": requirements.get("rule_expression_sha256"),
        "candidate_set_sha256": requirements.get("candidate_set_sha256"),
        "expected_candidate_count": requirements.get("candidate_count"),
    }
    _validate_attestation_binding(binding, location="shadow candidate attestation binding")
    return binding


def candidate_attestation_expected_binding(
    report: Mapping[str, Any],
    generation: Mapping[str, Any],
    requirements: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the exact schema-v1 binding for one complete declared rule scope."""

    return _candidate_attestation_expected_binding(report, generation, requirements)


def _empty_attestation_counts() -> dict[str, int]:
    return {
        "candidate_count": 0,
        "accepted": 0,
        "actionable": 0,
        "ambiguous": 0,
        "abstained": 0,
        "disagreements": 0,
        "provider_errors": 0,
    }


def _validate_attestation_binding(value: Mapping[str, Any], *, location: str) -> None:
    for field in ("dataset_id", "dataset_revision"):
        _attestation_string(value.get(field), location=f"{location}.{field}")
    for field in (
        "snapshot_sha256",
        "sample_metadata_manifest_sha256",
        "usable_snapshot_sha256",
        "population_sha256",
        "membership_sha256",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
        "expression_set_sha256",
        "candidate_set_sha256",
    ):
        _attestation_sha256(value.get(field), location=f"{location}.{field}")
    source_revision = value.get("source_revision")
    if not isinstance(source_revision, str) or _SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise CelPromotionAuditError(f"{location}.source_revision must be one exact lowercase commit SHA")
    rule_expressions = value.get("rule_expression_sha256")
    if not isinstance(rule_expressions, Mapping) or len(rule_expressions) > 1_024:
        raise CelPromotionAuditError(f"{location}.rule_expression_sha256 is invalid")
    for rule_id, expression_hash in rule_expressions.items():
        _attestation_string(rule_id, location=f"{location}.rule_expression_sha256 rule", maximum=256)
        _attestation_sha256(
            expression_hash,
            location=f"{location}.rule_expression_sha256.{rule_id}",
        )
    candidate_count = value.get("expected_candidate_count")
    if isinstance(candidate_count, bool) or not isinstance(candidate_count, int) or not 0 <= candidate_count <= 16_384:
        raise CelPromotionAuditError(f"{location}.expected_candidate_count is invalid")


def _validate_attestation_summary_counts(value: Mapping[str, Any], *, location: str) -> None:
    count_fields = set(_empty_attestation_counts())
    for field in count_fields:
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise CelPromotionAuditError(f"{location}.{field} must be a non-negative integer")
    per_rule = value.get("per_rule")
    if not isinstance(per_rule, Mapping) or len(per_rule) > 1_024:
        raise CelPromotionAuditError(f"{location}.per_rule is invalid")
    for rule_id, raw_counts in per_rule.items():
        _attestation_string(rule_id, location=f"{location}.per_rule rule", maximum=256)
        counts = _attestation_mapping(
            raw_counts,
            frozenset(count_fields),
            location=f"{location}.per_rule.{rule_id}",
        )
        for field in count_fields:
            count = counts.get(field)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise CelPromotionAuditError(f"{location}.per_rule.{rule_id}.{field} must be a non-negative integer")


def _validate_candidate_attestation_bundle(
    value: Mapping[str, Any],
    *,
    expected_binding: Mapping[str, Any],
    expected_requirements: Mapping[str, Any],
) -> dict[str, Any]:
    top_fields = frozenset(
        {
            "schema_version",
            "purpose",
            "label_source",
            "binding",
            "adjudicator",
            "candidates",
            "summary",
            "evidence_sha256",
        }
    )
    document = _attestation_mapping(value, top_fields, location="candidate attestations")
    schema_version = document.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1 or document.get("purpose") != _ATTESTATION_PURPOSE:
        raise CelPromotionAuditError("candidate attestations use an unsupported schema or purpose")
    label_source = document.get("label_source")
    if label_source not in _ATTESTATION_LABEL_SOURCES:
        raise CelPromotionAuditError(
            f"candidate attestations.label_source must be one of {sorted(_ATTESTATION_LABEL_SOURCES)}"
        )
    binding = _attestation_mapping(
        document.get("binding"),
        _ATTESTATION_BINDING_FIELDS,
        location="candidate attestations.binding",
    )
    _validate_attestation_binding(binding, location="candidate attestations.binding")
    if dict(binding) != dict(expected_binding):
        differing = sorted(
            field for field in _ATTESTATION_BINDING_FIELDS if binding.get(field) != expected_binding.get(field)
        )
        raise CelPromotionAuditError(f"candidate attestation binding mismatch: {differing}")

    adjudicator = _attestation_mapping(
        document.get("adjudicator"),
        _ATTESTATION_ADJUDICATOR_FIELDS,
        location="candidate attestations.adjudicator",
    )
    model_name = _attestation_string(
        adjudicator.get("model_name"),
        location="candidate attestations.adjudicator.model_name",
    )
    if "skill-scanner" in model_name.casefold().replace("_", "-"):
        raise CelPromotionAuditError("candidate attestation adjudicator must be scanner-independent")
    for field in (
        "model_digest",
        "rubric_sha256",
        "prompt_sha256",
        "options_sha256",
        "deterministic_check_sha256",
    ):
        _attestation_sha256(adjudicator.get(field), location=f"candidate attestations.adjudicator.{field}")
    provenance_fields = (
        frozenset({"corpus_id", "report_sha256", "scanner_outputs_used_as_labels"})
        if label_source == "independent_ollama"
        else frozenset({"agent_id", "agent_definition_sha256", "run_id", "scanner_outputs_used_as_labels"})
    )
    provenance = _attestation_mapping(
        adjudicator.get("provenance"),
        provenance_fields,
        location="candidate attestations.adjudicator.provenance",
    )
    if provenance.get("scanner_outputs_used_as_labels") is not False:
        raise CelPromotionAuditError("candidate attestation provenance must be scanner-independent")
    if label_source == "independent_ollama":
        _attestation_string(provenance.get("corpus_id"), location="candidate attestations.provenance.corpus_id")
        _attestation_sha256(
            provenance.get("report_sha256"),
            location="candidate attestations.provenance.report_sha256",
        )
    else:
        agent_id = _attestation_string(
            provenance.get("agent_id"),
            location="candidate attestations.provenance.agent_id",
        )
        if "skill-scanner" in agent_id.casefold().replace("_", "-"):
            raise CelPromotionAuditError("candidate attestation agent must be scanner-independent")
        _attestation_string(provenance.get("run_id"), location="candidate attestations.provenance.run_id")
        _attestation_sha256(
            provenance.get("agent_definition_sha256"),
            location="candidate attestations.provenance.agent_definition_sha256",
        )
    provenance_sha256 = _attestation_sha256(
        adjudicator.get("provenance_sha256"),
        location="candidate attestations.adjudicator.provenance_sha256",
    )
    if provenance_sha256 != _candidate_attestation_provenance_sha256(cast(str, label_source), provenance):
        raise CelPromotionAuditError("candidate attestation provenance hash does not match canonical provenance")

    raw_passes = adjudicator.get("passes")
    if not isinstance(raw_passes, list) or len(raw_passes) != 2:
        raise CelPromotionAuditError("candidate attestations.adjudicator.passes must contain exactly two passes")
    pass_contract: list[dict[str, Any]] = []
    for index, raw_pass in enumerate(raw_passes):
        item = _attestation_mapping(
            raw_pass,
            frozenset({"pass_id", "seed"}),
            location=f"candidate attestations.adjudicator.passes[{index}]",
        )
        pass_id = _attestation_string(
            item.get("pass_id"),
            location=f"candidate attestations.adjudicator.passes[{index}].pass_id",
            maximum=128,
        )
        seed = item.get("seed")
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
            raise CelPromotionAuditError("candidate attestation pass seed must be a bounded integer")
        pass_contract.append({"pass_id": pass_id, "seed": seed})
    if (
        len({item["pass_id"] for item in pass_contract}) != 2
        or len({item["seed"] for item in pass_contract}) != 2
        or pass_contract != sorted(pass_contract, key=lambda item: item["pass_id"])
    ):
        raise CelPromotionAuditError("candidate attestation passes must have sorted distinct IDs and seeds")

    expected_candidates = expected_requirements.get("candidates")
    raw_candidates = document.get("candidates")
    if (
        not isinstance(expected_candidates, Mapping)
        or not isinstance(raw_candidates, Mapping)
        or set(raw_candidates) != set(expected_candidates)
        or len(raw_candidates) > 16_384
    ):
        raise CelPromotionAuditError("candidate attestations must cover the exact bounded candidate identity set")

    per_rule_counts: dict[str, dict[str, int]] = {}
    global_counts = _empty_attestation_counts()
    candidate_results: dict[str, dict[str, Any]] = {}
    for candidate_id, raw_candidate in sorted(raw_candidates.items()):
        location = f"candidate attestations.candidates.{candidate_id}"
        _attestation_sha256(candidate_id, location=location)
        candidate = _attestation_mapping(raw_candidate, _ATTESTATION_CANDIDATE_FIELDS, location=location)
        if candidate.get("candidate_identity_sha256") != candidate_id:
            raise CelPromotionAuditError(f"{location}.candidate_identity_sha256 must match its key")
        expected_candidate = cast(Mapping[str, Any], expected_candidates[candidate_id])
        candidate_binding = {field: candidate[field] for field in _ATTESTATION_CANDIDATE_BINDING_FIELDS}
        if candidate_binding != dict(expected_candidate):
            raise CelPromotionAuditError(f"{location} does not match the audited candidate identity")
        if _candidate_attestation_identity(candidate) != candidate_id:
            raise CelPromotionAuditError(f"{location} candidate identity hash is not canonical")
        if _sample_id_sha256(cast(str, candidate["sample_id"])) != candidate["sample_id_sha256"]:
            raise CelPromotionAuditError(f"{location}.sample_id_sha256 does not match sample_id")
        for field in (
            "candidate_identity_sha256",
            "normalized_finding_identity_sha256",
            "sample_id_sha256",
            "sample_content_sha256",
            "source_evidence_sha256",
            "file_path_sha256",
            "expression_sha256",
            "lineage_identity_sha256",
        ):
            _attestation_sha256(candidate.get(field), location=f"{location}.{field}")
        for field in (
            "sample_id",
            "rule_id",
            "severity",
            "category",
            "analyzer",
            "evidence_value_class",
            "context_kind",
        ):
            _attestation_string(candidate.get(field), location=f"{location}.{field}")
        if candidate.get("severity") not in _BLOCKING_SEVERITIES:
            raise CelPromotionAuditError(f"{location}.severity must remain HIGH or CRITICAL")
        for field in ("line_number", "lineage_ordinal", "lineage_count"):
            number = candidate.get(field)
            if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                raise CelPromotionAuditError(f"{location}.{field} must be a non-negative integer")
        if candidate["lineage_count"] <= 0 or candidate["lineage_ordinal"] >= candidate["lineage_count"]:
            raise CelPromotionAuditError(f"{location} has inconsistent lineage ordinal/count")

        deterministic = _attestation_mapping(
            candidate.get("deterministic"),
            frozenset({"label", "reason_code"}),
            location=f"{location}.deterministic",
        )
        deterministic_label, deterministic_reason = _validate_attestation_label_reason(
            deterministic.get("label"),
            deterministic.get("reason_code"),
            location=f"{location}.deterministic",
        )
        if deterministic_label not in {"benign_non_actionable", "ambiguous"}:
            raise CelPromotionAuditError(f"{location}.deterministic must be benign_non_actionable or ambiguous")
        candidate_passes = candidate.get("passes")
        if not isinstance(candidate_passes, list) or len(candidate_passes) != 2:
            raise CelPromotionAuditError(f"{location}.passes must contain exactly two passes")
        labels: list[str] = []
        provider_error = False
        for index, raw_pass in enumerate(candidate_passes):
            pass_location = f"{location}.passes[{index}]"
            item = _attestation_mapping(
                raw_pass,
                frozenset({"pass_id", "seed", "label", "reason_code", "request_sha256", "response_sha256"}),
                location=pass_location,
            )
            if (
                item.get("pass_id") != pass_contract[index]["pass_id"]
                or item.get("seed") != pass_contract[index]["seed"]
            ):
                raise CelPromotionAuditError(f"{pass_location} does not match the adjudicator pass contract")
            label, reason = _validate_attestation_label_reason(
                item.get("label"),
                item.get("reason_code"),
                location=pass_location,
            )
            labels.append(label)
            provider_error = provider_error or reason == "provider_error"
            _attestation_sha256(item.get("request_sha256"), location=f"{pass_location}.request_sha256")
            _attestation_sha256(item.get("response_sha256"), location=f"{pass_location}.response_sha256")
        agreement = labels[0] == labels[1]
        accepted_label = candidate.get("accepted_label")
        if accepted_label not in _ATTESTATION_LABELS:
            raise CelPromotionAuditError(f"{location}.accepted_label is invalid")
        expected_accepted = labels[0] if agreement else "abstain"
        if accepted_label != expected_accepted:
            raise CelPromotionAuditError(f"{location}.accepted_label does not match the two-pass result")

        rule_id = cast(str, candidate["rule_id"])
        counts = per_rule_counts.setdefault(rule_id, _empty_attestation_counts())
        for target in (global_counts, counts):
            target["candidate_count"] += 1
            if accepted_label != "abstain":
                target["accepted"] += 1
            if accepted_label == "actionable":
                target["actionable"] += 1
            elif accepted_label == "ambiguous":
                target["ambiguous"] += 1
            elif accepted_label == "abstain":
                target["abstained"] += 1
            if not agreement:
                target["disagreements"] += 1
            if provider_error:
                target["provider_errors"] += 1
        candidate_results[candidate_id] = {
            "rule_id": rule_id,
            "accepted_label": accepted_label,
            "agreement": agreement,
            "provider_error": provider_error,
            "deterministic_label": deterministic_label,
            "deterministic_reason_code": deterministic_reason,
        }

    expected_summary = {
        **global_counts,
        "per_rule": {rule_id: counts for rule_id, counts in sorted(per_rule_counts.items())},
    }
    summary = _attestation_mapping(
        document.get("summary"),
        _ATTESTATION_SUMMARY_FIELDS,
        location="candidate attestations.summary",
    )
    _validate_attestation_summary_counts(summary, location="candidate attestations.summary")
    if dict(summary) != expected_summary:
        raise CelPromotionAuditError("candidate attestation summary does not match recomputed results")
    evidence_sha256 = _attestation_sha256(
        document.get("evidence_sha256"),
        location="candidate attestations.evidence_sha256",
    )
    if evidence_sha256 != _candidate_attestation_bundle_sha256(document):
        raise CelPromotionAuditError("candidate attestation evidence hash does not match canonical content")
    return {
        "status": "complete",
        "label_source": label_source,
        "evidence_sha256": evidence_sha256,
        "counts": expected_summary,
        "candidate_results": candidate_results,
        "covered_rule_ids": sorted(cast(Mapping[str, Any], expected_requirements["by_rule"])),
    }


def validate_candidate_attestation_bundle(
    value: Mapping[str, Any],
    *,
    expected_binding: Mapping[str, Any],
    expected_requirements: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate an exact rawless schema-v1 bundle against one shadow audit."""

    return _validate_candidate_attestation_bundle(
        value,
        expected_binding=expected_binding,
        expected_requirements=expected_requirements,
    )


def _scoped_attestation_requirements(
    value: Mapping[str, Any],
    all_requirements: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Resolve a supplied bundle to complete, explicitly declared rule scopes."""

    top_fields = frozenset(
        {
            "schema_version",
            "purpose",
            "label_source",
            "binding",
            "adjudicator",
            "candidates",
            "summary",
            "evidence_sha256",
        }
    )
    document = _attestation_mapping(value, top_fields, location="candidate attestations")
    binding = _attestation_mapping(
        document.get("binding"),
        _ATTESTATION_BINDING_FIELDS,
        location="candidate attestations.binding",
    )
    declared_expressions = binding.get("rule_expression_sha256")
    all_expressions = all_requirements.get("rule_expression_sha256")
    if (
        not isinstance(declared_expressions, Mapping)
        or not declared_expressions
        or len(declared_expressions) > 1_024
        or not isinstance(all_expressions, Mapping)
    ):
        raise CelPromotionAuditError("candidate attestation rule scope is empty or invalid")
    for rule_id, expression_hash in declared_expressions.items():
        if not isinstance(rule_id, str) or all_expressions.get(rule_id) != expression_hash:
            raise CelPromotionAuditError("candidate attestation rule scope is unknown or stale")
    scoped = scoped_candidate_attestation_requirements(
        all_requirements,
        list(declared_expressions),
    )
    if scoped["rule_expression_sha256"] != dict(declared_expressions):
        raise CelPromotionAuditError("candidate attestation rule scope expression identity is invalid")
    return scoped


def scoped_candidate_attestation_requirements(
    all_requirements: Mapping[str, Any],
    rule_ids: Sequence[str],
) -> Mapping[str, Any]:
    """Return the complete authoritative candidate set for declared rules."""

    if (
        isinstance(rule_ids, (str, bytes))
        or not rule_ids
        or len(rule_ids) > 1_024
        or any(not isinstance(rule_id, str) or not rule_id for rule_id in rule_ids)
        or len(set(rule_ids)) != len(rule_ids)
    ):
        raise CelPromotionAuditError("candidate attestation rule scope is empty or invalid")
    all_by_rule = all_requirements.get("by_rule")
    all_candidates = all_requirements.get("candidates")
    if not isinstance(all_by_rule, Mapping) or not isinstance(all_candidates, Mapping):
        raise CelPromotionAuditError("candidate attestation requirements are invalid")
    scoped_candidates: dict[str, Mapping[str, Any]] = {}
    for rule_id in rule_ids:
        if rule_id not in all_by_rule:
            raise CelPromotionAuditError("candidate attestation rule scope is unknown or empty")
        rule_scope = all_by_rule[rule_id]
        if not isinstance(rule_scope, Mapping):
            raise CelPromotionAuditError("shadow candidate attestation rule scope is invalid")
        candidate_ids = rule_scope.get("candidate_identity_sha256")
        if not isinstance(candidate_ids, list) or not candidate_ids:
            raise CelPromotionAuditError("shadow candidate attestation rule scope is empty")
        for candidate_id in candidate_ids:
            if not isinstance(candidate_id, str) or candidate_id not in all_candidates:
                raise CelPromotionAuditError("shadow candidate attestation rule scope is incomplete")
            scoped_candidates[candidate_id] = cast(Mapping[str, Any], all_candidates[candidate_id])
    return _finalize_attestation_requirements(scoped_candidates)


def _validated_attestation_requirements_from_promotion(
    promotion: Mapping[str, Any],
    generation: Mapping[str, Any],
) -> Mapping[str, Any]:
    raw = promotion.get("malicious_blocking_candidate_attestation_requirements")
    fields = {
        "candidate_count",
        "candidate_set_sha256",
        "membership_sha256",
        "rule_expression_sha256",
        "by_rule",
        "candidates",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise CelPromotionAuditError("shadow promotion evidence lacks exact candidate attestation requirements")
    candidates = raw.get("candidates")
    if not isinstance(candidates, Mapping) or len(candidates) > 16_384:
        raise CelPromotionAuditError("shadow candidate attestation requirement set is invalid")
    generation_rules = cast(Mapping[str, Mapping[str, Any]], generation["rules"])
    normalized: dict[str, Mapping[str, Any]] = {}
    for candidate_id, candidate in candidates.items():
        if (
            not isinstance(candidate_id, str)
            or not isinstance(candidate, Mapping)
            or set(candidate) != _ATTESTATION_CANDIDATE_BINDING_FIELDS
            or candidate.get("candidate_identity_sha256") != candidate_id
        ):
            raise CelPromotionAuditError("shadow candidate attestation requirement identity is invalid")
        sample_id = candidate.get("sample_id")
        rule_id = candidate.get("rule_id")
        if (
            not isinstance(sample_id, str)
            or not sample_id
            or not isinstance(rule_id, str)
            or rule_id not in generation_rules
            or candidate.get("expression_sha256") != generation_rules[rule_id]["expression_hash"]
            or candidate.get("severity") not in _BLOCKING_SEVERITIES
            or _sample_id_sha256(sample_id) != candidate.get("sample_id_sha256")
        ):
            raise CelPromotionAuditError("shadow candidate attestation requirement binding is invalid")
        for field in (
            "candidate_identity_sha256",
            "normalized_finding_identity_sha256",
            "sample_id_sha256",
            "sample_content_sha256",
            "source_evidence_sha256",
            "file_path_sha256",
            "expression_sha256",
            "lineage_identity_sha256",
        ):
            _attestation_sha256(candidate.get(field), location=f"shadow requirement {candidate_id}.{field}")
        for field in (
            "sample_id",
            "rule_id",
            "severity",
            "category",
            "analyzer",
            "evidence_value_class",
            "context_kind",
        ):
            _attestation_string(candidate.get(field), location=f"shadow requirement {candidate_id}.{field}")
        for field in ("line_number", "lineage_ordinal", "lineage_count"):
            number = candidate.get(field)
            if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                raise CelPromotionAuditError(f"shadow requirement {candidate_id}.{field} is invalid")
        if candidate["lineage_count"] <= 0 or candidate["lineage_ordinal"] >= candidate["lineage_count"]:
            raise CelPromotionAuditError(f"shadow requirement {candidate_id} has invalid lineage bounds")
        if _candidate_attestation_identity(candidate) != candidate_id:
            raise CelPromotionAuditError("shadow candidate attestation requirement identity is invalid")
        normalized[candidate_id] = candidate
    recomputed = _finalize_attestation_requirements(normalized)
    if dict(raw) != recomputed:
        raise CelPromotionAuditError("shadow candidate attestation requirement aggregate is not canonical")
    return raw


def _apply_candidate_attestation_eligibility(
    per_rule: Mapping[str, Any],
    requirements: Mapping[str, Any],
    validation: Mapping[str, Any],
    *,
    aggregate_no_regression: bool,
) -> dict[str, Any]:
    copied = cast(dict[str, Any], json.loads(json.dumps(per_rule, ensure_ascii=False)))
    by_rule = cast(Mapping[str, Mapping[str, Any]], requirements["by_rule"])
    candidate_results = cast(Mapping[str, Mapping[str, Any]], validation.get("candidate_results", {}))
    validation_status = validation.get("status")
    raw_covered_rules = validation.get("covered_rule_ids", [])
    covered_rules = set(cast(Sequence[str], raw_covered_rules))
    for rule_id, rule in sorted(copied.items()):
        expected = by_rule.get(rule_id)
        expected_ids = [] if expected is None else cast(list[str], expected["candidate_identity_sha256"])
        results = [
            candidate_results[candidate_id] for candidate_id in expected_ids if candidate_id in candidate_results
        ]
        accepted_benign = sum(result["accepted_label"] == "benign_non_actionable" for result in results)
        actionable = sum(result["accepted_label"] == "actionable" for result in results)
        ambiguous = sum(result["accepted_label"] == "ambiguous" for result in results)
        abstained = sum(result["accepted_label"] == "abstain" for result in results)
        disagreements = sum(result["agreement"] is not True for result in results)
        provider_errors = sum(result["provider_error"] is True for result in results)
        deterministic_disqualifying = sum(
            result.get("deterministic_label") != "benign_non_actionable" for result in results
        )
        rule_covered = rule_id in covered_rules
        complete_benign_attestation = (
            validation_status in {"complete", "complete_scoped"}
            and rule_covered
            and len(results) == len(expected_ids)
            and accepted_benign == len(expected_ids)
            and actionable == 0
            and ambiguous == 0
            and abstained == 0
            and disagreements == 0
            and provider_errors == 0
            and deterministic_disqualifying == 0
        )
        attestation_required = bool(expected_ids)
        if not attestation_required:
            attestation_status = "not_required"
        elif not rule_covered or validation_status not in {"complete", "complete_scoped"}:
            attestation_status = "not_supplied"
        elif complete_benign_attestation:
            attestation_status = "complete_benign_non_actionable"
        else:
            attestation_status = "complete_disqualifying_labels"

        benign = cast(Mapping[str, Any], rule["benign"])
        malicious = cast(Mapping[str, Any], rule["malicious"])
        benign_package = cast(Mapping[str, Any], benign["counterfactual_single_rule_enforcement"])
        malicious_package = cast(Mapping[str, Any], malicious["counterfactual_single_rule_enforcement"])
        malicious_blocking_findings = cast(
            Mapping[str, Any], malicious["counterfactual_finding_classification"]["blocking"]
        )
        zero_package_losses = all(
            cast(Mapping[str, Any], malicious_package[field])["delta"] == 0
            and cast(Mapping[str, Any], malicious_package[field])["exact"] is True
            for field in ("packages_with_findings", "blocked_packages", "signal_packages")
        )
        blocking_finding_safe = (attestation_required and complete_benign_attestation) or (
            not attestation_required
            and cast(Mapping[str, Any], malicious_blocking_findings["known_lost"])["count"] == 0
            and cast(Mapping[str, Any], malicious_blocking_findings["indeterminate"])["count"] == 0
            and malicious_blocking_findings["exact"] is True
        )
        eligible = (
            rule["coverage_status"] == "evaluated"
            and rule["decisions"]["fallback"] == 0
            and rule["error_counts"] == {}
            and benign_package["targeted_benign_actionable_packages"] > 0
            and benign_package["relative_actionable_package_reduction_lower_bound"] >= 0.20
            and zero_package_losses
            and blocking_finding_safe
            and aggregate_no_regression
        )
        rule["pre_attestation_potentially_promotable"] = rule["potentially_promotable_from_this_audit"]
        rule["potentially_promotable_from_this_audit"] = eligible
        rule["malicious_blocking_candidate_attestation"] = {
            "required": attestation_required,
            "status": attestation_status,
            "expected_candidate_count": len(expected_ids),
            "expected_candidate_set_sha256": _candidate_set_sha256(set(expected_ids)),
            "attested_candidate_count": len(results),
            "accepted_benign_non_actionable": accepted_benign,
            "actionable": actionable,
            "ambiguous": ambiguous,
            "abstained": abstained,
            "disagreements": disagreements,
            "provider_errors": provider_errors,
            "deterministic_disqualifying": deterministic_disqualifying,
        }
        rule["promotion_checks"] = {
            "zero_malicious_package_block_signal_loss": zero_package_losses,
            "malicious_blocking_findings_safe_or_attested": blocking_finding_safe,
            "aggregate_recall_macro_f1_no_regression": aggregate_no_regression,
        }
    return copied


def _detection_output_sha256(outcomes: Mapping[str, Any]) -> str:
    """Hash detection outputs while excluding CEL-only observational data."""

    normalized: dict[str, Any] = {}
    for benchmark_id, raw in sorted(outcomes.items()):
        if not isinstance(benchmark_id, str) or not isinstance(raw, Mapping):
            raise CelPromotionAuditError("sample outcomes contain an invalid entry")
        findings = raw.get("findings")
        if not isinstance(findings, list):
            raise CelPromotionAuditError("sample outcome findings must be an array")
        if any(not isinstance(finding, Mapping) for finding in findings):
            raise CelPromotionAuditError("sample outcome contains an invalid finding")
        normalized[benchmark_id] = {
            key: value for key, value in raw.items() if key not in {"cel_suppressed", "findings"}
        }
        normalized[benchmark_id]["findings"] = [
            {key: value for key, value in finding.items() if key not in {"cel_decision", "cel_decisions"}}
            for finding in cast(list[Mapping[str, Any]], findings)
        ]
    return hashlib.sha256(
        b"skill-scanner-cel-promotion-detection-output-v1\0" + _canonical_bytes(normalized)
    ).hexdigest()


def _run_population(
    snapshot: FrozenSnapshot,
    population: DevelopmentPopulation,
    *,
    scanner: _Scanner,
    cel_mode: CelMode,
    generation: Mapping[str, Any],
) -> dict[str, Any]:
    counts = _empty_counts()
    errors: list[dict[str, str]] = []
    accumulators = {
        rule_id: _blank_rule_accumulator(identity)
        for rule_id, identity in cast(Mapping[str, Mapping[str, str]], generation["rules"]).items()
    }
    baseline_packages: dict[str, dict[str, set[str]]] = {
        label: {field: set() for field in ("with_findings", "blocked", "actionable", "signal")}
        for label in ("benign", "malicious")
    }
    attestation_requirements: dict[str, dict[str, Any]] = {}
    try:
        for sample in population.samples:
            sample_path = snapshot.root.joinpath(*sample.relative_path.parts)
            try:
                result = scanner.scan_skill(sample_path)
            except Exception as exc:
                errors.append({"benchmark_id": sample.benchmark_id, "error": str(exc)})
                _record_scan_error(counts, sample)
                continue
            loader = recognize_loader_disposition(result)
            _record_sample(
                counts,
                sample,
                result,
                expected_cel_mode=cel_mode,
                loader_recovery=loader.recovery,
                loader_rejection=loader.rejection,
            )
            content_sha256 = _sample_content_sha256(sample_path) if cel_mode is CelMode.SHADOW else None
            _accumulate_sample_incidence(
                accumulators,
                baseline_packages,
                sample,
                result,
                attestation_requirements=attestation_requirements,
                sample_content_sha256=content_sha256,
            )
    finally:
        close = getattr(scanner, "close", None)
        if callable(close):
            close()

    finalized = _finalize_counts(counts)
    track: dict[str, Any] = {
        "name": TRACK_NAME,
        "detector_profile": "core_only",
        "protocol": SELECTION_POLICY,
        "partition": "train_validation_intersection",
        "population_sha256": population.population_sha256,
        "status": "passed" if not errors and finalized["samples"] == population.usable_samples else "failed",
        **finalized,
        "per_source": {},
        "per_structural_family": {},
        "per_category": {},
        "errors": errors,
    }
    track["promotion_audit"] = {
        "baseline_package_counts": {
            label: {field: len(values) for field, values in sorted(fields.items())}
            for label, fields in sorted(baseline_packages.items())
        },
        "per_rule": _finalize_rule_incidence(accumulators, baseline_packages, track),
        "malicious_blocking_candidate_attestation_requirements": _finalize_attestation_requirements(
            attestation_requirements
        ),
    }
    track["detection_output_sha256"] = _detection_output_sha256(track["sample_outcomes"])
    return track


def run_worker_report(
    snapshot_dir: Path,
    *,
    dataset_id: str,
    dataset_lock: Path,
    cel_mode: CelMode | str,
    expected_rule_count: int = DEFAULT_EXPECTED_RULE_COUNT,
    scanner_factory: Callable[[str, CelMode], Any] = _default_scanner_factory,
) -> dict[str, Any]:
    """Run one fully validated OFF or SHADOW development worker."""

    mode = CelMode(cel_mode)
    if mode not in {CelMode.OFF, CelMode.SHADOW}:
        raise CelPromotionAuditError("promotion audit workers support only off or shadow mode")
    snapshot = load_frozen_snapshot(snapshot_dir, dataset_id=dataset_id, dataset_lock=dataset_lock)
    population = select_joint_train_validation(snapshot)
    start_producer = _producer_components()
    if _SOURCE_REVISION_RE.fullmatch(start_producer["source_revision"]) is None:
        raise CelPromotionAuditError(
            "promotion audit requires SKILL_SCANNER_SOURCE_REVISION or GITHUB_SHA as one exact commit SHA"
        )
    start_harness_sha256 = _audit_harness_sha256()
    scanner = scanner_factory("core_only", mode)
    try:
        generation = _generation_from_scanner(scanner, expected_rule_count=expected_rule_count)
    except Exception:
        close = getattr(scanner, "close", None)
        if callable(close):
            close()
        raise
    track = _run_population(
        snapshot,
        population,
        scanner=scanner,
        cel_mode=mode,
        generation=generation,
    )

    end_snapshot = load_frozen_snapshot(snapshot_dir, dataset_id=dataset_id, dataset_lock=dataset_lock)
    end_population = select_joint_train_validation(end_snapshot)
    end_producer = _producer_components()
    end_harness_sha256 = _audit_harness_sha256()
    drifted = sorted(
        {
            *(["snapshot"] if end_snapshot != snapshot else []),
            *(["population"] if end_population != population else []),
            *(field for field, value in start_producer.items() if end_producer.get(field) != value),
            *(["audit_harness_sha256"] if end_harness_sha256 != start_harness_sha256 else []),
        }
    )
    if drifted:
        track["errors"].append(
            {"benchmark_id": "__audit_identity__", "error": f"audit identity changed: {', '.join(drifted)}"}
        )
        track["status"] = "failed"
    evidence_identity, producer = _evidence_identity(snapshot, [track], mode, start_producer)
    errors = list(track["errors"])
    return {
        "schema_version": 1,
        "status": "passed" if track["status"] == "passed" and not drifted else "failed",
        "profile": AUDIT_PROFILE,
        "release_blocking": False,
        "worker_invocation_id": secrets.token_hex(16),
        "cel_mode": mode.value,
        "evidence_identity": evidence_identity,
        "producer": producer,
        "audit_harness_sha256": start_harness_sha256,
        "identity_verification": {
            "status": "passed" if not drifted else "failed",
            "drifted_fields": drifted,
            "start": {"snapshot_sha256": snapshot.artifact_manifest_sha256, **start_producer},
            "end": {"snapshot_sha256": end_snapshot.artifact_manifest_sha256, **end_producer},
            "errors": [] if not drifted else [f"audit identity changed: {', '.join(drifted)}"],
        },
        "dataset": {
            "id": str(snapshot.dataset["id"]),
            "revision": str(snapshot.dataset["revision"]),
            "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
            "sample_metadata_manifest_sha256": snapshot.sample_metadata_manifest_sha256,
            "usable_artifact_manifest_sha256": snapshot.usable_artifact_manifest_sha256,
            "quarantine_manifest_sha256": snapshot.quarantine_manifest_sha256,
            "selection": population.to_dict(),
        },
        "cel_generation": generation,
        "tracks": {TRACK_NAME: track},
        "summary": _summary([track]),
        "errors": errors,
        "limitations": [
            "Dataset labels are package labels, not finding-level truth labels.",
            "Candidate incidence is reported separately from final package-classification deltas.",
            "Mixed-lineage normalized severities are reported as bounded indeterminate effects and block promotion.",
            "CEL timing is truthful only for the complete layer; batched evaluation is not allocated per rule.",
            "This joint train/validation audit is non-release evidence and excludes both sealed test protocols.",
        ],
    }


def compact_audit_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Compact one worker without mislabeling it as release evidence."""

    compact = compact_release_report(report)
    release_metadata = compact.pop("release_evidence")
    compact["audit_evidence"] = {
        **release_metadata,
        "purpose": "cel_shadow_promotion_development_audit",
        "release_blocking": False,
    }
    return compact


def _timing_summary(report: Mapping[str, Any], *, run_index: int) -> dict[str, Any]:
    summary = report.get("summary")
    if not isinstance(summary, Mapping):
        raise CelPromotionAuditError("worker report lacks a summary")
    cel = summary.get("cel")
    if not isinstance(cel, Mapping):
        raise CelPromotionAuditError("worker report lacks CEL timing")
    values = {
        "p95_scan_latency_ms": summary.get("p95_scan_latency_ms"),
        "cel_time_ratio": summary.get("cel_time_ratio"),
        "cel_elapsed_ms": cel.get("elapsed_ms"),
        "cel_projection_ms": cel.get("projection_ms"),
        "cel_evaluation_ms": cel.get("evaluation_ms"),
    }
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
        for value in values.values()
    ):
        raise CelPromotionAuditError("worker report contains invalid timing")
    return {
        "run_index": run_index,
        **{key: float(cast(int | float, value)) for key, value in values.items()},
    }


def assemble_audit_summary(
    baseline: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    *,
    expected_rule_count: int = DEFAULT_EXPECTED_RULE_COUNT,
    candidate_attestations: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one OFF + five SHADOW reports and return a bounded summary."""

    if len(candidates) != REQUIRED_SHADOW_RUNS:
        raise CelPromotionAuditError(f"promotion audit requires exactly {REQUIRED_SHADOW_RUNS} shadow reports")
    reports = [baseline, *candidates]
    generations: list[Mapping[str, Any]] = []
    rule_sets: list[frozenset[str]] = []
    promotions: list[Mapping[str, Any]] = []
    selections: list[Mapping[str, Any]] = []
    invocation_ids: list[str] = []
    for index, report in enumerate(reports):
        expected_mode = CelMode.OFF.value if index == 0 else CelMode.SHADOW.value
        if (
            report.get("status") != "passed"
            or report.get("errors") != []
            or report.get("profile") != AUDIT_PROFILE
            or report.get("release_blocking") is not False
            or report.get("cel_mode") != expected_mode
        ):
            raise CelPromotionAuditError(f"worker[{index}] is not one clean {expected_mode} development report")
        audit_evidence = report.get("audit_evidence")
        if (
            not isinstance(audit_evidence, Mapping)
            or audit_evidence.get("format") != "compact-v3"
            or audit_evidence.get("purpose") != "cel_shadow_promotion_development_audit"
            or audit_evidence.get("release_blocking") is not False
        ):
            raise CelPromotionAuditError(f"worker[{index}] is not compact-v3 development evidence")
        producer = report.get("producer")
        source_revision = producer.get("source_revision") if isinstance(producer, Mapping) else None
        if not isinstance(source_revision, str) or _SOURCE_REVISION_RE.fullmatch(source_revision) is None:
            raise CelPromotionAuditError(f"worker[{index}] lacks one exact source revision")
        invocation_id = report.get("worker_invocation_id")
        if not isinstance(invocation_id, str) or _WORKER_INVOCATION_RE.fullmatch(invocation_id) is None:
            raise CelPromotionAuditError(f"worker[{index}] lacks one valid invocation identity")
        invocation_ids.append(invocation_id)
        generation, rule_ids = _validated_report_generation(
            report,
            location=f"worker[{index}]",
            expected_rule_count=expected_rule_count,
        )
        generations.append(generation)
        rule_sets.append(rule_ids)
        promotions.append(
            _validated_promotion_incidence(
                report,
                generation,
                rule_ids,
                location=f"worker[{index}]",
            )
        )
        dataset = report.get("dataset")
        selection = dataset.get("selection") if isinstance(dataset, Mapping) else None
        if not isinstance(selection, Mapping):
            raise CelPromotionAuditError(f"worker[{index}] lacks a development population identity")
        selections.append(selection)
    if len(set(invocation_ids)) != len(invocation_ids):
        raise CelPromotionAuditError("promotion audit workers must have unique invocation identities")

    baseline_generation = generations[0]
    baseline_selection = selections[0]
    candidate_generation = generations[1]
    candidate_selection = selections[1]
    if baseline_generation != candidate_generation:
        raise CelPromotionAuditError("OFF and SHADOW workers used different CEL generations")
    if rule_sets[0] != rule_sets[1]:
        raise CelPromotionAuditError("OFF and SHADOW workers used different CEL rule identity sets")
    if baseline_selection != candidate_selection:
        raise CelPromotionAuditError("OFF and SHADOW workers used different development populations")
    for index, (generation, rule_ids, selection) in enumerate(
        zip(generations[2:], rule_sets[2:], selections[2:], strict=True),
        start=2,
    ):
        if generation != candidate_generation or rule_ids != rule_sets[1]:
            raise CelPromotionAuditError(f"shadow worker[{index}] changed the CEL generation")
        if selection != candidate_selection:
            raise CelPromotionAuditError(f"shadow worker[{index}] changed the development population")
    harness_hashes = [report.get("audit_harness_sha256") for report in reports]
    current_harness_sha256 = _audit_harness_sha256()
    if (
        any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in harness_hashes
        )
        or len(set(harness_hashes)) != 1
        or harness_hashes[0] != current_harness_sha256
    ):
        raise CelPromotionAuditError("OFF, SHADOW, and assembler used different or invalid audit harnesses")

    comparison = compare_repeated_benchmark_reports(
        baseline,
        candidates,
        require_rule_promotion_evidence=False,
    )
    fingerprints = cast(list[str], comparison["stability_fingerprints"])
    promotion = promotions[1]
    per_rule = promotion.get("per_rule")
    if not isinstance(per_rule, Mapping):
        raise CelPromotionAuditError("shadow promotion incidence is invalid")
    for index, other_promotion in enumerate(promotions[2:], start=2):
        if other_promotion != promotion:
            raise CelPromotionAuditError(f"shadow worker[{index}] changed per-rule promotion incidence")
    attestation_requirements = _validated_attestation_requirements_from_promotion(
        promotion,
        candidate_generation,
    )
    complete_attestation_binding = _candidate_attestation_expected_binding(
        candidates[0],
        candidate_generation,
        attestation_requirements,
    )
    scoped_attestation_requirements: Mapping[str, Any] | None = None
    scoped_attestation_binding: Mapping[str, Any] | None = None
    if candidate_attestations is None:
        expected_candidate_count = cast(int, attestation_requirements["candidate_count"])
        attestation_validation: Mapping[str, Any] = {
            "status": "not_required" if expected_candidate_count == 0 else "not_supplied",
            "label_source": None,
            "evidence_sha256": None,
            "counts": {**_empty_attestation_counts(), "per_rule": {}},
            "candidate_results": {},
            "covered_rule_ids": [],
        }
    else:
        scoped_attestation_requirements = _scoped_attestation_requirements(
            candidate_attestations,
            attestation_requirements,
        )
        scoped_attestation_binding = _candidate_attestation_expected_binding(
            candidates[0],
            candidate_generation,
            scoped_attestation_requirements,
        )
        validated_bundle = _validate_candidate_attestation_bundle(
            candidate_attestations,
            expected_binding=scoped_attestation_binding,
            expected_requirements=scoped_attestation_requirements,
        )
        attestation_validation = {
            **validated_bundle,
            "status": (
                "complete"
                if scoped_attestation_requirements["candidate_count"] == attestation_requirements["candidate_count"]
                else "complete_scoped"
            ),
        }

    detection_hashes = [
        cast(Mapping[str, Any], cast(Mapping[str, Any], report["tracks"])[TRACK_NAME])["detection_output_sha256"]
        for report in reports
    ]
    detection_identity = len(set(detection_hashes)) == 1
    candidate_summaries = [cast(Mapping[str, Any], candidate["summary"]) for candidate in candidates]
    zero_runtime_failures = all(
        summary.get("cel_fallbacks") == 0
        and summary.get("scan_errors") == 0
        and isinstance(summary.get("cel"), Mapping)
        and cast(Mapping[str, Any], summary["cel"]).get("projection_incomplete") == 0
        and cast(Mapping[str, Any], summary["cel"]).get("error_counts") == {}
        for summary in candidate_summaries
    )
    baseline_timing = _timing_summary(baseline, run_index=0)
    shadow_timing = [_timing_summary(candidate, run_index=index) for index, candidate in enumerate(candidates, 1)]
    worst_shadow_p95 = max(run["p95_scan_latency_ms"] for run in shadow_timing)
    latency_limit = baseline_timing["p95_scan_latency_ms"] * 1.10
    latency_passed = worst_shadow_p95 <= latency_limit + 1e-12
    cel_share_passed = max(run["cel_time_ratio"] for run in shadow_timing) <= 0.05 + 1e-12
    runtime_safety = [
        {
            "run_index": index,
            "scan_errors": summary.get("scan_errors"),
            "cel_fallbacks": summary.get("cel_fallbacks"),
            "projection_incomplete": cast(Mapping[str, Any], summary["cel"]).get("projection_incomplete"),
            "error_counts": cast(Mapping[str, Any], summary["cel"]).get("error_counts"),
        }
        for index, summary in enumerate(candidate_summaries, 1)
    ]
    checks = {
        "five_stable_shadow_outputs": comparison.get("stable_output") is True and len(set(fingerprints)) == 1,
        "same_evidence_identity": comparison.get("same_evidence_identity") is True,
        "same_producer_identity": comparison.get("same_producer_identity") is True,
        "off_shadow_detection_output_identity": detection_identity,
        "zero_scan_cel_fallback_incomplete_or_errors": zero_runtime_failures,
        "p95_latency_within_ten_percent": latency_passed,
        "cel_time_within_five_percent": cel_share_passed,
        "comparison_passed": comparison.get("status") == "passed",
    }
    metric_names = (
        "recall",
        "package_block_recall",
        "signal_recall",
        "macro_f1",
        "benign_actionable_fpr",
    )
    baseline_metrics = {field: cast(Mapping[str, Any], baseline["summary"]).get(field) for field in metric_names}
    shadow_metrics = {field: candidate_summaries[0].get(field) for field in metric_names}
    metric_deltas = {
        field: float(cast(int | float, shadow_metrics[field])) - float(cast(int | float, baseline_metrics[field]))
        for field in metric_names
    }
    aggregate_no_regression = all(
        metric_deltas[field] >= -1e-12 for field in ("recall", "package_block_recall", "signal_recall", "macro_f1")
    )
    checks["aggregate_recall_and_macro_f1_no_regression"] = aggregate_no_regression
    per_rule_with_attestations = _apply_candidate_attestation_eligibility(
        per_rule,
        attestation_requirements,
        attestation_validation,
        aggregate_no_regression=aggregate_no_regression,
    )
    attestation_counts = cast(Mapping[str, Any], attestation_validation["counts"])
    scoped_requirement_summary = (
        {
            "candidate_count": 0,
            "candidate_set_sha256": _candidate_set_sha256(set()),
            "membership_sha256": _identifier_set_sha256(
                set(),
                namespace=b"skill-scanner-cel-malicious-blocking-candidate-membership-v1",
            ),
            "rule_expression_sha256": {},
            "binding_sha256": None,
        }
        if scoped_attestation_requirements is None or scoped_attestation_binding is None
        else {
            "candidate_count": scoped_attestation_requirements["candidate_count"],
            "candidate_set_sha256": scoped_attestation_requirements["candidate_set_sha256"],
            "membership_sha256": scoped_attestation_requirements["membership_sha256"],
            "rule_expression_sha256": scoped_attestation_requirements["rule_expression_sha256"],
            "binding_sha256": _domain_sha256(
                b"skill-scanner-cel-candidate-attestation-binding-v1",
                scoped_attestation_binding,
            ),
        }
    )
    attestation_summary = {
        "status": attestation_validation["status"],
        "label_source": attestation_validation["label_source"],
        "evidence_sha256": attestation_validation["evidence_sha256"],
        "expected_candidate_count": attestation_requirements["candidate_count"],
        "candidate_set_sha256": attestation_requirements["candidate_set_sha256"],
        "membership_sha256": attestation_requirements["membership_sha256"],
        "rule_expression_sha256": attestation_requirements["rule_expression_sha256"],
        "complete_requirement_binding_sha256": _domain_sha256(
            b"skill-scanner-cel-candidate-attestation-binding-v1",
            complete_attestation_binding,
        ),
        "supplied_scope": scoped_requirement_summary,
        "counts": dict(attestation_counts),
    }
    worker_report_hashes = [
        hashlib.sha256(b"skill-scanner-cel-promotion-worker-v1\0" + _canonical_bytes(report)).hexdigest()
        for report in reports
    ]
    summary = {
        "schema_version": 1,
        "status": "passed" if all(checks.values()) else "failed",
        "purpose": "cel_shadow_promotion_development_audit",
        "release_blocking": False,
        "dataset": cast(Mapping[str, Any], candidates[0]["dataset"]),
        "producer": candidates[0]["producer"],
        "evidence_identity": candidates[0]["evidence_identity"],
        "cel_generation": candidate_generation,
        "audit_harness_sha256": harness_hashes[0],
        "runs": {"off": 1, "shadow": REQUIRED_SHADOW_RUNS},
        "checks": checks,
        "stability": {
            "fingerprints": fingerprints,
            "worker_invocation_ids": invocation_ids,
            "detection_output_sha256": detection_hashes[0] if detection_identity else None,
            "off_worker_report_sha256": worker_report_hashes[0],
            "shadow_worker_report_sha256": worker_report_hashes[1:],
        },
        "timing": {
            "off": baseline_timing,
            "shadow": shadow_timing,
            "worst_shadow_p95_ms": worst_shadow_p95,
            "p95_latency_limit_ms": latency_limit,
            "max_shadow_cel_time_ratio": max(run["cel_time_ratio"] for run in shadow_timing),
        },
        "runtime_safety": runtime_safety,
        "global_metrics": {
            "baseline": baseline_metrics,
            "shadow": shadow_metrics,
            "shadow_minus_baseline": metric_deltas,
        },
        "candidate_attestations": attestation_summary,
        "per_rule": per_rule_with_attestations,
        "limitations": candidates[0].get("limitations", []),
    }
    if len(_canonical_bytes(summary)) > _MAX_SUMMARY_BYTES:
        raise CelPromotionAuditError(f"canonical promotion audit summary exceeds {_MAX_SUMMARY_BYTES} bytes")
    return summary


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CelPromotionAuditError(f"JSON input contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise CelPromotionAuditError(f"JSON input contains non-finite number {value}")


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise CelPromotionAuditError("JSON input exceeds the nesting limit")
    if isinstance(value, Mapping):
        for item in value.values():
            _json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _json_depth(item, depth + 1)
    return depth


def _read_json(path: Path, *, max_bytes: int = _MAX_WORKER_REPORT_BYTES) -> Mapping[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise CelPromotionAuditError(f"JSON input must be a regular non-symlink file: {source}")
    size = source.stat(follow_symlinks=False).st_size
    if size > max_bytes:
        raise CelPromotionAuditError(f"JSON input exceeds {max_bytes} bytes: {source}")
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CelPromotionAuditError(f"cannot read JSON input {source}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise CelPromotionAuditError(f"JSON input root must be an object: {source}")
    _json_depth(value)
    return value


def _write_json_new(path: Path, value: Mapping[str, Any], *, max_bytes: int) -> None:
    payload = _canonical_bytes(value) + b"\n"
    if len(payload) > max_bytes:
        raise CelPromotionAuditError(f"canonical JSON output exceeds {max_bytes} bytes")
    destination = Path(path)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise CelPromotionAuditError("JSON output parent must be an existing non-symlink directory")
    if destination.exists() or destination.is_symlink():
        raise CelPromotionAuditError(f"JSON output must be a new path: {destination}")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _run_workers(args: argparse.Namespace) -> int:
    candidate_attestations = (
        None
        if args.candidate_attestations is None
        else _read_json(args.candidate_attestations, max_bytes=_MAX_ATTESTATION_BUNDLE_BYTES)
    )
    output_dir = Path(args.output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise CelPromotionAuditError("output_dir must be a new non-symlink path")
    if not output_dir.parent.is_dir() or output_dir.parent.is_symlink():
        raise CelPromotionAuditError("output_dir parent must be an existing non-symlink directory")
    output_dir.mkdir(mode=0o700)
    script = Path(__file__).resolve(strict=True)
    common = [
        "--snapshot-dir",
        str(Path(args.snapshot_dir).resolve(strict=True)),
        "--dataset-id",
        args.dataset_id,
        "--dataset-lock",
        str(Path(args.dataset_lock).resolve(strict=True)),
        "--expected-rule-count",
        str(args.expected_rule_count),
    ]
    paths = [("off", output_dir / "off.json")]
    paths.extend(("shadow", output_dir / f"shadow-{index}.json") for index in range(1, REQUIRED_SHADOW_RUNS + 1))
    environment = dict(os.environ)
    for secret in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"):
        environment.pop(secret, None)
    environment.update(
        {
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "NO_PROXY": "*",
            "SKILL_SCANNER_DISABLE_NETWORK": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    for mode, path in paths:
        completed = subprocess.run(
            [sys.executable, "-I", str(script), "worker", *common, "--cel-mode", mode, "--output", str(path)],
            check=False,
            env=environment,
            text=True,
            capture_output=True,
        )
        if completed.returncode != 0:
            raise CelPromotionAuditError(
                f"{mode} worker failed with exit {completed.returncode}: {completed.stderr.strip()}"
            )
    baseline = _read_json(paths[0][1])
    candidates = [_read_json(path) for _mode, path in paths[1:]]
    summary = assemble_audit_summary(
        baseline,
        candidates,
        expected_rule_count=args.expected_rule_count,
        candidate_attestations=candidate_attestations,
    )
    _write_json_new(output_dir / "audit-summary.json", summary, max_bytes=_MAX_SUMMARY_BYTES)
    return 0 if summary["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a non-release joint train/validation CEL promotion audit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--snapshot-dir", type=Path, required=True)
        subparser.add_argument("--dataset-id", required=True)
        subparser.add_argument("--dataset-lock", type=Path, required=True)
        subparser.add_argument("--expected-rule-count", type=int, default=DEFAULT_EXPECTED_RULE_COUNT)

    worker = subparsers.add_parser("worker", help="run one isolated compact worker report")
    common(worker)
    worker.add_argument("--cel-mode", choices=(CelMode.OFF.value, CelMode.SHADOW.value), required=True)
    worker.add_argument("--output", type=Path, required=True)

    assemble = subparsers.add_parser("assemble", help="assemble one OFF and five SHADOW worker reports")
    assemble.add_argument("--baseline", type=Path, required=True)
    assemble.add_argument("--candidate", type=Path, action="append", required=True)
    assemble.add_argument(
        "--candidate-attestations",
        type=Path,
        help="optional strict per-candidate malicious HIGH/CRITICAL attestation bundle",
    )
    assemble.add_argument("--expected-rule-count", type=int, default=DEFAULT_EXPECTED_RULE_COUNT)
    assemble.add_argument("--output", type=Path, required=True)

    run = subparsers.add_parser("run", help="run six isolated workers and assemble a bounded audit")
    common(run)
    run.add_argument(
        "--candidate-attestations",
        type=Path,
        help="optional strict per-candidate malicious HIGH/CRITICAL attestation bundle",
    )
    run.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "worker":
            snapshot_root = args.snapshot_dir.resolve(strict=True)
            output = args.output.resolve(strict=False)
            if output == snapshot_root or output.is_relative_to(snapshot_root):
                raise CelPromotionAuditError("worker output must be outside the immutable snapshot")
            report = run_worker_report(
                args.snapshot_dir,
                dataset_id=args.dataset_id,
                dataset_lock=args.dataset_lock,
                cel_mode=args.cel_mode,
                expected_rule_count=args.expected_rule_count,
            )
            compact = compact_audit_report(report)
            _write_json_new(args.output, compact, max_bytes=_MAX_WORKER_REPORT_BYTES)
            return 0 if compact["status"] == "passed" else 1
        if args.command == "assemble":
            baseline = _read_json(args.baseline)
            candidates = [_read_json(path) for path in args.candidate]
            candidate_attestations = (
                None
                if args.candidate_attestations is None
                else _read_json(args.candidate_attestations, max_bytes=_MAX_ATTESTATION_BUNDLE_BYTES)
            )
            summary = assemble_audit_summary(
                baseline,
                candidates,
                expected_rule_count=args.expected_rule_count,
                candidate_attestations=candidate_attestations,
            )
            _write_json_new(args.output, summary, max_bytes=_MAX_SUMMARY_BYTES)
            return 0 if summary["status"] == "passed" else 1
        if args.command == "run":
            return _run_workers(args)
        raise CelPromotionAuditError(f"unsupported command: {args.command}")
    except (BenchmarkComparisonError, CelPromotionAuditError, PublicBenchmarkError) as exc:
        print(f"CEL promotion audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
