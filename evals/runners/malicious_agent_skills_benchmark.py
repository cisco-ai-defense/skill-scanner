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

"""Taxonomy and confirmed-positive recall reports for MaliciousAgentSkillsBench.

The 94k upstream ``safe`` rows never become scanner negatives here.  Static
recall accepts only separately materialized text packages whose case IDs have
external sandbox-behavior confirmation, and requires explicit de-overlap keys
from MaliciousSkillBench before scanning.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evals.datasets.malicious_agent_skills_bench import (
    DATASET_ID,
    MaliciousAgentCase,
    MaliciousAgentSkillsError,
    MaliciousAgentSkillsSnapshot,
)
from evals.datasets.quarantined_text import QuarantinedTextError, inspect_text_package

_ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONFIRMATION_KIND = "sandbox_behavior_confirmed"


class StaticSkillScanner(Protocol):
    """Minimal non-executing scanner interface."""

    def scan_skill(self, skill_directory: Path) -> Any: ...


@dataclass(frozen=True)
class SandboxConfirmedPackage:
    """Content-free binding from a MASB case to external sandbox evidence."""

    case_id: str
    package_directory: Path
    content_sha256: str
    normalized_content_sha256: str
    confirmation_kind: str
    confirmation_sha256: str


@dataclass(frozen=True)
class MaliciousAgentRecallOutcome:
    case_id: str
    source_id: str
    repository_id: str
    structural_family_id: str
    patterns: tuple[str, ...]
    finding_count: int
    actionable: bool
    analyzer_failures: tuple[str, ...]
    error_code: str | None


def _overlap_partition(
    snapshot: MaliciousAgentSkillsSnapshot,
    overlap_keys: Collection[str] | None,
) -> tuple[tuple[MaliciousAgentCase, ...], tuple[MaliciousAgentCase, ...], str]:
    if overlap_keys is None:
        return snapshot.malicious_cases, (), "not_evaluated"
    overlap = frozenset(overlap_keys)
    excluded = tuple(case for case in snapshot.malicious_cases if not overlap.isdisjoint(case.overlap_keys))
    eligible = tuple(case for case in snapshot.malicious_cases if overlap.isdisjoint(case.overlap_keys))
    return eligible, excluded, "applied"


def build_malicious_agent_taxonomy_report(
    snapshot: MaliciousAgentSkillsSnapshot,
    *,
    malicious_skill_bench_overlap_keys: Collection[str] | None = None,
) -> dict[str, Any]:
    """Report malicious taxonomy coverage without manufacturing benign gold."""

    eligible, excluded, overlap_status = _overlap_partition(snapshot, malicious_skill_bench_overlap_keys)
    pattern_counts = Counter(pattern for case in eligible for pattern in set(case.patterns))
    pattern_instance_counts = Counter(pattern for case in eligible for pattern in case.patterns)
    severity_counts = Counter(severity for case in eligible for severity in case.severities)
    source_counts = Counter(case.source_id for case in eligible)
    repository_counts = Counter(case.repository_id for case in eligible)
    family_counts = Counter(case.structural_family_id for case in eligible)
    return {
        "dataset_id": DATASET_ID,
        "revision": snapshot.revision,
        "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
        "artifact_manifest_pinned": snapshot.artifact_manifest_pinned,
        "status": "completed",
        "supplemental": True,
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "independent_metrics_eligible": overlap_status == "applied",
        "approved_uses": ["taxonomy_coverage", "case_mining", "sandbox_confirmed_recall"],
        "skills_metadata_population": snapshot.skills_population,
        "upstream_label_counts": dict(snapshot.label_counts),
        "safe_rows_used_as_benign": 0,
        "benign_gold_eligible": False,
        "benign_denominator": 0,
        "malicious_case_population": len(snapshot.malicious_cases),
        "duplicate_metadata_rows": snapshot.duplicate_metadata_rows,
        "deduplication": {
            "identity_format": "NFKC-casefold(source, repository, skill_name)",
            "duplicate_metadata_rows": snapshot.duplicate_metadata_rows,
            "unique_malicious_cases": len(snapshot.malicious_cases),
            "repository_grouping_required": True,
        },
        "malicious_skill_bench_deoverlap": {
            "status": overlap_status,
            "excluded_cases": len(excluded),
            "double_counted_cases": 0 if overlap_status == "applied" else None,
            "eligible_cases": len(eligible),
        },
        "per_pattern_case_count": dict(sorted(pattern_counts.items())),
        "per_pattern_instance_count": dict(sorted(pattern_instance_counts.items())),
        "per_severity_instance_count": dict(sorted(severity_counts.items())),
        "per_source": dict(sorted(source_counts.items())),
        "per_repository": dict(sorted(repository_counts.items())),
        "per_structural_family": dict(sorted(family_counts.items())),
        "provenance": {
            "dataset_revision": snapshot.revision,
            "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
            "case_identity_format": "masb-case-v1",
            "overlap_key_formats": ["identity", "repository", "url"],
        },
    }


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value)).upper()


def _validate_confirmation(record: SandboxConfirmedPackage) -> None:
    if not isinstance(record.case_id, str) or not record.case_id:
        raise MaliciousAgentSkillsError("confirmed package case_id must be non-empty")
    if record.confirmation_kind != _CONFIRMATION_KIND:
        raise MaliciousAgentSkillsError(
            f"confirmed package {record.case_id} must use confirmation_kind={_CONFIRMATION_KIND!r}"
        )
    for field, value in (
        ("content_sha256", record.content_sha256),
        ("normalized_content_sha256", record.normalized_content_sha256),
        ("confirmation_sha256", record.confirmation_sha256),
    ):
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise MaliciousAgentSkillsError(f"confirmed package {record.case_id}.{field} must be a lowercase SHA-256")
    if not isinstance(record.package_directory, Path):
        raise MaliciousAgentSkillsError(f"confirmed package {record.case_id}.package_directory must be a Path")


def _error_outcome(case: MaliciousAgentCase, error_code: str) -> MaliciousAgentRecallOutcome:
    return MaliciousAgentRecallOutcome(
        case_id=case.case_id,
        source_id=case.source_id,
        repository_id=case.repository_id,
        structural_family_id=case.structural_family_id,
        patterns=case.patterns,
        finding_count=0,
        actionable=False,
        analyzer_failures=(),
        error_code=error_code,
    )


def _scan_one(
    case: MaliciousAgentCase,
    record: SandboxConfirmedPackage,
    scanner: StaticSkillScanner,
) -> MaliciousAgentRecallOutcome:
    try:
        result = scanner.scan_skill(record.package_directory)
    except Exception as exc:  # confirmed malicious errors remain false negatives
        return _error_outcome(case, f"SCAN_EXCEPTION_{type(exc).__name__.upper()}")
    findings = tuple(getattr(result, "findings", ()) or ())
    failures = tuple(sorted(str(value) for value in (getattr(result, "analyzers_failed", ()) or ())))
    return MaliciousAgentRecallOutcome(
        case_id=case.case_id,
        source_id=case.source_id,
        repository_id=case.repository_id,
        structural_family_id=case.structural_family_id,
        patterns=case.patterns,
        finding_count=len(findings),
        actionable=any(_enum_value(getattr(finding, "severity", "")) in _ACTIONABLE_SEVERITIES for finding in findings),
        analyzer_failures=failures,
        error_code=None,
    )


def _group_outcomes(outcomes: Sequence[MaliciousAgentRecallOutcome], field: str) -> dict[str, dict[str, int | float]]:
    groups: dict[str, dict[str, int | float]] = {}
    for outcome in outcomes:
        values = outcome.patterns if field == "patterns" else (str(getattr(outcome, field)),)
        for value in set(values):
            counts = groups.setdefault(
                value,
                {"positive_population": 0, "actionable_detected": 0, "errors": 0, "positive_recall": 0.0},
            )
            counts["positive_population"] = int(counts["positive_population"]) + 1
            counts["actionable_detected"] = int(counts["actionable_detected"]) + int(outcome.actionable)
            counts["errors"] = int(counts["errors"]) + int(outcome.error_code is not None)
    for counts in groups.values():
        population = int(counts["positive_population"])
        counts["positive_recall"] = int(counts["actionable_detected"]) / population if population else 0.0
    return {key: groups[key] for key in sorted(groups)}


def run_malicious_agent_confirmed_recall(
    snapshot: MaliciousAgentSkillsSnapshot,
    *,
    confirmed_packages: Sequence[SandboxConfirmedPackage],
    malicious_skill_bench_overlap_keys: Collection[str],
    scanner: StaticSkillScanner,
) -> dict[str, Any]:
    """Run static recall on de-overlapped, externally confirmed malicious cases."""

    eligible, overlap_excluded, overlap_status = _overlap_partition(snapshot, malicious_skill_bench_overlap_keys)
    if overlap_status != "applied":  # pragma: no cover - the required argument makes this defensive
        raise MaliciousAgentSkillsError("MaliciousSkillBench overlap keys are required for recall")
    eligible_by_id = {case.case_id: case for case in eligible}
    all_by_id = {case.case_id: case for case in snapshot.malicious_cases}
    overlap_ids = {case.case_id for case in overlap_excluded}
    records_by_id: dict[str, SandboxConfirmedPackage] = {}
    for record in confirmed_packages:
        _validate_confirmation(record)
        if record.case_id not in all_by_id:
            raise MaliciousAgentSkillsError(f"confirmed package references an unknown case: {record.case_id}")
        if record.case_id in records_by_id:
            raise MaliciousAgentSkillsError(f"duplicate confirmed package case_id: {record.case_id}")
        records_by_id[record.case_id] = record

    excluded_confirmed = sorted(case_id for case_id in records_by_id if case_id in overlap_ids)
    valid_identities: dict[str, tuple[str, str]] = {}
    preflight_errors: list[MaliciousAgentRecallOutcome] = []
    for case_id in sorted(records_by_id):
        if case_id not in eligible_by_id:
            continue
        case = eligible_by_id[case_id]
        record = records_by_id[case_id]
        try:
            identity = inspect_text_package(record.package_directory)
        except (OSError, QuarantinedTextError):
            preflight_errors.append(_error_outcome(case, "PACKAGE_REVALIDATION_FAILED"))
            continue
        if (
            identity.content_sha256 != record.content_sha256
            or identity.normalized_content_sha256 != record.normalized_content_sha256
        ):
            preflight_errors.append(_error_outcome(case, "PACKAGE_CONTENT_HASH_DRIFT"))
            continue
        valid_identities[case_id] = (identity.content_sha256, identity.normalized_content_sha256)

    canonical_by_normalized: dict[str, str] = {}
    exact_duplicate_of: dict[str, str] = {}
    normalized_duplicate_of: dict[str, str] = {}
    canonical_by_exact: dict[str, str] = {}
    for case_id in sorted(valid_identities):
        exact, normalized = valid_identities[case_id]
        exact_canonical = canonical_by_exact.setdefault(exact, case_id)
        if exact_canonical != case_id:
            exact_duplicate_of[case_id] = exact_canonical
        normalized_canonical = canonical_by_normalized.setdefault(normalized, case_id)
        if normalized_canonical != case_id:
            normalized_duplicate_of[case_id] = normalized_canonical

    scan_outcomes = [
        _scan_one(eligible_by_id[case_id], records_by_id[case_id], scanner)
        for case_id in sorted(valid_identities)
        if case_id not in normalized_duplicate_of
    ]
    outcomes = tuple([*scan_outcomes, *preflight_errors])
    denominator = len(outcomes)
    actionable = sum(outcome.actionable for outcome in outcomes)
    errors = sum(outcome.error_code is not None for outcome in outcomes)
    return {
        "dataset_id": DATASET_ID,
        "revision": snapshot.revision,
        "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
        "status": "completed" if denominator else "no_eligible_confirmed_cases",
        "supplemental": True,
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "independent_metrics_eligible": True,
        "label_scope": "sandbox_confirmed_malicious_positive_only",
        "benign_gold_eligible": False,
        "safe_rows_used_as_benign": 0,
        "sample_execution": False,
        "network_enabled": False,
        "metadata_malicious_population": len(snapshot.malicious_cases),
        "confirmed_records": len(records_by_id),
        "overlap_excluded_confirmed": len(excluded_confirmed),
        "double_counted_cases": 0,
        "exact_duplicates_removed": len(exact_duplicate_of),
        "normalized_duplicates_removed": len(normalized_duplicate_of),
        "positive_population": denominator,
        "actionable_detected": actionable,
        "positive_recall": actionable / denominator if denominator else None,
        "errors": errors,
        "analyzer_failure_samples": sum(bool(outcome.analyzer_failures) for outcome in outcomes),
        "grouping": {
            "per_source": _group_outcomes(outcomes, "source_id"),
            "per_repository": _group_outcomes(outcomes, "repository_id"),
            "per_structural_family": _group_outcomes(outcomes, "structural_family_id"),
            "per_pattern": _group_outcomes(outcomes, "patterns"),
        },
        "deduplication": {
            "exact_duplicate_of": dict(sorted(exact_duplicate_of.items())),
            "normalized_duplicate_of": dict(sorted(normalized_duplicate_of.items())),
        },
        "provenance": {
            "confirmation_kind": _CONFIRMATION_KIND,
            "confirmation_hashes": sorted(record.confirmation_sha256 for record in records_by_id.values()),
            "malicious_skill_bench_overlap_keys_applied": True,
        },
        "outcomes": [
            {
                "case_id": outcome.case_id,
                "source_id": outcome.source_id,
                "repository_id": outcome.repository_id,
                "structural_family_id": outcome.structural_family_id,
                "patterns": list(outcome.patterns),
                "finding_count": outcome.finding_count,
                "actionable": outcome.actionable,
                "analyzer_failures": list(outcome.analyzer_failures),
                "error_code": outcome.error_code,
            }
            for outcome in outcomes
        ],
    }
