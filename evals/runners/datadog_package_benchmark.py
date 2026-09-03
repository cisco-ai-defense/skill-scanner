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

"""Supplemental positive-recall runner for quarantined DataDog packages.

The runner accepts only a snapshot already validated by
``load_datadog_package_snapshot``.  It invokes a caller-supplied static scanner;
it contains no package installer, subprocess, import, archive, or network path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evals.datasets.datadog_malicious_packages import (
    DATASET_ID,
    DataDogPackage,
    DataDogPackageSnapshot,
    DataDogQuarantinedPackage,
)
from evals.datasets.quarantined_text import QuarantinedTextError, inspect_text_package

_ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_GROUP_FIELDS = (
    "ecosystem",
    "source_id",
    "repository_id",
    "actor_campaign_id",
    "structural_family_id",
    "lexical_template_id",
)


class StaticPackageScanner(Protocol):
    """Minimal non-executing scanner interface."""

    def scan_skill(self, skill_directory: Path) -> Any: ...


@dataclass(frozen=True)
class DataDogRecallOutcome:
    sample_id: str
    ecosystem: str
    source_id: str
    repository_id: str
    actor_campaign_id: str
    structural_family_id: str
    lexical_template_id: str
    package_path: str | None
    finding_count: int
    actionable: bool
    analyzer_failures: tuple[str, ...]
    error_code: str | None


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value)).upper()


def _package_outcome(package: DataDogPackage, scanner: StaticPackageScanner) -> DataDogRecallOutcome:
    try:
        current_identity = inspect_text_package(package.package_directory)
        if (
            current_identity.content_sha256 != package.content_sha256
            or current_identity.normalized_content_sha256 != package.normalized_content_sha256
        ):
            raise QuarantinedTextError("package content changed after snapshot validation")
    except (OSError, QuarantinedTextError):
        return DataDogRecallOutcome(
            sample_id=package.sample_id,
            ecosystem=package.ecosystem,
            source_id=package.source_id,
            repository_id=package.repository_id,
            actor_campaign_id=package.actor_campaign_id,
            structural_family_id=package.structural_family_id,
            lexical_template_id=package.lexical_template_id,
            package_path=package.relative_path.as_posix(),
            finding_count=0,
            actionable=False,
            analyzer_failures=(),
            error_code="PACKAGE_REVALIDATION_FAILED",
        )
    try:
        result = scanner.scan_skill(package.package_directory)
    except Exception as exc:  # positive-label errors must remain false negatives
        return DataDogRecallOutcome(
            sample_id=package.sample_id,
            ecosystem=package.ecosystem,
            source_id=package.source_id,
            repository_id=package.repository_id,
            actor_campaign_id=package.actor_campaign_id,
            structural_family_id=package.structural_family_id,
            lexical_template_id=package.lexical_template_id,
            package_path=package.relative_path.as_posix(),
            finding_count=0,
            actionable=False,
            analyzer_failures=(),
            error_code=f"SCAN_EXCEPTION_{type(exc).__name__.upper()}",
        )
    findings = tuple(getattr(result, "findings", ()) or ())
    failures = tuple(sorted(str(value) for value in (getattr(result, "analyzers_failed", ()) or ())))
    return DataDogRecallOutcome(
        sample_id=package.sample_id,
        ecosystem=package.ecosystem,
        source_id=package.source_id,
        repository_id=package.repository_id,
        actor_campaign_id=package.actor_campaign_id,
        structural_family_id=package.structural_family_id,
        lexical_template_id=package.lexical_template_id,
        package_path=package.relative_path.as_posix(),
        finding_count=len(findings),
        actionable=any(_enum_value(getattr(finding, "severity", "")) in _ACTIONABLE_SEVERITIES for finding in findings),
        analyzer_failures=failures,
        error_code=None,
    )


def _quarantine_outcome(package: DataDogQuarantinedPackage) -> DataDogRecallOutcome:
    return DataDogRecallOutcome(
        sample_id=package.sample_id,
        ecosystem=package.ecosystem,
        source_id=package.source_id,
        repository_id=package.repository_id,
        actor_campaign_id=package.actor_campaign_id,
        structural_family_id=package.structural_family_id,
        lexical_template_id=package.lexical_template_id,
        package_path=None,
        finding_count=0,
        actionable=False,
        analyzer_failures=(),
        error_code=f"INGESTION_{package.error_code}",
    )


def _group_metrics(outcomes: tuple[DataDogRecallOutcome, ...], field: str) -> dict[str, dict[str, int | float]]:
    groups: dict[str, dict[str, int | float]] = {}
    for outcome in outcomes:
        value = str(getattr(outcome, field))
        metrics = groups.setdefault(
            value,
            {"positive_population": 0, "actionable_detected": 0, "errors": 0, "positive_recall": 0.0},
        )
        metrics["positive_population"] = int(metrics["positive_population"]) + 1
        metrics["actionable_detected"] = int(metrics["actionable_detected"]) + int(outcome.actionable)
        metrics["errors"] = int(metrics["errors"]) + int(outcome.error_code is not None)
    for metrics in groups.values():
        population = int(metrics["positive_population"])
        metrics["positive_recall"] = int(metrics["actionable_detected"]) / population if population else 0.0
    return {key: groups[key] for key in sorted(groups)}


def run_datadog_package_recall(
    snapshot: DataDogPackageSnapshot,
    *,
    scanner: StaticPackageScanner,
) -> dict[str, Any]:
    """Run a non-blocking malicious-package recall diagnostic.

    Exact and conservatively normalized duplicates contribute one deterministic
    representative.  Quarantined and scanner-error positives remain in the
    denominator and therefore cannot improve recall.
    """

    scanned = tuple(_package_outcome(package, scanner) for package in snapshot.evaluation_packages)
    quarantined = tuple(_quarantine_outcome(package) for package in snapshot.quarantine)
    outcomes = (*scanned, *quarantined)
    actionable = sum(outcome.actionable for outcome in outcomes)
    errors = sum(outcome.error_code is not None for outcome in outcomes)
    denominator = len(outcomes)
    normalized_removed = len(snapshot.packages) - len(snapshot.evaluation_packages)

    return {
        "dataset_id": DATASET_ID,
        "revision": snapshot.revision,
        "artifact_manifest_sha256": snapshot.artifact_manifest_sha256,
        "population_sha256": snapshot.population_sha256,
        "artifact_manifest_pinned": snapshot.artifact_manifest_pinned,
        "status": "completed",
        "supplemental": True,
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "label_scope": "malicious_positive_only",
        "benign_gold_eligible": False,
        "network_enabled": False,
        "sample_execution": False,
        "declared_positive_population": len(snapshot.packages) + len(snapshot.quarantine),
        "materialized_population": len(snapshot.packages),
        "quarantined_population": len(snapshot.quarantine),
        "exact_duplicates_removed": len(snapshot.exact_duplicate_of),
        "normalized_duplicates_removed": normalized_removed,
        "positive_population": denominator,
        "actionable_detected": actionable,
        "positive_recall": actionable / denominator if denominator else 0.0,
        "errors": errors,
        "analyzer_failure_samples": sum(bool(outcome.analyzer_failures) for outcome in outcomes),
        "grouping": {f"per_{field}": _group_metrics(tuple(outcomes), field) for field in _GROUP_FIELDS},
        "deduplication": {
            "exact_duplicate_of": dict(sorted(snapshot.exact_duplicate_of.items())),
            "normalized_duplicate_of": dict(sorted(snapshot.normalized_duplicate_of.items())),
        },
        "outcomes": [
            {
                "sample_id": outcome.sample_id,
                "ecosystem": outcome.ecosystem,
                "source_id": outcome.source_id,
                "repository_id": outcome.repository_id,
                "actor_campaign_id": outcome.actor_campaign_id,
                "structural_family_id": outcome.structural_family_id,
                "lexical_template_id": outcome.lexical_template_id,
                "package_path": outcome.package_path,
                "finding_count": outcome.finding_count,
                "actionable": outcome.actionable,
                "analyzer_failures": list(outcome.analyzer_failures),
                "error_code": outcome.error_code,
            }
            for outcome in outcomes
        ],
    }
