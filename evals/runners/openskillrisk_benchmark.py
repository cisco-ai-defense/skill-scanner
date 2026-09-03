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

"""Supplemental positive-recall runner for a validated OpenSkillRisk snapshot.

This runner intentionally accepts an already-configured static scanner instead
of constructing one.  Acquisition, sample execution, sandbox creation, hosted
LLMs, and network analyzers are outside this module's contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evals.datasets.openskillrisk import (
    DATASET_ID,
    OpenSkillRiskSnapshot,
    OpenSkillRiskTask,
    revalidate_referenced_package,
)

_ACTIONABLE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


class StaticSkillScanner(Protocol):
    """Minimal scanner interface; implementations must not execute samples."""

    def scan_skill(self, skill_directory: Path) -> Any: ...


@dataclass(frozen=True)
class OpenSkillRiskOutcome:
    task_id: str
    skill_id: str
    split: str
    attack_type: str
    package_path: str
    finding_count: int
    actionable: bool
    analyzer_failures: tuple[str, ...]
    scan_error: str | None


def _enum_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw).upper()


def _scan_one(
    snapshot: OpenSkillRiskSnapshot,
    task: OpenSkillRiskTask,
    scanner: StaticSkillScanner,
) -> OpenSkillRiskOutcome:
    package = revalidate_referenced_package(snapshot, task)
    relative_package = package.relative_to(snapshot.root).as_posix()
    try:
        result = scanner.scan_skill(package)
    except Exception as exc:  # retain errors in the positive-recall denominator
        return OpenSkillRiskOutcome(
            task_id=task.task_id,
            skill_id=task.skill_id,
            split=task.split,
            attack_type=task.attack_type,
            package_path=relative_package,
            finding_count=0,
            actionable=False,
            analyzer_failures=(),
            scan_error=f"SCAN_EXCEPTION:{type(exc).__name__}",
        )

    findings = tuple(getattr(result, "findings", ()) or ())
    analyzer_failures = tuple(sorted(str(value) for value in (getattr(result, "analyzers_failed", ()) or ())))
    actionable = any(_enum_value(getattr(finding, "severity", "")) in _ACTIONABLE_SEVERITIES for finding in findings)
    return OpenSkillRiskOutcome(
        task_id=task.task_id,
        skill_id=task.skill_id,
        split=task.split,
        attack_type=task.attack_type,
        package_path=relative_package,
        finding_count=len(findings),
        actionable=actionable,
        analyzer_failures=analyzer_failures,
        scan_error=None,
    )


def run_openskillrisk_static_benchmark(
    snapshot: OpenSkillRiskSnapshot,
    *,
    scanner: StaticSkillScanner,
    split: str | None = None,
) -> dict[str, Any]:
    """Scan only validated task-referenced package paths and report recall evidence."""

    selected = snapshot.selected(split)
    outcomes = tuple(_scan_one(snapshot, task, scanner) for task in selected)
    actionable = sum(outcome.actionable for outcome in outcomes)
    errors = sum(outcome.scan_error is not None for outcome in outcomes)
    analyzer_failure_samples = sum(bool(outcome.analyzer_failures) for outcome in outcomes)
    by_attack_type: dict[str, dict[str, int | float]] = {}
    for outcome in outcomes:
        metrics = by_attack_type.setdefault(
            outcome.attack_type,
            {"samples": 0, "actionable": 0, "scan_errors": 0, "positive_recall": 0.0},
        )
        metrics["samples"] = int(metrics["samples"]) + 1
        metrics["actionable"] = int(metrics["actionable"]) + int(outcome.actionable)
        metrics["scan_errors"] = int(metrics["scan_errors"]) + int(outcome.scan_error is not None)
    for metrics in by_attack_type.values():
        samples = int(metrics["samples"])
        metrics["positive_recall"] = int(metrics["actionable"]) / samples if samples else 0.0

    return {
        "dataset_id": DATASET_ID,
        "revision": snapshot.revision,
        "supplemental": True,
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "artifact_manifest_pinned": not snapshot.integrity_hashes_pending,
        "label_scope": "positive_risk_only",
        "population": len(outcomes),
        "actionable_detected": actionable,
        "positive_recall": actionable / len(outcomes) if outcomes else 0.0,
        "scan_errors": errors,
        "analyzer_failure_samples": analyzer_failure_samples,
        "by_attack_type": {key: by_attack_type[key] for key in sorted(by_attack_type)},
        "outcomes": [
            {
                "task_id": outcome.task_id,
                "skill_id": outcome.skill_id,
                "split": outcome.split,
                "attack_type": outcome.attack_type,
                "package_path": outcome.package_path,
                "finding_count": outcome.finding_count,
                "actionable": outcome.actionable,
                "analyzer_failures": list(outcome.analyzer_failures),
                "scan_error": outcome.scan_error,
            }
            for outcome in outcomes
        ],
    }
