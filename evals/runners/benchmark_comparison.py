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

"""Population-locked old-versus-current benchmark comparisons.

The comparator deliberately refuses to compare different dataset revisions,
track definitions, or class counts.  Without that lock, apparent detection
improvements can be caused by a changed benchmark denominator rather than a
scanner change.

It supports the historical ``recall`` name as an alias for the explicit
``package_block_recall`` metric, so an old report can be compared with a new
report without weakening the classification semantics.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from evals.runners.public_dataset_benchmark import run_public_benchmark
from skill_scanner.core.cel import qualification as cel_qualification
from skill_scanner.core.cel.models import CelMode

_EPSILON = 1e-12
_MAX_LATENCY_REGRESSION = 0.10
_MAX_CEL_TIME_RATIO = 0.05
_NORMALIZED_LOSS_GENERATION_DOMAIN = b"skill-scanner-cel-normalized-loss-generation-v1\0"
_NORMALIZED_LOSS_POPULATION_DOMAIN = b"skill-scanner-cel-normalized-loss-population-v1\0"
_GROUP_DIMENSIONS = ("per_category", "per_source", "per_structural_family")
_PRODUCER_FIELDS = frozenset(
    {
        "scanner_version",
        "source_revision",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
    }
)
_HIGHER_IS_BETTER = (
    "package_block_precision",
    "package_block_recall",
    "signal_recall",
    "macro_f1",
)
_LOWER_IS_BETTER = (
    "benign_actionable_fpr",
    "critical_high_false_negatives",
    "p95_scan_latency_ms",
    "cel_time_ratio",
    "cel_fallbacks",
    "scan_errors",
)
_AUDIT_ONLY_METRICS = (
    "loader_fallbacks",
    "recovered_scan_errors",
    "loader_rejections",
)


class BenchmarkComparisonError(ValueError):
    """Raised when two benchmark reports are not safely comparable."""


def _mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkComparisonError(f"{location} must be an object")
    return value


def _number(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BenchmarkComparisonError(f"{location} must be numeric")
    result = float(value)
    if result != result or result in {float("inf"), float("-inf")}:
        raise BenchmarkComparisonError(f"{location} must be finite")
    return result


def _metric(scope: Mapping[str, Any], name: str, location: str) -> float | None:
    value = scope.get(name)
    if value is None and name == "package_block_recall":
        value = scope.get("recall")
    if value is None and name == "package_block_precision":
        value = scope.get("precision")
    if value is None and name in {
        "scan_errors",
        "loader_fallbacks",
        "recovered_scan_errors",
        "loader_rejections",
    }:
        # Reports produced before scan_errors became explicit could only have
        # passed when their runner-level errors array was empty.  Treating the
        # absent counter as zero preserves comparison with those passed runs.
        value = 0
    if value is None:
        return None
    return _number(value, f"{location}.{name}")


def _loader_recovery_identity(
    baseline_scope: Mapping[str, Any],
    candidate_scope: Mapping[str, Any],
    location: str,
) -> dict[str, Any]:
    def identity(scope: Mapping[str, Any], side: str) -> dict[str, Any]:
        loader_fallbacks = _metric(scope, "loader_fallbacks", f"{side}.{location}")
        recovered_errors = _metric(scope, "recovered_scan_errors", f"{side}.{location}")
        if loader_fallbacks is None or recovered_errors is None:
            raise BenchmarkComparisonError(f"{side}.{location} lacks loader recovery counters")
        if not loader_fallbacks.is_integer() or not recovered_errors.is_integer():
            raise BenchmarkComparisonError(f"{side}.{location} loader recovery counters must be integers")
        raw_ids = scope.get("loader_fallback_sample_ids", [])
        if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, list):
            raise BenchmarkComparisonError(f"{side}.{location}.loader_fallback_sample_ids must be an array")
        if any(not isinstance(value, str) or not value for value in raw_ids) or len(raw_ids) != len(set(raw_ids)):
            raise BenchmarkComparisonError(
                f"{side}.{location}.loader_fallback_sample_ids must contain unique non-empty strings"
            )
        if raw_ids != sorted(raw_ids):
            raise BenchmarkComparisonError(f"{side}.{location}.loader_fallback_sample_ids must be sorted")
        if loader_fallbacks != recovered_errors or int(loader_fallbacks) != len(raw_ids):
            raise BenchmarkComparisonError(f"{side}.{location} loader recovery evidence is inconsistent")
        return {
            "loader_fallbacks": int(loader_fallbacks),
            "recovered_scan_errors": int(recovered_errors),
            "sample_ids": list(raw_ids),
        }

    baseline = identity(baseline_scope, "baseline")
    candidate = identity(candidate_scope, "candidate")
    return {"baseline": baseline, "candidate": candidate, "matches": baseline == candidate}


def _loader_rejection_identity(
    baseline_scope: Mapping[str, Any],
    candidate_scope: Mapping[str, Any],
    location: str,
) -> dict[str, Any]:
    def identity(scope: Mapping[str, Any], side: str) -> dict[str, Any]:
        rejections = _metric(scope, "loader_rejections", f"{side}.{location}")
        if rejections is None or not rejections.is_integer():
            raise BenchmarkComparisonError(f"{side}.{location}.loader_rejections must be an integer")
        raw_ids = scope.get("loader_rejection_sample_ids", [])
        if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, list):
            raise BenchmarkComparisonError(f"{side}.{location}.loader_rejection_sample_ids must be an array")
        if (
            any(not isinstance(value, str) or not value for value in raw_ids)
            or len(raw_ids) != len(set(raw_ids))
            or raw_ids != sorted(raw_ids)
        ):
            raise BenchmarkComparisonError(
                f"{side}.{location}.loader_rejection_sample_ids must contain sorted unique strings"
            )
        if int(rejections) != len(raw_ids):
            raise BenchmarkComparisonError(f"{side}.{location} closed loader rejection evidence is inconsistent")
        return {"loader_rejections": int(rejections), "sample_ids": list(raw_ids)}

    baseline = identity(baseline_scope, "baseline")
    candidate = identity(candidate_scope, "candidate")
    return {"baseline": baseline, "candidate": candidate, "matches": baseline == candidate}


def _identity(report: Mapping[str, Any], location: str) -> tuple[Any, ...]:
    dataset = _mapping(report.get("dataset"), f"{location}.dataset")
    fields = ("id", "revision", "artifact_manifest_sha256", "sample_metadata_manifest_sha256")
    values = tuple(dataset.get(field) for field in fields)
    if any(not isinstance(value, str) or not value for value in values):
        raise BenchmarkComparisonError(f"{location}.dataset must contain non-empty {', '.join(fields)}")
    return values


def _tracks(report: Mapping[str, Any], location: str) -> Mapping[str, Mapping[str, Any]]:
    raw = _mapping(report.get("tracks"), f"{location}.tracks")
    if not raw:
        raise BenchmarkComparisonError(f"{location}.tracks must not be empty")
    result: dict[str, Mapping[str, Any]] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not name:
            raise BenchmarkComparisonError(f"{location}.tracks contains an invalid name")
        result[name] = _mapping(value, f"{location}.tracks.{name}")
    return result


def _population(scope: Mapping[str, Any], location: str) -> tuple[int, int, int]:
    values: list[int] = []
    for field in ("samples", "malicious", "benign"):
        value = scope.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BenchmarkComparisonError(f"{location}.{field} must be a non-negative integer")
        values.append(value)
    if values[1] + values[2] > values[0]:
        raise BenchmarkComparisonError(f"{location} class counts exceed samples")
    return values[0], values[1], values[2]


def _lock_population(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    location: str,
) -> None:
    baseline_population = _population(baseline, f"baseline.{location}")
    candidate_population = _population(candidate, f"candidate.{location}")
    if baseline_population != candidate_population:
        raise BenchmarkComparisonError(
            f"{location} population differs: baseline={baseline_population}, candidate={candidate_population}"
        )


def _lock_population_digest(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    location: str,
) -> str:
    digests: list[str] = []
    for side, scope in (("baseline", baseline), ("candidate", candidate)):
        digest = scope.get("population_sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise BenchmarkComparisonError(f"{side}.{location}.population_sha256 must be a lowercase SHA-256")
        digests.append(digest)
    if digests[0] != digests[1]:
        raise BenchmarkComparisonError(
            f"{location} selected population identity differs: baseline={digests[0]}, candidate={digests[1]}"
        )
    return digests[0]


def _confidence_interval(scope: Mapping[str, Any], metric: str, location: str) -> list[float] | None:
    intervals = scope.get("confidence_intervals_95")
    if intervals is None:
        return None
    intervals = _mapping(intervals, f"{location}.confidence_intervals_95")
    value = intervals.get(metric)
    if value is None and metric == "package_block_recall":
        value = intervals.get("recall")
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) != 2:
        raise BenchmarkComparisonError(f"{location}.confidence_intervals_95.{metric} must be a two-item array")
    lower = _number(value[0], f"{location}.confidence_intervals_95.{metric}[0]")
    upper = _number(value[1], f"{location}.confidence_intervals_95.{metric}[1]")
    if not 0.0 <= lower <= upper <= 1.0:
        raise BenchmarkComparisonError(f"{location}.confidence_intervals_95.{metric} must be within [0, 1]")
    return [lower, upper]


def _interval_relation(baseline: list[float] | None, candidate: list[float] | None) -> str | None:
    if baseline is None or candidate is None:
        return None
    if candidate[0] > baseline[1]:
        return "candidate_above"
    if candidate[1] < baseline[0]:
        return "candidate_below"
    return "overlap"


def _metric_delta(
    name: str,
    baseline_scope: Mapping[str, Any],
    candidate_scope: Mapping[str, Any],
    location: str,
) -> dict[str, Any] | None:
    baseline = _metric(baseline_scope, name, f"baseline.{location}")
    candidate = _metric(candidate_scope, name, f"candidate.{location}")
    if baseline is None and candidate is None:
        return None
    if baseline is None or candidate is None:
        raise BenchmarkComparisonError(f"{location}.{name} exists in only one report")
    absolute = candidate - baseline
    relative = absolute / abs(baseline) if abs(baseline) > _EPSILON else None
    if abs(absolute) <= _EPSILON:
        outcome = "unchanged"
    elif name in _HIGHER_IS_BETTER:
        outcome = "improved" if absolute > 0 else "regressed"
    else:
        outcome = "improved" if absolute < 0 else "regressed"

    baseline_interval = _confidence_interval(baseline_scope, name, f"baseline.{location}")
    candidate_interval = _confidence_interval(candidate_scope, name, f"candidate.{location}")
    return {
        "baseline": baseline,
        "candidate": candidate,
        "absolute_delta": absolute,
        "relative_delta": relative,
        "preferred_direction": "higher" if name in _HIGHER_IS_BETTER else "lower",
        "outcome": outcome,
        "confidence_intervals_95": {
            "baseline": baseline_interval,
            "candidate": candidate_interval,
            "relation": _interval_relation(baseline_interval, candidate_interval),
        },
    }


def _false_negative_delta(
    baseline_scope: Mapping[str, Any], candidate_scope: Mapping[str, Any], location: str
) -> dict[str, list[str]]:
    def identifiers(scope: Mapping[str, Any], side: str) -> set[str]:
        values = scope.get("critical_high_false_negative_ids")
        if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
            raise BenchmarkComparisonError(
                f"{side}.{location}.critical_high_false_negative_ids must be an array of IDs"
            )
        if len(values) != len(set(values)):
            raise BenchmarkComparisonError(f"{side}.{location}.critical_high_false_negative_ids contains duplicates")
        return set(values)

    baseline = identifiers(baseline_scope, "baseline")
    candidate = identifiers(candidate_scope, "candidate")
    return {
        "new": sorted(candidate - baseline),
        "resolved": sorted(baseline - candidate),
        "unchanged": sorted(baseline & candidate),
    }


def _string_set(value: Any, location: str) -> set[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise BenchmarkComparisonError(f"{location} must be an array")
    result = set(value)
    if len(result) != len(value) or any(not isinstance(item, str) or not item for item in value):
        raise BenchmarkComparisonError(f"{location} must contain unique non-empty strings")
    return result


def _cel_telemetry_delta(
    baseline_scope: Mapping[str, Any],
    candidate_scope: Mapping[str, Any],
    location: str,
) -> dict[str, Any] | None:
    baseline_raw = baseline_scope.get("cel")
    candidate_raw = candidate_scope.get("cel")
    if baseline_raw is None and candidate_raw is None:
        return None
    if baseline_raw is None or candidate_raw is None:
        raise BenchmarkComparisonError(f"{location}.cel exists in only one report")
    baseline = _mapping(baseline_raw, f"baseline.{location}.cel")
    candidate = _mapping(candidate_raw, f"candidate.{location}.cel")

    count_fields = (
        "evaluated",
        "retained",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
        "elapsed_ms",
        "projection_ms",
        "evaluation_ms",
    )
    counts: dict[str, Any] = {}
    for field in count_fields:
        baseline_value = _number(baseline.get(field), f"baseline.{location}.cel.{field}")
        candidate_value = _number(candidate.get(field), f"candidate.{location}.cel.{field}")
        if baseline_value < 0 or candidate_value < 0:
            raise BenchmarkComparisonError(f"{location}.cel.{field} must be non-negative")
        counts[field] = {
            "baseline": baseline_value,
            "candidate": candidate_value,
            "absolute_delta": candidate_value - baseline_value,
        }

    sample_deltas: dict[str, Any] = {}
    for field in (
        "would_suppress_sample_ids",
        "suppressed_sample_ids",
        "fallback_sample_ids",
        "projection_incomplete_sample_ids",
    ):
        baseline_ids = _string_set(baseline.get(field, []), f"baseline.{location}.cel.{field}")
        candidate_ids = _string_set(candidate.get(field, []), f"candidate.{location}.cel.{field}")
        sample_deltas[field] = {
            "new": sorted(candidate_ids - baseline_ids),
            "resolved": sorted(baseline_ids - candidate_ids),
            "unchanged": sorted(baseline_ids & candidate_ids),
        }

    baseline_rules = _mapping(baseline.get("per_rule", {}), f"baseline.{location}.cel.per_rule")
    candidate_rules = _mapping(candidate.get("per_rule", {}), f"candidate.{location}.cel.per_rule")
    per_rule: dict[str, Any] = {}
    for rule_id in sorted(set(baseline_rules) | set(candidate_rules)):
        if not isinstance(rule_id, str) or not rule_id:
            raise BenchmarkComparisonError(f"{location}.cel.per_rule contains an invalid rule ID")
        baseline_rule = _mapping(baseline_rules.get(rule_id, {}), f"baseline.{location}.cel.per_rule.{rule_id}")
        candidate_rule = _mapping(candidate_rules.get(rule_id, {}), f"candidate.{location}.cel.per_rule.{rule_id}")
        decisions: dict[str, Any] = {}
        for decision in ("keep", "would_suppress", "fallback", "suppressed"):
            baseline_count = _number(
                baseline_rule.get(decision, 0),
                f"baseline.{location}.cel.per_rule.{rule_id}.{decision}",
            )
            candidate_count = _number(
                candidate_rule.get(decision, 0),
                f"candidate.{location}.cel.per_rule.{rule_id}.{decision}",
            )
            decisions[decision] = {
                "baseline": baseline_count,
                "candidate": candidate_count,
                "absolute_delta": candidate_count - baseline_count,
            }
        per_rule[rule_id] = decisions

    identity_fields = (
        "modes",
        "runtimes",
        "runtime_versions",
        "fact_schemas",
        "expression_set_hashes",
    )
    return {
        "counts": counts,
        "sample_ids": sample_deltas,
        "per_rule": per_rule,
        "identity": {
            field: {
                "baseline": sorted(_string_set(baseline.get(field, []), f"baseline.{location}.cel.{field}")),
                "candidate": sorted(_string_set(candidate.get(field, []), f"candidate.{location}.cel.{field}")),
            }
            for field in identity_fields
        },
    }


def _promotion_checks(
    baseline_scope: Mapping[str, Any],
    candidate_scope: Mapping[str, Any],
    location: str,
    *,
    require_loader_identity: bool,
) -> dict[str, Any]:
    block_baseline = _metric(baseline_scope, "package_block_recall", f"baseline.{location}")
    block_candidate = _metric(candidate_scope, "package_block_recall", f"candidate.{location}")
    signal_baseline = _metric(baseline_scope, "signal_recall", f"baseline.{location}")
    signal_candidate = _metric(candidate_scope, "signal_recall", f"candidate.{location}")
    macro_baseline = _metric(baseline_scope, "macro_f1", f"baseline.{location}")
    macro_candidate = _metric(candidate_scope, "macro_f1", f"candidate.{location}")
    fpr_baseline = _metric(baseline_scope, "benign_actionable_fpr", f"baseline.{location}")
    fpr_candidate = _metric(candidate_scope, "benign_actionable_fpr", f"candidate.{location}")
    latency_baseline = _metric(baseline_scope, "p95_scan_latency_ms", f"baseline.{location}")
    latency_candidate = _metric(candidate_scope, "p95_scan_latency_ms", f"candidate.{location}")
    cel_ratio = _metric(candidate_scope, "cel_time_ratio", f"candidate.{location}")
    fallbacks = _metric(candidate_scope, "cel_fallbacks", f"candidate.{location}")
    candidate_cel = _mapping(candidate_scope.get("cel"), f"candidate.{location}.cel")
    projection_incomplete = _number(
        candidate_cel.get("projection_incomplete"),
        f"candidate.{location}.cel.projection_incomplete",
    )
    errors = _metric(candidate_scope, "scan_errors", f"candidate.{location}")
    false_negatives = _false_negative_delta(baseline_scope, candidate_scope, location)
    loader_recovery = _loader_recovery_identity(baseline_scope, candidate_scope, location)
    loader_rejection = _loader_rejection_identity(baseline_scope, candidate_scope, location)

    checks = {
        "no_new_critical_high_false_negatives": not false_negatives["new"],
        "package_block_recall_non_regression": (
            block_baseline is not None and block_candidate is not None and block_candidate + _EPSILON >= block_baseline
        ),
        "signal_recall_non_regression": (
            signal_baseline is not None
            and signal_candidate is not None
            and signal_candidate + _EPSILON >= signal_baseline
        ),
        "macro_f1_non_regression": (
            macro_baseline is not None and macro_candidate is not None and macro_candidate + _EPSILON >= macro_baseline
        ),
        "benign_actionable_fpr_non_regression": (
            fpr_baseline is not None and fpr_candidate is not None and fpr_candidate <= fpr_baseline + _EPSILON
        ),
        "p95_latency_within_ten_percent": (
            latency_baseline is not None
            and latency_candidate is not None
            and latency_candidate <= latency_baseline * (1.0 + _MAX_LATENCY_REGRESSION) + _EPSILON
        ),
        "cel_time_within_five_percent": (cel_ratio is not None and cel_ratio <= _MAX_CEL_TIME_RATIO + _EPSILON),
        "zero_cel_fallbacks": fallbacks == 0,
        "zero_cel_projection_incomplete": projection_incomplete == 0,
        "zero_scan_errors": errors in {None, 0},
    }
    if require_loader_identity:
        checks["loader_recovery_identity"] = loader_recovery["matches"]
        checks["loader_rejection_identity"] = loader_rejection["matches"]
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "new_critical_high_false_negative_ids": false_negatives["new"],
        "latency_limit_ms": (None if latency_baseline is None else latency_baseline * (1.0 + _MAX_LATENCY_REGRESSION)),
        "cel_time_ratio_limit": _MAX_CEL_TIME_RATIO,
    }


def _scope_comparison(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    location: str,
    *,
    require_loader_identity: bool,
) -> dict[str, Any]:
    _lock_population(baseline, candidate, location)
    deltas: dict[str, Any] = {}
    for metric in (*_HIGHER_IS_BETTER, *_LOWER_IS_BETTER, *_AUDIT_ONLY_METRICS):
        delta = _metric_delta(metric, baseline, candidate, location)
        if delta is not None:
            deltas[metric] = delta
    return {
        "population": {
            "samples": baseline["samples"],
            "malicious": baseline["malicious"],
            "benign": baseline["benign"],
        },
        "metrics": deltas,
        "critical_high_false_negative_ids": _false_negative_delta(baseline, candidate, location),
        "loader_recovery": _loader_recovery_identity(baseline, candidate, location),
        "loader_rejection": _loader_rejection_identity(baseline, candidate, location),
        "cel": _cel_telemetry_delta(baseline, candidate, location),
        "promotion": _promotion_checks(
            baseline,
            candidate,
            location,
            require_loader_identity=require_loader_identity,
        ),
    }


def _require_completed_report(report: Mapping[str, Any], location: str) -> None:
    if report.get("status") != "passed":
        raise BenchmarkComparisonError(f"{location}.status must be 'passed'")
    errors = report.get("errors")
    if not isinstance(errors, list) or errors:
        raise BenchmarkComparisonError(f"{location}.errors must be an empty array")


def _require_active_cel_evidence(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    baseline_producer: Mapping[str, str],
    candidate_producer: Mapping[str, str],
) -> None:
    baseline_mode = baseline.get("cel_mode")
    candidate_mode = candidate.get("cel_mode")
    if candidate_mode not in {CelMode.SHADOW.value, CelMode.ENFORCE.value}:
        return
    if baseline_mode != CelMode.OFF.value:
        raise BenchmarkComparisonError("active CEL comparison requires a cel_mode=off baseline")
    baseline_summary = _mapping(baseline.get("summary"), "baseline.summary")
    candidate_summary = _mapping(candidate.get("summary"), "candidate.summary")
    baseline_cel = _mapping(baseline_summary.get("cel"), "baseline.summary.cel")
    candidate_cel = _mapping(candidate_summary.get("cel"), "candidate.summary.cel")
    baseline_modes = _string_set(baseline_cel.get("modes", []), "baseline.summary.cel.modes")
    candidate_modes = _string_set(candidate_cel.get("modes", []), "candidate.summary.cel.modes")
    if baseline_modes != {CelMode.OFF.value}:
        raise BenchmarkComparisonError("baseline CEL telemetry does not prove off mode")
    if candidate_modes != {candidate_mode}:
        raise BenchmarkComparisonError("candidate CEL telemetry does not match claimed active mode")
    baseline_runtimes = _string_set(baseline_cel.get("runtimes", []), "baseline.summary.cel.runtimes")
    candidate_runtimes = _string_set(candidate_cel.get("runtimes", []), "candidate.summary.cel.runtimes")
    baseline_versions = _string_set(
        baseline_cel.get("runtime_versions", []),
        "baseline.summary.cel.runtime_versions",
    )
    candidate_versions = _string_set(
        candidate_cel.get("runtime_versions", []),
        "candidate.summary.cel.runtime_versions",
    )
    for report_label, runtimes, versions, producer in (
        ("baseline", baseline_runtimes, baseline_versions, baseline_producer),
        ("candidate", candidate_runtimes, candidate_versions, candidate_producer),
    ):
        if len(runtimes) != 1 or len(versions) != 1:
            raise BenchmarkComparisonError(f"{report_label} report lacks one qualified CEL runtime version")
        error = cel_qualification.qualification_error(
            next(iter(runtimes)),
            next(iter(versions)),
            expected_helper_version=producer["scanner_version"],
        )
        if error is not None:
            raise BenchmarkComparisonError(f"{report_label} report lacks a qualified CEL runtime: {error}")
    if baseline_versions != candidate_versions:
        raise BenchmarkComparisonError("candidate and off baseline used different qualified CEL helper builds")

    baseline_fact_schemas = _string_set(
        baseline_cel.get("fact_schemas", []),
        "baseline.summary.cel.fact_schemas",
    )
    candidate_fact_schemas = _string_set(
        candidate_cel.get("fact_schemas", []),
        "candidate.summary.cel.fact_schemas",
    )
    baseline_expression_hashes = _string_set(
        baseline_cel.get("expression_set_hashes", []),
        "baseline.summary.cel.expression_set_hashes",
    )
    candidate_expression_hashes = _string_set(
        candidate_cel.get("expression_set_hashes", []),
        "candidate.summary.cel.expression_set_hashes",
    )
    if baseline_fact_schemas != {"v1"} or candidate_fact_schemas != {"v1"}:
        raise BenchmarkComparisonError("candidate and off baseline must use CEL fact schema v1")
    if (
        not candidate_expression_hashes
        or candidate_expression_hashes != baseline_expression_hashes
        or any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in candidate_expression_hashes
        )
    ):
        raise BenchmarkComparisonError("candidate and off baseline lack the same CEL expression generation hash")

    for field in (
        "evaluated",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
        "elapsed_ms",
        "projection_ms",
        "evaluation_ms",
    ):
        if _number(baseline_cel.get(field), f"baseline.summary.cel.{field}") != 0:
            raise BenchmarkComparisonError("off baseline reports active CEL evaluation or decisions")
    evaluated = _number(candidate_cel.get("evaluated"), "candidate.summary.cel.evaluated")
    if evaluated <= 0:
        raise BenchmarkComparisonError("candidate report does not prove any active CEL evaluation")


def _evidence_identity(report: Mapping[str, Any], location: str) -> dict[str, str]:
    raw = _mapping(report.get("evidence_identity"), f"{location}.evidence_identity")
    expected = {
        "dataset_or_corpus_id",
        "snapshot_sha256",
        "build_sha256",
        "policy_sha256",
        "rules_sha256",
        "expression_set_hash",
        "cel_mode",
    }
    if set(raw) != expected:
        raise BenchmarkComparisonError(f"{location}.evidence_identity must contain exactly {sorted(expected)}")
    result: dict[str, str] = {}
    for field in expected:
        value = raw[field]
        if not isinstance(value, str) or not value:
            raise BenchmarkComparisonError(f"{location}.evidence_identity.{field} must be a non-empty string")
        if field.endswith("sha256") or field == "expression_set_hash":
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise BenchmarkComparisonError(f"{location}.evidence_identity.{field} must be a lowercase SHA-256")
        result[field] = value
    if result["cel_mode"] != report.get("cel_mode"):
        raise BenchmarkComparisonError(f"{location}.evidence_identity.cel_mode does not match report cel_mode")
    return result


def _producer_identity(
    report: Mapping[str, Any],
    evidence: Mapping[str, str],
    location: str,
) -> dict[str, str]:
    raw = _mapping(report.get("producer"), f"{location}.producer")
    if set(raw) != _PRODUCER_FIELDS:
        raise BenchmarkComparisonError(f"{location}.producer must contain exactly {sorted(_PRODUCER_FIELDS)}")
    producer: dict[str, str] = {}
    for field in _PRODUCER_FIELDS:
        value = raw[field]
        if not isinstance(value, str) or not value:
            raise BenchmarkComparisonError(f"{location}.producer.{field} must be a non-empty string")
        producer[field] = value
    for field in ("build_sha256", "policy_sha256", "rules_sha256"):
        value = producer[field]
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise BenchmarkComparisonError(f"{location}.producer.{field} must be a lowercase SHA-256")
        if value != evidence[field]:
            raise BenchmarkComparisonError(f"{location}.producer.{field} does not match evidence_identity.{field}")
    return producer


def _require_stable_run_identity(
    report: Mapping[str, Any],
    evidence: Mapping[str, str],
    producer: Mapping[str, str],
    location: str,
) -> None:
    verification = _mapping(report.get("identity_verification"), f"{location}.identity_verification")
    if verification.get("status") != "passed":
        raise BenchmarkComparisonError(f"{location}.identity_verification.status must be 'passed'")
    drifted = verification.get("drifted_fields")
    errors = verification.get("errors")
    if drifted != [] or errors != []:
        raise BenchmarkComparisonError(f"{location}.identity_verification must not contain drift or errors")
    start = _mapping(verification.get("start"), f"{location}.identity_verification.start")
    end = _mapping(verification.get("end"), f"{location}.identity_verification.end")
    expected = {"snapshot_sha256", *_PRODUCER_FIELDS}
    if set(start) != expected or set(end) != expected:
        raise BenchmarkComparisonError(
            f"{location}.identity_verification start/end must contain exactly {sorted(expected)}"
        )
    if start != end:
        raise BenchmarkComparisonError(f"{location}.identity_verification start and end identities differ")
    if start["snapshot_sha256"] != evidence["snapshot_sha256"]:
        raise BenchmarkComparisonError(f"{location}.identity_verification snapshot does not match evidence_identity")
    if any(start[field] != producer[field] for field in _PRODUCER_FIELDS):
        raise BenchmarkComparisonError(f"{location}.identity_verification producer does not match report producer")


def compare_benchmark_reports(
    baseline_report: Mapping[str, Any], candidate_report: Mapping[str, Any]
) -> dict[str, Any]:
    """Compare two complete benchmark reports over the exact same population."""

    baseline = _mapping(baseline_report, "baseline")
    candidate = _mapping(candidate_report, "candidate")
    _require_completed_report(baseline, "baseline")
    _require_completed_report(candidate, "candidate")
    baseline_evidence = _evidence_identity(baseline, "baseline")
    candidate_evidence = _evidence_identity(candidate, "candidate")
    baseline_producer = _producer_identity(baseline, baseline_evidence, "baseline")
    candidate_producer = _producer_identity(candidate, candidate_evidence, "candidate")
    _require_stable_run_identity(baseline, baseline_evidence, baseline_producer, "baseline")
    _require_stable_run_identity(candidate, candidate_evidence, candidate_producer, "candidate")
    baseline_identity = _identity(baseline, "baseline")
    candidate_identity = _identity(candidate, "candidate")
    if baseline_identity != candidate_identity:
        raise BenchmarkComparisonError(
            "candidate and baseline dataset identity differs: "
            f"baseline={baseline_identity}, candidate={candidate_identity}"
        )

    if baseline_evidence["policy_sha256"] != candidate_evidence["policy_sha256"]:
        raise BenchmarkComparisonError("candidate and baseline policy identity differs")
    active_cel_comparison = candidate.get("cel_mode") in {
        CelMode.SHADOW.value,
        CelMode.ENFORCE.value,
    }
    if active_cel_comparison:
        for field in (
            "dataset_or_corpus_id",
            "snapshot_sha256",
            "build_sha256",
            "policy_sha256",
            "rules_sha256",
            "expression_set_hash",
        ):
            if baseline_evidence[field] != candidate_evidence[field]:
                raise BenchmarkComparisonError(f"active CEL comparison changes evidence identity field {field}")
        if baseline_producer != candidate_producer:
            raise BenchmarkComparisonError("active CEL comparison changes producer identity")
        _require_active_cel_evidence(
            baseline,
            candidate,
            baseline_producer=baseline_producer,
            candidate_producer=candidate_producer,
        )

    baseline_tracks = _tracks(baseline, "baseline")
    candidate_tracks = _tracks(candidate, "candidate")
    if set(baseline_tracks) != set(candidate_tracks):
        raise BenchmarkComparisonError("candidate and baseline track sets differ")

    summary = _scope_comparison(
        _mapping(baseline.get("summary"), "baseline.summary"),
        _mapping(candidate.get("summary"), "candidate.summary"),
        "summary",
        require_loader_identity=active_cel_comparison,
    )
    tracks: dict[str, Any] = {}
    missing_dimensions: list[str] = []
    for track_name in sorted(baseline_tracks):
        baseline_track = baseline_tracks[track_name]
        candidate_track = candidate_tracks[track_name]
        track_identity_fields = ("detector_profile", "protocol", "partition")
        baseline_track_identity = tuple(baseline_track.get(field) for field in track_identity_fields)
        candidate_track_identity = tuple(candidate_track.get(field) for field in track_identity_fields)
        if baseline_track_identity != candidate_track_identity:
            raise BenchmarkComparisonError(f"track {track_name!r} definition differs")

        population_sha256 = _lock_population_digest(
            baseline_track,
            candidate_track,
            f"tracks.{track_name}",
        )
        comparison = _scope_comparison(
            baseline_track,
            candidate_track,
            f"tracks.{track_name}",
            require_loader_identity=active_cel_comparison,
        )
        comparison["population"]["population_sha256"] = population_sha256
        group_comparisons: dict[str, Any] = {}
        for dimension in _GROUP_DIMENSIONS:
            baseline_groups = baseline_track.get(dimension)
            candidate_groups = candidate_track.get(dimension)
            if baseline_groups is None or candidate_groups is None:
                missing_dimensions.append(f"{track_name}.{dimension}")
                continue
            baseline_groups = _mapping(baseline_groups, f"baseline.tracks.{track_name}.{dimension}")
            candidate_groups = _mapping(candidate_groups, f"candidate.tracks.{track_name}.{dimension}")
            if set(baseline_groups) != set(candidate_groups):
                raise BenchmarkComparisonError(f"track {track_name!r} {dimension} populations differ")
            group_comparisons[dimension] = {
                group_name: _scope_comparison(
                    _mapping(
                        baseline_groups[group_name],
                        f"baseline.tracks.{track_name}.{dimension}.{group_name}",
                    ),
                    _mapping(
                        candidate_groups[group_name],
                        f"candidate.tracks.{track_name}.{dimension}.{group_name}",
                    ),
                    f"tracks.{track_name}.{dimension}.{group_name}",
                    require_loader_identity=active_cel_comparison,
                )
                for group_name in sorted(baseline_groups)
            }
        comparison["groups"] = group_comparisons
        tracks[track_name] = comparison

    group_promotions = [
        group["promotion"]
        for track in tracks.values()
        for dimension in track["groups"].values()
        for group in dimension.values()
    ]
    all_promotions = [
        summary["promotion"],
        *[track["promotion"] for track in tracks.values()],
        *group_promotions,
    ]
    complete_grouping = not missing_dimensions
    return {
        "schema_version": 1,
        "dataset": {
            "id": baseline_identity[0],
            "revision": baseline_identity[1],
            "artifact_manifest_sha256": baseline_identity[2],
            "sample_metadata_manifest_sha256": baseline_identity[3],
        },
        "baseline_cel_mode": baseline.get("cel_mode"),
        "candidate_cel_mode": candidate.get("cel_mode"),
        "comparison_kind": "cel_activation" if active_cel_comparison else "scanner_upgrade",
        "evidence_identity": {
            "baseline": baseline_evidence,
            "candidate": candidate_evidence,
            "changed_fields": sorted(
                field for field in baseline_evidence if baseline_evidence[field] != candidate_evidence[field]
            ),
        },
        "producer": {
            "baseline": baseline_producer,
            "candidate": candidate_producer,
            "changed_fields": sorted(
                field for field in baseline_producer if baseline_producer[field] != candidate_producer[field]
            ),
        },
        "status": ("passed" if complete_grouping and all(item["passed"] for item in all_promotions) else "failed"),
        "population_locked": True,
        "summary": summary,
        "tracks": tracks,
        "missing_group_dimensions": sorted(set(missing_dimensions)),
    }


_RULE_FIXTURE_FIELDS = frozenset(
    {
        "true_positive_fixture_ids",
        "benign_near_miss_fixture_ids",
        "boundary_fixture_ids",
    }
)


def _rule_fixture_coverage(value: Mapping[str, Any] | None) -> dict[str, dict[str, list[str]]]:
    """Validate independently supplied committed-fixture coverage."""

    if value is None:
        return {}
    coverage: dict[str, dict[str, list[str]]] = {}
    for rule_id, raw_rule in sorted(value.items()):
        if not isinstance(rule_id, str) or not rule_id:
            raise BenchmarkComparisonError("rule fixture evidence contains an invalid rule ID")
        rule = _mapping(raw_rule, f"rule_fixture_evidence.{rule_id}")
        if set(rule) != _RULE_FIXTURE_FIELDS:
            raise BenchmarkComparisonError(
                f"rule_fixture_evidence.{rule_id} must contain exactly {sorted(_RULE_FIXTURE_FIELDS)}"
            )
        coverage[rule_id] = {
            field: sorted(_string_set(rule[field], f"rule_fixture_evidence.{rule_id}.{field}"))
            for field in sorted(_RULE_FIXTURE_FIELDS)
        }
    return coverage


def _promotion_rule_ids(value: Sequence[str] | None) -> frozenset[str]:
    """Return the explicit, duplicate-free set of rules under promotion review."""

    if value is None:
        return frozenset()
    if isinstance(value, (str, bytes)):
        raise BenchmarkComparisonError("promoted_rule_ids must be an array of rule IDs")
    if any(not isinstance(rule_id, str) or not rule_id for rule_id in value):
        raise BenchmarkComparisonError("promoted_rule_ids must contain non-empty rule IDs")
    if len(value) != len(set(value)):
        raise BenchmarkComparisonError("promoted_rule_ids must not contain duplicates")
    return frozenset(value)


def normalized_loss_generation_sha256(
    baseline_identity: Mapping[str, Any], candidate_identity: Mapping[str, Any]
) -> str:
    """Bind exact normalized-loss evidence to both immutable scan generations."""

    payload = {"baseline": dict(baseline_identity), "candidate": dict(candidate_identity)}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(_NORMALIZED_LOSS_GENERATION_DOMAIN + encoded).hexdigest()


def normalized_loss_population_sha256(
    *,
    rule_id: str,
    targeted_benign_sample_ids: Sequence[str],
    baseline_actionable_sample_ids: Sequence[str],
    candidate_actionable_sample_ids: Sequence[str],
    resolved_actionable_sample_ids: Sequence[str],
    malicious_support_sample_ids: Sequence[str],
    malicious_block_loss_sample_ids: Sequence[str],
) -> str:
    """Hash the exact per-rule counterfactual population and outcomes."""

    payload = {
        "baseline_actionable_sample_ids": list(baseline_actionable_sample_ids),
        "candidate_actionable_sample_ids": list(candidate_actionable_sample_ids),
        "malicious_block_loss_sample_ids": list(malicious_block_loss_sample_ids),
        "malicious_support_sample_ids": list(malicious_support_sample_ids),
        "resolved_actionable_sample_ids": list(resolved_actionable_sample_ids),
        "rule_id": rule_id,
        "targeted_benign_sample_ids": list(targeted_benign_sample_ids),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(_NORMALIZED_LOSS_POPULATION_DOMAIN + encoded).hexdigest()


def _exact_normalized_loss_evidence(
    baseline_report: Mapping[str, Any],
    candidate_report: Mapping[str, Any],
    *,
    rule_id: str,
    benign_sample_ids: Sequence[str],
    malicious_sample_ids: Sequence[str],
) -> dict[str, Any] | None:
    """Compute a rule-attributable package counterfactual from full outcomes.

    The caller invokes this only for a single promoted rule in enforce mode;
    every other CEL rule is required to remain shadow. Therefore the exact
    actionable-package delta is attributable to this rule rather than to a
    mixture of simultaneous suppressions.
    """

    baseline_tracks = _tracks(baseline_report, "baseline")
    candidate_tracks = _tracks(candidate_report, "candidate")
    if set(baseline_tracks) != set(candidate_tracks):
        return None
    outcome_pairs: dict[str, tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
    for track_name in sorted(candidate_tracks):
        baseline_track = baseline_tracks[track_name]
        candidate_track = candidate_tracks[track_name]
        if (
            baseline_track.get("sample_outcomes_format") is not None
            or candidate_track.get("sample_outcomes_format") is not None
        ):
            return None
        baseline_outcomes = baseline_track.get("sample_outcomes")
        candidate_outcomes = candidate_track.get("sample_outcomes")
        if not isinstance(baseline_outcomes, Mapping) or not isinstance(candidate_outcomes, Mapping):
            return None
        for benchmark_id in set(baseline_outcomes) & set(candidate_outcomes):
            baseline_outcome = baseline_outcomes[benchmark_id]
            candidate_outcome = candidate_outcomes[benchmark_id]
            if isinstance(baseline_outcome, Mapping) and isinstance(candidate_outcome, Mapping):
                outcome_pairs[f"{track_name}:{benchmark_id}"] = (baseline_outcome, candidate_outcome)

    def classified(stable_id: str, *, label: str) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
        pair = outcome_pairs.get(stable_id)
        if pair is None:
            return None
        baseline_outcome, candidate_outcome = pair
        booleans = ("actionable", "blocked", "signal", "scan_error")
        if (
            baseline_outcome.get("label") != label
            or candidate_outcome.get("label") != label
            or any(type(outcome.get(field)) is not bool for outcome in pair for field in booleans)
            or baseline_outcome["scan_error"]
            or candidate_outcome["scan_error"]
        ):
            return None
        return pair

    benign_pairs = {stable_id: classified(stable_id, label="benign") for stable_id in benign_sample_ids}
    malicious_pairs = {stable_id: classified(stable_id, label="malicious") for stable_id in malicious_sample_ids}
    if any(pair is None for pair in (*benign_pairs.values(), *malicious_pairs.values())):
        return None

    baseline_actionable = sorted(
        stable_id for stable_id, pair in benign_pairs.items() if pair is not None and pair[0]["actionable"]
    )
    candidate_actionable = sorted(
        stable_id for stable_id, pair in benign_pairs.items() if pair is not None and pair[1]["actionable"]
    )
    resolved_actionable = sorted(set(baseline_actionable) - set(candidate_actionable))
    malicious_block_loss = sorted(
        stable_id
        for stable_id, pair in malicious_pairs.items()
        if pair is not None and pair[0]["blocked"] and not pair[1]["blocked"]
    )
    relative_reduction = (
        (len(baseline_actionable) - len(candidate_actionable)) / len(baseline_actionable)
        if baseline_actionable
        else None
    )
    benign_ids = sorted(benign_sample_ids)
    malicious_ids = sorted(malicious_sample_ids)
    baseline_identity = _evidence_identity(baseline_report, "baseline")
    candidate_identity = _evidence_identity(candidate_report, "candidate")
    return {
        "normalized_loss_evidence_status": "computed_exact_sample_outcomes",
        "normalized_loss_evidence_exact": True,
        "normalized_loss_population_sha256": normalized_loss_population_sha256(
            rule_id=rule_id,
            targeted_benign_sample_ids=benign_ids,
            baseline_actionable_sample_ids=baseline_actionable,
            candidate_actionable_sample_ids=candidate_actionable,
            resolved_actionable_sample_ids=resolved_actionable,
            malicious_support_sample_ids=malicious_ids,
            malicious_block_loss_sample_ids=malicious_block_loss,
        ),
        "normalized_loss_generation_sha256": normalized_loss_generation_sha256(
            baseline_identity,
            candidate_identity,
        ),
        "baseline_actionable_fp_sample_ids": baseline_actionable,
        "candidate_actionable_fp_sample_ids": candidate_actionable,
        "resolved_actionable_fp_sample_ids": resolved_actionable,
        "malicious_block_loss_sample_ids": malicious_block_loss,
        "relative_actionable_fp_reduction": relative_reduction,
        "passes_twenty_percent_reduction": (
            relative_reduction is not None and relative_reduction + _EPSILON >= 0.20 and not malicious_block_loss
        ),
    }


def _rule_promotion_evidence(
    baseline_report: Mapping[str, Any],
    candidate_report: Mapping[str, Any],
    fixture_evidence: Mapping[str, Any] | None,
    *,
    promoted_rule_ids: frozenset[str],
) -> dict[str, Any]:
    tracks = _tracks(candidate_report, "candidate")
    fixture_coverage = _rule_fixture_coverage(fixture_evidence)
    unexpected_fixture_rules = sorted(set(fixture_coverage) - set(promoted_rule_ids))
    if unexpected_fixture_rules:
        raise BenchmarkComparisonError(
            f"rule fixture evidence contains rules outside the explicit promotion set: {unexpected_fixture_rules}"
        )
    candidate_mode = candidate_report.get("cel_mode")
    if candidate_mode not in {CelMode.SHADOW.value, CelMode.ENFORCE.value}:
        raise BenchmarkComparisonError("rule promotion evidence requires a shadow or enforce candidate report")
    evidence: dict[str, dict[str, Any]] = {}
    observed_rule_ids: set[str] = set()
    for track_name, track in tracks.items():
        outcomes_format = track.get("sample_outcomes_format")
        if outcomes_format not in {None, "cel-referenced-v3"}:
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} uses unsupported sample outcome format {outcomes_format!r}"
            )
        compact_references = outcomes_format == "cel-referenced-v3"
        outcomes = _mapping(track.get("sample_outcomes"), f"candidate.tracks.{track_name}.sample_outcomes")
        annotated_counts: dict[str, dict[str, int]] = {}
        annotated_would_suppress_samples: set[str] = set()
        annotated_fallback_samples: set[str] = set()
        annotated_suppressed_samples: set[str] = set()
        for benchmark_id, raw_outcome in outcomes.items():
            outcome = _mapping(
                raw_outcome,
                f"candidate.tracks.{track_name}.sample_outcomes.{benchmark_id}",
            )
            label = outcome.get("label")
            findings = outcome.get("findings")
            if label not in {"malicious", "benign"} or not isinstance(findings, list):
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} has invalid sample outcome {benchmark_id!r}"
                )
            suppressed_entries = outcome.get("cel_suppressed", [])
            if not isinstance(suppressed_entries, list):
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} has invalid suppressed CEL evidence for {benchmark_id!r}"
                )
            for raw_entry in suppressed_entries:
                entry = _mapping(
                    raw_entry,
                    f"candidate.tracks.{track_name}.sample_outcomes.{benchmark_id}.cel_suppressed",
                )
                expected_suppressed_fields = (
                    {"rule_id", "category", "severity", "analyzer", "count"}
                    if compact_references
                    else {
                        "rule_id",
                        "category",
                        "severity",
                        "analyzer",
                        "count",
                        "expression_hash",
                        "pack",
                        "rollout",
                    }
                )
                if set(entry) != expected_suppressed_fields:
                    raise BenchmarkComparisonError(
                        f"candidate track {track_name!r} has invalid suppressed CEL fields for {benchmark_id!r}"
                    )
                rule_id = entry.get("rule_id")
                category = entry.get("category")
                severity = entry.get("severity")
                analyzer = entry.get("analyzer")
                count = entry.get("count")
                if (
                    not isinstance(rule_id, str)
                    or not rule_id
                    or not isinstance(category, str)
                    or not category
                    or severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"}
                    or not isinstance(analyzer, str)
                    or not analyzer
                    or isinstance(count, bool)
                    or not isinstance(count, int)
                    or count <= 0
                ):
                    raise BenchmarkComparisonError(
                        f"candidate track {track_name!r} has invalid suppressed CEL identity for {benchmark_id!r}"
                    )
                decisions = annotated_counts.setdefault(
                    rule_id,
                    {"keep": 0, "would_suppress": 0, "fallback": 0, "suppressed": 0},
                )
                decisions["would_suppress"] += count
                decisions["suppressed"] += count
                annotated_would_suppress_samples.add(benchmark_id)
                annotated_suppressed_samples.add(benchmark_id)
                if rule_id in promoted_rule_ids and severity in {"CRITICAL", "HIGH", "MEDIUM"}:
                    rule = evidence.setdefault(
                        rule_id,
                        {
                            "malicious_support_sample_ids": set(),
                            "benign_near_miss_sample_ids": set(),
                            "targeted_benign_findings": 0,
                            "would_suppress_benign_findings": 0,
                            "would_suppress_malicious_high_critical_findings": 0,
                            "would_suppress_malicious_high_critical_sample_ids": set(),
                        },
                    )
                    stable_id = f"{track_name}:{benchmark_id}"
                    if label == "malicious":
                        rule["malicious_support_sample_ids"].add(stable_id)
                        if severity in {"CRITICAL", "HIGH"}:
                            rule["would_suppress_malicious_high_critical_findings"] += count
                            rule["would_suppress_malicious_high_critical_sample_ids"].add(stable_id)
                    elif label == "benign":
                        rule["benign_near_miss_sample_ids"].add(stable_id)
                        rule["targeted_benign_findings"] += count
                        rule["would_suppress_benign_findings"] += count

            for raw_finding in findings:
                finding = _mapping(
                    raw_finding,
                    f"candidate.tracks.{track_name}.sample_outcomes.{benchmark_id}.finding",
                )
                severity = finding.get("severity")
                singular_decision = finding.get("cel_decision")
                raw_lineage = finding.get("cel_decisions")
                if raw_lineage is None:
                    if singular_decision is None:
                        continue
                    raw_lineage = [
                        {
                            "rule_id": finding.get("rule_id"),
                            "decision": singular_decision,
                            "count": 1,
                        }
                    ]
                    strict_lineage = False
                else:
                    if not isinstance(raw_lineage, list) or len(raw_lineage) > 4_096:
                        raise BenchmarkComparisonError(
                            f"candidate track {track_name!r} has invalid CEL lineage for {benchmark_id!r}"
                        )
                    strict_lineage = True
                singular_found = singular_decision is None
                for raw_entry in raw_lineage:
                    entry = _mapping(
                        raw_entry,
                        f"candidate.tracks.{track_name}.sample_outcomes.{benchmark_id}.cel_decisions",
                    )
                    expected_lineage_fields = (
                        {"rule_id", "decision", "count"}
                        if compact_references
                        else {
                            "rule_id",
                            "decision",
                            "reason",
                            "fact_schema",
                            "expression_hash",
                            "pack",
                            "rollout",
                            "count",
                        }
                    )
                    if strict_lineage and set(entry) != expected_lineage_fields:
                        raise BenchmarkComparisonError(
                            f"candidate track {track_name!r} has invalid CEL lineage fields for {benchmark_id!r}"
                        )
                    rule_id = entry.get("rule_id")
                    decision = entry.get("decision")
                    count = entry.get("count", 1)
                    if (
                        not isinstance(rule_id, str)
                        or not rule_id
                        or decision not in {"keep", "would_suppress", "fallback"}
                        or isinstance(count, bool)
                        or not isinstance(count, int)
                        or count <= 0
                    ):
                        raise BenchmarkComparisonError(
                            f"candidate track {track_name!r} has invalid CEL lineage identity for {benchmark_id!r}"
                        )
                    singular_found = singular_found or (
                        rule_id == finding.get("rule_id") and decision == singular_decision
                    )
                    decisions = annotated_counts.setdefault(
                        rule_id,
                        {"keep": 0, "would_suppress": 0, "fallback": 0, "suppressed": 0},
                    )
                    decisions[decision] += count
                    if decision == "would_suppress":
                        annotated_would_suppress_samples.add(benchmark_id)
                    elif decision == "fallback":
                        annotated_fallback_samples.add(benchmark_id)
                    if rule_id not in promoted_rule_ids:
                        continue
                    if severity not in {"CRITICAL", "HIGH", "MEDIUM"}:
                        continue
                    rule = evidence.setdefault(
                        rule_id,
                        {
                            "malicious_support_sample_ids": set(),
                            "benign_near_miss_sample_ids": set(),
                            "targeted_benign_findings": 0,
                            "would_suppress_benign_findings": 0,
                            "would_suppress_malicious_high_critical_findings": 0,
                            "would_suppress_malicious_high_critical_sample_ids": set(),
                        },
                    )
                    stable_id = f"{track_name}:{benchmark_id}"
                    if label == "malicious":
                        rule["malicious_support_sample_ids"].add(stable_id)
                        if severity in {"CRITICAL", "HIGH"} and decision == "would_suppress":
                            rule["would_suppress_malicious_high_critical_findings"] += count
                            rule["would_suppress_malicious_high_critical_sample_ids"].add(stable_id)
                    elif label == "benign":
                        rule["benign_near_miss_sample_ids"].add(stable_id)
                        rule["targeted_benign_findings"] += count
                        if decision == "would_suppress":
                            rule["would_suppress_benign_findings"] += count
                if not singular_found:
                    raise BenchmarkComparisonError(
                        f"candidate track {track_name!r} CEL winner is absent from lineage for {benchmark_id!r}"
                    )

        cel = _mapping(track.get("cel"), f"candidate.tracks.{track_name}.cel")
        reported_would_suppress = _string_set(
            cel.get("would_suppress_sample_ids", []),
            f"candidate.tracks.{track_name}.cel.would_suppress_sample_ids",
        )
        reported_fallbacks = _string_set(
            cel.get("fallback_sample_ids", []),
            f"candidate.tracks.{track_name}.cel.fallback_sample_ids",
        )
        reported_suppressed = _string_set(
            cel.get("suppressed_sample_ids", []),
            f"candidate.tracks.{track_name}.cel.suppressed_sample_ids",
        )
        if annotated_would_suppress_samples != reported_would_suppress:
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL would-suppress outcomes disagree with telemetry"
            )
        if annotated_fallback_samples != reported_fallbacks:
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL fallback outcomes disagree with telemetry"
            )
        if annotated_suppressed_samples != reported_suppressed:
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL suppressed outcomes disagree with telemetry"
            )
        if _number(cel.get("would_suppress"), f"candidate.tracks.{track_name}.cel.would_suppress") != sum(
            counts["would_suppress"] for counts in annotated_counts.values()
        ):
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL would-suppress count disagrees with sample outcomes"
            )
        if _number(cel.get("fallbacks"), f"candidate.tracks.{track_name}.cel.fallbacks") != sum(
            counts["fallback"] for counts in annotated_counts.values()
        ):
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL fallback count disagrees with sample outcomes"
            )
        if _number(cel.get("suppressed"), f"candidate.tracks.{track_name}.cel.suppressed") != sum(
            counts["suppressed"] for counts in annotated_counts.values()
        ):
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL suppressed count disagrees with sample outcomes"
            )
        reported_rules = _mapping(cel.get("per_rule", {}), f"candidate.tracks.{track_name}.cel.per_rule")
        if set(reported_rules) != set(annotated_counts):
            raise BenchmarkComparisonError(
                f"candidate track {track_name!r} CEL per-rule outcomes disagree with sample outcomes"
            )
        for rule_id, counts in annotated_counts.items():
            reported = _mapping(
                reported_rules[rule_id],
                f"candidate.tracks.{track_name}.cel.per_rule.{rule_id}",
            )
            if any(reported.get(decision) != count for decision, count in counts.items()):
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} CEL per-rule counts disagree for {rule_id!r}"
                )
            observed_rule_ids.add(rule_id)
            rollouts = _string_set(
                reported.get("rollouts", []),
                f"candidate.tracks.{track_name}.cel.per_rule.{rule_id}.rollouts",
            )
            if len(rollouts) != 1:
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} CEL rule {rule_id!r} must report exactly one rollout"
                )
            rollout = next(iter(rollouts))
            if rollout not in {"shadow", "enforce"}:
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} CEL rule {rule_id!r} reports an invalid rollout"
                )

            # The explicit promotion set is the authoritative rollout boundary.
            # In global shadow mode no rule may suppress. In global enforce mode,
            # only explicitly promoted rules may have an enforce rollout, and an
            # enforce-rollout rule must suppress every false decision instead of
            # retaining a contradictory would-suppress lineage.
            expected_rollout = "enforce" if rule_id in promoted_rule_ids else "shadow"
            if candidate_mode == CelMode.ENFORCE.value and rollout != expected_rollout:
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} CEL rollout disagrees with the explicit promoted rule set "
                    f"for {rule_id!r}"
                )
            if candidate_mode == CelMode.SHADOW.value and counts["suppressed"] != 0:
                raise BenchmarkComparisonError(
                    f"candidate track {track_name!r} suppressed CEL decisions while global mode is shadow"
                )
            if candidate_mode == CelMode.ENFORCE.value:
                if rollout == "enforce" and counts["suppressed"] != counts["would_suppress"]:
                    raise BenchmarkComparisonError(
                        f"candidate track {track_name!r} retained false CEL decisions for enforced rule {rule_id!r}"
                    )
                if rollout == "shadow" and counts["suppressed"] != 0:
                    raise BenchmarkComparisonError(
                        f"candidate track {track_name!r} suppressed a shadow-rollout CEL rule {rule_id!r}"
                    )

    missing_promoted_rules = sorted(promoted_rule_ids - observed_rule_ids)
    if missing_promoted_rules:
        raise BenchmarkComparisonError(
            f"candidate CEL telemetry never evaluated explicitly promoted rules: {missing_promoted_rules}"
        )

    finalized: dict[str, Any] = {}
    for rule_id in sorted(promoted_rule_ids):
        rule = evidence.get(
            rule_id,
            {
                "malicious_support_sample_ids": set(),
                "benign_near_miss_sample_ids": set(),
                "targeted_benign_findings": 0,
                "would_suppress_benign_findings": 0,
                "would_suppress_malicious_high_critical_findings": 0,
                "would_suppress_malicious_high_critical_sample_ids": set(),
            },
        )
        fixtures = fixture_coverage.get(
            rule_id,
            {
                "true_positive_fixture_ids": [],
                "benign_near_miss_fixture_ids": [],
                "boundary_fixture_ids": [],
            },
        )
        targeted = rule["targeted_benign_findings"]
        suppressed = rule["would_suppress_benign_findings"]
        malicious_ids = sorted(rule["malicious_support_sample_ids"])
        benign_ids = sorted(rule["benign_near_miss_sample_ids"])
        malicious_high_critical_ids = sorted(rule["would_suppress_malicious_high_critical_sample_ids"])
        malicious_high_critical_findings = rule["would_suppress_malicious_high_critical_findings"]
        true_positive_fixture_ids = fixtures["true_positive_fixture_ids"]
        benign_near_miss_fixture_ids = fixtures["benign_near_miss_fixture_ids"]
        boundary_fixture_ids = fixtures["boundary_fixture_ids"]
        normalized_loss = None
        if candidate_mode == CelMode.ENFORCE.value and len(promoted_rule_ids) == 1:
            normalized_loss = _exact_normalized_loss_evidence(
                baseline_report,
                candidate_report,
                rule_id=rule_id,
                benign_sample_ids=benign_ids,
                malicious_sample_ids=malicious_ids,
            )
        if normalized_loss is None:
            normalized_loss = {
                "normalized_loss_evidence_status": "not_available",
                "normalized_loss_evidence_exact": False,
                "normalized_loss_population_sha256": None,
                "normalized_loss_generation_sha256": None,
                "baseline_actionable_fp_sample_ids": [],
                "candidate_actionable_fp_sample_ids": [],
                "resolved_actionable_fp_sample_ids": [],
                "malicious_block_loss_sample_ids": [],
                "relative_actionable_fp_reduction": None,
                "passes_twenty_percent_reduction": False,
            }
        eligible = (
            normalized_loss["normalized_loss_evidence_exact"] is True
            and normalized_loss["passes_twenty_percent_reduction"] is True
            and bool(malicious_ids)
            and bool(true_positive_fixture_ids)
            and bool(benign_near_miss_fixture_ids)
            and bool(boundary_fixture_ids)
        )
        finalized[rule_id] = {
            "malicious_support_sample_ids": malicious_ids,
            "benign_near_miss_sample_ids": benign_ids,
            "true_positive_fixture_ids": true_positive_fixture_ids,
            "benign_near_miss_fixture_ids": benign_near_miss_fixture_ids,
            "boundary_fixture_ids": boundary_fixture_ids,
            "observed_targeted_benign_candidates": targeted,
            "observed_would_suppress_benign_candidates": suppressed,
            "observed_would_suppress_malicious_high_critical_candidates": malicious_high_critical_findings,
            "observed_would_suppress_malicious_high_critical_sample_ids": malicious_high_critical_ids,
            **normalized_loss,
            "has_malicious_support": bool(malicious_ids),
            "has_true_positive_fixture": bool(true_positive_fixture_ids),
            "has_benign_near_miss_fixture": bool(benign_near_miss_fixture_ids),
            "has_boundary_fixture": bool(boundary_fixture_ids),
            "eligible_for_promotion": eligible,
        }
    return finalized


def _stability_fingerprint(report: Mapping[str, Any]) -> str:
    tracks = _tracks(report, "candidate")
    normalized: dict[str, Any] = {}
    for track_name, track in sorted(tracks.items()):
        cel = _mapping(track.get("cel"), f"candidate.tracks.{track_name}.cel")
        normalized[track_name] = {
            "sample_outcomes": track.get("sample_outcomes"),
            "sample_outcomes_count": track.get("sample_outcomes_count"),
            "sample_outcomes_sha256": track.get("sample_outcomes_sha256"),
            "tp": track.get("tp"),
            "tn": track.get("tn"),
            "fp": track.get("fp"),
            "fn": track.get("fn"),
            "critical_high_false_negative_ids": track.get("critical_high_false_negative_ids"),
            "cel": {
                field: cel.get(field)
                for field in (
                    "modes",
                    "runtimes",
                    "runtime_versions",
                    "fact_schemas",
                    "expression_set_hashes",
                    "evaluated",
                    "retained",
                    "would_suppress",
                    "suppressed",
                    "fallbacks",
                    "projection_incomplete",
                    "error_counts",
                    "per_rule",
                    "would_suppress_sample_ids",
                    "suppressed_sample_ids",
                    "fallback_sample_ids",
                    "projection_incomplete_sample_ids",
                )
            },
        }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compare_repeated_benchmark_reports(
    baseline_report: Mapping[str, Any],
    candidate_reports: Sequence[Mapping[str, Any]],
    *,
    rule_fixture_evidence: Mapping[str, Any] | None = None,
    promoted_rule_ids: Sequence[str] | None = None,
    require_rule_promotion_evidence: bool = True,
) -> dict[str, Any]:
    """Require five stable candidate runs plus independent rule-fixture coverage.

    Runtime fallback telemetry is deliberately not accepted as evidence of a
    malformed/projection-boundary fixture: mandatory benchmark runs must have
    zero fallbacks. Callers promoting rules supply reviewed committed fixture
    IDs through ``rule_fixture_evidence`` and the exact intended rule set
    through ``promoted_rule_ids``. Other shadow rules are still fully
    reconciled, but they cannot become accidental promotion requirements.
    """

    if len(candidate_reports) != 5:
        raise BenchmarkComparisonError("stable comparison requires exactly five candidate runs")
    promoted_rules = _promotion_rule_ids(promoted_rule_ids)
    if require_rule_promotion_evidence and not promoted_rules:
        raise BenchmarkComparisonError(
            "required rule promotion evidence needs an explicit non-empty promoted_rule_ids set"
        )
    comparisons = [compare_benchmark_reports(baseline_report, candidate) for candidate in candidate_reports]
    identities = [
        _evidence_identity(candidate, f"candidate[{index}]") for index, candidate in enumerate(candidate_reports)
    ]
    same_identity = all(identity == identities[0] for identity in identities[1:])
    producers = [
        _producer_identity(candidate, identities[index], f"candidate[{index}]")
        for index, candidate in enumerate(candidate_reports)
    ]
    same_producer = all(producer == producers[0] for producer in producers[1:])
    fingerprints = [_stability_fingerprint(candidate) for candidate in candidate_reports]
    stable_outputs = len(set(fingerprints)) == 1
    rule_evidence = _rule_promotion_evidence(
        baseline_report,
        candidate_reports[0],
        rule_fixture_evidence,
        promoted_rule_ids=promoted_rules,
    )
    rule_promotion_passed = (
        bool(rule_evidence)
        and set(rule_evidence) == set(promoted_rules)
        and all(rule["eligible_for_promotion"] for rule in rule_evidence.values())
    )
    if not require_rule_promotion_evidence:
        rule_promotion_passed = True
    passed = (
        same_identity
        and same_producer
        and stable_outputs
        and rule_promotion_passed
        and all(comparison["status"] == "passed" for comparison in comparisons)
    )
    return {
        "schema_version": 1,
        "status": "passed" if passed else "failed",
        "runs": len(candidate_reports),
        "same_evidence_identity": same_identity,
        "same_producer_identity": same_producer,
        "stable_output": stable_outputs,
        "stability_fingerprints": fingerprints,
        "rule_promotion_evidence": rule_evidence,
        "rule_promotion_evidence_required": require_rule_promotion_evidence,
        "rule_promotion_passed": rule_promotion_passed,
        "comparisons": comparisons,
    }


def run_cel_mode_comparison(
    snapshot_dir: Path,
    *,
    candidate_mode: CelMode | str,
    dataset_id: str | None = None,
    dataset_lock: Path | None = None,
    profile: str = "release",
    scanner_factory: Callable[[str, CelMode], Any] | None = None,
) -> dict[str, Any]:
    """Run CEL-off and candidate-mode scans, then compare locked reports."""

    mode = CelMode(candidate_mode)
    if mode is CelMode.OFF:
        raise BenchmarkComparisonError("candidate_mode must be shadow or enforce")
    common: dict[str, Any] = {
        "dataset_id": dataset_id,
        "dataset_lock": dataset_lock,
        "profile": profile,
    }
    if scanner_factory is not None:
        common["scanner_factory"] = scanner_factory
    baseline = run_public_benchmark(snapshot_dir, cel_mode=CelMode.OFF, **common)
    candidate = run_public_benchmark(snapshot_dir, cel_mode=mode, **common)
    return {
        "schema_version": 1,
        "baseline": baseline,
        "candidate": candidate,
        "comparison": compare_benchmark_reports(baseline, candidate),
    }


def run_repeated_cel_mode_comparison(
    snapshot_dir: Path,
    *,
    candidate_mode: CelMode | str,
    dataset_id: str | None = None,
    dataset_lock: Path | None = None,
    profile: str = "release",
    scanner_factory: Callable[[str, CelMode], Any] | None = None,
    rule_fixture_evidence: Mapping[str, Any] | None = None,
    promoted_rule_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run one OFF baseline plus five active-mode candidates."""

    mode = CelMode(candidate_mode)
    if mode is CelMode.OFF:
        raise BenchmarkComparisonError("candidate_mode must be shadow or enforce")
    common: dict[str, Any] = {
        "dataset_id": dataset_id,
        "dataset_lock": dataset_lock,
        "profile": profile,
    }
    if scanner_factory is not None:
        common["scanner_factory"] = scanner_factory
    baseline = run_public_benchmark(snapshot_dir, cel_mode=CelMode.OFF, **common)
    candidates = [run_public_benchmark(snapshot_dir, cel_mode=mode, **common) for _ in range(5)]
    return {
        "schema_version": 1,
        "baseline": baseline,
        "candidates": candidates,
        "comparison": compare_repeated_benchmark_reports(
            baseline,
            candidates,
            rule_fixture_evidence=rule_fixture_evidence,
            promoted_rule_ids=promoted_rule_ids,
        ),
    }
