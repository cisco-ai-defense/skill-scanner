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

"""Run non-blocking drift/disagreement analysis on pinned raw ClawHub data.

This runner never downloads or executes samples and never treats an upstream
scanner verdict as ground truth.  It accepts only the offline snapshot adapter
and a deterministic static scanner.  All decode, materialization, analyzer,
and scan errors remain represented in the fixed population denominator.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from evals.datasets.clawhub_security_signals import (
    DATASET_ID,
    RAW_CONTRACT_FILE,
    SPLIT_ORDER,
    ClawhubRowRecord,
    ClawhubSecuritySignalsError,
    ClawhubSecuritySignalsSnapshot,
    iter_clawhub_security_signal_rows,
    load_clawhub_security_signals_snapshot,
)
from evals.datasets.public_datasets import (
    LOCK_FILE,
    get_locked_dataset,
    load_dataset_lock,
    materialize_locked_skill_row,
)

_ACTIONABLE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
_POSITIVE_EXTERNAL_STATUSES = frozenset({"suspicious", "malicious"})
_MAX_CANDIDATE_RECORDS = 10_000
_CEL_COUNT_FIELDS = (
    "evaluated",
    "retained",
    "would_suppress",
    "suppressed",
    "fallbacks",
    "projection_incomplete",
)
_CEL_TIMING_FIELDS = ("elapsed_ms", "projection_ms", "evaluation_ms")
_CEL_IDENTITY_FIELDS = ("mode", "runtime", "runtime_version", "fact_schema", "expression_set_hash")


class StaticSkillScanner(Protocol):
    """Minimal scanner contract; implementations must be static and offline."""

    def scan_skill(self, skill_directory: Path) -> Any: ...


class ClawhubBenchmarkError(ValueError):
    """Raised when a supplemental benchmark cannot be evaluated safely."""


def _enum_name(value: Any) -> str:
    return str(getattr(value, "value", value)).upper()


def _finding_value(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _finding_summary(findings: Sequence[Any]) -> tuple[bool, list[str], list[str], Counter[str], Counter[str]]:
    actionable = False
    rule_ids: set[str] = set()
    analyzers: set[str] = set()
    severities: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    for finding in findings:
        severity = _enum_name(_finding_value(finding, "severity", "UNKNOWN"))
        rule_id = str(_finding_value(finding, "rule_id", "UNKNOWN"))[:256]
        analyzer = str(_finding_value(finding, "analyzer", "UNKNOWN"))[:128]
        actionable = actionable or severity in _ACTIONABLE_SEVERITIES
        severities[severity] += 1
        rules[rule_id] += 1
        rule_ids.add(rule_id)
        analyzers.add(analyzer)
    return actionable, sorted(rule_ids)[:64], sorted(analyzers)[:32], severities, rules


def _signal_state(value: Any) -> str:
    if not isinstance(value, str):
        return "unavailable"
    return "positive" if value.casefold() in _POSITIVE_EXTERNAL_STATUSES else "non_positive"


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _top_groups(counter: Counter[str], *, limit: int = 100) -> list[dict[str, int | str]]:
    return [
        {"group_sha256": group, "candidates": count}
        for group, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def _candidate_record(
    record: ClawhubRowRecord,
    *,
    finding_count: int,
    rule_ids: Sequence[str],
    analyzers: Sequence[str],
) -> dict[str, Any]:
    return {
        "row_id": record.row_id,
        "split": record.split,
        "provenance": dict(record.provenance),
        "grouping": dict(record.grouping),
        "finding_count": finding_count,
        "rule_ids": list(rule_ids),
        "analyzers": list(analyzers),
    }


def _error_record(record: ClawhubRowRecord, *, stage: str, code: str) -> dict[str, Any]:
    return {
        "row_id": record.row_id,
        "split": record.split,
        "line_number": record.line_number,
        "stage": stage,
        "code": code,
        "provenance": dict(record.provenance),
    }


def _new_bucket() -> dict[str, int]:
    return {
        "population": 0,
        "ingestion_errors": 0,
        "materialization_errors": 0,
        "scan_errors": 0,
        "scan_completed": 0,
        "any_finding": 0,
        "actionable": 0,
    }


def _increment_bucket(bucket: dict[str, int], key: str) -> None:
    bucket[key] = bucket.get(key, 0) + 1


def _new_cel_aggregate() -> dict[str, Any]:
    return {
        "samples_with_metadata": 0,
        "samples_without_metadata": 0,
        "invalid_metadata_samples": 0,
        "identity": {field: set() for field in _CEL_IDENTITY_FIELDS},
        "totals": Counter(),
        "timing_ms": {field: 0.0 for field in _CEL_TIMING_FIELDS},
        "errors": Counter(),
        "per_rule": {},
    }


def _record_cel_telemetry(aggregate: dict[str, Any], result: Any) -> None:
    scan_metadata = getattr(result, "scan_metadata", None)
    cel = scan_metadata.get("cel") if isinstance(scan_metadata, Mapping) else None
    if not isinstance(cel, Mapping):
        aggregate["samples_without_metadata"] += 1
        return
    aggregate["samples_with_metadata"] += 1
    invalid = False
    for field in _CEL_IDENTITY_FIELDS:
        value = cel.get(field)
        if not isinstance(value, str):
            invalid = True
        else:
            aggregate["identity"][field].add(value)
    for field in _CEL_COUNT_FIELDS:
        value = cel.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            invalid = True
        else:
            aggregate["totals"][field] += value
    for field in _CEL_TIMING_FIELDS:
        value = cel.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            invalid = True
        else:
            aggregate["timing_ms"][field] += float(value)
    errors = cel.get("errors")
    if not isinstance(errors, list):
        invalid = True
    else:
        for error in errors:
            code = error.get("code") if isinstance(error, Mapping) else None
            aggregate["errors"][str(code)[:128] if isinstance(code, str) else "INVALID_ERROR_RECORD"] += 1
    per_rule = cel.get("per_rule")
    if not isinstance(per_rule, Mapping):
        invalid = True
    else:
        for rule_id, values in per_rule.items():
            if not isinstance(rule_id, str) or not isinstance(values, Mapping):
                invalid = True
                continue
            output = aggregate["per_rule"].setdefault(
                rule_id[:256],
                {
                    "keep": 0,
                    "would_suppress": 0,
                    "fallback": 0,
                    "suppressed": 0,
                    "expression_hashes": set(),
                    "packs": set(),
                    "rollouts": set(),
                },
            )
            for field in ("keep", "would_suppress", "fallback", "suppressed"):
                value = values.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    invalid = True
                else:
                    output[field] += value
            for source_field, target_field in (
                ("expression_hash", "expression_hashes"),
                ("pack", "packs"),
                ("rollout", "rollouts"),
            ):
                value = values.get(source_field)
                if not isinstance(value, str):
                    invalid = True
                else:
                    output[target_field].add(value[:256])
    if invalid:
        aggregate["invalid_metadata_samples"] += 1


def _render_cel_aggregate(aggregate: dict[str, Any]) -> dict[str, Any]:
    per_rule: dict[str, dict[str, Any]] = {}
    for rule_id, values in sorted(aggregate["per_rule"].items()):
        per_rule[rule_id] = {
            "keep": values["keep"],
            "would_suppress": values["would_suppress"],
            "fallback": values["fallback"],
            "suppressed": values["suppressed"],
            "expression_hashes": sorted(values["expression_hashes"]),
            "packs": sorted(values["packs"]),
            "rollouts": sorted(values["rollouts"]),
        }
    return {
        "samples_with_metadata": aggregate["samples_with_metadata"],
        "samples_without_metadata": aggregate["samples_without_metadata"],
        "invalid_metadata_samples": aggregate["invalid_metadata_samples"],
        "identity_values": {field: sorted(aggregate["identity"][field]) for field in _CEL_IDENTITY_FIELDS},
        "totals": _counter_dict(aggregate["totals"]),
        "timing_ms": {field: round(aggregate["timing_ms"][field], 3) for field in _CEL_TIMING_FIELDS},
        "error_codes": _counter_dict(aggregate["errors"]),
        "per_rule": per_rule,
    }


def run_clawhub_security_signals_benchmark(
    snapshot: ClawhubSecuritySignalsSnapshot,
    *,
    scanner: StaticSkillScanner,
    max_candidate_records: int = 1_000,
    temporary_root: Path | None = None,
) -> dict[str, Any]:
    """Scan a pinned snapshot and report non-authoritative disagreement data."""

    if isinstance(max_candidate_records, bool) or not 0 <= max_candidate_records <= _MAX_CANDIDATE_RECORDS:
        raise ClawhubBenchmarkError(f"max_candidate_records must be between 0 and {_MAX_CANDIDATE_RECORDS}")
    if temporary_root is not None:
        temporary_root = Path(temporary_root)
        if temporary_root.is_symlink() or not temporary_root.is_dir():
            raise ClawhubBenchmarkError("temporary_root must be an existing non-symlink directory")
        temporary_root = temporary_root.resolve(strict=True)
        if temporary_root == snapshot.root or temporary_root.is_relative_to(snapshot.root):
            raise ClawhubBenchmarkError("temporary_root must be outside the immutable dataset snapshot")

    by_split = {split.name: _new_bucket() for split in snapshot.splits}
    by_verdict = {verdict: _new_bucket() for verdict in ("clean", "suspicious", "malicious", "unknown")}
    disagreement_matrix: Counter[str] = Counter()
    external_overlap: dict[str, Counter[str]] = {
        name: Counter() for name in ("static_status", "virustotal_status", "skillspector_status")
    }
    finding_severities: Counter[str] = Counter()
    finding_rules: Counter[str] = Counter()
    false_positive_groups: Counter[str] = Counter()
    family_groups: Counter[str] = Counter()
    false_positive_candidates: list[dict[str, Any]] = []
    review_gap_candidates: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    error_counts: Counter[str] = Counter()
    cel_aggregate = _new_cel_aggregate()
    analyzer_failure_samples = 0
    processed = 0

    with tempfile.TemporaryDirectory(prefix="skill-scanner-clawhub-", dir=temporary_root) as run_dir_text:
        # macOS may spell its real temporary directory through ``/var``, which
        # is a compatibility symlink to ``/private/var``. Resolve the trusted
        # directory created by tempfile before the materializer's strict
        # ancestor-symlink check.
        run_dir = Path(run_dir_text).resolve(strict=True)
        for ordinal, record in enumerate(iter_clawhub_security_signal_rows(snapshot), start=1):
            processed += 1
            split_bucket = by_split[record.split]
            verdict_name = record.silver_verdict or "unknown"
            verdict_bucket = by_verdict[verdict_name]
            _increment_bucket(split_bucket, "population")
            _increment_bucket(verdict_bucket, "population")

            if record.ingestion_error is not None or record.row is None:
                _increment_bucket(split_bucket, "ingestion_errors")
                _increment_bucket(verdict_bucket, "ingestion_errors")
                error_counts[f"ingestion:{record.ingestion_error or 'UNKNOWN'}"] += 1
                disagreement_matrix["silver_unknown/current_unavailable"] += 1
                if len(errors) < max_candidate_records:
                    errors.append(
                        _error_record(
                            record,
                            stage="ingestion",
                            code=record.ingestion_error or "UNKNOWN",
                        )
                    )
                continue

            destination = run_dir / f"sample-{ordinal:08d}"
            try:
                materialized = materialize_locked_skill_row(
                    DATASET_ID,
                    record.row,
                    destination,
                    snapshot.lock_manifest,
                )
            except Exception as exc:
                code = f"{type(exc).__name__}"
                _increment_bucket(split_bucket, "materialization_errors")
                _increment_bucket(verdict_bucket, "materialization_errors")
                error_counts[f"materialization:{code}"] += 1
                disagreement_matrix[f"silver_{verdict_name}/current_unavailable"] += 1
                if len(errors) < max_candidate_records:
                    errors.append(_error_record(record, stage="materialization", code=code))
                continue

            try:
                try:
                    result = scanner.scan_skill(materialized)
                except Exception as exc:
                    code = type(exc).__name__
                    _increment_bucket(split_bucket, "scan_errors")
                    _increment_bucket(verdict_bucket, "scan_errors")
                    error_counts[f"scan:{code}"] += 1
                    disagreement_matrix[f"silver_{verdict_name}/current_unavailable"] += 1
                    if len(errors) < max_candidate_records:
                        errors.append(_error_record(record, stage="scan", code=code))
                    continue

                try:
                    findings = tuple(getattr(result, "findings", ()) or ())
                    failures = tuple(
                        sorted(str(item)[:256] for item in (getattr(result, "analyzers_failed", ()) or ()))
                    )
                    actionable, rule_ids, analyzers, severities, rules = _finding_summary(findings)
                except Exception as exc:
                    code = f"INVALID_RESULT_{type(exc).__name__}"
                    _increment_bucket(split_bucket, "scan_errors")
                    _increment_bucket(verdict_bucket, "scan_errors")
                    error_counts[f"scan:{code}"] += 1
                    disagreement_matrix[f"silver_{verdict_name}/current_unavailable"] += 1
                    if len(errors) < max_candidate_records:
                        errors.append(_error_record(record, stage="scan", code=code))
                    continue
                if failures:
                    analyzer_failure_samples += 1
                _record_cel_telemetry(cel_aggregate, result)
                finding_severities.update(severities)
                finding_rules.update(rules)
                _increment_bucket(split_bucket, "scan_completed")
                _increment_bucket(verdict_bucket, "scan_completed")
                if findings:
                    _increment_bucket(split_bucket, "any_finding")
                    _increment_bucket(verdict_bucket, "any_finding")
                if actionable:
                    _increment_bucket(split_bucket, "actionable")
                    _increment_bucket(verdict_bucket, "actionable")
                state = "actionable" if actionable else "not_actionable"
                disagreement_matrix[f"silver_{verdict_name}/current_{state}"] += 1

                for signal_name in external_overlap:
                    upstream_state = _signal_state(record.row.get(signal_name))
                    external_overlap[signal_name][f"upstream_{upstream_state}/current_{state}"] += 1

                candidate = _candidate_record(
                    record,
                    finding_count=len(findings),
                    rule_ids=rule_ids,
                    analyzers=analyzers,
                )
                if verdict_name == "clean" and actionable:
                    repository_group = record.grouping["repository_group_sha256"]
                    structural_family = record.grouping["structural_family_sha256"]
                    false_positive_groups[repository_group] += 1
                    family_groups[structural_family] += 1
                    if len(false_positive_candidates) < max_candidate_records:
                        false_positive_candidates.append(candidate)
                elif verdict_name in {"suspicious", "malicious"} and not actionable:
                    if len(review_gap_candidates) < max_candidate_records:
                        review_gap_candidates.append(candidate)
            finally:
                # Materialization is text-only and owned by this temporary run.
                # Remove it between rows so the full 67k corpus is never copied
                # into one persistent local tree.
                if destination.exists() and not destination.is_symlink():
                    shutil.rmtree(destination)

    if processed != snapshot.population:
        raise ClawhubBenchmarkError(
            f"row iterator population drift (expected {snapshot.population}, received {processed})"
        )

    total_errors = sum(error_counts.values())
    clean_population = by_verdict["clean"]["population"]
    clean_actionable = by_verdict["clean"]["actionable"]
    report = {
        "schema_version": 1,
        "status": "complete_with_errors" if total_errors or analyzer_failure_samples else "complete",
        "dataset": {
            "id": DATASET_ID,
            "revision": snapshot.revision,
            "config": "default",
            "splits": [split.name for split in snapshot.splits],
            "raw_snapshot_lock_sha256": snapshot.raw_contract_sha256,
            "raw_artifact_manifest_sha256": snapshot.raw_artifact_manifest_sha256,
            "raw_split_artifacts_pinned": True,
            "repository_artifact_manifest_pinned": snapshot.repository_artifact_manifest_pinned,
        },
        "supplemental": True,
        "release_blocking": False,
        "release_decision": "not_applicable",
        "authoritative_metrics_eligible": False,
        "label_scope": "scanner_derived_silver_signals_not_ground_truth",
        "population_denominator": snapshot.population,
        "processed_rows": processed,
        "errors": {
            "total": total_errors,
            "counts": _counter_dict(error_counts),
            "records": errors,
            "records_truncated": total_errors > len(errors),
        },
        "analyzer_failure_samples": analyzer_failure_samples,
        "cel": _render_cel_aggregate(cel_aggregate),
        "drift": {
            "by_split": by_split,
            "by_silver_verdict": by_verdict,
            "finding_severities": _counter_dict(finding_severities),
            "finding_rules": _counter_dict(finding_rules),
        },
        "disagreement": {
            "interpretation": "descriptive overlap only; this is not an accuracy/confusion matrix",
            "silver_verdict_vs_current_actionability": _counter_dict(disagreement_matrix),
            "upstream_signal_vs_current_actionability": {
                key: _counter_dict(external_overlap[key]) for key in sorted(external_overlap)
            },
            "review_gap_candidates": {
                "count": disagreement_matrix["silver_suspicious/current_not_actionable"]
                + disagreement_matrix["silver_malicious/current_not_actionable"],
                "records": review_gap_candidates,
                "records_truncated": (
                    disagreement_matrix["silver_suspicious/current_not_actionable"]
                    + disagreement_matrix["silver_malicious/current_not_actionable"]
                    > len(review_gap_candidates)
                ),
            },
        },
        "false_positive_mining": {
            "interpretation": "human-review candidates only; silver clean is not benign gold",
            "silver_clean_actionable_candidates": clean_actionable,
            "candidate_rate_over_silver_clean": clean_actionable / clean_population if clean_population else 0.0,
            "records": false_positive_candidates,
            "records_truncated": clean_actionable > len(false_positive_candidates),
            "top_repository_groups": _top_groups(false_positive_groups),
            "top_structural_families": _top_groups(family_groups),
        },
    }
    return report


def _build_static_scanner(*, detector_profile: str, cel_mode: str) -> StaticSkillScanner:
    """Build only local deterministic analyzers; no hosted or network analyzer."""

    from skill_scanner.core.analyzer_factory import build_core_analyzers
    from skill_scanner.core.cel.models import CelMode
    from skill_scanner.core.rule_registry import PackLoader, RuleRegistry
    from skill_scanner.core.scan_policy import ScanPolicy
    from skill_scanner.core.scanner import SkillScanner
    from skill_scanner.data import DATA_DIR, list_available_packs, resolve_rule_packs

    policy = ScanPolicy.default()
    policy.cel.mode = CelMode(cel_mode)
    if detector_profile == "core_only":
        registry = RuleRegistry()
        registry.register_pack(PackLoader().load_bundled_pack(DATA_DIR / "packs" / "core"))
        extra_rules = None
    elif detector_profile == "full_packs":
        registry = PackLoader().build_registry()
        extra_rules = resolve_rule_packs(list_available_packs())
    else:  # pragma: no cover - argparse constrains this
        raise ClawhubBenchmarkError(f"unsupported detector profile: {detector_profile}")
    return SkillScanner(
        analyzers=build_core_analyzers(policy, extra_rules_dirs=extra_rules),
        policy=policy,
        rule_registry=registry,
    )


def _write_report(report: Mapping[str, Any], output: Path | None) -> None:
    rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if output is None:
        print(rendered, end="")
        return
    output = Path(output)
    if output.is_symlink():
        raise ClawhubBenchmarkError("output must not be a symbolic link")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.exists() and not output.is_file():
        raise ClawhubBenchmarkError("output must be a regular file path")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _validate_output_target(output: Path | None, *, snapshot: Path, protected_inputs: Sequence[Path]) -> None:
    if output is None:
        return
    output = Path(output)
    parent = output.parent.resolve(strict=False)
    candidate = parent / output.name
    if snapshot.exists() and not snapshot.is_symlink():
        snapshot_root = snapshot.resolve(strict=True)
        if candidate == snapshot_root or candidate.is_relative_to(snapshot_root):
            raise ClawhubBenchmarkError("output must be outside the immutable dataset snapshot")
    for protected in protected_inputs:
        if candidate == protected.resolve(strict=False):
            raise ClawhubBenchmarkError("output must not overwrite a dataset lock or raw-snapshot lock")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True, help="Already-acquired raw snapshot root")
    parser.add_argument("--revision", help="Pinned commit; defaults to the repository dataset lock")
    parser.add_argument("--dataset-lock", type=Path)
    parser.add_argument("--split", action="append", choices=SPLIT_ORDER, dest="splits")
    parser.add_argument("--detector-profile", choices=("core_only", "full_packs"), default="full_packs")
    parser.add_argument("--cel-mode", choices=("off", "shadow"), default="shadow")
    parser.add_argument("--max-candidate-records", type=int, default=1_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    lock = load_dataset_lock(args.dataset_lock) if args.dataset_lock is not None else load_dataset_lock()
    revision = args.revision or get_locked_dataset(DATASET_ID, lock)["revision"]
    try:
        protected_inputs = [
            args.dataset_lock or LOCK_FILE,
            RAW_CONTRACT_FILE,
        ]
        _validate_output_target(args.output, snapshot=args.snapshot, protected_inputs=protected_inputs)
    except (ClawhubBenchmarkError, OSError, RuntimeError) as exc:
        parser.error(str(exc))
    if not args.snapshot.exists() and not args.snapshot.is_symlink():
        _write_report(
            {
                "schema_version": 1,
                "status": "skipped",
                "dataset": {"id": DATASET_ID, "revision": revision},
                "supplemental": True,
                "release_blocking": False,
                "release_decision": "not_applicable",
                "reason": "offline snapshot unavailable; no download was attempted",
            },
            args.output,
        )
        return 0
    try:
        snapshot = load_clawhub_security_signals_snapshot(
            args.snapshot,
            revision=revision,
            splits=tuple(args.splits or SPLIT_ORDER),
            dataset_lock=args.dataset_lock,
        )
        scanner = _build_static_scanner(detector_profile=args.detector_profile, cel_mode=args.cel_mode)
        report = run_clawhub_security_signals_benchmark(
            snapshot,
            scanner=scanner,
            max_candidate_records=args.max_candidate_records,
        )
    except (ClawhubSecuritySignalsError, ClawhubBenchmarkError, OSError, ValueError) as exc:
        report = {
            "schema_version": 1,
            "status": "failed",
            "dataset": {"id": DATASET_ID, "revision": revision},
            "supplemental": True,
            "release_blocking": False,
            "release_decision": "not_applicable",
            "error": {"type": type(exc).__name__, "message": str(exc)[:512]},
        }
        _write_report(report, args.output)
        return 2
    _write_report(report, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
