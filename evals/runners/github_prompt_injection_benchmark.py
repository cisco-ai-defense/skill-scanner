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

"""Nonblocking static benchmarks for GitHub prompt-injection corpora.

The caller supplies an already-configured offline static scanner.  This module
does not construct analyzers, contact services, execute source content, or
interpret a dataset repository.  Each payload is copied into a text-only,
quoted SKILL.md wrapper in a private temporary directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evals.datasets.github_prompt_injection import (
    IN_PAGE_DATASET_ID,
    IN_PAGE_REVISION,
    INJECAGENT_DATASET_ID,
    INJECAGENT_REVISION,
    NOTINJECT_DATASET_ID,
    NOTINJECT_REVISION,
    GitHubPromptInjectionSnapshot,
    PromptInjectionSample,
    load_in_page_snapshot,
    load_injecagent_snapshot,
    load_notinject_snapshot,
    materialize_inert_wrapper,
    revalidate_snapshot,
)
from evals.datasets.public_datasets import LOCK_FILE

_POSITIVE_DATASETS = frozenset({INJECAGENT_DATASET_ID, IN_PAGE_DATASET_ID})
_SIGNAL_CATEGORIES = frozenset({"prompt_injection", "transitive_trust_abuse"})
_ACTIONABLE_SEVERITIES = frozenset({"MEDIUM", "HIGH", "CRITICAL"})
_VALID_SEVERITIES = frozenset({"SAFE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CEL_IDENTITY_FIELDS = ("mode", "runtime", "runtime_version", "fact_schema", "expression_set_hash")
_CEL_COUNT_FIELDS = (
    "evaluated",
    "retained",
    "would_suppress",
    "suppressed",
    "fallbacks",
    "projection_incomplete",
)


class StaticSkillScanner(Protocol):
    """Minimal sync scanner interface for inert, local skill directories."""

    def scan_skill(self, skill_directory: Path) -> Any: ...


@dataclass(frozen=True)
class SupplementalOutcome:
    """Content-free scan outcome for one supplemental identity."""

    sample: PromptInjectionSample
    finding_count: int
    signal_count: int
    signal_detected: bool
    actionable_signal_detected: bool
    signal_findings: tuple[dict[str, str], ...]
    analyzer_failures: tuple[str, ...]
    scan_error: str | None
    candidate_signal_detected: bool
    candidate_actionable_signal_detected: bool
    control_finding_count: int
    control_signal_count: int
    control_signal_detected: bool
    control_actionable_signal_detected: bool
    control_signal_findings: tuple[dict[str, str], ...]
    control_analyzer_failures: tuple[str, ...]
    control_scan_error: str | None
    scanner_metadata: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class _RawScanOutcome:
    finding_count: int
    signal_count: int
    signal_detected: bool
    actionable_signal_detected: bool
    signal_findings: tuple[dict[str, str], ...]
    analyzer_failures: tuple[str, ...]
    scan_error: str | None
    scanner_metadata: dict[str, Any] | None


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _finding_value(finding: Any, field: str) -> Any:
    return finding.get(field, "") if isinstance(finding, Mapping) else getattr(finding, field, "")


def _finding_record(finding: Any) -> dict[str, str]:
    record = {
        "rule_id": _enum_value(_finding_value(finding, "rule_id")),
        "category": _enum_value(_finding_value(finding, "category")).casefold(),
        "severity": _enum_value(_finding_value(finding, "severity")).upper(),
        "analyzer": _enum_value(_finding_value(finding, "analyzer")),
    }
    if (
        not _IDENTITY_RE.fullmatch(record["rule_id"])
        or record["category"] not in _SIGNAL_CATEGORIES
        or record["severity"] not in _VALID_SEVERITIES
        or not _IDENTITY_RE.fullmatch(record["analyzer"])
    ):
        raise ValueError("selected signal finding violates the closed result schema")
    return record


def _is_indirect_injection_signal(finding: Any) -> bool:
    return _enum_value(_finding_value(finding, "category")).casefold() in _SIGNAL_CATEGORIES


def _stable_failure_identity(value: Any) -> str:
    raw = value.get("analyzer", "unknown") if isinstance(value, Mapping) else value
    candidate = _enum_value(raw)
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", candidate):
        return candidate
    digest = hashlib.sha256(candidate.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"analyzer-{digest}"


def _bounded_metadata_string(value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 256 or (not value and not allow_empty):
        raise ValueError("scanner metadata contains an invalid bounded string")
    return value


def _sanitize_scan_metadata(result: Any) -> dict[str, Any] | None:
    raw = getattr(result, "scan_metadata", None)
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("scan_metadata must be a mapping")
    fingerprint = _bounded_metadata_string(raw.get("policy_fingerprint_sha256"))
    if not _HEX64_RE.fullmatch(fingerprint):
        raise ValueError("scanner policy fingerprint is invalid")
    policy = {
        "name": _bounded_metadata_string(raw.get("policy_name")),
        "version": _bounded_metadata_string(raw.get("policy_version")),
        "preset_base": _bounded_metadata_string(raw.get("policy_preset_base"), allow_empty=True),
        "fingerprint_sha256": fingerprint,
    }

    cel_raw = raw.get("cel")
    if not isinstance(cel_raw, Mapping):
        raise ValueError("scanner CEL metadata is missing")
    cel: dict[str, Any] = {
        field: _bounded_metadata_string(cel_raw.get(field), allow_empty=True) for field in _CEL_IDENTITY_FIELDS
    }
    expression_set_hash = cel["expression_set_hash"]
    if expression_set_hash and not _HEX64_RE.fullmatch(expression_set_hash):
        raise ValueError("CEL expression-set identity is invalid")
    for field in _CEL_COUNT_FIELDS:
        value = cel_raw.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("CEL count metadata is invalid")
        cel[field] = value
    for field in ("elapsed_ms", "projection_ms", "evaluation_ms"):
        value = cel_raw.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("CEL timing metadata is invalid")
        cel[field] = float(value)
    error_codes: list[str] = []
    errors = cel_raw.get("errors")
    if not isinstance(errors, list) or len(errors) > 100:
        raise ValueError("CEL error metadata is invalid")
    for error in errors:
        code = error.get("code") if isinstance(error, Mapping) else None
        error_codes.append(_bounded_metadata_string(code))
    cel["error_codes"] = sorted(error_codes)

    per_rule = cel_raw.get("per_rule")
    if not isinstance(per_rule, Mapping):
        raise ValueError("CEL per-rule metadata is invalid")
    rule_identity: dict[str, dict[str, str]] = {}
    for raw_rule_id, raw_values in per_rule.items():
        rule_id = _bounded_metadata_string(raw_rule_id)
        if not _IDENTITY_RE.fullmatch(rule_id) or not isinstance(raw_values, Mapping):
            raise ValueError("CEL per-rule identity is invalid")
        expression_hash = _bounded_metadata_string(raw_values.get("expression_hash"))
        if not _HEX64_RE.fullmatch(expression_hash):
            raise ValueError("CEL rule expression hash is invalid")
        rule_identity[rule_id] = {
            "expression_hash": expression_hash,
            "pack": _bounded_metadata_string(raw_values.get("pack")),
            "rollout": _bounded_metadata_string(raw_values.get("rollout")),
        }
    cel["rule_identity_sha256"] = hashlib.sha256(
        json.dumps(rule_identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    cel["rule_packs"] = sorted({values["pack"] for values in rule_identity.values()})
    cel["rule_count"] = len(rule_identity)

    contract_raw = raw.get("rule_contract")
    if not isinstance(contract_raw, Mapping):
        raise ValueError("scanner rule-contract metadata is missing")
    contract: dict[str, Any] = {}
    for field in ("status",):
        contract[field] = _bounded_metadata_string(contract_raw.get(field))
    for field in ("schema_version", "checked", "invalid_findings"):
        value = contract_raw.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("scanner rule-contract counts are invalid")
        contract[field] = value
    return {"policy": policy, "cel": cel, "rule_contract": contract}


def _scan_payload(
    sample: PromptInjectionSample,
    *,
    scanner: StaticSkillScanner,
    scratch_root: Path,
    control: bool,
) -> _RawScanOutcome:
    directory_name = f"{sample.sample_id}{'-control' if control else ''}"
    destination = scratch_root / directory_name
    if destination.is_absolute() and destination.parent.resolve(strict=True) != scratch_root.resolve(strict=True):
        raise ValueError("sample materialization escaped the private scratch directory")
    package = materialize_inert_wrapper(sample, destination, control=control)
    try:
        result = scanner.scan_skill(package)
    except Exception as exc:  # Errors stay in the metric denominator.
        return _RawScanOutcome(
            finding_count=0,
            signal_count=0,
            signal_detected=False,
            actionable_signal_detected=False,
            signal_findings=(),
            analyzer_failures=(),
            scan_error=f"SCAN_EXCEPTION:{type(exc).__name__}",
            scanner_metadata=None,
        )

    findings = tuple(getattr(result, "findings", ()) or ())
    try:
        signal_findings = tuple(
            _finding_record(finding) for finding in findings if _is_indirect_injection_signal(finding)
        )
        scanner_metadata = _sanitize_scan_metadata(result)
    except (TypeError, ValueError):
        return _RawScanOutcome(
            finding_count=len(findings),
            signal_count=0,
            signal_detected=False,
            actionable_signal_detected=False,
            signal_findings=(),
            analyzer_failures=(),
            scan_error="RESULT_CONTRACT_ERROR",
            scanner_metadata=None,
        )
    actionable = any(item["severity"] in _ACTIONABLE_SEVERITIES for item in signal_findings)
    failures = tuple(
        sorted({_stable_failure_identity(value) for value in (getattr(result, "analyzers_failed", ()) or ())})
    )
    return _RawScanOutcome(
        finding_count=len(findings),
        signal_count=len(signal_findings),
        signal_detected=bool(signal_findings),
        actionable_signal_detected=actionable,
        signal_findings=signal_findings,
        analyzer_failures=failures,
        scan_error=None,
        scanner_metadata=scanner_metadata,
    )


def _scan_one(
    sample: PromptInjectionSample,
    *,
    scanner: StaticSkillScanner,
    scratch_root: Path,
) -> SupplementalOutcome:
    candidate = _scan_payload(sample, scanner=scanner, scratch_root=scratch_root, control=False)
    if sample.control_payload is None:
        control = _RawScanOutcome(0, 0, False, False, (), (), None, None)
    else:
        control = _scan_payload(sample, scanner=scanner, scratch_root=scratch_root, control=True)
    candidate_complete = candidate.scan_error is None and not candidate.analyzer_failures
    control_complete = control.scan_error is None and not control.analyzer_failures
    qualified_signal = (
        candidate_complete and control_complete and candidate.signal_detected and not control.signal_detected
    )
    qualified_actionable = (
        candidate_complete and control_complete and candidate.actionable_signal_detected and not control.signal_detected
    )
    metadata = tuple(value for value in (candidate.scanner_metadata, control.scanner_metadata) if value is not None)
    return SupplementalOutcome(
        sample=sample,
        finding_count=candidate.finding_count,
        signal_count=candidate.signal_count,
        signal_detected=qualified_signal,
        actionable_signal_detected=qualified_actionable,
        signal_findings=candidate.signal_findings,
        analyzer_failures=candidate.analyzer_failures,
        scan_error=candidate.scan_error,
        candidate_signal_detected=candidate.signal_detected,
        candidate_actionable_signal_detected=candidate.actionable_signal_detected,
        control_finding_count=control.finding_count,
        control_signal_count=control.signal_count,
        control_signal_detected=control.signal_detected,
        control_actionable_signal_detected=control.actionable_signal_detected,
        control_signal_findings=control.signal_findings,
        control_analyzer_failures=control.analyzer_failures,
        control_scan_error=control.scan_error,
        scanner_metadata=metadata,
    )


def _scan_snapshot(
    snapshot: GitHubPromptInjectionSnapshot,
    *,
    scanner: StaticSkillScanner,
) -> tuple[SupplementalOutcome, ...]:
    revalidate_snapshot(snapshot)
    temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="skill-scanner-inert-supplemental-",
        dir=temporary_parent,
    ) as temporary:
        scratch_root = Path(temporary)
        os.chmod(scratch_root, 0o700)
        try:
            outcomes = tuple(
                _scan_one(sample, scanner=scanner, scratch_root=scratch_root) for sample in snapshot.samples
            )
        finally:
            revalidate_snapshot(snapshot)
    return outcomes


def _outcome_record(outcome: SupplementalOutcome) -> dict[str, Any]:
    sample = outcome.sample
    return {
        "sample_id": sample.sample_id,
        "source_id": sample.source_id,
        "repository_group_id": sample.repository_group_id,
        "structural_family_id": sample.structural_family_id,
        "lexical_template_id": sample.lexical_template_id,
        "benchmark_labels": list(sample.benchmark_labels),
        "split": sample.split,
        "parent_sample_id": sample.parent_sample_id,
        "split_inherited_from": sample.split_inherited_from,
        "dedup_parent_id": sample.dedup_parent_id,
        "dedup_relation": sample.dedup_relation,
        "content_sha256": sample.content_sha256,
        "normalized_content_sha256": sample.normalized_content_sha256,
        "lexical_template_sha256": sample.lexical_template_sha256,
        "control_content_sha256": sample.control_content_sha256,
        "trigger_count": sample.trigger_count,
        "finding_count": outcome.finding_count,
        "signal_count": outcome.signal_count,
        "signal_detected": outcome.signal_detected,
        "actionable_signal_detected": outcome.actionable_signal_detected,
        "candidate_signal_detected": outcome.candidate_signal_detected,
        "candidate_actionable_signal_detected": outcome.candidate_actionable_signal_detected,
        "control_finding_count": outcome.control_finding_count,
        "control_signal_count": outcome.control_signal_count,
        "control_signal_detected": outcome.control_signal_detected,
        "control_actionable_signal_detected": outcome.control_actionable_signal_detected,
        "signal_findings": list(outcome.signal_findings),
        "control_signal_findings": list(outcome.control_signal_findings),
        "analyzer_failures": list(outcome.analyzer_failures),
        "control_analyzer_failures": list(outcome.control_analyzer_failures),
        "scan_error": outcome.scan_error,
        "control_scan_error": outcome.control_scan_error,
    }


def _group_metrics(
    outcomes: Iterable[SupplementalOutcome],
    attribute: str,
    *,
    rate_name: str,
    deduplicate: bool = True,
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[SupplementalOutcome]] = {}
    seen_groups: dict[str, set[str]] = {}
    for outcome in outcomes:
        key = str(getattr(outcome.sample, attribute))
        seen = seen_groups.setdefault(key, set())
        if deduplicate and outcome.sample.dedup_parent_id in seen:
            continue
        seen.add(outcome.sample.dedup_parent_id)
        grouped.setdefault(key, []).append(outcome)
    result: dict[str, dict[str, Any]] = {}
    for key, members in sorted(grouped.items()):
        detected = sum(member.signal_detected for member in members)
        actionable = sum(member.actionable_signal_detected for member in members)
        result[key] = {
            "samples": len(members),
            "signal_detected": detected,
            "actionable_signal_detected": actionable,
            "scan_errors": sum(
                member.scan_error is not None or member.control_scan_error is not None for member in members
            ),
            rate_name: detected / len(members) if members else 0.0,
            f"{rate_name}_wilson_95": _wilson_interval(detected, len(members)),
        }
    return result


def _wilson_interval(successes: int, population: int) -> list[float]:
    if population <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    proportion = successes / population
    denominator = 1.0 + (z * z / population)
    center = (proportion + z * z / (2.0 * population)) / denominator
    margin = (
        z
        * math.sqrt((proportion * (1.0 - proportion) / population) + z * z / (4.0 * population * population))
        / denominator
    )
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _label_metrics(outcomes: Iterable[SupplementalOutcome], *, rate_name: str) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[SupplementalOutcome]] = {}
    seen_groups: dict[str, set[str]] = {}
    for outcome in outcomes:
        for label in outcome.sample.benchmark_labels:
            seen = seen_groups.setdefault(label, set())
            if outcome.sample.dedup_parent_id in seen:
                continue
            seen.add(outcome.sample.dedup_parent_id)
            grouped.setdefault(label, []).append(outcome)
    result: dict[str, dict[str, Any]] = {}
    for label, members in sorted(grouped.items()):
        detected = sum(member.signal_detected for member in members)
        result[label] = {
            "samples": len(members),
            "signal_detected": detected,
            rate_name: detected / len(members),
            f"{rate_name}_wilson_95": _wilson_interval(detected, len(members)),
        }
    return result


def _scanner_provenance(outcomes: Iterable[SupplementalOutcome]) -> dict[str, Any]:
    outcomes_tuple = tuple(outcomes)
    expected_invocations = sum(1 + int(outcome.sample.control_payload is not None) for outcome in outcomes_tuple)
    records = [record for outcome in outcomes_tuple for record in outcome.scanner_metadata]
    identity_values: set[str] = set()
    cel_totals: Counter[str] = Counter()
    timing_totals: dict[str, float] = {field: 0.0 for field in ("elapsed_ms", "projection_ms", "evaluation_ms")}
    error_codes: Counter[str] = Counter()
    for record in records:
        cel = record["cel"]
        identity = {
            "policy": record["policy"],
            "cel": {
                field: cel[field]
                for field in (*_CEL_IDENTITY_FIELDS, "rule_identity_sha256", "rule_packs", "rule_count")
            },
            "rule_contract": {
                "status": record["rule_contract"]["status"],
                "schema_version": record["rule_contract"]["schema_version"],
            },
        }
        identity_values.add(json.dumps(identity, sort_keys=True, separators=(",", ":")))
        for field in _CEL_COUNT_FIELDS:
            cel_totals[field] += int(cel[field])
        for field in ("elapsed_ms", "projection_ms", "evaluation_ms"):
            timing_totals[field] += float(cel[field])
        error_codes.update(cel["error_codes"])
    if not records:
        status = "unavailable"
    elif len(identity_values) > 1:
        status = "inconsistent"
    elif len(records) != expected_invocations:
        status = "partial"
    else:
        status = "complete"
    return {
        "status": status,
        "expected_scan_invocations": expected_invocations,
        "metadata_scan_invocations": len(records),
        "identity_set_sha256": (
            hashlib.sha256(json.dumps(sorted(identity_values), separators=(",", ":")).encode()).hexdigest()
            if identity_values
            else None
        ),
        "identity": json.loads(next(iter(identity_values))) if len(identity_values) == 1 else None,
        "cel_totals": {field: cel_totals[field] for field in _CEL_COUNT_FIELDS},
        "cel_timing_ms": {
            field: round(timing_totals[field], 3) for field in ("elapsed_ms", "projection_ms", "evaluation_ms")
        },
        "cel_error_codes": {key: error_codes[key] for key in sorted(error_codes)},
    }


def _dedup_summary(samples: Iterable[PromptInjectionSample]) -> dict[str, Any]:
    samples_tuple = tuple(samples)
    relations = Counter(sample.dedup_relation for sample in samples_tuple)
    return {
        "samples": len(samples_tuple),
        "canonical_groups": len({sample.dedup_parent_id for sample in samples_tuple}),
        "primary_representatives": sum(sample.dedup_relation == "canonical" for sample in samples_tuple),
        "relations": {key: relations[key] for key in sorted(relations)},
        "split_inheritance_recorded": all(bool(sample.split_inherited_from) for sample in samples_tuple),
    }


def _report_header(snapshot: GitHubPromptInjectionSnapshot) -> dict[str, Any]:
    return {
        "dataset_id": snapshot.dataset_id,
        "revision": snapshot.revision,
        "dataset_kind": snapshot.kind,
        "adapter_schema_version": snapshot.adapter_schema_version,
        "dataset_lock_entry_sha256": snapshot.lock_entry_sha256,
        "dataset_access": snapshot.access,
        "dataset_license_spdx": snapshot.license_spdx,
        "dataset_code_license_spdx": snapshot.license_code_spdx,
        "dataset_download_policy": snapshot.download_policy,
        "status": "completed",
        "supplemental": True,
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "artifact_manifest_pinned": not snapshot.lock_hashes_pending,
        "adapter_file_hashes_verified": True,
        "observed_artifact_manifest_sha256": snapshot.observed_artifact_manifest_sha256,
        "wrapper_schema_sha256": hashlib.sha256(b"quoted-text-only-skill-wrapper-v1").hexdigest(),
        "execution_policy": {
            "runner_sample_execution": False,
            "runner_network_operations": False,
            "scanner_contract": "caller-supplied-offline-static-scanner",
            "scanner_offline_enforcement": "external_to_runner",
            "wrapper": "quoted_text_only",
        },
    }


def _result_status(outcomes: Iterable[SupplementalOutcome]) -> tuple[str, bool]:
    complete = all(
        outcome.scan_error is None
        and outcome.control_scan_error is None
        and not outcome.analyzer_failures
        and not outcome.control_analyzer_failures
        for outcome in outcomes
    )
    return ("completed" if complete else "incomplete", complete)


def run_indirect_injection_signal_benchmark(
    snapshot: GitHubPromptInjectionSnapshot,
    *,
    scanner: StaticSkillScanner,
) -> dict[str, Any]:
    """Report positive indirect-injection signal recall for positive corpora."""

    if snapshot.dataset_id not in _POSITIVE_DATASETS or snapshot.kind not in {
        "injecagent_positive",
        "in_page_positive",
    }:
        raise ValueError("positive signal benchmark requires an InjecAgent or In-Page snapshot")
    outcomes = _scan_snapshot(snapshot, scanner=scanner)
    primary_outcomes = tuple(outcome for outcome in outcomes if outcome.sample.dedup_relation == "canonical")
    detected = sum(outcome.signal_detected for outcome in primary_outcomes)
    actionable = sum(outcome.actionable_signal_detected for outcome in primary_outcomes)
    raw_detected = sum(outcome.signal_detected for outcome in outcomes)
    raw_actionable = sum(outcome.actionable_signal_detected for outcome in outcomes)
    status, metric_valid = _result_status(outcomes)
    scanner_provenance = _scanner_provenance(outcomes)
    if scanner_provenance["status"] == "inconsistent":
        status, metric_valid = "incomplete", False
    report = _report_header(snapshot)
    report.update(
        {
            "status": status,
            "metric_valid": metric_valid,
            "label_scope": "positive_indirect_injection_signal_only",
            "metric_scope": "signal_recall_not_package_block_recall",
            "population": len(primary_outcomes),
            "signal_detected": detected,
            "positive_signal_recall": detected / len(primary_outcomes) if primary_outcomes else 0.0,
            "positive_signal_recall_wilson_95": _wilson_interval(detected, len(primary_outcomes)),
            "actionable_signal_detected": actionable,
            "actionable_signal_recall": actionable / len(primary_outcomes) if primary_outcomes else 0.0,
            "actionable_signal_recall_wilson_95": _wilson_interval(actionable, len(primary_outcomes)),
            "raw_row_population": len(outcomes),
            "raw_row_signal_detected": raw_detected,
            "raw_row_positive_signal_recall": raw_detected / len(outcomes) if outcomes else 0.0,
            "raw_row_positive_signal_recall_wilson_95": _wilson_interval(raw_detected, len(outcomes)),
            "raw_row_actionable_signal_detected": raw_actionable,
            "raw_row_actionable_signal_recall": raw_actionable / len(outcomes) if outcomes else 0.0,
            "scan_errors": sum(
                outcome.scan_error is not None or outcome.control_scan_error is not None for outcome in outcomes
            ),
            "scan_error_invocations": sum(
                int(outcome.scan_error is not None) + int(outcome.control_scan_error is not None)
                for outcome in outcomes
            ),
            "analyzer_failure_samples": sum(
                bool(outcome.analyzer_failures or outcome.control_analyzer_failures) for outcome in outcomes
            ),
            "deduplication": _dedup_summary(snapshot.samples),
            "group_metric_deduplication": "one_dedup_parent_representative_per_group",
            "scanner_provenance": scanner_provenance,
            "per_source": _group_metrics(outcomes, "source_id", rate_name="positive_signal_recall"),
            "per_structural_family": _group_metrics(
                outcomes,
                "structural_family_id",
                rate_name="positive_signal_recall",
            ),
            "per_lexical_template": _group_metrics(
                outcomes,
                "lexical_template_id",
                rate_name="positive_signal_recall",
            ),
            "per_label": _label_metrics(outcomes, rate_name="positive_signal_recall"),
            "raw_per_source": _group_metrics(
                outcomes,
                "source_id",
                rate_name="positive_signal_recall",
                deduplicate=False,
            ),
            "outcomes": [_outcome_record(outcome) for outcome in outcomes],
        }
    )
    return report


def run_notinject_hard_negative_benchmark(
    snapshot: GitHubPromptInjectionSnapshot,
    *,
    scanner: StaticSkillScanner,
) -> dict[str, Any]:
    """Report diagnostic flagging on NotInject without creating an FPR gate."""

    if snapshot.dataset_id != NOTINJECT_DATASET_ID or snapshot.kind != "notinject_hard_negative":
        raise ValueError("NotInject benchmark requires a validated NotInject snapshot")
    outcomes = _scan_snapshot(snapshot, scanner=scanner)
    primary_outcomes = tuple(outcome for outcome in outcomes if outcome.sample.dedup_relation == "canonical")
    flagged = sum(outcome.signal_detected for outcome in primary_outcomes)
    actionable = sum(outcome.actionable_signal_detected for outcome in primary_outcomes)
    raw_flagged = sum(outcome.signal_detected for outcome in outcomes)
    raw_actionable = sum(outcome.actionable_signal_detected for outcome in outcomes)
    status, metric_valid = _result_status(outcomes)
    scanner_provenance = _scanner_provenance(outcomes)
    if scanner_provenance["status"] == "inconsistent":
        status, metric_valid = "incomplete", False
    report = _report_header(snapshot)
    report.update(
        {
            "status": status,
            "metric_valid": metric_valid,
            "label_scope": "benign_prompt_hard_negative_diagnostic_only",
            "metric_scope": "diagnostic_flagged_rate_not_package_benign_gold",
            "release_fpr_eligible": False,
            "population": len(primary_outcomes),
            "diagnostic_flagged": flagged,
            "diagnostic_flagged_rate": flagged / len(primary_outcomes) if primary_outcomes else 0.0,
            "diagnostic_flagged_rate_wilson_95": _wilson_interval(flagged, len(primary_outcomes)),
            "actionable_diagnostic_flagged": actionable,
            "actionable_diagnostic_flagged_rate": (actionable / len(primary_outcomes) if primary_outcomes else 0.0),
            "actionable_diagnostic_flagged_rate_wilson_95": _wilson_interval(actionable, len(primary_outcomes)),
            "raw_row_population": len(outcomes),
            "raw_row_diagnostic_flagged": raw_flagged,
            "raw_row_diagnostic_flagged_rate": raw_flagged / len(outcomes) if outcomes else 0.0,
            "raw_row_actionable_diagnostic_flagged": raw_actionable,
            "scan_errors": sum(
                outcome.scan_error is not None or outcome.control_scan_error is not None for outcome in outcomes
            ),
            "analyzer_failure_samples": sum(bool(outcome.analyzer_failures) for outcome in outcomes),
            "deduplication": _dedup_summary(snapshot.samples),
            "group_metric_deduplication": "one_dedup_parent_representative_per_group",
            "scanner_provenance": scanner_provenance,
            "per_source": _group_metrics(outcomes, "source_id", rate_name="diagnostic_flagged_rate"),
            "per_structural_family": _group_metrics(
                outcomes,
                "structural_family_id",
                rate_name="diagnostic_flagged_rate",
            ),
            "per_lexical_template": _group_metrics(
                outcomes,
                "lexical_template_id",
                rate_name="diagnostic_flagged_rate",
            ),
            "per_label": _label_metrics(outcomes, rate_name="diagnostic_flagged_rate"),
            "raw_per_source": _group_metrics(
                outcomes,
                "source_id",
                rate_name="diagnostic_flagged_rate",
                deduplicate=False,
            ),
            "hard_negative_candidates": [
                _outcome_record(outcome) for outcome in primary_outcomes if outcome.signal_detected
            ],
            "raw_row_hard_negative_candidates": [
                _outcome_record(outcome) for outcome in outcomes if outcome.signal_detected
            ],
            "outcomes": [_outcome_record(outcome) for outcome in outcomes],
        }
    )
    return report


def skipped_supplemental_report(dataset_id: str) -> dict[str, Any]:
    """Return an explicit non-result only when an optional snapshot is absent."""

    if dataset_id not in {*_POSITIVE_DATASETS, NOTINJECT_DATASET_ID}:
        raise ValueError("unknown GitHub supplemental dataset")
    return {
        "dataset_id": dataset_id,
        "status": "skipped",
        "reason_code": "SNAPSHOT_UNAVAILABLE",
        "supplemental": True,
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
    }


def _build_static_scanner(*, detector_profile: str, cel_mode: str) -> StaticSkillScanner:
    """Build deterministic local analyzers only; no hosted or network analyzer."""

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
        raise ValueError(f"unsupported detector profile: {detector_profile}")
    return SkillScanner(
        analyzers=build_core_analyzers(policy, extra_rules_dirs=extra_rules),
        policy=policy,
        rule_registry=registry,
    )


def _write_report(report: Mapping[str, Any], output: Path) -> None:
    rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    output = Path(output)
    if output.is_symlink():
        raise ValueError("output must not be a symbolic link")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.exists() and not output.is_file():
        raise ValueError("output must be a regular file path")
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


def _validate_output_target(output: Path, *, snapshot: Path, dataset_lock: Path | None) -> None:
    candidate = output.parent.resolve(strict=False) / output.name
    if snapshot.exists() and not snapshot.is_symlink():
        snapshot_root = snapshot.resolve(strict=True)
        if candidate == snapshot_root or candidate.is_relative_to(snapshot_root):
            raise ValueError("output must be outside the immutable dataset snapshot")
    if candidate == (dataset_lock or LOCK_FILE).resolve(strict=False):
        raise ValueError("output must not overwrite the dataset lock")


def main(argv: Sequence[str] | None = None) -> int:
    """Run one pinned supplemental snapshot without acquiring any data."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("injecagent", "in-page", "notinject"), required=True)
    parser.add_argument("--snapshot", type=Path, required=True, help="Already-acquired exact snapshot root")
    parser.add_argument("--dataset-lock", type=Path)
    parser.add_argument("--detector-profile", choices=("core_only", "full_packs"), default="full_packs")
    parser.add_argument("--cel-mode", choices=("off", "shadow", "enforce"), default="shadow")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        _validate_output_target(args.output, snapshot=args.snapshot, dataset_lock=args.dataset_lock)
        if not args.snapshot.exists() and not args.snapshot.is_symlink():
            dataset_ids = {
                "injecagent": INJECAGENT_DATASET_ID,
                "in-page": IN_PAGE_DATASET_ID,
                "notinject": NOTINJECT_DATASET_ID,
            }
            _write_report(skipped_supplemental_report(dataset_ids[args.dataset]), args.output)
            return 0
        loaders = {
            "injecagent": (load_injecagent_snapshot, INJECAGENT_REVISION),
            "in-page": (load_in_page_snapshot, IN_PAGE_REVISION),
            "notinject": (load_notinject_snapshot, NOTINJECT_REVISION),
        }
        loader, revision = loaders[args.dataset]
        snapshot = loader(args.snapshot, revision=revision, dataset_lock=args.dataset_lock)
        scanner = _build_static_scanner(detector_profile=args.detector_profile, cel_mode=args.cel_mode)
        if args.dataset == "notinject":
            report = run_notinject_hard_negative_benchmark(snapshot, scanner=scanner)
        else:
            report = run_indirect_injection_signal_benchmark(snapshot, scanner=scanner)
        _write_report(report, args.output)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


__all__ = [
    "main",
    "run_indirect_injection_signal_benchmark",
    "run_notinject_hard_negative_benchmark",
    "skipped_supplemental_report",
]


if __name__ == "__main__":  # pragma: no cover - exercised through CLI smoke tests
    raise SystemExit(main())
