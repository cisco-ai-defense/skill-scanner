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

"""Offline false-positive audit for provenance-locked official skill bundles.

The corpus is all-benign and supplemental: it can expose false positives but
cannot establish malicious recall, precision, F1, or a vendor trust decision.
No detector receives vendor identity.  Scanner behavior is compared under CEL
OFF and SHADOW using exact finding identities; SHADOW must not change retained
findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evals.datasets.official_bundled_skills import (  # noqa: E402
    LOCK_FILE,
    PROFILE_FILE,
    OfficialBundleError,
    OfficialPackage,
    OfficialSource,
    build_lock,
    load_and_verify_lock,
)
from skill_scanner import __version__ as scanner_version  # noqa: E402
from skill_scanner.core.analyzer_factory import build_core_analyzers  # noqa: E402
from skill_scanner.core.cel.go_runtime import CEL_GO_VERSION  # noqa: E402
from skill_scanner.core.cel.models import CelMode  # noqa: E402
from skill_scanner.core.models import Finding, ScanResult  # noqa: E402
from skill_scanner.core.rule_registry import PackLoader, RuleRegistry  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402
from skill_scanner.data import DATA_DIR, list_available_packs, resolve_rule_packs  # noqa: E402

REPORT_VERSION = 1
_ACTIONABLE = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
_BLOCKING = frozenset({"CRITICAL", "HIGH"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CEL_COUNT_FIELDS = (
    "evaluated",
    "retained",
    "would_suppress",
    "suppressed",
    "fallbacks",
    "projection_incomplete",
)
_CEL_IDENTITY_FIELDS = ("mode", "runtime", "runtime_version", "fact_schema", "expression_set_hash")


def _wilson(successes: int, total: int) -> list[float]:
    if total <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total))
    margin /= denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _tree_hash(root: Path, namespace: bytes) -> str:
    digest = hashlib.sha256(namespace + b"\0")
    for current_raw, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_raw)
        directory_names[:] = sorted(
            name for name in directory_names if not (current / name).is_symlink() and name != "__pycache__"
        )
        for name in sorted(file_names):
            path = current / name
            if path.is_symlink() or path.suffix in {".pyc", ".pyo"}:
                continue
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
    return digest.hexdigest()


def _core_registry() -> RuleRegistry:
    loader = PackLoader()
    registry = RuleRegistry()
    registry.register_pack(loader.load_bundled_pack(DATA_DIR / "packs" / "core"))
    return registry


def _scanner(detector_profile: str, mode: CelMode) -> SkillScanner:
    policy = ScanPolicy.default()
    policy.cel.mode = mode
    if detector_profile == "core_only":
        extra_rule_dirs = None
        registry = _core_registry()
    elif detector_profile == "full_packs":
        extra_rule_dirs = resolve_rule_packs(list_available_packs())
        registry = PackLoader().build_registry()
    else:
        raise ValueError(f"unsupported detector profile: {detector_profile}")
    analyzers = build_core_analyzers(policy, extra_rules_dirs=extra_rule_dirs)
    return SkillScanner(analyzers=analyzers, policy=policy, rule_registry=registry)


def _severity(finding: Finding) -> str:
    return str(getattr(finding.severity, "value", finding.severity)).upper()


def _category(finding: Finding) -> str:
    return str(getattr(finding.category, "value", finding.category))


def _relative_finding_path(package: OfficialPackage, finding: Finding) -> str | None:
    if not finding.file_path:
        return None
    raw = Path(finding.file_path)
    if raw.is_absolute():
        try:
            return raw.resolve(strict=False).relative_to(package.absolute_path).as_posix()
        except ValueError:
            # An analyzer must not attribute an official package finding to an
            # unrelated host path. Preserve a stable sentinel, not host data.
            return "<outside-package>"
    return raw.as_posix()


def _finding_record(package: OfficialPackage, finding: Finding) -> dict[str, Any]:
    return {
        "package_id": package.package_id,
        "rule_id": finding.rule_id or "unidentified",
        "category": _category(finding),
        "severity": _severity(finding),
        "analyzer": finding.analyzer or "unidentified",
        "path": _relative_finding_path(package, finding),
        "line": finding.line_number,
        "finding_id": finding.id,
    }


def _identity(record: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        record[field]
        for field in ("package_id", "rule_id", "category", "severity", "analyzer", "path", "line", "finding_id")
    )


def _identity_sort_key(identity: Sequence[Any]) -> tuple[str, ...]:
    return tuple("" if value is None else str(value) for value in identity)


def _cel_record(result: ScanResult) -> dict[str, Any]:
    metadata = result.scan_metadata if isinstance(result.scan_metadata, Mapping) else {}
    cel = metadata.get("cel") if isinstance(metadata, Mapping) else None
    if not isinstance(cel, Mapping):
        return {"invalid": True, "validation_errors": ["TELEMETRY_MISSING"]}
    validation_errors: list[str] = []
    record: dict[str, Any] = {"invalid": False}
    for field in _CEL_COUNT_FIELDS:
        value = cel.get(field)
        record[field] = value if type(value) is int and value >= 0 else -1
        if record[field] < 0:
            validation_errors.append(f"TELEMETRY_INVALID_{field.upper()}")
    for field in _CEL_IDENTITY_FIELDS:
        value = cel.get(field)
        record[field] = value if isinstance(value, str) and value else "unspecified"
        if record[field] == "unspecified":
            validation_errors.append(f"TELEMETRY_INVALID_{field.upper()}")
    raw_errors = cel.get("errors", [])
    error_counts: Counter[str] = Counter()
    if isinstance(raw_errors, (str, bytes)) or not isinstance(raw_errors, Sequence):
        error_counts["INVALID_ERRORS"] += 1
    else:
        for error in raw_errors:
            if not isinstance(error, Mapping):
                error_counts["INVALID_ERRORS"] += 1
                continue
            rule_id = error.get("rule_id")
            code = error.get("code")
            if not isinstance(rule_id, str) or not rule_id or not isinstance(code, str) or not code:
                error_counts["INVALID_ERRORS"] += 1
                continue
            error_counts[f"{rule_id}:{code}"] += 1
    record["errors"] = dict(sorted(error_counts.items()))
    per_rule = cel.get("per_rule", {})
    record["per_rule"] = dict(per_rule) if isinstance(per_rule, Mapping) else {"INVALID_PER_RULE": {}}
    if not isinstance(per_rule, Mapping):
        validation_errors.append("TELEMETRY_INVALID_PER_RULE")
    for field in ("elapsed_ms", "projection_ms", "evaluation_ms"):
        value = cel.get(field)
        record[field] = (
            float(value)
            if not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
            else -1.0
        )
        if record[field] < 0:
            validation_errors.append(f"TELEMETRY_INVALID_{field.upper()}")
    record["validation_errors"] = validation_errors
    return record


def _cel_contract_errors(record: Mapping[str, Any], expected_mode: CelMode) -> list[str]:
    """Return stable release-contract violations for one scanner result."""

    errors = list(record.get("validation_errors", []))
    if record.get("invalid") is True:
        return sorted(set(errors or ["TELEMETRY_INVALID"]))

    if record.get("mode") != expected_mode.value:
        errors.append("MODE_MISMATCH")
    if record.get("runtime") != "cel-go":
        errors.append("RUNTIME_MISMATCH")
    runtime_version = record.get("runtime_version")
    runtime_prefix = f"{CEL_GO_VERSION};helper="
    if (
        not isinstance(runtime_version, str)
        or not runtime_version.startswith(runtime_prefix)
        or not runtime_version.removeprefix(runtime_prefix)
        or len(runtime_version.encode("utf-8")) > 256
        or "\x00" in runtime_version
    ):
        errors.append("RUNTIME_VERSION_INVALID")
    if record.get("fact_schema") != "v1":
        errors.append("FACT_SCHEMA_MISMATCH")
    if not isinstance(record.get("expression_set_hash"), str) or not _SHA256_RE.fullmatch(
        str(record.get("expression_set_hash"))
    ):
        errors.append("GENERATION_INVALID")

    fallbacks = record.get("fallbacks")
    projection_incomplete = record.get("projection_incomplete")
    would_suppress = record.get("would_suppress")
    suppressed = record.get("suppressed")
    if fallbacks != 0:
        errors.append("FALLBACK_PRESENT")
    if projection_incomplete != 0:
        errors.append("PROJECTION_INCOMPLETE")
    if isinstance(projection_incomplete, int) and isinstance(fallbacks, int) and projection_incomplete > fallbacks:
        errors.append("PROJECTION_FALLBACK_COUNT_MISMATCH")
    if isinstance(suppressed, int) and isinstance(would_suppress, int) and suppressed > would_suppress:
        errors.append("SUPPRESSION_COUNT_MISMATCH")
    if expected_mode is CelMode.OFF:
        for field in ("evaluated", "would_suppress", "suppressed", "fallbacks", "projection_incomplete"):
            if record.get(field) != 0:
                errors.append(f"OFF_NONZERO_{field.upper()}")
    elif expected_mode is CelMode.SHADOW and suppressed != 0:
        errors.append("SHADOW_SUPPRESSED")

    raw_errors = record.get("errors")
    if not isinstance(raw_errors, Mapping):
        errors.append("TELEMETRY_INVALID_ERRORS")
    elif raw_errors:
        errors.append("EVALUATION_ERRORS_PRESENT")

    raw_per_rule = record.get("per_rule")
    if not isinstance(raw_per_rule, Mapping):
        errors.append("TELEMETRY_INVALID_PER_RULE")
    else:
        per_rule_totals: Counter[str] = Counter()
        for rule_id, values in raw_per_rule.items():
            if not isinstance(rule_id, str) or not rule_id or not isinstance(values, Mapping):
                errors.append("TELEMETRY_INVALID_PER_RULE")
                continue
            for field in ("keep", "would_suppress", "fallback", "suppressed"):
                value = values.get(field)
                if type(value) is not int or value < 0:
                    errors.append("TELEMETRY_INVALID_PER_RULE_COUNT")
                else:
                    per_rule_totals[field] += value
            if not isinstance(values.get("expression_hash"), str) or not _SHA256_RE.fullmatch(
                str(values.get("expression_hash"))
            ):
                errors.append("TELEMETRY_INVALID_EXPRESSION_HASH")
            if not isinstance(values.get("pack"), str) or not values.get("pack"):
                errors.append("TELEMETRY_INVALID_PACK")
            if values.get("rollout") not in {"shadow", "enforce"}:
                errors.append("TELEMETRY_INVALID_ROLLOUT")
        for decision, total_field in (
            ("would_suppress", "would_suppress"),
            ("fallback", "fallbacks"),
            ("suppressed", "suppressed"),
        ):
            if per_rule_totals[decision] != record.get(total_field):
                errors.append("TELEMETRY_PER_RULE_COUNT_MISMATCH")
        resolved = per_rule_totals["keep"] + per_rule_totals["would_suppress"]
        evaluated = record.get("evaluated")
        if (
            not isinstance(evaluated, int)
            or not isinstance(fallbacks, int)
            or not resolved <= evaluated <= resolved + fallbacks
        ):
            errors.append("TELEMETRY_EVALUATED_COUNT_MISMATCH")

    if record.get("projection_ms", -1.0) + record.get("evaluation_ms", -1.0) > record.get("elapsed_ms", -1.0) + 0.002:
        errors.append("TELEMETRY_PHASE_TIMING_INVALID")
    return sorted(set(errors))


def _accumulate_cel_per_rule(
    aggregate: dict[str, Counter[str]],
    expression_hashes: dict[str, set[str]],
    raw_per_rule: object,
) -> None:
    """Aggregate the runtime's canonical per-rule decision counters.

    Per-rule telemetry deliberately uses the singular decision names emitted
    by ``CelTelemetry`` (``keep`` and ``fallback``). The top-level CEL summary
    uses derived plural names (``retained`` and ``fallbacks``), so applying
    that schema here would silently attribute every per-rule decision as zero.
    """

    if not isinstance(raw_per_rule, Mapping):
        return
    for rule_id, values in raw_per_rule.items():
        if not isinstance(rule_id, str) or not rule_id or not isinstance(values, Mapping):
            continue
        identity = values.get("expression_hash")
        if isinstance(identity, str) and identity:
            expression_hashes[rule_id].add(identity)
        for field in ("keep", "would_suppress", "fallback", "suppressed"):
            value = values.get(field, 0)
            if type(value) is int and value >= 0:
                aggregate[rule_id][field] += value


def _load_record(result: ScanResult) -> dict[str, Any]:
    metadata = result.scan_metadata if isinstance(result.scan_metadata, Mapping) else {}
    load = metadata.get("loader", {}) if isinstance(metadata, Mapping) else {}
    if not isinstance(load, Mapping):
        return {}
    allowed = (
        "fallback_used",
        "fallback_mode",
        "strict_error_type",
        "strict_error_code",
        "manifest_complete",
        "capability_facts_trusted",
        "rejection_used",
        "rejection_mode",
        "content_scanned",
    )
    return {field: load[field] for field in allowed if field in load}


def _empty_group(source_ids: Sequence[str]) -> dict[str, Any]:
    return {
        "source_ids": sorted(set(source_ids)),
        "denominator": 0,
        "scanned": 0,
        "load_errors": 0,
        "analyzer_partial_failures": 0,
        "packages_medium_plus": 0,
        "packages_high_plus": 0,
    }


def _finalize_group(group: dict[str, Any]) -> dict[str, Any]:
    denominator = group["denominator"]
    group["medium_plus_package_fpr"] = group["packages_medium_plus"] / denominator if denominator else 0.0
    group["high_plus_package_fpr"] = group["packages_high_plus"] / denominator if denominator else 0.0
    group["medium_plus_package_fpr_wilson95"] = _wilson(group["packages_medium_plus"], denominator)
    group["high_plus_package_fpr_wilson95"] = _wilson(group["packages_high_plus"], denominator)
    group["clean_scanned_packages"] = group["scanned"] - group["packages_medium_plus"]
    return group


def _run_one(
    sources: Sequence[OfficialSource],
    detector_profile: str,
    mode: CelMode,
) -> dict[str, Any]:
    scanner = _scanner(detector_profile, mode)
    gate = getattr(scanner, "cel_gate", None)
    expected_generation = getattr(gate, "expression_set_hash", None)
    expected_runtime = getattr(gate, "validated_runtime_name", None)
    expected_runtime_version = getattr(gate, "validated_runtime_version", None)
    expected_gate_mode = getattr(getattr(gate, "mode", None), "value", None)
    findings: list[dict[str, Any]] = []
    retained_findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    load_events: list[dict[str, Any]] = []
    analyzer_failures: list[dict[str, Any]] = []
    cel_totals: Counter[str] = Counter()
    cel_errors: Counter[str] = Counter()
    cel_per_rule: dict[str, Counter[str]] = defaultdict(Counter)
    cel_identities: dict[str, set[str]] = defaultdict(set)
    cel_runtime_identities: dict[str, set[str]] = defaultdict(set)
    cel_contract_failures: list[dict[str, str]] = []
    total_cel_ms = 0.0
    groups: dict[str, dict[str, Any]] = {}
    source_by_package: dict[str, OfficialSource] = {}
    for source in sources:
        groups.setdefault(source.source_group, _empty_group([source.source_id]))
        groups[source.source_group]["source_ids"] = sorted(
            set(groups[source.source_group]["source_ids"]) | {source.source_id}
        )
        for package in source.packages:
            source_by_package[package.package_id] = source

    started = time.perf_counter()
    package_outcomes: list[dict[str, Any]] = []
    for source in sources:
        group = groups[source.source_group]
        for package in source.packages:
            group["denominator"] += 1
            outcome: dict[str, Any] = {
                "package_id": package.package_id,
                "source_id": source.source_id,
                "source_group": source.source_group,
                "tree_sha256": package.tree_sha256,
                "status": "scan_error",
                "medium_plus": False,
                "high_plus": False,
            }
            before = time.perf_counter()
            try:
                result = scanner.scan_skill(package.absolute_path)
            except Exception as exc:  # scanner failures belong in the fixed denominator
                message_hash = hashlib.sha256(str(exc).encode("utf-8", errors="replace")).hexdigest()
                errors.append(
                    {
                        "package_id": package.package_id,
                        "error_type": type(exc).__name__,
                        "message_sha256": message_hash,
                    }
                )
                group["load_errors"] += 1
                outcome["scan_ms"] = (time.perf_counter() - before) * 1000.0
                package_outcomes.append(outcome)
                continue
            outcome["status"] = "scanned"
            outcome["scan_ms"] = (time.perf_counter() - before) * 1000.0
            group["scanned"] += 1

            load = _load_record(result)
            if load:
                load_events.append({"package_id": package.package_id, **load})
                group["load_errors"] += 1
                outcome["status"] = "loader_failure"
            if result.analyzers_failed:
                group["analyzer_partial_failures"] += 1
                for failure in result.analyzers_failed:
                    analyzer_failures.append(
                        {
                            "package_id": package.package_id,
                            "analyzer": str(failure.get("analyzer", "unidentified")),
                            "error_type": str(failure.get("error_type", "unidentified")),
                        }
                    )

            package_findings = [_finding_record(package, finding) for finding in result.findings]
            retained_findings.extend(package_findings)
            actionable = [record for record in package_findings if record["severity"] in _ACTIONABLE]
            blocking = [record for record in package_findings if record["severity"] in _BLOCKING]
            outcome["medium_plus"] = bool(actionable)
            outcome["high_plus"] = bool(blocking)
            if actionable:
                group["packages_medium_plus"] += 1
            if blocking:
                group["packages_high_plus"] += 1
            findings.extend(actionable)

            cel = _cel_record(result)
            expected_identity = {
                "mode": expected_gate_mode,
                "runtime": expected_runtime,
                "runtime_version": expected_runtime_version,
                "expression_set_hash": expected_generation,
            }
            for field, expected in expected_identity.items():
                if not isinstance(expected, str) or not expected:
                    cel_contract_failures.append(
                        {"package_id": package.package_id, "code": f"GATE_{field.upper()}_INVALID"}
                    )
                elif cel.get(field) != expected:
                    cel_contract_failures.append(
                        {"package_id": package.package_id, "code": f"GATE_{field.upper()}_MISMATCH"}
                    )
            for field in _CEL_IDENTITY_FIELDS:
                value = cel.get(field)
                if isinstance(value, str) and value and value != "unspecified":
                    cel_runtime_identities[field].add(value)
            for code in _cel_contract_errors(cel, mode):
                cel_contract_failures.append({"package_id": package.package_id, "code": code})
            for field in (
                "evaluated",
                "retained",
                "would_suppress",
                "suppressed",
                "fallbacks",
                "projection_incomplete",
            ):
                value = cel.get(field, -1)
                if type(value) is int and value >= 0:
                    cel_totals[field] += value
                else:
                    cel_errors[f"TELEMETRY_INVALID_{field.upper()}"] += 1
            elapsed_ms = cel.get("elapsed_ms", -1.0)
            if isinstance(elapsed_ms, (int, float)) and math.isfinite(elapsed_ms) and elapsed_ms >= 0:
                total_cel_ms += float(elapsed_ms)
            else:
                cel_errors["TELEMETRY_INVALID_ELAPSED_MS"] += 1
            for error, count in cel.get("errors", {}).items():
                if type(count) is int:
                    cel_errors[str(error)] += count
            _accumulate_cel_per_rule(cel_per_rule, cel_identities, cel.get("per_rule", {}))
            package_outcomes.append(outcome)

    findings.sort(key=lambda record: _identity_sort_key(_identity(record)))
    retained_findings.sort(key=lambda record: _identity_sort_key(_identity(record)))
    per_rule: dict[str, dict[str, Any]] = {}
    grouped_findings: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in findings:
        grouped_findings[(record["rule_id"], record["severity"], record["analyzer"])].append(record)
    for (rule_id, severity, analyzer), records in sorted(grouped_findings.items()):
        affected_packages = sorted({record["package_id"] for record in records})
        key = f"{rule_id}|{severity}|{analyzer}"
        per_rule[key] = {
            "rule_id": rule_id,
            "severity": severity,
            "analyzer": analyzer,
            "finding_count": len(records),
            "package_count": len(affected_packages),
            "package_ids": affected_packages,
            "locations": [
                {"package_id": record["package_id"], "path": record["path"], "line": record["line"]}
                for record in records
            ],
        }

    overall = _empty_group([source.source_id for source in sources])
    for group in groups.values():
        for field in (
            "denominator",
            "scanned",
            "load_errors",
            "analyzer_partial_failures",
            "packages_medium_plus",
            "packages_high_plus",
        ):
            overall[field] += group[field]

    run_contract_errors: list[str] = []
    if errors:
        run_contract_errors.append("SCANNER_FAILURES_PRESENT")
    if load_events:
        run_contract_errors.append("LOADER_FAILURES_PRESENT")
    if analyzer_failures:
        run_contract_errors.append("ANALYZER_FAILURES_PRESENT")
    if cel_contract_failures:
        run_contract_errors.append("CEL_CONTRACT_FAILURES_PRESENT")
    for field in _CEL_IDENTITY_FIELDS:
        values = cel_runtime_identities.get(field, set())
        if len(values) != 1:
            run_contract_errors.append(f"CEL_{field.upper()}_DRIFT")
    if any(len(values) != 1 for values in cel_identities.values()):
        run_contract_errors.append("CEL_RULE_EXPRESSION_DRIFT")

    return {
        "detector_profile": detector_profile,
        "cel_mode": mode.value,
        "duration_seconds": time.perf_counter() - started,
        "denominator": sum(len(source.packages) for source in sources),
        "unique_content_denominator": len(
            {(package.tree_sha256, package.skill_sha256) for source in sources for package in source.packages}
        ),
        "scanned": sum(group["scanned"] for group in groups.values()),
        "scanner_error_count": len(errors),
        "load_error_count": len(errors) + len(load_events),
        "loader_failure_count": len(load_events),
        "load_errors": errors,
        "load_events": sorted(load_events, key=lambda item: item["package_id"]),
        "analyzer_partial_failure_count": len(analyzer_failures),
        "analyzer_partial_failures": sorted(
            analyzer_failures, key=lambda item: (item["package_id"], item["analyzer"], item["error_type"])
        ),
        "overall_package_fpr": _finalize_group(overall),
        "source_groups": {key: _finalize_group(value) for key, value in sorted(groups.items())},
        "package_outcomes": sorted(package_outcomes, key=lambda item: item["package_id"]),
        "retained_findings": retained_findings,
        "medium_plus_findings": findings,
        "per_rule_false_positives": per_rule,
        "cel": {
            **dict(cel_totals),
            "errors": dict(sorted(cel_errors.items())),
            "elapsed_ms": total_cel_ms,
            "per_rule": {rule: dict(counts) for rule, counts in sorted(cel_per_rule.items())},
            "expression_hashes": {rule: sorted(values) for rule, values in sorted(cel_identities.items())},
            "identities": {field: sorted(values) for field, values in sorted(cel_runtime_identities.items())},
            "contract_failures": sorted(cel_contract_failures, key=lambda item: (item["package_id"], item["code"])),
        },
        "contract_errors": sorted(set(run_contract_errors)),
        "contract_passed": not run_contract_errors,
    }


def _compare_off_shadow(off: Mapping[str, Any], shadow: Mapping[str, Any]) -> dict[str, Any]:
    off_findings = {_identity(record) for record in off.get("retained_findings", off["medium_plus_findings"])}
    shadow_findings = {_identity(record) for record in shadow.get("retained_findings", shadow["medium_plus_findings"])}
    off_errors = {
        (record["package_id"], record["error_type"], record["message_sha256"]) for record in off["load_errors"]
    }
    shadow_errors = {
        (record["package_id"], record["error_type"], record["message_sha256"]) for record in shadow["load_errors"]
    }
    added = sorted(shadow_findings - off_findings, key=_identity_sort_key)
    removed = sorted(off_findings - shadow_findings, key=_identity_sort_key)
    error_added = sorted(shadow_errors - off_errors)
    error_removed = sorted(off_errors - shadow_errors)
    off_identity = off.get("cel", {}).get("identities", {})
    shadow_identity = shadow.get("cel", {}).get("identities", {})
    generation_fields = ("runtime", "runtime_version", "fact_schema", "expression_set_hash")
    generation_equal = all(off_identity.get(field) == shadow_identity.get(field) for field in generation_fields)
    return {
        "finding_identities_equal": not added and not removed,
        "load_error_identities_equal": not error_added and not error_removed,
        "cel_generation_identity_equal": generation_equal,
        "added_finding_identities": [list(identity) for identity in added],
        "removed_finding_identities": [list(identity) for identity in removed],
        "added_load_errors": [list(identity) for identity in error_added],
        "removed_load_errors": [list(identity) for identity in error_removed],
        "shadow_would_suppress": shadow["cel"].get("would_suppress", 0),
        "shadow_fallbacks": shadow["cel"].get("fallbacks", 0),
        "shadow_projection_incomplete": shadow["cel"].get("projection_incomplete", 0),
    }


def run_benchmark(
    *,
    lock_path: Path = LOCK_FILE,
    profile_path: Path = PROFILE_FILE,
    detector_profiles: Sequence[str] = ("core_only",),
    cel_modes: Sequence[CelMode] = (CelMode.OFF, CelMode.SHADOW),
) -> dict[str, Any]:
    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    profile_sha256 = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    sources = load_and_verify_lock(lock_path, profile_path)
    scanner_root = Path(__file__).resolve().parents[2] / "skill_scanner"
    rules_root = DATA_DIR / "packs"
    scanner_build_sha256 = _tree_hash(scanner_root, b"skill-scanner-official-goodware-build-v1")
    bundled_rules_sha256 = _tree_hash(rules_root, b"skill-scanner-official-goodware-rules-v1")
    source_identity = tuple(
        (
            source.source_id,
            source.inventory_sha256,
            tuple((package.package_id, package.tree_sha256, package.skill_sha256) for package in source.packages),
        )
        for source in sources
    )
    runs: dict[str, dict[str, Any]] = {}
    comparisons: dict[str, Any] = {}
    for detector_profile in detector_profiles:
        profile_runs: dict[str, Any] = {}
        for mode in cel_modes:
            profile_runs[mode.value] = _run_one(sources, detector_profile, mode)
        runs[detector_profile] = profile_runs
        if "off" in profile_runs and "shadow" in profile_runs:
            comparisons[detector_profile] = _compare_off_shadow(profile_runs["off"], profile_runs["shadow"])

    run_contract_pass = all(run["contract_passed"] for profile_runs in runs.values() for run in profile_runs.values())
    comparison_pass = all(
        value["finding_identities_equal"]
        and value["load_error_identities_equal"]
        and value["cel_generation_identity_equal"]
        for value in comparisons.values()
    )
    final_sources = load_and_verify_lock(lock_path, profile_path)
    final_source_identity = tuple(
        (
            source.source_id,
            source.inventory_sha256,
            tuple((package.package_id, package.tree_sha256, package.skill_sha256) for package in source.packages),
        )
        for source in final_sources
    )
    if final_source_identity != source_identity:
        raise OfficialBundleError("official bundled-skill inventory changed during the benchmark")
    if hashlib.sha256(lock_path.read_bytes()).hexdigest() != lock_sha256:
        raise OfficialBundleError("official bundled-skill lock changed during the benchmark")
    if hashlib.sha256(profile_path.read_bytes()).hexdigest() != profile_sha256:
        raise OfficialBundleError("official bundled-skill profile changed during the benchmark")
    if _tree_hash(scanner_root, b"skill-scanner-official-goodware-build-v1") != scanner_build_sha256:
        raise OfficialBundleError("scanner implementation changed during the benchmark")
    if _tree_hash(rules_root, b"skill-scanner-official-goodware-rules-v1") != bundled_rules_sha256:
        raise OfficialBundleError("bundled rule generation changed during the benchmark")
    return {
        "report_version": REPORT_VERSION,
        "corpus_id": "official-bundled-agent-skills-goodware",
        "label_policy": {
            "label": "benign-hard-negative",
            "authoritative_for": ["false_positive_mining", "official_bundle_compatibility"],
            "not_authoritative_for": ["malicious_recall", "precision", "f1", "vendor_allowlisting"],
        },
        "producer": {
            "scanner_version": scanner_version,
            "scanner_build_sha256": scanner_build_sha256,
            "bundled_rules_sha256": bundled_rules_sha256,
        },
        "inputs": {
            "lock_sha256": lock_sha256,
            "profile_sha256": profile_sha256,
        },
        "sources": [
            {
                "id": source.source_id,
                "vendor": source.vendor,
                "tool": source.tool,
                "source_group": source.source_group,
                "resolved_root": str(source.root),
                "root_locator": source.root_locator,
                "inventory_sha256": source.inventory_sha256,
                "package_count": len(source.packages),
                "file_count": source.file_count,
                "total_bytes": source.total_bytes,
                "provenance": dict(source.provenance),
                "versions": sorted({package.version for package in source.packages}),
                "licenses": sorted({package.license for package in source.packages}),
                "packages": [package.lock_record() for package in source.packages],
            }
            for source in sources
        ],
        "denominator": sum(len(source.packages) for source in sources),
        "runs": runs,
        "off_shadow_comparisons": comparisons,
        "contract_checks": {
            "all_runs_complete_and_error_free": run_contract_pass,
            "off_shadow_identities_equal": comparison_pass,
        },
        "contract_passed": run_contract_pass and comparison_pass,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot = subparsers.add_parser("snapshot", help="print a lock candidate; never writes vendor content")
    snapshot.add_argument("--profile", type=Path, default=PROFILE_FILE)
    run = subparsers.add_parser("run", help="verify the lock and scan every official package")
    run.add_argument("--lock", type=Path, default=LOCK_FILE)
    run.add_argument("--profile", type=Path, default=PROFILE_FILE)
    run.add_argument("--output", type=Path)
    run.add_argument(
        "--detector-profile",
        action="append",
        choices=("core_only", "full_packs"),
        dest="detector_profiles",
    )
    run.add_argument("--cel-mode", action="append", choices=("off", "shadow"), dest="cel_modes")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "snapshot":
        print(json.dumps(build_lock(args.profile), indent=2, sort_keys=True))
        return 0
    detector_profiles = args.detector_profiles or ["core_only"]
    modes = [CelMode(mode) for mode in (args.cel_modes or ["off", "shadow"])]
    report = run_benchmark(
        lock_path=args.lock,
        profile_path=args.profile,
        detector_profiles=detector_profiles,
        cel_modes=modes,
    )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["contract_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
