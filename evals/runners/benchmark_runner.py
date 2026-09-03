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

"""
Comprehensive evaluation benchmark runner for Skill Scanner.

Based on MCP Scanner's evaluation framework structure.
Evaluates analyzer accuracy across threat categories.
"""

import hashlib
import json
import math
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.runners.finding_matcher import (
    IDENTITY_FIELDS,
    match_findings,
    validate_expectation_document,
)
from evals.runners.loader_fallback import recognize_loader_disposition
from skill_scanner.core.scanner import SkillScanner

_STRICT_IDENTITY_FIELDS = frozenset({"rule_id", "category", "severity", "file_path", "analyzer"})
_LOCATION_IDENTITY_FIELDS = ("line_number", "evidence_id")
_ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
_BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_SIGNAL_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_GOLDEN_MANIFEST_DOMAIN = b"skill-scanner-exact-golden-manifest-v1\0"


def build_committed_golden_evidence(
    eval_dir: Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Build release evidence bound to every committed strict expectation.

    The manifest digest covers scanner-independent label attestations (the raw
    expectation bytes), the independently hashed fixture content, and
    package/verdict metadata. It is recomputed from the repository rather than
    hand-authored by a workflow.
    """

    repository_root = (repository_root or Path(__file__).resolve().parents[2]).resolve()
    eval_dir = eval_dir.resolve()
    entries: list[dict[str, str]] = []
    legacy_count = 0
    seen_case_ids: set[str] = set()
    label_sources: Counter[str] = Counter()

    for expected_path in sorted(eval_dir.rglob("_expected.json")):
        raw = expected_path.read_bytes()
        document = json.loads(raw)
        validated = validate_expectation_document(document, fixture_dir=expected_path.parent)
        if validated.evaluation_quality == "legacy_degraded":
            legacy_count += 1
            continue

        case_id = document["case_id"]
        if case_id in seen_case_ids:
            raise ValueError(f"duplicate strict golden case_id {case_id!r}")
        seen_case_ids.add(case_id)
        label_source = validated.label_source
        if label_source is None:
            raise ValueError(f"strict golden case {case_id!r} lacks a label attestation")
        label_sources[label_source] += 1
        try:
            expectation_path = expected_path.resolve().relative_to(repository_root).as_posix()
        except ValueError as exc:
            raise ValueError(f"golden expectation is outside repository root: {expected_path}") from exc

        entries.append(
            {
                "case_id": case_id,
                "expectation_path": expectation_path,
                "expectation_sha256": hashlib.sha256(raw).hexdigest(),
                "fixture_sha256": document["provenance"]["fixture_sha256"],
                "label_source": label_source,
                "label_provenance_sha256": document["provenance"]["label_provenance_sha256"],
                "label_evidence_sha256": document["provenance"]["label_evidence_sha256"],
                "package_label": document["package_label"],
                "expected_verdict": document["expected_verdict"],
            }
        )

    entries.sort(key=lambda entry: entry["case_id"])
    canonical = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    strict_count = len(entries)
    return {
        "schema_version": 1,
        "strict_fixtures": strict_count,
        "legacy_degraded_fixtures": legacy_count,
        "manifest_sha256": hashlib.sha256(_GOLDEN_MANIFEST_DOMAIN + canonical).hexdigest(),
        "label_sources": {
            source: label_sources[source]
            for source in (
                "public_labeled",
                "independent_ollama",
                "agent_labeled",
                "human_reviewed",
            )
        },
        "scanner_derived_fixtures": 0,
        "sealed_hf_model_labeled_fixtures": 0,
    }


def _legacy_expectation_indices(
    expected_findings: Sequence[Any],
    evaluation_quality: str | None = None,
) -> tuple[int, ...]:
    """Return expectations that do not provide a complete finding identity.

    Legacy records remain supported by the matcher, where omitted fields act as
    wildcards.  Keeping the classification here makes that weaker comparison
    visible in both human-readable and JSON benchmark output.
    """

    if evaluation_quality == "legacy_degraded":
        return tuple(range(len(expected_findings)))
    if evaluation_quality == "strict":
        return ()

    degraded: list[int] = []
    for index, expected in enumerate(expected_findings):
        if not isinstance(expected, Mapping):
            # The matcher will reject this as an ingestion error.  Classifying
            # it as degraded as well keeps reporting useful on the error row.
            degraded.append(index)
            continue
        has_required_fields = _STRICT_IDENTITY_FIELDS.issubset(expected)
        has_stable_location = any(expected.get(field) is not None for field in _LOCATION_IDENTITY_FIELDS)
        if not has_required_fields or not has_stable_location:
            degraded.append(index)
    return tuple(degraded)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _finding_value(finding: Any, field: str) -> Any:
    actual_field = "id" if field == "evidence_id" else field
    if isinstance(finding, Mapping):
        if field == "evidence_id" and "id" not in finding:
            return finding.get("evidence_id")
        return finding.get(actual_field)
    return getattr(finding, actual_field, None)


def _json_identity(finding: Any) -> dict[str, Any]:
    """Return the canonical, snippet-free identity used by the matcher."""

    identity: dict[str, Any] = {}
    for field in IDENTITY_FIELDS:
        value = _enum_value(_finding_value(finding, field))
        if value is None:
            continue
        if field == "file_path":
            value = str(value).replace("\\", "/")
            while value.startswith("./"):
                value = value[2:]
        elif field == "severity" and isinstance(value, str):
            value = value.upper()
        elif field in {"category", "analyzer"} and isinstance(value, str):
            value = value.lower()
        identity[field] = value
    return identity


def _category(finding: Any) -> str:
    value = _enum_value(_finding_value(finding, "category"))
    return value.lower() if isinstance(value, str) and value else "unclassified"


def _severity(finding: Any) -> str:
    value = _enum_value(_finding_value(finding, "severity"))
    return value.upper() if isinstance(value, str) else ""


def _safe_divide(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    return _safe_divide(2 * precision * recall, precision + recall)


def _wilson_interval(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 0.0)
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, center - margin), min(1.0, center + margin))


def _p95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


@dataclass
class EvalMetrics:
    """Finding-level metrics for a single threat category."""

    category: str
    fixtures: int
    expected_findings: int
    actual_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    precision_confidence_interval_95: tuple[float, float]
    recall_confidence_interval_95: tuple[float, float]


@dataclass
class BenchmarkResult:
    """Complete benchmark results."""

    total_skills_evaluated: int
    safe_skills: int
    malicious_skills: int
    benign_packages: int
    contextual_risk_packages: int
    evaluation_errors: int
    loader_fallbacks: int
    recovered_scan_errors: int
    loader_rejections: int
    loader_rejection_sample_ids: list[str]
    finding_true_positives: int
    finding_false_positives: int
    finding_false_negatives: int
    strict_identity_skills: int
    legacy_degraded_skills: int
    legacy_degraded_findings: int
    overall_accuracy: float
    overall_precision: float
    overall_recall: float
    overall_f1: float
    finding_macro_f1: float
    finding_precision_confidence_interval_95: tuple[float, float]
    finding_recall_confidence_interval_95: tuple[float, float]
    package_true_positives: int
    package_false_positives: int
    package_true_negatives: int
    package_false_negatives: int
    package_block_recall: float
    package_signal_recall: float
    package_macro_f1: float
    benign_actionable_false_positives: int
    benign_actionable_false_positive_rate: float
    package_block_recall_confidence_interval_95: tuple[float, float]
    package_signal_recall_confidence_interval_95: tuple[float, float]
    benign_actionable_fpr_confidence_interval_95: tuple[float, float]
    category_metrics: list[EvalMetrics]
    scan_duration_seconds: float
    skills_per_second: float
    p95_scan_latency_ms: float
    cel_time_ratio: float
    cel_fallbacks: int


class SkillBenchmarkRunner:
    """
    Runs comprehensive benchmarks on evaluation skills.

    Inspired by MCP Scanner's evaluation framework.
    """

    def __init__(self, eval_skills_dir: Path):
        """
        Initialize benchmark runner.

        Args:
            eval_skills_dir: Directory containing evaluation skills
        """
        self.eval_skills_dir = eval_skills_dir
        self.scanner = SkillScanner()
        self.results: list[dict[str, Any]] = []

    def close(self) -> None:
        """Release the scanner and any persistent CEL helper it owns."""

        close = getattr(getattr(self, "scanner", None), "close", None)
        if callable(close):
            close()

    def run_benchmark(self) -> BenchmarkResult:
        """Run the benchmark and release scanner-owned resources."""

        try:
            return self._run_benchmark()
        finally:
            self.close()

    def _run_benchmark(self) -> BenchmarkResult:
        """
        Run complete benchmark suite.

        Returns:
            BenchmarkResult with all metrics
        """
        print("[BENCHMARK] Starting Skill Scanner Benchmark")
        print("=" * 70)

        start_time = time.time()

        # Find all evaluation skills
        eval_skills = self._find_evaluation_skills()

        print(f"Found {len(eval_skills)} evaluation skills")
        print()

        # Scan each skill
        for skill_path, expected_file in eval_skills:
            self._evaluate_skill(skill_path, expected_file)

        # Calculate metrics
        duration = time.time() - start_time
        benchmark_result = self._calculate_benchmark_metrics(duration)

        return benchmark_result

    def _find_evaluation_skills(self) -> list[tuple[Path, Path]]:
        """Find every expectation file, including fixtures with missing skills.

        A missing ``SKILL.md`` is an ingestion failure, not permission to drop
        that fixture from the benchmark denominator.
        """

        return [
            (expected_file.parent, expected_file)
            for expected_file in sorted(self.eval_skills_dir.rglob("_expected.json"))
        ]

    def _evaluate_skill(self, skill_path: Path, expected_file: Path):
        """Evaluate a single skill."""
        expected: dict[str, Any] | None = None
        expected_findings: list[Any] = []
        degraded_indices: tuple[int, ...] = ()
        matching_mode = "unavailable"
        package_label: str | None = None
        skill_name = skill_path.name
        try:
            with open(expected_file, encoding="utf-8") as f:
                loaded_expected = json.load(f)
            expected = loaded_expected if isinstance(loaded_expected, dict) else None
            if expected:
                skill_name_value = expected.get("skill_name")
                if isinstance(skill_name_value, str) and skill_name_value:
                    skill_name = skill_name_value
                loaded_findings = expected.get("expected_findings")
                if isinstance(loaded_findings, list):
                    expected_findings = loaded_findings
                quality_value = expected.get("evaluation_quality")
                if quality_value in {"strict", "legacy_degraded"}:
                    matching_mode = quality_value
                    degraded_indices = _legacy_expectation_indices(expected_findings, matching_mode)
            validated = validate_expectation_document(loaded_expected, fixture_dir=skill_path)
            assert expected is not None  # JSON objects validate only after being assigned above.

            skill_name = validated.skill_name
            expected_safe = validated.expected_safe
            package_label = validated.package_label
            expected_findings = list(validated.expected_findings)
            matching_mode = validated.evaluation_quality
            degraded_indices = _legacy_expectation_indices(expected_findings, matching_mode)

            print(f"[EVAL] Evaluating: {skill_name}")
            print(f"   Expected: {'SAFE' if expected_safe else 'MALICIOUS'}")
            if degraded_indices:
                print(
                    "   [WARN] Legacy degraded matching: "
                    f"{len(degraded_indices)} expectation(s) omit canonical identity fields"
                )

            if not (skill_path / "SKILL.md").is_file():
                raise FileNotFoundError(f"evaluation fixture is missing {skill_path / 'SKILL.md'}")

            # Scan the skill
            scan_result = self.scanner.scan_skill(skill_path)
            loader_disposition = recognize_loader_disposition(scan_result)

            # Compare results
            eval_result = self._compare_results(expected, scan_result, skill_name)
            eval_result["recovered_scan_error"] = loader_disposition.recovery is not None
            eval_result["loader_fallback_code"] = (
                loader_disposition.recovery.error_code if loader_disposition.recovery is not None else None
            )
            eval_result["loader_rejection_code"] = (
                loader_disposition.rejection.error_code if loader_disposition.rejection is not None else None
            )
            eval_result["benchmark_id"] = str(expected.get("case_id") or skill_name)

            self.results.append(eval_result)

            # Print result
            status = "[OK] PASS" if eval_result["correct"] else "[FAIL]"
            print(f"   Result: {status}")
            print(f"   Detected: {len(scan_result.findings)} findings")
            print()

        except Exception as e:
            print(f"   [ERROR] ERROR: {e}")
            print()
            expected_safe = None
            if expected:
                if isinstance(expected.get("expected_safe"), bool):
                    expected_safe = expected["expected_safe"]
                elif isinstance(expected.get("is_malicious"), bool):
                    expected_safe = not expected["is_malicious"]
                elif expected.get("expected_verdict") in {"safe", "unsafe"}:
                    expected_safe = expected["expected_verdict"] == "safe"
            self.results.append(
                {
                    "skill_name": skill_name,
                    "benchmark_id": str(expected.get("case_id") or skill_name) if expected else skill_name,
                    "expected_safe": expected_safe,
                    "package_label": package_label,
                    "actual_safe": None,
                    "safe_match": False,
                    "expected_threat_count": len(expected_findings),
                    "detected_threat_count": 0,
                    "matched_threats": 0,
                    "false_positives": 0,
                    "false_negatives": len(expected_findings),
                    "threat_coverage": 0.0,
                    "correct": False,
                    "matching_mode": matching_mode,
                    "legacy_degraded_findings": len(degraded_indices),
                    "matched_pairs": [],
                    "unmatched_expected_findings": [
                        _json_identity(finding) for finding in expected_findings if isinstance(finding, Mapping)
                    ],
                    "unmatched_actual_findings": [],
                    "matched_categories": {},
                    "false_positive_categories": {},
                    "false_negative_categories": dict(
                        sorted(Counter(_category(finding) for finding in expected_findings).items())
                    ),
                    "package_blocked": None,
                    "package_actionable": None,
                    "package_signal": None,
                    "scan_duration_ms": 0.0,
                    "cel_elapsed_ms": 0.0,
                    "cel_fallbacks": 0,
                    "recovered_scan_error": False,
                    "loader_fallback_code": None,
                    "loader_rejection_code": None,
                    "error": str(e),
                }
            )

    def _compare_results(self, expected: dict, scan_result, skill_name: str) -> dict:
        """Compare expected vs actual results."""
        quality = expected.get("evaluation_quality")
        if quality == "strict":
            expected_safe = expected.get("expected_verdict") == "safe"
        elif "expected_safe" in expected:
            expected_safe = expected["expected_safe"]
        elif "is_malicious" in expected:
            expected_safe = not expected["is_malicious"]
        else:
            expected_safe = True
        raw_package_label = expected.get("package_label")
        package_label = raw_package_label if raw_package_label in {"benign", "malicious", "contextual_risk"} else None
        actual_safe = scan_result.is_safe

        expected_threats = expected.get("expected_findings", [])
        actual_findings = scan_result.findings
        degraded_indices = _legacy_expectation_indices(expected_threats, quality)

        match_result = match_findings(expected_threats, actual_findings)
        matched_threats = match_result.matched_count
        false_positives = len(match_result.unmatched_actual_indices)
        false_negatives = len(match_result.unmatched_expected_indices)

        # Calculate correctness
        safe_match = expected_safe == actual_safe
        threat_coverage = matched_threats / len(expected_threats) if expected_threats else 1.0

        correct = safe_match and false_positives == 0 and false_negatives == 0

        matched_pairs = [
            {
                "expected": _json_identity(expected_threats[expected_index]),
                "actual": _json_identity(actual_findings[actual_index]),
            }
            for expected_index, actual_index in match_result.matched_pairs
        ]
        unmatched_expected = [
            _json_identity(expected_threats[index]) for index in match_result.unmatched_expected_indices
        ]
        unmatched_actual = [_json_identity(actual_findings[index]) for index in match_result.unmatched_actual_indices]
        matched_categories = Counter(
            _category(expected_threats[expected_index])
            if _category(expected_threats[expected_index]) != "unclassified"
            else _category(actual_findings[actual_index])
            for expected_index, actual_index in match_result.matched_pairs
        )
        false_negative_categories = Counter(
            _category(expected_threats[index]) for index in match_result.unmatched_expected_indices
        )
        false_positive_categories = Counter(
            _category(actual_findings[index]) for index in match_result.unmatched_actual_indices
        )
        severities = {_severity(finding) for finding in actual_findings}

        scan_duration_ms = float(getattr(scan_result, "scan_duration_seconds", 0.0) or 0.0) * 1_000
        if not math.isfinite(scan_duration_ms) or scan_duration_ms < 0:
            raise ValueError("scanner returned invalid scan duration")
        metadata = getattr(scan_result, "scan_metadata", None) or {}
        cel = metadata.get("cel", {}) if isinstance(metadata, Mapping) else {}
        if not isinstance(cel, Mapping):
            raise ValueError("scanner returned invalid CEL telemetry")
        cel_elapsed_ms = cel.get("elapsed_ms", 0.0)
        cel_fallbacks = cel.get("fallbacks", 0)
        if (
            isinstance(cel_elapsed_ms, bool)
            or not isinstance(cel_elapsed_ms, (int, float))
            or not math.isfinite(cel_elapsed_ms)
            or cel_elapsed_ms < 0
            or float(cel_elapsed_ms) > scan_duration_ms + 1e-9
        ):
            raise ValueError("scanner returned invalid CEL duration")
        if isinstance(cel_fallbacks, bool) or not isinstance(cel_fallbacks, int) or cel_fallbacks < 0:
            raise ValueError("scanner returned invalid CEL fallback count")

        return {
            "skill_name": skill_name,
            "expected_safe": expected_safe,
            "package_label": package_label,
            "actual_safe": actual_safe,
            "safe_match": safe_match,
            "expected_threat_count": len(expected_threats),
            "detected_threat_count": len(actual_findings),
            "matched_threats": matched_threats,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "threat_coverage": threat_coverage,
            "correct": correct,
            "matching_mode": quality or ("legacy_degraded" if degraded_indices else "strict"),
            "legacy_degraded_findings": len(degraded_indices),
            "matched_pairs": matched_pairs,
            "unmatched_expected_findings": unmatched_expected,
            "unmatched_actual_findings": unmatched_actual,
            "matched_categories": dict(sorted(matched_categories.items())),
            "false_positive_categories": dict(sorted(false_positive_categories.items())),
            "false_negative_categories": dict(sorted(false_negative_categories.items())),
            "package_blocked": bool(severities & _BLOCKING_SEVERITIES),
            "package_actionable": bool(severities & _ACTIONABLE_SEVERITIES),
            "package_signal": bool(severities & _SIGNAL_SEVERITIES),
            "scan_duration_ms": scan_duration_ms,
            "cel_elapsed_ms": float(cel_elapsed_ms),
            "cel_fallbacks": cel_fallbacks,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "expected_severity": expected.get("expected_severity", "UNKNOWN"),
            "actual_severity": scan_result.max_severity.value,
        }

    def _calculate_benchmark_metrics(self, duration: float) -> BenchmarkResult:
        """Calculate aggregate benchmark metrics."""
        if not self.results:
            return BenchmarkResult(
                total_skills_evaluated=0,
                safe_skills=0,
                malicious_skills=0,
                benign_packages=0,
                contextual_risk_packages=0,
                evaluation_errors=0,
                loader_fallbacks=0,
                recovered_scan_errors=0,
                loader_rejections=0,
                loader_rejection_sample_ids=[],
                finding_true_positives=0,
                finding_false_positives=0,
                finding_false_negatives=0,
                strict_identity_skills=0,
                legacy_degraded_skills=0,
                legacy_degraded_findings=0,
                overall_accuracy=0.0,
                overall_precision=0.0,
                overall_recall=0.0,
                overall_f1=0.0,
                finding_macro_f1=0.0,
                finding_precision_confidence_interval_95=(0.0, 0.0),
                finding_recall_confidence_interval_95=(0.0, 0.0),
                package_true_positives=0,
                package_false_positives=0,
                package_true_negatives=0,
                package_false_negatives=0,
                package_block_recall=0.0,
                package_signal_recall=0.0,
                package_macro_f1=0.0,
                benign_actionable_false_positives=0,
                benign_actionable_false_positive_rate=0.0,
                package_block_recall_confidence_interval_95=(0.0, 0.0),
                package_signal_recall_confidence_interval_95=(0.0, 0.0),
                benign_actionable_fpr_confidence_interval_95=(0.0, 0.0),
                category_metrics=[],
                scan_duration_seconds=duration,
                skills_per_second=0.0,
                p95_scan_latency_ms=0.0,
                cel_time_ratio=0.0,
                cel_fallbacks=0,
            )

        # Overall metrics
        total = len(self.results)
        correct = sum(1 for r in self.results if r.get("correct", False))
        safe_count = sum(1 for r in self.results if r.get("expected_safe") is True)
        malicious_count = sum(1 for r in self.results if r.get("expected_safe") is False)
        benign_count = sum(1 for r in self.results if r.get("package_label") == "benign")
        contextual_risk_count = sum(1 for r in self.results if r.get("package_label") == "contextual_risk")
        error_count = sum(1 for r in self.results if "error" in r)
        loader_fallbacks = sum(1 for r in self.results if r.get("loader_fallback_code") is not None)
        recovered_scan_errors = sum(1 for r in self.results if r.get("recovered_scan_error") is True)
        loader_rejections = sum(1 for r in self.results if r.get("loader_rejection_code") is not None)
        loader_rejection_sample_ids = sorted(
            {
                str(r.get("benchmark_id") or r.get("skill_name"))
                for r in self.results
                if r.get("loader_rejection_code") is not None
            }
        )
        if loader_rejections != len(loader_rejection_sample_ids):
            raise ValueError("closed loader rejection counters are inconsistent")
        if loader_fallbacks != recovered_scan_errors:
            raise ValueError("loader fallback recovery counters are inconsistent")

        # Finding-level counts. Every unmatched actual is a false positive and
        # every unmatched expectation is a false negative.
        tp = sum(r.get("matched_threats", 0) for r in self.results)
        fp = sum(r.get("false_positives", 0) for r in self.results)
        fn = sum(r.get("false_negatives", 0) for r in self.results)
        legacy_degraded_skills = sum(1 for r in self.results if r.get("matching_mode") == "legacy_degraded")
        legacy_degraded_findings = sum(r.get("legacy_degraded_findings", 0) for r in self.results)
        strict_identity_skills = sum(1 for r in self.results if r.get("matching_mode") == "strict")

        # Calculate metrics
        accuracy = correct / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # Package classification uses the plan's explicit blocking threshold
        # (CRITICAL/HIGH), independent of a scanner's presentation verdict.
        package_tp = package_tn = package_fp = package_fn = 0
        benign_actionable_fp = 0
        malicious_signal_tp = 0
        for result in self.results:
            expected_safe = result.get("expected_safe")
            if not isinstance(expected_safe, bool):
                continue
            is_error = "error" in result
            blocked = result.get("package_blocked") is True
            actionable = result.get("package_actionable") is True
            if expected_safe:
                if is_error or blocked:
                    package_fp += 1
                else:
                    package_tn += 1
                if result.get("package_label") == "benign" and (is_error or actionable):
                    benign_actionable_fp += 1
            elif is_error or not blocked:
                package_fn += 1
            else:
                package_tp += 1
            if not expected_safe and not is_error and result.get("package_signal") is True:
                malicious_signal_tp += 1

        package_precision = _safe_divide(package_tp, package_tp + package_fp)
        package_recall = _safe_divide(package_tp, package_tp + package_fn)
        package_f1 = _f1(package_precision, package_recall)
        benign_precision = _safe_divide(package_tn, package_tn + package_fn)
        benign_recall = _safe_divide(package_tn, package_tn + package_fp)
        package_macro_f1 = (package_f1 + _f1(benign_precision, benign_recall)) / 2

        # Finding-level per-category metrics are derived from the exact
        # one-to-one assignment retained on each fixture result.
        all_categories = sorted(
            {
                category
                for result in self.results
                for field in (
                    "matched_categories",
                    "false_positive_categories",
                    "false_negative_categories",
                )
                for category in result.get(field, {})
            }
        )
        category_metrics: list[EvalMetrics] = []
        for category in all_categories:
            category_tp = sum(result.get("matched_categories", {}).get(category, 0) for result in self.results)
            category_fp = sum(result.get("false_positive_categories", {}).get(category, 0) for result in self.results)
            category_fn = sum(result.get("false_negative_categories", {}).get(category, 0) for result in self.results)
            fixtures = sum(
                1
                for result in self.results
                if any(
                    result.get(field, {}).get(category, 0)
                    for field in (
                        "matched_categories",
                        "false_positive_categories",
                        "false_negative_categories",
                    )
                )
            )
            category_precision = _safe_divide(category_tp, category_tp + category_fp)
            category_recall = _safe_divide(category_tp, category_tp + category_fn)
            category_metrics.append(
                EvalMetrics(
                    category=category,
                    fixtures=fixtures,
                    expected_findings=category_tp + category_fn,
                    actual_findings=category_tp + category_fp,
                    true_positives=category_tp,
                    false_positives=category_fp,
                    false_negatives=category_fn,
                    precision=category_precision,
                    recall=category_recall,
                    f1_score=_f1(category_precision, category_recall),
                    precision_confidence_interval_95=_wilson_interval(category_tp, category_tp + category_fp),
                    recall_confidence_interval_95=_wilson_interval(category_tp, category_tp + category_fn),
                )
            )

        scan_latencies = [
            float(result.get("scan_duration_ms", 0.0)) for result in self.results if "error" not in result
        ]
        total_scan_ms = sum(scan_latencies)
        total_cel_ms = sum(float(result.get("cel_elapsed_ms", 0.0)) for result in self.results if "error" not in result)
        cel_fallbacks = sum(int(result.get("cel_fallbacks", 0)) for result in self.results)

        return BenchmarkResult(
            total_skills_evaluated=total,
            safe_skills=safe_count,
            malicious_skills=malicious_count,
            benign_packages=benign_count,
            contextual_risk_packages=contextual_risk_count,
            evaluation_errors=error_count,
            loader_fallbacks=loader_fallbacks,
            recovered_scan_errors=recovered_scan_errors,
            loader_rejections=loader_rejections,
            loader_rejection_sample_ids=loader_rejection_sample_ids,
            finding_true_positives=tp,
            finding_false_positives=fp,
            finding_false_negatives=fn,
            strict_identity_skills=strict_identity_skills,
            legacy_degraded_skills=legacy_degraded_skills,
            legacy_degraded_findings=legacy_degraded_findings,
            overall_accuracy=accuracy,
            overall_precision=precision,
            overall_recall=recall,
            overall_f1=f1,
            finding_macro_f1=_safe_divide(sum(metric.f1_score for metric in category_metrics), len(category_metrics)),
            finding_precision_confidence_interval_95=_wilson_interval(tp, tp + fp),
            finding_recall_confidence_interval_95=_wilson_interval(tp, tp + fn),
            package_true_positives=package_tp,
            package_false_positives=package_fp,
            package_true_negatives=package_tn,
            package_false_negatives=package_fn,
            package_block_recall=package_recall,
            package_signal_recall=_safe_divide(malicious_signal_tp, malicious_count),
            package_macro_f1=package_macro_f1,
            benign_actionable_false_positives=benign_actionable_fp,
            benign_actionable_false_positive_rate=_safe_divide(benign_actionable_fp, benign_count),
            package_block_recall_confidence_interval_95=_wilson_interval(package_tp, package_tp + package_fn),
            package_signal_recall_confidence_interval_95=_wilson_interval(malicious_signal_tp, malicious_count),
            benign_actionable_fpr_confidence_interval_95=_wilson_interval(benign_actionable_fp, benign_count),
            category_metrics=category_metrics,
            scan_duration_seconds=duration,
            skills_per_second=total / duration if duration > 0 else 0.0,
            p95_scan_latency_ms=_p95(scan_latencies),
            cel_time_ratio=_safe_divide(total_cel_ms, total_scan_ms),
            cel_fallbacks=cel_fallbacks,
        )

    def print_report(self, result: BenchmarkResult):
        """Print benchmark report."""
        print()
        print("=" * 70)
        print("[RESULTS] BENCHMARK RESULTS")
        print("=" * 70)
        print()

        print(f"Total Skills Evaluated: {result.total_skills_evaluated}")
        print(f"  - Safe Skills: {result.safe_skills}")
        print(f"  - Malicious Skills: {result.malicious_skills}")
        print(f"  - Benign Packages: {result.benign_packages}")
        print(f"  - Contextual-Risk Packages: {result.contextual_risk_packages}")
        print(f"  - Evaluation Errors: {result.evaluation_errors}")
        print(f"  - Loader Fallbacks: {result.loader_fallbacks}")
        print(f"  - Recovered Scan Errors: {result.recovered_scan_errors}")
        print(f"  - Closed Loader Rejections: {result.loader_rejections}")
        print(f"  - Strict Identity Skills: {result.strict_identity_skills}")
        print(
            "  - Legacy Degraded Matching: "
            f"{result.legacy_degraded_skills} skills / "
            f"{result.legacy_degraded_findings} findings"
        )
        print()

        print("Performance:")
        print(f"  - Total Duration: {result.scan_duration_seconds:.2f}s")
        print(f"  - Skills/Second: {result.skills_per_second:.2f}")
        print()

        print("Detection Metrics:")
        print(f"  - Accuracy:  {result.overall_accuracy:.1%}")
        print(f"  - Precision: {result.overall_precision:.1%}")
        print(f"  - Recall:    {result.overall_recall:.1%}")
        print(f"  - F1 Score:  {result.overall_f1:.1%}")
        print(
            "  - Finding Counts: "
            f"TP={result.finding_true_positives}, "
            f"FP={result.finding_false_positives}, "
            f"FN={result.finding_false_negatives}"
        )
        print(
            "  - Package Block Counts: "
            f"TP={result.package_true_positives}, "
            f"FP={result.package_false_positives}, "
            f"TN={result.package_true_negatives}, "
            f"FN={result.package_false_negatives}"
        )
        print(f"  - Package Block Recall: {result.package_block_recall:.1%}")
        print(f"  - Package Signal Recall: {result.package_signal_recall:.1%}")
        print(f"  - Package Macro-F1: {result.package_macro_f1:.1%}")
        print(f"  - Finding Macro-F1: {result.finding_macro_f1:.1%}")
        print(
            "  - Benign Actionable False-Positive Rate: "
            f"{result.benign_actionable_false_positive_rate:.1%} "
            f"({result.benign_actionable_false_positives}/{result.benign_packages})"
        )
        print(f"  - P95 Scan Latency: {result.p95_scan_latency_ms:.2f}ms")
        print(f"  - CEL Time Ratio: {result.cel_time_ratio:.1%}")
        print(f"  - CEL Fallbacks: {result.cel_fallbacks}")
        print()

        if result.category_metrics:
            print("Finding Metrics by Category:")
            for metric in result.category_metrics:
                print(
                    f"  - {metric.category}: TP={metric.true_positives}, "
                    f"FP={metric.false_positives}, FN={metric.false_negatives}, "
                    f"Precision={metric.precision:.1%}, Recall={metric.recall:.1%}"
                )
            print()

        # Print individual results
        print("Individual Results:")
        for r in self.results:
            if "error" in r:
                print(f"  [FAIL] {r['skill_name']}: ERROR - {r['error']}")
            else:
                status = "[OK]" if r["correct"] else "[FAIL]"
                coverage = r["threat_coverage"] * 100
                print(
                    f"  {status} {r['skill_name']}: "
                    f"Safe={r['safe_match']}, "
                    f"Coverage={coverage:.0f}% "
                    f"({r['matched_threats']}/{r['expected_threat_count']})"
                )

        print()
        print("=" * 70)


def main():
    """Main entry point for benchmark."""
    import argparse

    parser = argparse.ArgumentParser(description="Run Skill Scanner benchmarks")
    parser.add_argument("--eval-dir", default="evals/skills", help="Directory containing evaluation skills")
    parser.add_argument("--output", help="Output file for JSON results")
    parser.add_argument("--category", help="Run only specific category (e.g., prompt-injection)")

    args = parser.parse_args()

    # Find eval directory
    eval_dir = Path(args.eval_dir)
    if not eval_dir.exists():
        print(f"Error: Evaluation directory not found: {eval_dir}")
        return 1

    # Filter by category if specified
    if args.category:
        eval_dir = eval_dir / args.category
        if not eval_dir.exists():
            print(f"Error: Category not found: {args.category}")
            return 1

    # Run benchmark
    runner = SkillBenchmarkRunner(eval_dir)
    result = runner.run_benchmark()

    # Print report
    runner.print_report(result)

    # Save JSON if requested
    if args.output:
        output_data = {"benchmark": asdict(result), "individual_results": runner.results}
        output_path = Path(args.output)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        golden_path = output_path.parent / "golden-corpus.json"
        golden_evidence = build_committed_golden_evidence(eval_dir)
        with open(golden_path, "w", encoding="utf-8") as f:
            json.dump(golden_evidence, f, indent=2)
            f.write("\n")
        print(f"Results saved to: {output_path}")
        print(f"Golden corpus evidence saved to: {golden_path}")

    if result.evaluation_errors:
        print("[ERROR] One or more evaluation skills could not be evaluated")
        return 1

    # Exit code based on accuracy
    if result.overall_accuracy < 0.8:
        print("[WARNING] Accuracy below 80%")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
