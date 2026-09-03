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

"""Run the local primary/Meta comparison exactly five paired times.

Each repeat scans a fixture once with the primary LLM and applies Meta to that
exact result. The compact success artifact contains only aggregate metrics,
stable output hashes, and source/prompt/model provenance. An incomplete repeat
instead writes a separate rawless failure artifact containing only stable codes
and hashes; neither artifact serializes sample content or model responses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evals.runners.eval_runner import _evaluation_provenance, _scanner_source_sha256, run_comparison

_REQUIRED_REPEATS = 5
_PROMPT_HASH_LABELS = {
    "skill_scanner/data/prompts/skill_threat_analysis_prompt.md": "primary_prompt",
    "skill_scanner/data/prompts/skill_meta_analysis_prompt.md": "meta_system_prompt",
    "skill_scanner/data/prompts/llm_response_schema.json": "primary_response_schema",
}
_ERROR_CODE_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


class OllamaMetaBenchmarkError(RuntimeError):
    """Raised when exact paired benchmark invariants are not satisfied."""


def _stable_hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_sha256(value: object) -> str | None:
    return value if isinstance(value, str) and _is_sha256(value) else None


def _safe_error_code(value: object, fallback: str) -> str:
    if (
        isinstance(value, str)
        and 3 <= len(value) <= 96
        and value[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        and all(character in _ERROR_CODE_CHARACTERS for character in value)
    ):
        return value
    return fallback


def _prompt_hashes(provenance: Mapping[str, Any] | None, fallback: Mapping[str, Any]) -> dict[str, str]:
    source = provenance.get("prompt_sha256") if isinstance(provenance, Mapping) else None
    if not isinstance(source, Mapping):
        source = fallback.get("prompt_sha256")
    if not isinstance(source, Mapping):
        return {}
    return {
        label: digest
        for path, label in sorted(_PROMPT_HASH_LABELS.items())
        if (digest := _safe_sha256(source.get(path))) is not None
    }


def _failure_records(arm: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Extract an allowlisted, rawless view of per-fixture failures."""

    if not isinstance(arm, Mapping):
        return []
    run_status = arm.get("run_status")
    errors = run_status.get("errors") if isinstance(run_status, Mapping) else None
    if not isinstance(errors, list):
        return []

    records: list[dict[str, Any]] = []
    for error in errors:
        if not isinstance(error, Mapping):
            continue
        phase_value = error.get("phase")
        phase = phase_value if isinstance(phase_value, str) else ""
        fallback_code = {
            "initialization": "BENCHMARK_INITIALIZATION_FAILED",
            "meta_analysis": "META_ANALYSIS_INCOMPLETE",
            "paired_primary": "PAIRED_PRIMARY_INCOMPLETE",
            "evaluation": "PRIMARY_EVALUATION_INCOMPLETE",
        }.get(phase, "BENCHMARK_REPETITION_INCOMPLETE")
        diagnostics = error.get("failure_diagnostics")
        diagnostic_values = diagnostics if isinstance(diagnostics, list) and diagnostics else [{}]
        for diagnostic in diagnostic_values:
            if not isinstance(diagnostic, Mapping):
                diagnostic = {}
            outer_code = _safe_error_code(diagnostic.get("outer_error_code"), fallback_code)
            record: dict[str, Any] = {
                "fixture_identity_sha256": _safe_sha256(error.get("fixture_identity_sha256")),
                "fixture_content_sha256": _safe_sha256(error.get("fixture_content_sha256")),
                "outer_error_code": outer_code,
                "inner_error_code": _safe_error_code(diagnostic.get("inner_error_code"), outer_code),
                "repair_attempted": max(0, int(diagnostic.get("repair_attempted", 0)))
                if type(diagnostic.get("repair_attempted", 0)) is int
                else 0,
                "repair_succeeded": max(0, int(diagnostic.get("repair_succeeded", 0)))
                if type(diagnostic.get("repair_succeeded", 0)) is int
                else 0,
            }
            repair_error_code = diagnostic.get("repair_error_code")
            if repair_error_code is not None:
                record["repair_error_code"] = _safe_error_code(repair_error_code, "META_REPAIR_RUNTIME_FAILED")
            for field in (
                "request_sha256",
                "response_sha256",
                "repair_request_sha256",
                "repair_response_sha256",
            ):
                if (digest := _safe_sha256(diagnostic.get(field))) is not None:
                    record[field] = digest
            records.append(record)

    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        unique.setdefault(_stable_hash(record), record)
    deduplicated = list(unique.values())
    bound = [
        record
        for record in deduplicated
        if record["fixture_identity_sha256"] is not None and record["fixture_content_sha256"] is not None
    ]
    return bound or deduplicated


def _arm_provenance(arm: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    provenance = arm.get("provenance") if isinstance(arm, Mapping) else None
    return provenance if isinstance(provenance, Mapping) else None


def _build_failure_artifact(
    *,
    repetition_index: int,
    primary: Mapping[str, Any] | None,
    meta: Mapping[str, Any] | None,
    baseline_provenance: Mapping[str, Any],
    current_source_sha256: str,
    ollama_model: str,
    ollama_model_digest: str,
    fallback_outer_error_code: str | None = None,
    fallback_inner_error_code: str | None = None,
) -> dict[str, Any]:
    """Build the strict allowlisted artifact used after one failed repeat."""

    meta_provenance = _arm_provenance(meta)
    primary_provenance = _arm_provenance(primary)
    provenance = meta_provenance or primary_provenance
    records = _failure_records(meta)
    if not records:
        records = _failure_records(primary)
    if not records:
        outer = _safe_error_code(fallback_outer_error_code, "BENCHMARK_REPETITION_INCOMPLETE")
        records = [
            {
                "fixture_identity_sha256": None,
                "fixture_content_sha256": None,
                "outer_error_code": outer,
                "inner_error_code": _safe_error_code(fallback_inner_error_code, outer),
                "repair_attempted": 0,
                "repair_succeeded": 0,
            }
        ]

    observed_sources = {
        digest
        for candidate in (
            baseline_provenance.get("scanner_source_sha256"),
            primary_provenance.get("scanner_source_sha256") if primary_provenance else None,
            meta_provenance.get("scanner_source_sha256") if meta_provenance else None,
            current_source_sha256,
        )
        if (digest := _safe_sha256(candidate)) is not None
    }
    meta_analysis = meta.get("meta_analysis") if isinstance(meta, Mapping) else None
    response_schema_sha256 = None
    request_options_sha256 = None
    if isinstance(meta_analysis, Mapping):
        response_schema_sha256 = _safe_sha256(meta_analysis.get("response_schema_sha256"))
        request_options_sha256 = _safe_sha256(meta_analysis.get("request_options_sha256"))
    if response_schema_sha256 is None and meta_provenance:
        response_schema_sha256 = _safe_sha256(meta_provenance.get("meta_response_schema_sha256"))
    if request_options_sha256 is None and meta_provenance:
        request_options_sha256 = _safe_sha256(meta_provenance.get("meta_request_options_sha256"))

    repair_attempted = sum(int(record["repair_attempted"]) for record in records)
    repair_succeeded = sum(int(record["repair_succeeded"]) for record in records)
    return {
        "schema_version": 1,
        "benchmark": "paired-local-ollama-meta",
        "status": "incomplete",
        "repetition_index": repetition_index,
        "fixture_failures": records,
        "model_identifier_sha256": _stable_hash({"model": ollama_model}),
        "model_digest": _safe_sha256(ollama_model_digest),
        "prompt_sha256": _prompt_hashes(provenance, baseline_provenance),
        "response_schema_sha256": response_schema_sha256,
        "request_options_sha256": request_options_sha256,
        "repair_counts": {
            "attempted": repair_attempted,
            "succeeded": repair_succeeded,
        },
        "source_drift": {
            "detected": len(observed_sources) > 1,
            "baseline_sha256": _safe_sha256(baseline_provenance.get("scanner_source_sha256")),
            "observed_sha256": sorted(observed_sources),
        },
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def _arm_summary(arm: Mapping[str, Any]) -> dict[str, Any]:
    individual = arm.get("individual_results", [])
    if not isinstance(individual, list):
        individual = []
    provenance = arm.get("provenance")
    meta_analysis = arm.get("meta_analysis")
    meta_stats = arm.get("meta_analysis_stats")
    repair_identity = {
        "policy": provenance.get("meta_contract_repair_policy") if isinstance(provenance, Mapping) else None,
        "provenance_telemetry": (
            provenance.get("meta_contract_repair_telemetry") if isinstance(provenance, Mapping) else None
        ),
        "telemetry": (meta_analysis.get("contract_repair_telemetry") if isinstance(meta_analysis, Mapping) else None),
        "stats": (
            {
                key: meta_stats.get(key)
                for key in (
                    "contract_repairs_attempted",
                    "contract_repairs_succeeded",
                    "contract_repairs_failed",
                    "contract_repair_error_codes",
                )
            }
            if isinstance(meta_stats, Mapping)
            else None
        ),
    }
    contract_repair_sha256 = _stable_hash(repair_identity)
    return {
        "run_status": arm.get("run_status"),
        "metrics": arm.get("metrics"),
        "provenance": provenance,
        "llm_analysis": arm.get("llm_analysis"),
        "meta_analysis": meta_analysis,
        "meta_analysis_stats": meta_stats,
        "contract_repair_sha256": contract_repair_sha256,
        "result_sha256": _stable_hash(
            {"individual_results": individual, "contract_repair_sha256": contract_repair_sha256}
        ),
    }


def _metric(arm: Mapping[str, Any], name: str) -> float:
    metrics = arm.get("metrics")
    if not isinstance(metrics, Mapping):
        return 0.0
    value = metrics.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value)


def _is_complete(arm: Mapping[str, Any]) -> bool:
    status = arm.get("run_status")
    return isinstance(status, Mapping) and status.get("complete") is True


def run_five_repeat_benchmark(
    *,
    test_skills_dir: Path,
    ollama_model: str,
    ollama_base_url: str,
    ollama_model_digest: str,
    repeats: int = _REQUIRED_REPEATS,
    failure_output: Path | None = None,
) -> dict[str, Any]:
    """Return an exact-five paired primary/Meta qualification artifact."""

    if repeats != _REQUIRED_REPEATS:
        raise OllamaMetaBenchmarkError(f"local LLM/Meta qualification requires exactly {_REQUIRED_REPEATS} repeats")
    if not test_skills_dir.is_dir():
        raise OllamaMetaBenchmarkError(f"fixture directory does not exist: {test_skills_dir}")

    repository_root = Path(__file__).resolve().parents[2]
    baseline_provenance = _evaluation_provenance(ollama_model, ollama_model_digest)
    benchmark_started = time.perf_counter()
    runs: list[dict[str, Any]] = []
    for run_index in range(repeats):
        run_started = time.perf_counter()
        try:
            comparison = run_comparison(
                test_skills_dir,
                ollama_model=ollama_model,
                ollama_base_url=ollama_base_url,
                ollama_model_digest=ollama_model_digest,
                meta_seed=0,
            )
        except Exception as exc:
            failure_artifact = _build_failure_artifact(
                repetition_index=run_index,
                primary=None,
                meta=None,
                baseline_provenance=baseline_provenance,
                current_source_sha256=_scanner_source_sha256(repository_root),
                ollama_model=ollama_model,
                ollama_model_digest=ollama_model_digest,
                fallback_outer_error_code="BENCHMARK_REPETITION_FAILED",
                fallback_inner_error_code=(
                    "BENCHMARK_TIMEOUT" if isinstance(exc, TimeoutError) else "BENCHMARK_RUNTIME_FAILED"
                ),
            )
            if failure_output is not None:
                _write_json_atomic(failure_output, failure_artifact)
            raise OllamaMetaBenchmarkError(
                f"paired repetition {run_index + 1} failed; stopped before the next repetition"
            ) from exc
        primary = comparison.get("without_meta")
        meta = comparison.get("with_meta")
        comparison_status = comparison.get("comparison_status")
        if not isinstance(primary, Mapping) or not isinstance(meta, Mapping):
            failure_artifact = _build_failure_artifact(
                repetition_index=run_index,
                primary=primary if isinstance(primary, Mapping) else None,
                meta=meta if isinstance(meta, Mapping) else None,
                baseline_provenance=baseline_provenance,
                current_source_sha256=_scanner_source_sha256(repository_root),
                ollama_model=ollama_model,
                ollama_model_digest=ollama_model_digest,
                fallback_outer_error_code="BENCHMARK_COMPARISON_MALFORMED",
                fallback_inner_error_code="BENCHMARK_COMPARISON_MALFORMED",
            )
            if failure_output is not None:
                _write_json_atomic(failure_output, failure_artifact)
            raise OllamaMetaBenchmarkError("paired comparison returned malformed benchmark arms")
        run = {
            "run_index": run_index,
            "comparison_status": comparison_status,
            "primary": _arm_summary(primary),
            "meta": _arm_summary(meta),
            "duration_seconds": time.perf_counter() - run_started,
        }
        runs.append(run)
        if not (
            _is_complete(run["primary"])
            and _is_complete(run["meta"])
            and isinstance(comparison_status, Mapping)
            and comparison_status.get("complete") is True
        ):
            failure_artifact = _build_failure_artifact(
                repetition_index=run_index,
                primary=primary,
                meta=meta,
                baseline_provenance=baseline_provenance,
                current_source_sha256=_scanner_source_sha256(repository_root),
                ollama_model=ollama_model,
                ollama_model_digest=ollama_model_digest,
            )
            if failure_output is not None:
                _write_json_atomic(failure_output, failure_artifact)
            raise OllamaMetaBenchmarkError(
                f"paired repetition {run_index + 1} was incomplete; stopped before the next repetition"
            )

    primary_hashes = [str(run["primary"]["result_sha256"]) for run in runs]
    meta_hashes = [str(run["meta"]["result_sha256"]) for run in runs]
    provenance_hashes = [
        _stable_hash(
            {
                "primary": run["primary"].get("provenance"),
                "meta": run["meta"].get("provenance"),
            }
        )
        for run in runs
    ]
    all_complete = all(
        _is_complete(run["primary"])
        and _is_complete(run["meta"])
        and isinstance(run["comparison_status"], Mapping)
        and run["comparison_status"].get("complete") is True
        for run in runs
    )
    zero_recall_regression = all(
        _metric(run["meta"], "true_positives") >= _metric(run["primary"], "true_positives")
        and _metric(run["meta"], "false_negatives") <= _metric(run["primary"], "false_negatives")
        and _metric(run["meta"], "recall") >= _metric(run["primary"], "recall")
        for run in runs
    )
    no_precision_regression = all(
        _metric(run["meta"], "false_positives") <= _metric(run["primary"], "false_positives")
        and _metric(run["meta"], "precision") >= _metric(run["primary"], "precision")
        and _metric(run["meta"], "f1_score") >= _metric(run["primary"], "f1_score")
        for run in runs
    )
    material_improvement = any(
        _metric(run["meta"], "false_positives") < _metric(run["primary"], "false_positives")
        or _metric(run["meta"], "false_negatives") < _metric(run["primary"], "false_negatives")
        for run in runs
    )
    stability = {
        "primary": len(set(primary_hashes)) == 1,
        "meta": len(set(meta_hashes)) == 1,
        "provenance": len(set(provenance_hashes)) == 1,
    }
    checks = {
        "all_complete": all_complete,
        "exact_five_runs": len(runs) == _REQUIRED_REPEATS,
        "stable_primary_output": stability["primary"],
        "stable_meta_output": stability["meta"],
        "stable_provenance": stability["provenance"],
        "zero_recall_regression": zero_recall_regression,
        "no_precision_or_f1_regression": no_precision_regression,
        "material_improvement": material_improvement,
    }
    return {
        "schema_version": 1,
        "benchmark": "paired-local-ollama-meta",
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "repeats": repeats,
        "model": ollama_model,
        "model_digest": ollama_model_digest,
        "runs": runs,
        "timing": {
            "total_seconds": time.perf_counter() - benchmark_started,
            "per_run_seconds": [run["duration_seconds"] for run in runs],
        },
        "checks": checks,
        "qualified": all(checks.values()),
    }


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _default_failure_output(success_output: Path) -> Path:
    suffix = success_output.suffix or ".json"
    stem = success_output.name[: -len(success_output.suffix)] if success_output.suffix else success_output.name
    return success_output.with_name(f"{stem}.failure{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-skills-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--failure-output",
        type=Path,
        help="Rawless failure artifact path (defaults to OUTPUT with .failure before its suffix)",
    )
    parser.add_argument("--ollama-model", required=True)
    parser.add_argument("--ollama-base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--ollama-model-digest", required=True)
    parser.add_argument("--repeats", type=int, default=_REQUIRED_REPEATS)
    args = parser.parse_args()

    failure_output = args.failure_output or _default_failure_output(args.output)
    if failure_output.resolve() == args.output.resolve():
        parser.error("--failure-output must differ from --output")

    try:
        artifact = run_five_repeat_benchmark(
            test_skills_dir=args.test_skills_dir,
            ollama_model=args.ollama_model,
            ollama_base_url=args.ollama_base_url,
            ollama_model_digest=args.ollama_model_digest,
            repeats=args.repeats,
            failure_output=failure_output,
        )
    except OllamaMetaBenchmarkError:
        # The allowlisted failure artifact is the only diagnostic surface.
        # Avoid reflecting a chained provider/parser exception to the console.
        return 2
    _write_json_atomic(args.output, artifact)
    return 0 if artifact["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
