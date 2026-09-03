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

from __future__ import annotations

import json

import pytest

import evals.runners.ollama_meta_benchmark as benchmark_module
from evals.runners.ollama_meta_benchmark import (
    OllamaMetaBenchmarkError,
    _arm_summary,
    _default_failure_output,
    _write_json_atomic,
    run_five_repeat_benchmark,
)


def _arm(*, false_positives: int, false_negatives: int) -> dict:
    true_positives = 10 - false_negatives
    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / 10
    f1 = 2 * precision * recall / (precision + recall)
    return {
        "run_status": {"status": "complete", "complete": True, "errors": []},
        "metrics": {
            "accuracy": 1.0,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": 5,
            "false_negatives": false_negatives,
            "errors": 0,
        },
        "individual_results": [
            {
                "skill_name": "bounded-fixture",
                "expected_safe": False,
                "actual_safe": false_negatives == 0,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
            }
        ],
        "provenance": {
            "scanner_source_sha256": "a" * 64,
            "prompt_sha256": {"prompt": "b" * 64},
            "ollama_model_digest": "c" * 64,
        },
    }


def test_exact_five_paired_runs_qualify_only_with_stable_material_improvement(tmp_path, monkeypatch) -> None:
    calls: list[int] = []

    def fake_comparison(*_args, **_kwargs):
        calls.append(len(calls))
        return {
            "without_meta": _arm(false_positives=2, false_negatives=1),
            "with_meta": _arm(false_positives=1, false_negatives=0),
            "comparison_status": {"status": "complete", "complete": True, "reason": None},
        }

    monkeypatch.setattr(benchmark_module, "run_comparison", fake_comparison)

    failure_output = tmp_path / "paired.failure.json"
    artifact = run_five_repeat_benchmark(
        test_skills_dir=tmp_path,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model_digest="c" * 64,
        failure_output=failure_output,
    )

    assert calls == [0, 1, 2, 3, 4]
    assert artifact["repeats"] == 5
    assert artifact["qualified"] is True
    assert all(artifact["checks"].values())
    assert artifact["timing"]["total_seconds"] >= 0
    assert len(artifact["timing"]["per_run_seconds"]) == 5
    assert all(duration >= 0 for duration in artifact["timing"]["per_run_seconds"])
    assert len({run["primary"]["result_sha256"] for run in artifact["runs"]}) == 1
    assert len({run["meta"]["result_sha256"] for run in artifact["runs"]}) == 1
    assert not failure_output.exists()


def test_recall_regression_and_unstable_output_fail_qualification(tmp_path, monkeypatch) -> None:
    calls = 0

    def fake_comparison(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        meta = _arm(false_positives=0, false_negatives=2)
        meta["individual_results"][0]["run"] = calls
        return {
            "without_meta": _arm(false_positives=2, false_negatives=1),
            "with_meta": meta,
            "comparison_status": {"status": "complete", "complete": True, "reason": None},
        }

    monkeypatch.setattr(benchmark_module, "run_comparison", fake_comparison)

    artifact = run_five_repeat_benchmark(
        test_skills_dir=tmp_path,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model_digest="c" * 64,
    )

    assert artifact["qualified"] is False
    assert artifact["checks"]["zero_recall_regression"] is False
    assert artifact["checks"]["stable_meta_output"] is False


def test_repeat_count_is_closed_to_exactly_five(tmp_path) -> None:
    with pytest.raises(OllamaMetaBenchmarkError, match="exactly 5 repeats"):
        run_five_repeat_benchmark(
            test_skills_dir=tmp_path,
            ollama_model="ollama/qwen-test",
            ollama_base_url="http://127.0.0.1:11434",
            ollama_model_digest="c" * 64,
            repeats=4,
        )


def test_incomplete_repetition_stops_before_next_model_call(tmp_path, monkeypatch) -> None:
    calls = 0

    def fake_comparison(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        meta = _arm(false_positives=1, false_negatives=0)
        meta["run_status"] = {"status": "incomplete", "complete": False, "errors": []}
        return {
            "without_meta": _arm(false_positives=2, false_negatives=1),
            "with_meta": meta,
            "comparison_status": {"status": "incomplete", "complete": False, "reason": "meta_incomplete"},
        }

    monkeypatch.setattr(benchmark_module, "run_comparison", fake_comparison)

    with pytest.raises(OllamaMetaBenchmarkError, match="repetition 1 was incomplete"):
        run_five_repeat_benchmark(
            test_skills_dir=tmp_path,
            ollama_model="ollama/qwen-test",
            ollama_base_url="http://127.0.0.1:11434",
            ollama_model_digest="c" * 64,
        )

    assert calls == 1


def test_incomplete_repetition_writes_only_rawless_failure_identity(tmp_path, monkeypatch) -> None:
    raw_sample = "RAW-SAMPLE-CONTENT-MUST-NOT-PERSIST"
    raw_model = "RAW-MODEL-OUTPUT-MUST-NOT-PERSIST"
    raw_error = "RAW-ERROR-TEXT-MUST-NOT-PERSIST"
    primary = _arm(false_positives=2, false_negatives=1)
    meta = _arm(false_positives=1, false_negatives=0)
    primary["provenance"]["scanner_source_sha256"] = "b" * 64
    meta["provenance"].update(
        {
            "scanner_source_sha256": "b" * 64,
            "meta_response_schema_sha256": "e" * 64,
            "meta_request_options_sha256": "f" * 64,
        }
    )
    meta["meta_analysis"] = {
        "response_schema_sha256": "e" * 64,
        "request_options_sha256": "f" * 64,
    }
    meta["run_status"] = {
        "status": "incomplete",
        "complete": False,
        "errors": [
            {
                "phase": "meta_analysis",
                "message": raw_error,
                "skill_name": raw_sample,
                "fixture_identity_sha256": "1" * 64,
                "fixture_content_sha256": "2" * 64,
                "failure_diagnostics": [
                    {
                        "outer_error_code": "META_BATCH_PARSE_FAILED",
                        "inner_error_code": "META_CONTRACT_ASSESSMENT_FIELDS",
                        "request_sha256": "3" * 64,
                        "response_sha256": "4" * 64,
                        "repair_attempted": 1,
                        "repair_succeeded": 0,
                        "repair_request_sha256": "5" * 64,
                        "repair_response_sha256": "6" * 64,
                        "repair_error_code": "META_CONTRACT_DELTA_CONSISTENCY",
                        "raw_output": raw_model,
                    }
                ],
            }
        ],
    }
    meta["individual_results"][0]["error"] = raw_model

    monkeypatch.setattr(
        benchmark_module,
        "_evaluation_provenance",
        lambda *_args, **_kwargs: {
            "scanner_source_sha256": "a" * 64,
            "prompt_sha256": {
                "skill_scanner/data/prompts/skill_threat_analysis_prompt.md": "7" * 64,
                "skill_scanner/data/prompts/skill_meta_analysis_prompt.md": "8" * 64,
                "skill_scanner/data/prompts/llm_response_schema.json": "9" * 64,
            },
        },
    )
    monkeypatch.setattr(benchmark_module, "_scanner_source_sha256", lambda _root: "c" * 64)
    calls = 0

    def fake_comparison(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {
            "without_meta": primary,
            "with_meta": meta,
            "comparison_status": {"status": "incomplete", "complete": False, "reason": raw_error},
        }

    monkeypatch.setattr(benchmark_module, "run_comparison", fake_comparison)
    failure_output = tmp_path / "benchmark.failure.json"

    with pytest.raises(OllamaMetaBenchmarkError, match="repetition 1 was incomplete"):
        run_five_repeat_benchmark(
            test_skills_dir=tmp_path,
            ollama_model="ollama/raw-model-name",
            ollama_base_url="http://127.0.0.1:11434",
            ollama_model_digest="d" * 64,
            failure_output=failure_output,
        )

    assert calls == 1
    artifact = json.loads(failure_output.read_text(encoding="utf-8"))
    assert set(artifact) == {
        "schema_version",
        "benchmark",
        "status",
        "repetition_index",
        "fixture_failures",
        "model_identifier_sha256",
        "model_digest",
        "prompt_sha256",
        "response_schema_sha256",
        "request_options_sha256",
        "repair_counts",
        "source_drift",
        "harness_sha256",
    }
    assert artifact["repetition_index"] == 0
    assert artifact["fixture_failures"] == [
        {
            "fixture_identity_sha256": "1" * 64,
            "fixture_content_sha256": "2" * 64,
            "outer_error_code": "META_BATCH_PARSE_FAILED",
            "inner_error_code": "META_CONTRACT_ASSESSMENT_FIELDS",
            "repair_attempted": 1,
            "repair_succeeded": 0,
            "request_sha256": "3" * 64,
            "response_sha256": "4" * 64,
            "repair_request_sha256": "5" * 64,
            "repair_response_sha256": "6" * 64,
            "repair_error_code": "META_CONTRACT_DELTA_CONSISTENCY",
        }
    ]
    assert artifact["repair_counts"] == {"attempted": 1, "succeeded": 0}
    assert artifact["source_drift"] == {
        "detected": True,
        "baseline_sha256": "a" * 64,
        "observed_sha256": ["a" * 64, "b" * 64, "c" * 64],
    }
    assert artifact["response_schema_sha256"] == "e" * 64
    assert artifact["request_options_sha256"] == "f" * 64
    serialized = json.dumps(artifact, sort_keys=True)
    for forbidden in (raw_sample, raw_model, raw_error, "ollama/raw-model-name"):
        assert forbidden not in serialized


def test_runtime_failure_writes_stable_code_without_exception_text(tmp_path, monkeypatch) -> None:
    raw_error = "provider-secret-must-not-persist"
    monkeypatch.setattr(
        benchmark_module,
        "_evaluation_provenance",
        lambda *_args, **_kwargs: {"scanner_source_sha256": "a" * 64, "prompt_sha256": {}},
    )
    monkeypatch.setattr(benchmark_module, "_scanner_source_sha256", lambda _root: "a" * 64)
    monkeypatch.setattr(
        benchmark_module,
        "run_comparison",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError(raw_error)),
    )
    failure_output = tmp_path / "runtime.failure.json"

    with pytest.raises(OllamaMetaBenchmarkError, match="repetition 1 failed"):
        run_five_repeat_benchmark(
            test_skills_dir=tmp_path,
            ollama_model="ollama/qwen-test",
            ollama_base_url="http://127.0.0.1:11434",
            ollama_model_digest="d" * 64,
            failure_output=failure_output,
        )

    artifact = json.loads(failure_output.read_text(encoding="utf-8"))
    assert artifact["fixture_failures"][0]["outer_error_code"] == "BENCHMARK_REPETITION_FAILED"
    assert artifact["fixture_failures"][0]["inner_error_code"] == "BENCHMARK_TIMEOUT"
    assert raw_error not in failure_output.read_text(encoding="utf-8")


def test_contract_repair_telemetry_participates_in_stability_hash() -> None:
    arm = _arm(false_positives=1, false_negatives=0)
    arm["provenance"]["meta_contract_repair_policy"] = {
        "version": 1,
        "max_attempts_per_batch": 1,
        "instruction_set_sha256": "d" * 64,
    }
    arm["meta_analysis"] = {
        "contract_repair_telemetry": {
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "error_codes": {},
        }
    }
    arm["meta_analysis_stats"] = {
        "contract_repairs_attempted": 0,
        "contract_repairs_succeeded": 0,
        "contract_repairs_failed": 0,
        "contract_repair_error_codes": {},
    }
    arm["provenance"]["meta_contract_repair_telemetry"] = dict(arm["meta_analysis"]["contract_repair_telemetry"])
    first = _arm_summary(arm)

    arm["meta_analysis"]["contract_repair_telemetry"]["attempted"] = 1
    arm["meta_analysis"]["contract_repair_telemetry"]["succeeded"] = 1
    arm["provenance"]["meta_contract_repair_telemetry"]["attempted"] = 1
    arm["provenance"]["meta_contract_repair_telemetry"]["succeeded"] = 1
    arm["meta_analysis_stats"]["contract_repairs_attempted"] = 1
    arm["meta_analysis_stats"]["contract_repairs_succeeded"] = 1
    second = _arm_summary(arm)

    assert first["contract_repair_sha256"] != second["contract_repair_sha256"]
    assert first["result_sha256"] != second["result_sha256"]


def test_atomic_writer_emits_complete_json(tmp_path) -> None:
    target = tmp_path / "artifact.json"

    _write_json_atomic(target, {"qualified": True, "runs": 5})

    assert json.loads(target.read_text(encoding="utf-8")) == {"qualified": True, "runs": 5}
    assert not list(tmp_path.glob(".artifact.json.*.tmp"))


def test_default_failure_output_is_separate_from_success_artifact(tmp_path) -> None:
    success = tmp_path / "paired.json"
    assert _default_failure_output(success) == tmp_path / "paired.failure.json"
