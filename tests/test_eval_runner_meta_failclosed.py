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
from types import SimpleNamespace

import pytest

import evals.runners.eval_runner as eval_runner_module
from evals.runners.eval_runner import (
    EvaluationRunner,
    _evaluation_provenance,
    _serializable_evaluation_result,
    _validate_local_ollama_config,
    run_comparison,
)
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult


def test_evaluation_runner_always_closes_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = EvaluationRunner.__new__(EvaluationRunner)
    closed: list[bool] = []
    runner.scanner = type("ClosingScanner", (), {"close": lambda self: closed.append(True)})()
    monkeypatch.setattr(runner, "_run_evaluation", lambda: {"status": "passed"})

    assert runner.run_evaluation() == {"status": "passed"}
    assert closed == [True]

    closed.clear()

    def fail() -> dict:
        raise RuntimeError("evaluation failed")

    monkeypatch.setattr(runner, "_run_evaluation", fail)
    with pytest.raises(RuntimeError, match="evaluation failed"):
        runner.run_evaluation()
    assert closed == [True]


def test_local_ollama_provenance_binds_source_prompts_and_exact_model_digest() -> None:
    provenance = _evaluation_provenance("ollama/qwen-test", "a" * 64)

    assert len(provenance["scanner_source_sha256"]) == 64
    assert set(provenance["scanner_source_sha256"]) <= set("0123456789abcdef")
    assert provenance["ollama_model"] == "ollama/qwen-test"
    assert provenance["ollama_model_digest"] == "a" * 64
    assert provenance["ollama_model_digest_status"] == "supplied"
    assert set(provenance["prompt_sha256"]) == {
        "skill_scanner/data/prompts/skill_threat_analysis_prompt.md",
        "skill_scanner/data/prompts/skill_meta_analysis_prompt.md",
        "skill_scanner/data/prompts/llm_response_schema.json",
    }
    assert all(len(value) == 64 for value in provenance["prompt_sha256"].values())


@pytest.mark.parametrize("digest", ["short", "g" * 64, "A" * 64])
def test_local_ollama_provenance_rejects_noncanonical_model_digest(digest: str) -> None:
    with pytest.raises(ValueError, match="exactly 64 lowercase hexadecimal"):
        _evaluation_provenance("ollama/qwen-test", digest)


def test_result_serialization_removes_nested_display_only_objects() -> None:
    display_object = object()

    serialized = _serializable_evaluation_result(
        {
            "metrics": {"accuracy": 1.0},
            "eval_results_with_scan": [display_object],
            "paired_primary": {
                "metrics": {"accuracy": 1.0},
                "eval_results_with_scan": [display_object],
            },
        }
    )

    assert serialized == {
        "metrics": {"accuracy": 1.0},
        "paired_primary": {"metrics": {"accuracy": 1.0}},
    }


def _write_safe_fixture(root) -> None:
    fixture = root / "safe-fixture"
    fixture.mkdir()
    (fixture / "SKILL.md").write_text(
        "---\nname: safe-fixture\ndescription: Safe fixture\n---\n\n# Safe\n",
        encoding="utf-8",
    )
    (fixture / "_expected.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evaluation_quality": "legacy_degraded",
                "skill_name": "safe-fixture",
                "expected_safe": True,
                "expected_findings": [],
            }
        ),
        encoding="utf-8",
    )


class _FakeScanner:
    def __init__(self, *args, **kwargs) -> None:
        del args, kwargs

    def scan_skill(self, _skill_dir):
        return SimpleNamespace(
            skill_name="safe-fixture",
            findings=[],
            analyzers_used=["static"],
            analyzers_failed=[],
            is_safe=True,
        )


class _SuccessfulMetaAnalyzer:
    def __init__(self, *, model, base_url, policy, temperature, max_tokens, timeout) -> None:
        del policy
        assert temperature == 0.0
        assert max_tokens == 16_384
        assert timeout == 120
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.contract_repair_policy = {
            "version": 1,
            "max_attempts_per_batch": 1,
            "instruction_set_sha256": "d" * 64,
        }
        self.response_schema_sha256 = "e" * 64
        self.request_options_sha256 = "9aae3bd8903f3ad47e7c97d77539c4277882883bcf2b6a200abbd3aca1952c8d"
        self.contract_repair_telemetry = {
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "error_codes": {},
        }

    async def analyze_with_findings(self, *, skill, findings, analyzers_used):
        del skill, findings, analyzers_used
        return MetaAnalysisResult(routing={"contract_repair": dict(self.contract_repair_telemetry)})


def _patch_runner_dependencies(monkeypatch, meta_analyzer_class) -> None:
    monkeypatch.setattr(eval_runner_module, "build_analyzers", lambda *args, **kwargs: [])
    monkeypatch.setattr(eval_runner_module, "SkillScanner", _FakeScanner)
    monkeypatch.setattr(
        "skill_scanner.core.analyzers.meta_analyzer.MetaAnalyzer",
        meta_analyzer_class,
    )


@pytest.mark.parametrize(
    ("model", "base_url", "message"),
    [
        ("claude-3-5-sonnet", "http://127.0.0.1:11434", "must start with 'ollama/'"),
        ("ollama/qwen", "https://models.example.test", "loopback Ollama endpoint"),
        ("ollama/qwen", "http://user:pass@127.0.0.1:11434", "loopback Ollama endpoint"),
    ],
)
def test_local_ollama_validation_rejects_nonlocal_or_non_ollama(model, base_url, message) -> None:
    with pytest.raises(ValueError, match=message):
        _validate_local_ollama_config(model, base_url)


def test_requested_meta_initialization_failure_marks_every_fixture_incomplete(tmp_path, monkeypatch) -> None:
    _write_safe_fixture(tmp_path)
    calls = []
    monkeypatch.setattr(
        eval_runner_module,
        "build_analyzers",
        lambda *args, **kwargs: calls.append(kwargs) or [],
    )
    monkeypatch.setattr(eval_runner_module, "SkillScanner", _FakeScanner)

    runner = EvaluationRunner(
        tmp_path,
        use_meta=True,
        ollama_model="hosted/model",
        ollama_base_url="http://127.0.0.1:11434",
        meta_seed=17,
    )
    results = runner.run_evaluation()

    assert calls[0]["use_llm"] is False
    assert results["run_status"]["complete"] is False
    assert results["metrics"]["errors"] == 1
    assert results["individual_results"][0]["actual_safe"] is None
    assert "only permits local Ollama" in results["individual_results"][0]["error"]
    assert results["meta_analysis"]["status"] == "initialization_failed"
    assert results["meta_analysis"]["seed"] == 17
    assert results["meta_analysis"]["seed_applied_to_model"] is False
    assert results["meta_analysis_stats"]["skills_failed"] == 1


def test_requested_primary_llm_cannot_fall_back_to_hosted_model(tmp_path, monkeypatch) -> None:
    _write_safe_fixture(tmp_path)
    calls = []
    monkeypatch.setattr(
        eval_runner_module,
        "build_analyzers",
        lambda *args, **kwargs: calls.append(kwargs) or [],
    )
    monkeypatch.setattr(eval_runner_module, "SkillScanner", _FakeScanner)

    runner = EvaluationRunner(
        tmp_path,
        use_llm=True,
        ollama_model="openai/gpt-5",
        ollama_base_url="http://127.0.0.1:11434",
    )
    results = runner.run_evaluation()

    assert calls[0]["use_llm"] is False
    assert results["run_status"]["complete"] is False
    assert results["llm_analysis"]["status"] == "initialization_failed"
    assert results["metrics"]["errors"] == 1


def test_meta_request_failure_is_counted_instead_of_reusing_unfiltered_scan(tmp_path, monkeypatch) -> None:
    _write_safe_fixture(tmp_path)

    class FailingMetaAnalyzer(_SuccessfulMetaAnalyzer):
        async def analyze_with_findings(self, *, skill, findings, analyzers_used):
            del skill, findings, analyzers_used
            raise ConnectionError("local Ollama unavailable")

    _patch_runner_dependencies(monkeypatch, FailingMetaAnalyzer)
    runner = EvaluationRunner(
        tmp_path,
        use_meta=True,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
        meta_seed=23,
    )

    results = runner.run_evaluation()

    assert results["run_status"]["complete"] is False
    assert results["metrics"]["errors"] == 1
    assert results["individual_results"][0]["actual_safe"] is None
    assert "local Ollama unavailable" in results["individual_results"][0]["error"]
    assert results["meta_analysis"]["model"] == "ollama/qwen-test"
    assert results["meta_analysis"]["base_url"] == "http://127.0.0.1:11434"
    assert results["meta_analysis"]["status"] == "incomplete"
    assert results["meta_analysis_stats"] == {
        "total_filtered": 0,
        "total_validated": 0,
        "skills_attempted": 1,
        "skills_processed": 0,
        "skills_failed": 1,
        "contract_repairs_attempted": 0,
        "contract_repairs_succeeded": 0,
        "contract_repairs_failed": 0,
        "contract_repair_error_codes": {},
    }


def test_degraded_meta_result_marks_run_incomplete(tmp_path, monkeypatch) -> None:
    _write_safe_fixture(tmp_path)

    class DegradedMetaAnalyzer(_SuccessfulMetaAnalyzer):
        async def analyze_with_findings(self, *, skill, findings, analyzers_used):
            del skill, findings, analyzers_used
            return MetaAnalysisResult(
                analysis_warnings=[
                    {
                        "code": "META_BATCH_REQUEST_FAILED",
                        "message": "request failed",
                        "first_index": 0,
                        "last_index": 0,
                        "finding_count": 1,
                        "failure_diagnostic": {
                            "outer_error_code": "META_BATCH_REQUEST_FAILED",
                            "inner_error_code": "META_REQUEST_CONNECTION_FAILED",
                            "request_sha256": "1" * 64,
                            "repair_attempted": 0,
                            "repair_succeeded": 0,
                        },
                    }
                ]
            )

    _patch_runner_dependencies(monkeypatch, DegradedMetaAnalyzer)
    runner = EvaluationRunner(
        tmp_path,
        use_meta=True,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://localhost:11434",
    )

    results = runner.run_evaluation()

    assert results["run_status"]["complete"] is False
    assert results["metrics"]["errors"] == 1
    assert "META_BATCH_REQUEST_FAILED" in results["individual_results"][0]["error"]
    failure = results["run_status"]["errors"][0]
    assert len(failure["fixture_identity_sha256"]) == 64
    assert len(failure["fixture_content_sha256"]) == 64
    assert failure["failure_diagnostics"] == [
        {
            "outer_error_code": "META_BATCH_REQUEST_FAILED",
            "inner_error_code": "META_REQUEST_CONNECTION_FAILED",
            "request_sha256": "1" * 64,
            "repair_attempted": 0,
            "repair_succeeded": 0,
        }
    ]


def test_successful_meta_run_records_config_and_seed_limitation(tmp_path, monkeypatch) -> None:
    _write_safe_fixture(tmp_path)
    _patch_runner_dependencies(monkeypatch, _SuccessfulMetaAnalyzer)
    runner = EvaluationRunner(
        tmp_path,
        use_meta=True,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://[::1]:11434/",
        ollama_model_digest="b" * 64,
        meta_seed=41,
    )

    results = runner.run_evaluation()

    assert results["run_status"] == {"status": "complete", "complete": True, "errors": []}
    assert results["metrics"]["errors"] == 0
    assert results["meta_analysis"] == {
        "requested": True,
        "provider": "ollama",
        "model": "ollama/qwen-test",
        "base_url": "http://[::1]:11434",
        "loopback_only": True,
        "seed": 41,
        "seed_applied_to_model": False,
        "reproducibility_limitations": [
            "MetaAnalyzer does not currently expose an Ollama seed parameter; "
            "the recorded seed is not applied to model sampling."
        ],
        "status": "complete",
        "temperature": 0.0,
        "max_tokens": 16384,
        "timeout_seconds": 120,
        "contract_repair_policy": {
            "version": 1,
            "max_attempts_per_batch": 1,
            "instruction_set_sha256": "d" * 64,
        },
        "response_schema_sha256": "e" * 64,
        "request_options_sha256": "9aae3bd8903f3ad47e7c97d77539c4277882883bcf2b6a200abbd3aca1952c8d",
        "contract_repair_telemetry": {
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "error_codes": {},
        },
    }
    assert results["meta_analysis_stats"]["skills_attempted"] == 1
    assert results["meta_analysis_stats"]["skills_processed"] == 1
    assert results["meta_analysis_stats"]["contract_repairs_attempted"] == 0
    assert results["meta_analysis_stats"]["contract_repairs_succeeded"] == 0
    assert results["meta_analysis_stats"]["contract_repairs_failed"] == 0
    assert results["provenance"]["meta_contract_repair_policy"] == results["meta_analysis"]["contract_repair_policy"]
    assert results["provenance"]["meta_response_schema_sha256"] == "e" * 64
    assert (
        results["provenance"]["meta_request_options_sha256"]
        == "9aae3bd8903f3ad47e7c97d77539c4277882883bcf2b6a200abbd3aca1952c8d"
    )
    assert results["provenance"]["ollama_model_digest"] == "b" * 64
    assert results["provenance"]["ollama_model_digest_status"] == "supplied"
    assert results["paired_primary"]["run_status"] == {
        "status": "complete",
        "complete": True,
        "errors": [],
    }
    assert results["paired_primary"]["total_skills"] == 1
    assert results["paired_primary"]["metrics"] == results["metrics"]


def test_successful_meta_contract_repair_is_hashed_into_run_metadata(tmp_path, monkeypatch) -> None:
    _write_safe_fixture(tmp_path)

    class RepairingMetaAnalyzer(_SuccessfulMetaAnalyzer):
        async def analyze_with_findings(self, *, skill, findings, analyzers_used):
            del skill, findings, analyzers_used
            self.contract_repair_telemetry = {
                "attempted": 1,
                "succeeded": 1,
                "failed": 0,
                "error_codes": {"META_CONTRACT_ASSESSMENT_FIELDS": 1},
            }
            return MetaAnalysisResult(routing={"contract_repair": dict(self.contract_repair_telemetry)})

    _patch_runner_dependencies(monkeypatch, RepairingMetaAnalyzer)
    runner = EvaluationRunner(
        tmp_path,
        use_meta=True,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model_digest="c" * 64,
    )

    results = runner.run_evaluation()

    assert results["run_status"]["complete"] is True
    assert results["meta_analysis_stats"]["contract_repairs_attempted"] == 1
    assert results["meta_analysis_stats"]["contract_repairs_succeeded"] == 1
    assert results["meta_analysis_stats"]["contract_repairs_failed"] == 0
    assert results["meta_analysis_stats"]["contract_repair_error_codes"] == {"META_CONTRACT_ASSESSMENT_FIELDS": 1}
    assert results["meta_analysis"]["contract_repair_telemetry"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "error_codes": {"META_CONTRACT_ASSESSMENT_FIELDS": 1},
    }
    assert (
        results["provenance"]["meta_contract_repair_telemetry"] == results["meta_analysis"]["contract_repair_telemetry"]
    )
    assert results["provenance"]["meta_contract_repair_policy"] == results["meta_analysis"]["contract_repair_policy"]


def test_comparison_uses_one_primary_scan_and_its_paired_pre_meta_result(monkeypatch, tmp_path) -> None:
    calls: list[bool] = []
    primary_metrics = {
        "accuracy": 0.5,
        "precision": 0.5,
        "recall": 0.5,
        "f1_score": 0.5,
        "true_positives": 1,
        "false_positives": 1,
        "true_negatives": 0,
        "false_negatives": 1,
    }
    meta_metrics = {
        **primary_metrics,
        "accuracy": 1.0,
        "precision": 1.0,
        "recall": 1.0,
        "f1_score": 1.0,
        "false_positives": 0,
        "false_negatives": 0,
    }

    class StubRunner:
        def __init__(self, _test_dir, *, use_meta, **_kwargs) -> None:
            calls.append(use_meta)

        def run_evaluation(self):
            return {
                "run_status": {"status": "complete", "complete": True, "errors": []},
                "metrics": meta_metrics,
                "eval_results_with_scan": [],
                "individual_results": [],
                "total_skills": 0,
                "paired_primary": {
                    "run_status": {"status": "complete", "complete": True, "errors": []},
                    "metrics": primary_metrics,
                    "eval_results_with_scan": [],
                    "individual_results": [],
                    "total_skills": 0,
                },
            }

    monkeypatch.setattr(eval_runner_module, "EvaluationRunner", StubRunner)

    comparison = run_comparison(
        tmp_path,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
    )

    assert calls == [True]
    assert comparison["comparison_status"]["complete"] is True
    assert comparison["without_meta"]["metrics"] is primary_metrics
    assert comparison["with_meta"]["metrics"] is meta_metrics


def test_identical_paired_meta_result_is_not_claimed_as_an_improvement(monkeypatch, tmp_path, capsys) -> None:
    metrics = {
        "accuracy": 1.0,
        "precision": 1.0,
        "recall": 1.0,
        "f1_score": 1.0,
        "true_positives": 1,
        "false_positives": 0,
        "true_negatives": 1,
        "false_negatives": 0,
    }
    result_row = SimpleNamespace(
        skill_name="paired-fixture",
        actual_findings_count=1,
        expected_safe=False,
        actual_safe=False,
        error=None,
    )

    class StubRunner:
        def __init__(self, _test_dir, **_kwargs) -> None:
            pass

        def run_evaluation(self):
            primary = {
                "run_status": {"status": "complete", "complete": True, "errors": []},
                "metrics": metrics,
                "eval_results_with_scan": [result_row],
                "individual_results": [],
                "total_skills": 1,
            }
            return {
                **primary,
                "paired_primary": primary,
                "meta_analysis_stats": {"total_filtered": 0, "total_validated": 1},
            }

    monkeypatch.setattr(eval_runner_module, "EvaluationRunner", StubRunner)

    comparison = run_comparison(
        tmp_path,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
    )

    assert comparison["comparison_status"]["complete"] is True
    output = capsys.readouterr().out
    assert "Meta-Analyzer did not change the paired classification outcome." in output
    assert "IMPROVED signal-to-noise" not in output


def test_incomplete_meta_arm_is_not_presented_as_a_metric_comparison(tmp_path, monkeypatch, capsys) -> None:
    class StubRunner:
        def __init__(self, _test_dir, *, use_meta, **kwargs) -> None:
            del kwargs
            self.use_meta = use_meta

        def run_evaluation(self):
            return {
                "run_status": {
                    "status": "incomplete" if self.use_meta else "complete",
                    "complete": not self.use_meta,
                    "errors": ([{"phase": "meta_analysis", "message": "failed"}] if self.use_meta else []),
                },
                "metrics": {"accuracy": 1.0 if not self.use_meta else 0.0, "errors": int(self.use_meta)},
                "eval_results_with_scan": [],
                "individual_results": [],
                "total_skills": 1,
            }

    monkeypatch.setattr(eval_runner_module, "EvaluationRunner", StubRunner)

    comparison = run_comparison(
        tmp_path,
        ollama_model="ollama/qwen-test",
        ollama_base_url="http://127.0.0.1:11434",
    )

    output = capsys.readouterr().out
    assert comparison["comparison_status"]["complete"] is False
    assert "COMPARISON INCOMPLETE" in output
    assert "COMPARISON RESULTS" not in output
    assert "with-meta arm is not being presented as a successful meta result" in output
