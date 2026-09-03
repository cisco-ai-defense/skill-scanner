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

import copy
import hashlib
import json
from pathlib import Path

import pytest

from evals.runners.independent_ollama_labeler import (
    EVALUATION_TRACK,
    IndependentLabelingError,
    OllamaProvider,
    run_independent_labeling,
)

_MODEL_DIGEST = "a" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _manifest() -> dict:
    rubric = "Label package behavior as benign, malicious, contextual_risk, or abstain."
    prompt = "Rubric:\n{rubric}\nCase {case_id}:\n{content}"
    cases = [
        ("agree", "This package only formats local text."),
        ("disagree", "This package sends environment values to a remote host."),
        ("abstain", "The behavior cannot be determined from the supplied text."),
    ]
    return {
        "schema_version": 1,
        "corpus_id": "committed-unlabeled-near-misses-v1",
        "evaluation_track": EVALUATION_TRACK,
        "contains_authoritative_labels": False,
        "model": {"name": "qwen-test:fixed", "digest": _MODEL_DIGEST},
        "rubric": {"text": rubric, "sha256": _sha(rubric)},
        "prompt": {"text": prompt, "sha256": _sha(prompt)},
        "passes": [{"pass_id": "pass-a", "seed": 101}, {"pass_id": "pass-b", "seed": 202}],
        "cases": [
            {
                "case_id": case_id,
                "content": content,
                "content_sha256": _sha(content),
                "label_status": "unlabeled",
                "sealed_labeled_test": False,
            }
            for case_id, content in cases
        ],
    }


def _write_manifest(tmp_path: Path, manifest: dict) -> Path:
    path = tmp_path / "labeling-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class _Provider:
    def __init__(self, *, digest: str = _MODEL_DIGEST, fail: bool = False):
        self.digest = digest
        self.fail = fail
        self.calls: list[tuple[str, int]] = []

    def model_digest(self, model: str) -> str:
        assert model == "qwen-test:fixed"
        return self.digest

    def label(self, *, model: str, rendered_prompt: str, rubric: str, seed: int) -> dict:
        del model, rubric
        self.calls.append((rendered_prompt, seed))
        if self.fail:
            raise RuntimeError("provider unavailable")
        if "Case agree:" in rendered_prompt:
            label = "benign"
        elif "Case disagree:" in rendered_prompt:
            label = "malicious" if seed == 101 else "contextual_risk"
        else:
            label = "abstain"
        return {"label": label, "rationale_codes": ["bounded_evidence"]}


def test_two_pass_agreement_accepts_and_disagreement_or_abstention_does_not(tmp_path: Path) -> None:
    provider = _Provider()
    report = run_independent_labeling(_write_manifest(tmp_path, _manifest()), provider=provider)

    assert report["status"] == "passed"
    assert report["evaluation_track"] == EVALUATION_TRACK
    assert report["authoritative_hf_metrics_eligible"] is False
    assert report["scanner_outputs_used_as_labels"] is False
    assert report["counts"] == {
        "cases": 3,
        "accepted": 1,
        "abstained": 2,
        "disagreements": 1,
        "provider_errors": 0,
    }
    assert [case["accepted_label"] for case in report["cases"]] == ["benign", "abstain", "abstain"]
    assert len(provider.calls) == 6
    assert {seed for _, seed in provider.calls} == {101, 202}


def test_frozen_model_rubric_prompt_and_content_hashes_are_enforced(tmp_path: Path) -> None:
    for mutate, message in (
        (lambda value: value["model"].update(digest="x" * 64), "model.digest"),
        (lambda value: value["rubric"].update(text="changed"), "rubric.sha256"),
        (lambda value: value["prompt"].update(text="{rubric}\n{content}\nchanged"), "prompt.sha256"),
        (lambda value: value["cases"][0].update(content="changed"), "content_sha256"),
    ):
        manifest = _manifest()
        mutate(manifest)
        with pytest.raises(IndependentLabelingError, match=message):
            run_independent_labeling(_write_manifest(tmp_path, manifest), provider=_Provider())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(contains_authoritative_labels=True),
        lambda value: value["cases"][0].update(label_status="malicious"),
        lambda value: value["cases"][0].update(sealed_labeled_test=True),
        lambda value: value["cases"][0].update(scanner_output={"severity": "HIGH"}),
    ],
)
def test_authoritative_sealed_or_scanner_derived_inputs_are_rejected(tmp_path: Path, mutation) -> None:
    manifest = _manifest()
    mutation(manifest)

    with pytest.raises(IndependentLabelingError):
        run_independent_labeling(_write_manifest(tmp_path, manifest), provider=_Provider())


def test_installed_model_digest_must_match_frozen_manifest(tmp_path: Path) -> None:
    with pytest.raises(IndependentLabelingError, match="installed Ollama model digest"):
        run_independent_labeling(
            _write_manifest(tmp_path, _manifest()),
            provider=_Provider(digest="b" * 64),
        )


def test_provider_errors_fail_report_and_abstain_without_losing_cases(tmp_path: Path) -> None:
    report = run_independent_labeling(
        _write_manifest(tmp_path, _manifest()),
        provider=_Provider(fail=True),
    )

    assert report["status"] == "failed"
    assert report["counts"]["cases"] == 3
    assert report["counts"]["provider_errors"] == 6
    assert report["counts"]["accepted"] == 0
    assert all(case["accepted_label"] == "abstain" for case in report["cases"])


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434",
        "http://localhost:11434",
        "http://10.0.0.2:11434",
        "http://token@127.0.0.1:11434",
        "http://127.0.0.1:11434/api",
    ],
)
def test_ollama_provider_accepts_only_literal_loopback_http(endpoint: str) -> None:
    with pytest.raises(IndependentLabelingError, match="loopback literal"):
        OllamaProvider(endpoint)


def test_manifest_is_not_mutated_by_validation(tmp_path: Path) -> None:
    manifest = _manifest()
    original = copy.deepcopy(manifest)
    run_independent_labeling(_write_manifest(tmp_path, manifest), provider=_Provider())
    assert manifest == original


def test_duplicate_manifest_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "labeling-manifest.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")

    with pytest.raises(IndependentLabelingError, match="duplicate JSON key"):
        run_independent_labeling(path, provider=_Provider())
