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

"""Pure helpers behind published experiment figures: sampling, label classes, the OpenJev screen."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.experiments.c1_prompt_guard import label_class, score_at, spread
from evals.experiments.c4_openjev_screen import auc, fit_logistic, labelled, load_judge, select, unlabelled


class TestPromptGuardSampling:
    def test_a_limit_spans_the_whole_corpus(self) -> None:
        records = list(range(10))
        chosen = spread(records, 4)
        assert chosen == [0, 2, 5, 7]

    def test_a_limit_above_half_the_corpus_is_not_a_prefix(self) -> None:
        # len // limit == 1 here, where a stride degenerates to the first `limit` records.
        records = list(range(10))
        chosen = spread(records, 6)
        assert len(chosen) == len(set(chosen)) == 6
        assert max(chosen) >= 8

    @pytest.mark.parametrize("limit", [0, 10, 25])
    def test_no_limit_or_a_limit_past_the_end_keeps_everything(self, limit: int) -> None:
        assert spread(list(range(10)), limit) == list(range(10))


class TestPromptGuardLabels:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [("malicious", True), ("obviously_malicious", True), ("benign", False), (None, None), ("other", None)],
    )
    def test_label_classes(self, label: str | None, expected: bool | None) -> None:
        assert label_class(label) is expected

    def test_unlabelled_records_stay_out_of_the_confusion_matrix(self) -> None:
        rows = [
            {"probability": 0.9, "positive": None},
            {"probability": 0.9, "positive": True},
            {"probability": 0.1, "positive": False},
        ]
        metrics = score_at(rows, 0.5)
        assert metrics["has_negative_class"] is True
        assert metrics["false_positive_rate"] == 0.0

    def test_an_unlabelled_corpus_has_no_false_positive_rate(self) -> None:
        rows = [{"probability": 0.9, "positive": None}, {"probability": 0.1, "positive": None}]
        metrics = score_at(rows, 0.5)
        assert metrics["false_positive_rate"] is None


class TestOpenJevScreen:
    def test_auc_orders_ties_by_average_rank(self) -> None:
        assert auc([0.1, 0.2, 0.8, 0.9], [False, False, True, True]) == 1.0
        assert auc([0.5, 0.5], [False, True]) == 0.5
        assert auc([0.1, 0.2], [True, True]) is None

    def test_logistic_fit_separates_a_separable_toy_set(self) -> None:
        import numpy as np

        x = np.array([[-2.0], [-1.5], [-1.0], [1.0], [1.5], [2.0], [2.5]])
        y = np.array([False, False, False, True, True, True, True])
        coef, intercept = fit_logistic(x, y)
        scores = x @ coef + intercept
        assert coef[0] > 0
        assert all(scores[y] > 0) and all(scores[~y] < 0)

    def test_judge_caps_read_both_row_shapes(self, tmp_path: Path) -> None:
        path = tmp_path / "judge.jsonl"
        rows = [
            {"record_id": "a", "label": "benign", "findings": [{"severity": "HIGH", "llm_verdict": "CONTEXTUAL_RISK"}]},
            # The judge-only runner writes "confidence"; the Bedrock runner writes "llm_confidence".
            {"record_id": "b", "label": "benign", "findings": [{"severity": "MEDIUM", "confidence": "LOW"}]},
            {"record_id": "c", "label": "benign", "findings": [{"severity": "MEDIUM", "llm_confidence": "LOW"}]},
            {"record_id": "d", "label": "benign", "error": "timeout"},
            {"record_id": "e", "label": "benign", "capability_ok": False, "findings": []},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows))
        assert set(load_judge(path, None)) == {"a", "b", "c"}
        assert {k: v[1] for k, v in load_judge(path, None).items()} == {"a": True, "b": True, "c": True}
        assert load_judge(path, "contextual")["a"][1] is False
        assert load_judge(path, "low-confidence")["b"][1] is False
        assert load_judge(path, "low-confidence")["c"][1] is False

    def test_the_threshold_keeps_the_recall_floor_at_the_lowest_fpr(self) -> None:
        import numpy as np

        ids = ["m1", "m2", "m3", "b1", "b2", "b3"]
        judge = {i: ("malicious" if i.startswith("m") else "benign", True) for i in ids}
        scores = np.array([0.9, 0.8, 0.7, 0.6, 0.2, 0.1])
        alone = labelled(ids, np.zeros(len(ids)), judge, -1.0)
        assert alone["recall"] == 1.0 and alone["fpr"] == 1.0
        threshold, metrics = select(ids, scores, judge, keep_recall=0.97, alone_recall=alone["recall"])
        # Every malicious record still passes, and every benign one scores below the threshold.
        assert metrics["recall"] == 1.0
        assert metrics["fpr"] == 0.0
        assert 0.6 < threshold <= 0.7
        real = unlabelled(ids, scores, judge, threshold)
        assert real["judge_calls"] == pytest.approx(0.5)
        assert real["flag_rate"] == pytest.approx(0.5)
