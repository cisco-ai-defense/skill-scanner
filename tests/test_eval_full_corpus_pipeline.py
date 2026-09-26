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

"""The rules the full-corpus pipeline applies before any figure is computed.

Each is a way a published number could silently move: a retried judge row, a budget notice read
as a failure, an unlabelled record counted as a negative, an overlay that misses a change, or a
record identifier reaching the published report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.experiments.f1_full_corpus_store import check_static, latest_jev, merge_judge, verdict_cells
from evals.experiments.f2_full_corpus_analysis import literal, run_id, verdict_summary
from evals.experiments.f3_overlay_check import compare, flagged, overlay
from evals.experiments.f4_labelled_ab import compare as ab_compare
from evals.experiments.f4_labelled_ab import recall_cost
from evals.experiments.f5_policy_pack_path import greedy_path
from evals.publish.large_scale_report import refuse_leaks, scrub_failure_kinds


def _jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


def _finding(rule: str, severity: str = "HIGH") -> dict:
    return {"rule_id": rule, "severity": severity}


class TestStoreRules:
    def test_a_genuine_judge_answer_beats_a_later_failure(self, tmp_path: Path) -> None:
        first = _jsonl(tmp_path / "a.jsonl", [{"record_id": "r", "capability_ok": True, "verdict": "SAFE"}])
        retry = _jsonl(tmp_path / "b.jsonl", [{"record_id": "r", "capability_ok": False, "error": "timeout"}])
        judged, _ = merge_judge([first, retry])
        assert judged["r"]["capability_ok"] is True

    def test_a_later_answer_replaces_an_earlier_failure(self, tmp_path: Path) -> None:
        first = _jsonl(tmp_path / "a.jsonl", [{"record_id": "r", "capability_ok": False, "error": "timeout"}])
        retry = _jsonl(tmp_path / "b.jsonl", [{"record_id": "r", "capability_ok": True, "verdict": "SUSPICIOUS"}])
        judged, _ = merge_judge([first, retry])
        assert judged["r"]["verdict"] == "SUSPICIOUS"

    def test_a_budget_only_row_with_a_verdict_is_partial_coverage_not_failure(self, tmp_path: Path) -> None:
        rows = [
            {
                "record_id": "r",
                "capability_ok": False,
                "capability_detail": "LLM_CONTEXT_BUDGET_EXCEEDED",
                "verdict": "SAFE",
                "max_severity": "INFO",
            },
            # No verdict: nothing was answered, so it stays a failure.
            {"record_id": "s", "capability_ok": False, "capability_detail": "LLM_CONTEXT_BUDGET_EXCEEDED"},
        ]
        judged, reclassified = merge_judge([_jsonl(tmp_path / "j.jsonl", rows)])
        assert reclassified == 1
        assert judged["r"]["capability_ok"] is True and judged["r"]["complete"] is False
        assert not judged["s"]["capability_ok"]
        assert verdict_cells(judged) == {"SAFE|INFO": 1}

    def test_a_static_run_listing_a_record_twice_is_refused(self, tmp_path: Path) -> None:
        path = _jsonl(tmp_path / "s.jsonl", [{"record_id": "r", "findings": []}, {"record_id": "r", "findings": []}])
        with pytest.raises(SystemExit, match="twice"):
            check_static("static-x", [path])

    def test_an_answered_jev_row_beats_an_errored_retry(self, tmp_path: Path) -> None:
        rows = [{"record_id": "r", "errors": 0, "probes": {"prompt_injection": 0.2}}, {"record_id": "r", "errors": 1}]
        latest = latest_jev([_jsonl(tmp_path / "j.jsonl", rows)])
        assert latest["r"]["errors"] == 0


class TestAnalysisInputs:
    @pytest.mark.parametrize("value", ["static-head", "judge_full", "run.2"])
    def test_plain_run_ids_are_accepted(self, value: str) -> None:
        assert run_id(value) == value

    @pytest.mark.parametrize("value", ["x' OR '1'='1", "a b", "", "run;drop"])
    def test_anything_else_is_refused_before_it_reaches_sql(self, value: str) -> None:
        with pytest.raises(SystemExit):
            run_id(value)

    def test_a_path_literal_escapes_quotes(self) -> None:
        assert literal(Path("/data/o'brien")) == "'/data/o''brien'"

    def test_verdicts_that_disagree_with_their_findings_are_counted(self) -> None:
        summary = verdict_summary({"SAFE|NONE": 5, "SAFE|MEDIUM": 1, "SUSPICIOUS|LOW": 2, "MALICIOUS|HIGH": 2})
        assert summary["safe_with_medium_plus_finding"] == 1
        assert summary["unsafe_without_medium_plus_finding"] == 2
        assert summary["non_safe_rate"]["count"] == 4


class TestOverlayCheck:
    def test_the_latest_rescan_wins_and_a_cleared_record_leaves(self, tmp_path: Path) -> None:
        base = _jsonl(
            tmp_path / "base.jsonl",
            [
                {"record_id": "a", "findings": [_finding("R1")]},
                {"record_id": "b", "findings": [_finding("R2")]},
                {"record_id": "c", "findings": []},
            ],
        )
        first = _jsonl(tmp_path / "o1.jsonl", [{"record_id": "a", "findings": [_finding("R1", "LOW")]}])
        second = _jsonl(tmp_path / "o2.jsonl", [{"record_id": "a", "findings": [_finding("R3")]}])
        full = _jsonl(
            tmp_path / "full.jsonl",
            [
                {"record_id": "a", "findings": [_finding("R3")]},
                {"record_id": "b", "findings": [_finding("R2", "LOW")]},
                {"record_id": "c", "findings": [_finding("R4")]},
            ],
        )
        base_flags, n_base = flagged([base])
        composed = overlay(base_flags, [[first], [second]])
        exact, n_exact = flagged([full])
        report = compare(composed, exact, n_base, n_exact)
        assert composed == {"a": frozenset({"R3"}), "b": frozenset({"R2"})}
        # b: a change the overlay missed; c: a record the rescan sets should have included.
        assert report["only_composed"] == 1 and report["only_exact"] == 1
        assert report["only_composed_by_rules"] == [("R2", 1)]
        assert report["only_exact_by_rules"] == [("R4", 1)]


class TestLabelledComparison:
    def test_unlabelled_records_get_a_flag_rate_not_a_confusion_matrix(self) -> None:
        base = {"u": (None, [_finding("R")]), "m": ("malicious", [_finding("R")]), "b": ("benign", [])}
        final = {"u": (None, []), "m": ("malicious", [_finding("R")]), "b": ("benign", [])}
        block = ab_compare(base, final)
        assert block["medium_plus_base"] == {
            "positives": 1,
            "tp": 1,
            "negatives": 1,
            "fp": 0,
            "unlabelled": 1,
            "flagged_unlabelled": 1,
        }
        assert block["medium_plus_final"]["flagged_unlabelled"] == 0

    def test_only_records_both_runs_could_read_are_compared(self) -> None:
        base = {"a": ("benign", []), "b": ("benign", [])}
        final = {"a": ("benign", [])}
        assert ab_compare(base, final)["records"] == 1

    def test_the_recall_cost_names_what_carried_each_lost_detection(self) -> None:
        base = {
            "m1": ("malicious", [_finding("UNPINNED", "MEDIUM")]),
            "m2": ("malicious", [_finding("UNPINNED", "MEDIUM"), _finding("MENTION", "HIGH")]),
            "m3": ("malicious", [_finding("REAL", "HIGH")]),
            "b1": ("benign", [_finding("UNPINNED", "MEDIUM")]),
        }
        final = {
            "m1": ("malicious", [_finding("UNPINNED", "LOW")]),
            "m2": ("malicious", []),
            "m3": ("malicious", [_finding("REAL", "HIGH")]),
            "b1": ("benign", []),
        }
        cost = recall_cost(base, final)
        assert cost["records"] == 2
        assert dict(cost["carried_by"]) == {"UNPINNED": 1, "MENTION + UNPINNED": 1}


class TestPackPath:
    def test_the_path_demotes_judge_cleared_noise_before_detections(self) -> None:
        real = {f"n{i}": {"NOISY"} for i in range(60)} | {f"d{i}": {"DETECTOR"} for i in range(60)}
        judge = {f"n{i}": False for i in range(60)} | {f"d{i}": False for i in range(60)}
        positives = [{"DETECTOR"}] * 5
        negatives: list[set[str]] = [set()]
        path = greedy_path(
            real, judge, 1000, positives, negatives, steps=2, min_gain=50, recall_weight=25.0, agree_weight=0.5
        )
        # Both clear 60 judge-cleared skills, but demoting DETECTOR loses five detections.
        assert [step["demote"] for step in path[1:]] == ["NOISY", "DETECTOR"]
        assert path[1]["dev_tp_lost"] == 0 and path[2]["dev_tp_lost"] == 5

    def test_a_rule_below_the_minimum_gain_is_never_demoted(self) -> None:
        real = {f"n{i}": {"NOISY"} for i in range(10)}
        judge = dict.fromkeys(real, False)
        path = greedy_path(real, judge, 100, [], [set()], steps=3, min_gain=50, recall_weight=25.0, agree_weight=0.5)
        assert len(path) == 1


class TestPublishedReportGuard:
    @pytest.mark.parametrize(
        "text",
        [
            '{"store": "/home/ubuntu/full-corpus-run/store"}',
            '{"id": "g_00814001"}',
            '{"path": "b00814/g_0081"}',
            '{"token": "hf_abcdefghijklmnopqrstuvwxyz"}',
            '{"description": "the skill runs curl"}',
            '{"title": "Prompt injection"}',
        ],
    )
    def test_leaks_are_refused(self, text: str) -> None:
        with pytest.raises(SystemExit, match="refusing to publish"):
            refuse_leaks(text)

    def test_metrics_pass(self) -> None:
        refuse_leaks(json.dumps({"rule_id": "PIPELINE_TAINT_FLOW", "rate": 0.02, "prompt": "new", "cap": None}))

    def test_failure_kinds_lose_their_record_path(self) -> None:
        kinds = [["SkillLoadError: SKILL.md contains null bytes: /data/gitskills-full/b00814/g_00814001/SKILL.md", 3]]
        assert scrub_failure_kinds(kinds) == [["SkillLoadError: SKILL.md contains null bytes", 3]]
