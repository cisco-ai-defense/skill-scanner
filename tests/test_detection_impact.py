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

"""The pull-request detection-impact check: what it compares, what fails it, what it may publish."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evals.runners.detection_impact import (
    DetectionImpactError,
    Tolerance,
    compare,
    degraded,
    main,
    refuse_leaks,
    render_comment,
)

SUFFIX = ".skill-scanner.static.jsonl"
TOLERANCE = Tolerance(recall_drop=0.005, fpr_rise=0.005)


def _row(record_id: str, label: str | None, *findings: tuple[str, str], **extra: Any) -> dict[str, Any]:
    ranks = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
    top = max(findings, key=lambda f: ranks[f[1]], default=None)
    return {
        "record_id": record_id,
        "label": label,
        "max_severity": top[1] if top else "NONE",
        "findings": [{"rule_id": rule, "severity": severity} for rule, severity in findings],
        "error": extra.get("error"),
        "capability_ok": extra.get("capability_ok", True),
        "extra": {"analyzers_failed": extra.get("analyzers_failed", [])},
    }


def _write(directory: Path, corpus: str, rows: list[dict[str, Any]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{corpus}{SUFFIX}").write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def _dev_rows(detected: int, false_alarms: int, *, extra_rule: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for i in range(100):
        findings = [("RULE_A", "HIGH")] if i < detected else []
        if extra_rule and i >= 90:
            findings.append((extra_rule, "MEDIUM"))
        rows.append(_row(f"ASB04_{i:06d}", "malicious", *findings))
    for i in range(100):
        findings = [("RULE_A", "MEDIUM")] if i < false_alarms else []
        rows.append(_row(f"ASB05_{i:06d}", "benign", *findings))
    return rows


def _compare(tmp_path: Path, base_rows: list, head_rows: list, **kwargs: Any) -> dict[str, Any]:
    _write(tmp_path / "base", "msb-trainval", base_rows)
    _write(tmp_path / "head", "msb-trainval", head_rows)
    for corpus, rows in (kwargs.pop("extra_corpora", None) or {}).items():
        _write(tmp_path / "base", corpus, rows[0])
        _write(tmp_path / "head", corpus, rows[1])
    return compare(
        tmp_path / "base",
        tmp_path / "head",
        tolerance=kwargs.pop("tolerance", TOLERANCE),
        repo=kwargs.pop("repo", tmp_path),
        resamples=50,
    )


class TestCorpusRules:
    @pytest.mark.parametrize(
        ("corpus", "reason"),
        [
            ("msb-source-disjoint", "frozen test split"),
            ("harmfulskillbench-corpus", "flag rates only"),
            ("notinject", "benign denominator"),
            ("msb-balanced-800", "overlaps the frozen test split"),
        ],
    )
    def test_forbidden_corpora_are_refused_not_scored(self, tmp_path: Path, corpus: str, reason: str) -> None:
        rows = _dev_rows(50, 2)
        with pytest.raises(DetectionImpactError, match=reason):
            _compare(tmp_path, rows, rows, extra_corpora={corpus: (rows, rows)})

    def test_an_unregistered_corpus_is_refused(self, tmp_path: Path) -> None:
        rows = _dev_rows(50, 2)
        with pytest.raises(DetectionImpactError, match="not a corpus a pull request may score"):
            _compare(tmp_path, rows, rows, extra_corpora={"somewhere-else": (rows, rows)})

    def test_the_development_split_is_required(self, tmp_path: Path) -> None:
        rows = [_row("c_" + "0" * 20, None)]
        _write(tmp_path / "base", "clawhub-sample", rows)
        _write(tmp_path / "head", "clawhub-sample", rows)
        with pytest.raises(DetectionImpactError, match="development split is missing"):
            compare(tmp_path / "base", tmp_path / "head", tolerance=TOLERANCE, repo=tmp_path, resamples=10)

    def test_the_real_skill_sample_reports_a_flag_rate_and_no_class_metrics(self, tmp_path: Path) -> None:
        dev = _dev_rows(50, 2)
        real_base = [_row(f"c_{i:020x}", None, *([("RULE_A", "HIGH")] if i < 10 else [])) for i in range(100)]
        real_head = [_row(f"c_{i:020x}", None, *([("RULE_A", "HIGH")] if i < 5 else [])) for i in range(100)]
        report = _compare(tmp_path, dev, dev, extra_corpora={"clawhub-sample": (real_base, real_head)})
        block = report["corpora"]["clawhub-sample"]
        assert "metrics" not in block
        assert block["flag_rate"]["base"]["rate"] == 0.10 and block["flag_rate"]["head"]["rate"] == 0.05
        assert all("fires_head_malicious" not in rule for rule in block["rules"])

    def test_base_and_head_must_scan_the_same_records(self, tmp_path: Path) -> None:
        with pytest.raises(DetectionImpactError, match="different records"):
            _compare(tmp_path, _dev_rows(50, 2), _dev_rows(50, 2)[:-1])


class TestGates:
    def test_an_unchanged_tree_passes(self, tmp_path: Path) -> None:
        rows = _dev_rows(50, 2)
        report = _compare(tmp_path, rows, rows)
        assert report["passed"] and report["corpora"]["msb-trainval"]["rules"] == []

    def test_a_recall_drop_beyond_tolerance_fails(self, tmp_path: Path) -> None:
        report = _compare(tmp_path, _dev_rows(50, 2), _dev_rows(40, 2))
        assert not report["passed"]
        assert any("recall fell 10.00 points" in failure for failure in report["failures"])

    def test_an_fpr_rise_beyond_tolerance_fails(self, tmp_path: Path) -> None:
        report = _compare(tmp_path, _dev_rows(50, 2), _dev_rows(50, 6))
        assert any("FPR rose 4.00 points" in failure for failure in report["failures"])

    def test_a_change_within_tolerance_passes(self, tmp_path: Path) -> None:
        loose = Tolerance(recall_drop=0.2, fpr_rise=0.2)
        assert _compare(tmp_path, _dev_rows(50, 2), _dev_rows(45, 4), tolerance=loose)["passed"]

    def test_the_accept_label_waives_a_metric_trade_but_not_a_defect(self, tmp_path: Path) -> None:
        accept = Tolerance(recall_drop=0.005, fpr_rise=0.005, accept_metric_changes=True)
        report = _compare(tmp_path, _dev_rows(50, 2), _dev_rows(40, 0), tolerance=accept)
        assert report["passed"] and report["accepted"]
        head = _dev_rows(40, 0)
        head[0]["capability_ok"] = False
        report = _compare(tmp_path / "second", _dev_rows(50, 2), head, tolerance=accept)
        assert not report["passed"]
        assert any("capability-degraded" in failure for failure in report["failures"])

    def test_a_capability_degraded_row_fails_even_when_metrics_do_not_move(self, tmp_path: Path) -> None:
        # The FILE_MAGIC_MISMATCH contract bug looked exactly like this: rows still present, analyzer failed.
        head = _dev_rows(50, 2)
        head[150]["capability_ok"] = False
        report = _compare(tmp_path, _dev_rows(50, 2), head)
        assert any("1 capability-degraded rows" in failure for failure in report["failures"])

    def test_a_lenient_loader_fallback_is_not_degradation(self) -> None:
        row = _row("x", "benign", analyzers_failed=[{"analyzer": "skill_loader", "error": "SkillLoadError:X"}])
        assert not degraded(row)
        assert degraded(_row("y", "benign", analyzers_failed=[{"analyzer": "static", "error": "boom"}]))

    def test_a_new_scan_error_fails(self, tmp_path: Path) -> None:
        head = _dev_rows(50, 2)
        head[199]["error"] = "SkillLoadError: unreadable"
        report = _compare(tmp_path, _dev_rows(50, 2), head)
        assert any("scan errors rose from 0 to 1" in failure for failure in report["failures"])


class TestRuleAccounting:
    def test_a_new_rule_reports_fires_sole_lifts_and_class_split(self, tmp_path: Path) -> None:
        base = _dev_rows(50, 0)
        head = _dev_rows(50, 0, extra_rule="RULE_NEW")
        report = _compare(tmp_path, base, head, tolerance=Tolerance(recall_drop=1, fpr_rise=1))
        rule = next(r for r in report["corpora"]["msb-trainval"]["rules"] if r["rule_id"] == "RULE_NEW")
        assert rule["new_rule"] and rule["fires_base"] == 0 and rule["fires_head"] == 10
        # Records 90-99 were undetected; the new rule alone lifts every one of them to MEDIUM+.
        assert rule["sole_driver_head"] == 10 and rule["lifted_head"] == 10
        assert rule["fires_head_malicious"] == 10 and rule["fires_head_benign"] == 0
        assert report["corpora"]["msb-trainval"]["tiers"]["up"] == 10

    def test_tier_moves_count_both_directions(self, tmp_path: Path) -> None:
        base = _dev_rows(50, 2)
        head = _dev_rows(48, 2)
        tiers = _compare(tmp_path, base, head, tolerance=Tolerance(recall_drop=1, fpr_rise=1))["corpora"][
            "msb-trainval"
        ]["tiers"]
        assert tiers == {"up": 0, "down": 2, "transitions": {"HIGH->NONE": 2}}


class TestEvidence:
    def _fixture(self, repo: Path, malicious: int, benign: int) -> None:
        fixtures = repo / "tests" / "fixtures"
        fixtures.mkdir(parents=True)
        (fixtures / "rule_a_msb_non_test_2026-09-02.json").write_text(
            json.dumps(
                {
                    "rule": {"id": "RULE_A", "implementation_sha256": "ab" * 32},
                    "dataset": {"selection": "source_disjoint and m_structural_disjoint train/validation only"},
                    "package_results": {"rule_hits_malicious": malicious, "rule_hits_benign": benign},
                }
            )
        )

    def test_hits_matching_the_bound_evidence_pass(self, tmp_path: Path) -> None:
        self._fixture(tmp_path / "repo", malicious=50, benign=2)
        report = _compare(tmp_path, _dev_rows(50, 2), _dev_rows(50, 2), repo=tmp_path / "repo")
        assert report["passed"] and report["evidence_checks"][0]["matches"]

    def test_hits_that_drift_from_the_bound_evidence_fail(self, tmp_path: Path) -> None:
        self._fixture(tmp_path / "repo", malicious=50, benign=2)
        loose = Tolerance(recall_drop=1, fpr_rise=1)
        report = _compare(tmp_path, _dev_rows(50, 2), _dev_rows(49, 2), repo=tmp_path / "repo", tolerance=loose)
        assert any("re-verify and rebind" in failure for failure in report["failures"])


class TestPublishedComment:
    def test_the_comment_carries_aggregates_and_no_record_identifier(self, tmp_path: Path) -> None:
        report = _compare(tmp_path, _dev_rows(50, 2), _dev_rows(40, 2))
        comment = render_comment(report, base_sha="a" * 40, head_sha="b" * 40)
        assert "Recall" in comment and "RULE_A" in comment
        assert "ASB04_" not in comment and "ASB05_" not in comment
        refuse_leaks(comment)

    @pytest.mark.parametrize(
        "text",
        ["record ASB04_000123 regressed", "see /home/runner/work/x", "token ghp_" + "a" * 30, '{"snippet": "x"}'],
    )
    def test_leaks_are_refused(self, text: str) -> None:
        with pytest.raises(DetectionImpactError, match="refusing to publish"):
            refuse_leaks(text)

    def test_the_cli_writes_both_outputs_and_exits_on_the_gate(self, tmp_path: Path) -> None:
        _write(tmp_path / "base", "msb-trainval", _dev_rows(50, 2))
        _write(tmp_path / "head", "msb-trainval", _dev_rows(40, 2))
        arguments = [
            "--base-rows", str(tmp_path / "base"), "--head-rows", str(tmp_path / "head"),
            "--report", str(tmp_path / "report.json"), "--comment", str(tmp_path / "comment.md"),
            "--base-sha", "a" * 40, "--head-sha", "b" * 40, "--repo", str(tmp_path), "--resamples", "20",
        ]  # fmt: skip
        assert main(arguments) == 1
        assert json.loads((tmp_path / "report.json").read_text())["passed"] is False
        assert (tmp_path / "comment.md").read_text().startswith("<!-- detection-impact -->")
        assert main([*arguments, "--accept-metric-changes"]) == 0
