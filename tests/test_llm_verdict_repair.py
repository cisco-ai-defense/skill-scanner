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

"""Tests for the opt-in package-verdict repair.

A model that returns ``SAFE`` while listing findings has contradicted itself.
The strict default rejects the whole response, which is safe but not
label-neutral: measured on Gemma 4 the contradiction hit 22.5% of benign
packages and 0% of malicious ones, so the discard suppresses the analyzer
precisely where it would produce false positives.  The repair exists so an
evaluation can opt into escalating the summary verdict instead, and it must
never escalate in the other direction.
"""

from __future__ import annotations

import pytest

from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer


@pytest.fixture
def analyzer() -> LLMAnalyzer:
    return LLMAnalyzer.__new__(LLMAnalyzer)


def _prepared(analyzer: LLMAnalyzer) -> LLMAnalyzer:
    analyzer.verdict_repairs = 0
    return analyzer


def _finding(severity: str = "LOW") -> dict:
    return {"severity": severity, "verdict": "CONTEXTUAL_RISK", "title": "note"}


class TestRepairIsOffByDefault:
    def test_default_leaves_the_contradiction_in_place(
        self, analyzer: LLMAnalyzer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT", raising=False)
        payload = {"verdict": "SAFE", "findings": [_finding()]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SAFE"
        assert analyzer.verdict_repairs == 0

    def test_strict_validation_still_rejects_it(self, analyzer: LLMAnalyzer) -> None:
        payload = {
            "verdict": "SAFE",
            "findings": [_finding()],
            "overall_assessment": "fine",
            "primary_threats": [],
        }
        with pytest.raises(ValueError, match="SAFE package verdict requires an empty findings array"):
            analyzer._validate_primary_contract(payload)

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
    def test_unrecognised_flag_values_do_not_enable_it(
        self, analyzer: LLMAnalyzer, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT", value)
        payload = {"verdict": "SAFE", "findings": [_finding()]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SAFE"


class TestRepairWhenEnabled:
    @pytest.fixture(autouse=True)
    def _enable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT", "1")

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_recognised_flag_values_enable_it(
        self, analyzer: LLMAnalyzer, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT", value)
        payload = {"verdict": "SAFE", "findings": [_finding()]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SUSPICIOUS"

    def test_escalates_and_counts(self, analyzer: LLMAnalyzer) -> None:
        payload = {"verdict": "SAFE", "findings": [_finding(), _finding("MEDIUM")]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SUSPICIOUS"
        assert analyzer.verdict_repairs == 1

    def test_repaired_payload_now_passes_validation(self, analyzer: LLMAnalyzer) -> None:
        payload = {
            "verdict": "SAFE",
            "findings": [
                {
                    "severity": "LOW",
                    "verdict": "CONTEXTUAL_RISK",
                    "category": "other",
                    "confidence": 50,
                    "evidence_ids": ["e1"],
                    "aitech": "AITECH-0001",
                    "aisubtech": "",
                    "title": "note",
                    "description": "d",
                    "location": "SKILL.md:1",
                    "evidence": "x",
                    "remediation": "y",
                }
            ],
            "overall_assessment": "fine",
            "primary_threats": [],
        }
        _prepared(analyzer)._repair_primary_verdict(payload)
        # The repair's purpose is to make an otherwise-discarded analysis usable.
        assert payload["verdict"] == "SUSPICIOUS"

    def test_findings_are_never_modified(self, analyzer: LLMAnalyzer) -> None:
        findings = [_finding("HIGH")]
        payload = {"verdict": "SAFE", "findings": findings}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["findings"] is findings
        assert payload["findings"] == [{"severity": "HIGH", "verdict": "CONTEXTUAL_RISK", "title": "note"}]


class TestRepairIsEscalateOnly:
    @pytest.fixture(autouse=True)
    def _enable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT", "1")

    def test_safe_with_no_findings_is_consistent_and_untouched(self, analyzer: LLMAnalyzer) -> None:
        payload = {"verdict": "SAFE", "findings": []}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SAFE"
        assert analyzer.verdict_repairs == 0

    @pytest.mark.parametrize("verdict", ["SUSPICIOUS", "MALICIOUS"])
    def test_a_risk_verdict_is_never_downgraded(self, analyzer: LLMAnalyzer, verdict: str) -> None:
        payload = {"verdict": verdict, "findings": [_finding()]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == verdict
        assert analyzer.verdict_repairs == 0

    def test_malicious_is_never_reduced_to_suspicious(self, analyzer: LLMAnalyzer) -> None:
        payload = {"verdict": "MALICIOUS", "findings": [_finding("CRITICAL")]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "MALICIOUS"

    def test_malformed_findings_are_left_to_the_validator(self, analyzer: LLMAnalyzer) -> None:
        payload = {"verdict": "SAFE", "findings": "not-a-list"}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SAFE"
        assert analyzer.verdict_repairs == 0

    def test_missing_findings_key_is_not_a_crash(self, analyzer: LLMAnalyzer) -> None:
        payload: dict = {"verdict": "SAFE"}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SAFE"

    def test_repeated_repairs_accumulate(self, analyzer: LLMAnalyzer) -> None:
        _prepared(analyzer)
        for _ in range(3):
            analyzer._repair_primary_verdict({"verdict": "SAFE", "findings": [_finding()]})
        assert analyzer.verdict_repairs == 3
