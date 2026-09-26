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
    analyzer.taxonomy_repairs = 0
    return analyzer


def _finding(severity: str = "LOW") -> dict:
    return {"severity": severity, "verdict": "CONTEXTUAL_RISK", "title": "note"}


class TestRepairIsOnByDefault:
    def test_default_repairs_the_contradiction(self, analyzer: LLMAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT", raising=False)
        payload = {"verdict": "SAFE", "findings": [_finding()]}
        _prepared(analyzer)._repair_primary_verdict(payload)
        assert payload["verdict"] == "SUSPICIOUS"
        assert analyzer.verdict_repairs == 1

    def test_strict_validation_still_rejects_it(self, analyzer: LLMAnalyzer) -> None:
        payload = {
            "verdict": "SAFE",
            "findings": [_finding()],
            "overall_assessment": "fine",
            "primary_threats": [],
        }
        with pytest.raises(ValueError, match="SAFE package verdict requires an empty findings array"):
            analyzer._validate_primary_contract(payload)

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "OFF"])
    def test_explicit_off_values_restore_the_strict_path(
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

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", "", "maybe"])
    def test_any_other_value_keeps_it_on(
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
        """The repair must make the payload *usable*, not merely change a string.

        Asserting only that the verdict flipped would pass even if every other field
        were still contract-invalid, so the payload is built valid in every other
        respect and run through the real validator afterwards. The only defect is the
        ``SAFE`` verdict alongside a finding, which is exactly what the repair exists
        to correct.
        """
        payload = {
            "verdict": "SAFE",
            "findings": [
                {
                    "severity": "LOW",
                    "verdict": "CONTEXTUAL_RISK",
                    "category": "data_exfiltration",
                    "confidence": "LOW",
                    "evidence_ids": ["e1"],
                    "aitech": "AITech-1.1",
                    "aisubtech": None,
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
        prepared = _prepared(analyzer)
        # The validator rejects a cited evidence ID it never packed, so the ID this
        # payload cites has to be one the request actually included.
        prepared._allowed_evidence_ids = {"e1"}

        with pytest.raises(ValueError, match="SAFE package verdict requires an empty findings array"):
            prepared._validate_primary_contract(payload)

        prepared._repair_primary_verdict(payload)

        assert payload["verdict"] == "SUSPICIOUS"
        # The repair's purpose is to make an otherwise-discarded analysis usable, so the
        # validator must now accept it.
        prepared._validate_primary_contract(payload)

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


class TestOptionalTaxonomyRepair:
    """An invented optional AISubtech code must not void an otherwise valid analysis."""

    @staticmethod
    def _payload(aisubtech: object) -> dict:
        return {
            "verdict": "SUSPICIOUS",
            "findings": [
                {
                    "severity": "MEDIUM",
                    "verdict": "CONTEXTUAL_RISK",
                    "category": "data_exfiltration",
                    "confidence": "LOW",
                    "evidence_ids": ["e1"],
                    "aitech": "AITech-1.1",
                    "aisubtech": aisubtech,
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

    def test_an_invented_code_is_cleared_and_the_response_validates(self, analyzer: LLMAnalyzer) -> None:
        prepared = _prepared(analyzer)
        prepared._allowed_evidence_ids = {"e1"}
        payload = self._payload("AISubtech-99.99.99")
        with pytest.raises(ValueError, match="AISubtech"):
            prepared._validate_primary_contract(self._payload("AISubtech-99.99.99"))
        prepared._repair_optional_taxonomy(payload)
        assert payload["findings"][0]["aisubtech"] is None
        assert prepared.taxonomy_repairs == 1
        prepared._validate_primary_contract(payload)

    def test_a_valid_code_is_left_alone(self, analyzer: LLMAnalyzer) -> None:
        prepared = _prepared(analyzer)
        payload = self._payload("AISubtech-1.1.1")
        prepared._repair_optional_taxonomy(payload)
        assert payload["findings"][0]["aisubtech"] == "AISubtech-1.1.1"
        assert prepared.taxonomy_repairs == 0

    def test_the_required_aitech_code_is_still_strict(self, analyzer: LLMAnalyzer) -> None:
        # The repair is scoped to the optional field; an invalid required code must still
        # fail the response rather than be silently rewritten.
        prepared = _prepared(analyzer)
        prepared._allowed_evidence_ids = {"e1"}
        payload = self._payload(None)
        payload["findings"][0]["aitech"] = "AITech-99.9"
        prepared._repair_optional_taxonomy(payload)
        with pytest.raises(ValueError, match="AITech"):
            prepared._validate_primary_contract(payload)
