# Copyright 2026 Cisco Systems, Inc.
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

"""Regression tests for output-budgeted meta-analysis batching."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results
from skill_scanner.core.models import Finding, Severity, Skill, ThreatCategory


def _findings(count: int) -> list[Finding]:
    return [
        Finding(
            id=f"finding-{index}",
            rule_id="TEST_RULE",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.HIGH,
            title=f"Finding {index}",
            description="Potentially unsafe behavior",
            analyzer="static",
        )
        for index in range(count)
    ]


def _skill() -> MagicMock:
    skill = MagicMock(spec=Skill)
    skill.name = "batch-test"
    skill.description = "Meta-analysis batching fixture"
    return skill


def _prompt_indices(user_prompt: str) -> list[int]:
    findings_section = user_prompt.split("### Findings from Analyzers", maxsplit=1)[1]
    payload = findings_section.split("```json\n", maxsplit=1)[1].split("\n```", maxsplit=1)[0]
    return [item["_index"] for item in json.loads(payload)]


def _classification(indices: list[int], *, alternate_false_positives: bool = False) -> str:
    validated = []
    false_positives = []
    for index in indices:
        if alternate_false_positives and index % 2:
            false_positives.append({"_index": index, "false_positive_reason": "Benign fixture"})
        else:
            validated.append(
                {
                    "_index": index,
                    "confidence": "HIGH",
                    "confidence_reason": "Test classification",
                    "exploitability": "Low",
                    "impact": "Low",
                }
            )
    return json.dumps(
        {
            "overall_risk_assessment": {
                "risk_level": "MEDIUM",
                "summary": "Test assessment",
                "skill_verdict": "SUSPICIOUS",
            },
            "validated_findings": validated,
            "false_positives": false_positives,
            "missed_threats": [],
            "priority_order": [item["_index"] for item in validated],
            "correlations": [],
            "recommendations": [],
        }
    )


def _response(content: str, *, finish_reason: str, input_tokens: int, output_tokens: int) -> MagicMock:
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content), finish_reason=finish_reason)]
    response.usage = MagicMock(
        prompt_tokens=input_tokens,
        completion_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )
    return response


@pytest.mark.asyncio
async def test_hundreds_of_findings_are_batched_with_global_indices() -> None:
    analyzer = MetaAnalyzer(model="test-model", api_key="test-key", max_tokens=8192)
    analyzer._build_skill_context = MagicMock(return_value=("bounded context", []))
    findings = _findings(257)
    batches: list[list[int]] = []

    async def classify(_system_prompt: str, user_prompt: str) -> str:
        indices = _prompt_indices(user_prompt)
        batches.append(indices)
        return _classification(indices, alternate_false_positives=True)

    analyzer._make_llm_request = AsyncMock(side_effect=classify)

    result = await analyzer.analyze_with_findings(_skill(), findings, ["static"])

    assert len(batches) > 1
    assert all(len(batch) <= analyzer._max_findings_per_batch() for batch in batches)
    assert [index for batch in batches for index in batch] == list(range(257))

    classified_indices = [item["_index"] for item in result.validated_findings + result.false_positives]
    assert len(classified_indices) == 257
    assert len(set(classified_indices)) == 257
    assert sorted(classified_indices) == list(range(257))
    assert result.analysis_warnings == []


@pytest.mark.asyncio
async def test_malformed_response_degrades_only_its_batch_without_resending() -> None:
    # 320 * .75 / 80 = three findings per batch.
    analyzer = MetaAnalyzer(model="test-model", api_key="test-key", max_tokens=320)
    analyzer._build_skill_context = MagicMock(return_value=("bounded context", []))
    findings = _findings(9)
    calls: list[list[int]] = []

    async def classify(_system_prompt: str, user_prompt: str) -> str:
        indices = _prompt_indices(user_prompt)
        calls.append(indices)
        if indices == [3, 4, 5]:
            return '{"validated_findings": ['
        return _classification(indices, alternate_false_positives=True)

    analyzer._make_llm_request = AsyncMock(side_effect=classify)

    result = await analyzer.analyze_with_findings(_skill(), findings, ["static"])

    assert calls == [[0, 1, 2], [3, 4, 5], [6, 7, 8]]
    classified_indices = [item["_index"] for item in result.validated_findings + result.false_positives]
    assert sorted(classified_indices) == list(range(9))
    assert len(classified_indices) == len(set(classified_indices))

    degraded = {item["_index"] for item in result.validated_findings if item.get("meta_analysis_degraded")}
    assert degraded == {3, 4, 5}
    assert [warning["code"] for warning in result.analysis_warnings] == ["META_BATCH_PARSE_FAILED"]
    assert result.overall_risk_assessment["risk_level"] == "UNKNOWN"
    assert result.overall_risk_assessment["skill_verdict"] == "UNKNOWN"
    assert result.overall_risk_assessment["partial_risk_level"] == "MEDIUM"
    assert result.overall_risk_assessment["partial_skill_verdict"] == "SUSPICIOUS"
    assert result.overall_risk_assessment["partial_summary"] == "Test assessment"
    assert "incomplete" in result.overall_risk_assessment["summary"].lower()
    assert result.overall_risk_assessment["meta_analysis_status"] == "degraded"
    assert result.overall_risk_assessment["meta_analysis_warnings"] == result.analysis_warnings
    applied = apply_meta_analysis_to_results(findings, result, _skill())
    assert all(applied[index].metadata["meta_analysis_degraded"] is True for index in (3, 4, 5))
    assert all(applied[index].metadata["meta_validated"] is False for index in (3, 4, 5))


@pytest.mark.asyncio
async def test_length_finish_reason_bisects_batch_and_aggregates_all_usage() -> None:
    # 640 * .75 / 80 = six findings: one initial batch, then two halves.
    analyzer = MetaAnalyzer(model="test-model", api_key="test-key", max_tokens=640)
    analyzer._build_skill_context = MagicMock(return_value=("bounded context", []))
    findings = _findings(6)
    calls: list[list[int]] = []

    async def complete(**kwargs):
        indices = _prompt_indices(kwargs["messages"][1]["content"])
        calls.append(indices)
        if len(calls) == 1:
            return _response("truncated", finish_reason="length", input_tokens=100, output_tokens=640)
        return _response(
            _classification(indices),
            finish_reason="stop",
            input_tokens=50,
            output_tokens=30,
        )

    with patch("skill_scanner.core.analyzers.meta_analyzer.acompletion", new=AsyncMock(side_effect=complete)):
        result = await analyzer.analyze_with_findings(_skill(), findings, ["static"])

    assert calls == [[0, 1, 2, 3, 4, 5], [0, 1, 2], [3, 4, 5]]
    assert [item["_index"] for item in result.validated_findings] == list(range(6))
    assert result.analysis_warnings == []
    assert analyzer.llm_usage == {
        "input_tokens": 200,
        "output_tokens": 700,
        "total_tokens": 900,
    }


@pytest.mark.asyncio
async def test_incomplete_batch_is_filled_once_without_duplicate_indices() -> None:
    analyzer = MetaAnalyzer(model="test-model", api_key="test-key", max_tokens=320)
    analyzer._build_skill_context = MagicMock(return_value=("bounded context", []))
    findings = _findings(3)

    # Index 0 is duplicated, index 1 is absent, and index 99 is outside the batch.
    response = json.dumps(
        {
            "validated_findings": [{"_index": 0}, {"_index": 0}, {"_index": 99}],
            "false_positives": [{"_index": 0}, {"_index": 2}],
            "priority_order": [0, 0, 99],
        }
    )
    analyzer._make_llm_request = AsyncMock(return_value=response)

    result = await analyzer.analyze_with_findings(_skill(), findings, ["static"])

    classified_indices = [item["_index"] for item in result.validated_findings + result.false_positives]
    assert sorted(classified_indices) == [0, 1, 2]
    assert len(classified_indices) == len(set(classified_indices))
    assert next(item for item in result.validated_findings if item["_index"] == 1)["meta_analysis_degraded"] is True
    assert result.analysis_warnings[0]["code"] == "META_BATCH_INCOMPLETE"
    assert analyzer._make_llm_request.await_count == 1
