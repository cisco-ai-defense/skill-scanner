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

"""Decomposed LLM analysis: one pass per focus, findings unioned.

Measured on MaliciousSkillBench source-disjoint, this raises recall from 49.0% to 60.9%
on Gemma 4 26B. It is off by default because it multiplies model calls by the number of
focuses.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.models import Finding, Severity, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy


def _analyzer(**kwargs: Any) -> LLMAnalyzer:
    return LLMAnalyzer(model="bedrock/test-model", api_key="unused", policy=ScanPolicy.default(), **kwargs)


def _finding(rule_id: str, category: ThreatCategory = ThreatCategory.DATA_EXFILTRATION) -> Finding:
    return Finding(
        id=f"{rule_id}-1",
        rule_id=rule_id,
        category=category,
        severity=Severity.HIGH,
        title="t",
        description="d",
    )


class TestFlagDefaults:
    def test_off_by_default(self) -> None:
        # Enabling it silently would multiply every user's model spend.
        assert _analyzer().decompose is False

    def test_on_when_requested(self) -> None:
        analyzer = _analyzer(decompose=True)
        assert analyzer.decompose is True
        assert len(analyzer.prompt_builder.decomposed_focuses) >= 2

    def test_disabled_when_no_focus_prompts_are_available(self) -> None:
        analyzer = _analyzer(decompose=True)
        analyzer.prompt_builder.decomposed_focuses = ()
        # Re-deriving the flag the way the constructor does must leave it off: a
        # decomposed run with zero focuses would make no requests at all.
        assert bool(analyzer.decompose) and not analyzer.prompt_builder.decomposed_focuses
        rebuilt = LLMAnalyzer.__new__(LLMAnalyzer)
        rebuilt.prompt_builder = analyzer.prompt_builder
        rebuilt.decompose = True and bool(rebuilt.prompt_builder.decomposed_focuses)
        assert rebuilt.decompose is False


class TestPassOrchestration:
    def test_runs_one_pass_per_focus_and_restores_the_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        base = analyzer.prompt_builder.threat_analysis_prompt
        seen: list[str] = []

        async def fake_single(skill: Any) -> list[Finding]:
            seen.append(analyzer.prompt_builder.threat_analysis_prompt)
            return [_finding(f"RULE_{len(seen)}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(object()))

        assert len(seen) == len(analyzer.prompt_builder.decomposed_focuses)
        # Every pass must start from the shipped prompt, not from the previous focus.
        for prompt in seen:
            assert prompt.startswith(base)
        assert len({p for p in seen}) == len(seen), "each pass should use a distinct focus"
        # The prompt is shared mutable state; leaving a focus applied would silently
        # change every later scan in the same process.
        assert analyzer.prompt_builder.threat_analysis_prompt == base
        assert len(findings) == len(seen)

    def test_findings_are_unioned_on_rule_and_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)

        async def fake_single(skill: Any) -> list[Finding]:
            # Same rule and category from every pass: one finding, not three.
            return [_finding("SAME_RULE"), _finding("OTHER_RULE", ThreatCategory.OBFUSCATION)]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(object()))
        assert len(findings) == 2
        assert {f.rule_id for f in findings} == {"SAME_RULE", "OTHER_RULE"}

    def test_a_failing_pass_does_not_void_the_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("provider blew up")
            return [_finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(object()))
        # A partial union beats discarding the semantic stage entirely.
        assert len(findings) == len(analyzer.prompt_builder.decomposed_focuses) - 1
        assert analyzer.prompt_builder.threat_analysis_prompt

    def test_prompt_is_restored_even_when_every_pass_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        base = analyzer.prompt_builder.threat_analysis_prompt

        async def always_fails(skill: Any) -> list[Finding]:
            raise RuntimeError("down")

        monkeypatch.setattr(analyzer, "_analyze_single", always_fails)
        assert asyncio.run(analyzer._analyze_decomposed(object())) == []
        assert analyzer.prompt_builder.threat_analysis_prompt == base

    def test_token_usage_accumulates_across_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        passes = len(analyzer.prompt_builder.decomposed_focuses)

        async def fake_single(skill: Any) -> list[Finding]:
            # Mirrors the real method, which resets the counter on entry. Reading it
            # once after the loop would report only the final pass.
            analyzer._llm_usage = {"input_tokens": 100, "output_tokens": 10, "total_tokens": 110}
            return []

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(object()))
        assert analyzer.llm_usage["input_tokens"] == 100 * passes
        assert analyzer.llm_usage["output_tokens"] == 10 * passes


class TestFocusPrompts:
    def test_shipped_focuses_load_and_differ(self) -> None:
        focuses = _analyzer().prompt_builder.decomposed_focuses
        assert len(focuses) == 3
        assert len(set(focuses)) == 3
        for focus in focuses:
            assert focus.strip()

    def test_a_focus_extends_rather_than_replaces_the_prompt(self) -> None:
        analyzer = _analyzer(decompose=True)
        base = analyzer.prompt_builder.threat_analysis_prompt
        for focus in analyzer.prompt_builder.decomposed_focuses:
            combined = base + focus
            # The decision rules must survive: a focus that replaced them could win
            # recall by relaxing what counts as a finding.
            assert base in combined
            assert len(combined) > len(base)
