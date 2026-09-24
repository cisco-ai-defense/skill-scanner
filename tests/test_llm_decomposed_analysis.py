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
import json
from types import SimpleNamespace
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


class TestUnionCorrectness:
    """Regressions for three defects in the first version of the union."""

    def test_distinct_findings_in_one_category_both_survive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)

        async def fake_single(skill: Any) -> list[Finding]:
            # rule_id is derived from the category, so these two share it. Keying the
            # union on rule_id alone dropped one of them.
            a = _finding("LLM_DATA_EXFILTRATION")
            a.file_path, a.line_number, a.title = "a.py", 1, "sends token to host A"
            b = _finding("LLM_DATA_EXFILTRATION")
            b.file_path, b.line_number, b.title = "b.py", 9, "sends token to host B"
            return [a, b]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(object()))
        assert len(findings) == 2, "two distinct findings in one category must both survive"

    def test_a_later_high_is_not_hidden_behind_an_earlier_low(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            finding = _finding("LLM_DATA_EXFILTRATION")
            finding.file_path, finding.line_number, finding.title = "a.py", 1, "same finding"
            # Same identity, escalating severity: the union must keep the worst, not the
            # first, or a later HIGH disappears behind an earlier LOW.
            finding.severity = Severity.LOW if calls["n"] == 1 else Severity.CRITICAL
            return [finding]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(object()))
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_unioned_findings_have_unique_ids(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        categories = [ThreatCategory.DATA_EXFILTRATION, ThreatCategory.OBFUSCATION, ThreatCategory.MALWARE]
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            # Every pass numbers its findings from zero, so without renumbering two
            # different findings would both be exported as ..._0.
            finding = _finding("R", categories[calls["n"] % len(categories)])
            finding.id = "llm_finding_s_0"
            finding.title = f"pass {calls['n']}"
            calls["n"] += 1
            return [finding]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids)), f"ids must be unique after the union, got {ids}"

    def test_package_verdict_keeps_the_strongest_across_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        sequence = ["MALICIOUS", "SAFE", "SAFE"]
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            analyzer.last_overall_verdict = sequence[calls["n"] % len(sequence)]
            analyzer.last_primary_threats = [f"threat-{calls['n']}"]
            calls["n"] += 1
            return [_finding("R")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(object()))
        # A trailing SAFE pass must not contradict a MALICIOUS finding the union kept.
        assert analyzer.last_overall_verdict == "MALICIOUS"
        assert len(analyzer.last_primary_threats) == len(sequence)

    def test_completed_pass_count_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("provider down")
            return []

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(object()))
        # A partially failed decomposition must be distinguishable from a complete one.
        assert analyzer.last_decomposed_passes == len(analyzer.prompt_builder.decomposed_focuses) - 1


class TestMantleRequestBody:
    """The mantle route builds its own body, so controls must be carried explicitly."""

    def test_reasoning_effort_reaches_the_mantle_body(self) -> None:
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        config = ProviderConfig(model="bedrock-mantle/google.gemma-4-26b-a4b")
        handler = LLMRequestHandler(provider_config=config, max_tokens=64, reasoning_effort="low")
        body = json.loads(handler._build_bedrock_mantle_body([{"role": "user", "content": "hi"}]))
        # Dropping it silently would make --llm-reasoning-effort a no-op on this route.
        assert body["reasoning_effort"] == "low"

    def test_disabled_reasoning_is_translated_not_dropped(self) -> None:
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        config = ProviderConfig(model="bedrock-mantle/google.gemma-4-26b-a4b")
        handler = LLMRequestHandler(provider_config=config, max_tokens=64, reasoning_effort="disabled")
        body = json.loads(handler._build_bedrock_mantle_body([{"role": "user", "content": "hi"}]))
        assert body["reasoning_effort"] == "none"

    def test_no_reasoning_field_when_unset(self) -> None:
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        config = ProviderConfig(model="bedrock-mantle/google.gemma-4-26b-a4b")
        handler = LLMRequestHandler(provider_config=config, max_tokens=64)
        body = json.loads(handler._build_bedrock_mantle_body([{"role": "user", "content": "hi"}]))
        assert "reasoning_effort" not in body


class TestMantleSigning:
    def test_configured_session_token_is_signed_with(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An explicit token must reach the signature, not the one botocore resolved.

        A caller may supply only the session token and leave the key pair to the
        environment. Signing with a stale token, or none, yields a signature AWS rejects.
        """
        from botocore.credentials import Credentials

        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
        config = ProviderConfig(
            model="bedrock-mantle/google.gemma-4-26b-a4b",
            aws_session_token="explicit-token",
        )
        handler = LLMRequestHandler(provider_config=config, max_tokens=64)

        signed_with: dict[str, Any] = {}

        class FakeSession:
            def set_config_variable(self, *args: Any) -> None:
                return None

            def get_credentials(self) -> Credentials:
                return Credentials("AKIA", "secret", "stale-or-absent")

        class FakeAuth:
            def __init__(self, credentials: Any, service: str, region: str) -> None:
                signed_with["token"] = credentials.token

            def add_auth(self, request: Any) -> None:
                request.headers["Authorization"] = "signed"

        monkeypatch.setattr("botocore.session.Session", FakeSession)
        monkeypatch.setattr("botocore.auth.SigV4Auth", FakeAuth)

        class Boom(Exception):
            pass

        def explode(*args: Any, **kwargs: Any) -> None:
            raise Boom

        monkeypatch.setattr("urllib.request.urlopen", explode)
        with pytest.raises(Boom):
            handler._post_bedrock_mantle(b"{}")

        assert signed_with["token"] == "explicit-token"
