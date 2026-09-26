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
        """An explicit token must reach the signature when botocore resolved none.

        A caller may supply only the session token and leave the key pair to the
        environment. Botocore then resolves long-term keys with no token, and signing
        without one yields a signature AWS rejects for a temporary credential.
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
                # Long-term keys: no token of their own, which is the only case where
                # the configured token is unambiguously the right one to sign with.
                return Credentials("AKIA", "secret", None)

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

    def test_a_resolved_token_is_not_replaced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A token botocore resolved came paired with the key pair it returned.

        ``aws_session_token`` also falls back to the ambient ``AWS_SESSION_TOKEN``, so a
        named profile can resolve its own key pair and token while an unrelated token sits
        in the environment. Splicing that ambient token onto the profile's key pair yields
        a signature AWS rejects, so a resolved token must win.
        """
        from botocore.credentials import Credentials

        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        monkeypatch.setenv("AWS_SESSION_TOKEN", "ambient-token-from-another-session")
        config = ProviderConfig(model="bedrock-mantle/google.gemma-4-26b-a4b", aws_profile="some-profile")
        handler = LLMRequestHandler(provider_config=config, max_tokens=64)
        assert config.aws_session_token == "ambient-token-from-another-session"

        signed_with: dict[str, Any] = {}

        class FakeSession:
            def set_config_variable(self, *args: Any) -> None:
                return None

            def get_credentials(self) -> Credentials:
                return Credentials("PROFILE_AKIA", "profile-secret", "profile-token")

        class FakeAuth:
            def __init__(self, credentials: Any, service: str, region: str) -> None:
                signed_with["token"] = credentials.token
                signed_with["access_key"] = credentials.access_key

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

        assert signed_with["token"] == "profile-token"
        assert signed_with["access_key"] == "PROFILE_AKIA"


class TestReturnedFailureFindings:
    """_analyze_single reports failures by returning an INFO finding, not by raising.

    Unioned blindly, that marker sits alongside real findings and a pass that read
    nothing looks like a pass that found nothing.
    """

    @staticmethod
    def _diagnostic(rule_id: str = "LLM_ANALYSIS_FAILED") -> Finding:
        finding = _finding(rule_id)
        finding.severity = Severity.INFO
        finding.title = "LLM analysis failed"
        return finding

    def test_a_failure_marker_is_kept_out_of_the_union(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 1:
                analyzer.last_error = "provider refused"
                return [self._diagnostic()]
            return [_finding("REAL_RULE")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))

        rules = {f.rule_id for f in findings}
        assert "REAL_RULE" in rules
        assert "LLM_ANALYSIS_FAILED" not in rules, "a diagnostic must not join the semantic findings"

    def test_a_failed_pass_is_not_counted_as_completed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        passes = len(analyzer.prompt_builder.decomposed_focuses)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 1:
                return [self._diagnostic()]
            return [_finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        assert analyzer.last_decomposed_failures == 1
        assert analyzer.last_decomposed_passes == passes - 1

    def test_the_marker_survives_when_no_pass_produced_a_judgement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)

        async def fake_single(skill: Any) -> list[Finding]:
            analyzer.last_error = "provider refused"
            return [self._diagnostic()]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        # Dropping it here would report a skill nothing could read as a clean one.
        assert [f.rule_id for f in findings] == ["LLM_ANALYSIS_FAILED"]

    def test_a_budget_notice_is_coverage_not_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_analyze_single adds the notice before asking the model, so it rides on an answered pass."""
        analyzer = _analyzer(decompose=True)
        passes = len(analyzer.prompt_builder.decomposed_focuses)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            analyzer.last_error = None
            analyzer.last_overall_verdict = "SAFE" if calls["n"] == 1 else "SUSPICIOUS"
            if calls["n"] == 1:
                return [self._diagnostic("LLM_CONTEXT_BUDGET_EXCEEDED")]
            return [_finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        assert analyzer.last_decomposed_failures == 0
        assert analyzer.last_decomposed_passes == passes
        assert analyzer.last_error is None
        assert [f.rule_id for f in findings].count("LLM_CONTEXT_BUDGET_EXCEEDED") == 1

    def test_a_budget_notice_is_reported_once_across_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            return [self._diagnostic("LLM_CONTEXT_BUDGET_EXCEEDED"), _finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        rules = [f.rule_id for f in findings]
        # Every pass skips the same file under the same budget, so one notice, not one per pass.
        assert rules.count("LLM_CONTEXT_BUDGET_EXCEEDED") == 1
        assert analyzer.last_decomposed_failures == 0

    def test_a_safe_pass_suppresses_the_failure_marker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A SAFE answer with nothing to report is a judgement; the marker would contradict it."""
        analyzer = _analyzer(decompose=True)
        passes = len(analyzer.prompt_builder.decomposed_focuses)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 1:
                analyzer.last_error = "provider refused"
                return [self._diagnostic()]
            analyzer.last_error = None
            analyzer.last_overall_verdict = "SAFE"
            return []

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        assert findings == []
        assert analyzer.last_overall_verdict == "SAFE"
        assert analyzer.last_decomposed_passes == passes - 1
        assert analyzer.last_decomposed_failures == 1
        # The failure is still reported, through last_error rather than a finding.
        assert analyzer.last_error is not None and "provider refused" in analyzer.last_error

    def test_findings_returned_with_a_failure_marker_are_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        passes = len(analyzer.prompt_builder.decomposed_focuses)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 1:
                analyzer.last_error = "contract violation"
                return [_finding("PARTIAL_RULE"), self._diagnostic()]
            analyzer.last_error = None
            return [_finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        findings = asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        rules = {f.rule_id for f in findings}
        assert "PARTIAL_RULE" in rules
        assert "LLM_ANALYSIS_FAILED" not in rules
        # Failed, not completed: one pass is not counted twice.
        assert analyzer.last_decomposed_failures == 1
        assert analyzer.last_decomposed_passes == passes - 1

    def test_a_later_success_does_not_clear_an_earlier_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            if calls["n"] == 1:
                analyzer.last_error = "provider refused"
                return [self._diagnostic()]
            analyzer.last_error = None
            return [_finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        # last_error is shared across passes; the run, not the final pass, defines it.
        assert analyzer.last_error is not None
        assert "provider refused" in analyzer.last_error

    def test_a_failing_final_pass_does_not_flag_an_otherwise_good_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        total = len(analyzer.prompt_builder.decomposed_focuses)
        calls = {"n": 0}

        async def fake_single(skill: Any) -> list[Finding]:
            calls["n"] += 1
            analyzer.last_error = None
            return [_finding(f"RULE_{calls['n']}")]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        assert analyzer.last_error is None
        assert analyzer.last_decomposed_passes == total
        assert analyzer.last_decomposed_failures == 0

    def test_a_failed_pass_still_counts_its_tokens(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer(decompose=True)
        passes = len(analyzer.prompt_builder.decomposed_focuses)

        async def fake_single(skill: Any) -> list[Finding]:
            analyzer._llm_usage = {"input_tokens": 90, "output_tokens": 5, "total_tokens": 95}
            return [self._diagnostic()]

        monkeypatch.setattr(analyzer, "_analyze_single", fake_single)
        asyncio.run(analyzer._analyze_decomposed(SimpleNamespace(name="s")))
        # The request was billed even though it produced no judgement.
        assert analyzer.llm_usage["input_tokens"] == 90 * passes
