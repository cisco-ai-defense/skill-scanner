# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for optional, provider-aware LLM reasoning controls."""

from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from skill_scanner.config.config import Config
from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.llm_reasoning import (
    ReasoningConfigurationError,
    ReasoningControlUnsupportedError,
    build_litellm_reasoning_params,
    ensure_google_sdk_reasoning_supported,
    resolve_llm_reasoning_effort,
)


def _provider(model: str, provider: str | None = None) -> MagicMock:
    config = MagicMock()
    config.model = model
    config.provider = provider
    config.use_google_sdk = False
    config.get_request_params.return_value = {"api_key": "test-key"}
    return config


def _response(content: str = '{"result":"ok"}') -> MagicMock:
    choice = MagicMock()
    choice.message.content = content
    choice.finish_reason = "stop"
    choice.provider_specific_fields = {}
    response = MagicMock()
    response.choices = [choice]
    response.usage = MagicMock(prompt_tokens=1, completion_tokens=1, total_tokens=2)
    return response


class TestReasoningResolution:
    def test_unset_preserves_provider_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SKILL_SCANNER_LLM_REASONING_EFFORT", raising=False)
        monkeypatch.delenv("SKILL_SCANNER_META_LLM_REASONING_EFFORT", raising=False)
        assert resolve_llm_reasoning_effort() is None
        assert resolve_llm_reasoning_effort(meta=True) is None

    def test_scanner_wide_environment_is_validated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REASONING_EFFORT", " LoW ")
        assert resolve_llm_reasoning_effort() == "low"

    def test_meta_specific_environment_precedes_scanner_wide(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REASONING_EFFORT", "medium")
        monkeypatch.setenv("SKILL_SCANNER_META_LLM_REASONING_EFFORT", "minimal")
        assert resolve_llm_reasoning_effort(meta=True) == "minimal"

    def test_explicit_value_precedes_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REASONING_EFFORT", "high")
        assert resolve_llm_reasoning_effort("disabled") == "disabled"

    @pytest.mark.parametrize("value", ["", "none", "off", "extreme"])
    def test_invalid_or_ambiguous_values_are_rejected(
        self,
        value: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_REASONING_EFFORT", value)
        if value == "":
            assert resolve_llm_reasoning_effort() is None
        else:
            with pytest.raises(ValueError, match="SKILL_SCANNER_LLM_REASONING_EFFORT must be one of"):
                resolve_llm_reasoning_effort()

    def test_config_resolves_environment_without_changing_unset_default(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("SKILL_SCANNER_LLM_REASONING_EFFORT", raising=False)
        assert Config().llm_reasoning_effort is None
        monkeypatch.setenv("SKILL_SCANNER_LLM_REASONING_EFFORT", "medium")
        assert Config().llm_reasoning_effort == "medium"


class TestProviderAwareParams:
    def test_unset_emits_no_request_fields(self) -> None:
        assert build_litellm_reasoning_params(None, model="anthropic/claude-sonnet-5") == {}

    @pytest.mark.parametrize("effort", ["minimal", "low", "medium", "high", "xhigh", "max"])
    def test_configured_effort_uses_litellm_normalized_field(self, effort: str) -> None:
        assert build_litellm_reasoning_params(
            effort,
            model="anthropic/claude-sonnet-5",
            provider="anthropic",
        ) == {"reasoning_effort": effort}

    @pytest.mark.parametrize(
        "model,provider",
        [
            ("anthropic/claude-sonnet-5", "anthropic"),
            ("claude-sonnet-5", None),
            ("bedrock/anthropic.claude-sonnet-5-v1:0", "aws-bedrock"),
            ("vertex_ai/claude-sonnet-5@default", "gcp-vertex"),
        ],
    )
    def test_disabled_uses_native_thinking_field_on_anthropic_routes(
        self,
        model: str,
        provider: str | None,
    ) -> None:
        params = build_litellm_reasoning_params("disabled", model=model, provider=provider)
        assert params == {"thinking": {"type": "disabled"}}
        assert "reasoning_effort" not in params

    @pytest.mark.parametrize(
        "model,provider",
        [
            ("gpt-5", "openai"),
            ("openai/claude-sonnet-5", "openai-compatible"),
            ("openrouter/anthropic/claude-sonnet-5", "openrouter"),
            ("anthropic/claude-sonnet-5", "orcarouter"),
            ("orcarouter/anthropic/claude-sonnet-5", ""),
            ("bedrock/amazon.nova-pro-v1:0", "aws-bedrock"),
        ],
    )
    def test_disabled_uses_openai_semantics_on_gateway_routes(
        self,
        model: str,
        provider: str,
    ) -> None:
        assert build_litellm_reasoning_params("disabled", model=model, provider=provider) == {
            "reasoning_effort": "none"
        }

    def test_direct_google_sdk_rejects_configured_control_instead_of_dropping_it(self) -> None:
        ensure_google_sdk_reasoning_supported(None, model="models/gemini-3.1-pro")
        with pytest.raises(ReasoningControlUnsupportedError, match="direct Google GenAI SDK"):
            ensure_google_sdk_reasoning_supported("low", model="models/gemini-3.1-pro")


class TestMainLLMRequestPath:
    @pytest.mark.asyncio
    async def test_unset_preserves_outgoing_request_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SKILL_SCANNER_LLM_REASONING_EFFORT", raising=False)
        handler = LLMRequestHandler(_provider("gpt-5", "openai"), max_retries=0)
        handler.response_schema = None
        with patch(
            "skill_scanner.core.analyzers.llm_request_handler.acompletion",
            AsyncMock(return_value=_response()),
        ) as completion:
            await handler.make_request([{"role": "user", "content": "test"}])

        kwargs = completion.await_args.kwargs
        assert "reasoning_effort" not in kwargs
        assert "thinking" not in kwargs

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "model,provider,effort,expected",
        [
            ("gpt-5", "openai", "low", {"reasoning_effort": "low"}),
            (
                "anthropic/claude-sonnet-5",
                "anthropic",
                "disabled",
                {"thinking": {"type": "disabled"}},
            ),
            (
                "openai/claude-sonnet-5",
                "openai-compatible",
                "disabled",
                {"reasoning_effort": "none"},
            ),
        ],
    )
    async def test_configured_control_reaches_litellm(
        self,
        model: str,
        provider: str,
        effort: str,
        expected: dict[str, object],
    ) -> None:
        handler = LLMRequestHandler(
            _provider(model, provider),
            reasoning_effort=effort,
            max_retries=0,
        )
        handler.response_schema = None
        with patch(
            "skill_scanner.core.analyzers.llm_request_handler.acompletion",
            AsyncMock(return_value=_response()),
        ) as completion:
            await handler.make_request([{"role": "user", "content": "test"}])

        kwargs = completion.await_args.kwargs
        for key, value in expected.items():
            assert kwargs[key] == value
        unexpected = "thinking" if "reasoning_effort" in expected else "reasoning_effort"
        assert unexpected not in kwargs

    def test_direct_google_handler_fails_loudly_when_control_is_set(self) -> None:
        provider = _provider("models/gemini-3.1-pro")
        provider.use_google_sdk = True
        with pytest.raises(ReasoningControlUnsupportedError, match="direct Google GenAI SDK"):
            LLMRequestHandler(provider, reasoning_effort="low")


class TestMetaAndAlignmentPaths:
    def test_alignment_client_preserves_legacy_positional_arguments(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        monkeypatch.delenv("SKILL_SCANNER_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("SKILL_SCANNER_LLM_REASONING_EFFORT", raising=False)
        client = AlignmentLLMClient(
            "gpt-4o",
            "test-key",
            "https://llm.example/v1",
            "2026-01-01",
            '{"appkey":"legacy"}',
            0.25,
            2048,
            45,
        )

        assert client._base_url == "https://llm.example/v1"
        assert client._api_version == "2026-01-01"
        assert client._llm_user == '{"appkey":"legacy"}'
        assert client._temperature == 0.25
        assert client._max_tokens == 2048
        assert client._timeout == 45

    def test_alignment_orchestrator_preserves_legacy_positional_arguments(self) -> None:
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
            AlignmentOrchestrator,
        )

        with (
            patch(
                "skill_scanner.core.analyzers.behavioral.alignment.alignment_orchestrator.AlignmentLLMClient"
            ) as client_type,
            patch(
                "skill_scanner.core.analyzers.behavioral.alignment.alignment_orchestrator.ThreatVulnerabilityClassifier"
            ),
        ):
            AlignmentOrchestrator(
                "gpt-4o",
                "test-key",
                "https://llm.example/v1",
                0.25,
                2048,
                45,
            )

        assert client_type.call_args.kwargs["temperature"] == 0.25
        assert client_type.call_args.kwargs["max_tokens"] == 2048
        assert client_type.call_args.kwargs["timeout"] == 45

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "model,provider,effort,expected",
        [
            ("gpt-5", "openai", None, {}),
            ("gpt-5", "openai", "medium", {"reasoning_effort": "medium"}),
            (
                "anthropic/claude-sonnet-5",
                "anthropic",
                "disabled",
                {"thinking": {"type": "disabled"}},
            ),
        ],
    )
    async def test_meta_request_uses_shared_provider_mapping(
        self,
        model: str,
        provider: str,
        effort: str | None,
        expected: dict[str, object],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

        monkeypatch.delenv("SKILL_SCANNER_LLM_REASONING_EFFORT", raising=False)
        monkeypatch.delenv("SKILL_SCANNER_META_LLM_REASONING_EFFORT", raising=False)
        analyzer = MetaAnalyzer(
            model=model,
            api_key="test-key",
            provider=provider,
            reasoning_effort=effort,
            max_retries=1,
        )
        with patch(
            "skill_scanner.core.analyzers.meta_analyzer.acompletion",
            AsyncMock(return_value=_response()),
        ) as completion:
            await analyzer._make_llm_request("system", "user")

        kwargs = completion.await_args.kwargs
        if not expected:
            assert "reasoning_effort" not in kwargs
            assert "thinking" not in kwargs
        for key, value in expected.items():
            assert kwargs[key] == value

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "model,provider,effort,expected",
        [
            ("gpt-5", "openai", None, {}),
            ("gpt-5", "openai", "low", {"reasoning_effort": "low"}),
            (
                "bedrock/anthropic.claude-sonnet-5-v1:0",
                "aws-bedrock",
                "disabled",
                {"thinking": {"type": "disabled"}},
            ),
        ],
    )
    async def test_alignment_request_uses_shared_provider_mapping(
        self,
        model: str,
        provider: str,
        effort: str | None,
        expected: dict[str, object],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        monkeypatch.delenv("SKILL_SCANNER_LLM_REASONING_EFFORT", raising=False)
        client = AlignmentLLMClient(
            model=model,
            api_key="test-key",
            provider=provider,
            reasoning_effort=effort,
        )
        with patch(
            "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.acompletion",
            AsyncMock(return_value=_response()),
        ) as completion:
            await client._make_llm_request("prompt")

        kwargs = completion.await_args.kwargs
        if not expected:
            assert "reasoning_effort" not in kwargs
            assert "thinking" not in kwargs
        for key, value in expected.items():
            assert kwargs[key] == value

    @pytest.mark.asyncio
    async def test_openai_compatible_bare_claude_models_are_normalized(self) -> None:
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

        bare_model = "claude-sonnet-5"
        expected_model = "openai/claude-sonnet-5"
        meta = MetaAnalyzer(
            model=bare_model,
            api_key="test-key",
            provider="openai-compatible",
            reasoning_effort="disabled",
            max_retries=1,
        )
        alignment = AlignmentLLMClient(
            model=bare_model,
            api_key="test-key",
            provider="openai-compatible",
            reasoning_effort="disabled",
        )

        with patch(
            "skill_scanner.core.analyzers.meta_analyzer.acompletion",
            AsyncMock(return_value=_response()),
        ) as meta_completion:
            await meta._make_llm_request("system", "user")
        with patch(
            "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.acompletion",
            AsyncMock(return_value=_response()),
        ) as alignment_completion:
            await alignment._make_llm_request("prompt")

        for completion in (meta_completion, alignment_completion):
            assert completion.await_args.kwargs["model"] == expected_model
            assert completion.await_args.kwargs["reasoning_effort"] == "none"
            assert "thinking" not in completion.await_args.kwargs

    @pytest.mark.asyncio
    async def test_orcarouter_meta_default_and_alignment_share_gateway_semantics(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

        for variable in (
            "SKILL_SCANNER_LLM_MODEL",
            "SKILL_SCANNER_META_LLM_MODEL",
            "SKILL_SCANNER_LLM_PROVIDER",
            "SKILL_SCANNER_LLM_REASONING_EFFORT",
            "SKILL_SCANNER_META_LLM_REASONING_EFFORT",
        ):
            monkeypatch.delenv(variable, raising=False)

        meta = MetaAnalyzer(
            api_key="test-key",
            provider="orcarouter",
            reasoning_effort="disabled",
            max_retries=1,
        )
        alignment = AlignmentLLMClient(
            model="orcarouter/anthropic/claude-sonnet-5",
            api_key="test-key",
            provider="orcarouter",
            reasoning_effort="disabled",
        )

        with patch(
            "skill_scanner.core.analyzers.meta_analyzer.acompletion",
            AsyncMock(return_value=_response()),
        ) as meta_completion:
            await meta._make_llm_request("system", "user")
        with patch(
            "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.acompletion",
            AsyncMock(return_value=_response()),
        ) as alignment_completion:
            await alignment._make_llm_request("prompt")

        for completion in (meta_completion, alignment_completion):
            kwargs = completion.await_args.kwargs
            assert kwargs["model"] == "openai/anthropic/claude-sonnet-5"
            assert kwargs["api_base"] == "https://api.orcarouter.ai/v1"
            assert kwargs["reasoning_effort"] == "none"
            assert "thinking" not in kwargs


class TestEntryPointPlumbing:
    def test_cli_parser_accepts_canonical_values_and_rejects_none(self) -> None:
        from skill_scanner.cli.cli import build_parser

        args = build_parser().parse_args(["scan", "/tmp/skill", "--llm-reasoning-effort", "disabled"])
        assert args.llm_reasoning_effort == "disabled"
        with pytest.raises(SystemExit):
            build_parser().parse_args(["scan", "/tmp/skill", "--llm-reasoning-effort", "none"])

    def test_cli_forwards_setting_to_main_and_meta_factories(self) -> None:
        from skill_scanner.cli.cli import _build_analyzers, _build_meta_analyzer

        policy = ScanPolicy.default()
        args = argparse.Namespace(
            enable_meta=True,
            llm_provider="anthropic",
            llm_reasoning_effort="disabled",
        )
        with patch("skill_scanner.cli.cli.build_analyzers", return_value=[]) as factory:
            _build_analyzers(policy, args, lambda _message: None)
        assert factory.call_args.kwargs["llm_reasoning_effort"] == "disabled"

        with patch("skill_scanner.cli.cli.MetaAnalyzer", return_value=MagicMock()) as meta_type:
            _build_meta_analyzer(
                args,
                2,
                lambda _message: None,
                policy=policy,
                reasoning_effort="disabled",
            )
        assert meta_type.call_args.kwargs["reasoning_effort"] == "disabled"
        assert meta_type.call_args.kwargs["provider"] == "anthropic"

    def test_core_factory_forwards_setting_to_main_and_behavioral_analyzers(self) -> None:
        from skill_scanner.core.analyzer_factory import build_analyzers

        with (
            patch("skill_scanner.core.analyzers.llm_analyzer.LLMAnalyzer", return_value=MagicMock()) as llm_type,
            patch(
                "skill_scanner.core.analyzers.behavioral_analyzer.BehavioralAnalyzer",
                return_value=MagicMock(),
            ) as behavioral_type,
        ):
            build_analyzers(
                ScanPolicy.default(),
                use_llm=True,
                use_behavioral=True,
                llm_provider="anthropic",
                llm_reasoning_effort="low",
            )

        assert llm_type.call_args.kwargs["reasoning_effort"] == "low"
        assert behavioral_type.call_args.kwargs["llm_reasoning_effort"] == "low"
        assert behavioral_type.call_args.kwargs["llm_provider"] == "anthropic"

    def test_core_factory_does_not_swallow_invalid_reasoning_environment(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from skill_scanner.core.analyzer_factory import build_analyzers

        monkeypatch.setenv("SKILL_SCANNER_LLM_REASONING_EFFORT", "turbo")
        monkeypatch.delenv("SKILL_SCANNER_LLM_PROVIDER", raising=False)
        with pytest.raises(ReasoningConfigurationError, match="SKILL_SCANNER_LLM_REASONING_EFFORT"):
            build_analyzers(
                ScanPolicy.default(),
                use_llm=True,
                llm_model="gpt-5",
                llm_api_key="test-key",
            )

    def test_cli_main_reports_reasoning_configuration_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from skill_scanner.cli.cli import main

        monkeypatch.setattr("sys.argv", ["skill-scanner", "list-analyzers"])
        with patch(
            "skill_scanner.cli.cli.list_analyzers_command",
            side_effect=ReasoningConfigurationError("unsupported direct Google reasoning control"),
        ):
            assert main() == 1
        assert "LLM reasoning configuration error" in capsys.readouterr().err

    @pytest.mark.asyncio
    async def test_api_returns_400_for_reasoning_configuration_error(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from skill_scanner.api import router
        from skill_scanner.api.router import ScanRequest, scan_skill

        (tmp_path / "SKILL.md").write_text("---\nname: test\ndescription: test\n---\n", encoding="utf-8")
        monkeypatch.setattr(router, "_ALLOWED_ROOTS", [tmp_path.resolve()])
        request = ScanRequest(
            skill_directory=str(tmp_path),
            use_llm=True,
            llm_reasoning_effort="low",
        )
        with patch(
            "skill_scanner.api.router._build_analyzers",
            side_effect=ReasoningConfigurationError("unsupported direct Google reasoning control"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await scan_skill(request)
        assert exc_info.value.status_code == 400
        assert "unsupported direct Google reasoning control" in exc_info.value.detail

    def test_api_models_validate_and_router_forwards_setting(self) -> None:
        from skill_scanner.api.router import BatchScanRequest, ScanRequest, _build_analyzers

        scan_request = ScanRequest(skill_directory="/tmp/skill", llm_reasoning_effort="minimal")
        batch_request = BatchScanRequest(skills_directory="/tmp/skills", llm_reasoning_effort="disabled")
        assert scan_request.llm_reasoning_effort == "minimal"
        assert batch_request.llm_reasoning_effort == "disabled"
        assert ScanRequest(skill_directory="/tmp/skill").llm_reasoning_effort is None
        with pytest.raises(ValidationError):
            ScanRequest(skill_directory="/tmp/skill", llm_reasoning_effort="none")

        with patch("skill_scanner.api.router.build_analyzers", return_value=[]) as factory:
            _build_analyzers(ScanPolicy.default(), llm_reasoning_effort="high")
        assert factory.call_args.kwargs["llm_reasoning_effort"] == "high"
