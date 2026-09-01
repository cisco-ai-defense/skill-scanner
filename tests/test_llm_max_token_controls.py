# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for configurable LLM output budgets and truncation."""

from __future__ import annotations

import os
from enum import Enum
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from skill_scanner.config.config import Config
from skill_scanner.core.analyzers.llm_request_handler import (
    LLMRequestHandler,
    LLMResponseTruncatedError,
    get_truncation_finish_reason,
)
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.llm_token_options import resolve_llm_max_tokens


@pytest.fixture
def litellm_handler() -> LLMRequestHandler:
    provider = MagicMock()
    provider.model = "gpt-4o"
    provider.use_google_sdk = False
    provider.get_request_params.return_value = {}
    handler = LLMRequestHandler(provider_config=provider, max_tokens=4096, max_retries=0)
    handler.response_schema = None
    return handler


def _litellm_response(
    content: str,
    *,
    finish_reason: object = "stop",
    native_finish_reason: str | None = None,
) -> MagicMock:
    choice = MagicMock()
    choice.message.content = content
    choice.finish_reason = finish_reason
    choice.provider_specific_fields = (
        {"native_finish_reason": native_finish_reason} if native_finish_reason is not None else {}
    )
    response = MagicMock()
    response.choices = [choice]
    response.usage = MagicMock(prompt_tokens=10, completion_tokens=20, total_tokens=30)
    return response


class TestMaxTokenResolution:
    def test_scanner_wide_environment_overrides_default(self) -> None:
        with patch.dict(os.environ, {"SKILL_SCANNER_LLM_MAX_TOKENS": "16384"}, clear=False):
            assert resolve_llm_max_tokens(default=4096) == 16384

    def test_meta_environment_precedes_scanner_wide_environment(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SKILL_SCANNER_LLM_MAX_TOKENS": "16384",
                "SKILL_SCANNER_META_LLM_MAX_TOKENS": "32768",
            },
            clear=False,
        ):
            assert resolve_llm_max_tokens(meta=True) == 32768

    def test_explicit_value_precedes_environment(self) -> None:
        with patch.dict(os.environ, {"SKILL_SCANNER_LLM_MAX_TOKENS": "16384"}, clear=False):
            assert resolve_llm_max_tokens(2048) == 2048

    @pytest.mark.parametrize("raw", ["0", "-1", "not-an-int"])
    def test_invalid_environment_value_is_rejected(self, raw: str) -> None:
        with patch.dict(os.environ, {"SKILL_SCANNER_LLM_MAX_TOKENS": raw}, clear=False):
            with pytest.raises(ValueError, match="SKILL_SCANNER_LLM_MAX_TOKENS must be a positive integer"):
                resolve_llm_max_tokens()

    def test_config_loads_validated_environment_value(self) -> None:
        with patch.dict(os.environ, {"SKILL_SCANNER_LLM_MAX_TOKENS": "12288"}, clear=False):
            assert Config().llm_max_tokens == 12288

    def test_factory_environment_precedes_policy_and_explicit_precedes_environment(self) -> None:
        from skill_scanner.core.analyzer_factory import build_analyzers

        policy = ScanPolicy.default()
        policy.llm_analysis.max_output_tokens = 4096
        with (
            patch.dict(os.environ, {"SKILL_SCANNER_LLM_MAX_TOKENS": "16384"}, clear=False),
            patch("skill_scanner.core.analyzers.llm_analyzer.LLMAnalyzer") as analyzer_type,
        ):
            analyzer_type.return_value = MagicMock()
            build_analyzers(policy, use_llm=True)
            assert analyzer_type.call_args.kwargs["max_tokens"] == 16384

            build_analyzers(policy, use_llm=True, llm_max_tokens=2048)
            assert analyzer_type.call_args.kwargs["max_tokens"] == 2048


class TestAPIMaxTokenControls:
    def test_request_models_accept_positive_values(self) -> None:
        from skill_scanner.api.router import BatchScanRequest, ScanRequest

        assert ScanRequest(skill_directory="/tmp/skill", llm_max_tokens=16384).llm_max_tokens == 16384
        assert BatchScanRequest(skills_directory="/tmp/skills", llm_max_tokens=32768).llm_max_tokens == 32768

    @pytest.mark.parametrize("value", [0, -1])
    def test_request_models_reject_non_positive_values(self, value: int) -> None:
        from skill_scanner.api.router import BatchScanRequest, ScanRequest

        with pytest.raises(ValidationError):
            ScanRequest(skill_directory="/tmp/skill", llm_max_tokens=value)
        with pytest.raises(ValidationError):
            BatchScanRequest(skills_directory="/tmp/skills", llm_max_tokens=value)

    def test_router_forwards_api_value_to_factory(self) -> None:
        from skill_scanner.api.router import _build_analyzers

        with patch("skill_scanner.api.router.build_analyzers", return_value=[]) as factory:
            _build_analyzers(ScanPolicy.default(), llm_max_tokens=24576)

        assert factory.call_args.kwargs["llm_max_tokens"] == 24576


class TestTruncationDetection:
    @pytest.mark.parametrize(
        "finish_reason,native_reason,expected",
        [
            ("length", None, "length"),
            ("stop", "max_tokens", "max_tokens"),
            ("MAX_OUTPUT_TOKENS", None, "MAX_OUTPUT_TOKENS"),
            ("stop", None, None),
        ],
    )
    def test_shared_detector_normalizes_provider_reasons(
        self,
        finish_reason: str,
        native_reason: str | None,
        expected: str | None,
    ) -> None:
        choice = _litellm_response(
            "{}",
            finish_reason=finish_reason,
            native_finish_reason=native_reason,
        ).choices[0]
        assert get_truncation_finish_reason(choice) == expected

    @pytest.mark.asyncio
    async def test_normal_litellm_path_raises_typed_actionable_error(
        self,
        litellm_handler: LLMRequestHandler,
    ) -> None:
        response = _litellm_response('{"findings":[', finish_reason="length")
        with (
            patch(
                "skill_scanner.core.analyzers.llm_request_handler.acompletion",
                AsyncMock(return_value=response),
            ),
            pytest.raises(LLMResponseTruncatedError) as exc_info,
        ):
            await litellm_handler.make_request(
                [{"role": "user", "content": "scan"}],
                context="threat analysis for demo",
            )

        assert exc_info.value.finish_reason == "length"
        assert exc_info.value.max_tokens == 4096
        assert "SKILL_SCANNER_LLM_MAX_TOKENS" in str(exc_info.value)
        assert "API llm_max_tokens" in str(exc_info.value)
        assert litellm_handler.last_usage["output_tokens"] == 20

    @pytest.mark.asyncio
    async def test_plain_json_fallback_path_checks_truncation(self) -> None:
        provider = MagicMock()
        provider.model = "azure/gpt-4o"
        provider.use_google_sdk = False
        provider.get_request_params.return_value = {}
        handler = LLMRequestHandler(provider_config=provider, max_tokens=2048, max_retries=0)
        response = _litellm_response('{"findings":[', finish_reason="length")
        schema_error = RuntimeError("Missing required parameter: 'response_format.json_schema'.")

        with (
            patch(
                "skill_scanner.core.analyzers.llm_request_handler.acompletion",
                AsyncMock(side_effect=[schema_error, response]),
            ),
            pytest.raises(LLMResponseTruncatedError),
        ):
            await handler.make_request([{"role": "user", "content": "scan"}], context="fallback demo")

        assert handler.last_usage["output_tokens"] == 20

    @pytest.mark.asyncio
    async def test_google_sdk_max_tokens_candidate_raises_typed_error(self) -> None:
        class FinishReason(Enum):
            MAX_TOKENS = "MAX_TOKENS"

        provider = MagicMock()
        provider.model = "gemini-2.0-flash"
        provider.use_google_sdk = True
        provider.api_key = "test-key"
        handler = LLMRequestHandler(provider_config=provider, max_tokens=1024, max_retries=0)
        handler.response_schema = None

        response = MagicMock()
        response.text = '{"findings":['
        response.candidates = [MagicMock(finish_reason=FinishReason.MAX_TOKENS)]
        response.usage_metadata = MagicMock(
            prompt_token_count=10,
            candidates_token_count=1024,
            total_token_count=1034,
        )
        mock_genai = MagicMock()
        mock_genai.Client.return_value.models.generate_content.return_value = response

        with (
            patch("skill_scanner.core.analyzers.llm_request_handler.genai", mock_genai),
            pytest.raises(LLMResponseTruncatedError) as exc_info,
        ):
            await handler.make_request([{"role": "user", "content": "scan"}], context="google demo")

        assert exc_info.value.finish_reason == "MAX_TOKENS"
        assert handler.last_usage["output_tokens"] == 1024
