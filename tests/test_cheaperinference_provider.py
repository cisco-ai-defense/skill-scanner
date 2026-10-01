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

"""End-to-end regression tests for Cheaper Inference provider integration."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.adjudicator import Adjudicator
from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer


def test_environment_provider_selects_cheaperinference_default_model() -> None:
    """An environment-only provider must select the Cheaper Inference default."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "cheaperinference",
            "SKILL_SCANNER_LLM_API_KEY": "test-key",
        },
        clear=True,
    ):
        analyzer = LLMAnalyzer()

    assert analyzer.model == "openai/gpt-5.4-mini"
    assert analyzer.provider_config.get_request_params() == {
        "api_key": "test-key",
        "api_base": "https://api.cheaperinference.com/v1",
    }


def test_cheaperinference_preserves_existing_openai_adapter_prefix() -> None:
    """An already-normalized model must not become ``openai/openai/...``."""
    analyzer = LLMAnalyzer(
        model="openai/gpt-5.4-mini",
        provider="cheaperinference",
        api_key="test-key",
    )

    assert analyzer.model == "openai/gpt-5.4-mini"


def test_cheaperinference_gemini_model_keeps_gateway_api_key() -> None:
    """A Gemini model name on the gateway must not switch to Google AI Studio auth."""
    with patch.dict(os.environ, {}, clear=True):
        analyzer = LLMAnalyzer(
            model="gemini-3.1-pro",
            provider="cheaperinference",
            api_key="test-key",
        )
        params = analyzer.provider_config.get_request_params()

        assert "GEMINI_API_KEY" not in os.environ

    assert analyzer.model == "openai/gemini-3.1-pro"
    assert params == {
        "api_key": "test-key",
        "api_base": "https://api.cheaperinference.com/v1",
    }


@pytest.mark.asyncio
async def test_meta_analyzer_uses_cheaperinference_adapter_and_endpoint() -> None:
    """Meta-analysis must use the same normalized route as primary analysis."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "cheaperinference",
            "SKILL_SCANNER_LLM_API_KEY": "test-key",
        },
        clear=True,
    ):
        analyzer = MetaAnalyzer()

    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = "{}"
    with patch(
        "skill_scanner.core.analyzers.meta_analyzer.acompletion",
        new_callable=AsyncMock,
        return_value=response,
    ) as mock_acompletion:
        await analyzer._make_llm_request("system", "user")

    assert analyzer.model == "openai/gpt-5.4-mini"
    kwargs = mock_acompletion.call_args.kwargs
    assert kwargs["model"] == "openai/gpt-5.4-mini"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == "https://api.cheaperinference.com/v1"


def test_adjudicator_uses_cheaperinference_adapter_and_endpoint() -> None:
    """Adjudication must not send LiteLLM the unrecognized Cheaper Inference prefix."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "cheaperinference",
            "SKILL_SCANNER_LLM_API_KEY": "test-key",
        },
        clear=True,
    ):
        adjudicator = Adjudicator(max_retries=0)

    response = {
        "choices": [
            {
                "message": {
                    "content": '{"verdict":"real","confidence":5,"reason":"test"}',
                }
            }
        ]
    }
    with patch("litellm.completion", return_value=response) as mock_completion:
        result = adjudicator._call_llm("test prompt")

    assert result == {"verdict": "real", "confidence": 5, "reason": "test"}
    kwargs = mock_completion.call_args.kwargs
    assert kwargs["model"] == "openai/gpt-5.4-mini"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == "https://api.cheaperinference.com/v1"
