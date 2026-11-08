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

"""End-to-end regression tests for Runcrate provider integration."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.adjudicator import Adjudicator
from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import AlignmentLLMClient
from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

DEFAULT_MODEL = "deepseek-ai/DeepSeek-V4-Flash"
RUNCRATE_BASE_URL = "https://api.runcrate.ai/v1"


def test_environment_provider_selects_runcrate_default_model() -> None:
    """An environment-only provider must select the Runcrate default."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "runcrate",
            "SKILL_SCANNER_LLM_API_KEY": "test-key",
        },
        clear=True,
    ):
        analyzer = LLMAnalyzer()

    assert analyzer.model == f"openai/{DEFAULT_MODEL}"
    assert analyzer.provider_config.get_request_params() == {
        "api_key": "test-key",
        "api_base": RUNCRATE_BASE_URL,
    }


def test_runcrate_model_prefix_routes_via_openai_adapter() -> None:
    """The runcrate/ prefix routes through LiteLLM's OpenAI adapter with the default endpoint."""
    analyzer = LLMAnalyzer(
        model=f"runcrate/{DEFAULT_MODEL}",
        api_key="test-key",
    )

    assert analyzer.model == f"openai/{DEFAULT_MODEL}"
    assert analyzer.provider_config.is_runcrate
    assert analyzer.provider_config.get_request_params() == {
        "api_key": "test-key",
        "api_base": RUNCRATE_BASE_URL,
    }


def test_runcrate_provider_override_with_bare_model_uses_default_endpoint() -> None:
    """The explicit runcrate provider maps a bare model id to the OpenAI adapter."""
    analyzer = LLMAnalyzer(
        model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        provider="runcrate",
        api_key="test-key",
    )

    assert analyzer.model == "openai/meta-llama/Llama-3.3-70B-Instruct-Turbo"
    assert analyzer.provider_config.get_request_params()["api_base"] == RUNCRATE_BASE_URL


def test_runcrate_custom_base_url_overrides_default_endpoint() -> None:
    """An explicit base_url overrides the Runcrate default endpoint."""
    analyzer = LLMAnalyzer(
        model=f"runcrate/{DEFAULT_MODEL}",
        api_key="test-key",
        base_url="https://runcrate.internal/v1",
    )

    assert analyzer.provider_config.get_request_params() == {
        "api_key": "test-key",
        "api_base": "https://runcrate.internal/v1",
    }


def test_runcrate_preserves_existing_openai_adapter_prefix() -> None:
    """An already-normalized model must not become ``openai/openai/...``."""
    analyzer = LLMAnalyzer(
        model=f"openai/{DEFAULT_MODEL}",
        provider="runcrate",
        api_key="test-key",
    )

    assert analyzer.model == f"openai/{DEFAULT_MODEL}"


@pytest.mark.parametrize(
    "downstream",
    ["google/gemini-2.5-pro", "google/vertex-model", "azure/gpt-4o"],
)
def test_runcrate_not_hijacked_by_downstream_model_name(downstream: str) -> None:
    """The runcrate prefix wins over native gemini/vertex/azure substring detection."""
    config = ProviderConfig(model=f"runcrate/{downstream}", api_key="test-key")

    assert config.is_runcrate
    assert not (config.is_gemini or config.is_vertex or config.is_azure)
    assert config.model == f"openai/{downstream}"
    assert config.get_request_params()["api_base"] == RUNCRATE_BASE_URL


@pytest.mark.asyncio
async def test_meta_analyzer_uses_runcrate_adapter_and_endpoint() -> None:
    """Meta-analysis must use the same normalized route as primary analysis."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "runcrate",
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

    assert analyzer.model == f"openai/{DEFAULT_MODEL}"
    kwargs = mock_acompletion.call_args.kwargs
    assert kwargs["model"] == f"openai/{DEFAULT_MODEL}"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == RUNCRATE_BASE_URL


def test_adjudicator_uses_runcrate_adapter_and_endpoint() -> None:
    """Adjudication must not send LiteLLM the unrecognized Runcrate prefix."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "runcrate",
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
    assert kwargs["model"] == f"openai/{DEFAULT_MODEL}"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == RUNCRATE_BASE_URL


def test_alignment_client_uses_shared_runcrate_provider_config() -> None:
    """The behavioral alignment client must resolve the Runcrate key and endpoint via ProviderConfig."""
    with patch.dict(os.environ, {}, clear=True):
        client = AlignmentLLMClient(
            model=f"runcrate/{DEFAULT_MODEL}",
            api_key="test-key",
        )

    assert client._provider_config is not None
    assert client._provider_config.is_runcrate
    assert client._api_key == "test-key"
