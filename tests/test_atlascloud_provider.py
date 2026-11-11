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

"""Regression tests for the Atlas Cloud / OrcaRouter gateway wiring across LLM paths."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.adjudicator import Adjudicator
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer
from skill_scanner.core.scan_policy import ScanPolicy

ATLAS_URL = "https://api.atlascloud.ai/v1"


@pytest.mark.parametrize("provider", ["atlascloud", "orcarouter"])
def test_adjudicator_does_not_send_ambient_openai_key_to_gateway(provider: str) -> None:
    """Without a scanner key the adjudicator must send nothing, not OPENAI_API_KEY."""
    with patch.dict(
        os.environ,
        {"SKILL_SCANNER_LLM_PROVIDER": provider, "OPENAI_API_KEY": "sk-ambient-openai"},
        clear=True,
    ):
        adjudicator = Adjudicator(max_retries=0)

    assert adjudicator._provider_config is None
    with patch("litellm.completion") as mock_completion:
        assert adjudicator._call_llm("prompt") is None
    mock_completion.assert_not_called()


def test_adjudicator_atlascloud_with_key_uses_gateway() -> None:
    with patch.dict(
        os.environ,
        {"SKILL_SCANNER_LLM_PROVIDER": "atlascloud", "SKILL_SCANNER_LLM_API_KEY": "test-key"},
        clear=True,
    ):
        adjudicator = Adjudicator(max_retries=0)

    response = {"choices": [{"message": {"content": '{"verdict":"real","confidence":5,"reason":"t"}'}}]}
    with patch("litellm.completion", return_value=response) as mock_completion:
        adjudicator._call_llm("prompt")
    kwargs = mock_completion.call_args.kwargs
    assert kwargs["model"] == "openai/anthropic/claude-sonnet-5"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == ATLAS_URL


@pytest.mark.asyncio
async def test_meta_analyzer_uses_atlascloud_adapter_and_endpoint() -> None:
    with patch.dict(
        os.environ,
        {"SKILL_SCANNER_LLM_PROVIDER": "atlascloud", "SKILL_SCANNER_LLM_API_KEY": "test-key"},
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

    kwargs = mock_acompletion.call_args.kwargs
    assert kwargs["model"] == "openai/anthropic/claude-sonnet-5"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == ATLAS_URL


def test_atlascloud_sends_openai_user_param_like_other_openai_gateways() -> None:
    """Atlas Cloud accepts the OpenAI `user` field; it must behave like OrcaRouter."""
    for provider in ("atlascloud", "orcarouter"):
        analyzer = LLMAnalyzer(provider=provider, api_key="k", llm_user="u-1")
        assert analyzer.provider_config.get_request_params()["user"] == "u-1"


def test_behavioral_analyzer_passes_base_url_and_gateway_default_model() -> None:
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "atlascloud",
            "SKILL_SCANNER_LLM_API_KEY": "test-key",
            "SKILL_SCANNER_LLM_BASE_URL": "https://proxy.internal/v1",
        },
        clear=True,
    ):
        with patch("skill_scanner.core.analyzers.behavioral.alignment.AlignmentOrchestrator") as orchestrator:
            BehavioralAnalyzer(use_alignment_verification=True)

    kwargs = orchestrator.call_args.kwargs
    assert kwargs["llm_base_url"] == "https://proxy.internal/v1"
    assert kwargs["llm_model"] == "atlascloud/anthropic/claude-sonnet-5"


def test_behavioral_analyzer_explicit_base_url_and_model_win() -> None:
    with patch.dict(os.environ, {"SKILL_SCANNER_LLM_BASE_URL": "https://env/v1"}, clear=True):
        with patch("skill_scanner.core.analyzers.behavioral.alignment.AlignmentOrchestrator") as orchestrator:
            BehavioralAnalyzer(
                use_alignment_verification=True,
                llm_model="atlascloud/deepseek-ai/deepseek-v3.2",
                llm_api_key="k",
                llm_provider="atlascloud",
                llm_base_url="https://explicit/v1",
            )
    kwargs = orchestrator.call_args.kwargs
    assert kwargs["llm_base_url"] == "https://explicit/v1"
    assert kwargs["llm_model"] == "atlascloud/deepseek-ai/deepseek-v3.2"


def test_alignment_client_routes_to_configured_base_url_not_public_endpoint() -> None:
    from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import AlignmentLLMClient

    with patch.dict(os.environ, {}, clear=True):
        client = AlignmentLLMClient(
            model="atlascloud/anthropic/claude-sonnet-5",
            api_key="k",
            base_url="https://proxy.internal/v1",
            provider="atlascloud",
        )
    assert client._provider_config.get_request_params()["api_base"] == "https://proxy.internal/v1"


def test_factory_forwards_base_url_to_behavioral_analyzer() -> None:
    from skill_scanner.core import analyzer_factory

    with patch("skill_scanner.core.analyzers.behavioral_analyzer.BehavioralAnalyzer") as cls:
        with patch.dict(os.environ, {"SKILL_SCANNER_LLM_BASE_URL": "https://env/v1"}):
            analyzer_factory.build_analyzers(ScanPolicy.default(), use_behavioral=True)
    assert cls.call_args.kwargs["llm_base_url"] == "https://env/v1"
