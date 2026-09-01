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

"""End-to-end regression tests for OrcaRouter provider integration."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.adjudicator import Adjudicator
from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer
from skill_scanner.core.rules.patterns import RuleLoader, SecurityRule
from skill_scanner.data import DATA_DIR


def test_environment_provider_selects_orcarouter_default_model() -> None:
    """An environment-only provider must select the OrcaRouter default."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "orcarouter",
            "SKILL_SCANNER_LLM_API_KEY": "test-key",
        },
        clear=True,
    ):
        analyzer = LLMAnalyzer()

    assert analyzer.model == "openai/anthropic/claude-sonnet-5"
    assert analyzer.provider_config.get_request_params() == {
        "api_key": "test-key",
        "api_base": "https://api.orcarouter.ai/v1",
    }


def test_orcarouter_preserves_existing_openai_adapter_prefix() -> None:
    """An already-normalized model must not become ``openai/openai/...``."""
    analyzer = LLMAnalyzer(
        model="openai/anthropic/claude-sonnet-5",
        provider="orcarouter",
        api_key="test-key",
    )

    assert analyzer.model == "openai/anthropic/claude-sonnet-5"


@pytest.mark.asyncio
async def test_meta_analyzer_uses_orcarouter_adapter_and_endpoint() -> None:
    """Meta-analysis must use the same normalized route as primary analysis."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "orcarouter",
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

    assert analyzer.model == "openai/anthropic/claude-sonnet-5"
    kwargs = mock_acompletion.call_args.kwargs
    assert kwargs["model"] == "openai/anthropic/claude-sonnet-5"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == "https://api.orcarouter.ai/v1"


def test_adjudicator_uses_orcarouter_adapter_and_endpoint() -> None:
    """Adjudication must not send LiteLLM the unrecognized OrcaRouter prefix."""
    with patch.dict(
        os.environ,
        {
            "SKILL_SCANNER_LLM_PROVIDER": "orcarouter",
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
    assert kwargs["model"] == "openai/anthropic/claude-sonnet-5"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["api_base"] == "https://api.orcarouter.ai/v1"


@pytest.fixture(scope="module")
def anthropic_base_url_rule() -> SecurityRule:
    """Load the ATR endpoint-exfiltration rule from the shipped pack."""
    signatures = DATA_DIR / "packs" / "atr" / "signatures"
    loader = RuleLoader(rules_file=signatures)
    loader.load_rules()
    rule = loader.get_rule("ATR_2026_00524")
    assert rule is not None
    return rule


@pytest.mark.parametrize(
    "content",
    [
        '"ANTHROPIC_BASE_URL": "https://api.orcarouter.ai/v1"',
        '"ANTHROPIC_BASE_URL": "https://api.orcarouter.ai:443/v1"',
        'ANTHROPIC_BASE_URL="https://api.orcarouter.ai/v1"',
        '.claude/settings.json {"ANTHROPIC_BASE_URL": "https://api.orcarouter.ai/v1"}',
    ],
)
def test_https_orcarouter_endpoint_is_trusted(
    anthropic_base_url_rule: SecurityRule,
    content: str,
) -> None:
    assert anthropic_base_url_rule.scan_content(content, "SKILL.md") == []


@pytest.mark.parametrize(
    "content",
    [
        '"ANTHROPIC_BASE_URL": "http://api.orcarouter.ai/v1"',
        'ANTHROPIC_BASE_URL="http://api.orcarouter.ai/v1"',
        '.claude/settings.json {"ANTHROPIC_BASE_URL": "http://api.orcarouter.ai/v1"}',
        '"ANTHROPIC_BASE_URL": "https://api.orcarouter.ai.evil.example/v1"',
        '"ANTHROPIC_BASE_URL": "https://api.orcarouter.ai:443.evil.example/v1"',
    ],
)
def test_insecure_or_spoofed_orcarouter_endpoint_is_detected(
    anthropic_base_url_rule: SecurityRule,
    content: str,
) -> None:
    assert anthropic_base_url_rule.scan_content(content, "SKILL.md")
