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

"""Models that reject a forced ``tool_choice`` get plain JSON with the schema in the prompt.

LiteLLM emulates ``response_format: json_schema`` on Anthropic and Bedrock with a
forced tool call, which Claude Sonnet 5.5 and later reject with a 400.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from skill_scanner.core.analyzers import llm_request_handler
from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler, model_rejects_forced_tool_use


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("claude-sonnet-5-5", True),
        ("bedrock/us.anthropic.claude-sonnet-5-5", True),
        ("anthropic/claude-opus-5-5", True),
        ("claude-fable-5-1", True),
        ("claude-sonnet-5", False),
        ("claude-opus-4-8", False),
        ("claude-haiku-4-5", False),
        ("gpt-4o", False),
        (None, False),
    ],
)
def test_model_rejects_forced_tool_use(model: str | None, expected: bool) -> None:
    assert model_rejects_forced_tool_use(model) is expected


def _handler(model: str) -> LLMRequestHandler:
    provider_config = MagicMock()
    provider_config.model = model
    provider_config.use_bedrock_mantle = False
    provider_config.use_google_sdk = False
    provider_config.is_ollama = False
    provider_config.get_request_params.return_value = {}
    return LLMRequestHandler(provider_config=provider_config, max_retries=0)


def _send(handler: LLMRequestHandler, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    sent: dict[str, Any] = {}

    async def fake_completion(**kwargs: Any) -> Any:
        sent.update(kwargs)
        message = SimpleNamespace(content="{}")
        return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=None)

    monkeypatch.setattr(llm_request_handler, "acompletion", fake_completion)
    messages = [{"role": "system", "content": "You are a judge."}, {"role": "user", "content": "Skill"}]
    asyncio.run(handler.make_request(messages, context="test"))
    return sent


def test_rejecting_model_gets_json_object_and_schema_in_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _handler("claude-sonnet-5-5")
    sent = _send(handler, monkeypatch)

    assert sent["response_format"] == {"type": "json_object"}
    assert "temperature" not in sent
    system = sent["messages"][0]["content"]
    assert system.startswith("You are a judge.")
    assert json.dumps(handler.response_schema, separators=(",", ":")) in system


def test_other_models_keep_json_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _send(_handler("claude-haiku-4-5"), monkeypatch)

    assert sent["response_format"]["type"] == "json_schema"
    assert sent["messages"][0]["content"] == "You are a judge."
    assert sent["temperature"] == 0.0
