# Copyright 2026 Cisco Systems, Inc.
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

"""On-device Apple Foundation Model routing. These tests never call the real SDK."""

from __future__ import annotations

import asyncio
import inspect
import sys
from types import ModuleType, SimpleNamespace

import pytest

from skill_scanner.core.analyzers.adjudicator import _LLM_LOCK, Adjudicator
from skill_scanner.core.analyzers.apple_fm import apple_fm_acompletion, is_apple_fm_model
from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import AlignmentLLMClient
from skill_scanner.core.analyzers.llm_analyzer import LLMProvider
from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler
from skill_scanner.core.analyzers.llm_request_options import supports_openai_user_param
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer


def _clear_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SKILL_SCANNER_META_LLM_API_KEY", "SKILL_SCANNER_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_apple_fm_prefix_is_case_insensitive() -> None:
    assert is_apple_fm_model("apple-fm/system")
    assert is_apple_fm_model("Apple-FM/System")
    assert not is_apple_fm_model("gpt-4o")
    assert not is_apple_fm_model(None)


def test_provider_config_allows_keyless_apple_fm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)
    monkeypatch.setenv("SKILL_SCANNER_LLM_API_KEY", "should-not-be-used")

    config = ProviderConfig(model="apple-fm/system")
    config.validate()

    assert config.is_apple_fm is True
    assert config.api_key is None
    assert config.model == "apple-fm/system"
    assert supports_openai_user_param(config.model, "apple-fm") is False


def test_provider_name_maps_to_system_model(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)

    config = ProviderConfig(model="system", provider="apple-fm")

    assert config.is_apple_fm is True
    assert config.model == "apple-fm/system"
    assert LLMProvider.is_valid_provider("apple-fm")


def test_hosted_model_still_requires_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)

    config = ProviderConfig(model="gpt-4o", api_key=None)
    with pytest.raises(ValueError, match="API key required"):
        config.validate()


def test_meta_analyzer_allows_keyless_apple_fm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)

    analyzer = MetaAnalyzer(model="apple-fm/system", max_tokens=128)

    assert analyzer.api_key is None
    assert analyzer.is_apple_fm is True
    assert analyzer.model == "apple-fm/system"


def test_request_handler_routes_to_apple_fm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)
    captured: dict = {}

    async def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"findings": []}'))],
            usage=None,
        )

    monkeypatch.setattr(
        "skill_scanner.core.analyzers.llm_request_handler.apple_fm_acompletion",
        fake_completion,
        raising=False,
    )
    # The handler imports the adapter inside the method, so patch the source module.
    monkeypatch.setattr(
        "skill_scanner.core.analyzers.apple_fm.apple_fm_acompletion",
        fake_completion,
    )
    config = ProviderConfig(model="apple-fm/system")
    handler = LLMRequestHandler(config, max_tokens=128, temperature=0.0, timeout=5)
    content = asyncio.run(handler.make_request([{"role": "user", "content": "scan"}], context="test"))

    assert content == '{"findings": []}'
    assert captured["model"] == "apple-fm/system"
    assert captured["temperature"] == 0.0
    assert captured["max_tokens"] == 128


def test_meta_request_uses_apple_fm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)
    captured: dict = {}

    async def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))],
            usage=None,
        )

    monkeypatch.setattr("skill_scanner.core.analyzers.apple_fm.apple_fm_acompletion", fake_completion)
    analyzer = MetaAnalyzer(model="apple-fm/system", max_tokens=64, temperature=0.0)
    content = asyncio.run(analyzer._make_llm_request("system", "user"))

    assert content == "{}"
    assert captured["messages"][0]["role"] == "system"
    assert captured["temperature"] == 0.0


def test_alignment_client_allows_keyless_apple_fm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)
    captured: dict = {}

    async def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"aligned": true}'))],
            usage=None,
        )

    monkeypatch.setattr(
        "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.apple_fm_acompletion",
        fake_completion,
    )
    client = AlignmentLLMClient(model="apple-fm/system", api_key=None, max_tokens=32, temperature=0.0)
    content = asyncio.run(client._make_llm_request("does this match"))

    assert client._is_apple_fm is True
    assert content == '{"aligned": true}'
    assert captured["model"] == "apple-fm/system"


class _FakeSession:
    def __init__(self, instructions: str = "") -> None:
        self.instructions = instructions

    async def respond(self, prompt: str, options=None):
        return f"{self.instructions}|{prompt}|{getattr(options, 'temperature', None)}"


class _FakeFM:
    class GenerationOptions:
        def __init__(self, temperature=None, maximum_response_tokens=None) -> None:
            self.temperature = temperature
            self.maximum_response_tokens = maximum_response_tokens

    class LanguageModelSession:
        def __init__(self, instructions: str = "") -> None:
            self.instructions = instructions

        async def respond(self, prompt: str, options=None):
            return await _FakeSession(self.instructions).respond(prompt, options)

    class SystemLanguageModel:
        def is_available(self):
            return True, None


def _install_fake_sdk(monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> None:
    monkeypatch.setitem(sys.modules, "apple_fm_sdk", module)


def test_adapter_maps_messages_and_options(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = _FakeFM.SystemLanguageModel
    fake.LanguageModelSession = _FakeFM.LanguageModelSession
    fake.GenerationOptions = _FakeFM.GenerationOptions
    _install_fake_sdk(monkeypatch, fake)

    response = asyncio.run(
        apple_fm_acompletion(
            model="apple-fm/system",
            messages=[
                {"role": "system", "content": "be careful"},
                {"role": "user", "content": "scan this"},
            ],
            temperature=0.0,
            max_tokens=1000,
        )
    )

    assert response.choices[0].message.content == "be careful|scan this|0.0"


def test_missing_sdk_raises_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "apple_fm_sdk", None)
    with pytest.raises(ImportError, match="pip install apple-fm-sdk"):
        asyncio.run(apple_fm_acompletion(model="apple-fm/system", messages=[{"role": "user", "content": "hi"}]))


def test_timeout_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    class SlowSession:
        def __init__(self, instructions: str = "") -> None:
            self.instructions = instructions

        async def respond(self, prompt: str, options=None):
            await asyncio.sleep(5)
            return prompt

    class SlowFM(_FakeFM):
        class LanguageModelSession(SlowSession):
            pass

    fake = ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = SlowFM.SystemLanguageModel
    fake.LanguageModelSession = SlowFM.LanguageModelSession
    fake.GenerationOptions = SlowFM.GenerationOptions
    _install_fake_sdk(monkeypatch, fake)

    with pytest.raises(TimeoutError, match="timed out after 0.01"):
        asyncio.run(
            apple_fm_acompletion(
                model="apple-fm/system",
                messages=[{"role": "user", "content": "hi"}],
                timeout=0.01,
            )
        )


def test_guided_schema_is_passed_to_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    class GuidedSession:
        def __init__(self, instructions: str = "") -> None:
            self.instructions = instructions

        async def respond(self, prompt: str, options=None, json_schema=None):
            seen["json_schema"] = json_schema
            return {"verdict": "SAFE", "findings": [], "overall_assessment": "clean", "primary_threats": []}

    class GuidedFM(_FakeFM):
        class LanguageModelSession(GuidedSession):
            pass

    fake = ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = GuidedFM.SystemLanguageModel
    fake.LanguageModelSession = GuidedFM.LanguageModelSession
    fake.GenerationOptions = GuidedFM.GenerationOptions
    _install_fake_sdk(monkeypatch, fake)

    response = asyncio.run(
        apple_fm_acompletion(
            model="apple-fm/system",
            messages=[{"role": "user", "content": "scan"}],
            json_schema={
                "type": "object",
                "properties": {
                    "verdict": {"type": "string"},
                    "note": {"type": ["string", "null"]},
                },
                "required": ["verdict"],
            },
        )
    )

    schema = seen["json_schema"]
    assert schema["title"]
    assert schema["x-order"] == ["verdict", "note"]
    assert schema["properties"]["note"]["type"] == "string"
    assert response.choices[0].message.content.startswith("{")


def test_language_model_session_accepts_instructions() -> None:
    """Guard the adapter against a signature that dropped the instructions parameter."""
    assert "instructions" in inspect.signature(_FakeFM.LanguageModelSession).parameters


def test_missing_instructions_channel_is_not_merged_into_the_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    class BareSession:
        def __init__(self) -> None:
            pass

        async def respond(self, prompt: str, options=None):
            return prompt

    class BareFM(_FakeFM):
        class LanguageModelSession(BareSession):
            pass

    fake = ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = BareFM.SystemLanguageModel
    fake.LanguageModelSession = BareFM.LanguageModelSession
    fake.GenerationOptions = BareFM.GenerationOptions
    _install_fake_sdk(monkeypatch, fake)

    with pytest.raises(RuntimeError, match="separate instructions"):
        asyncio.run(
            apple_fm_acompletion(
                model="apple-fm/system",
                messages=[
                    {"role": "system", "content": "policy"},
                    {"role": "user", "content": "skill text"},
                ],
            )
        )


def test_adjudicator_apple_fm_holds_the_llm_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_keys(monkeypatch)
    monkeypatch.setenv("SKILL_SCANNER_LLM_MODEL", "apple-fm/system")
    held: dict[str, bool] = {}

    async def fake_completion(**kwargs):
        held["locked"] = _LLM_LOCK.locked()
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"verdict": "real"}'))],
            usage=None,
        )

    monkeypatch.setattr("skill_scanner.core.analyzers.apple_fm.apple_fm_acompletion", fake_completion)

    result = Adjudicator()._call_apple_fm("skill text")

    assert held["locked"] is True
    assert result == {"verdict": "real"}
