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

"""Ollama-specific configuration regressions.

These tests never contact the local daemon; live Ollama checks are explicit
developer smoke tests so the normal suite remains deterministic.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer


def test_meta_analyzer_allows_keyless_local_ollama(monkeypatch) -> None:
    """Ollama has no API key, matching the primary LLM analyzer contract."""
    for name in ("SKILL_SCANNER_META_LLM_API_KEY", "SKILL_SCANNER_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    analyzer = MetaAnalyzer(
        model="ollama/test-model",
        base_url="http://127.0.0.1:11434",
        max_tokens=256,
    )

    assert analyzer.api_key is None
    assert analyzer.is_ollama is True
    assert analyzer.model == "ollama/test-model"
    assert analyzer.base_url == "http://127.0.0.1:11434"


def test_primary_ollama_requests_disable_hidden_thinking() -> None:
    """Bounded structured scans must reserve output budget for visible JSON."""
    config = ProviderConfig(
        model="ollama/test-model",
        base_url="http://127.0.0.1:11434",
        provider="ollama",
    )

    assert config.get_request_params() == {
        "api_base": "http://127.0.0.1:11434",
        "reasoning_effort": "none",
    }


def test_meta_ollama_requests_disable_hidden_thinking(monkeypatch) -> None:
    """The meta path sends the same Ollama no-thinking request option."""
    captured: dict = {}
    for name in ("SKILL_SCANNER_META_LLM_API_KEY", "SKILL_SCANNER_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    async def fake_completion(**kwargs):
        captured.update(kwargs)
        message = SimpleNamespace(content='{"validated_findings": []}')
        choice = SimpleNamespace(message=message, finish_reason="stop")
        return SimpleNamespace(choices=[choice], usage=None)

    monkeypatch.setattr("skill_scanner.core.analyzers.meta_analyzer.acompletion", fake_completion)
    analyzer = MetaAnalyzer(
        model="ollama/test-model",
        base_url="http://127.0.0.1:11434",
        max_tokens=256,
    )

    asyncio.run(analyzer._make_llm_request("system", "user"))

    assert captured["model"] == "ollama/test-model"
    assert captured["api_base"] == "http://127.0.0.1:11434"
    assert captured["reasoning_effort"] == "none"
    assert "api_key" not in captured
