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

"""Tests for env-driven ``temperature`` resolution and the omit option.

Models like Anthropic Claude 4.x on Bedrock and OpenAI's o1-series reject
the ``temperature`` parameter outright.  The handlers need to be able to
omit the parameter from outgoing requests entirely when configured to do
so via ``SKILL_SCANNER_LLM_TEMPERATURE`` (or its meta-analyzer variant).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from skill_scanner.core.analyzers.llm_request_handler import (
    _TEMPERATURE_UNSET,
    LLMRequestHandler,
    _resolve_temperature,
)
from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip any inherited temperature/meta env vars per test."""
    monkeypatch.delenv("SKILL_SCANNER_LLM_TEMPERATURE", raising=False)
    monkeypatch.delenv("SKILL_SCANNER_META_LLM_TEMPERATURE", raising=False)


class TestResolveTemperature:
    """``_resolve_temperature`` is the shared waterfall used by every handler."""

    def test_default_when_env_unset(self) -> None:
        assert _resolve_temperature(_TEMPERATURE_UNSET, "MISSING_VAR", default=0.0) == 0.0

    def test_env_numeric_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_TEMP", "0.7")
        assert _resolve_temperature(_TEMPERATURE_UNSET, "MY_TEMP", default=0.0) == pytest.approx(0.7)

    @pytest.mark.parametrize("value", ["none", "NONE", "null", "unset", "omit", "skip"])
    def test_env_omit_values_return_none(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("MY_TEMP", value)
        assert _resolve_temperature(_TEMPERATURE_UNSET, "MY_TEMP", default=0.0) is None

    def test_env_empty_string_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_TEMP", "")
        assert _resolve_temperature(_TEMPERATURE_UNSET, "MY_TEMP", default=0.3) == 0.3

    def test_env_invalid_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_TEMP", "not-a-float")
        assert _resolve_temperature(_TEMPERATURE_UNSET, "MY_TEMP", default=0.5) == 0.5

    def test_explicit_argument_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_TEMP", "0.9")
        assert _resolve_temperature(0.2, "MY_TEMP", default=0.0) == 0.2

    def test_explicit_none_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit ``temperature=None`` means "omit" even if env sets a number."""
        monkeypatch.setenv("MY_TEMP", "0.5")
        assert _resolve_temperature(None, "MY_TEMP", default=0.0) is None


class TestLLMRequestHandlerTemperature:
    """``LLMRequestHandler`` resolves temperature once at init."""

    def _make(self, **kwargs: object) -> LLMRequestHandler:
        return LLMRequestHandler(provider_config=MagicMock(), **kwargs)

    def test_default_is_zero(self) -> None:
        assert self._make().temperature == 0.0

    def test_env_numeric_applied_when_arg_omitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_TEMPERATURE", "0.4")
        assert self._make().temperature == pytest.approx(0.4)

    def test_env_none_drops_temperature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_TEMPERATURE", "none")
        assert self._make().temperature is None

    def test_explicit_none_drops_temperature(self) -> None:
        assert self._make(temperature=None).temperature is None

    def test_explicit_value_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_TEMPERATURE", "0.9")
        assert self._make(temperature=0.2).temperature == pytest.approx(0.2)


class TestMetaAnalyzerTemperature:
    """The meta-analyzer prefers its own env var, falling back to the global one."""

    def _make(self, **kwargs: object) -> MetaAnalyzer:
        # api_key bypasses the no-key validation; model selects a non-Bedrock
        # path so we don't trigger AWS-specific validation branches.
        return MetaAnalyzer(api_key="sk-test", model="claude-3-5-sonnet-20241022", **kwargs)

    def test_default_is_point_one(self) -> None:
        assert self._make().temperature == pytest.approx(0.1)

    def test_meta_specific_env_wins_over_scanner_wide(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_TEMPERATURE", "0.5")
        monkeypatch.setenv("SKILL_SCANNER_META_LLM_TEMPERATURE", "0.05")
        assert self._make().temperature == pytest.approx(0.05)

    def test_meta_specific_none_drops_temperature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_META_LLM_TEMPERATURE", "none")
        assert self._make().temperature is None

    def test_falls_back_to_scanner_wide_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_TEMPERATURE", "none")
        assert self._make().temperature is None

    def test_explicit_none_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_TEMPERATURE", "0.7")
        assert self._make(temperature=None).temperature is None
