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

"""Tests for _sanitize_schema_for_google in LLMRequestHandler.

Verifies that the sanitizer correctly converts JSON Schema constructs
that are incompatible with the Google GenAI SDK's structured output format.
"""

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler


@pytest.fixture
def handler() -> LLMRequestHandler:
    """Build an LLMRequestHandler with a mock provider config.

    Uses MagicMock to avoid ProviderConfig side effects (Gemini SDK
    detection, API key resolution) that are irrelevant to schema
    sanitization tests.
    """
    return LLMRequestHandler(provider_config=MagicMock())


class TestSanitizeSchemaForGoogle:
    """Tests for _sanitize_schema_for_google."""

    def test_converts_nullable_union_type(self, handler: LLMRequestHandler) -> None:
        schema = {"type": ["string", "null"], "description": "optional"}
        result = handler._sanitize_schema_for_google(schema)
        assert result == {"type": "STRING", "nullable": True, "description": "optional"}

    def test_normalizes_scalar_type_case(self, handler: LLMRequestHandler) -> None:
        schema = {"type": "string", "description": "required"}
        result = handler._sanitize_schema_for_google(schema)
        assert result == {"type": "STRING", "description": "required"}

    def test_strips_additional_properties(self, handler: LLMRequestHandler) -> None:
        schema = {
            "type": "object",
            "properties": {
                "inner": {"type": "object", "additionalProperties": False, "properties": {}},
            },
            "additionalProperties": False,
        }
        result = handler._sanitize_schema_for_google(schema)
        assert "additionalProperties" not in result
        assert "additionalProperties" not in result["properties"]["inner"]

    def test_handles_nested_array_items(self, handler: LLMRequestHandler) -> None:
        schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence": {"type": ["string", "null"]},
                },
            },
        }
        result = handler._sanitize_schema_for_google(schema)
        assert result["items"]["properties"]["evidence"] == {
            "type": "STRING",
            "nullable": True,
        }

    @pytest.mark.parametrize(
        "json_type,expected",
        [
            ("string", "STRING"),
            ("number", "NUMBER"),
            ("integer", "INTEGER"),
            ("boolean", "BOOLEAN"),
            ("array", "ARRAY"),
            ("object", "OBJECT"),
        ],
    )
    def test_all_json_types_uppercased(self, handler: LLMRequestHandler, json_type: str, expected: str) -> None:
        result = handler._sanitize_schema_for_google({"type": json_type})
        assert result["type"] == expected

    def test_null_only_union_raises(self, handler: LLMRequestHandler) -> None:
        with pytest.raises(NotImplementedError, match="null-only types"):
            handler._sanitize_schema_for_google({"type": ["null"]})

    def test_scalar_null_type_raises(self, handler: LLMRequestHandler) -> None:
        with pytest.raises(NotImplementedError, match="null-only types"):
            handler._sanitize_schema_for_google({"type": "null"})

    def test_multi_type_union_raises(self, handler: LLMRequestHandler) -> None:
        with pytest.raises(NotImplementedError, match="multi-type unions"):
            handler._sanitize_schema_for_google({"type": ["string", "number"]})

    def test_multi_type_nullable_union_raises(self, handler: LLMRequestHandler) -> None:
        with pytest.raises(NotImplementedError, match="multi-type unions"):
            handler._sanitize_schema_for_google({"type": ["string", "number", "null"]})

    def test_shipped_response_schema(self, handler: LLMRequestHandler) -> None:
        """Verify sanitization of the actual llm_response_schema.json shipped with the package."""
        schema_path = (
            Path(__file__).resolve().parents[1] / "skill_scanner" / "data" / "prompts" / "llm_response_schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = handler._sanitize_schema_for_google(schema)

        finding_props = result["properties"]["findings"]["items"]["properties"]

        for field in ("aisubtech", "location", "evidence", "remediation"):
            assert finding_props[field]["type"] == "STRING", f"{field} type not normalized"
            assert finding_props[field]["nullable"] is True, f"{field} not marked nullable"

        assert finding_props["severity"]["type"] == "STRING"
        assert "nullable" not in finding_props["severity"]

        assert "additionalProperties" not in result
        assert "additionalProperties" not in result["properties"]["findings"]["items"]


class TestDropParams:
    """Regression: acompletion must be called with drop_params=True for model compatibility."""

    @pytest.mark.asyncio
    async def test_acompletion_called_with_drop_params(self):
        """LLMRequestHandler._make_litellm_request must pass drop_params=True."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        provider_config = MagicMock(spec=ProviderConfig)
        provider_config.model = "gpt-5.4-2026-03-05"
        provider_config.use_google_sdk = False
        provider_config.get_request_params.return_value = {"api_key": "test-key"}

        handler = LLMRequestHandler(
            provider_config=provider_config,
            temperature=0.0,
        )
        handler.response_schema = None  # disable structured output for simplicity

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[
            0
        ].message.content = '{"findings": [], "overall_assessment": "safe", "primary_threats": []}'

        with patch(
            "skill_scanner.core.analyzers.llm_request_handler.acompletion",
            new_callable=AsyncMock,
        ) as mock_acompletion:
            mock_acompletion.return_value = mock_response
            await handler.make_request([{"role": "user", "content": "test"}])

        assert mock_acompletion.called, "acompletion should have been called"
        call_kwargs = mock_acompletion.call_args
        kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
        assert kwargs.get("drop_params") is True, f"acompletion must be called with drop_params=True, got: {kwargs}"


class TestLiteLLMRequestFallback:
    """Tests for switching from json_schema to plain JSON output."""

    @pytest.fixture
    def litellm_handler(self) -> LLMRequestHandler:
        provider_config = MagicMock()
        provider_config.model = "gpt-4o"
        provider_config.use_google_sdk = False
        provider_config.get_request_params.return_value = {}
        return LLMRequestHandler(provider_config=provider_config, max_retries=0)

    @staticmethod
    def _mock_litellm_response(content: str) -> MagicMock:
        response = MagicMock()
        response.choices = [MagicMock(message=MagicMock(content=content))]
        return response

    @pytest.mark.asyncio
    async def test_falls_back_to_json_object_when_backend_rejects_schema(self, litellm_handler: LLMRequestHandler):
        error = RuntimeError("Azure error: Missing required parameter: 'response_format.json_schema'.")
        plain_json_response = TestLiteLLMRequestFallback._mock_litellm_response(
            '{"overall_assessment":"unsafe","findings":[]}'
        )

        with patch(
            "skill_scanner.core.analyzers.llm_request_handler.acompletion",
            AsyncMock(side_effect=[error, plain_json_response]),
        ) as mocked_acompletion:
            result = await litellm_handler.make_request([{"role": "user", "content": "Scan this"}], context="demo")

        assert result == '{"overall_assessment":"unsafe","findings":[]}'
        assert mocked_acompletion.await_count == 2
        assert mocked_acompletion.await_args_list[0].kwargs["response_format"]["type"] == "json_schema"
        assert mocked_acompletion.await_args_list[1].kwargs["response_format"]["type"] == "json_object"
        assert litellm_handler._use_plain_json_output is True

    @pytest.mark.asyncio
    async def test_force_json_object_env_skips_schema_attempt(self, litellm_handler: LLMRequestHandler):
        plain_json_response = TestLiteLLMRequestFallback._mock_litellm_response(
            '{"overall_assessment":"unsafe","findings":[]}'
        )

        with (
            patch.dict(os.environ, {"SKILL_SCANNER_LLM_FORCE_JSON_OBJECT": "1"}, clear=False),
            patch(
                "skill_scanner.core.analyzers.llm_request_handler.acompletion",
                AsyncMock(return_value=plain_json_response),
            ) as mocked_acompletion,
        ):
            forced_handler = LLMRequestHandler(provider_config=litellm_handler.provider_config, max_retries=0)
            result = await forced_handler.make_request([{"role": "user", "content": "Scan this"}], context="demo")

        assert result == '{"overall_assessment":"unsafe","findings":[]}'
        assert mocked_acompletion.await_count == 1
        assert mocked_acompletion.await_args_list[0].kwargs["response_format"]["type"] == "json_object"
