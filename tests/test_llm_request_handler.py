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
from pathlib import Path
from unittest.mock import MagicMock

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
