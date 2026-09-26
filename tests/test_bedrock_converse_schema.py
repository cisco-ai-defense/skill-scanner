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

"""Structured output over the standard Bedrock Converse route.

Bedrock's structured-output validator rejects array cardinality keywords, answering
``output_config.format.schema: For 'array' type, property 'maxItems' is not
supported``.  Our response schema bounds ``evidence_ids``, so before this every
judged request against a ``bedrock/`` model failed while the scan still returned
static findings -- a broken provider that reads as a quiet quality result.
"""

from __future__ import annotations

import json

from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

BEDROCK_MODEL = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"

_BOUNDED_ARRAY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["evidence_ids"],
    "properties": {
        "evidence_ids": {
            "type": "array",
            "minItems": 1,
            "maxItems": 8,
            "uniqueItems": True,
            "items": {"type": "string"},
        }
    },
}


def _handler(*, model: str = BEDROCK_MODEL, schema: dict | None = None) -> LLMRequestHandler:
    handler = LLMRequestHandler(ProviderConfig(model=model, api_key="unused-in-these-tests"))
    handler.response_schema = schema if schema is not None else _BOUNDED_ARRAY_SCHEMA
    return handler


class TestSchemaSanitizing:
    def test_cardinality_keywords_are_removed_recursively(self) -> None:
        result = LLMRequestHandler._sanitize_schema_for_constrained_decoding(_BOUNDED_ARRAY_SCHEMA)
        serialized = json.dumps(result)
        for keyword in ("maxItems", "minItems", "uniqueItems"):
            assert keyword not in serialized

    def test_structure_survives_sanitizing(self) -> None:
        result = LLMRequestHandler._sanitize_schema_for_constrained_decoding(_BOUNDED_ARRAY_SCHEMA)
        array = result["properties"]["evidence_ids"]
        # Losing a bound is acceptable; losing the type or the item shape would
        # defeat the point of using structured output at all.
        assert array["type"] == "array"
        assert array["items"] == {"type": "string"}
        assert result["required"] == ["evidence_ids"]
        assert result["additionalProperties"] is False

    def test_supported_keywords_are_untouched(self) -> None:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["verdict"],
            "properties": {"verdict": {"type": "string", "enum": ["SAFE"], "description": "d"}},
        }
        assert LLMRequestHandler._sanitize_schema_for_constrained_decoding(schema) == schema

    def test_sanitizer_does_not_mutate_its_input(self) -> None:
        original = json.dumps(_BOUNDED_ARRAY_SCHEMA, sort_keys=True)
        LLMRequestHandler._sanitize_schema_for_constrained_decoding(_BOUNDED_ARRAY_SCHEMA)
        assert json.dumps(_BOUNDED_ARRAY_SCHEMA, sort_keys=True) == original


class TestResponseFormat:
    def test_bedrock_schema_is_sanitized_in_the_request(self) -> None:
        response_format = _handler()._build_response_format()
        assert response_format is not None
        assert response_format["type"] == "json_schema"
        assert response_format["json_schema"]["strict"] is True
        assert "maxItems" not in json.dumps(response_format)

    def test_every_structured_output_route_strips_the_bounds(self) -> None:
        """The keywords are stripped everywhere, not only on Bedrock.

        This assertion is the reverse of what it was. The original reasoning was that
        only the Bedrock validator objects, so stripping bounds elsewhere would weaken a
        contract other providers honour. Serving the judge from a local vLLM endpoint
        disproved it: every judged request failed with
        ``Grammar error: Unimplemented keys: ["uniqueItems"]``, because xgrammar rejects
        the same keywords Bedrock does. Keeping them buys nothing -- the bounds are
        restated in the prompt -- and costs the whole semantic stage on any
        constrained-decoding backend.
        """
        for model in ("gpt-5.2", "bedrock/anthropic.claude-haiku-4-5", "openai/gemma4"):
            response_format = _handler(model=model)._build_response_format()
            assert response_format is not None
            serialized = json.dumps(response_format)
            for keyword in ("maxItems", "minItems", "uniqueItems"):
                assert keyword not in serialized, f"{keyword} survived for {model}"

    def test_the_schema_still_constrains_shape_after_stripping(self) -> None:
        # Stripping cardinality must not become stripping structure: the point of the
        # fix was to keep strict structured output rather than fall back to plain JSON.
        response_format = _handler(model="openai/gemma4")._build_response_format()
        assert response_format["type"] == "json_schema"
        assert response_format["json_schema"]["strict"] is True
        assert "properties" in json.dumps(response_format)


class TestFallbackDetection:
    def test_bedrock_schema_rejection_triggers_json_object_fallback(self) -> None:
        # Bedrock names the offending field ``output_config.format.schema`` and never
        # says ``json_schema``, so the original checks missed it and the request
        # failed outright instead of degrading.
        handler = _handler()
        response_format = handler._build_response_format()
        error = Exception(
            'BedrockException - {"message":"The model returned the following errors: '
            "output_config.format.schema: For 'array' type, property 'maxItems' is not supported\"}"
        )
        assert handler._should_fallback_to_json_object(error, response_format) is True

    def test_xgrammar_grammar_error_triggers_json_object_fallback(self) -> None:
        """vLLM reports this as a grammar error naming the unimplemented keys.

        Observed verbatim when serving the judge from a local vLLM endpoint. The
        original detector looked for ``response_format.json_schema`` and the Bedrock
        field name, so this wording fell through and the request failed outright.
        """
        handler = _handler(model="openai/gemma4")
        response_format = handler._build_response_format()
        error = Exception(
            'litellm.BadRequestError: OpenAIException - Grammar error: Unimplemented keys: ["uniqueItems"]'
        )
        assert handler._should_fallback_to_json_object(error, response_format) is True

    def test_unrelated_errors_do_not_trigger_fallback(self) -> None:
        handler = _handler()
        response_format = handler._build_response_format()
        assert handler._should_fallback_to_json_object(Exception("connection reset"), response_format) is False

    def test_json_object_requests_are_left_alone(self) -> None:
        handler = _handler()
        assert handler._should_fallback_to_json_object(Exception("anything"), {"type": "json_object"}) is False
