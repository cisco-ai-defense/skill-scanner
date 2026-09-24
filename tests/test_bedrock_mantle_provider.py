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

"""Tests for the SigV4-signed Bedrock mantle provider path.

The mantle route is an OpenAI-compatible endpoint in front of Bedrock that
serves models absent from the bedrock-runtime catalogue.  It authenticates with
SigV4 rather than a bearer key, so it cannot go through LiteLLM's ``bedrock/``
adapter and gets its own client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.analyzers.llm_provider_config import (
    BEDROCK_MANTLE_SIGV4_SERVICE,
    ProviderConfig,
    default_bedrock_mantle_base_url,
)
from skill_scanner.core.analyzers.llm_request_handler import (
    LLMRequestHandler,
    LLMResponseTruncatedError,
)

MANTLE_MODEL = "bedrock-mantle/google.gemma-4-26b-a4b"
BARE_MODEL = "google.gemma-4-26b-a4b"


def _config(**kwargs: Any) -> ProviderConfig:
    return ProviderConfig(model=kwargs.pop("model", MANTLE_MODEL), aws_region="us-east-1", **kwargs)


def _handler(config: ProviderConfig | None = None, **kwargs: Any) -> LLMRequestHandler:
    return LLMRequestHandler(provider_config=config or _config(), **kwargs)


def _payload(content: str = '{"overall_assessment":"safe","findings":[]}', **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": BARE_MODEL,
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
    }
    payload.update(overrides)
    return payload


class TestDetection:
    def test_mantle_prefix_selects_the_signed_client(self) -> None:
        config = _config()
        assert config.is_bedrock_mantle is True
        assert config.use_bedrock_mantle is True
        assert config.use_google_sdk is False

    def test_mantle_is_not_treated_as_plain_bedrock(self) -> None:
        # "bedrock-mantle/" must not satisfy the "bedrock/" substring check,
        # or requests would be signed for bedrock-runtime and fail.
        assert _config().is_bedrock is False

    def test_plain_bedrock_model_is_unaffected(self) -> None:
        config = ProviderConfig(model="bedrock/anthropic.claude-sonnet-4-5", aws_region="us-east-1")
        assert config.is_bedrock is True
        assert config.is_bedrock_mantle is False
        assert config.use_bedrock_mantle is False

    def test_provider_name_selects_mantle_without_a_prefix(self) -> None:
        config = ProviderConfig(model=BARE_MODEL, provider="bedrock-mantle", aws_region="us-east-1")
        assert config.is_bedrock_mantle is True
        assert config.model == BARE_MODEL

    def test_routing_prefix_is_stripped_from_the_model_id(self) -> None:
        assert _config().model == BARE_MODEL

    def test_empty_model_id_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            ProviderConfig(model="bedrock-mantle/", aws_region="us-east-1")


class TestCredentialsAndEndpoint:
    def test_validate_passes_without_an_api_key(self) -> None:
        config = _config()
        assert config.api_key is None
        config.validate()

    def test_base_url_defaults_to_the_regional_mantle_host(self) -> None:
        assert _config().base_url == "https://bedrock-mantle.us-east-1.api.aws/openai/v1"

    def test_base_url_follows_the_configured_region(self) -> None:
        config = ProviderConfig(model=MANTLE_MODEL, aws_region="eu-west-1")
        assert config.base_url == default_bedrock_mantle_base_url("eu-west-1")

    def test_explicit_base_url_is_preserved(self) -> None:
        config = ProviderConfig(model=MANTLE_MODEL, base_url="https://example.invalid/openai/v1")
        assert config.base_url == "https://example.invalid/openai/v1"

    def test_endpoint_appends_the_chat_completions_path(self) -> None:
        assert _handler()._bedrock_mantle_endpoint() == (
            "https://bedrock-mantle.us-east-1.api.aws/openai/v1/chat/completions"
        )

    def test_endpoint_is_idempotent_when_already_complete(self) -> None:
        config = ProviderConfig(model=MANTLE_MODEL, base_url="https://example.invalid/v1/chat/completions")
        assert _handler(config)._bedrock_mantle_endpoint() == "https://example.invalid/v1/chat/completions"

    def test_sigv4_service_is_bedrock(self) -> None:
        # The mantle host is api.aws but the signing service is still "bedrock".
        assert BEDROCK_MANTLE_SIGV4_SERVICE == "bedrock"


class TestSchemaSanitizing:
    def test_unique_items_is_removed_recursively(self) -> None:
        schema = {
            "type": "object",
            "properties": {"tags": {"type": "array", "uniqueItems": True, "items": {"type": "string"}}},
            "uniqueItems": True,
        }
        result = LLMRequestHandler._sanitize_schema_for_bedrock_mantle(schema)
        assert "uniqueItems" not in json.dumps(result)
        assert result["properties"]["tags"]["items"] == {"type": "string"}

    def test_supported_keywords_survive(self) -> None:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["a"],
            "properties": {"a": {"type": "string", "enum": ["x"], "description": "d"}},
        }
        assert LLMRequestHandler._sanitize_schema_for_bedrock_mantle(schema) == schema

    def test_scanner_schema_is_sent_strict_and_sanitized(self) -> None:
        handler = _handler()
        response_format = handler._build_bedrock_mantle_response_format()
        assert response_format is not None
        assert response_format["type"] == "json_schema"
        assert response_format["json_schema"]["strict"] is True
        assert "uniqueItems" not in json.dumps(response_format)


class TestRequestBody:
    def test_body_is_valid_json_with_the_bare_model_id(self) -> None:
        raw = _handler(max_tokens=256)._build_bedrock_mantle_body([{"role": "user", "content": "hi"}])
        body = json.loads(raw)
        assert body["model"] == BARE_MODEL
        assert body["max_tokens"] == 256
        assert body["messages"] == [{"role": "user", "content": "hi"}]

    def test_forced_json_object_overrides_the_schema(self) -> None:
        body = json.loads(
            _handler()._build_bedrock_mantle_body([{"role": "user", "content": "hi"}], force_json_object=True)
        )
        assert body["response_format"] == {"type": "json_object"}

    def test_body_is_bytes_so_signing_matches_transmission(self) -> None:
        # SigV4 signs the payload; the signed and transmitted bodies must be
        # byte-identical, so the builder must return bytes and not re-serialize.
        assert isinstance(_handler()._build_bedrock_mantle_body([{"role": "user", "content": "hi"}]), bytes)


class TestResponseHandling:
    def test_content_and_usage_are_extracted(self) -> None:
        handler = _handler()
        content = handler._read_bedrock_mantle_content(_payload(), "ctx")
        assert content == '{"overall_assessment":"safe","findings":[]}'
        assert handler.last_usage == {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18}

    def test_a_substituted_model_is_rejected(self) -> None:
        # The mantle catalogue has no listing route, so the model id is a pinned
        # constant; a silent substitution would invalidate a whole benchmark run.
        with pytest.raises(RuntimeError, match="served model"):
            _handler()._read_bedrock_mantle_content(_payload(model="google.gemma-3-27b-it"), "ctx")

    def test_truncation_is_surfaced_as_a_typed_error(self) -> None:
        payload = _payload()
        payload["choices"][0]["finish_reason"] = "length"
        with pytest.raises(LLMResponseTruncatedError):
            _handler()._read_bedrock_mantle_content(payload, "ctx")

    def test_missing_choices_is_an_error_not_an_empty_answer(self) -> None:
        with pytest.raises(RuntimeError, match="no choices"):
            _handler()._read_bedrock_mantle_content(_payload(choices=[]), "ctx")


class TestDispatch:
    @pytest.mark.asyncio
    async def test_mantle_config_uses_the_signed_client(self) -> None:
        handler = _handler()
        with patch.object(handler, "_post_bedrock_mantle", return_value=_payload()) as post:
            result = await handler.make_request([{"role": "user", "content": "hi"}], context="ctx")
        assert result == '{"overall_assessment":"safe","findings":[]}'
        assert post.call_count == 1

    @pytest.mark.asyncio
    async def test_stand_in_provider_config_does_not_reach_aws(self) -> None:
        # Regression: a MagicMock auto-creates truthy attributes, so a permissive
        # ``getattr(..., False)`` check diverted mocked callers into the signed
        # client and attempted real AWS credential resolution.
        provider_config = MagicMock()
        provider_config.model = "gpt-4o"
        provider_config.use_google_sdk = False
        provider_config.get_request_params.return_value = {}
        handler = LLMRequestHandler(provider_config=provider_config, max_retries=0)

        response = MagicMock()
        response.choices = [MagicMock(message=MagicMock(content="{}"), finish_reason="stop")]
        with (
            patch.object(handler, "_post_bedrock_mantle", side_effect=AssertionError("must not sign")) as post,
            patch(
                "skill_scanner.core.analyzers.llm_request_handler.acompletion",
                AsyncMock(return_value=response),
            ),
        ):
            await handler.make_request([{"role": "user", "content": "hi"}], context="ctx")
        assert post.call_count == 0


class TestJsonObjectFallbackGuard:
    """The mantle route rejects ``json_object`` unless a message mentions JSON."""

    def test_json_instruction_is_appended_to_the_system_message(self) -> None:
        messages = [
            {"role": "system", "content": "You are an analyzer."},
            {"role": "user", "content": "Assess this skill."},
        ]
        result = LLMRequestHandler._ensure_json_mentioned(messages)
        assert result[0]["role"] == "system"
        assert "json" in result[0]["content"].lower()
        assert result[1] == messages[1]

    def test_existing_mention_is_left_untouched(self) -> None:
        messages = [{"role": "user", "content": "Return JSON only."}]
        assert LLMRequestHandler._ensure_json_mentioned(messages) is messages

    def test_mention_detection_is_case_insensitive(self) -> None:
        messages = [{"role": "user", "content": "Return a json object."}]
        assert LLMRequestHandler._ensure_json_mentioned(messages) is messages

    def test_a_system_message_is_added_when_none_exists(self) -> None:
        messages = [{"role": "user", "content": "Assess this skill."}]
        result = LLMRequestHandler._ensure_json_mentioned(messages)
        assert len(result) == 2
        assert result[-1]["role"] == "system"
        assert "json" in result[-1]["content"].lower()

    def test_the_caller_s_messages_are_not_mutated(self) -> None:
        messages = [{"role": "system", "content": "You are an analyzer."}]
        LLMRequestHandler._ensure_json_mentioned(messages)
        assert messages == [{"role": "system", "content": "You are an analyzer."}]

    def test_guard_applies_to_the_forced_fallback_body(self) -> None:
        handler = _handler()
        body = json.loads(
            handler._build_bedrock_mantle_body(
                [{"role": "user", "content": "Assess this skill."}], force_json_object=True
            )
        )
        assert body["response_format"] == {"type": "json_object"}
        assert any("json" in message["content"].lower() for message in body["messages"])

    def test_guard_does_not_touch_strict_schema_requests(self) -> None:
        handler = _handler()
        body = json.loads(handler._build_bedrock_mantle_body([{"role": "user", "content": "Assess this skill."}]))
        assert body["response_format"]["type"] == "json_schema"
        assert body["messages"] == [{"role": "user", "content": "Assess this skill."}]


class TestMetaInvocationAccounting:
    """The meta invocation rate must follow the routing decision, not the reason text.

    Keying on the reason string reported a zero invocation rate for a sweep where
    meta had in fact run on 78% of packages, which would have been published as
    "meta never ran".
    """

    @staticmethod
    def _telemetry():
        from evals.runners.judged_dataset_benchmark import JudgeTelemetry

        return JudgeTelemetry()

    @staticmethod
    def _scanner(telemetry, meta_result):
        from unittest.mock import MagicMock

        from evals.runners.judged_dataset_benchmark import ARMS_BY_NAME, JudgedScanner

        scanner = MagicMock()
        scanner.loader.load_skill.return_value = MagicMock()
        meta = MagicMock()

        async def _analyze(**_kwargs):
            return meta_result

        meta.analyze_with_findings = _analyze
        meta.llm_usage = {"input_tokens": 0, "output_tokens": 0}
        return JudgedScanner(
            scanner,
            arm=ARMS_BY_NAME["core_judge_meta"],
            telemetry=telemetry,
            meta_analyzer=meta,
        )

    def _run(self, routing):
        from unittest.mock import MagicMock, patch

        from skill_scanner.core.models import Severity

        telemetry = self._telemetry()
        meta_result = MagicMock(routing=routing, false_positives=[], missed_threats=[], correlations=[])
        finding = MagicMock(metadata={}, severity=Severity.HIGH)
        scanner = self._scanner(telemetry, meta_result)
        with patch(
            "skill_scanner.core.analyzers.meta_analyzer.apply_meta_analysis_to_results",
            side_effect=lambda original_findings, meta_result, skill: original_findings,
        ):
            result = MagicMock(findings=[finding], analyzers_used=["static_analyzer", "llm_analyzer"])
            scanner._apply_meta(result, Path("/tmp/skill"))
        return telemetry

    def test_a_run_decision_counts_as_invoked(self) -> None:
        telemetry = self._run({"decision": "run", "reason": "ambiguous_finding_context"})
        assert telemetry.meta_invoked == 1
        assert telemetry.meta_routing_reasons == {"ambiguous_finding_context": 1}

    @pytest.mark.parametrize("reason", ["clear_deterministic_findings", "no_findings"])
    def test_a_skip_decision_does_not_count_as_invoked(self, reason: str) -> None:
        telemetry = self._run({"decision": "skip", "reason": reason})
        assert telemetry.meta_invoked == 0
        assert telemetry.meta_routing_reasons == {reason: 1}

    def test_the_reason_is_always_recorded_even_when_absent(self) -> None:
        telemetry = self._run({"decision": "run"})
        assert telemetry.meta_invoked == 1
        assert telemetry.meta_routing_reasons == {"unreported": 1}

    def test_a_missing_routing_block_is_not_counted_as_invoked(self) -> None:
        telemetry = self._run(None)
        assert telemetry.meta_invoked == 0
