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

"""
LLM Request Handler.

Handles LLM API requests with retry logic and exponential backoff.
Supports both LiteLLM and Google Generative AI SDK.
Uses structured outputs (JSON schema) when available.
"""

import asyncio
import importlib
import json
import logging
import os
import threading
import warnings
from pathlib import Path
from typing import Any, TypedDict, cast

from ...llm_reasoning import (
    build_litellm_reasoning_params,
    ensure_google_sdk_reasoning_supported,
    resolve_llm_reasoning_effort,
)
from ...llm_token_options import resolve_llm_max_tokens
from .llm_provider_config import LITELLM_AVAILABLE, ProviderConfig


class LLMTokenUsage(TypedDict):
    """Provider-normalized token counts for one or more LLM calls."""

    input_tokens: int
    output_tokens: int
    total_tokens: int


def _empty_token_usage() -> LLMTokenUsage:
    return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def _extract_token_usage(response: Any) -> LLMTokenUsage:
    """Read token counts from a LiteLLM (or compatible) response object.

    LiteLLM exposes usage as ``response.usage.prompt_tokens`` /
    ``response.usage.completion_tokens``.  Both fields are normalised to the
    ``input_tokens`` / ``output_tokens`` names used in our output schema so
    callers never need to know which provider returned which key.
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return _empty_token_usage()
    input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
    output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
    total_tokens = int(getattr(usage, "total_tokens", 0) or input_tokens + output_tokens)
    return {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens}


class _AttrView:
    """Attribute access over a JSON mapping.

    ``get_truncation_finish_reason`` and ``_extract_token_usage`` both read
    provider responses with ``getattr``.  The Bedrock mantle route returns plain
    JSON, so wrapping it here lets those helpers stay single-implementation
    instead of growing a dict branch that could drift from the attribute one.
    """

    __slots__ = ("_data",)

    def __init__(self, data: Any) -> None:
        self._data = data if isinstance(data, dict) else {}

    def __getattr__(self, name: str) -> Any:
        value = self._data.get(name)
        if isinstance(value, dict):
            return _AttrView(value)
        return value


def _add_token_usage(total: LLMTokenUsage, delta: LLMTokenUsage) -> None:
    """Accumulate *delta* into *total* in-place."""
    total["input_tokens"] += delta["input_tokens"]
    total["output_tokens"] += delta["output_tokens"]
    total["total_tokens"] += delta["total_tokens"]


def _extract_google_sdk_token_usage(response: Any) -> LLMTokenUsage:
    """Read token counts from a Google GenAI SDK ``GenerateContentResponse``.

    The SDK exposes usage as ``response.usage_metadata.prompt_token_count`` /
    ``candidates_token_count``, normalised here to the same ``input_tokens`` /
    ``output_tokens`` names ``_extract_token_usage`` produces for LiteLLM.
    """
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return _empty_token_usage()
    input_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
    output_tokens = int(getattr(usage, "candidates_token_count", 0) or 0)
    total_tokens = int(getattr(usage, "total_token_count", 0) or input_tokens + output_tokens)
    return {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens}


class LLMResponseTruncatedError(RuntimeError):
    """Raised when a provider reports that an LLM output hit its token limit."""

    def __init__(
        self,
        message: str,
        *,
        finish_reason: str,
        model: str,
        max_tokens: int,
        context: str = "",
    ) -> None:
        super().__init__(message)
        self.finish_reason = finish_reason
        self.model = model
        self.max_tokens = max_tokens
        self.context = context


_TRUNCATION_FINISH_REASONS = frozenset(
    {
        "length",
        "maxtoken",
        "maxtokens",
        "maxoutputtoken",
        "maxoutputtokens",
        "maxcompletiontoken",
        "maxcompletiontokens",
        "outputtokenlimit",
        "tokenlimit",
    }
)


def _normalize_finish_reason(reason: Any) -> str | None:
    """Normalize string and provider-enum finish reasons for comparison."""
    if reason is None:
        return None

    for attr in ("name", "value"):
        attr_value = getattr(reason, attr, None)
        if isinstance(attr_value, str):
            reason = attr_value
            break

    if not isinstance(reason, str):
        return None
    return reason.strip()


def get_truncation_finish_reason(choice: Any) -> str | None:
    """Return the provider finish reason when *choice* hit an output limit."""
    reasons = [getattr(choice, "finish_reason", None)]
    provider_fields = getattr(choice, "provider_specific_fields", None)
    if isinstance(provider_fields, dict):
        reasons.append(provider_fields.get("native_finish_reason"))

    for reason in reasons:
        normalized = _normalize_finish_reason(reason)
        if normalized is None:
            continue
        compact = "".join(character for character in normalized.lower() if character.isalnum())
        if compact in _TRUNCATION_FINISH_REASONS:
            return normalized
    return None


logger = logging.getLogger(__name__)

# JSON Schema keywords rejected by the Bedrock mantle strict-schema validator.
# Verified against google.gemma-4-26b-a4b: the scanner schema is accepted once
# ``uniqueItems`` is removed and needs no other change.
_BEDROCK_MANTLE_UNSUPPORTED_SCHEMA_KEYWORDS = frozenset({"uniqueItems"})

# The Bedrock Converse structured-output validator rejects array cardinality
# keywords outright, answering with
# ``output_config.format.schema: For 'array' type, property 'maxItems' is not
# supported``.  Our response schema bounds ``evidence_ids``, so before this every
# judged request over a ``bedrock/`` model failed and the analyzer reported zero
# tokens while the scan still returned static findings -- a failure that reads as a
# quiet quality result rather than a broken provider.
_BEDROCK_UNSUPPORTED_SCHEMA_KEYWORDS = frozenset({"maxItems", "minItems", "uniqueItems"})

# LiteLLM intentionally remains unloaded until an LLM request is made.  Its
# module initialization may refresh a remote model-cost map, which must never
# happen during deterministic scans or while merely importing scanner modules.
acompletion: Any = None
_LITELLM_IMPORT_LOCK = threading.Lock()


def _get_litellm_acompletion(*, local_only: bool) -> Any:
    """Load LiteLLM lazily, forcing its bundled cost map for local Ollama."""

    global acompletion
    if acompletion is not None:
        return acompletion
    if not LITELLM_AVAILABLE:
        raise ImportError("LiteLLM is required for this LLM provider. Install with: pip install litellm")
    with _LITELLM_IMPORT_LOCK:
        cached = globals().get("acompletion")
        if cached is not None:
            return cached
        if local_only:
            # This environment variable is read during LiteLLM import.  Assign
            # rather than setdefault so an Ollama-only scan cannot inherit a
            # permissive value from the parent environment.
            os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
        module = importlib.import_module("litellm")
        acompletion = module.acompletion
        return acompletion


genai: Any
try:
    from google import genai as _genai

    genai = _genai
    GOOGLE_GENAI_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    GOOGLE_GENAI_AVAILABLE = False
    genai = None

# Sentinel: caller did not supply ``temperature``; resolve from env (or use default).
_TEMPERATURE_UNSET = object()

# Env values that explicitly disable the temperature parameter so newer models
# that reject ``temperature`` (e.g. Claude 4.x via Bedrock, OpenAI o1) work
# without code changes.
_TEMPERATURE_OMIT_VALUES = frozenset({"none", "null", "unset", "omit", "skip"})


def _resolve_temperature(
    explicit: Any,
    env_var: str,
    default: float,
) -> float | None:
    """Resolve the request-time ``temperature`` from constructor + env.

    Precedence:
        1. An explicit non-sentinel argument always wins (including ``None``,
           which means "drop the parameter from the request").
        2. ``os.environ[env_var]`` — a numeric value is parsed as a float, and
           a value in ``_TEMPERATURE_OMIT_VALUES`` returns ``None`` to drop the
           parameter.
        3. ``default`` (today: 0.0 for the per-file analyzer, 0.1 for meta).

    Returns:
        ``float`` to send as ``temperature``, or ``None`` to omit it entirely.
    """
    if explicit is not _TEMPERATURE_UNSET:
        return cast(float | None, explicit)

    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return default
    if raw.lower() in _TEMPERATURE_OMIT_VALUES:
        return None
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "Ignoring invalid %s=%r (expected a float or 'none'); using %s",
            env_var,
            raw,
            default,
        )
        return default


# Suppress LiteLLM cosmetic warnings (doesn't affect functionality)
warnings.filterwarnings("ignore", message=".*Pydantic serializer warnings.*")
warnings.filterwarnings("ignore", message=".*Expected `Message`.*")
warnings.filterwarnings("ignore", message=".*Expected `StreamingChoices`.*")
warnings.filterwarnings("ignore", message=".*close_litellm_async_clients.*")
# LiteLLM's logging worker creates unawaited coroutines during sync teardown
warnings.filterwarnings("ignore", message=".*async_success_handler.*was never awaited.*")
warnings.filterwarnings("ignore", message=".*Enable tracemalloc.*")


class LLMRequestHandler:
    """Handles LLM API requests with retry logic and structured outputs."""

    def __init__(
        self,
        provider_config: ProviderConfig,
        max_tokens: int | None = None,
        temperature: Any = _TEMPERATURE_UNSET,
        max_retries: int = 3,
        rate_limit_delay: float = 2.0,
        timeout: int = 120,
        reasoning_effort: str | None = None,
    ):
        """
        Initialize request handler.

        Args:
            provider_config: Provider configuration
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature.  Pass ``None`` to omit the
                ``temperature`` parameter from the LLM request entirely —
                required for models that reject it (e.g. Claude 4.x via
                Bedrock, OpenAI o1-series).  When omitted, the value is
                resolved from ``SKILL_SCANNER_LLM_TEMPERATURE`` (numeric
                value, or ``"none"`` to drop the parameter), falling back
                to ``0.0``.
            max_retries: Max retry attempts on rate limits
            rate_limit_delay: Base delay for exponential backoff
            timeout: Request timeout in seconds
            reasoning_effort: Optional reasoning-depth control. Resolves from
                ``SKILL_SCANNER_LLM_REASONING_EFFORT`` when omitted. The
                ``disabled`` value uses provider-aware request semantics.
        """
        self.provider_config = provider_config
        self.max_tokens = resolve_llm_max_tokens(max_tokens)
        self.temperature = _resolve_temperature(temperature, "SKILL_SCANNER_LLM_TEMPERATURE", default=0.0)
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout
        self.reasoning_effort = resolve_llm_reasoning_effort(reasoning_effort)
        if self.provider_config.use_google_sdk:
            ensure_google_sdk_reasoning_supported(
                self.reasoning_effort,
                model=self.provider_config.model,
            )

        # Load JSON schema for structured outputs
        self.response_schema = self._load_response_schema()
        self._use_plain_json_output = self._env_flag_enabled("SKILL_SCANNER_LLM_FORCE_JSON_OBJECT")

        # Token usage for the most recent make_request() call (reset each call).
        self._last_usage: LLMTokenUsage = _empty_token_usage()

    @property
    def last_usage(self) -> LLMTokenUsage:
        """Token counts from the most recent make_request() call."""
        return dict(self._last_usage)  # type: ignore[return-value]

    def _env_flag_enabled(self, env_name: str) -> bool:
        """Treat common truthy env values as enabled."""
        raw_value = os.getenv(env_name, "")
        return raw_value.strip().lower() in {"1", "true", "yes", "on"}

    def _load_response_schema(self) -> dict[str, Any] | None:
        """Load JSON schema for structured outputs."""
        try:
            schema_path = Path(__file__).parent.parent.parent / "data" / "prompts" / "llm_response_schema.json"
            if schema_path.exists():
                loaded: dict[str, Any] = json.loads(schema_path.read_text(encoding="utf-8"))
                # Keep schema in sync with active taxonomy profile, including
                # custom profiles loaded via SKILL_SCANNER_TAXONOMY_PATH.
                try:
                    from ...threats.cisco_ai_taxonomy import VALID_AITECH_CODES

                    aitech_codes = sorted(VALID_AITECH_CODES)
                    loaded["properties"]["findings"]["items"]["properties"]["aitech"]["enum"] = aitech_codes
                except Exception as e:
                    logger.warning("Could not inject runtime AITech enum into schema: %s", e)
                return loaded
        except Exception as e:
            logger.warning("Could not load response schema: %s", e)
        return None

    def _sanitize_schema_for_google(self, schema: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize JSON Schema for Google GenAI SDK structured output compatibility.

        Handles two incompatibilities between standard JSON Schema and what
        the Google GenAI SDK accepts:

        1. ``additionalProperties`` — not supported; removed recursively.
        2. Nullable union types like ``["string", "null"]`` — the SDK expects
           a single type enum value (e.g. ``"STRING"``) plus ``nullable: true``.
           Scalar type strings are also uppercased to match the SDK's enum.
        """
        sanitized: dict[str, Any] = {}
        for key, value in schema.items():
            if key == "additionalProperties":
                # Skip additionalProperties - Google SDK doesn't support it
                continue
            elif key == "type" and isinstance(value, list):
                types = list(value)
                has_null = "null" in types
                if has_null:
                    types.remove("null")
                if len(types) == 0:
                    raise NotImplementedError(f"Google GenAI SDK does not support null-only types: {value!r}")
                if len(types) > 1:
                    raise NotImplementedError(f"Google GenAI SDK does not support multi-type unions: {value!r}")
                sanitized["type"] = types[0].upper()
                if has_null:
                    sanitized["nullable"] = True
            elif key == "type" and isinstance(value, str):
                if value == "null":
                    raise NotImplementedError("Google GenAI SDK does not support null-only types")
                sanitized["type"] = value.upper()
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_schema_for_google(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_schema_for_google(item) if isinstance(item, dict) else item for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized

    def _should_use_json_object(self) -> bool:
        """Pick the safest response format for the current backend."""
        if self._use_plain_json_output:
            return True

        model_lower = self.provider_config.model.lower()
        unsupported_json_schema_providers = ["deepseek", "minimax"]
        return any(name in model_lower for name in unsupported_json_schema_providers)

    def _build_response_format(self) -> dict[str, Any] | None:
        """Build the response format for LiteLLM requests."""
        if not self.response_schema:
            return None

        if self._should_use_json_object():
            return {"type": "json_object"}

        schema = self.response_schema
        if getattr(self.provider_config, "is_bedrock", False) is True:
            schema = self._sanitize_schema_for_bedrock(schema)

        return {
            "type": "json_schema",
            "json_schema": {
                "name": "security_analysis_response",
                "schema": schema,
                "strict": True,
            },
        }

    def _should_fallback_to_json_object(self, error: Exception, response_format: dict[str, Any] | None) -> bool:
        """Detect backends that reject structured output and need plain JSON mode."""
        if not response_format or response_format.get("type") != "json_schema":
            return False

        error_msg = str(error).lower()
        if "response_format.json_schema" in error_msg:
            return True

        # Bedrock names the offending field ``output_config.format.schema`` and never
        # mentions ``json_schema``, so the checks below missed it and the request
        # failed outright instead of degrading.
        if "output_config.format.schema" in error_msg:
            return True

        if "json_schema" in error_msg and any(
            phrase in error_msg
            for phrase in [
                "missing required parameter",
                "unsupported",
                "not supported",
                "invalid",
                "unknown parameter",
            ]
        ):
            return True

        return False

    async def make_request(self, messages: list[dict[str, str]], context: str = "") -> str:
        """
        Make LLM request with retry logic and exponential backoff.

        Args:
            messages: Messages to send (should include system and user messages)
            context: Context for logging

        Returns:
            Response text content

        Raises:
            Exception: If all retries exhausted
        """
        self._last_usage = _empty_token_usage()
        # Compared with ``is True`` on purpose: a stand-in provider config (for
        # example a MagicMock in tests) auto-creates truthy attributes, and a
        # permissive check would silently divert those callers to the signed
        # mantle client and attempt real AWS credential resolution.
        if getattr(self.provider_config, "use_bedrock_mantle", False) is True:
            return await self._make_bedrock_mantle_request(messages, context)
        if self.provider_config.use_google_sdk:
            # For Google SDK, combine system and user messages into a single prompt
            # Google SDK doesn't have separate system/user roles like OpenAI/Anthropic
            prompt_parts = []
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "system":
                    prompt_parts.append(f"System Instructions:\n{content}\n")
                elif role == "user":
                    prompt_parts.append(f"User Request:\n{content}\n")

            combined_prompt = "\n".join(prompt_parts).strip()
            return await self._make_google_sdk_request(combined_prompt, context)
        else:
            return await self._make_litellm_request(messages, context)

    async def _make_litellm_request(self, messages: list[dict[str, str]], context: str) -> str:
        """Make request using LiteLLM with structured outputs when supported."""
        last_exception = None
        completion = _get_litellm_acompletion(local_only=bool(getattr(self.provider_config, "is_ollama", False)))

        for attempt in range(self.max_retries + 1):
            try:
                request_params = {
                    "model": self.provider_config.model,
                    "messages": messages,
                    "max_tokens": self.max_tokens,
                    "timeout": self.timeout,
                    **self.provider_config.get_request_params(),
                }
                if self.temperature is not None:
                    request_params["temperature"] = self.temperature
                request_params.update(
                    build_litellm_reasoning_params(
                        self.reasoning_effort,
                        model=self.provider_config.model,
                        provider=getattr(self.provider_config, "provider", None),
                    )
                )

                response_format = self._build_response_format()
                if response_format:
                    request_params["response_format"] = response_format

                response = await completion(**request_params, drop_params=True)
                self._last_usage = _extract_token_usage(response)
                choice = response.choices[0]
                self._raise_if_truncated(choice, context=context)
                content: str = choice.message.content or ""
                return content

            except LLMResponseTruncatedError:
                raise
            except Exception as e:
                response_format = request_params.get("response_format")
                if self._should_fallback_to_json_object(e, response_format):
                    logger.warning(
                        "Structured output rejected for %s, retrying with plain JSON output",
                        context,
                    )
                    self._use_plain_json_output = True
                    retry_params = dict(request_params)
                    retry_params["response_format"] = {"type": "json_object"}
                    response = await completion(**retry_params, drop_params=True)
                    self._last_usage = _extract_token_usage(response)
                    choice = response.choices[0]
                    self._raise_if_truncated(choice, context=context)
                    fallback_content: str = choice.message.content or ""
                    return fallback_content

                last_exception = e
                error_msg = str(e).lower()

                # Check for rate limiting
                if any(
                    keyword in error_msg
                    for keyword in ["rate limit", "quota", "too many requests", "429", "throttling"]
                ):
                    if attempt < self.max_retries:
                        delay = (2**attempt) * self.rate_limit_delay
                        logger.warning(
                            "Rate limit hit for %s, retrying in %ss (attempt %d/%d)",
                            context,
                            delay,
                            attempt + 1,
                            self.max_retries + 1,
                        )
                        await asyncio.sleep(delay)
                        continue

                # For other errors, don't retry
                logger.error("LLM API error for %s: %s", context, e)
                break

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("All retries exhausted")

    def _bedrock_mantle_endpoint(self) -> str:
        """Return the chat-completions URL for the configured mantle base."""
        base = (self.provider_config.base_url or "").rstrip("/")
        if not base:
            raise ValueError("Bedrock mantle requires a base URL")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    @staticmethod
    def _sanitize_schema_for_bedrock(schema: Any) -> Any:
        """Drop JSON Schema keywords the Bedrock Converse validator rejects.

        Stripping a cardinality bound loosens the contract slightly but keeps
        strict structured output, which is what actually keeps finding parsing
        reliable.  Falling back to ``json_object`` instead would lose the whole
        structural guarantee to save a bound the prompt already states.
        """
        if isinstance(schema, dict):
            return {
                key: LLMRequestHandler._sanitize_schema_for_bedrock(value)
                for key, value in schema.items()
                if key not in _BEDROCK_UNSUPPORTED_SCHEMA_KEYWORDS
            }
        if isinstance(schema, list):
            return [LLMRequestHandler._sanitize_schema_for_bedrock(item) for item in schema]
        return schema

    @staticmethod
    def _sanitize_schema_for_bedrock_mantle(schema: Any) -> Any:
        """Drop JSON Schema keywords the mantle strict validator rejects.

        Mirrors ``_sanitize_schema_for_google``. Without this the scanner's own
        response schema is refused with ``invalid_json_schema`` and the request
        silently degrades to ``json_object``, losing the structural guarantee
        that keeps finding parsing reliable.
        """
        if isinstance(schema, dict):
            return {
                key: LLMRequestHandler._sanitize_schema_for_bedrock_mantle(value)
                for key, value in schema.items()
                if key not in _BEDROCK_MANTLE_UNSUPPORTED_SCHEMA_KEYWORDS
            }
        if isinstance(schema, list):
            return [LLMRequestHandler._sanitize_schema_for_bedrock_mantle(value) for value in schema]
        return schema

    def _build_bedrock_mantle_response_format(self) -> dict[str, Any] | None:
        """Build a mantle-compatible response format."""
        response_format = self._build_response_format()
        if not response_format or response_format.get("type") != "json_schema":
            return response_format

        json_schema = dict(response_format["json_schema"])
        json_schema["schema"] = self._sanitize_schema_for_bedrock_mantle(json_schema.get("schema"))
        return {"type": "json_schema", "json_schema": json_schema}

    def _build_bedrock_mantle_body(
        self,
        messages: list[dict[str, str]],
        *,
        force_json_object: bool = False,
    ) -> bytes:
        """Serialize the OpenAI-compatible request body.

        The exact bytes are returned because SigV4 signs the payload; the signed
        body and the transmitted body must be byte-identical.
        """
        payload: dict[str, Any] = {
            "model": self.provider_config.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature

        # The mantle route builds its own body instead of going through LiteLLM, so the
        # reasoning control has to be translated here or it is silently dropped and
        # --llm-reasoning-effort does nothing on this route. The same translator is
        # reused so there is one mapping, and the endpoint was verified to accept the
        # OpenAI-compatible field including the "none" that "disabled" maps to.
        payload.update(
            build_litellm_reasoning_params(
                self.reasoning_effort,
                model=self.provider_config.model,
                provider=self.provider_config.provider,
            )
        )

        response_format = {"type": "json_object"} if force_json_object else self._build_bedrock_mantle_response_format()
        if response_format:
            payload["response_format"] = response_format
        if response_format and response_format.get("type") == "json_object":
            payload["messages"] = self._ensure_json_mentioned(payload["messages"])

        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _ensure_json_mentioned(messages: list[dict[str, str]]) -> list[dict[str, str]]:
        """Guarantee the literal word "json" appears when using ``json_object``.

        The mantle route rejects a ``json_object`` request whose messages never
        mention JSON:

            'messages' must contain the word 'json' in some form, to use
            'response_format' of type 'json_object'.

        That request is the schema-rejection fallback, so without this guard a
        backend that refuses strict schemas fails twice and surfaces a confusing
        400 instead of degrading cleanly.
        """
        if any("json" in (message.get("content") or "").lower() for message in messages):
            return messages

        adjusted = [dict(message) for message in messages]
        for message in adjusted:
            if message.get("role") == "system":
                message["content"] = f"{message.get('content') or ''}\n\nRespond with a single JSON object.".strip()
                return adjusted

        adjusted.append({"role": "system", "content": "Respond with a single JSON object."})
        return adjusted

    def _post_bedrock_mantle(self, body: bytes) -> dict[str, Any]:
        """SigV4-sign *body* and POST it to the mantle endpoint.

        Synchronous on purpose; the caller runs it in an executor.  Uses stdlib
        urllib so the mantle path adds no dependency beyond botocore, which the
        Bedrock extra already requires.
        """
        import urllib.error
        import urllib.request

        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.session import Session

        from .llm_provider_config import BEDROCK_MANTLE_SIGV4_SERVICE

        region = self.provider_config.aws_region or "us-east-1"
        session = Session()
        if self.provider_config.aws_profile:
            session.set_config_variable("profile", self.provider_config.aws_profile)
        credentials = session.get_credentials()
        if credentials is None:
            raise ValueError(
                "No AWS credentials found for the Bedrock mantle endpoint. "
                "Configure a profile, environment credentials, or an instance role."
            )

        configured_token = self.provider_config.aws_session_token
        if configured_token and credentials.token != configured_token:
            # A caller can supply the session token explicitly while leaving the access
            # key and secret to the environment, which is how the LiteLLM Bedrock path
            # accepts them. Signing with the token botocore happened to resolve -- or
            # with none at all -- produces a signature AWS rejects for a temporary
            # credential, so the configured token wins.
            from botocore.credentials import Credentials

            frozen = credentials.get_frozen_credentials()
            credentials = Credentials(frozen.access_key, frozen.secret_key, configured_token)

        url = self._bedrock_mantle_endpoint()
        signed = AWSRequest(method="POST", url=url, data=body, headers={"Content-Type": "application/json"})
        SigV4Auth(credentials.get_frozen_credentials(), BEDROCK_MANTLE_SIGV4_SERVICE, region).add_auth(signed)

        request = urllib.request.Request(url, data=body, headers=dict(signed.headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = ""
            try:
                detail = error.read().decode("utf-8", errors="replace")[:500]
            except Exception:  # noqa: BLE001 - diagnostic best effort only
                detail = ""
            raise RuntimeError(f"Bedrock mantle request failed with HTTP {error.code}: {detail}") from error

        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise RuntimeError("Bedrock mantle returned a non-object response")
        return decoded

    def _read_bedrock_mantle_content(self, payload: dict[str, Any], context: str) -> str:
        """Validate the model pin, record usage, and return the message content."""
        returned_model = payload.get("model")
        expected_model = self.provider_config.model
        if isinstance(returned_model, str) and returned_model != expected_model:
            # The mantle catalogue has no listing route, so the model id is a
            # pinned constant. A silent substitution would invalidate the run.
            raise RuntimeError(f"Bedrock mantle served model {returned_model!r} but {expected_model!r} was requested")

        view = _AttrView(payload)
        self._last_usage = _extract_token_usage(view)

        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError("Bedrock mantle returned no choices")
        choice = choices[0]
        self._raise_if_truncated(_AttrView(choice), context=context)
        message = choice.get("message") or {}
        content = message.get("content")
        return content if isinstance(content, str) else ""

    async def _make_bedrock_mantle_request(self, messages: list[dict[str, str]], context: str = "") -> str:
        """Make a request against the SigV4-signed Bedrock mantle route."""
        loop = asyncio.get_event_loop()
        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            body = self._build_bedrock_mantle_body(messages)
            try:
                payload = await loop.run_in_executor(None, self._post_bedrock_mantle, body)
                return self._read_bedrock_mantle_content(payload, context)

            except LLMResponseTruncatedError:
                raise
            except Exception as error:  # noqa: BLE001 - classified below
                if self._should_fallback_to_json_object(error, self._build_bedrock_mantle_response_format()):
                    logger.warning(
                        "Structured output rejected for %s, retrying with plain JSON output",
                        context,
                    )
                    self._use_plain_json_output = True
                    retry_body = self._build_bedrock_mantle_body(messages, force_json_object=True)
                    payload = await loop.run_in_executor(None, self._post_bedrock_mantle, retry_body)
                    return self._read_bedrock_mantle_content(payload, context)

                last_exception = error
                error_msg = str(error).lower()
                if any(
                    keyword in error_msg
                    for keyword in ["rate limit", "quota", "too many requests", "429", "throttling"]
                ):
                    if attempt < self.max_retries:
                        delay = (2**attempt) * self.rate_limit_delay
                        logger.warning(
                            "Rate limit hit for %s, retrying in %ss (attempt %d/%d)",
                            context,
                            delay,
                            attempt + 1,
                            self.max_retries + 1,
                        )
                        await asyncio.sleep(delay)
                        continue

                logger.error("Bedrock mantle API error for %s: %s", context, error)
                break

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("All retries exhausted")

    def _raise_if_truncated(self, choice: Any, *, context: str = "") -> None:
        """Raise a typed, actionable error for provider-reported truncation."""
        finish_reason = get_truncation_finish_reason(choice)
        if finish_reason is None:
            return

        context_suffix = f" while {context}" if context else ""
        message = (
            f"LLM output was truncated{context_suffix}: provider finish_reason={finish_reason!r}, "
            f"model={self.provider_config.model!r}, max_tokens={self.max_tokens}. Increase "
            "--llm-max-tokens, the API llm_max_tokens field, or "
            "SKILL_SCANNER_LLM_MAX_TOKENS and retry."
        )
        logger.error(message)
        raise LLMResponseTruncatedError(
            message,
            finish_reason=finish_reason,
            model=self.provider_config.model,
            max_tokens=self.max_tokens,
            context=context,
        )

    async def _make_google_sdk_request(self, prompt: str, context: str = "") -> str:
        """Make request using Google GenAI SDK (new SDK) with structured outputs."""
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                # Create client with API key (new SDK uses Client pattern)
                client = genai.Client(api_key=self.provider_config.api_key)

                # Build generation config with structured output
                # New SDK uses GenerateContentConfig type
                config_dict: dict[str, Any] = {
                    "max_output_tokens": self.max_tokens,
                }
                if self.temperature is not None:
                    config_dict["temperature"] = self.temperature

                # Add structured output support using Google Gemini SDK format
                # According to Gemini docs: https://ai.google.dev/gemini-api/docs/structured-output
                # Format: response_mime_type="application/json" and response_schema={...}
                # Note: Google SDK doesn't support additionalProperties in schema
                if self.response_schema:
                    config_dict["response_mime_type"] = "application/json"
                    # Remove additionalProperties for Google SDK compatibility
                    sanitized_schema = self._sanitize_schema_for_google(self.response_schema)
                    config_dict["response_schema"] = sanitized_schema

                # Generate content using new SDK API
                # New SDK uses client.models.generate_content(model, contents, config)
                loop = asyncio.get_event_loop()

                def generate():
                    # New SDK API: client.models.generate_content(model=..., contents=..., config=...)
                    response = client.models.generate_content(
                        model=self.provider_config.model,
                        contents=prompt,
                        config=config_dict,
                    )
                    return response

                response = await loop.run_in_executor(None, generate)
                self._last_usage = _extract_google_sdk_token_usage(response)

                # Google exposes MAX_TOKENS on the candidate when available.
                # Check it before reading response.text, which may itself raise
                # for incomplete content in some SDK versions.
                candidates = getattr(response, "candidates", None)
                if candidates:
                    self._raise_if_truncated(candidates[0], context=context)

                # Extract text from response (new SDK format)
                # Response has .text attribute directly
                if hasattr(response, "text") and response.text:
                    text_val: str = response.text
                    return text_val
                elif hasattr(response, "candidates") and response.candidates:
                    # Fallback: check candidates array
                    candidate = response.candidates[0]
                    if hasattr(candidate, "content") and candidate.content:
                        parts = candidate.content.parts if hasattr(candidate.content, "parts") else []
                        if parts and hasattr(parts[0], "text"):
                            part_text: str = parts[0].text
                            return part_text
                elif hasattr(response, "content"):
                    # Another fallback
                    return str(response.content)
                else:
                    return str(response)

            except LLMResponseTruncatedError:
                raise
            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()

                # Check if retryable
                if "quota" in error_msg or "rate limit" in error_msg or "429" in error_msg:
                    if attempt < self.max_retries:
                        wait_time = self.rate_limit_delay * (2**attempt)
                        await asyncio.sleep(wait_time)
                        continue

                # Non-retryable error - log for debugging
                logger.error("LLM analysis failed: %s", e)
                raise

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("All retries exhausted")
