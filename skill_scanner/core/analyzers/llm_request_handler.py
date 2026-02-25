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
import json
import logging
import warnings
from pathlib import Path
from typing import Any

from .llm_provider_config import ProviderConfig

logger = logging.getLogger(__name__)

acompletion: Any
try:
    from litellm import acompletion as _acompletion

    acompletion = _acompletion
    LITELLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False
    acompletion = None

genai: Any
try:
    from google import genai as _genai

    genai = _genai
    GOOGLE_GENAI_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    GOOGLE_GENAI_AVAILABLE = False
    genai = None

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
        max_tokens: int = 4000,
        temperature: float = 0.0,
        max_retries: int = 3,
        rate_limit_delay: float = 2.0,
        timeout: int = 120,
    ):
        """
        Initialize request handler.

        Args:
            provider_config: Provider configuration
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature
            max_retries: Max retry attempts on rate limits
            rate_limit_delay: Base delay for exponential backoff
            timeout: Request timeout in seconds
        """
        self.provider_config = provider_config
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout

        # Load JSON schema for structured outputs
        self.response_schema = self._load_response_schema()

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
            return await self._make_google_sdk_request(combined_prompt)
        else:
            return await self._make_litellm_request(messages, context)

    async def _make_litellm_request(self, messages: list[dict[str, str]], context: str) -> str:
        """Make request using LiteLLM with structured outputs when supported."""
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                request_params = {
                    "model": self.provider_config.model,
                    "messages": messages,
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "timeout": self.timeout,
                    **self.provider_config.get_request_params(),
                }

                # Add structured output support using LiteLLM's unified format
                # According to LiteLLM docs: https://docs.litellm.ai/docs/completion/json_mode
                # Format: response_format={ "type": "json_schema", "json_schema": { "name": "...", "schema": {...}, "strict": true } }
                # Works for: OpenAI, Anthropic Claude, Gemini (via LiteLLM), Bedrock, Vertex AI, Groq, Ollama, Databricks
                if self.response_schema:
                    request_params["response_format"] = {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "security_analysis_response",
                            "schema": self.response_schema,
                            "strict": True,  # Enforce strict schema compliance - prevents extra fields
                        },
                    }

                response = await acompletion(**request_params)
                content: str = response.choices[0].message.content or ""
                return content

            except Exception as e:
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

    async def _make_google_sdk_request(self, prompt: str) -> str:
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
                    "temperature": self.temperature,
                }

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
