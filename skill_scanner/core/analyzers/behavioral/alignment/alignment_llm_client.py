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

"""Alignment LLM Client for Semantic Verification.

This module handles all LLM API interactions specifically for semantic alignment
verification between skill descriptions and their implementation.

The client manages:
- LLM configuration (API keys, endpoints, models)
- Request construction for alignment verification
- API communication via litellm
- Response retrieval with retry logic
"""

import asyncio
import logging
import os

try:
    from litellm import acompletion

    LITELLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False
    acompletion = None


class AlignmentLLMClient:
    """LLM client for semantic alignment verification queries.

    Handles communication with LLM providers (OpenAI, Azure, Gemini, Bedrock, etc.)
    specifically for alignment verification tasks.

    Uses litellm for unified interface across providers and per-request
    parameter passing to avoid configuration conflicts.
    """

    # Default configuration
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_RETRY_BASE_DELAY = 2
    PROMPT_LENGTH_THRESHOLD = 50000  # Warn if prompt exceeds this

    def __init__(
        self,
        model: str = "gemini/gemini-2.0-flash",
        api_key: str | None = None,
        base_url: str | None = None,
        api_version: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 120,
    ):
        """Initialize the alignment LLM client.

        Args:
            model: LLM model to use
            api_key: API key (or resolved from environment)
            base_url: Optional base URL for API
            api_version: Optional API version
            temperature: Temperature for responses
            max_tokens: Max tokens for responses
            timeout: Request timeout in seconds

        Raises:
            ImportError: If litellm is not available
            ValueError: If API key is not provided
        """
        if not LITELLM_AVAILABLE:
            raise ImportError("litellm is required for alignment verification. Install with: pip install litellm")

        # Resolve API key from environment if not provided
        self._api_key = api_key or self._resolve_api_key(model)
        if not self._api_key and not self._is_bedrock_model(model):
            raise ValueError("LLM provider API key is required for alignment verification")

        # Store configuration for per-request usage
        self._model = model
        self._base_url = base_url
        self._api_version = api_version
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout

        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"AlignmentLLMClient initialized with model: {self._model}")

    def _resolve_api_key(self, model: str) -> str | None:
        """Resolve API key from environment variables.

        Args:
            model: Model name to determine provider

        Returns:
            API key or None
        """
        model_lower = model.lower()

        # Special cases with different auth mechanisms
        if "vertex" in model_lower:
            # Vertex AI uses Google Cloud service account credentials
            return os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        elif "ollama" in model_lower:
            # Ollama is local and typically doesn't need API key
            return None

        # All providers (including Bedrock, Gemini, OpenAI, Anthropic, Azure):
        # Use SKILL_SCANNER_LLM_API_KEY
        return os.environ.get("SKILL_SCANNER_LLM_API_KEY")

    def _is_bedrock_model(self, model: str) -> bool:
        """Check if model is AWS Bedrock.

        Args:
            model: Model name

        Returns:
            True if Bedrock model
        """
        return "bedrock" in model.lower()

    async def verify_alignment(self, prompt: str) -> str:
        """Send alignment verification prompt to LLM with retry logic.

        Args:
            prompt: Comprehensive prompt with alignment verification evidence

        Returns:
            LLM response (JSON string)

        Raises:
            Exception: If LLM API call fails after retries
        """
        # Log prompt length for debugging
        prompt_length = len(prompt)
        self.logger.debug(f"Prompt length: {prompt_length} characters")

        # Check against threshold
        if prompt_length > self.PROMPT_LENGTH_THRESHOLD:
            self.logger.warning(
                f"Large prompt detected: {prompt_length} characters "
                f"(threshold: {self.PROMPT_LENGTH_THRESHOLD}) - may be truncated by LLM"
            )

        # Retry logic with exponential backoff
        max_retries = self.DEFAULT_MAX_RETRIES
        base_delay = self.DEFAULT_RETRY_BASE_DELAY

        for attempt in range(max_retries):
            try:
                return await self._make_llm_request(prompt)
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2**attempt)
                    self.logger.warning(
                        f"LLM request failed (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(f"LLM request failed after {max_retries} attempts: {e}")
                    raise

    async def _make_llm_request(self, prompt: str) -> str:
        """Make a single LLM API request.

        Args:
            prompt: Prompt to send

        Returns:
            LLM response content

        Raises:
            Exception: If API call fails
        """
        try:
            request_params = {
                "model": self._model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a security expert analyzing agent skills. "
                            "You receive complete dataflow analysis and code context. "
                            "Analyze if the skill description accurately describes what the code actually does. "
                            "Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "timeout": self._timeout,
            }

            # Add API key if available
            if self._api_key:
                request_params["api_key"] = self._api_key

            # Only enable JSON mode for supported models/providers
            # Azure OpenAI with older API versions may not support this
            if not self._model.startswith("azure/"):
                request_params["response_format"] = {"type": "json_object"}

            # Add optional parameters if configured
            if self._base_url:
                request_params["api_base"] = self._base_url
            if self._api_version:
                request_params["api_version"] = self._api_version

            self.logger.debug(f"Sending alignment verification request to {self._model}")
            response = await acompletion(**request_params)

            # Extract content from response
            content = response.choices[0].message.content

            # Log response for debugging
            if not content or not content.strip():
                self.logger.warning(f"Empty response from LLM model {self._model}")
                self.logger.debug(f"Full response object: {response}")
            else:
                self.logger.debug(f"LLM response length: {len(content)} chars")

            return content if content else ""

        except Exception as e:
            self.logger.error(f"LLM alignment verification failed: {e}", exc_info=True)
            raise
