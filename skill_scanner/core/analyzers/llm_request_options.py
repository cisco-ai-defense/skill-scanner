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

"""Shared optional LiteLLM request parameters."""

from __future__ import annotations

import os

LLM_USER_ENV_VAR = "SKILL_SCANNER_LLM_USER"

_OPENAI_USER_PROVIDERS = {"openai", "openai-compatible", "custom-openai"}
_NON_OPENAI_MODEL_PREFIXES = (
    "anthropic/",
    "bedrock/",
    "claude-",
    "gemini/",
    "gemini-",
    "models/gemini-",
    "ollama/",
    "openrouter/",
    "vertex/",
    "vertex_ai/",
)


def resolve_llm_user(llm_user: str | None = None) -> str | None:
    """Return the configured raw Chat Completions user string, if any."""
    raw_value = llm_user if llm_user is not None else os.getenv(LLM_USER_ENV_VAR)
    if raw_value is None or not raw_value.strip():
        return None
    return raw_value


def supports_openai_user_param(model: str | None, provider: str | None = None) -> bool:
    """Return True when the LiteLLM route should receive the OpenAI `user` parameter."""
    model_lower = (model or "").strip().lower()
    if model_lower.startswith(_NON_OPENAI_MODEL_PREFIXES):
        return False

    provider_normalized = (provider or "").strip().lower().replace("_", "-")
    if provider_normalized in _OPENAI_USER_PROVIDERS:
        return True

    return model_lower.startswith(("azure/", "openai/", "gpt-"))
