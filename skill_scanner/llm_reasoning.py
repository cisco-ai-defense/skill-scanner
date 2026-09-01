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

"""Validated, provider-aware controls for optional LLM reasoning effort."""

from __future__ import annotations

import os
from typing import Literal, TypeAlias

LLM_REASONING_EFFORT_ENV_VAR = "SKILL_SCANNER_LLM_REASONING_EFFORT"
META_LLM_REASONING_EFFORT_ENV_VAR = "SKILL_SCANNER_META_LLM_REASONING_EFFORT"

LLMReasoningEffort: TypeAlias = Literal[
    "disabled",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
]
LLM_REASONING_EFFORT_VALUES: tuple[str, ...] = (
    "disabled",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
)


class ReasoningConfigurationError(ValueError):
    """Raised when a requested reasoning control is invalid or unsafe."""


class ReasoningControlUnsupportedError(ReasoningConfigurationError):
    """Raised when a configured control cannot be represented safely."""


def normalize_llm_reasoning_effort(
    value: str | None,
    *,
    source: str = "reasoning_effort",
) -> LLMReasoningEffort | None:
    """Validate and normalize one user-facing reasoning-effort value."""
    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        raise ReasoningConfigurationError(f"{source} must be one of: {', '.join(LLM_REASONING_EFFORT_VALUES)}")
    if normalized not in LLM_REASONING_EFFORT_VALUES:
        raise ReasoningConfigurationError(
            f"{source} must be one of: {', '.join(LLM_REASONING_EFFORT_VALUES)}; got {value!r}"
        )
    return normalized  # type: ignore[return-value]


def resolve_llm_reasoning_effort(
    explicit: str | None = None,
    *,
    meta: bool = False,
) -> LLMReasoningEffort | None:
    """Resolve explicit, analyzer-specific, then scanner-wide configuration."""
    if explicit is not None:
        return normalize_llm_reasoning_effort(explicit)

    env_vars = (
        (META_LLM_REASONING_EFFORT_ENV_VAR, LLM_REASONING_EFFORT_ENV_VAR) if meta else (LLM_REASONING_EFFORT_ENV_VAR,)
    )
    for env_var in env_vars:
        raw_value = os.getenv(env_var)
        if raw_value is not None and raw_value.strip():
            return normalize_llm_reasoning_effort(raw_value, source=env_var)
    return None


def _uses_anthropic_native_api(model: str | None, provider: str | None) -> bool:
    """Return whether LiteLLM routes directly to an Anthropic-native API."""
    model_lower = (model or "").strip().lower()
    provider_normalized = (provider or "").strip().lower().replace("_", "-")

    # Explicit gateway adapters expose OpenAI-compatible semantics even when
    # their downstream model name contains "claude".
    if provider_normalized in {
        "openai",
        "openai-compatible",
        "custom-openai",
        "azure-openai",
        "azure-ai",
        "openrouter",
        "orcarouter",
    }:
        return False
    if model_lower.startswith(("openai/", "azure/", "openrouter/", "orcarouter/")):
        return False

    if model_lower.startswith("anthropic/"):
        return True
    if model_lower.startswith(("bedrock/", "bedrock-converse/", "bedrock_converse/")):
        return "claude" in model_lower
    if model_lower.startswith(("vertex_ai/claude", "vertex/claude")):
        return True
    if model_lower.startswith("claude-"):
        return provider_normalized in {"", "anthropic"}

    return (
        provider_normalized
        in {
            "anthropic",
            "aws-bedrock",
            "bedrock",
            "bedrock-converse",
            "gcp-vertex",
            "vertex",
            "vertex-ai",
        }
        and "claude" in model_lower
    )


def build_litellm_reasoning_params(
    reasoning_effort: str | None,
    *,
    model: str | None,
    provider: str | None = None,
) -> dict[str, object]:
    """Translate the user-facing setting into safe LiteLLM request fields.

    ``disabled`` is intentionally not passed as ``reasoning_effort='none'``
    on Anthropic-native routes. LiteLLM currently maps that value to omission,
    while Claude Sonnet 5 interprets an omitted ``thinking`` field as adaptive
    thinking. The native explicit disable field is required there.
    """
    normalized = normalize_llm_reasoning_effort(reasoning_effort)
    if normalized is None:
        return {}
    if normalized == "disabled":
        if _uses_anthropic_native_api(model, provider):
            return {"thinking": {"type": "disabled"}}
        return {"reasoning_effort": "none"}
    return {"reasoning_effort": normalized}


def ensure_google_sdk_reasoning_supported(reasoning_effort: str | None, *, model: str) -> None:
    """Reject a control the direct Google SDK path cannot translate safely.

    LiteLLM normalizes ``reasoning_effort`` for provider adapters, but the
    direct Google SDK uses model-specific thinking levels or numeric budgets.
    Silently dropping the configured control would violate the user's intent.
    """
    normalized = normalize_llm_reasoning_effort(reasoning_effort)
    if normalized is not None:
        raise ReasoningControlUnsupportedError(
            "llm_reasoning_effort is not supported by the direct Google GenAI SDK "
            f"path for model {model!r}; use a LiteLLM-backed route or leave it unset"
        )
