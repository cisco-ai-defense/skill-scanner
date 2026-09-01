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

"""Validated output-token settings shared by LLM entry points."""

from __future__ import annotations

import os

DEFAULT_LLM_MAX_TOKENS = 8192
LLM_MAX_TOKENS_ENV_VAR = "SKILL_SCANNER_LLM_MAX_TOKENS"
META_LLM_MAX_TOKENS_ENV_VAR = "SKILL_SCANNER_META_LLM_MAX_TOKENS"


def validate_llm_max_tokens(value: int, *, source: str = "max_tokens") -> int:
    """Return *value* when it is a positive integer, otherwise fail loudly."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{source} must be a positive integer; got {value!r}")
    return value


def resolve_llm_max_tokens(
    explicit: int | None = None,
    *,
    meta: bool = False,
    default: int = DEFAULT_LLM_MAX_TOKENS,
) -> int:
    """Resolve a validated output-token budget.

    Precedence is explicit argument, meta-specific environment variable (for
    meta-analysis), scanner-wide environment variable, then *default*.
    """
    if explicit is not None:
        return validate_llm_max_tokens(explicit)

    env_vars = (META_LLM_MAX_TOKENS_ENV_VAR, LLM_MAX_TOKENS_ENV_VAR) if meta else (LLM_MAX_TOKENS_ENV_VAR,)
    for env_var in env_vars:
        raw = os.getenv(env_var)
        if raw is None or not raw.strip():
            continue
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"{env_var} must be a positive integer; got {raw!r}") from exc
        return validate_llm_max_tokens(value, source=env_var)

    return validate_llm_max_tokens(default, source="default max_tokens")
