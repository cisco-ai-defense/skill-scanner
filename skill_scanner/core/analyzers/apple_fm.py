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

"""On-device completions via Apple's Foundation Models Python SDK.

``apple-fm/<name>`` selects the system language model. No API key is
used: inference stays on the Mac that has Apple Intelligence enabled.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any

_PREFIX = "apple-fm/"


def is_apple_fm_model(model: str | None) -> bool:
    """Return True when ``model`` selects the on-device Foundation Model."""
    return bool(model) and model.lower().startswith(_PREFIX)


def require_apple_fm_sdk() -> None:
    """Raise ImportError with an install hint when apple-fm-sdk is missing.

    Called when an analyzer is built, so a requested on-device scan fails
    before scanning instead of reporting every skill as unanalysed.
    """
    import importlib.util

    if importlib.util.find_spec("apple_fm_sdk") is None:
        raise ImportError(
            'apple-fm-sdk is not installed. Install it with: pip install "apple-fm-sdk>=0.2.1,<0.3" '
            "(macOS 26+, Apple Intelligence enabled, full Xcode to build)"
        )


def apple_fm_runtime_status() -> tuple[bool, str]:
    """Return whether the on-device model can run, and why if it cannot."""
    try:
        import apple_fm_sdk as fm
    except ImportError:
        return (
            False,
            "apple-fm-sdk is not installed. Install it with: pip install apple-fm-sdk "
            "(macOS 26+, Apple Intelligence enabled).",
        )
    try:
        availability = fm.SystemLanguageModel().is_available()
    except Exception as exc:
        return False, f"Foundation Models not available: {exc}"
    if isinstance(availability, tuple):
        available = bool(availability[0])
        detail = availability[1] if len(availability) > 1 else None
        reason = detail or "unavailable"
    else:
        available = bool(availability)
        reason = "unavailable"
    if not available:
        return False, f"Foundation Models not available: {reason}"
    return True, ""


class _Message:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _Message(content)


class _Usage:
    prompt_tokens = None
    completion_tokens = None


class AppleFMContextWindowError(RuntimeError):
    """The on-device model rejected the prompt as larger than its context window."""


class AppleFMResponse:
    """LiteLLM-shaped completion so existing callers can read ``choices``."""

    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]
        self.usage = _Usage()


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(str(part.get("text") or ""))
            else:
                parts.append(str(part))
        return "\n".join(part for part in parts if part)
    return str(content)


def _apple_json_schema(schema: dict) -> dict:
    """Drop JSON Schema features the on-device guided decoder rejects."""

    titles = {"n": 0}

    def visit(node: Any) -> Any:
        if isinstance(node, list):
            return [visit(item) for item in node]
        if not isinstance(node, dict):
            return node
        cleaned: dict = {}
        for key, value in node.items():
            if key in {"uniqueItems", "pattern", "minItems", "maxItems", "minLength", "maxLength", "format"}:
                continue
            if key == "type" and isinstance(value, list):
                types = [item for item in value if item != "null"]
                cleaned[key] = types[0] if len(types) == 1 else (types or "string")
                continue
            cleaned[key] = visit(value)
        properties = cleaned.get("properties")
        if isinstance(properties, dict) and "x-order" not in cleaned:
            cleaned["x-order"] = list(properties)
        if (cleaned.get("type") == "object" or isinstance(properties, dict)) and "title" not in cleaned:
            titles["n"] += 1
            cleaned["title"] = f"Object{titles['n']}"
        return cleaned

    return visit(schema)


def _generation_options(fm: Any, params: dict) -> Any:
    """Map temperature and max token fields onto GenerationOptions."""
    options_cls = getattr(fm, "GenerationOptions", None)
    if options_cls is None:
        return None
    kwargs: dict = {}
    temperature = params.get("temperature")
    if temperature is not None and not isinstance(temperature, bool):
        kwargs["temperature"] = float(temperature)
    max_tokens = params.get("max_completion_tokens")
    if max_tokens is None:
        max_tokens = params.get("max_tokens")
    if max_tokens is not None and not isinstance(max_tokens, bool):
        limit = int(max_tokens)
        if limit > 0:
            kwargs["maximum_response_tokens"] = limit
    if not kwargs:
        return None
    return options_cls(**kwargs)


def _split_messages(messages: list) -> tuple[str, str]:
    system_parts = []
    user_parts = []
    for message in messages or []:
        if not isinstance(message, dict):
            user_parts.append(str(message))
            continue
        role = str(message.get("role") or "user").lower()
        text = _content_text(message.get("content"))
        if not text:
            continue
        if role == "system":
            system_parts.append(text)
        else:
            user_parts.append(text)
    return "\n\n".join(system_parts), "\n\n".join(user_parts)


async def apple_fm_acompletion(**params: Any) -> AppleFMResponse:
    """Run one prompt on the system Foundation Model.

    Accepts the same keyword arguments as a LiteLLM completion and ignores
    provider fields such as ``api_key`` and ``drop_params``.
    """
    available, reason = apple_fm_runtime_status()
    if not available:
        if "not installed" in reason:
            raise ImportError(reason)
        raise RuntimeError(reason)
    import apple_fm_sdk as fm

    instructions, prompt = _split_messages(params.get("messages") or [])
    if not prompt:
        prompt = instructions
        instructions = ""

    session_kwargs: dict = {}
    try:
        signature = inspect.signature(fm.LanguageModelSession)
    except (TypeError, ValueError):
        signature = None
    if instructions and signature is not None and "instructions" in signature.parameters:
        session_kwargs["instructions"] = instructions
    elif instructions:
        # Keep the policy channel separate from skill content. Merging them
        # into one prompt lets the skill text sit in the same instruction
        # stream the adjudicator uses to demote findings.
        raise RuntimeError(
            "Apple Foundation Models session cannot take separate instructions; "
            "refusing to merge them into the user prompt"
        )

    session = fm.LanguageModelSession(**session_kwargs)
    respond_kwargs: dict = {}
    try:
        respond_signature = inspect.signature(session.respond)
    except (TypeError, ValueError):
        respond_signature = None
    options = _generation_options(fm, params)
    if options is not None and (respond_signature is None or "options" in respond_signature.parameters):
        respond_kwargs["options"] = options
    json_schema = params.get("json_schema")
    if isinstance(json_schema, dict) and (respond_signature is None or "json_schema" in respond_signature.parameters):
        respond_kwargs["json_schema"] = _apple_json_schema(json_schema)

    async def _respond() -> Any:
        return await session.respond(prompt, **respond_kwargs)

    timeout = params.get("timeout")
    try:
        if timeout:
            raw = await asyncio.wait_for(_respond(), timeout=float(timeout))
        else:
            raw = await _respond()
    except TimeoutError as exc:
        if not timeout:
            raise
        raise TimeoutError(f"apple-fm request timed out after {timeout} seconds") from exc
    except Exception as exc:
        if _is_context_window_error(exc):
            raise AppleFMContextWindowError("Apple Foundation Models context window cannot fit this prompt") from exc
        raise
    text = _response_text(raw)
    return AppleFMResponse(text)


def _is_context_window_error(exc: BaseException) -> bool:
    """Recognize the SDK's context-window failure without importing it."""
    if type(exc).__name__ == "ExceededContextWindowSizeError":
        return True
    message = str(exc).lower()
    return "context window" in message or "context length" in message


def _response_text(raw: Any) -> str:
    """Normalize a string, JSON object, or generated-content result to text."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (dict, list)):
        return json.dumps(raw)
    to_json = getattr(raw, "to_json", None)
    if callable(to_json):
        encoded = to_json()
        if isinstance(encoded, str):
            return encoded
        if isinstance(encoded, (dict, list)):
            return json.dumps(encoded)
    value = getattr(raw, "value", None)
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str) and value.strip().startswith(("{", "[")):
        return value
    content = getattr(raw, "content", None)
    if isinstance(content, (dict, list)):
        return json.dumps(content)
    if isinstance(content, str):
        return content
    return str(raw if content is None else content)
