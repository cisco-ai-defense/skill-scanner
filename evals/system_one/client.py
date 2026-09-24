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

"""Client for the System One typed-decision protocol.

One canonicalizer and one request function.  Hosted Jev and a self-hosted shim
differ only by URL, which is what makes them comparable at all: the same body,
the same questions, the same parsing.

Four guards, each of which exists because its absence produced a plausible wrong
answer.

*The endpoint is allowlisted.*  Skill content is sent in the request body, so the
destination is restricted rather than taken from a flag unchecked.

*The canonical body is the single source of truth.*  Request digests have to stay
stable across a resume, so the bytes that are hashed are the bytes that are sent.

*The served model is pinned.*  A silent substitution would invalidate a whole arm,
and there is no catalogue endpoint to detect it after the fact.

*Answers must cover exactly the questions asked.*  A provider answering a subset
would otherwise look like a confident decision on the missing ones.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from evals.system_one.answers import AnswerError, derive_action, flatten_answers
from evals.system_one.state import canonical_json, estimated_tokens, projected_cost_tokens

# Hosted Jev plus loopback for a self-hosted shim reached over an SSH tunnel.
ALLOWED_ENDPOINTS: frozenset[tuple[str, str]] = frozenset(
    {("https", "api.typesafe.ai"), ("http", "127.0.0.1"), ("http", "localhost")}
)

DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_API_KEY_ENV = "TYPESAFE_API_KEY"

# Retry-after is honoured but capped, so a hostile or mistaken header cannot stall a sweep.
MAX_RETRY_AFTER_SECONDS = 5.0
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class EndpointError(ValueError):
    """Raised when an endpoint is not on the allowlist."""


class ProviderError(RuntimeError):
    """Raised when the provider response violates the protocol."""


def validate_endpoint(endpoint: str) -> None:
    """Reject endpoints outside the allowlist, and any embedded credentials."""
    parsed = urlsplit(endpoint)
    if (parsed.scheme, parsed.hostname or "") not in ALLOWED_ENDPOINTS:
        raise EndpointError(f"endpoint not allowed: {endpoint}")
    if parsed.username or parsed.password:
        raise EndpointError("endpoint must not embed credentials")


def canonical_request(model: str, state: Any, questions: dict[str, Any]) -> str:
    """The single source of truth for the wire body."""
    return canonical_json({"model": model, "state": state, "questions": questions})


@dataclass
class Budget:
    """Reserve-then-record spend accounting.

    Aborts on measured overrun, not just projected, because an underestimate would
    otherwise let a sweep run past its cap unnoticed.
    """

    max_usd: float
    input_usd_per_million: float = 0.0
    reserved_tokens: int = 0
    actual_tokens: int = 0
    calls: int = 0
    max_calls: int = 1_000_000
    exceeded: bool = False

    def _cost(self, tokens: int) -> float:
        return (tokens / 1_000_000) * self.input_usd_per_million

    def reserve(self, tokens: int) -> None:
        if self.calls >= self.max_calls:
            self.exceeded = True
            raise ProviderError(f"call cap reached: {self.max_calls}")
        projected = self._cost(self.reserved_tokens + tokens)
        if self.max_usd and projected > self.max_usd:
            self.exceeded = True
            raise ProviderError(f"projected spend ${projected:.4f} exceeds cap ${self.max_usd:.2f}")
        self.reserved_tokens += tokens
        self.calls += 1

    def record(self, tokens: int) -> None:
        self.actual_tokens += tokens
        measured = self._cost(self.actual_tokens)
        if self.max_usd and measured > self.max_usd:
            self.exceeded = True
            raise ProviderError(f"measured spend ${measured:.4f} exceeds cap ${self.max_usd:.2f}")

    @property
    def estimated_usd(self) -> float:
        return self._cost(self.actual_tokens)


@dataclass
class Prediction:
    """One value-free prediction row."""

    case_id: str
    model: str
    model_revision: str
    context_variant: str
    question_variant: str
    action: str
    confidence: float
    detected: bool
    probabilities: dict[str, float] = field(default_factory=dict)
    answers: dict[str, Any] = field(default_factory=dict)
    route: str = "system_one"
    duration_ms: int = 0
    input_tokens: int = 0
    request_sha256: str = ""
    context_bytes: int = 0
    truncated: bool = False
    packing_tier: str = ""
    error_code: str | None = None

    def as_row(self) -> dict[str, Any]:
        row = {
            "schema_version": 1,
            "case_id": self.case_id,
            "model": self.model,
            "model_revision": self.model_revision,
            "context_variant": self.context_variant,
            "question_variant": self.question_variant,
            "action": self.action,
            "confidence": self.confidence,
            "detected": self.detected,
            "probabilities": self.probabilities,
            "route": self.route,
            "duration_ms": self.duration_ms,
            "input_tokens": self.input_tokens,
            "request_sha256": self.request_sha256,
            "context_bytes": self.context_bytes,
            "truncated": self.truncated,
            "packing_tier": self.packing_tier,
        }
        if self.error_code:
            row["error_code"] = self.error_code
        return row


def _sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()


def _post(endpoint: str, body: bytes, api_key: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def evaluate(
    *,
    case_id: str,
    state: Any,
    questions: dict[str, Any],
    model: str,
    model_revision: str,
    question_variant: str,
    context_variant: str,
    api_key: str,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: int = 60,
    retries: int = 2,
    budget: Budget | None = None,
    packing_tier: str = "",
    context_bytes: int = 0,
    truncated: bool = False,
) -> Prediction:
    """Send one decision request and return a value-free prediction row."""
    validate_endpoint(endpoint)
    if not api_key:
        raise ProviderError("missing API key")
    if not questions:
        raise ProviderError("at least one question is required")

    body_text = canonical_request(model, state, questions)
    body = body_text.encode("utf-8")
    digest = _sha256(body_text)
    tokens = estimated_tokens(body)

    base = Prediction(
        case_id=case_id,
        model=model,
        model_revision=model_revision,
        context_variant=context_variant,
        question_variant=question_variant,
        action="error",
        confidence=0.0,
        detected=False,
        input_tokens=projected_cost_tokens(body),
        request_sha256=digest,
        context_bytes=context_bytes or len(body),
        truncated=truncated,
        packing_tier=packing_tier,
        route="error",
    )

    if budget is not None:
        try:
            budget.reserve(tokens)
        except ProviderError as error:
            base.error_code = "provider_budget_exceeded"
            base.answers = {"detail": str(error)}
            return base

    started = time.monotonic()
    payload: dict[str, Any] | None = None
    last_error: str | None = None
    for attempt in range(retries + 1):
        try:
            payload = _post(endpoint, body, api_key, timeout)
            break
        except urllib.error.HTTPError as error:
            last_error = f"HTTP {error.code}"
            if error.code in RETRYABLE_STATUS and attempt < retries:
                delay = min(MAX_RETRY_AFTER_SECONDS, float(error.headers.get("retry-after") or 1))
                time.sleep(delay)
                continue
            break
        except Exception as error:  # noqa: BLE001 - classified into an error row
            last_error = f"{type(error).__name__}"
            if attempt < retries:
                time.sleep(min(MAX_RETRY_AFTER_SECONDS, 2**attempt))
                continue
            break

    base.duration_ms = int((time.monotonic() - started) * 1000)
    if payload is None:
        base.error_code = "provider_or_parse_failure"
        base.answers = {"detail": last_error or "unknown"}
        return base

    served = payload.get("model")
    if isinstance(served, str) and model_revision and served != model_revision:
        base.error_code = "model_version_mismatch"
        base.answers = {"served": served, "expected": model_revision}
        return base

    answers = payload.get("answers")
    if not isinstance(answers, dict) or set(answers) != set(questions):
        base.error_code = "answer_key_mismatch"
        return base

    try:
        values, probabilities, confidence = flatten_answers(answers)
    except AnswerError as error:
        base.error_code = "invalid_response"
        base.answers = {"detail": str(error)[:200]}
        return base

    action, action_confidence = derive_action(question_variant, values, probabilities)
    usage = payload.get("usage") or {}
    actual_tokens = int(usage.get("input_tokens") or tokens)
    if budget is not None:
        try:
            budget.record(actual_tokens)
        except ProviderError as error:
            base.error_code = "provider_budget_exceeded"
            base.answers = {"detail": str(error)}
            return base

    base.action = action
    base.confidence = action_confidence if action != "error" else confidence
    base.detected = action in {"confirm", "block"}
    base.probabilities = probabilities
    base.answers = values
    base.route = "system_one" if action != "error" else "error"
    base.input_tokens = actual_tokens
    if action == "error":
        base.error_code = "invalid_disposition"
    return base
