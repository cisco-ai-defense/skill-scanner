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

"""Optional System One screening tier, advisory only.

A "System One" model answers typed questions and returns a calibrated probability
rather than text, which makes it attractive as a cheap screen in front of an expensive
judge.  This analyzer speaks that protocol (``POST /v1/systemone``) against any
compatible endpoint.

**It cannot change a verdict, and that is deliberate.**  Measured on 439 records from
the MaliciousSkillBench source-disjoint split, across both a raw-text framing and the
structured candidate-centric packing, the model tested returned answers that barely
depended on which question was asked (within-record spread 0.041 across eight threat
probes) and that were *inverted* with respect to the label: AUC 0.29 to 0.31, malicious
records averaging 0.568 against 0.683 for benign, correlating partly with input length.
Wiring a signal like that into severity would make the scanner worse.

So the probability is recorded for observability and triage, and no finding is emitted.  If a future model separates the classes on a given corpus, that can be
demonstrated with this tier enabled before anything is allowed to act on it.  The
measurements live in ``docs/reference/measured-results.md``.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from ..models import Finding, Skill
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# Guarded well below a typical 16k-token prompt limit at a pessimistic two bytes per
# token. Oversize content is skipped rather than truncated: a model that answers
# confidently about content it never saw is a fail-open, not a low score.
MAX_STATE_BYTES = 24_000

DEFAULT_TIMEOUT_SECONDS = 60

# One overall question. Per-threat-family fan-out was measured and added nothing,
# because the answers did not depend on the question; see the module docstring.
SCREENING_QUESTION = "Is this skill malicious or unsafe to install?"

SCREENING_INSTRUCTIONS = (
    "A skill is an open specification: it may contain any code, in any language, for any "
    "legitimate purpose. Treat ordinary development, build, test and documentation work as "
    "allowed. Answer only about what the content actually does."
)


class SystemOneAnalyzer(BaseAnalyzer):
    """Query a System One endpoint and record its calibrated probability.

    Emits no findings.  The result is exposed on the analyzer as
    ``last_result`` so it can be inspected, logged, or used to prioritise review.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        model: str,
        api_key: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        policy: Any = None,
    ) -> None:
        super().__init__("system_one", policy)
        if not endpoint.startswith(("http://127.0.0.1", "http://localhost", "https://")):
            # A plaintext endpoint off loopback would put skill content on the wire in
            # clear text. Loopback is allowed so a locally served model can be used.
            raise ValueError(
                "System One endpoint must be https, or http on loopback; refusing "
                f"plaintext to a remote host: {endpoint}"
            )
        self.endpoint = endpoint
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.last_result: dict[str, Any] | None = None
        self.last_error: str | None = None

    def get_name(self) -> str:
        return "system_one"

    def analyze(self, skill: Skill) -> list[Finding]:
        """Record a screening probability. Always returns no findings."""

        self.last_result = None
        self.last_error = None

        state = self._build_state(skill)
        if state is None:
            self.last_error = "no readable content, or it exceeds the screening budget"
            self.last_result = {"status": "skipped", "reason": self.last_error}
            return []

        try:
            payload = self._post(state)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            self.last_error = f"{type(error).__name__}: {error}"
            logger.warning(
                "System One screening failed for %s: %s",
                getattr(skill, "name", "unknown"),
                self.last_error,
            )
            self.last_result = {"status": "error", "reason": self.last_error}
            return []

        probability = self._read_probability(payload)
        if probability is None:
            # A type mismatch is recorded as such rather than coerced: turning a format
            # error into a number would manufacture confidence.
            self.last_error = "response was not a calibrated noul answer"
            self.last_result = {"status": "unusable", "reason": self.last_error}
            return []

        self.last_result = {
            "status": "ok",
            "model": self.model,
            "probability": probability,
            "question": SCREENING_QUESTION,
            # Stated on every record so a reader cannot mistake this for a verdict.
            "advisory_only": True,
        }
        return []

    def _build_state(self, skill: Skill) -> str | None:
        """Concatenate the skill's text, or return None when it does not fit."""

        parts = []
        for file in getattr(skill, "files", None) or []:
            text = getattr(file, "content", None)
            if not text:
                continue
            parts.append(f"=== {getattr(file, 'relative_path', '?')} ===\n{text}")
        state = "\n\n".join(parts)
        if not state.strip():
            return None
        if len(state.encode("utf-8", errors="replace")) > MAX_STATE_BYTES:
            return None
        return state

    def _post(self, state: str) -> dict[str, Any]:
        body = json.dumps(
            {
                "model": self.model,
                "state": state,
                "questions": {
                    "malicious": {
                        "prompt": SCREENING_QUESTION,
                        "type": "noul",
                        # Required per question by this protocol, not per request.
                        "instructions": SCREENING_INSTRUCTIONS,
                    }
                },
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                decoded = json.loads(response.read())
            if not isinstance(decoded, dict):
                raise ValueError("response was not a JSON object")
            return decoded
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:200]
            raise ValueError(f"HTTP {error.code}: {detail}") from error

    @staticmethod
    def _read_probability(payload: Any) -> float | None:
        """Extract the calibrated probability, refusing an answer of the wrong type.

        The protocol returns ``{"type": "noul", "noul": <probability>}`` with no
        probabilities map. A client that looks for a ``<name>.true`` key, as a
        differently-shaped hosted API would, reads nothing at all.
        """

        if not isinstance(payload, dict):
            return None
        answer = (payload.get("answers") or {}).get("malicious")
        if not isinstance(answer, dict) or answer.get("type") != "noul":
            return None
        value = answer.get("noul")
        if not isinstance(value, (int, float)):
            return None
        probability = float(value)
        return probability if 0.0 <= probability <= 1.0 else None
