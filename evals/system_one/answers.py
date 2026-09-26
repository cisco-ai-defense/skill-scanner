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

"""Parsing and action derivation for System One typed answers.

The provider returns calibrated per-option probabilities rather than generated
text, so this module only validates and flattens them.  Nothing here samples,
decodes or re-ranks; that happens server-side.

Three guards carried over deliberately, each of which exists because its absence
produced a wrong answer that looked right:

*Distributions must sum to one.*  A provider that emits partial mass would
otherwise yield confident-looking actions from an incoherent distribution.

*Noul questions must actually answer nouls.*  A provider that answers the same
questions as a yes/no choice emits ``<name>.yes``, so every ``<name>.true``
lookup defaults to zero and the branch returns a **confident allow** with no
error code, which then lands in the cascade's trusted-allow band and skips the
judge entirely.  Requiring the namespace turns that silent pass into a loud
error.

*Exact disposition ties resolve upward.*  When two dispositions agree to within
1e-9 the winner is whichever key the provider happened to emit first.  Measured
on one 1,412-row arm, 14 rows were exact ties and 21-29% of them flipped under a
numerically neutral change, while the non-tie flip rate sat at the floor.  The
ties, not the arithmetic, were the instability.  Resolving toward higher severity
is reproducible and never downgrades, which the cascade's never-downgrade
invariant already requires.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

# Ordering used to merge tier decisions. `alert` and `deny` are accepted because
# the scanner's own vocabulary uses them; `error` and `not_applicable` sort below
# everything so they never win a merge.
ACTION_RANK: Mapping[str, int] = {
    "allow": 0,
    "confirm": 1,
    "alert": 1,
    "block": 2,
    "deny": 2,
    "error": -1,
    "not_applicable": -1,
}

SEVERITY: Mapping[str, int] = {"allow": 0, "confirm": 1, "block": 2}

# Two dispositions whose probabilities agree to within this margin are a genuine tie.
DISPOSITION_TIE_EPSILON = 1e-9

# Context recipes use the K prefix, so skill question variants use SQ to avoid
# any chance of a recipe id being read as a question id.
DISPOSITION_QUESTIONS = frozenset({"Q0", "Q2", "Q4", "SQ2"})

PROBABILITY_SUM_TOLERANCE = 0.02


class AnswerError(ValueError):
    """Raised when a provider answer violates the typed-answer contract."""


def parse_answer(answer: Mapping[str, Any]) -> tuple[Any, dict[str, float], float]:
    """Validate one typed answer and return (value, probabilities, confidence)."""
    answer_type = answer.get("type")
    if answer_type == "choice":
        value = answer.get("choice")
        probabilities = answer.get("probabilities")
        confidence = answer.get("confidence")
    elif answer_type == "score":
        value = answer.get("score")
        probabilities = answer.get("probabilities")
        confidence = answer.get("confidence")
    elif answer_type == "noul":
        value = answer.get("noul")
        numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
        probabilities = {"true": value, "false": 1 - value} if numeric else None
        confidence = abs(float(value) - 0.5) * 2 if numeric else None
    else:
        raise AnswerError(f"unsupported answer type: {answer_type!r}")

    if (
        not isinstance(probabilities, Mapping)
        or not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= float(confidence) <= 1
    ):
        raise AnswerError("invalid probabilities or confidence")

    parsed: dict[str, float] = {}
    for key, probability in probabilities.items():
        if (
            not isinstance(probability, (int, float))
            or isinstance(probability, bool)
            or not math.isfinite(probability)
            or not 0 <= probability <= 1
        ):
            raise AnswerError(f"invalid probability for {key!r}")
        parsed[str(key)] = float(probability)

    total = sum(parsed.values())
    if not 1 - PROBABILITY_SUM_TOLERANCE <= total <= 1 + PROBABILITY_SUM_TOLERANCE:
        raise AnswerError(f"probabilities do not sum to one: {total}")

    return value, parsed, float(confidence)


def flatten_answers(answers: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, float], float]:
    """Parse every answer and flatten probability keys to ``<question>.<option>``."""
    values: dict[str, Any] = {}
    probabilities: dict[str, float] = {}
    confidences: list[float] = []
    for question_id, answer in answers.items():
        value, parsed, confidence = parse_answer(answer)
        values[question_id] = value
        confidences.append(confidence)
        for option, probability in parsed.items():
            probabilities[f"{question_id}.{option}"] = probability
    overall = min(confidences) if confidences else 0.0
    return values, probabilities, overall


def resolve_disposition_tie(action: str, probabilities: Mapping[str, float]) -> str:
    """Break exact disposition ties toward the more conservative outcome."""
    top = probabilities.get(f"disposition.{action}", 0)
    best = action
    for candidate, rank in SEVERITY.items():
        if candidate == action:
            continue
        value = probabilities.get(f"disposition.{candidate}")
        if value is None:
            continue
        if abs(value - top) <= DISPOSITION_TIE_EPSILON and rank > SEVERITY[best]:
            best = candidate
    return best


def derive_action(
    question_id: str,
    answers: Mapping[str, Any],
    probabilities: Mapping[str, float],
) -> tuple[str, float]:
    """Map typed answers onto an action and its confidence."""
    if question_id in DISPOSITION_QUESTIONS:
        action = str(answers.get("disposition", "error"))
        if action not in {"allow", "confirm", "block"}:
            return "error", 0.0
        action = resolve_disposition_tie(action, probabilities)
        return action, max(probabilities.get(f"disposition.{action}", 0.0), 0.0)

    # Without this the yes/no-instead-of-noul case returns a confident allow.
    if not any(key.endswith(".true") for key in probabilities):
        return "error", 0.0

    if question_id == "Q1":
        high = max(
            probabilities.get("exfiltration.true", 0.0),
            probabilities.get("persistence.true", 0.0),
            probabilities.get("hidden_execution.true", 0.0),
            probabilities.get("dangerous_effect.true", 0.0) * probabilities.get("high_impact.true", 0.0),
        )
        if high >= 0.75:
            return "block", high
        review = max(
            probabilities.get("sensitive_access.true", 0.0),
            probabilities.get("context_required.true", 0.0),
            probabilities.get("dangerous_effect.true", 0.0),
        )
        return ("confirm", review) if review >= 0.5 else ("allow", 1 - review)

    dangerous = max(
        (
            value
            for key, value in probabilities.items()
            if key.endswith(".true")
            and any(name in key for name in ("data_exfiltration", "destructive_command", "remote_hidden_execution"))
        ),
        default=0.0,
    )
    any_signal = max((value for key, value in probabilities.items() if key.endswith(".true")), default=0.0)
    if dangerous >= 0.75:
        return "block", dangerous
    return ("confirm", any_signal) if any_signal >= 0.5 else ("allow", 1 - any_signal)


def max_action(actions: list[str] | tuple[str, ...]) -> str:
    """Merge tier actions, never downgrading below the most severe real decision."""
    best = "allow"
    seen = False
    for action in actions:
        rank = ACTION_RANK.get(action)
        if rank is None or rank < 0:
            continue
        seen = True
        if rank > ACTION_RANK[best]:
            best = action
    return best if seen else "allow"
