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

"""Render the skill question configs into the System One wire shape.

The provider expects each question as ``{"type", "instructions", ...}`` where
``instructions`` is either a nested policy object or a flat string.  The flat form
exists because some backends type the field as a plain string and reject a nested
object; carrying both means one config can drive every backend without editing it
per provider.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(__file__).with_name("questions-skill-v1.json")

INSTRUCTION_FORMATS = ("structured", "string")


def load_config(path: Path | None = None) -> dict[str, Any]:
    return json.loads((path or CONFIG_PATH).read_text(encoding="utf-8"))


def build_questions(
    config: dict[str, Any],
    *,
    instruction_id: str,
    question_id: str,
    instruction_format: str = "structured",
) -> dict[str, Any]:
    """Render one question variant into the provider's wire shape."""
    if instruction_format not in INSTRUCTION_FORMATS:
        raise ValueError(f"unknown instruction format {instruction_format!r}")

    variants = config["instruction_variants"]
    if instruction_id not in variants:
        raise KeyError(f"unknown instruction variant {instruction_id!r}")
    policy = str(variants[instruction_id]["policy"]).strip()

    question_variants = config["question_variants"]
    if question_id not in question_variants:
        raise KeyError(f"unknown question variant {question_id!r}")

    rendered: dict[str, Any] = {}
    for name, spec in question_variants[question_id]["questions"].items():
        decision = str(spec.get("prompt") or "").strip()
        question: dict[str, Any] = {"type": spec["type"]}
        if spec["type"] == "choice":
            # The provider derives its option set from the criteria keys.
            question["criteria"] = spec.get("criteria") or {option: option for option in (spec.get("options") or [])}
        elif spec["type"] == "score":
            question["criteria"] = list(spec.get("legend") or [])
        question["instructions"] = (
            f"{policy}\n\n{decision}" if instruction_format == "string" else {"policy": policy, "decision": decision}
        )
        rendered[name] = question
    return rendered


def question_ids(config: dict[str, Any]) -> list[str]:
    return sorted(config["question_variants"])


def instruction_ids(config: dict[str, Any]) -> list[str]:
    return sorted(config["instruction_variants"])


def never_auto_block(config: dict[str, Any], question_id: str) -> bool:
    """Whether this format is a triage screen that must not decide a block alone."""
    return bool(config["question_variants"][question_id].get("never_auto_block"))
