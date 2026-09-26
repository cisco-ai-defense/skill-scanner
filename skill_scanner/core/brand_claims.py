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

"""Decide whether skill metadata *claims* an affiliation with Anthropic.

Impersonation is a claim of affiliation, not a mention of a vendor. Skills are written
for Claude and routinely name Anthropic: "wrap AI APIs (OpenAI, Anthropic, etc.)",
"use the Anthropic SDK". On a sample of real published skills, 51 of 57 flagged by the
old "contains 'anthropic'" test were such mentions and 6 made a claim. Shared by the
static analyzer and the core pack so both apply one definition.
"""

from __future__ import annotations

import re

# "By/from Anthropic" asserts authorship. Two phrasings that share the words do not: "powered
# by Anthropic" describes the model a tool calls, and "anthropic-report.py" is an identifier.
_AUTHORSHIP_CLAIM_RE = re.compile(
    r"(?<!powered )\b(?:by|from|made by|built by|created by|developed by|maintained by|published by)"
    r"\s+anthropic\b(?![-_./]\w)"
    r"|\banthropic[- ](?:approved|endorsed|verified|certified|sanctioned|team|staff|employees?)\b",
    re.IGNORECASE,
)

_OFFICIAL_RE = re.compile(r"\bofficial\b", re.IGNORECASE)
_ANTHROPIC_RE = re.compile(r"\banthropic\b", re.IGNORECASE)
# The noun phrase after "official" ends at punctuation or a function word.
_PHRASE_END_RE = re.compile(
    r"[.,;:!?()\[\]{}|\u2014\u2013\n]|\s(?:and|or|for|to|from|by|with|in|on|at|that|which|of|as)\b",
    re.IGNORECASE,
)
# "Official" is a claim about the skill only when it qualifies the skill itself. "Anthropic's
# official brand colors" and "the official Anthropic specification" point at Anthropic's own
# material; on 435 real skills flagged for those phrasings the judge cleared 89%.
_SELF_NOUNS = frozenset(
    {
        "skill", "skills", "plugin", "plugins", "tool", "tools", "helper", "helpers", "extension",
        "integration", "assistant", "release", "version", "package", "app", "server", "bot", "workflow",
        "product", "build", "edition", "distribution", "anthropic", "claude",
    }
)  # fmt: skip

_BRAND_GUIDELINE_RE = re.compile(r"\b(?:brand|guidelines|colou?rs|typography|style)\b", re.IGNORECASE)


def _official_claim(text: str) -> bool:
    for match in _OFFICIAL_RE.finditer(text):
        window = text[max(0, match.start() - 30) : match.end() + 30]
        if not _ANTHROPIC_RE.search(window):
            continue
        rest = text[match.end() : match.end() + 60]
        end = _PHRASE_END_RE.search(rest)
        words = [w.strip("'\"").lower() for w in (rest[: end.start()] if end else rest).split()]
        words = [w[:-2] if w.endswith("'s") else w for w in words if w]
        # Nothing after it ("Anthropic official", a name like "anthropic-official") asserts the
        # thing itself is official; otherwise the phrase's head noun decides.
        if not words or words[-1] in _SELF_NOUNS:
            return True
    return False


def claims_anthropic_affiliation(name: str, description: str) -> bool:
    """Whether the name or description asserts it is from, by, or endorsed by Anthropic."""

    text = f"{name}\n{description}"
    if "anthropic" not in text.lower():
        return False
    if _BRAND_GUIDELINE_RE.search(description) and not re.search(r"\bofficial\b", text, re.IGNORECASE):
        return False
    return bool(_AUTHORSHIP_CLAIM_RE.search(text)) or _official_claim(text)
