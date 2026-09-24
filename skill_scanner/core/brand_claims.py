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

_AFFILIATION_CLAIM_RE = re.compile(
    r"\b(?:by|from|made by|built by|created by|developed by|maintained by|published by)\s+anthropic\b"
    r"|\bofficial\b.{0,30}\banthropic\b"
    r"|\banthropic\b.{0,30}\bofficial\b"
    r"|\banthropic[- ](?:approved|endorsed|verified|certified|sanctioned|team|staff|employees?)\b",
    re.IGNORECASE,
)

# Anthropic's own brand-guideline skills describe applying the brand; they are not
# claiming to be Anthropic, and the previous rule exempted them for the same reason.
_BRAND_GUIDELINE_RE = re.compile(r"\b(?:brand|guidelines|colou?rs|typography|style)\b", re.IGNORECASE)


def claims_anthropic_affiliation(name: str, description: str) -> bool:
    """Whether the name or description asserts it is from, by, or endorsed by Anthropic."""

    text = f"{name}\n{description}"
    if "anthropic" not in text.lower():
        return False
    if _BRAND_GUIDELINE_RE.search(description) and not re.search(r"\bofficial\b", text, re.IGNORECASE):
        return False
    return bool(_AFFILIATION_CLAIM_RE.search(text))
