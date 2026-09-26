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

"""Byte-bounded state construction for System One requests.

Jev accepts 32,768 tokens, which sounds generous until you notice that code
tokenizes far worse than prose.  Measured against Gemma 4, repetitive Python came
in at 3.06 bytes per token, and minified JavaScript or base64 is worse.  The
corpora here are adversarial by construction, so budgets are enforced in **bytes**
and guarded at a pessimistic 2 bytes per token; the optimistic 4 is used only to
project cost.

Two properties are load-bearing and are the reason this logic is not inlined at
the call sites:

*Truncation keeps the interesting middle.*  Cutting head and tail alone would
discard exactly the payload an obfuscated sample hides in the centre, so the
middle budget is spent on windows around security-relevant terms.

*Untrusted text is neutralized.*  These corpora are largely prompt-injection
samples.  Framing tags inside sample content are rewritten so a malicious
``SKILL.md`` cannot close the harness's own delimiters and have its instructions
read as policy.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Sequence
from typing import Any

# Terms worth preserving through truncation. The shell-oriented entries are
# carried over unchanged so results stay comparable with the prior programme;
# the skill-oriented ones are added because a skill package hides its payload in
# frontmatter, tool declarations and bundled scripts rather than in one command.
SECURITY_TERMS: tuple[str, ...] = (
    # Carried over verbatim.
    "/etc/shadow",
    "sudoers",
    "authorized_keys",
    "private key",
    "api_token",
    "api key",
    "password",
    "credential",
    "secret",
    "iptables",
    "firewall",
    "crontab",
    "curl ",
    "wget ",
    "http://",
    "https://",
    "| bash",
    "| sh",
    "base64",
    "eval(",
    "exec(",
    "reverse shell",
    "/dev/tcp",
    "systemctl",
    "startup",
    "rm -rf",
    "chmod 777",
    # Skill-package specific.
    "allowed-tools",
    "allowed_tools",
    "ignore previous",
    "ignore all previous",
    "disregard",
    "system prompt",
    "child_process",
    "subprocess",
    "os.system",
    "__import__",
    "atob(",
    "fromcharcode",
    "\\u202e",
    "webhook",
    "pastebin",
    "ngrok",
    ".onion",
    "id_rsa",
    ".env",
    ".aws/credentials",
    "postinstall",
    "preinstall",
)

# Tags the harness uses to frame untrusted content. Replaced with look-alike
# guillemets inside sample text so the structure cannot be forged.
FRAMING_TAGS: tuple[str, ...] = (
    "SKILL_PURPOSE",
    "CANDIDATE_FINDING",
    "FILE_CONTENT",
    "PACKAGE_SHAPE",
    "SIBLING_FINDINGS",
    "TYPED_FACTS",
)

TRUNCATION_MARKER = "\n...[truncated]...\n"

# Guard ratio for the token estimate. Deliberately pessimistic: a request that
# overflows silently gets a confident answer about content the model never saw.
GUARD_BYTES_PER_TOKEN = 2
# Used only to project spend, never to decide whether a request is safe to send.
COST_BYTES_PER_TOKEN = 4


def utf8_prefix(value: str, limit: int) -> str:
    """Leading bytes of *value*, truncated without splitting a character."""
    data = value.encode()
    if len(data) <= limit:
        return value
    return data[:limit].decode(errors="ignore")


def utf8_suffix(value: str, limit: int) -> str:
    """Trailing bytes of *value*, truncated without splitting a character."""
    data = value.encode()
    if len(data) <= limit:
        return value
    return data[-limit:].decode(errors="ignore")


def neutralize(value: str) -> str:
    """Defuse harness framing tags appearing inside untrusted sample text."""
    for tag in FRAMING_TAGS:
        value = value.replace(f"<{tag}", f"‹{tag}").replace(f"</{tag}>", f"‹/{tag}›")
    return value


def safe_identifier(value: Any, *, default: str = "unknown") -> str:
    """Bound and escape a free-form identifier such as a skill or file name."""
    bounded = str(value or default)[:128]
    sanitized = re.sub(r"[^A-Za-z0-9._:/-]", "_", bounded)
    return html.escape(sanitized or default, quote=True)


def bound_value(value: str, limit: int) -> tuple[str, bool]:
    """Bound *value* to *limit* bytes, preserving security-relevant windows.

    Returns the bounded text and whether truncation occurred.  Head and tail each
    receive a quarter of the budget; the remaining half is spent on windows
    around matched security terms, falling back to the centre of the text when no
    term matches.
    """
    value = neutralize(value)
    if len(value.encode()) <= limit:
        return value, False

    budget = max(0, limit - len(TRUNCATION_MARKER.encode()))
    head = budget // 4
    tail = budget // 4
    middle = budget - head - tail

    lowered = value.lower()
    snippets: list[str] = []
    remaining = middle
    for term in SECURITY_TERMS:
        position = lowered.find(term)
        if position < 0 or remaining <= 0:
            continue
        start = max(0, position - 64)
        snippet = utf8_prefix(value[start : position + len(term) + 64], remaining)
        if snippet:
            snippets.append(snippet)
            remaining -= len(snippet.encode())
    if not snippets and middle:
        center = len(value) // 2
        snippets.append(utf8_prefix(value[max(0, center - middle // 2) :], middle))

    bounded = (
        utf8_prefix(value, head)
        + TRUNCATION_MARKER
        + "\n...\n".join(snippets)
        + TRUNCATION_MARKER
        + utf8_suffix(value, tail)
    )
    return bounded, True


def minimize(value: Any) -> Any:
    """Replace long strings with size markers, for the data-minimized recipe."""
    if isinstance(value, str):
        if len(value) <= 128:
            return value
        return f"<bounded-text bytes={len(value.encode())}>"
    if isinstance(value, list):
        return [minimize(item) for item in value[:32]]
    if isinstance(value, dict):
        return {str(key): minimize(item) for key, item in list(value.items())[:64]}
    return value


def relevance_score(text: str, current: str) -> int:
    """Rank sibling context by security terms and shared tokens with *current*."""
    lowered = text.lower()
    score = sum(term in lowered for term in SECURITY_TERMS)
    tokens = set(re.findall(r"[a-z0-9_./-]{4,}", lowered))
    score += min(5, len(tokens & set(re.findall(r"[a-z0-9_./-]{4,}", current.lower()))))
    return score


def canonical_json(value: Any) -> str:
    """Deterministic serialization, so request digests are reproducible."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def estimated_tokens(payload: str | bytes, *, bytes_per_token: int = GUARD_BYTES_PER_TOKEN) -> int:
    """Pessimistic token estimate used by the pre-flight oversize guard."""
    data = payload.encode() if isinstance(payload, str) else payload
    return max(1, len(data) // max(1, bytes_per_token))


def projected_cost_tokens(payload: str | bytes) -> int:
    """Optimistic token estimate, for spend projection only."""
    return estimated_tokens(payload, bytes_per_token=COST_BYTES_PER_TOKEN)


def total_bytes(fields: Sequence[str]) -> int:
    """Byte total of the rendered fields, for budget accounting."""
    return sum(len(field.encode()) for field in fields)
