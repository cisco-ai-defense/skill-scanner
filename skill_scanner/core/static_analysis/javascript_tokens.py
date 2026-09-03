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

"""Bounded JavaScript/TypeScript tokenization shared by static analyzers.

This deliberately small lexer recognizes only the token classes needed by the
repository's syntax-aware detectors.  It never executes code and deliberately
skips comments, template contents, and regular-expression contents.  Callers
that need fail-open behavior can inspect ``complete`` and ``error_codes``;
the compatibility helper returns the same token prefix as the original lexer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MAX_JAVASCRIPT_TOKENS = 16_384
MAX_JAVASCRIPT_STRING_CHARS = 256


@dataclass(frozen=True, slots=True)
class JavascriptToken:
    """One bounded token with no retained source offset or raw source text."""

    kind: Literal["identifier", "punctuation", "string"]
    value: str
    line: int


@dataclass(frozen=True, slots=True)
class JavascriptTokenization:
    """A token prefix and stable status suitable for fail-open consumers."""

    tokens: tuple[JavascriptToken, ...]
    complete: bool
    error_codes: tuple[str, ...]


def tokenize_javascript(
    source: str,
    *,
    max_tokens: int = MAX_JAVASCRIPT_TOKENS,
) -> JavascriptTokenization:
    """Return bounded JS/TS tokens while excluding comments and literals.

    Token production intentionally matches the original
    ``active_dynamic_execution`` lexer.  Status is additive: existing callers
    can continue consuming the same prefix, while semantic correlation must
    decline incomplete input instead of constructing a partial flow.
    """

    if max_tokens < 1:
        return JavascriptTokenization((), False, ("JS_TOKEN_LIMIT",))

    tokens: list[JavascriptToken] = []
    errors: list[str] = []
    index = 0
    line = 1
    length = len(source)

    def append(
        kind: Literal["identifier", "punctuation", "string"],
        value: str,
        token_line: int,
    ) -> bool:
        tokens.append(JavascriptToken(kind, value, token_line))
        if len(tokens) >= max_tokens:
            errors.append("JS_TOKEN_LIMIT")
            return True
        return False

    while index < length and len(tokens) < max_tokens:
        character = source[index]
        if character.isspace():
            if character == "\n":
                line += 1
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            if newline < 0:
                index = length
                break
            line += 1
            index = newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                errors.append("JS_UNCLOSED_COMMENT")
                index = length
                break
            line += source.count("\n", index, end + 2)
            index = end + 2
            continue
        if character in {"'", '"', "`"}:
            quote = character
            token_line = line
            index += 1
            value: list[str] = []
            closed = False
            while index < length:
                current = source[index]
                if current == "\\":
                    if index + 1 < length:
                        escaped = source[index + 1]
                        if quote != "`":
                            value.append(escaped)
                        line += int(escaped == "\n")
                        index += 2
                        continue
                    index += 1
                    break
                if current == quote:
                    index += 1
                    closed = True
                    break
                if current == "\n":
                    line += 1
                if quote != "`" and len(value) < MAX_JAVASCRIPT_STRING_CHARS:
                    value.append(current)
                index += 1
            if not closed:
                errors.append("JS_UNCLOSED_TEMPLATE" if quote == "`" else "JS_UNCLOSED_STRING")
            if quote != "`" and append("string", "".join(value), token_line):
                break
            continue
        if character.isalpha() or character in {"_", "$"}:
            token_line = line
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] in {"_", "$"}):
                end += 1
            if append("identifier", source[index:end], token_line):
                break
            index = end
            continue
        if character == "/" and (not tokens or tokens[-1].value in {"(", "=", "[", "{", ",", ";", ":"}):
            # Best-effort regex-literal skipping prevents text such as
            # /eval\(/ from becoming a call token. Division remains ordinary
            # punctuation, exactly as in the original bounded lexer.
            token_line = line
            index += 1
            in_class = False
            closed = False
            while index < length:
                current = source[index]
                if current == "\\":
                    index += 2
                    continue
                if current == "\n":
                    line += 1
                    break
                if current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "/" and not in_class:
                    index += 1
                    while index < length and source[index].isalpha():
                        index += 1
                    closed = True
                    break
                index += 1
            if not closed:
                errors.append("JS_UNCLOSED_REGEX")
            if append("punctuation", "/regex/", token_line):
                break
            continue
        if append("punctuation", character, line):
            break
        index += 1

    return JavascriptTokenization(tuple(tokens), not errors, tuple(dict.fromkeys(errors)))


def javascript_token_prefix(
    source: str,
    *,
    max_tokens: int = MAX_JAVASCRIPT_TOKENS,
) -> list[JavascriptToken]:
    """Return the legacy list-shaped token prefix for compatibility."""

    return list(tokenize_javascript(source, max_tokens=max_tokens).tokens)


__all__ = [
    "JavascriptToken",
    "JavascriptTokenization",
    "MAX_JAVASCRIPT_STRING_CHARS",
    "MAX_JAVASCRIPT_TOKENS",
    "javascript_token_prefix",
    "tokenize_javascript",
]
