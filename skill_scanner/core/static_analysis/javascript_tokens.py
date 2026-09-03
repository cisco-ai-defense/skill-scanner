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
skips comments, template literal text, and regular-expression contents.  The
executable expressions inside template substitutions are tokenized recursively
after the complete template structure has been validated.  Callers that need
fail-open behavior can inspect ``complete`` and ``error_codes``; the
compatibility helper returns the same bounded token prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MAX_JAVASCRIPT_TOKENS = 16_384
MAX_JAVASCRIPT_STRING_CHARS = 256
MAX_JAVASCRIPT_TEMPLATE_DEPTH = 64
_TEMPLATE_BOUNDARY = "/template/"


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

    def record_error(code: str) -> None:
        if code not in errors:
            errors.append(code)

    def skip_quoted(position: int, end: int, quote: str, current_line: int) -> tuple[int, int, bool]:
        position += 1
        while position < end:
            character = source[position]
            if character == "\\":
                if position + 1 < end:
                    current_line += int(source[position + 1] == "\n")
                    position += 2
                    continue
                return end, current_line, False
            if character == quote:
                return position + 1, current_line, True
            current_line += int(character == "\n")
            position += 1
        return end, current_line, False

    def skip_regex(position: int, end: int, current_line: int) -> tuple[int, int, bool]:
        position += 1
        in_class = False
        while position < end:
            character = source[position]
            if character == "\\":
                position = min(end, position + 2)
                continue
            if character == "\n":
                return position + 1, current_line + 1, False
            if character == "[":
                in_class = True
            elif character == "]":
                in_class = False
            elif character == "/" and not in_class:
                position += 1
                while position < end and source[position].isalpha():
                    position += 1
                return position, current_line, True
            position += 1
        return end, current_line, False

    def can_start_regex(position: int, start: int) -> bool:
        previous = position - 1
        while previous >= start and source[previous].isspace():
            previous -= 1
        return previous < start or source[previous] in "([={,;:"

    def template_expression_end(
        start: int,
        end: int,
        start_line: int,
        template_depth: int,
    ) -> tuple[int, int, str | None]:
        brace_depth = 0
        position = start
        current_line = start_line
        while position < end:
            character = source[position]
            if character in {"'", '"'}:
                position, current_line, closed = skip_quoted(position, end, character, current_line)
                if not closed:
                    return end, current_line, "JS_UNCLOSED_STRING"
                continue
            if source.startswith("//", position):
                newline = source.find("\n", position + 2, end)
                if newline < 0:
                    return end, current_line, "JS_UNCLOSED_TEMPLATE_EXPRESSION"
                position = newline + 1
                current_line += 1
                continue
            if source.startswith("/*", position):
                closing = source.find("*/", position + 2, end)
                if closing < 0:
                    return end, current_line, "JS_UNCLOSED_COMMENT"
                current_line += source.count("\n", position, closing + 2)
                position = closing + 2
                continue
            if character == "`":
                position, current_line, _spans, error = parse_template(
                    position,
                    end,
                    current_line,
                    template_depth + 1,
                    collect_spans=False,
                )
                if error is not None:
                    return end, current_line, error
                continue
            if character == "/" and can_start_regex(position, start):
                position, current_line, closed = skip_regex(position, end, current_line)
                if not closed:
                    return end, current_line, "JS_UNCLOSED_REGEX"
                continue
            if character == "{":
                brace_depth += 1
            elif character == "}":
                if brace_depth == 0:
                    return position, current_line, None
                brace_depth -= 1
            current_line += int(character == "\n")
            position += 1
        return end, current_line, "JS_UNCLOSED_TEMPLATE_EXPRESSION"

    def parse_template(
        start: int,
        end: int,
        start_line: int,
        template_depth: int,
        *,
        collect_spans: bool = True,
    ) -> tuple[int, int, list[tuple[int, int, int]], str | None]:
        if template_depth > MAX_JAVASCRIPT_TEMPLATE_DEPTH:
            return end, start_line, [], "JS_TEMPLATE_DEPTH_LIMIT"

        spans: list[tuple[int, int, int]] = []
        position = start + 1
        current_line = start_line
        while position < end:
            character = source[position]
            if character == "\\":
                if position + 1 >= end:
                    return end, current_line, [], "JS_UNCLOSED_TEMPLATE"
                current_line += int(source[position + 1] == "\n")
                position += 2
                continue
            if character == "`":
                return position + 1, current_line, spans, None
            if source.startswith("${", position):
                expression_start = position + 2
                expression_line = current_line
                closing, current_line, error = template_expression_end(
                    expression_start,
                    end,
                    expression_line,
                    template_depth,
                )
                if error is not None:
                    return end, current_line, [], error
                if collect_spans:
                    spans.append((expression_start, closing, expression_line))
                position = closing + 1
                continue
            current_line += int(character == "\n")
            position += 1
        return end, current_line, [], "JS_UNCLOSED_TEMPLATE"

    def lex_region(start: int, end: int, start_line: int, template_depth: int) -> bool:
        position = start
        current_line = start_line
        region_token_start = len(tokens)
        while position < end and len(tokens) < max_tokens:
            character = source[position]
            if character.isspace():
                current_line += int(character == "\n")
                position += 1
                continue
            if source.startswith("//", position):
                newline = source.find("\n", position + 2, end)
                if newline < 0:
                    return True
                current_line += 1
                position = newline + 1
                continue
            if source.startswith("/*", position):
                closing = source.find("*/", position + 2, end)
                if closing < 0:
                    record_error("JS_UNCLOSED_COMMENT")
                    return True
                current_line += source.count("\n", position, closing + 2)
                position = closing + 2
                continue
            if character in {"'", '"'}:
                token_line = current_line
                quote = character
                value: list[str] = []
                position += 1
                closed = False
                while position < end:
                    current = source[position]
                    if current == "\\":
                        if position + 1 < end:
                            escaped = source[position + 1]
                            value.append(escaped)
                            current_line += int(escaped == "\n")
                            position += 2
                            continue
                        position += 1
                        break
                    if current == quote:
                        position += 1
                        closed = True
                        break
                    current_line += int(current == "\n")
                    if len(value) < MAX_JAVASCRIPT_STRING_CHARS:
                        value.append(current)
                    position += 1
                if not closed:
                    record_error("JS_UNCLOSED_STRING")
                if append("string", "".join(value), token_line):
                    return False
                continue
            if character == "`":
                following, following_line, spans, error = parse_template(
                    position,
                    end,
                    current_line,
                    template_depth + 1,
                )
                if error is not None:
                    record_error(error)
                    return True
                # Structural sentinels keep separately evaluated substitutions
                # from synthesizing a call across a template boundary, e.g.
                # `${eval}${(payload)}` or eval`${(payload)}`.
                if append("punctuation", _TEMPLATE_BOUNDARY, current_line):
                    return False
                for expression_start, expression_end, expression_line in spans:
                    if not lex_region(expression_start, expression_end, expression_line, template_depth + 1):
                        return False
                    if append("punctuation", _TEMPLATE_BOUNDARY, expression_line):
                        return False
                position = following
                current_line = following_line
                continue
            if character.isalpha() or character in {"_", "$"}:
                token_line = current_line
                following = position + 1
                while following < end and (source[following].isalnum() or source[following] in {"_", "$"}):
                    following += 1
                if append("identifier", source[position:following], token_line):
                    return False
                position = following
                continue
            if character == "/" and (
                len(tokens) == region_token_start or tokens[-1].value in {"(", "=", "[", "{", ",", ";", ":"}
            ):
                # Best-effort regex-literal skipping prevents text such as
                # /eval\(/ from becoming a call token. Division remains
                # ordinary punctuation, as in the original bounded lexer.
                token_line = current_line
                position, current_line, closed = skip_regex(position, end, current_line)
                if not closed:
                    record_error("JS_UNCLOSED_REGEX")
                if append("punctuation", "/regex/", token_line):
                    return False
                continue
            if append("punctuation", character, current_line):
                return False
            position += 1
        return len(tokens) < max_tokens

    lex_region(0, length, 1, 0)

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
    "MAX_JAVASCRIPT_TEMPLATE_DEPTH",
    "MAX_JAVASCRIPT_TOKENS",
    "javascript_token_prefix",
    "tokenize_javascript",
]
