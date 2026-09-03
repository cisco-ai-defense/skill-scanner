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

"""Regression contract for the shared bounded JavaScript tokenizer."""

from skill_scanner.core.rules.active_dynamic_execution import _lex_javascript
from skill_scanner.core.static_analysis.javascript_tokens import (
    JavascriptToken,
    tokenize_javascript,
)


def _triples(source: str) -> list[tuple[str, str, int]]:
    return [(token.kind, token.value, token.line) for token in tokenize_javascript(source).tokens]


def test_token_stream_matches_the_frozen_active_detector_contract() -> None:
    source = """// ignored eval(payload)\nconst cp = require("node:child_process");\ncp.exec(command);\nconst text = 'eval(secret)';\n"""

    expected = [
        ("identifier", "const", 2),
        ("identifier", "cp", 2),
        ("punctuation", "=", 2),
        ("identifier", "require", 2),
        ("punctuation", "(", 2),
        ("string", "node:child_process", 2),
        ("punctuation", ")", 2),
        ("punctuation", ";", 2),
        ("identifier", "cp", 3),
        ("punctuation", ".", 3),
        ("identifier", "exec", 3),
        ("punctuation", "(", 3),
        ("identifier", "command", 3),
        ("punctuation", ")", 3),
        ("punctuation", ";", 3),
        ("identifier", "const", 4),
        ("identifier", "text", 4),
        ("punctuation", "=", 4),
        ("string", "eval(secret)", 4),
        ("punctuation", ";", 4),
    ]
    result = tokenize_javascript(source)

    assert result.complete is True
    assert _triples(source) == expected
    assert _lex_javascript(source) == list(result.tokens)
    assert all(isinstance(token, JavascriptToken) for token in result.tokens)


def test_template_regex_comments_and_escaped_strings_keep_legacy_shape() -> None:
    source = 'const a = `eval(${value})`; const r = /eval\\(/gi; /* x */ const s = "a\\"b";'

    assert _triples(source) == [
        ("identifier", "const", 1),
        ("identifier", "a", 1),
        ("punctuation", "=", 1),
        ("punctuation", ";", 1),
        ("identifier", "const", 1),
        ("identifier", "r", 1),
        ("punctuation", "=", 1),
        ("punctuation", "/regex/", 1),
        ("punctuation", ";", 1),
        ("identifier", "const", 1),
        ("identifier", "s", 1),
        ("punctuation", "=", 1),
        ("string", 'a"b', 1),
        ("punctuation", ";", 1),
    ]


def test_status_addition_marks_malformed_and_budget_inputs_incomplete() -> None:
    malformed = tokenize_javascript("const ok = 1; /* never closed")
    limited = tokenize_javascript("a b c", max_tokens=2)

    assert malformed.complete is False
    assert malformed.error_codes == ("JS_UNCLOSED_COMMENT",)
    assert _triples("const ok = 1; /* never closed")[:2] == [
        ("identifier", "const", 1),
        ("identifier", "ok", 1),
    ]
    assert limited.complete is False
    assert limited.error_codes == ("JS_TOKEN_LIMIT",)
    assert [token.value for token in limited.tokens] == ["a", "b"]
