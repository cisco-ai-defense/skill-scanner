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
    MAX_JAVASCRIPT_TEMPLATE_DEPTH,
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


def test_template_substitution_regex_comments_and_escaped_strings_keep_safe_shape() -> None:
    source = 'const a = `eval(${value})`; const r = /eval\\(/gi; /* x */ const s = "a\\"b";'

    assert _triples(source) == [
        ("identifier", "const", 1),
        ("identifier", "a", 1),
        ("punctuation", "=", 1),
        ("punctuation", "/template/", 1),
        ("identifier", "value", 1),
        ("punctuation", "/template/", 1),
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


def test_template_literal_text_is_inert_but_executable_substitution_is_tokenized() -> None:
    source = r"""const literal = `eval(ignored)`;
const escaped = `\${eval(ignored)}`;
const active = `before ${eval(payload)} after`;
"""

    result = tokenize_javascript(source)
    eval_tokens = [token for token in result.tokens if token.value == "eval"]

    assert result.complete is True
    assert [(token.kind, token.line) for token in eval_tokens] == [("identifier", 3)]
    assert not {"before", "after", "ignored"}.intersection(token.value for token in result.tokens)


def test_nested_template_braces_comments_strings_and_regex_are_balanced() -> None:
    source = """const value = `outer ${
({
  close: "}",
  nested: `inner ${eval(payload)}`,
  rx: /}/,
  note: (
    // } and ` stay inside this comment
    payload
  )
})
}`;
"""

    result = tokenize_javascript(source)

    assert result.complete is True
    assert result.error_codes == ()
    assert [(token.value, token.line) for token in result.tokens if token.value == "eval"] == [("eval", 4)]
    assert "inner" not in {token.value for token in result.tokens}
    assert "/regex/" in {token.value for token in result.tokens}


def test_template_boundaries_do_not_synthesize_execution_calls() -> None:
    separated = tokenize_javascript("const value = `${eval}${(payload)}`;")
    tagged = tokenize_javascript("eval`${(payload)}`;")
    literal_tagged = tokenize_javascript("eval`literal text`(payload);")

    assert [token.value for token in separated.tokens] == [
        "const",
        "value",
        "=",
        "/template/",
        "eval",
        "/template/",
        "(",
        "payload",
        ")",
        "/template/",
        ";",
    ]
    assert [token.value for token in tagged.tokens] == [
        "eval",
        "/template/",
        "(",
        "payload",
        ")",
        "/template/",
        ";",
    ]
    assert [token.value for token in literal_tagged.tokens] == [
        "eval",
        "/template/",
        "(",
        "payload",
        ")",
        ";",
    ]


def test_regex_at_template_substitution_start_remains_inert() -> None:
    result = tokenize_javascript("const matched = `${/eval(payload)/.test(value)}`;")

    assert result.complete is True
    assert [token.value for token in result.tokens].count("/regex/") == 1
    assert "eval" not in {token.value for token in result.tokens}


def test_malformed_template_substitutions_emit_no_executable_prefix() -> None:
    cases = {
        "const value = `${eval(payload)}": "JS_UNCLOSED_TEMPLATE",
        "const value = `x ${eval(payload)`;": "JS_UNCLOSED_TEMPLATE",
        "const value = `${eval(payload); 'oops}`;": "JS_UNCLOSED_STRING",
        "const value = `${eval(payload); /* }`;": "JS_UNCLOSED_COMMENT",
        "const value = `${/eval(payload)}`;": "JS_UNCLOSED_REGEX",
    }

    for source, error_code in cases.items():
        result = tokenize_javascript(source)
        assert result.complete is False
        assert result.error_codes == (error_code,)
        assert "eval" not in {token.value for token in result.tokens}


def test_template_recursion_and_token_budgets_are_bounded() -> None:
    nested = "eval(payload)"
    for _ in range(MAX_JAVASCRIPT_TEMPLATE_DEPTH):
        nested = f"`inner ${{{nested}}}`"
    too_deep = tokenize_javascript(f"`outer ${{{nested}}}`")
    limited = tokenize_javascript("`${eval(payload)}`", max_tokens=3)
    complete = tokenize_javascript("`${eval(payload)}`", max_tokens=8)

    assert too_deep.complete is False
    assert too_deep.error_codes == ("JS_TEMPLATE_DEPTH_LIMIT",)
    assert too_deep.tokens == ()
    assert limited.complete is False
    assert limited.error_codes == ("JS_TOKEN_LIMIT",)
    assert [token.value for token in limited.tokens] == ["/template/", "eval", "("]
    assert complete.complete is True
    assert [token.value for token in complete.tokens] == [
        "/template/",
        "eval",
        "(",
        "payload",
        ")",
        "/template/",
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
