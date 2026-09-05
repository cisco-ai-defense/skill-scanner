# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for dynamic ``builtins.exec`` construction."""

import ast
import sys

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.static_analysis.python_shell_semantics import (
    MAX_PYTHON_SHELL_BINDINGS,
    MAX_PYTHON_SHELL_EAGER_EXPR_NODES,
    find_python_shell_candidates,
)

_EVAL_RULE_ID = "COMMAND_INJECTION_EVAL"
_SHELL_RULE_ID = "COMMAND_INJECTION_SHELL_TRUE"
_PATTERN = "python_ast:getattr_joined_builtin_exec"

ISSUE_204_SOURCE = """import base64
import builtins

decrypted_data = base64.b64decode('just a test')
_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))
_runner(decrypted_data.decode('utf-8'))
"""


def _eval_findings(make_skill, source: str, *, analyzer: StaticAnalyzer | None = None, path: str = "tool.py"):
    skill = make_skill({path: source})
    return [
        finding
        for finding in (analyzer or StaticAnalyzer(use_yara=False)).analyze(skill)
        if finding.rule_id == _EVAL_RULE_ID
    ]


def test_reported_dynamic_exec_is_canonical_command_injection(make_skill) -> None:
    findings = _eval_findings(make_skill, ISSUE_204_SOURCE)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.category is ThreatCategory.COMMAND_INJECTION
    assert finding.title == "Dangerous code execution functions that can execute arbitrary code"
    assert finding.remediation == (
        "Avoid eval(), exec(), and compile(). Use safer alternatives like ast.literal_eval() or operator module"
    )
    assert finding.file_path == "tool.py"
    assert finding.line_number == 6
    assert finding.snippet == "_runner(decrypted_data.decode('utf-8'))"
    assert finding.metadata["matched_pattern"] == _PATTERN
    assert finding.metadata["matched_text"] == "_runner(...) -> builtins.exec"
    assert finding.metadata["signature_context"] == "code"
    assert finding.metadata["signature_polarity"] == "active"
    assert finding.metadata["signature_match_start"] == 0
    assert finding.metadata["signature_match_end"] == len("_runner")


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as bi\n_runner = getattr(bi, ''.join(('e', 'x', 'e', 'c')))\n_runner(payload)\n",
        "\"\"\"module documentation\"\"\"\nimport builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "from __future__ import annotations\nimport builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
    ],
    ids=["aliased-builtins-and-tuple", "inert-module-docstring", "future-import"],
)
def test_exact_positive_variants_remain_detectable(make_skill, source: str) -> None:
    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].metadata["matched_pattern"] == _PATTERN


def test_dynamic_exec_lookup_invoked_without_temporary_alias_is_detected(make_skill) -> None:
    source = "import builtins\ngetattr(builtins, ''.join(['e', 'x', 'e', 'c']))(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 2
    assert findings[0].metadata["matched_pattern"] == _PATTERN
    assert findings[0].metadata["matched_text"] == "getattr(...) -> builtins.exec"


@pytest.mark.parametrize(
    ("source", "expected_line", "expected_text"),
    [
        (
            "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner.__call__(payload)\n",
            3,
            "_runner(...) -> builtins.exec",
        ),
        (
            "import builtins\ngetattr(builtins, ''.join(['e', 'x', 'e', 'c'])).__call__(payload)\n",
            2,
            "getattr(...) -> builtins.exec",
        ),
        (
            "import builtins\n"
            "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
            "_runner.__call__.__call__(payload)\n",
            3,
            "_runner(...) -> builtins.exec",
        ),
        (
            "import builtins\ngetattr(builtins, ''.join(['e', 'x', 'e', 'c'])).__call__.__call__(payload)\n",
            2,
            "getattr(...) -> builtins.exec",
        ),
    ],
    ids=["tracked-alias", "inline-lookup", "chained-alias", "chained-inline-lookup"],
)
def test_dynamic_exec_call_protocol_invocation_is_detected(
    make_skill,
    source: str,
    expected_line: int,
    expected_text: str,
) -> None:
    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line
    assert findings[0].metadata["matched_pattern"] == _PATTERN
    assert findings[0].metadata["matched_text"] == expected_text


@pytest.mark.parametrize(
    "source",
    [
        "import builtins\ngetattr(plugin, ''.join(['e', 'x', 'e', 'c']))(payload)\n",
        "import builtins\ngetattr(builtins, ''.join(['e', 'v', 'a', 'l']))(payload)\n",
        "import builtins\ngetattr = safe\ngetattr(builtins, ''.join(['e', 'x', 'e', 'c']))(payload)\n",
    ],
    ids=["unreviewed-receiver", "different-name", "shadowed-getattr"],
)
def test_unreviewed_direct_dynamic_exec_lookups_are_not_claimed(make_skill, source: str) -> None:
    assert _eval_findings(make_skill, source) == []


def test_ast_dynamic_exec_is_not_suppressed_by_legacy_line_exclusion(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "_runner(payload)  # use of exec(\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


def test_legacy_line_exclusion_still_suppresses_nonsemantic_regex_match(make_skill) -> None:
    assert _eval_findings(make_skill, "exec(payload)  # use of exec(\n") == []


@pytest.mark.parametrize(
    "invocation",
    [
        "unused = _runner(payload)",
        "unused: object = _runner(payload)",
    ],
)
def test_direct_alias_invocation_in_assignment_value_is_detected(make_skill, invocation: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


@pytest.mark.parametrize(
    "invocation",
    [
        "print(_runner(payload))",
        "result = [_runner(payload)]",
        "result = _runner(payload) if True else safe",
        "result = _runner(payload) if 1 else safe",
        "result = _runner(payload) and safe",
        "result = True and _runner(payload)",
        "result = 1 and _runner(payload)",
        "result = False or _runner(payload)",
        "result = 0 or _runner(payload)",
        "result = safe if _runner(payload) else other",
        "result = {'payload': _runner(payload)}",
        "result = {_runner(payload)}",
        'result = f"{_runner(payload)}"',
        "result = (captured := _runner(payload))",
        "print(*_runner(payload))",
        "print(**_runner(payload))",
        "result = (lambda value: value)(_runner(payload))",
        "result = (lambda value=_runner(payload): value)()",
        "result = (lambda: _runner(payload))()",
        "result = [item for item in _runner(payload)]",
        "result = {item for item in _runner(payload)}",
        "result = {item: item for item in _runner(payload)}",
        "result = (item for item in _runner(payload))",
    ],
    ids=[
        "call-argument",
        "list-element",
        "selected-if-expression",
        "truthy-scalar-selected-if-expression",
        "first-bool-operand",
        "proven-selected-and-operand",
        "truthy-scalar-selected-and-operand",
        "proven-selected-or-operand",
        "false-scalar-selected-or-operand",
        "if-expression-test",
        "dict-value",
        "set-element",
        "formatted-value",
        "named-expression-value",
        "starred-call-argument",
        "mapping-call-argument",
        "lambda-call-argument",
        "lambda-default",
        "immediately-invoked-zero-argument-lambda",
        "list-comprehension-first-iterable",
        "set-comprehension-first-iterable",
        "dict-comprehension-first-iterable",
        "generator-first-iterable",
    ],
)
def test_alias_invocation_in_definitely_eager_wrapper_is_detected(make_skill, invocation: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


@pytest.mark.parametrize(
    "invocation",
    [
        "delayed = lambda: _runner(payload)",
        "delayed = (_runner(payload) for item in items)",
        "result = [_runner(payload) for item in items]",
        "result = (lambda required: _runner(payload))()",
        "result = (lambda: _runner(payload))(unexpected)",
        "result = (lambda: (_runner(payload), (yield 1)))()",
        "result = (lambda: (_runner(payload), (_runner := print)))()",
        "result = (lambda: (_runner(payload), (lambda value=(_runner := print): None)))()",
        "result = (lambda: (_runner(payload), (lambda value=(yield 1): None)))()",
        "result = False and _runner(payload)",
        "result = 0 and _runner(payload)",
        "result = True or _runner(payload)",
        "result = 1 or _runner(payload)",
        "result = _runner(payload) if False else safe",
        "result = _runner(payload) if 0 else safe",
        "result = safe if True else _runner(payload)",
        "result = safe if 1 else _runner(payload)",
        "result = _runner(payload) if condition else safe",
        "result = [mutate(), _runner(payload)]",
    ],
    ids=[
        "lambda",
        "generator",
        "list-comprehension",
        "lambda-missing-required-argument",
        "zero-argument-lambda-given-an-argument",
        "generator-lambda-body-is-delayed",
        "lambda-walrus-makes-alias-local",
        "nested-lambda-default-walrus-binds-outer-lambda",
        "nested-lambda-default-yield-makes-outer-generator",
        "short-circuit-bool",
        "false-scalar-short-circuit-and",
        "short-circuit-or",
        "truthy-scalar-short-circuit-or",
        "unselected-if-body",
        "false-scalar-unselected-if-body",
        "unselected-if-else",
        "truthy-scalar-unselected-if-else",
        "conditional-if-body",
        "prior-effect-invalidates-alias",
    ],
)
def test_possibly_unevaluated_nested_alias_call_is_not_reported(make_skill, invocation: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{invocation}\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "expression",
    [
        "[_runner(payload) for item in (0,)]",
        "{_runner(payload) for item in [0]}",
        "{item: _runner(payload) for item in {0}}",
        "{_runner(key_payload): item for item in {0: 1}}",
        "[item for item in b'x' if _runner(payload)]",
        "[_runner(payload) for item in 'x' if True]",
    ],
    ids=[
        "list-result",
        "set-result",
        "dict-value",
        "dict-key",
        "filter",
        "true-filter-result",
    ],
)
def test_alias_invocation_in_guaranteed_first_comprehension_iteration_is_detected(
    make_skill,
    expression: str,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{expression}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.parametrize(
    "expression",
    [
        "[_runner(payload) for item in ()]",
        "[_runner(payload) for item in (0,) if False]",
        "[_runner(payload) for _runner in (0,)]",
        "[_runner(payload) for item in (mutate(),)]",
        "[_runner(payload) for item in (0,) if mutate()]",
        "(_runner(payload) for item in (0,))",
        "[_runner(payload) for item in (0,) for nested in (0,)]",
    ],
    ids=[
        "empty-iterable",
        "false-filter",
        "target-shadow",
        "effectful-iterable",
        "effectful-filter",
        "delayed-generator",
        "nested-generator",
    ],
)
def test_unproven_or_unreachable_comprehension_result_is_not_reported(
    make_skill,
    expression: str,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{expression}\n"

    assert _eval_findings(make_skill, source) == []


def test_immediate_lambda_does_not_inherit_a_class_local_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "class Loader:\n"
        "    _runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "    result = (lambda: _runner(payload))()\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_comprehension_does_not_inherit_a_class_local_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "class Loader:\n"
        "    _runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "    result = [_runner(payload) for item in (0,)]\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize("conversion", ["s", "r", "a"])
def test_fstring_conversion_invalidates_alias_before_format_spec(make_skill, conversion: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f'result = f"{{value!{conversion}:{{_runner(payload)}}}}"\n'
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "invocation",
    [
        'result = t"{_runner(payload)}"',
        'result = t"{value:{_runner(payload)}}"',
        'result = t"{value!r:{_runner(payload)}}"',
    ],
    ids=["value", "format-spec", "stored-conversion-before-format-spec"],
)
@pytest.mark.skipif(not hasattr(ast, "TemplateStr"), reason="template strings require Python 3.14+")
def test_template_string_interpolations_are_eager(make_skill, invocation: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_starred_arguments_run_before_textually_earlier_keywords(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "wrapper(value=_runner(payload), *mutate())\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_starred_exec_call_runs_before_textually_earlier_keyword_effect(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "wrapper(value=mutate(), *_runner(payload))\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.parametrize(
    "statement",
    [
        "if _runner(payload):\n    pass",
        "while _runner(payload):\n    break",
        "for item in _runner(payload):\n    pass",
        "with _runner(payload):\n    pass",
        "match _runner(payload):\n    case _:\n        pass",
    ],
    ids=["if-test", "while-test", "for-iterable", "with-context", "match-subject"],
)
def test_alias_invocation_in_mandatory_compound_header_is_detected(make_skill, statement: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.parametrize(
    ("definition", "expected_line"),
    [
        ("def load(value=_runner(payload)):\n    pass", 3),
        ("async def load(value=_runner(payload)):\n    pass", 3),
        ("@_runner(payload)\ndef load():\n    pass", 3),
        ("@_runner\ndef load():\n    pass", 3),
        ("@_runner\nclass Loader:\n    pass", 3),
        ("@_runner\n@mutate()\ndef load():\n    pass", 3),
        ("class Loader(_runner(payload)):\n    pass", 3),
        ("class Loader(metaclass=_runner(payload)):\n    pass", 3),
    ],
    ids=[
        "default",
        "async-default",
        "called-decorator",
        "bare-function-decorator",
        "bare-class-decorator",
        "captured-bare-decorator-before-effect",
        "class-base",
        "class-keyword",
    ],
)
def test_alias_invocation_in_eager_definition_expression_is_detected(
    make_skill,
    definition: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{definition}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize(
    ("decorator", "definition", "expected_text"),
    [
        (
            "@getattr(builtins, ''.join(['e', 'x', 'e', 'c']))",
            "def load():\n    pass",
            "getattr(...) -> builtins.exec",
        ),
        (
            "@getattr(builtins, ''.join(['e', 'x', 'e', 'c'])).__call__",
            "async def load():\n    pass",
            "getattr(...) -> builtins.exec",
        ),
        (
            "@getattr(builtins, ''.join(['e', 'x', 'e', 'c'])).__call__.__call__",
            "class Loader:\n    pass",
            "getattr(...) -> builtins.exec",
        ),
        ("@_runner.__call__", "def load():\n    pass", "_runner(...) -> builtins.exec"),
        ("@_runner.__call__.__call__", "class Loader:\n    pass", "_runner(...) -> builtins.exec"),
    ],
    ids=["direct-function", "direct-async-call", "direct-class-chained", "alias-call", "alias-chained"],
)
def test_dynamic_exec_callable_decorator_is_detected(
    make_skill,
    decorator: str,
    definition: str,
    expected_text: str,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{decorator}\n{definition}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_text"] == expected_text


@pytest.mark.parametrize(
    "definition",
    [
        "def load(value=_runner(payload)):\n    pass",
        "class Loader(_runner(payload)):\n    pass",
    ],
    ids=["function-default", "class-base"],
)
def test_direct_dynamic_exec_decorator_preserves_later_definition_inputs(
    make_skill,
    definition: str,
) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "@getattr(builtins, ''.join(['e', 'x', 'e', 'c'])).__call__\n"
        f"{definition}\n"
    )

    findings = _eval_findings(make_skill, source)

    assert [finding.line_number for finding in findings] == [3, 4]


@pytest.mark.parametrize(
    "decorator",
    [
        "@getattr(plugin, ''.join(['e', 'x', 'e', 'c']))",
        "@getattr(builtins, ''.join(['e', 'v', 'a', 'l']))",
        "@getattr(builtins, ''.join(['e', 'x', 'e', 'c'])).other.__call__",
    ],
    ids=["unreviewed-receiver", "different-name", "intervening-attribute"],
)
def test_unreviewed_dynamic_exec_decorator_is_not_claimed(make_skill, decorator: str) -> None:
    source = f"import builtins\n{decorator}\ndef load():\n    pass\n"

    assert _eval_findings(make_skill, source) == []


def test_shadowed_getattr_dynamic_exec_decorator_is_not_claimed(make_skill) -> None:
    source = (
        "import builtins\ngetattr = safe\n@getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\ndef load():\n    pass\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_effectful_decorator_precedes_function_default(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "@mutate()\n"
        "def load(value=_runner(payload)):\n"
        "    pass\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_effectful_decorator_precedes_bare_exec_decorator(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "@mutate()\n"
        "@_runner\n"
        "def load():\n"
        "    pass\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "definition",
    [
        "class Loader[_runner](_runner(payload)):\n    pass",
        "class Loader[_runner](metaclass=_runner(payload)):\n    pass",
    ],
    ids=["base", "keyword"],
)
@pytest.mark.skipif(
    "type_params" not in getattr(ast.ClassDef, "_fields", ()),
    reason="class type parameters require Python 3.12+",
)
def test_generic_class_type_parameter_shadows_exec_alias_in_header(make_skill, definition: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{definition}\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "definition",
    [
        "class Loader[T](_runner(payload)):\n    pass",
        "class Loader[T](metaclass=_runner(payload)):\n    pass",
    ],
    ids=["base", "keyword"],
)
@pytest.mark.skipif(
    "type_params" not in getattr(ast.ClassDef, "_fields", ()),
    reason="class type parameters require Python 3.12+",
)
def test_unrelated_generic_class_parameter_keeps_exec_alias_in_header(make_skill, definition: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{definition}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_module_exec_alias_invoked_in_eager_class_body_is_detected(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "class Loader:\n"
        "    _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


def test_private_class_name_does_not_inherit_unmangled_module_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "__runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "class Loader:\n"
        "    __runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize("alias", ["_runner", "__runner__"])
def test_nonprivate_class_name_keeps_module_exec_alias(make_skill, alias: str) -> None:
    source = (
        "import builtins\n"
        f"{alias} = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "class Loader:\n"
        f"    {alias}(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


@pytest.mark.parametrize(
    ("body", "expected_count"),
    [
        ("    _runner(payload)\n    _runner = None\n", 1),
        ("    _runner = None\n    _runner(payload)\n", 0),
    ],
    ids=["call-before-local-shadow", "local-shadow-before-call"],
)
def test_class_body_exec_alias_respects_source_order(make_skill, body: str, expected_count: int) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nclass Loader:\n{body}"

    assert len(_eval_findings(make_skill, source)) == expected_count


@pytest.mark.parametrize(
    ("literal", "expected_count"),
    [("a", 0), ("YQ==", 1)],
    ids=["invalid-decode-stops-class-body", "valid-decode-continues-class-body"],
)
def test_literal_base64_decode_controls_later_class_body_exec(
    make_skill,
    literal: str,
    expected_count: int,
) -> None:
    source = (
        "import base64, builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "class Loader:\n"
        f"    payload = base64.b64decode('{literal}')\n"
        "    _runner(payload)\n"
    )

    assert len(_eval_findings(make_skill, source)) == expected_count


def test_nested_class_body_uses_module_fallback_not_outer_class_locals(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "class Outer:\n"
        "    _runner = None\n"
        "    class Inner:\n"
        "        _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 6


def test_nested_class_body_does_not_inherit_outer_class_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "module_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "_runner = None\n"
        "class Outer:\n"
        "    _runner = module_runner\n"
        "    class Inner:\n"
        "        _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "body",
    [
        "    _runner(payload)\n    global _runner\n",
        "    global harmless\n    _runner(payload)\n",
    ],
    ids=["compiler-invalid-order", "bounded-global-scope"],
)
def test_class_global_scope_is_outside_bounded_body_scan(make_skill, body: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nclass Loader:\n{body}"

    assert _eval_findings(make_skill, source) == []


def test_class_local_getattr_delete_respects_shadowed_module_fallback(make_skill) -> None:
    source = (
        "getattr = None\n"
        "import builtins\n"
        "class Loader:\n"
        "    getattr = None\n"
        "    del getattr\n"
        "    _runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "    _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_unbound_class_delete_stops_before_later_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "shadowed = None\n"
        "class Loader:\n"
        "    del shadowed\n"
        "    _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "compiler_name",
    [
        "__module__",
        "__qualname__",
        *(["__firstlineno__"] if sys.version_info >= (3, 13) else []),
    ],
)
def test_compiler_seeded_class_name_shadows_module_exec_alias(make_skill, compiler_name: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"{compiler_name} = _runner\n"
        "class Loader:\n"
        f"    {compiler_name}(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_class_module_name_preserves_rebound_module_name_exec_identity(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__name__ = _runner\n"
        "class Loader:\n"
        "    __module__(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 5


@pytest.mark.parametrize(
    "cell_name",
    [
        "__class__",
        *(["__classdict__"] if sys.version_info >= (3, 12) else []),
        *(["__conditional_annotations__"] if sys.version_info >= (3, 14) else []),
    ],
)
def test_nested_class_implicit_cell_shadows_module_exec_alias(make_skill, cell_name: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"{cell_name} = _runner\n"
        "class Outer:\n"
        "    class Inner:\n"
        f"        {cell_name}(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_class_docstring_shadows_module_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__doc__ = _runner\n"
        "class Loader:\n"
        "    'class documentation'\n"
        "    __doc__(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_class_without_docstring_keeps_module_doc_fallback(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__doc__ = _runner\n"
        "class Loader:\n"
        "    __doc__(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 5


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="class annotations use deferred machinery on 3.14+")
def test_compiler_seeded_class_annotations_shadow_module_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__annotations__ = _runner\n"
        "class Loader:\n"
        "    value: int\n"
        "    __annotations__(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_future_class_annotations_seed_mapping_before_body(make_skill) -> None:
    source = (
        "from __future__ import annotations\n"
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__annotations__ = _runner\n"
        "class Loader:\n"
        "    __annotations__(payload)\n"
        "    value: int\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.skipif(sys.version_info < (3, 14), reason="uses Python 3.14 class annotation bookkeeping")
def test_class_annotation_bookkeeping_is_fresh_from_module_binding(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__conditional_annotations__ = None\n"
        "class Loader:\n"
        "    value: int\n"
        "    _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 6


def test_alias_invocation_in_assert_test_is_detected(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nassert _runner(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("try:\n    _runner(payload)\nexcept Exception:\n    pass", 4),
        ("try:\n    pass\nfinally:\n    _runner(payload)", 6),
        ("try:\n    pass\nexcept Exception:\n    pass\nelse:\n    _runner(payload)", 8),
        ("try:\n    pass\nexcept Exception:\n    pass\nfinally:\n    _runner(payload)", 8),
        ("try:\n    pass\nexcept* Exception:\n    pass\nelse:\n    _runner(payload)", 8),
        ("try:\n    pass\nexcept* Exception:\n    pass\nfinally:\n    _runner(payload)", 8),
        ("global harmless\n_runner(payload)", 4),
        ("value = 0\nvalue += _runner(payload)", 4),
        ("if True:\n    _runner(payload)", 4),
        ("if not False:\n    _runner(payload)", 4),
        ("if not not True:\n    _runner(payload)", 4),
        ("if not [0]:\n    pass\nelse:\n    _runner(payload)", 6),
        ("if 1:\n    _runner(payload)", 4),
        ("while True:\n    _runner(payload)\n    break", 4),
        ("while not 0:\n    _runner(payload)\n    break", 4),
        ("while 1:\n    _runner(payload)\n    break", 4),
        ("while 0:\n    pass\nelse:\n    _runner(payload)", 6),
        ("if False:\n    pass\nelse:\n    _runner(payload)", 6),
        ("if 0:\n    pass\nelse:\n    _runner(payload)", 6),
        ("assert False, _runner(payload)", 3),
        ("assert 0, _runner(payload)", 3),
        ("getattr += _runner(payload)", 3),
        ("if True:\n    getattr = None\n    _runner(payload)", 5),
        ("if True:\n    getattr = _runner\n    getattr(payload)", 5),
    ],
    ids=[
        "try-body-prefix",
        "try-finally-prefix",
        "inert-try-else",
        "inert-try-finally-with-handler",
        "inert-try-star-else",
        "inert-try-star-finally",
        "module-global-declaration",
        "augassign-bound-name-value",
        "literal-true-if-body",
        "not-false-if-body",
        "double-not-true-if-body",
        "not-nonempty-list-else",
        "truthy-number-if-body",
        "literal-true-while-body",
        "not-zero-while-body",
        "truthy-number-while-body",
        "false-number-while-else",
        "literal-false-if-else",
        "false-number-if-else",
        "literal-false-assert-message",
        "false-number-assert-message",
        "builtin-getattr-augassign",
        "nested-getattr-rebind-keeps-existing-alias",
        "nested-getattr-copy-keeps-exec-provenance",
    ],
)
def test_alias_invocation_in_guaranteed_statement_position_is_detected(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize("iterable", ["()", "[]", "{}", "''", "b''"])
def test_empty_literal_for_executes_guaranteed_else(make_skill, iterable: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"for item in {iterable}:\n"
        "    pass\n"
        "else:\n"
        "    _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 6


@pytest.mark.parametrize("iterable", ["()", "[]", "{}", "''", "b''"])
def test_empty_literal_for_preserves_provenance_after_loop(make_skill, iterable: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"for item in {iterable}:\n"
        "    pass\n"
        "_runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 5


@pytest.mark.parametrize(
    ("loop", "invocation", "expected_line"),
    [
        ("for _runner in ():\n    pass", "_runner(payload)", 5),
        ("for item in ():\n    pass\nelse:\n    alias = _runner", "alias(payload)", 7),
    ],
    ids=["skipped-target-rebind", "else-created-alias"],
)
def test_empty_literal_for_preserves_exact_resulting_bindings(
    make_skill,
    loop: str,
    invocation: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{loop}\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize(
    "else_body",
    ["_runner = None", "mutate()"],
    ids=["rebind", "effect"],
)
def test_empty_literal_for_does_not_restore_invalidated_else_provenance(
    make_skill,
    else_body: str,
) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "for item in ():\n"
        "    pass\n"
        "else:\n"
        f"    {else_body}\n"
        "_runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    ("loop", "invocation", "expected_line"),
    [
        ("while False:\n    _runner(unreachable_payload)", "_runner(payload)", 5),
        (
            "while 0:\n    mutate()\nelse:\n    alias = _runner",
            "alias(payload)",
            7,
        ),
    ],
    ids=["unreachable-body", "else-created-alias"],
)
def test_statically_false_while_preserves_selected_state(
    make_skill,
    loop: str,
    invocation: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{loop}\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize("else_body", ["_runner = None", "mutate()"], ids=["rebind", "effect"])
def test_statically_false_while_does_not_restore_invalidated_else_state(
    make_skill,
    else_body: str,
) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "while False:\n"
        "    pass\n"
        "else:\n"
        f"    {else_body}\n"
        "_runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "match_statement",
    [
        "match mutate():\n    case _:\n        _runner(payload)",
        "match 1:\n    case _ if False:\n        _runner(payload)",
        "match 1:\n    case _runner:\n        _runner(payload)",
        "match 1:\n    case _:\n        mutate()\n        _runner(payload)",
        "match 1:\n    case 1:\n        pass\n    case _:\n        _runner(payload)",
        "match 1:\n    case _:\n        raise\n        _runner(payload)",
    ],
    ids=[
        "effectful-subject",
        "guarded-case",
        "capture-shadows-alias",
        "body-mutation",
        "earlier-matching-case",
        "unreachable-body-suffix",
    ],
)
def test_unproven_or_unreachable_match_body_is_not_reported(
    make_skill,
    match_statement: str,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{match_statement}\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(("subject", "pattern"), [("1", "_"), ("[]", "item")], ids=["wildcard", "capture"])
def test_alias_invocation_in_leading_irrefutable_match_body_is_detected(
    make_skill,
    subject: str,
    pattern: str,
) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"match {subject}:\n"
        f"    case {pattern}:\n"
        "        _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 5


def test_leading_irrefutable_match_scans_the_guaranteed_body_prefix(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "match 1:\n"
        "    case _:\n"
        "        alias = _runner\n"
        "        alias(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 6


@pytest.mark.parametrize("non_iterable", ["None", "False", "0", "0.0"])
def test_falsey_non_iterable_for_does_not_reach_else(make_skill, non_iterable: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"for item in {non_iterable}:\n"
        "    pass\n"
        "else:\n"
        "    _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize("iterable", ["(0,)", "[0]", "{0}", "{0: 1}", "'x'", "b'x'"])
def test_nonempty_literal_for_executes_guaranteed_first_iteration(make_skill, iterable: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"for item in {iterable}:\n"
        "    _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


def test_nonempty_literal_for_target_rebinding_invalidates_exec_alias(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "for _runner in (0,):\n"
        "    _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    ("branch", "invocation", "expected_line"),
    [
        ("if True:\n    pass", "_runner(payload)", 5),
        ("if False:\n    mutate()\nelse:\n    pass", "_runner(payload)", 7),
        ("if True:\n    alias = _runner", "alias(payload)", 5),
    ],
    ids=["true-body", "false-else", "updated-alias"],
)
def test_completed_deterministic_if_preserves_provenance(
    make_skill,
    branch: str,
    invocation: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{branch}\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


def test_completed_deterministic_if_preserves_exec_rebinding(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "if True:\n"
        "    _runner = None\n"
        "_runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "test",
    [
        "[missing]",
        "(mutate(),)",
        "{missing}",
        "{missing: 1}",
        "{'key': mutate()}",
        "not condition",
        "not mutate()",
    ],
    ids=["list-name", "tuple-call", "set-name", "dict-key", "dict-value-call", "not-name", "not-call"],
)
def test_effectful_or_failing_container_test_does_not_select_branch(make_skill, test: str) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"if {test}:\n"
        "    _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    ("literal", "expected_line"),
    [
        ("-1", 4),
        ("--1", 4),
        ("1.0", 4),
        ("1j", 4),
        ("'enabled'", 4),
        ("b'enabled'", 4),
        ("...", 4),
        ("[1]", 4),
        ("(1,)", 4),
        ("{1}", 4),
        ("{'enabled': 1}", 4),
        ("0.0", 6),
        ("0j", 6),
        ("''", 6),
        ("b''", 6),
        ("None", 6),
        ("[]", 6),
        ("()", 6),
        ("{}", 6),
    ],
    ids=[
        "truthy-signed-int",
        "truthy-repeated-sign",
        "truthy-float",
        "truthy-complex",
        "truthy-string",
        "truthy-bytes",
        "truthy-ellipsis",
        "truthy-list",
        "truthy-tuple",
        "truthy-set",
        "truthy-dict",
        "false-float",
        "false-complex",
        "false-string",
        "false-bytes",
        "false-none",
        "false-list",
        "false-tuple",
        "false-dict",
    ],
)
def test_inert_literal_selects_only_guaranteed_if_branch(
    make_skill,
    literal: str,
    expected_line: int,
) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"if {literal}:\n"
        "    _runner(body_payload)\n"
        "else:\n"
        "    _runner(else_payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("try:\n    raise\nfinally:\n    _runner(payload)", 6),
        ("try:\n    alias = _runner\n    raise\nfinally:\n    alias(payload)", 7),
        ("try:\n    if 1:\n        raise\nfinally:\n    _runner(payload)", 7),
        ("try:\n    raise\n    _runner = safe\nfinally:\n    _runner(payload)", 7),
        (
            "try:\n    try:\n        raise\n    finally:\n        pass\nfinally:\n    _runner(payload)",
            9,
        ),
        ("while True:\n    try:\n        break\n    finally:\n        _runner(payload)", 7),
        ("while True:\n    try:\n        continue\n    finally:\n        _runner(payload)", 7),
        ("try:\n    while True:\n        break\nfinally:\n    _runner(payload)", 7),
        (
            "while True:\n"
            "    try:\n"
            "        break\n"
            "    except Exception:\n"
            "        mutate()\n"
            "    finally:\n"
            "        _runner(payload)",
            9,
        ),
        (
            "while True:\n"
            "    try:\n"
            "        break\n"
            "    except* Exception:\n"
            "        mutate()\n"
            "    finally:\n"
            "        _runner(payload)",
            9,
        ),
        (
            "while True:\n"
            "    try:\n"
            "        continue\n"
            "    except* Exception:\n"
            "        mutate()\n"
            "    finally:\n"
            "        _runner(payload)",
            9,
        ),
    ],
    ids=[
        "bare-raise",
        "alias-created-before-raise",
        "raise-in-guaranteed-branch",
        "unreachable-rebind-after-raise",
        "nested-finally",
        "break-finally",
        "continue-finally",
        "loop-break-before-outer-finally",
        "break-skips-handler-before-finally",
        "break-skips-exception-group-handler-before-finally",
        "continue-skips-exception-group-handler-before-finally",
    ],
)
def test_inert_abrupt_exit_preserves_provenance_for_guaranteed_finally(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("try:\n    raise\nexcept:\n    pass\nfinally:\n    _runner(payload)", 8),
        ("try:\n    raise\nexcept:\n    _runner(payload)\nfinally:\n    pass", 6),
        (
            "try:\n    raise\nexcept:\n    alias = _runner\nfinally:\n    alias(payload)",
            8,
        ),
        ("try:\n    raise\nexcept:\n    raise\nfinally:\n    _runner(payload)", 8),
        (
            "try:\n    raise\nexcept:\n    pass\nfinally:\n    pass\n_runner(payload)",
            9,
        ),
        ("try:\n    pass\nfinally:\n    pass\n_runner(payload)", 7),
    ],
    ids=[
        "caught-raise-finally",
        "caught-raise-handler",
        "handler-alias-finally",
        "handler-reraise-finally",
        "caught-raise-continuation",
        "normal-try-continuation",
    ],
)
def test_inert_try_path_preserves_guaranteed_exec_provenance(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize(
    "statement",
    [
        "try:\n    raise\nexcept:\n    _runner = None\nfinally:\n    _runner(payload)",
        "try:\n    raise\nexcept:\n    mutate()\nfinally:\n    _runner(payload)",
        "try:\n    raise\nexcept RuntimeError:\n    pass\nfinally:\n    _runner(payload)",
        ("try:\n    raise\nexcept RuntimeError:\n    pass\nexcept:\n    pass\nfinally:\n    _runner(payload)"),
        "try:\n    raise\nexcept* BaseException:\n    pass\nfinally:\n    _runner(payload)",
        "try:\n    raise ValueError()\nexcept:\n    pass\nfinally:\n    _runner(payload)",
        "try:\n    raise\nexcept:\n    pass\nelse:\n    _runner(payload)",
    ],
    ids=[
        "handler-rebind",
        "handler-effect",
        "typed-handler",
        "preceding-typed-handler",
        "exception-group-handler",
        "effectful-raise",
        "unreachable-else",
    ],
)
def test_unproven_raise_handler_flow_does_not_claim_exec(make_skill, statement: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "statement",
    [
        "try:\n    _runner = None\n    raise\nfinally:\n    _runner(payload)",
        "try:\n    mutate()\n    raise\nfinally:\n    _runner(payload)",
        "try:\n    raise\n    _runner(payload)\nfinally:\n    pass",
        "try:\n    raise\nfinally:\n    _runner = None\n    _runner(payload)",
        "try:\n    raise\nexcept RuntimeError:\n    mutate()\nfinally:\n    _runner(payload)",
        "try:\n    raise\nfinally:\n    pass\n_runner(payload)",
        "while True:\n    try:\n        break\n        _runner(payload)\n    finally:\n        pass",
        "try:\n    while True:\n        continue\nfinally:\n    _runner(payload)",
    ],
    ids=[
        "alias-rebound-before-raise",
        "effect-before-raise",
        "unreachable-call-after-raise",
        "alias-rebound-in-finally",
        "handler-may-mutate-alias",
        "no-provenance-leak-after-try",
        "unreachable-call-after-break",
        "infinite-continue-before-outer-finally",
    ],
)
def test_inert_abrupt_exit_does_not_restore_stale_or_unreachable_provenance(
    make_skill,
    statement: str,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    assert _eval_findings(make_skill, source) == []


def test_effectful_raise_does_not_restore_alias_for_finally(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "try:\n"
        "    raise _runner(payload)\n"
        "finally:\n"
        "    _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


def test_future_feature_binding_is_known_for_augassign(make_skill) -> None:
    source = (
        "from __future__ import annotations\n"
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "annotations += _runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("_runner(payload).field += 1", 3),
        ("container = []\ncontainer[_runner(payload)] += 1", 4),
    ],
    ids=["attribute-target", "subscript-target"],
)
def test_alias_invocation_in_augassign_target_is_detected(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("_runner(payload).field = 0", 3),
        ("container = []\ncontainer[_runner(payload)] = 0", 4),
        (
            "container = []\nalias = container[alias(payload)] = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))",
            4,
        ),
        ("del _runner(payload).field", 3),
        ("container = []\ndel container[_runner(payload)]", 4),
        ("known = 0\ndel known, _runner(payload).field", 4),
        ("getattr[_runner(payload)] = 0", 3),
        ("del getattr[_runner(payload)]", 3),
    ],
    ids=[
        "assign-attribute",
        "assign-subscript",
        "chained-assign",
        "delete-attribute",
        "delete-subscript",
        "delete-after-known-name",
        "builtin-getattr-assign-target",
        "builtin-getattr-delete-target",
    ],
)
def test_alias_invocation_in_assignment_target_address_is_detected(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


def test_delete_stops_before_target_after_unbound_name(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "del missing, _runner(payload).field\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_delete_does_not_treat_builtin_getattr_as_namespace_bound(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "del getattr, _runner(payload).field\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "statement",
    [
        "missing[_runner(payload)] = 0",
        "missing[_runner(payload)]: int = 0",
        "missing[_runner(payload)] += 1",
        "del missing[_runner(payload)]",
        "container = []\ncontainer[missing:_runner(payload)] = 0",
        "container = []\ncontainer[missing, _runner(payload)] = 0",
    ],
    ids=["assign", "annassign", "augassign", "delete", "slice", "tuple-index"],
)
def test_target_address_stops_before_alias_after_unbound_name(make_skill, statement: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "statement",
    [
        "value = missing\nvalue += _runner(payload)",
        "container = [missing]\ncontainer[_runner(payload)] = 0",
        "container = (missing,)\ndel container[_runner(payload)]",
    ],
    ids=["augassign-target", "assignment-target", "delete-target"],
)
def test_unproven_rhs_does_not_create_known_target(make_skill, statement: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    assert _eval_findings(make_skill, source) == []


def test_unproven_parenthesized_annassign_rhs_does_not_create_known_target(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "(alias): object = missing\n"
        "alias += _runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "statement",
    [
        "base64.b64decode('a')[_runner(payload)] = 0",
        "container = []\ncontainer[_runner(payload)]: int = base64.b64decode('a')",
        "decoded = base64.b64decode('a')\ndecoded += _runner(payload)",
    ],
    ids=["target-address", "annotated-target-address", "later-known-binding"],
)
def test_invalid_literal_base64_decode_does_not_prove_later_evaluation(make_skill, statement: str) -> None:
    source = f"import base64, builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    assert _eval_findings(make_skill, source) == []


def test_valid_literal_base64_decode_allows_annotated_target_address(make_skill) -> None:
    source = (
        "import base64, builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "container = []\n"
        "container[_runner(payload)]: int = base64.b64decode('YQ==')\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred by default on Python 3.14+")
@pytest.mark.parametrize(
    ("literal", "expected_count"),
    [("a", 0), ("YQ==", 1)],
    ids=["invalid-stops-before-annotation", "valid-reaches-annotation"],
)
def test_literal_base64_decode_controls_eager_name_annotation(
    make_skill,
    literal: str,
    expected_count: int,
) -> None:
    source = (
        "import base64, builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"alias: _runner(payload) = base64.b64decode('{literal}')\n"
    )

    assert len(_eval_findings(make_skill, source)) == expected_count


@pytest.mark.parametrize(
    ("literal", "expected_count"),
    [("a", 0), ("YQ==", 1)],
    ids=["invalid-stops-expression", "valid-continues-expression"],
)
def test_literal_base64_decode_controls_later_tuple_evaluation(
    make_skill,
    literal: str,
    expected_count: int,
) -> None:
    source = (
        "import base64, builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = (base64.b64decode('{literal}'), _runner(payload))\n"
    )

    assert len(_eval_findings(make_skill, source)) == expected_count


@pytest.mark.parametrize(
    "assignment",
    [
        "alias = _runner\nalias(payload)",
        "_runner = _runner\n_runner(payload)",
    ],
    ids=["new-name", "self-assignment"],
)
def test_dynamic_exec_provenance_survives_plain_name_copy(make_skill, assignment: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{assignment}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


@pytest.mark.parametrize(
    ("assignment", "receiver"),
    [
        ("bi = builtins", "bi"),
        ("bi = bi2 = builtins", "bi2"),
        ("(bi): object = builtins", "bi"),
    ],
    ids=["plain", "chained", "parenthesized-annotated"],
)
def test_builtins_provenance_survives_name_copy(make_skill, assignment: str, receiver: str) -> None:
    source = (
        "import builtins\n"
        f"{assignment}\n"
        f"_runner = getattr({receiver}, ''.join(['e', 'x', 'e', 'c']))\n"
        "_runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 4


def test_base64_provenance_survives_name_copy(make_skill) -> None:
    source = (
        "import base64, builtins\n"
        "decoder = base64\n"
        "decoded = decoder.b64decode('just a test')\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "_runner(decoded)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 5


@pytest.mark.parametrize(
    "setup",
    [
        "lookup = getattr",
        "lookup = getattr\ngetattr = None",
        "(lookup): object = getattr",
    ],
    ids=["plain", "captured-before-rebind", "parenthesized-annotated"],
)
def test_builtin_getattr_provenance_survives_name_copy(make_skill, setup: str) -> None:
    source = f"import builtins\n{setup}\n_runner = lookup(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == source.count("\n")


def test_deleting_module_getattr_binding_restores_builtin_provenance(make_skill) -> None:
    source = (
        "getattr = None\n"
        "del getattr\n"
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "_runner(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 5


def test_arbitrary_effect_does_not_restore_builtin_provenance(make_skill) -> None:
    source = "mutate()\nimport builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    ("source_prefix", "assignment"),
    [
        ("", "(alias): object = _runner"),
        ("from __future__ import annotations\n", "(alias): object = _runner"),
        ("", "(alias): object = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))"),
        (
            "from __future__ import annotations\n",
            "(alias): object = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))",
        ),
    ],
    ids=["eager-copy", "deferred-copy", "eager-initial-lookup", "deferred-initial-lookup"],
)
def test_dynamic_exec_provenance_survives_parenthesized_annotated_name_assignment(
    make_skill,
    source_prefix: str,
    assignment: str,
) -> None:
    source = (
        source_prefix
        + "import builtins\n"
        + "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        + f"{assignment}\n"
        + "alias(payload)\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == source.count("\n")


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="Python 3.14 defers module annotation storage")
def test_eager_simple_annotated_copy_does_not_cross_user_annotation_mapping(make_skill) -> None:
    source = (
        "import builtins\n"
        + "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        + "alias: object = _runner\n"
        + "alias(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_future_simple_annotated_copy_does_not_cross_user_annotation_mapping(make_skill) -> None:
    source = (
        "from __future__ import annotations\n"
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "alias: object = _runner\n"
        "alias(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.skipif(sys.version_info < (3, 14), reason="Python 3.14+ defers module annotation storage")
def test_deferred_simple_annotated_lookup_keeps_exec_provenance(make_skill) -> None:
    source = "import builtins\nalias: object = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nalias(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.skipif(sys.version_info < (3, 14), reason="uses Python 3.14 deferred module annotations")
def test_rebound_conditional_annotations_stops_before_later_exec(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "__conditional_annotations__ = None\n"
        "value: int = 1\n"
        "_runner(payload)\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.skipif(sys.version_info < (3, 14), reason="uses Python 3.14 deferred module annotations")
def test_conditional_annotations_rebind_does_not_hide_prior_exec(make_skill) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "_runner(payload)\n"
        "__conditional_annotations__ = None\n"
        "value: int = 1\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred by default on Python 3.14+")
@pytest.mark.parametrize(
    "definition",
    [
        "value: _runner(payload)",
        "(value): _runner(payload)",
        "def load(value: _runner(payload)):\n    pass",
    ],
    ids=["annotated-assignment", "parenthesized-annotated-assignment", "function-parameter"],
)
def test_dynamic_exec_in_eager_annotation_is_detected(make_skill, definition: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{definition}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("_runner(payload).field: int", 3),
        ("_runner(payload).field: int = 0", 3),
        ("container = []\ncontainer[_runner(payload)]: int", 4),
        ("container = []\ncontainer[_runner(payload)]: int = 0", 4),
    ],
    ids=["attribute", "attribute-with-value", "subscript", "subscript-with-value"],
)
def test_dynamic_exec_in_annotated_target_address_is_detected(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred by default on Python 3.14+")
@pytest.mark.parametrize(
    ("statement", "expected_line"),
    [
        ("container = None\ncontainer.field: _runner(payload)", 4),
        ("container = []\nkey = 0\ncontainer[key]: _runner(payload)", 5),
    ],
    ids=["attribute", "subscript"],
)
def test_dynamic_exec_in_valueless_nonsimple_annotation_is_detected(
    make_skill,
    statement: str,
    expected_line: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{statement}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == expected_line


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred by default on Python 3.14+")
@pytest.mark.parametrize(
    ("definition", "expected_count"),
    [
        ("def load(value: mutate(), /, other: _runner(payload)):\n    pass", 1),
        ("def load(value: _runner(payload), /, other: mutate()):\n    pass", 0),
    ],
    ids=["regular-arg-before-positional-only", "regular-arg-effect-before-positional-only"],
)
def test_eager_function_annotations_follow_compiler_order(
    make_skill,
    definition: str,
    expected_count: int,
) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{definition}\n"

    assert len(_eval_findings(make_skill, source)) == expected_count


@pytest.mark.parametrize(
    "definition",
    [
        "value: _runner(payload)",
        "(value): _runner(payload)",
        "def load(value: _runner(payload)):\n    pass",
    ],
    ids=["annotated-assignment", "parenthesized-annotated-assignment", "function-parameter"],
)
def test_future_annotations_do_not_execute_dynamic_exec(make_skill, definition: str) -> None:
    source = (
        "from __future__ import annotations\n"
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"{definition}\n"
    )

    assert _eval_findings(make_skill, source) == []


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred by default on Python 3.14+")
@pytest.mark.skipif(
    "type_params" not in getattr(ast.FunctionDef, "_fields", ()),
    reason="function type parameters require Python 3.12+",
)
@pytest.mark.parametrize(
    ("type_parameter", "expected_count"),
    [("_runner", 0), ("T", 1)],
    ids=["shadowing-type-parameter", "unrelated-type-parameter"],
)
def test_generic_function_annotation_uses_type_parameter_scope(
    make_skill,
    type_parameter: str,
    expected_count: int,
) -> None:
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"def load[{type_parameter}](value: _runner(payload)):\n"
        "    pass\n"
    )

    assert len(_eval_findings(make_skill, source)) == expected_count


def test_guaranteed_prefix_nesting_limit_is_enforced(make_skill) -> None:
    nested = "_runner(payload)"
    for _ in range(34):
        nested = "if True:\n" + "\n".join(f"    {line}" for line in nested.splitlines())
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{nested}\n"

    assert _eval_findings(make_skill, source) == []


def test_guaranteed_prefix_binding_limit_is_enforced() -> None:
    assignments = "\n".join(f"    value_{index} = 0" for index in range(MAX_PYTHON_SHELL_BINDINGS + 10))
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        "if True:\n"
        f"{assignments}\n"
        "    _runner(payload)\n"
    )

    assert find_python_shell_candidates(source) == ()


def test_class_compiler_bindings_are_charged_before_body_scan() -> None:
    assignments = "\n".join(f"value_{index} = 0" for index in range(MAX_PYTHON_SHELL_BINDINGS - 5))
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"{assignments}\n"
        "class Loader:\n"
        "    _runner(payload)\n"
    )

    assert find_python_shell_candidates(source) == ()


def test_eager_expression_traversal_limit_is_enforced(make_skill) -> None:
    elements = ", ".join(("0",) * MAX_PYTHON_SHELL_EAGER_EXPR_NODES + ("_runner(payload)",))
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nresult = [{elements}]\n"

    assert _eval_findings(make_skill, source) == []


def test_literal_truth_proof_accepts_an_expression_at_the_node_limit(make_skill) -> None:
    elements = ", ".join(("0",) * (MAX_PYTHON_SHELL_EAGER_EXPR_NODES - 3))
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = _runner(payload) if [{elements}] else None\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_literal_truth_proof_rejects_an_expression_over_the_node_limit(make_skill) -> None:
    elements = ", ".join(("0",) * (MAX_PYTHON_SHELL_EAGER_EXPR_NODES - 2))
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = _runner(payload) if [{elements}] else None\n"
    )

    assert _eval_findings(make_skill, source) == []


def _literal_unary_test_node_limit(monkeypatch: pytest.MonkeyPatch) -> int:
    """Keep the unary boundary test below CPython 3.11's parser recursion cap."""

    if sys.version_info >= (3, 12):
        return MAX_PYTHON_SHELL_EAGER_EXPR_NODES
    node_limit = 128
    monkeypatch.setattr(
        "skill_scanner.core.static_analysis.python_shell_semantics.MAX_PYTHON_SHELL_EAGER_EXPR_NODES",
        node_limit,
    )
    return node_limit


def test_signed_literal_truth_proof_accepts_an_expression_at_the_node_limit(
    make_skill,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_limit = _literal_unary_test_node_limit(monkeypatch)
    signs = "-" * (node_limit - 3)
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = _runner(payload) if {signs}1 else None\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_signed_literal_truth_proof_rejects_an_expression_over_the_node_limit(
    make_skill,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_limit = _literal_unary_test_node_limit(monkeypatch)
    signs = "-" * (node_limit - 2)
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = _runner(payload) if {signs}1 else None\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_not_literal_truth_proof_accepts_an_expression_at_the_node_limit(
    make_skill,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_limit = _literal_unary_test_node_limit(monkeypatch)
    negation_count = node_limit - 3
    literal = "False" if negation_count % 2 else "True"
    condition = "not " * negation_count + literal
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = _runner(payload) if {condition} else None\n"
    )

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_not_literal_truth_proof_rejects_an_expression_over_the_node_limit(
    make_skill,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_limit = _literal_unary_test_node_limit(monkeypatch)
    negation_count = node_limit - 2
    literal = "False" if negation_count % 2 else "True"
    condition = "not " * negation_count + literal
    source = (
        "import builtins\n"
        "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
        f"result = _runner(payload) if {condition} else None\n"
    )

    assert _eval_findings(make_skill, source) == []


def test_direct_alias_invocation_in_module_raise_is_detected(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nraise _runner(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


def test_module_raise_of_alias_without_invocation_is_not_reported(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nraise _runner\n"

    assert _eval_findings(make_skill, source) == []


def test_direct_alias_invocation_in_raise_cause_is_detected(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nraise RuntimeError from _runner(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


def test_candidates_are_owned_by_their_canonical_rules(make_skill) -> None:
    source = """import builtins
_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))
_runner(payload)
import subprocess
enabled = True
subprocess.run(['echo', 'ok'], shell=enabled)
"""

    candidates = find_python_shell_candidates(source)

    assert [(candidate.rule_id, candidate.line_number) for candidate in candidates] == [
        (_EVAL_RULE_ID, 3),
        (_SHELL_RULE_ID, 6),
    ]
    skill = make_skill({"tool.py": source})
    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    semantic_findings = [
        finding for finding in findings if str(finding.metadata.get("matched_pattern", "")).startswith("python_ast:")
    ]
    assert [(finding.rule_id, finding.line_number) for finding in semantic_findings] == [
        (_EVAL_RULE_ID, 3),
        (_SHELL_RULE_ID, 6),
    ]


def test_direct_exec_is_not_duplicated_by_semantic_supplement(make_skill) -> None:
    findings = _eval_findings(make_skill, "exec(payload)\n")

    assert len(findings) == 1
    assert findings[0].metadata["matched_pattern"] != _PATTERN


def test_dynamic_exec_alias_is_not_duplicated_when_policy_keeps_raw_findings(make_skill) -> None:
    source = "import builtins\nexec = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nexec(payload)\n"
    policy = ScanPolicy.default()
    policy.rule_scoping.dedupe_duplicate_findings = False

    findings = _eval_findings(make_skill, source, analyzer=StaticAnalyzer(use_yara=False, policy=policy))

    assert len(findings) == 1
    assert findings[0].metadata["matched_pattern"] != _PATTERN


@pytest.mark.parametrize(
    "source",
    [
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n",
        "import builtins\n_runner = getattr(plugin, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nsuffix = 'c'\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', suffix]))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, '-'.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['p', 'r', 'i', 'n', 't']))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner = safe\n_runner(payload)\n",
        "import builtins\nbuiltins = plugin\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nbuiltins.exec = safe\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nsetattr(builtins, 'exec', print)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nglobals()['getattr'] = safe_lookup\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nvars(builtins)['exec'] = print\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nimport builtins as bi\nx = setattr(bi, 'exec', print)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nignored = setattr(__import__('builtins'), 'exec', print)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nimport plugin\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins, plugin\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nfrom plugin import hook\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\ngetattr = safe_lookup\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nx = (getattr := safe_lookup)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nx = (builtins := plugin)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\ndef getattr(*args):\n    return safe_lookup(*args)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\ndef builtins():\n    return plugin\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nfrom plugin import *\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nglobals()['_runner'] = safe\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nmutate()\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nif enabled:\n    _runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\ndel _runner\n_runner(payload)\n",
        "def run():\n    import builtins\n    runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n    runner(payload)\n",
    ],
    ids=[
        "lookup-without-invocation",
        "wrong-receiver",
        "runtime-name-part",
        "nonempty-separator",
        "harmless-builtin",
        "callable-reassigned",
        "builtins-shadowed",
        "builtin-exec-replaced",
        "builtin-exec-replaced-via-setattr",
        "getattr-replaced-via-globals",
        "builtin-exec-replaced-via-vars",
        "one-of-multiple-builtins-aliases-mutates-exec",
        "builtin-exec-replaced-through-untracked-import",
        "untrusted-import",
        "mixed-multi-import",
        "untrusted-import-from",
        "getattr-shadowed",
        "getattr-shadowed-by-named-expression",
        "builtins-shadowed-by-named-expression",
        "getattr-shadowed-by-definition",
        "builtins-shadowed-by-definition",
        "wildcard-import-may-shadow",
        "callable-replaced-via-globals",
        "effect-after-binding",
        "compound-invocation",
        "deleted-alias-invocation",
        "delayed-function-scope",
    ],
)
def test_unproven_or_nonexecuting_variants_are_not_reported(make_skill, source: str) -> None:
    assert _eval_findings(make_skill, source) == []


def test_literal_join_part_limit_is_enforced(make_skill) -> None:
    parts = ", ".join(["'e'", "'x'", "'e'", "'c'", *("''" for _ in range(13))])
    source = f"import builtins\n_runner = getattr(builtins, ''.join([{parts}]))\n_runner(payload)\n"

    assert _eval_findings(make_skill, source) == []


def test_dynamic_exec_respects_rule_disabling(make_skill) -> None:
    analyzer = StaticAnalyzer(use_yara=False, disabled_rules={_EVAL_RULE_ID})

    assert _eval_findings(make_skill, ISSUE_204_SOURCE, analyzer=analyzer) == []


def test_dynamic_exec_respects_documentation_scoping(make_skill) -> None:
    policy = ScanPolicy.default()
    policy.rule_scoping.skip_in_docs.add(_EVAL_RULE_ID)
    analyzer = StaticAnalyzer(use_yara=False, policy=policy)

    assert _eval_findings(make_skill, ISSUE_204_SOURCE, analyzer=analyzer, path="docs/example.py") == []


def test_dynamic_exec_respects_rule_file_types(make_skill, tmp_path) -> None:
    rules_file = tmp_path / "javascript-only.yaml"
    rules_file.write_text(
        """- id: COMMAND_INJECTION_EVAL
  category: command_injection
  severity: CRITICAL
  patterns: ['exec\\s*\\(']
  file_types: [javascript]
  description: JavaScript-only execution
  remediation: Avoid dynamic execution
""",
        encoding="utf-8",
    )

    assert (
        _eval_findings(
            make_skill,
            ISSUE_204_SOURCE,
            analyzer=StaticAnalyzer(rules_file=rules_file, use_yara=False),
        )
        == []
    )


def test_malformed_python_is_ignored_without_crashing(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c'])\n_runner(payload)\n"

    assert _eval_findings(make_skill, source) == []


@pytest.mark.parametrize(
    "source",
    [
        (
            "import builtins\n"
            "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
            "from __future__ import annotations\n"
            "_runner(payload)\n"
        ),
        (
            "import builtins\n"
            "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
            "if True:\n"
            "    from __future__ import annotations\n"
            "    _runner(payload)\n"
        ),
        (
            "from __future__ import made_up_feature\n"
            "import builtins\n"
            "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
            "_runner(payload)\n"
        ),
        (
            "import builtins\n"
            "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
            "class Loader:\n"
            "    _runner(payload)\n"
            "    return\n"
        ),
        (
            "import builtins\n"
            "_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n"
            "def load(value, value, default=_runner(payload)):\n"
            "    pass\n"
        ),
    ],
    ids=[
        "late-future-import",
        "nested-future-import",
        "unknown-future-feature",
        "class-return",
        "duplicate-parameter",
    ],
)
def test_compiler_invalid_source_is_ignored(make_skill, source: str) -> None:
    with pytest.raises(SyntaxError):
        compile(source, "<test>", "exec")

    assert _eval_findings(make_skill, source) == []
