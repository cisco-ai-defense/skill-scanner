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

"""Bounded, syntax-aware detection of active dynamic execution instructions.

The broad signature packs intentionally remain the recall-oriented candidate
extractors.  This module adds one core-owned, high-confidence signal for calls
that are actually present in active SKILL.md instructions or code.  It does
not interpret prose as source code, execute samples, or inspect arbitrary
package objects.
"""

from __future__ import annotations

import ast
import hashlib
import re
import textwrap
from dataclasses import dataclass
from typing import Literal

from ..models import Finding, Severity, Skill, ThreatCategory
from ..static_analysis.javascript_tokens import (
    JavascriptToken as _JsToken,
)
from ..static_analysis.javascript_tokens import (
    javascript_token_prefix,
    tokenize_javascript,
)

RULE_ID = "ACTIVE_DYNAMIC_EXECUTION"

# These limits are deliberately below the semantic projection limits.  A
# broad signature can still retain a candidate if this higher-confidence
# parser declines an oversized or malformed region.
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_LINES = 32_768
MAX_FENCED_BLOCKS = 512
MAX_BLOCK_BYTES = 128 * 1024
MAX_AST_NODES = 8_192
MAX_JS_TOKENS = 16_384
MAX_DETECTIONS = 64
MAX_INLINE_CHARS = 4_096

_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
# Many shipped skills use a short bold label as a semantic section heading.
# Recognize only a complete, bounded line so ordinary emphasized prose cannot
# reclassify the following executable region.
_BOLD_HEADING_RE = re.compile(r"^\s{0,3}\*\*(?P<title>[^*\n]{1,128}?)\*\*\s*:?[ \t]*$")
_NEGATIVE_SECTION_RE = re.compile(
    r"\b(?:anti[- ]?patterns?|bad|dangerous|do not use|insecure|negative|prohibited|unsafe|what not to do)\b",
    re.IGNORECASE,
)
_EXAMPLE_SECTION_RE = re.compile(
    r"\b(?:demos?|documentation|examples?|reference|samples?|testing)\b",
    re.IGNORECASE,
)
_INLINE_EXAMPLE_RE = re.compile(
    r"\b(?:e\.g\.|for example|for instance|illustrat(?:e|ion)|sample (?:code|usage)|such as)\b",
    re.IGNORECASE,
)
_ACTION_RE = re.compile(
    r"\b(?:call|evaluate|execute|feed|invoke|pass|run|use)\b",
    re.IGNORECASE,
)
_SCOPED_PROHIBITION_RE = re.compile(
    r"(?:^|[.;:!?]\s*)(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|forbid(?:den)?|no)\s+"
    r"(?:(?:calls?\s+to|execution\s+of|invocation\s+of|use\s+of)\s+)?"
    r"(?:(?:ever\s+)?(?:call|execute|invoke|run|use)(?:ing)?\s*)?(?:the\s*)?$",
    re.IGNORECASE,
)
_INLINE_CODE_RE = re.compile(r"(?<!`)`([^`\n]{1,4096})`(?!`)")
_BROAD_CALL_RE = re.compile(
    r"\b(?:eval|exec|os\.system|"
    r"subprocess\.(?:Popen|call|run)|child_process\.exec)\s*\(",
    re.IGNORECASE,
)
_LIST_PREFIX_RE = re.compile(r"^\s*(?:(?:[-*+]\s+)|(?:\d+[.)]\s+))")
_JAVASCRIPT_STATEMENT_RE = re.compile(
    r"^(?:await\s+|const\s+|eval\s*\(|import\s+|let\s+|require\s*\(|return\s+|var\s+|"
    r"child_process\.|[A-Za-z_$][\w$]*\s*=)",
)

_PYTHON_LANGUAGES = frozenset({"py", "python", "python3"})
_JAVASCRIPT_LANGUAGES = frozenset(
    {"cjs", "javascript", "js", "jsx", "mjs", "node", "nodejs", "ts", "tsx", "typescript"}
)
_CHILD_PROCESS_MODULES = frozenset({"child_process", "node:child_process"})
# This reviewed set deliberately matches the zero-benign development evidence
# slice.  Broader process APIs (for example check_call/execSync/spawn) are
# common in legitimate automation and need source-to-sink evidence before they
# can be promoted to an actionable rule.
_CHILD_PROCESS_METHODS = frozenset({"exec"})
_SUBPROCESS_METHODS = frozenset({"Popen", "call", "run"})
_PROHIBITION_PREFIXES = (
    ("do", "not"),
    ("must", "not"),
    ("should", "not"),
    ("don't",),
    ("never",),
    ("avoid",),
    ("forbid",),
    ("forbidden",),
)
# Preserve the exact forms accepted by the former ``verb(?:ing)?`` grammar.
_PROHIBITION_ACTIONS = frozenset(
    {
        "call",
        "calling",
        "execute",
        "executeing",
        "invoke",
        "invokeing",
        "run",
        "runing",
        "use",
        "useing",
    }
)
_CALL_PLACEHOLDER = "\0"


@dataclass(frozen=True, slots=True)
class _MarkdownBlock:
    language: str
    content: str
    start_line: int
    section_kind: Literal["active", "example", "negative"]


@dataclass(frozen=True, slots=True)
class _InstructionLine:
    text: str
    line_number: int
    section_kind: Literal["active", "example", "negative"]


@dataclass(frozen=True, slots=True)
class _ExecutionCall:
    api_class: str
    language: Literal["python", "javascript"]
    line_number: int
    snippet: str
    context_kind: Literal["active_instruction", "code"]


@dataclass(slots=True, eq=False)
class _PythonLexicalScope:
    """The bounded subset of Python lexical scope needed for ``eval``/``exec``."""

    kind: Literal["module", "function", "lambda", "class", "comprehension"]
    parent: _PythonLexicalScope | None
    bindings: dict[str, set[str]]
    globals: set[str]
    nonlocals: set[str]


class _PythonScopeBuilder(ast.NodeVisitor):
    """Associate calls with scopes without flattening nested bindings.

    Python's compiler determines function-local bindings for the whole scope,
    so binding order is intentionally irrelevant here.  Module and class
    scopes retain that conservative behavior to avoid treating a locally
    rebound builtin as executable code.
    """

    def __init__(self) -> None:
        self.root = _PythonLexicalScope("module", None, {}, set(), set())
        self.current = self.root
        self.call_scopes: dict[ast.Call, _PythonLexicalScope] = {}

    def _bind(self, name: str, kind: str = "shadow") -> None:
        if name in {"eval", "exec"}:
            self.current.bindings.setdefault(name, set()).add(kind)

    def _bind_target(self, target: ast.AST, *, scope: _PythonLexicalScope | None = None) -> None:
        previous = self.current
        if scope is not None:
            self.current = scope
        try:
            for child in ast.walk(target):
                if isinstance(child, ast.Name) and child.id in {"eval", "exec"}:
                    self._bind(child.id)
        finally:
            self.current = previous

    def _visit_arguments_in_outer_scope(self, arguments: ast.arguments) -> None:
        for default in arguments.defaults:
            self.visit(default)
        for keyword_default in arguments.kw_defaults:
            if keyword_default is not None:
                self.visit(keyword_default)
        for argument in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            self.visit(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            self.visit(arguments.kwarg.annotation)

    @staticmethod
    def _argument_names(arguments: ast.arguments) -> list[str]:
        names = [argument.arg for argument in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]]
        if arguments.vararg is not None:
            names.append(arguments.vararg.arg)
        if arguments.kwarg is not None:
            names.append(arguments.kwarg.arg)
        return names

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self._bind(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_arguments_in_outer_scope(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

        parent = self.current
        self.current = _PythonLexicalScope("function", parent, {}, set(), set())
        try:
            for name in self._argument_names(node.args):
                self._bind(name)
            for statement in node.body:
                self.visit(statement)
        finally:
            self.current = parent

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        self._visit_arguments_in_outer_scope(node.args)
        parent = self.current
        self.current = _PythonLexicalScope("lambda", parent, {}, set(), set())
        try:
            for name in self._argument_names(node.args):
                self._bind(name)
            self.visit(node.body)
        finally:
            self.current = parent

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._bind(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

        parent = self.current
        self.current = _PythonLexicalScope("class", parent, {}, set(), set())
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.current = parent

    def _visit_comprehension_expression(
        self,
        generators: list[ast.comprehension],
        values: tuple[ast.expr, ...],
    ) -> None:
        if not generators:
            for value in values:
                self.visit(value)
            return

        # Python evaluates the first iterable in the enclosing scope.  The
        # targets, filters, subsequent iterables, and result run in the hidden
        # comprehension scope.
        self.visit(generators[0].iter)
        parent = self.current
        self.current = _PythonLexicalScope("comprehension", parent, {}, set(), set())
        try:
            first = generators[0]
            self._bind_target(first.target)
            for condition in first.ifs:
                self.visit(condition)
            for generator in generators[1:]:
                self.visit(generator.iter)
                self._bind_target(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            for value in values:
                self.visit(value)
        finally:
            self.current = parent

    def visit_ListComp(self, node: ast.ListComp) -> None:  # noqa: N802
        self._visit_comprehension_expression(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:  # noqa: N802
        self._visit_comprehension_expression(node.generators, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        self._visit_comprehension_expression(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:  # noqa: N802
        self._visit_comprehension_expression(node.generators, (node.key, node.value))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:  # noqa: N802
        # Assignment expressions in comprehensions bind in the nearest
        # containing non-comprehension scope.
        target_scope = self.current
        while target_scope.kind == "comprehension" and target_scope.parent is not None:
            target_scope = target_scope.parent
        self._bind_target(node.target, scope=target_scope)
        self.visit(node.value)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self._bind(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        for alias in node.names:
            local_name = alias.asname or alias.name
            kind = f"builtin:{alias.name}" if node.module == "builtins" else "shadow"
            self._bind(local_name, kind)

    def visit_Global(self, node: ast.Global) -> None:  # noqa: N802
        self.current.globals.update(name for name in node.names if name in {"eval", "exec"})

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:  # noqa: N802
        self.current.nonlocals.update(name for name in node.names if name in {"eval", "exec"})

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._bind(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:  # noqa: N802
        if node.name is not None:
            self._bind(node.name)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:  # noqa: N802
        if node.name is not None:
            self._bind(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:  # noqa: N802
        if node.rest is not None:
            self._bind(node.rest)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.call_scopes[node] = self.current
        self.generic_visit(node)


def _section_kind(title: str) -> Literal["active", "example", "negative"]:
    if _NEGATIVE_SECTION_RE.search(title):
        return "negative"
    if _EXAMPLE_SECTION_RE.search(title):
        return "example"
    return "active"


def _normalise_fence_language(tail: str) -> str:
    info = tail.strip()
    if not info:
        return ""
    token = info.split(maxsplit=1)[0].strip().lower()
    if token.startswith("{.") and token.endswith("}"):
        token = token[2:-1]
    return token


def _markdown_regions(content: str) -> tuple[list[_MarkdownBlock], list[_InstructionLine]]:
    """Walk bounded CommonMark fences and headings without retaining a DOM."""

    lines = content.splitlines()
    if len(lines) > MAX_DOCUMENT_LINES:
        lines = lines[:MAX_DOCUMENT_LINES]

    blocks: list[_MarkdownBlock] = []
    instructions: list[_InstructionLine] = []
    current_section: Literal["active", "example", "negative"] = "active"
    fence_character: str | None = None
    fence_length = 0
    fence_language = ""
    fence_start = 0
    fence_section: Literal["active", "example", "negative"] = "active"
    fence_lines: list[str] = []

    def finish_block() -> None:
        nonlocal fence_lines
        if len(blocks) >= MAX_FENCED_BLOCKS:
            fence_lines = []
            return
        block = "\n".join(fence_lines)
        if len(block.encode("utf-8", errors="ignore")) <= MAX_BLOCK_BYTES:
            blocks.append(
                _MarkdownBlock(
                    language=fence_language,
                    content=block,
                    start_line=fence_start + 1,
                    section_kind=fence_section,
                )
            )
        fence_lines = []

    for line_number, line in enumerate(lines, start=1):
        fence_match = _FENCE_RE.match(line)
        if fence_character is not None:
            if fence_match is not None:
                marker = fence_match.group("marker")
                tail = fence_match.group("tail")
                if marker[0] == fence_character and len(marker) >= fence_length and not tail.strip(" \t\r"):
                    finish_block()
                    fence_character = None
                    fence_length = 0
                    fence_language = ""
                    continue
            fence_lines.append(line)
            continue

        heading = _HEADING_RE.match(line)
        if heading is not None:
            current_section = _section_kind(heading.group("title"))
            instructions.append(_InstructionLine(line, line_number, current_section))
            continue

        bold_heading = _BOLD_HEADING_RE.match(line)
        if bold_heading is not None:
            # Bold labels are subordinate to the surrounding Markdown
            # heading. They may make a region more explicitly illustrative or
            # negative, but an ordinary bold label must not escape an enclosing
            # Examples/Reference section and turn sample code active.
            bold_kind = _section_kind(bold_heading.group("title"))
            if bold_kind != "active":
                current_section = bold_kind
            instructions.append(_InstructionLine(line, line_number, current_section))
            continue

        if fence_match is not None:
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            # A backtick in a backtick fence info string is invalid CommonMark.
            # Treat that line as ordinary text instead of opening an attacker-
            # controlled unbounded region.
            if marker[0] != "`" or "`" not in tail:
                fence_character = marker[0]
                fence_length = len(marker)
                fence_language = _normalise_fence_language(tail)
                fence_start = line_number
                fence_section = current_section
                fence_lines = []
                continue

        instructions.append(_InstructionLine(line, line_number, current_section))

    # CommonMark permits an unclosed fenced block through end-of-document.
    if fence_character is not None:
        finish_block()
    return blocks, instructions


def _ast_within_budget(source: str) -> ast.AST | None:
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError, MemoryError):
        return None
    for count, _node in enumerate(ast.walk(tree), start=1):
        if count > MAX_AST_NODES:
            return None
    return tree


def _python_imports(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    modules: dict[str, str] = {"builtins": "builtins", "os": "os", "subprocess": "subprocess"}
    functions: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"builtins", "os", "subprocess"}:
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"builtins", "os", "subprocess"}:
            for alias in node.names:
                local_name = alias.asname or alias.name
                functions[local_name] = f"{node.module}.{alias.name}"
    return modules, functions


def _python_lookup_parent(scope: _PythonLexicalScope) -> _PythonLexicalScope | None:
    """Return the next scope used by Python's lexical name lookup."""

    parent = scope.parent
    if scope.kind in {"function", "lambda", "comprehension"}:
        # Function-like scopes do not close over an intervening class namespace.
        while parent is not None and parent.kind == "class":
            parent = parent.parent
    return parent


def _python_builtin_binding(scope: _PythonLexicalScope, name: str) -> str | None:
    """Resolve a direct ``eval``/``exec`` name to its builtin API, if any."""

    root = scope
    while root.parent is not None:
        root = root.parent

    current: _PythonLexicalScope | None = scope
    visited_global = False
    while current is not None:
        if current.kind != "module" and name in current.globals:
            if visited_global:
                return name
            current = root
            visited_global = True
            continue
        if name in current.nonlocals:
            current = _python_lookup_parent(current)
            continue

        bindings = current.bindings.get(name)
        if bindings:
            if len(bindings) == 1:
                binding = next(iter(bindings))
                if binding.startswith("builtin:"):
                    return binding.removeprefix("builtin:")
            return None
        current = _python_lookup_parent(current)
    return name


def _python_api_class(
    function: ast.expr,
    modules: dict[str, str],
    functions: dict[str, str],
    scope: _PythonLexicalScope,
) -> str | None:
    if isinstance(function, ast.Name):
        if function.id in {"eval", "exec"}:
            builtin = _python_builtin_binding(scope, function.id)
            return f"python_{builtin}" if builtin in {"eval", "exec"} else None
        imported = functions.get(function.id)
        if imported == "os.system":
            return "python_os_system"
        if imported and imported.startswith("subprocess.") and imported.rsplit(".", 1)[-1] in _SUBPROCESS_METHODS:
            return "python_subprocess"
        if imported in {"builtins.eval", "builtins.exec"}:
            return f"python_{imported.rsplit('.', 1)[-1]}"
        return None

    if not isinstance(function, ast.Attribute) or not isinstance(function.value, ast.Name):
        return None
    module = modules.get(function.value.id)
    if module == "os" and function.attr == "system":
        return "python_os_system"
    if module == "subprocess" and function.attr in _SUBPROCESS_METHODS:
        return "python_subprocess"
    if module == "builtins" and function.attr in {"eval", "exec"}:
        return f"python_{function.attr}"
    return None


def _python_execution_calls(source: str) -> list[tuple[str, int]]:
    tree = _ast_within_budget(source)
    if tree is None:
        return []
    modules, functions = _python_imports(tree)
    scopes = _PythonScopeBuilder()
    scopes.visit(tree)
    calls: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        api_class = _python_api_class(node.func, modules, functions, scopes.call_scopes[node])
        if api_class is not None:
            calls.append((api_class, max(1, node.lineno)))
            if len(calls) >= MAX_DETECTIONS:
                break
    return calls


def _lex_javascript(source: str) -> list[_JsToken]:
    """Return the legacy bounded token prefix for this rule."""

    return javascript_token_prefix(source, max_tokens=MAX_JS_TOKENS)


def _javascript_bindings(tokens: list[_JsToken]) -> tuple[set[str], dict[str, str], set[str]]:
    namespaces: set[str] = {"child_process"}
    functions: dict[str, str] = {}
    shadowed_eval: set[str] = set()
    count = len(tokens)

    def is_module_string(position: int) -> bool:
        return (
            0 <= position < count
            and tokens[position].kind == "string"
            and tokens[position].value in _CHILD_PROCESS_MODULES
        )

    for index, token in enumerate(tokens):
        # import * as cp from "node:child_process"
        if (
            token.value == "import"
            and index + 5 < count
            and tokens[index + 1].value == "*"
            and tokens[index + 2].value == "as"
            and tokens[index + 4].value == "from"
            and is_module_string(index + 5)
        ):
            namespaces.add(tokens[index + 3].value)

        # import { exec as run, spawn } from "child_process"
        if token.value == "import" and index + 1 < count and tokens[index + 1].value == "{":
            closing = next((pos for pos in range(index + 2, min(count, index + 64)) if tokens[pos].value == "}"), -1)
            if (
                closing > 0
                and closing + 2 < count
                and tokens[closing + 1].value == "from"
                and is_module_string(closing + 2)
            ):
                position = index + 2
                while position < closing:
                    imported = tokens[position].value
                    if imported in _CHILD_PROCESS_METHODS:
                        local = imported
                        if position + 2 < closing and tokens[position + 1].value == "as":
                            local = tokens[position + 2].value
                            position += 2
                        functions[local] = imported
                    position += 1

        if token.value not in {"const", "let", "var"} or index + 2 >= count:
            if token.value == "function" and index + 1 < count and tokens[index + 1].value == "eval":
                shadowed_eval.add("eval")
            continue

        # const cp = require("child_process")
        if (
            tokens[index + 1].kind == "identifier"
            and tokens[index + 2].value == "="
            and index + 6 < count
            and tokens[index + 3].value == "require"
            and tokens[index + 4].value == "("
            and is_module_string(index + 5)
            and tokens[index + 6].value == ")"
        ):
            local = tokens[index + 1].value
            if (
                index + 8 < count
                and tokens[index + 7].value == "."
                and tokens[index + 8].value in _CHILD_PROCESS_METHODS
            ):
                functions[local] = tokens[index + 8].value
            else:
                namespaces.add(local)

        # const { exec: run, spawn } = require("child_process")
        if tokens[index + 1].value == "{":
            closing = next((pos for pos in range(index + 2, min(count, index + 64)) if tokens[pos].value == "}"), -1)
            if (
                closing > 0
                and closing + 5 < count
                and tokens[closing + 1].value == "="
                and tokens[closing + 2].value == "require"
                and tokens[closing + 3].value == "("
                and is_module_string(closing + 4)
                and tokens[closing + 5].value == ")"
            ):
                position = index + 2
                while position < closing:
                    imported = tokens[position].value
                    if imported in _CHILD_PROCESS_METHODS:
                        local = imported
                        if position + 2 < closing and tokens[position + 1].value == ":":
                            local = tokens[position + 2].value
                            position += 2
                        functions[local] = imported
                    position += 1

        if tokens[index + 1].value == "eval":
            shadowed_eval.add("eval")
    return namespaces, functions, shadowed_eval


def _javascript_execution_calls(source: str) -> list[tuple[str, int]]:
    tokenization = tokenize_javascript(source, max_tokens=MAX_JS_TOKENS)
    if not tokenization.complete:
        return []
    tokens = list(tokenization.tokens)
    namespaces, functions, shadowed_eval = _javascript_bindings(tokens)
    calls: list[tuple[str, int]] = []

    for index, token in enumerate(tokens):
        if len(calls) >= MAX_DETECTIONS:
            break
        previous = tokens[index - 1].value if index else ""
        following = tokens[index + 1].value if index + 1 < len(tokens) else ""
        if token.value == "eval" and following == "(" and previous not in {".", "?."} and "eval" not in shadowed_eval:
            calls.append(("javascript_eval", token.line))
            continue
        if token.value in functions and following == "(":
            calls.append(("javascript_child_process", token.line))
            continue
        if (
            token.value in namespaces
            and index + 3 < len(tokens)
            and tokens[index + 1].value in {".", "?"}
            and tokens[index + 2].value in _CHILD_PROCESS_METHODS
            and tokens[index + 3].value == "("
        ):
            calls.append(("javascript_child_process", token.line))
            continue
        # require("child_process").exec(...)
        if (
            token.value == "require"
            and index + 6 < len(tokens)
            and tokens[index + 1].value == "("
            and tokens[index + 2].kind == "string"
            and tokens[index + 2].value in _CHILD_PROCESS_MODULES
            and tokens[index + 3].value == ")"
            and tokens[index + 4].value == "."
            and tokens[index + 5].value in _CHILD_PROCESS_METHODS
            and tokens[index + 6].value == "("
        ):
            calls.append(("javascript_child_process", token.line))
    return calls


def _line_snippet(source: str, relative_line: int) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    index = min(max(0, relative_line - 1), len(lines) - 1)
    return lines[index].strip()[:200]


def _block_calls(block: _MarkdownBlock) -> list[_ExecutionCall]:
    if block.section_kind != "active" or not block.content.strip():
        return []
    encoded_size = len(block.content.encode("utf-8", errors="ignore"))
    if encoded_size > MAX_BLOCK_BYTES:
        return []

    language = block.language
    parsed: list[tuple[str, int]] = []
    detected_language: Literal["python", "javascript"]
    if language in _PYTHON_LANGUAGES:
        parsed = _python_execution_calls(block.content)
        detected_language = "python"
    elif language in _JAVASCRIPT_LANGUAGES:
        parsed = _javascript_execution_calls(block.content)
        detected_language = "javascript"
    elif not language:
        parsed = _python_execution_calls(block.content)
        detected_language = "python"
        if not parsed:
            parsed = _javascript_execution_calls(block.content)
            detected_language = "javascript"
    else:
        return []

    return [
        _ExecutionCall(
            api_class=api_class,
            language=detected_language,
            line_number=block.start_line + relative_line - 1,
            snippet=_line_snippet(block.content, relative_line),
            context_kind="code",
        )
        for api_class, relative_line in parsed
    ]


def _extract_balanced_call(line: str, start: int) -> str | None:
    opening = line.find("(", start)
    if opening < 0:
        return None
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, min(len(line), start + MAX_INLINE_CHARS)):
        character = line[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return line[start : index + 1]
    return None


def _is_pure_prohibition(line: str) -> bool:
    """Recognize a complete coordinated list of forbidden execution calls."""

    # This is a precision-only suppression. Oversized direct callers must fail
    # open just like the normal inline-instruction path does.
    if len(line) > MAX_INLINE_CHARS:
        return False
    spans: list[tuple[int, int]] = []
    for candidate in _BROAD_CALL_RE.finditer(line):
        expression = _extract_balanced_call(line, candidate.start())
        if expression is not None:
            spans.append((candidate.start(), candidate.start() + len(expression)))
    if not spans:
        return False
    # Removing backticks changes offsets, so rebuild from the original first,
    # then strip Markdown delimiters from the bounded normalized grammar.
    for start, end in reversed(spans):
        line = line[:start] + _CALL_PLACEHOLDER + line[end:]
    return _matches_pure_prohibition_grammar(line.replace("`", ""))


def _matches_pure_prohibition_grammar(line: str) -> bool:
    """Parse the small prohibition grammar in deterministic linear time."""

    value = line.strip()
    if not value:
        return False

    # Strip the same optional Markdown list marker as the former expression.
    if value[0] in "-*+" and len(value) > 1 and value[1].isspace():
        value = value[2:].lstrip()
    elif value[0].isdigit():
        marker_end = 0
        while marker_end < len(value) and value[marker_end].isdigit():
            marker_end += 1
        if (
            marker_end < len(value)
            and value[marker_end] in ".)"
            and marker_end + 1 < len(value)
            and value[marker_end + 1].isspace()
        ):
            value = value[marker_end + 2 :].lstrip()

    value = value.rstrip()
    if value.endswith((".", "!")):
        value = value[:-1].rstrip()
    # Commas are grammar tokens even when adjacent to a conjunction.
    tokens = value.replace(",", " , ").split()
    if not tokens:
        return False
    folded = [token.casefold() for token in tokens]

    position = -1
    for prefix in _PROHIBITION_PREFIXES:
        if tuple(folded[: len(prefix)]) == prefix:
            position = len(prefix)
            break
    if position < 0:
        return False

    def consume_call(index: int, *, allow_ever: bool) -> int | None:
        had_ever = False
        if allow_ever and index < len(tokens) and folded[index] == "ever":
            had_ever = True
            index += 1
        if index < len(tokens) and folded[index] in _PROHIBITION_ACTIONS:
            index += 1
        elif had_ever:
            return None
        if index >= len(tokens) or tokens[index] != _CALL_PLACEHOLDER:
            return None
        return index + 1

    consumed = consume_call(position, allow_ever=True)
    if consumed is None:
        return False
    position = consumed
    while position < len(tokens):
        if tokens[position] == ",":
            position += 1
            if position < len(tokens) and folded[position] in {"and", "or"}:
                position += 1
        elif folded[position] in {"and", "or"}:
            position += 1
        else:
            return False
        consumed = consume_call(position, allow_ever=False)
        if consumed is None:
            return False
        position = consumed
    return True


def _inline_calls(instruction: _InstructionLine) -> list[_ExecutionCall]:
    line = instruction.text
    if instruction.section_kind != "active" or not line.strip() or len(line) > MAX_INLINE_CHARS:
        return []
    if _INLINE_EXAMPLE_RE.search(line):
        return []
    if _is_pure_prohibition(line):
        return []

    cleaned = _LIST_PREFIX_RE.sub("", line, count=1).strip()
    whole_python = _python_execution_calls(cleaned)
    if whole_python:
        return [
            _ExecutionCall(api, "python", instruction.line_number, line.strip()[:200], "active_instruction")
            for api, _relative_line in whole_python
        ]
    whole_javascript = _javascript_execution_calls(cleaned) if _JAVASCRIPT_STATEMENT_RE.match(cleaned) else []
    if whole_javascript:
        return [
            _ExecutionCall(api, "javascript", instruction.line_number, line.strip()[:200], "active_instruction")
            for api, _relative_line in whole_javascript
        ]

    inline_ranges = [(match.start(1), match.end(1)) for match in _INLINE_CODE_RE.finditer(line)]
    calls: list[_ExecutionCall] = []
    seen_spans: set[tuple[int, int]] = set()
    for candidate in _BROAD_CALL_RE.finditer(line):
        expression = _extract_balanced_call(line, candidate.start())
        if expression is None:
            continue
        end = candidate.start() + len(expression)
        span = (candidate.start(), end)
        if span in seen_spans:
            continue
        seen_spans.add(span)

        prefix = line[max(0, candidate.start() - 160) : candidate.start()]
        in_inline_code = any(start <= candidate.start() and end_pos >= end for start, end_pos in inline_ranges)
        outside = (line[: candidate.start()] + line[end:]).strip(" `\t-*+0123456789.)")
        code_only = not outside
        if not code_only and not (_ACTION_RE.search(prefix) and (in_inline_code or len(prefix.split()) <= 24)):
            continue
        local_prefix = re.split(r"[.;:!?]", prefix)[-1].rstrip(" `\t")
        if _SCOPED_PROHIBITION_RE.search(local_prefix):
            continue

        python_calls = _python_execution_calls(expression)
        if python_calls:
            calls.extend(
                _ExecutionCall(api, "python", instruction.line_number, line.strip()[:200], "active_instruction")
                for api, _relative_line in python_calls
            )
            continue
        javascript_calls = _javascript_execution_calls(expression)
        calls.extend(
            _ExecutionCall(api, "javascript", instruction.line_number, line.strip()[:200], "active_instruction")
            for api, _relative_line in javascript_calls
        )
    return calls


def find_active_dynamic_execution(skill: Skill) -> list[_ExecutionCall]:
    """Return bounded normalized calls; intended for tests and benchmark mining."""

    content = skill.instruction_body
    if not content or len(content.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        return []
    blocks, instructions = _markdown_regions(content)
    calls: list[_ExecutionCall] = []
    for block in blocks:
        calls.extend(_block_calls(block))
        if len(calls) >= MAX_DETECTIONS:
            return calls[:MAX_DETECTIONS]
    for instruction in instructions:
        calls.extend(_inline_calls(instruction))
        if len(calls) >= MAX_DETECTIONS:
            return calls[:MAX_DETECTIONS]

    deduplicated: list[_ExecutionCall] = []
    seen: set[tuple[str, int, str]] = set()
    for call in sorted(calls, key=lambda item: (item.line_number, item.api_class, item.language)):
        identity = (call.api_class, call.line_number, call.context_kind)
        if identity in seen:
            continue
        seen.add(identity)
        deduplicated.append(call)
    return deduplicated


def check_active_dynamic_execution(skill: Skill) -> list[Finding]:
    """Emit one package-level finding for syntax-confirmed active execution."""

    calls = find_active_dynamic_execution(skill)
    if not calls:
        return []
    first = calls[0]
    api_classes = sorted({call.api_class for call in calls})
    languages = sorted({call.language for call in calls})
    context_kind = first.context_kind
    physical_line = first.line_number + max(0, skill.instruction_body_line_offset)
    identity = f"{RULE_ID}:SKILL.md:{physical_line}:{first.api_class}"
    finding_id = f"{RULE_ID}_{hashlib.sha256(identity.encode()).hexdigest()[:10]}"
    executable = first.api_class
    argument_classes = ["inline_code"]
    if any(value.endswith(("eval", "exec")) for value in api_classes):
        argument_classes.append("dynamic")
    command = {
        "executable": executable,
        "argument_classes": argument_classes,
        "downloads": False,
        "executes": True,
        "destructive": False,
        "privilege_change": False,
        "source_class": "skill_code",
        "sink_class": "process_execution",
        "file_path": "SKILL.md",
    }
    signals = [
        {
            "rule_id": RULE_ID,
            "kind": "fenced_code_language" if context_kind == "code" else "finding",
            "file_path": "SKILL.md",
            "value_class": languages[0] if len(languages) == 1 else "code_execution",
        }
    ]
    semantic_facts = {
        "evidence_kind": "command",
        "context_kind": context_kind,
        "evidence_value_class": "execution_api",
        "evidence_count": len(calls),
        "signal_kind": "finding",
        "candidate_command": command,
        "commands": [command],
        "signals": signals,
    }
    return [
        Finding(
            id=finding_id,
            rule_id="ACTIVE_DYNAMIC_EXECUTION",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="Active instruction invokes dynamic code or process execution",
            description=(
                "SKILL.md contains a syntax-confirmed dynamic code or process execution call in active instructions."
            ),
            file_path="SKILL.md",
            line_number=physical_line,
            snippet=first.snippet,
            remediation=(
                "Remove dynamic execution, use a fixed allowlisted operation, or isolate non-operative examples in an "
                "explicit example section."
            ),
            analyzer="static",
            metadata={
                "analysis_basis": "bounded_commonmark_syntax",
                "api_classes": api_classes,
                "languages": languages,
                "semantic_facts": semantic_facts,
            },
        )
    ]


__all__ = ["RULE_ID", "check_active_dynamic_execution", "find_active_dynamic_execution"]
