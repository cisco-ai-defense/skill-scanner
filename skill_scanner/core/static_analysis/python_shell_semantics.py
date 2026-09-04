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

"""Conservative Python recovery for named ``subprocess`` shell flags.

The signature pack already detects literal ``shell=True`` calls.  This module
adds only the smallest missing semantic case: a name whose value is known to be
the exact boolean ``True`` through straight-line assignments and aliases.  It
never executes source, does not infer through compound control flow, and drops
all bindings at expressions that might have side effects.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

MAX_PYTHON_SHELL_SOURCE_BYTES = 1024 * 1024
MAX_PYTHON_SHELL_AST_NODES = 50_000
MAX_PYTHON_SHELL_BINDINGS = 4_096
MAX_PYTHON_SHELL_CANDIDATES = 256
MAX_PYTHON_SHELL_SCOPE_DEPTH = 32
MAX_PYTHON_SHELL_IDENTIFIER_CHARS = 128

_SUBPROCESS_METHODS = frozenset({"Popen", "call", "run"})


@dataclass(frozen=True, slots=True)
class PythonShellBoolCandidate:
    """A syntactic subprocess call whose named shell flag is exactly true."""

    line_number: int
    start_column: int
    end_column: int
    method_name: str
    variable_name: str

    @property
    def evidence(self) -> str:
        """Return bounded evidence without retaining attacker-controlled source."""

        return f"subprocess.{self.method_name}(..., shell={self.variable_name})"


def find_named_shell_true_calls(source: str) -> tuple[PythonShellBoolCandidate, ...]:
    """Find straight-line ``subprocess`` calls with a provably true name.

    Literal values remain the regex signature's responsibility.  Invalid,
    binary-like, oversized, or structurally complex input simply produces no
    additional candidates.
    """

    if not source or "\x00" in source or len(source) > MAX_PYTHON_SHELL_SOURCE_BYTES:
        return ()
    try:
        if len(source.encode("utf-8")) > MAX_PYTHON_SHELL_SOURCE_BYTES:
            return ()
        tree = ast.parse(source)
    except (MemoryError, RecursionError, SyntaxError, UnicodeError, ValueError):
        return ()

    if not _ast_is_bounded(tree):
        return ()

    scanner = _StraightLineShellScanner(source)
    scanner.scan(tree)
    return tuple(scanner.candidates)


def _ast_is_bounded(tree: ast.AST) -> bool:
    pending = [tree]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_PYTHON_SHELL_AST_NODES:
            return False
        pending.extend(ast.iter_child_nodes(node))
    return True


def _is_side_effect_free(expression: ast.expr | None) -> bool:
    """Accept only value reads and construction of inert literal containers."""

    if expression is None:
        return True
    pending: list[ast.expr] = [expression]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Constant, ast.Name)):
            continue
        if isinstance(node, (ast.List, ast.Tuple)):
            if any(isinstance(element, ast.Starred) for element in node.elts):
                return False
            pending.extend(node.elts)
            continue
        # Dict and set construction can call attacker-controlled ``__hash__``
        # methods.  Treat both as side-effect boundaries even without unpacking.
        return False
    return True


def _exact_bool(expression: ast.expr, bindings: dict[str, bool]) -> bool | None:
    if isinstance(expression, ast.Constant) and type(expression.value) is bool:
        return expression.value
    if isinstance(expression, ast.Name):
        return bindings.get(expression.id)
    return None


def _name_targets(targets: list[ast.expr]) -> tuple[str, ...] | None:
    names: list[str] = []
    for target in targets:
        if not isinstance(target, ast.Name):
            return None
        names.append(target.id)
    return tuple(names)


class _StraightLineShellScanner:
    def __init__(self, source: str) -> None:
        self.lines = source.split("\n")
        self.candidates: list[PythonShellBoolCandidate] = []
        self.candidate_lines: set[int] = set()

    def scan(self, tree: ast.Module) -> None:
        self._scan_body(tree.body, depth=0)

    def _scan_body(self, body: list[ast.stmt], *, depth: int) -> None:
        if depth > MAX_PYTHON_SHELL_SCOPE_DEPTH or len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
            return

        external_names = {
            name for statement in body if isinstance(statement, (ast.Global, ast.Nonlocal)) for name in statement.names
        }
        bindings: dict[str, bool] = {}

        for statement in body:
            if len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
                return

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_body(statement.body, depth=depth + 1)
                # Defaults, annotations, and decorators may run while the
                # definition is evaluated, so outer bindings do not cross it.
                bindings.clear()
                continue

            if isinstance(statement, ast.Assign):
                call = self._direct_call(statement.value)
                if call is not None:
                    self._record_call(call, bindings)
                    bindings.clear()
                    continue
                targets = _name_targets(statement.targets)
                if targets is None or not _is_side_effect_free(statement.value):
                    bindings.clear()
                    continue
                value = _exact_bool(statement.value, bindings)
                for name in targets:
                    bindings.pop(name, None)
                    if name not in external_names and value is not None:
                        bindings[name] = value
                self._enforce_binding_limit(bindings)
                continue

            if isinstance(statement, ast.AnnAssign):
                call = self._direct_call(statement.value)
                if call is not None:
                    self._record_call(call, bindings)
                    bindings.clear()
                    continue
                if (
                    not isinstance(statement.target, ast.Name)
                    or not _is_side_effect_free(statement.annotation)
                    or not _is_side_effect_free(statement.value)
                ):
                    bindings.clear()
                    continue
                name = statement.target.id
                value = _exact_bool(statement.value, bindings) if statement.value is not None else None
                bindings.pop(name, None)
                if name not in external_names and value is not None:
                    bindings[name] = value
                self._enforce_binding_limit(bindings)
                continue

            if isinstance(statement, ast.Expr):
                call = self._direct_call(statement.value)
                if call is not None:
                    self._record_call(call, bindings)
                    bindings.clear()
                elif not _is_side_effect_free(statement.value):
                    bindings.clear()
                continue

            if isinstance(statement, (ast.Return, ast.Raise)):
                terminal_expression = statement.value if isinstance(statement, ast.Return) else statement.exc
                call = self._direct_call(terminal_expression)
                if call is not None:
                    self._record_call(call, bindings)
                return

            if isinstance(statement, ast.Delete):
                targets = _name_targets(statement.targets)
                if targets is None:
                    bindings.clear()
                else:
                    for name in targets:
                        bindings.pop(name, None)
                continue

            if isinstance(statement, ast.Pass):
                continue

            # Imports, calls hidden in unsupported expressions, augmented
            # assignments, and every compound statement are hard boundaries.
            # Processing resumes with no facts so a later exact assignment can
            # establish fresh positive evidence.
            bindings.clear()

    def _record_call(self, call: ast.Call, bindings: dict[str, bool]) -> None:
        function = call.func
        if not (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id == "subprocess"
            and function.attr in _SUBPROCESS_METHODS
        ):
            return

        shell_keywords = [keyword for keyword in call.keywords if keyword.arg == "shell"]
        if len(shell_keywords) != 1 or any(keyword.arg is None for keyword in call.keywords):
            return
        shell_keyword = shell_keywords[0]
        if (
            not isinstance(shell_keyword.value, ast.Name)
            or len(shell_keyword.value.id) > MAX_PYTHON_SHELL_IDENTIFIER_CHARS
            or bindings.get(shell_keyword.value.id) is not True
        ):
            return

        # Positional arguments and earlier keyword values are evaluated before
        # shell=.  A call or overloaded operation there could mutate the name
        # before Python reads it, so decline the candidate unless they are all
        # inert value/container expressions.
        if any(not _is_side_effect_free(argument) for argument in call.args):
            return
        for keyword in call.keywords:
            if keyword is shell_keyword:
                break
            if not _is_side_effect_free(keyword.value):
                return

        line_number = getattr(function, "lineno", 0)
        end_line_number = getattr(function, "end_lineno", 0)
        byte_start = getattr(function, "col_offset", -1)
        byte_end = getattr(function, "end_col_offset", -1)
        if not (1 <= line_number <= len(self.lines) and end_line_number == line_number and 0 <= byte_start <= byte_end):
            return
        if line_number in self.candidate_lines:
            return
        line = self.lines[line_number - 1]
        try:
            start_column = len(line.encode("utf-8")[:byte_start].decode("utf-8"))
            end_column = len(line.encode("utf-8")[:byte_end].decode("utf-8"))
        except UnicodeError:
            return
        if end_column <= start_column:
            return

        self.candidates.append(
            PythonShellBoolCandidate(
                line_number=line_number,
                start_column=start_column,
                end_column=end_column,
                method_name=function.attr,
                variable_name=shell_keyword.value.id,
            )
        )
        self.candidate_lines.add(line_number)

    @staticmethod
    def _enforce_binding_limit(bindings: dict[str, bool]) -> None:
        if len(bindings) > MAX_PYTHON_SHELL_BINDINGS:
            bindings.clear()

    @staticmethod
    def _direct_call(expression: ast.expr | None) -> ast.Call | None:
        if isinstance(expression, ast.Call):
            return expression
        if isinstance(expression, ast.Await) and isinstance(expression.value, ast.Call):
            return expression.value
        return None
