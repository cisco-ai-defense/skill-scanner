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

"""Conservative positive evidence for Python shell execution.

The signature pack already detects literal ``shell=True`` and ``os.system``
spelling.  This module supplements those patterns with two small semantic
cases: exact named boolean flags and import-resolved ``os.system`` aliases,
including aliases inside a literal Python ``-c`` payload that is passed to a
reviewed ``subprocess`` call.  It never executes source, does not infer through
compound control flow, and shares hard resource limits across outer and
embedded syntax trees.
"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

MAX_PYTHON_SHELL_SOURCE_BYTES = 1024 * 1024
MAX_PYTHON_SHELL_AST_NODES = 50_000
MAX_PYTHON_SHELL_BINDINGS = 4_096
MAX_PYTHON_SHELL_CANDIDATES = 256
MAX_PYTHON_SHELL_SCOPE_DEPTH = 32
MAX_PYTHON_SHELL_IDENTIFIER_CHARS = 128
MAX_PYTHON_SHELL_EMBEDDED_BYTES = 256 * 1024
MAX_PYTHON_SHELL_EMBEDDED_PAYLOADS = 64

_SUBPROCESS_METHODS = frozenset({"Popen", "call", "run"})
_SUBPROCESS_CALL_IDENTITIES = frozenset(f"callable:subprocess.{method}" for method in _SUBPROCESS_METHODS)
_PYTHON_C_BASE_KEYWORDS = frozenset({"args", "shell"})
_PYTHON_C_RUN_KEYWORDS = _PYTHON_C_BASE_KEYWORDS | {"check"}
_OS_SYSTEM_IDENTITY = "callable:os.system"
_PYTHON_EXECUTABLE_RE = re.compile(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", re.IGNORECASE)
_RAW_OS_SYSTEM_CALL_RE = re.compile(r"\bos\.system\s*\(")


@dataclass(frozen=True, slots=True)
class PythonShellBoolCandidate:
    """A syntactic subprocess call whose named shell flag is exactly true."""

    line_number: int
    start_column: int
    end_column: int
    method_name: str
    variable_name: str

    @property
    def matched_pattern(self) -> str:
        """Return explicit semantic provenance for signature metadata."""

        return "python_ast:named_shell_flag_is_true"

    @property
    def evidence(self) -> str:
        """Return bounded evidence without retaining attacker-controlled source."""

        return f"subprocess.{self.method_name}(..., shell={self.variable_name})"


@dataclass(frozen=True, slots=True)
class PythonOsSystemCandidate:
    """An import-resolved ``os.system`` alias with outer-source evidence."""

    line_number: int
    start_column: int
    end_column: int
    embedded_method_name: str | None = None

    @property
    def matched_pattern(self) -> str:
        """Return explicit semantic provenance for signature metadata."""

        if self.embedded_method_name is not None:
            return "python_ast:embedded_python_c_resolved_os_system"
        return "python_ast:resolved_os_system_alias"

    @property
    def evidence(self) -> str:
        """Return bounded evidence without retaining attacker-controlled source."""

        if self.embedded_method_name is not None:
            return f"subprocess.{self.embedded_method_name}(... Python -c payload invokes import-resolved os.system)"
        return "import-resolved alias invokes os.system(...)"


PythonShellCandidate = PythonShellBoolCandidate | PythonOsSystemCandidate


@dataclass(slots=True)
class _ExpressionScanState:
    """Mutable facts shared while one expression is evaluated in order."""

    bool_bindings: dict[str, bool]
    identities: dict[str, str]
    poisoned_modules: set[str]
    external_names: set[str]
    scope_depth: int
    evidence_anchor: ast.expr | None
    embedded_method_name: str | None


@dataclass(slots=True)
class _AnalysisBudget:
    """Cumulative limits shared by the outer file and embedded payloads."""

    remaining_nodes: int
    remaining_embedded_bytes: int
    remaining_embedded_payloads: int

    def consume_tree(self, tree: ast.AST) -> bool:
        """Charge one syntax tree without walking beyond the remaining limit."""

        pending = [tree]
        count = 0
        while pending:
            node = pending.pop()
            count += 1
            if count > self.remaining_nodes:
                return False
            pending.extend(ast.iter_child_nodes(node))
        self.remaining_nodes -= count
        return True

    def consume_embedded_source(self, source: str) -> bool:
        """Charge one decoded payload before parsing it."""

        if not source or "\x00" in source or self.remaining_embedded_payloads <= 0:
            return False
        try:
            source_bytes = len(source.encode("utf-8"))
        except UnicodeError:
            return False
        if source_bytes > self.remaining_embedded_bytes:
            return False
        self.remaining_embedded_bytes -= source_bytes
        self.remaining_embedded_payloads -= 1
        return True


def find_python_shell_candidates(source: str) -> tuple[PythonShellCandidate, ...]:
    """Find bounded, straight-line positive evidence for reviewed shell sinks.

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
        # ``ast.parse`` accepts some trees (such as duplicate keywords or a
        # top-level return) that CPython will never execute.
        compile(source, "<unknown>", "exec", dont_inherit=True)
        budget = _AnalysisBudget(
            remaining_nodes=MAX_PYTHON_SHELL_AST_NODES,
            remaining_embedded_bytes=MAX_PYTHON_SHELL_EMBEDDED_BYTES,
            remaining_embedded_payloads=MAX_PYTHON_SHELL_EMBEDDED_PAYLOADS,
        )
        if not budget.consume_tree(tree):
            return ()
        scanner = _StraightLineShellScanner(source, budget)
        scanner.scan(tree)
    except (MemoryError, OverflowError, RecursionError, SyntaxError, TypeError, UnicodeError, ValueError):
        return ()
    return tuple(scanner.candidates)


def find_named_shell_true_calls(source: str) -> tuple[PythonShellBoolCandidate, ...]:
    """Preserve the focused #203 API while sharing the broader bounded pass."""

    return tuple(
        candidate
        for candidate in find_python_shell_candidates(source)
        if isinstance(candidate, PythonShellBoolCandidate)
    )


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
    def __init__(self, source: str, budget: _AnalysisBudget) -> None:
        self.source = source
        self.lines = source.split("\n")
        self.budget = budget
        self.candidates: list[PythonShellCandidate] = []
        self.candidate_keys: set[tuple[int, int, int, str]] = set()
        self.allow_embedded_canonical = False
        self.annotations_are_deferred = sys.version_info >= (3, 14)
        self.remaining_expression_visits = MAX_PYTHON_SHELL_AST_NODES

    def scan(self, tree: ast.Module) -> None:
        """Scan the outer module with no assumed bindings."""

        self.annotations_are_deferred = self.annotations_are_deferred or any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(imported.name == "annotations" for imported in statement.names)
            for statement in tree.body
        )
        self._scan_body(tree.body, depth=0, evidence_anchor=None, embedded_method_name=None)

    def _scan_body(
        self,
        body: list[ast.stmt],
        *,
        depth: int,
        evidence_anchor: ast.expr | None,
        embedded_method_name: str | None,
    ) -> None:
        if depth > MAX_PYTHON_SHELL_SCOPE_DEPTH or len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
            return

        external_names = {
            name for statement in body if isinstance(statement, (ast.Global, ast.Nonlocal)) for name in statement.names
        }
        bool_bindings: dict[str, bool] = {}
        identities: dict[str, str] = {}
        poisoned_modules: set[str] = set()
        expression_state = _ExpressionScanState(
            bool_bindings=bool_bindings,
            identities=identities,
            poisoned_modules=poisoned_modules,
            external_names=external_names,
            scope_depth=depth,
            evidence_anchor=evidence_anchor,
            embedded_method_name=embedded_method_name,
        )

        for statement in body:
            if len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
                return

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_definition_expressions(statement, expression_state)
                # Delayed scopes receive no outer identities: a module alias
                # may be rebound before the function is ever called.
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    evidence_anchor=evidence_anchor,
                    embedded_method_name=embedded_method_name,
                )
                # Defaults, annotations, and decorators may run while the
                # definition is evaluated, so outer facts do not cross it.
                self._poison_known_modules(identities, poisoned_modules)
                bool_bindings.clear()
                identities.clear()
                continue

            if isinstance(statement, ast.Import):
                bool_bindings.clear()
                self._apply_import(statement, identities, poisoned_modules)
                self._enforce_binding_limit(bool_bindings, identities)
                continue

            if isinstance(statement, ast.ImportFrom):
                bool_bindings.clear()
                self._apply_import_from(statement, identities, poisoned_modules)
                self._enforce_binding_limit(bool_bindings, identities)
                continue

            if isinstance(statement, ast.ClassDef):
                self._scan_expressions(
                    [*statement.decorator_list, *statement.bases, *(keyword.value for keyword in statement.keywords)],
                    expression_state,
                )
                # Class bodies execute in their own namespace, while methods
                # are delayed scopes that do not close over class bindings.
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    evidence_anchor=evidence_anchor,
                    embedded_method_name=embedded_method_name,
                )
                self._poison_known_modules(identities, poisoned_modules)
                bool_bindings.clear()
                identities.clear()
                continue

            if isinstance(statement, ast.Assign):
                value = _exact_bool(statement.value, bool_bindings)
                expression_is_safe = self._scan_expression(statement.value, expression_state)
                self._poison_module_targets(statement.targets, identities, poisoned_modules)
                targets = _name_targets(statement.targets)
                if targets is None or not expression_is_safe:
                    self._clear_expression_facts(expression_state)
                    continue
                for name in targets:
                    bool_bindings.pop(name, None)
                    identities.pop(name, None)
                    if name not in external_names and value is not None:
                        bool_bindings[name] = value
                self._enforce_binding_limit(bool_bindings, identities)
                continue

            if isinstance(statement, ast.AnnAssign):
                value = _exact_bool(statement.value, bool_bindings) if statement.value is not None else None
                expression_is_safe = self._scan_expression(statement.value, expression_state)
                self._poison_module_targets([statement.target], identities, poisoned_modules)
                if (
                    not isinstance(statement.target, ast.Name)
                    or not _is_side_effect_free(statement.annotation)
                    or not expression_is_safe
                ):
                    if not _is_side_effect_free(statement.annotation) or not _is_side_effect_free(statement.value):
                        self._clear_expression_facts(expression_state)
                    continue
                if statement.value is None:
                    # A simple annotation-only declaration evaluates its
                    # annotation but does not rebind the declared name.
                    continue
                name = statement.target.id
                bool_bindings.pop(name, None)
                identities.pop(name, None)
                if name not in external_names and value is not None:
                    bool_bindings[name] = value
                self._enforce_binding_limit(bool_bindings, identities)
                continue

            if isinstance(statement, ast.Expr):
                expression_is_safe = self._scan_expression(statement.value, expression_state)
                if not _is_side_effect_free(statement.value):
                    bool_bindings.clear()
                if not expression_is_safe:
                    self._clear_expression_facts(expression_state)
                continue

            if isinstance(statement, (ast.Return, ast.Raise)):
                terminal_expression = statement.value if isinstance(statement, ast.Return) else statement.exc
                expressions = (
                    [terminal_expression, statement.cause]
                    if isinstance(statement, ast.Raise)
                    else [terminal_expression]
                )
                self._scan_expressions(expressions, expression_state)
                return

            if isinstance(statement, ast.Delete):
                self._poison_module_targets(statement.targets, identities, poisoned_modules)
                targets = _name_targets(statement.targets)
                if targets is None:
                    bool_bindings.clear()
                    identities.clear()
                else:
                    for name in targets:
                        bool_bindings.pop(name, None)
                        identities.pop(name, None)
                continue

            if isinstance(statement, ast.Pass):
                continue

            if isinstance(statement, (ast.If, ast.While)):
                self._scan_expression(statement.test, expression_state)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self._scan_expression(statement.iter, expression_state)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._scan_expression(item.context_expr, expression_state)
                    # __enter__ can change later name/attribute resolution.
                    self._clear_expression_facts(expression_state)
            elif isinstance(statement, ast.Match):
                self._scan_expression(statement.subject, expression_state)

            nested_bodies: list[list[ast.stmt]] | None = None
            if isinstance(statement, ast.If):
                if isinstance(statement.test, ast.Constant):
                    nested_bodies = [statement.body if bool(statement.test.value) else statement.orelse]
                else:
                    nested_bodies = [statement.body, statement.orelse]
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                definitely_empty = (
                    (isinstance(statement.iter, (ast.List, ast.Tuple, ast.Set)) and not statement.iter.elts)
                    or isinstance(statement.iter, ast.Dict)
                    and not statement.iter.keys
                )
                nested_bodies = [statement.orelse] if definitely_empty else [statement.body, statement.orelse]
            elif isinstance(statement, ast.While):
                if isinstance(statement.test, ast.Constant) and not bool(statement.test.value):
                    nested_bodies = [statement.orelse]
                else:
                    nested_bodies = [statement.body, statement.orelse]
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                nested_bodies = [statement.body]
            elif isinstance(statement, (ast.Try, ast.TryStar)):
                nested_bodies = [
                    statement.body,
                    *(handler.body for handler in statement.handlers),
                    statement.orelse,
                    statement.finalbody,
                ]
            elif isinstance(statement, ast.Match):
                nested_bodies = [case.body for case in statement.cases]

            if nested_bodies is not None:
                # A compound header can execute arbitrary code, so no outer
                # fact is safe to carry inward.  Self-contained nested suites
                # still receive their own bounded source-ordered scan.
                for nested_body in nested_bodies:
                    if nested_body:
                        self._scan_body(
                            nested_body,
                            depth=depth + 1,
                            evidence_anchor=evidence_anchor,
                            embedded_method_name=embedded_method_name,
                        )
                self._poison_known_modules(identities, poisoned_modules)
                bool_bindings.clear()
                identities.clear()
                continue

            if isinstance(statement, ast.AugAssign):
                self._poison_module_targets([statement.target], identities, poisoned_modules)

            # Calls hidden in unsupported expressions, augmented assignments,
            # and unsupported statements are hard boundaries. Processing
            # resumes with no facts so later direct imports or assignments can
            # establish fresh positive evidence.
            self._poison_known_modules(identities, poisoned_modules)
            bool_bindings.clear()
            identities.clear()

    def _scan_definition_expressions(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
        state: _ExpressionScanState,
    ) -> None:
        expressions: list[ast.expr | None] = [*statement.decorator_list]
        expressions.extend(statement.args.defaults)
        expressions.extend(statement.args.kw_defaults)
        if not self.annotations_are_deferred:
            parameters = [
                *statement.args.posonlyargs,
                *statement.args.args,
                statement.args.vararg,
                *statement.args.kwonlyargs,
                statement.args.kwarg,
            ]
            expressions.extend(parameter.annotation for parameter in parameters if parameter is not None)
            expressions.append(statement.returns)
        self._scan_expressions(expressions, state)

    def _scan_expressions(self, expressions: Sequence[ast.expr | None], state: _ExpressionScanState) -> bool:
        all_safe = True
        for expression in expressions:
            all_safe = self._scan_expression(expression, state) and all_safe
        return all_safe

    def _scan_expression(
        self,
        expression: ast.expr | None,
        state: _ExpressionScanState,
        expression_depth: int = 0,
    ) -> bool:
        """Record reachable calls while invalidating facts at effect boundaries."""

        if expression is None:
            return True
        self.remaining_expression_visits -= 1
        if (
            self.remaining_expression_visits < 0
            or state.scope_depth + expression_depth > MAX_PYTHON_SHELL_SCOPE_DEPTH
            or len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES
        ):
            self._clear_expression_facts(state)
            return False

        def scan(child: ast.expr | None) -> bool:
            return self._scan_expression(child, state, expression_depth + 1)

        if isinstance(expression, (ast.Constant, ast.Name)):
            return True
        if isinstance(expression, ast.NamedExpr):
            exact_value = _exact_bool(expression.value, state.bool_bindings)
            is_safe = scan(expression.value)
            name = expression.target.id
            state.bool_bindings.pop(name, None)
            state.identities.pop(name, None)
            if is_safe and exact_value is not None and name not in state.external_names:
                state.bool_bindings[name] = exact_value
            return is_safe
        if isinstance(expression, ast.Attribute):
            if self._resolve_identity(expression, state.identities) is not None:
                return True
            scan(expression.value)
            self._clear_expression_facts(state)
            return False
        if isinstance(expression, (ast.List, ast.Tuple)):
            all_safe = True
            for element in expression.elts:
                all_safe = scan(element.value if isinstance(element, ast.Starred) else element) and all_safe
                if isinstance(element, ast.Starred):
                    self._clear_expression_facts(state)
                    all_safe = False
            return all_safe
        if isinstance(expression, (ast.Set, ast.Dict)):
            children = [child for child in ast.iter_child_nodes(expression) if isinstance(child, ast.expr)]
            for child in children:
                scan(child)
                # Hashing/insertion can dispatch attacker-controlled methods.
                self._clear_expression_facts(state)
            return not children
        if isinstance(expression, ast.BoolOp):
            all_safe = True
            for index, bool_value in enumerate(expression.values):
                truth = self._known_truth(bool_value, state.bool_bindings)
                all_safe = scan(bool_value) and all_safe
                if index == len(expression.values) - 1:
                    break
                if (isinstance(expression.op, ast.And) and truth is False) or (
                    isinstance(expression.op, ast.Or) and truth is True
                ):
                    break
                if truth is None:
                    self._clear_expression_facts(state)
                    all_safe = False
            return all_safe
        if isinstance(expression, ast.IfExp):
            truth = self._known_truth(expression.test, state.bool_bindings)
            test_is_safe = scan(expression.test)
            if truth is None:
                self._clear_expression_facts(state)
                return False
            return scan(expression.body if truth else expression.orelse) and test_is_safe
        if isinstance(expression, ast.Call):
            function_identity = self._resolve_identity(expression.func, state.identities)
            reviewed_spelling = function_identity is not None or self._is_reviewed_call_spelling(expression.func)
            function_is_safe = reviewed_spelling or scan(expression.func)
            arguments_are_safe = True
            call_values = [(value, isinstance(value, ast.Starred)) for value in expression.args] + [
                (keyword.value, keyword.arg is None) for keyword in expression.keywords
            ]
            call_values.sort(key=lambda item: (getattr(item[0], "lineno", 0), getattr(item[0], "col_offset", 0)))
            for call_value, expands in call_values:
                arguments_are_safe = (
                    scan(call_value.value if isinstance(call_value, ast.Starred) else call_value) and arguments_are_safe
                )
                if expands:
                    self._clear_expression_facts(state)
                    arguments_are_safe = False
            if reviewed_spelling and function_is_safe and arguments_are_safe:
                preserves_facts = self._record_call(
                    expression,
                    state.bool_bindings,
                    state.identities,
                    depth=state.scope_depth,
                    evidence_anchor=state.evidence_anchor,
                    embedded_method_name=state.embedded_method_name,
                )
                if preserves_facts:
                    return True
            if isinstance(expression.func, ast.Lambda) and self._zero_argument_lambda(expression):
                scan(expression.func.body)
            self._clear_expression_facts(state)
            return False
        if isinstance(expression, ast.Lambda):
            return self._scan_expressions([*expression.args.defaults, *expression.args.kw_defaults], state)
        if isinstance(expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            first = expression.generators[0]
            iterable_is_empty = self._known_iterable_empty(first.iter)
            iterable_is_safe = scan(first.iter)
            if isinstance(expression, ast.GeneratorExp) or iterable_is_empty is True:
                if iterable_is_empty is None:
                    self._clear_expression_facts(state)
                return iterable_is_safe and iterable_is_empty is not None
            local_state = self._comprehension_state(state, first.target)
            if iterable_is_empty is None:
                self._clear_expression_facts(local_state)
            conditions_are_true = len(expression.generators) == 1
            for condition in first.ifs:
                truth = self._known_truth(condition, local_state.bool_bindings)
                self._scan_expression(condition, local_state, expression_depth + 1)
                conditions_are_true = conditions_are_true and truth is True
                if truth is False:
                    break
            if conditions_are_true:
                result_values: list[ast.expr] = (
                    [expression.key, expression.value] if isinstance(expression, ast.DictComp) else [expression.elt]
                )
                self._scan_expressions(result_values, local_state)
            self._clear_expression_facts(state)
            return False
        if isinstance(expression, ast.Compare):
            scan(expression.left)
            for comparator in expression.comparators:
                scan(comparator)
                self._clear_expression_facts(state)
            return False

        for nested in ast.iter_child_nodes(expression):
            if isinstance(nested, ast.expr):
                scan(nested)
        self._clear_expression_facts(state)
        return False

    @staticmethod
    def _known_truth(expression: ast.expr, bindings: dict[str, bool]) -> bool | None:
        exact = _exact_bool(expression, bindings)
        if exact is not None:
            return exact
        if isinstance(expression, ast.Constant):
            return bool(expression.value)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return bool(expression.elts)
        if isinstance(expression, ast.Dict):
            return bool(expression.keys)
        return None

    @staticmethod
    def _known_iterable_empty(expression: ast.expr) -> bool | None:
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return not expression.elts
        if isinstance(expression, ast.Dict):
            return not expression.keys
        if isinstance(expression, ast.Constant) and isinstance(expression.value, (str, bytes)):
            return not expression.value
        return None

    @staticmethod
    def _zero_argument_lambda(call: ast.Call) -> bool:
        if call.args or call.keywords or not isinstance(call.func, ast.Lambda):
            return False
        arguments = call.func.args
        return not (
            arguments.posonlyargs or arguments.args or arguments.vararg or arguments.kwonlyargs or arguments.kwarg
        )

    @staticmethod
    def _is_reviewed_call_spelling(expression: ast.expr) -> bool:
        return (
            isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
            and (
                (expression.value.id == "subprocess" and expression.attr in _SUBPROCESS_METHODS)
                or (expression.value.id == "os" and expression.attr == "system")
            )
        )

    @staticmethod
    def _comprehension_state(state: _ExpressionScanState, target: ast.expr) -> _ExpressionScanState:
        bool_bindings = dict(state.bool_bindings)
        identities = dict(state.identities)
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                bool_bindings.pop(node.id, None)
                identities.pop(node.id, None)
        return _ExpressionScanState(
            bool_bindings,
            identities,
            state.poisoned_modules,
            state.external_names,
            state.scope_depth + 1,
            state.evidence_anchor,
            state.embedded_method_name,
        )

    @classmethod
    def _clear_expression_facts(cls, state: _ExpressionScanState) -> None:
        cls._poison_known_modules(state.identities, state.poisoned_modules)
        state.bool_bindings.clear()
        state.identities.clear()

    def _record_call(
        self,
        call: ast.Call,
        bool_bindings: dict[str, bool],
        identities: dict[str, str],
        *,
        depth: int,
        evidence_anchor: ast.expr | None,
        embedded_method_name: str | None,
    ) -> bool:
        function_identity = self._resolve_identity(call.func, identities)

        if function_identity == _OS_SYSTEM_IDENTITY and (
            self._is_alias_spelling(call.func) or (evidence_anchor is not None and self.allow_embedded_canonical)
        ):
            self._record_os_system(
                evidence_anchor or call.func,
                embedded_method_name=embedded_method_name,
            )

        if evidence_anchor is None:
            self._record_named_shell_flag(call, bool_bindings)
            if function_identity in _SUBPROCESS_CALL_IDENTITIES:
                self._scan_python_c_payload(call, function_identity, depth=depth)

        return function_identity in (_SUBPROCESS_CALL_IDENTITIES | {_OS_SYSTEM_IDENTITY}) and (
            self._call_arguments_are_side_effect_free(call)
        )

    def _record_named_shell_flag(
        self,
        call: ast.Call,
        bindings: dict[str, bool],
    ) -> None:
        """Preserve #203's exact, unaliased subprocess ownership."""

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
        # shell=. A call or overloaded operation there could mutate the name
        # before Python reads it, so require inert values.
        if any(not _is_side_effect_free(argument) for argument in call.args):
            return
        for keyword in call.keywords:
            if keyword is shell_keyword:
                break
            if not _is_side_effect_free(keyword.value):
                return

        span = self._source_span(function)
        if span is None:
            return
        line_number, start_column, end_column = span
        self._append_candidate(
            PythonShellBoolCandidate(
                line_number=line_number,
                start_column=start_column,
                end_column=end_column,
                method_name=function.attr,
                variable_name=shell_keyword.value.id,
            )
        )

    def _record_os_system(self, anchor: ast.expr, *, embedded_method_name: str | None) -> None:
        span = self._source_span(anchor)
        if span is None:
            return
        line_number, start_column, end_column = span
        self._append_candidate(
            PythonOsSystemCandidate(
                line_number=line_number,
                start_column=start_column,
                end_column=end_column,
                embedded_method_name=embedded_method_name,
            )
        )

    def _scan_python_c_payload(self, call: ast.Call, function_identity: str, *, depth: int) -> None:
        if not self._call_arguments_are_side_effect_free(call):
            return
        payload_info = self._constant_python_c_payload(call, function_identity)
        if payload_info is None:
            return
        payload, payload_expression = payload_info
        if not self.budget.consume_embedded_source(payload):
            return
        try:
            tree = ast.parse(payload)
            compile(payload, "<embedded-python-c>", "exec", dont_inherit=True)
            if not self.budget.consume_tree(tree):
                return
        except (MemoryError, OverflowError, RecursionError, SyntaxError, TypeError, UnicodeError, ValueError):
            return
        method_name = function_identity.rsplit(".", 1)[-1]
        try:
            raw_payload = ast.get_source_segment(self.source, payload_expression)
        except (MemoryError, UnicodeError):
            raw_payload = None
        previous_allowance = self.allow_embedded_canonical
        previous_annotations = self.annotations_are_deferred
        self.allow_embedded_canonical = raw_payload is None or _RAW_OS_SYSTEM_CALL_RE.search(raw_payload) is None
        self.annotations_are_deferred = sys.version_info >= (3, 14) or any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(imported.name == "annotations" for imported in statement.names)
            for statement in tree.body
        )
        try:
            self._scan_body(
                tree.body,
                depth=depth + 1,
                evidence_anchor=call.func,
                embedded_method_name=method_name,
            )
        finally:
            self.allow_embedded_canonical = previous_allowance
            self.annotations_are_deferred = previous_annotations

    @staticmethod
    def _constant_python_c_payload(call: ast.Call, function_identity: str) -> tuple[str, ast.expr] | None:
        """Return a literal Python ``-c`` payload only when execution is unambiguous."""

        if function_identity not in _SUBPROCESS_CALL_IDENTITIES:
            return None
        keyword_names = [keyword.arg for keyword in call.keywords]
        if any(name is None for name in keyword_names) or len(set(keyword_names)) != len(keyword_names):
            return None
        allowed_keywords = (
            _PYTHON_C_RUN_KEYWORDS if function_identity == "callable:subprocess.run" else _PYTHON_C_BASE_KEYWORDS
        )
        if any(name not in allowed_keywords for name in keyword_names):
            return None
        if any(keyword.arg == "check" and not isinstance(keyword.value, ast.Constant) for keyword in call.keywords):
            return None
        shell_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "shell"]
        if shell_keywords and not (
            len(shell_keywords) == 1
            and isinstance(shell_keywords[0], ast.Constant)
            and shell_keywords[0].value is False
        ):
            return None

        args_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "args"]
        if len(call.args) == 1:
            if args_keywords:
                return None
            command = call.args[0]
        elif call.args:
            return None
        elif len(args_keywords) == 1:
            command = args_keywords[0]
        else:
            return None
        if not isinstance(command, (ast.List, ast.Tuple)) or any(
            isinstance(element, ast.Starred) for element in command.elts
        ):
            return None

        values: list[str] = []
        for element in command.elts:
            if not isinstance(element, ast.Constant) or type(element.value) is not str:
                return None
            values.append(element.value)
        if len(values) < 3 or _PYTHON_EXECUTABLE_RE.fullmatch(values[0]) is None or values[1] != "-c":
            return None
        return values[2], command.elts[2]

    @staticmethod
    def _resolve_identity(expression: ast.expr, identities: dict[str, str]) -> str | None:
        if isinstance(expression, ast.Name):
            return identities.get(expression.id)
        if not isinstance(expression, ast.Attribute) or not isinstance(expression.value, ast.Name):
            return None
        module_identity = identities.get(expression.value.id)
        if module_identity == "module:os" and expression.attr == "system":
            return _OS_SYSTEM_IDENTITY
        if module_identity == "module:subprocess" and expression.attr in _SUBPROCESS_METHODS:
            return f"callable:subprocess.{expression.attr}"
        return None

    @staticmethod
    def _is_alias_spelling(expression: ast.expr) -> bool:
        if isinstance(expression, ast.Name):
            return True
        return not (
            isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
            and expression.value.id == "os"
        )

    @staticmethod
    def _call_arguments_are_side_effect_free(call: ast.Call) -> bool:
        return all(_is_side_effect_free(argument) for argument in call.args) and all(
            keyword.arg is not None and _is_side_effect_free(keyword.value) for keyword in call.keywords
        )

    @staticmethod
    def _identity_module(identity: str | None) -> str | None:
        if identity in {_OS_SYSTEM_IDENTITY, "module:os"}:
            return "os"
        if identity == "module:subprocess" or identity in _SUBPROCESS_CALL_IDENTITIES:
            return "subprocess"
        return None

    @classmethod
    def _poison_known_modules(cls, identities: dict[str, str], poisoned_modules: set[str]) -> None:
        for identity in identities.values():
            module = cls._identity_module(identity)
            if module is not None:
                poisoned_modules.add(module)

    @classmethod
    def _poison_module_targets(
        cls,
        targets: list[ast.expr],
        identities: dict[str, str],
        poisoned_modules: set[str],
    ) -> None:
        pending = list(targets)
        while pending:
            target = pending.pop()
            if isinstance(target, ast.Attribute):
                module = cls._identity_module(cls._resolve_identity(target, identities))
                if module is not None:
                    poisoned_modules.add(module)
                else:
                    # An unresolved attribute target may still be an alias of a
                    # reviewed module, so a later import cannot safely restore
                    # positive identity evidence.
                    cls._poison_known_modules(identities, poisoned_modules)
                continue
            if isinstance(target, ast.Subscript):
                # Mapping writes such as ``os.__dict__["system"] = fake`` can
                # mutate reviewed callables without an Attribute store node.
                cls._poison_known_modules(identities, poisoned_modules)
                continue
            if isinstance(target, ast.Starred):
                pending.append(target.value)
            elif isinstance(target, (ast.List, ast.Tuple)):
                pending.extend(target.elts)

    @staticmethod
    def _apply_import(
        statement: ast.Import,
        identities: dict[str, str],
        poisoned_modules: set[str],
    ) -> None:
        for imported in statement.names:
            local_name = imported.asname or imported.name.split(".", 1)[0]
            identities.pop(local_name, None)
            if imported.name == "os" and "os" not in poisoned_modules:
                identities[local_name] = "module:os"
            elif imported.name == "subprocess" and "subprocess" not in poisoned_modules:
                identities[local_name] = "module:subprocess"
            elif imported.name.startswith("os.") and imported.asname is None and "os" not in poisoned_modules:
                # ``import os.path`` binds the root name ``os``; the aliased
                # form ``import os.path as o`` binds the submodule and must not
                # be treated as an ``os`` module alias.
                identities[local_name] = "module:os"

    @staticmethod
    def _apply_import_from(
        statement: ast.ImportFrom,
        identities: dict[str, str],
        poisoned_modules: set[str],
    ) -> None:
        if any(imported.name == "*" for imported in statement.names):
            identities.clear()
            return
        for imported in statement.names:
            local_name = imported.asname or imported.name
            identities.pop(local_name, None)
            if statement.level != 0:
                continue
            if statement.module == "os" and imported.name == "system" and "os" not in poisoned_modules:
                identities[local_name] = _OS_SYSTEM_IDENTITY
            elif (
                statement.module == "subprocess"
                and imported.name in _SUBPROCESS_METHODS
                and "subprocess" not in poisoned_modules
            ):
                identities[local_name] = f"callable:subprocess.{imported.name}"

    def _source_span(self, expression: ast.expr) -> tuple[int, int, int] | None:
        line_number = getattr(expression, "lineno", 0)
        end_line_number = getattr(expression, "end_lineno", 0)
        byte_start = getattr(expression, "col_offset", -1)
        byte_end = getattr(expression, "end_col_offset", -1)
        if not (1 <= line_number <= len(self.lines) and end_line_number == line_number and 0 <= byte_start <= byte_end):
            return None
        line = self.lines[line_number - 1]
        try:
            encoded_line = line.encode("utf-8")
            start_column = len(encoded_line[:byte_start].decode("utf-8"))
            end_column = len(encoded_line[:byte_end].decode("utf-8"))
        except UnicodeError:
            return None
        if end_column <= start_column:
            return None
        return line_number, start_column, end_column

    def _append_candidate(self, candidate: PythonShellCandidate) -> None:
        key = (candidate.line_number, candidate.start_column, candidate.end_column, candidate.matched_pattern)
        if key in self.candidate_keys or len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
            return
        self.candidates.append(candidate)
        self.candidate_keys.add(key)

    @staticmethod
    def _enforce_binding_limit(bindings: dict[str, bool], identities: dict[str, str]) -> None:
        if len(bindings) + len(identities) > MAX_PYTHON_SHELL_BINDINGS:
            bindings.clear()
            identities.clear()
