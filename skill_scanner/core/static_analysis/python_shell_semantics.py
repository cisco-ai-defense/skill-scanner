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

"""Conservative positive evidence for reviewed Python execution sinks.

The signature pack already detects literal ``shell=True``, ``os.system``, and
``exec`` spelling. This module supplements those patterns with exact named
boolean flags, import-resolved ``os.system`` aliases, and the issue-#204
literal-join construction of ``builtins.exec``. It never executes source and
shares hard resource limits across outer and embedded syntax trees.
"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

MAX_PYTHON_SHELL_SOURCE_BYTES = 1024 * 1024
MAX_PYTHON_SHELL_AST_NODES = 50_000
MAX_PYTHON_SHELL_BINDINGS = 4_096
MAX_PYTHON_SHELL_CANDIDATES = 256
MAX_PYTHON_SHELL_SCOPE_DEPTH = 32
MAX_PYTHON_SHELL_IDENTIFIER_CHARS = 128
MAX_PYTHON_SHELL_EMBEDDED_BYTES = 256 * 1024
MAX_PYTHON_SHELL_EMBEDDED_PAYLOADS = 64
MAX_PYTHON_SHELL_JOIN_PARTS = 16
MAX_PYTHON_SHELL_JOIN_CHARS = 32

_SHELL_RULE_ID = "COMMAND_INJECTION_SHELL_TRUE"
_EVAL_RULE_ID = "COMMAND_INJECTION_EVAL"
_SUBPROCESS_METHODS = frozenset({"Popen", "call", "run"})
_SUBPROCESS_CALL_IDENTITIES = frozenset(f"callable:subprocess.{method}" for method in _SUBPROCESS_METHODS)
_PYTHON_C_BASE_KEYWORDS = frozenset({"args", "shell"})
_PYTHON_C_RUN_KEYWORDS = _PYTHON_C_BASE_KEYWORDS | {"check"}
_OS_SYSTEM_IDENTITY = "callable:os.system"
_PYTHON_EXECUTABLE_RE = re.compile(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", re.IGNORECASE)
_RAW_OS_SYSTEM_CALL_RE = re.compile(r"\bos\.system\s*\(")
_LEGACY_OS_SYSTEM_CALL_RE = re.compile(r"os\.system\s*\(")

_ScopeKind = Literal["module", "function", "class"]
_FlowKind = Literal["normal", "return", "raise", "break", "continue", "halt", "terminal"]


@dataclass(frozen=True, slots=True)
class PythonShellBoolCandidate:
    """A syntactic subprocess call whose named shell flag is exactly true."""

    line_number: int
    start_column: int
    end_column: int
    method_name: str
    variable_name: str

    @property
    def rule_id(self) -> str:
        """Return the canonical signature rule that owns this candidate."""

        return _SHELL_RULE_ID

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
    equivalent_regex_spans: tuple[tuple[int, int, int], ...] = ()

    @property
    def rule_id(self) -> str:
        """Return the canonical signature rule that owns this candidate."""

        return _SHELL_RULE_ID

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


@dataclass(frozen=True, slots=True)
class PythonDynamicExecCandidate:
    """A proven invocation of the issue-#204 dynamic ``builtins.exec`` alias."""

    line_number: int
    start_column: int
    end_column: int
    variable_name: str

    @property
    def rule_id(self) -> str:
        """Return the canonical signature rule that owns this candidate."""

        return _EVAL_RULE_ID

    @property
    def matched_pattern(self) -> str:
        """Return explicit semantic provenance for signature metadata."""

        return "python_ast:getattr_joined_builtin_exec"

    @property
    def evidence(self) -> str:
        """Return bounded evidence without retaining executed source."""

        return f"{self.variable_name}(...) -> builtins.exec"


PythonShellCandidate = PythonShellBoolCandidate | PythonOsSystemCandidate | PythonDynamicExecCandidate


@dataclass(slots=True)
class _ExpressionScanState:
    """Mutable facts shared while one expression is evaluated in order."""

    bool_bindings: dict[str, bool]
    identities: dict[str, str]
    poisoned_modules: set[str]
    external_names: set[str]
    scope_depth: int
    evidence_anchor: ast.expr | None
    equivalent_regex_spans: tuple[tuple[int, int, int], ...]
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


@dataclass(slots=True)
class _BodyScanResult:
    """Poison and control-flow state returned by one bounded suite scan."""

    poisoned_modules: set[str]
    flow: _FlowKind = "normal"


@dataclass(slots=True)
class _DynamicExecState:
    """Narrow module-scope provenance for the issue-#204 construction."""

    enabled: bool
    builtins_names: set[str] = field(default_factory=set)
    exec_names: set[str] = field(default_factory=set)
    getattr_is_builtin: bool = True

    def clear(self) -> None:
        """Invalidate every fact after unsupported syntax or effects."""

        self.builtins_names.clear()
        self.exec_names.clear()
        self.getattr_is_builtin = False

    def rebind(self, name: str) -> None:
        """Forget provenance replaced by one ordinary name binding."""

        self.builtins_names.discard(name)
        self.exec_names.discard(name)
        if name == "getattr":
            self.getattr_is_builtin = False

    @property
    def binding_count(self) -> int:
        return len(self.builtins_names) + len(self.exec_names)


def find_python_shell_candidates(source: str) -> tuple[PythonShellCandidate, ...]:
    """Find bounded positive evidence for reviewed execution sinks.

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
        budget = _AnalysisBudget(
            remaining_nodes=MAX_PYTHON_SHELL_AST_NODES,
            remaining_embedded_bytes=MAX_PYTHON_SHELL_EMBEDDED_BYTES,
            remaining_embedded_payloads=MAX_PYTHON_SHELL_EMBEDDED_PAYLOADS,
        )
        if not budget.consume_tree(tree):
            return ()
        # ``ast.parse`` accepts some trees (such as duplicate keywords or a
        # top-level return) that CPython will never execute. Charge the parsed
        # tree before asking the compiler to do any additional recursive work.
        compile(source, "<unknown>", "exec", dont_inherit=True)
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


def _bound_names(node: ast.AST) -> set[str]:
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del))
    }


def _loaded_names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)}


def _literal_joined_exec(expression: ast.expr) -> bool:
    """Fold only ``''.join`` over a bounded literal list or tuple."""

    if (
        not isinstance(expression, ast.Call)
        or expression.keywords
        or len(expression.args) != 1
        or not isinstance(expression.func, ast.Attribute)
        or expression.func.attr != "join"
        or not isinstance(expression.func.value, ast.Constant)
        or expression.func.value.value != ""
        or not isinstance(expression.args[0], (ast.List, ast.Tuple))
    ):
        return False

    elements = expression.args[0].elts
    if not elements or len(elements) > MAX_PYTHON_SHELL_JOIN_PARTS:
        return False

    parts: list[str] = []
    result_length = 0
    for element in elements:
        if not isinstance(element, ast.Constant) or type(element.value) is not str:
            return False
        result_length += len(element.value)
        if result_length > MAX_PYTHON_SHELL_JOIN_CHARS:
            return False
        parts.append(element.value)
    return "".join(parts) == "exec"


def _is_dynamic_exec_lookup(expression: ast.expr, state: _DynamicExecState) -> bool:
    return bool(
        state.enabled
        and state.getattr_is_builtin
        and isinstance(expression, ast.Call)
        and not expression.keywords
        and len(expression.args) == 2
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "getattr"
        and isinstance(expression.args[0], ast.Name)
        and expression.args[0].id in state.builtins_names
        and _literal_joined_exec(expression.args[1])
    )


class _StraightLineShellScanner:
    def __init__(self, source: str, budget: _AnalysisBudget) -> None:
        self.source = source
        self.lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
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
        self._scan_body(
            tree.body,
            depth=0,
            scope_kind="module",
            evidence_anchor=None,
            equivalent_regex_spans=(),
            embedded_method_name=None,
        )

    def _scan_body(
        self,
        body: list[ast.stmt],
        *,
        depth: int,
        scope_kind: _ScopeKind,
        evidence_anchor: ast.expr | None,
        equivalent_regex_spans: tuple[tuple[int, int, int], ...],
        embedded_method_name: str | None,
        initial_bool_bindings: dict[str, bool] | None = None,
        initial_identities: dict[str, str] | None = None,
        poisoned_modules: set[str] | None = None,
    ) -> _BodyScanResult:
        if poisoned_modules is None:
            poisoned_modules = set()
        if depth > MAX_PYTHON_SHELL_SCOPE_DEPTH or len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
            return _BodyScanResult(poisoned_modules)

        external_names = {
            name for statement in body if isinstance(statement, (ast.Global, ast.Nonlocal)) for name in statement.names
        }
        bool_bindings = dict(initial_bool_bindings or {})
        identities = dict(initial_identities or {})
        expression_state = _ExpressionScanState(
            bool_bindings=bool_bindings,
            identities=identities,
            poisoned_modules=poisoned_modules,
            external_names=external_names,
            scope_depth=depth,
            evidence_anchor=evidence_anchor,
            equivalent_regex_spans=equivalent_regex_spans,
            embedded_method_name=embedded_method_name,
        )
        dynamic_exec_state = _DynamicExecState(enabled=depth == 0 and evidence_anchor is None)

        def scan_nested_body(
            nested_body: list[ast.stmt],
            *,
            inherit_facts: bool = False,
            shadow_target: ast.expr | None = None,
            shadow_names: set[str] | None = None,
            isolate_poison: bool = False,
        ) -> _BodyScanResult:
            if not nested_body:
                nested_poison = set(poisoned_modules) if isolate_poison else poisoned_modules
                return _BodyScanResult(nested_poison)
            nested_bools = dict(bool_bindings) if inherit_facts else None
            nested_identities = dict(identities) if inherit_facts else None
            if shadow_target is not None and nested_bools is not None and nested_identities is not None:
                for name in self._target_names(shadow_target):
                    nested_bools.pop(name, None)
                    nested_identities.pop(name, None)
            if shadow_names and nested_bools is not None and nested_identities is not None:
                for name in shadow_names:
                    nested_bools.pop(name, None)
                    nested_identities.pop(name, None)
            return self._scan_body(
                nested_body,
                depth=depth + 1,
                scope_kind=scope_kind,
                evidence_anchor=evidence_anchor,
                equivalent_regex_spans=equivalent_regex_spans,
                embedded_method_name=embedded_method_name,
                initial_bool_bindings=nested_bools,
                initial_identities=nested_identities,
                poisoned_modules=set(poisoned_modules) if isolate_poison else poisoned_modules,
            )

        for statement_index, statement in enumerate(body):
            if len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
                return _BodyScanResult(poisoned_modules)

            self._scan_dynamic_exec_statement(statement, dynamic_exec_state)
            if dynamic_exec_state.binding_count > MAX_PYTHON_SHELL_BINDINGS:
                dynamic_exec_state.clear()

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_definition_expressions(statement, expression_state)
                definition_is_inert = self._plain_function_definition_is_inert(statement)
                # Delayed scopes receive no outer identities: a module alias
                # may be rebound before the function is ever called.
                if evidence_anchor is None:
                    self._scan_body(
                        statement.body,
                        depth=depth + 1,
                        scope_kind="function",
                        evidence_anchor=None,
                        equivalent_regex_spans=(),
                        embedded_method_name=None,
                        poisoned_modules=set(poisoned_modules),
                    )
                elif (
                    isinstance(statement, ast.FunctionDef)
                    and definition_is_inert
                    and statement_index + 1 < len(body)
                    and self._is_direct_zero_arg_call(statement, body[statement_index + 1])
                ):
                    invoked_bools = dict(bool_bindings)
                    invoked_identities = dict(identities)
                    for name in self._function_shadowed_names(statement):
                        invoked_bools.pop(name, None)
                        invoked_identities.pop(name, None)
                    self._seed_zero_arg_function_defaults(
                        statement,
                        bool_bindings,
                        identities,
                        invoked_bools,
                        invoked_identities,
                    )
                    self._scan_body(
                        statement.body,
                        depth=depth + 1,
                        scope_kind="function",
                        evidence_anchor=evidence_anchor,
                        equivalent_regex_spans=equivalent_regex_spans,
                        embedded_method_name=embedded_method_name,
                        initial_bool_bindings=invoked_bools,
                        initial_identities=invoked_identities,
                        poisoned_modules=poisoned_modules,
                    )
                # Defaults, annotations, and decorators may run while the
                # definition is evaluated, so outer facts do not cross it.
                if definition_is_inert:
                    bool_bindings.pop(statement.name, None)
                    identities.pop(statement.name, None)
                else:
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                continue

            if isinstance(statement, ast.Import):
                bool_bindings.clear()
                self._apply_import(statement, identities, poisoned_modules)
                self._enforce_binding_limit(bool_bindings, identities, poisoned_modules)
                continue

            if isinstance(statement, ast.ImportFrom):
                bool_bindings.clear()
                self._apply_import_from(statement, identities, poisoned_modules)
                self._enforce_binding_limit(bool_bindings, identities, poisoned_modules)
                continue

            if isinstance(statement, ast.ClassDef):
                header_is_safe = self._scan_expressions(statement.decorator_list, expression_state)
                type_parameter_names = self._type_parameter_names(statement)
                for name in type_parameter_names:
                    bool_bindings.pop(name, None)
                    identities.pop(name, None)
                header_is_safe = self._scan_expressions(statement.bases, expression_state) and header_is_safe
                for keyword in statement.keywords:
                    header_is_safe = self._scan_expression(keyword.value, expression_state) and header_is_safe
                    if keyword.arg is None:
                        # Expanding a class keyword mapping can invoke arbitrary
                        # mapping protocols before later keywords are evaluated.
                        self._clear_expression_facts(expression_state)
                        header_is_safe = False
                inherit_class_facts = (
                    header_is_safe
                    and scope_kind != "class"
                    and not statement.bases
                    and not statement.keywords
                    and not type_parameter_names
                )
                # Class bodies execute in their own namespace, while methods
                # are delayed scopes that do not close over class bindings.
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    scope_kind="class",
                    evidence_anchor=evidence_anchor,
                    equivalent_regex_spans=equivalent_regex_spans,
                    embedded_method_name=embedded_method_name,
                    initial_bool_bindings=bool_bindings if inherit_class_facts else None,
                    initial_identities=identities if inherit_class_facts else None,
                    poisoned_modules=poisoned_modules,
                )
                if inherit_class_facts and self._body_is_inert(statement.body):
                    bool_bindings.pop(statement.name, None)
                    identities.pop(statement.name, None)
                else:
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                continue

            if isinstance(statement, ast.Assign):
                value = _exact_bool(statement.value, bool_bindings)
                identity_value = self._resolve_identity(statement.value, identities)
                expression_is_safe = self._scan_expression(statement.value, expression_state)
                for target in statement.targets:
                    expression_is_safe = self._scan_assignment_target(target, expression_state) and expression_is_safe
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
                    elif identity_value is not None:
                        identities[name] = identity_value
                self._enforce_binding_limit(bool_bindings, identities, poisoned_modules)
                continue

            if isinstance(statement, ast.AnnAssign):
                value = _exact_bool(statement.value, bool_bindings) if statement.value is not None else None
                identity_value = (
                    self._resolve_identity(statement.value, identities) if statement.value is not None else None
                )
                expression_is_safe = self._scan_expression(statement.value, expression_state)
                expression_is_safe = (
                    self._scan_assignment_target(statement.target, expression_state) and expression_is_safe
                )
                self._poison_module_targets([statement.target], identities, poisoned_modules)
                if not isinstance(statement.target, ast.Name):
                    if not expression_is_safe:
                        self._clear_expression_facts(expression_state)
                    continue
                name = statement.target.id
                if statement.value is not None:
                    # CPython stores the RHS before evaluating an eager module
                    # or class annotation, so a same-name store hides an alias.
                    bool_bindings.pop(name, None)
                    identities.pop(name, None)
                    if expression_is_safe and name not in external_names and value is not None:
                        bool_bindings[name] = value
                    elif expression_is_safe and name not in external_names and identity_value is not None:
                        identities[name] = identity_value
                annotation_is_safe = True
                if scope_kind in {"module", "class"} and not self.annotations_are_deferred:
                    annotation_is_safe = self._scan_expression(statement.annotation, expression_state)
                if not expression_is_safe or not annotation_is_safe:
                    self._clear_expression_facts(expression_state)
                self._enforce_binding_limit(bool_bindings, identities, poisoned_modules)
                continue

            if isinstance(statement, ast.Expr):
                expression_is_safe = self._scan_expression(statement.value, expression_state)
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
                return _BodyScanResult(poisoned_modules, "return" if isinstance(statement, ast.Return) else "raise")

            if isinstance(statement, ast.Assert):
                truth = self._known_truth(statement.test, bool_bindings)
                test_is_safe = self._scan_expression(statement.test, expression_state)
                if truth is False:
                    self._scan_expression(statement.msg, expression_state)
                    return _BodyScanResult(poisoned_modules, "raise")
                if truth is None or not test_is_safe:
                    self._clear_expression_facts(expression_state)
                continue

            if isinstance(statement, ast.Delete):
                targets_are_safe = True
                for target in statement.targets:
                    targets_are_safe = self._scan_assignment_target(target, expression_state) and targets_are_safe
                self._poison_module_targets(statement.targets, identities, poisoned_modules)
                targets = _name_targets(statement.targets)
                if targets is None or not targets_are_safe:
                    bool_bindings.clear()
                    identities.clear()
                else:
                    for name in targets:
                        bool_bindings.pop(name, None)
                        identities.pop(name, None)
                continue

            if isinstance(statement, ast.Pass):
                continue

            if isinstance(statement, ast.Break):
                return _BodyScanResult(poisoned_modules, "break")

            if isinstance(statement, ast.Continue):
                return _BodyScanResult(poisoned_modules, "continue")

            if isinstance(statement, ast.If):
                truth = self._known_truth(statement.test, bool_bindings)
                header_is_safe = self._scan_expression(statement.test, expression_state)
                selected_body: list[ast.stmt] | None = None
                selected_result: _BodyScanResult | None = None
                if truth is not None:
                    selected_body = statement.body if truth else statement.orelse
                    selected_result = scan_nested_body(
                        selected_body,
                        inherit_facts=header_is_safe,
                    )
                else:
                    branch_results = [
                        scan_nested_body(statement.body, isolate_poison=True),
                        scan_nested_body(statement.orelse, isolate_poison=True),
                    ]
                    poisoned_modules.update(*(result.poisoned_modules for result in branch_results))
                    branch_flows = {result.flow for result in branch_results}
                    if branch_flows and branch_flows <= {"return", "raise", "halt", "terminal"}:
                        flow = branch_results[0].flow if len(branch_flows) == 1 else "terminal"
                        return _BodyScanResult(poisoned_modules, flow)
                    if branch_flows == {"break"}:
                        return _BodyScanResult(poisoned_modules, "break")
                    if branch_flows == {"continue"}:
                        return _BodyScanResult(poisoned_modules, "continue")
                if (
                    selected_body is None
                    or not header_is_safe
                    or not self._body_preserves_facts(selected_body, bool_bindings, identities)
                ):
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                if selected_result is not None and selected_result.flow != "normal":
                    return _BodyScanResult(poisoned_modules, selected_result.flow)
                continue

            if isinstance(statement, ast.While):
                truth = self._known_truth(statement.test, bool_bindings)
                header_is_safe = self._scan_expression(statement.test, expression_state)
                while_result: _BodyScanResult | None = None
                condition_is_unchanged = False
                body_preserves_facts = False
                if truth is False:
                    while_result = scan_nested_body(statement.orelse, inherit_facts=header_is_safe)
                elif truth is True:
                    while_result = scan_nested_body(statement.body, inherit_facts=header_is_safe)
                    body_preserves_facts = self._body_preserves_facts(
                        statement.body,
                        bool_bindings,
                        identities,
                        require_deterministic_control_flow=True,
                    )
                    condition_is_unchanged = isinstance(statement.test, ast.Constant) or body_preserves_facts
                    if while_result.flow == "normal" and not isinstance(statement.test, ast.Constant):
                        scan_nested_body(statement.orelse)
                else:
                    branch_results = [
                        scan_nested_body(statement.body, isolate_poison=True),
                        scan_nested_body(statement.orelse, isolate_poison=True),
                    ]
                    poisoned_modules.update(*(result.poisoned_modules for result in branch_results))
                preserves_after_break = bool(
                    truth is True
                    and header_is_safe
                    and while_result is not None
                    and while_result.flow == "break"
                    and body_preserves_facts
                )
                if not preserves_after_break and (
                    truth is not False or not header_is_safe or not self._body_is_inert(statement.orelse)
                ):
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                if while_result is not None and while_result.flow in {"return", "raise", "terminal"}:
                    return _BodyScanResult(poisoned_modules, while_result.flow)
                if truth is True and while_result is not None:
                    if while_result.flow == "halt":
                        return _BodyScanResult(poisoned_modules, "halt")
                    if (while_result.flow == "continue" and condition_is_unchanged) or (
                        while_result.flow == "normal" and self._body_is_inert(statement.body) and condition_is_unchanged
                    ):
                        return _BodyScanResult(poisoned_modules, "halt")
                continue

            if isinstance(statement, (ast.For, ast.AsyncFor)):
                iterable_is_empty = self._known_iterable_empty(statement.iter)
                header_is_safe = self._scan_expression(statement.iter, expression_state)
                body_result: _BodyScanResult | None = None
                else_result: _BodyScanResult | None = None
                if iterable_is_empty is True:
                    else_result = scan_nested_body(statement.orelse, inherit_facts=header_is_safe)
                elif (
                    iterable_is_empty is False
                    and isinstance(statement, ast.For)
                    and (
                        isinstance(statement.target, ast.Name)
                        or self._literal_for_target_binds(statement.target, statement.iter)
                    )
                ):
                    body_result = scan_nested_body(
                        statement.body,
                        inherit_facts=header_is_safe,
                        shadow_target=statement.target,
                    )
                    if body_result.flow != "break":
                        else_result = scan_nested_body(statement.orelse)
                elif iterable_is_empty is None:
                    branch_results = [
                        scan_nested_body(statement.body, isolate_poison=True),
                        scan_nested_body(statement.orelse, isolate_poison=True),
                    ]
                    poisoned_modules.update(*(result.poisoned_modules for result in branch_results))
                protected_names = bool_bindings.keys() | identities.keys()
                preserves_after_inert_iteration = bool(
                    iterable_is_empty is False
                    and isinstance(statement, ast.For)
                    and isinstance(statement.target, ast.Name)
                    and statement.target.id not in protected_names
                    and header_is_safe
                    and self._body_is_inert(statement.body)
                    and self._body_is_inert(statement.orelse)
                )
                if not preserves_after_inert_iteration and (
                    iterable_is_empty is not True or not header_is_safe or not self._body_is_inert(statement.orelse)
                ):
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                if body_result is not None and body_result.flow in {"return", "raise", "terminal", "halt"}:
                    return _BodyScanResult(poisoned_modules, body_result.flow)
                if else_result is not None and else_result.flow in {"return", "raise", "terminal", "halt"}:
                    return _BodyScanResult(poisoned_modules, else_result.flow)
                continue

            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._scan_expression(item.context_expr, expression_state)
                    # Context-manager entry can change later name resolution.
                    self._clear_expression_facts(expression_state)
                    self._scan_assignment_target(item.optional_vars, expression_state)
                scan_nested_body(statement.body)
                self._poison_known_modules(identities, poisoned_modules)
                bool_bindings.clear()
                identities.clear()
                continue

            if isinstance(statement, (ast.Try, ast.TryStar)):
                explicit_safe_raise = bool(
                    statement.body
                    and isinstance(statement.body[0], ast.Raise)
                    and _is_side_effect_free(statement.body[0].exc)
                    and _is_side_effect_free(statement.body[0].cause)
                )
                simple_zero_division = self._starts_with_simple_zero_division(statement.body)
                known_safe_raise = explicit_safe_raise or simple_zero_division
                direct_safe_return = bool(
                    statement.body
                    and isinstance(statement.body[0], ast.Return)
                    and _is_side_effect_free(statement.body[0].value)
                )
                if known_safe_raise:
                    for handler in statement.handlers:
                        if not self._scan_expression(handler.type, expression_state):
                            break
                body_result = (
                    _BodyScanResult(poisoned_modules, "raise")
                    if simple_zero_division
                    else scan_nested_body(statement.body, inherit_facts=True)
                )
                body_preserves_facts = self._body_preserves_facts(statement.body, bool_bindings, identities)
                safe_raise_path = known_safe_raise or (body_result.flow == "raise" and body_preserves_facts)
                safe_normal_body = body_result.flow == "normal" and body_preserves_facts
                if safe_raise_path and not known_safe_raise:
                    for handler in statement.handlers:
                        if not self._scan_expression(handler.type, expression_state):
                            break
                alternative_results: list[_BodyScanResult] = []
                guaranteed_handler: ast.ExceptHandler | None = None
                if safe_raise_path:
                    guaranteed_handler = next((handler for handler in statement.handlers if handler.type is None), None)
                    for handler in statement.handlers:
                        alternative_results.append(
                            scan_nested_body(
                                handler.body,
                                inherit_facts=handler is guaranteed_handler,
                                isolate_poison=True,
                            )
                        )
                        if handler is guaranteed_handler:
                            break
                elif body_result.flow == "terminal":
                    for handler in statement.handlers:
                        alternative_results.append(scan_nested_body(handler.body, isolate_poison=True))
                elif body_result.flow == "raise":
                    for handler in statement.handlers:
                        alternative_results.append(scan_nested_body(handler.body, isolate_poison=True))
                elif body_result.flow not in {"return", "break", "continue", "halt"} and not safe_normal_body:
                    for handler in statement.handlers:
                        alternative_results.append(scan_nested_body(handler.body, isolate_poison=True))
                    alternative_results.append(
                        scan_nested_body(
                            statement.orelse,
                            isolate_poison=True,
                        )
                    )
                elif safe_normal_body:
                    alternative_results.append(
                        scan_nested_body(
                            statement.orelse,
                            inherit_facts=True,
                            isolate_poison=True,
                        )
                    )
                if alternative_results:
                    poisoned_modules.update(*(result.poisoned_modules for result in alternative_results))
                handler_is_inert = guaranteed_handler is not None and all(
                    isinstance(item, ast.Pass) for item in guaranteed_handler.body
                )
                handler_path_is_safe = guaranteed_handler is not None and all(
                    _is_side_effect_free(handler.type)
                    for handler in statement.handlers[: statement.handlers.index(guaranteed_handler)]
                )
                finally_result = (
                    _BodyScanResult(poisoned_modules)
                    if body_result.flow == "halt"
                    else scan_nested_body(
                        statement.finalbody,
                        inherit_facts=(safe_normal_body and self._body_is_inert(statement.orelse))
                        or direct_safe_return
                        or (body_result.flow in {"return", "break", "continue"} and body_preserves_facts)
                        or bool(safe_raise_path and not statement.handlers)
                        or bool(safe_raise_path and handler_is_inert and handler_path_is_safe)
                        or bool(body_result.flow == "terminal" and body_preserves_facts and not statement.handlers),
                    )
                )
                try_preserves_facts = (
                    safe_normal_body
                    and self._body_is_inert(statement.orelse)
                    and self._body_is_inert(statement.finalbody)
                ) or (
                    bool(safe_raise_path and handler_is_inert and handler_path_is_safe)
                    and self._body_is_inert(statement.finalbody)
                )
                if not try_preserves_facts:
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                if finally_result.flow != "normal":
                    return _BodyScanResult(poisoned_modules, finally_result.flow)
                if body_result.flow in {"return", "break", "continue", "halt"}:
                    return _BodyScanResult(poisoned_modules, body_result.flow)
                if body_result.flow == "terminal" and not statement.handlers:
                    return _BodyScanResult(poisoned_modules, "terminal")
                if safe_normal_body:
                    else_result = alternative_results[-1] if alternative_results else body_result
                    if else_result.flow != "normal":
                        return _BodyScanResult(poisoned_modules, else_result.flow)
                elif safe_raise_path and guaranteed_handler is not None:
                    handler_index = statement.handlers.index(guaranteed_handler)
                    if handler_index < len(alternative_results) and alternative_results[handler_index].flow != "normal":
                        return _BodyScanResult(poisoned_modules, alternative_results[handler_index].flow)
                elif body_result.flow == "raise" and not statement.handlers:
                    return _BodyScanResult(poisoned_modules, "raise")
                continue

            if isinstance(statement, ast.Match):
                subject_is_safe = self._scan_expression(statement.subject, expression_state)
                case_results: list[_BodyScanResult] = []
                match_result: _BodyScanResult | None = None
                match_preserves_facts = False
                definite_miss_prefix = True
                for case in statement.cases:
                    pattern_match = self._known_pattern_match(case.pattern, statement.subject, bool_bindings)
                    if pattern_match is False:
                        continue
                    selected_after_definite_misses = definite_miss_prefix
                    definite_miss_prefix = False
                    bound_names = self._pattern_bound_names(case.pattern)
                    guard_bools = dict(bool_bindings) if pattern_match is True and subject_is_safe else {}
                    guard_identities = dict(identities) if pattern_match is True and subject_is_safe else {}
                    for name in bound_names:
                        guard_bools.pop(name, None)
                        guard_identities.pop(name, None)
                    guard_poison = set(poisoned_modules)
                    guard_state = _ExpressionScanState(
                        bool_bindings=guard_bools,
                        identities=guard_identities,
                        poisoned_modules=guard_poison,
                        external_names=external_names,
                        scope_depth=depth + 1,
                        evidence_anchor=evidence_anchor,
                        equivalent_regex_spans=equivalent_regex_spans,
                        embedded_method_name=embedded_method_name,
                    )
                    guard_truth = self._known_truth(case.guard, guard_bools) if case.guard is not None else True
                    guard_is_safe = self._scan_expression(case.guard, guard_state)
                    poisoned_modules.update(guard_poison)
                    if guard_truth is False:
                        continue
                    case_result = scan_nested_body(
                        case.body,
                        inherit_facts=pattern_match is True
                        and subject_is_safe
                        and guard_is_safe
                        and guard_truth is True,
                        shadow_names=bound_names,
                        isolate_poison=True,
                    )
                    case_results.append(case_result)
                    if pattern_match is True and guard_truth is True:
                        match_result = case_result
                        protected_names = bool_bindings.keys() | identities.keys()
                        match_preserves_facts = bool(
                            selected_after_definite_misses
                            and case.guard is None
                            and subject_is_safe
                            and case_result.flow == "normal"
                            and protected_names.isdisjoint(bound_names)
                            and self._body_preserves_facts(
                                case.body,
                                bool_bindings,
                                identities,
                                require_deterministic_control_flow=True,
                            )
                        )
                        break
                if case_results:
                    poisoned_modules.update(*(result.poisoned_modules for result in case_results))
                if not match_preserves_facts:
                    self._poison_known_modules(identities, poisoned_modules)
                    bool_bindings.clear()
                    identities.clear()
                if match_result is not None and match_result.flow != "normal":
                    return _BodyScanResult(poisoned_modules, match_result.flow)
                continue

            if isinstance(statement, ast.AugAssign):
                self._scan_assignment_target(statement.target, expression_state, load_before_store=True)
                self._scan_expression(statement.value, expression_state)
                self._poison_module_targets([statement.target], identities, poisoned_modules)

            # Calls hidden in unsupported expressions, augmented assignments,
            # and unsupported statements are hard boundaries. Processing
            # resumes with no facts so later direct imports or assignments can
            # establish fresh positive evidence.
            self._poison_known_modules(identities, poisoned_modules)
            bool_bindings.clear()
            identities.clear()

        return _BodyScanResult(poisoned_modules)

    def _scan_dynamic_exec_statement(self, statement: ast.stmt, state: _DynamicExecState) -> None:
        """Advance the narrow module-level issue-#204 provenance state."""

        if not state.enabled:
            return

        if isinstance(statement, ast.Import):
            for imported in statement.names:
                local_name = imported.asname or imported.name.split(".", 1)[0]
                state.rebind(local_name)
                if imported.name == "builtins":
                    state.builtins_names.add(local_name)
            return

        if isinstance(statement, ast.ImportFrom):
            if any(imported.name == "*" for imported in statement.names):
                state.clear()
                return
            for imported in statement.names:
                state.rebind(imported.asname or imported.name)
            return

        if isinstance(statement, ast.Assign):
            targets = _name_targets(statement.targets)
            if targets is None:
                state.clear()
                return

            dynamic_exec = _is_dynamic_exec_lookup(statement.value, state)
            for name in _bound_names(statement.value):
                state.rebind(name)
            if not dynamic_exec and not _is_side_effect_free(statement.value):
                state.exec_names.clear()
                state.builtins_names.difference_update(_loaded_names(statement.value))
            for name in targets:
                state.rebind(name)
                if dynamic_exec and len(name) <= MAX_PYTHON_SHELL_IDENTIFIER_CHARS:
                    state.exec_names.add(name)
            return

        if isinstance(statement, ast.Expr):
            call = statement.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in state.exec_names:
                self._record_dynamic_exec(call.func)
                state.clear()
            elif not isinstance(statement.value, ast.Constant):
                state.clear()
            return

        if isinstance(statement, ast.Pass):
            return

        # No claims cross definitions, control flow, annotations, deletion,
        # mutation, or another unsupported execution boundary.
        state.clear()

    def _scan_assignment_target(
        self,
        target: ast.expr | None,
        state: _ExpressionScanState,
        *,
        load_before_store: bool = False,
    ) -> bool:
        """Scan expressions evaluated while assigning or deleting a target."""

        if target is None or isinstance(target, ast.Name):
            return True
        if isinstance(target, ast.Attribute):
            self._scan_expression(target.value, state)
            # Attribute load/store can dispatch a descriptor or custom setter.
            self._clear_expression_facts(state)
            return False
        if isinstance(target, ast.Subscript):
            self._scan_expression(target.value, state)
            self._scan_expression(target.slice, state)
            # Subscription load/store can invoke arbitrary user protocols.
            self._clear_expression_facts(state)
            return False
        if isinstance(target, ast.Starred):
            return self._scan_assignment_target(target.value, state, load_before_store=load_before_store)
        if isinstance(target, (ast.List, ast.Tuple)):
            # Iterable unpacking itself occurs before the component stores.
            self._clear_expression_facts(state)
            for element in target.elts:
                self._scan_assignment_target(element, state, load_before_store=load_before_store)
            return False
        self._clear_expression_facts(state)
        return False

    @staticmethod
    def _target_names(target: ast.expr) -> set[str]:
        return {node.id for node in ast.walk(target) if isinstance(node, ast.Name)}

    @staticmethod
    def _type_parameter_names(statement: ast.AST) -> set[str]:
        return {
            name
            for parameter in getattr(statement, "type_params", ())
            if isinstance((name := getattr(parameter, "name", None)), str)
        }

    @staticmethod
    def _is_irrefutable_pattern(pattern: ast.pattern) -> bool:
        return isinstance(pattern, ast.MatchAs) and pattern.pattern is None

    @staticmethod
    def _pattern_bound_names(pattern: ast.pattern) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(pattern):
            if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name is not None:
                names.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest is not None:
                names.add(node.rest)
        return names

    @classmethod
    def _known_pattern_match(
        cls,
        pattern: ast.pattern,
        subject: ast.expr,
        bool_bindings: dict[str, bool],
    ) -> bool | None:
        if isinstance(subject, ast.Constant):
            subject_value: object = subject.value
        elif isinstance(subject, ast.Name) and subject.id in bool_bindings:
            subject_value = bool_bindings[subject.id]
        else:
            return None
        if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
            return True
        if isinstance(pattern, ast.MatchSingleton):
            return subject_value is pattern.value
        if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
            return bool(subject_value == pattern.value.value)
        if isinstance(pattern, ast.MatchOr):
            outcomes = [cls._known_pattern_match(option, subject, bool_bindings) for option in pattern.patterns]
            if any(outcome is True for outcome in outcomes):
                return True
            if all(outcome is False for outcome in outcomes):
                return False
        return None

    @staticmethod
    def _body_is_inert(body: list[ast.stmt]) -> bool:
        return all(
            isinstance(statement, ast.Pass)
            or (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant))
            for statement in body
        )

    def _body_preserves_facts(
        self,
        body: list[ast.stmt],
        bool_bindings: dict[str, bool],
        identities: dict[str, str],
        *,
        require_deterministic_control_flow: bool = False,
    ) -> bool:
        """Prove a tiny deterministic suite cannot mutate tracked facts."""

        for statement in body:
            if self._body_is_inert([statement]):
                continue
            if isinstance(statement, ast.Return):
                return _is_side_effect_free(statement.value)
            if isinstance(statement, ast.Raise):
                return _is_side_effect_free(statement.exc) and _is_side_effect_free(statement.cause)
            if isinstance(statement, (ast.Break, ast.Continue)):
                return True
            if isinstance(statement, ast.Assign):
                targets = _name_targets(statement.targets)
                protected_names = bool_bindings.keys() | identities.keys()
                if (
                    targets is not None
                    and not protected_names.intersection(targets)
                    and _is_side_effect_free(statement.value)
                ):
                    continue
                return False
            if isinstance(statement, ast.If):
                truth = self._known_truth(statement.test, bool_bindings)
                if not _is_side_effect_free(statement.test):
                    return False
                if truth is None:
                    if require_deterministic_control_flow:
                        return False
                    if statement.orelse and all(
                        self._body_preserves_facts(
                            branch,
                            bool_bindings,
                            identities,
                            require_deterministic_control_flow=require_deterministic_control_flow,
                        )
                        for branch in (statement.body, statement.orelse)
                    ):
                        continue
                    return False
                selected = statement.body if truth else statement.orelse
                if self._body_preserves_facts(
                    selected,
                    bool_bindings,
                    identities,
                    require_deterministic_control_flow=require_deterministic_control_flow,
                ):
                    continue
            return False
        return True

    @staticmethod
    def _starts_with_simple_zero_division(body: list[ast.stmt]) -> bool:
        if not body or not isinstance(body[0], ast.Expr) or not isinstance(body[0].value, ast.BinOp):
            return False
        expression = body[0].value
        return (
            isinstance(expression.op, (ast.Div, ast.FloorDiv, ast.Mod))
            and isinstance(expression.left, ast.Constant)
            and type(expression.left.value) in {int, float, complex}
            and isinstance(expression.right, ast.Constant)
            and type(expression.right.value) in {int, float, complex}
            and expression.right.value == 0
        )

    def _plain_function_definition_is_inert(self, statement: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if statement.decorator_list or self._type_parameter_names(statement):
            return False
        expressions: list[ast.expr | None] = [*statement.args.defaults, *statement.args.kw_defaults]
        if not self.annotations_are_deferred:
            parameters = [
                *statement.args.args,
                *statement.args.posonlyargs,
                statement.args.vararg,
                *statement.args.kwonlyargs,
                statement.args.kwarg,
            ]
            expressions.extend(parameter.annotation for parameter in parameters if parameter is not None)
            expressions.append(statement.returns)
        return all(_is_side_effect_free(expression) for expression in expressions)

    @staticmethod
    def _is_direct_zero_arg_call(statement: ast.FunctionDef, following: ast.stmt) -> bool:
        if not (
            isinstance(following, ast.Expr)
            and isinstance(following.value, ast.Call)
            and isinstance(following.value.func, ast.Name)
            and following.value.func.id == statement.name
            and not following.value.args
            and not following.value.keywords
        ):
            return False
        positional = [*statement.args.posonlyargs, *statement.args.args]
        if len(statement.args.defaults) < len(positional) or any(
            default is None for default in statement.args.kw_defaults
        ):
            return False
        pending: list[ast.AST] = list(statement.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                return False
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            pending.extend(ast.iter_child_nodes(node))
        return True

    @staticmethod
    def _function_shadowed_names(statement: ast.FunctionDef) -> set[str]:
        names = {
            parameter.arg
            for parameter in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            )
        }
        if statement.args.vararg is not None:
            names.add(statement.args.vararg.arg)
        if statement.args.kwarg is not None:
            names.add(statement.args.kwarg.arg)
        pending: list[ast.AST] = list(statement.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
                continue
            if isinstance(node, ast.Lambda):
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)
            elif isinstance(node, ast.Import):
                names.update(alias.asname or alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
            pending.extend(ast.iter_child_nodes(node))
        return names

    def _seed_zero_arg_function_defaults(
        self,
        statement: ast.FunctionDef,
        source_bools: dict[str, bool],
        source_identities: dict[str, str],
        body_bools: dict[str, bool],
        body_identities: dict[str, str],
    ) -> None:
        positional = [*statement.args.posonlyargs, *statement.args.args]
        default_parameters = positional[len(positional) - len(statement.args.defaults) :]
        defaults = [
            *zip(default_parameters, statement.args.defaults, strict=True),
            *(
                (parameter, default)
                for parameter, default in zip(statement.args.kwonlyargs, statement.args.kw_defaults, strict=True)
                if default is not None
            ),
        ]
        for parameter, default in defaults:
            exact_bool = _exact_bool(default, source_bools)
            exact_identity = self._resolve_identity(default, source_identities)
            if exact_bool is not None:
                body_bools[parameter.arg] = exact_bool
            elif exact_identity is not None:
                body_identities[parameter.arg] = exact_identity

    @classmethod
    def _literal_for_target_binds(cls, target: ast.expr, iterable: ast.expr) -> bool:
        if not isinstance(iterable, (ast.List, ast.Tuple)) or not iterable.elts:
            return False
        if any(isinstance(element, ast.Starred) for element in iterable.elts):
            return False
        return cls._literal_value_binds_target(target, iterable.elts[0])

    @classmethod
    def _literal_value_binds_target(cls, target: ast.expr, value: ast.expr) -> bool:
        if isinstance(target, ast.Name):
            return True
        if not isinstance(target, (ast.List, ast.Tuple)) or not isinstance(value, (ast.List, ast.Tuple)):
            return False
        if any(isinstance(element, ast.Starred) for element in target.elts) or len(target.elts) != len(value.elts):
            return False
        return all(
            cls._literal_value_binds_target(target_element, value_element)
            for target_element, value_element in zip(target.elts, value.elts, strict=True)
        )

    def _scan_definition_expressions(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
        state: _ExpressionScanState,
    ) -> None:
        self._scan_expressions(statement.decorator_list, state)
        self._scan_expressions(statement.args.defaults, state)
        self._scan_expressions(statement.args.kw_defaults, state)
        for name in self._type_parameter_names(statement):
            state.bool_bindings.pop(name, None)
            state.identities.pop(name, None)
        if not self.annotations_are_deferred:
            parameters = [
                *statement.args.args,
                *statement.args.posonlyargs,
                statement.args.vararg,
                *statement.args.kwonlyargs,
                statement.args.kwarg,
            ]
            self._scan_expressions(
                [*(parameter.annotation for parameter in parameters if parameter is not None), statement.returns],
                state,
            )

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
            identity_value = self._resolve_identity(expression.value, state.identities)
            is_safe = scan(expression.value)
            name = expression.target.id
            state.bool_bindings.pop(name, None)
            state.identities.pop(name, None)
            if is_safe and exact_value is not None and name not in state.external_names:
                state.bool_bindings[name] = exact_value
            elif is_safe and identity_value is not None and name not in state.external_names:
                state.identities[name] = identity_value
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
                element_is_safe = scan(element.value if isinstance(element, ast.Starred) else element)
                all_safe = element_is_safe and all_safe
                if isinstance(element, ast.Starred) and (
                    not element_is_safe or self._known_iterable_empty(element.value) is None
                ):
                    self._clear_expression_facts(state)
                    all_safe = False
            return all_safe
        if isinstance(expression, ast.Set):
            has_unpack = any(isinstance(element, ast.Starred) for element in expression.elts)
            for element in expression.elts:
                scan(element.value if isinstance(element, ast.Starred) else element)
                if has_unpack:
                    # SET_UPDATE can dispatch before a later display segment.
                    self._clear_expression_facts(state)
            if expression.elts and not has_unpack:
                # BUILD_SET hashes only after every element expression ran.
                self._clear_expression_facts(state)
            return not expression.elts
        if isinstance(expression, ast.Dict):
            has_unpack = any(key is None for key in expression.keys)
            for key, value in zip(expression.keys, expression.values, strict=True):
                if key is not None:
                    scan(key)
                scan(value)
                if has_unpack:
                    # DICT_UPDATE can dispatch before a later display segment.
                    self._clear_expression_facts(state)
            if expression.values and not has_unpack:
                # BUILD_MAP hashes only after every key/value expression ran.
                self._clear_expression_facts(state)
            return not expression.values
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            truth = self._known_truth(expression, state.bool_bindings)
            operand_is_safe = scan(expression.operand)
            return truth is not None and operand_is_safe
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
            invocation_is_possible = True
            for call_value in expression.args:
                arguments_are_safe = (
                    scan(call_value.value if isinstance(call_value, ast.Starred) else call_value) and arguments_are_safe
                )
                if isinstance(call_value, ast.Starred):
                    if self._starred_expansion_definitely_fails(call_value.value):
                        invocation_is_possible = False
                    self._clear_expression_facts(state)
                    arguments_are_safe = False
            shell_binding: tuple[str, bool | None] | None = None
            keyword_names: set[str] = set()
            for keyword in expression.keywords:
                keyword_is_safe = scan(keyword.value)
                arguments_are_safe = keyword_is_safe and arguments_are_safe
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Name)
                    and len(keyword.value.id) <= MAX_PYTHON_SHELL_IDENTIFIER_CHARS
                ):
                    shell_binding = (keyword.value.id, state.bool_bindings.get(keyword.value.id))
                if keyword.arg is None:
                    unpacked_names = self._literal_keyword_names(keyword.value)
                    if unpacked_names is None or not keyword_names.isdisjoint(unpacked_names):
                        invocation_is_possible = False
                    else:
                        keyword_names.update(unpacked_names)
                    self._clear_expression_facts(state)
                    arguments_are_safe = False
                elif keyword.arg in keyword_names:
                    invocation_is_possible = False
                else:
                    keyword_names.add(keyword.arg)
            if (
                invocation_is_possible
                and function_identity == _OS_SYSTEM_IDENTITY
                and (
                    self._is_alias_spelling(expression.func)
                    or (state.evidence_anchor is not None and self.allow_embedded_canonical)
                )
            ):
                # Python captures the callee before evaluating arguments, but
                # a provably failing expansion never reaches the invocation.
                self._record_os_system(
                    state.evidence_anchor or expression.func,
                    embedded_method_name=state.embedded_method_name,
                    equivalent_regex_spans=state.equivalent_regex_spans,
                )
            if invocation_is_possible and shell_binding is not None:
                self._record_named_shell_flag(expression, shell_binding)
            if reviewed_spelling and function_is_safe and arguments_are_safe:
                preserves_facts = self._record_call(
                    expression,
                    state.bool_bindings,
                    function_identity,
                    depth=state.scope_depth,
                    evidence_anchor=state.evidence_anchor,
                )
                if preserves_facts:
                    return True
            if isinstance(expression.func, ast.Lambda) and self._lambda_call_binds(expression):
                lambda_state = self._lambda_body_state(state, expression.func, expression)
                self._scan_expression(expression.func.body, lambda_state, expression_depth + 1)
            self._clear_expression_facts(state)
            return False
        if isinstance(expression, ast.Lambda):
            return self._scan_expressions([*expression.args.defaults, *expression.args.kw_defaults], state)
        if isinstance(expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return self._scan_comprehension(expression, state, expression_depth)
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

    def _scan_comprehension(
        self,
        expression: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        state: _ExpressionScanState,
        expression_depth: int,
    ) -> bool:
        """Scan only comprehension stages proven to execute in source order."""

        if state.scope_depth + expression_depth + len(expression.generators) > MAX_PYTHON_SHELL_SCOPE_DEPTH:
            self._clear_expression_facts(state)
            return False
        first = expression.generators[0]
        first_empty = self._known_iterable_empty(first.iter)
        first_is_safe = self._scan_expression(first.iter, state, expression_depth + 1)
        if isinstance(expression, ast.GeneratorExp):
            if first.is_async or first_empty is None or not first_is_safe:
                self._clear_expression_facts(state)
                return False
            return True

        def scan_stage(index: int, stage_state: _ExpressionScanState, iterable_already_scanned: bool) -> None:
            generator = expression.generators[index]
            iterable_is_empty = self._known_iterable_empty(generator.iter)
            iterable_is_safe = (
                first_is_safe
                if iterable_already_scanned
                else self._scan_expression(generator.iter, stage_state, expression_depth + index + 1)
            )
            if generator.is_async:
                self._clear_expression_facts(stage_state)
                return
            if iterable_is_empty is True:
                return
            if iterable_is_empty is None or not isinstance(generator.target, ast.Name):
                self._clear_expression_facts(stage_state)
                return
            local_state = self._comprehension_state(stage_state, generator.target)
            if not iterable_is_safe:
                self._clear_expression_facts(local_state)
            for condition in generator.ifs:
                truth = self._known_truth(condition, local_state.bool_bindings)
                self._scan_expression(condition, local_state, expression_depth + index + 1)
                if truth is False:
                    return
                if truth is None:
                    self._clear_expression_facts(local_state)
                    return
            if index + 1 < len(expression.generators):
                scan_stage(index + 1, local_state, False)
                return
            result_values: list[ast.expr] = (
                [expression.key, expression.value] if isinstance(expression, ast.DictComp) else [expression.elt]
            )
            self._scan_expressions(result_values, local_state)

        scan_stage(0, state, True)
        self._clear_expression_facts(state)
        return False

    @staticmethod
    def _known_truth(expression: ast.expr, bindings: dict[str, bool]) -> bool | None:
        exact = _exact_bool(expression, bindings)
        if exact is not None:
            return exact
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            operand = expression.operand
            operand_truth = _exact_bool(operand, bindings)
            if operand_truth is None and isinstance(operand, ast.Constant):
                operand_truth = bool(operand.value)
            if operand_truth is None and isinstance(operand, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                operand_empty = _StraightLineShellScanner._known_iterable_empty(operand)
                operand_truth = None if operand_empty is None else not operand_empty
            return None if operand_truth is None else not operand_truth
        if isinstance(expression, ast.Constant):
            return bool(expression.value)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            is_empty = _StraightLineShellScanner._known_iterable_empty(expression)
            return None if is_empty is None else not is_empty
        return None

    @staticmethod
    def _starred_expansion_definitely_fails(expression: ast.expr) -> bool:
        return isinstance(expression, ast.Constant) and not isinstance(expression.value, (str, bytes))

    @staticmethod
    def _literal_keyword_names(expression: ast.expr) -> set[str] | None:
        if not isinstance(expression, ast.Dict):
            return None
        names: set[str] = set()
        for key in expression.keys:
            if key is None or not isinstance(key, ast.Constant) or type(key.value) is not str:
                return None
            names.add(key.value)
        return names

    @staticmethod
    def _known_iterable_empty(expression: ast.expr) -> bool | None:
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            for element in expression.elts:
                if not isinstance(element, ast.Starred):
                    return False
                nested_empty = _StraightLineShellScanner._known_iterable_empty(element.value)
                if nested_empty is None:
                    return None
                if nested_empty is False:
                    return False
            return True
        if isinstance(expression, ast.Dict):
            for key, value in zip(expression.keys, expression.values, strict=True):
                if key is not None:
                    return False
                nested_empty = _StraightLineShellScanner._known_iterable_empty(value)
                if nested_empty is None:
                    return None
                if nested_empty is False:
                    return False
            return True
        if isinstance(expression, ast.Constant) and isinstance(expression.value, (str, bytes)):
            return not expression.value
        return None

    @staticmethod
    def _lambda_call_binds(call: ast.Call) -> bool:
        """Prove a direct lambda call binds without executing deferred code."""

        if not isinstance(call.func, ast.Lambda):
            return False
        arguments = call.func.args
        if any(isinstance(argument, ast.Starred) for argument in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return False
        pending: list[ast.AST] = [call.func.body]
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                return False
            if isinstance(node, ast.Lambda):
                continue
            pending.extend(ast.iter_child_nodes(node))

        positional = [*arguments.posonlyargs, *arguments.args]
        if len(call.args) > len(positional) and arguments.vararg is None:
            return False
        bound = {parameter.arg for parameter in positional[: len(call.args)]}
        normal_names = {parameter.arg for parameter in arguments.args}
        kwonly_names = {parameter.arg for parameter in arguments.kwonlyargs}
        posonly_names = {parameter.arg for parameter in arguments.posonlyargs}
        for keyword in call.keywords:
            name = keyword.arg
            if name in normal_names or name in kwonly_names:
                if name in bound:
                    return False
                bound.add(name)
            elif name not in posonly_names and arguments.kwarg is None:
                return False
            elif name in posonly_names and arguments.kwarg is None:
                return False

        required_positional = positional[: len(positional) - len(arguments.defaults)]
        if any(parameter.arg not in bound for parameter in required_positional):
            return False
        return all(
            default is not None or parameter.arg in bound
            for parameter, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True)
        )

    @staticmethod
    def _lambda_body_state(
        state: _ExpressionScanState,
        expression: ast.Lambda,
        call: ast.Call,
    ) -> _ExpressionScanState:
        bool_bindings = dict(state.bool_bindings)
        identities = dict(state.identities)
        parameters = [
            *expression.args.posonlyargs,
            *expression.args.args,
            expression.args.vararg,
            *expression.args.kwonlyargs,
            expression.args.kwarg,
        ]
        for parameter in parameters:
            if parameter is not None:
                bool_bindings.pop(parameter.arg, None)
                identities.pop(parameter.arg, None)
        positional = [*expression.args.posonlyargs, *expression.args.args]
        bound_names: set[str] = set()
        for parameter, argument in zip(positional, call.args, strict=False):
            bound_names.add(parameter.arg)
            exact_value = _exact_bool(argument, state.bool_bindings)
            exact_identity = _StraightLineShellScanner._resolve_identity(argument, state.identities)
            if exact_value is not None:
                bool_bindings[parameter.arg] = exact_value
            elif exact_identity is not None:
                identities[parameter.arg] = exact_identity
        keyword_parameters = {
            parameter.arg: parameter for parameter in [*expression.args.args, *expression.args.kwonlyargs]
        }
        for keyword in call.keywords:
            if keyword.arg is None or keyword.arg not in keyword_parameters:
                continue
            bound_names.add(keyword.arg)
            exact_value = _exact_bool(keyword.value, state.bool_bindings)
            exact_identity = _StraightLineShellScanner._resolve_identity(keyword.value, state.identities)
            if exact_value is not None:
                bool_bindings[keyword.arg] = exact_value
            elif exact_identity is not None:
                identities[keyword.arg] = exact_identity
        default_parameters = positional[len(positional) - len(expression.args.defaults) :]
        for parameter, positional_default in zip(default_parameters, expression.args.defaults, strict=True):
            if parameter.arg in bound_names:
                continue
            exact_value = _exact_bool(positional_default, state.bool_bindings)
            exact_identity = _StraightLineShellScanner._resolve_identity(positional_default, state.identities)
            if exact_value is not None:
                bool_bindings[parameter.arg] = exact_value
            elif exact_identity is not None:
                identities[parameter.arg] = exact_identity
        for parameter, keyword_default in zip(expression.args.kwonlyargs, expression.args.kw_defaults, strict=True):
            if parameter.arg in bound_names or keyword_default is None:
                continue
            exact_value = _exact_bool(keyword_default, state.bool_bindings)
            exact_identity = _StraightLineShellScanner._resolve_identity(keyword_default, state.identities)
            if exact_value is not None:
                bool_bindings[parameter.arg] = exact_value
            elif exact_identity is not None:
                identities[parameter.arg] = exact_identity
        return _ExpressionScanState(
            bool_bindings,
            identities,
            state.poisoned_modules,
            state.external_names,
            state.scope_depth + 1,
            state.evidence_anchor,
            state.equivalent_regex_spans,
            state.embedded_method_name,
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
            state.equivalent_regex_spans,
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
        function_identity: str | None,
        *,
        depth: int,
        evidence_anchor: ast.expr | None,
    ) -> bool:
        if evidence_anchor is None:
            if function_identity in _SUBPROCESS_CALL_IDENTITIES:
                self._scan_python_c_payload(call, function_identity, depth=depth)

        return function_identity in (_SUBPROCESS_CALL_IDENTITIES | {_OS_SYSTEM_IDENTITY}) and (
            self._call_arguments_are_side_effect_free(call, bool_bindings)
        )

    def _record_named_shell_flag(
        self,
        call: ast.Call,
        shell_binding: tuple[str, bool | None],
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

        variable_name, exact_value = shell_binding
        if exact_value is not True:
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
                variable_name=variable_name,
            )
        )

    def _record_os_system(
        self,
        anchor: ast.expr,
        *,
        embedded_method_name: str | None,
        equivalent_regex_spans: tuple[tuple[int, int, int], ...],
    ) -> None:
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
                equivalent_regex_spans=equivalent_regex_spans,
            )
        )

    def _record_dynamic_exec(self, function: ast.Name) -> None:
        span = self._source_span(function)
        if span is None:
            return
        line_number, start_column, end_column = span
        self._append_candidate(
            PythonDynamicExecCandidate(
                line_number=line_number,
                start_column=start_column,
                end_column=end_column,
                variable_name=function.id,
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
            if not self.budget.consume_tree(tree):
                return
            compile(payload, "<embedded-python-c>", "exec", dont_inherit=True)
        except (MemoryError, OverflowError, RecursionError, SyntaxError, TypeError, UnicodeError, ValueError):
            return
        method_name = function_identity.rsplit(".", 1)[-1]
        try:
            raw_payload = ast.get_source_segment(self.source, payload_expression)
        except (MemoryError, UnicodeError):
            raw_payload = None
        equivalent_regex_spans = self._raw_payload_regex_spans(payload_expression, raw_payload)
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
                scope_kind="module",
                evidence_anchor=call.func,
                equivalent_regex_spans=equivalent_regex_spans,
                embedded_method_name=method_name,
            )
        finally:
            self.allow_embedded_canonical = previous_allowance
            self.annotations_are_deferred = previous_annotations

    def _raw_payload_regex_spans(
        self,
        payload_expression: ast.expr,
        raw_payload: str | None,
    ) -> tuple[tuple[int, int, int], ...]:
        """Map legacy regex hits in a raw payload literal to outer-source spans."""

        if raw_payload is None:
            return ()
        start_line = getattr(payload_expression, "lineno", 0)
        byte_start = getattr(payload_expression, "col_offset", -1)
        if not (1 <= start_line <= len(self.lines) and byte_start >= 0):
            return ()
        start_column = self._byte_to_character_column(self.lines[start_line - 1], byte_start)
        if start_column is None:
            return ()
        spans: list[tuple[int, int, int]] = []
        raw_lines = raw_payload.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        for offset, raw_line in enumerate(raw_lines):
            base_column = start_column if offset == 0 else 0
            for match in _LEGACY_OS_SYSTEM_CALL_RE.finditer(raw_line):
                spans.append((start_line + offset, base_column + match.start(), base_column + match.end()))
                if len(spans) >= MAX_PYTHON_SHELL_CANDIDATES:
                    return tuple(spans)
        return tuple(spans)

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
        if isinstance(expression, ast.NamedExpr):
            return _StraightLineShellScanner._resolve_identity(expression.value, identities)
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
    def _call_arguments_are_side_effect_free(call: ast.Call, bool_bindings: dict[str, bool] | None = None) -> bool:
        bindings = bool_bindings or {}
        return all(
            _StraightLineShellScanner._is_inert_call_value(argument, bindings) for argument in call.args
        ) and all(
            keyword.arg is not None and _StraightLineShellScanner._is_inert_call_value(keyword.value, bindings)
            for keyword in call.keywords
        )

    @staticmethod
    def _is_inert_call_value(expression: ast.expr, bool_bindings: dict[str, bool]) -> bool:
        if isinstance(expression, ast.Constant):
            return True
        if isinstance(expression, ast.Name):
            return expression.id in bool_bindings
        if isinstance(expression, (ast.List, ast.Tuple)):
            return all(
                not isinstance(element, ast.Starred)
                and _StraightLineShellScanner._is_inert_call_value(element, bool_bindings)
                for element in expression.elts
            )
        return False

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
        start_column = self._byte_to_character_column(line, byte_start)
        end_column = self._byte_to_character_column(line, byte_end)
        if start_column is None or end_column is None:
            return None
        if end_column <= start_column:
            return None
        return line_number, start_column, end_column

    @staticmethod
    def _byte_to_character_column(line: str, byte_column: int) -> int | None:
        try:
            return len(line.encode("utf-8")[:byte_column].decode("utf-8"))
        except UnicodeError:
            return None

    def _append_candidate(self, candidate: PythonShellCandidate) -> None:
        key = (candidate.line_number, candidate.start_column, candidate.end_column, candidate.matched_pattern)
        if key in self.candidate_keys or len(self.candidates) >= MAX_PYTHON_SHELL_CANDIDATES:
            return
        self.candidates.append(candidate)
        self.candidate_keys.add(key)

    @classmethod
    def _enforce_binding_limit(
        cls,
        bindings: dict[str, bool],
        identities: dict[str, str],
        poisoned_modules: set[str],
    ) -> None:
        if len(bindings) + len(identities) > MAX_PYTHON_SHELL_BINDINGS:
            cls._poison_known_modules(identities, poisoned_modules)
            bindings.clear()
            identities.clear()
