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

"""Conservative recovery of constructed paths passed to Python ``open``.

The signature pack already owns literal sensitive paths. This module adds one
small positive-evidence case: an exact string built through straight-line
assignments, concatenation, or a reviewed ``os.path.join`` call reaches the
built-in ``open`` in a proven read-only mode. Effects and general compound flow
erase all path facts; a canonical ``os.path.exists(exact_path)`` guard may carry
unchanged facts into its body.
"""

from __future__ import annotations

import ast
import ntpath
import posixpath
import re
import sys
from dataclasses import dataclass, field

MAX_PYTHON_PATH_SOURCE_BYTES = 1024 * 1024
MAX_PYTHON_PATH_AST_NODES = 50_000
MAX_PYTHON_PATH_BINDINGS = 4_096
MAX_PYTHON_PATH_CANDIDATES = 256
MAX_PYTHON_PATH_SCOPE_DEPTH = 32
MAX_PYTHON_PATH_VALUE_DEPTH = 24
MAX_PYTHON_PATH_STRING_CHARS = 4_096
MAX_PYTHON_PATH_JOIN_PARTS = 32
MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES = 64
MAX_PYTHON_PATH_RUNTIME_PROVENANCE_WORK = 250_000

_MAX_C_INT = (1 << 31) - 1

_READ_ONLY_MODES = frozenset({"r", "rb", "br", "rt", "tr"})
_OPEN_KEYWORDS = frozenset({"buffering", "closefd", "encoding", "errors", "file", "mode", "newline", "opener"})
_ENV_FILE_RE = re.compile(r"^\.env(?:\.[A-Za-z0-9_-]+)?$")


@dataclass(frozen=True, slots=True)
class PythonSensitiveFileReadCandidate:
    """One exact sensitive path passed to a syntactic built-in ``open``."""

    path: str
    line_number: int
    start_column: int
    end_column: int


@dataclass(slots=True)
class _RuntimeProvenanceBudget:
    remaining: int
    possible_helpers: set[str]
    possible_os_modules: set[str]
    possible_os_paths: set[str]
    annotations_are_deferred: bool
    json_import_cache_trusted: bool = True
    patch_import_cache_trusted: bool = True
    exhausted: bool = False

    def visit(self) -> bool:
        if self.remaining <= 0:
            self.exhausted = True
            return False
        self.remaining -= 1
        return True

    def is_exhausted(self) -> bool:
        return self.exhausted


@dataclass(slots=True)
class _ExpressionReadState:
    bindings: dict[str, str]
    os_available: bool
    open_available: bool
    reviewed_json_modules: set[str] = field(default_factory=set)


_RUNTIME_BUDGET_ATTR = "_skill_scanner_runtime_budget"
_AST_SINGLETON_TYPES = (ast.boolop, ast.cmpop, ast.expr_context, ast.operator, ast.unaryop)
_AST_TYPE_ALIAS_TYPE = vars(ast).get("TypeAlias")
_AST_TYPE_ALIAS_TYPES: tuple[type[ast.AST], ...] = (
    (_AST_TYPE_ALIAS_TYPE,) if isinstance(_AST_TYPE_ALIAS_TYPE, type) else ()
)


def find_constructed_sensitive_file_reads(
    source: str,
    filename: str = "<unknown>",
) -> tuple[PythonSensitiveFileReadCandidate, ...]:
    """Find bounded, positively resolved sensitive-path reads in Python source."""

    if not source or "\x00" in source or len(source) > MAX_PYTHON_PATH_SOURCE_BYTES:
        return ()
    try:
        if len(source.encode("utf-8")) > MAX_PYTHON_PATH_SOURCE_BYTES:
            return ()
        tree = ast.parse(source, filename=filename)
    except (MemoryError, RecursionError, SyntaxError, UnicodeError, ValueError):
        return ()
    runtime_budget = _prepare_bounded_ast(tree)
    if runtime_budget is None or runtime_budget.is_exhausted():
        return ()
    try:
        # ``ast.parse`` accepts a few trees that fail Python's later compiler
        # validation (for example, repeated keyword arguments).  Such code can
        # never execute, so it cannot provide positive evidence of a read.
        # Compile the original source as the final CPython validity check while
        # leaving the bounded, tagged tree available to the scanner below.
        compile(source, filename, "exec", dont_inherit=True)
    except (MemoryError, OverflowError, RecursionError, SyntaxError, TypeError, ValueError):
        return ()

    scanner = _StraightLineSensitiveReadScanner(source, runtime_budget)
    scanner.scan(tree)
    if runtime_budget.is_exhausted():
        return ()
    return tuple(scanner.candidates)


def _prepare_bounded_ast(tree: ast.AST) -> _RuntimeProvenanceBudget | None:
    annotations_are_deferred = sys.version_info >= (3, 14) or (
        isinstance(tree, ast.Module)
        and any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(imported.name == "annotations" for imported in statement.names)
            for statement in tree.body
        )
    )
    budget = _RuntimeProvenanceBudget(
        MAX_PYTHON_PATH_RUNTIME_PROVENANCE_WORK,
        {"__builtins__"},
        set(),
        set(),
        annotations_are_deferred,
    )
    alias_edges: dict[str, list[str]] = {}
    os_path_alias_edges: list[tuple[str, str]] = []
    possible_json_modules: set[str] = set()
    edge_count = 0
    pending = [tree]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_PYTHON_PATH_AST_NODES:
            return None
        # CPython shares context/operator singleton instances across parses.
        # Their owning expressions are charged, so leave these leaf nodes
        # untagged rather than leaking one scan's budget into another.
        if not isinstance(node, _AST_SINGLETON_TYPES):
            setattr(node, _RUNTIME_BUDGET_ATTR, budget)
        if (
            isinstance(node, (ast.Import, ast.ImportFrom))
            and not _is_reviewed_static_import(node)
            and not (isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "__future__")
        ):
            # An arbitrary import can run module code that replaces the cached
            # stdlib patch factory before a delayed scope imports it.
            budget.patch_import_cache_trusted = False
        if isinstance(node, ast.Import):
            for imported in node.names:
                local_name = _bound_import_name(imported)
                if imported.name.split(".", 1)[0] in {"importlib", "sys"}:
                    budget.json_import_cache_trusted = False
                if imported.name == "builtins":
                    budget.possible_helpers.add(local_name)
                elif imported.name == "os":
                    budget.possible_os_modules.add(local_name)
                elif imported.name == "json":
                    possible_json_modules.add(local_name)
                elif imported.name == "os.path":
                    if imported.asname is None:
                        budget.possible_os_modules.add("os")
                    else:
                        budget.possible_os_paths.add(local_name)
                elif imported.name in {"ntpath", "posixpath"}:
                    budget.possible_os_paths.add(local_name)
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".", 1)[0] in {"importlib", "sys"}:
                budget.json_import_cache_trusted = False
            if node.module == "os":
                budget.possible_os_paths.update(
                    imported.asname or imported.name for imported in node.names if imported.name == "path"
                )
        elif (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Name)
            and all(isinstance(target, ast.Name) for target in node.targets)
        ):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            alias_edges.setdefault(node.value.id, []).extend(targets)
            edge_count += len(targets)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Name):
            alias_edges.setdefault(node.value.id, []).append(node.target.id)
            edge_count += 1
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Name):
            alias_edges.setdefault(node.value.id, []).append(node.target.id)
            edge_count += 1
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Lambda):
            function = node.func
            positional = [*function.args.posonlyargs, *function.args.args]
            for parameter, argument in zip(positional, node.args, strict=False):
                if isinstance(argument, ast.Name):
                    alias_edges.setdefault(argument.id, []).append(parameter.arg)
                    edge_count += 1
            parameter_by_name = {parameter.arg: parameter for parameter in (*positional, *function.args.kwonlyargs)}
            for keyword in node.keywords:
                if keyword.arg in parameter_by_name and isinstance(keyword.value, ast.Name):
                    alias_edges.setdefault(keyword.value.id, []).append(keyword.arg)
                    edge_count += 1
            if function.args.defaults:
                defaulted = positional[-len(function.args.defaults) :]
                for parameter, default in zip(defaulted, function.args.defaults, strict=True):
                    if isinstance(default, ast.Name):
                        alias_edges.setdefault(default.id, []).append(parameter.arg)
                        edge_count += 1
            for parameter, keyword_default in zip(
                function.args.kwonlyargs,
                function.args.kw_defaults,
                strict=True,
            ):
                if isinstance(keyword_default, ast.Name):
                    alias_edges.setdefault(keyword_default.id, []).append(parameter.arg)
                    edge_count += 1
        elif (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "path"
            and isinstance(node.value.value, ast.Name)
        ):
            targets = (
                [target.id for target in node.targets if isinstance(target, ast.Name)]
                if isinstance(node, ast.Assign)
                else ([node.target.id] if isinstance(node.target, ast.Name) else [])
            )
            os_path_alias_edges.extend((node.value.value.id, target) for target in targets)
            edge_count += len(targets)
        if (
            edge_count > MAX_PYTHON_PATH_BINDINGS
            or len(budget.possible_helpers) > MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES
            or len(budget.possible_os_modules) > MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES
            or len(budget.possible_os_paths) > MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES
        ):
            budget.exhausted = True
            return budget
        pending.extend(ast.iter_child_nodes(node))

    pending_names = list(budget.possible_helpers)
    for source_name in pending_names:
        if not budget.visit():
            return budget
        for target_name in alias_edges.get(source_name, ()):
            if target_name in budget.possible_helpers:
                continue
            if len(budget.possible_helpers) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
                budget.exhausted = True
                return budget
            budget.possible_helpers.add(target_name)
            pending_names.append(target_name)

    pending_modules = list(budget.possible_os_modules)
    for source_name in pending_modules:
        if not budget.visit():
            return budget
        for target_name in alias_edges.get(source_name, ()):
            if target_name in budget.possible_os_modules:
                continue
            if len(budget.possible_os_modules) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
                budget.exhausted = True
                return budget
            budget.possible_os_modules.add(target_name)
            pending_modules.append(target_name)

    pending_json_modules = list(possible_json_modules)
    for source_name in pending_json_modules:
        if not budget.visit():
            return budget
        for target_name in alias_edges.get(source_name, ()):
            if target_name in possible_json_modules:
                continue
            if len(possible_json_modules) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
                budget.exhausted = True
                return budget
            possible_json_modules.add(target_name)
            pending_json_modules.append(target_name)

    for source_name, target_name in os_path_alias_edges:
        if not budget.visit():
            return budget
        if source_name not in budget.possible_os_modules or target_name in budget.possible_os_paths:
            continue
        if len(budget.possible_os_paths) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
            budget.exhausted = True
            return budget
        budget.possible_os_paths.add(target_name)

    if not _tree_preserves_json_import_cache(tree, possible_json_modules):
        budget.json_import_cache_trusted = False

    pending_paths = list(budget.possible_os_paths)
    for source_name in pending_paths:
        if not budget.visit():
            return budget
        for target_name in alias_edges.get(source_name, ()):
            if target_name in budget.possible_os_paths:
                continue
            if len(budget.possible_os_paths) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
                budget.exhausted = True
                return budget
            budget.possible_os_paths.add(target_name)
            pending_paths.append(target_name)
    return budget


def _visit_runtime_node(node: ast.AST) -> bool:
    budget = getattr(node, _RUNTIME_BUDGET_ATTR, None)
    return not isinstance(budget, _RuntimeProvenanceBudget) or budget.visit()


def _tree_preserves_json_import_cache(root: ast.AST, module_names: set[str]) -> bool:
    """Allow a JSON module identity only as the direct receiver of ``load``."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return False
        if isinstance(node, ast.Attribute) and node.attr == "modules":
            return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                return False
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "load"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in module_names
            ):
                pending.extend(node.args)
                pending.extend(keyword.value for keyword in node.keywords)
                continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in module_names:
            return False
        pending.extend(ast.iter_child_nodes(node))
    return True


def _possible_runtime_helpers(node: ast.AST, *, include_globals: bool = False) -> set[str]:
    budget = getattr(node, _RUNTIME_BUDGET_ATTR, None)
    names = set(budget.possible_helpers) if isinstance(budget, _RuntimeProvenanceBudget) else {"__builtins__"}
    return names | ({"globals"} if include_globals else set())


def _is_possible_os_module(node: ast.AST, module_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in module_names


def _is_possible_os_path(
    node: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Name)
        and node.id in path_names
        or (
            isinstance(node, ast.Attribute) and node.attr == "path" and _is_possible_os_module(node.value, module_names)
        )
    )


def _target_may_replace_os_path_join(
    target: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    """Recognize stores that can replace the shared ``os.path.join``."""

    if isinstance(target, ast.Attribute):
        if target.attr == "join" and _is_possible_os_path(target.value, module_names, path_names):
            return True
        if target.attr == "path" and _is_possible_os_module(target.value, module_names):
            return True
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
        receiver = target.value
        key = target.slice.value
        if (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id == "vars"
            and len(receiver.args) == 1
            and not receiver.keywords
        ):
            receiver = receiver.args[0]
        if isinstance(receiver, ast.Attribute) and receiver.attr == "__dict__":
            receiver = receiver.value
        if key == "join" and _is_possible_os_path(receiver, module_names, path_names):
            return True
        if key == "path" and _is_possible_os_module(receiver, module_names):
            return True
    if isinstance(target, (ast.List, ast.Tuple)):
        return any(_target_may_replace_os_path_join(item, module_names, path_names) for item in target.elts)
    if isinstance(target, ast.Starred):
        return _target_may_replace_os_path_join(target.value, module_names, path_names)
    return False


def _augassign_target_evaluation_invalidates_os_path_join(
    target: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    """Inspect only target-address effects that run before an AugAssign RHS."""

    if isinstance(target, ast.Name):
        return False
    expressions: list[ast.AST]
    if _target_may_replace_os_path_join(target, module_names, path_names):
        expressions = [target.slice] if isinstance(target, ast.Subscript) else []
    elif isinstance(target, ast.Attribute):
        expressions = [target.value]
    elif isinstance(target, ast.Subscript):
        expressions = [target.value, target.slice]
    else:
        expressions = [target]
    return any(
        _node_may_replace_os_path_join(expression, module_names, path_names)
        or _node_escapes_os_path_identity(expression, module_names, path_names)
        for expression in expressions
    )


def _attribute_name_may_match(node: ast.AST, name: str) -> bool:
    return not isinstance(node, ast.Constant) or not isinstance(node.value, str) or node.value == name


def _os_runtime_mapping_target(
    node: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> str | None:
    receiver: ast.AST | None = None
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        receiver = node.value
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
        and not node.keywords
    ):
        receiver = node.args[0]
    if receiver is None:
        return None
    if _is_possible_os_path(receiver, module_names, path_names):
        return "join"
    if _is_possible_os_module(receiver, module_names):
        return "path"
    return None


def _node_may_replace_os_path_join(
    root: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    """Conservatively find explicit mutation of the cached ``os.path`` module."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
            _decorator_application_may_replace_os_path_join(node, module_names, path_names)
        ):
            return True
        if isinstance(node, ast.ImportFrom) and (
            node.module in {"ntpath", "os.path", "posixpath"}
            or (node.module == "os" and any(imported.name in {"*", "__dict__"} for imported in node.names))
        ):
            return True
        if isinstance(node, ast.Call) and _nested_lambdas_may_replace_os_path_join(
            node.func,
            module_names,
            path_names,
        ):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.Assign) and any(
            _target_may_replace_os_path_join(target, module_names, path_names) for target in node.targets
        ):
            return True
        if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and _target_may_replace_os_path_join(
            node.target,
            module_names,
            path_names,
        ):
            return True
        if isinstance(node, ast.Delete) and any(
            _target_may_replace_os_path_join(target, module_names, path_names) for target in node.targets
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"delattr", "setattr"}
            and len(node.args) >= 2
        ):
            receiver = node.args[0]
            attribute = node.args[1]
            if _is_possible_os_path(receiver, module_names, path_names) and _attribute_name_may_match(
                attribute,
                "join",
            ):
                return True
            if _is_possible_os_module(receiver, module_names) and _attribute_name_may_match(attribute, "path"):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            mapping_target = _os_runtime_mapping_target(node.func.value, module_names, path_names)
            if mapping_target is not None:
                if node.func.attr in {"clear", "popitem", "update"}:
                    return True
                if node.func.attr in {"__delitem__", "__setitem__", "pop", "setdefault"} and (
                    not node.args or _attribute_name_may_match(node.args[0], mapping_target)
                ):
                    return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _nested_lambdas_may_replace_os_path_join(
    root: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    """Inspect directly expressed lambdas that can run as decorators."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Lambda):
            local_names = {
                argument.arg
                for argument in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                    *([node.args.vararg] if node.args.vararg is not None else []),
                    *([node.args.kwarg] if node.args.kwarg is not None else []),
                )
            }
            lambda_modules = module_names - local_names
            lambda_paths = path_names - local_names
            positional = [*node.args.posonlyargs, *node.args.args]
            defaulted_positional = positional[len(positional) - len(node.args.defaults) :]
            for argument, positional_default in zip(defaulted_positional, node.args.defaults, strict=True):
                default_kind = _os_identity_kind(positional_default, module_names, path_names)
                if default_kind == "module":
                    lambda_modules.add(argument.arg)
                elif default_kind == "path":
                    lambda_paths.add(argument.arg)
            for argument, keyword_default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
                if keyword_default is None:
                    continue
                default_kind = _os_identity_kind(keyword_default, module_names, path_names)
                if default_kind == "module":
                    lambda_modules.add(argument.arg)
                elif default_kind == "path":
                    lambda_paths.add(argument.arg)
            if _node_may_replace_os_path_join(
                node.body,
                lambda_modules,
                lambda_paths,
            ) or _node_escapes_os_path_identity(node.body, lambda_modules, lambda_paths):
                return True
            pending.extend(_definition_eager_nodes(node))
            pending.append(node.body)
            continue
        pending.extend(ast.iter_child_nodes(node))
    return False


def _decorator_application_may_replace_os_path_join(
    statement: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    return any(
        _nested_lambdas_may_replace_os_path_join(decorator, module_names, path_names)
        for decorator in statement.decorator_list
    )


def _node_escapes_os_path_identity(
    root: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    """Return whether eager evaluation exposes a tracked cached-module identity."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Assign):
            targets = _name_targets(node.targets)
            if targets is not None and _os_identity_kind(node.value, module_names, path_names) is not None:
                continue
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
            and _os_identity_kind(node.value, module_names, path_names) is not None
        ):
            pending.append(node.annotation)
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            continue
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"exists", "join"}
            and _is_possible_os_path(node.func.value, module_names, path_names)
        ):
            pending.extend(node.args)
            pending.extend(keyword.value for keyword in node.keywords)
            continue
        if _is_possible_os_module(node, module_names) or _is_possible_os_path(
            node,
            module_names,
            path_names,
        ):
            return True
        if isinstance(node, ast.Attribute) and (
            _is_possible_os_module(node.value, module_names)
            or _is_possible_os_path(node.value, module_names, path_names)
        ):
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _os_identity_kind(
    node: ast.AST,
    module_names: set[str],
    path_names: set[str],
) -> str | None:
    if _is_possible_os_module(node, module_names):
        return "module"
    if _is_possible_os_path(node, module_names, path_names):
        return "path"
    return None


def _class_body_may_export_os_identity(
    statement: ast.stmt,
    module_names: set[str],
    path_names: set[str],
) -> bool:
    """Return whether a class can publish a tracked identity as an attribute."""

    identity_names = module_names | path_names
    pending: list[ast.AST] = [statement]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.ClassDef):
            if any(_node_binds_name(body_statement, name) for name in identity_names for body_statement in node.body):
                return True
            pending.extend(node.body)
            continue
        pending.extend(ast.iter_child_nodes(node))
    return False


def _advance_os_aliases(
    statement: ast.stmt,
    module_names: set[str],
    path_names: set[str],
) -> tuple[set[str], set[str]]:
    """Advance exact local ``os``/``os.path`` identities in source order."""

    next_modules = set(module_names)
    next_paths = set(path_names)
    assigned_names: tuple[str, ...] = ()
    assigned_kind: str | None = None

    if isinstance(statement, (ast.Global, ast.Nonlocal)):
        return next_modules, next_paths

    if isinstance(statement, ast.Import):
        for imported in statement.names:
            local_name = _bound_import_name(imported)
            next_modules.discard(local_name)
            next_paths.discard(local_name)
            if imported.name == "os":
                next_modules.add(local_name)
            elif imported.name == "os.path":
                if imported.asname is None:
                    next_modules.add("os")
                else:
                    next_paths.add(local_name)
            elif imported.name in {"ntpath", "posixpath"}:
                next_paths.add(local_name)
        return next_modules, next_paths

    if isinstance(statement, ast.ImportFrom):
        if any(imported.name == "*" for imported in statement.names):
            return set(), set()
        for imported in statement.names:
            local_name = imported.asname or imported.name
            next_modules.discard(local_name)
            next_paths.discard(local_name)
            if statement.module == "os" and imported.name == "path":
                next_paths.add(local_name)
        return next_modules, next_paths

    if isinstance(statement, ast.Assign):
        assigned_names = _name_targets(statement.targets) or ()
        assigned_kind = _os_identity_kind(statement.value, module_names, path_names)
    elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        assigned_names = (statement.target.id,)
        assigned_kind = (
            _os_identity_kind(statement.value, module_names, path_names) if statement.value is not None else None
        )

    for name in tuple(next_modules):
        if _node_binds_name(statement, name):
            next_modules.discard(name)
    for name in tuple(next_paths):
        if _node_binds_name(statement, name):
            next_paths.discard(name)
    if assigned_kind == "module":
        next_modules.update(assigned_names)
    elif assigned_kind == "path":
        next_paths.update(assigned_names)
    return next_modules, next_paths


def _bounded_string(value: str) -> str | None:
    return value if len(value) <= MAX_PYTHON_PATH_STRING_CHARS else None


def _normalize_path(value: str) -> str:
    """Normalize separators, treating repeated root slashes conservatively."""

    normalized = posixpath.normpath(value.replace("\\", "/"))
    if normalized.startswith("//"):
        normalized = f"/{normalized.lstrip('/')}"
    return normalized


def _is_sensitive_path(value: str) -> bool:
    if "\x00" in value:
        return False
    path = _normalize_path(value)
    if path.startswith("/etc/") and len(path) > len("/etc/"):
        return True

    parts = tuple(part for part in path.split("/") if part not in {"", "."})
    if len(parts) >= 2 and parts[-2:] == (".aws", "credentials"):
        return True
    if (
        len(parts) >= 2
        and parts[-2] == ".ssh"
        and parts[-1]
        in {
            "authorized_keys",
            "id_dsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_ed25519",
            "id_ed25519_sk",
            "id_rsa",
        }
    ):
        return True
    if any(part in {".gnupg", ".netrc", ".pgpass"} for part in parts):
        return True
    return bool(parts and _ENV_FILE_RE.fullmatch(parts[-1]))


def _bound_import_name(alias: ast.alias) -> str:
    return alias.asname or alias.name.split(".", 1)[0]


def _definition_eager_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda,
) -> tuple[ast.AST, ...]:
    """Return expressions that may be evaluated when a definition is created."""

    eager: list[ast.AST] = []
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        eager.extend(node.decorator_list)
        eager.extend(node.args.defaults)
        eager.extend(default for default in node.args.kw_defaults if default is not None)
        budget = getattr(node, _RUNTIME_BUDGET_ATTR, None)
        if not isinstance(budget, _RuntimeProvenanceBudget) or not budget.annotations_are_deferred:
            for argument in (*node.args.args, *node.args.posonlyargs):
                if argument.annotation is not None:
                    eager.append(argument.annotation)
            if node.args.vararg is not None and node.args.vararg.annotation is not None:
                eager.append(node.args.vararg.annotation)
            for argument in node.args.kwonlyargs:
                if argument.annotation is not None:
                    eager.append(argument.annotation)
            if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
                eager.append(node.args.kwarg.annotation)
            if node.returns is not None:
                eager.append(node.returns)
    elif isinstance(node, ast.ClassDef):
        eager.extend(node.decorator_list)
        eager.extend(node.bases)
        eager.extend(keyword.value for keyword in node.keywords)
    else:
        eager.extend(node.args.defaults)
        eager.extend(default for default in node.args.kw_defaults if default is not None)
    return tuple(eager)


def _node_binds_name(root: ast.AST, name: str) -> bool:
    """Find a conservative binding without recursively entering delayed scopes."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.Lambda):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            # Comprehension targets are isolated on supported Python versions.
            # Their iterable/filter/value expressions can still contain a
            # named expression that binds in the enclosing scope, so traverse
            # every eager expression but never the generator targets.
            if isinstance(node, ast.DictComp):
                pending.extend((node.key, node.value))
            else:
                pending.append(node.elt)
            for generator in node.generators:
                pending.append(generator.iter)
                pending.extend(generator.ifs)
            continue
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
            return True
        if isinstance(node, ast.Import) and any(_bound_import_name(alias) == name for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" or (alias.asname or alias.name) == name for alias in node.names
        ):
            return True
        if isinstance(node, ast.ExceptHandler) and node.name == name:
            return True
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return True
        if isinstance(node, ast.MatchAs) and node.name == name:
            return True
        if isinstance(node, ast.MatchStar) and node.name == name:
            return True
        if isinstance(node, ast.MatchMapping) and node.rest == name:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _node_loads_any_name(root: ast.AST, names: set[str]) -> bool:
    """Find a load that is known to fail after a straight-line deletion."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _definitely_bound_names_after(statement: ast.stmt) -> set[str]:
    """Return simple names bound whenever a straight-line statement completes."""

    if isinstance(statement, ast.Import):
        return {_bound_import_name(imported) for imported in statement.names}
    if isinstance(statement, ast.ImportFrom):
        return {imported.asname or imported.name for imported in statement.names if imported.name != "*"}
    if isinstance(statement, ast.Assign):
        return set(_name_targets(statement.targets) or ())
    if isinstance(statement, ast.AnnAssign):
        return (
            {statement.target.id} if statement.value is not None and isinstance(statement.target, ast.Name) else set()
        )
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    return set()


def _target_may_replace_runtime_open(
    target: ast.AST,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> bool:
    if not _visit_runtime_node(target):
        return True
    if (
        isinstance(target, ast.Attribute)
        and target.attr == "open"
        and isinstance(target.value, ast.Name)
        and target.value.id in builtins_names
    ):
        return True
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and target.slice.value == "open":
        receiver = target.value
        if isinstance(receiver, ast.Name) and receiver.id in builtins_names:
            return True
        if (
            isinstance(receiver, ast.Attribute)
            and receiver.attr == "__dict__"
            and isinstance(receiver.value, ast.Name)
            and receiver.value.id in builtins_names
        ):
            return True
        if (
            globals_is_builtin
            and isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id == "globals"
            and not receiver.args
            and not receiver.keywords
        ):
            return True
        if (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id in {"locals", "vars"}
            and not receiver.args
            and not receiver.keywords
        ):
            return True
        if (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id == "vars"
            and len(receiver.args) == 1
            and not receiver.keywords
            and isinstance(receiver.args[0], ast.Name)
            and receiver.args[0].id in builtins_names
        ):
            return True
    if isinstance(target, (ast.List, ast.Tuple)):
        return any(
            _target_may_replace_runtime_open(element, builtins_names, globals_is_builtin) for element in target.elts
        )
    if isinstance(target, ast.Starred):
        return _target_may_replace_runtime_open(target.value, builtins_names, globals_is_builtin)
    return False


def _augassign_target_evaluation_invalidates_runtime_open(
    target: ast.AST,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> bool:
    """Inspect only the address computation that precedes an AugAssign RHS."""

    if isinstance(target, ast.Name):
        return False
    # The reviewed runtime-open receivers themselves are inert; their final
    # store happens after the RHS. A subscript index still runs first.
    expressions: list[ast.AST]
    if _target_may_replace_runtime_open(target, builtins_names, globals_is_builtin):
        expressions = [target.slice] if isinstance(target, ast.Subscript) else []
    elif isinstance(target, ast.Attribute):
        expressions = [target.value]
    elif isinstance(target, ast.Subscript):
        expressions = [target.value, target.slice]
    else:
        expressions = [target]
    return any(
        _node_may_replace_runtime_open(expression, builtins_names, globals_is_builtin)
        or _node_escapes_runtime_identity(expression, builtins_names, globals_is_builtin)
        for expression in expressions
    )


def _node_may_replace_runtime_open(
    root: ast.AST,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> bool:
    """Recognize explicit global/builtin ``open`` replacement syntax."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # Definitions do not execute their bodies at the definition site.
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)) and not _is_reviewed_static_import(node):
            # Arbitrary imported module code can replace the process-wide
            # built-in even without a local helper reference.
            return True
        if isinstance(node, ast.Assign) and any(
            _target_may_replace_runtime_open(target, builtins_names, globals_is_builtin) for target in node.targets
        ):
            return True
        if isinstance(
            node,
            (ast.AnnAssign, ast.AugAssign, ast.NamedExpr),
        ) and _target_may_replace_runtime_open(node.target, builtins_names, globals_is_builtin):
            return True
        if isinstance(node, ast.Delete) and any(
            _target_may_replace_runtime_open(target, builtins_names, globals_is_builtin) for target in node.targets
        ):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            # Dynamic Python can replace the process-wide built-in without a
            # syntactic helper reference. Later supplemental path proofs are
            # therefore no longer authoritative.
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"delattr", "setattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in builtins_names
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "open"
        ):
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _assigned_runtime_helper_names(statement: ast.stmt, builtins_names: set[str]) -> tuple[str, ...]:
    """Return simple names directly assigned a reviewed builtins identity."""

    if isinstance(statement, ast.Assign):
        if not isinstance(statement.value, ast.Name) or statement.value.id not in builtins_names:
            return ()
        if not all(isinstance(target, ast.Name) for target in statement.targets):
            return ()
        return tuple(target.id for target in statement.targets if isinstance(target, ast.Name))
    if (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and isinstance(statement.value, ast.Name)
        and statement.value.id in builtins_names
    ):
        return (statement.target.id,)
    return ()


def _lambda_runtime_helpers(node: ast.Lambda, builtins_names: set[str]) -> set[str]:
    """Discard helper names local to an immediately invoked lambda."""

    local_names = {
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            *([node.args.vararg] if node.args.vararg is not None else []),
            *([node.args.kwarg] if node.args.kwarg is not None else []),
        )
    }
    local_names.update(_lambda_body_local_names(node.body))
    return builtins_names - local_names


def _lambda_body_local_names(root: ast.AST) -> set[str]:
    """Collect assignment-expression locals without leaking comprehension targets."""

    names: set[str] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Lambda):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            pending.append(node.elt)
            for generator in node.generators:
                pending.append(generator.iter)
                pending.extend(generator.ifs)
            continue
        if isinstance(node, ast.DictComp):
            pending.extend((node.key, node.value))
            for generator in node.generators:
                pending.append(generator.iter)
                pending.extend(generator.ifs)
            continue
        pending.extend(ast.iter_child_nodes(node))
    return names


def _nested_lambdas_load_runtime_helper(root: ast.AST, builtins_names: set[str]) -> bool:
    """Inspect lambdas selected through an eager callable/decorator expression."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Lambda):
            lambda_names = _lambda_runtime_helpers(node, builtins_names)
            if _node_loads_runtime_helper(node.body, lambda_names):
                return True
            pending.extend(_definition_eager_nodes(node))
            pending.append(node.body)
            continue
        pending.extend(ast.iter_child_nodes(node))
    return False


def _is_direct_builtins_import_call(node: ast.AST) -> bool:
    """Recognize the exact built-in module lookup supported by this pass."""

    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "builtins"
    )


def _node_loads_runtime_helper(root: ast.AST, builtins_names: set[str]) -> bool:
    """Return whether eager evaluation loads a reviewed builtins identity."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Call):
            if _is_direct_builtins_import_call(node):
                return True
            if _nested_lambdas_load_runtime_helper(node.func, builtins_names):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in builtins_names:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _node_escapes_runtime_identity(
    root: ast.AST,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> bool:
    identity_names = builtins_names | {"locals", "vars"}
    if globals_is_builtin:
        identity_names.add("globals")
    return _node_loads_runtime_helper(root, identity_names)


def _decorator_application_escapes_runtime_helper(
    statement: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> bool:
    """Recognize effects of a directly expressed lambda decorator."""

    identity_names = builtins_names | ({"globals"} if globals_is_builtin else set())
    return any(_nested_lambdas_load_runtime_helper(decorator, identity_names) for decorator in statement.decorator_list)


def _advance_runtime_helper_identities(
    statement: ast.stmt,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> tuple[bool, bool]:
    """Update runtime-helper identities and report whether tracking stayed bounded."""

    if isinstance(statement, (ast.Global, ast.Nonlocal)):
        # Declarations change name resolution; they do not bind or replace the
        # referenced object at runtime. Keep the incoming provenance so a
        # following mutation through that external name remains visible.
        return globals_is_builtin, True
    if isinstance(statement, ast.Import):
        for imported in statement.names:
            local_name = _bound_import_name(imported)
            builtins_names.discard(local_name)
            if imported.name == "builtins":
                if len(builtins_names) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
                    builtins_names.clear()
                    return False, False
                builtins_names.add(local_name)
            if local_name == "globals":
                globals_is_builtin = False
        return globals_is_builtin, True
    if isinstance(statement, ast.ImportFrom):
        if statement.module == "builtins" and any(
            imported.name in {"__dict__", "globals", "locals", "vars"} for imported in statement.names
        ):
            builtins_names.clear()
            return False, False
        if any(imported.name == "*" for imported in statement.names):
            builtins_names.clear()
            return False, True
        for imported in statement.names:
            local_name = imported.asname or imported.name
            builtins_names.discard(local_name)
            if local_name == "globals":
                globals_is_builtin = False
        return globals_is_builtin, True

    if isinstance(statement, ast.Delete) and (
        _node_binds_name(statement, "globals") or any(_node_binds_name(statement, name) for name in builtins_names)
    ):
        builtins_names.clear()
        return False, False
    assigned_runtime_helpers = _assigned_runtime_helper_names(statement, builtins_names)
    if assigned_runtime_helpers:
        unsupported_load = isinstance(statement, ast.AnnAssign) and _node_escapes_runtime_identity(
            statement.annotation,
            builtins_names,
            globals_is_builtin,
        )
    else:
        unsupported_load = _node_escapes_runtime_identity(statement, builtins_names, globals_is_builtin)
    if unsupported_load:
        builtins_names.clear()
        return False, False
    for builtins_name in tuple(builtins_names):
        if _node_binds_name(statement, builtins_name):
            builtins_names.discard(builtins_name)
    if globals_is_builtin and _node_binds_name(statement, "globals"):
        globals_is_builtin = False
    for assigned_name in assigned_runtime_helpers:
        if assigned_name in builtins_names:
            continue
        if len(builtins_names) >= MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
            builtins_names.clear()
            return False, False
        builtins_names.add(assigned_name)
    return globals_is_builtin, True


def _scope_binds_open(body: list[ast.stmt]) -> bool:
    """Return whether eager code binds ``open`` in the current namespace."""

    return any(_node_binds_name(statement, "open") for statement in body)


def _class_body_has_runtime_provenance_hazard(body: list[ast.stmt]) -> bool:
    """Fail closed when class-namespace flow can escape or hide identities."""

    if not body:
        return False
    identity_names = _possible_runtime_helpers(body[0], include_globals=True)
    if any(
        not isinstance(statement, (ast.Global, ast.Nonlocal))
        and any(_node_binds_name(statement, name) for name in identity_names)
        for statement in body
    ):
        return True
    pending: list[ast.AST] = list(body)
    declares_external_open = False
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            if identity_names.intersection(node.names):
                return True
            if "open" in node.names:
                declares_external_open = True
        pending.extend(ast.iter_child_nodes(node))
    return declares_external_open and any(
        not isinstance(statement, (ast.Global, ast.Nonlocal)) and _node_binds_name(statement, "open")
        for statement in body
    )


def _class_body_may_mutate_decorator_lexical_state(
    body: list[ast.stmt],
    tracked_names: set[str],
) -> bool:
    """Fail closed when a class body can change a decorator's outer facts."""

    pending: list[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.ClassDef):
            # A nested class body executes before the outer class decorator is
            # applied, so its external writes can change captured path facts.
            pending.extend(_definition_eager_nodes(node))
            pending.extend(node.body)
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)) and tracked_names.intersection(node.names):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "globals"
            and not node.args
            and not node.keywords
        ):
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _class_body_may_rebind_external_names(
    body: list[ast.stmt],
    tracked_names: set[str],
) -> bool:
    """Return whether eager class code writes a tracked global/nonlocal name."""

    external_names: set[str] = set()
    written_names: set[str] = set()
    nested_classes: list[ast.ClassDef] = []
    has_wildcard_import = False
    pending: list[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            external_names.update(tracked_names.intersection(node.names))
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in tracked_names:
                written_names.add(node.name)
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.Lambda):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.ClassDef):
            if node.name in tracked_names:
                written_names.add(node.name)
            pending.extend(_definition_eager_nodes(node))
            nested_classes.append(node)
            continue
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            if isinstance(node, ast.DictComp):
                pending.extend((node.key, node.value))
            else:
                pending.append(node.elt)
            for generator in node.generators:
                pending.append(generator.iter)
                pending.extend(generator.ifs)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in tracked_names:
                written_names.add(node.id)
        elif isinstance(node, ast.Import):
            written_names.update(
                local_name for imported in node.names if (local_name := _bound_import_name(imported)) in tracked_names
            )
        elif isinstance(node, ast.ImportFrom):
            if any(imported.name == "*" for imported in node.names):
                has_wildcard_import = True
            else:
                written_names.update(
                    local_name
                    for imported in node.names
                    if (local_name := imported.asname or imported.name) in tracked_names
                )
        elif isinstance(node, ast.ExceptHandler) and node.name in tracked_names:
            written_names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in tracked_names:
            written_names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest in tracked_names:
            written_names.add(node.rest)
        pending.extend(ast.iter_child_nodes(node))

    if external_names.intersection(written_names) or (external_names and has_wildcard_import):
        return True
    return any(_class_body_may_rebind_external_names(node.body, tracked_names) for node in nested_classes)


def _class_body_is_trivially_inert(body: list[ast.stmt]) -> bool:
    """Accept only class bodies that cannot run hooks before decoration."""

    return all(
        isinstance(statement, ast.Pass) or isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
        for statement in body
    )


def _scope_may_shadow_open(body: list[ast.stmt]) -> bool:
    """Return whether a scope can stop resolving the runtime builtin ``open``."""

    return _scope_binds_open(body) or _scope_may_replace_runtime_open(body)


def _invalidate_runtime_helper_bindings(
    nodes: tuple[ast.AST, ...],
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> bool:
    """Discard helper identities rebound by eagerly evaluated nodes."""

    for builtins_name in tuple(builtins_names):
        if any(_node_binds_name(node, builtins_name) for node in nodes):
            builtins_names.discard(builtins_name)
    if globals_is_builtin and any(_node_binds_name(node, "globals") for node in nodes):
        return False
    return globals_is_builtin


def _class_namespace_is_unreviewed(statement: ast.ClassDef) -> bool:
    return bool(statement.bases or statement.keywords)


def _runtime_open_state_before_child(
    statement: ast.stmt,
    builtins_names: set[str],
    globals_is_builtin: bool,
) -> tuple[bool, bool, set[str], bool]:
    """Resolve runtime-helper effects evaluated before an eager child body."""

    child_names = set(builtins_names)
    child_globals_is_builtin = globals_is_builtin
    runtime_open_unavailable = False
    namespace_open_bound = False
    if isinstance(statement, ast.ClassDef):
        eager_nodes = _definition_eager_nodes(statement)
        runtime_open_unavailable = (
            _class_namespace_is_unreviewed(statement)
            or any(_node_may_replace_runtime_open(node, child_names, child_globals_is_builtin) for node in eager_nodes)
            or any(_node_escapes_runtime_identity(node, child_names, child_globals_is_builtin) for node in eager_nodes)
        )
        namespace_open_bound = any(_node_binds_name(node, "open") for node in eager_nodes)
        child_globals_is_builtin = _invalidate_runtime_helper_bindings(
            eager_nodes,
            child_names,
            child_globals_is_builtin,
        )
    elif isinstance(statement, ast.If):
        runtime_open_unavailable = _node_may_replace_runtime_open(
            statement.test,
            child_names,
            child_globals_is_builtin,
        ) or _node_escapes_runtime_identity(statement.test, child_names, child_globals_is_builtin)
        namespace_open_bound = _node_binds_name(statement.test, "open")
        child_globals_is_builtin = _invalidate_runtime_helper_bindings(
            (statement.test,),
            child_names,
            child_globals_is_builtin,
        )
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            runtime_open_unavailable = (
                runtime_open_unavailable
                or _node_may_replace_runtime_open(
                    item.context_expr,
                    child_names,
                    child_globals_is_builtin,
                )
                or _node_escapes_runtime_identity(
                    item.context_expr,
                    child_names,
                    child_globals_is_builtin,
                )
            )
            namespace_open_bound = namespace_open_bound or _node_binds_name(item.context_expr, "open")
            child_globals_is_builtin = _invalidate_runtime_helper_bindings(
                (item.context_expr,),
                child_names,
                child_globals_is_builtin,
            )
            if item.optional_vars is None:
                continue
            runtime_open_unavailable = (
                runtime_open_unavailable
                or _target_may_replace_runtime_open(
                    item.optional_vars,
                    child_names,
                    child_globals_is_builtin,
                )
                or _node_escapes_runtime_identity(
                    item.optional_vars,
                    child_names,
                    child_globals_is_builtin,
                )
            )
            namespace_open_bound = namespace_open_bound or _node_binds_name(item.optional_vars, "open")
            child_globals_is_builtin = _invalidate_runtime_helper_bindings(
                (item.optional_vars,),
                child_names,
                child_globals_is_builtin,
            )
    return runtime_open_unavailable, namespace_open_bound, child_names, child_globals_is_builtin


def _summarize_runtime_open_effects(
    body: list[ast.stmt],
    builtins_names: set[str],
    globals_is_builtin: bool,
    *,
    depth: int = 0,
) -> tuple[bool, set[str], bool, bool]:
    """Track helper aliases through the eager compound shapes used here."""

    if depth > MAX_PYTHON_PATH_SCOPE_DEPTH:
        return False, set(), False, False

    for statement in body:
        if isinstance(statement, ast.ClassDef):
            eager_nodes = _definition_eager_nodes(statement)
            if any(_node_may_replace_runtime_open(node, builtins_names, globals_is_builtin) for node in eager_nodes):
                return True, builtins_names, globals_is_builtin, True
            if any(_node_escapes_runtime_identity(node, builtins_names, globals_is_builtin) for node in eager_nodes):
                return False, set(), False, False
            class_names = set(builtins_names)
            class_globals_is_builtin = globals_is_builtin
            class_globals_is_builtin = _invalidate_runtime_helper_bindings(
                eager_nodes,
                class_names,
                class_globals_is_builtin,
            )
            replaced, _, _, complete = _summarize_runtime_open_effects(
                statement.body,
                class_names,
                class_globals_is_builtin,
                depth=depth + 1,
            )
            if replaced or not complete:
                return replaced, builtins_names, globals_is_builtin, complete
            if _class_namespace_is_unreviewed(statement) or _class_body_has_runtime_provenance_hazard(statement.body):
                return False, set(), False, False
            if _decorator_application_escapes_runtime_helper(
                statement,
                builtins_names,
                globals_is_builtin,
            ):
                return False, set(), False, False
            builtins_names.discard(statement.name)
            if statement.name == "globals":
                globals_is_builtin = False
            continue

        if isinstance(statement, ast.If):
            if _node_may_replace_runtime_open(statement.test, builtins_names, globals_is_builtin):
                return True, builtins_names, globals_is_builtin, True
            if _node_escapes_runtime_identity(statement.test, builtins_names, globals_is_builtin):
                return False, set(), False, False
            branch_names = set(builtins_names)
            branch_globals_is_builtin = _invalidate_runtime_helper_bindings(
                (statement.test,),
                branch_names,
                globals_is_builtin,
            )
            merged_names: set[str] = set()
            merged_globals_is_builtin = False
            for branch in (statement.body, statement.orelse):
                if branch:
                    replaced, result_names, result_globals, complete = _summarize_runtime_open_effects(
                        branch,
                        set(branch_names),
                        branch_globals_is_builtin,
                        depth=depth + 1,
                    )
                else:
                    replaced = False
                    result_names = set(branch_names)
                    result_globals = branch_globals_is_builtin
                    complete = True
                if replaced or not complete:
                    return replaced, builtins_names, globals_is_builtin, complete
                merged_names.update(result_names)
                if len(merged_names) > MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES:
                    return False, set(), False, False
                merged_globals_is_builtin = merged_globals_is_builtin or result_globals
            builtins_names = merged_names
            globals_is_builtin = merged_globals_is_builtin
            continue

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                if _node_may_replace_runtime_open(item.context_expr, builtins_names, globals_is_builtin):
                    return True, builtins_names, globals_is_builtin, True
                if _node_escapes_runtime_identity(
                    item.context_expr,
                    builtins_names,
                    globals_is_builtin,
                ):
                    return False, set(), False, False
                globals_is_builtin = _invalidate_runtime_helper_bindings(
                    (item.context_expr,),
                    builtins_names,
                    globals_is_builtin,
                )
                if item.optional_vars is None:
                    continue
                if _target_may_replace_runtime_open(
                    item.optional_vars,
                    builtins_names,
                    globals_is_builtin,
                ):
                    return True, builtins_names, globals_is_builtin, True
                if _node_escapes_runtime_identity(
                    item.optional_vars,
                    builtins_names,
                    globals_is_builtin,
                ):
                    return False, set(), False, False
                globals_is_builtin = _invalidate_runtime_helper_bindings(
                    (item.optional_vars,),
                    builtins_names,
                    globals_is_builtin,
                )
            replaced, builtins_names, globals_is_builtin, complete = _summarize_runtime_open_effects(
                statement.body,
                builtins_names,
                globals_is_builtin,
                depth=depth + 1,
            )
            if replaced or not complete:
                return replaced, builtins_names, globals_is_builtin, complete
            continue

        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match)) and (
            _node_escapes_runtime_identity(statement, builtins_names, globals_is_builtin)
            or any(
                _node_binds_name(statement, name) for name in _possible_runtime_helpers(statement, include_globals=True)
            )
        ):
            # Helper identities can cross iterations and exception edges.
            # This rule does not interpret those flows, so fail closed.
            return False, set(), False, False

        if _node_may_replace_runtime_open(statement, builtins_names, globals_is_builtin):
            return True, builtins_names, globals_is_builtin, True
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            _decorator_application_escapes_runtime_helper(
                statement,
                builtins_names,
                globals_is_builtin,
            )
        ):
            return False, set(), False, False
        globals_is_builtin, identities_complete = _advance_runtime_helper_identities(
            statement,
            builtins_names,
            globals_is_builtin,
        )
        if not identities_complete:
            return False, builtins_names, globals_is_builtin, False
    return False, builtins_names, globals_is_builtin, True


def _scope_may_replace_runtime_open(body: list[ast.stmt]) -> bool:
    builtins_names = _possible_runtime_helpers(body[0]) if body else {"__builtins__"}
    replaced, _, _, complete = _summarize_runtime_open_effects(
        body,
        builtins_names,
        True,
    )
    return replaced or not complete


def _function_can_use_builtin_open(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    arguments = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
        *([node.args.vararg] if node.args.vararg is not None else []),
        *([node.args.kwarg] if node.args.kwarg is not None else []),
    ]
    return not any(argument.arg == "open" for argument in arguments) and not any(
        _node_binds_name(statement, "open") for statement in node.body
    )


def _name_targets(targets: list[ast.expr]) -> tuple[str, ...] | None:
    names: list[str] = []
    for target in targets:
        if not isinstance(target, ast.Name):
            return None
        names.append(target.id)
    return tuple(names)


def _is_direct_os_path_join(node: ast.Call) -> bool:
    function = node.func
    return (
        isinstance(function, ast.Attribute)
        and function.attr == "join"
        and isinstance(function.value, ast.Attribute)
        and function.value.attr == "path"
        and isinstance(function.value.value, ast.Name)
        and function.value.value.id == "os"
    )


def _is_reviewed_os_path_attribute(node: ast.AST) -> bool:
    """Recognize descriptor-free lookups on the proven stdlib ``os.path``."""

    if not isinstance(node, ast.Attribute):
        return False
    if node.attr == "path":
        return isinstance(node.value, ast.Name) and node.value.id == "os"
    return (
        node.attr in {"exists", "join"}
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "path"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "os"
    )


def _is_reviewed_json_load(node: ast.Call, module_names: set[str]) -> bool:
    """Recognize a ``json.load`` lookup on a source-ordered stdlib import."""

    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "load"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in module_names
    )


def _has_inert_literal_hash(node: ast.AST) -> bool:
    """Return whether hashing one exact literal cannot dispatch user code."""

    return isinstance(node, ast.Constant) and type(node.value) in {
        bool,
        bytes,
        complex,
        float,
        int,
        str,
        type(None),
    }


def _is_reviewed_patch_factory_call(node: ast.AST, patch_factory_names: set[str]) -> bool:
    """Recognize inert construction of a stdlib patcher for ``builtins.open``."""

    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in patch_factory_names
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "builtins.open"
    )


def _is_reviewed_patch_import(node: ast.AST) -> bool:
    """Recognize the sole import that establishes trusted patch provenance."""

    return (
        isinstance(node, ast.ImportFrom)
        and node.level == 0
        and node.module == "unittest.mock"
        and bool(node.names)
        and all(imported.name == "patch" for imported in node.names)
    )


def _is_reviewed_static_import(node: ast.AST) -> bool:
    """Recognize imports whose identities are explicitly modeled here."""

    return (
        _is_reviewed_patch_import(node)
        or (isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "__future__")
        or (
            isinstance(node, ast.Import)
            and bool(node.names)
            and all(imported.name in {"builtins", "json", "os", "os.path"} for imported in node.names)
        )
    )


def _node_loads_patch_factory_identity(root: ast.AST, patch_factory_names: set[str]) -> bool:
    """Return whether eager evaluation exposes a tracked patch function."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Lambda):
            # Binding arbitrary immediate-lambda results is outside this
            # narrow identity proof; conservatively retire patch provenance.
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.ClassDef):
            pending.extend(_definition_eager_nodes(node))
            pending.extend(node.body)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)) and _import_exposes_patch_runtime(node):
            return True
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in patch_factory_names:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _node_loads_reviewed_module_identity(root: ast.AST, module_names: set[str]) -> bool:
    """Return whether eager code exposes a tracked stdlib module object."""

    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.ClassDef):
            pending.extend(_definition_eager_nodes(node))
            pending.extend(node.body)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in module_names:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _import_exposes_patch_runtime(statement: ast.Import | ast.ImportFrom) -> bool:
    """Recognize imports that make stdlib patch internals mutable in scope."""

    if isinstance(statement, ast.Import):
        return any(imported.name.split(".", 1)[0] in {"importlib", "sys", "unittest"} for imported in statement.names)
    if statement.level != 0:
        return True
    module_root = (statement.module or "").split(".", 1)[0]
    if statement.module == "unittest.mock":
        return any(imported.name != "patch" for imported in statement.names)
    return module_root in {"importlib", "sys", "unittest"}


class _StraightLineSensitiveReadScanner:
    def __init__(self, source: str, runtime_budget: _RuntimeProvenanceBudget) -> None:
        self.lines = source.split("\n")
        self.candidates: list[PythonSensitiveFileReadCandidate] = []
        self.candidate_lines: set[int] = set()
        self.runtime_budget = runtime_budget
        self.os_path_join_available = True
        self.reviewed_json_import_available = runtime_budget.json_import_cache_trusted

    def scan(self, tree: ast.Module) -> None:
        # Module code executes eagerly, so an early call can still resolve the
        # builtin before a later module assignment. Delayed functions are more
        # conservative because they can run after all module statements.
        self._scan_body(
            tree.body,
            depth=0,
            builtin_open=True,
            delayed_builtin_open=not self._scope_may_shadow_runtime_open(
                tree.body,
                function_scope=False,
            ),
        )

    def _evaluated_statement_view(self, statement: ast.stmt, *, function_scope: bool) -> ast.stmt:
        if isinstance(statement, _AST_TYPE_ALIAS_TYPES):
            alias_name = vars(statement).get("name")
            if not isinstance(alias_name, ast.Name):
                return statement
            evaluated_statement: ast.stmt = ast.copy_location(
                ast.Assign(
                    targets=[alias_name],
                    value=ast.Constant(value=None),
                ),
                statement,
            )
            setattr(evaluated_statement, _RUNTIME_BUDGET_ATTR, self.runtime_budget)
            return evaluated_statement
        if not isinstance(statement, ast.AnnAssign):
            return statement
        annotation_is_eager = not function_scope and not self.runtime_budget.annotations_are_deferred
        if statement.value is None and isinstance(statement.target, ast.Name) and not function_scope:
            evaluated_expression = statement.annotation if annotation_is_eager else ast.Constant(value=None)
            evaluated_statement = ast.copy_location(ast.Expr(value=evaluated_expression), statement)
            setattr(evaluated_statement, _RUNTIME_BUDGET_ATTR, self.runtime_budget)
            return evaluated_statement
        if annotation_is_eager:
            return statement
        evaluated_statement = ast.copy_location(
            ast.AnnAssign(
                target=statement.target,
                annotation=ast.Constant(value=None),
                value=statement.value,
                simple=statement.simple,
            ),
            statement,
        )
        setattr(evaluated_statement, _RUNTIME_BUDGET_ATTR, self.runtime_budget)
        return evaluated_statement

    def _delayed_runtime_trust_survives(
        self,
        body: list[ast.stmt],
        *,
        function_scope: bool,
    ) -> bool:
        """Check eager statements in order before trusting a delayed scope."""

        state = _ExpressionReadState({}, False, True)
        for original_statement in body:
            statement = self._evaluated_statement_view(
                original_statement,
                function_scope=function_scope,
            )
            if self._node_has_unreviewed_execution(
                statement,
                state.bindings,
                state.os_available,
                state.open_available,
            ):
                return False
            if isinstance(statement, ast.Import):
                for imported in statement.names:
                    local_name = _bound_import_name(imported)
                    state.bindings.pop(local_name, None)
                    if local_name == "os":
                        state.os_available = imported.name == "os" or (
                            imported.asname is None and imported.name.startswith("os.")
                        )
                continue
            if isinstance(statement, ast.ImportFrom):
                if any(imported.name == "*" for imported in statement.names):
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
                    continue
                for imported in statement.names:
                    local_name = imported.asname or imported.name
                    state.bindings.pop(local_name, None)
                    if local_name == "os":
                        state.os_available = False
                    if local_name == "open":
                        state.open_available = False
                continue
            if isinstance(statement, ast.Assign):
                value = self._exact_string(statement.value, state.bindings, state.os_available)
                targets = _name_targets(statement.targets)
                if targets is None:
                    state.bindings.clear()
                    state.os_available = False
                else:
                    for name in targets:
                        state.bindings.pop(name, None)
                        if name == "os":
                            state.os_available = False
                        if name == "open":
                            state.open_available = False
                        if value is not None:
                            state.bindings[name] = value
                continue
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                if statement.value is None and not function_scope:
                    continue
                value = self._exact_string(statement.value, state.bindings, state.os_available)
                name = statement.target.id
                state.bindings.pop(name, None)
                if name == "os":
                    state.os_available = False
                if name == "open":
                    state.open_available = False
                if value is not None:
                    state.bindings[name] = value
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                state.bindings.pop(statement.name, None)
                if statement.name == "os":
                    state.os_available = False
                if statement.name == "open":
                    state.open_available = False
                continue
            if isinstance(statement, (ast.Expr, ast.Pass, ast.Global, ast.Nonlocal)):
                continue
            state.bindings.clear()
            state.os_available = False
        return True

    def _scope_binds_runtime_open(
        self,
        body: list[ast.stmt],
        *,
        function_scope: bool,
    ) -> bool:
        return _scope_binds_open(
            [self._evaluated_statement_view(statement, function_scope=function_scope) for statement in body]
        )

    def _scope_may_replace_tracked_runtime_open(
        self,
        body: list[ast.stmt],
        *,
        function_scope: bool,
    ) -> bool:
        return _scope_may_replace_runtime_open(
            [self._evaluated_statement_view(statement, function_scope=function_scope) for statement in body]
        )

    def _scope_may_shadow_runtime_open(
        self,
        body: list[ast.stmt],
        *,
        function_scope: bool,
    ) -> bool:
        return self._scope_binds_runtime_open(
            body,
            function_scope=function_scope,
        ) or self._scope_may_replace_tracked_runtime_open(
            body,
            function_scope=function_scope,
        )

    def _scan_body(
        self,
        body: list[ast.stmt],
        *,
        depth: int,
        builtin_open: bool,
        delayed_builtin_open: bool,
        class_scope: bool = False,
        function_scope: bool = False,
        allow_reviewed_json_imports: bool = True,
        initial_bindings: dict[str, str] | None = None,
        initial_os_available: bool = False,
        initial_os_module_names: set[str] | None = None,
        initial_os_path_names: set[str] | None = None,
        initial_reviewed_json_modules: set[str] | None = None,
        initial_reviewed_callable_names: set[str] | None = None,
        initial_runtime_helpers: set[str] | None = None,
        initial_globals_is_builtin: bool = True,
        eager_lexical_builtin_open: bool | None = None,
    ) -> None:
        if depth > MAX_PYTHON_PATH_SCOPE_DEPTH or len(self.candidates) >= MAX_PYTHON_PATH_CANDIDATES:
            return

        delayed_unreviewed_execution = not self._delayed_runtime_trust_survives(
            body,
            function_scope=function_scope,
        )
        evaluated_body = [
            self._evaluated_statement_view(statement, function_scope=function_scope) for statement in body
        ]
        delayed_os_path_join_available = (
            self.os_path_join_available
            and not delayed_unreviewed_execution
            and not any(
                _class_body_may_export_os_identity(
                    statement,
                    self.runtime_budget.possible_os_modules,
                    self.runtime_budget.possible_os_paths,
                )
                or _node_may_replace_os_path_join(
                    statement,
                    self.runtime_budget.possible_os_modules,
                    self.runtime_budget.possible_os_paths,
                )
                or _node_escapes_os_path_identity(
                    statement,
                    self.runtime_budget.possible_os_modules,
                    self.runtime_budget.possible_os_paths,
                )
                for statement in evaluated_body
            )
        )
        bindings = dict(initial_bindings or {})
        os_available = initial_os_available
        os_module_names = set(initial_os_module_names or ())
        os_path_names = set(initial_os_path_names or ())
        open_available = builtin_open
        delayed_open_available = delayed_builtin_open
        eager_lexical_open_available = (
            builtin_open if eager_lexical_builtin_open is None else eager_lexical_builtin_open
        )
        builtins_names = (
            set(initial_runtime_helpers)
            if initial_runtime_helpers is not None
            else set(self.runtime_budget.possible_helpers)
        )
        globals_is_builtin = initial_globals_is_builtin
        pending_runtime_open_invalidation = False
        pending_os_path_join_invalidation = False
        patch_factory_names: set[str] = set()
        patch_factory_import_available = self.runtime_budget.patch_import_cache_trusted
        reviewed_json_modules = set(initial_reviewed_json_modules or ())
        reviewed_callable_names = set(initial_reviewed_callable_names or ())
        definitely_bound_names: set[str] = set()
        definitely_deleted_names: set[str] = set()
        external_names = {
            name for statement in body if isinstance(statement, (ast.Global, ast.Nonlocal)) for name in statement.names
        }

        def invalidate_namespace_open() -> None:
            """Invalidate an ``open`` binding in this scope's namespace."""

            nonlocal delayed_open_available, open_available
            open_available = False
            if not class_scope:
                delayed_open_available = False

        for statement in body:
            if len(self.candidates) >= MAX_PYTHON_PATH_CANDIDATES:
                return

            if pending_runtime_open_invalidation:
                open_available = False
                eager_lexical_open_available = False
                pending_runtime_open_invalidation = False
            if pending_os_path_join_invalidation:
                self.os_path_join_available = False
                os_available = False
                pending_os_path_join_invalidation = False

            entry_reviewed_json_import_available = self.reviewed_json_import_available
            annotation_is_eager = not function_scope and not self.runtime_budget.annotations_are_deferred
            evaluated_statement = self._evaluated_statement_view(
                statement,
                function_scope=function_scope,
            )
            if definitely_deleted_names and (
                _node_loads_any_name(evaluated_statement, definitely_deleted_names)
                or (
                    isinstance(evaluated_statement, ast.AugAssign)
                    and isinstance(evaluated_statement.target, ast.Name)
                    and evaluated_statement.target.id in definitely_deleted_names
                )
            ):
                return
            newly_bound_names = _definitely_bound_names_after(evaluated_statement)
            definitely_bound_names.update(newly_bound_names)
            definitely_deleted_names.difference_update(newly_bound_names)

            statement_os_module_names = set(os_module_names)
            statement_os_path_names = set(os_path_names)
            if class_scope:
                # LOAD_NAME in a class body can fall back to the enclosing
                # lexical/module scope, while lambdas and comprehensions skip
                # the class namespace entirely. Keep both possibilities when
                # recognizing mutation of the shared cached modules.
                statement_os_module_names.update(self.runtime_budget.possible_os_modules)
                statement_os_path_names.update(self.runtime_budget.possible_os_paths)
            mutation_module_names = statement_os_module_names
            mutation_path_names = statement_os_path_names
            if isinstance(
                evaluated_statement,
                (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match, ast.If),
            ):
                # Unsupported control flow may import an alias before mutating
                # the cached module. Use the bounded whole-file over-approximation
                # for that statement only; straight-line rebindings stay precise.
                mutation_module_names = mutation_module_names | self.runtime_budget.possible_os_modules
                mutation_path_names = mutation_path_names | self.runtime_budget.possible_os_paths
            compound_os_alias_ambiguous = (
                _class_body_may_export_os_identity(
                    evaluated_statement,
                    self.runtime_budget.possible_os_modules,
                    self.runtime_budget.possible_os_paths,
                )
                or isinstance(
                    evaluated_statement,
                    (
                        ast.If,
                        ast.With,
                        ast.AsyncWith,
                        ast.For,
                        ast.AsyncFor,
                        ast.While,
                        ast.Try,
                        ast.TryStar,
                        ast.Match,
                    ),
                )
                and any(
                    _node_binds_name(evaluated_statement, name)
                    for name in self.runtime_budget.possible_os_modules | self.runtime_budget.possible_os_paths
                )
            )
            if self.os_path_join_available and (
                compound_os_alias_ambiguous
                or _node_may_replace_os_path_join(
                    evaluated_statement,
                    mutation_module_names,
                    mutation_path_names,
                )
                or _node_escapes_os_path_identity(
                    evaluated_statement,
                    mutation_module_names,
                    mutation_path_names,
                )
            ):
                pending_os_path_join_invalidation = True
            os_module_names, os_path_names = _advance_os_aliases(
                evaluated_statement,
                os_module_names,
                os_path_names,
            )

            statement_binds_open = not isinstance(evaluated_statement, (ast.Global, ast.Nonlocal)) and _node_binds_name(
                evaluated_statement,
                "open",
            )
            exact_class_helper = (
                isinstance(statement, ast.Import)
                and any(imported.name == "builtins" for imported in statement.names)
                or bool(_assigned_runtime_helper_names(evaluated_statement, builtins_names))
            )
            class_identity_diverges = (
                class_scope
                and not isinstance(
                    statement,
                    (ast.Global, ast.Nonlocal),
                )
                and not exact_class_helper
                and any(
                    _node_binds_name(evaluated_statement, name)
                    for name in _possible_runtime_helpers(evaluated_statement, include_globals=True)
                )
            )
            statement_runtime_helpers = set(builtins_names)
            statement_globals_is_builtin = globals_is_builtin
            (
                child_runtime_open_unavailable,
                child_namespace_open_bound,
                child_runtime_helpers,
                child_globals_is_builtin,
            ) = _runtime_open_state_before_child(
                evaluated_statement,
                statement_runtime_helpers,
                statement_globals_is_builtin,
            )
            runtime_open_replaced, builtins_names, globals_is_builtin, identities_complete = (
                _summarize_runtime_open_effects(
                    [evaluated_statement],
                    builtins_names,
                    globals_is_builtin,
                )
            )
            if runtime_open_replaced or not identities_complete:
                # The statement's supported reads happen before assignment
                # targets and child-body effects. Delayed code can observe the
                # mutation, while the current statement keeps its prior value.
                delayed_open_available = False
                pending_runtime_open_invalidation = True
            current_patch_factory_names = set(patch_factory_names)
            current_reviewed_callable_names = {
                name for name in reviewed_callable_names if not _node_binds_name(evaluated_statement, name)
            }
            reviewed_callable_names = set(current_reviewed_callable_names)
            unreviewed_execution = self._node_has_unreviewed_execution(
                evaluated_statement,
                bindings,
                os_available,
                open_available,
                current_reviewed_callable_names,
            )
            unreviewed_identity_execution = self._node_has_unreviewed_patch_execution(
                evaluated_statement,
                bindings,
                os_available,
                open_available,
                current_patch_factory_names,
            )
            unreviewed_patch_execution = bool(current_patch_factory_names) and unreviewed_identity_execution
            current_reviewed_json_modules = set(reviewed_json_modules)
            reviewed_json_modules.difference_update(
                {name for name in reviewed_json_modules if _node_binds_name(evaluated_statement, name)}
            )
            reviewed_json_identity_exposed = _node_loads_reviewed_module_identity(
                evaluated_statement,
                current_reviewed_json_modules,
            )
            if unreviewed_execution or unreviewed_identity_execution or reviewed_json_identity_exposed:
                reviewed_json_modules.clear()
                self.reviewed_json_import_available = False
            class_rebinds_reviewed_json = isinstance(statement, ast.ClassDef) and (
                _class_body_may_rebind_external_names(
                    statement.body,
                    current_reviewed_json_modules,
                )
            )
            if class_rebinds_reviewed_json:
                reviewed_json_modules.clear()
                self.reviewed_json_import_available = False
            patch_factory_identity_exposed = _node_loads_patch_factory_identity(
                evaluated_statement,
                current_patch_factory_names,
            )
            next_patch_factory_names = {
                name for name in patch_factory_names if not _node_binds_name(evaluated_statement, name)
            }
            class_rebinds_patch_factory = isinstance(statement, ast.ClassDef) and (
                _class_body_may_rebind_external_names(statement.body, current_patch_factory_names)
            )
            if unreviewed_execution or unreviewed_patch_execution or patch_factory_identity_exposed:
                next_patch_factory_names.clear()
                patch_factory_import_available = False
            if class_rebinds_patch_factory:
                next_patch_factory_names.clear()
                patch_factory_import_available = False
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                patch_factory_names = next_patch_factory_names
            if unreviewed_execution:
                pending_runtime_open_invalidation = True
                pending_os_path_join_invalidation = True
            if class_identity_diverges:
                # Methods, nested classes, and comprehensions skip this class
                # namespace. A local shadow therefore makes the shared runtime
                # helper provenance ambiguous from the following statement.
                delayed_open_available = False
                pending_runtime_open_invalidation = True

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._record_definition_eager_opens(
                    statement,
                    bindings,
                    os_available,
                    open_available,
                    current_patch_factory_names,
                    current_reviewed_json_modules,
                )
                patch_factory_names = next_patch_factory_names
                # Delayed scopes receive no path or import facts. The only
                # inherited marker prevents a module/enclosing ``open``
                # binding from being mistaken for the built-in.
                type_parameter_names = {parameter.name for parameter in getattr(statement, "type_params", ())}
                function_open_available = (
                    delayed_open_available
                    and "open" not in type_parameter_names
                    and _function_can_use_builtin_open(statement)
                )
                current_os_path_join_available = self.os_path_join_available
                self.os_path_join_available = (
                    current_os_path_join_available and delayed_os_path_join_available and not unreviewed_execution
                )
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=function_open_available,
                    delayed_builtin_open=(
                        function_open_available
                        and not self._scope_may_replace_tracked_runtime_open(
                            statement.body,
                            function_scope=True,
                        )
                    ),
                    function_scope=True,
                    allow_reviewed_json_imports=False,
                    initial_os_module_names=set(self.runtime_budget.possible_os_modules) - type_parameter_names,
                    initial_os_path_names=set(self.runtime_budget.possible_os_paths) - type_parameter_names,
                )
                self.os_path_join_available = current_os_path_join_available
                if _definition_eager_nodes(statement) or unreviewed_execution:
                    bindings.clear()
                    os_available = False
                else:
                    bindings.pop(statement.name, None)
                    if statement.name == "os":
                        os_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, _AST_TYPE_ALIAS_TYPES):
                alias_name = vars(statement).get("name")
                if not isinstance(alias_name, ast.Name):
                    bindings.clear()
                    os_available = False
                    continue
                name = alias_name.id
                bindings.pop(name, None)
                if name == "os":
                    os_available = False
                if name == "open":
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.ClassDef):
                (
                    decorator_patch_factory_names,
                    class_decorator_state,
                ) = self._record_definition_eager_opens(
                    statement,
                    bindings,
                    os_available,
                    open_available,
                    current_patch_factory_names,
                    current_reviewed_json_modules,
                )
                patch_factory_names = next_patch_factory_names
                # A method or nested class skips the surrounding class
                # namespace. Keep class-body sequential lookup separate from
                # the enclosing lexical marker used by delayed code.
                class_header_module_names = statement_os_module_names | self.runtime_budget.possible_os_modules
                class_header_path_names = statement_os_path_names | self.runtime_budget.possible_os_paths
                class_header_unreviewed = any(
                    self._node_has_unreviewed_execution(
                        eager_node,
                        bindings,
                        os_available,
                        open_available,
                    )
                    for eager_node in _definition_eager_nodes(statement)
                )
                if self.os_path_join_available and (
                    class_header_unreviewed
                    or any(
                        _node_may_replace_os_path_join(
                            eager_node,
                            class_header_module_names,
                            class_header_path_names,
                        )
                        or _node_escapes_os_path_identity(
                            eager_node,
                            class_header_module_names,
                            class_header_path_names,
                        )
                        for eager_node in _definition_eager_nodes(statement)
                    )
                ):
                    self.os_path_join_available = False
                    os_available = False
                    pending_os_path_join_invalidation = False
                type_parameter_names = {parameter.name for parameter in getattr(statement, "type_params", ())}
                class_open_available = (eager_lexical_open_available if class_scope else open_available) and not (
                    "open" in type_parameter_names
                    or child_runtime_open_unavailable
                    or (child_namespace_open_bound and not class_scope)
                )
                class_replaces_runtime_open = self._scope_may_replace_tracked_runtime_open(
                    statement.body,
                    function_scope=False,
                )
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=class_open_available,
                    delayed_builtin_open=(
                        delayed_open_available
                        and "open" not in type_parameter_names
                        and not class_replaces_runtime_open
                    ),
                    class_scope=True,
                    function_scope=False,
                    allow_reviewed_json_imports=allow_reviewed_json_imports,
                    initial_os_module_names=(statement_os_module_names | self.runtime_budget.possible_os_modules)
                    - type_parameter_names,
                    initial_os_path_names=(statement_os_path_names | self.runtime_budget.possible_os_paths)
                    - type_parameter_names,
                    initial_runtime_helpers=child_runtime_helpers,
                    initial_globals_is_builtin=child_globals_is_builtin,
                    eager_lexical_builtin_open=class_open_available,
                )
                class_decorator_state.os_available = class_decorator_state.os_available and self.os_path_join_available
                class_decorator_state.open_available = (
                    class_decorator_state.open_available and not class_replaces_runtime_open
                )
                class_body_has_unreviewed_execution = any(
                    self._node_has_unreviewed_execution(
                        body_statement,
                        bindings,
                        os_available,
                        open_available,
                    )
                    for body_statement in statement.body
                )
                if class_body_has_unreviewed_execution or any(
                    _node_loads_patch_factory_identity(body_statement, decorator_patch_factory_names)
                    for body_statement in statement.body
                ):
                    # Decorator expressions captured their patchers before the
                    # body ran, but the body can still replace the shared
                    # patcher application's implementation.
                    decorator_patch_factory_names.clear()
                decorator_lexical_names = (
                    set(bindings)
                    | statement_runtime_helpers
                    | statement_os_module_names
                    | statement_os_path_names
                    | {"globals", "open", "os"}
                )
                if (
                    not _class_namespace_is_unreviewed(statement)
                    and not getattr(statement, "type_params", ())
                    and _class_body_is_trivially_inert(statement.body)
                    and not class_body_has_unreviewed_execution
                    and not _class_body_may_mutate_decorator_lexical_state(
                        statement.body,
                        decorator_lexical_names,
                    )
                ):
                    self._record_direct_lambda_decorator_applications(
                        statement,
                        class_decorator_state,
                        decorator_patch_factory_names,
                    )
                bindings.clear()
                os_available = False
                if class_replaces_runtime_open:
                    open_available = False
                    delayed_open_available = False
                    eager_lexical_open_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.Import):
                static_import_is_reviewed = _is_reviewed_static_import(statement)
                if not static_import_is_reviewed:
                    # Importing arbitrary module code can mutate cached stdlib
                    # modules or ``builtins.open`` before the next statement.
                    # Do not carry any positive path or runtime provenance
                    # across that execution boundary.
                    bindings.clear()
                    os_available = False
                    self.os_path_join_available = False
                    open_available = False
                    delayed_open_available = False
                    eager_lexical_open_available = False
                    pending_os_path_join_invalidation = False
                    pending_runtime_open_invalidation = False
                if _import_exposes_patch_runtime(statement):
                    patch_factory_names.clear()
                    patch_factory_import_available = False
                reviewed_json_import = (
                    allow_reviewed_json_imports and self.reviewed_json_import_available and static_import_is_reviewed
                )
                if not reviewed_json_import:
                    reviewed_json_modules.clear()
                for imported in statement.names:
                    local_name = _bound_import_name(imported)
                    bindings.pop(local_name, None)
                    reviewed_json_modules.discard(local_name)
                    if reviewed_json_import and imported.name == "json":
                        reviewed_json_modules.add(local_name)
                    if local_name == "os":
                        os_available = self.os_path_join_available and (
                            imported.name == "os" or (imported.asname is None and imported.name.startswith("os."))
                        )
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.ImportFrom):
                static_import_is_reviewed = _is_reviewed_static_import(statement)
                if not static_import_is_reviewed:
                    # As with an arbitrary plain import, executing an
                    # unmodeled module invalidates all positive runtime facts.
                    bindings.clear()
                    os_available = False
                    self.os_path_join_available = False
                    open_available = False
                    delayed_open_available = False
                    eager_lexical_open_available = False
                    pending_os_path_join_invalidation = False
                    pending_runtime_open_invalidation = False
                if not (
                    allow_reviewed_json_imports and self.reviewed_json_import_available and static_import_is_reviewed
                ):
                    reviewed_json_modules.clear()
                patch_import_is_reviewed = patch_factory_import_available and not _import_exposes_patch_runtime(
                    statement
                )
                if not patch_import_is_reviewed:
                    patch_factory_names.clear()
                    patch_factory_import_available = False
                if any(imported.name == "*" for imported in statement.names):
                    bindings.clear()
                    os_available = False
                    patch_factory_names.clear()
                else:
                    for imported in statement.names:
                        local_name = imported.asname or imported.name
                        bindings.pop(local_name, None)
                        reviewed_json_modules.discard(local_name)
                        if local_name == "os":
                            os_available = False
                        if (
                            patch_import_is_reviewed
                            and statement.level == 0
                            and statement.module == "unittest.mock"
                            and imported.name == "patch"
                        ):
                            patch_factory_names.add(local_name)
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.Assign):
                eager_state = _ExpressionReadState(
                    dict(bindings),
                    os_available,
                    open_available,
                    set(current_reviewed_json_modules),
                )
                assigned_value = self._exact_string(statement.value, bindings, os_available)
                value_is_direct_open = (
                    isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Name)
                    and statement.value.func.id == "open"
                )
                self._scan_eager_expression_opens(statement.value, eager_state, depth=0)
                for target in statement.targets:
                    self._scan_assignment_target(
                        target,
                        assigned_value,
                        eager_state,
                        depth=0,
                    )
                if value_is_direct_open:
                    bindings.clear()
                    os_available = False
                    if statement_binds_open:
                        invalidate_namespace_open()
                    continue
                targets = _name_targets(statement.targets)
                if targets is None:
                    bindings.clear()
                    os_available = False
                    if statement_binds_open:
                        invalidate_namespace_open()
                    continue
                value = self._exact_string(statement.value, bindings, os_available)
                if value is None and not self._expression_is_inert(statement.value, bindings, os_available):
                    bindings.clear()
                    os_available = False
                for name in targets:
                    bindings.pop(name, None)
                    if name == "os":
                        os_available = False
                    if name == "open":
                        open_available = False
                    if name not in external_names and value is not None:
                        bindings[name] = value
                if isinstance(statement.value, ast.Lambda) and not self._node_has_unreviewed_patch_execution(
                    statement.value.body,
                    bindings,
                    os_available,
                    open_available,
                    set(),
                ):
                    reviewed_callable_names.update(name for name in targets if name not in external_names)
                self._enforce_binding_limit(bindings)
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.AnnAssign):
                eager_state = _ExpressionReadState(
                    dict(bindings),
                    os_available,
                    open_available,
                    set(current_reviewed_json_modules),
                )
                value_is_direct_open = False
                if statement.value is not None:
                    value_is_direct_open = (
                        isinstance(statement.value, ast.Call)
                        and isinstance(statement.value.func, ast.Name)
                        and statement.value.func.id == "open"
                    )
                    self._scan_eager_expression_opens(statement.value, eager_state, depth=0)
                if not isinstance(statement.target, ast.Name):
                    self._scan_eager_expression_opens(statement.target, eager_state, depth=0)
                if statement.value is not None:
                    assigned_value = self._exact_string(statement.value, bindings, os_available)
                    self._scan_assignment_target(
                        statement.target,
                        assigned_value,
                        eager_state,
                        depth=0,
                        address_already_scanned=not isinstance(statement.target, ast.Name),
                    )
                if annotation_is_eager:
                    self._scan_eager_expression_opens(statement.annotation, eager_state, depth=0)
                if statement.value is None and isinstance(statement.target, ast.Name) and not function_scope:
                    if annotation_is_eager and not self._expression_is_inert(
                        statement.annotation,
                        bindings,
                        os_available,
                    ):
                        bindings.clear()
                        os_available = False
                    continue
                if value_is_direct_open:
                    bindings.clear()
                    os_available = False
                    if statement_binds_open:
                        invalidate_namespace_open()
                    continue
                if (
                    not isinstance(statement.target, ast.Name)
                    or (
                        annotation_is_eager
                        and not self._expression_is_inert(statement.annotation, bindings, os_available)
                    )
                    or not self._expression_is_inert(statement.value, bindings, os_available)
                ):
                    bindings.clear()
                    os_available = False
                    if statement_binds_open:
                        invalidate_namespace_open()
                    continue
                name = statement.target.id
                value = self._exact_string(statement.value, bindings, os_available)
                bindings.pop(name, None)
                if name == "os":
                    os_available = False
                if name == "open":
                    open_available = False
                if name not in external_names and value is not None:
                    bindings[name] = value
                self._enforce_binding_limit(bindings)
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.AugAssign):
                if self.os_path_join_available and _augassign_target_evaluation_invalidates_os_path_join(
                    statement.target,
                    statement_os_module_names,
                    statement_os_path_names,
                ):
                    self.os_path_join_available = False
                    os_available = False
                    pending_os_path_join_invalidation = False
                if _augassign_target_evaluation_invalidates_runtime_open(
                    statement.target,
                    statement_runtime_helpers,
                    statement_globals_is_builtin,
                ):
                    open_available = False
                    delayed_open_available = False
                    eager_lexical_open_available = False
                eager_state = _ExpressionReadState(
                    dict(bindings),
                    os_available,
                    open_available,
                    set(current_reviewed_json_modules),
                )
                reviewed_attribute_store = isinstance(statement.target, ast.Attribute) and (
                    _target_may_replace_os_path_join(
                        statement.target,
                        statement_os_module_names,
                        statement_os_path_names,
                    )
                    or _target_may_replace_runtime_open(
                        statement.target,
                        statement_runtime_helpers,
                        statement_globals_is_builtin,
                    )
                )
                if not reviewed_attribute_store:
                    self._scan_eager_expression_opens(statement.target, eager_state, depth=0)
                value_is_direct_open = (
                    isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Name)
                    and statement.value.func.id == "open"
                )
                self._scan_eager_expression_opens(statement.value, eager_state, depth=0)
                if value_is_direct_open:
                    bindings.clear()
                    os_available = False
                    if statement_binds_open:
                        invalidate_namespace_open()
                    continue
                target = statement.target
                augmented_value: str | None = None
                if isinstance(target, ast.Name) and isinstance(statement.op, ast.Add):
                    left = bindings.get(target.id)
                    right = self._exact_string(statement.value, bindings, os_available)
                    if left is not None and right is not None:
                        augmented_value = _bounded_string(left + right)
                bindings.clear()
                os_available = False
                if isinstance(target, ast.Name):
                    if target.id == "open":
                        open_available = False
                    if target.id not in external_names and augmented_value is not None:
                        bindings[target.id] = augmented_value
                elif _node_binds_name(target, "open"):
                    open_available = False
                self._enforce_binding_limit(bindings)
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.Delete):
                eager_state = _ExpressionReadState(
                    dict(bindings),
                    os_available,
                    open_available,
                    set(current_reviewed_json_modules),
                )
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        if target.id not in definitely_bound_names:
                            if pending_os_path_join_invalidation:
                                self.os_path_join_available = False
                            return
                        definitely_bound_names.discard(target.id)
                        definitely_deleted_names.add(target.id)
                    self._scan_delete_target(target, eager_state, depth=0)
                targets = _name_targets(statement.targets)
                if targets is None:
                    bindings.clear()
                    os_available = False
                else:
                    for name in targets:
                        bindings.pop(name, None)
                        if name == "os":
                            os_available = False
                        if name == "open":
                            open_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, (ast.With, ast.AsyncWith)):
                with_runtime_helpers = set(statement_runtime_helpers)
                with_globals_is_builtin = statement_globals_is_builtin
                for item in statement.items:
                    self._record_direct_open(
                        item.context_expr,
                        bindings,
                        os_available,
                        open_available,
                        current_reviewed_json_modules,
                    )
                    context_has_unreviewed_execution = self._node_has_unreviewed_execution(
                        item.context_expr,
                        bindings,
                        os_available,
                        open_available,
                        current_reviewed_callable_names,
                    )
                    bindings.clear()
                    os_available = False
                    if context_has_unreviewed_execution:
                        self.os_path_join_available = False
                        pending_os_path_join_invalidation = False
                        open_available = False
                        delayed_open_available = False
                        eager_lexical_open_available = False
                        pending_runtime_open_invalidation = False
                    if self.os_path_join_available and (
                        _node_may_replace_os_path_join(
                            item.context_expr,
                            statement_os_module_names | self.runtime_budget.possible_os_modules,
                            statement_os_path_names | self.runtime_budget.possible_os_paths,
                        )
                        or _node_escapes_os_path_identity(
                            item.context_expr,
                            statement_os_module_names | self.runtime_budget.possible_os_modules,
                            statement_os_path_names | self.runtime_budget.possible_os_paths,
                        )
                    ):
                        self.os_path_join_available = False
                        pending_os_path_join_invalidation = False
                    context_invalidates_runtime_open = _node_may_replace_runtime_open(
                        item.context_expr,
                        with_runtime_helpers,
                        with_globals_is_builtin,
                    ) or _node_escapes_runtime_identity(
                        item.context_expr,
                        with_runtime_helpers,
                        with_globals_is_builtin,
                    )
                    if context_invalidates_runtime_open:
                        open_available = False
                        delayed_open_available = False
                        eager_lexical_open_available = False
                    with_globals_is_builtin = _invalidate_runtime_helper_bindings(
                        (item.context_expr,),
                        with_runtime_helpers,
                        with_globals_is_builtin,
                    )
                    if _node_binds_name(item.context_expr, "open"):
                        invalidate_namespace_open()
                    if item.optional_vars is None:
                        continue
                    target_state = _ExpressionReadState(
                        dict(bindings),
                        os_available,
                        open_available,
                        set(current_reviewed_json_modules),
                    )
                    self._scan_assignment_target(
                        item.optional_vars,
                        None,
                        target_state,
                        depth=0,
                    )
                    if self.os_path_join_available and (
                        _target_may_replace_os_path_join(
                            item.optional_vars,
                            statement_os_module_names | self.runtime_budget.possible_os_modules,
                            statement_os_path_names | self.runtime_budget.possible_os_paths,
                        )
                        or _node_escapes_os_path_identity(
                            item.optional_vars,
                            statement_os_module_names | self.runtime_budget.possible_os_modules,
                            statement_os_path_names | self.runtime_budget.possible_os_paths,
                        )
                    ):
                        self.os_path_join_available = False
                        pending_os_path_join_invalidation = False
                    if _target_may_replace_runtime_open(
                        item.optional_vars,
                        with_runtime_helpers,
                        with_globals_is_builtin,
                    ):
                        open_available = False
                        delayed_open_available = False
                        eager_lexical_open_available = False
                    if _node_escapes_runtime_identity(
                        item.optional_vars,
                        with_runtime_helpers,
                        with_globals_is_builtin,
                    ):
                        open_available = False
                        delayed_open_available = False
                        eager_lexical_open_available = False
                    with_globals_is_builtin = _invalidate_runtime_helper_bindings(
                        (item.optional_vars,),
                        with_runtime_helpers,
                        with_globals_is_builtin,
                    )
                    if _node_binds_name(item.optional_vars, "open"):
                        invalidate_namespace_open()
                body_binds_open = self._scope_binds_runtime_open(
                    statement.body,
                    function_scope=function_scope,
                )
                body_replaces_runtime_open = self._scope_may_replace_tracked_runtime_open(
                    statement.body,
                    function_scope=function_scope,
                )
                body_open_available = open_available
                body_delayed_open_available = delayed_open_available and not body_replaces_runtime_open
                if body_binds_open and not class_scope:
                    body_delayed_open_available = False
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=body_open_available,
                    delayed_builtin_open=body_delayed_open_available,
                    class_scope=class_scope,
                    function_scope=function_scope,
                    allow_reviewed_json_imports=allow_reviewed_json_imports,
                    initial_os_module_names=statement_os_module_names,
                    initial_os_path_names=statement_os_path_names,
                    initial_runtime_helpers=with_runtime_helpers,
                    initial_globals_is_builtin=with_globals_is_builtin,
                    eager_lexical_builtin_open=eager_lexical_open_available,
                )
                if body_binds_open or body_replaces_runtime_open:
                    open_available = False
                if body_replaces_runtime_open or (body_binds_open and not class_scope):
                    delayed_open_available = False
                if body_replaces_runtime_open:
                    eager_lexical_open_available = False
                continue

            if isinstance(statement, ast.Expr):
                if self._record_direct_open(
                    statement.value,
                    bindings,
                    os_available,
                    open_available,
                    current_reviewed_json_modules,
                ):
                    bindings.clear()
                    os_available = False
                elif not self._expression_is_inert(statement.value, bindings, os_available):
                    bindings.clear()
                    os_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.If) and self._is_exact_path_exists_guard(
                statement,
                bindings,
                os_available,
            ):
                # ``os.path.exists(exact_path)`` is a narrow, read-only guard.
                # Carry the already-proven local facts into its body so a
                # guarded ``with open(alias)`` is classified independently of
                # the alias spelling. The state after the conditional is still
                # discarded because the body may not execute.
                body_open_available = (
                    open_available and not child_runtime_open_unavailable and not child_namespace_open_bound
                )
                post_statement_reviewed_json_import_available = self.reviewed_json_import_available
                self.reviewed_json_import_available = entry_reviewed_json_import_available
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=body_open_available,
                    delayed_builtin_open=(
                        delayed_open_available and not child_runtime_open_unavailable and not child_namespace_open_bound
                    ),
                    class_scope=class_scope,
                    function_scope=function_scope,
                    allow_reviewed_json_imports=allow_reviewed_json_imports,
                    initial_bindings=dict(bindings),
                    initial_os_available=os_available,
                    initial_os_module_names=statement_os_module_names,
                    initial_os_path_names=statement_os_path_names,
                    initial_reviewed_json_modules=current_reviewed_json_modules,
                    initial_reviewed_callable_names=current_reviewed_callable_names,
                    initial_runtime_helpers=child_runtime_helpers,
                    initial_globals_is_builtin=child_globals_is_builtin,
                    eager_lexical_builtin_open=(eager_lexical_open_available and not child_runtime_open_unavailable),
                )
                self.reviewed_json_import_available = (
                    post_statement_reviewed_json_import_available and self.reviewed_json_import_available
                )
                bindings.clear()
                os_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.Return):
                if statement.value is not None:
                    self._record_direct_open(
                        statement.value,
                        bindings,
                        os_available,
                        open_available,
                        current_reviewed_json_modules,
                    )
                if pending_os_path_join_invalidation:
                    self.os_path_join_available = False
                return

            if isinstance(statement, ast.Raise):
                eager_state = _ExpressionReadState(
                    dict(bindings),
                    os_available,
                    open_available,
                    set(current_reviewed_json_modules),
                )
                if statement.exc is not None:
                    self._scan_eager_expression_opens(statement.exc, eager_state, depth=0)
                if statement.cause is not None:
                    self._scan_eager_expression_opens(statement.cause, eager_state, depth=0)
                if pending_os_path_join_invalidation:
                    self.os_path_join_available = False
                return

            if isinstance(statement, ast.Assert):
                eager_state = _ExpressionReadState(
                    dict(bindings),
                    os_available,
                    open_available,
                    set(current_reviewed_json_modules),
                )
                self._scan_eager_expression_opens(statement.test, eager_state, depth=0)
                truth = self._known_expression_truth(statement.test, eager_state)
                if truth is False and statement.msg is not None:
                    self._scan_eager_expression_opens(statement.msg, eager_state, depth=0)
                if truth is not True:
                    if pending_os_path_join_invalidation:
                        self.os_path_join_available = False
                    return
                if not self._expression_is_inert(statement.test, bindings, os_available):
                    bindings.clear()
                    os_available = False
                    open_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, (ast.Break, ast.Continue)):
                if pending_os_path_join_invalidation:
                    self.os_path_join_available = False
                return

            if isinstance(statement, ast.Pass):
                continue

            bindings.clear()
            os_available = False
            if statement_binds_open:
                invalidate_namespace_open()

        if pending_os_path_join_invalidation:
            self.os_path_join_available = False

    def _record_definition_eager_opens(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
        patch_factory_names: set[str],
        reviewed_json_modules: set[str],
    ) -> tuple[set[str], _ExpressionReadState]:
        """Record proven reads evaluated while a definition is created."""

        state = _ExpressionReadState(
            dict(bindings),
            os_available,
            open_available,
            set(reviewed_json_modules),
        )
        active_patch_factory_names = set(patch_factory_names)
        for decorator in statement.decorator_list:
            if _is_reviewed_patch_factory_call(decorator, active_patch_factory_names):
                continue
            decorator_has_unreviewed_execution = self._node_has_unreviewed_execution(
                decorator,
                state.bindings,
                state.os_available,
                state.open_available,
            ) or self._node_has_unreviewed_patch_execution(
                decorator,
                state.bindings,
                state.os_available,
                state.open_available,
                active_patch_factory_names,
            )
            decorator_exposes_patch_factory = _node_loads_patch_factory_identity(
                decorator,
                active_patch_factory_names,
            )
            self._scan_eager_expression_opens(decorator, state, depth=0)
            if decorator_has_unreviewed_execution or decorator_exposes_patch_factory:
                active_patch_factory_names.clear()
            else:
                active_patch_factory_names.difference_update(
                    {name for name in active_patch_factory_names if _node_binds_name(decorator, name)}
                )

        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            before_type_parameters = [
                *statement.args.defaults,
                *(default for default in statement.args.kw_defaults if default is not None),
            ]
            after_type_parameters: list[ast.expr] = []
            if not self.runtime_budget.annotations_are_deferred:
                annotated_arguments = [*statement.args.args, *statement.args.posonlyargs]
                if statement.args.vararg is not None:
                    annotated_arguments.append(statement.args.vararg)
                annotated_arguments.extend(statement.args.kwonlyargs)
                if statement.args.kwarg is not None:
                    annotated_arguments.append(statement.args.kwarg)
                after_type_parameters.extend(
                    argument.annotation for argument in annotated_arguments if argument.annotation is not None
                )
                if statement.returns is not None:
                    after_type_parameters.append(statement.returns)
        else:
            before_type_parameters = []
            after_type_parameters = [
                *statement.bases,
                *(keyword.value for keyword in statement.keywords),
            ]

        for expression in before_type_parameters:
            self._scan_eager_expression_opens(expression, state, depth=0)

        type_parameters = getattr(statement, "type_params", ())
        decorator_application_state = state
        if type_parameters:
            # Type parameters shadow names only inside their annotation scope;
            # decorator callables were created in the enclosing lexical scope.
            decorator_application_state = _ExpressionReadState(
                dict(state.bindings),
                state.os_available,
                state.open_available,
                set(state.reviewed_json_modules),
            )
        for type_parameter in type_parameters:
            name = type_parameter.name
            state.bindings.pop(name, None)
            if name == "os":
                state.os_available = False
            if name == "open":
                state.open_available = False
            state.reviewed_json_modules.discard(name)

        for eager_expression in after_type_parameters:
            self._scan_eager_expression_opens(eager_expression, state, depth=0)

        if type_parameters and after_type_parameters:
            # Eager header effects inside a type-parameter scope are not
            # projected back into the enclosing lexical state. Stop rather
            # than manufacture stale decorator-application facts.
            decorator_application_state = _ExpressionReadState({}, False, False, set())
        elif not type_parameters:
            decorator_application_state = state

        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._record_direct_lambda_decorator_applications(
                statement,
                decorator_application_state,
                active_patch_factory_names,
            )
        return active_patch_factory_names, decorator_application_state

    def _record_direct_lambda_decorator_applications(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        state: _ExpressionReadState,
        patch_factory_names: set[str],
    ) -> None:
        """Interpret direct-lambda applications across reviewed patchers."""

        decorated_value_is_fresh = True
        for decorator in reversed(statement.decorator_list):
            if _is_reviewed_patch_factory_call(decorator, patch_factory_names):
                if isinstance(statement, ast.ClassDef) or not decorated_value_is_fresh:
                    # Class patching performs descriptor lookups, and an inner
                    # decorator can replace a fresh function with an object
                    # whose patching attributes execute arbitrary code.
                    return
                continue
            if not (
                isinstance(decorator, ast.Lambda)
                and not decorator.args.defaults
                and not any(decorator.args.kw_defaults)
            ):
                return
            lambda_invalidates_patch_factory = (
                _node_loads_patch_factory_identity(
                    decorator.body,
                    patch_factory_names,
                )
                or self._node_has_unreviewed_execution(
                    decorator.body,
                    state.bindings,
                    state.os_available,
                    state.open_available,
                )
                or self._node_has_unreviewed_patch_execution(
                    decorator.body,
                    state.bindings,
                    state.os_available,
                    state.open_available,
                    patch_factory_names,
                )
            )
            synthetic_call = ast.Call(
                func=decorator,
                args=[ast.Constant(value=None)],
                keywords=[],
            )
            if not self._scan_immediate_lambda_body(
                decorator,
                synthetic_call,
                state,
                {},
                [None],
                [],
                depth=0,
            ):
                return
            if lambda_invalidates_patch_factory:
                patch_factory_names.clear()
            decorated_value_is_fresh = False

    def _exact_string(
        self,
        node: ast.AST | None,
        bindings: dict[str, str],
        os_available: bool,
        depth: int = 0,
    ) -> str | None:
        if node is None or depth > MAX_PYTHON_PATH_VALUE_DEPTH:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _bounded_string(node.value)
        if isinstance(node, ast.Name):
            return bindings.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._exact_string(node.left, bindings, os_available, depth + 1)
            right = self._exact_string(node.right, bindings, os_available, depth + 1)
            if left is not None and right is not None:
                return _bounded_string(left + right)
            return None
        if (
            not os_available
            or not isinstance(node, ast.Call)
            or not _is_direct_os_path_join(node)
            or node.keywords
            or not node.args
            or len(node.args) > MAX_PYTHON_PATH_JOIN_PARTS
            or any(isinstance(argument, ast.Starred) for argument in node.args)
        ):
            return None
        parts: list[str] = []
        for argument in node.args:
            value = self._exact_string(argument, bindings, os_available, depth + 1)
            if value is None:
                return None
            parts.append(value)
        posix_value = _bounded_string(posixpath.join(*parts))
        windows_value = _bounded_string(ntpath.join(*parts))
        if (
            posix_value is None
            or windows_value is None
            or _normalize_path(posix_value) != _normalize_path(windows_value)
        ):
            return None
        return posix_value

    def _expression_is_inert(self, node: ast.AST | None, bindings: dict[str, str], os_available: bool) -> bool:
        if node is None:
            return True
        pending = [node]
        while pending:
            current = pending.pop()
            if isinstance(current, (ast.Constant, ast.Name)):
                continue
            if isinstance(current, (ast.List, ast.Tuple)):
                if any(isinstance(element, ast.Starred) for element in current.elts):
                    return False
                pending.extend(current.elts)
                continue
            if self._exact_string(current, bindings, os_available) is not None:
                continue
            return False
        return True

    def _node_has_unreviewed_execution(
        self,
        root: ast.AST,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
        reviewed_callable_names: set[str] | None = None,
    ) -> bool:
        """Recognize execution that can mutate process-global runtime state."""

        pending = [root]
        while pending:
            node = pending.pop()
            if not _visit_runtime_node(node):
                return True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.decorator_list:
                    return True
                pending.extend(_definition_eager_nodes(node))
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if _is_reviewed_static_import(node):
                    continue
                return True
            if isinstance(node, ast.Lambda):
                pending.extend(_definition_eager_nodes(node))
                continue
            if isinstance(node, ast.ClassDef):
                if node.decorator_list or node.bases or node.keywords:
                    return True
                pending.extend(node.body)
                continue
            if isinstance(node, (ast.With, ast.AsyncWith)):
                pending.extend(item.context_expr for item in node.items)
                pending.extend(node.body)
                continue
            if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
                return True
            if isinstance(node, ast.Attribute) and node.attr == "modules":
                # Loading an import-cache mapping lets this statement replace
                # a later ``import os`` with an arbitrary module object.
                return True
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
                first_iterable = node.generators[0].iter if node.generators else None
                if isinstance(first_iterable, (ast.Tuple, ast.List, ast.Set)) and not first_iterable.elts:
                    pending.append(first_iterable)
                    continue
                return True
            if isinstance(node, ast.GeneratorExp):
                if node.generators:
                    pending.append(node.generators[0].iter)
                continue
            if isinstance(node, ast.Call):
                if (
                    reviewed_callable_names
                    and isinstance(node.func, ast.Name)
                    and node.func.id in reviewed_callable_names
                ):
                    pending.extend(node.args)
                    pending.extend(keyword.value for keyword in node.keywords)
                    continue
                if isinstance(node.func, ast.Lambda):
                    pending.extend(_definition_eager_nodes(node.func))
                    pending.extend(node.args)
                    pending.extend(keyword.value for keyword in node.keywords)
                    pending.append(node.func.body)
                    continue
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "open"
                    and self._reviewed_open_path(node, bindings, os_available, open_available) is not None
                ):
                    continue
                if (
                    os_available
                    and _is_direct_os_path_join(node)
                    and self._exact_string(
                        node,
                        bindings,
                        os_available,
                    )
                    is not None
                ):
                    continue
                if (
                    os_available
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "exists"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "path"
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "os"
                    and len(node.args) == 1
                    and not node.keywords
                    and self._exact_string(node.args[0], bindings, os_available) is not None
                ):
                    continue
                return True
            pending.extend(ast.iter_child_nodes(node))
        return False

    def _node_has_unreviewed_patch_execution(
        self,
        root: ast.AST,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
        patch_factory_names: set[str],
    ) -> bool:
        """Recognize hooks that can alter a previously imported patch factory."""

        pending = [root]
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                pending.extend(_definition_eager_nodes(node))
                continue
            if isinstance(node, ast.ClassDef):
                pending.extend(_definition_eager_nodes(node))
                pending.extend(node.body)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if _is_reviewed_static_import(node):
                    continue
                return True
            if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
                return True
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return True
            if isinstance(node, ast.Call):
                if _is_reviewed_patch_factory_call(node, patch_factory_names):
                    continue
                if isinstance(node.func, ast.Lambda):
                    pending.extend(_definition_eager_nodes(node.func))
                    pending.extend(node.args)
                    pending.extend(keyword.value for keyword in node.keywords)
                    pending.append(node.func.body)
                    continue
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"globals", "locals", "vars"}
                    and not node.args
                    and not node.keywords
                ):
                    continue
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "open"
                    and self._reviewed_open_path(node, bindings, os_available, open_available) is not None
                ):
                    continue
                if (
                    os_available
                    and _is_direct_os_path_join(node)
                    and self._exact_string(
                        node,
                        bindings,
                        os_available,
                    )
                    is not None
                ):
                    continue
                if (
                    os_available
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "exists"
                    and _is_reviewed_os_path_attribute(node.func)
                    and len(node.args) == 1
                    and not node.keywords
                    and self._exact_string(node.args[0], bindings, os_available) is not None
                ):
                    continue
                return True
            if isinstance(node, ast.Attribute):
                if os_available and _is_reviewed_os_path_attribute(node):
                    continue
                return True
            if isinstance(node, ast.Subscript):
                if (
                    isinstance(node.value, (ast.Tuple, ast.List))
                    and isinstance(node.ctx, ast.Load)
                    and isinstance(node.slice, ast.Constant)
                    and type(node.slice.value) is int
                    and -len(node.value.elts) <= node.slice.value < len(node.value.elts)
                ):
                    pending.extend(node.value.elts)
                    continue
                return True
            if isinstance(node, ast.BinOp):
                if self._exact_string(node, bindings, os_available) is not None:
                    continue
                return True
            if isinstance(node, (ast.BoolOp, ast.Compare, ast.IfExp, ast.UnaryOp)):
                return True
            if isinstance(node, ast.Dict):
                if any(key is None or not _has_inert_literal_hash(key) for key in node.keys):
                    return True
                pending.extend(key for key in node.keys if key is not None)
                pending.extend(node.values)
                continue
            if isinstance(node, ast.Set):
                if any(
                    isinstance(element, ast.Starred) or not _has_inert_literal_hash(element) for element in node.elts
                ):
                    return True
                continue
            if isinstance(node, (ast.List, ast.Tuple)):
                if any(isinstance(element, ast.Starred) for element in node.elts):
                    return True
                pending.extend(node.elts)
                continue
            if isinstance(node, (ast.FormattedValue, ast.JoinedStr, ast.Starred)):
                return True
            pending.extend(ast.iter_child_nodes(node))
        return False

    def _record_direct_open(
        self,
        expression: ast.expr,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
        reviewed_json_modules: set[str],
    ) -> bool:
        direct_call = (
            expression.value
            if isinstance(expression, ast.Await) and isinstance(expression.value, ast.Call)
            else expression
        )
        is_direct = (
            isinstance(direct_call, ast.Call)
            and isinstance(direct_call.func, ast.Name)
            and direct_call.func.id == "open"
        )
        state = _ExpressionReadState(
            dict(bindings),
            os_available,
            open_available,
            set(reviewed_json_modules),
        )
        self._scan_eager_expression_opens(expression, state, depth=0)
        return is_direct

    def _scan_eager_expression_opens(
        self,
        node: ast.AST,
        state: _ExpressionReadState,
        *,
        depth: int,
    ) -> None:
        """Scan one expression in runtime order until positive evidence is lost."""

        if depth > MAX_PYTHON_PATH_VALUE_DEPTH or not _visit_runtime_node(node):
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        child_depth = depth + 1
        if isinstance(node, (ast.Constant, ast.Name)):
            return
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                self._scan_eager_expression_opens(value, state, depth=child_depth)
                truth = self._known_expression_truth(value, state)
                if truth is None:
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
                    return
                if (isinstance(node.op, ast.And) and not truth) or (isinstance(node.op, ast.Or) and truth):
                    return
            return
        if isinstance(node, ast.IfExp):
            self._scan_eager_expression_opens(node.test, state, depth=child_depth)
            truth = self._known_expression_truth(node.test, state)
            if truth is None:
                state.bindings.clear()
                state.os_available = False
                state.open_available = False
                return
            self._scan_eager_expression_opens(node.body if truth else node.orelse, state, depth=child_depth)
            return
        if isinstance(node, ast.Compare):
            self._scan_eager_expression_opens(node.left, state, depth=child_depth)
            left = node.left
            for operator, comparator in zip(node.ops, node.comparators, strict=True):
                self._scan_eager_expression_opens(comparator, state, depth=child_depth)
                comparison = self._known_comparison_result(left, operator, comparator, state)
                if comparison is not True:
                    if comparison is None:
                        state.bindings.clear()
                        state.os_available = False
                        state.open_available = False
                    return
                left = comparator
            return
        if isinstance(node, ast.NamedExpr):
            self._scan_eager_expression_opens(node.value, state, depth=child_depth)
            named_value = self._exact_string(node.value, state.bindings, state.os_available)
            target_name = node.target.id
            state.bindings.pop(target_name, None)
            if target_name == "os":
                state.os_available = False
            if target_name == "open":
                state.open_available = False
            state.reviewed_json_modules.discard(target_name)
            if named_value is not None:
                state.bindings[target_name] = named_value
            return
        if isinstance(node, ast.Lambda):
            for default in node.args.defaults:
                self._scan_eager_expression_opens(default, state, depth=child_depth)
            for keyword_default in node.args.kw_defaults:
                if keyword_default is not None:
                    self._scan_eager_expression_opens(keyword_default, state, depth=child_depth)
            return
        if isinstance(node, ast.Call):
            immediate_lambda = node.func if isinstance(node.func, ast.Lambda) else None
            reviewed_path_join_identity = state.os_available and _is_direct_os_path_join(node)
            reviewed_json_load_identity = _is_reviewed_json_load(
                node,
                state.reviewed_json_modules,
            )
            reviewed_path_exists_identity = (
                state.os_available
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "exists"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "path"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "os"
            )
            direct_open_state = (
                (dict(state.bindings), state.os_available, state.open_available)
                if isinstance(node.func, ast.Name) and node.func.id == "open"
                else None
            )
            captured_defaults: dict[str, str] = {}
            if immediate_lambda is None:
                if not (reviewed_path_join_identity or reviewed_path_exists_identity or reviewed_json_load_identity):
                    self._scan_eager_expression_opens(node.func, state, depth=child_depth)
            else:
                captured_defaults = self._scan_lambda_defaults(
                    immediate_lambda,
                    state,
                    depth=child_depth,
                )
            argument_values: list[str | None] = []
            for argument in node.args:
                self._scan_eager_expression_opens(argument, state, depth=child_depth)
                argument_values.append(self._exact_string(argument, state.bindings, state.os_available))
            keyword_values: list[tuple[str | None, str | None]] = []
            for keyword in node.keywords:
                self._scan_eager_expression_opens(keyword.value, state, depth=child_depth)
                keyword_values.append(
                    (
                        keyword.arg,
                        self._exact_string(keyword.value, state.bindings, state.os_available),
                    )
                )
                if keyword.arg is None:
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
                    state.reviewed_json_modules.clear()
            if immediate_lambda is not None and self._scan_immediate_lambda_body(
                immediate_lambda,
                node,
                state,
                captured_defaults,
                argument_values,
                keyword_values,
                depth=child_depth,
            ):
                return
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                assert direct_open_state is not None
                open_bindings, open_os_available, open_available = direct_open_state
                self._record_open(
                    node,
                    open_bindings,
                    open_os_available,
                    open_available,
                )
                if (
                    self._reviewed_open_path(
                        node,
                        open_bindings,
                        open_os_available,
                        open_available,
                    )
                    is None
                ):
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
                    state.reviewed_json_modules.clear()
                return
            if (
                reviewed_path_join_identity
                and self._exact_string(
                    node,
                    state.bindings,
                    state.os_available,
                )
                is not None
            ):
                return
            if (
                reviewed_path_exists_identity
                and len(node.args) == 1
                and not node.keywords
                and self._exact_string(node.args[0], state.bindings, state.os_available) is not None
            ):
                return
            state.bindings.clear()
            state.os_available = False
            # Any unreviewed call can mutate module globals or builtins before
            # a later eager read, even without spelling a tracked helper.
            state.open_available = False
            return
        if isinstance(node, ast.GeneratorExp):
            if node.generators:
                self._scan_eager_expression_opens(node.generators[0].iter, state, depth=child_depth)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            self._scan_eager_comprehension_opens(node, state, depth=child_depth)
            return
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    self._scan_eager_expression_opens(value, state, depth=child_depth)
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
                    continue
                self._scan_eager_expression_opens(key, state, depth=child_depth)
                if not _has_inert_literal_hash(key):
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
                self._scan_eager_expression_opens(value, state, depth=child_depth)
            return
        if isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                value = element.value if isinstance(element, ast.Starred) else element
                self._scan_eager_expression_opens(value, state, depth=child_depth)
                if isinstance(element, ast.Starred):
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
            return
        if isinstance(node, ast.Set):
            for element in node.elts:
                value = element.value if isinstance(element, ast.Starred) else element
                self._scan_eager_expression_opens(value, state, depth=child_depth)
                if isinstance(element, ast.Starred) or not _has_inert_literal_hash(element):
                    state.bindings.clear()
                    state.os_available = False
                    state.open_available = False
            return
        if isinstance(node, ast.Attribute):
            if state.os_available and _is_reviewed_os_path_attribute(node):
                return
            self._scan_eager_expression_opens(node.value, state, depth=child_depth)
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        if isinstance(node, ast.Subscript):
            self._scan_eager_expression_opens(node.value, state, depth=child_depth)
            self._scan_eager_expression_opens(node.slice, state, depth=child_depth)
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        if isinstance(node, ast.BinOp):
            self._scan_eager_expression_opens(node.left, state, depth=child_depth)
            self._scan_eager_expression_opens(node.right, state, depth=child_depth)
            if self._exact_string(node, state.bindings, state.os_available) is None:
                state.bindings.clear()
                state.os_available = False
                state.open_available = False
            return
        if isinstance(node, ast.UnaryOp):
            self._scan_eager_expression_opens(node.operand, state, depth=child_depth)
            if self._known_expression_truth(node, state) is None:
                state.bindings.clear()
                state.os_available = False
                state.open_available = False
            return
        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
            suspended_value = getattr(node, "value", None)
            if suspended_value is not None:
                self._scan_eager_expression_opens(suspended_value, state, depth=child_depth)
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        if isinstance(node, ast.Slice):
            for component in (node.lower, node.upper, node.step):
                if component is not None:
                    self._scan_eager_expression_opens(component, state, depth=child_depth)
            return
        for child in ast.iter_child_nodes(node):
            self._scan_eager_expression_opens(child, state, depth=child_depth)
        state.bindings.clear()
        state.os_available = False
        state.open_available = False

    def _scan_assignment_target(
        self,
        target: ast.AST,
        assigned_value: str | None,
        state: _ExpressionReadState,
        *,
        depth: int,
        address_already_scanned: bool = False,
    ) -> None:
        """Apply one assignment target after its right-hand side is evaluated."""

        if depth > MAX_PYTHON_PATH_VALUE_DEPTH:
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        if isinstance(target, ast.Name):
            state.bindings.pop(target.id, None)
            if target.id == "os":
                state.os_available = False
            if target.id == "open":
                state.open_available = False
            state.reviewed_json_modules.discard(target.id)
            if assigned_value is not None:
                state.bindings[target.id] = assigned_value
            return
        if isinstance(target, ast.Starred):
            self._scan_assignment_target(target.value, None, state, depth=depth + 1)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            # Unpacking can fail before Python evaluates any nested target
            # address. Without an exact shape proof, no later address read is
            # guaranteed to execute.
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            state.reviewed_json_modules.clear()
            return
        if not address_already_scanned:
            self._scan_eager_expression_opens(target, state, depth=depth + 1)
        state.bindings.clear()
        state.os_available = False
        state.open_available = False

    def _scan_delete_target(
        self,
        target: ast.AST,
        state: _ExpressionReadState,
        *,
        depth: int,
    ) -> None:
        """Evaluate and apply delete targets in their left-to-right order."""

        if depth > MAX_PYTHON_PATH_VALUE_DEPTH:
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        if isinstance(target, ast.Name):
            state.bindings.pop(target.id, None)
            if target.id == "os":
                state.os_available = False
            if target.id == "open":
                state.open_available = False
            state.reviewed_json_modules.discard(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._scan_delete_target(element, state, depth=depth + 1)
            return
        self._scan_eager_expression_opens(target, state, depth=depth + 1)
        state.bindings.clear()
        state.os_available = False
        state.open_available = False

    def _scan_lambda_defaults(
        self,
        function: ast.Lambda,
        state: _ExpressionReadState,
        *,
        depth: int,
    ) -> dict[str, str]:
        """Evaluate lambda defaults once and retain exact captured strings."""

        captured: dict[str, str] = {}
        positional = [*function.args.posonlyargs, *function.args.args]
        defaulted_positional = positional[len(positional) - len(function.args.defaults) :]
        for argument, default in zip(defaulted_positional, function.args.defaults, strict=True):
            self._scan_eager_expression_opens(default, state, depth=depth)
            exact_default = self._exact_string(default, state.bindings, state.os_available)
            if exact_default is not None:
                captured[argument.arg] = exact_default
        for argument, keyword_default in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True):
            if keyword_default is None:
                continue
            self._scan_eager_expression_opens(keyword_default, state, depth=depth)
            exact_default = self._exact_string(keyword_default, state.bindings, state.os_available)
            if exact_default is not None:
                captured[argument.arg] = exact_default
        return captured

    def _scan_immediate_lambda_body(
        self,
        function: ast.Lambda,
        call: ast.Call,
        state: _ExpressionReadState,
        captured_defaults: dict[str, str],
        argument_values: list[str | None],
        keyword_values: list[tuple[str | None, str | None]],
        *,
        depth: int,
    ) -> bool:
        """Interpret a directly invoked lambda with statically bound arguments."""

        positional = [*function.args.posonlyargs, *function.args.args]
        if (
            any(isinstance(argument, ast.Starred) for argument in call.args)
            or any(keyword.arg is None for keyword in call.keywords)
            or function.args.vararg is not None
            or function.args.kwarg is not None
            or len(call.args) > len(positional)
        ):
            return False
        parameter_names = {argument.arg for argument in (*positional, *function.args.kwonlyargs)}
        local_names = parameter_names | _lambda_body_local_names(function.body)
        bound_values: dict[str, str] = {}
        bound_runtime_helpers: set[str] = set()
        bound_names: set[str] = set()
        for argument, value, expression in zip(positional, argument_values, call.args, strict=False):
            bound_names.add(argument.arg)
            if value is not None:
                bound_values[argument.arg] = value
            if (
                isinstance(expression, ast.Name)
                and expression.id in self.runtime_budget.possible_helpers
                or _is_direct_builtins_import_call(expression)
            ):
                bound_runtime_helpers.add(argument.arg)

        positional_only = {argument.arg for argument in function.args.posonlyargs}
        parameters = parameter_names
        for (keyword_name, value), keyword in zip(keyword_values, call.keywords, strict=True):
            if (
                keyword_name is None
                or keyword_name not in parameters
                or keyword_name in positional_only
                or keyword_name in bound_names
            ):
                return False
            bound_names.add(keyword_name)
            if value is not None:
                bound_values[keyword_name] = value
            if (
                isinstance(keyword.value, ast.Name)
                and keyword.value.id in self.runtime_budget.possible_helpers
                or _is_direct_builtins_import_call(keyword.value)
            ):
                bound_runtime_helpers.add(keyword_name)

        first_default = len(positional) - len(function.args.defaults)
        for index, argument in enumerate(positional):
            if argument.arg in bound_names:
                continue
            if index < first_default:
                return False
            bound_names.add(argument.arg)
            if argument.arg in captured_defaults:
                bound_values[argument.arg] = captured_defaults[argument.arg]
            default = function.args.defaults[index - first_default]
            if (
                isinstance(default, ast.Name)
                and default.id in self.runtime_budget.possible_helpers
                or _is_direct_builtins_import_call(default)
            ):
                bound_runtime_helpers.add(argument.arg)
        for argument, keyword_default in zip(
            function.args.kwonlyargs,
            function.args.kw_defaults,
            strict=True,
        ):
            if argument.arg in bound_names:
                continue
            if keyword_default is None:
                return False
            bound_names.add(argument.arg)
            if argument.arg in captured_defaults:
                bound_values[argument.arg] = captured_defaults[argument.arg]
            if (
                isinstance(keyword_default, ast.Name)
                and keyword_default.id in self.runtime_budget.possible_helpers
                or _is_direct_builtins_import_call(keyword_default)
            ):
                bound_runtime_helpers.add(argument.arg)

        child_state = _ExpressionReadState(
            {name: value for name, value in state.bindings.items() if name not in local_names},
            state.os_available and "os" not in local_names,
            state.open_available and "open" not in local_names,
            {name for name in state.reviewed_json_modules if name not in local_names},
        )
        child_state.bindings.update(bound_values)
        self._scan_eager_expression_opens(function.body, child_state, depth=depth)
        lambda_module_names = self.runtime_budget.possible_os_modules - local_names
        lambda_path_names = self.runtime_budget.possible_os_paths - local_names
        lambda_has_unreviewed_execution = self._node_has_unreviewed_execution(
            function.body,
            child_state.bindings,
            child_state.os_available,
            child_state.open_available,
        )
        if lambda_has_unreviewed_execution:
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
        else:
            state.os_available = state.os_available and child_state.os_available
            state.open_available = state.open_available and child_state.open_available
            outer_names = set(state.bindings) - local_names
            if not outer_names.issubset(child_state.bindings):
                state.bindings.clear()
        if (
            lambda_has_unreviewed_execution
            or _node_may_replace_os_path_join(
                function.body,
                lambda_module_names,
                lambda_path_names,
            )
            or _node_escapes_os_path_identity(
                function.body,
                lambda_module_names,
                lambda_path_names,
            )
        ):
            state.os_available = False
        helper_names = self.runtime_budget.possible_helpers - (local_names - bound_runtime_helpers)
        if _node_may_replace_runtime_open(
            function.body,
            helper_names,
            "globals" not in local_names,
        ) or _node_escapes_runtime_identity(
            function.body,
            helper_names,
            "globals" not in local_names,
        ):
            state.open_available = False
        return True

    def _scan_eager_comprehension_opens(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp,
        state: _ExpressionReadState,
        *,
        depth: int,
    ) -> None:
        """Scan an eager comprehension only when one iteration is certain."""

        if len(node.generators) != 1 or node.generators[0].is_async:
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        generator = node.generators[0]
        self._scan_eager_expression_opens(generator.iter, state, depth=depth)
        if isinstance(generator.iter, (ast.Tuple, ast.List, ast.Set)) and not generator.iter.elts:
            return
        if not isinstance(generator.iter, (ast.Tuple, ast.List, ast.Set)):
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        if not isinstance(generator.target, ast.Name):
            state.bindings.clear()
            state.os_available = False
            state.open_available = False
            return
        child_state = _ExpressionReadState(
            dict(state.bindings),
            state.os_available,
            state.open_available,
            set(state.reviewed_json_modules),
        )
        for name in tuple(child_state.bindings):
            if _node_binds_name(generator.target, name):
                child_state.bindings.pop(name, None)
        if _node_binds_name(generator.target, "os"):
            child_state.os_available = False
        if _node_binds_name(generator.target, "open"):
            child_state.open_available = False
        child_state.reviewed_json_modules.difference_update(
            name for name in tuple(child_state.reviewed_json_modules) if _node_binds_name(generator.target, name)
        )
        target_name = generator.target.id

        def project_reviewed_json_modules() -> None:
            for name in tuple(state.reviewed_json_modules):
                if name != target_name and name not in child_state.reviewed_json_modules:
                    state.reviewed_json_modules.discard(name)

        for condition in generator.ifs:
            self._scan_eager_expression_opens(condition, child_state, depth=depth)
            truth = self._known_expression_truth(condition, child_state)
            if truth is False:
                state.os_available = state.os_available and child_state.os_available
                state.open_available = state.open_available and child_state.open_available
                state.bindings.clear()
                project_reviewed_json_modules()
                return
            if truth is None:
                state.bindings.clear()
                state.os_available = False
                state.open_available = False
                state.reviewed_json_modules.clear()
                return
        hash_value: ast.expr | None
        if isinstance(node, ast.DictComp):
            self._scan_eager_expression_opens(node.key, child_state, depth=depth)
            self._scan_eager_expression_opens(node.value, child_state, depth=depth)
            hash_value = node.key
        else:
            self._scan_eager_expression_opens(node.elt, child_state, depth=depth)
            hash_value = node.elt if isinstance(node, ast.SetComp) else None
        if hash_value is not None and not _has_inert_literal_hash(hash_value):
            child_state.bindings.clear()
            child_state.os_available = False
            child_state.open_available = False
            child_state.reviewed_json_modules.clear()
        state.os_available = state.os_available and child_state.os_available
        state.open_available = state.open_available and child_state.open_available
        state.bindings.clear()
        project_reviewed_json_modules()

    def _known_expression_truth(
        self,
        node: ast.AST,
        state: _ExpressionReadState,
    ) -> bool | None:
        inverted = False
        unary_depth = 0
        while isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            unary_depth += 1
            if unary_depth > MAX_PYTHON_PATH_VALUE_DEPTH:
                return None
            inverted = not inverted
            node = node.operand

        result: bool | None
        if isinstance(node, ast.Constant):
            result = bool(node.value)
        elif isinstance(node, ast.Lambda) and not node.args.defaults and not any(node.args.kw_defaults):
            result = True
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = bool(node.elts)
        elif isinstance(node, ast.Dict):
            result = bool(node.keys)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
            and self._reviewed_open_path(
                node,
                state.bindings,
                state.os_available,
                state.open_available,
            )
            is not None
        ):
            result = True
        else:
            exact_value = self._exact_string(node, state.bindings, state.os_available)
            result = bool(exact_value) if exact_value is not None else None
        if result is None:
            return None
        return not result if inverted else result

    def _known_comparison_result(
        self,
        left: ast.AST,
        operator: ast.cmpop,
        right: ast.AST,
        state: _ExpressionReadState,
    ) -> bool | None:
        left_known, left_value = self._known_expression_value(left, state)
        right_known, right_value = self._known_expression_value(right, state)
        if not left_known or not right_known:
            return None
        try:
            if isinstance(operator, ast.Eq):
                return left_value == right_value
            if isinstance(operator, ast.NotEq):
                return left_value != right_value
            if isinstance(operator, ast.Lt):
                return bool(left_value < right_value)  # type: ignore[operator]
            if isinstance(operator, ast.LtE):
                return bool(left_value <= right_value)  # type: ignore[operator]
            if isinstance(operator, ast.Gt):
                return bool(left_value > right_value)  # type: ignore[operator]
            if isinstance(operator, ast.GtE):
                return bool(left_value >= right_value)  # type: ignore[operator]
            if isinstance(operator, ast.Is):
                if not self._is_identity_singleton(left_value) or not self._is_identity_singleton(right_value):
                    return None
                return left_value is right_value
            if isinstance(operator, ast.IsNot):
                if not self._is_identity_singleton(left_value) or not self._is_identity_singleton(right_value):
                    return None
                return left_value is not right_value
        except (TypeError, ValueError):
            return None
        return None

    @staticmethod
    def _is_identity_singleton(value: object) -> bool:
        return value is None or value is True or value is False or value is Ellipsis

    def _known_expression_value(
        self,
        node: ast.AST,
        state: _ExpressionReadState,
    ) -> tuple[bool, object]:
        if isinstance(node, ast.Constant) and isinstance(
            node.value,
            (bytes, complex, float, int, str, type(None)),
        ):
            return True, node.value
        exact_value = self._exact_string(node, state.bindings, state.os_available)
        if exact_value is not None:
            return True, exact_value
        return False, None

    def _is_exact_path_exists_guard(
        self,
        statement: ast.If,
        bindings: dict[str, str],
        os_available: bool,
    ) -> bool:
        if statement.orelse or not os_available:
            return False
        test = statement.test
        if (
            not isinstance(test, ast.Call)
            or len(test.args) != 1
            or test.keywords
            or isinstance(test.args[0], ast.Starred)
        ):
            return False
        if not (
            isinstance(test.func, ast.Attribute)
            and test.func.attr == "exists"
            and _is_reviewed_os_path_attribute(test.func)
        ):
            return False
        return self._exact_string(test.args[0], bindings, os_available) is not None

    def _record_open(
        self,
        call: ast.Call,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
    ) -> None:
        normalized_path = self._reviewed_open_path(call, bindings, os_available, open_available)
        if normalized_path is None or not _is_sensitive_path(normalized_path):
            return
        line_number = getattr(call.func, "lineno", 0)
        end_line_number = getattr(call.func, "end_lineno", 0)
        byte_start = getattr(call.func, "col_offset", -1)
        byte_end = getattr(call.func, "end_col_offset", -1)
        if (
            line_number in self.candidate_lines
            or not 1 <= line_number <= len(self.lines)
            or end_line_number != line_number
            or not 0 <= byte_start <= byte_end
        ):
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
            PythonSensitiveFileReadCandidate(
                path=normalized_path,
                line_number=line_number,
                start_column=start_column,
                end_column=end_column,
            )
        )
        self.candidate_lines.add(line_number)

    def _reviewed_open_path(
        self,
        call: ast.Call,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
    ) -> str | None:
        """Resolve a call whose arguments cannot dispatch user code."""

        if not open_available or len(call.args) > 2 or any(isinstance(argument, ast.Starred) for argument in call.args):
            return None
        if any(keyword.arg is None or keyword.arg not in _OPEN_KEYWORDS for keyword in call.keywords):
            return None
        keyword_names = [keyword.arg for keyword in call.keywords]
        if len(keyword_names) != len(set(keyword_names)):
            return None
        if any(keyword.arg == "opener" for keyword in call.keywords):
            return None
        file_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "file"]
        mode_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "mode"]
        closefd_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "closefd"]
        if closefd_keywords and not (
            isinstance(closefd_keywords[0], ast.Constant) and closefd_keywords[0].value is True
        ):
            return None
        if (call.args and file_keywords) or (len(call.args) >= 2 and mode_keywords):
            return None
        if any(not self._expression_is_inert(argument, bindings, os_available) for argument in call.args):
            return None
        if any(not self._expression_is_inert(keyword.value, bindings, os_available) for keyword in call.keywords):
            return None

        path_node = call.args[0] if call.args else (file_keywords[0] if file_keywords else None)
        mode_node = call.args[1] if len(call.args) >= 2 else (mode_keywords[0] if mode_keywords else None)
        path = self._exact_string(path_node, bindings, os_available)
        if path is None or "\x00" in path:
            return None
        if mode_node is not None:
            mode = self._exact_string(mode_node, bindings, os_available)
            if mode not in _READ_ONLY_MODES:
                return None
        else:
            mode = "r"

        keyword_values = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg is not None}
        buffering_node = keyword_values.get("buffering")
        if buffering_node is not None:
            buffering = self._literal_int(buffering_node)
            if buffering is None or not -1 <= buffering <= _MAX_C_INT:
                return None
            if buffering == 0 and "b" not in mode:
                return None
        for keyword_name in ("encoding", "errors"):
            value_node = keyword_values.get(keyword_name)
            if value_node is not None and not (isinstance(value_node, ast.Constant) and value_node.value is None):
                return None
        newline_node = keyword_values.get("newline")
        if newline_node is not None and not (
            isinstance(newline_node, ast.Constant) and newline_node.value in {None, "", "\n", "\r", "\r\n"}
        ):
            return None
        if "b" in mode and any(name in keyword_values for name in ("encoding", "errors", "newline")):
            return None
        return _normalize_path(path)

    @staticmethod
    def _literal_int(node: ast.AST) -> int | None:
        """Return an exact integer literal without invoking conversion hooks."""

        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.USub)
            and isinstance(node.operand, ast.Constant)
            and type(node.operand.value) is int
        ):
            return -node.operand.value
        return None

    @staticmethod
    def _enforce_binding_limit(bindings: dict[str, str]) -> None:
        if len(bindings) > MAX_PYTHON_PATH_BINDINGS:
            bindings.clear()
