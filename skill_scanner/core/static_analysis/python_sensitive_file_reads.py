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
built-in ``open`` in a proven read-only mode. Effects and compound flow erase
all path facts rather than being interpreted.
"""

from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass

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
    exhausted: bool = False

    def visit(self) -> bool:
        if self.remaining <= 0:
            self.exhausted = True
            return False
        self.remaining -= 1
        return True

    def is_exhausted(self) -> bool:
        return self.exhausted


_RUNTIME_BUDGET_ATTR = "_skill_scanner_runtime_budget"
_AST_SINGLETON_TYPES = (ast.boolop, ast.cmpop, ast.expr_context, ast.operator, ast.unaryop)


def find_constructed_sensitive_file_reads(
    source: str,
    filename: str = "<unknown>",
) -> tuple[PythonSensitiveFileReadCandidate, ...]:
    """Find bounded, straight-line sensitive-path reads in Python source."""

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

    scanner = _StraightLineSensitiveReadScanner(source, runtime_budget)
    scanner.scan(tree)
    if runtime_budget.is_exhausted():
        return ()
    return tuple(scanner.candidates)


def _prepare_bounded_ast(tree: ast.AST) -> _RuntimeProvenanceBudget | None:
    budget = _RuntimeProvenanceBudget(
        MAX_PYTHON_PATH_RUNTIME_PROVENANCE_WORK,
        {"__builtins__"},
    )
    alias_edges: dict[str, list[str]] = {}
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
        if isinstance(node, ast.Import):
            budget.possible_helpers.update(
                _bound_import_name(imported) for imported in node.names if imported.name == "builtins"
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
        if (
            edge_count > MAX_PYTHON_PATH_BINDINGS
            or len(budget.possible_helpers) > MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES
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
    return budget


def _visit_runtime_node(node: ast.AST) -> bool:
    budget = getattr(node, _RUNTIME_BUDGET_ATTR, None)
    return not isinstance(budget, _RuntimeProvenanceBudget) or budget.visit()


def _possible_runtime_helpers(node: ast.AST, *, include_globals: bool = False) -> set[str]:
    budget = getattr(node, _RUNTIME_BUDGET_ATTR, None)
    names = set(budget.possible_helpers) if isinstance(budget, _RuntimeProvenanceBudget) else {"__builtins__"}
    return names | ({"globals"} if include_globals else set())


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
            "id_ed25519",
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
        arguments = node.args
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
            if argument.annotation is not None:
                eager.append(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            eager.append(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            eager.append(arguments.kwarg.annotation)
        eager.extend(arguments.defaults)
        eager.extend(default for default in arguments.kw_defaults if default is not None)
        if node.returns is not None:
            eager.append(node.returns)
        eager.extend(getattr(node, "type_params", ()))
    elif isinstance(node, ast.ClassDef):
        eager.extend(node.decorator_list)
        eager.extend(node.bases)
        eager.extend(keyword.value for keyword in node.keywords)
        eager.extend(getattr(node, "type_params", ()))
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
    local_names.update(name for name in builtins_names if _node_binds_name(node.body, name))
    return builtins_names - local_names


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


def _node_loads_runtime_helper(root: ast.AST, builtins_names: set[str]) -> bool:
    """Return whether eager evaluation loads a reviewed builtins identity."""

    pending = [root]
    while pending:
        node = pending.pop()
        if not _visit_runtime_node(node):
            return True
        if isinstance(node, ast.Call):
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
        if isinstance(node, (ast.Global, ast.Nonlocal)) and "open" in node.names:
            declares_external_open = True
            break
        pending.extend(ast.iter_child_nodes(node))
    return declares_external_open and any(
        not isinstance(statement, (ast.Global, ast.Nonlocal)) and _node_binds_name(statement, "open")
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
    return bool(statement.bases) or any(keyword.arg in {None, "metaclass"} for keyword in statement.keywords)


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


class _StraightLineSensitiveReadScanner:
    def __init__(self, source: str, runtime_budget: _RuntimeProvenanceBudget) -> None:
        self.lines = source.split("\n")
        self.candidates: list[PythonSensitiveFileReadCandidate] = []
        self.candidate_lines: set[int] = set()
        self.runtime_budget = runtime_budget

    def scan(self, tree: ast.Module) -> None:
        # Module code executes eagerly, so an early call can still resolve the
        # builtin before a later module assignment. Delayed functions are more
        # conservative because they can run after all module statements.
        self._scan_body(
            tree.body,
            depth=0,
            builtin_open=True,
            delayed_builtin_open=not _scope_may_shadow_open(tree.body),
        )

    def _scan_body(
        self,
        body: list[ast.stmt],
        *,
        depth: int,
        builtin_open: bool,
        delayed_builtin_open: bool,
        class_scope: bool = False,
        initial_runtime_helpers: set[str] | None = None,
        initial_globals_is_builtin: bool = True,
        eager_lexical_builtin_open: bool | None = None,
    ) -> None:
        if depth > MAX_PYTHON_PATH_SCOPE_DEPTH or len(self.candidates) >= MAX_PYTHON_PATH_CANDIDATES:
            return

        bindings: dict[str, str] = {}
        os_available = False
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

            statement_binds_open = not isinstance(statement, (ast.Global, ast.Nonlocal)) and _node_binds_name(
                statement,
                "open",
            )
            exact_class_helper = (
                isinstance(statement, ast.Import)
                and any(imported.name == "builtins" for imported in statement.names)
                or bool(_assigned_runtime_helper_names(statement, builtins_names))
            )
            class_identity_diverges = (
                class_scope
                and not isinstance(
                    statement,
                    (ast.Global, ast.Nonlocal),
                )
                and not exact_class_helper
                and any(
                    _node_binds_name(statement, name)
                    for name in _possible_runtime_helpers(statement, include_globals=True)
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
                statement,
                statement_runtime_helpers,
                statement_globals_is_builtin,
            )
            runtime_open_replaced, builtins_names, globals_is_builtin, identities_complete = (
                _summarize_runtime_open_effects(
                    [statement],
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
            if class_identity_diverges:
                # Methods, nested classes, and comprehensions skip this class
                # namespace. A local shadow therefore makes the shared runtime
                # helper provenance ambiguous from the following statement.
                delayed_open_available = False
                pending_runtime_open_invalidation = True

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Delayed scopes receive no path or import facts. The only
                # inherited marker prevents a module/enclosing ``open``
                # binding from being mistaken for the built-in.
                function_open_available = delayed_open_available and _function_can_use_builtin_open(statement)
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=function_open_available,
                    delayed_builtin_open=(
                        function_open_available and not _scope_may_replace_runtime_open(statement.body)
                    ),
                )
                bindings.clear()
                os_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.ClassDef):
                # A method or nested class skips the surrounding class
                # namespace. Keep class-body sequential lookup separate from
                # the enclosing lexical marker used by delayed code.
                class_open_available = (eager_lexical_open_available if class_scope else open_available) and not (
                    child_runtime_open_unavailable or (child_namespace_open_bound and not class_scope)
                )
                class_replaces_runtime_open = _scope_may_replace_runtime_open(statement.body)
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=class_open_available,
                    delayed_builtin_open=(delayed_open_available and not class_replaces_runtime_open),
                    class_scope=True,
                    initial_runtime_helpers=child_runtime_helpers,
                    initial_globals_is_builtin=child_globals_is_builtin,
                    eager_lexical_builtin_open=class_open_available,
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
                for imported in statement.names:
                    local_name = _bound_import_name(imported)
                    bindings.pop(local_name, None)
                    if local_name == "os":
                        os_available = imported.name == "os" or (
                            imported.asname is None and imported.name.startswith("os.")
                        )
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.ImportFrom):
                if any(imported.name == "*" for imported in statement.names):
                    bindings.clear()
                    os_available = False
                else:
                    for imported in statement.names:
                        local_name = imported.asname or imported.name
                        bindings.pop(local_name, None)
                        if local_name == "os":
                            os_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.Assign):
                if self._record_direct_open(statement.value, bindings, os_available, open_available):
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
                self._enforce_binding_limit(bindings)
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, ast.AnnAssign):
                if statement.value is not None and self._record_direct_open(
                    statement.value,
                    bindings,
                    os_available,
                    open_available,
                ):
                    bindings.clear()
                    os_available = False
                    if statement_binds_open:
                        invalidate_namespace_open()
                    continue
                if (
                    not isinstance(statement.target, ast.Name)
                    or not self._expression_is_inert(statement.annotation, bindings, os_available)
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
                if _augassign_target_evaluation_invalidates_runtime_open(
                    statement.target,
                    statement_runtime_helpers,
                    statement_globals_is_builtin,
                ):
                    open_available = False
                    delayed_open_available = False
                    eager_lexical_open_available = False
                if self._record_direct_open(statement.value, bindings, os_available, open_available):
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
                    self._record_direct_open(item.context_expr, bindings, os_available, open_available)
                    bindings.clear()
                    os_available = False
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
                body_binds_open = _scope_binds_open(statement.body)
                body_replaces_runtime_open = _scope_may_replace_runtime_open(statement.body)
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
                if self._record_direct_open(statement.value, bindings, os_available, open_available):
                    bindings.clear()
                    os_available = False
                elif not self._expression_is_inert(statement.value, bindings, os_available):
                    bindings.clear()
                    os_available = False
                if statement_binds_open:
                    invalidate_namespace_open()
                continue

            if isinstance(statement, (ast.Return, ast.Raise)):
                expression = statement.value if isinstance(statement, ast.Return) else statement.exc
                if expression is not None:
                    self._record_direct_open(expression, bindings, os_available, open_available)
                return

            if isinstance(statement, (ast.Break, ast.Continue)):
                return

            if isinstance(statement, ast.Pass):
                continue

            bindings.clear()
            os_available = False
            if statement_binds_open:
                invalidate_namespace_open()

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
        return _bounded_string(posixpath.join(*parts))

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

    def _record_direct_open(
        self,
        expression: ast.expr,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
    ) -> bool:
        call = (
            expression.value
            if isinstance(expression, ast.Await) and isinstance(expression.value, ast.Call)
            else expression
        )
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "open":
            return False
        self._record_open(call, bindings, os_available, open_available)
        return True

    def _record_open(
        self,
        call: ast.Call,
        bindings: dict[str, str],
        os_available: bool,
        open_available: bool,
    ) -> None:
        if not open_available or len(call.args) > 2 or any(isinstance(argument, ast.Starred) for argument in call.args):
            return
        if any(keyword.arg is None or keyword.arg not in _OPEN_KEYWORDS for keyword in call.keywords):
            return
        if any(keyword.arg == "opener" for keyword in call.keywords):
            return
        file_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "file"]
        mode_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "mode"]
        if len(file_keywords) > 1 or len(mode_keywords) > 1:
            return
        if (call.args and file_keywords) or (len(call.args) >= 2 and mode_keywords):
            return
        if any(not self._expression_is_inert(argument, bindings, os_available) for argument in call.args):
            return
        if any(not self._expression_is_inert(keyword.value, bindings, os_available) for keyword in call.keywords):
            return

        path_node = call.args[0] if call.args else (file_keywords[0] if file_keywords else None)
        mode_node = call.args[1] if len(call.args) >= 2 else (mode_keywords[0] if mode_keywords else None)
        path = self._exact_string(path_node, bindings, os_available)
        if path is None:
            return
        if mode_node is not None:
            mode = self._exact_string(mode_node, bindings, os_available)
            if mode not in _READ_ONLY_MODES:
                return

        normalized_path = _normalize_path(path)
        if not _is_sensitive_path(normalized_path):
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

    @staticmethod
    def _enforce_binding_limit(bindings: dict[str, str]) -> None:
        if len(bindings) > MAX_PYTHON_PATH_BINDINGS:
            bindings.clear()
