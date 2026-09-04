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
    if not _ast_is_bounded(tree):
        return ()

    scanner = _StraightLineSensitiveReadScanner(source)
    scanner.scan(tree)
    return tuple(scanner.candidates)


def _ast_is_bounded(tree: ast.AST) -> bool:
    pending = [tree]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_PYTHON_PATH_AST_NODES:
            return False
        pending.extend(ast.iter_child_nodes(node))
    return True


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


def _node_binds_name(root: ast.AST, name: str) -> bool:
    """Find a conservative binding without recursively entering delayed scopes."""

    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
            continue
        if isinstance(node, ast.Lambda):
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
    def __init__(self, source: str) -> None:
        self.lines = source.split("\n")
        self.candidates: list[PythonSensitiveFileReadCandidate] = []
        self.candidate_lines: set[int] = set()

    def scan(self, tree: ast.Module) -> None:
        module_uses_builtin_open = not any(_node_binds_name(statement, "open") for statement in tree.body)
        self._scan_body(tree.body, depth=0, builtin_open=module_uses_builtin_open)

    def _scan_body(self, body: list[ast.stmt], *, depth: int, builtin_open: bool) -> None:
        if depth > MAX_PYTHON_PATH_SCOPE_DEPTH or len(self.candidates) >= MAX_PYTHON_PATH_CANDIDATES:
            return

        bindings: dict[str, str] = {}
        os_available = False
        open_available = builtin_open
        external_names = {
            name for statement in body if isinstance(statement, (ast.Global, ast.Nonlocal)) for name in statement.names
        }

        for statement in body:
            if len(self.candidates) >= MAX_PYTHON_PATH_CANDIDATES:
                return

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Delayed scopes receive no path or import facts. The only
                # inherited marker prevents a module/enclosing ``open``
                # binding from being mistaken for the built-in.
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    builtin_open=open_available and _function_can_use_builtin_open(statement),
                )
                bindings.clear()
                os_available = False
                if statement.name == "open":
                    open_available = False
                continue

            if isinstance(statement, ast.ClassDef):
                self._scan_body(statement.body, depth=depth + 1, builtin_open=open_available)
                bindings.clear()
                os_available = False
                if statement.name == "open":
                    open_available = False
                continue

            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                bindings.clear()
                os_available = (
                    isinstance(statement, ast.Import)
                    and len(statement.names) == 1
                    and statement.names[0].name == "os"
                    and statement.names[0].asname is None
                )
                if _node_binds_name(statement, "open"):
                    open_available = False
                continue

            if isinstance(statement, ast.Assign):
                if self._record_direct_open(statement.value, bindings, os_available, open_available):
                    bindings.clear()
                    os_available = False
                    if any(_node_binds_name(target, "open") for target in statement.targets):
                        open_available = False
                    continue
                targets = _name_targets(statement.targets)
                if targets is None:
                    bindings.clear()
                    os_available = False
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
                    if _node_binds_name(statement.target, "open"):
                        open_available = False
                    continue
                if (
                    not isinstance(statement.target, ast.Name)
                    or not self._expression_is_inert(statement.annotation, bindings, os_available)
                    or not self._expression_is_inert(statement.value, bindings, os_available)
                ):
                    bindings.clear()
                    os_available = False
                    if _node_binds_name(statement.target, "open"):
                        open_available = False
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
                continue

            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._record_direct_open(item.context_expr, bindings, os_available, open_available)
                    bindings.clear()
                    os_available = False
                    if item.optional_vars is not None and _node_binds_name(item.optional_vars, "open"):
                        open_available = False
                self._scan_body(statement.body, depth=depth + 1, builtin_open=open_available)
                continue

            if isinstance(statement, ast.Expr):
                if self._record_direct_open(statement.value, bindings, os_available, open_available):
                    bindings.clear()
                    os_available = False
                elif not self._expression_is_inert(statement.value, bindings, os_available):
                    bindings.clear()
                    os_available = False
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
            if _node_binds_name(statement, "open"):
                open_available = False

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
