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

"""Recover commands from one narrowly reviewed repeating-XOR idiom.

This module is deliberately not a Python evaluator.  It recognizes the exact
shape of a pure helper that XORs literal bytes with a literal, repeating key,
then decodes the result as UTF-8 or ASCII.  Only literal calls to such a helper
at a reviewed shell sink are decoded.  Scanned source is never imported,
compiled, or executed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

MAX_XOR_SOURCE_BYTES = 1024 * 1024
MAX_XOR_AST_NODES = 50_000
MAX_XOR_SCOPE_DEPTH = 32
MAX_XOR_BINDINGS = 4_096
MAX_XOR_CANDIDATES = 256
MAX_XOR_IDENTIFIER_CHARS = 128
MAX_XOR_KEY_BYTES = 4_096
MAX_XOR_CIPHERTEXT_BYTES = 4_096
MAX_XOR_COMMAND_BYTES = 4_096

_REQUIRED_BUILTINS = frozenset({"bytes", "enumerate", "len"})
_SUBPROCESS_METHODS = frozenset({"Popen", "call", "run"})
_SUBPROCESS_CALL_IDENTITIES = frozenset(f"callable:subprocess.{method}" for method in _SUBPROCESS_METHODS)
_OS_SYSTEM_IDENTITY = "callable:os.system"
_SUBPROCESS_LITERAL_OPTIONS = {
    "Popen": frozenset(
        {
            "close_fds",
            "creationflags",
            "cwd",
            "encoding",
            "errors",
            "pipesize",
            "process_group",
            "restore_signals",
            "start_new_session",
            "text",
            "umask",
            "universal_newlines",
        }
    ),
    "call": frozenset(
        {
            "close_fds",
            "creationflags",
            "cwd",
            "encoding",
            "errors",
            "pipesize",
            "process_group",
            "restore_signals",
            "start_new_session",
            "text",
            "timeout",
            "umask",
            "universal_newlines",
        }
    ),
    "run": frozenset(
        {
            "capture_output",
            "check",
            "close_fds",
            "creationflags",
            "cwd",
            "encoding",
            "errors",
            "pipesize",
            "process_group",
            "restore_signals",
            "start_new_session",
            "text",
            "timeout",
            "umask",
            "universal_newlines",
        }
    ),
}


@dataclass(frozen=True, slots=True)
class DecodedPythonCommand:
    """A statically recovered command passed to a reviewed shell sink."""

    line_number: int
    command: str
    api_name: str

    @property
    def analysis_basis(self) -> str:
        """Return bounded analyzer-owned provenance for downstream metadata."""

        return "bounded_python_repeating_xor"


@dataclass(frozen=True, slots=True)
class _RepeatingXorDecoder:
    key: bytes
    encoding: str


@dataclass(slots=True)
class _ScopeFacts:
    decoders: dict[str, _RepeatingXorDecoder]
    identities: dict[str, str]
    safe_builtins: set[str]
    poisoned_modules: set[str]


def find_decoded_python_commands(source: str) -> tuple[DecodedPythonCommand, ...]:
    """Return commands proven by the bounded repeating-XOR recognizer."""

    if not source or "\x00" in source or len(source) > MAX_XOR_SOURCE_BYTES:
        return ()
    try:
        if len(source.encode("utf-8")) > MAX_XOR_SOURCE_BYTES:
            return ()
        tree = ast.parse(source)
        if not _tree_within_budget(tree):
            return ()
        scanner = _StraightLineXorScanner()
        scanner.scan(tree)
    except (MemoryError, OverflowError, RecursionError, SyntaxError, UnicodeError, ValueError):
        return ()
    return tuple(scanner.candidates)


def _tree_within_budget(tree: ast.AST) -> bool:
    pending = [tree]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_XOR_AST_NODES:
            return False
        pending.extend(ast.iter_child_nodes(node))
    return True


def _literal_bytes(expression: ast.expr) -> bytes | None:
    if isinstance(expression, ast.Constant) and type(expression.value) is bytes:
        value = expression.value
        return value if 0 < len(value) <= MAX_XOR_CIPHERTEXT_BYTES else None
    if not isinstance(expression, (ast.List, ast.Tuple)) or any(
        isinstance(element, ast.Starred) for element in expression.elts
    ):
        return None
    if not 0 < len(expression.elts) <= MAX_XOR_CIPHERTEXT_BYTES:
        return None
    values: list[int] = []
    for element in expression.elts:
        if not isinstance(element, ast.Constant) or type(element.value) is not int or not 0 <= element.value <= 255:
            return None
        values.append(element.value)
    return bytes(values)


def _is_inert_expression(expression: ast.expr | None) -> bool:
    """Accept only plain reads and construction of inert literal containers."""

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
        return False
    return True


def _is_literal_option(expression: ast.expr) -> bool:
    """Accept bounded option values whose evaluation cannot invoke source code."""

    pending = [expression]
    element_count = 0
    while pending:
        node = pending.pop()
        element_count += 1
        if element_count > MAX_XOR_CIPHERTEXT_BYTES:
            return False
        if isinstance(node, ast.Constant):
            continue
        if isinstance(node, (ast.List, ast.Tuple)):
            if any(isinstance(element, ast.Starred) for element in node.elts):
                return False
            pending.extend(node.elts)
            continue
        return False
    return True


def _definition_eager_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda,
) -> tuple[ast.AST, ...]:
    """Return definition expressions evaluated in the enclosing scope."""

    eager: list[ast.AST] = []
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        eager.extend(node.decorator_list)
        eager.extend(node.args.defaults)
        eager.extend(default for default in node.args.kw_defaults if default is not None)
        eager.extend(type_parameter for type_parameter in getattr(node, "type_params", ()))
        annotated_arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg is not None:
            annotated_arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            annotated_arguments.append(node.args.kwarg)
        eager.extend(argument.annotation for argument in annotated_arguments if argument.annotation is not None)
        if node.returns is not None:
            eager.append(node.returns)
    elif isinstance(node, ast.ClassDef):
        eager.extend(node.decorator_list)
        eager.extend(node.bases)
        eager.extend(keyword.value for keyword in node.keywords)
        eager.extend(type_parameter for type_parameter in getattr(node, "type_params", ()))
    else:
        eager.extend(node.args.defaults)
        eager.extend(default for default in node.args.kw_defaults if default is not None)
    return tuple(eager)


def _scope_unsafe_builtins(
    body: list[ast.stmt],
    arguments: ast.arguments | None = None,
    type_parameters: tuple[ast.AST, ...] = (),
) -> frozenset[str]:
    """Find lexical bindings that prevent proving the decoder's builtin calls."""

    watched_names = _REQUIRED_BUILTINS | {"__builtins__"}
    bound_names: set[str] = set()
    if arguments is not None:
        function_arguments = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        if arguments.vararg is not None:
            function_arguments.append(arguments.vararg)
        if arguments.kwarg is not None:
            function_arguments.append(arguments.kwarg)
        bound_names.update(argument.arg for argument in function_arguments if argument.arg in watched_names)
    for type_parameter in type_parameters:
        type_parameter_name = getattr(type_parameter, "name", None)
        if isinstance(type_parameter_name, str) and type_parameter_name in watched_names:
            bound_names.add(type_parameter_name)

    pending: list[ast.AST] = list(reversed(body))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in watched_names:
                bound_names.add(node.name)
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, ast.Lambda):
            pending.extend(_definition_eager_nodes(node))
            continue
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            # Comprehension iteration variables have their own implicit scope,
            # while named expressions in the eager parts bind outside it.
            if isinstance(node, ast.DictComp):
                pending.extend((node.key, node.value))
            else:
                pending.append(node.elt)
            for generator in node.generators:
                pending.append(generator.iter)
                pending.extend(generator.ifs)
            continue
        if isinstance(node, ast.Name) and node.id in watched_names and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound_names.add(node.id)
            continue
        if isinstance(node, ast.Import):
            bound_names.update(
                local_name
                for imported in node.names
                if (local_name := imported.asname or imported.name.split(".", 1)[0]) in watched_names
            )
        elif isinstance(node, ast.ImportFrom):
            if any(imported.name == "*" for imported in node.names):
                bound_names.update(watched_names)
            else:
                bound_names.update(
                    local_name
                    for imported in node.names
                    if (local_name := imported.asname or imported.name) in watched_names
                )
        elif isinstance(node, ast.ExceptHandler) and node.name in watched_names:
            bound_names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound_names.update(name for name in node.names if name in watched_names)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in watched_names:
            bound_names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest in watched_names:
            bound_names.add(node.rest)
        pending.extend(ast.iter_child_nodes(node))

    if "__builtins__" in bound_names:
        return _REQUIRED_BUILTINS
    return frozenset(bound_names & _REQUIRED_BUILTINS)


def _name_call(expression: ast.expr, name: str, *, argument_count: int) -> ast.Call | None:
    if not isinstance(expression, ast.Call):
        return None
    if not isinstance(expression.func, ast.Name) or expression.func.id != name:
        return None
    if len(expression.args) != argument_count or expression.keywords:
        return None
    return expression


def _matches_key_index(expression: ast.expr, *, key_name: str, index_name: str) -> bool:
    if not isinstance(expression, ast.Subscript):
        return False
    if not isinstance(expression.value, ast.Name) or expression.value.id != key_name:
        return False
    modulo = expression.slice
    if not isinstance(modulo, ast.BinOp) or not isinstance(modulo.op, ast.Mod):
        return False
    if not isinstance(modulo.left, ast.Name) or modulo.left.id != index_name:
        return False
    key_length = _name_call(modulo.right, "len", argument_count=1)
    return bool(
        key_length is not None and isinstance(key_length.args[0], ast.Name) and key_length.args[0].id == key_name
    )


def _matches_xor_element(
    expression: ast.expr,
    *,
    key_name: str,
    index_name: str,
    value_name: str,
) -> bool:
    if not isinstance(expression, ast.BinOp) or not isinstance(expression.op, ast.BitXor):
        return False
    pairs = ((expression.left, expression.right), (expression.right, expression.left))
    return any(
        isinstance(value, ast.Name)
        and value.id == value_name
        and _matches_key_index(key_index, key_name=key_name, index_name=index_name)
        for value, key_index in pairs
    )


def _match_repeating_xor_decoder(function: ast.FunctionDef | ast.AsyncFunctionDef) -> _RepeatingXorDecoder | None:
    """Match the reviewed helper shape without evaluating arbitrary syntax."""

    arguments = function.args
    if (
        isinstance(function, ast.AsyncFunctionDef)
        or len(function.name) > MAX_XOR_IDENTIFIER_CHARS
        or function.decorator_list
        or bool(getattr(function, "type_params", ()))
        or function.returns is not None
        or arguments.posonlyargs
        or len(arguments.args) != 1
        or arguments.vararg is not None
        or arguments.kwonlyargs
        or arguments.kw_defaults
        or arguments.kwarg is not None
        or arguments.defaults
    ):
        return None
    parameter = arguments.args[0]
    if parameter.annotation is not None or len(parameter.arg) > MAX_XOR_IDENTIFIER_CHARS:
        return None

    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and type(body[0].value.value) is str
    ):
        body = body[1:]
    if len(body) != 2:
        return None

    key_statement, return_statement = body
    if not isinstance(key_statement, ast.Assign) or len(key_statement.targets) != 1:
        return None
    key_target = key_statement.targets[0]
    if not isinstance(key_target, ast.Name) or len(key_target.id) > MAX_XOR_IDENTIFIER_CHARS:
        return None
    if not isinstance(key_statement.value, ast.Constant) or type(key_statement.value.value) is not bytes:
        return None
    key = key_statement.value.value
    if not 0 < len(key) <= MAX_XOR_KEY_BYTES:
        return None

    if not isinstance(return_statement, ast.Return) or not isinstance(return_statement.value, ast.Call):
        return None
    decode_call = return_statement.value
    if (
        not isinstance(decode_call.func, ast.Attribute)
        or decode_call.func.attr != "decode"
        or len(decode_call.args) != 1
        or decode_call.keywords
        or not isinstance(decode_call.args[0], ast.Constant)
        or type(decode_call.args[0].value) is not str
    ):
        return None
    encoding = decode_call.args[0].value.lower().replace("_", "-")
    if encoding not in {"ascii", "utf-8"}:
        return None

    bytes_call = _name_call(decode_call.func.value, "bytes", argument_count=1)
    if bytes_call is None or not isinstance(bytes_call.args[0], ast.GeneratorExp):
        return None
    generator = bytes_call.args[0]
    if len(generator.generators) != 1:
        return None
    comprehension = generator.generators[0]
    if comprehension.is_async or comprehension.ifs:
        return None
    if not isinstance(comprehension.target, ast.Tuple) or len(comprehension.target.elts) != 2:
        return None
    index_target, value_target = comprehension.target.elts
    if not isinstance(index_target, ast.Name) or not isinstance(value_target, ast.Name):
        return None
    if any(len(name) > MAX_XOR_IDENTIFIER_CHARS for name in (key_target.id, index_target.id, value_target.id)):
        return None
    enumerate_call = _name_call(comprehension.iter, "enumerate", argument_count=1)
    if (
        enumerate_call is None
        or not isinstance(enumerate_call.args[0], ast.Name)
        or enumerate_call.args[0].id != parameter.arg
    ):
        return None

    local_names = {parameter.arg, key_target.id, index_target.id, value_target.id}
    if len(local_names) != 4 or local_names & _REQUIRED_BUILTINS:
        return None
    if not _matches_xor_element(
        generator.elt,
        key_name=key_target.id,
        index_name=index_target.id,
        value_name=value_target.id,
    ):
        return None
    return _RepeatingXorDecoder(key=key, encoding=encoding)


class _StraightLineXorScanner:
    """Track only the bindings needed to prove the reviewed decode-and-run idiom."""

    def __init__(self) -> None:
        self.candidates: list[DecodedPythonCommand] = []
        self.candidate_keys: set[tuple[int, str, str]] = set()

    def scan(self, tree: ast.Module) -> None:
        self._scan_body(
            tree.body,
            depth=0,
            unavailable_builtins=frozenset(),
            nested_unavailable_builtins=_scope_unsafe_builtins(tree.body),
        )

    def _scan_body(
        self,
        body: list[ast.stmt],
        *,
        depth: int,
        unavailable_builtins: frozenset[str],
        nested_unavailable_builtins: frozenset[str] | None = None,
    ) -> None:
        if depth > MAX_XOR_SCOPE_DEPTH or len(self.candidates) >= MAX_XOR_CANDIDATES:
            return
        if nested_unavailable_builtins is None:
            nested_unavailable_builtins = unavailable_builtins
        facts = _ScopeFacts(
            decoders={},
            identities={},
            safe_builtins=set(_REQUIRED_BUILTINS - unavailable_builtins),
            poisoned_modules=set(),
        )

        for statement in body:
            if len(self.candidates) >= MAX_XOR_CANDIDATES:
                return

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_unavailable_builtins = nested_unavailable_builtins | _scope_unsafe_builtins(
                    statement.body,
                    statement.args,
                    tuple(getattr(statement, "type_params", ())),
                )
                self._scan_body(
                    statement.body,
                    depth=depth + 1,
                    unavailable_builtins=function_unavailable_builtins,
                )
                self._invalidate_name(statement.name, facts)
                decoder = _match_repeating_xor_decoder(statement)
                if decoder is not None and statement.name not in _REQUIRED_BUILTINS:
                    facts.decoders[statement.name] = decoder
                else:
                    self._clear_after_unknown_effect(facts)
                self._enforce_binding_limit(facts)
                continue

            if isinstance(statement, ast.Import):
                if not self._apply_import(statement, facts):
                    self._clear_after_unknown_effect(facts)
                self._enforce_binding_limit(facts)
                continue

            if isinstance(statement, ast.ImportFrom):
                if not self._apply_import_from(statement, facts):
                    self._clear_after_unknown_effect(facts)
                self._enforce_binding_limit(facts)
                continue

            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                call = self._direct_call(value)
                reviewed = call is not None and self._record_call(call, facts)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                self._poison_module_targets(targets, facts)
                names = self._target_names(targets)
                if names is None:
                    self._clear_after_unknown_effect(facts)
                else:
                    for name in names:
                        self._invalidate_name(name, facts)
                    annotation = statement.annotation if isinstance(statement, ast.AnnAssign) else None
                    if (call is not None and not reviewed) or (
                        call is None and (not _is_inert_expression(value) or not _is_inert_expression(annotation))
                    ):
                        self._clear_after_unknown_effect(facts)
                continue

            if isinstance(statement, ast.Expr):
                call = self._direct_call(statement.value)
                if call is not None:
                    if not self._record_call(call, facts):
                        self._clear_after_unknown_effect(facts)
                elif not isinstance(statement.value, ast.Constant):
                    self._clear_after_unknown_effect(facts)
                continue

            if isinstance(statement, ast.Return):
                if depth > 0:
                    call = self._direct_call(statement.value)
                    if call is not None:
                        self._record_call(call, facts)
                # A return ends the straight-line path.  At module depth,
                # ``ast.parse`` accepts it even though Python cannot execute it.
                return

            if isinstance(statement, ast.Raise):
                call = self._direct_call(statement.exc)
                if call is not None:
                    self._record_call(call, facts)
                return

            if isinstance(statement, ast.Delete):
                self._poison_module_targets(statement.targets, facts)
                names = self._target_names(statement.targets)
                if names is None:
                    self._clear_after_unknown_effect(facts)
                else:
                    for name in names:
                        self._invalidate_name(name, facts)
                continue

            if isinstance(statement, ast.Pass):
                continue

            # Class bodies, conditionals, loops, exception handlers, and all
            # other compound flow are intentionally outside this recognizer.
            # Their delayed function children are independent scopes, though,
            # and can be scanned without interpreting the enclosing flow.
            self._scan_nested_function_scopes(
                statement,
                depth=depth,
                unavailable_builtins=nested_unavailable_builtins,
            )
            self._clear_after_unknown_effect(facts)

    def _scan_nested_function_scopes(
        self,
        root: ast.AST,
        *,
        depth: int,
        unavailable_builtins: frozenset[str],
    ) -> None:
        """Scan delayed functions nested below unsupported compound flow."""

        pending = list(reversed(tuple(ast.iter_child_nodes(root))))
        while pending and len(self.candidates) < MAX_XOR_CANDIDATES:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_unavailable_builtins = unavailable_builtins | _scope_unsafe_builtins(
                    node.body,
                    node.args,
                    tuple(getattr(node, "type_params", ())),
                )
                self._scan_body(
                    node.body,
                    depth=depth + 1,
                    unavailable_builtins=function_unavailable_builtins,
                )
                # The recursive body scan owns every scope below this one.
                continue
            if isinstance(node, ast.Lambda):
                continue
            pending.extend(reversed(tuple(ast.iter_child_nodes(node))))

    def _record_call(self, call: ast.Call, facts: _ScopeFacts) -> bool:
        identity = self._resolve_identity(call.func, facts.identities)
        if identity == _OS_SYSTEM_IDENTITY:
            if call.keywords:
                return False
            command_expression = self._single_command_argument(call)
            api_name = "os.system"
        elif identity in _SUBPROCESS_CALL_IDENTITIES and self._has_literal_shell_true(call):
            method_name = identity.rsplit(".", 1)[-1]
            allowed_options = _SUBPROCESS_LITERAL_OPTIONS[method_name]
            keyword_names = [keyword.arg for keyword in call.keywords]
            if any(
                keyword.arg not in ({"args", "shell"} | allowed_options)
                or (keyword.arg not in {"args", "shell"} and not _is_literal_option(keyword.value))
                for keyword in call.keywords
            ) or len(keyword_names) != len(set(keyword_names)):
                return False
            command_expression = self._single_command_argument(call)
            api_name = f"subprocess.{method_name}"
        else:
            return False
        if command_expression is None or not isinstance(command_expression, ast.Call):
            return False
        if not isinstance(command_expression.func, ast.Name):
            return False
        decoder = facts.decoders.get(command_expression.func.id)
        if decoder is None or not _REQUIRED_BUILTINS.issubset(facts.safe_builtins):
            return False
        if len(command_expression.args) != 1 or command_expression.keywords:
            return False
        ciphertext = _literal_bytes(command_expression.args[0])
        if ciphertext is None or len(ciphertext) > MAX_XOR_COMMAND_BYTES:
            return False
        try:
            decoded = bytes(value ^ decoder.key[index % len(decoder.key)] for index, value in enumerate(ciphertext))
            command = decoded.decode(decoder.encoding)
        except (UnicodeDecodeError, ValueError):
            return False
        if not command or "\x00" in command or len(command.encode("utf-8")) > MAX_XOR_COMMAND_BYTES:
            return False
        line_number = getattr(call.func, "lineno", 0)
        if line_number < 1:
            return False
        key = (line_number, command, api_name)
        if key not in self.candidate_keys:
            self.candidates.append(
                DecodedPythonCommand(
                    line_number=line_number,
                    command=command,
                    api_name=api_name,
                )
            )
            self.candidate_keys.add(key)
        return True

    @staticmethod
    def _single_command_argument(call: ast.Call) -> ast.expr | None:
        if any(keyword.arg is None for keyword in call.keywords):
            return None
        args_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "args"]
        if len(call.args) == 1 and not args_keywords:
            return call.args[0]
        if not call.args and len(args_keywords) == 1:
            return args_keywords[0]
        return None

    @staticmethod
    def _has_literal_shell_true(call: ast.Call) -> bool:
        shell_values = [keyword.value for keyword in call.keywords if keyword.arg == "shell"]
        return bool(
            len(shell_values) == 1
            and isinstance(shell_values[0], ast.Constant)
            and type(shell_values[0].value) is bool
            and shell_values[0].value is True
            and all(keyword.arg is not None for keyword in call.keywords)
        )

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

    def _apply_import(self, statement: ast.Import, facts: _ScopeFacts) -> bool:
        reviewed = True
        for imported in statement.names:
            local_name = imported.asname or imported.name.split(".", 1)[0]
            self._invalidate_name(local_name, facts)
            if imported.name == "os" and "os" not in facts.poisoned_modules:
                facts.identities[local_name] = "module:os"
            elif imported.name == "subprocess" and "subprocess" not in facts.poisoned_modules:
                facts.identities[local_name] = "module:subprocess"
            else:
                reviewed = False
        return reviewed

    def _apply_import_from(self, statement: ast.ImportFrom, facts: _ScopeFacts) -> bool:
        if statement.level == 0 and statement.module == "__future__":
            return True
        if statement.level != 0 or any(imported.name == "*" for imported in statement.names):
            return False
        reviewed = True
        for imported in statement.names:
            local_name = imported.asname or imported.name
            self._invalidate_name(local_name, facts)
            if statement.module == "os" and imported.name == "system" and "os" not in facts.poisoned_modules:
                facts.identities[local_name] = _OS_SYSTEM_IDENTITY
            elif (
                statement.module == "subprocess"
                and imported.name in _SUBPROCESS_METHODS
                and "subprocess" not in facts.poisoned_modules
            ):
                facts.identities[local_name] = f"callable:subprocess.{imported.name}"
            else:
                reviewed = False
        return reviewed

    @classmethod
    def _poison_module_targets(cls, targets: list[ast.expr], facts: _ScopeFacts) -> None:
        pending = list(targets)
        while pending:
            target = pending.pop()
            if isinstance(target, ast.Attribute):
                identity = cls._resolve_identity(target, facts.identities)
                if identity == _OS_SYSTEM_IDENTITY:
                    facts.poisoned_modules.add("os")
                elif identity in _SUBPROCESS_CALL_IDENTITIES:
                    facts.poisoned_modules.add("subprocess")
                continue
            if isinstance(target, ast.Starred):
                pending.append(target.value)
            elif isinstance(target, (ast.List, ast.Tuple)):
                pending.extend(target.elts)

    @staticmethod
    def _target_names(targets: list[ast.expr]) -> tuple[str, ...] | None:
        if any(not isinstance(target, ast.Name) for target in targets):
            return None
        return tuple(target.id for target in targets if isinstance(target, ast.Name))

    @staticmethod
    def _invalidate_name(name: str, facts: _ScopeFacts) -> None:
        facts.decoders.pop(name, None)
        facts.identities.pop(name, None)
        if name == "__builtins__":
            facts.safe_builtins.clear()
        else:
            facts.safe_builtins.discard(name)

    @staticmethod
    def _clear_after_unknown_effect(facts: _ScopeFacts) -> None:
        for identity in facts.identities.values():
            if identity == "module:os" or identity == _OS_SYSTEM_IDENTITY:
                facts.poisoned_modules.add("os")
            elif identity == "module:subprocess" or identity in _SUBPROCESS_CALL_IDENTITIES:
                facts.poisoned_modules.add("subprocess")
        facts.decoders.clear()
        facts.identities.clear()
        facts.safe_builtins.clear()

    @staticmethod
    def _enforce_binding_limit(facts: _ScopeFacts) -> None:
        if len(facts.decoders) + len(facts.identities) > MAX_XOR_BINDINGS:
            _StraightLineXorScanner._clear_after_unknown_effect(facts)

    @staticmethod
    def _direct_call(expression: ast.expr | None) -> ast.Call | None:
        if isinstance(expression, ast.Call):
            return expression
        return None
