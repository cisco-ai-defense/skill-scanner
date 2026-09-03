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

"""Bounded same-file JavaScript/TypeScript source-to-sink analysis.

The extractor is intentionally smaller than a JavaScript runtime or a general
type checker.  It follows exact lexical values through declarations, simple
assignments, member access, reviewed value-preserving calls, and reviewed
security APIs.  It never imports modules, resolves package dependencies, or
executes source.  Unsupported syntax produces no invented provenance; lexical
and resource-limit failures return an incomplete, empty result so existing
primitive detectors remain the fail-open coverage.

Callback/event provenance for ``node:http(s)``, XMLHttpRequest, and WebSocket,
module-to-module dataflow, and dynamic computed request shapes remain explicit
gaps. They require richer control-flow and callback binding; this extractor
does not approximate them through co-occurrence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, TypeVar
from urllib.parse import urlsplit

from .javascript_tokens import JavascriptToken, tokenize_javascript
from .url_classifier import classify_url

MAX_JAVASCRIPT_DATAFLOW_BYTES = 512 * 1024
MAX_JAVASCRIPT_DATAFLOW_TOKENS = 16_384
MAX_JAVASCRIPT_DATAFLOW_DEPTH = 64
MAX_JAVASCRIPT_DATAFLOW_SCOPES = 1_024
MAX_JAVASCRIPT_DATAFLOW_BINDINGS = 1_024
MAX_JAVASCRIPT_DATAFLOW_CALLS = 4_096
MAX_JAVASCRIPT_DATAFLOW_HOPS = 8
MAX_JAVASCRIPT_DATAFLOW_FACTS = 256
MAX_JAVASCRIPT_DATAFLOW_FLOWS = 64
MAX_VALUE_ORIGINS = 8
MAX_VALUE_PROPERTIES = 32
MAX_VALUE_STRINGS = 8

SensitiveSourceClass = Literal["credential_file", "sensitive_environment"]
SourceClass = Literal["credential_file", "environment_reference", "sensitive_environment"]
FlowSourceClass = Literal[
    "credential_file",
    "environment_reference",
    "sensitive_environment",
    "network",
    "obfuscation",
]
CredentialUse = Literal["", "authentication", "payload"]

_SENSITIVE_NAME_TOKENS = frozenset(
    {
        "apikey",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "secret",
        "token",
    }
)
_SENSITIVE_NAME_PAIRS = frozenset({("api", "key"), ("access", "key"), ("private", "key")})
_GENERIC_CREDENTIAL_NAME_TOKENS = frozenset(
    {
        "access",
        "api",
        "auth",
        "authorization",
        "bearer",
        "client",
        "credential",
        "credentials",
        "key",
        "oauth",
        "password",
        "passwd",
        "private",
        "secret",
        "service",
        "token",
        "user",
    }
)
_COMMON_SECOND_LEVEL_SUFFIXES = frozenset({"ac", "co", "com", "edu", "gov", "net", "org"})
_SENSITIVE_PATH_PARTS = (
    "/etc/passwd",
    "/etc/shadow",
    ".aws/credentials",
    ".config/gcloud",
    ".docker/config.json",
    ".gnupg",
    ".kube/config",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh/",
    "id_ed25519",
    "id_rsa",
)
_CHILD_PROCESS_MODULES = frozenset({"child_process", "node:child_process"})
_CHILD_PROCESS_METHODS = frozenset({"exec", "execFile", "execFileSync", "execSync", "spawn", "spawnSync"})
_FS_MODULES = frozenset({"fs", "node:fs"})
_FS_PROMISE_MODULES = frozenset({"fs/promises", "node:fs/promises"})
_FS_READ_METHODS = frozenset({"readFile", "readFileSync"})
_FS_WRITE_METHODS = frozenset({"appendFile", "appendFileSync", "writeFile", "writeFileSync"})
_PATH_MODULES = frozenset({"node:path", "path"})
_FETCH_MODULES = frozenset({"cross-fetch", "node-fetch"})
_AXIOS_METHODS = frozenset({"delete", "get", "head", "patch", "post", "put", "request"})
_RESPONSE_METHODS = frozenset({"arrayBuffer", "blob", "json", "text"})
_PAYLOAD_PROPERTIES = frozenset({"body", "data", "form", "json", "payload"})
_AUTH_HEADER_NAMES = frozenset({"authorization", "proxy-authorization", "x-api-key", "x-auth-token"})
_PREFIX_KEYWORDS = frozenset({"await", "delete", "new", "return", "throw", "typeof", "void", "yield"})
_EMPTY_IDENTIFIERS = frozenset({"false", "null", "super", "this", "true", "undefined"})
_ASI_NON_TERMINATORS = frozenset(
    {
        "!",
        "%",
        "&",
        "(",
        "*",
        "+",
        ",",
        "-",
        ".",
        "/",
        ":",
        "<",
        "=",
        ">",
        "?",
        "[",
        "^",
        "|",
        "{",
    }
)
_ASI_CONTINUATIONS = frozenset(
    {"!", "%", "&", "(", "*", "+", ",", "-", ".", "/", ":", "<", "=", ">", "?", "[", "^", "|"}
)
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
_CLOSE_TO_OPEN = {value: key for key, value in _OPEN_TO_CLOSE.items()}


@dataclass(frozen=True, slots=True)
class JavascriptEndpoint:
    """A normalized literal network endpoint; paths and query data are omitted."""

    scheme: str
    host: str


@dataclass(frozen=True, slots=True)
class JavascriptSourceFact:
    """A reviewed sensitive source observed in executable syntax."""

    source_class: SourceClass
    line: int


@dataclass(frozen=True, slots=True)
class JavascriptNetworkFact:
    """A reviewed network call and the source classes it transmits."""

    api_class: str
    line: int
    method: str
    direction: Literal["inbound", "outbound"]
    downloads: bool
    endpoints: tuple[JavascriptEndpoint, ...] = ()
    source_classes: tuple[SourceClass, ...] = ()
    credential_use: CredentialUse = ""
    provider_bound_authentication: bool = False


@dataclass(frozen=True, slots=True)
class JavascriptExecutionFact:
    """A syntax-bound interpreter or child-process sink."""

    api_class: str
    line: int
    dynamic: bool
    source_classes: tuple[FlowSourceClass, ...] = ()


@dataclass(frozen=True, slots=True)
class JavascriptFilesystemFact:
    """A sensitive value written to a precision-qualified destination."""

    api_class: str
    line: int
    destination_class: Literal["environment_controlled", "unc_path"]
    source_classes: tuple[SensitiveSourceClass, ...]


@dataclass(frozen=True, slots=True)
class JavascriptTransformFact:
    """A reviewed decoding transform."""

    transform: Literal["base64_decode"]
    line: int


@dataclass(frozen=True, slots=True)
class JavascriptFlowFact:
    """One exact same-file source-to-sink connection."""

    source_class: FlowSourceClass
    sink_class: Literal["network", "code_execution", "filesystem_write"]
    transforms: tuple[Literal["decode"], ...]
    line: int


@dataclass(frozen=True, slots=True)
class JavascriptDataflowResult:
    """Bounded normalized output. Incomplete results never contain facts."""

    sources: tuple[JavascriptSourceFact, ...] = ()
    networks: tuple[JavascriptNetworkFact, ...] = ()
    executions: tuple[JavascriptExecutionFact, ...] = ()
    filesystem_writes: tuple[JavascriptFilesystemFact, ...] = ()
    transforms: tuple[JavascriptTransformFact, ...] = ()
    flows: tuple[JavascriptFlowFact, ...] = ()
    complete: bool = True
    error_codes: tuple[str, ...] = ()
    tokens_processed: int = 0


@dataclass(frozen=True, slots=True, order=True)
class _Origin:
    source_class: FlowSourceClass
    line: int
    hops: int = 0
    providers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Value:
    origins: tuple[_Origin, ...] = ()
    identities: frozenset[str] = frozenset()
    strings: tuple[str, ...] = ()
    properties: tuple[tuple[str, _Value], ...] = ()

    def property(self, name: str) -> _Value | None:
        return next((value for key, value in self.properties if key == name), None)


@dataclass(slots=True)
class _Scope:
    parent: int | None
    declared: set[str] = field(default_factory=set)
    bindings: dict[str, _Value] = field(default_factory=dict)


class _AnalysisLimit(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _is_sensitive_name(value: str) -> bool:
    tokens = _name_tokens(value)
    return bool(_SENSITIVE_NAME_TOKENS.intersection(tokens)) or any(
        pair in _SENSITIVE_NAME_PAIRS for pair in zip(tokens, tokens[1:], strict=False)
    )


def _name_tokens(value: str) -> tuple[str, ...]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return tuple(re.findall(r"[a-z0-9]+", expanded.lower()))[:32]


def _credential_provider_tokens(value: str) -> tuple[str, ...]:
    return tuple(
        token for token in _name_tokens(value)[:16] if len(token) >= 3 and token not in _GENERIC_CREDENTIAL_NAME_TOKENS
    )


def _service_provider_label(host: str) -> str:
    labels = [label for label in host.lower().rstrip(".").split(".") if label]
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9-]{1,63}", label) for label in labels):
        return ""
    if len(labels[-1]) == 2 and len(labels) >= 3 and labels[-2] in _COMMON_SECOND_LEVEL_SUFFIXES:
        return labels[-3]
    return labels[-2]


def _authentication_endpoints_match_providers(
    providers: set[str],
    endpoints: tuple[JavascriptEndpoint, ...],
) -> bool:
    if not providers or not endpoints:
        return False
    return all(
        endpoint.scheme == "https"
        and classify_url(f"{endpoint.scheme}://{endpoint.host}") != "suspicious"
        and bool(provider := _service_provider_label(endpoint.host))
        and provider in providers
        for endpoint in endpoints
    )


def _expand_template_literals(source: str) -> tuple[str, str | None]:
    """Turn template literals into bounded concatenation expressions.

    Literal fragments remain string tokens and ``${...}`` expressions remain
    executable tokens. Newlines are preserved so all emitted line numbers
    still refer to the original file. This is a lexical transformation only;
    tagged templates are deliberately left unsupported by the value model.
    """

    def copy_quoted(start: int, quote: str) -> tuple[str, int, bool]:
        position = start + 1
        while position < len(source):
            if source[position] == "\\":
                position += 2
                continue
            if source[position] == quote:
                return source[start : position + 1], position + 1, True
            position += 1
        return source[start:], len(source), False

    def template_expression_end(start: int) -> tuple[int, bool]:
        depth = 1
        position = start
        while position < len(source):
            character = source[position]
            if character in {"'", '"'}:
                _quoted, position, closed = copy_quoted(position, character)
                if not closed:
                    return len(source), False
                continue
            if source.startswith("//", position):
                newline = source.find("\n", position + 2)
                position = len(source) if newline < 0 else newline + 1
                continue
            if source.startswith("/*", position):
                close = source.find("*/", position + 2)
                if close < 0:
                    return len(source), False
                position = close + 2
                continue
            if character == "`":
                _expanded, position, error = expand_template(position)
                if error is not None:
                    return len(source), False
                continue
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return position, True
            position += 1
        return len(source), False

    def literal_token(value: str) -> str:
        # The shared lexer retains at most 256 characters per literal. Quotes
        # and backslashes are replaced, not interpreted; newlines remain so
        # source line identities are unchanged.
        safe = value.replace("\\", " ").replace('"', " ")
        return f'"{safe}"'

    def expand_template(start: int) -> tuple[str, int, str | None]:
        parts: list[str] = []
        literal: list[str] = []
        position = start + 1

        def flush_literal() -> None:
            if literal:
                parts.append(literal_token("".join(literal)))
                literal.clear()

        while position < len(source):
            character = source[position]
            if character == "\\":
                if position + 1 < len(source):
                    escaped = source[position + 1]
                    literal.append("\n" if escaped == "\n" else escaped)
                    position += 2
                    continue
                return "", len(source), "JS_DATAFLOW_UNCLOSED_TEMPLATE"
            if character == "`":
                flush_literal()
                if not parts:
                    parts.append('""')
                return f"({' + '.join(parts)})", position + 1, None
            if source.startswith("${", position):
                flush_literal()
                closing, closed = template_expression_end(position + 2)
                if not closed:
                    return "", len(source), "JS_DATAFLOW_UNCLOSED_TEMPLATE_EXPRESSION"
                expression, error = expand_region(position + 2, closing)
                if error is not None:
                    return "", len(source), error
                parts.append(f"({expression})")
                position = closing + 1
                continue
            literal.append(character)
            position += 1
        return "", len(source), "JS_DATAFLOW_UNCLOSED_TEMPLATE"

    def expand_region(start: int, end: int) -> tuple[str, str | None]:
        output: list[str] = []
        position = start
        while position < end:
            character = source[position]
            if character in {"'", '"'}:
                quoted, following, closed = copy_quoted(position, character)
                output.append(quoted)
                if not closed:
                    return "", "JS_DATAFLOW_UNCLOSED_STRING"
                position = following
                continue
            if source.startswith("//", position):
                newline = source.find("\n", position + 2, end)
                following = end if newline < 0 else newline + 1
                output.append(source[position:following])
                position = following
                continue
            if source.startswith("/*", position):
                close = source.find("*/", position + 2, end)
                if close < 0:
                    return "", "JS_DATAFLOW_UNCLOSED_COMMENT"
                output.append(source[position : close + 2])
                position = close + 2
                continue
            if character == "`":
                expanded, following, error = expand_template(position)
                if error is not None:
                    return "", error
                output.append(expanded)
                position = following
                continue
            output.append(character)
            position += 1
        return "".join(output), None

    expanded, error = expand_region(0, len(source))
    return (expanded, error)


def _is_sensitive_path(value: str) -> bool:
    lowered = value.lower().replace("\\", "/")
    return any(part in lowered for part in _SENSITIVE_PATH_PARTS)


_T = TypeVar("_T")


def _dedupe(values: list[_T]) -> tuple[_T, ...]:
    return tuple(dict.fromkeys(values))


class _JavascriptDataflowExtractor:
    """One bounded abstract interpretation of a complete token stream."""

    def __init__(self, tokens: tuple[JavascriptToken, ...]) -> None:
        self.tokens = tokens
        self.pairs: dict[int, int] = {}
        self.scope_at: list[int] = [0] * len(tokens)
        self.brace_scope: dict[int, int] = {}
        self.scopes: list[_Scope] = [_Scope(None)]
        self.binding_count = 0
        self.sources: list[JavascriptSourceFact] = []
        self.networks: list[JavascriptNetworkFact] = []
        self.executions: list[JavascriptExecutionFact] = []
        self.filesystem_writes: list[JavascriptFilesystemFact] = []
        self.transforms: list[JavascriptTransformFact] = []
        self.flows: list[JavascriptFlowFact] = []

    def extract(self) -> JavascriptDataflowResult:
        self._build_structure()
        self._collect_declarations()
        self._walk()
        return JavascriptDataflowResult(
            sources=_dedupe(self.sources),
            networks=_dedupe(self.networks),
            executions=_dedupe(self.executions),
            filesystem_writes=_dedupe(self.filesystem_writes),
            transforms=_dedupe(self.transforms),
            flows=_dedupe(self.flows),
            complete=True,
            tokens_processed=len(self.tokens),
        )

    def _build_structure(self) -> None:
        delimiter_stack: list[tuple[str, int]] = []
        scope_stack = [0]
        for index, token in enumerate(self.tokens):
            value = token.value
            self.scope_at[index] = scope_stack[-1]
            if value in _OPEN_TO_CLOSE:
                if len(delimiter_stack) >= MAX_JAVASCRIPT_DATAFLOW_DEPTH:
                    raise _AnalysisLimit("JS_DATAFLOW_DEPTH_LIMIT")
                delimiter_stack.append((value, index))
                if value == "{":
                    if len(self.scopes) >= MAX_JAVASCRIPT_DATAFLOW_SCOPES:
                        raise _AnalysisLimit("JS_DATAFLOW_SCOPE_LIMIT")
                    child = len(self.scopes)
                    self.scopes.append(_Scope(scope_stack[-1]))
                    self.brace_scope[index] = child
                    scope_stack.append(child)
            elif value in _CLOSE_TO_OPEN:
                if not delimiter_stack or delimiter_stack[-1][0] != _CLOSE_TO_OPEN[value]:
                    raise _AnalysisLimit("JS_DATAFLOW_SYNTAX_DELIMITER")
                _opening, opening_index = delimiter_stack.pop()
                self.pairs[opening_index] = index
                self.pairs[index] = opening_index
                if value == "}":
                    if len(scope_stack) == 1:
                        raise _AnalysisLimit("JS_DATAFLOW_SYNTAX_DELIMITER")
                    scope_stack.pop()
        if delimiter_stack or len(scope_stack) != 1:
            raise _AnalysisLimit("JS_DATAFLOW_SYNTAX_DELIMITER")

        call_count = sum(
            1
            for index, token in enumerate(self.tokens[:-1])
            if token.kind == "identifier" and self.tokens[index + 1].value == "("
        )
        if call_count > MAX_JAVASCRIPT_DATAFLOW_CALLS:
            raise _AnalysisLimit("JS_DATAFLOW_CALL_LIMIT")

    def _collect_declarations(self) -> None:
        count = len(self.tokens)
        index = 0
        while index < count:
            token = self.tokens[index]
            scope = self.scope_at[index]
            if token.value in {"const", "let", "var"}:
                end = self._statement_end(index + 1)
                equal = self._top_level_token(index + 1, end, "=")
                lhs_end = equal if equal is not None else end
                for name in self._declared_names(index + 1, lhs_end):
                    self._declare(scope, name)
                index = max(index + 1, end)
                continue
            if token.value == "import":
                end = self._statement_end(index + 1)
                for name in self._import_local_names(index + 1, end):
                    self._declare(scope, name)
                index = max(index + 1, end)
                continue
            if token.value in {"function", "class"} and index + 1 < count:
                name_token = self.tokens[index + 1]
                if name_token.kind == "identifier":
                    self._declare(scope, name_token.value)
            if token.value == "function":
                opening = next(
                    (
                        position
                        for position in range(index + 1, min(count, index + 128))
                        if self.tokens[position].value == "("
                    ),
                    None,
                )
                if opening is not None and opening in self.pairs:
                    closing = self.pairs[opening]
                    body = closing + 1
                    if body < count and self.tokens[body].value == "{" and body in self.brace_scope:
                        for name in self._parameter_names(opening + 1, closing):
                            self._declare(self.brace_scope[body], name)
            if token.value == "=" and index + 1 < count and self.tokens[index + 1].value == ">":
                body = index + 2
                if body < count and self.tokens[body].value == "{" and body in self.brace_scope:
                    for name in self._arrow_parameter_names(index):
                        self._declare(self.brace_scope[body], name)
            index += 1

    def _declare(self, scope: int, name: str) -> None:
        if not name or name in self.scopes[scope].declared:
            return
        self.scopes[scope].declared.add(name)
        self.binding_count += 1
        if self.binding_count > MAX_JAVASCRIPT_DATAFLOW_BINDINGS:
            raise _AnalysisLimit("JS_DATAFLOW_BINDING_LIMIT")

    def _declared_names(self, start: int, end: int) -> list[str]:
        if start >= end:
            return []
        if self.tokens[start].kind == "identifier":
            return [self.tokens[start].value]
        if self.tokens[start].value != "{" or start not in self.pairs:
            return []
        closing = min(end, self.pairs[start])
        names: list[str] = []
        position = start + 1
        while position < closing:
            token = self.tokens[position]
            if token.kind != "identifier":
                position += 1
                continue
            local = token.value
            if position + 2 < closing and self.tokens[position + 1].value in {":", "as"}:
                candidate = self.tokens[position + 2]
                if candidate.kind == "identifier":
                    local = candidate.value
                    position += 2
            names.append(local)
            position += 1
        return names

    def _parameter_names(self, start: int, end: int) -> list[str]:
        return [
            token.value
            for token in self.tokens[start:end]
            if token.kind == "identifier" and token.value not in {"readonly", "public", "private", "protected"}
        ]

    def _arrow_parameter_names(self, equal_index: int) -> list[str]:
        previous = equal_index - 1
        if previous < 0:
            return []
        if self.tokens[previous].kind == "identifier":
            return [self.tokens[previous].value]
        if self.tokens[previous].value == ")" and previous in self.pairs:
            return self._parameter_names(self.pairs[previous] + 1, previous)
        return []

    def _import_local_names(self, start: int, end: int) -> list[str]:
        names: list[str] = []
        position = start
        while position < end:
            token = self.tokens[position]
            if token.value == "from" or token.kind == "string":
                break
            if token.value in {"as", "type"}:
                position += 1
                continue
            if token.kind == "identifier":
                if position > start and self.tokens[position - 1].value == "as":
                    names.append(token.value)
                elif not names or self.tokens[start].value != "{":
                    names.append(token.value)
                elif position + 1 >= end or self.tokens[position + 1].value != "as":
                    names.append(token.value)
            position += 1
        return names

    def _walk(self) -> None:
        index = 0
        count = len(self.tokens)
        while index < count:
            token = self.tokens[index]
            if token.value == "import":
                index = self._process_import(index)
                continue
            if token.value in {"const", "let", "var"}:
                index = self._process_declaration(index)
                continue
            if self._is_plain_assignment(index):
                index = self._process_assignment(index)
                continue
            property_assignment = self._property_assignment(index)
            if property_assignment is not None:
                index = self._process_property_assignment(index, *property_assignment)
                continue
            if token.value in {"function", "class"}:
                body = self._body_after_signature(index)
                if body is not None:
                    index = body + 1
                    continue
            if token.kind == "identifier" or token.value in {"(", "[", "{"}:
                _value, following = self._parse_atom(index, count, self.scope_at[index], 0)
                if following > index:
                    index = following
                    continue
            index += 1

    def _body_after_signature(self, start: int) -> int | None:
        for position in range(start + 1, min(len(self.tokens), start + 256)):
            if self.tokens[position].value == "{" and position in self.brace_scope:
                return position
            if self.tokens[position].value == ";":
                return None
        return None

    def _process_import(self, start: int) -> int:
        end = self._statement_end(start + 1)
        module_token = next(
            (
                self.tokens[position]
                for position in range(start + 1, end)
                if self.tokens[position].kind == "string"
                and (position == start + 1 or self.tokens[position - 1].value == "from")
            ),
            None,
        )
        if module_token is None:
            return max(start + 1, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))
        namespace = self._module_value(module_token.value)
        if not namespace.identities:
            return max(start + 1, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))

        scope = self.scope_at[start]
        position = start + 1
        if position < end and self.tokens[position].value == "type":
            return max(start + 1, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))
        if position < end and self.tokens[position].kind == "identifier":
            self._set_binding(scope, self.tokens[position].value, self._module_default(module_token.value, namespace))
        star = next((pos for pos in range(start + 1, end) if self.tokens[pos].value == "*"), None)
        if star is not None and star + 2 < end and self.tokens[star + 1].value == "as":
            self._set_binding(scope, self.tokens[star + 2].value, namespace)
        opening = next((pos for pos in range(start + 1, end) if self.tokens[pos].value == "{"), None)
        if opening is not None and opening in self.pairs:
            closing = min(end, self.pairs[opening])
            position = opening + 1
            while position < closing:
                imported = self.tokens[position]
                if imported.kind != "identifier":
                    position += 1
                    continue
                local = imported.value
                if position + 2 < closing and self.tokens[position + 1].value == "as":
                    local = self.tokens[position + 2].value
                    position += 2
                self._set_binding(scope, local, self._member(namespace, imported.value, imported.line))
                position += 1
        return max(start + 1, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))

    def _process_declaration(self, start: int) -> int:
        end = self._statement_end(start + 1)
        cursor = start + 1
        scope = self.scope_at[start]
        while cursor < end:
            equal = self._top_level_token(cursor, end, "=")
            if equal is None:
                break
            separator = self._top_level_token(equal + 1, end, ",")
            value_end = separator if separator is not None else end
            value = self._eval_span(equal + 1, value_end, scope, 0)
            self._bind_declaration(scope, cursor, equal, value)
            if separator is None:
                break
            cursor = separator + 1
        return max(start + 1, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))

    def _bind_declaration(self, scope: int, start: int, end: int, value: _Value) -> None:
        if start >= end:
            return
        target = self.tokens[start]
        if target.kind == "identifier":
            self._set_binding(scope, target.value, self._advance(value))
            return
        if target.value != "{" or target.value not in _OPEN_TO_CLOSE or start not in self.pairs:
            return
        closing = min(end, self.pairs[start])
        position = start + 1
        while position < closing:
            imported = self.tokens[position]
            if imported.kind != "identifier":
                position += 1
                continue
            local = imported.value
            if position + 2 < closing and self.tokens[position + 1].value in {":", "as"}:
                local_token = self.tokens[position + 2]
                if local_token.kind == "identifier":
                    local = local_token.value
                    position += 2
            self._set_binding(scope, local, self._advance(self._member(value, imported.value, imported.line)))
            position += 1

    def _is_plain_assignment(self, index: int) -> bool:
        if self.tokens[index].kind != "identifier" or index + 1 >= len(self.tokens):
            return False
        if self.tokens[index + 1].value != "=":
            return False
        previous = self.tokens[index - 1].value if index else ";"
        following = self.tokens[index + 2].value if index + 2 < len(self.tokens) else ""
        if previous in {"!", "%", "&", "*", "+", "-", ".", "/", "<", "=", ">", "?", "^", "|"}:
            return False
        if following in {"=", ">"}:
            return False
        return index == 0 or previous in {";", "{", "}"}

    def _process_assignment(self, start: int) -> int:
        end = self._statement_end(start + 2)
        scope = self.scope_at[start]
        value = self._eval_span(start + 2, end, scope, 0)
        self._set_binding(scope, self.tokens[start].value, self._advance(value))
        return max(start + 2, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))

    def _property_assignment(self, index: int) -> tuple[str | None, int] | None:
        if self.tokens[index].kind != "identifier":
            return None
        previous = self.tokens[index - 1].value if index else ";"
        if index and previous not in {";", "{", "}"}:
            return None
        if index + 3 < len(self.tokens) and self.tokens[index + 1].value == ".":
            member = self.tokens[index + 2]
            if member.kind == "identifier" and self.tokens[index + 3].value == "=":
                return member.value, index + 3
        if index + 2 < len(self.tokens) and self.tokens[index + 1].value == "[" and index + 1 in self.pairs:
            closing = self.pairs[index + 1]
            if closing + 1 >= len(self.tokens) or self.tokens[closing + 1].value != "=":
                return None
            key_value = self._eval_span(index + 2, closing, self.scope_at[index], 0)
            key = key_value.strings[0] if len(key_value.strings) == 1 else None
            return key, closing + 1
        return None

    def _process_property_assignment(self, start: int, property_name: str | None, equal: int) -> int:
        end = self._statement_end(equal + 1)
        scope = self.scope_at[start]
        assigned = self._advance(self._eval_span(equal + 1, end, scope, 0))
        base = self._resolve(scope, self.tokens[start].value)
        if property_name is None:
            updated = self._merge([base, assigned])
            updated = _Value(
                updated.origins,
                updated.identities | {"ambiguous_object_shape"},
                updated.strings,
                updated.properties,
            )
        else:
            properties = dict(base.properties)
            properties[property_name] = assigned
            combined = self._merge([base, assigned])
            updated = _Value(
                combined.origins,
                combined.identities,
                combined.strings,
                tuple(properties.items()),
            )
        self._set_binding(scope, self.tokens[start].value, updated)
        return max(equal + 1, end + int(end < len(self.tokens) and self.tokens[end].value == ";"))

    def _eval_span(self, start: int, end: int, scope: int, depth: int) -> _Value:
        self._check_depth(depth)
        values: list[_Value] = []
        position = start
        while position < end:
            token = self.tokens[position]
            if token.kind == "identifier" or token.kind == "string" or token.value in {"(", "[", "{"}:
                value, following = self._parse_atom(
                    position, end, self.scope_at[position] if position < len(self.scope_at) else scope, depth + 1
                )
                values.append(value)
                position = max(position + 1, following)
                continue
            position += 1
        return self._merge(values)

    def _parse_atom(self, start: int, end: int, scope: int, depth: int) -> tuple[_Value, int]:
        self._check_depth(depth)
        if start >= end:
            return _Value(), start
        token = self.tokens[start]
        if token.kind == "string":
            return _Value(strings=(token.value,)), start + 1
        if token.value in _PREFIX_KEYWORDS:
            return self._parse_atom(start + 1, end, scope, depth + 1)
        if token.value == "(" and start in self.pairs:
            closing = self.pairs[start]
            if closing >= end:
                return _Value(), end
            if closing + 2 < end and self.tokens[closing + 1].value == "=" and self.tokens[closing + 2].value == ">":
                return _Value(), closing + 3
            value = self._eval_span(start + 1, closing, scope, depth + 1)
            return self._postfix(value, "", closing + 1, end, scope, depth + 1)
        if token.value == "{" and start in self.pairs:
            closing = self.pairs[start]
            if closing >= end:
                return _Value(), end
            value = self._object_value(start + 1, closing, scope, depth + 1)
            return self._postfix(value, "", closing + 1, end, scope, depth + 1)
        if token.value == "[" and start in self.pairs:
            closing = self.pairs[start]
            if closing >= end:
                return _Value(), end
            value = self._eval_span(start + 1, closing, scope, depth + 1)
            return self._postfix(value, "", closing + 1, end, scope, depth + 1)
        if token.kind != "identifier" or token.value in _EMPTY_IDENTIFIERS:
            return _Value(), start + 1
        if token.value in {"async", "function"}:
            return _Value(), start + 1
        value = self._resolve(scope, token.value)
        return self._postfix(value, token.value, start + 1, end, scope, depth + 1)

    def _postfix(
        self,
        value: _Value,
        canonical: str,
        position: int,
        end: int,
        scope: int,
        depth: int,
    ) -> tuple[_Value, int]:
        self._check_depth(depth)
        while position < end:
            if self.tokens[position].value == "?" and position + 1 < end and self.tokens[position + 1].value == ".":
                position += 1
            if self.tokens[position].value == "." and position + 1 < end:
                member = self.tokens[position + 1]
                if member.kind != "identifier":
                    break
                value = self._member(value, member.value, member.line)
                canonical = f"{canonical}.{member.value}" if canonical else member.value
                position += 2
                continue
            if self.tokens[position].value == "[" and position in self.pairs:
                closing = self.pairs[position]
                if closing >= end:
                    break
                key_value = self._eval_span(position + 1, closing, scope, depth + 1)
                if len(key_value.strings) == 1:
                    key = key_value.strings[0]
                    value = self._member(value, key, self.tokens[position].line)
                    canonical = f"{canonical}.{key}" if canonical else key
                else:
                    value = _Value()
                    canonical = ""
                position = closing + 1
                continue
            if self.tokens[position].value == "(" and position in self.pairs:
                closing = self.pairs[position]
                if closing >= end:
                    break
                args = [
                    self._eval_span(arg_start, arg_end, scope, depth + 1)
                    for arg_start, arg_end in self._argument_spans(position + 1, closing)
                ]
                value = self._call_value(value, canonical, args, self.tokens[position].line)
                canonical = ""
                position = closing + 1
                continue
            break
        return value, position

    def _object_value(self, start: int, end: int, scope: int, depth: int) -> _Value:
        properties: list[tuple[str, _Value]] = []
        values: list[_Value] = []
        identities: set[str] = set()
        for part_start, part_end in self._argument_spans(start, end):
            if part_start >= part_end:
                continue
            if part_start + 2 < part_end and all(self.tokens[part_start + offset].value == "." for offset in range(3)):
                spread = self._eval_span(part_start + 3, part_end, scope, depth + 1)
                properties.extend(spread.properties)
                values.append(spread)
                if spread.origins and not spread.properties:
                    identities.add("ambiguous_object_shape")
                continue
            colon = self._top_level_token(part_start, part_end, ":")
            if colon is not None and colon > part_start:
                key_token = self.tokens[part_start]
                if key_token.kind in {"identifier", "string"}:
                    item = self._eval_span(colon + 1, part_end, scope, depth + 1)
                    properties.append((key_token.value, item))
                    values.append(item)
                    continue
                if key_token.value == "[" and part_start in self.pairs and self.pairs[part_start] == colon - 1:
                    key = self._eval_span(part_start + 1, colon - 1, scope, depth + 1)
                    item = self._eval_span(colon + 1, part_end, scope, depth + 1)
                    values.append(item)
                    if len(key.strings) == 1:
                        properties.append((key.strings[0], item))
                    elif item.origins:
                        identities.add("ambiguous_object_shape")
                    continue
            token = self.tokens[part_start]
            if token.kind == "identifier":
                item = self._resolve(scope, token.value)
                properties.append((token.value, item))
                values.append(item)
            else:
                values.append(self._eval_span(part_start, part_end, scope, depth + 1))
        if len(properties) > MAX_VALUE_PROPERTIES:
            raise _AnalysisLimit("JS_DATAFLOW_VALUE_LIMIT")
        combined = self._merge(values)
        return _Value(
            combined.origins,
            combined.identities | identities,
            combined.strings,
            tuple(properties),
        )

    def _call_value(self, callee: _Value, canonical: str, args: list[_Value], line: int) -> _Value:
        identities = callee.identities
        if "builtin_require" in identities:
            if len(args) == 1 and len(args[0].strings) == 1:
                return self._module_value(args[0].strings[0])
            return _Value()
        if identities & {"builtin_buffer_from"}:
            if len(args) >= 2 and any(value.lower().replace("-", "") == "base64" for value in args[1].strings):
                self._append_fact(self.transforms, JavascriptTransformFact("base64_decode", line))
                return self._merge([args[0], _Value(origins=(_Origin("obfuscation", line),))])
            return _Value()
        if "builtin_atob" in identities:
            self._append_fact(self.transforms, JavascriptTransformFact("base64_decode", line))
            base = args[0] if args else _Value()
            return self._merge([base, _Value(origins=(_Origin("obfuscation", line),))])
        if identities & {"builtin_eval", "builtin_function"}:
            consumed = args[0] if args else _Value()
            self._record_execution("eval" if "builtin_eval" in identities else "Function", line, consumed)
            return _Value()
        child_methods = sorted(
            identity.removeprefix("child_process:") for identity in identities if identity.startswith("child_process:")
        )
        if child_methods:
            method = child_methods[0]
            consumed = self._merge(args[:2] if method.startswith(("spawn", "execFile")) else args[:1])
            self._record_execution(f"child_process.{method}", line, consumed)
            return _Value()
        network_methods = sorted(
            identity.removeprefix("network:") for identity in identities if identity.startswith("network:")
        )
        if network_methods:
            return self._record_network(network_methods[0], line, args)
        if identities & {"fs:read", "fs_promises:read"}:
            path = args[0] if args else _Value()
            if any(_is_sensitive_path(value) for value in path.strings):
                origin = _Origin("credential_file", line)
                self._append_fact(self.sources, JavascriptSourceFact("credential_file", line))
                return _Value(origins=(origin,))
            return _Value()
        write_methods = sorted(
            identity.removeprefix("fs_write:") for identity in identities if identity.startswith("fs_write:")
        )
        if write_methods:
            self._record_filesystem_write(write_methods[0], line, args)
            return _Value()
        if "network_response_reader" in identities:
            return _Value(origins=callee.origins)
        if identities & {"value_preserving", "json_stringify"}:
            return self._merge([callee, *args])
        # Unknown calls are not assumed to return their arguments. This keeps
        # the pass value-provenance based rather than a broad co-occurrence
        # heuristic; reviewed wrappers can be added explicitly with evidence.
        return _Value()

    def _record_network(self, method_identity: str, line: int, args: list[_Value]) -> _Value:
        api_class, method = self._network_api_method(method_identity, args)
        url_value = args[0] if args else _Value()
        payload = _Value()
        authentication = _Value()
        options = _Value()
        if method_identity in {"fetch", "undici.request"} and len(args) >= 2:
            options = args[1]
            payload = self._properties_value(options, _PAYLOAD_PROPERTIES)
            authentication = self._authentication_value(options.property("headers"))
        elif method_identity == "navigator.sendBeacon" and len(args) >= 2:
            payload = args[1]
        elif method_identity.startswith("axios."):
            axios_method = method_identity.removeprefix("axios.")
            if axios_method in {"patch", "post", "put"} and len(args) >= 2:
                payload = args[1]
            elif axios_method == "request" and args:
                url_value = args[0].property("url") or _Value()
                payload = self._properties_value(args[0], _PAYLOAD_PROPERTIES)
                authentication = self._authentication_value(args[0].property("headers"))
                options = args[0]
        if "ambiguous_object_shape" in options.identities and self._sensitive_classes(options):
            raise _AnalysisLimit("JS_DATAFLOW_AMBIGUOUS_NETWORK_PAYLOAD")
        payload = self._merge([payload, self._sensitive_only(url_value)])
        payload_sources = self._sensitive_classes(payload)
        auth_sources = self._sensitive_classes(authentication)
        source_classes = tuple(sorted(payload_sources | auth_sources))
        credential_use: CredentialUse = "payload" if payload_sources else "authentication" if auth_sources else ""
        direction: Literal["inbound", "outbound"] = (
            "outbound" if source_classes or method in {"delete", "patch", "post", "put"} else "inbound"
        )
        endpoints = self._endpoints(url_value)
        auth_providers = {
            provider
            for origin in authentication.origins
            for provider in origin.providers
            if origin.source_class in {"credential_file", "sensitive_environment"}
        }
        provider_bound_authentication = bool(auth_sources) and _authentication_endpoints_match_providers(
            auth_providers,
            endpoints,
        )
        fact = JavascriptNetworkFact(
            api_class=api_class,
            line=line,
            method=method,
            direction=direction,
            downloads=method_identity != "navigator.sendBeacon",
            endpoints=endpoints,
            source_classes=source_classes,
            credential_use=credential_use,
            provider_bound_authentication=provider_bound_authentication,
        )
        self._append_fact(self.networks, fact)
        for source_class in sorted(payload_sources):
            self._append_flow(JavascriptFlowFact(source_class, "network", (), line))
        if auth_sources and not provider_bound_authentication:
            for source_class in sorted(auth_sources):
                self._append_flow(JavascriptFlowFact(source_class, "network", (), line))
        return _Value(origins=(_Origin("network", line),), identities=frozenset({"network_response"}))

    def _network_api_method(self, identity: str, args: list[_Value]) -> tuple[str, str]:
        if identity == "fetch":
            method = "get"
            if len(args) >= 2:
                method_value = args[1].property("method")
                if method_value and method_value.strings:
                    candidate = method_value.strings[0].lower()
                    if candidate in {"delete", "get", "head", "options", "patch", "post", "put"}:
                        method = candidate
            return "fetch", method
        if identity == "undici.request":
            method = "get"
            if len(args) >= 2:
                method_value = args[1].property("method")
                if method_value and method_value.strings:
                    method = method_value.strings[0].lower()
            return "undici.request", method
        if identity == "navigator.sendBeacon":
            return "navigator.sendBeacon", "post"
        method = identity.removeprefix("axios.")
        if method == "request" and args:
            method_value = args[0].property("method")
            method = method_value.strings[0].lower() if method_value and method_value.strings else "get"
        return identity, method

    def _record_execution(self, api_class: str, line: int, consumed: _Value) -> None:
        source_class_values: set[FlowSourceClass] = set()
        for origin in consumed.origins:
            source_class_values.add(origin.source_class)
        # A sensitive process.env member also carries the more precise
        # environment-control origin. Avoid emitting two equivalent execution
        # flows for the same value.
        if "environment_reference" in source_class_values:
            source_class_values.discard("sensitive_environment")
        source_classes = tuple(sorted(source_class_values))
        self._append_fact(
            self.executions,
            JavascriptExecutionFact(api_class, line, bool(consumed.origins), source_classes),
        )
        for source_class in source_classes:
            transforms: tuple[Literal["decode"], ...] = ("decode",) if source_class == "obfuscation" else ()
            self._append_flow(JavascriptFlowFact(source_class, "code_execution", transforms, line))

    def _record_filesystem_write(self, method: str, line: int, args: list[_Value]) -> None:
        if len(args) < 2:
            return
        destination, data = args[0], args[1]
        sources = self._sensitive_classes(data)
        if not sources:
            return
        destination_class: Literal["environment_controlled", "unc_path"] | None = None
        if any(origin.source_class == "environment_reference" for origin in destination.origins):
            destination_class = "environment_controlled"
        elif any(value.startswith(("\\", "//")) for value in destination.strings):
            destination_class = "unc_path"
        if destination_class is None:
            return
        sensitive_sources = tuple(sorted(sources))
        self._append_fact(
            self.filesystem_writes,
            JavascriptFilesystemFact(
                api_class=f"fs.{method}",
                line=line,
                destination_class=destination_class,
                source_classes=sensitive_sources,
            ),
        )
        for source_class in sensitive_sources:
            self._append_flow(JavascriptFlowFact(source_class, "filesystem_write", (), line))

    def _member(self, value: _Value, name: str, line: int) -> _Value:
        exact = value.property(name)
        if exact is not None:
            return exact
        identities: set[str] = set()
        for identity in value.identities:
            if identity == "process" and name == "env":
                identities.add("process_env")
            elif identity == "process_env":
                origins: list[_Origin] = [_Origin("environment_reference", line)]
                self._append_fact(self.sources, JavascriptSourceFact("environment_reference", line))
                if _is_sensitive_name(name):
                    self._append_fact(self.sources, JavascriptSourceFact("sensitive_environment", line))
                    origins.append(
                        _Origin(
                            "sensitive_environment",
                            line,
                            providers=_credential_provider_tokens(name),
                        )
                    )
                return _Value(origins=tuple(origins))
            elif identity == "global" and name == "fetch":
                identities.add("network:fetch")
            elif identity == "global" and name == "eval":
                identities.add("builtin_eval")
            elif identity == "global" and name == "Buffer":
                identities.add("builtin_buffer")
            elif identity == "builtin_buffer" and name == "from":
                identities.add("builtin_buffer_from")
            elif identity == "buffer_namespace" and name == "Buffer":
                identities.add("builtin_buffer")
            elif identity == "child_process_namespace" and name in _CHILD_PROCESS_METHODS:
                identities.add(f"child_process:{name}")
            elif identity in {"fs_namespace", "fs_promises_namespace"} and name in _FS_READ_METHODS:
                prefix = "fs_promises" if identity == "fs_promises_namespace" else "fs"
                identities.add(f"{prefix}:read")
            elif identity in {"fs_namespace", "fs_promises_namespace"} and name in _FS_WRITE_METHODS:
                identities.add(f"fs_write:{name}")
            elif identity == "fs_namespace" and name == "promises":
                identities.add("fs_promises_namespace")
            elif identity == "axios_namespace" and name in _AXIOS_METHODS:
                identities.add(f"network:axios.{name}")
            elif identity == "undici_namespace" and name == "fetch":
                identities.add("network:fetch")
            elif identity == "undici_namespace" and name == "request":
                identities.add("network:undici.request")
            elif identity == "navigator" and name == "sendBeacon":
                identities.add("network:navigator.sendBeacon")
            elif identity == "json_namespace" and name == "stringify":
                identities.add("json_stringify")
            elif identity == "path_namespace" and name in {"join", "resolve"}:
                identities.add("value_preserving")
            elif identity == "network_response" and name in _RESPONSE_METHODS:
                identities.add("network_response_reader")
            elif identity == "network_response" and name in {"body", "data"}:
                identities.add("network_response")
        if name in {"toString", "valueOf"} and value.origins:
            identities.add("value_preserving")
        return _Value(origins=value.origins, identities=frozenset(identities), strings=value.strings)

    def _resolve(self, scope: int, name: str) -> _Value:
        current: int | None = scope
        while current is not None:
            item = self.scopes[current]
            if name in item.bindings:
                return item.bindings[name]
            if name in item.declared:
                return _Value()
            current = item.parent
        builtins = {
            "Buffer": "builtin_buffer",
            "Function": "builtin_function",
            "JSON": "json_namespace",
            "String": "value_preserving",
            "URLSearchParams": "value_preserving",
            "atob": "builtin_atob",
            "encodeURIComponent": "value_preserving",
            "eval": "builtin_eval",
            "fetch": "network:fetch",
            "global": "global",
            "globalThis": "global",
            "navigator": "navigator",
            "process": "process",
            "require": "builtin_require",
            "window": "global",
        }
        identity = builtins.get(name)
        return _Value(identities=frozenset({identity})) if identity else _Value()

    def _module_value(self, module: str) -> _Value:
        if module in _CHILD_PROCESS_MODULES:
            return _Value(identities=frozenset({"child_process_namespace"}))
        if module in _FS_MODULES:
            return _Value(identities=frozenset({"fs_namespace"}))
        if module in _FS_PROMISE_MODULES:
            return _Value(identities=frozenset({"fs_promises_namespace"}))
        if module == "axios":
            return _Value(identities=frozenset({"axios_namespace"}))
        if module in _FETCH_MODULES:
            return _Value(identities=frozenset({"network:fetch"}))
        if module == "undici":
            return _Value(identities=frozenset({"undici_namespace"}))
        if module in {"buffer", "node:buffer"}:
            return _Value(identities=frozenset({"buffer_namespace"}))
        if module in _PATH_MODULES:
            return _Value(identities=frozenset({"path_namespace"}))
        return _Value()

    @staticmethod
    def _module_default(module: str, namespace: _Value) -> _Value:
        if module in _FETCH_MODULES:
            return _Value(identities=frozenset({"network:fetch"}))
        return namespace

    def _set_binding(self, scope: int, name: str, value: _Value) -> None:
        if not name:
            return
        self.scopes[scope].bindings[name] = value

    def _advance(self, value: _Value) -> _Value:
        origins = tuple(
            _Origin(origin.source_class, origin.line, origin.hops + 1, origin.providers) for origin in value.origins
        )
        if any(origin.hops > MAX_JAVASCRIPT_DATAFLOW_HOPS for origin in origins):
            raise _AnalysisLimit("JS_DATAFLOW_HOP_LIMIT")
        properties = tuple((key, self._advance(item)) for key, item in value.properties)
        return _Value(origins, value.identities, value.strings, properties)

    def _merge(self, values: list[_Value]) -> _Value:
        origins = tuple(sorted({origin for value in values for origin in value.origins}))
        identities = frozenset(identity for value in values for identity in value.identities)
        strings = tuple(dict.fromkeys(string for value in values for string in value.strings))
        property_values: dict[str, list[_Value]] = {}
        for value in values:
            for key, item in value.properties:
                property_values.setdefault(key, []).append(item)
        if (
            len(origins) > MAX_VALUE_ORIGINS
            or len(strings) > MAX_VALUE_STRINGS
            or len(property_values) > MAX_VALUE_PROPERTIES
        ):
            raise _AnalysisLimit("JS_DATAFLOW_VALUE_LIMIT")
        properties = tuple((key, self._merge(items)) for key, items in property_values.items())
        return _Value(origins, identities, strings, properties)

    @staticmethod
    def _sensitive_only(value: _Value) -> _Value:
        origins = tuple(
            origin for origin in value.origins if origin.source_class in {"credential_file", "sensitive_environment"}
        )
        return _Value(origins=origins)

    @staticmethod
    def _sensitive_classes(value: _Value) -> set[SensitiveSourceClass]:
        classes: set[SensitiveSourceClass] = set()
        for origin in value.origins:
            if origin.source_class == "credential_file":
                classes.add("credential_file")
            elif origin.source_class == "sensitive_environment":
                classes.add("sensitive_environment")
        return classes

    def _properties_value(self, value: _Value, names: frozenset[str]) -> _Value:
        return self._merge([item for key, item in value.properties if key.lower() in names])

    def _authentication_value(self, headers: _Value | None) -> _Value:
        if headers is None:
            return _Value()
        return self._merge([item for key, item in headers.properties if key.lower() in _AUTH_HEADER_NAMES])

    @staticmethod
    def _endpoints(value: _Value) -> tuple[JavascriptEndpoint, ...]:
        endpoints: list[JavascriptEndpoint] = []
        for fragment in value.strings:
            try:
                parsed = urlsplit(fragment)
            except ValueError:
                continue
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            if scheme not in {"http", "https"} or not host:
                continue
            endpoint = JavascriptEndpoint(scheme, host[:253])
            if endpoint not in endpoints:
                endpoints.append(endpoint)
            if len(endpoints) >= MAX_VALUE_STRINGS:
                break
        return tuple(endpoints)

    def _append_fact(self, target: list[_T], fact: _T) -> None:
        if fact in target:
            return
        if (
            len(self.sources)
            + len(self.networks)
            + len(self.executions)
            + len(self.filesystem_writes)
            + len(self.transforms)
            >= MAX_JAVASCRIPT_DATAFLOW_FACTS
        ):
            raise _AnalysisLimit("JS_DATAFLOW_FACT_LIMIT")
        target.append(fact)

    def _append_flow(self, flow: JavascriptFlowFact) -> None:
        if flow in self.flows:
            return
        if len(self.flows) >= MAX_JAVASCRIPT_DATAFLOW_FLOWS:
            raise _AnalysisLimit("JS_DATAFLOW_FLOW_LIMIT")
        self.flows.append(flow)

    def _statement_end(self, start: int) -> int:
        position = start
        previous = start - 1
        while position < len(self.tokens):
            token = self.tokens[position]
            if token.value == ";":
                return position
            if (
                previous >= start
                and token.line > self.tokens[previous].line
                and self.tokens[previous].value not in _ASI_NON_TERMINATORS
                and token.value not in _ASI_CONTINUATIONS
            ):
                return position
            if token.value in _OPEN_TO_CLOSE and position in self.pairs:
                previous = self.pairs[position]
                position = previous + 1
                continue
            previous = position
            position += 1
        return len(self.tokens)

    def _top_level_token(self, start: int, end: int, value: str) -> int | None:
        position = start
        while position < end:
            token = self.tokens[position]
            if token.value == value:
                return position
            if token.value in _OPEN_TO_CLOSE and position in self.pairs:
                position = self.pairs[position] + 1
                continue
            position += 1
        return None

    def _argument_spans(self, start: int, end: int) -> list[tuple[int, int]]:
        if start >= end:
            return []
        spans: list[tuple[int, int]] = []
        cursor = start
        position = start
        while position < end:
            token = self.tokens[position]
            if token.value == ",":
                spans.append((cursor, position))
                cursor = position + 1
                position += 1
                continue
            if token.value in _OPEN_TO_CLOSE and position in self.pairs:
                position = self.pairs[position] + 1
                continue
            position += 1
        spans.append((cursor, end))
        return spans

    @staticmethod
    def _check_depth(depth: int) -> None:
        if depth > MAX_JAVASCRIPT_DATAFLOW_DEPTH:
            raise _AnalysisLimit("JS_DATAFLOW_DEPTH_LIMIT")


def analyze_javascript_dataflow(source: str) -> JavascriptDataflowResult:
    """Extract bounded same-file JS/TS source, sink, and flow facts.

    Any lexical, structural, or resource-limit failure returns no partial
    facts. Existing signature and YARA candidates therefore remain available
    as fail-open coverage to callers.
    """

    encoded_size = len(source.encode("utf-8", errors="ignore"))
    if encoded_size > MAX_JAVASCRIPT_DATAFLOW_BYTES:
        return JavascriptDataflowResult(
            complete=False,
            error_codes=("JS_DATAFLOW_FILE_LIMIT",),
        )
    expanded_source, template_error = _expand_template_literals(source)
    if template_error is not None:
        return JavascriptDataflowResult(
            complete=False,
            error_codes=(template_error,),
        )
    tokenization = tokenize_javascript(expanded_source, max_tokens=MAX_JAVASCRIPT_DATAFLOW_TOKENS)
    if not tokenization.complete:
        return JavascriptDataflowResult(
            complete=False,
            error_codes=tuple(f"JS_DATAFLOW_{code.removeprefix('JS_')}" for code in tokenization.error_codes),
            tokens_processed=len(tokenization.tokens),
        )
    try:
        return _JavascriptDataflowExtractor(tokenization.tokens).extract()
    except (MemoryError, RecursionError):
        return JavascriptDataflowResult(
            complete=False,
            error_codes=("JS_DATAFLOW_RUNTIME_LIMIT",),
            tokens_processed=len(tokenization.tokens),
        )
    except _AnalysisLimit as error:
        return JavascriptDataflowResult(
            complete=False,
            error_codes=(error.code,),
            tokens_processed=len(tokenization.tokens),
        )


__all__ = [
    "JavascriptDataflowResult",
    "JavascriptEndpoint",
    "JavascriptExecutionFact",
    "JavascriptFilesystemFact",
    "JavascriptFlowFact",
    "JavascriptNetworkFact",
    "JavascriptSourceFact",
    "JavascriptTransformFact",
    "MAX_JAVASCRIPT_DATAFLOW_BINDINGS",
    "MAX_JAVASCRIPT_DATAFLOW_BYTES",
    "MAX_JAVASCRIPT_DATAFLOW_CALLS",
    "MAX_JAVASCRIPT_DATAFLOW_DEPTH",
    "MAX_JAVASCRIPT_DATAFLOW_FACTS",
    "MAX_JAVASCRIPT_DATAFLOW_FLOWS",
    "MAX_JAVASCRIPT_DATAFLOW_HOPS",
    "MAX_JAVASCRIPT_DATAFLOW_SCOPES",
    "MAX_JAVASCRIPT_DATAFLOW_TOKENS",
    "analyze_javascript_dataflow",
]
