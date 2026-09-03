# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Conservative static validator for the trusted CEL expression subset.

The official CEL compiler remains authoritative for syntax and type checking
once a qualified native runtime is available. This module deliberately does
not implement CEL evaluation. It parses only Skill Scanner's small policy
subset so invalid protobuf paths, incompatible scalar operations, and
non-Boolean rules fail during pack validation even in the staged/off mode.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

from google.protobuf.descriptor import Descriptor, FieldDescriptor
from google.protobuf.descriptor_pb2 import FileDescriptorProto

from ..semantic import scan_facts_pb2


class CelValidationError(ValueError):
    """A CEL expression is outside Skill Scanner's bounded subset."""


@dataclass(frozen=True)
class CelExpressionLimits:
    max_expression_bytes: int = 16 * 1_024
    max_tokens: int = 4_096
    max_ast_nodes: int = 4_096
    max_depth: int = 64
    max_comprehension_depth: int = 2
    max_literal_regex_chars: int = 512


_TOKEN_RE = re.compile(
    r"(?P<SPACE>[ \t\r\n]+)"
    r"|(?P<COMMENT>//[^\r\n]*)"
    r"|(?P<STRING>'(?:\\[^\r\n]|[^'\\\r\n])*'|\"(?:\\[^\r\n]|[^\"\\\r\n])*\")"
    r"|(?P<NUMBER>[0-9]+[uU]|[0-9]+\.[0-9]+|[0-9]+)"
    r"|(?P<OP>&&|\|\||==|!=|<=|>=|<|>|!)"
    r"|(?P<DOT>\.)"
    r"|(?P<LPAREN>\()"
    r"|(?P<RPAREN>\))"
    r"|(?P<COMMA>,)"
    r"|(?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)",
    re.DOTALL,
)

_METHODS = {"startsWith", "endsWith", "contains", "matches", "exists", "all"}
_MACROS = {"exists", "all"}
_RESERVED_IDENTIFIERS = {
    "as",
    "break",
    "const",
    "continue",
    "else",
    "false",
    "for",
    "function",
    "has",
    "if",
    "import",
    "in",
    "let",
    "loop",
    "namespace",
    "null",
    "package",
    "return",
    "true",
    "var",
    "void",
    "while",
}
_RE2_UNSUPPORTED = (
    (re.compile(r"\(\?(?:[=!]|<[=!])"), "lookaround"),
    (re.compile(r"\(\?(?!:)"), "group extension"),
    (re.compile(r"\\(?:[1-9][0-9]*|g[<{]|k[<{'])"), "backreference"),
    (re.compile(r"(?:[*+?]|\{\d+(?:,\d*)?\})\+"), "possessive quantifier"),
    (re.compile(r"\(\*"), "backtracking control"),
)
_REGEX_ALLOWED_ESCAPES = frozenset(r"AbBdDsSwWafnrtv.*+?()|[]{}^$\\-")
_REGEX_REPEAT_RE = re.compile(r"\{([0-9]+)(?:,([0-9]*))?\}")


def _decimal_exceeds(digits: str, maximum: int) -> bool:
    """Compare an arbitrary-size decimal literal without Python int parsing."""

    normalized = digits.lstrip("0") or "0"
    limit = str(maximum)
    return len(normalized) > len(limit) or (len(normalized) == len(limit) and normalized > limit)


def _regex_repetitions(pattern: str) -> list[tuple[int, int]]:
    """Return unescaped RE2 repetition bounds outside character classes."""

    repetitions: list[tuple[int, int]] = []
    index = 0
    in_character_class = False
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            index += 4 if index + 1 < len(pattern) and pattern[index + 1] == "x" else 2
            continue
        if character == "[":
            in_character_class = True
            index += 1
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            index += 1
            continue
        if character == "{" and not in_character_class:
            repeat = _REGEX_REPEAT_RE.match(pattern, index)
            if repeat is not None:
                minimum = int(repeat.group(1))
                maximum_text = repeat.group(2)
                maximum = int(maximum_text) if maximum_text else minimum
                repetitions.append((minimum, maximum))
                index = repeat.end()
                continue
        index += 1
    return repetitions


def _tokenize(expression: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(expression):
        match = _TOKEN_RE.match(expression, position)
        if not match:
            fragment = expression[position : position + 20]
            raise CelValidationError(f"unsupported CEL token near {fragment!r}")
        position = match.end()
        kind = match.lastgroup or ""
        if kind not in {"SPACE", "COMMENT"}:
            tokens.append((kind, match.group()))
    return tokens


def _decode_cel_string_literal(literal: str) -> str:
    """Decode the ordinary CEL string form accepted by the subset tokenizer."""

    body = literal[1:-1]
    result: list[str] = []
    index = 0
    simple_escapes = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "?": "?",
        "'": "'",
        '"': '"',
    }
    while index < len(body):
        character = body[index]
        if character != "\\":
            code_point = ord(character)
            if code_point < 0x20 or code_point == 0x7F:
                raise CelValidationError("CEL string literal contains an unescaped control character")
            if 0xD800 <= code_point <= 0xDFFF:
                raise CelValidationError("CEL string literal contains an invalid surrogate code point")
            result.append(character)
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise CelValidationError("invalid CEL string escape at end of literal")
        escape = body[index]
        if escape in simple_escapes:
            result.append(simple_escapes[escape])
            index += 1
            continue
        widths = {"x": 2, "u": 4, "U": 8}
        width = widths.get(escape)
        if width is None:
            raise CelValidationError(f"invalid CEL string escape \\{escape}")
        digits = body[index + 1 : index + 1 + width]
        if len(digits) != width or not all(value in "0123456789abcdefABCDEF" for value in digits):
            raise CelValidationError(f"invalid CEL \\{escape} escape")
        try:
            code_point = int(digits, 16)
            if code_point > 0x10FFFF or 0xD800 <= code_point <= 0xDFFF:
                raise CelValidationError(f"invalid CEL \\{escape} code point")
            result.append(chr(code_point))
        except ValueError as exc:
            raise CelValidationError(f"invalid CEL \\{escape} code point") from exc
        index += width + 1
    return "".join(result)


def _validate_literal_regex(literal: str, limits: CelExpressionLimits) -> None:
    pattern = _decode_cel_string_literal(literal)
    if len(pattern) > limits.max_literal_regex_chars:
        raise CelValidationError("literal CEL regex exceeds 512 characters")
    for unsupported, feature in _RE2_UNSUPPORTED:
        if unsupported.search(pattern):
            raise CelValidationError(f"literal CEL regex uses RE2-unsupported {feature}")
    for minimum, maximum in _regex_repetitions(pattern):
        if minimum > 1_000 or maximum > 1_000:
            raise CelValidationError("literal CEL regex repetition exceeds RE2 limit 1000")
    index = 0
    while index < len(pattern):
        if pattern[index] != "\\":
            index += 1
            continue
        if index + 1 >= len(pattern):
            raise CelValidationError("invalid CEL regex literal: trailing escape")
        escape = pattern[index + 1]
        if escape == "x":
            digits = pattern[index + 2 : index + 4]
            if len(digits) != 2 or not all(value in "0123456789abcdefABCDEF" for value in digits):
                raise CelValidationError("invalid CEL regex literal: invalid hexadecimal escape")
            index += 4
            continue
        if escape not in _REGEX_ALLOWED_ESCAPES:
            raise CelValidationError(f"literal CEL regex escape \\{escape} is outside the supported RE2 subset")
        index += 2
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            re.compile(pattern)
    except (re.error, FutureWarning) as exc:
        raise CelValidationError(f"invalid CEL regex literal: {exc}") from exc


@dataclass(frozen=True)
class _StaticType:
    kind: str
    message: Descriptor | None = None
    element: _StaticType | None = None

    @property
    def display_name(self) -> str:
        if self.kind == "message" and self.message is not None:
            return str(self.message.full_name)
        if self.kind == "list" and self.element is not None:
            return f"list({self.element.display_name})"
        return self.kind


@dataclass(frozen=True)
class _ExpressionInfo:
    static_type: _StaticType
    field_selection: bool = False
    ast_nodes: int = 1
    ast_depth: int = 1


_BOOL = _StaticType("bool")
_STRING = _StaticType("string")
_INT = _StaticType("int")
_UINT = _StaticType("uint")
_DOUBLE = _StaticType("double")


def _is_repeated_field(field: FieldDescriptor) -> bool:
    """Handle the protobuf 5/6 descriptor API transition without guesswork."""

    try:
        return bool(field.is_repeated)
    except AttributeError:
        pass
    try:
        return bool(field.label == FieldDescriptor.LABEL_REPEATED)
    except AttributeError:
        # Some upb compatibility builds expose neither usable convenience
        # property. The canonical serialized descriptor remains stable.
        file_proto = FileDescriptorProto.FromString(field.file.serialized_pb)
        relative_name = str(field.containing_type.full_name)
        if file_proto.package and relative_name.startswith(f"{file_proto.package}."):
            relative_name = relative_name[len(file_proto.package) + 1 :]
        messages = file_proto.message_type
        message_proto = None
        for part in relative_name.split("."):
            message_proto = next((item for item in messages if item.name == part), None)
            if message_proto is None:
                raise CelValidationError(f"cannot resolve protobuf descriptor for {field.full_name!r}")
            messages = message_proto.nested_type
        assert message_proto is not None
        field_proto = next((item for item in message_proto.field if item.number == field.number), None)
        if field_proto is None:
            raise CelValidationError(f"cannot resolve protobuf descriptor for {field.full_name!r}")
        return bool(field_proto.label == field_proto.LABEL_REPEATED)


def _field_type(field: FieldDescriptor) -> _StaticType:
    if field.type == FieldDescriptor.TYPE_MESSAGE:
        value_type = _StaticType("message", message=field.message_type)
    elif field.type == FieldDescriptor.TYPE_BOOL:
        value_type = _BOOL
    elif field.type == FieldDescriptor.TYPE_STRING:
        value_type = _STRING
    elif field.type in {
        FieldDescriptor.TYPE_INT32,
        FieldDescriptor.TYPE_INT64,
        FieldDescriptor.TYPE_SINT32,
        FieldDescriptor.TYPE_SINT64,
        FieldDescriptor.TYPE_SFIXED32,
        FieldDescriptor.TYPE_SFIXED64,
    }:
        value_type = _INT
    elif field.type in {
        FieldDescriptor.TYPE_UINT32,
        FieldDescriptor.TYPE_UINT64,
        FieldDescriptor.TYPE_FIXED32,
        FieldDescriptor.TYPE_FIXED64,
    }:
        value_type = _UINT
    elif field.type in {FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_DOUBLE}:
        value_type = _DOUBLE
    else:
        raise CelValidationError(f"protobuf field {field.full_name!r} has unsupported CEL type {field.type}")

    if _is_repeated_field(field):
        if field.message_type is not None and field.message_type.GetOptions().map_entry:
            raise CelValidationError(f"protobuf map field {field.full_name!r} is not permitted")
        return _StaticType("list", element=value_type)
    return value_type


def _same_type(left: _StaticType, right: _StaticType) -> bool:
    if left.kind != right.kind:
        return False
    if left.kind == "message":
        return bool(
            left.message is not None and right.message is not None and left.message.full_name == right.message.full_name
        )
    if left.kind == "list":
        return bool(left.element is not None and right.element is not None and _same_type(left.element, right.element))
    return True


class _SubsetTypeChecker:
    """Recursive-descent parser and protobuf-aware checker for our subset."""

    def __init__(self, tokens: list[tuple[str, str]], limits: CelExpressionLimits) -> None:
        self.tokens = tokens
        self.limits = limits
        self.position = 0
        self.depth = 0
        self.max_depth = 0
        self.comprehension_depth = 0
        self.bindings: dict[str, _StaticType] = {}
        self.ast_nodes = 0

    def _node(
        self,
        static_type: _StaticType,
        *children: _ExpressionInfo,
        field_selection: bool = False,
    ) -> _ExpressionInfo:
        """Create one bounded source-AST node.

        Counting nodes independently from lexer tokens gives the configured
        4,096-node limit its intended meaning. Tracking the composed depth also
        catches long unary or Boolean chains that contain no parentheses.
        """

        self.ast_nodes += 1
        if self.ast_nodes > self.limits.max_ast_nodes:
            raise CelValidationError("CEL expression exceeds AST node budget")
        ast_depth = 1 + max((child.ast_depth for child in children), default=0)
        if ast_depth > self.limits.max_depth:
            raise CelValidationError("CEL expression AST depth exceeds 64")
        return _ExpressionInfo(
            static_type,
            field_selection=field_selection,
            ast_nodes=1 + sum(child.ast_nodes for child in children),
            ast_depth=ast_depth,
        )

    def check(self) -> None:
        result = self._parse_or()
        if self.position != len(self.tokens):
            kind, value = self.tokens[self.position]
            if kind == "RPAREN":
                raise CelValidationError("unbalanced CEL parentheses")
            raise CelValidationError(f"unexpected CEL token {value!r}")
        if result.static_type.kind != "bool":
            raise CelValidationError(
                "CEL expression must return bool; "
                f"descriptor-backed validation inferred {result.static_type.display_name}"
            )

    def _peek(self, kind: str | None = None, value: str | None = None) -> bool:
        if self.position >= len(self.tokens):
            return False
        token_kind, token_value = self.tokens[self.position]
        return (kind is None or token_kind == kind) and (value is None or token_value == value)

    def _consume(self, kind: str | None = None, value: str | None = None) -> tuple[str, str]:
        if not self._peek(kind, value):
            expected = value if value is not None else kind or "token"
            if self.position >= len(self.tokens):
                raise CelValidationError(f"expected {expected}, found end of CEL expression")
            raise CelValidationError(f"expected {expected}, found {self.tokens[self.position][1]!r}")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _enter_parenthesis(self) -> None:
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        if self.max_depth > self.limits.max_depth:
            raise CelValidationError("CEL expression nesting exceeds 64")

    def _leave_parenthesis(self) -> None:
        self.depth -= 1

    def _parse_or(self) -> _ExpressionInfo:
        left = self._parse_and()
        while self._peek("OP", "||"):
            self._consume("OP", "||")
            right = self._parse_and()
            self._require_bool(left, "operator '||'")
            self._require_bool(right, "operator '||'")
            left = self._node(_BOOL, left, right)
        return left

    def _parse_and(self) -> _ExpressionInfo:
        left = self._parse_relation()
        while self._peek("OP", "&&"):
            self._consume("OP", "&&")
            right = self._parse_relation()
            self._require_bool(left, "operator '&&'")
            self._require_bool(right, "operator '&&'")
            left = self._node(_BOOL, left, right)
        return left

    def _parse_relation(self) -> _ExpressionInfo:
        left = self._parse_unary()
        if self._peek("OP") and self.tokens[self.position][1] in {"==", "!=", "<", "<=", ">", ">="}:
            operator = self._consume("OP")[1]
            right = self._parse_unary()
            if not _same_type(left.static_type, right.static_type):
                raise CelValidationError(
                    f"operator {operator!r} has incompatible types "
                    f"{left.static_type.display_name} and {right.static_type.display_name}"
                )
            if operator not in {"==", "!="} and left.static_type.kind not in {"int", "uint", "double", "string"}:
                raise CelValidationError(
                    f"ordering operator {operator!r} is not permitted for {left.static_type.display_name}"
                )
            return self._node(_BOOL, left, right)

        if self._peek("IDENT", "in"):
            self._consume("IDENT", "in")
            right = self._parse_unary()
            if right.static_type.kind != "list" or right.static_type.element is None:
                raise CelValidationError("operator 'in' requires a repeated protobuf field on the right")
            if not _same_type(left.static_type, right.static_type.element):
                raise CelValidationError(
                    "operator 'in' has incompatible element types "
                    f"{left.static_type.display_name} and {right.static_type.element.display_name}"
                )
            return self._node(_BOOL, left, right)
        return left

    def _parse_unary(self) -> _ExpressionInfo:
        negations = 0
        while self._peek("OP", "!"):
            self._consume("OP", "!")
            negations += 1
        value = self._parse_postfix()
        for _ in range(negations):
            self._require_bool(value, "operator '!'")
            value = self._node(_BOOL, value)
        return value

    def _parse_postfix(self) -> _ExpressionInfo:
        value = self._parse_primary()
        while self._peek("DOT"):
            self._consume("DOT")
            _, member_name = self._consume("IDENT")
            if self._peek("LPAREN"):
                if member_name not in _METHODS:
                    raise CelValidationError(f"method {member_name!r} is not permitted")
                if member_name in _MACROS:
                    value = self._parse_comprehension(value, member_name)
                else:
                    value = self._parse_string_method(value, member_name)
                continue
            value = self._select_field(value, member_name)
        return value

    def _parse_primary(self) -> _ExpressionInfo:
        if self._peek("LPAREN"):
            self._consume("LPAREN")
            self._enter_parenthesis()
            value = self._parse_or()
            if not self._peek("RPAREN"):
                raise CelValidationError("unbalanced CEL parentheses")
            self._consume("RPAREN")
            self._leave_parenthesis()
            return _ExpressionInfo(
                value.static_type,
                field_selection=value.field_selection,
                ast_nodes=value.ast_nodes,
                ast_depth=value.ast_depth,
            )

        if self._peek("STRING"):
            literal = self._consume("STRING")[1]
            _decode_cel_string_literal(literal)
            return self._node(_STRING)

        if self._peek("NUMBER"):
            number = self._consume("NUMBER")[1]
            if number[-1:] in {"u", "U"}:
                if _decimal_exceeds(number[:-1], 2**64 - 1):
                    raise CelValidationError("CEL uint literal exceeds uint64 range")
                return self._node(_UINT)
            if "." in number:
                return self._node(_DOUBLE)
            if _decimal_exceeds(number, 2**63 - 1):
                raise CelValidationError("CEL int literal exceeds int64 range")
            return self._node(_INT)

        if not self._peek("IDENT"):
            if self.position >= len(self.tokens):
                raise CelValidationError("unexpected end of CEL expression")
            raise CelValidationError(f"unexpected CEL token {self.tokens[self.position][1]!r}")

        _, identifier = self._consume("IDENT")
        if identifier in {"true", "false"}:
            return self._node(_BOOL)
        if identifier == "f":
            return self._node(_StaticType("message", message=scan_facts_pb2.ScanFacts.DESCRIPTOR))
        if identifier in self.bindings:
            return self._node(self.bindings[identifier])
        if self._peek("LPAREN"):
            if identifier == "has":
                return self._parse_has()
            raise CelValidationError(f"function {identifier!r} is not permitted")
        if identifier == "in":
            raise CelValidationError("operator 'in' is missing its left operand")
        raise CelValidationError(f"undeclared top-level identifier {identifier!r}")

    def _parse_has(self) -> _ExpressionInfo:
        self._consume("LPAREN")
        self._enter_parenthesis()
        value = self._parse_or()
        if not self._peek("RPAREN"):
            raise CelValidationError("unbalanced CEL parentheses")
        self._consume("RPAREN")
        self._leave_parenthesis()
        if not value.field_selection:
            raise CelValidationError("has requires a protobuf field selection")
        return self._node(_BOOL, value)

    def _parse_comprehension(self, receiver: _ExpressionInfo, method_name: str) -> _ExpressionInfo:
        if receiver.static_type.kind != "list" or receiver.static_type.element is None:
            raise CelValidationError(f"{method_name} requires a repeated protobuf field")
        self._consume("LPAREN")
        self._enter_parenthesis()
        if not self._peek("IDENT"):
            raise CelValidationError(f"{method_name} must bind one identifier")
        binding = self._consume("IDENT")[1]
        if binding == "f" or binding in _RESERVED_IDENTIFIERS:
            raise CelValidationError(
                f"comprehension binding {binding!r} cannot shadow the typed root variable or use a reserved name"
            )
        if not self._peek("COMMA"):
            raise CelValidationError(f"{method_name} must bind one identifier")
        self._consume("COMMA")

        self.comprehension_depth += 1
        if self.comprehension_depth > self.limits.max_comprehension_depth:
            raise CelValidationError("CEL comprehension nesting exceeds two")
        previous = self.bindings.get(binding)
        had_previous = binding in self.bindings
        self.bindings[binding] = receiver.static_type.element
        try:
            predicate = self._parse_or()
        finally:
            if had_previous:
                assert previous is not None
                self.bindings[binding] = previous
            else:
                self.bindings.pop(binding, None)
            self.comprehension_depth -= 1

        if not self._peek("RPAREN"):
            raise CelValidationError("unbalanced CEL parentheses")
        self._consume("RPAREN")
        self._leave_parenthesis()
        self._require_bool(predicate, f"{method_name} predicate")
        return self._node(_BOOL, receiver, predicate)

    def _parse_string_method(self, receiver: _ExpressionInfo, method_name: str) -> _ExpressionInfo:
        if receiver.static_type.kind != "string":
            raise CelValidationError(
                f"{method_name} requires a string receiver, found {receiver.static_type.display_name}"
            )
        self._consume("LPAREN")
        self._enter_parenthesis()
        if not self._peek("STRING"):
            raise CelValidationError(f"{method_name} requires a literal string argument")
        literal = self._consume("STRING")[1]
        _decode_cel_string_literal(literal)
        literal_info = self._node(_STRING)
        if not self._peek("RPAREN"):
            raise CelValidationError(f"{method_name} requires a literal string argument")
        self._consume("RPAREN")
        self._leave_parenthesis()
        if method_name == "matches":
            _validate_literal_regex(literal, self.limits)
        return self._node(_BOOL, receiver, literal_info)

    def _select_field(self, receiver: _ExpressionInfo, field_name: str) -> _ExpressionInfo:
        message = receiver.static_type.message
        if receiver.static_type.kind != "message" or message is None:
            raise CelValidationError(f"cannot select field {field_name!r} from {receiver.static_type.display_name}")
        field = message.fields_by_name.get(field_name)
        if field is None:
            raise CelValidationError(f"undefined protobuf field {field_name!r} on {message.full_name}")
        return self._node(_field_type(field), receiver, field_selection=True)

    @staticmethod
    def _require_bool(value: _ExpressionInfo, context: str) -> None:
        if value.static_type.kind != "bool":
            raise CelValidationError(f"{context} requires bool, found {value.static_type.display_name}")


def validate_cel_expression(expression: str, limits: CelExpressionLimits | None = None) -> None:
    """Validate one expression against the bounded, typed ScanFacts subset."""

    limits = limits or CelExpressionLimits()
    if not isinstance(expression, str) or not expression.strip():
        raise CelValidationError("CEL expression must be a non-empty string")
    try:
        expression_size = len(expression.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise CelValidationError("CEL expression contains an invalid Unicode code point") from exc
    if expression_size > limits.max_expression_bytes:
        raise CelValidationError("CEL expression exceeds 16 KiB")

    tokens = _tokenize(expression)
    if len(tokens) > limits.max_tokens:
        raise CelValidationError("CEL expression exceeds token/AST budget")
    if not any(kind == "IDENT" and value == "f" for kind, value in tokens):
        raise CelValidationError("CEL expression must reference the typed root variable 'f'")

    # Decode every literal up front so invalid escapes cannot hide in ordinary
    # comparisons or literal-only string methods. Regexes receive additional
    # RE2-subset validation when their method call is parsed.
    for kind, value in tokens:
        if kind == "STRING":
            _decode_cel_string_literal(value)

    _SubsetTypeChecker(tokens, limits).check()
