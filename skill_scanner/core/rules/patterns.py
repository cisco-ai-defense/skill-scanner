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

"""
Pattern matching utilities for security rules.
"""

import ast
import logging
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

import yaml

from ...core.models import Severity, ThreatCategory
from ..static_analysis.javascript_tokens import tokenize_javascript

logger = logging.getLogger(__name__)

CategoryResolution = Literal["native", "legacy_mapped", "unknown_fallback"]

# Reviewed compatibility map for the two bundled legacy taxonomies.  This is
# intentionally not consulted in strict mode: schema-v2 packs must use the
# canonical ThreatCategory enum and fail startup on every unknown value.
LEGACY_SIGNATURE_CATEGORY_MAP = MappingProxyType(
    {
        # ATR categories
        "agent_manipulation": ThreatCategory.SOCIAL_ENGINEERING,
        "context_exfiltration": ThreatCategory.DATA_EXFILTRATION,
        "data_poisoning": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
        "excessive_autonomy": ThreatCategory.AUTONOMY_ABUSE,
        "model_abuse": ThreatCategory.HARMFUL_CONTENT,
        "model_security": ThreatCategory.POLICY_VIOLATION,
        "privilege_escalation": ThreatCategory.UNAUTHORIZED_TOOL_USE,
        "skill_compromise": ThreatCategory.SUPPLY_CHAIN_ATTACK,
        "tool_poisoning": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
        # PromptGuard category
        "pii_exposure": ThreatCategory.DATA_EXFILTRATION,
    }
)


@dataclass(frozen=True)
class CategoryNormalizationMetrics:
    """Per-generation accounting for signature category normalization."""

    native_rules: int = 0
    legacy_mapped_rules: int = 0
    unknown_fallback_rules: int = 0
    mapped_source_categories: tuple[tuple[str, int], ...] = ()
    unknown_source_categories: tuple[tuple[str, int], ...] = ()

    @property
    def total_rules(self) -> int:
        return self.native_rules + self.legacy_mapped_rules + self.unknown_fallback_rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "native_rules": self.native_rules,
            "legacy_mapped_rules": self.legacy_mapped_rules,
            "unknown_fallback_rules": self.unknown_fallback_rules,
            "mapped_source_categories": dict(self.mapped_source_categories),
            "unknown_source_categories": dict(self.unknown_source_categories),
            "total_rules": self.total_rules,
        }


SIGNATURE_CONTEXT_KINDS = frozenset(
    {
        "active_instruction",
        "code",
        "documentation",
        "example",
        "instruction",
        "negative_example",
        "package",
        "prohibition",
        "unknown",
    }
)
SIGNATURE_POLARITIES = frozenset({"active", "illustrative", "negative", "unknown"})

# Matches a regex character class like [^\n] or [a-z0-9].
# Used to strip character-class contents before checking whether a pattern
# contains \n for genuine multiline spanning (vs single-line [^\n] anchoring).
_CHAR_CLASS_RE = re.compile(r"\[[^\]]*\]")

_JS_BUN_SPAWN_PREFIX = re.compile(r"\bBun\s*\.\s*$")
_JS_BUN_GUARD_MAX_CHARS = 65_536
_JS_BUN_GUARD_MAX_TOKENS = 4096
_JS_BUN_DYNAMIC_CODE = frozenset(
    {
        "eval",
        "Function",
        "AsyncFunction",
        "constructor",
        "Object",
        "Reflect",
        "Proxy",
        "globalThis",
        "global",
        "self",
        "window",
        "setTimeout",
        "setInterval",
    }
)
_JS_BUN_SENSITIVE_STRING = re.compile(r"\b(?:Bun|process|spawnSync|execPath)\b")
_JS_BUN_ALLOWED_PROCESS_PREFIXES = (
    ("process", ".", "execPath", ","),
    ("process", ".", "execPath", "]"),
    ("process", ".", "argv", ".", "slice", "("),
    ("process", ".", "cwd", "("),
    ("process", ".", "env", ","),
    ("process", ".", "env", "}"),
    ("process", ".", "stdout", ".", "write", "("),
    ("process", ".", "stderr", ".", "write", "("),
    ("process", ".", "exit", "("),
)


def _js_matching_group_end(source: str, start: int) -> int | None:
    """Find a call's closing parenthesis, failing closed on ambiguous syntax."""
    if start >= len(source) or source[start] != "(":
        return None
    pairs = {"[": "]", "{": "}", "(": ")"}
    stack = ["("]
    quote = ""
    escaped = False
    for index in range(start + 1, min(len(source), start + 4096)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
        elif char in "`/":
            # Templates, comments, and regex literals need a JS parser. Do not
            # suppress a finding when one appears in the call.
            return None
        elif char in pairs:
            stack.append(char)
        elif char in "]})":
            if not stack or pairs[stack[-1]] != char:
                return None
            stack.pop()
            if not stack:
                return index
    return None


def _js_split_top_level(source: str) -> list[str] | None:
    """Split simple JS arguments without treating nested commas as separators."""
    pairs = {"[": "]", "{": "}", "(": ")"}
    stack: list[str] = []
    quote = ""
    escaped = False
    start = 0
    parts: list[str] = []
    for index, char in enumerate(source):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
        elif char in "`/":
            return None
        elif char in pairs:
            stack.append(char)
        elif char in "]})":
            if not stack or pairs[stack[-1]] != char:
                return None
            stack.pop()
        elif char == "," and not stack:
            part = source[start:index].strip()
            if not part:
                return None
            parts.append(part)
            start = index + 1
    if quote or stack:
        return None
    last = source[start:].strip()
    if last:
        parts.append(last)
    elif source and not source.rstrip().endswith(","):
        return None
    return parts


def _js_plain_string(source: str) -> str | None:
    """Decode only ordinary quoted literals; escaped/dynamic strings stay unknown."""
    if len(source) >= 2 and source[0] in "\"'" and source[-1] == source[0] and "\\" not in source:
        return source[1:-1]
    return None


def _js_bun_options(source: str | None) -> dict[str, str] | None:
    """Parse a plain options object; reject spread, shorthand, and computed keys."""
    if source is None:
        return {}
    if not source.startswith("{") or not source.endswith("}"):
        return None
    entries = _js_split_top_level(source[1:-1])
    if entries is None:
        return None
    options = {}
    for entry in entries:
        key, separator, value = entry.partition(":")
        key = key.strip()
        value = value.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_$][\w$]*", key) or not value or key in options:
            return None
        options[key] = value
    return options


def _js_code_prefix(source: str, end: int) -> str | None:
    """Mask strings and comments before checking a nearby constant binding."""
    if end > 4096:
        return None
    code = list(source[:end])
    quote = ""
    escaped = False
    comment = ""
    index = 0
    while index < end:
        char = source[index]
        next_char = source[index + 1] if index + 1 < end else ""
        if comment == "line":
            if char in "\r\n":
                comment = ""
            else:
                code[index] = " "
            index += 1
            continue
        if comment == "block":
            code[index] = " "
            if char == "*" and next_char == "/":
                code[index + 1] = " "
                comment = ""
                index += 2
            else:
                index += 1
            continue
        if quote:
            code[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            code[index] = " "
            quote = char
        elif char == "/" and next_char in {"/", "*"}:
            code[index : index + 2] = [" ", " "]
            comment = "line" if next_char == "/" else "block"
            index += 2
            continue
        elif char in "`/":
            return None
        index += 1
    return "".join(code) if not quote and comment != "block" else None


def _is_safe_bun_spawn_sync(source: str, open_paren: int) -> bool:
    """Recognize only the two reviewed fixed Bun bootstrap call shapes."""
    end = _js_matching_group_end(source, open_paren)
    if end is None:
        return False
    call_args = _js_split_top_level(source[open_paren + 1 : end])
    if call_args is None or len(call_args) not in {1, 2}:
        return False
    command = call_args[0]
    if not command.startswith("[") or not command.endswith("]"):
        return False
    argv = _js_split_top_level(command[1:-1])
    if not argv or argv[0] != "process.execPath":
        return False
    options = _js_bun_options(call_args[1] if len(call_args) == 2 else None)
    if options is None:
        return False
    if len(argv) == 3 and [_js_plain_string(item) for item in argv[1:]] == ["install", "--frozen-lockfile"]:
        code_prefix = _js_code_prefix(source, open_paren)
        if code_prefix is None:
            return False
        declarations = re.findall(r"\b(?:const|let|var)\s+scriptsDirectory\b[^;]*;", code_prefix)
        return (
            options == {"cwd": "scriptsDirectory"}
            and len(declarations) == 1
            and re.fullmatch(r"const\s+scriptsDirectory\s*=\s*import\.meta\.dir\s*;", declarations[0]) is not None
            and not re.search(r"\bfunction\b[^{};]*\([^)]*\bscriptsDirectory\b", code_prefix)
            and not re.search(r"\([^)]*\bscriptsDirectory\b[^)]*\)\s*=>", code_prefix)
        )
    if len(argv) == 2 and argv[1] == "...process.argv.slice(1)":
        return options == {
            "cwd": "process.cwd()",
            "env": "process.env",
            "stdin": '"inherit"',
            "stdout": '"inherit"',
            "stderr": '"inherit"',
        }
    return False


def _js_bun_globals_unchanged(source: str) -> bool:
    """Reject bounded sources with shadowing, mutation, or dynamic code shapes."""
    if len(source) > _JS_BUN_GUARD_MAX_CHARS:
        return False
    tokenization = tokenize_javascript(source, max_tokens=_JS_BUN_GUARD_MAX_TOKENS)
    if not tokenization.complete:
        return False
    tokens = tokenization.tokens
    values = [token.value for token in tokens]
    for index, token in enumerate(tokens):
        if token.kind == "string" and _JS_BUN_SENSITIVE_STRING.search(token.value):
            # Computed properties and dynamic source strings are ambiguous.
            return False
        if token.kind != "identifier":
            continue
        if token.value in _JS_BUN_DYNAMIC_CODE:
            return False
        if token.value == "Bun":
            if (index > 0 and values[index - 1] in {".", "[", "?"}) or values[index + 1 : index + 4] != [
                ".",
                "spawnSync",
                "(",
            ]:
                return False
        elif token.value == "process":
            if index > 0 and values[index - 1] == "?":
                return False
            if index > 0 and values[index - 1] == "." and values[index - 3 : index] != [".", ".", "."]:
                return False
            if not any(
                values[index : index + len(prefix)] == list(prefix) for prefix in _JS_BUN_ALLOWED_PROCESS_PREFIXES
            ):
                return False
        elif token.value == "import" and values[index : index + 5] == ["import", ".", "meta", ".", "dir"]:
            if values[index + 5 : index + 6] != [";"]:
                return False
    return True


# A failed or over-budget parse must leave the regex finding in place.  These
# limits match the bounded Python analysis used elsewhere in the scanner.
_MAX_SUBPROCESS_SOURCE_BYTES = 1024 * 1024
_MAX_SUBPROCESS_AST_NODES = 50_000
_SUBPROCESS_SAFE_KEYWORDS = {
    "run": frozenset({"input", "capture_output", "text", "check", "timeout", "shell"}),
    "call": frozenset({"timeout", "shell"}),
    "Popen": frozenset({"shell"}),
}
_DYNAMIC_BINDING_NAMES = frozenset(
    {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "patch",
        "monkeypatch",
        "__import__",
        "__builtins__",
    }
)


def _fixed_data_argument(node: ast.expr) -> bool:
    """Accept literal argv data or an f-string with a fixed, non-option prefix.

    An arbitrary value in its own argv element may be interpreted as an option
    by the child program.  Such calls retain the existing finding.  Formatted
    values are limited to names so evaluating an argument cannot itself run a
    command or another side-effecting expression.
    """

    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if not isinstance(node, ast.JoinedStr) or not node.values:
        return False
    first = node.values[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return False
    if not first.value or first.value.startswith("-"):
        return False
    return all(
        isinstance(part, ast.Constant)
        or (isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name) and part.format_spec is None)
        for part in node.values
    )


def _known_non_shell_argv(argv: ast.List | ast.Tuple) -> bool:
    """Recognize reviewed non-shell command shapes without general CLI assumptions."""

    if not argv.elts or not isinstance(argv.elts[0], ast.Constant):
        return False
    executable = argv.elts[0].value
    if executable == "lsof" and len(argv.elts) == 3:
        option, port = argv.elts[1:]
        return (
            isinstance(option, ast.Constant)
            and option.value == "-ti"
            and isinstance(port, ast.JoinedStr)
            and bool(port.values)
            and isinstance(port.values[0], ast.Constant)
            and port.values[0].value == ":"
            and _fixed_data_argument(port)
        )
    if executable == "gh" and len(argv.elts) >= 3:
        subcommand, route = argv.elts[1:3]
        return (
            isinstance(subcommand, ast.Constant)
            and subcommand.value == "api"
            and isinstance(route, ast.JoinedStr)
            and bool(route.values)
            and isinstance(route.values[0], ast.Constant)
            and route.values[0].value == "repos/"
            and _fixed_data_argument(route)
            and all(isinstance(arg, ast.Constant) and isinstance(arg.value, str) for arg in argv.elts[3:])
        )
    return False


def _safe_subprocess_argv_calls(content: str) -> dict[tuple[int, int], tuple[int, int]]:
    """Return AST spans proven to use fixed, direct subprocess argv.

    This is deliberately narrower than "a list was passed": only the
    reviewed gh API and lsof port-query shapes are suppressed.  Shell
    wrappers, dynamic executables, and unknown keyword expansion all keep
    the CRITICAL regex finding.
    """

    try:
        if len(content) > _MAX_SUBPROCESS_SOURCE_BYTES or len(content.encode("utf-8")) > _MAX_SUBPROCESS_SOURCE_BYTES:
            return {}
        tree = ast.parse(content)
    except (SyntaxError, RecursionError, MemoryError, ValueError, UnicodeError):
        return {}

    nodes: list[ast.AST] = []
    for node in ast.walk(tree):
        nodes.append(node)
        if len(nodes) > _MAX_SUBPROCESS_AST_NODES:
            return {}

    # Any other use of the module object might replace its callables.  Dynamic
    # namespace operations and pattern bindings are also treated as unknown.
    direct_subprocess_uses = {
        id(node.func.value)
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr in _SUBPROCESS_SAFE_KEYWORDS
    }
    direct_subprocess_uses.update(
        id(node.type.value)
        for node in nodes
        if isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Attribute)
        and isinstance(node.type.value, ast.Name)
        and node.type.value.id == "subprocess"
        and node.type.attr in {"TimeoutExpired", "CalledProcessError"}
    )
    imported = False
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess" and alias.asname is None:
                    imported = True
                elif alias.asname == "subprocess" or alias.name.split(".", 1)[0] == "subprocess":
                    return {}
        elif isinstance(node, ast.ImportFrom):
            if any((alias.asname or alias.name) == "subprocess" for alias in node.names):
                return {}
            if node.module == "unittest.mock" and any(alias.name == "patch" for alias in node.names):
                return {}
            if node.module == "os" and any(
                alias.name in {"environ", "environb", "putenv", "unsetenv", "chdir"} for alias in node.names
            ):
                return {}
            if node.module == "builtins" and any(alias.name in _DYNAMIC_BINDING_NAMES for alias in node.names):
                return {}
            if node.module == "sys" and any(alias.name == "modules" for alias in node.names):
                return {}
        elif isinstance(node, ast.Constant) and node.value in {
            "subprocess",
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "sys.modules",
        }:
            # Covers string-target patching, including mock.patch and
            # monkeypatch.setattr, before the reviewed call executes.
            return {}
        elif isinstance(node, ast.Name):
            if node.id in _DYNAMIC_BINDING_NAMES and isinstance(node.ctx, ast.Load):
                return {}
            if node.id == "subprocess" and (
                not isinstance(node.ctx, ast.Load) or id(node) not in direct_subprocess_uses
            ):
                return {}
        elif isinstance(node, ast.Attribute) and (
            node.attr in _DYNAMIC_BINDING_NAMES
            or node.attr in {"environ", "environb", "putenv", "unsetenv", "chdir"}
            or (node.attr == "modules" and isinstance(node.value, ast.Name) and node.value.id == "sys")
        ):
            return {}
        elif isinstance(node, ast.arg) and node.arg == "subprocess":
            return {}
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == "subprocess":
            return {}
        elif isinstance(node, ast.ExceptHandler) and node.name == "subprocess":
            return {}
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == "subprocess":
            return {}
        elif isinstance(node, ast.MatchMapping) and node.rest == "subprocess":
            return {}
    if not imported:
        return {}

    safe_spans: dict[tuple[int, int], tuple[int, int]] = {}
    for node in nodes:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "subprocess":
            continue
        if node.func.attr not in _SUBPROCESS_SAFE_KEYWORDS or len(node.args) != 1:
            continue
        argv = node.args[0]
        if not isinstance(argv, (ast.List, ast.Tuple)) or not _known_non_shell_argv(argv):
            continue
        if any(
            keyword.arg not in _SUBPROCESS_SAFE_KEYWORDS[node.func.attr]
            or (
                keyword.arg == "shell"
                and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False)
            )
            or (keyword.arg != "shell" and not isinstance(keyword.value, (ast.Constant, ast.Name)))
            for keyword in node.keywords
        ):
            continue
        safe_spans[(node.lineno, node.col_offset)] = (node.end_lineno, node.end_col_offset)
    return safe_spans


_CODE_SUFFIXES = frozenset({".bash", ".js", ".py", ".sh", ".ts", ".zsh"})
_EXAMPLE_PATH_PARTS = frozenset(
    {
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "reference",
        "references",
        "test",
        "tests",
    }
)
_EXAMPLE_FILENAMES = frozenset(
    {
        "changelog.md",
        "contributing.md",
        "readme.md",
        "security.md",
    }
)
_INSTRUCTION_PATH_PARTS = frozenset({"agent", "agents", "command", "commands", "instruction", "instructions"})
# CommonMark fenced code blocks may be indented by at most three spaces.  The
# marker run is captured separately so the structural walker can require a
# matching delimiter and a closing run at least as long as the opener.
_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+")
_NEGATIVE_EXAMPLE_RE = re.compile(
    r"\b(?:bad|dangerous|insecure|negative|unsafe|vulnerable)\s+(?:code\s+)?examples?\b"
    r"|\b(?:anti[- ]?pattern|incorrect example|what not to do)\b",
    re.IGNORECASE,
)
_SCOPED_PROHIBITION_PREFIX_RE = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't|avoid|forbidden|prohibited)"
    r"\s+(?:(?:ever\s+)?(?:use|call|invoke|run|execute|permit|allow)(?:ing)?\s+)?$",
    re.IGNORECASE,
)
_SCOPED_NO_PREFIX_RE = re.compile(
    r"(?:^|\s)(?:(?:[-*+>]\s+)|(?://|#)\s*)*no\s+"
    r"(?:calls?\s+to\s+|execut(?:e|ing|ion)\s+|invok(?:e|ing)\s+|use\s+(?:of\s+)?)?$",
    re.IGNORECASE,
)
_CLAUSE_BOUNDARY_RE = re.compile(
    r"[;.!?]|\b(?:but|except|however|instead|then|unless)\b",
    re.IGNORECASE,
)
_UNSAFE_TRAILING_CLAUSE_RE = re.compile(
    r"(?<!\\)[;?]|&&|\|\||\b(?:but|except|however|instead|then|unless)\b",
    re.IGNORECASE,
)
# A slash is ambiguous list punctuation only when separated as punctuation.
# Treating every slash as coordination makes ordinary absolute and relative
# paths (for example ``find /tmp``) impossible to classify as prohibitions.
_LIST_COORDINATION_RE = re.compile(r",|\s+/\s+|\b(?:and|or)\b", re.IGNORECASE)

# A deliberately narrow grammar for a complete, coordinated prohibition.
# Broad command-execution patterns can match both members of a benign
# instruction such as ``No eval() or exec()``.  Merely seeing a negation before
# the first match is not enough: every remaining clause must be another known
# execution primitive joined only by a list separator.  Anything mixed,
# contrastive, exceptionally long, or otherwise ambiguous remains active.
_NEGATIVE_EXECUTION_PRIMITIVE_NAME = r"""
    (?:
        eval|exec|execute|run_command|shell|bash|cmd|powershell|system_call|os_exec|
        subprocess(?:\.(?:run|call|Popen))?|child_process(?:\.exec)?|
        spawn|execFile|system|popen|os\.(?:system|popen|exec)|
        new\s+Function|vm\.(?:runIn\w*|createContext|compileFunction)
    )
"""
_NEGATIVE_EXECUTION_PRIMITIVE = rf"""
    (?:
        `\s*{_NEGATIVE_EXECUTION_PRIMITIVE_NAME}\s*\(\s*\)\s*`|
        {_NEGATIVE_EXECUTION_PRIMITIVE_NAME}\s*\(\s*\)
    )
"""
_PURE_NEGATIVE_EXECUTION_LIST_RE = re.compile(
    rf"""
    ^\s*(?:(?:[-*+>]\s+)|(?://|\#)\s*)*
    (?:
        no\s+(?:(?:calls?\s+to|execution\s+of|invocation\s+of|use\s+of)\s+)?|
        (?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't|avoid|forbid(?:den)?)
        \s+(?:(?:ever\s+)?(?:use|call|invoke|run|execute)(?:ing)?\s+)?
    )
    {_NEGATIVE_EXECUTION_PRIMITIVE}
    (?:
        \s*(?:,\s*(?:or\s+)?|\s+or\s+)\s*
        {_NEGATIVE_EXECUTION_PRIMITIVE}
    )+
    [.!]?\s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _is_pure_negative_execution_list(line: str) -> bool:
    """Return true only for a bounded, complete list of prohibited primitives."""

    # Avoid spending regex time on attacker-controlled pathological lines. A
    # long or compound instruction is ambiguous and must fail open anyway.
    return len(line) <= 512 and bool(_PURE_NEGATIVE_EXECUTION_LIST_RE.fullmatch(line))


def _is_example_path(file_path: str | None) -> bool:
    if not file_path:
        return False
    path = Path(file_path.replace("\\", "/"))
    lowered_parts = {part.lower() for part in path.parts}
    return bool(lowered_parts & _EXAMPLE_PATH_PARTS) or path.name.lower() in _EXAMPLE_FILENAMES


def _classify_signature_context(
    line: str,
    file_path: str | None,
    *,
    in_fence: bool,
    negative_example_section: bool,
    match_start: int,
    match_end: int,
    additional_active_match: bool,
) -> tuple[str, str]:
    """Return bounded execution-context and polarity classifications.

    The return values are deliberately small enums. The matching line remains
    ordinary finding evidence and is never copied into the CEL fact model.
    Unknown or ambiguous cases remain active (fail-open) at the CEL gate.
    """

    prefix = line[:match_start]
    local_prefix = _CLAUSE_BOUNDARY_RE.split(prefix)[-1]
    scoped_prohibition = bool(
        _SCOPED_PROHIBITION_PREFIX_RE.search(local_prefix) or _SCOPED_NO_PREFIX_RE.search(local_prefix)
    )
    # Inspect from the beginning of the match, not merely after it. Some broad
    # extractors greedily absorb a semicolon or contrastive clause into the
    # match itself (for example ``eval(); exec(x)``). Such content must remain
    # active even when the matched span is preceded by a scoped negation.
    trailing_clause = bool(_UNSAFE_TRAILING_CLAUSE_RE.search(line[match_start:]))
    coordinated_clause = bool(_LIST_COORDINATION_RE.search(line[match_start:]))
    explicit_negative_example = bool(_NEGATIVE_EXAMPLE_RE.search(prefix))
    safe_negative = not trailing_clause and not coordinated_clause and not additional_active_match

    if not in_fence and _is_pure_negative_execution_list(line):
        return "prohibition", "negative"
    if safe_negative and (explicit_negative_example or (negative_example_section and in_fence)):
        return "negative_example", "negative"
    if scoped_prohibition and safe_negative:
        return "prohibition", "negative"

    path = Path((file_path or "").replace("\\", "/"))
    if _is_example_path(file_path):
        return "example", "illustrative"
    if in_fence:
        return "code", "active"
    if path.name.lower() == "skill.md":
        return "active_instruction", "active"
    if path.suffix.lower() in _CODE_SUFFIXES:
        return "code", "active"
    # Signature rules scan the whole package, including auxiliary Markdown and
    # configuration files.  A valid package path is a structured file-role
    # fact, not an unknown execution context.  Keep operational agent/command
    # documents distinct from documentation; all remaining package files use
    # the neutral ``package`` role.  The CEL projector consumes this bounded
    # classification directly and never reparses the matched snippet.
    lowered_parts = {part.lower() for part in path.parts}
    if path.suffix.lower() == ".md" and lowered_parts & _INSTRUCTION_PATH_PARTS:
        return "instruction", "active"
    if file_path:
        return "package", "active"
    return "unknown", "unknown"


def _build_signature_line_contexts(lines: Sequence[str]) -> tuple[tuple[bool, bool], ...]:
    """Return structural flags for already-split content lines."""
    contexts: list[tuple[bool, bool]] = []
    fence_marker: str | None = None
    fence_length = 0
    negative_example_section = False
    for line in lines:
        fence_match = _FENCE_RE.match(line)

        if fence_marker is not None:
            # Everything through a valid closing delimiter belongs to the
            # fenced block. In particular, heading-looking source comments
            # must not mutate the surrounding Markdown section state.
            contexts.append((True, negative_example_section))
            if fence_match is not None:
                marker = fence_match.group("marker")
                tail = fence_match.group("tail")
                if marker[0] == fence_marker and len(marker) >= fence_length and not tail.strip(" \t\r"):
                    fence_marker = None
                    fence_length = 0
            continue

        if _HEADING_RE.match(line):
            negative_example_section = bool(_NEGATIVE_EXAMPLE_RE.search(line))

        if fence_match is not None:
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            # CommonMark forbids backticks in a backtick fence's info string.
            # Treat malformed/ambiguous candidates as ordinary active text
            # rather than expanding the negative-example suppression region.
            if marker[0] != "`" or "`" not in tail:
                contexts.append((True, negative_example_section))
                fence_marker = marker[0]
                fence_length = len(marker)
                continue

        contexts.append((False, negative_example_section))
    return tuple(contexts)


def _signature_line_contexts(content: str) -> list[tuple[bool, bool]]:
    """Return structural context flags without retaining source text."""

    return list(_build_signature_line_contexts(_split_universal_newlines(content)))


def _split_universal_newlines(content: str) -> tuple[str, ...]:
    """Match Python's LF/CRLF/CR source lines while preserving a trailing line."""

    return tuple(content.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


@dataclass(frozen=True, slots=True, eq=False)
class SignatureScanContext:
    """Transient, per-content state shared across signature rules.

    Previously, splitting a large file and walking all Markdown headings and
    fences repeated once per matching rule. The static analyzer creates one
    context for each content scan and passes it to every rule. Structural flags
    stay lazy, so files with no candidates pay only for one shared line split
    and never run the Markdown context walk.
    """

    content: str = field(repr=False)
    lines: tuple[str, ...] = field(init=False, repr=False)
    _line_contexts: tuple[tuple[bool, bool], ...] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "lines", _split_universal_newlines(self.content))

    def line_context(self, zero_based_line: int) -> tuple[bool, bool]:
        """Return cached fence/section flags for one physical line."""

        contexts = self._line_contexts
        if contexts is None:
            contexts = _build_signature_line_contexts(self.lines)
            object.__setattr__(self, "_line_contexts", contexts)
        return contexts[zero_based_line]

    def classify_match(
        self,
        zero_based_line: int,
        file_path: str | None,
        *,
        match_start: int,
        match_end: int,
        additional_active_match: bool = False,
    ) -> tuple[str, str]:
        """Classify a syntax-aware match with the signature context policy."""

        if (
            isinstance(zero_based_line, bool)
            or not isinstance(zero_based_line, int)
            or not 0 <= zero_based_line < len(self.lines)
            or isinstance(match_start, bool)
            or not isinstance(match_start, int)
            or isinstance(match_end, bool)
            or not isinstance(match_end, int)
        ):
            return "unknown", "unknown"
        line = self.lines[zero_based_line]
        if not 0 <= match_start <= match_end <= len(line):
            return "unknown", "unknown"
        in_fence, negative_example_section = self.line_context(zero_based_line)
        return _classify_signature_context(
            line,
            file_path,
            in_fence=in_fence,
            negative_example_section=negative_example_section,
            match_start=match_start,
            match_end=match_end,
            additional_active_match=additional_active_match,
        )


def _has_additional_pattern_match(
    patterns: list[re.Pattern[str]],
    line: str,
    current_pattern: re.Pattern[str],
    current_span: tuple[int, int],
) -> bool:
    """Conservatively detect another active signature primitive on a line."""

    for pattern in patterns:
        for candidate in pattern.finditer(line):
            if pattern is current_pattern and candidate.span() == current_span:
                continue
            return True
    return False


_PYTHON_WHOLE_ENV = r"""
    (?:
        os\s*\.\s*environ\s*\.\s*(?:items|copy)\s*\(\s*\)
        |
        dict\s*\(\s*(?:\*\*\s*)?os\s*\.\s*environ(?:\s*\.\s*items\s*\(\s*\))?\s*\)
        |
        os\s*\.\s*environ(?!\s*(?:\[|\.get\s*\(|\.\s*(?:keys|values)\s*\(|\.\s*[A-Za-z_]))
    )
"""
_PYTHON_WHOLE_ENV_RE = re.compile(_PYTHON_WHOLE_ENV, re.VERBOSE)
_PYTHON_ENV_SINK_RE = re.compile(
    rf"""
    \b(?:
        print|pprint\.pprint|logging\.\w+|logger\.\w+|
        json\.dump|json\.dumps|
        requests\.(?:post|put|patch|request)|httpx\.(?:post|put|patch|request)
    )\s*\([^#\n]{{0,400}}{_PYTHON_WHOLE_ENV}
    """,
    re.VERBOSE,
)
_PYTHON_LOOP_RE = re.compile(
    r"\bfor\s+(?P<key>[A-Za-z_]\w*)\s*,\s*(?P<value>[A-Za-z_]\w*)\s+in\s+"
    r"os\s*\.\s*environ(?:\s*\.\s*items\s*\(\s*\))?\s*:",
)
_PYTHON_SUBPROCESS_ENV_RE = re.compile(
    r"\b(?:(?P<var>[A-Za-z_]\w*)\s*=\s*)?subprocess\.(?P<func>run|check_output|Popen)\s*\("
    r"[^#\n]{0,200}(?:['\"]env['\"]|\[\s*['\"]env['\"])",
)
_PYTHON_NETWORK_SINK_RE = re.compile(r"\b(?:requests|httpx)\.(?:post|put|patch|request)\s*\(")
_JS_WHOLE_PROCESS_ENV = r"process\.env\b(?!\s*(?:\.|\[))"
_JS_ENV_SERIALIZE_RE = re.compile(
    rf"\b(?:JSON\.stringify|console\.(?:log|info|warn|error))\s*\([^;\n]{{0,240}}{_JS_WHOLE_PROCESS_ENV}"
)
_JS_ENTRIES_SINK_RE = re.compile(
    rf"Object\.entries\s*\(\s*{_JS_WHOLE_PROCESS_ENV}\s*\)[^;\n]{{0,320}}"
    r"(?:console\.(?:log|info|warn|error)|fetch\s*\(|axios\.(?:post|put|patch|request))"
)
_JS_URLSEARCHPARAMS_SINK_RE = re.compile(
    r"\b(?:fetch|axios\.(?:post|put|patch|request))\s*\([^;\n]{0,320}"
    rf"\bnew\s+URLSearchParams\s*\(\s*{_JS_WHOLE_PROCESS_ENV}\s*\)"
)
_SHELL_DUMP_COMMAND_RE = re.compile(
    r"(?:^|[;&|]\s*)"
    r"(?P<cmd>env|printenv|export[ \t]+-p|declare[ \t]+-x|set)"
    r"(?P<tail>[ \t]*(?:$|[#;|>]|>>))"
)
_SHELL_SUBSTITUTION_RE = re.compile(r"\$\(\s*(?:env|printenv|export[ \t]+-p|declare[ \t]+-x|set)\s*\)")
_SHELL_FILTERED_ENV_RE = re.compile(r"(?:^|[;&|]\s*)(?:env|printenv)[ \t]*\|[ \t]*grep\b")


def _strip_python_comment(line: str) -> str:
    """Return a conservative Python code prefix for signature precision."""

    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            return line[:index]
    return line


def _mask_python_string_literals(code: str) -> str:
    """Blank comments and literals across lines, retaining f-string expressions."""

    chars = list(code)
    index = 0
    while index < len(code):
        char = code[index]
        if char == "#":
            end = code.find("\n", index)
            if end == -1:
                end = len(code)
            chars[index:end] = [" "] * (end - index)
            index = end
            continue
        if char not in {"'", '"'}:
            index += 1
            continue
        delimiter = char * 3 if code.startswith(char * 3, index) else char
        prefix_start = index
        while prefix_start and code[prefix_start - 1].isalpha():
            prefix_start -= 1
        is_f_string = "f" in code[prefix_start:index].lower()
        index += len(delimiter)
        expression_depth = 0
        while index < len(code) and (expression_depth or not code.startswith(delimiter, index)):
            if len(delimiter) == 1 and code[index] == "\n" and not expression_depth:
                break
            if expression_depth and code[index] in {"'", '"'}:
                index = _mask_nested_quoted_literal(code, chars, index)
                continue
            if code[index] == "\\" and expression_depth == 0:
                step = 2
            elif is_f_string and expression_depth == 0 and code[index] == "{" and code.startswith("{{", index):
                step = 2
            elif is_f_string and expression_depth == 0 and code[index] == "{":
                expression_depth = 1
                step = 1
            elif is_f_string and expression_depth and code[index] == "{":
                expression_depth += 1
                step = 1
            elif is_f_string and expression_depth and code[index] == "}":
                expression_depth -= 1
                step = 1
            else:
                step = 1
            if not expression_depth:
                for offset in range(index, min(len(code), index + step)):
                    if code[offset] != "\n":
                        chars[offset] = " "
            index += step
        if code.startswith(delimiter, index):
            index += len(delimiter)
    return "".join(chars)


def _mask_nested_quoted_literal(code: str, chars: list[str], index: int) -> int:
    """Mask a quoted value inside an interpolation without changing offsets."""

    quote = code[index]
    index += 1
    while index < len(code) and code[index] not in {quote, "\n"}:
        step = 2 if code[index] == "\\" else 1
        for offset in range(index, min(len(code), index + step)):
            if code[offset] != "\n":
                chars[offset] = " "
        index += step
    return index + 1 if index < len(code) and code[index] == quote else index


def _mask_js_string_literals(code: str) -> str:
    """Blank comments and quoted text across lines, retaining template expressions."""

    chars = list(code)
    index = 0
    while index < len(code):
        quote = code[index]
        if code.startswith("//", index) or code.startswith("/*", index):
            line_comment = code.startswith("//", index)
            end = code.find("\n" if line_comment else "*/", index + 2)
            end = len(code) if end == -1 else end + (0 if line_comment else 2)
            for offset in range(index, end):
                if code[offset] != "\n":
                    chars[offset] = " "
            index = end
            continue
        if quote not in {"'", '"', "`"}:
            index += 1
            continue
        index += 1
        expression_depth = 0
        while index < len(code) and (expression_depth or code[index] != quote):
            if quote != "`" and code[index] == "\n" and not expression_depth:
                break
            if expression_depth and code[index] in {"'", '"'}:
                index = _mask_nested_quoted_literal(code, chars, index)
                continue
            if code[index] == "\\" and expression_depth == 0:
                step = 2
            elif quote == "`" and expression_depth == 0 and code.startswith("${", index):
                expression_depth = 1
                step = 2
            elif quote == "`" and expression_depth and code[index] == "{":
                expression_depth += 1
                step = 1
            elif quote == "`" and expression_depth and code[index] == "}":
                expression_depth -= 1
                step = 1
            else:
                step = 1
            if not expression_depth:
                for offset in range(index, min(len(code), index + step)):
                    if code[offset] != "\n":
                        chars[offset] = " "
            index += step
        if index < len(code) and code[index] == quote:
            index += 1
    return "".join(chars)


def _is_comment_only_match(line: str, match_start: int, language: str) -> bool:
    prefix = line[:match_start].strip()
    stripped = line.strip()
    if language == "python":
        return stripped.startswith("#")
    if language == "shell":
        return stripped.startswith("#")
    if language in {"javascript", "typescript"}:
        return stripped.startswith(("//", "/*", "*")) or prefix.endswith("/*")
    return False


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _contains_identifier(line: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", line) is not None


def _python_loop_dumps_values(lines: Sequence[str], line_index: int, match: re.Match[str]) -> bool:
    value = match.group("value")
    line = _strip_python_comment(lines[line_index])
    inline_body = line[match.end() :]
    if _contains_identifier(inline_body, value) and (
        "print" in inline_body or _PYTHON_NETWORK_SINK_RE.search(inline_body)
    ):
        return True

    base_indent = _line_indent(lines[line_index])
    for body_line in lines[line_index + 1 : min(len(lines), line_index + 9)]:
        if not body_line.strip():
            continue
        if _line_indent(body_line) <= base_indent:
            break
        code = _strip_python_comment(body_line)
        if _contains_identifier(code, value) and (
            "print" in code or "json.dump" in code or _PYTHON_NETWORK_SINK_RE.search(code) or "urlopen" in code
        ):
            return True
    return False


# ``stdout=None`` and ``stdout=sys.stdout`` inherit the parent's stdout, so they do not capture.
_PYTHON_SUBPROCESS_CAPTURE_RE = re.compile(
    r"\b(?:capture_output\s*=\s*True|stdout\s*=(?!\s*(?:None|sys\s*\.\s*stdout)\b))"
)


def _python_call_text(lines: Sequence[str], line_index: int, call_start: int) -> str:
    """Return a call's argument text, following it across at most a few lines."""

    parts: list[str] = []
    depth = 0
    for offset, raw in enumerate(lines[line_index : min(len(lines), line_index + 6)]):
        code = _strip_python_comment(raw)
        segment = code[call_start:] if offset == 0 else code
        for position, char in enumerate(segment):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    parts.append(segment[: position + 1])
                    return "\n".join(parts)
        parts.append(segment)
    return "\n".join(parts)


def _python_subprocess_env_is_exfiltrated(
    lines: Sequence[str], masked_lines: Sequence[str], line_index: int, match: re.Match[str]
) -> bool:
    line = masked_lines[line_index]
    if _PYTHON_NETWORK_SINK_RE.search(line[match.end() :]) or "urlopen" in line[match.end() :]:
        return True
    if match.group("func") != "check_output":
        call_text = _python_call_text(lines, line_index, match.start("func"))
        if _PYTHON_SUBPROCESS_CAPTURE_RE.search(call_text) is None:
            # Uncaptured output is inherited from the parent and printed to stdout.
            return True
    var = match.group("var")
    if var is None:
        return False
    for code in masked_lines[line_index + 1 : min(len(lines), line_index + 7)]:
        if re.search(rf"\b{re.escape(var)}\b", code) and (_PYTHON_NETWORK_SINK_RE.search(code) or "urlopen" in code):
            return True
    return False


_SHELL_COMMAND_SEPARATOR_RE = re.compile(r";|&&|\|\|")


def _shell_env_dump_match(line: str) -> re.Match[str] | None:
    """Return the first whole-environment dump among a line's shell commands.

    The filtered-read exception (``env | grep ...``) applies only to its own
    command, so a later ``; env > file`` on the same line is still reported.
    """

    separators = list(_SHELL_COMMAND_SEPARATOR_RE.finditer(line))
    # Later commands start on the separator's last character so the patterns'
    # ``[;&|]`` command-boundary prefix matches there.
    starts = [0] + [separator.end() - 1 for separator in separators]
    ends = [separator.start() for separator in separators] + [len(line)]
    for start, end in zip(starts, ends, strict=True):
        if _SHELL_FILTERED_ENV_RE.search(line, start, end):
            continue
        match = _SHELL_SUBSTITUTION_RE.search(line, start, end) or _SHELL_DUMP_COMMAND_RE.search(line, start, end)
        if match is not None and re.match(r"\s*[;&|]?\s*set\s+-", match.group(0)):
            continue
        if match is not None:
            return match
    return None


def _env_dump_language(file_path: str | None, content: str) -> str | None:
    path = Path((file_path or "").replace("\\", "/"))
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".mjs", ".cjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix in {".sh", ".bash", ".zsh"}:
        return "shell"
    first_line = content.splitlines()[0] if content.splitlines() else ""
    if first_line.startswith("#!") and re.search(r"\b(?:ba|z|k)?sh\b|\benv\s+(?:ba|z|k)?sh\b", first_line):
        return "shell"
    return None


def _scan_env_dump_content(
    content: str,
    file_path: str | None,
    scan_context: SignatureScanContext,
) -> list[dict[str, Any]]:
    """Scan DATA_EXFIL_ENV_DUMP with language-aware behavior boundaries."""

    language = _env_dump_language(file_path, content)
    if language is None:
        return []

    source = "\n".join(scan_context.lines)
    if language == "python":
        masked_lines = _mask_python_string_literals(source).split("\n")
    elif language in {"javascript", "typescript"}:
        masked_lines = _mask_js_string_literals(source).split("\n")
    else:
        masked_lines = []

    results: list[dict[str, Any]] = []
    seen_lines: set[int] = set()
    for zero_index, line in enumerate(scan_context.lines):
        line_number = zero_index + 1
        match: re.Match[str] | None = None
        matched_text: str | None = None
        if language == "python":
            code = masked_lines[zero_index]
            # Match on the masked text so the span never points into a string
            # literal; masking preserves offsets, so the span is valid for ``code``.
            match = _PYTHON_ENV_SINK_RE.search(code)
            if match is not None:
                matched_text = line[match.start() : match.end()]
            if match is None:
                loop_match = _PYTHON_LOOP_RE.search(code)
                if loop_match is not None and _python_loop_dumps_values(masked_lines, zero_index, loop_match):
                    match = loop_match
            if match is None:
                subprocess_match = _PYTHON_SUBPROCESS_ENV_RE.search(_strip_python_comment(line))
                if (
                    subprocess_match is not None
                    and "subprocess" in code[subprocess_match.start() : subprocess_match.end()]
                    and _python_subprocess_env_is_exfiltrated(
                        scan_context.lines, masked_lines, zero_index, subprocess_match
                    )
                ):
                    match = subprocess_match
        elif language in {"javascript", "typescript"}:
            code = masked_lines[zero_index]
            match = (
                _JS_ENV_SERIALIZE_RE.search(code)
                or _JS_ENTRIES_SINK_RE.search(code)
                or _JS_URLSEARCHPARAMS_SINK_RE.search(code)
            )
        else:
            stripped = line.strip()
            match = None
            if not stripped.startswith("#"):
                match = _shell_env_dump_match(line)

        if match is None or _is_comment_only_match(line, match.start(), language):
            continue
        if line_number in seen_lines:
            continue
        seen_lines.add(line_number)

        stripped_line = line.strip()
        leading_space = len(line) - len(line.lstrip())
        relative_match_start = max(0, match.start() - leading_space)
        relative_match_end = min(len(stripped_line), match.end() - leading_space)
        context_kind, polarity = scan_context.classify_match(
            zero_index,
            file_path,
            match_start=match.start(),
            match_end=match.end(),
            additional_active_match=False,
        )
        results.append(
            {
                "line_number": line_number,
                "line_content": stripped_line,
                "pattern_index": None,
                "match_start": relative_match_start,
                "match_end": relative_match_end,
                "matched_pattern": "DATA_EXFIL_ENV_DUMP language-aware scanner",
                "matched_text": matched_text if matched_text is not None else match.group(0),
                "file_path": file_path,
                "context_kind": context_kind,
                "polarity": polarity,
            }
        )
    return results


class SecurityRule:
    """Represents a security detection rule."""

    def __init__(self, rule_data: dict[str, Any], *, strict: bool = False):
        self.id = rule_data["id"]
        raw_category = rule_data.get("category")
        self.source_category = raw_category if isinstance(raw_category, str) else None
        try:
            self.category = ThreatCategory(raw_category)
            self.category_resolution: CategoryResolution = "native"
        except (TypeError, ValueError):
            if strict:
                raise ValueError(f"Rule {self.id} uses unknown category {raw_category!r}") from None
            mapped_category = LEGACY_SIGNATURE_CATEGORY_MAP.get(raw_category) if isinstance(raw_category, str) else None
            if mapped_category is not None:
                self.category = mapped_category
                self.category_resolution = "legacy_mapped"
            else:
                self.category = ThreatCategory.POLICY_VIOLATION
                self.category_resolution = "unknown_fallback"
        try:
            self.severity = Severity(rule_data["severity"])
        except (TypeError, ValueError):
            if strict:
                raise ValueError(f"Rule {self.id} uses unknown severity {rule_data.get('severity')!r}") from None
            logger.warning(
                "Rule %s uses unknown severity '%s'; falling back to HIGH",
                self.id,
                rule_data["severity"],
            )
            self.severity = Severity.HIGH
        self.patterns = rule_data["patterns"]
        self.exclude_patterns = rule_data.get("exclude_patterns", [])
        self.file_types = rule_data.get("file_types", [])
        self.description = rule_data["description"]
        self.remediation = rule_data.get("remediation", "")

        # Compile regex patterns
        self.compiled_patterns = []
        for pattern in self.patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                if strict:
                    raise ValueError(f"Invalid regex {pattern!r} for rule {self.id}: {e}") from e
                logger.warning("Failed to compile pattern '%s' for rule %s: %s", pattern, self.id, e)

        # Compile exclude patterns
        self.compiled_exclude_patterns = []
        for pattern in self.exclude_patterns:
            try:
                self.compiled_exclude_patterns.append(re.compile(pattern))
            except re.error as e:
                if strict:
                    raise ValueError(f"Invalid exclude regex {pattern!r} for rule {self.id}: {e}") from e
                logger.warning("Failed to compile exclude pattern '%s' for rule %s: %s", pattern, self.id, e)

    def matches_file_type(self, file_type: str) -> bool:
        """Check if this rule applies to the given file type."""
        if not self.file_types:
            return True  # Rule applies to all file types
        return file_type in self.file_types

    def scan_content(
        self,
        content: str,
        file_path: str | None = None,
        *,
        scan_context: SignatureScanContext | None = None,
    ) -> list[dict[str, Any]]:
        """
        Scan content for rule violations.

        Returns:
            List of matches with line numbers and snippets
        """
        matches = []
        # A caller-provided context is valid only for the exact immutable
        # string object it prepared. Rebuild defensively on accidental reuse
        # with different content rather than returning mismatched line data.
        if scan_context is None or scan_context.content is not content:
            scan_context = SignatureScanContext(content)
        if self.id == "DATA_EXFIL_ENV_DUMP":
            return _scan_env_dump_content(content, file_path, scan_context)
        lines = scan_context.lines
        safe_subprocess_calls: dict[tuple[int, int], tuple[int, int]] | None = None
        bun_source: str | None = None
        bun_line_offsets: list[int] | None = None
        bun_globals_unchanged: bool | None = None

        def is_safe_subprocess_match(
            match: re.Match[str], line_number: int, line: str, start: int, end: tuple[int, int]
        ) -> bool:
            nonlocal safe_subprocess_calls
            if self.id != "COMMAND_INJECTION_OS_SYSTEM" or not match.group(0).startswith("subprocess."):
                return False
            if safe_subprocess_calls is None:
                safe_subprocess_calls = _safe_subprocess_argv_calls(content)
            call_end = safe_subprocess_calls.get((line_number, len(line[:start].encode("utf-8"))))
            return call_end is not None and end <= call_end

        def is_safe_bun_match(match: re.Match[str], line_number: int, line: str) -> bool:
            nonlocal bun_source, bun_line_offsets, bun_globals_unchanged
            if (
                self.id != "COMMAND_INJECTION_JS_CHILD_PROCESS"
                or match.re.pattern != r"\bspawnSync\s*\("
                or _JS_BUN_SPAWN_PREFIX.search(line[: match.start()]) is None
            ):
                return False
            if bun_source is None:
                # SignatureScanContext normalizes CRLF/CR, so offsets must use
                # the same normalized source as its line and match positions.
                bun_source = "\n".join(lines)
                bun_line_offsets = []
                offset = 0
                for source_line in lines:
                    bun_line_offsets.append(offset)
                    offset += len(source_line) + 1
            if bun_line_offsets is None or not _is_safe_bun_spawn_sync(
                bun_source, bun_line_offsets[line_number - 1] + match.end() - 1
            ):
                return False
            if bun_globals_unchanged is None:
                bun_globals_unchanged = _js_bun_globals_unchanged(bun_source)
            return bun_globals_unchanged

        for line_num, line in enumerate(lines, start=1):
            # Check exclude patterns first
            excluded = False
            for exclude_pattern in self.compiled_exclude_patterns:
                if exclude_pattern.search(line):
                    excluded = True
                    break

            if excluded:
                continue

            for pattern_index, pattern in enumerate(self.compiled_patterns):
                # When a safe argv call is skipped, continue looking for a
                # second call on the same line that still merits a finding.
                candidate_matches = (
                    pattern.finditer(line)
                    if self.id == "COMMAND_INJECTION_OS_SYSTEM"
                    or (self.id == "COMMAND_INJECTION_JS_CHILD_PROCESS" and pattern.pattern == r"\bspawnSync\s*\(")
                    else (pattern.search(line),)
                )
                for match in candidate_matches:
                    if match is None:
                        continue
                    match_end = (line_num, len(line[: match.end()].encode("utf-8")))
                    if is_safe_subprocess_match(match, line_num, line, match.start(), match_end) or is_safe_bun_match(
                        match, line_num, line
                    ):
                        continue
                    stripped_line = line.strip()
                    leading_space = len(line) - len(line.lstrip())
                    relative_match_start = max(0, match.start() - leading_space)
                    relative_match_end = min(len(stripped_line), match.end() - leading_space)
                    context_kind, polarity = scan_context.classify_match(
                        line_num - 1,
                        file_path,
                        match_start=match.start(),
                        match_end=match.end(),
                        additional_active_match=_has_additional_pattern_match(
                            self.compiled_patterns,
                            line,
                            pattern,
                            match.span(),
                        ),
                    )
                    result: dict[str, Any] = {
                        "line_number": line_num,
                        "line_content": stripped_line,
                        "pattern_index": pattern_index,
                        "match_start": relative_match_start,
                        "match_end": relative_match_end,
                        "matched_pattern": pattern.pattern,
                        "matched_text": match.group(0),
                        "file_path": file_path,
                        "context_kind": context_kind,
                        "polarity": polarity,
                    }
                    matches.append(result)
                    break

        # Some rules intentionally span lines (for example "...\\n...open(...)").
        # The primary pass above is line-based for speed; this pass captures
        # multiline-only regexes and maps matches back to starting line number.
        for pattern_index, pattern in enumerate(self.compiled_patterns):
            # Check for \\n *outside* character classes.  Patterns that use
            # [^\\n] (negated newline inside a character class) are still
            # single-line patterns — they must NOT enter the multiline pass
            # or they will duplicate every match already found in pass 1.
            stripped = _CHAR_CLASS_RE.sub("", pattern.pattern)
            if "\\n" not in stripped:
                continue
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                excluded = False
                for exclude_pattern in self.compiled_exclude_patterns:
                    if exclude_pattern.search(matched_text):
                        excluded = True
                        break
                if excluded:
                    continue

                start_line = content.count("\n", 0, match.start()) + 1
                snippet = lines[start_line - 1].strip() if 0 <= start_line - 1 < len(lines) else ""
                line_start = content.rfind("\n", 0, match.start()) + 1
                context_line = lines[start_line - 1]
                leading_space = len(context_line) - len(context_line.lstrip())
                source_start = match.start() - line_start
                end_line = content.count("\n", 0, match.end()) + 1
                end_line_start = content.rfind("\n", 0, match.end()) + 1
                end_column = len(content[end_line_start : match.end()].encode("utf-8"))
                if is_safe_subprocess_match(match, start_line, context_line, source_start, (end_line, end_column)):
                    continue
                relative_start = max(0, source_start - leading_space)
                relative_end = min(len(snippet), max(relative_start, match.end() - line_start - leading_space))
                context_end = min(len(context_line), max(source_start, match.end() - line_start))
                context_kind, polarity = scan_context.classify_match(
                    start_line - 1,
                    file_path,
                    match_start=source_start,
                    match_end=context_end,
                    additional_active_match=False,
                )
                result = {
                    "line_number": start_line,
                    "line_content": snippet,
                    "pattern_index": pattern_index,
                    "match_start": relative_start,
                    "match_end": relative_end,
                    "matched_pattern": pattern.pattern,
                    "matched_text": matched_text[:200],
                    "file_path": file_path,
                    "context_kind": context_kind,
                    "polarity": polarity,
                }
                matches.append(result)

        return matches


class RuleLoader:
    """Loads security rules from YAML files."""

    def __init__(
        self,
        rules_file: Path | None = None,
        extra_rules_dirs: list[Path] | None = None,
        trusted_pack_dirs: list[Path] | None = None,
        strict: bool = False,
    ):
        """
        Initialize rule loader.

        Args:
            rules_file: Path to a single YAML file **or** a directory
                containing multiple ``*.yaml`` category files.  If *None*,
                defaults to the core pack's ``signatures/`` directory.
            extra_rules_dirs: Additional directories of ``*.yaml`` signature
                files to load (e.g. from community rule packs).  Rules are
                appended after the primary ``rules_file`` rules.
            trusted_pack_dirs: Explicit schema-v2 pack roots.  These are
                validated atomically and loaded fail-fast after legacy rules.
            strict: Fail instead of warning on malformed regex rules and
                duplicate IDs. Intended for rule validation commands.
        """
        if rules_file is None:
            from ...data import DATA_DIR

            sigs_dir = DATA_DIR / "packs" / "core" / "signatures"
            rules_file = sigs_dir

        self.rules_file = rules_file
        self.extra_rules_dirs = extra_rules_dirs or []
        self.trusted_pack_dirs = trusted_pack_dirs or []
        self.strict = strict
        self.rules: list[SecurityRule] = []
        self.rules_by_id: dict[str, SecurityRule] = {}
        self.rules_by_category: dict[ThreatCategory, list[SecurityRule]] = {}
        self.category_normalization_metrics = CategoryNormalizationMetrics()
        # IDs of the rules in the primary (core) rules source, as opposed to
        # opt-in packs from ``extra_rules_dirs`` or trusted packs.
        self.primary_rule_ids: frozenset[str] = frozenset()

    @staticmethod
    def _extract_rules_list(data: Any, source_path: Path) -> list[dict]:
        """Extract a list of rule dicts from parsed YAML data.

        Handles both flat-list format (core) and dict-with-``signatures``
        key format (community packs like ATR).
        """
        if data is None:
            raise RuntimeError(f"Failed to load rules from {source_path}: file is empty")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "signatures" in data:
            sigs = data["signatures"]
            if isinstance(sigs, list):
                return sigs
        raise RuntimeError(
            f"Failed to load rules from {source_path}: expected a YAML list "
            "of rule objects or a dict with a 'signatures' key"
        )

    def _load_from_path(self, rules_path: Path) -> list[dict]:
        """Load raw rule dicts from a file or directory of YAML files."""
        rules_data: list[dict] = []
        if rules_path.is_dir():
            yaml_files = sorted(rules_path.glob("*.yaml"))
            if not yaml_files:
                raise RuntimeError(f"No .yaml rule files found in {rules_path}")

            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception as e:
                    raise RuntimeError(f"Failed to load rules from {yaml_file}: {e}") from e
                rules_data.extend(self._extract_rules_list(data, yaml_file))
        else:
            try:
                with open(rules_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception as e:
                raise RuntimeError(f"Failed to load rules from {rules_path}: {e}")
            rules_data.extend(self._extract_rules_list(data, rules_path))
        return rules_data

    def load_rules(self) -> list[SecurityRule]:
        """
        Load rules from the primary source and any extra pack directories.

        Returns:
            List of SecurityRule objects
        """
        rules_data = self._load_from_path(Path(self.rules_file))
        self.primary_rule_ids = frozenset(
            str(rule_data["id"]) for rule_data in rules_data if isinstance(rule_data, dict) and "id" in rule_data
        )

        for extra_dir in self.extra_rules_dirs:
            extra_path = Path(extra_dir)
            if extra_path.is_dir():
                try:
                    rules_data.extend(self._load_from_path(extra_path))
                except Exception as e:
                    if self.strict:
                        raise
                    logger.warning("Failed to load extra rule pack from %s: %s", extra_path, e)

        loaded_rules: list[SecurityRule] = []
        loaded_by_id: dict[str, SecurityRule] = {}
        loaded_by_category: dict[ThreatCategory, list[SecurityRule]] = {}
        resolution_counts: Counter[str] = Counter()
        mapped_source_categories: Counter[str] = Counter()
        unknown_source_categories: Counter[str] = Counter()

        def record_category_resolution(rule: SecurityRule) -> None:
            resolution_counts[rule.category_resolution] += 1
            source_category = rule.source_category or "<missing-or-non-string>"
            if rule.category_resolution == "legacy_mapped":
                mapped_source_categories[source_category] += 1
            elif rule.category_resolution == "unknown_fallback":
                unknown_source_categories[source_category] += 1

        for rule_data in rules_data:
            if self.strict:
                if not isinstance(rule_data, dict):
                    raise ValueError("Every signature rule must be a mapping")
                rule = SecurityRule(rule_data, strict=True)
                if rule.id in loaded_by_id:
                    raise ValueError(f"Duplicate signature rule ID: {rule.id}")
                loaded_rules.append(rule)
                loaded_by_id[rule.id] = rule
                loaded_by_category.setdefault(rule.category, []).append(rule)
                record_category_resolution(rule)
                continue
            try:
                rule = SecurityRule(rule_data)
                loaded_rules.append(rule)
                loaded_by_id[rule.id] = rule

                if rule.category not in loaded_by_category:
                    loaded_by_category[rule.category] = []
                loaded_by_category[rule.category].append(rule)
                record_category_resolution(rule)
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", rule_data.get("id", "unknown"), e)

        if self.trusted_pack_dirs:
            # Import lazily to avoid a module cycle: the registry validates
            # raw signature implementations, while this module instantiates
            # the runtime SecurityRule objects.
            from ..rule_registry import PackLoader

            pack_loader = PackLoader()
            for pack_dir in self.trusted_pack_dirs:
                pack = pack_loader.load_trusted_pack(pack_dir)
                for rule_data in pack.signature_rules:
                    rule = SecurityRule(rule_data, strict=True)
                    if rule.id in loaded_by_id:
                        raise ValueError(f"Rule ID collision: trusted pack '{pack.name}' redefines rule '{rule.id}'")
                    loaded_rules.append(rule)
                    loaded_by_id[rule.id] = rule
                    loaded_by_category.setdefault(rule.category, []).append(rule)
                    record_category_resolution(rule)

        if unknown_source_categories:
            details = ", ".join(f"{category}={count}" for category, count in sorted(unknown_source_categories.items()))
            logger.warning(
                "%d signature rule(s) use unmapped categories; falling back to POLICY_VIOLATION (%s)",
                sum(unknown_source_categories.values()),
                details,
            )

        metrics = CategoryNormalizationMetrics(
            native_rules=resolution_counts["native"],
            legacy_mapped_rules=resolution_counts["legacy_mapped"],
            unknown_fallback_rules=resolution_counts["unknown_fallback"],
            mapped_source_categories=tuple(sorted(mapped_source_categories.items())),
            unknown_source_categories=tuple(sorted(unknown_source_categories.items())),
        )

        # Publish only a completely loaded generation.
        self.rules = loaded_rules
        self.rules_by_id = loaded_by_id
        self.rules_by_category = loaded_by_category
        self.category_normalization_metrics = metrics

        return self.rules

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        """Get a specific rule by ID."""
        return self.rules_by_id.get(rule_id)

    def get_rules_for_file_type(self, file_type: str) -> list[SecurityRule]:
        """Get all rules that apply to a specific file type."""
        return [rule for rule in self.rules if rule.matches_file_type(file_type)]

    def get_rules_for_category(self, category: ThreatCategory) -> list[SecurityRule]:
        """Get all rules in a specific threat category."""
        return self.rules_by_category.get(category, [])
