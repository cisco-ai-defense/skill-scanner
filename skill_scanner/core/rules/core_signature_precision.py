# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Candidate-local precision for broad core signatures.

These refinements deliberately know nothing about a package author, install
location, signature, or allowlist.  They suppress only when the candidate's
syntax, data flow, and package file role prove that the primitive lacks the
threat sink named by its rule.  Unknown shapes fail open.
"""

from __future__ import annotations

import re
from ast import Call, Constant, parse, walk
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..models import Finding, Severity, Skill
from ..static_analysis.url_classifier import classify_url, extract_urls

CORE_PRECISION_RULE_IDS = frozenset(
    {
        "PROMPT_INJECTION_CONCEALMENT",
        "YARA_prompt_injection_generic",
    }
)

_JS_FS_CALL_RE = re.compile(
    r"\bfs\.(?P<operation>readFile|readFileSync|createReadStream|writeFile|writeFileSync|"
    r"createWriteStream|appendFile|appendFileSync)\s*\("
)
_JS_PROCESS_CALL_RE = re.compile(
    r"\b(?:(?:child_process)\s*\.\s*)?"
    r"(?P<api>exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\("
)
_JS_PROCESS_IMPORT_RE = re.compile(r"\b(?:child_process|node:child_process)\b")
_JS_WRITE_OPERATIONS = frozenset({"writeFile", "writeFileSync", "createWriteStream", "appendFile", "appendFileSync"})
_JS_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"/(?:etc/(?:passwd|shadow|sudoers)|proc/(?:self/)?environ)\b|"
    r"\.ssh/(?:id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys)|"
    r"\.aws/credentials|\.gnupg(?:/|\b)|\.netrc\b|\.pgpass\b|"
    r"(?:^|[^A-Za-z0-9])\.env(?:\.[A-Za-z0-9_-]+)?\b|"
    r"keychain|wallet|browser[_-]?(?:cookie|history|login)|"
    r"(?:credential|secret|api[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|session[_-]?cookie)"
    r"(?:s|File|Path|_file|_path)?\b"
    r")"
)
_JS_NETWORK_SINK_RE = re.compile(
    r"(?i)\b(?:fetch\s*\(|axios\.(?:post|put|patch|request)\s*\(|"
    r"(?:https?|http2)\.(?:request|get)\s*\(|"
    r"XMLHttpRequest\b|WebSocket\s*\(|navigator\.sendBeacon\s*\()"
)
_JS_NETWORK_CALL_RE = re.compile(r"\b(?P<api>fetch)\s*\(")
_NETWORK_CAPABILITY_RE = re.compile(
    r"(?i)\b(?:api|download|fetch|internet|network|online|remote|retrieve|search|url|web)\b"
)
_SENSITIVE_NETWORK_VALUE_RE = re.compile(
    r"(?i)\b(?:authorization|cookie|credential|password|private[_-]?key|secret|session|token)\b|"
    r"(?:process\.env|os\.(?:environ|getenv))"
)
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
_DOMAIN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_COMMON_SECOND_LEVEL_SUFFIXES = frozenset({"ac", "co", "com", "edu", "gov", "net", "org"})
_NON_DOMAIN_FILE_SUFFIXES = frozenset(
    {
        "bash",
        "cfg",
        "cjs",
        "css",
        "csv",
        "html",
        "ini",
        "js",
        "json",
        "md",
        "mjs",
        "py",
        "rst",
        "sh",
        "toml",
        "ts",
        "txt",
        "xml",
        "yaml",
        "yml",
    }
)
_JS_ASSIGNMENT_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=")
_JS_UNTRUSTED_VALUE_RE = re.compile(
    r"(?i)(?:process\.argv|req(?:uest)?\s*\.|user(?:Input|Command)?\b|"
    r"input(?:Command)?\b|params?\s*\.|query\s*\.|body\s*\[)"
)
_JS_SHELL_OPTION_RE = re.compile(r"\bshell\s*:\s*true\b", re.IGNORECASE)
_JS_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<parameters>[^)]*)\)\s*\{")
_JS_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_JS_LITERAL_RE = re.compile(r"^(['\"])(?P<value>(?:\\.|(?!\1).)*)\1$", re.DOTALL)
_JS_CONST_ASSIGNMENT_RE_TEMPLATE = r"(?m)\bconst\s+{identifier}\s*=\s*(?P<value>[^;\r\n]{{1,4096}})\s*;"
_JS_SHELL_EXECUTABLES = frozenset(
    {"bash", "cmd", "cmd.exe", "dash", "fish", "powershell", "powershell.exe", "pwsh", "sh", "zsh"}
)
_JS_CODE_INTERPRETER_FLAGS = {
    "node": frozenset({"-e", "--eval"}),
    "perl": frozenset({"-e"}),
    "php": frozenset({"-r"}),
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "ruby": frozenset({"-e"}),
}

# Only two closed setup/UI clauses from benign guidance are accepted.  Broad
# verbs such as run/install/click/remove/invoke cannot by themselves prove a
# line harmless; unknown complements fail open.
_USER_DIRECTION_RE = re.compile(
    r"(?is)^\s*(?:[-*]\s+)?do\s+not\s+(?:tell|inform|notify)\s+(?:the\s+)?users?\s+to\s+"
    r"(?:"
    r"add\s+(?:the\s+)?[a-z][a-z0-9_-]{0,31}\s+connector\s+to\s+open\s+(?:the\s+)?gallery|"
    r"run\s+(?:the\s+)?legacy\s+marketplace\s+command"
    r"(?:\s+for\s+(?:this|the)\s+local\s+setup)?"
    r")[.!?]?\s*$"
)
_CONDITIONAL_ACCURACY_RE = re.compile(
    r"(?is)^\s*(?:[-*]\s+)?do\s+not\s+(?:tell|inform|notify)\s+(?:the\s+)?users?\s+"
    r"(?:"
    r"(?:[a-z][a-z0-9_-]{0,31}\s+)?channel\s+setup\s+is\s+ready\s+when\s+"
    r"(?:a|the)\s+required\s+supporting\s+app\s+is\s+still\s+misconfigured|"
    r"an?\s+icon\s+color\s+was\s+configured\s+unless\s+(?:the\s+)?connector\s+"
    r"exposes\s+that\s+exact\s+setting"
    r")[.!?]?\s*$"
)
# A line can contain a benign user-direction clause and a second, active
# instruction override.  YARA emits one rule/line candidate after duplicate
# collapse, so this bounded guard keeps the complete line fail-open when the
# supposedly benign clause co-occurs with a separate injection primitive.
_ACTIVE_PROMPT_OVERRIDE_RE = re.compile(
    r"(?i)\b(?:"
    r"(?:bypass|disregard|forget|ignore)\s+(?:(?:all|any|every)\s+)?"
    r"(?:(?:of\s+)?(?:the|your|my)\s+)?(?:previous|prior|above|earlier|preceding|system|original)\s+"
    r"(?:commands?|guidelines?|instructions?|directives?|rules?|constraints?|restrictions?|safety|protocols?|"
    r"system\s*prompts?)|"
    r"new\s+(?:instructions?|directives?|guidelines?)\s*:\s*you\s+are|"
    r"system\s*prompt\s*override"
    r")\b"
)
_ACTIVE_COERCION_RE = re.compile(
    r"(?i)\b(?:"
    r"always\s+(?:consult|use|run|execute|invoke|call|trigger|employ)\s+this\s+"
    r"(?:tool|function|command|operation)\s+(?:immediately|first|before|prior|initially)|"
    r"(?:you|user)\s+(?:must|need\s+to|have\s+to|are\s+required\s+to)\s+"
    r"(?:use|execute|run|invoke|call)\s+this\s+(?:tool|function|command|operation)|"
    r"(?:required|mandatory|essential)\s+to\s+(?:execute|use|run|invoke|call)\s+"
    r"(?:this|the\s+current)\s+(?:tool|function|command|operation)\s+"
    r"(?:first|before|initially|prior)"
    r")\b"
)

_MAX_CALL_CHARS = 16_384
_FLOW_WINDOW_LINES = 16


@dataclass(frozen=True, slots=True)
class CorePrecisionDecision:
    """Bounded result of one core-signature candidate classification."""

    keep: bool
    reason: str
    evidence_value_class: str | None = None
    candidate_command: dict[str, Any] | None = None
    candidate_flow: dict[str, Any] | None = None
    severity_override: Severity | None = None
    network_direction: str | None = None
    destination_class: str | None = None


def _line_start(content: str, line_number: int) -> int | None:
    if line_number < 1:
        return None
    offset = 0
    for current, line in enumerate(content.splitlines(keepends=True), start=1):
        if current == line_number:
            return offset
        offset += len(line)
    if line_number == 1 and not content:
        return 0
    return None


def _line_text(content: str, line_number: int) -> str | None:
    lines = content.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return None


def _split_js_arguments(content: str, opening_parenthesis: int) -> tuple[list[str], str] | None:
    """Split a bounded JavaScript call without evaluating or fully parsing it."""

    limit = min(len(content), opening_parenthesis + _MAX_CALL_CHARS)
    arguments: list[str] = []
    argument_start = opening_parenthesis + 1
    parentheses = 1
    brackets = 0
    braces = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening_parenthesis + 1
    while index < limit:
        character = content[index]
        following = content[index + 1] if index + 1 < limit else ""
        if line_comment:
            if character in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if character == "/" and following == "*":
            block_comment = True
            index += 2
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "(":
            parentheses += 1
        elif character == ")":
            parentheses -= 1
            if parentheses == 0:
                arguments.append(content[argument_start:index].strip())
                return arguments, content[opening_parenthesis - 1 : index + 1]
        elif character == "[":
            brackets += 1
        elif character == "]" and brackets:
            brackets -= 1
        elif character == "{":
            braces += 1
        elif character == "}" and braces:
            braces -= 1
        elif character == "," and parentheses == 1 and brackets == 0 and braces == 0:
            arguments.append(content[argument_start:index].strip())
            argument_start = index + 1
        index += 1
    return None


def _call_at_line(
    content: str,
    line_number: int,
    pattern: re.Pattern[str],
) -> tuple[re.Match[str], list[str], str] | None:
    start = _line_start(content, line_number)
    line = _line_text(content, line_number)
    if start is None or line is None:
        return None
    match = pattern.search(line)
    if match is None:
        return None
    opening = start + match.end() - 1
    parsed = _split_js_arguments(content, opening)
    if parsed is None:
        return None
    arguments, expression = parsed
    return match, arguments, expression


def _literal_value(expression: str) -> str | None:
    match = _JS_LITERAL_RE.fullmatch(expression.strip())
    if match is None:
        return None
    value = match.group("value")
    if "${" in value:
        return None
    return value.replace("\\'", "'").replace('\\"', '"')


def _executable_name(value: str) -> str:
    """Return a platform-neutral executable basename."""

    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _assigned_static_or_configured_executable(content: str, identifier: str, before: int) -> str | None:
    """Resolve only a literal or environment-configured literal fallback."""

    escaped = re.escape(identifier)
    pattern = re.compile(
        rf"\b(?:const|let|var)\s+{escaped}\s*=\s*"
        rf"(?:(?:process\.env\.[A-Za-z_$][\w$]*\s*\|\|\s*)?(['\"]))"
        rf"(?P<value>[A-Za-z0-9_./-]+)\1\s*;?"
    )
    matches = list(pattern.finditer(content[:before]))
    return matches[-1].group("value") if matches else None


def _enclosing_wrapper(
    content: str,
    call_offset: int,
    executable_argument: str,
    argv_argument: str,
) -> tuple[str, int] | None:
    """Return a simple wrapper name when the process call consumes its first two parameters."""

    for function in reversed(list(_JS_FUNCTION_RE.finditer(content[:call_offset]))):
        if not _brace_is_open_at(content, function.end() - 1, call_offset):
            continue
        parameters = [value.strip() for value in function.group("parameters").split(",")]
        if len(parameters) < 2:
            return None
        if executable_argument.strip() != parameters[0] or argv_argument.strip() != parameters[1]:
            return None
        return function.group("name"), function.start()
    return None


def _brace_is_open_at(content: str, opening_brace: int, target: int) -> bool:
    """Return whether a lexical function brace still encloses ``target``."""

    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening_brace
    while index < min(target, len(content)):
        character = content[index]
        following = content[index + 1] if index + 1 < target else ""
        if line_comment:
            if character in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if character == "/" and following == "*":
            block_comment = True
            index += 2
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth <= 0:
                return False
        index += 1
    return depth > 0


def _wrapper_has_only_structured_literal_calls(content: str, name: str, definition_offset: int) -> bool:
    calls = 0
    call_pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    for match in call_pattern.finditer(content):
        if abs(match.start() - definition_offset) < 32:
            continue
        parsed = _split_js_arguments(content, match.end() - 1)
        if parsed is None:
            return False
        arguments, expression = parsed
        if len(arguments) < 2:
            return False
        executable = _literal_value(arguments[0])
        if executable is None or not arguments[1].lstrip().startswith("["):
            return False
        if _executable_name(executable) in _JS_SHELL_EXECUTABLES or _JS_SHELL_OPTION_RE.search(expression):
            return False
        calls += 1
    return calls > 0


def _command_fact(*, shell: bool, dynamic: bool, file_path: str) -> dict[str, Any]:
    argument_classes = ["dynamic"] if dynamic else ["literal"]
    if shell:
        argument_classes.append("inline_code")
    return {
        "executable": "shell" if shell else "process",
        "argument_classes": argument_classes,
        "downloads": False,
        "executes": True,
        "destructive": False,
        "privilege_change": False,
        "source_class": "user_input" if dynamic else "signature_candidate",
        "sink_class": "shell_execution" if shell else "process_execution",
        "file_path": file_path,
    }


def _flow_fact(source: str, sink: str, file_path: str) -> dict[str, Any]:
    return {
        "source_class": source,
        "sink_class": sink,
        "transforms": [],
        "cross_file": False,
        "source_path": file_path,
        "sink_path": file_path,
    }


def _provider_label(host: str) -> str:
    labels = [label for label in host.lower().rstrip(".").split(".") if label]
    if len(labels) < 2 or any(_DOMAIN_LABEL_RE.fullmatch(label) is None for label in labels):
        return ""
    if len(labels[-1]) == 2 and len(labels) >= 3 and labels[-2] in _COMMON_SECOND_LEVEL_SUFFIXES:
        return labels[-3]
    return labels[-2]


def _https_provider_labels(material: str) -> tuple[set[str], bool]:
    """Return normalized providers and whether every observed URL is safe HTTPS."""

    providers: set[str] = set()
    urls = extract_urls(material[:1_000_000])[:128]
    for raw_url in urls:
        try:
            parsed = urlsplit(raw_url)
            port = parsed.port
        except ValueError:
            return set(), False
        provider = _provider_label(parsed.hostname or "")
        if (
            parsed.scheme.lower() != "https"
            or not provider
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or classify_url(raw_url) == "suspicious"
        ):
            return set(), False
        providers.add(provider)
    return providers, bool(urls)


def _resolved_js_network_destination(content: str, destination: str, call_offset: int) -> str | None:
    """Resolve one literal or immutable same-file destination conservatively.

    Other URLs elsewhere in the file are not evidence about this call.  An
    identifier qualifies only when it has one bounded ``const`` declaration,
    before the call, whose value resolves through at most two immutable names
    to a string literal. Function parameters, mutable bindings, expressions,
    and shadowed names deliberately fail open.
    """

    value = _literal_value(destination)
    if value is not None:
        return value
    identifier = destination.strip()
    seen: set[str] = set()
    for _depth in range(2):
        if _JS_IDENTIFIER_RE.fullmatch(identifier) is None or identifier in seen:
            return None
        seen.add(identifier)
        pattern = re.compile(_JS_CONST_ASSIGNMENT_RE_TEMPLATE.format(identifier=re.escape(identifier)))
        assignments = list(pattern.finditer(content))
        if len(assignments) != 1 or assignments[0].start() >= call_offset:
            return None
        initializer = assignments[0].group("value").strip()
        value = _literal_value(initializer)
        if value is not None:
            return value
        identifier = initializer
    return None


def declared_network_provider_labels(skill: Skill) -> set[str]:
    """Extract bounded provider labels only from authoritative skill prose."""

    if not skill.manifest_complete:
        return set()
    material = "\n".join(
        value
        for value in (
            skill.manifest.description,
            skill.manifest.compatibility,
            skill.instruction_body[:65_536],
        )
        if isinstance(value, str)
    )
    if _NETWORK_CAPABILITY_RE.search(material) is None:
        return set()
    providers, urls_valid = _https_provider_labels(material)
    observed_urls = extract_urls(material[:1_000_000])[:128]
    if observed_urls and not urls_valid:
        return set()
    for match in list(_DOMAIN_TOKEN_RE.finditer(material[:65_536]))[:128]:
        domain = match.group(0)
        if domain.rsplit(".", 1)[-1].lower() in _NON_DOMAIN_FILE_SUFFIXES:
            continue
        provider = _provider_label(domain)
        if provider:
            providers.add(provider)
    return providers


def manifest_or_instructions_declare_network(skill: Skill) -> bool:
    """Return whether complete metadata explicitly declares network behavior."""

    if not skill.manifest_complete:
        return False
    compatibility = skill.manifest.compatibility
    if isinstance(compatibility, str) and re.search(r"(?i)\b(?:internet|network)\b", compatibility):
        return True
    return bool(declared_network_provider_labels(skill))


def _js_read_only_network_candidate(
    skill: Skill,
    finding: Finding,
    content: str,
) -> CorePrecisionDecision:
    line_number = finding.line_number
    if not isinstance(line_number, int):
        return CorePrecisionDecision(True, "unclassified_javascript_network_candidate")
    call = _call_at_line(content, line_number, _JS_NETWORK_CALL_RE)
    if call is None:
        return CorePrecisionDecision(True, "unclassified_javascript_network_candidate")
    match, arguments, expression = call
    if not arguments:
        return CorePrecisionDecision(True, "missing_network_destination")

    # Sending a body, selecting an outbound method, or placing a sensitive
    # value in the request remains a data-exfiltration candidate even when the
    # provider itself is declared.
    if re.search(r"(?i)\bbody\s*:", expression):
        return CorePrecisionDecision(True, "javascript_network_payload")
    method = re.search(r"(?i)\bmethod\s*:\s*['\"](?P<method>[A-Z]+)['\"]", expression)
    if method is not None and method.group("method").lower() not in {"get", "head"}:
        return CorePrecisionDecision(True, "javascript_outbound_network_method")
    if _SENSITIVE_NETWORK_VALUE_RE.search(expression):
        return CorePrecisionDecision(True, "javascript_sensitive_request_value")
    destination = arguments[0].strip()
    line_start = _line_start(content, line_number)
    if line_start is None:
        return CorePrecisionDecision(True, "unclassified_javascript_network_candidate")
    resolved_destination = _resolved_js_network_destination(content, destination, line_start + match.start())
    if resolved_destination is None:
        return CorePrecisionDecision(True, "dynamic_javascript_network_destination")

    declared = declared_network_provider_labels(skill)
    destination_providers, destination_valid = _https_provider_labels(resolved_destination)
    if not declared or not destination_valid or not destination_providers or not destination_providers <= declared:
        return CorePrecisionDecision(True, "unbound_javascript_network_provider")
    return CorePrecisionDecision(
        True,
        "declared_read_only_javascript_network",
        evidence_value_class="declared_read_only_network",
        candidate_flow=_flow_fact("declared_remote_resource", "local_read", finding.file_path or ""),
        severity_override=Severity.LOW,
        network_direction="inbound",
        destination_class="declared_service",
    )


def _python_call_at_line(content: str, line_number: int) -> Call | None:
    try:
        tree = parse(content)
    except (SyntaxError, ValueError):
        return None
    return next((node for node in walk(tree) if isinstance(node, Call) and node.lineno == line_number), None)


def _python_request_has_payload(call: Call) -> bool:
    # urllib.request.Request(url, data=None, headers={}, ..., method=None)
    if len(call.args) >= 2:
        value = call.args[1]
        if not isinstance(value, Constant) or value.value is not None:
            return True
    for item in call.keywords:
        if item.arg in {"data", "json", "body"}:
            if not isinstance(item.value, Constant) or item.value.value is not None:
                return True
        if item.arg == "method":
            if not isinstance(item.value, Constant) or not isinstance(item.value.value, str):
                return True
            if item.value.value.lower() not in {"get", "head"}:
                return True
    return False


def _python_read_only_network_candidate(
    skill: Skill,
    finding: Finding,
    content: str,
) -> CorePrecisionDecision:
    line_number = finding.line_number
    if not isinstance(line_number, int):
        return CorePrecisionDecision(True, "unclassified_python_network_candidate")
    call = _python_call_at_line(content, line_number)
    if call is None or _python_request_has_payload(call):
        return CorePrecisionDecision(True, "python_network_payload_or_unclassified_call")
    if not manifest_or_instructions_declare_network(skill):
        return CorePrecisionDecision(True, "python_network_capability_undeclared")

    # Reuse the analyzer's AST/data-flow normalization. In particular, a
    # credential in an Authorization header is accepted only when its provider
    # matches a provider-declared destination; payload credentials, generic
    # dynamic helpers, and mismatched providers remain outbound.
    from ..analyzers.correlation_analyzer import CorrelationAnalyzer

    try:
        signals = CorrelationAnalyzer()._extract_signals(skill).get(Path(finding.file_path or "").as_posix())
    except Exception:
        return CorePrecisionDecision(True, "python_network_projection_failure")
    if signals is None:
        return CorePrecisionDecision(True, "python_network_signal_missing")
    nearby = [event for event in signals.networks if line_number <= event.line <= line_number + 2]
    if not nearby:
        return CorePrecisionDecision(True, "python_network_event_missing")
    if any(
        event.direction != "inbound"
        or not event.downloads
        or event.destination_class not in {"configured_service", "declared_service"}
        or event.credential_use not in {"", "authentication"}
        for event in nearby
    ):
        return CorePrecisionDecision(True, "python_network_event_not_provider_bound_read_only")
    return CorePrecisionDecision(
        True,
        "declared_read_only_python_network",
        evidence_value_class="declared_read_only_network",
        candidate_flow=_flow_fact("declared_remote_resource", "local_read", finding.file_path or ""),
        severity_override=Severity.LOW,
        network_direction="inbound",
        destination_class="declared_service",
    )


def _classify_js_filesystem(
    finding: Finding,
    content: str,
    *,
    unreferenced: bool,
    hidden: bool,
) -> CorePrecisionDecision:
    line_number = finding.line_number
    if not isinstance(line_number, int):
        return CorePrecisionDecision(True, "unclassified_filesystem_candidate")
    call = _call_at_line(content, line_number, _JS_FS_CALL_RE)
    if call is None:
        return CorePrecisionDecision(True, "unclassified_filesystem_candidate")
    match, _arguments, expression = call
    operation = match.group("operation")
    if operation in _JS_WRITE_OPERATIONS:
        # A local filesystem write is not an exfiltration sink.  Staging plus
        # egress remains detectable at the later external-network sink.
        return CorePrecisionDecision(False, "local_filesystem_write_without_egress")

    file_path = finding.file_path or ""
    sensitive = _JS_SENSITIVE_PATH_RE.search(expression) is not None
    if sensitive:
        return CorePrecisionDecision(
            True,
            "sensitive_filesystem_read",
            evidence_value_class="sensitive_source_stage",
            candidate_flow=_flow_fact("credential_file", "filesystem_read", file_path),
        )
    # A bounded local text window cannot prove that a later callback, helper,
    # or computed request option does not transmit this value.  Until a
    # scope-correct JS data-flow proof exists, every read candidate fails open.
    role = "concealed" if hidden or unreferenced else "referenced"
    return CorePrecisionDecision(True, f"{role}_filesystem_read_without_complete_flow_proof")


def _classify_js_child_process(finding: Finding, content: str) -> CorePrecisionDecision:
    line_number = finding.line_number
    if not isinstance(line_number, int):
        return CorePrecisionDecision(True, "unclassified_process_candidate")
    call = _call_at_line(content, line_number, _JS_PROCESS_CALL_RE)
    if call is None:
        snippet = finding.snippet or ""
        if _JS_PROCESS_IMPORT_RE.search(snippet):
            return CorePrecisionDecision(False, "module_import_without_execution")
        return CorePrecisionDecision(True, "unclassified_process_candidate")
    match, arguments, expression = call
    api = match.group("api")
    file_path = finding.file_path or ""
    if api in {"exec", "execSync"}:
        dynamic = bool(arguments and (_JS_UNTRUSTED_VALUE_RE.search(arguments[0]) or "${" in arguments[0]))
        return CorePrecisionDecision(
            True,
            "shell_execution_candidate",
            evidence_value_class="active_interpolated_execution" if dynamic else "execution_api",
            candidate_command=_command_fact(shell=True, dynamic=dynamic, file_path=file_path),
        )
    if len(arguments) < 2:
        return CorePrecisionDecision(True, "unclassified_process_candidate")

    executable_argument = arguments[0].strip()
    argv_argument = arguments[1].strip()
    dynamic = bool(_JS_UNTRUSTED_VALUE_RE.search(executable_argument) or _JS_UNTRUSTED_VALUE_RE.search(argv_argument))
    literal_executable = _literal_value(executable_argument)
    executable_name = _executable_name(literal_executable) if literal_executable else None
    dynamic = dynamic or literal_executable is None
    shell = bool(_JS_SHELL_OPTION_RE.search(expression))
    shell = shell or bool(
        executable_name in _JS_SHELL_EXECUTABLES
        and re.search(r"(?:^|[\[,(\s])['\"](?:-c|/c|-command)['\"]", argv_argument, re.IGNORECASE)
    )
    interpreter_flags = _JS_CODE_INTERPRETER_FLAGS.get(executable_name or "", frozenset())
    inline_code = any(
        re.search(rf"(?:^|[\[,(\s])['\"]{re.escape(flag)}['\"]", argv_argument) for flag in interpreter_flags
    )
    if shell or dynamic or inline_code:
        return CorePrecisionDecision(
            True,
            "dynamic_shell_or_process_selection",
            evidence_value_class="shell_injection_sequence" if shell else "active_interpolated_execution",
            candidate_command=_command_fact(shell=shell or inline_code, dynamic=True, file_path=file_path),
        )

    # Structured argv avoids shell token injection, but an interpreter can
    # still execute an attacker-selected script and a fixed utility can retain
    # dangerous subcommands.  Candidate suppression requires a real AST/data-
    # flow proof that this lexical classifier does not provide.
    return CorePrecisionDecision(
        True,
        "process_execution_without_complete_dataflow_proof",
        evidence_value_class="active_interpolated_execution" if dynamic else "execution_api",
        candidate_command=_command_fact(shell=False, dynamic=dynamic, file_path=file_path),
    )


def classify_core_signature_candidate(
    finding: Finding,
    content: str,
    *,
    skill: Skill | None = None,
    unreferenced: bool = False,
    hidden: bool = False,
) -> CorePrecisionDecision:
    """Classify one broad core candidate, failing open for unknown shapes."""

    if finding.rule_id in {"PROMPT_INJECTION_CONCEALMENT", "YARA_prompt_injection_generic"}:
        line = finding.snippet or ""
        # The generic YARA rule contains several independent injection
        # families.  This refinement is valid only for its concealment string;
        # instruction override, tool injection, shadow parameter, and
        # privilege-escalation matches remain untouched.
        if (
            finding.rule_id == "YARA_prompt_injection_generic"
            and finding.metadata.get("matched_string") != "$hidden_behavior"
        ):
            return CorePrecisionDecision(True, "non_concealment_yara_primitive")
        if _ACTIVE_PROMPT_OVERRIDE_RE.search(line) or _ACTIVE_COERCION_RE.search(line):
            return CorePrecisionDecision(True, "cooccurring_active_override_or_coercion")
        if _USER_DIRECTION_RE.search(line) or _CONDITIONAL_ACCURACY_RE.search(line):
            return CorePrecisionDecision(False, "user_action_guidance_not_concealment")
        return CorePrecisionDecision(True, "action_concealment_or_ambiguous")
    # The remaining broad process, filesystem, and network candidates require
    # scope-correct AST/data-flow evidence before they can be suppressed or
    # demoted safely.  Keep them fail-open even when this helper is called
    # directly; the scanner currently invokes this module only for the two
    # closed concealment grammars above.
    return CorePrecisionDecision(True, "rule_not_refined_fail_open")


def _annotate_retained_candidate(finding: Finding, decision: CorePrecisionDecision) -> None:
    facts = finding.metadata.setdefault("semantic_facts", {})
    if not isinstance(facts, dict):
        return
    if decision.evidence_value_class is not None:
        finding.metadata["evidence_value_class"] = decision.evidence_value_class
        finding.metadata["evidence_count"] = 1
        facts["evidence_value_class"] = decision.evidence_value_class
        facts["evidence_count"] = 1
    if decision.candidate_command is not None:
        facts["candidate_command"] = decision.candidate_command
        facts["commands"] = [decision.candidate_command]
    if decision.candidate_flow is not None:
        facts["candidate_flow"] = decision.candidate_flow
        facts["flows"] = [decision.candidate_flow]
    if decision.severity_override is not None:
        finding.severity = decision.severity_override
        finding.title = "Declared read-only network access"
        finding.description = (
            "The package performs a provider-bound read-only network request declared by its instructions. "
            "No outbound payload or sensitive source-to-sink flow was identified."
        )
        finding.remediation = (
            "Keep the destination declaration and review changes that add request bodies or new providers."
        )
    if decision.network_direction is not None:
        facts["network_direction"] = decision.network_direction
    if decision.destination_class is not None:
        facts["destination_class"] = decision.destination_class


def refine_core_signature_findings(
    skill: Skill,
    findings: list[Finding],
    *,
    unreferenced_scripts: set[str] | frozenset[str],
) -> list[Finding]:
    """Remove proven near misses and retain all ambiguous candidates."""

    files = {Path(item.relative_path).as_posix(): item for item in skill.files}
    unreferenced = {Path(path).as_posix() for path in unreferenced_scripts}
    refined: list[Finding] = []
    for finding in findings:
        if finding.rule_id not in CORE_PRECISION_RULE_IDS:
            refined.append(finding)
            continue
        path = Path(finding.file_path or "").as_posix()
        skill_file = files.get(path)
        if path == "SKILL.md":
            content = skill.instruction_body
            hidden = False
        elif skill_file is not None:
            content = skill_file.read_content()
            hidden = skill_file.is_hidden
        else:
            # A recursively loaded alias can lack an inventory entry.  Its
            # candidate cannot be proven inert, so preserve it.
            refined.append(finding)
            continue
        decision = classify_core_signature_candidate(
            finding,
            content,
            skill=skill,
            unreferenced=path in unreferenced,
            hidden=hidden,
        )
        if decision.keep:
            _annotate_retained_candidate(finding, decision)
            refined.append(finding)
    return refined


__all__ = [
    "CORE_PRECISION_RULE_IDS",
    "CorePrecisionDecision",
    "classify_core_signature_candidate",
    "declared_network_provider_labels",
    "manifest_or_instructions_declare_network",
    "refine_core_signature_findings",
]
