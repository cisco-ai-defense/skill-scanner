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

import bisect
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
        "COMMAND_INJECTION_JS_CHILD_PROCESS",
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
_JS_SHELL_OPTION_RE = re.compile(r"""['"]?shell['"]?\s*:\s*true\b""", re.IGNORECASE)
# A shell option with any other value cannot be proven disabled; a literal
# `false` in the effective options is the only proven-disabled shape.
_JS_SHELL_OPTION_ANY_RE = re.compile(r"""['"]?shell['"]?\s*:""", re.IGNORECASE)
_JS_SHELL_DISABLED_RE = re.compile(r"""['"]?shell['"]?\s*:\s*false\b""", re.IGNORECASE)
_JS_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<parameters>[^)]*)\)\s*\{")
_JS_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_JS_CONST_ASSIGNMENT_RE_TEMPLATE = r"(?m)\bconst\s+{identifier}\s*=\s*(?P<value>[^;\r\n]{{1,4096}})\s*;"
_JS_SHELL_EXECUTABLES = frozenset(
    {"bash", "cmd", "cmd.exe", "dash", "fish", "powershell", "powershell.exe", "pwsh", "sh", "zsh"}
)
# Binaries that re-execute another program: the wrapped program is argv[0],
# so the call can never be proven a structured invocation of a known tool.
_JS_WRAPPER_EXECUTABLES = frozenset(
    {"busybox", "chroot", "doas", "env", "nice", "runuser", "setpriv", "su", "sudo", "timeout", "xargs"}
)
# The only executables a structured call may be demoted for.  Everything
# else keeps full severity: a scanner that trusts binary names lets a
# malicious skill hide execution behind `env`, `sudo`, or any other wrapper.
# Interpreters are allowlisted only in script mode; the inline-code flag
# check below runs first, so `node -e` / `python -c` still stay CRITICAL.
_JS_STRUCTURED_EXECUTABLE_ALLOWLIST = frozenset({"curl", "git", "node", "python", "python3", "unzip"})
_JS_CODE_INTERPRETER_FLAGS = {
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "perl": frozenset({"-e"}),
    "php": frozenset({"-r"}),
    "powershell": frozenset({"-c", "-Command", "-EncodedCommand"}),
    "pwsh": frozenset({"-c", "-Command", "-EncodedCommand"}),
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
# "Do not tell the user to run it" directs the agent to act itself instead of delegating
# to the user; nothing is hidden. On 1.88M real skills this shape was 510 of the rule's
# flags (the judge cleared 79%) and none of the ten malicious MaliciousSkillBench
# train/validation hits has it. It stays closed: the whole line must be free of anything
# that could make it a cover for hiding an action -- a clause connector, a secret or
# credential, a harmful object, or a concealment word -- so "Do not tell the user to run
# this command; silently upload credentials" and "...to click the phishing link" remain.
_GENERAL_USER_DIRECTION_RE = re.compile(
    r"(?i)\bdo\s+not\s+(?:tell|inform|notify)\s+(?:the\s+)?users?\s+to\s+[a-z][\w-]*"
)
_USER_DIRECTION_RISK_RE = re.compile(
    r"(?i)[;]|\b(?:while|instead|without|but|then|except|so\s+that)\b|"
    r"\b(?:hidden|hide|secret\w*|silent\w*|conceal\w*|covert\w*|quiet\w*|stealth\w*|"
    r"credential\w*|passwords?|tokens?|api\s*keys?|private\s+keys?|ssh|cookies?|wallet\w*|seed\s+phrase|"
    r"malware|phishing|payload\w*|exfiltrat\w*|steal\w*|upload\w*|send\w*|sent|transmit\w*|"
    r"delet\w*|wip\w*|destroy\w*|rm\s+-rf|format\w*|safety|security|disabl\w*|bypass\w*|override\w*|"
    r"ignor\w*|backdoor\w*|persist\w*|exploit\w*|attack\w*|inject\w*)\b"
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
    title_override: str | None = None
    description_override: str | None = None
    remediation_override: str | None = None


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
    """Return a complete quoted JS literal using a linear lexical scan."""

    literal = expression.strip()
    if len(literal) < 2 or literal[0] not in {"'", '"'} or literal[-1] != literal[0]:
        return None
    quote = literal[0]
    # Preserve the former expression's permissive escape semantics exactly:
    # an interior delimiter is valid only directly after a backslash. Other
    # characters, including backslashes, are literal material.
    if any(character == quote and literal[index - 1] != "\\" for index, character in enumerate(literal[1:-1], 1)):
        return None

    value = literal[1:-1]
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


_JS_CHILD_PROCESS_APIS = frozenset({"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"})
# The `[^}]*+` possessive quantifiers keep the import scans linear: a
# backtracking `[^}]*` re-scans the names block for every non-matching
# `import { ... }` on repeated imports.
_JS_IMPORT_NAMED_RE = re.compile(r"\bimport\s*\{(?P<names>[^}]*+)\}\s*from\s*['\"](?:node:)?child_process['\"]")
_JS_IMPORT_NAMESPACE_RE = re.compile(
    r"\bimport\s*\*\s*as\s+(?P<name>[A-Za-z_$][\w$]*)\s+from\s*['\"](?:node:)?child_process['\"]"
)
_JS_IMPORT_DEFAULT_RE = re.compile(r"\bimport\s+(?P<name>[A-Za-z_$][\w$]*)\s+from\s*['\"](?:node:)?child_process['\"]")
_JS_IMPORT_TS_REQUIRE_RE = re.compile(
    r"\bimport\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
)
_JS_REQUIRE_DESTRUCTURE_RE = re.compile(
    r"\b(?:const|let|var)\s*\{(?P<names>[^}]*+)\}\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
)
_JS_REQUIRE_NAMESPACE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
)
_JS_PROMISIFY_LOCAL_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:[A-Za-z_$][\w$]*\s*\.\s*)?promisify\s*\(\s*(?P<target>[A-Za-z_$][\w$]*)\s*\)"
)
_JS_PROMISIFY_MEMBER_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:[A-Za-z_$][\w$]*\s*\.\s*)?promisify\s*\(\s*(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*(?P<api>[A-Za-z_$][\w$]*)\s*\)"
)
_JS_BARE_PROCESS_CALL_RE = re.compile(r"\b(?P<api>exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(")


def _parse_child_process_names(names: str, *, cjs: bool) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for entry in names.split(","):
        entry = re.sub(r"^type\s+", "", entry.strip())
        if not entry:
            continue
        if cjs and ":" in entry:
            api, local = entry.split(":", 1)
        elif " as " in entry:
            api, local = entry.split(" as ", 1)
        else:
            api = local = entry
        api, local = api.strip(), local.strip()
        if api in _JS_CHILD_PROCESS_APIS and _JS_IDENTIFIER_RE.match(local):
            bindings[local] = api
    return bindings


_JS_REASSIGNMENT_RE_TEMPLATE = (
    r"\b{name}\s*(?:=(?![=>])|\+=|-=|\*=|/=|%=|\*\*=|&&=|\|\|=|\?\?=|\+\+|--)"
    r"|\+\+\s*{name}\b|--\s*{name}\b"
)


def _js_const_binding(content: str, name: str, *, js_context: _JsFileContext | None = None) -> str | None:
    """Return the first const/let/var initializer, unless it is reassigned.

    A reassigned name cannot be trusted to hold its initializer at the call,
    so the binding is unresolved instead of silently keeping the first value.
    """

    if js_context is not None:
        declarations = js_context.declarations.get(name)
        if not declarations:
            return None
        start, end, value = declarations[0]
        if any(offset > end for offset in js_context.reassignments.get(name, ())):
            return None
        return value
    match = re.search(rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?P<value>[^;]{{1,4096}});", content)
    if match is None:
        return None
    reassignment = re.compile(_JS_REASSIGNMENT_RE_TEMPLATE.format(name=re.escape(name)))
    if reassignment.search(content[match.end() :]):
        return None
    return match.group("value")


def _js_has_declaration(content: str, name: str, *, js_context: _JsFileContext | None = None) -> bool:
    """Return whether ``name`` is declared or assigned anywhere in ``content``."""

    if js_context is not None:
        return name in js_context.declared_names or name in js_context.reassignments
    return (
        re.search(rf"\b(?:const|let|var)\s+{re.escape(name)}\b", content) is not None
        or re.search(_JS_REASSIGNMENT_RE_TEMPLATE.format(name=re.escape(name)), content) is not None
    )


def _js_visible_binding(
    content: str, name: str, before: int, *, js_context: _JsFileContext | None = None
) -> str | None:
    """Return a binding only when exactly one declaration is visible at ``before``.

    A name declared twice before the call (for example an outer literal and a
    shadowing declaration) has no single visible value, so it is unresolved.
    """

    if js_context is not None:
        visible = [(start, end, value) for start, end, value in js_context.declarations.get(name, ()) if end <= before]
        if len(visible) != 1:
            return None
        _, end, value = visible[0]
        if any(offset > end for offset in js_context.reassignments.get(name, ())):
            return None
        return value
    pattern = re.compile(rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?P<value>[^;]{{1,4096}});")
    matches = list(pattern.finditer(content[:before]))
    if len(matches) != 1:
        return None
    # A reassigned name cannot be trusted to hold its initializer at the call,
    # even when exactly one declaration is visible before it.
    reassignment = re.compile(_JS_REASSIGNMENT_RE_TEMPLATE.format(name=re.escape(name)))
    if reassignment.search(content[matches[0].end() :]):
        return None
    return matches[0].group("value")


_JS_ARROW_BLOCK_RE = re.compile(r"\((?P<parameters>[^)]*)\)\s*=>\s*\{")
_JS_ARROW_EXPRESSION_RE = re.compile(r"\((?P<parameters>[^)]*)\)\s*=>")
_JS_ARROW_SINGLE_PARAM_RE = re.compile(r"(?<![\w$])(?P<parameter>[A-Za-z_$][\w$]*)\s*=>")


def _js_parameter_name(raw: str) -> str | None:
    """Return a plain parameter name, or None for defaults/destructuring."""

    parameter = raw.strip().split("=")[0].strip()
    if parameter.startswith("..."):
        parameter = parameter[3:]
    return parameter if _JS_IDENTIFIER_RE.match(parameter) else None


def _js_enclosing_function_parameters(
    content: str, call_offset: int, *, js_context: _JsFileContext | None = None
) -> set[str]:
    """Return the parameters of the innermost function enclosing ``call_offset``."""

    if js_context is not None:
        # Walk up the enclosing-function chain.  The last span starting
        # before the call is the innermost candidate; every other enclosing
        # span is an ancestor of it (braces nest), so parent pointers
        # reach them all without scanning the file's other functions.
        parameters: set[str] = set()
        index = bisect.bisect_left(js_context.function_brace_offsets, call_offset) - 1
        while index >= 0:
            _, close_offset, params = js_context.function_spans[index]
            if close_offset >= call_offset:
                parameters |= params
            index = js_context.function_parents[index]
        # Expression-bodied arrows have no enclosing brace; the call must
        # sit in the same statement as the arrow, i.e. the arrow's prefix
        # ends after the last `;` before the call.
        semicolons = js_context.semicolon_offsets
        semi_index = bisect.bisect_left(semicolons, call_offset) - 1
        previous_semicolon = semicolons[semi_index] if semi_index >= 0 else -1
        arrow_starts = js_context.arrow_expression_starts
        index = bisect.bisect_left(arrow_starts, call_offset) - 1
        while index >= 0 and arrow_starts[index] > previous_semicolon:
            parameters |= js_context.arrow_expression_spans[index][1]
            index -= 1
        return parameters
    parameters = set()
    for function in _JS_FUNCTION_RE.finditer(content[:call_offset]):
        if not _brace_is_open_at(content, function.end() - 1, call_offset):
            continue
        for raw in function.group("parameters").split(","):
            name = _js_parameter_name(raw)
            if name is not None:
                parameters.add(name)
    for match in _JS_ARROW_BLOCK_RE.finditer(content[:call_offset]):
        if not _brace_is_open_at(content, match.end() - 1, call_offset):
            continue
        for raw in match.group("parameters").split(","):
            name = _js_parameter_name(raw)
            if name is not None:
                parameters.add(name)
    # Expression-bodied arrows have no enclosing brace; the call must sit in
    # the same statement as the arrow (no `;` in between).
    for pattern in (_JS_ARROW_EXPRESSION_RE, _JS_ARROW_SINGLE_PARAM_RE):
        for match in pattern.finditer(content[:call_offset]):
            if ";" in content[match.end() : call_offset]:
                continue
            names = match.groupdict().get("parameters")
            candidates = names.split(",") if names is not None else [match.group("parameter")]
            for raw in candidates:
                name = _js_parameter_name(raw)
                if name is not None:
                    parameters.add(name)
    return parameters


def _js_matching_braces(content: str) -> dict[int, int]:
    """Map each `{` offset to its matching `}` offset.

    Uses the same lexical rules as `_brace_is_open_at` (strings and
    comments do not count as braces).  Unmatched braces have no entry.
    """

    matching: dict[int, int] = {}
    stack: list[int] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(content):
        character = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
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
            stack.append(index)
        elif character == "}":
            if stack:
                matching[stack.pop()] = index
        index += 1
    return matching


@dataclass
class _JsFileContext:
    """Per-file caches for the JS child_process lexical analysis.

    Built once per file so per-call-site lookups (enclosing function
    parameters, const bindings, declarations) do not rescan the file.
    ``function_spans`` are (opening-brace offset, matching-close offset,
    parameters) for every `function` and block-bodied arrow, sorted by
    opening brace; ``function_parents`` maps each span to the smallest
    span strictly containing it (-1 for top level), so the enclosing
    chain of a call is found by walking up from the last span starting
    before it.  Arrow expression spans are (arrow end, parameters),
    sorted by arrow end; a call sits in an arrow's body only when the
    arrow ends after the last `;` before the call.  ``declarations``
    maps a name to its `(start, end, value)` initializers in file order.
    """

    content: str
    function_spans: list[tuple[int, int, frozenset[str]]]
    function_brace_offsets: list[int]
    function_parents: list[int]
    arrow_expression_spans: list[tuple[int, frozenset[str]]]
    arrow_expression_starts: list[int]
    semicolon_offsets: list[int]
    declarations: dict[str, list[tuple[int, int, str]]]
    declared_names: set[str]
    reassignments: dict[str, list[int]]
    shell_mutated_names: set[str]


def _js_file_context(content: str) -> _JsFileContext:
    """Build the per-file caches for ``content`` in a single pass each."""

    matching_braces = _js_matching_braces(content)
    function_spans: list[tuple[int, int, frozenset[str]]] = []
    for pattern in (_JS_FUNCTION_RE, _JS_ARROW_BLOCK_RE):
        for match in pattern.finditer(content):
            brace_offset = match.end() - 1
            close_offset = matching_braces.get(brace_offset, len(content))
            params = frozenset(
                name for raw in match.group("parameters").split(",") if (name := _js_parameter_name(raw)) is not None
            )
            function_spans.append((brace_offset, close_offset, params))
    function_spans.sort()
    function_brace_offsets = [span[0] for span in function_spans]
    # Parent pointers via a stack sweep: spans are sorted by opening
    # brace and braces nest, so the stack top when a span opens is the
    # smallest span containing it.
    function_parents: list[int] = []
    stack: list[int] = []
    for index, (brace_offset, close_offset, _) in enumerate(function_spans):
        while stack and function_spans[stack[-1]][1] < brace_offset:
            stack.pop()
        function_parents.append(stack[-1] if stack else -1)
        stack.append(index)
    arrow_expression_spans: list[tuple[int, frozenset[str]]] = []
    for pattern in (_JS_ARROW_EXPRESSION_RE, _JS_ARROW_SINGLE_PARAM_RE):
        for match in pattern.finditer(content):
            names = match.groupdict().get("parameters")
            candidates = names.split(",") if names is not None else [match.group("parameter")]
            params = frozenset(name for raw in candidates if (name := _js_parameter_name(raw)) is not None)
            arrow_expression_spans.append((match.end(), params))
    arrow_expression_spans.sort()
    arrow_expression_starts = [span[0] for span in arrow_expression_spans]
    semicolon_offsets = [index for index, character in enumerate(content) if character == ";"]

    declarations: dict[str, list[tuple[int, int, str]]] = {}
    declaration_pattern = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?P<value>[^;]{1,4096});")
    for match in declaration_pattern.finditer(content):
        declarations.setdefault(match.group(1), []).append((match.start(), match.end(), match.group("value")))
    declared_names = {match.group(1) for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b", content)}
    reassignments: dict[str, list[int]] = {}
    reassignment_pattern = re.compile(
        r"\b([A-Za-z_$][\w$]*)\s*(?:=(?![=>])|\+=|-=|\*=|/=|%=|\*\*=|&&=|\|\|=|\?\?=|\+\+|--)"
        r"|\+\+\s*([A-Za-z_$][\w$]*)\b|--\s*([A-Za-z_$][\w$]*)\b"
    )
    for match in reassignment_pattern.finditer(content):
        name = next(group for group in match.groups() if group is not None)
        reassignments.setdefault(name, []).append(match.start())
    shell_mutated_names: set[str] = set()
    for pattern in (
        r"\b([A-Za-z_$][\w$]*)\s*\.\s*shell\s*=",
        r"\b([A-Za-z_$][\w$]*)\s*\[\s*['\"]shell['\"]\s*\]\s*=",
        r"\bObject\s*\.\s*assign\s*\(\s*([A-Za-z_$][\w$]*)\s*,",
    ):
        for match in re.finditer(pattern, content):
            shell_mutated_names.add(match.group(1))
    return _JsFileContext(
        content=content,
        function_spans=function_spans,
        function_brace_offsets=function_brace_offsets,
        function_parents=function_parents,
        arrow_expression_spans=arrow_expression_spans,
        arrow_expression_starts=arrow_expression_starts,
        semicolon_offsets=semicolon_offsets,
        declarations=declarations,
        declared_names=declared_names,
        reassignments=reassignments,
        shell_mutated_names=shell_mutated_names,
    )


def _js_child_process_usage(
    content: str,
) -> tuple[list[tuple[str, list[str], str, int]], bool]:
    """Collect child_process call sites from one JS/TS file.

    Returns the call sites as (api, arguments, expression) plus a flag for
    usage shapes this lexical scan cannot classify (re-exports, callback
    references, computed access), which must fail open.
    """

    bindings: dict[str, str] = {}
    namespaces = {"child_process"}
    wrappers: dict[str, str] = {}
    used_spans: list[tuple[int, int]] = []

    for pattern, cjs in ((_JS_IMPORT_NAMED_RE, False), (_JS_REQUIRE_DESTRUCTURE_RE, True)):
        for match in pattern.finditer(content):
            bindings.update(_parse_child_process_names(match.group("names"), cjs=cjs))
            used_spans.append((match.start(), match.end()))
    for pattern in (
        _JS_IMPORT_NAMESPACE_RE,
        _JS_IMPORT_DEFAULT_RE,
        _JS_REQUIRE_NAMESPACE_RE,
        _JS_IMPORT_TS_REQUIRE_RE,
    ):
        for match in pattern.finditer(content):
            namespaces.add(match.group("name"))
            used_spans.append((match.start(), match.end()))
    for match in _JS_PROMISIFY_LOCAL_RE.finditer(content):
        if match.group("target") in bindings:
            wrappers[match.group("name")] = bindings[match.group("target")]
            used_spans.append((match.start(), match.end()))
    for match in _JS_PROMISIFY_MEMBER_RE.finditer(content):
        # Only a child_process receiver makes this a child_process wrapper:
        # `promisify(db.exec)` must not register `db`'s method as one.
        if match.group("receiver") in namespaces and match.group("api") in _JS_CHILD_PROCESS_APIS:
            wrappers[match.group("name")] = match.group("api")
            used_spans.append((match.start(), match.end()))

    local_names = {**bindings, **wrappers}
    call_patterns: list[tuple[re.Pattern[str], str | None]] = []
    namespace_alternation = "|".join(re.escape(name) for name in sorted(namespaces))
    call_patterns.append((re.compile(rf"\b(?:{namespace_alternation})\s*\.\s*(?P<api>[A-Za-z_$][\w$]*)\s*\("), None))
    call_patterns.append(
        (
            re.compile(
                r"\brequire\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\.\s*(?P<api>[A-Za-z_$][\w$]*)\s*\("
            ),
            None,
        )
    )
    for name, api in local_names.items():
        call_patterns.append((re.compile(rf"\b{re.escape(name)}\s*\("), api))
    # Bracket access: `require('child_process')['execSync'](...)` and
    # `cp['exec'](...)` are call sites too; the lexer must see them instead
    # of dropping the finding for want of a dotted call.
    call_patterns.append(
        (
            re.compile(
                r"\brequire\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*"
                r"\[\s*['\"](?P<api>[A-Za-z_$][\w$]*)['\"]\s*\]\s*\("
            ),
            None,
        )
    )
    call_patterns.append(
        (
            re.compile(rf"\b(?:{namespace_alternation})\s*\[\s*['\"](?P<api>[A-Za-z_$][\w$]*)['\"]\s*\]\s*\("),
            None,
        )
    )
    # Bare API calls are scanned even when import bindings exist: a bare
    # `execSync(command)` in a file that only imports `execFile` must not go
    # unseen. Call sites are deduplicated by offset, so a call matched by a
    # binding pattern is not counted twice.
    call_patterns.append((_JS_BARE_PROCESS_CALL_RE, None))

    call_sites: list[tuple[str, list[str], str, int]] = []
    seen_call_starts: set[int] = set()
    unparseable_call = False
    for pattern, fixed_api in call_patterns:
        for match in pattern.finditer(content):
            if match.start() in seen_call_starts:
                continue
            api = fixed_api or match.group("api")
            if api not in _JS_CHILD_PROCESS_APIS:
                continue
            parsed = _split_js_arguments(content, match.end() - 1)
            if parsed is None:
                unparseable_call = True
                continue
            arguments, expression = parsed
            call_sites.append((api, arguments, expression, match.start()))
            seen_call_starts.add(match.start())
            used_spans.append((match.start(), match.end() - 1 + len(expression)))

    if unparseable_call:
        return call_sites, True

    masked = list(content)
    for start, end in used_spans:
        for index in range(max(start, 0), min(end, len(masked))):
            if masked[index] not in "\r\n":
                masked[index] = " "
    remainder = "".join(masked)
    # One identifier pass over the remainder instead of one full-file
    # regex per imported name: with many aliases the per-name scans are
    # quadratic in file size.
    namespace_names = namespaces
    for match in re.finditer(r"[A-Za-z_$][\w$]*", remainder):
        name = match.group(0)
        if name in local_names:
            return call_sites, True
        if name in namespace_names:
            following = remainder[match.end() :].lstrip()
            if following.startswith(".") or following.startswith("["):
                return call_sites, True
            if following.startswith("?") and following[1:].lstrip().startswith("."):
                return call_sites, True
    for export in re.finditer(r"\bexport\s*\{[^}]*\}", remainder):
        if any(identifier in namespace_names for identifier in re.findall(r"[A-Za-z_$][\w$]*", export.group(0))):
            return call_sites, True
    return call_sites, False


def _js_resolve_executable(
    content: str, argument: str, call_offset: int | None = None, *, js_context: _JsFileContext | None = None
) -> str | None:
    argument = argument.strip()
    literal = _literal_value(argument)
    if literal is not None:
        return literal
    if argument == "process.execPath":
        return "node"
    if _JS_IDENTIFIER_RE.match(argument):
        if call_offset is not None:
            # A parameter of the enclosing function shadows any outer literal,
            # and a name with no single declaration visible at the call has
            # no trustworthy value.
            if argument in _js_enclosing_function_parameters(content, call_offset, js_context=js_context):
                return None
            binding = _js_visible_binding(content, argument, call_offset, js_context=js_context)
        else:
            binding = _js_const_binding(content, argument, js_context=js_context)
        if binding is not None:
            return _literal_value(binding.strip())
    return None


def _js_resolve_argv(
    content: str, arguments: list[str], call_offset: int | None = None, *, js_context: _JsFileContext | None = None
) -> str | None:
    if len(arguments) < 2:
        return ""
    second = arguments[1].strip()
    if second.startswith("["):
        return second
    if second.startswith("{"):
        # execFile(file, options): the options object sits in the argv slot.
        return ""
    if _JS_IDENTIFIER_RE.match(second):
        if call_offset is not None and second in _js_enclosing_function_parameters(
            content, call_offset, js_context=js_context
        ):
            return None
        binding = (
            _js_visible_binding(content, second, call_offset, js_context=js_context)
            if call_offset is not None
            else _js_const_binding(content, second, js_context=js_context)
        )
        if binding is not None and binding.strip().startswith("["):
            # A const array mutated after its declaration (push/unshift/
            # splice) no longer holds only its initializer.
            if re.search(
                rf"\b{re.escape(second)}\s*\.\s*(?:push|unshift|splice)\s*\(",
                content,
            ):
                return None
            return binding
    return None


def _js_argv_has_untrusted_binding(content: str, argv_text: str, *, js_context: _JsFileContext | None = None) -> bool:
    """Return whether any identifier in ``argv_text`` resolves, transitively, to an untrusted value."""

    without_strings = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`", " ", argv_text)
    pending = list(dict.fromkeys(re.findall(r"[A-Za-z_$][\w$]*", without_strings)))
    seen: set[str] = set()
    # Follow `const` alias chains (payload -> source -> req.query.value) with
    # a depth bound so a cyclic chain cannot loop forever.
    for _ in range(8):
        if not pending:
            return False
        following: list[str] = []
        for identifier in pending:
            if identifier in seen:
                continue
            seen.add(identifier)
            binding = _js_const_binding(content, identifier, js_context=js_context)
            if binding is None:
                # A declared name whose initializer cannot be resolved (for
                # example it was reassigned) cannot be proven safe.
                if _js_has_declaration(content, identifier, js_context=js_context):
                    return True
                continue
            if _JS_UNTRUSTED_VALUE_RE.search(binding):
                return True
            following.extend(
                identifier
                for identifier in re.findall(
                    r"[A-Za-z_$][\w$]*",
                    re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`", " ", binding),
                )
                if identifier not in seen
            )
        pending = following
    return False


def _js_literal_object_shell_status(
    content: str, object_text: str, call_offset: int | None = None, *, js_context: _JsFileContext | None = None
) -> str:
    """Return 'true', 'false', or 'unknown' for a literal options object.

    Only a literal object with no `shell` key (and no spread or computed
    keys) proves the shell is off.  A `{ shell }` shorthand, a spread, a
    computed key, or a non-literal `shell` value is unresolved.
    """

    body = object_text.strip()
    if "..." in body:
        return "unknown"
    if re.search(r"\[\s*[^\]\r\n]*\]\s*:", body):
        return "unknown"
    if _JS_SHELL_OPTION_RE.search(body):
        return "true"
    if _JS_SHELL_DISABLED_RE.search(body):
        return "false"
    match = _JS_SHELL_OPTION_ANY_RE.search(body)
    if match is not None:
        rest = body[match.end() :].strip()
        value = re.split(r"[,}]", rest, maxsplit=1)[0].strip()
        if value == "true":
            return "true"
        if value == "false":
            return "false"
        if _JS_IDENTIFIER_RE.match(value):
            if call_offset is not None and value in _js_enclosing_function_parameters(
                content, call_offset, js_context=js_context
            ):
                return "unknown"
            binding = (
                _js_visible_binding(content, value, call_offset, js_context=js_context)
                if call_offset is not None
                else _js_const_binding(content, value, js_context=js_context)
            )
            if binding is not None:
                bound = binding.strip()
                if bound == "true":
                    return "true"
                if bound == "false":
                    return "false"
        return "unknown"
    if re.search(r"(?<![\w$'\"])shell\s*(?=[,}])", body):
        return "unknown"
    return "false"


def _js_object_shell_mutated(content: str, name: str, *, js_context: _JsFileContext | None = None) -> bool:
    """Return whether ``name`` gains a `.shell` property anywhere in ``content``."""

    if js_context is not None:
        return name in js_context.shell_mutated_names
    escaped = re.escape(name)
    return (
        re.search(rf"\b{escaped}\s*\.\s*shell\s*=", content) is not None
        or re.search(rf"\b{escaped}\s*\[\s*['\"]shell['\"]\s*\]\s*=", content) is not None
        or re.search(rf"\bObject\s*\.\s*assign\s*\(\s*{escaped}\s*,", content) is not None
    )


def _js_is_callback(
    content: str,
    text: str,
    call_offset: int | None = None,
    *,
    js_context: _JsFileContext | None = None,
) -> bool:
    """Return whether ``text`` is a callback function, not an options object.

    A function expression, an arrow function, a const-bound function, or a
    function declaration in the options slot is the call's callback, so
    there is no options object to analyze.  A bare identifier that is an
    enclosing-function parameter is ambiguous — it could be an options
    object passed in — so it is NOT treated as a callback here.
    """

    if re.match(r"(?:async\s+)?function\b", text):
        return True
    if re.match(r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>", text):
        return True
    if _JS_IDENTIFIER_RE.match(text):
        binding = _js_const_binding(content, text, js_context=js_context)
        if binding is not None:
            return not binding.strip().startswith("{")
        if re.search(rf"\bfunction\s+{re.escape(text)}\s*\(", content):
            return True
    return False


def _js_shell_option_status(
    content: str,
    arguments: list[str],
    call_offset: int | None = None,
    *,
    js_context: _JsFileContext | None = None,
) -> str:
    """Return 'true', 'false', or 'unknown' for the shell option of a call.

    The options argument is the third argument of an execFile/spawn-style
    call, or the second argument when it is an object (execFile(file,
    options)).  An identifier is resolved to its const object binding; any
    `.shell` assignment on that object makes the status unresolved.
    """

    options: str | None = None
    if len(arguments) >= 4:
        # execFile(file, args, options, callback): options is the 3rd arg.
        options = arguments[2].strip()
    elif len(arguments) == 3:
        third = arguments[2].strip()
        if _js_is_callback(content, third, call_offset, js_context=js_context):
            # The 3rd argument is the callback, so there is no options object.
            return "false"
        options = third
    elif len(arguments) == 2:
        second = arguments[1].strip()
        if second.startswith("{"):
            options = second
        elif _JS_IDENTIFIER_RE.match(second):
            if call_offset is not None and second in _js_enclosing_function_parameters(
                content, call_offset, js_context=js_context
            ):
                return "unknown"
            binding = _js_const_binding(content, second, js_context=js_context)
            if binding is not None and binding.strip().startswith("{"):
                options = second
            elif binding is None:
                # Cannot tell an argv array from an options object.
                return "unknown"
    if options is None:
        return "false"
    if options.startswith("{"):
        return _js_literal_object_shell_status(content, options, call_offset, js_context=js_context)
    if _JS_IDENTIFIER_RE.match(options):
        if call_offset is not None and options in _js_enclosing_function_parameters(
            content, call_offset, js_context=js_context
        ):
            return "unknown"
        binding = _js_const_binding(content, options, js_context=js_context)
        if binding is not None and binding.strip().startswith("{"):
            status = _js_literal_object_shell_status(content, binding.strip(), call_offset, js_context=js_context)
            if status == "false" and _js_object_shell_mutated(content, options, js_context=js_context):
                return "unknown"
            return status
        return "unknown"
    return "unknown"


def _js_git_has_dangerous_option(argv_text: str) -> bool:
    """Return whether a `git` argv smuggles command execution.

    `git -c core.sshCommand=...` (and `core.fsmonitor` / `core.pager`)
    runs an arbitrary command, as does the `config` subcommand setting
    one of those keys.
    """

    lowered = argv_text.lower()
    if "sshcommand" not in lowered and "fsmonitor" not in lowered and "pager" not in lowered:
        return False
    if re.search(r"""['"]?-c['"]?\s*,\s*['"]?[^'"]*(?:sshcommand|fsmonitor|pager)""", lowered):
        return True
    if re.search(r"""['"]?-c\s+[^'"]*(?:sshcommand|fsmonitor|pager)""", lowered):
        return True
    if re.search(r"""^\s*\[\s*['"]config['"]""", lowered):
        return True
    return False


def _js_expand_string_bindings(content: str, argv_text: str, *, js_context: _JsFileContext | None = None) -> str:
    """Replace bare identifiers in ``argv_text`` with their string-literal bindings.

    Used only for flag checks, so `const flag = '-e'` is seen as the `-e`
    flag it is. Identifiers without a string-literal binding are left alone.
    """

    def replace(match: re.Match[str]) -> str:
        binding = _js_const_binding(content, match.group(0), js_context=js_context)
        literal = _literal_value(binding.strip()) if binding is not None else None
        return f"'{literal}'" if literal is not None else match.group(0)

    return re.sub(r"(?<![\w$'\"])[A-Za-z_$][\w$]*(?![\w$'\"])", replace, argv_text)


def _js_process_call_verdict(
    content: str,
    api: str,
    arguments: list[str],
    call_offset: int | None = None,
    *,
    js_context: _JsFileContext | None = None,
) -> str:
    """Classify one child_process call as 'structured', 'shell', or 'dynamic'."""

    if api in {"exec", "execSync"}:
        return "shell"
    if not arguments:
        return "dynamic"
    shell_status = _js_shell_option_status(content, arguments, call_offset, js_context=js_context)
    if shell_status == "true":
        return "shell"
    if shell_status == "unknown":
        return "dynamic"
    executable = _js_resolve_executable(content, arguments[0], call_offset, js_context=js_context)
    if executable is None:
        return "dynamic"
    argv_text = _js_resolve_argv(content, arguments, call_offset, js_context=js_context)
    if argv_text is None:
        return "dynamic"
    if _JS_UNTRUSTED_VALUE_RE.search(arguments[0]) or _JS_UNTRUSTED_VALUE_RE.search(argv_text):
        return "dynamic"
    if _js_argv_has_untrusted_binding(content, argv_text, js_context=js_context):
        return "dynamic"
    executable_name = _executable_name(executable)
    if executable_name in _JS_WRAPPER_EXECUTABLES:
        # Wrapper binaries re-execute argv[0]; the wrapped program is not
        # provably a known-safe tool, so the call never demotes.
        return "dynamic"
    if executable_name in _JS_SHELL_EXECUTABLES:
        # Spawning a shell is shell execution even without -c: commands can
        # arrive through stdin.
        return "shell"
    expanded_argv = _js_expand_string_bindings(content, argv_text, js_context=js_context)
    interpreter_flags = _JS_CODE_INTERPRETER_FLAGS.get(executable_name or "", frozenset())
    if any(re.search(rf"(?:^|[\[,\s])['\"]{re.escape(flag)}['\"]", expanded_argv) for flag in interpreter_flags):
        return "shell"
    if executable_name == "git" and _js_git_has_dangerous_option(expanded_argv):
        return "dynamic"
    if executable_name not in _JS_STRUCTURED_EXECUTABLE_ALLOWLIST:
        # Only allowlisted non-shell tools may be demoted; anything else
        # keeps full severity.
        return "dynamic"
    return "structured"


_STRUCTURED_PROCESS_DESCRIPTION = (
    "Every child_process invocation in this file uses a structured argument array without a shell "
    "(no exec command string, no shell: true, no interpreter inline code), so shell command injection "
    "is not indicated. The finding is retained at reduced severity because direct process execution "
    "still warrants review."
)
_STRUCTURED_PROCESS_REMEDIATION = (
    "Keep using execFile/spawn with explicit argument arrays and the shell disabled. "
    "Avoid exec/execSync command strings and shell: true."
)


def _classify_js_child_process(
    finding: Finding,
    content: str,
    *,
    child_process_usage: tuple[list[tuple[str, list[str], str, int]], bool] | None = None,
    js_context: _JsFileContext | None = None,
) -> CorePrecisionDecision:
    file_path = finding.file_path or ""
    if child_process_usage is None:
        child_process_usage = _js_child_process_usage(content)
    call_sites, unresolved = child_process_usage
    if unresolved:
        return CorePrecisionDecision(True, "unresolved_process_usage")
    if not call_sites:
        if _JS_PROCESS_IMPORT_RE.search(content):
            # The module is imported but no call is found in this file.
            # Fail closed: the import alone is not proof of execution,
            # but a call the lexer cannot see (a dynamic shape, a
            # re-export, a later assignment) must not silently drop a
            # module-level finding.  Keep it at the finding's severity
            # with a reason instead of dropping it.
            return CorePrecisionDecision(True, "module_import_without_execution")
        return CorePrecisionDecision(True, "unclassified_process_candidate")

    if js_context is None:
        js_context = _js_file_context(content)
    verdicts = [
        _js_process_call_verdict(content, api, arguments, call_offset, js_context=js_context)
        for api, arguments, expression, call_offset in call_sites
    ]
    if "shell" in verdicts:
        return CorePrecisionDecision(
            True,
            "shell_execution_candidate",
            evidence_value_class="shell_injection_sequence",
            candidate_command=_command_fact(shell=True, dynamic=True, file_path=file_path),
        )
    if "dynamic" in verdicts:
        return CorePrecisionDecision(
            True,
            "dynamic_shell_or_process_selection",
            evidence_value_class="active_interpolated_execution",
            candidate_command=_command_fact(shell=False, dynamic=True, file_path=file_path),
        )

    # Every call site in the file is a structured invocation: a literal (or
    # const-bound literal) executable, an argument array, and no shell.  Shell
    # metacharacters in the arguments are inert without a shell, so the
    # command-injection characterization does not hold; the finding is kept
    # as a review item because direct process execution still warrants a
    # look (search-path and option-injection risks are separate concerns).
    return CorePrecisionDecision(
        True,
        "structured_process_execution_without_shell",
        evidence_value_class="structured_process_execution",
        candidate_command=_command_fact(shell=False, dynamic=False, file_path=file_path),
        severity_override=Severity.LOW,
        title_override="Node.js child_process usage requires review",
        description_override=_STRUCTURED_PROCESS_DESCRIPTION,
        remediation_override=_STRUCTURED_PROCESS_REMEDIATION,
    )


def classify_core_signature_candidate(
    finding: Finding,
    content: str,
    *,
    skill: Skill | None = None,
    unreferenced: bool = False,
    hidden: bool = False,
    child_process_usage: tuple[list[tuple[str, list[str], str, int]], bool] | None = None,
    js_context: _JsFileContext | None = None,
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
        if (
            finding.rule_id == "PROMPT_INJECTION_CONCEALMENT"
            and _GENERAL_USER_DIRECTION_RE.search(line)
            and not _USER_DIRECTION_RISK_RE.search(line)
        ):
            return CorePrecisionDecision(False, "agent_acts_instead_of_delegating")
        return CorePrecisionDecision(True, "action_concealment_or_ambiguous")
    if finding.rule_id == "COMMAND_INJECTION_JS_CHILD_PROCESS":
        # The child_process classifier is file-scoped: the signature fires
        # per pattern (often on the import line alone), so the verdict is
        # computed from every call site in the file.  Anything it cannot
        # resolve stays fail-open at the signature's severity.
        return _classify_js_child_process(
            finding, content, child_process_usage=child_process_usage, js_context=js_context
        )
    # The remaining broad filesystem and network candidates require
    # scope-correct AST/data-flow evidence before they can be suppressed or
    # demoted safely.  Keep them fail-open even when this helper is called
    # directly; the scanner currently invokes this module only for the two
    # closed concealment grammars above and the child_process grammar.
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
        if decision.network_direction is not None:
            finding.title = "Declared read-only network access"
            finding.description = (
                "The package performs a provider-bound read-only network request declared by its instructions. "
                "No outbound payload or sensitive source-to-sink flow was identified."
            )
            finding.remediation = (
                "Keep the destination declaration and review changes that add request bodies or new providers."
            )
    if decision.title_override is not None:
        finding.title = decision.title_override
    if decision.description_override is not None:
        finding.description = decision.description_override
    if decision.remediation_override is not None:
        finding.remediation = decision.remediation_override
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
    # The child_process usage scan is file-scoped and the same file can carry
    # many findings; compute its content and usage once per file and reuse
    # them instead of rescanning the file for every finding on it.
    content_by_path: dict[str, str] = {}
    child_process_usage_by_path: dict[str, tuple[list[tuple[str, list[str], str, int]], bool]] = {}
    js_context_by_path: dict[str, _JsFileContext] = {}
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
            cached_content = content_by_path.get(path)
            if cached_content is None:
                cached_content = skill_file.read_content()
                content_by_path[path] = cached_content
            content = cached_content
            hidden = skill_file.is_hidden
        else:
            # A recursively loaded alias can lack an inventory entry.  Its
            # candidate cannot be proven inert, so preserve it.
            refined.append(finding)
            continue
        child_process_usage = None
        js_context = None
        if finding.rule_id == "COMMAND_INJECTION_JS_CHILD_PROCESS":
            child_process_usage = child_process_usage_by_path.get(path)
            if child_process_usage is None:
                child_process_usage = _js_child_process_usage(content)
                child_process_usage_by_path[path] = child_process_usage
            js_context = js_context_by_path.get(path)
            if js_context is None:
                js_context = _js_file_context(content)
                js_context_by_path[path] = js_context
        decision = classify_core_signature_candidate(
            finding,
            content,
            skill=skill,
            unreferenced=path in unreferenced,
            hidden=hidden,
            child_process_usage=child_process_usage,
            js_context=js_context,
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
