# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
Bash script taint tracker for behavioral analysis.

Performs lightweight dataflow analysis on bash scripts to detect
multi-line data flows from sensitive sources to dangerous sinks.

Tracks:
- Variable assignments from tainted sources (command substitution, env, file reads)
- Taint propagation through variable usage
- Taint sinks (curl, wget, nc, eval, exec, source)
- Pipe chains with credential data
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class BashTaintType(Enum):
    """Types of taint that can flow through bash variables."""

    CREDENTIAL = auto()  # Credential / secret file data
    SENSITIVE_FILE = auto()  # General sensitive file read
    ENV_VAR = auto()  # Environment variable (may contain secrets)
    NETWORK_INPUT = auto()  # Data from curl/wget
    USER_INPUT = auto()  # Data from read/stdin
    COMMAND_OUTPUT = auto()  # Output of arbitrary command


@dataclass
class TaintedVariable:
    """A variable that carries tainted data."""

    name: str
    taints: set[BashTaintType]
    source_line: int
    source_snippet: str


@dataclass
class BashTaintFlow:
    """A detected taint flow from source to sink."""

    source_var: str
    source_line: int
    source_snippet: str
    sink_command: str
    sink_line: int
    sink_snippet: str
    taints: set[BashTaintType]
    severity: str  # CRITICAL, HIGH, MEDIUM


@dataclass
class BashDownloadedExecutable:
    """A downloaded file subsequently made executable or invoked."""

    url: str
    destination: str
    download_line: int
    sink_line: int
    sink_snippet: str


class _DownloadExpansionLimit(ValueError):
    """The current command exhausted its shell-value expansion budget."""


@dataclass
class _DownloadExpansion:
    """Bound retained expansions across all arguments of one command."""

    variables: dict[str, str]
    remaining: int = 65536

    def value(self, token: str) -> str:
        """Resolve one value, stopping this command when its budget is spent."""
        if self.remaining <= 0:
            raise _DownloadExpansionLimit
        value = _download_value(token, self.variables)
        self.remaining -= len(value)
        if self.remaining < 0:
            raise _DownloadExpansionLimit
        return value


def _download_value(token: str, variables: dict[str, str]) -> str:
    """Resolve a simple shell value without reading the environment."""
    # Expansion is bounded because the input is untrusted shell source.
    limit = 4096
    if len(token) > limit:
        return ""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        if token[0] == "'":
            return token[1:-1]
        token = token[1:-1]
    parts: list[str] = []
    end = 0
    size = 0
    for match in _VAR_REF.finditer(token):
        literal = token[end : match.start()]
        value = variables.get(match[1], "${" + match[1] + "}")
        size += len(literal) + len(value)
        if size > limit:
            return ""
        parts.extend((literal, value))
        end = match.end()
    if size + len(token) - end > limit:
        return ""
    return "".join(parts) + token[end:]


def _download_target(command: list[str], expansion: _DownloadExpansion) -> tuple[str, str] | None:
    """Prefer explicit downloader output over a stdout redirection."""
    name = expansion.value(command[0]).rsplit("/", 1)[-1]
    if name not in {"curl", "wget", "fetch"}:
        return None
    short_option = "O" if name == "wget" else "o"
    long_option = "--output-document" if name == "wget" else "--output"
    explicit = None
    redirected = None
    url = None
    index = 1
    while index < len(command):
        token = command[index]
        if token == long_option:
            if index + 1 >= len(command):
                return None
            explicit = command[index + 1]
            index += 1
        elif token in {">", "1>"}:
            if index + 1 < len(command):
                redirected = command[index + 1]
                index += 1
        elif re.fullmatch(r"\d*(?:>>|>&|<|<&)|\d+>", token):
            # These operands are logs, descriptors or input, not payloads.
            index += 1
        elif token.startswith(long_option + "="):
            explicit = token.split("=", 1)[1]
        elif token.startswith("-") and not token.startswith("--") and short_option in token[1:]:
            suffix = token.split(short_option, 1)[1]
            if suffix:
                explicit = suffix
            elif index + 1 < len(command):
                explicit = command[index + 1]
                index += 1
            else:
                return None
        else:
            value = expansion.value(token)
            if value.startswith(("https://", "http://")):
                if url is not None:
                    return None
                url = value
        index += 1
    if url is None:
        return None
    destination = expansion.value(explicit) if explicit is not None else "-"
    if destination == "-" and redirected is not None:
        destination = expansion.value(redirected)
    if not destination or destination == "-":
        return None
    return url, posixpath.normpath(destination)


def _shell_script_operand(args: list[str]) -> list[str]:
    """Select a shell's script operand without mistaking option values for it."""
    index = 0
    while index < len(args):
        option = args[index].strip("\"'")
        if option == "--":
            return args[index + 1 : index + 2]
        if option == "-":
            return []
        if option in {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}:
            index += 2
            continue
        if option.startswith(("-", "+")):
            if not option.startswith("--"):
                flags = option[1:]
                if "c" in flags or "s" in flags:
                    return []
                if flags.endswith(("o", "O")):
                    index += 1
            index += 1
            continue
        return args[index : index + 1]
    return []


def _download_sink(command: list[str], expansion: _DownloadExpansion) -> list[str]:
    """Recognize explicit execute modes and supported invocation forms."""
    name = expansion.value(command[0]).rsplit("/", 1)[-1]
    args = command[1:]
    if name == "chmod":
        while args and args[0].startswith("-"):
            if args[0] == "-x":
                return []
            args = args[1:]
        if not args:
            return []
        mode = expansion.value(args[0])
        executable = bool(re.search(r"(?:^|,)[ugoa]*[+=][rwxXst]*x", mode))
        if re.fullmatch(r"[0-7]{3,4}", mode):
            executable = any(int(digit) & 1 for digit in mode[-3:])
        if not executable:
            return []
        targets = args[1:]
    elif name == "exec":
        if args[:1] == ["-a"]:
            args = args[2:]
        while args and args[0].startswith("-"):
            args = args[1:]
        targets = args[:1]
    elif name in {"bash", "sh", "zsh"}:
        targets = _shell_script_operand(args)
    elif name in {"source", "."}:
        if args and args[0].startswith("-"):
            return []
        targets = args[:1]
    else:
        raw_name = command[0].strip("\"'")
        if not raw_name.startswith(("/", "./", "../", "$", "~")):
            return []
        targets = command[:1]
    return [posixpath.normpath(value) for token in targets if (value := expansion.value(token))]


def _download_quote_state(line: str, quote: str) -> str:
    """Track multiline quotes without interpreting the quoted command text."""
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace() or line[index - 1] in ";&|<>"):
            break
        index += 1
    return quote


def _download_tokens(line: str) -> list[str]:
    """Keep numbered redirects distinct, retaining their source adjacency."""
    lexer = shlex.shlex(line, posix=False, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    tokens: list[str] = []
    end = 0
    for token in lexer:
        start = line.find(token, end)
        if start < 0:
            raise ValueError("Cannot locate shell token in source")
        if token in {">", ">>", ">&"} and tokens and tokens[-1].isascii() and tokens[-1].isdigit() and start == end:
            tokens[-1] += token
        else:
            tokens.append(token)
        end = start + len(token)
    return tokens


def _download_heredocs(tokens: list[str]) -> list[str]:
    """Recognize heredocs outside quoted words and arithmetic expansions."""
    heredocs: list[str] = []
    arithmetic_depth = 0
    for index, token in enumerate(tokens):
        if token.startswith(("'", '"')):
            continue
        if arithmetic_depth:
            arithmetic_depth = max(0, arithmetic_depth + token.count("(") - token.count(")"))
            continue
        if "$((" in token:
            arithmetic = token[token.index("$((") :]
            arithmetic_depth = max(0, arithmetic.count("(") - arithmetic.count(")"))
        elif token == "<<" and index + 1 < len(tokens):
            heredocs.append(tokens[index + 1].lstrip("-").strip("\"'"))
    return heredocs


def analyze_bash_downloads(content: str) -> list[BashDownloadedExecutable]:
    """Match simple shell download destinations with later execution intent.

    This is a line-based heuristic, not a shell interpreter or a control-flow
    proof. Variables retain unresolved placeholders; no environment is read.
    """
    variables: dict[str, str] = {}
    downloads: dict[str, tuple[str, int]] = {}
    reported: set[tuple[str, int]] = set()
    findings: list[BashDownloadedExecutable] = []
    pending: list[str] = []
    quote = ""
    start_line = 1
    heredocs: list[str] = []
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        if heredocs:
            if raw_line.lstrip("\t") == heredocs[0]:
                heredocs.pop(0)
            continue
        if not pending:
            start_line = line_number
        quote = _download_quote_state(raw_line, quote)
        if raw_line.endswith("\\") and quote != "'":
            pending.append(raw_line[:-1] + " ")
            continue
        pending.append(raw_line)
        if quote:
            pending.append("\n")
            continue
        line = "".join(pending)
        pending.clear()
        assignment = _VAR_ASSIGN_SIMPLE.fullmatch(line.strip())
        if assignment:
            try:
                values = shlex.split(assignment[2], comments=True, posix=False)
            except ValueError:
                continue
            if len(values) == 1:
                variables[assignment[1]] = _download_value(values[0], variables)
                continue
        try:
            tokens = _download_tokens(line)
        except ValueError:
            continue
        heredocs.extend(_download_heredocs(tokens))
        command: list[str] = []
        for token in [*tokens, ";"]:
            if token not in {";", "&&", "||", "|", "&"}:
                command.append(token)
                continue
            while command and command[0] in {"then", "do", "else", "command", "if", "elif", "while", "until", "!"}:
                command.pop(0)
            if not command:
                continue
            if len(command) == 1 and (assignment := _VAR_ASSIGN_SIMPLE.fullmatch(command[0])):
                variables[assignment[1]] = _download_value(assignment[2], variables)
            else:
                if command[0].strip("\"'") in {"cd", "pushd", "popd"}:
                    downloads = {path: download for path, download in downloads.items() if posixpath.isabs(path)}
                expansion = _DownloadExpansion(variables)
                try:
                    download = _download_target(command, expansion)
                    targets = _download_sink(command, expansion)
                except _DownloadExpansionLimit:
                    command = []
                    continue
                if download:
                    url, destination = download
                    downloads[destination] = (url, start_line)
                for destination in targets:
                    if destination not in downloads:
                        continue
                    url, download_line = downloads[destination]
                    identity = (destination, download_line)
                    if identity in reported:
                        continue
                    findings.append(BashDownloadedExecutable(url, destination, download_line, start_line, line.strip()))
                    reported.add(identity)
            command = []
    return findings


# Patterns that introduce taint via command substitution
_CREDENTIAL_FILE_PATTERNS = [
    re.compile(
        r"(?:cat|head|tail|less|more)\s+[^\s]*(?:\.env|\.pem|\.key|\.crt|credentials|\.ssh|\.aws|\.gnupg|\.netrc|secret|token|password)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:cat|head|tail|less|more)\s+[^\s]*/etc/(?:passwd|shadow|hosts)"),
]

_SENSITIVE_FILE_PATTERNS = [
    re.compile(r"(?:cat|head|tail|less|more)\s+"),
]

_ENV_PATTERNS = [
    re.compile(
        r"\$\{?(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS?|AUTH|AWS_SECRET|PRIVATE_KEY|DB_PASS)", re.IGNORECASE
    ),
    re.compile(r"printenv\s"),
]

_NETWORK_SOURCE_PATTERNS = [
    re.compile(r"(?:curl|wget)\s"),
]

# Sink patterns — commands that consume tainted data dangerously
_NETWORK_SINK_PATTERN = re.compile(r"(?:curl|wget|nc|ncat|netcat)\b")
_EXEC_SINK_PATTERN = re.compile(r"(?:eval|exec|bash|sh|zsh|source|python3?|node|ruby|perl)\b")

# Variable assignment patterns
_VAR_ASSIGN_CMD_SUB = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\((.*)\)\s*$")
_VAR_ASSIGN_BACKTICK = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=`(.*)`\s*$")
_VAR_ASSIGN_SIMPLE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)$")

# Variable reference pattern
_VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def analyze_bash_script(content: str, file_path: str) -> list[BashTaintFlow]:
    """Analyze a bash script for taint flows from sensitive sources to sinks.

    Args:
        content: The bash script content.
        file_path: Path to the file (for reporting).

    Returns:
        List of detected taint flows.
    """
    flows: list[BashTaintFlow] = []
    tainted_vars: dict[str, TaintedVariable] = {}

    lines = content.split("\n")

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # --- Phase 1: Track variable assignments that introduce taint ---
        _track_variable_assignment(line, line_num, tainted_vars)

        # --- Phase 2: Check for tainted data reaching sinks ---
        _check_sinks(line, line_num, tainted_vars, flows)

    return flows


def _classify_command_taint(command: str) -> set[BashTaintType]:
    """Determine what taint types a command introduces."""
    taints: set[BashTaintType] = set()

    for pat in _CREDENTIAL_FILE_PATTERNS:
        if pat.search(command):
            taints.add(BashTaintType.CREDENTIAL)
            return taints  # Credential is the strongest, return early

    for pat in _ENV_PATTERNS:
        if pat.search(command):
            taints.add(BashTaintType.ENV_VAR)

    for pat in _NETWORK_SOURCE_PATTERNS:
        if pat.search(command):
            taints.add(BashTaintType.NETWORK_INPUT)

    for pat in _SENSITIVE_FILE_PATTERNS:
        if pat.search(command):
            taints.add(BashTaintType.SENSITIVE_FILE)

    if not taints:
        taints.add(BashTaintType.COMMAND_OUTPUT)

    return taints


def _track_variable_assignment(
    line: str,
    line_num: int,
    tainted_vars: dict[str, TaintedVariable],
) -> None:
    """Check if a line is a variable assignment that introduces or propagates taint."""

    # Check command substitution: VAR=$(command)
    match = _VAR_ASSIGN_CMD_SUB.match(line) or _VAR_ASSIGN_BACKTICK.match(line)
    if match:
        var_name = match.group(1)
        command = match.group(2)
        taints = _classify_command_taint(command)

        # Also propagate taints from variables used in the command
        for ref_match in _VAR_REF.finditer(command):
            ref_name = ref_match.group(1)
            if ref_name in tainted_vars:
                taints.update(tainted_vars[ref_name].taints)

        tainted_vars[var_name] = TaintedVariable(
            name=var_name,
            taints=taints,
            source_line=line_num,
            source_snippet=line,
        )
        return

    # Check simple assignment: VAR=value (check if RHS uses tainted vars)
    match = _VAR_ASSIGN_SIMPLE.match(line)
    if match:
        var_name = match.group(1)
        rhs = match.group(2)

        propagated_taints: set[BashTaintType] = set()
        for ref_match in _VAR_REF.finditer(rhs):
            ref_name = ref_match.group(1)
            if ref_name in tainted_vars:
                propagated_taints.update(tainted_vars[ref_name].taints)

        # Check if RHS directly references sensitive env vars
        for pat in _ENV_PATTERNS:
            if pat.search(rhs):
                propagated_taints.add(BashTaintType.ENV_VAR)

        if propagated_taints:
            tainted_vars[var_name] = TaintedVariable(
                name=var_name,
                taints=propagated_taints,
                source_line=line_num,
                source_snippet=line,
            )


def _check_sinks(
    line: str,
    line_num: int,
    tainted_vars: dict[str, TaintedVariable],
    flows: list[BashTaintFlow],
) -> None:
    """Check if a line sends tainted data to a dangerous sink."""

    # Find all variable references in this line
    referenced_tainted: list[TaintedVariable] = []
    for ref_match in _VAR_REF.finditer(line):
        ref_name = ref_match.group(1)
        if ref_name in tainted_vars:
            referenced_tainted.append(tainted_vars[ref_name])

    if not referenced_tainted:
        return

    # Check if the line is a network sink
    is_network_sink = bool(_NETWORK_SINK_PATTERN.search(line))
    is_exec_sink = bool(_EXEC_SINK_PATTERN.search(line))

    if not is_network_sink and not is_exec_sink:
        return

    for tainted_var in referenced_tainted:
        combined_taints = tainted_var.taints

        # Determine severity
        if BashTaintType.CREDENTIAL in combined_taints and is_network_sink:
            severity = "CRITICAL"
        elif BashTaintType.SENSITIVE_FILE in combined_taints and is_network_sink:
            severity = "CRITICAL"
        elif BashTaintType.ENV_VAR in combined_taints and is_network_sink:
            severity = "HIGH"
        elif BashTaintType.NETWORK_INPUT in combined_taints and is_exec_sink:
            severity = "HIGH"
        elif is_network_sink:
            severity = "MEDIUM"
        elif is_exec_sink:
            severity = "MEDIUM"
        else:
            severity = "MEDIUM"

        sink_cmd = ""
        if is_network_sink:
            m = _NETWORK_SINK_PATTERN.search(line)
            if m:
                sink_cmd = m.group(0)
        elif is_exec_sink:
            m = _EXEC_SINK_PATTERN.search(line)
            if m:
                sink_cmd = m.group(0)

        flows.append(
            BashTaintFlow(
                source_var=tainted_var.name,
                source_line=tainted_var.source_line,
                source_snippet=tainted_var.source_snippet,
                sink_command=sink_cmd,
                sink_line=line_num,
                sink_snippet=line,
                taints=combined_taints,
                severity=severity,
            )
        )
