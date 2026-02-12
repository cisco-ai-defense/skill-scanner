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

import re
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
