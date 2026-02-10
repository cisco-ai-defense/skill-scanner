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
Context-aware command safety evaluation.

Replaces the flat SAFE_COMMANDS whitelist with a tiered evaluation system
that considers:
  - Command identity (what program is being run)
  - Arguments (what flags and targets)
  - Pipeline context (chained commands, redirections)
  - Environment (variable manipulation, subshells)
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple


class CommandRisk(Enum):
    """Risk classification for commands."""

    SAFE = "safe"  # Purely informational, no side effects
    CAUTION = "caution"  # Generally safe but context-dependent
    RISKY = "risky"  # Can modify system or exfiltrate data
    DANGEROUS = "dangerous"  # Direct system modification or remote execution


class CommandVerdict(NamedTuple):
    """Result of evaluating a command's safety."""

    risk: CommandRisk
    reason: str
    should_suppress_yara: bool  # Whether to suppress YARA code_execution findings


# --------------------------------------------------------------------------- #
# Command classification tables
# --------------------------------------------------------------------------- #

# Tier 1: Safe commands - read-only, informational, no side effects
_SAFE_COMMANDS = frozenset(
    {
        # Text/file inspection
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "wc",
        "file",
        "stat",
        "ls",
        "dir",
        "tree",
        # Search
        "grep",
        "rg",
        "ag",
        "ack",
        "find",
        "fd",
        "locate",
        "which",
        "where",
        "whereis",
        "type",
        # Text processing (read-only)
        "sort",
        "uniq",
        "cut",
        "tr",
        "fold",
        "column",
        "paste",
        "join",
        "diff",
        "comm",
        "fmt",
        "nl",
        "expand",
        "unexpand",
        # Info
        "echo",
        "printf",
        "true",
        "false",
        "date",
        "cal",
        "uname",
        "hostname",
        "whoami",
        "id",
        "groups",
        "env",
        "printenv",
        "pwd",
        "basename",
        "dirname",
        "realpath",
        "readlink",
        # Hashing / checksums
        "sha256sum",
        "sha512sum",
        "md5sum",
        "shasum",
        "cksum",
        "b2sum",
        # Programming tools (read-only / check modes)
        "python",
        "python3",
        "node",
        "ruby",
        # Version checks
        "git",
        "npm",
        "pip",
        "pip3",
        "uv",
        "cargo",
        "go",
        "java",
        "javac",
    }
)

# Tier 2: Caution commands - generally safe but can be misused with certain args
_CAUTION_COMMANDS = frozenset(
    {
        # File manipulation
        "cp",
        "mv",
        "ln",
        "mkdir",
        "rmdir",
        "touch",
        # Permissions
        "chmod",
        "chown",
        "chgrp",
        # Editors (usually safe in non-interactive)
        "sed",
        "awk",
        "gawk",
        "perl",
        # Build tools
        "make",
        "cmake",
        "gradle",
        "mvn",
        "dotnet",
        "rustc",
        # Package managers (can install things)
        "apt",
        "apt-get",
        "brew",
        "yum",
        "dnf",
        "pacman",
        "apk",
        "yarn",
        "pnpm",
    }
)

# Tier 3: Risky commands - can modify system or exfiltrate data
_RISKY_COMMANDS = frozenset(
    {
        "rm",
        "dd",
        "mkfs",
        "mount",
        "umount",
        "fdisk",
        "iptables",
        "nft",
        "ufw",
        "systemctl",
        "service",
        "launchctl",
        "crontab",
        "at",
        "ssh",
        "scp",
        "rsync",
        "sftp",
        "docker",
        "podman",
        "kubectl",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "telnet",
        "nmap",
    }
)

# Tier 4: Dangerous commands - direct code execution, network exfiltration
_DANGEROUS_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "eval",
        "exec",
        "source",
        "bash",
        "sh",
        "zsh",
        "dash",
        "fish",
        "csh",
        "tcsh",
        "ksh",
        "sudo",
        "su",
        "doas",
        "base64",  # When combined with pipe, likely obfuscation
        "openssl",  # Can encrypt/exfil data
        "gpg",
    }
)

# Dangerous argument patterns (command-independent)
_DANGEROUS_ARG_PATTERNS = [
    re.compile(r"-o\s+/dev/tcp/"),  # bash /dev/tcp redirect
    re.compile(r">(>)?\s*/etc/"),  # Write to system config
    re.compile(r">\s*/dev/null\s*2>&1\s*&"),  # Background + suppress output
    # Command substitution is only high-risk when invoking dangerous programs.
    re.compile(r"\$\((?:curl|wget|bash|sh|python|perl|ruby|node|nc|ncat|netcat)[^)]*\)"),
    re.compile(r"`(?:curl|wget|bash|sh|python|perl|ruby|node|nc|ncat|netcat)[^`]*`"),
    re.compile(r"\|\s*(bash|sh|eval|exec|python)"),  # Pipe to shell
    re.compile(r"--exec"),  # find --exec or similar
    re.compile(r"&&\s*(rm|dd|curl|wget|bash|sh)"),  # Chain with dangerous
]


@dataclass
class CommandContext:
    """Parsed command context for evaluation."""

    raw_command: str
    base_command: str
    arguments: list[str] = field(default_factory=list)
    has_pipeline: bool = False
    has_redirect: bool = False
    has_subshell: bool = False
    has_background: bool = False
    chained_commands: list[str] = field(default_factory=list)


def parse_command(raw: str) -> CommandContext:
    """Parse a command string into structured context."""
    raw = raw.strip()
    ctx = CommandContext(raw_command=raw, base_command="")

    if not raw:
        return ctx

    # Detect pipelines, redirects, subshells
    ctx.has_pipeline = "|" in raw and "||" not in raw.replace("||", "")
    ctx.has_redirect = bool(re.search(r"[12]?>", raw))
    ctx.has_subshell = "$(" in raw or "`" in raw.replace("``", "")
    ctx.has_background = raw.rstrip().endswith("&") and not raw.rstrip().endswith("&&")

    # Split chained commands (&&, ||, ;)
    parts = re.split(r"\s*(?:&&|\|\||;)\s*", raw)
    ctx.chained_commands = [p.strip() for p in parts if p.strip()]

    # Get first base command
    first_part = ctx.chained_commands[0] if ctx.chained_commands else raw
    # Handle env vars, sudo prefix
    tokens = first_part.split()
    for i, tok in enumerate(tokens):
        if "=" in tok and i == 0:
            continue  # env var assignment
        if tok in ("sudo", "su", "doas", "env", "nohup", "nice", "time", "timeout"):
            continue  # prefix commands
        ctx.base_command = tok.split("/")[-1]  # Strip path prefix
        ctx.arguments = tokens[i + 1 :]
        break

    if not ctx.base_command and tokens:
        ctx.base_command = tokens[0].split("/")[-1]

    return ctx


def evaluate_command(raw_command: str, *, policy=None) -> CommandVerdict:
    """
    Evaluate a command string for safety.

    Args:
        raw_command: The full command string to evaluate
        policy: Optional ``ScanPolicy``.  When provided, the command-safety
            tier sets come from ``policy.command_safety`` (if non-empty),
            allowing organisations to customise which commands are in each tier.

    Returns:
        CommandVerdict with risk level, reason, and whether to suppress YARA findings
    """
    # Resolve effective command sets (policy overrides → hardcoded defaults)
    safe_cmds = _SAFE_COMMANDS
    caution_cmds = _CAUTION_COMMANDS
    risky_cmds = _RISKY_COMMANDS
    dangerous_cmds = _DANGEROUS_COMMANDS
    if policy is not None and hasattr(policy, "command_safety"):
        cs = policy.command_safety
        if cs.safe_commands:
            safe_cmds = cs.safe_commands
        if cs.caution_commands:
            caution_cmds = cs.caution_commands
        if cs.risky_commands:
            risky_cmds = cs.risky_commands
        if cs.dangerous_commands:
            dangerous_cmds = cs.dangerous_commands

    ctx = parse_command(raw_command)

    if not ctx.base_command:
        return CommandVerdict(CommandRisk.SAFE, "Empty command", True)

    base = ctx.base_command.lower()

    # Check for dangerous argument patterns (overrides all)
    for pattern in _DANGEROUS_ARG_PATTERNS:
        if pattern.search(ctx.raw_command):
            return CommandVerdict(
                CommandRisk.DANGEROUS,
                f"Dangerous argument pattern detected: {pattern.pattern}",
                False,
            )

    # Classify base command
    # Check safe first, then caution, then risky, then dangerous
    # But dangerous overrides all if matched
    if base in dangerous_cmds:
        # Some dangerous commands have safe modes
        if base in ("curl", "wget"):
            # curl/wget just downloading to stdout for display is less risky
            args_str = " ".join(ctx.arguments)
            if not ctx.has_pipeline and not ctx.has_redirect:
                return CommandVerdict(
                    CommandRisk.RISKY,
                    f"Network command '{base}' used without pipe/redirect (likely display only)",
                    False,
                )
            else:
                return CommandVerdict(
                    CommandRisk.DANGEROUS,
                    f"Network command '{base}' with pipe or redirect - possible exfiltration/injection",
                    False,
                )
        if base == "base64":
            if not ctx.has_pipeline:
                return CommandVerdict(CommandRisk.CAUTION, "base64 without pipeline", True)
            return CommandVerdict(
                CommandRisk.DANGEROUS,
                "base64 in pipeline - likely obfuscation",
                False,
            )
        if base in ("bash", "sh", "zsh", "dash", "fish"):
            # Check if it's just running a script file
            if ctx.arguments and not ctx.has_pipeline and ctx.arguments[0].endswith((".sh", ".bash")):
                return CommandVerdict(
                    CommandRisk.CAUTION,
                    f"Shell executing script file: {ctx.arguments[0]}",
                    True,
                )
            return CommandVerdict(
                CommandRisk.DANGEROUS,
                f"Shell invocation '{base}' may execute arbitrary code",
                False,
            )
        return CommandVerdict(
            CommandRisk.DANGEROUS,
            f"Dangerous command: '{base}'",
            False,
        )

    if base in risky_cmds:
        return CommandVerdict(
            CommandRisk.RISKY,
            f"Risky command: '{base}'",
            False,
        )

    if base in safe_cmds:
        # Even safe commands can be risky in pipelines with dangerous downstream
        if ctx.has_pipeline:
            # Check what's downstream
            for chained in ctx.chained_commands[1:]:
                chained_base = chained.split()[0].split("/")[-1] if chained.split() else ""
                if chained_base in dangerous_cmds:
                    return CommandVerdict(
                        CommandRisk.DANGEROUS,
                        f"Safe command '{base}' piped to dangerous '{chained_base}'",
                        False,
                    )
        # Version/help check modes
        args_str = " ".join(ctx.arguments).lower()
        if "--version" in args_str or "--help" in args_str or "-v" == args_str or "-h" == args_str:
            return CommandVerdict(CommandRisk.SAFE, f"Version/help check for '{base}'", True)

        return CommandVerdict(
            CommandRisk.SAFE,
            f"Safe command: '{base}'",
            True,
        )

    if base in caution_cmds:
        # Check if caution commands have risky args
        if ctx.has_pipeline or ctx.has_subshell:
            return CommandVerdict(
                CommandRisk.RISKY,
                f"Caution command '{base}' with pipeline/subshell",
                False,
            )
        return CommandVerdict(
            CommandRisk.CAUTION,
            f"Generally safe command: '{base}'",
            True,
        )

    # Unknown command - treat with caution
    if ctx.has_pipeline or ctx.has_subshell or ctx.has_redirect:
        return CommandVerdict(
            CommandRisk.RISKY,
            f"Unknown command '{base}' with shell operators",
            False,
        )

    return CommandVerdict(
        CommandRisk.CAUTION,
        f"Unknown command: '{base}'",
        False,
    )
