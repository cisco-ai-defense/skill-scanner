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

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple

logger = logging.getLogger(__name__)
_MAX_PATTERN_LENGTH = 1000


def _safe_compile(pattern: str, flags: int = 0, *, max_length: int = _MAX_PATTERN_LENGTH) -> re.Pattern | None:
    if len(pattern) > max_length:
        logger.warning("Regex pattern too long (%d chars), skipping: %.60s...", len(pattern), pattern)
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        logger.warning("Invalid regex pattern %r: %s", pattern, e)
        return None


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
        # Programming tools (kept in SAFE – dangerous invocations caught by arg patterns)
        "python",
        "python3",
        "node",
        "ruby",
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
        # GTFOBins-capable: safe in common use but can spawn shells / execute code
        "find",  # -exec, -execdir can run arbitrary commands
        "less",  # !command shell escape
        "more",  # !command shell escape
        "git",  # arbitrary code via hooks, subcommands
        "npm",  # run/exec can execute arbitrary code
        "pip",  # install can run setup.py
        "pip3",  # install can run setup.py
        "uv",  # run can execute arbitrary code
        "cargo",  # run/build can execute build scripts
        "go",  # run/generate can execute arbitrary code
        "java",  # executes bytecode
        "javac",  # compiler, can trigger annotation processors
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
    re.compile(r"\|\s*(bash|sh|eval|exec|python|curl|wget|nc|ncat|netcat|socat)"),  # Pipe to shell/network
    re.compile(r"-{1,2}exec\b"),  # find -exec / --exec or similar
    re.compile(r"&&\s*(rm|dd|curl|wget|bash|sh)"),  # Chain with dangerous
    # --- GTFOBins-style abuse patterns ---
    # Python/python3 with -c (inline code execution)
    re.compile(r"\bpython[23]?\s+.*-c\s"),
    # Node with -e/--eval (inline JS execution)
    re.compile(r"\bnode\s+.*(?:-e|--eval)\s"),
    # Ruby with -e (inline code execution)
    re.compile(r"\bruby\s+.*-e\s"),
    # env used to spawn a shell
    re.compile(r"\benv\s+.*(?:/bin/(?:ba)?sh|/bin/(?:z|da|fi)sh)"),
    # find with -exec/-execdir (arbitrary command execution)
    re.compile(r"\bfind\s+.*-exec(?:dir)?\s"),
    # less/more/man with shell escape (!)
    re.compile(r"\b(?:less|more|man)\s+.*!\s*/bin/"),
    # pip/pip3 install from untrusted index (supply-chain attack)
    re.compile(r"\bpip[3]?\s+install\s+(?:--index-url|--extra-index-url|-i)\s"),
    # git clone/remote chained with shell operators
    re.compile(r"\bgit\s+(?:clone|remote\s+add)\s+.*[;&|]"),
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
    pipe_targets: list[str] = field(default_factory=list)


def parse_command(raw: str) -> CommandContext:
    """Parse a command string into structured context."""
    raw = raw.strip()
    ctx = CommandContext(raw_command=raw, base_command="")

    if not raw:
        return ctx

    # Detect pipelines, redirects, subshells
    # Match a single pipe token and exclude logical OR (||).
    ctx.has_pipeline = bool(re.search(r"(?<!\|)\|(?!\|)", raw))
    ctx.has_redirect = bool(re.search(r"[12]?>", raw))
    ctx.has_subshell = "$(" in raw or "`" in raw.replace("``", "")
    ctx.has_background = raw.rstrip().endswith("&") and not raw.rstrip().endswith("&&")

    # Split chained commands (&&, ||, ;)
    parts = re.split(r"\s*(?:&&|\|\||;)\s*", raw)
    ctx.chained_commands = [p.strip() for p in parts if p.strip()]

    # Split the first chain segment on pipes to find downstream pipe targets.
    # This is critical: ``cat file | curl ...`` must surface ``curl`` as a
    # pipe target so that downstream-danger checks work correctly.
    if ctx.has_pipeline and ctx.chained_commands:
        pipe_parts = re.split(r"\s*\|\s*", ctx.chained_commands[0])
        ctx.pipe_targets = [p.strip() for p in pipe_parts[1:] if p.strip()]

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

    if policy is not None and hasattr(policy, "command_safety"):
        max_pat_len = getattr(
            getattr(policy, "analysis_thresholds", None),
            "max_regex_pattern_length",
            _MAX_PATTERN_LENGTH,
        )
        for pat_str in getattr(policy.command_safety, "dangerous_arg_patterns", []):
            try:
                compiled = _safe_compile(pat_str, max_length=max_pat_len)
                if compiled and compiled.search(ctx.raw_command):
                    return CommandVerdict(
                        CommandRisk.DANGEROUS,
                        f"Policy dangerous arg pattern matched: {pat_str}",
                        False,
                    )
            except Exception:
                logger.warning("Failed to apply pattern %r", pat_str)

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
            # Check pipe targets (split on |) and chained commands (split on &&/||/;)
            downstream_segments = list(ctx.pipe_targets) + list(ctx.chained_commands[1:])
            for segment in downstream_segments:
                seg_base = segment.split()[0].split("/")[-1] if segment.split() else ""
                if seg_base in dangerous_cmds or seg_base in risky_cmds:
                    return CommandVerdict(
                        CommandRisk.DANGEROUS,
                        f"Safe command '{base}' piped to dangerous '{seg_base}'",
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

        # Safe sub-modes for GTFOBins-capable commands that were promoted from SAFE.
        # These common read-only invocations are demoted back to SAFE.
        if base == "find" and not any(a in ("-exec", "-execdir", "-ok", "-delete") for a in ctx.arguments):
            return CommandVerdict(CommandRisk.SAFE, "find without exec/delete", True)

        if base == "git":
            _SAFE_GIT_SUBCMDS = frozenset(
                {
                    "status",
                    "log",
                    "diff",
                    "branch",
                    "show",
                    "tag",
                    "describe",
                    "rev-parse",
                    "ls-files",
                    "remote",
                    "fetch",
                    "config",
                }
            )
            if ctx.arguments and ctx.arguments[0] in _SAFE_GIT_SUBCMDS:
                return CommandVerdict(
                    CommandRisk.SAFE,
                    f"git {ctx.arguments[0]} is read-only",
                    True,
                )

        if base in ("less", "more") and not ctx.has_pipeline:
            return CommandVerdict(CommandRisk.SAFE, f"'{base}' viewing file", True)

        if base in ("npm", "pip", "pip3", "uv", "cargo", "go"):
            _SAFE_PKG_SUBCMDS = frozenset(
                {
                    "list",
                    "show",
                    "info",
                    "search",
                    "outdated",
                    "version",
                    "help",
                    "config",
                    "view",
                    "freeze",
                }
            )
            if ctx.arguments and ctx.arguments[0] in _SAFE_PKG_SUBCMDS:
                return CommandVerdict(
                    CommandRisk.SAFE,
                    f"{base} {ctx.arguments[0]} is read-only",
                    True,
                )

        if base in ("java", "javac") and not ctx.has_pipeline:
            return CommandVerdict(
                CommandRisk.CAUTION,
                f"'{base}' compilation/execution",
                True,
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
