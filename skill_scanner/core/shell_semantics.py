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


"""Shell semantics shared by the analyzers that reason about piped commands."""

from __future__ import annotations

import re
from collections.abc import Sequence

_STDIN_OPERANDS = frozenset({"-", "/dev/stdin", "/dev/fd/0"})
# Options after which stdin is not the program: an inline program or a module. Per
# interpreter, because the letters differ -- for a shell ``-e`` is errexit, not eval.
_SHELL_INTERPRETERS = frozenset({"bash", "sh", "zsh"})
_INLINE_PROGRAM_OPTIONS: dict[str, frozenset[str]] = {
    "bash": frozenset({"-c"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
    "python": frozenset({"-c", "-m"}),
    "python3": frozenset({"-c", "-m"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
}
# Options that consume the next argument, so it is not mistaken for a script operand.
_INTERPRETER_VALUE_OPTIONS = frozenset({"-o", "+o", "-O", "+O", "-W", "-X", "-r", "--require", "--input-type"})
_SHELL_CONTROL = frozenset({"&&", "||", ";", ";;", "&", "|", "|&"})
_SHELL_WORD_CHARACTER_RE = re.compile(r"[A-Za-z0-9$_./~'\"-]")
# A redirection is not an operand: ``curl URL | sh 2>/dev/null`` still runs what was fetched.
_REDIRECTION_RE = re.compile(r"^(?:\d*[<>]{1,2}&?|&>{1,2})(?P<target>.*)$")
# An inline program that itself executes what it reads runs stdin just the same:
# ``python -c 'exec(sys.stdin.read())'``, ``node -e 'eval(...)'``, ``bash -c "$(cat)"``.
_INLINE_EXECUTES_RE = re.compile(
    r"\b(?:exec|eval)\s*\(|\bFunction\s*\(|\bvm\.run|\$\(\s*cat\b|\bsource\s+/dev/stdin|^\s*eval\b|[;&|]\s*eval\b"
)


def interpreter_reads_stdin_program(executable: str, arguments: Sequence[str]) -> bool:
    """Whether a piped interpreter runs its standard input as a program.

    ``curl URL | bash`` and ``| python -`` execute what was fetched. ``| python -m
    json.tool``, ``| python script.py`` and ``| node -e '...'`` do not: the program comes
    from a module, a file or the command line, and stdin is only the data it reads. On a
    labelled benchmark 18 of 31 benign network-to-execution flags were ``curl ... |
    python -m json.tool``.
    """

    inline = _INLINE_PROGRAM_OPTIONS.get(executable)
    if inline is None:
        return True
    arguments = list(arguments)
    index = 0
    options_done = False
    while index < len(arguments):
        argument = arguments[index]
        # Text extracted from Markdown can run past the command: ``| sh && tool login``,
        # ``| bash  # recommended``, ``| sh → blocked``. The command ends there, and
        # nothing before it named a program, so stdin is the program.
        if _ends_command(argument):
            return True
        redirection = _REDIRECTION_RE.match(argument)
        if redirection is not None:
            index += 1 if redirection.group("target") else 2
            continue
        if not options_done:
            if argument == "-s" and executable in _SHELL_INTERPRETERS:
                return True  # the program is stdin; the operands are its arguments
            # Exact, or attached to its value (python -mjson.tool, bash -xc 'cmd').
            if argument in inline or (
                argument.startswith("-")
                and not argument.startswith("--")
                and any(option[1] in argument[1:] for option in inline if len(option) == 2)
            ):
                program = arguments[index + 1] if argument in inline and index + 1 < len(arguments) else ""
                return bool(program) and _INLINE_EXECUTES_RE.search(program) is not None
            if argument in _INTERPRETER_VALUE_OPTIONS:
                index += 2
                continue
            if argument == "--":
                options_done = True
                index += 1
                continue
            if argument.startswith(("-", "+")) and argument not in _STDIN_OPERANDS:
                index += 1
                continue
        return argument in _STDIN_OPERANDS
    return True


def _ends_command(token: str) -> bool:
    if token in _SHELL_CONTROL or token.startswith(("#", "(", ")")):
        return True
    # Prose punctuation such as an arrow or a dash carries no shell word at all.
    return _SHELL_WORD_CHARACTER_RE.search(token) is None
