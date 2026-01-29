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

"""Command execution utilities for Skill Scanner."""

import os
import shlex
import shutil
from typing import Any

try:
    from expandvars import expand as _expand_custom
    from expandvars import expandvars as _expandvars_lib

    _HAS_EXPANDVARS = True
except Exception:
    _expandvars_lib = _expand_custom = None
    _HAS_EXPANDVARS = False


def build_env_for_expansion(server_env: dict[str, Any] | None) -> dict[str, str]:
    """Merge OS and server envs, coercing all values to str."""
    merged = {**os.environ, **(server_env or {})}
    return {k: str(v) for k, v in merged.items()}


def decide_windows_semantics(expand_mode: str) -> bool:
    """Decide whether to use Windows quoting rules for argument splitting."""
    mode = (expand_mode or "auto").lower()
    if mode == "windows":
        return True
    if mode in ("linux", "mac"):
        return False
    if mode == "off":
        return os.name == "nt"
    return os.name == "nt"


def expand_text(text: str, env: dict[str, str], expand_mode: str) -> str:
    """
    Expand '~' and environment variables according to mode.

    Modes:
        off      → only expand '~'.
        linux/mac→ use $VAR and ${VAR}.
        windows  → use %VAR%.
        auto     → pick linux/mac on POSIX; windows on Windows.
    """
    if not text:
        return ""

    text = os.path.expanduser(text)
    mode = (expand_mode or "auto").lower()

    if mode == "off":
        return text.strip()

    if mode == "auto":
        mode = "windows" if os.name == "nt" else "linux"

    try:
        if mode in ("linux", "mac"):
            if _HAS_EXPANDVARS and _expandvars_lib:
                old_environ = dict(os.environ)
                try:
                    os.environ.update(env)
                    return _expandvars_lib(text).strip()
                finally:
                    os.environ.clear()
                    os.environ.update(old_environ)
            return os.path.expandvars(text).strip()

        if mode == "windows":
            if _HAS_EXPANDVARS and _expand_custom:
                return _expand_custom(
                    text,
                    environ=env,
                    var_symbol="%",
                    surrounded_vars_only=True,
                    escape_char="",
                ).strip()
            return text.strip()
    except Exception:
        return os.path.expandvars(text).strip()

    return text.strip()


def normalize_and_expand_command_args(
    command: str, args: list[str], env: dict[str, str], expand_mode: str
) -> tuple[str, list[str]]:
    """Expand variables in command and its args."""
    expanded_command = expand_text(command or "", env, expand_mode)
    expanded_args = [expand_text(a, env, expand_mode) for a in (args or [])]
    return expanded_command, expanded_args


def split_embedded_args(
    expanded_command: str, current_args: list[str], windows_semantics: bool
) -> tuple[str, list[str]]:
    """Split command string into command + args if needed."""
    if not current_args and (" " in expanded_command or "\t" in expanded_command):
        parts = shlex.split(expanded_command, posix=not windows_semantics)
        if parts:
            return parts[0], parts[1:]
    return expanded_command, current_args


def resolve_executable_path(cmd_command: str) -> str | None:
    """Resolve executable path (quoted or relative)."""
    candidate = (cmd_command or "").strip().strip('"').strip("'")
    if not candidate:
        return None
    if os.path.isabs(candidate) or os.path.sep in candidate:
        return candidate if os.path.exists(candidate) else shutil.which(candidate)
    return shutil.which(candidate)
