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
Data directory for Skill Scanner.

Contains prompts and rule files, matching MCP Scanner structure.
"""

from pathlib import Path

DATA_DIR = Path(__file__).parent
PROMPTS_DIR = DATA_DIR / "prompts"

# Canonical locations under the core pack (new layout)
_CORE_PACK = DATA_DIR / "packs" / "core"
YARA_RULES_DIR = _CORE_PACK / "yara"
SIGNATURES_DIR = _CORE_PACK / "signatures"

_PACKS_DIR = DATA_DIR / "packs"


def list_available_packs() -> list[str]:
    """Return names of available rule packs (excluding ``core``).

    Only directories that contain a ``signatures/`` sub-directory or a
    ``pack.yaml`` manifest are considered valid packs.
    """
    if not _PACKS_DIR.is_dir():
        return []
    packs: list[str] = []
    for entry in sorted(_PACKS_DIR.iterdir()):
        if not entry.is_dir() or entry.name == "core":
            continue
        if (entry / "signatures").is_dir() or (entry / "pack.yaml").is_file():
            packs.append(entry.name)
    return packs


def resolve_rule_packs(names: list[str]) -> list[Path]:
    """Map pack names to their ``signatures/`` directories.

    Args:
        names: Pack names (e.g. ``["atr"]``).

    Returns:
        List of resolved ``signatures/`` directory paths.

    Raises:
        ValueError: If a requested pack does not exist or has no
            ``signatures/`` directory.
    """
    available = list_available_packs()
    dirs: list[Path] = []
    for name in names:
        if name not in available:
            raise ValueError(f"Unknown rule pack '{name}'. Available packs: {', '.join(available) or '(none)'}")
        sigs_dir = _PACKS_DIR / name / "signatures"
        if not sigs_dir.is_dir():
            raise ValueError(f"Rule pack '{name}' has no signatures/ directory")
        dirs.append(sigs_dir)
    return dirs


__all__ = [
    "DATA_DIR",
    "PROMPTS_DIR",
    "YARA_RULES_DIR",
    "SIGNATURES_DIR",
    "list_available_packs",
    "resolve_rule_packs",
]
