#!/usr/bin/env python3
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
Pre-commit hook: validate ThreatCategory enum against official Cisco taxonomy.

This script enforces two invariants:

1. **Enum guard** -- every member of the ``ThreatCategory`` enum in
   ``skill_scanner/core/models.py`` must be present in the ALLOWED_CATEGORIES
   set defined below.

2. **Usage guard** -- every ``ThreatCategory.<NAME>`` reference across all
   ``.py`` source files must use a name that exists in the enum (and therefore
   in the allowlist).

The allowlist is deliberately maintained *separately* from the enum so that
adding a new category requires a conscious update in two places: the enum and
this script.  This two-step gate prevents accidental or ad-hoc category
additions from slipping through.

Usage:
    python scripts/check_taxonomy.py          # check the whole repo
    python scripts/check_taxonomy.py FILE...  # check only listed files

Exit codes:
    0  all checks pass
    1  one or more violations found
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Official Cisco AI Security Framework -- allowed ThreatCategory values
#
# Source: skill_scanner/threats/cisco_ai_taxonomy.py  (AITech codes)
#         skill_scanner/threats/threats.py             (scanner mappings)
#
# To add a new category:
#   1. Verify the category maps to a real AITech code in the Cisco framework
#   2. Add the enum member to skill_scanner/core/models.py
#   3. Add the member name to ALLOWED_CATEGORIES below
#   4. Add the threat mapping in skill_scanner/threats/threats.py
# ---------------------------------------------------------------------------
ALLOWED_CATEGORIES: set[str] = {
    "PROMPT_INJECTION",
    "COMMAND_INJECTION",
    "DATA_EXFILTRATION",
    "UNAUTHORIZED_TOOL_USE",
    "OBFUSCATION",
    "HARDCODED_SECRETS",
    "SOCIAL_ENGINEERING",
    "RESOURCE_ABUSE",
    "POLICY_VIOLATION",
    "MALWARE",
    "HARMFUL_CONTENT",
    "SKILL_DISCOVERY_ABUSE",
    "TRANSITIVE_TRUST_ABUSE",
    "AUTONOMY_ABUSE",
    "TOOL_CHAINING_ABUSE",
    "UNICODE_STEGANOGRAPHY",
    "SUPPLY_CHAIN_ATTACK",
}

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------
MODELS_FILE = Path("skill_scanner/core/models.py")
SOURCE_DIR = Path("skill_scanner")
TESTS_DIR = Path("tests")

# Regex to extract enum member names from the ThreatCategory class body
_ENUM_MEMBER_RE = re.compile(r"^\s+([A-Z][A-Z0-9_]+)\s*=\s*\"", re.MULTILINE)

# Regex to find ThreatCategory.<NAME> usage in Python source
_USAGE_RE = re.compile(r"ThreatCategory\.([A-Z][A-Z0-9_]+)")


def _find_repo_root() -> Path:
    """Walk up from this script's location to find the repo root."""
    candidate = Path(__file__).resolve().parent.parent
    if (candidate / "pyproject.toml").exists():
        return candidate
    # Fallback: cwd
    return Path.cwd()


def _extract_enum_members(models_path: Path) -> set[str]:
    """Parse ThreatCategory enum members from models.py using regex."""
    text = models_path.read_text(encoding="utf-8")

    # Find the ThreatCategory class body
    match = re.search(
        r"class ThreatCategory\(.*?\):\s*\n(.*?)(?=\nclass |\n[A-Z@]|\Z)",
        text,
        re.DOTALL,
    )
    if not match:
        print("ERROR: Could not find ThreatCategory class in", models_path)
        sys.exit(1)

    class_body = match.group(1)
    members = set(_ENUM_MEMBER_RE.findall(class_body))

    if not members:
        print("ERROR: Found ThreatCategory class but no enum members in", models_path)
        sys.exit(1)

    return members


def _scan_usage(files: list[Path]) -> list[tuple[Path, int, str]]:
    """Scan Python files for ThreatCategory.<NAME> references.

    Returns list of (file, line_number, member_name) tuples for any
    member that is NOT in ALLOWED_CATEGORIES.
    """
    violations: list[tuple[Path, int, str]] = []

    for fpath in files:
        try:
            lines = fpath.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for line_num, line in enumerate(lines, start=1):
            for m in _USAGE_RE.finditer(line):
                name = m.group(1)
                if name not in ALLOWED_CATEGORIES:
                    violations.append((fpath, line_num, name))

    return violations


def _collect_python_files(root: Path, only_files: list[str] | None) -> list[Path]:
    """Collect .py files to scan."""
    if only_files:
        return [Path(f) for f in only_files if f.endswith(".py")]

    py_files: list[Path] = []
    for search_dir in (root / SOURCE_DIR, root / TESTS_DIR):
        if search_dir.is_dir():
            py_files.extend(search_dir.rglob("*.py"))

    # Also include scripts/ itself
    scripts_dir = root / "scripts"
    if scripts_dir.is_dir():
        py_files.extend(scripts_dir.rglob("*.py"))

    return py_files


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    root = _find_repo_root()
    models_path = root / MODELS_FILE

    if not models_path.exists():
        print(f"ERROR: {models_path} not found. Run from the repo root.")
        return 1

    errors: list[str] = []

    # ---- Check 1: Enum guard ----
    enum_members = _extract_enum_members(models_path)

    unauthorized = enum_members - ALLOWED_CATEGORIES
    if unauthorized:
        errors.append(
            "TAXONOMY ERROR: ThreatCategory enum contains values not in official taxonomy:\n"
            + "".join(f"  - {name}\n" for name in sorted(unauthorized))
            + "Allowed values: "
            + ", ".join(sorted(ALLOWED_CATEGORIES))
        )

    missing_from_enum = ALLOWED_CATEGORIES - enum_members
    if missing_from_enum:
        errors.append(
            "TAXONOMY WARNING: Allowlist contains categories missing from ThreatCategory enum:\n"
            + "".join(f"  - {name}\n" for name in sorted(missing_from_enum))
            + "Update the enum in models.py or remove from the allowlist in this script."
        )

    # ---- Check 2: Usage guard ----
    only_files = args if args else None
    py_files = _collect_python_files(root, only_files)
    usage_violations = _scan_usage(py_files)

    if usage_violations:
        errors.append(
            "TAXONOMY ERROR: Found ThreatCategory references not in official taxonomy:\n"
            + "".join(f"  - {fpath}:{line_num}: ThreatCategory.{name}\n" for fpath, line_num, name in usage_violations)
            + "Allowed values: "
            + ", ".join(sorted(ALLOWED_CATEGORIES))
        )

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print(f"Taxonomy check passed: {len(enum_members)} categories, {len(py_files)} files scanned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
