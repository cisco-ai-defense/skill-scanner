# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Shared helper utilities for extracted Python check modules."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skill_scanner.core.scan_policy import ScanPolicy


def generate_finding_id(rule_id: str, context: str) -> str:
    """Generate a deterministic, unique finding ID.

    Replicates the logic previously in ``BaseAnalyzer._generate_finding_id``.
    """
    combined = f"{rule_id}:{context}"
    hash_obj = hashlib.sha256(combined.encode())
    return f"{rule_id}_{hash_obj.hexdigest()[:10]}"


def is_doc_file(rel_path: str, policy: ScanPolicy) -> bool:
    """Check if a file is in a documentation directory.

    Uses ``doc_path_indicators`` and ``doc_filename_patterns`` from the
    policy to determine if a path belongs to a documentation area.
    """
    path_obj = Path(rel_path)
    parts = path_obj.parts
    doc_indicators = policy.rule_scoping.doc_path_indicators
    if any(p.lower() in doc_indicators for p in parts):
        return True
    doc_re = policy._compiled_doc_filename_re
    if doc_re and doc_re.search(path_obj.stem):
        return True
    return False


# ---------------------------------------------------------------------------
# Pre-compiled regex patterns for file operation detection
# (previously module-level constants in static.py)
# ---------------------------------------------------------------------------

READ_PATTERNS = [
    re.compile(r"open\([^)]+['\"]r['\"]"),
    re.compile(r"\.read\("),
    re.compile(r"\.readline\("),
    re.compile(r"\.readlines\("),
    re.compile(r"Path\([^)]+\)\.read_text"),
    re.compile(r"Path\([^)]+\)\.read_bytes"),
    re.compile(r"with\s+open\([^)]+['\"]r"),
]

WRITE_PATTERNS = [
    re.compile(r"open\([^)]+['\"]w['\"]"),
    re.compile(r"\.write\("),
    re.compile(r"\.writelines\("),
    re.compile(r"pathlib\.Path\([^)]+\)\.write"),
    re.compile(r"with\s+open\([^)]+['\"]w"),
]

GREP_PATTERNS = [
    re.compile(r"re\.search\("),
    re.compile(r"re\.findall\("),
    re.compile(r"re\.match\("),
    re.compile(r"re\.finditer\("),
    re.compile(r"re\.sub\("),
    re.compile(r"grep"),
]

GLOB_PATTERNS = [
    re.compile(r"glob\.glob\("),
    re.compile(r"glob\.iglob\("),
    re.compile(r"Path\([^)]*\)\.glob\("),
    re.compile(r"\.glob\("),
    re.compile(r"\.rglob\("),
    re.compile(r"fnmatch\."),
]

SKILL_NAME_PATTERN = re.compile(r"[a-z0-9-]+")
