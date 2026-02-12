# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""File inventory analysis checks.

Rules: EXCESSIVE_FILE_COUNT, OVERSIZED_FILE, ARCHIVE_CONTAINS_EXECUTABLE.

Note: Unreferenced script collection (for LLM enrichment) remains in the
StaticAnalyzer because it writes to ``self._unreferenced_scripts``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill
    from skill_scanner.core.scan_policy import ScanPolicy


def check_file_inventory(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Analyze the file inventory of the skill package for anomalies.

    Returns findings for excessive file count, oversized files, and
    archives containing executable scripts.

    Note: Unreferenced script detection remains in StaticAnalyzer since
    it needs to write to analyzer state for LLM enrichment.
    """
    findings: list[Finding] = []

    if not skill.files:
        return findings

    # Gather file stats
    total_size = 0
    largest_file = None
    largest_size = 0
    type_counts: dict[str, int] = {}

    for sf in skill.files:
        type_counts[sf.file_type] = type_counts.get(sf.file_type, 0) + 1
        total_size += sf.size_bytes
        if sf.size_bytes > largest_size:
            largest_size = sf.size_bytes
            largest_file = sf

    # -- EXCESSIVE_FILE_COUNT --
    max_file_count = policy.file_limits.max_file_count
    if len(skill.files) > max_file_count:
        findings.append(
            Finding(
                id=generate_finding_id("EXCESSIVE_FILE_COUNT", str(len(skill.files))),
                rule_id="EXCESSIVE_FILE_COUNT",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.LOW,
                title="Skill package contains many files",
                description=(
                    f"Skill package contains {len(skill.files)} files. "
                    f"Large file counts increase attack surface and may indicate "
                    f"bundled dependencies or unnecessary content."
                ),
                file_path=".",
                remediation="Review file inventory and remove unnecessary files.",
                analyzer="static",
                metadata={
                    "file_count": len(skill.files),
                    "type_breakdown": type_counts,
                },
            )
        )

    # -- OVERSIZED_FILE --
    max_file_size = policy.file_limits.max_file_size_bytes
    if largest_file and largest_size > max_file_size:
        findings.append(
            Finding(
                id=generate_finding_id("OVERSIZED_FILE", largest_file.relative_path),
                rule_id="OVERSIZED_FILE",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.LOW,
                title="Oversized file in skill package",
                description=(
                    f"File {largest_file.relative_path} is {largest_size / 1024 / 1024:.1f}MB. "
                    f"Large files in skill packages may contain hidden content or serve as "
                    f"a vector for resource abuse."
                ),
                file_path=largest_file.relative_path,
                remediation="Review large files and consider hosting externally.",
                analyzer="static",
            )
        )

    # -- ARCHIVE_CONTAINS_EXECUTABLE --
    for sf in skill.files:
        if sf.extracted_from and sf.file_type in ("python", "bash"):
            findings.append(
                Finding(
                    id=generate_finding_id("ARCHIVE_CONTAINS_EXECUTABLE", sf.relative_path),
                    rule_id="ARCHIVE_CONTAINS_EXECUTABLE",
                    category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                    severity=Severity.HIGH,
                    title="Archive contains executable script",
                    description=(
                        f"Executable script '{sf.relative_path}' was extracted from "
                        f"archive '{sf.extracted_from}'. Archives can be used to conceal "
                        f"malicious scripts from casual inspection."
                    ),
                    file_path=sf.relative_path,
                    remediation=(
                        "Remove executable scripts from archives. "
                        "Include scripts directly in the skill package for transparency."
                    ),
                    analyzer="static",
                    metadata={
                        "extracted_from": sf.extracted_from,
                        "file_type": sf.file_type,
                    },
                )
            )

    return findings
