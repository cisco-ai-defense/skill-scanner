# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Binary and archive file detection checks.

Rules: FILE_MAGIC_MISMATCH, ARCHIVE_FILE_DETECTED, BINARY_FILE_DETECTED.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill
    from skill_scanner.core.scan_policy import ScanPolicy


def check_binary_files(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Check for binary files with tiered asset classification and magic byte validation."""
    from skill_scanner.core.file_magic import check_extension_mismatch

    findings: list[Finding] = []

    INERT_EXTENSIONS = policy.file_classification.inert_extensions
    STRUCTURED_EXTENSIONS = policy.file_classification.structured_extensions
    ARCHIVE_EXTENSIONS = policy.file_classification.archive_extensions

    min_confidence = policy.analysis_thresholds.min_confidence_pct / 100.0

    for skill_file in skill.files:
        file_path_obj = Path(skill_file.relative_path)
        ext = file_path_obj.suffix.lower()
        if file_path_obj.name.endswith(".tar.gz"):
            ext = ".tar.gz"

        # Run file magic mismatch check on ALL files with known extensions
        if skill_file.path.exists():
            mismatch = check_extension_mismatch(skill_file.path, min_confidence=min_confidence)
            if mismatch:
                mismatch_severity, mismatch_desc, magic_match = mismatch
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                }
                findings.append(
                    Finding(
                        id=generate_finding_id("FILE_MAGIC_MISMATCH", skill_file.relative_path),
                        rule_id="FILE_MAGIC_MISMATCH",
                        category=ThreatCategory.OBFUSCATION,
                        severity=severity_map.get(mismatch_severity, Severity.MEDIUM),
                        title="File extension does not match actual content type",
                        description=mismatch_desc,
                        file_path=skill_file.relative_path,
                        remediation="Rename the file to match its actual content type, or remove it if it appears malicious.",
                        analyzer="static",
                        metadata={
                            "actual_type": magic_match.content_type,
                            "actual_family": magic_match.content_family,
                            "claimed_extension": ext,
                            "confidence_score": magic_match.score,
                        },
                    )
                )

        # Only check further if the file is classified as binary
        if skill_file.file_type != "binary":
            continue

        if ext in INERT_EXTENSIONS:
            continue

        if ext in STRUCTURED_EXTENSIONS:
            continue

        if ext in ARCHIVE_EXTENSIONS:
            findings.append(
                Finding(
                    id=generate_finding_id("ARCHIVE_FILE_DETECTED", skill_file.relative_path),
                    rule_id="ARCHIVE_FILE_DETECTED",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.MEDIUM,
                    title="Archive file detected in skill package",
                    description=(
                        f"Archive file found: {skill_file.relative_path}. "
                        f"Archives can contain hidden executables, scripts, or other malicious content "
                        f"that is not visible without extraction."
                    ),
                    file_path=skill_file.relative_path,
                    remediation="Extract archive contents and include files directly, or document the archive's purpose.",
                    analyzer="static",
                )
            )
            continue

        findings.append(
            Finding(
                id=generate_finding_id("BINARY_FILE_DETECTED", skill_file.relative_path),
                rule_id="BINARY_FILE_DETECTED",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.INFO,
                title="Binary file detected in skill package",
                description=(
                    f"Binary file found: {skill_file.relative_path}. "
                    f"Binary files cannot be inspected by static analysis. "
                    f"Consider using Python or Bash scripts for transparency."
                ),
                file_path=skill_file.relative_path,
                remediation="Review binary file necessity. Replace with auditable scripts if possible.",
                analyzer="static",
            )
        )

    return findings
