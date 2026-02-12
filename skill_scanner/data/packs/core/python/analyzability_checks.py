# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Analyzability score checks.

Rules: UNANALYZABLE_BINARY, LOW_ANALYZABILITY.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

if TYPE_CHECKING:
    from skill_scanner.core.analyzability import AnalyzabilityReport
    from skill_scanner.core.scan_policy import ScanPolicy


def check_analyzability(report: AnalyzabilityReport, policy: ScanPolicy) -> list[Finding]:
    """Generate findings when analyzability score is below acceptable thresholds.

    Fail-closed: what the scanner cannot inspect should be flagged, not trusted.
    """
    findings: list[Finding] = []

    # -- UNANALYZABLE_BINARY --
    _unanalyzable_enabled = "UNANALYZABLE_BINARY" not in policy.disabled_rules
    _skip_inert = policy.file_classification.skip_inert_extensions
    _inert_exts = set(policy.file_classification.inert_extensions) if _skip_inert else set()
    _doc_indicators = set(policy.rule_scoping.doc_path_indicators)

    for fd in report.file_details:
        if not fd.is_analyzable and fd.skip_reason and "Binary file" in fd.skip_reason:
            if not _unanalyzable_enabled:
                continue
            ext = Path(fd.relative_path).suffix.lower()
            if _skip_inert and ext in _inert_exts:
                continue
            parts = Path(fd.relative_path).parts
            if any(p.lower() in _doc_indicators for p in parts):
                continue
            findings.append(
                Finding(
                    id=f"UNANALYZABLE_BINARY_{fd.relative_path}",
                    rule_id="UNANALYZABLE_BINARY",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.MEDIUM,
                    title="Unanalyzable binary file",
                    description=(
                        f"Binary file '{fd.relative_path}' cannot be inspected by the scanner. "
                        f"Reason: {fd.skip_reason}. Binary files resist static analysis "
                        f"and may contain hidden functionality."
                    ),
                    file_path=fd.relative_path,
                    remediation=(
                        "Replace binary files with source code, or submit the binary "
                        "to VirusTotal for independent verification (--use-virustotal)."
                    ),
                    analyzer="analyzability",
                    metadata={"skip_reason": fd.skip_reason, "weight": fd.weight},
                )
            )

    # -- LOW_ANALYZABILITY --
    if "LOW_ANALYZABILITY" in policy.disabled_rules:
        return findings

    if report.risk_level == "HIGH":
        findings.append(
            Finding(
                id="LOW_ANALYZABILITY_CRITICAL",
                rule_id="LOW_ANALYZABILITY",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.HIGH,
                title="Critically low analyzability score",
                description=(
                    f"Only {report.score:.0f}% of skill content could be analyzed. "
                    f"{report.unanalyzable_files} of {report.total_files} files are opaque "
                    f"to the scanner. The safety assessment has low confidence."
                ),
                remediation=(
                    "Replace opaque files (binaries, encrypted content) with "
                    "inspectable source code to improve scan confidence."
                ),
                analyzer="analyzability",
                metadata={
                    "score": round(report.score, 1),
                    "unanalyzable_files": report.unanalyzable_files,
                    "total_files": report.total_files,
                    "risk_level": report.risk_level,
                },
            )
        )
    elif report.risk_level == "MEDIUM":
        findings.append(
            Finding(
                id="LOW_ANALYZABILITY_MODERATE",
                rule_id="LOW_ANALYZABILITY",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.MEDIUM,
                title="Moderate analyzability score",
                description=(
                    f"Only {report.score:.0f}% of skill content could be analyzed. "
                    f"{report.unanalyzable_files} of {report.total_files} files are opaque "
                    f"to the scanner. Some content could not be verified as safe."
                ),
                remediation="Review opaque files and replace with inspectable formats where possible.",
                analyzer="analyzability",
                metadata={
                    "score": round(report.score, 1),
                    "unanalyzable_files": report.unanalyzable_files,
                    "total_files": report.total_files,
                    "risk_level": report.risk_level,
                },
            )
        )

    return findings
