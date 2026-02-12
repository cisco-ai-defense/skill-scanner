# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Hidden file and __pycache__ detection checks.

Rules: PYCACHE_FILES_DETECTED, HIDDEN_EXECUTABLE_SCRIPT, HIDDEN_DATA_FILE.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill
    from skill_scanner.core.scan_policy import ScanPolicy


def check_hidden_files(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Check for hidden files (dotfiles) and __pycache__ in skill package."""
    findings: list[Finding] = []

    CODE_EXTENSIONS = policy.file_classification.code_extensions
    benign_dotfiles = policy.hidden_files.benign_dotfiles
    benign_dotdirs = policy.hidden_files.benign_dotdirs

    flagged_pycache_dirs: set[str] = set()

    for skill_file in skill.files:
        rel_path = skill_file.relative_path
        path_obj = Path(rel_path)

        if skill_file.is_pycache:
            pycache_dir = str(path_obj.parent)
            if pycache_dir in flagged_pycache_dirs:
                continue
            flagged_pycache_dirs.add(pycache_dir)

            pyc_count = sum(
                1 for sf in skill.files if sf.is_pycache and str(Path(sf.relative_path).parent) == pycache_dir
            )

            findings.append(
                Finding(
                    id=generate_finding_id("PYCACHE_FILES_DETECTED", pycache_dir),
                    rule_id="PYCACHE_FILES_DETECTED",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Python bytecode cache directory detected",
                    description=(
                        f"__pycache__ directory found at {pycache_dir}/ "
                        f"containing {pyc_count} bytecode file(s). "
                        f"Pre-compiled bytecode should not be distributed in skill packages."
                    ),
                    file_path=pycache_dir,
                    remediation="Remove __pycache__ directories from skill packages. Ship source code only.",
                    analyzer="static",
                )
            )
        elif skill_file.is_hidden:
            ext = path_obj.suffix.lower()
            parts = path_obj.parts
            filename = path_obj.name

            if filename.lower() in benign_dotfiles:
                continue

            hidden_parts = [p for p in parts if p.startswith(".") and p != "."]
            if any(p.lower() in benign_dotdirs for p in hidden_parts):
                continue

            if ext in CODE_EXTENSIONS:
                findings.append(
                    Finding(
                        id=generate_finding_id("HIDDEN_EXECUTABLE_SCRIPT", rel_path),
                        rule_id="HIDDEN_EXECUTABLE_SCRIPT",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.HIGH,
                        title="Hidden executable script detected",
                        description=(
                            f"Hidden script file found: {rel_path}. "
                            f"Hidden files (dotfiles) are often used to conceal malicious code "
                            f"from casual inspection."
                        ),
                        file_path=rel_path,
                        remediation="Move script to a visible location or remove if not needed.",
                        analyzer="static",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=generate_finding_id("HIDDEN_DATA_FILE", rel_path),
                        rule_id="HIDDEN_DATA_FILE",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.LOW,
                        title="Hidden data file detected",
                        description=(
                            f"Hidden file found: {rel_path}. "
                            f"Hidden files may contain concealed configuration or data "
                            f"that should be reviewed."
                        ),
                        file_path=rel_path,
                        remediation="Move file to a visible location or document its purpose.",
                        analyzer="static",
                    )
                )

    return findings
