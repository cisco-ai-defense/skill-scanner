# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Asset file scanning checks.

Rules: ASSET_PROMPT_INJECTION, ASSET_SUSPICIOUS_URL.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill

# Patterns to detect in asset/template files
_ASSET_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
        "ASSET_PROMPT_INJECTION",
        Severity.HIGH,
        "Prompt injection pattern in asset file",
    ),
    (
        re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
        "ASSET_PROMPT_INJECTION",
        Severity.HIGH,
        "Prompt override pattern in asset file",
    ),
    (
        re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
        "ASSET_PROMPT_INJECTION",
        Severity.MEDIUM,
        "Role reassignment pattern in asset file",
    ),
    (
        re.compile(r"https?://[^\s]+\.(tk|ml|ga|cf|gq)/", re.IGNORECASE),
        "ASSET_SUSPICIOUS_URL",
        Severity.MEDIUM,
        "Suspicious free domain URL in asset",
    ),
]

_ASSET_DIRS = {"assets", "templates", "references", "data"}


def check_asset_files(skill: Skill) -> list[Finding]:
    """Scan files in assets/, templates/, and references/ directories for injection patterns."""
    findings: list[Finding] = []

    for skill_file in skill.files:
        path_parts = skill_file.relative_path.split("/")

        is_asset_file = (
            (len(path_parts) > 1 and path_parts[0] in _ASSET_DIRS)
            or skill_file.relative_path.endswith((".template", ".tmpl", ".tpl"))
            or (
                skill_file.file_type == "other"
                and skill_file.relative_path.endswith((".txt", ".json", ".yaml", ".yml"))
            )
        )

        if not is_asset_file:
            continue

        content = skill_file.read_content()
        if not content:
            continue

        for pattern, rule_id, severity, description in _ASSET_PATTERNS:
            matches = list(pattern.finditer(content))

            for match in matches:
                line_number = content[: match.start()].count("\n") + 1
                line_content = content.split("\n")[line_number - 1] if content else ""

                findings.append(
                    Finding(
                        id=generate_finding_id(rule_id, f"{skill_file.relative_path}:{line_number}"),
                        rule_id=rule_id,
                        category=ThreatCategory.PROMPT_INJECTION
                        if "PROMPT" in rule_id
                        else ThreatCategory.COMMAND_INJECTION
                        if "CODE" in rule_id or "SCRIPT" in rule_id
                        else ThreatCategory.OBFUSCATION
                        if "BASE64" in rule_id
                        else ThreatCategory.POLICY_VIOLATION,
                        severity=severity,
                        title=description,
                        description=f"Pattern '{match.group()[:50]}...' detected in asset file",
                        file_path=skill_file.relative_path,
                        line_number=line_number,
                        snippet=line_content[:100],
                        remediation="Review the asset file and remove any malicious or unnecessary dynamic patterns",
                        analyzer="static",
                    )
                )

    return findings
