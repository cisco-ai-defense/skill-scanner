# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Manifest validation checks.

Rules: MANIFEST_INVALID_NAME, MANIFEST_DESCRIPTION_TOO_LONG,
       SOCIAL_ENG_VAGUE_DESCRIPTION, SOCIAL_ENG_ANTHROPIC_IMPERSONATION,
       MANIFEST_MISSING_LICENSE.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import SKILL_NAME_PATTERN, generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import SkillManifest
    from skill_scanner.core.scan_policy import ScanPolicy


def check_manifest(manifest: SkillManifest, policy: ScanPolicy) -> list[Finding]:
    """Validate skill manifest for security and policy issues.

    Checks naming rules, description length/quality, brand impersonation,
    and license presence.
    """
    findings: list[Finding] = []

    # -- MANIFEST_INVALID_NAME --
    max_name_length = policy.file_limits.max_name_length
    if len(manifest.name) > max_name_length or not SKILL_NAME_PATTERN.fullmatch(manifest.name or ""):
        findings.append(
            Finding(
                id=generate_finding_id("MANIFEST_INVALID_NAME", "manifest"),
                rule_id="MANIFEST_INVALID_NAME",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.INFO,
                title="Skill name does not follow agent skills naming rules",
                description=(
                    f"Skill name '{manifest.name}' is invalid. Agent skills require lowercase letters, numbers, "
                    f"and hyphens only, with a maximum length of {max_name_length} characters."
                ),
                file_path="SKILL.md",
                remediation="Rename the skill to match `[a-z0-9-]{1,64}` (e.g., 'pdf-processing')",
                analyzer="static",
            )
        )

    # -- MANIFEST_DESCRIPTION_TOO_LONG --
    max_desc_length = policy.file_limits.max_description_length
    if len(manifest.description or "") > max_desc_length:
        findings.append(
            Finding(
                id=generate_finding_id("MANIFEST_DESCRIPTION_TOO_LONG", "manifest"),
                rule_id="MANIFEST_DESCRIPTION_TOO_LONG",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.LOW,
                title="Skill description exceeds agent skills length limit",
                description=(
                    f"Skill description is {len(manifest.description)} characters; Agent skills limit the "
                    f"`description` field to {max_desc_length} characters."
                ),
                file_path="SKILL.md",
                remediation=f"Shorten the description to {max_desc_length} characters or fewer while keeping it specific",
                analyzer="static",
            )
        )

    # -- SOCIAL_ENG_VAGUE_DESCRIPTION --
    min_desc_length = policy.file_limits.min_description_length
    if len(manifest.description) < min_desc_length:
        findings.append(
            Finding(
                id=generate_finding_id("SOCIAL_ENG_VAGUE_DESCRIPTION", "manifest"),
                rule_id="SOCIAL_ENG_VAGUE_DESCRIPTION",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                severity=Severity.LOW,
                title="Vague skill description",
                description=f"Skill description is too short ({len(manifest.description)} chars). Provide detailed explanation.",
                file_path="SKILL.md",
                remediation="Provide a clear, detailed description of what the skill does and when to use it",
                analyzer="static",
            )
        )

    # -- SOCIAL_ENG_ANTHROPIC_IMPERSONATION --
    description_lower = manifest.description.lower()
    name_lower = manifest.name.lower()
    is_anthropic_mentioned = "anthropic" in name_lower or "anthropic" in description_lower

    if is_anthropic_mentioned:
        legitimate_patterns = ["apply", "brand", "guidelines", "colors", "typography", "style"]
        is_legitimate = any(pattern in description_lower for pattern in legitimate_patterns)

        if not is_legitimate:
            findings.append(
                Finding(
                    id=generate_finding_id("SOCIAL_ENG_ANTHROPIC_IMPERSONATION", "manifest"),
                    rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.MEDIUM,
                    title="Potential Anthropic brand impersonation",
                    description="Skill name or description contains 'Anthropic', suggesting official affiliation",
                    file_path="SKILL.md",
                    remediation="Do not impersonate official skills or use unauthorized branding",
                    analyzer="static",
                )
            )

    if "claude official" in name_lower or "claude official" in description_lower:
        findings.append(
            Finding(
                id=generate_finding_id("SOCIAL_ENG_CLAUDE_OFFICIAL", "manifest"),
                rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                severity=Severity.HIGH,
                title="Claims to be official skill",
                description="Skill claims to be an 'official' skill",
                file_path="SKILL.md",
                remediation="Remove 'official' claims unless properly authorized",
                analyzer="static",
            )
        )

    # -- MANIFEST_MISSING_LICENSE --
    if not manifest.license:
        findings.append(
            Finding(
                id=generate_finding_id("MANIFEST_MISSING_LICENSE", "manifest"),
                rule_id="MANIFEST_MISSING_LICENSE",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.INFO,
                title="Skill does not specify a license",
                description="Skill manifest does not include a 'license' field. Specifying a license helps users understand usage terms.",
                file_path="SKILL.md",
                remediation="Add 'license' field to SKILL.md frontmatter (e.g., MIT, Apache-2.0)",
                analyzer="static",
            )
        )

    return findings
