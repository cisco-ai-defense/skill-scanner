# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Manifest-behavior consistency checks.

Rules: TOOL_ABUSE_UNDECLARED_NETWORK, SOCIAL_ENG_MISLEADING_DESC.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill


def skill_uses_network(skill: Skill) -> bool:
    """Check if skill code uses network libraries for EXTERNAL communication."""
    external_network_indicators = [
        "import requests",
        "from requests import",
        "import urllib.request",
        "from urllib.request import",
        "import http.client",
        "import httpx",
        "import aiohttp",
    ]
    socket_external_indicators = ["socket.connect", "socket.create_connection"]
    socket_localhost_indicators = ["localhost", "127.0.0.1", "::1"]

    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        if any(indicator in content for indicator in external_network_indicators):
            return True
        if "import socket" in content:
            has_socket_connect = any(ind in content for ind in socket_external_indicators)
            is_localhost_only = any(ind in content for ind in socket_localhost_indicators)
            if has_socket_connect and not is_localhost_only:
                return True
    return False


def manifest_declares_network(skill: Skill) -> bool:
    """Check if manifest declares network usage."""
    if skill.manifest.compatibility:
        compatibility_lower = skill.manifest.compatibility.lower()
        return "network" in compatibility_lower or "internet" in compatibility_lower
    return False


def check_description_mismatch(skill: Skill) -> bool:
    """Check for description/behavior mismatch (basic heuristic)."""
    description = skill.description.lower()
    simple_keywords = ["calculator", "format", "template", "style", "lint"]
    if any(keyword in description for keyword in simple_keywords):
        if skill_uses_network(skill):
            return True
    return False


def check_consistency(skill: Skill) -> list[Finding]:
    """Check for inconsistencies between manifest and actual behavior."""
    findings: list[Finding] = []

    uses_network = skill_uses_network(skill)
    declared_network = manifest_declares_network(skill)

    if uses_network and not declared_network:
        findings.append(
            Finding(
                id=generate_finding_id("TOOL_MISMATCH_NETWORK", skill.name),
                rule_id="TOOL_ABUSE_UNDECLARED_NETWORK",
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.MEDIUM,
                title="Undeclared network usage",
                description="Skill code uses network libraries but doesn't declare network requirement",
                file_path=None,
                remediation="Declare network usage in compatibility field or remove network calls",
                analyzer="static",
            )
        )

    if check_description_mismatch(skill):
        findings.append(
            Finding(
                id=generate_finding_id("DESC_BEHAVIOR_MISMATCH", skill.name),
                rule_id="SOCIAL_ENG_MISLEADING_DESC",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                severity=Severity.MEDIUM,
                title="Potential description-behavior mismatch",
                description="Skill performs actions not reflected in its description",
                file_path="SKILL.md",
                remediation="Ensure description accurately reflects all skill capabilities",
                analyzer="static",
            )
        )

    return findings
