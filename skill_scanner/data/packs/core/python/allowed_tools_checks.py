# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Allowed-tools violation checks.

Rules: ALLOWED_TOOLS_READ_VIOLATION, ALLOWED_TOOLS_WRITE_VIOLATION,
       ALLOWED_TOOLS_BASH_VIOLATION, ALLOWED_TOOLS_GREP_VIOLATION,
       ALLOWED_TOOLS_GLOB_VIOLATION, ALLOWED_TOOLS_NETWORK_USAGE.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import (
    GLOB_PATTERNS,
    GREP_PATTERNS,
    READ_PATTERNS,
    WRITE_PATTERNS,
    generate_finding_id,
)

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill


# ---------------------------------------------------------------------------
# Internal code-behaviour detectors
# ---------------------------------------------------------------------------


def _code_reads_files(skill: Skill) -> bool:
    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        for pattern in READ_PATTERNS:
            if pattern.search(content):
                return True
    return False


def _code_writes_files(skill: Skill) -> bool:
    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        for pattern in WRITE_PATTERNS:
            if pattern.search(content):
                return True
    return False


def _code_executes_bash(skill: Skill) -> bool:
    bash_indicators = [
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "commands.getoutput",
        "shell=True",
    ]
    if any(f.file_type == "bash" for f in skill.files):
        return True
    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        if any(indicator in content for indicator in bash_indicators):
            return True
    return False


def _code_uses_grep(skill: Skill) -> bool:
    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        for pattern in GREP_PATTERNS:
            if pattern.search(content):
                return True
    return False


def _code_uses_glob(skill: Skill) -> bool:
    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        for pattern in GLOB_PATTERNS:
            if pattern.search(content):
                return True
    return False


def _code_uses_network(skill: Skill) -> bool:
    network_indicators = [
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "urllib.request",
        "urllib.urlopen",
        "http.client",
        "httpx.",
        "aiohttp.",
        "socket.connect",
        "socket.create_connection",
    ]
    for skill_file in skill.get_scripts():
        content = skill_file.read_content()
        if any(indicator in content for indicator in network_indicators):
            return True
    return False


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------


def check_allowed_tools_violations(skill: Skill) -> list[Finding]:
    """Check if code behavior violates allowed-tools restrictions."""
    findings: list[Finding] = []

    if not skill.manifest.allowed_tools:
        return findings

    allowed_tools_lower = [tool.lower() for tool in skill.manifest.allowed_tools]

    if "read" not in allowed_tools_lower and _code_reads_files(skill):
        findings.append(
            Finding(
                id=generate_finding_id("ALLOWED_TOOLS_READ_VIOLATION", skill.name),
                rule_id="ALLOWED_TOOLS_READ_VIOLATION",
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.MEDIUM,
                title="Code reads files but Read tool not in allowed-tools",
                description=(
                    f"Skill restricts tools to {skill.manifest.allowed_tools} but bundled scripts appear to "
                    f"read files from the filesystem."
                ),
                file_path=None,
                remediation="Add 'Read' to allowed-tools or remove file reading operations from scripts",
                analyzer="static",
            )
        )

    if "write" not in allowed_tools_lower and _code_writes_files(skill):
        findings.append(
            Finding(
                id=generate_finding_id("ALLOWED_TOOLS_WRITE_VIOLATION", skill.name),
                rule_id="ALLOWED_TOOLS_WRITE_VIOLATION",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.MEDIUM,
                title="Skill declares no Write tool but bundled scripts write files",
                description=(
                    f"Skill restricts tools to {skill.manifest.allowed_tools} but bundled scripts appear to "
                    f"write to the filesystem, which conflicts with a read-only tool declaration."
                ),
                file_path=None,
                remediation="Either add 'Write' to allowed-tools (if intentional) or remove filesystem writes from scripts",
                analyzer="static",
            )
        )

    if "bash" not in allowed_tools_lower and _code_executes_bash(skill):
        findings.append(
            Finding(
                id=generate_finding_id("ALLOWED_TOOLS_BASH_VIOLATION", skill.name),
                rule_id="ALLOWED_TOOLS_BASH_VIOLATION",
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.HIGH,
                title="Code executes bash but Bash tool not in allowed-tools",
                description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code executes bash commands",
                file_path=None,
                remediation="Add 'Bash' to allowed-tools or remove bash execution from code",
                analyzer="static",
            )
        )

    if "grep" not in allowed_tools_lower and _code_uses_grep(skill):
        findings.append(
            Finding(
                id=generate_finding_id("ALLOWED_TOOLS_GREP_VIOLATION", skill.name),
                rule_id="ALLOWED_TOOLS_GREP_VIOLATION",
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.LOW,
                title="Code uses search/grep patterns but Grep tool not in allowed-tools",
                description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses regex search patterns",
                file_path=None,
                remediation="Add 'Grep' to allowed-tools or remove regex search operations",
                analyzer="static",
            )
        )

    if "glob" not in allowed_tools_lower and _code_uses_glob(skill):
        findings.append(
            Finding(
                id=generate_finding_id("ALLOWED_TOOLS_GLOB_VIOLATION", skill.name),
                rule_id="ALLOWED_TOOLS_GLOB_VIOLATION",
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.LOW,
                title="Code uses glob/file patterns but Glob tool not in allowed-tools",
                description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses glob patterns",
                file_path=None,
                remediation="Add 'Glob' to allowed-tools or remove glob operations",
                analyzer="static",
            )
        )

    if _code_uses_network(skill):
        findings.append(
            Finding(
                id=generate_finding_id("ALLOWED_TOOLS_NETWORK_USAGE", skill.name),
                rule_id="ALLOWED_TOOLS_NETWORK_USAGE",
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.MEDIUM,
                title="Code makes network requests",
                description=(
                    "Skill code makes network requests. While not controlled by allowed-tools, "
                    "network access should be documented and justified in the skill description."
                ),
                file_path=None,
                remediation="Document network usage in skill description or remove network operations if not needed",
                analyzer="static",
            )
        )

    return findings
