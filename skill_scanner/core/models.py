# Copyright 2026 Cisco Systems, Inc.
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
Data models for agent skills and security findings.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


class ThreatCategory(str, Enum):
    """Categories of security threats."""

    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    OBFUSCATION = "obfuscation"
    HARDCODED_SECRETS = "hardcoded_secrets"
    SOCIAL_ENGINEERING = "social_engineering"
    RESOURCE_ABUSE = "resource_abuse"
    POLICY_VIOLATION = "policy_violation"
    MALWARE = "malware"
    HARMFUL_CONTENT = "harmful_content"
    # New threat categories
    SKILL_DISCOVERY_ABUSE = "skill_discovery_abuse"
    TRANSITIVE_TRUST_ABUSE = "transitive_trust_abuse"
    AUTONOMY_ABUSE = "autonomy_abuse"
    TOOL_CHAINING_ABUSE = "tool_chaining_abuse"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"


@dataclass
class SkillManifest:
    """Parsed YAML frontmatter from SKILL.md.

    Supports Codex Skills and Cursor Agent Skills formats,
    which follow the Agent Skills specification. The format includes:
    - Required: name, description
    - Optional: license, compatibility, allowed-tools, metadata
    - Cursor Skills: disable-model-invocation (controls automatic invocation)
    - Codex Skills: metadata.short-description (optional user-facing description)
    """

    name: str
    description: str
    license: str | None = None
    compatibility: str | None = None
    allowed_tools: list[str] | None = None
    metadata: dict[str, Any] | None = None
    disable_model_invocation: bool = False

    def __post_init__(self):
        """Normalize allowed_tools to list."""
        if self.allowed_tools is None:
            self.allowed_tools = []
        elif isinstance(self.allowed_tools, str):
            # Agent skill docs commonly show comma-separated tool lists in YAML frontmatter
            # (e.g., "allowed-tools: Read, Grep, Glob"). Treat this as a list.
            parts = [p.strip() for p in self.allowed_tools.split(",")]
            self.allowed_tools = [p for p in parts if p]

    @property
    def short_description(self) -> str | None:
        """Get short-description from metadata (Codex Skills format)."""
        if self.metadata and isinstance(self.metadata, dict):
            return self.metadata.get("short-description")
        return None


@dataclass
class SkillFile:
    """A file within a skill package."""

    path: Path
    relative_path: str
    file_type: str  # 'markdown', 'python', 'bash', 'binary', 'other'
    content: str | None = None
    size_bytes: int = 0

    def read_content(self) -> str:
        """Read file content if not already loaded."""
        if self.content is None and self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.content = f.read()
            except (OSError, UnicodeDecodeError):
                self.content = ""  # Binary or unreadable file
        return self.content or ""


@dataclass
class Skill:
    """Represents a complete Agent Skill package.

    Supports the Agent Skills specification format used by
    OpenAI Codex Skills and Cursor Agent Skills. The package structure includes:
    - SKILL.md (required): Manifest and instructions
    - scripts/ (optional): Executable code
    - references/ (optional): Documentation files
    - assets/ (optional): Templates and resources
    """

    directory: Path
    manifest: SkillManifest
    skill_md_path: Path
    instruction_body: str
    files: list[SkillFile] = field(default_factory=list)
    referenced_files: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def description(self) -> str:
        return self.manifest.description

    def get_scripts(self) -> list[SkillFile]:
        """Get all script files (Python, Bash)."""
        return [f for f in self.files if f.file_type in ("python", "bash")]

    def get_markdown_files(self) -> list[SkillFile]:
        """Get all markdown files."""
        return [f for f in self.files if f.file_type == "markdown"]


@dataclass
class Finding:
    """A security issue discovered in a skill."""

    id: str  # Unique finding identifier (e.g., rule ID + line number)
    rule_id: str  # Rule that triggered this finding
    category: ThreatCategory
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    snippet: str | None = None
    remediation: str | None = None
    analyzer: str | None = None  # Which analyzer produced this finding (e.g., "static", "llm", "behavioral")
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "analyzer": self.analyzer,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """Results from scanning a single skill."""

    skill_name: str
    skill_directory: str
    findings: list[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    analyzers_used: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_safe(self) -> bool:
        """Check if skill passed all security checks."""
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    @property
    def max_severity(self) -> Severity:
        """Get the highest severity level found."""
        if not self.findings:
            return Severity.SAFE

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for severity in severity_order:
            if any(f.severity == severity for f in self.findings):
                return severity
        return Severity.SAFE

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: ThreatCategory) -> list[Finding]:
        """Get all findings of a specific category."""
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary.

        Output format is compatible with mcp-scanner-plugin's SkillResultParser.
        See: https://github.com/cisco/mcp-scanner-plugin
        """
        return {
            "skill_name": self.skill_name,
            "skill_path": self.skill_directory,  # Plugin expects skill_path
            "skill_directory": self.skill_directory,  # Keep for backward compatibility
            "is_safe": self.is_safe,
            "max_severity": self.max_severity.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_seconds": self.scan_duration_seconds,
            "duration_ms": int(self.scan_duration_seconds * 1000),  # Plugin expects duration_ms
            "analyzers_used": self.analyzers_used,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Report:
    """Aggregated report from scanning one or more skills."""

    scan_results: list[ScanResult] = field(default_factory=list)
    total_skills_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    safe_count: int = 0
    timestamp: datetime = field(default_factory=datetime.now)

    def add_scan_result(self, result: ScanResult):
        """Add a scan result and update counters."""
        self.scan_results.append(result)
        self.total_skills_scanned += 1
        self.total_findings += len(result.findings)

        for finding in result.findings:
            if finding.severity == Severity.CRITICAL:
                self.critical_count += 1
            elif finding.severity == Severity.HIGH:
                self.high_count += 1
            elif finding.severity == Severity.MEDIUM:
                self.medium_count += 1
            elif finding.severity == Severity.LOW:
                self.low_count += 1
            elif finding.severity == Severity.INFO:
                self.info_count += 1

        if result.is_safe:
            self.safe_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "summary": {
                "total_skills_scanned": self.total_skills_scanned,
                "total_findings": self.total_findings,
                "safe_skills": self.safe_count,
                "findings_by_severity": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                    "info": self.info_count,
                },
                "timestamp": self.timestamp.isoformat(),
            },
            "results": [result.to_dict() for result in self.scan_results],
        }
