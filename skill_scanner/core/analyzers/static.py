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
Static pattern analyzer for detecting security vulnerabilities.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from ...config.yara_modes import DEFAULT_YARA_MODE, YaraModeConfig
from ...core.models import Finding, Severity, Skill, ThreatCategory
from ...core.rules.patterns import RuleLoader, SecurityRule
from ...core.rules.yara_scanner import YaraScanner
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for file operation checks
_READ_PATTERNS = [
    re.compile(r"open\([^)]+['\"]r['\"]"),
    re.compile(r"open\([^)]+\)"),
    re.compile(r"\.read\("),
    re.compile(r"\.readline\("),
    re.compile(r"\.readlines\("),
    re.compile(r"Path\([^)]+\)\.read_text"),
    re.compile(r"Path\([^)]+\)\.read_bytes"),
    re.compile(r"with\s+open\([^)]+['\"]r"),
]

_WRITE_PATTERNS = [
    re.compile(r"open\([^)]+['\"]w['\"]"),
    re.compile(r"\.write\("),
    re.compile(r"\.writelines\("),
    re.compile(r"pathlib\.Path\([^)]+\)\.write"),
    re.compile(r"with\s+open\([^)]+['\"]w"),
]

_GREP_PATTERNS = [
    re.compile(r"re\.search\("),
    re.compile(r"re\.findall\("),
    re.compile(r"re\.match\("),
    re.compile(r"re\.finditer\("),
    re.compile(r"re\.sub\("),
    re.compile(r"\.search\("),
    re.compile(r"\.findall\("),
    re.compile(r"grep"),
]

_GLOB_PATTERNS = [
    re.compile(r"glob\.glob\("),
    re.compile(r"glob\.iglob\("),
    re.compile(r"Path\([^)]*\)\.glob\("),
    re.compile(r"\.glob\("),
    re.compile(r"\.rglob\("),
    re.compile(r"fnmatch\."),
]

_EXCEPTION_PATTERNS = [
    re.compile(r"except\s+(EOFError|StopIteration|KeyboardInterrupt|Exception|BaseException)"),
    re.compile(r"except\s*:"),
    re.compile(r"break\s*$", re.MULTILINE),
    re.compile(r"return\s*$", re.MULTILINE),
    re.compile(r"sys\.exit\s*\("),
    re.compile(r"raise\s+StopIteration"),
]

_SKILL_NAME_PATTERN = re.compile(r"[a-z0-9-]+")
_MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^\)]+)\)")
_PYTHON_IMPORT_PATTERN = re.compile(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", re.MULTILINE)
_BASH_SOURCE_PATTERN = re.compile(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))")
_RM_TARGET_PATTERN = re.compile(r"rm\s+-r[^;]*?\s+([^\s;]+)")


class StaticAnalyzer(BaseAnalyzer):
    """Static pattern-based security analyzer."""

    def __init__(
        self,
        rules_file: Path | None = None,
        use_yara: bool = True,
        yara_mode: YaraModeConfig | str | None = None,
        custom_yara_rules_path: str | Path | None = None,
        disabled_rules: set[str] | None = None,
    ):
        """
        Initialize static analyzer.

        Args:
            rules_file: Optional custom YAML rules file
            use_yara: Whether to use YARA scanning (default: True)
            yara_mode: YARA detection mode - can be:
                - YaraModeConfig instance
                - Mode name string: "strict", "balanced", "permissive"
                - None for default (balanced)
            custom_yara_rules_path: Path to directory containing custom YARA rules
                (.yara files). If provided, uses these instead of built-in rules.
            disabled_rules: Set of rule names to disable. Rules can be YARA rule
                names (e.g., "YARA_script_injection") or static rule IDs
                (e.g., "COMMAND_INJECTION_EVAL").
        """
        super().__init__("static_analyzer")

        self.rule_loader = RuleLoader(rules_file)
        self.rule_loader.load_rules()

        # Configure YARA mode
        if yara_mode is None:
            self.yara_mode = DEFAULT_YARA_MODE
        elif isinstance(yara_mode, str):
            self.yara_mode = YaraModeConfig.from_mode_name(yara_mode)
        else:
            self.yara_mode = yara_mode

        # Store disabled rules (merge with mode-based disabled rules)
        self.disabled_rules = set(disabled_rules or set())
        self.disabled_rules.update(self.yara_mode.disabled_rules)

        # Store custom YARA rules path
        self.custom_yara_rules_path = Path(custom_yara_rules_path) if custom_yara_rules_path else None

        self.use_yara = use_yara
        self.yara_scanner = None
        if use_yara:
            try:
                # Use custom rules path if provided
                if self.custom_yara_rules_path:
                    self.yara_scanner = YaraScanner(rules_dir=self.custom_yara_rules_path)
                    logger.info("Using custom YARA rules from: %s", self.custom_yara_rules_path)
                else:
                    self.yara_scanner = YaraScanner()
            except Exception as e:
                logger.warning("Could not load YARA scanner: %s", e)
                self.yara_scanner = None

    def _is_rule_enabled(self, rule_name: str) -> bool:
        """
        Check if a rule is enabled.

        A rule is enabled if:
        1. It's enabled in the current YARA mode
        2. It's not in the explicitly disabled rules set

        Args:
            rule_name: Name of the rule to check (e.g., "YARA_script_injection")

        Returns:
            True if the rule is enabled, False otherwise
        """
        # Check mode-based enable/disable first
        if not self.yara_mode.is_rule_enabled(rule_name):
            return False

        # Check if explicitly disabled via --disable-rule
        if rule_name in self.disabled_rules:
            return False

        # Also check without YARA_ prefix for convenience
        base_name = rule_name.replace("YARA_", "") if rule_name.startswith("YARA_") else rule_name
        if base_name in self.disabled_rules:
            return False

        return True

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using static pattern matching.

        Performs multi-pass scanning:
        1. Manifest validation
        2. Instruction body scanning (SKILL.md)
        3. Script/code scanning
        4. Consistency checks
        5. Reference file scanning

        Args:
            skill: Skill to analyze

        Returns:
            List of security findings
        """
        findings = []

        findings.extend(self._check_manifest(skill))
        findings.extend(self._scan_instruction_body(skill))
        findings.extend(self._scan_scripts(skill))
        findings.extend(self._check_consistency(skill))
        findings.extend(self._scan_referenced_files(skill))
        findings.extend(self._check_binary_files(skill))

        if self.yara_scanner:
            findings.extend(self._yara_scan(skill))

        findings.extend(self._scan_asset_files(skill))

        # Filter out disabled rules
        if self.disabled_rules:
            findings = [f for f in findings if self._is_rule_enabled(f.rule_id)]

        return findings

    def _check_manifest(self, skill: Skill) -> list[Finding]:
        """Validate skill manifest for security issues."""
        findings = []
        manifest = skill.manifest

        if len(manifest.name) > 64 or not _SKILL_NAME_PATTERN.fullmatch(manifest.name or ""):
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_INVALID_NAME", "manifest"),
                    rule_id="MANIFEST_INVALID_NAME",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Skill name does not follow agent skills naming rules",
                    description=(
                        f"Skill name '{manifest.name}' is invalid. Agent skills require lowercase letters, numbers, "
                        f"and hyphens only, with a maximum length of 64 characters."
                    ),
                    file_path="SKILL.md",
                    remediation="Rename the skill to match `[a-z0-9-]{1,64}` (e.g., 'pdf-processing')",
                    analyzer="static",
                )
            )

        if len(manifest.description or "") > 1024:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_DESCRIPTION_TOO_LONG", "manifest"),
                    rule_id="MANIFEST_DESCRIPTION_TOO_LONG",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Skill description exceeds agent skills length limit",
                    description=(
                        f"Skill description is {len(manifest.description)} characters; Agent skills limit the "
                        f"`description` field to 1024 characters."
                    ),
                    file_path="SKILL.md",
                    remediation="Shorten the description to 1024 characters or fewer while keeping it specific",
                    analyzer="static",
                )
            )

        if len(manifest.description) < 20:
            findings.append(
                Finding(
                    id=self._generate_finding_id("SOCIAL_ENG_VAGUE_DESCRIPTION", "manifest"),
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

        description_lower = manifest.description.lower()
        name_lower = manifest.name.lower()
        is_anthropic_mentioned = "anthropic" in name_lower or "anthropic" in description_lower

        if is_anthropic_mentioned:
            legitimate_patterns = ["apply", "brand", "guidelines", "colors", "typography", "style"]
            is_legitimate = any(pattern in description_lower for pattern in legitimate_patterns)

            if not is_legitimate:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("SOCIAL_ENG_ANTHROPIC_IMPERSONATION", "manifest"),
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

        if "claude official" in manifest.name.lower() or "claude official" in manifest.description.lower():
            findings.append(
                Finding(
                    id=self._generate_finding_id("SOCIAL_ENG_CLAUDE_OFFICIAL", "manifest"),
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

        if not manifest.license:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_MISSING_LICENSE", "manifest"),
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

    def _scan_instruction_body(self, skill: Skill) -> list[Finding]:
        """Scan SKILL.md instruction body for prompt injection patterns."""
        findings = []

        markdown_rules = self.rule_loader.get_rules_for_file_type("markdown")

        for rule in markdown_rules:
            matches = rule.scan_content(skill.instruction_body, "SKILL.md")
            for match in matches:
                findings.append(self._create_finding_from_match(rule, match))

        return findings

    def _scan_scripts(self, skill: Skill) -> list[Finding]:
        """Scan all script files (Python, Bash) for vulnerabilities."""
        findings = []

        for skill_file in skill.files:
            if skill_file.file_type not in ("python", "bash"):
                continue

            rules = self.rule_loader.get_rules_for_file_type(skill_file.file_type)

            content = skill_file.read_content()
            if not content:
                continue

            for rule in rules:
                matches = rule.scan_content(content, skill_file.relative_path)
                for match in matches:
                    if rule.id == "RESOURCE_ABUSE_INFINITE_LOOP" and skill_file.file_type == "python":
                        if self._is_loop_with_exception_handler(content, match["line_number"]):
                            continue
                    findings.append(self._create_finding_from_match(rule, match))

        return findings

    def _is_loop_with_exception_handler(self, content: str, loop_line_num: int) -> bool:
        """Check if a while True loop has an exception handler in surrounding context."""
        lines = content.split("\n")
        context_lines = lines[loop_line_num - 1 : min(loop_line_num + 20, len(lines))]
        context_text = "\n".join(context_lines)

        for pattern in _EXCEPTION_PATTERNS:
            if pattern.search(context_text):
                return True

        return False

    def _check_consistency(self, skill: Skill) -> list[Finding]:
        """Check for inconsistencies between manifest and actual behavior."""
        findings = []

        uses_network = self._skill_uses_network(skill)
        declared_network = self._manifest_declares_network(skill)

        if uses_network and not declared_network:
            findings.append(
                Finding(
                    id=self._generate_finding_id("TOOL_MISMATCH_NETWORK", skill.name),
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

        findings.extend(self._check_allowed_tools_violations(skill))

        if self._check_description_mismatch(skill):
            findings.append(
                Finding(
                    id=self._generate_finding_id("DESC_BEHAVIOR_MISMATCH", skill.name),
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

    def _scan_referenced_files(self, skill: Skill) -> list[Finding]:
        """Scan files referenced in instruction body with recursive scanning."""
        findings = []
        findings.extend(self._scan_references_recursive(skill, skill.referenced_files, max_depth=5))
        return findings

    def _scan_references_recursive(
        self,
        skill: Skill,
        references: list[str],
        max_depth: int = 5,
        current_depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[Finding]:
        """
        Recursively scan referenced files up to a maximum depth.

        This detects lazy-loaded content that might contain malicious patterns
        hidden in nested references.

        Args:
            skill: The skill being analyzed
            references: List of file paths to scan
            max_depth: Maximum recursion depth
            current_depth: Current depth in recursion
            visited: Set of already-visited files to prevent cycles

        Returns:
            List of findings from all referenced files
        """
        findings = []

        if visited is None:
            visited = set()

        if current_depth > max_depth:
            if references:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("LAZY_LOAD_DEEP", str(current_depth)),
                        rule_id="LAZY_LOAD_DEEP_NESTING",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Deeply nested file references detected",
                        description=(
                            f"Skill has file references nested more than {max_depth} levels deep. "
                            f"This could be an attempt to hide malicious content in files that are "
                            f"only loaded under specific conditions."
                        ),
                        file_path="SKILL.md",
                        remediation="Flatten the reference structure or ensure all nested files are safe",
                        analyzer="static",
                    )
                )
            return findings

        for ref_file_path in references:
            if ref_file_path in visited:
                continue
            visited.add(ref_file_path)

            full_path = skill.directory / ref_file_path
            if not full_path.exists():
                alt_paths = [
                    skill.directory / "references" / ref_file_path,
                    skill.directory / "assets" / ref_file_path,
                    skill.directory / "templates" / ref_file_path,
                    skill.directory / "scripts" / ref_file_path,
                ]
                for alt in alt_paths:
                    if alt.exists():
                        full_path = alt
                        break

            if not full_path.exists():
                continue

            try:
                with open(full_path, encoding="utf-8") as f:
                    content = f.read()

                suffix = full_path.suffix.lower()
                if suffix in (".md", ".markdown"):
                    rules = self.rule_loader.get_rules_for_file_type("markdown")
                elif suffix == ".py":
                    rules = self.rule_loader.get_rules_for_file_type("python")
                elif suffix in (".sh", ".bash"):
                    rules = self.rule_loader.get_rules_for_file_type("bash")
                else:
                    rules = []

                for rule in rules:
                    matches = rule.scan_content(content, ref_file_path)
                    for match in matches:
                        finding = self._create_finding_from_match(rule, match)
                        finding.metadata["reference_depth"] = current_depth
                        findings.append(finding)

                nested_refs = self._extract_references_from_content(full_path, content)
                if nested_refs:
                    findings.extend(
                        self._scan_references_recursive(skill, nested_refs, max_depth, current_depth + 1, visited)
                    )

            except Exception:
                pass

        return findings

    def _extract_references_from_content(self, file_path: Path, content: str) -> list[str]:
        """
        Extract file references from content based on file type.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of referenced file paths
        """
        references = []
        suffix = file_path.suffix.lower()

        if suffix in (".md", ".markdown"):
            markdown_links = _MARKDOWN_LINK_PATTERN.findall(content)
            for _, link in markdown_links:
                if not link.startswith(("http://", "https://", "ftp://", "#")):
                    references.append(link)

        elif suffix == ".py":
            import_patterns = _PYTHON_IMPORT_PATTERN.findall(content)
            for imp in import_patterns:
                if imp:
                    references.append(f"{imp}.py")

        elif suffix in (".sh", ".bash"):
            source_patterns = _BASH_SOURCE_PATTERN.findall(content)
            references.extend(source_patterns)

        return references

    def _check_binary_files(self, skill: Skill) -> list[Finding]:
        """Check for binary files in skill package."""
        findings = []

        ASSET_EXTENSIONS = {
            ".ttf",
            ".otf",
            ".woff",
            ".woff2",
            ".eot",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
            ".ico",
            ".bmp",
            ".tiff",
            ".tar.gz",
            ".tgz",
            ".zip",
        }

        for skill_file in skill.files:
            if skill_file.file_type == "binary":
                file_path_obj = Path(skill_file.relative_path)
                ext = file_path_obj.suffix.lower()
                if file_path_obj.name.endswith(".tar.gz"):
                    ext = ".tar.gz"

                if ext in ASSET_EXTENSIONS:
                    continue

                findings.append(
                    Finding(
                        id=self._generate_finding_id("BINARY_FILE_DETECTED", skill_file.relative_path),
                        rule_id="BINARY_FILE_DETECTED",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.INFO,
                        title="Binary file detected in skill package",
                        description=f"Binary file found: {skill_file.relative_path}. "
                        f"Binary files cannot be inspected by static analysis. "
                        f"Consider using Python or Bash scripts for transparency.",
                        file_path=skill_file.relative_path,
                        remediation="Review binary file necessity. Replace with auditable scripts if possible.",
                        analyzer="static",
                    )
                )

        return findings

    def _skill_uses_network(self, skill: Skill) -> bool:
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

    def _manifest_declares_network(self, skill: Skill) -> bool:
        """Check if manifest declares network usage."""
        if skill.manifest.compatibility:
            compatibility_lower = skill.manifest.compatibility.lower()
            return "network" in compatibility_lower or "internet" in compatibility_lower
        return False

    def _check_description_mismatch(self, skill: Skill) -> bool:
        """Check for description/behavior mismatch (basic heuristic)."""
        description = skill.description.lower()

        simple_keywords = ["calculator", "format", "template", "style", "lint"]
        if any(keyword in description for keyword in simple_keywords):
            if self._skill_uses_network(skill):
                return True

        return False

    def _check_allowed_tools_violations(self, skill: Skill) -> list[Finding]:
        """Check if code behavior violates allowed-tools restrictions."""
        findings = []

        if not skill.manifest.allowed_tools:
            return findings

        allowed_tools_lower = [tool.lower() for tool in skill.manifest.allowed_tools]

        if "read" not in allowed_tools_lower:
            if self._code_reads_files(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_READ_VIOLATION", skill.name),
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

        if "write" not in allowed_tools_lower:
            if self._code_writes_files(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_WRITE_VIOLATION", skill.name),
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

        if "bash" not in allowed_tools_lower:
            if self._code_executes_bash(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_BASH_VIOLATION", skill.name),
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

        # Note: ALLOWED_TOOLS_PYTHON_VIOLATION removed - too many false positives
        # Many skills include Python helper scripts that are NOT invoked directly by the agent
        # (e.g., build scripts, test files, utilities). The allowed-tools list controls what
        # the AGENT can use, not what helper scripts exist in the repo.
        # If direct Python execution is a concern, COMMAND_INJECTION_EVAL catches actual risks.

        if "grep" not in allowed_tools_lower:
            if self._code_uses_grep(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_GREP_VIOLATION", skill.name),
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

        if "glob" not in allowed_tools_lower:
            if self._code_uses_glob(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_GLOB_VIOLATION", skill.name),
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

        if self._code_uses_network(skill):
            findings.append(
                Finding(
                    id=self._generate_finding_id("ALLOWED_TOOLS_NETWORK_USAGE", skill.name),
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

    def _code_reads_files(self, skill: Skill) -> bool:
        """Check if code contains file reading operations."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _READ_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_writes_files(self, skill: Skill) -> bool:
        """Check if code contains file writing operations."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _WRITE_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_executes_bash(self, skill: Skill) -> bool:
        """Check if code executes bash/shell commands."""
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

        has_bash_scripts = any(f.file_type == "bash" for f in skill.files)
        if has_bash_scripts:
            return True

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if any(indicator in content for indicator in bash_indicators):
                return True
        return False

    def _code_uses_grep(self, skill: Skill) -> bool:
        """Check if code uses regex search/grep patterns."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _GREP_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_uses_glob(self, skill: Skill) -> bool:
        """Check if code uses glob/file pattern matching."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _GLOB_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_uses_network(self, skill: Skill) -> bool:
        """Check if code makes network requests."""
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

    def _scan_asset_files(self, skill: Skill) -> list[Finding]:
        """Scan files in assets/, templates/, and references/ directories for injection patterns."""
        findings = []

        ASSET_DIRS = ["assets", "templates", "references", "data"]

        ASSET_PATTERNS = [
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

        for skill_file in skill.files:
            path_parts = skill_file.relative_path.split("/")

            is_asset_file = (
                (len(path_parts) > 1 and path_parts[0] in ASSET_DIRS)
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

            for pattern, rule_id, severity, description in ASSET_PATTERNS:
                matches = list(pattern.finditer(content))

                for match in matches:
                    line_number = content[: match.start()].count("\n") + 1
                    line_content = content.split("\n")[line_number - 1] if content else ""

                    findings.append(
                        Finding(
                            id=self._generate_finding_id(rule_id, f"{skill_file.relative_path}:{line_number}"),
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

    def _create_finding_from_match(self, rule: SecurityRule, match: dict[str, Any]) -> Finding:
        """Create a Finding object from a rule match, aligned with AITech taxonomy."""
        threat_mapping = None
        try:
            threat_name = rule.category.value.upper().replace("_", " ")
            threat_mapping = ThreatMapping.get_threat_mapping("static", threat_name)
        except (ValueError, AttributeError):
            pass

        return Finding(
            id=self._generate_finding_id(rule.id, f"{match.get('file_path', 'unknown')}:{match.get('line_number', 0)}"),
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            title=rule.description,
            description=f"Pattern detected: {match.get('matched_text', 'N/A')}",
            file_path=match.get("file_path"),
            line_number=match.get("line_number"),
            snippet=match.get("line_content"),
            remediation=rule.remediation,
            analyzer="static",
            metadata={
                "matched_pattern": match.get("matched_pattern"),
                "matched_text": match.get("matched_text"),
                "aitech": threat_mapping.get("aitech") if threat_mapping else None,
                "aitech_name": threat_mapping.get("aitech_name") if threat_mapping else None,
                "scanner_category": threat_mapping.get("scanner_category") if threat_mapping else None,
            },
        )

    def _generate_finding_id(self, rule_id: str, context: str) -> str:
        """Generate a unique finding ID."""
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"

    def _yara_scan(self, skill: Skill) -> list[Finding]:
        """Scan skill files with YARA rules."""
        findings = []

        yara_matches = self.yara_scanner.scan_content(skill.instruction_body, "SKILL.md")
        for match in yara_matches:
            rule_name = match.get("rule_name", "")
            # Check if rule is enabled in current mode and not explicitly disabled
            if not self._is_rule_enabled(rule_name):
                continue
            findings.extend(self._create_findings_from_yara_match(match, skill))

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if content:
                yara_matches = self.yara_scanner.scan_content(content, skill_file.relative_path)
                for match in yara_matches:
                    rule_name = match.get("rule_name", "")
                    if rule_name == "capability_inflation_generic":
                        continue
                    findings.extend(self._create_findings_from_yara_match(match, skill, content))

        return findings

    def _create_findings_from_yara_match(
        self, match: dict[str, Any], skill: Skill, file_content: str | None = None
    ) -> list[Finding]:
        """Convert YARA match to Finding objects."""
        findings = []

        rule_name = match["rule_name"]
        namespace = match["namespace"]
        file_path = match["file_path"]
        meta = match["meta"].get("meta", {})

        category, severity = self._map_yara_rule_to_threat(rule_name, meta)

        SAFE_COMMANDS = {
            "soffice",
            "pandoc",
            "wkhtmltopdf",
            "convert",
            "gs",
            "pdftotext",
            "pdfinfo",
            "pdftoppm",
            "pdftohtml",
            "tesseract",
            "ffmpeg",
            "ffprobe",
            "zip",
            "unzip",
            "tar",
            "gzip",
            "gunzip",
            "bzip2",
            "bunzip2",
            "xz",
            "unxz",
            "7z",
            "7za",
            "gtimeout",
            "timeout",
            "grep",
            "head",
            "tail",
            "sort",
            "uniq",
            "wc",
            "file",
            "git",
        }

        SAFE_CLEANUP_DIRS = {
            "dist",
            "build",
            "tmp",
            "temp",
            ".tmp",
            ".temp",
            "bundle.html",
            "bundle.js",
            "bundle.css",
            "node_modules",
            ".next",
            ".nuxt",
            ".cache",
        }

        PLACEHOLDER_MARKERS = {
            "your-",
            "your_",
            "your ",
            "example",
            "sample",
            "dummy",
            "placeholder",
            "replace",
            "changeme",
            "change_me",
            "<your",
            "<insert",
        }

        for string_match in match["strings"]:
            # Skip exclusion patterns (these are used in YARA conditions but shouldn't create findings)
            string_identifier = string_match.get("identifier", "")
            if string_identifier.startswith("$documentation") or string_identifier.startswith("$safe"):
                continue

            if rule_name == "code_execution_generic":
                line_content = string_match.get("line_content", "").lower()
                matched_data = string_match.get("matched_data", "").lower()

                context_content = ""
                if file_content:
                    line_num = string_match.get("line_number", 0)
                    if line_num > 0:
                        lines = file_content.split("\n")
                        start_line = max(0, line_num - 4)
                        end_line = min(len(lines), line_num + 5)
                        context_content = "\n".join(lines[start_line:end_line]).lower()

                is_safe_command = any(
                    safe_cmd in line_content or safe_cmd in matched_data or safe_cmd in context_content
                    for safe_cmd in SAFE_COMMANDS
                )

                if is_safe_command:
                    continue

            if rule_name == "system_manipulation_generic":
                line_content = string_match.get("line_content", "").lower()

                if "rm -rf" in line_content or "rm -r" in line_content:
                    rm_targets = _RM_TARGET_PATTERN.findall(line_content)
                    if rm_targets:
                        all_safe = all(
                            any(safe_dir in target for safe_dir in SAFE_CLEANUP_DIRS) for target in rm_targets
                        )
                        if all_safe:
                            continue

            # Credential harvesting post-filters (controlled by mode)
            if rule_name == "credential_harvesting_generic":
                if self.yara_mode.credential_harvesting.filter_placeholder_patterns:
                    line_content = string_match.get("line_content", "")
                    matched_data = string_match.get("matched_data", "")
                    combined = f"{line_content} {matched_data}".lower()

                    if any(marker in combined for marker in PLACEHOLDER_MARKERS):
                        continue

                    if "export " in combined and "=" in combined:
                        _, value = combined.split("=", 1)
                        if any(marker in value for marker in PLACEHOLDER_MARKERS):
                            continue

            # Tool chaining post-filters (controlled by mode)
            if rule_name == "tool_chaining_abuse_generic":
                line_content = string_match.get("line_content", "")
                lower_line = line_content.lower()
                exfil_hints = ("send", "upload", "transmit", "webhook", "slack", "exfil", "forward")

                if self.yara_mode.tool_chaining.filter_generic_http_verbs:
                    if (
                        "get" in lower_line
                        and "post" in lower_line
                        and not any(hint in lower_line for hint in exfil_hints)
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_api_documentation:
                    if any(
                        token in line_content for token in ("@app.", "app.", "router.", "route", "endpoint")
                    ) and not any(hint in lower_line for hint in exfil_hints):
                        continue

                if self.yara_mode.tool_chaining.filter_email_field_mentions:
                    if "by email" in lower_line or "email address" in lower_line or "email field" in lower_line:
                        continue

            # Unicode steganography post-filters
            if rule_name == "prompt_injection_unicode_steganography":
                line_content = string_match.get("line_content", "")
                matched_data = string_match.get("matched_data", "")
                has_ascii_letters = any("A" <= char <= "Z" or "a" <= char <= "z" for char in line_content)

                # Filter short matches in non-Latin context (likely legitimate i18n)
                if len(matched_data) <= 2 and not has_ascii_letters:
                    continue

                # Filter if context suggests legitimate internationalization
                i18n_markers = ("i18n", "locale", "translation", "lang=", "charset", "utf-8", "encoding")
                if any(marker in line_content.lower() for marker in i18n_markers):
                    continue

                # Filter Cyrillic, CJK, Arabic, Hebrew text (legitimate non-Latin content)
                # These are indicated by presence of those scripts without zero-width chars
                cyrillic_cjk_pattern = any(
                    ("\u0400" <= char <= "\u04ff")  # Cyrillic
                    or ("\u4e00" <= char <= "\u9fff")  # CJK Unified
                    or ("\u0600" <= char <= "\u06ff")  # Arabic
                    or ("\u0590" <= char <= "\u05ff")  # Hebrew
                    for char in line_content
                )
                # If the line has legitimate non-Latin text but matched only 1-2 zero-width chars, skip
                if cyrillic_cjk_pattern and len(matched_data) < 10:
                    continue

            finding_id = self._generate_finding_id(f"YARA_{rule_name}", f"{file_path}:{string_match['line_number']}")

            description = meta.get("description", f"YARA rule {rule_name} matched")
            threat_type = meta.get("threat_type", "SECURITY THREAT")

            findings.append(
                Finding(
                    id=finding_id,
                    rule_id=f"YARA_{rule_name}",
                    category=category,
                    severity=severity,
                    title=f"{threat_type} detected by YARA",
                    description=f"{description}: {string_match['matched_data'][:100]}",
                    file_path=file_path,
                    line_number=string_match["line_number"],
                    snippet=string_match["line_content"],
                    remediation=f"Review and remove {threat_type.lower()} pattern",
                    analyzer="static",
                    metadata={
                        "yara_rule": rule_name,
                        "yara_namespace": namespace,
                        "matched_string": string_match["identifier"],
                        "threat_type": threat_type,
                    },
                )
            )

        return findings

    def _map_yara_rule_to_threat(self, rule_name: str, meta: dict[str, Any]) -> tuple:
        """Map YARA rule to ThreatCategory and Severity."""
        threat_type = meta.get("threat_type", "").upper()
        classification = meta.get("classification", "harmful")

        category_map = {
            "PROMPT INJECTION": ThreatCategory.PROMPT_INJECTION,
            "INJECTION ATTACK": ThreatCategory.COMMAND_INJECTION,
            "COMMAND INJECTION": ThreatCategory.COMMAND_INJECTION,
            "CREDENTIAL HARVESTING": ThreatCategory.HARDCODED_SECRETS,
            "DATA EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "SYSTEM MANIPULATION": ThreatCategory.UNAUTHORIZED_TOOL_USE,
            "CODE EXECUTION": ThreatCategory.COMMAND_INJECTION,
            "SQL INJECTION": ThreatCategory.COMMAND_INJECTION,
            "SKILL DISCOVERY ABUSE": ThreatCategory.SKILL_DISCOVERY_ABUSE,
            "TRANSITIVE TRUST ABUSE": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
            "AUTONOMY ABUSE": ThreatCategory.AUTONOMY_ABUSE,
            "TOOL CHAINING ABUSE": ThreatCategory.TOOL_CHAINING_ABUSE,
            "UNICODE STEGANOGRAPHY": ThreatCategory.UNICODE_STEGANOGRAPHY,
        }

        category = category_map.get(threat_type, ThreatCategory.POLICY_VIOLATION)

        if classification == "harmful":
            if "INJECTION" in threat_type or "CREDENTIAL" in threat_type:
                severity = Severity.CRITICAL
            elif "EXFILTRATION" in threat_type or "MANIPULATION" in threat_type:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return category, severity
