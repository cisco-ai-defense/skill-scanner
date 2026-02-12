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

from ...config.yara_modes import YaraModeConfig
from ...core.models import Finding, Severity, Skill, ThreatCategory
from ...core.rules.patterns import RuleLoader, SecurityRule
from ...core.rules.yara_scanner import YaraScanner
from ...core.scan_policy import ScanPolicy
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for file operation checks
_READ_PATTERNS = [
    re.compile(r"open\([^)]+['\"]r['\"]"),
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
_DEFAULT_SAFE_CLEANUP_DIRS = {
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
_DEFAULT_PLACEHOLDER_MARKERS = {
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


class StaticAnalyzer(BaseAnalyzer):
    """Static pattern-based security analyzer."""

    def __init__(
        self,
        rules_file: Path | None = None,
        use_yara: bool = True,
        yara_mode: YaraModeConfig | str | None = None,
        custom_yara_rules_path: str | Path | None = None,
        disabled_rules: set[str] | None = None,
        policy: ScanPolicy | None = None,
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
            policy: Scan policy for org-specific allowlists and rule scoping.
                If None, loads built-in defaults.
        """
        super().__init__("static_analyzer", policy=policy)

        # Unreferenced scripts are computed during _check_file_inventory()
        # and exposed to the scanner for LLM enrichment context (not as
        # standalone findings).
        self._unreferenced_scripts: list[str] = []

        self.rule_loader = RuleLoader(rules_file)
        self.rule_loader.load_rules()

        # Configure YARA mode.
        # When no explicit yara_mode is supplied, derive it from the policy's
        # ``preset_base`` so that ``--policy strict`` (or a custom policy
        # generated from the strict preset) automatically gets strict YARA
        # post-filtering.  ``preset_base`` is a stable field that survives
        # policy-name customisation (e.g. "acme-corp"), unlike
        # ``policy_name`` which is a user-facing display name.
        if yara_mode is None:
            preset = getattr(self.policy, "preset_base", "balanced")
            _PRESET_TO_YARA = {"strict": "strict", "permissive": "permissive"}
            mode_name = _PRESET_TO_YARA.get(preset, "balanced")
            self.yara_mode = YaraModeConfig.from_mode_name(mode_name)
        elif isinstance(yara_mode, str):
            self.yara_mode = YaraModeConfig.from_mode_name(yara_mode)
        else:
            self.yara_mode = yara_mode

        # Store disabled rules (merge CLI + mode + policy)
        self.disabled_rules = set(disabled_rules or set())
        self.disabled_rules.update(self.yara_mode.disabled_rules)
        self.disabled_rules.update(self.policy.disabled_rules)

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
        3. It's not in the policy's disabled_rules set

        Args:
            rule_name: Name of the rule to check (e.g., "YARA_script_injection")

        Returns:
            True if the rule is enabled, False otherwise
        """
        # Check mode-based enable/disable first
        if not self.yara_mode.is_rule_enabled(rule_name):
            return False

        # Check if explicitly disabled via policy or constructor
        if rule_name in self.disabled_rules:
            return False

        # Also check without YARA_ prefix for convenience
        base_name = rule_name.replace("YARA_", "") if rule_name.startswith("YARA_") else rule_name
        if base_name in self.disabled_rules:
            return False

        if rule_name in self.policy.disabled_rules:
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
        self._unreferenced_scripts = []  # reset per-scan enrichment state

        findings.extend(self._check_manifest(skill))
        findings.extend(self._scan_instruction_body(skill))
        findings.extend(self._scan_scripts(skill))
        findings.extend(self._check_consistency(skill))
        findings.extend(self._scan_referenced_files(skill))
        findings.extend(self._check_binary_files(skill))
        findings.extend(self._check_hidden_files(skill))
        findings.extend(self._check_file_inventory(skill))
        findings.extend(self._check_pdf_documents(skill))
        findings.extend(self._check_office_documents(skill))
        findings.extend(self._check_homoglyph_attacks(skill))

        if self.yara_scanner:
            findings.extend(self._yara_scan(skill))

        findings.extend(self._scan_asset_files(skill))

        # Filter out disabled rules (both explicitly disabled and via enabled=false knob)
        findings = [f for f in findings if self._is_rule_enabled(f.rule_id)]

        # Filter out well-known test/placeholder credentials
        findings = [f for f in findings if not self._is_known_test_credential(f)]

        return findings

    def get_unreferenced_scripts(self) -> list[str]:
        """Return unreferenced script paths computed during the last ``analyze()`` call.

        These are scripts present in the skill package that are not mentioned
        in SKILL.md.  They are stored as enrichment context for the LLM
        analyzer rather than emitted as standalone findings.
        """
        return list(self._unreferenced_scripts)

    def _is_known_test_credential(self, finding: Finding) -> bool:
        """Check if a finding matches a well-known test/placeholder credential (from policy)."""
        if finding.category != ThreatCategory.HARDCODED_SECRETS:
            return False
        snippet = finding.snippet or ""
        for cred in self.policy.credentials.known_test_values:
            if cred in snippet:
                return True
        return False

    def _is_doc_file(self, rel_path: str) -> bool:
        """Check if a file is in a documentation directory or is an educational file.

        Uses ``doc_path_indicators`` and ``doc_filename_patterns`` from the
        active scan policy to determine if a given relative path belongs to a
        documentation or example area (e.g. ``docs/``, ``examples/``).
        """
        path_obj = Path(rel_path)
        parts = path_obj.parts
        doc_indicators = self.policy.rule_scoping.doc_path_indicators
        if any(p.lower() in doc_indicators for p in parts):
            return True
        doc_re = self.policy._compiled_doc_filename_re
        if doc_re and doc_re.search(path_obj.stem):
            return True
        return False

    def _check_manifest(self, skill: Skill) -> list[Finding]:
        """Validate skill manifest for security issues."""
        findings = []
        manifest = skill.manifest

        max_name_length = self.policy.file_limits.max_name_length
        if len(manifest.name) > max_name_length or not _SKILL_NAME_PATTERN.fullmatch(manifest.name or ""):
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_INVALID_NAME", "manifest"),
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

        max_desc_length = self.policy.file_limits.max_description_length
        if len(manifest.description or "") > max_desc_length:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_DESCRIPTION_TOO_LONG", "manifest"),
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

        min_desc_length = self.policy.file_limits.min_description_length
        if len(manifest.description or "") < min_desc_length:
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
        skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)

        for skill_file in skill.files:
            if skill_file.file_type not in ("python", "bash"):
                continue

            rules = self.rule_loader.get_rules_for_file_type(skill_file.file_type)

            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._is_doc_file(skill_file.relative_path)

            for rule in rules:
                # Skip rules scoped out of documentation files
                if is_doc and rule.id in skip_in_docs:
                    continue
                matches = rule.scan_content(content, skill_file.relative_path)
                for match in matches:
                    if rule.id == "RESOURCE_ABUSE_INFINITE_LOOP" and skill_file.file_type == "python":
                        if self._is_loop_with_exception_handler(content, match["line_number"]):
                            continue
                    findings.append(self._create_finding_from_match(rule, match))

        return findings

    def _is_loop_with_exception_handler(self, content: str, loop_line_num: int) -> bool:
        """Check if a while True loop has an exception handler in surrounding context."""
        context_size = self.policy.analysis_thresholds.exception_handler_context_lines
        lines = content.split("\n")
        context_lines = lines[loop_line_num - 1 : min(loop_line_num + context_size, len(lines))]
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
        max_depth = self.policy.file_limits.max_reference_depth
        findings = []
        findings.extend(self._scan_references_recursive(skill, skill.referenced_files, max_depth=max_depth))
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

                skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)
                is_doc = self._is_doc_file(ref_file_path)

                for rule in rules:
                    # Skip rules scoped out of documentation files
                    if is_doc and rule.id in skip_in_docs:
                        continue
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
        """Check for binary files in skill package with tiered asset classification and magic byte validation."""
        from ..file_magic import check_extension_mismatch

        findings = []

        # Extension classifications from policy (org-customisable)
        INERT_EXTENSIONS = self.policy.file_classification.inert_extensions
        STRUCTURED_EXTENSIONS = self.policy.file_classification.structured_extensions
        ARCHIVE_EXTENSIONS = self.policy.file_classification.archive_extensions

        min_confidence = self.policy.analysis_thresholds.min_confidence_pct / 100.0

        for skill_file in skill.files:
            file_path_obj = Path(skill_file.relative_path)
            ext = file_path_obj.suffix.lower()
            if file_path_obj.name.endswith(".tar.gz"):
                ext = ".tar.gz"

            # Run file magic mismatch check on ALL files with known extensions
            # (regardless of whether they're classified as binary)
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
                            id=self._generate_finding_id("FILE_MAGIC_MISMATCH", skill_file.relative_path),
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
                # SVGs will be scanned by multimodal analyzer for embedded scripts
                # Just note their presence for now
                continue

            if ext in ARCHIVE_EXTENSIONS:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ARCHIVE_FILE_DETECTED", skill_file.relative_path),
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

            # Unknown binary file - informational only
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

    def _check_hidden_files(self, skill: Skill) -> list[Finding]:
        """Check for hidden files (dotfiles) and __pycache__ in skill package."""
        findings = []

        # Code extensions from policy (org-customisable)
        CODE_EXTENSIONS = self.policy.file_classification.code_extensions

        # Use policy-defined allowlists (org-customisable)
        benign_dotfiles = self.policy.hidden_files.benign_dotfiles
        benign_dotdirs = self.policy.hidden_files.benign_dotdirs

        # Track pycache directories already flagged (consolidate to one finding per dir)
        flagged_pycache_dirs: set[str] = set()

        for skill_file in skill.files:
            rel_path = skill_file.relative_path
            path_obj = Path(rel_path)

            if skill_file.is_pycache:
                # Consolidate: one finding per __pycache__ directory, not per file
                pycache_dir = str(path_obj.parent)
                if pycache_dir in flagged_pycache_dirs:
                    continue
                flagged_pycache_dirs.add(pycache_dir)

                # Count how many .pyc files are in this directory
                pyc_count = sum(
                    1 for sf in skill.files if sf.is_pycache and str(Path(sf.relative_path).parent) == pycache_dir
                )

                findings.append(
                    Finding(
                        id=self._generate_finding_id("PYCACHE_FILES_DETECTED", pycache_dir),
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

                # Skip known benign dotfiles (from policy)
                if filename.lower() in benign_dotfiles:
                    continue

                # Skip files inside known benign hidden directories (from policy)
                hidden_parts = [p for p in parts if p.startswith(".") and p != "."]
                if any(p.lower() in benign_dotdirs for p in hidden_parts):
                    continue

                if ext in CODE_EXTENSIONS:
                    findings.append(
                        Finding(
                            id=self._generate_finding_id("HIDDEN_EXECUTABLE_SCRIPT", rel_path),
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
                    # Unknown hidden data/config file
                    findings.append(
                        Finding(
                            id=self._generate_finding_id("HIDDEN_DATA_FILE", rel_path),
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
        """Scan ALL skill files with YARA rules (full-tree scan).

        Scans:
        - SKILL.md instruction body
        - All text-readable files (scripts, markdown, configs, etc.)
        - Binary files are scanned by YARA directly on disk if the scanner supports it
        """
        findings = []

        # Scan SKILL.md instruction body
        yara_matches = self.yara_scanner.scan_content(skill.instruction_body, "SKILL.md")
        for match in yara_matches:
            rule_name = match.get("rule_name", "")
            if not self._is_rule_enabled(rule_name):
                continue
            # embedded_shebang_in_binary only applies to binary files, not text
            if rule_name == "embedded_shebang_in_binary":
                continue
            findings.extend(self._create_findings_from_yara_match(match, skill))

        # Use policy-defined rule scoping (org-customisable)
        _SKILLMD_AND_SCRIPTS_ONLY = self.policy.rule_scoping.skillmd_and_scripts_only
        _SCRIPT_ONLY_YARA_RULES = self.policy.rule_scoping.skip_in_docs
        _CODE_ONLY_YARA_RULES = self.policy.rule_scoping.code_only

        def _is_skillmd_or_script(skill_file) -> bool:
            """Check if this is SKILL.md or an executable script."""
            return (
                skill_file.relative_path == "SKILL.md"
                or skill_file.file_type in ("python", "bash")
                or Path(skill_file.relative_path).suffix.lower() in {".py", ".sh", ".bash", ".rb", ".pl", ".js", ".ts"}
            )

        # Track which files have been scanned
        scanned_files = {"SKILL.md"}

        # Scan ALL files, not just scripts
        for skill_file in skill.files:
            if skill_file.relative_path in scanned_files:
                continue
            scanned_files.add(skill_file.relative_path)

            if skill_file.file_type == "binary":
                # For binary files, scan with YARA directly on disk.
                # scan_file() handles both text and binary: it tries UTF-8
                # first, then falls back to YARA's native filepath matcher.
                if skill_file.path.exists():
                    # Determine if this binary has an inert extension (images,
                    # fonts, databases) — used to suppress noisy shebang rule.
                    _ext = skill_file.path.suffix.lower()
                    _inert_exts = set(self.policy.file_classification.inert_extensions)
                    _is_inert = _ext in _inert_exts
                    _skip_shebang_inert = self.policy.file_classification.skip_inert_extensions
                    try:
                        yara_matches = self.yara_scanner.scan_file(
                            skill_file.path,
                            display_path=skill_file.relative_path,
                        )
                        for match in yara_matches:
                            rule_name = match.get("rule_name", "")
                            if not self._is_rule_enabled(rule_name):
                                continue
                            # Skip shebang-in-binary for inert file types (images,
                            # fonts, databases) — shebang-like bytes are coincidental.
                            if rule_name == "embedded_shebang_in_binary" and _is_inert and _skip_shebang_inert:
                                continue
                            findings.extend(self._create_findings_from_yara_match(match, skill))
                    except Exception as e:
                        logger.debug("YARA binary scan failed for %s: %s", skill_file.relative_path, e)
                continue

            # For text files, read content and scan
            content = skill_file.read_content()
            if content:
                is_doc = self._is_doc_file(skill_file.relative_path)

                yara_matches = self.yara_scanner.scan_content(content, skill_file.relative_path)
                for match in yara_matches:
                    rule_name = match.get("rule_name", "")
                    if rule_name == "capability_inflation_generic":
                        continue
                    if not self._is_rule_enabled(rule_name):
                        continue

                    # Most restrictive: only SKILL.md and scripts
                    if rule_name in _SKILLMD_AND_SCRIPTS_ONLY:
                        if not _is_skillmd_or_script(skill_file):
                            continue

                    # Skip script-specific YARA rules for documentation files
                    if is_doc and rule_name in _SCRIPT_ONLY_YARA_RULES:
                        continue

                    # Skip code-only YARA rules for non-script files (markdown, configs)
                    is_non_script = skill_file.file_type not in ("python", "bash")
                    if is_non_script and rule_name in _CODE_ONLY_YARA_RULES:
                        # Exception: SKILL.md is already scanned above
                        continue

                    # embedded_shebang_in_binary is only meaningful for binary files;
                    # text files (markdown, scripts) legitimately contain shebangs in
                    # code blocks, examples, and documentation.
                    if rule_name == "embedded_shebang_in_binary":
                        continue  # text files always skip; binary files handled above

                    findings.extend(self._create_findings_from_yara_match(match, skill, content))

        # Post-filter: apply policy zero-width steganography thresholds
        # The YARA rule has built-in thresholds (50 with decode, 200 alone).
        # The policy allows raising these thresholds (more permissive) to reduce FPs.
        zw_threshold_decode = self.policy.analysis_thresholds.zerowidth_threshold_with_decode
        zw_threshold_alone = self.policy.analysis_thresholds.zerowidth_threshold_alone

        if zw_threshold_decode != 50 or zw_threshold_alone != 200:
            # Only run this expensive check if policy overrides the default thresholds
            steg_files: set[str] = set()
            for f in findings:
                if f.rule_id == "YARA_prompt_injection_unicode_steganography" and f.file_path:
                    steg_files.add(f.file_path)

            if steg_files:
                _ZW_CHARS = frozenset("\u200b\u200c\u200d")
                _DECODE_PATTERNS = ("atob", "unescape", "fromCharCode", "base64", "decode")
                suppressed_files: set[str] = set()

                for rel_path in steg_files:
                    sf = next((s for s in skill.files if s.relative_path == rel_path), None)
                    if sf is None:
                        continue
                    content = sf.read_content()
                    if content is None:
                        continue
                    zw_count = sum(1 for ch in content if ch in _ZW_CHARS)
                    has_decode = any(pat in content for pat in _DECODE_PATTERNS)
                    threshold = zw_threshold_decode if has_decode else zw_threshold_alone
                    if zw_count <= threshold:
                        suppressed_files.add(rel_path)

                if suppressed_files:
                    findings = [
                        f
                        for f in findings
                        if not (
                            f.rule_id == "YARA_prompt_injection_unicode_steganography"
                            and f.file_path in suppressed_files
                        )
                    ]

        return findings

    # ------------------------------------------------------------------
    # OSS-powered document & homoglyph scanners
    # ------------------------------------------------------------------

    def _check_pdf_documents(self, skill: Skill) -> list[Finding]:
        """Scan PDF files using pdfid for structural analysis of suspicious elements.

        Uses Didier Stevens' pdfid library to detect /JS, /JavaScript,
        /OpenAction, /AA, /Launch and other markers that indicate embedded
        executable content inside PDF documents.
        """
        if "PDF_STRUCTURAL_THREAT" in self.policy.disabled_rules:
            return []

        try:
            from pdfid import pdfid as pdfid_mod  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("pdfid not installed – skipping structural PDF scan")
            return []

        findings: list[Finding] = []

        # Suspicious PDF keywords and their severity mapping
        suspicious_keywords: dict[str, tuple[Severity, str]] = {
            "/JS": (Severity.CRITICAL, "Embedded JavaScript code"),
            "/JavaScript": (Severity.CRITICAL, "JavaScript action dictionary"),
            "/OpenAction": (Severity.HIGH, "Auto-execute action on open"),
            "/AA": (Severity.HIGH, "Additional actions (auto-trigger)"),
            "/Launch": (Severity.CRITICAL, "Launch external application"),
            "/EmbeddedFile": (Severity.MEDIUM, "Embedded file attachment"),
            "/RichMedia": (Severity.MEDIUM, "Rich media (Flash/video) content"),
            "/XFA": (Severity.MEDIUM, "XFA form (can contain scripts)"),
            "/AcroForm": (Severity.LOW, "Interactive form fields"),
        }

        for sf in skill.files:
            # Target PDF files by extension or content family
            is_pdf = (
                sf.path.suffix.lower() == ".pdf"
                or sf.file_type in ("binary", "other")
                and sf.path.exists()
                and sf.path.stat().st_size > 4
                and sf.path.read_bytes()[:5] == b"%PDF-"
            )
            if not is_pdf or not sf.path.exists():
                continue

            try:
                # pdfid returns a xml.dom.minidom Document; parse keyword counts
                xml_doc = pdfid_mod.PDFiD(str(sf.path), disarm=False)
                if xml_doc is None:
                    continue

                # Check that pdfid considers this a valid PDF
                pdfid_elem = xml_doc.getElementsByTagName("PDFiD")
                if pdfid_elem and pdfid_elem[0].getAttribute("IsPDF") != "True":
                    continue

                # Extract keyword counts from the minidom XML structure
                detected: list[tuple[str, int, Severity, str]] = []
                for keyword_elem in xml_doc.getElementsByTagName("Keyword"):
                    name = keyword_elem.getAttribute("Name")
                    count = int(keyword_elem.getAttribute("Count") or "0")
                    if count > 0 and name in suspicious_keywords:
                        severity, desc = suspicious_keywords[name]
                        detected.append((name, count, severity, desc))

                if not detected:
                    continue

                # Use highest severity among all detected keywords
                _SEV_ORDER = {
                    Severity.CRITICAL: 5,
                    Severity.HIGH: 4,
                    Severity.MEDIUM: 3,
                    Severity.LOW: 2,
                    Severity.INFO: 1,
                }
                max_severity = max(detected, key=lambda d: _SEV_ORDER.get(d[2], 0))[2]
                keyword_summary = ", ".join(f"{name} ({count}x)" for name, count, _, _ in detected)
                detail_lines = "\n".join(
                    f"  - {name}: {desc} (found {count} occurrence(s))" for name, count, _, desc in detected
                )

                findings.append(
                    Finding(
                        id=self._generate_finding_id("PDF_STRUCTURAL_THREAT", sf.relative_path),
                        rule_id="PDF_STRUCTURAL_THREAT",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=max_severity,
                        title="PDF contains suspicious structural elements",
                        description=(
                            f"Structural analysis of '{sf.relative_path}' detected "
                            f"suspicious PDF keywords: {keyword_summary}.\n{detail_lines}\n"
                            f"These elements can execute code when the PDF is opened."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove JavaScript actions and auto-execute triggers from PDF files. "
                            "PDF files in skill packages should contain only static content."
                        ),
                        analyzer="static",
                        metadata={
                            "detected_keywords": {name: count for name, count, _, _ in detected},
                            "analysis_method": "pdfid_structural",
                        },
                    )
                )

            except Exception as e:
                logger.debug("pdfid analysis failed for %s: %s", sf.relative_path, e)

        return findings

    def _check_office_documents(self, skill: Skill) -> list[Finding]:
        """Scan Office documents for VBA macros and suspicious OLE indicators.

        Uses oletools (oleid) to detect macros, auto-executable triggers,
        embedded OLE objects, and encrypted content in Office files.
        """
        if "OFFICE_DOCUMENT_THREAT" in self.policy.disabled_rules:
            return []

        try:
            from oletools.oleid import OleID  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("oletools not installed – skipping Office document scan")
            return []

        findings: list[Finding] = []

        # Office file extensions
        office_extensions = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".odt",
            ".ods",
            ".odp",
        }

        for sf in skill.files:
            ext = sf.path.suffix.lower()
            if ext not in office_extensions or not sf.path.exists():
                continue

            try:
                oid = OleID(str(sf.path))
                indicators = oid.check()

                has_macros = False
                is_encrypted = False
                suspicious_indicators: list[str] = []

                for indicator in indicators:
                    ind_id = getattr(indicator, "id", "")
                    ind_value = getattr(indicator, "value", None)
                    ind_name = getattr(indicator, "name", str(indicator))

                    if ind_id == "vba_macros" and ind_value:
                        has_macros = True
                        suspicious_indicators.append(f"VBA macros detected: {ind_value}")
                    elif ind_id == "xlm_macros" and ind_value:
                        has_macros = True
                        suspicious_indicators.append(f"XLM/Excel4 macros detected: {ind_value}")
                    elif ind_id == "encrypted" and ind_value:
                        is_encrypted = True
                        suspicious_indicators.append(f"Document is encrypted: {ind_value}")
                    elif ind_id == "flash" and ind_value:
                        suspicious_indicators.append(f"Embedded Flash content: {ind_value}")
                    elif ind_id == "ObjectPool" and ind_value:
                        suspicious_indicators.append(f"Embedded OLE objects: {ind_value}")
                    elif ind_id == "ext_rels" and ind_value:
                        suspicious_indicators.append(f"External relationships: {ind_value}")

                if not suspicious_indicators:
                    continue

                # Determine severity
                if has_macros:
                    severity = Severity.CRITICAL
                    title = "Office document contains VBA macros"
                elif is_encrypted:
                    severity = Severity.HIGH
                    title = "Office document is encrypted (resists analysis)"
                else:
                    severity = Severity.MEDIUM
                    title = "Office document contains suspicious indicators"

                findings.append(
                    Finding(
                        id=self._generate_finding_id("OFFICE_DOCUMENT_THREAT", sf.relative_path),
                        rule_id="OFFICE_DOCUMENT_THREAT",
                        category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                        severity=severity,
                        title=title,
                        description=(
                            f"Analysis of '{sf.relative_path}' detected:\n"
                            + "\n".join(f"  - {s}" for s in suspicious_indicators)
                            + "\nMalicious macros in Office documents can execute code "
                            "when the agent processes the file."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove VBA macros from Office documents. Use plain text, "
                            "Markdown, or macro-free formats (.docx, .xlsx) instead."
                        ),
                        analyzer="static",
                        metadata={
                            "has_macros": has_macros,
                            "is_encrypted": is_encrypted,
                            "indicators": suspicious_indicators,
                            "analysis_method": "oletools_oleid",
                        },
                    )
                )

            except Exception as e:
                logger.debug("oleid analysis failed for %s: %s", sf.relative_path, e)

        return findings

    def _check_homoglyph_attacks(self, skill: Skill) -> list[Finding]:
        """Detect Unicode homoglyph attacks in code files.

        Uses the confusable-homoglyphs library (backed by Unicode Consortium's
        confusables.txt) to identify characters that look identical to ASCII
        but are from different scripts (e.g., Cyrillic 'a' vs Latin 'a').
        """
        try:
            from confusable_homoglyphs import confusables  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("confusable-homoglyphs not installed – skipping homoglyph check")
            return []

        findings: list[Finding] = []

        # Only scan executable code files where homoglyphs can evade pattern
        # matching.  Markdown is excluded because legitimate multilingual prose
        # (CJK, Cyrillic, Arabic mixed with Latin) triggers massive FPs.
        code_file_types = {"python", "bash"}

        # Code-like tokens that suggest a line is an identifier / expression,
        # not natural-language prose (used for additional filtering).
        _CODE_TOKEN_RE = re.compile(r"[=\(\)\[\]\{\};]|import |def |class |if |for |while |return |print\(")

        for sf in skill.files:
            if sf.file_type not in code_file_types:
                continue

            content = sf.read_content()
            if not content:
                continue

            # Check each line for mixed-script homoglyphs
            dangerous_lines: list[tuple[int, str, list[dict]]] = []

            for line_num, line in enumerate(content.split("\n"), 1):
                # Skip comments and empty lines
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue

                # Only check lines that contain non-ASCII characters
                if stripped.isascii():
                    continue

                # Heuristic: in code files, only flag lines that look like code
                # (have operators, parens, etc.) — skip i18n strings
                if not _CODE_TOKEN_RE.search(stripped):
                    continue

                # Check for confusable characters
                result = confusables.is_dangerous(stripped, preferred_aliases=["LATIN"])
                if result:
                    dangerous_lines.append((line_num, stripped, result))

            # Require multiple dangerous lines to reduce single-line i18n FPs.
            # A genuine homoglyph attack typically uses confusables across
            # several identifiers / expressions.
            min_dangerous_lines = self.policy.analysis_thresholds.min_dangerous_lines
            if len(dangerous_lines) < min_dangerous_lines:
                continue

            # Report the first few dangerous lines (avoid noise)
            reported = dangerous_lines[:5]
            line_details = "\n".join(f"  - Line {ln}: {text[:80]}" for ln, text, _ in reported)
            extra = ""
            if len(dangerous_lines) > 5:
                extra = f"\n  ... and {len(dangerous_lines) - 5} more lines"

            findings.append(
                Finding(
                    id=self._generate_finding_id("HOMOGLYPH_ATTACK", sf.relative_path),
                    rule_id="HOMOGLYPH_ATTACK",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Unicode homoglyph characters detected in code",
                    description=(
                        f"File '{sf.relative_path}' contains characters from mixed Unicode "
                        f"scripts that are visually identical to ASCII letters. "
                        f"This technique can bypass pattern-matching security rules.\n"
                        f"{line_details}{extra}"
                    ),
                    file_path=sf.relative_path,
                    line_number=reported[0][0],
                    remediation=(
                        "Replace all non-ASCII lookalike characters with their ASCII "
                        "equivalents. All code should use standard Latin characters."
                    ),
                    analyzer="static",
                    metadata={
                        "affected_lines": len(dangerous_lines),
                        "analysis_method": "confusable_homoglyphs",
                    },
                )
            )

        return findings

    def _check_file_inventory(self, skill: Skill) -> list[Finding]:
        """Analyze the file inventory of the skill package for anomalies."""
        findings = []

        if not skill.files:
            return findings

        # Count file types
        type_counts: dict[str, int] = {}
        ext_counts: dict[str, int] = {}
        total_size = 0
        largest_file = None
        largest_size = 0

        for sf in skill.files:
            file_type = sf.file_type
            type_counts[file_type] = type_counts.get(file_type, 0) + 1

            ext = sf.path.suffix.lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

            total_size += sf.size_bytes
            if sf.size_bytes > largest_size:
                largest_size = sf.size_bytes
                largest_file = sf

        # Check for excessive file count (possible resource waste)
        max_file_count = self.policy.file_limits.max_file_count
        if len(skill.files) > max_file_count:
            findings.append(
                Finding(
                    id=self._generate_finding_id("EXCESSIVE_FILE_COUNT", str(len(skill.files))),
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

        # Check for oversized individual files
        max_file_size = self.policy.file_limits.max_file_size_bytes
        if largest_file and largest_size > max_file_size:
            findings.append(
                Finding(
                    id=self._generate_finding_id("OVERSIZED_FILE", largest_file.relative_path),
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

        # Check for unreferenced script files (hidden functionality)
        code_extensions = self.policy.file_classification.code_extensions

        # Build the set of referenced file names (from SKILL.md)
        referenced_lower = {r.lower() for r in skill.referenced_files}

        # Expand references transitively: scripts imported by referenced scripts
        # are considered indirectly referenced (not hidden functionality)
        _import_re = re.compile(r"^(?:from\s+\.?(\w[\w.]*)\s+import|import\s+\.?(\w[\w.]*))", re.MULTILINE)
        _source_re = re.compile(r"(?:source|\.)\s+[\"']?([A-Za-z0-9_\-./]+\.(?:sh|bash))[\"']?")
        expanded_refs: set[str] = set(referenced_lower)
        for sf in skill.files:
            if sf.relative_path.lower() not in referenced_lower:
                fn = Path(sf.relative_path).name.lower()
                if fn not in referenced_lower and fn not in skill.instruction_body.lower():
                    continue  # this file itself isn't referenced
            content = sf.read_content()
            if not content:
                continue
            # Python: from X import Y → X.py is transitively referenced
            if sf.file_type == "python":
                for m in _import_re.finditer(content):
                    mod = (m.group(1) or m.group(2) or "").replace(".", "/")
                    if mod:
                        expanded_refs.add(f"{mod}.py")
                        expanded_refs.add(mod.split("/")[-1] + ".py")
            # Bash: source X.sh → X.sh is transitively referenced
            elif sf.file_type == "bash":
                for m in _source_re.finditer(content):
                    expanded_refs.add(m.group(1).lower())
                    expanded_refs.add(Path(m.group(1)).name.lower())

        # Well-known filenames that are almost never referenced in SKILL.md
        # but serve standard structural roles in Python/JS projects
        _BENIGN_FILENAMES = {
            "__init__.py",
            "__main__.py",
            "conftest.py",
            "setup.py",
            "setup.cfg",
            "manage.py",
            "wsgi.py",
            "asgi.py",
            "fabfile.py",
            "noxfile.py",
            "tasks.py",
            "makefile",
            "rakefile",
            "gulpfile.js",
            "gruntfile.js",
            "webpack.config.js",
            "tsconfig.json",
            "jest.config.js",
            "babel.config.js",
            ".eslintrc.js",
            "vite.config.js",
        }
        # Patterns for test files that are structural, not hidden functionality
        _TEST_FILE_RE = re.compile(r"^(?:test_|tests_).*\.py$|^.*_test\.py$|^conftest\.py$", re.IGNORECASE)

        for sf in skill.files:
            if sf.file_type in ("python", "bash") or sf.path.suffix.lower() in code_extensions:
                rel = sf.relative_path
                # Skip SKILL.md itself
                if rel.lower() == "skill.md":
                    continue
                filename = Path(rel).name
                filename_lower = filename.lower()

                # Skip well-known structural files (not hidden functionality)
                if filename_lower in _BENIGN_FILENAMES:
                    continue

                # Skip test files (test infrastructure, not hidden functionality)
                if _TEST_FILE_RE.match(filename):
                    continue

                # Check if referenced in SKILL.md (directly or transitively)
                is_referenced = (
                    rel.lower() in expanded_refs
                    or filename_lower in expanded_refs
                    or any(ref in rel.lower() for ref in expanded_refs if ref)
                    or filename_lower in skill.instruction_body.lower()
                )
                if not is_referenced:
                    # Store for LLM enrichment context instead of emitting
                    # a standalone finding (too noisy — ~95% FP in corpus).
                    self._unreferenced_scripts.append(rel)

        # Check for archives that contain executable scripts
        for sf in skill.files:
            if sf.extracted_from and sf.file_type in ("python", "bash"):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ARCHIVE_CONTAINS_EXECUTABLE", sf.relative_path),
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

        from ..command_safety import evaluate_command

        safe_cleanup_dirs = self.policy.system_cleanup.safe_rm_targets or _DEFAULT_SAFE_CLEANUP_DIRS
        placeholder_markers = self.policy.credentials.placeholder_markers or _DEFAULT_PLACEHOLDER_MARKERS

        for string_match in match["strings"]:
            # Skip exclusion patterns (these are used in YARA conditions but shouldn't create findings)
            string_identifier = string_match.get("identifier", "")
            if string_identifier.startswith("$documentation") or string_identifier.startswith("$safe"):
                continue

            if rule_name == "code_execution_generic":
                line_content = string_match.get("line_content", "").lower()
                matched_data = string_match.get("matched_data", "").lower()

                # Use context-aware command safety evaluation
                # Try to extract a command from the matched content
                cmd_to_eval = matched_data.strip() or line_content.strip()
                verdict = evaluate_command(cmd_to_eval, policy=self.policy)
                if verdict.should_suppress_yara:
                    continue

            if rule_name == "system_manipulation_generic":
                line_content = string_match.get("line_content", "").lower()

                if "rm -rf" in line_content or "rm -r" in line_content:
                    rm_targets = _RM_TARGET_PATTERN.findall(line_content)
                    if rm_targets:
                        all_safe = all(
                            any(safe_dir in target for safe_dir in safe_cleanup_dirs) for target in rm_targets
                        )
                        if all_safe:
                            continue

            # Credential harvesting post-filters (controlled by mode)
            if rule_name == "credential_harvesting_generic":
                if self.yara_mode.credential_harvesting.filter_placeholder_patterns:
                    line_content = string_match.get("line_content", "")
                    matched_data = string_match.get("matched_data", "")
                    combined = f"{line_content} {matched_data}".lower()

                    if any(marker in combined for marker in placeholder_markers):
                        continue

                    if "export " in combined and "=" in combined:
                        _, value = combined.split("=", 1)
                        if any(marker in value for marker in placeholder_markers):
                            continue

            # Tool chaining post-filters (controlled by mode + policy pipeline)
            if rule_name == "tool_chaining_abuse_generic":
                line_content = string_match.get("line_content", "")
                lower_line = line_content.lower()
                exfil_raw = ",".join(self.policy.pipeline.exfil_hints)
                exfil_hints = tuple(h.strip() for h in exfil_raw.split(","))

                if self.yara_mode.tool_chaining.filter_generic_http_verbs:
                    if (
                        "get" in lower_line
                        and "post" in lower_line
                        and not any(hint in lower_line for hint in exfil_hints)
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_api_documentation:
                    api_raw = ",".join(self.policy.pipeline.api_doc_tokens)
                    api_doc_tokens = tuple(t.strip() for t in api_raw.split(","))
                    if any(token in line_content for token in api_doc_tokens) and not any(
                        hint in lower_line for hint in exfil_hints
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_email_field_mentions:
                    if "by email" in lower_line or "email address" in lower_line or "email field" in lower_line:
                        continue

            # Unicode steganography post-filters
            if rule_name == "prompt_injection_unicode_steganography":
                _steg_rule_id = "YARA_prompt_injection_unicode_steganography"
                line_content = string_match.get("line_content", "")
                matched_data = string_match.get("matched_data", "")
                has_ascii_letters = any("A" <= char <= "Z" or "a" <= char <= "z" for char in line_content)

                # Filter short matches in non-Latin context (likely legitimate i18n)
                short_match_max = self.policy.analysis_thresholds.short_match_max_chars
                if len(matched_data) <= short_match_max and not has_ascii_letters:
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
                # If the line has legitimate non-Latin text but matched only a few zero-width chars, skip
                cyrillic_cjk_min = self.policy.analysis_thresholds.cyrillic_cjk_min_chars
                if cyrillic_cjk_pattern and len(matched_data) < cyrillic_cjk_min:
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
