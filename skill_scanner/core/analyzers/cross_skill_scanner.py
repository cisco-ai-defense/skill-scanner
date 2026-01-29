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
Cross-skill scanner for detecting coordinated attacks across multiple skills.

This analyzer looks for patterns that suggest multiple skills are working together
to perform malicious activities, such as:
- Data relay patterns (one skill collects data, another exfiltrates)
- Shared external URLs across skills
- Complementary trigger descriptions
"""

import re

from ..models import Finding, Severity, Skill, ThreatCategory
from .base import BaseAnalyzer


class CrossSkillScanner(BaseAnalyzer):
    """
    Analyzes multiple skills together to detect coordinated attack patterns.

    This analyzer is designed to be run on a collection of skills rather than
    a single skill, looking for suspicious patterns that only emerge when
    analyzing skills in relation to each other.
    """

    def __init__(self):
        """Initialize cross-skill scanner."""
        super().__init__("cross_skill_scanner")
        self._skills: list[Skill] = []

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze a single skill (no-op for cross-skill scanner).

        This analyzer only produces findings when analyzing skill sets.
        Call analyze_skill_set() instead.
        """
        return []

    def analyze_skill_set(self, skills: list[Skill]) -> list[Finding]:
        """
        Analyze a set of skills for coordinated attack patterns.

        Args:
            skills: List of skills to analyze together

        Returns:
            List of findings related to cross-skill patterns
        """
        if len(skills) < 2:
            return []

        self._skills = skills
        findings = []

        # Detection 1: Data relay patterns
        findings.extend(self._detect_data_relay_pattern())

        # Detection 2: Shared external URLs
        findings.extend(self._detect_shared_external_urls())

        # Detection 3: Complementary triggers
        findings.extend(self._detect_complementary_triggers())

        # Detection 4: Shared suspicious code patterns
        findings.extend(self._detect_shared_suspicious_patterns())

        return findings

    def _detect_data_relay_pattern(self) -> list[Finding]:
        """
        Detect data relay patterns where one skill collects data and another exfiltrates.

        Pattern: Skill A reads credentials/sensitive data, Skill B sends to network.
        """
        findings = []

        # Categorize skills by behavior
        collectors: list[tuple[Skill, set[str]]] = []  # Skills that read sensitive data
        exfiltrators: list[tuple[Skill, set[str]]] = []  # Skills with network output

        # Patterns that indicate data collection
        COLLECTION_PATTERNS = [
            r"credential",
            r"password",
            r"secret",
            r"api[_-]?key",
            r"token",
            r"\.env",
            r"config",
            r"ssh",
            r"private",
            r"\.pem",
            r"~/.ssh",
            r"/etc/passwd",
            r"/etc/shadow",
            r"keychain",
            r"wallet",
            r"cookie",
        ]

        # Patterns that indicate network exfiltration
        EXFIL_PATTERNS = [
            r"requests\.(post|put)",
            r"urllib\.request",
            r"httpx\.(post|put)",
            r"socket\.send",
            r"aiohttp.*post",
            r"webhook",
            r"discord\.com/api/webhooks",
            r"ngrok",
            r"localhost\.run",
        ]

        for skill in self._skills:
            skill_content = self._get_skill_content(skill)

            # Check for collection patterns
            collection_hits = set()
            for pattern in COLLECTION_PATTERNS:
                if re.search(pattern, skill_content, re.IGNORECASE):
                    collection_hits.add(pattern)
            if collection_hits:
                collectors.append((skill, collection_hits))

            # Check for exfiltration patterns
            exfil_hits = set()
            for pattern in EXFIL_PATTERNS:
                if re.search(pattern, skill_content, re.IGNORECASE):
                    exfil_hits.add(pattern)
            if exfil_hits:
                exfiltrators.append((skill, exfil_hits))

        # Flag if we have both collectors and exfiltrators
        if collectors and exfiltrators:
            collector_names = [s.name for s, _ in collectors]
            exfil_names = [s.name for s, _ in exfiltrators]

            # Only flag if they are different skills
            if set(collector_names) != set(exfil_names):
                findings.append(
                    Finding(
                        id=f"CROSS_SKILL_RELAY_{hash(tuple(collector_names + exfil_names)) & 0xFFFFFFFF:08x}",
                        rule_id="CROSS_SKILL_DATA_RELAY",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        title="Potential data relay attack pattern detected",
                        description=(
                            f"Skills appear to form a data relay chain. "
                            f"Collectors ({', '.join(collector_names)}) access sensitive data while "
                            f"exfiltrators ({', '.join(exfil_names)}) send data to external destinations. "
                            f"This pattern may indicate a coordinated attack."
                        ),
                        file_path="(cross-skill analysis)",
                        remediation=(
                            "Review these skills together to ensure they are not collaborating "
                            "to exfiltrate sensitive data. Consider disabling one or both skills."
                        ),
                        analyzer="cross_skill",
                        metadata={
                            "collectors": collector_names,
                            "exfiltrators": exfil_names,
                        },
                    )
                )

        return findings

    def _detect_shared_external_urls(self) -> list[Finding]:
        """
        Detect skills that reference the same external URLs.

        Multiple skills pointing to the same external resource may indicate
        coordinated command-and-control or exfiltration.
        """
        findings = []

        # Extract URLs from each skill
        skill_urls: dict[str, list[str]] = {}  # URL -> list of skill names

        for skill in self._skills:
            content = self._get_skill_content(skill)
            urls = self._extract_urls(content)

            for url in urls:
                # Normalize URL (remove path, keep domain)
                domain = self._extract_domain(url)
                if domain and not self._is_common_domain(domain):
                    if domain not in skill_urls:
                        skill_urls[domain] = []
                    if skill.name not in skill_urls[domain]:
                        skill_urls[domain].append(skill.name)

        # Flag domains referenced by multiple skills
        for domain, skill_names in skill_urls.items():
            if len(skill_names) >= 2:
                findings.append(
                    Finding(
                        id=f"CROSS_SKILL_URL_{hash(domain) & 0xFFFFFFFF:08x}",
                        rule_id="CROSS_SKILL_SHARED_URL",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.MEDIUM,
                        title="Multiple skills reference the same external domain",
                        description=(
                            f"Domain '{domain}' is referenced by {len(skill_names)} skills: "
                            f"{', '.join(skill_names)}. Multiple skills pointing to the same "
                            f"external resource may indicate coordinated C2 or exfiltration."
                        ),
                        file_path="(cross-skill analysis)",
                        remediation=(
                            "Review why multiple skills reference this domain and ensure "
                            "it is a legitimate, trusted resource."
                        ),
                        analyzer="cross_skill",
                        metadata={
                            "domain": domain,
                            "skills": skill_names,
                        },
                    )
                )

        return findings

    def _detect_complementary_triggers(self) -> list[Finding]:
        """
        Detect skills with complementary trigger descriptions.

        Pattern: One skill designed to collect, another to exfiltrate,
        with descriptions that suggest they work together.
        """
        findings = []

        # Keywords that suggest data collection
        COLLECTION_KEYWORDS = {
            "gather",
            "collect",
            "read",
            "scan",
            "find",
            "search",
            "extract",
            "parse",
            "load",
            "get",
            "fetch",
            "retrieve",
        }

        # Keywords that suggest data sending
        SENDING_KEYWORDS = {
            "send",
            "upload",
            "post",
            "submit",
            "transfer",
            "sync",
            "backup",
            "export",
            "share",
            "publish",
            "notify",
        }

        collectors = []
        senders = []

        for skill in self._skills:
            desc_lower = skill.description.lower()
            desc_words = set(re.findall(r"\b[a-z]+\b", desc_lower))

            if desc_words & COLLECTION_KEYWORDS:
                collectors.append(skill)
            if desc_words & SENDING_KEYWORDS:
                senders.append(skill)

        # Flag if we have complementary skills
        if collectors and senders:
            # Check for suspicious combinations
            for collector in collectors:
                for sender in senders:
                    if collector.name != sender.name:
                        # Check if they might work together
                        coll_words = set(re.findall(r"\b[a-z]+\b", collector.description.lower()))
                        send_words = set(re.findall(r"\b[a-z]+\b", sender.description.lower()))

                        # Look for shared context words (excluding stop words and action words)
                        EXCLUDE_WORDS = (
                            COLLECTION_KEYWORDS
                            | SENDING_KEYWORDS
                            | {
                                "the",
                                "a",
                                "an",
                                "is",
                                "are",
                                "to",
                                "for",
                                "and",
                                "or",
                                "in",
                                "with",
                            }
                        )
                        shared_context = (coll_words & send_words) - EXCLUDE_WORDS

                        if len(shared_context) >= 2:
                            findings.append(
                                Finding(
                                    id=f"CROSS_SKILL_COMPLEMENTARY_{hash(collector.name + sender.name) & 0xFFFFFFFF:08x}",
                                    rule_id="CROSS_SKILL_COMPLEMENTARY_TRIGGERS",
                                    category=ThreatCategory.SOCIAL_ENGINEERING,
                                    severity=Severity.LOW,
                                    title="Skills have complementary descriptions",
                                    description=(
                                        f"Skill '{collector.name}' (collector) and '{sender.name}' (sender) "
                                        f"have complementary descriptions with shared context: {', '.join(shared_context)}. "
                                        f"This may be intentional design or could indicate coordinated behavior."
                                    ),
                                    file_path="(cross-skill analysis)",
                                    remediation="Review these skills to ensure they are not designed to work together maliciously",
                                    analyzer="cross_skill",
                                    metadata={
                                        "collector": collector.name,
                                        "sender": sender.name,
                                        "shared_context": list(shared_context),
                                    },
                                )
                            )

        return findings

    def _detect_shared_suspicious_patterns(self) -> list[Finding]:
        """
        Detect skills that share suspicious code patterns.

        Similar obfuscation or encoding across skills may indicate
        they came from the same malicious source.
        """
        findings = []

        # Extract suspicious patterns from each skill
        SUSPICIOUS_PATTERNS = [
            (r"base64\.b64decode", "base64_decode"),
            (r"exec\s*\(", "exec_call"),
            (r"eval\s*\(", "eval_call"),
            (r"\\x[0-9a-fA-F]{2}", "hex_escape"),
            (r"chr\([0-9]+\)", "chr_call"),
            (r"getattr\s*\([^)]+,\s*['\"][^'\"]+['\"]\s*\)", "dynamic_getattr"),
        ]

        skill_patterns: dict[str, list[str]] = {}  # pattern -> list of skill names

        for skill in self._skills:
            content = self._get_skill_content(skill)

            for pattern, name in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content):
                    if name not in skill_patterns:
                        skill_patterns[name] = []
                    if skill.name not in skill_patterns[name]:
                        skill_patterns[name].append(skill.name)

        # Flag patterns shared by multiple skills
        for pattern_name, skill_names in skill_patterns.items():
            if len(skill_names) >= 2:
                findings.append(
                    Finding(
                        id=f"CROSS_SKILL_PATTERN_{hash(pattern_name + str(skill_names)) & 0xFFFFFFFF:08x}",
                        rule_id="CROSS_SKILL_SHARED_PATTERN",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Multiple skills share suspicious code pattern",
                        description=(
                            f"Pattern '{pattern_name}' found in {len(skill_names)} skills: "
                            f"{', '.join(skill_names)}. Shared suspicious patterns may indicate "
                            f"skills from the same malicious source."
                        ),
                        file_path="(cross-skill analysis)",
                        remediation=(
                            "Review these skills carefully - shared obfuscation or encoding "
                            "patterns often indicate malicious intent."
                        ),
                        analyzer="cross_skill",
                        metadata={
                            "pattern": pattern_name,
                            "skills": skill_names,
                        },
                    )
                )

        return findings

    def _get_skill_content(self, skill: Skill) -> str:
        """Get all content from a skill as a single string."""
        content_parts = [skill.description, skill.instruction_body]

        for skill_file in skill.files:
            try:
                file_content = skill_file.read_content()
                if file_content:
                    content_parts.append(file_content)
            except Exception:
                pass

        return "\n".join(content_parts)

    def _extract_urls(self, content: str) -> list[str]:
        """Extract URLs from content."""
        url_pattern = r'https?://[^\s<>"\')\]]+[^\s<>"\')\]\.,]'
        return re.findall(url_pattern, content)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        match = re.match(r"https?://([^/]+)", url)
        if match:
            return match.group(1).lower()
        return ""

    def _is_common_domain(self, domain: str) -> bool:
        """Check if domain is a common/trusted domain."""
        COMMON_DOMAINS = {
            # Code hosting / package registries
            "github.com",
            "githubusercontent.com",
            "gitlab.com",
            "pypi.org",
            "npmjs.com",
            "python.org",
            "crates.io",
            "rubygems.org",
            "packagist.org",
            # AI providers
            "anthropic.com",
            "openai.com",
            "claude.com",
            # Cloud providers
            "google.com",
            "googleapis.com",
            "microsoft.com",
            "azure.com",
            "amazon.com",
            "amazonaws.com",
            "aws.amazon.com",
            # Documentation / references
            "stackoverflow.com",
            "docs.python.org",
            "developer.mozilla.org",
            "mdn.io",
            # Standards organizations & licensing
            "apache.org",
            "www.apache.org",  # Apache license
            "opensource.org",  # OSI licenses
            "creativecommons.org",  # CC licenses
            "w3.org",
            "www.w3.org",  # W3C standards
            "ietf.org",  # IETF standards
            # XML/Document standards (used by Office docs)
            "schemas.openxmlformats.org",
            "schemas.microsoft.com",
            "purl.org",  # Persistent URLs for standards
            "dublincore.org",  # Metadata standard
            "xmlsoft.org",  # libxml
            # CDNs (common for web templates)
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "ajax.googleapis.com",
        }

        # Check if domain or parent domain is common
        for common in COMMON_DOMAINS:
            if domain == common or domain.endswith("." + common):
                return True
        return False
