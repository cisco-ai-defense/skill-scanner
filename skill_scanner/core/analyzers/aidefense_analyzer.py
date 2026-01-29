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
AI Defense API analyzer for agent skills security scanning.

Integrates with Cisco AI Defense API (https://api.aidefense.cisco.com) for:
- Prompt injection detection
- Tool poisoning detection
- Data exfiltration detection
- Malicious content analysis
"""

import asyncio
import hashlib
import json
import os
from typing import Any

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from ...core.models import Finding, Severity, Skill, ThreatCategory
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer

# AI Defense API endpoint - Cisco AI Defense Inspect API
AI_DEFENSE_API_URL = "https://us.api.inspect.aidefense.security.cisco.com/api/v1"

# Default enabled rules for AI Defense API
DEFAULT_ENABLED_RULES = [
    {"rule_name": "Prompt Injection"},
    {"rule_name": "Harassment"},
    {"rule_name": "Hate Speech"},
    {"rule_name": "Profanity"},
    {"rule_name": "Sexual Content & Exploitation"},
    {"rule_name": "Social Division & Polarization"},
    {"rule_name": "Violence & Public Safety Threats"},
    {"rule_name": "Code Detection"},
]


class AIDefenseAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses Cisco AI Defense API for threat detection.

    Sends skill content (prompts, markdown, code) to AI Defense API
    for comprehensive security analysis.

    **Important**: The "Code Detection" rule is automatically excluded when
    analyzing actual code files (Python scripts) to avoid false positives,
    since skills legitimately contain code. Code Detection is still used for
    prompts, markdown, and manifest content where malicious code injection
    would be a security concern.

    Example:
        >>> # Basic usage
        >>> analyzer = AIDefenseAnalyzer(api_key="your-api-key")
        >>> findings = analyzer.analyze(skill)

        >>> # Custom rules configuration
        >>> custom_rules = [
        ...     {"rule_name": "Prompt Injection"},
        ...     {"rule_name": "Code Detection"},  # Will be excluded for code files
        ... ]
        >>> analyzer = AIDefenseAnalyzer(
        ...     api_key="your-api-key",
        ...     enabled_rules=custom_rules,
        ...     include_rules=True
        ... )

        >>> # For API keys with pre-configured rules
        >>> analyzer = AIDefenseAnalyzer(
        ...     api_key="your-api-key",
        ...     include_rules=False  # Don't send rules config
        ... )
    """

    def __init__(
        self,
        api_key: str | None = None,
        api_url: str | None = None,
        timeout: int = 60,
        max_retries: int = 3,
        enabled_rules: list[dict[str, str]] | None = None,
        include_rules: bool = True,
    ):
        """
        Initialize AI Defense API analyzer.

        Args:
            api_key: AI Defense API key (or set AI_DEFENSE_API_KEY env var)
            api_url: Custom API URL (defaults to https://api.aidefense.cisco.com/api/v1)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts on failure
            enabled_rules: List of rules to enable (defaults to DEFAULT_ENABLED_RULES).
                          Format: [{"rule_name": "Prompt Injection"}, ...]
            include_rules: Whether to include enabled_rules in API payload.
                          Set to False if API key has pre-configured rules.
        """
        super().__init__("aidefense_analyzer")

        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for AI Defense analyzer. Install with: pip install httpx")

        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv("AI_DEFENSE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "AI Defense API key required. Set AI_DEFENSE_API_KEY environment variable or pass api_key parameter."
            )

        self.api_url = api_url or os.getenv("AI_DEFENSE_API_URL", AI_DEFENSE_API_URL)
        self.timeout = timeout
        self.max_retries = max_retries

        # Rules configuration
        self.enabled_rules = enabled_rules or DEFAULT_ENABLED_RULES
        self.include_rules = include_rules

        # Initialize async client
        self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                headers={
                    "X-Cisco-AI-Defense-API-Key": self.api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _close_client(self):
        """Close HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _get_payload(
        self,
        messages: list[dict[str, str]],
        metadata: dict[str, Any] | None = None,
        include_rules: bool | None = None,
        rules_override: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """
        Build API request payload with optional rules configuration.

        Args:
            messages: List of message dicts with "role" and "content"
            metadata: Optional metadata dict
            include_rules: Whether to include enabled_rules in config.
                          If None, uses self.include_rules
            rules_override: Optional list of rules to use instead of self.enabled_rules.
                           Useful for excluding certain rules (e.g., Code Detection for code files)

        Returns:
            Complete payload dict
        """
        payload = {
            "messages": messages,
        }

        if metadata:
            payload["metadata"] = metadata

        # Include rules config if requested
        if include_rules is None:
            include_rules = self.include_rules

        if include_rules:
            # Use override rules if provided, otherwise use instance rules
            rules_to_use = rules_override if rules_override is not None else self.enabled_rules
            if rules_to_use:
                payload["config"] = {"enabled_rules": rules_to_use}

        return payload

    def _get_rules_for_content_type(self, content_type: str) -> list[dict[str, str]]:
        """
        Get appropriate rules for a given content type.

        Excludes "Code Detection" for actual code files since they contain
        legitimate code. Code Detection is useful for detecting malicious
        code in prompts/markdown, but not for analyzing actual code files.

        Args:
            content_type: Type of content being analyzed
                         ("skill_instructions", "skill_manifest", "markdown_content", "code")

        Returns:
            List of rule dicts appropriate for the content type
        """
        if content_type == "code":
            # Exclude Code Detection for actual code files
            return [rule for rule in self.enabled_rules if rule.get("rule_name") != "Code Detection"]
        else:
            # Use all rules for prompts/markdown/manifest
            return self.enabled_rules

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using AI Defense API (sync wrapper).

        Args:
            skill: Skill to analyze

        Returns:
            List of security findings
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(self.analyze_async(skill))
        finally:
            loop.run_until_complete(self._close_client())

    async def analyze_async(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using AI Defense API (async).

        Args:
            skill: Skill to analyze

        Returns:
            List of security findings
        """
        findings = []

        try:
            # 1. Analyze SKILL.md content (prompts/instructions)
            skill_md_findings = await self._analyze_prompt_content(
                skill.instruction_body, skill.name, "SKILL.md", "skill_instructions"
            )
            findings.extend(skill_md_findings)

            # 2. Analyze manifest/description
            manifest_findings = await self._analyze_prompt_content(
                f"Name: {skill.manifest.name}\nDescription: {skill.manifest.description}",
                skill.name,
                "manifest",
                "skill_manifest",
            )
            findings.extend(manifest_findings)

            # 3. Analyze each markdown file
            for md_file in skill.get_markdown_files():
                content = md_file.read_content()
                if content:
                    md_findings = await self._analyze_prompt_content(
                        content, skill.name, md_file.relative_path, "markdown_content"
                    )
                    findings.extend(md_findings)

            # 4. Analyze code files
            for script_file in skill.get_scripts():
                content = script_file.read_content()
                if content:
                    code_findings = await self._analyze_code_content(
                        content, skill.name, script_file.relative_path, script_file.file_type
                    )
                    findings.extend(code_findings)

        except Exception as e:
            print(f"AI Defense API analysis failed for {skill.name}: {e}")
            # Return partial findings - don't fail completely

        return findings

    async def _analyze_prompt_content(
        self,
        content: str,
        skill_name: str,
        file_path: str,
        content_type: str,
    ) -> list[Finding]:
        """
        Analyze prompt/instruction content via AI Defense API.

        Args:
            content: Text content to analyze
            skill_name: Name of the skill
            file_path: Source file path
            content_type: Type of content being analyzed

        Returns:
            List of findings
        """
        if not content or not content.strip():
            return []

        findings = []

        try:
            # Build request payload for chat inspection (prompt injection detection)
            messages = [
                {
                    "role": "user",
                    "content": content[:10000],  # Limit content size
                }
            ]
            metadata = {
                "source": "skill_scanner",
                "skill_name": skill_name,
                "file_path": file_path,
                "content_type": content_type,
            }

            # Get appropriate rules for prompt content (includes Code Detection)
            rules_for_prompts = self._get_rules_for_content_type(content_type)
            payload = self._get_payload(messages, metadata, include_rules=True, rules_override=rules_for_prompts)

            # Call AI Defense API - chat inspection endpoint
            response = await self._make_api_request(endpoint="/inspect/chat", payload=payload)

            if response:
                # Process AI Defense response format:
                # {
                #   "classifications": ["SECURITY_VIOLATION"],
                #   "is_safe": false,
                #   "rules": [{"rule_name": "Prompt Injection", "classification": "SECURITY_VIOLATION"}],
                #   "action": "Block"
                # }

                is_safe = response.get("is_safe", True)
                classifications = response.get("classifications", [])
                rules = response.get("rules", [])
                action = response.get("action", "").lower()

                # Process each classification
                for classification in classifications:
                    if classification and classification != "NONE_VIOLATION":
                        severity = self._map_classification_to_severity(classification)
                        findings.append(
                            Finding(
                                id=self._generate_id(f"AIDEFENSE_{classification}", file_path),
                                rule_id=f"AIDEFENSE_{classification}",
                                category=self._map_violation_category(classification),
                                severity=severity,
                                title=f"{classification.replace('_', ' ').title()} detected",
                                description=f"AI Defense detected {classification.replace('_', ' ').lower()} in {file_path}",
                                file_path=file_path,
                                remediation="Review and address the security concern flagged by AI Defense",
                                analyzer="aidefense",
                                metadata={
                                    "classification": classification,
                                    "content_type": content_type,
                                    "is_safe": is_safe,
                                    "action": action,
                                },
                            )
                        )

                # Process triggered rules
                for rule in rules:
                    rule_name = rule.get("rule_name", "Unknown")
                    rule_classification = rule.get("classification", "")

                    # Skip non-violations
                    if rule_classification in ("NONE_VIOLATION", ""):
                        continue

                    findings.append(
                        Finding(
                            id=self._generate_id(f"AIDEFENSE_RULE_{rule_name}", file_path),
                            rule_id=f"AIDEFENSE_RULE_{rule_name.upper().replace(' ', '_')}",
                            category=self._map_violation_category(rule_classification),
                            severity=self._map_classification_to_severity(rule_classification),
                            title=f"Rule triggered: {rule_name}",
                            description=f"AI Defense rule '{rule_name}' detected {rule_classification.replace('_', ' ').lower()}",
                            file_path=file_path,
                            remediation=f"Address the {rule_name.lower()} issue detected by AI Defense",
                            analyzer="aidefense",
                            metadata={
                                "rule_name": rule_name,
                                "rule_id": rule.get("rule_id"),
                                "classification": rule_classification,
                                "entity_types": rule.get("entity_types", []),
                            },
                        )
                    )

                # Check overall action
                if action == "block" and not is_safe:
                    # Only add if we haven't already added findings for the specific violations
                    if not findings:
                        findings.append(
                            Finding(
                                id=self._generate_id("AIDEFENSE_BLOCKED", file_path),
                                rule_id="AIDEFENSE_BLOCKED",
                                category=ThreatCategory.PROMPT_INJECTION,
                                severity=Severity.HIGH,
                                title="Content blocked by AI Defense",
                                description=f"AI Defense blocked content in {file_path} as potentially malicious",
                                file_path=file_path,
                                analyzer="aidefense",
                                metadata={
                                    "action": action,
                                    "content_type": content_type,
                                    "is_safe": is_safe,
                                },
                            )
                        )

        except Exception as e:
            print(f"AI Defense prompt analysis failed for {file_path}: {e}")

        return findings

    async def _analyze_code_content(
        self,
        content: str,
        skill_name: str,
        file_path: str,
        language: str,
    ) -> list[Finding]:
        """
        Analyze code content via AI Defense API.

        Uses the HTTP inspection endpoint for code analysis.

        Args:
            content: Code content to analyze
            skill_name: Name of the skill
            file_path: Source file path
            language: Programming language

        Returns:
            List of findings
        """
        if not content or not content.strip():
            return []

        findings = []

        try:
            # Build request payload for code analysis using chat inspection
            # Code is analyzed as a message for potential security issues
            messages = [
                {"role": "user", "content": f"# Code Analysis for {file_path}\n```{language}\n{content[:15000]}\n```"}
            ]
            metadata = {
                "source": "skill_scanner",
                "skill_name": skill_name,
                "file_path": file_path,
                "language": language,
                "content_type": "code",
            }

            # Get appropriate rules for code files (excludes Code Detection)
            rules_for_code = self._get_rules_for_content_type("code")
            payload = self._get_payload(messages, metadata, include_rules=True, rules_override=rules_for_code)

            # Call AI Defense API - chat inspection endpoint for code
            response = await self._make_api_request(endpoint="/inspect/chat", payload=payload)

            if response:
                # Process AI Defense response (same format as prompt inspection)
                is_safe = response.get("is_safe", True)
                classifications = response.get("classifications", [])
                rules = response.get("rules", [])
                action = response.get("action", "").lower()

                # Process classifications
                for classification in classifications:
                    if classification and classification != "NONE_VIOLATION":
                        severity = self._map_classification_to_severity(classification)
                        findings.append(
                            Finding(
                                id=self._generate_id(f"AIDEFENSE_CODE_{classification}", file_path),
                                rule_id=f"AIDEFENSE_CODE_{classification}",
                                category=self._map_violation_category(classification),
                                severity=severity,
                                title=f"Code {classification.replace('_', ' ').lower()} detected",
                                description=f"AI Defense detected {classification.replace('_', ' ').lower()} in {language} code",
                                file_path=file_path,
                                remediation="Review and fix the code issue flagged by AI Defense",
                                analyzer="aidefense",
                                metadata={
                                    "classification": classification,
                                    "language": language,
                                    "is_safe": is_safe,
                                },
                            )
                        )

                # Process triggered rules
                for rule in rules:
                    rule_name = rule.get("rule_name", "Unknown")
                    rule_classification = rule.get("classification", "")

                    if rule_classification in ("NONE_VIOLATION", ""):
                        continue

                    findings.append(
                        Finding(
                            id=self._generate_id(f"AIDEFENSE_CODE_RULE_{rule_name}", file_path),
                            rule_id=f"AIDEFENSE_CODE_RULE_{rule_name.upper().replace(' ', '_')}",
                            category=self._map_violation_category(rule_classification),
                            severity=self._map_classification_to_severity(rule_classification),
                            title=f"Code rule triggered: {rule_name}",
                            description=f"AI Defense rule '{rule_name}' detected issue in {language} code",
                            file_path=file_path,
                            remediation=f"Address the {rule_name.lower()} issue in the code",
                            analyzer="aidefense",
                            metadata={
                                "rule_name": rule_name,
                                "classification": rule_classification,
                                "language": language,
                            },
                        )
                    )

                # Check action
                if action == "block" and not is_safe and not findings:
                    findings.append(
                        Finding(
                            id=self._generate_id("AIDEFENSE_CODE_BLOCKED", file_path),
                            rule_id="AIDEFENSE_CODE_BLOCKED",
                            category=ThreatCategory.MALWARE,
                            severity=Severity.HIGH,
                            title="Code blocked by AI Defense",
                            description=f"AI Defense blocked {language} code in {file_path} as potentially malicious",
                            file_path=file_path,
                            analyzer="aidefense",
                            metadata={
                                "action": action,
                                "language": language,
                                "is_safe": is_safe,
                            },
                        )
                    )

        except Exception as e:
            print(f"AI Defense code analysis failed for {file_path}: {e}")

        return findings

    async def _make_api_request(
        self,
        endpoint: str,
        payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Make request to AI Defense API with retry logic.

        Handles fallback for pre-configured rules: if API returns 400 with
        "already has rules configured" error, retries without rules config.

        Args:
            endpoint: API endpoint path
            payload: Request payload (may include config.enabled_rules)

        Returns:
            API response or None on failure
        """
        client = self._get_client()
        url = f"{self.api_url}{endpoint}"

        last_exception = None
        original_payload = payload.copy()
        tried_without_rules = False

        for attempt in range(self.max_retries):
            try:
                response = await client.post(url, json=payload)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 400:
                    # Check if this is a pre-configured rules error
                    try:
                        error_json = response.json()
                        error_msg = error_json.get("message", "").lower()

                        # If API key has pre-configured rules, retry without rules config
                        if (
                            "already has rules configured" in error_msg or "pre-configured" in error_msg
                        ) and not tried_without_rules:
                            # Remove config.enabled_rules and retry
                            payload_without_rules = original_payload.copy()
                            if "config" in payload_without_rules:
                                del payload_without_rules["config"]

                            print(
                                "AI Defense API key has pre-configured rules, retrying without enabled_rules config..."
                            )
                            payload = payload_without_rules
                            tried_without_rules = True
                            continue
                    except (ValueError, KeyError, json.JSONDecodeError):
                        # Can't parse error, fall through to generic error handling
                        pass

                    # Generic 400 error
                    print(f"AI Defense API error: {response.status_code} - {response.text}")
                    return None
                elif response.status_code == 429:
                    # Rate limited - wait and retry
                    delay = (2**attempt) * 1.0
                    print(f"AI Defense API rate limited, retrying in {delay}s...")
                    await asyncio.sleep(delay)
                    continue
                elif response.status_code == 401:
                    raise ValueError("Invalid AI Defense API key")
                elif response.status_code == 403:
                    raise ValueError("AI Defense API access denied - check permissions")
                else:
                    print(f"AI Defense API error: {response.status_code} - {response.text}")
                    return None

            except httpx.TimeoutException:
                last_exception = TimeoutError(f"AI Defense API timeout after {self.timeout}s")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1.0)
                    continue
            except httpx.RequestError as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1.0)
                    continue

        if last_exception:
            print(f"AI Defense API request failed after {self.max_retries} attempts: {last_exception}")

        return None

    def _convert_api_violation_to_finding(
        self,
        violation: dict[str, Any],
        skill_name: str,
        file_path: str,
        content_type: str,
    ) -> Finding | None:
        """Convert AI Defense API violation to Finding object."""
        try:
            violation_type = violation.get("type", "unknown").upper()
            severity_str = violation.get("severity", "medium").upper()

            # Map severity
            severity = self._map_violation_severity(severity_str)

            # Map category based on violation type
            category = self._map_violation_category(violation_type)

            # Get AITech mapping if available
            try:
                aitech_mapping = ThreatMapping.get_threat_mapping("llm", violation_type.replace("_", " "))
            except (ValueError, KeyError):
                aitech_mapping = {}

            return Finding(
                id=self._generate_id(f"AIDEFENSE_{violation_type}", file_path),
                rule_id=f"AIDEFENSE_{violation_type}",
                category=category,
                severity=severity,
                title=violation.get("title", f"AI Defense detected: {violation_type.replace('_', ' ').lower()}"),
                description=violation.get("description", f"Violation detected in {content_type}"),
                file_path=file_path,
                line_number=violation.get("line"),
                snippet=violation.get("evidence", violation.get("snippet", "")),
                remediation=violation.get("remediation", "Review and address the security concern"),
                analyzer="aidefense",
                metadata={
                    "violation_type": violation_type,
                    "confidence": violation.get("confidence"),
                    "aitech": aitech_mapping.get("aitech"),
                    "aitech_name": aitech_mapping.get("aitech_name"),
                },
            )

        except Exception as e:
            print(f"Failed to convert AI Defense violation: {e}")
            return None

    def _map_violation_severity(self, severity_str: str) -> Severity:
        """Map AI Defense severity string to Severity enum."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "INFORMATIONAL": Severity.INFO,
            "NONE_SEVERITY": Severity.MEDIUM,  # Default for AI Defense
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)

    def _map_classification_to_severity(self, classification: str) -> Severity:
        """Map AI Defense classification to severity level."""
        classification = classification.upper()
        severity_map = {
            "SECURITY_VIOLATION": Severity.HIGH,
            "PRIVACY_VIOLATION": Severity.HIGH,
            "SAFETY_VIOLATION": Severity.MEDIUM,
            "RELEVANCE_VIOLATION": Severity.LOW,
            "NONE_VIOLATION": Severity.INFO,
        }
        return severity_map.get(classification, Severity.MEDIUM)

    def _map_violation_category(self, violation_type: str) -> ThreatCategory:
        """Map AI Defense violation type to ThreatCategory."""
        violation_type = violation_type.upper()
        mapping = {
            "SECURITY_VIOLATION": ThreatCategory.PROMPT_INJECTION,
            "PRIVACY_VIOLATION": ThreatCategory.DATA_EXFILTRATION,
            "SAFETY_VIOLATION": ThreatCategory.SOCIAL_ENGINEERING,
            "RELEVANCE_VIOLATION": ThreatCategory.POLICY_VIOLATION,
            "PROMPT_INJECTION": ThreatCategory.PROMPT_INJECTION,
            "JAILBREAK": ThreatCategory.PROMPT_INJECTION,
            "TOOL_POISONING": ThreatCategory.PROMPT_INJECTION,
            "DATA_EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "DATA_LEAK": ThreatCategory.DATA_EXFILTRATION,
            "COMMAND_INJECTION": ThreatCategory.COMMAND_INJECTION,
            "CODE_INJECTION": ThreatCategory.COMMAND_INJECTION,
            "CREDENTIAL_THEFT": ThreatCategory.HARDCODED_SECRETS,
            "MALWARE": ThreatCategory.MALWARE,
            "SOCIAL_ENGINEERING": ThreatCategory.SOCIAL_ENGINEERING,
            "OBFUSCATION": ThreatCategory.OBFUSCATION,
        }
        return mapping.get(violation_type, ThreatCategory.POLICY_VIOLATION)

    def _convert_api_threat_to_finding(
        self,
        threat: dict[str, Any],
        skill_name: str,
        file_path: str,
        content_type: str,
    ) -> Finding | None:
        """Convert AI Defense API threat to Finding object (legacy support)."""
        # Delegate to violation converter for consistency
        return self._convert_api_violation_to_finding(threat, skill_name, file_path, content_type)

    def _convert_api_vulnerability_to_finding(
        self,
        vuln: dict[str, Any],
        skill_name: str,
        file_path: str,
        language: str,
    ) -> Finding | None:
        """Convert AI Defense API vulnerability to Finding object."""
        try:
            vuln_type = vuln.get("type", "unknown").upper()
            severity_str = vuln.get("severity", "MEDIUM").upper()

            # Map severity
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            # Map category
            category = self._map_vuln_type_to_category(vuln_type)

            return Finding(
                id=self._generate_id(f"AIDEFENSE_VULN_{vuln_type}", f"{file_path}_{vuln.get('line', 0)}"),
                rule_id=f"AIDEFENSE_VULN_{vuln_type}",
                category=category,
                severity=severity,
                title=vuln.get("title", f"Vulnerability: {vuln_type}"),
                description=vuln.get("description", f"Security vulnerability in {language} code"),
                file_path=file_path,
                line_number=vuln.get("line"),
                snippet=vuln.get("snippet", ""),
                remediation=vuln.get("remediation", "Fix the security vulnerability"),
                analyzer="aidefense",
                metadata={
                    "vuln_type": vuln_type,
                    "cwe": vuln.get("cwe"),
                    "language": language,
                },
            )

        except Exception as e:
            print(f"Failed to convert AI Defense vulnerability: {e}")
            return None

    def _map_threat_type_to_category(self, threat_type: str) -> ThreatCategory:
        """Map AI Defense threat type to ThreatCategory."""
        mapping = {
            "PROMPT_INJECTION": ThreatCategory.PROMPT_INJECTION,
            "PROMPT INJECTION": ThreatCategory.PROMPT_INJECTION,
            "JAILBREAK": ThreatCategory.PROMPT_INJECTION,
            "TOOL_POISONING": ThreatCategory.PROMPT_INJECTION,
            "TOOL POISONING": ThreatCategory.PROMPT_INJECTION,
            "DATA_EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "DATA EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "COMMAND_INJECTION": ThreatCategory.COMMAND_INJECTION,
            "COMMAND INJECTION": ThreatCategory.COMMAND_INJECTION,
            "CREDENTIAL_THEFT": ThreatCategory.HARDCODED_SECRETS,
            "MALWARE": ThreatCategory.MALWARE,
            "SOCIAL_ENGINEERING": ThreatCategory.SOCIAL_ENGINEERING,
            "OBFUSCATION": ThreatCategory.OBFUSCATION,
        }
        return mapping.get(threat_type.upper(), ThreatCategory.POLICY_VIOLATION)

    def _map_vuln_type_to_category(self, vuln_type: str) -> ThreatCategory:
        """Map vulnerability type to ThreatCategory."""
        mapping = {
            "INJECTION": ThreatCategory.COMMAND_INJECTION,
            "SQL_INJECTION": ThreatCategory.COMMAND_INJECTION,
            "COMMAND_INJECTION": ThreatCategory.COMMAND_INJECTION,
            "XSS": ThreatCategory.COMMAND_INJECTION,
            "PATH_TRAVERSAL": ThreatCategory.DATA_EXFILTRATION,
            "SENSITIVE_DATA": ThreatCategory.HARDCODED_SECRETS,
            "HARDCODED_SECRET": ThreatCategory.HARDCODED_SECRETS,
            "INSECURE_FUNCTION": ThreatCategory.COMMAND_INJECTION,
        }
        return mapping.get(vuln_type.upper(), ThreatCategory.POLICY_VIOLATION)

    def _map_pattern_to_category(self, pattern_type: str | None) -> ThreatCategory:
        """Map malicious pattern type to ThreatCategory."""
        if not pattern_type:
            return ThreatCategory.POLICY_VIOLATION

        pattern_type = pattern_type.upper()
        mapping = {
            "EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "BACKDOOR": ThreatCategory.MALWARE,
            "CREDENTIAL_THEFT": ThreatCategory.HARDCODED_SECRETS,
            "OBFUSCATION": ThreatCategory.OBFUSCATION,
            "INJECTION": ThreatCategory.COMMAND_INJECTION,
        }
        return mapping.get(pattern_type, ThreatCategory.MALWARE)

    def _map_confidence_to_severity(self, confidence: float) -> Severity:
        """Map confidence score to severity level."""
        if confidence >= 0.9:
            return Severity.CRITICAL
        elif confidence >= 0.7:
            return Severity.HIGH
        elif confidence >= 0.5:
            return Severity.MEDIUM
        elif confidence >= 0.3:
            return Severity.LOW
        else:
            return Severity.INFO

    def _generate_id(self, prefix: str, context: str) -> str:
        """Generate unique finding ID."""
        combined = f"{prefix}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{prefix}_{hash_obj.hexdigest()[:10]}"
