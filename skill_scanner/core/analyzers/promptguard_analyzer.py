# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
PromptGuard analyzer for agent skills security scanning.

Sends skill content (instructions, manifest, code) to the PromptGuard Guard
API and maps responses back to skill-scanner Finding objects.  PromptGuard
detects prompt injection, jailbreaks, data exfiltration, PII leaks, secret
key exposure, tool injection, toxicity, fraud, and malware patterns.

The analyzer ships zero detection logic — all intelligence stays server-side
behind the PromptGuard API.  This keeps the integration lightweight and
ensures detection models are always up to date.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from ..models import Finding, Severity, Skill, ThreatCategory
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

PROMPTGUARD_API_URL = "https://api.promptguard.co/api/v1/guard"

# ── Threat-type → Finding field maps ─────────────────────────────────────

_THREAT_TO_CATEGORY: dict[str, ThreatCategory] = {
    "prompt_injection": ThreatCategory.PROMPT_INJECTION,
    "jailbreak": ThreatCategory.PROMPT_INJECTION,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "system_prompt_leak": ThreatCategory.DATA_EXFILTRATION,
    "pii_leak": ThreatCategory.DATA_EXFILTRATION,
    "api_key_leak": ThreatCategory.HARDCODED_SECRETS,
    "secret_key_leak": ThreatCategory.HARDCODED_SECRETS,
    "toxicity": ThreatCategory.HARMFUL_CONTENT,
    "fraud_abuse": ThreatCategory.SOCIAL_ENGINEERING,
    "malware": ThreatCategory.MALWARE,
    "tool_injection": ThreatCategory.PROMPT_INJECTION,
    "mcp_violation": ThreatCategory.UNAUTHORIZED_TOOL_USE,
    "malicious_entity": ThreatCategory.MALWARE,
    "url_violation": ThreatCategory.DATA_EXFILTRATION,
    "policy_violation": ThreatCategory.POLICY_VIOLATION,
    "off_topic": ThreatCategory.POLICY_VIOLATION,
}

_THREAT_TO_SEVERITY: dict[str, Severity] = {
    "prompt_injection": Severity.CRITICAL,
    "jailbreak": Severity.CRITICAL,
    "data_exfiltration": Severity.CRITICAL,
    "pii_leak": Severity.HIGH,
    "api_key_leak": Severity.CRITICAL,
    "secret_key_leak": Severity.CRITICAL,
    "toxicity": Severity.MEDIUM,
    "fraud_abuse": Severity.HIGH,
    "malware": Severity.CRITICAL,
    "tool_injection": Severity.HIGH,
    "mcp_violation": Severity.HIGH,
    "malicious_entity": Severity.HIGH,
    "url_violation": Severity.MEDIUM,
    "system_prompt_leak": Severity.HIGH,
    "policy_violation": Severity.MEDIUM,
    "off_topic": Severity.LOW,
}

# Ordered from most to least severe — used by _confidence_to_severity.
_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.SAFE,
]


class PromptGuardAnalyzer(BaseAnalyzer):
    """Analyzer that sends skill content to the PromptGuard Guard API.

    PromptGuard scans for prompt injection, jailbreaks, PII, secret keys,
    data exfiltration, toxicity, fraud, malware, tool injection, and more.
    All detection runs server-side — this analyzer is a thin API client.

    Example::

        >>> analyzer = PromptGuardAnalyzer(api_key="your-api-key")
        >>> findings = analyzer.analyze(skill)
    """

    def __init__(
        self,
        api_key: str | None = None,
        api_url: str | None = None,
        timeout: int = 15,
    ):
        """Initialize PromptGuard analyzer.

        Args:
            api_key: PromptGuard API key (or set ``PROMPTGUARD_API_KEY`` env var).
                     Get a free key at https://promptguard.co
            api_url: Custom API endpoint (defaults to hosted API).
            timeout: Request timeout in seconds.
        """
        super().__init__("promptguard_analyzer")

        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for the PromptGuard analyzer. Install with: pip install httpx")

        self.api_key = api_key or os.getenv("PROMPTGUARD_API_KEY")
        if not self.api_key:
            raise ValueError(
                "PromptGuard API key required. "
                "Set PROMPTGUARD_API_KEY environment variable or pass api_key parameter. "
                "Get a free key at https://promptguard.co"
            )

        self.api_url = api_url or os.getenv("PROMPTGUARD_API_URL", PROMPTGUARD_API_URL)
        self.timeout = timeout

    # ── Public API ────────────────────────────────────────────────────────

    def analyze(self, skill: Skill) -> list[Finding]:
        """Analyze a skill by sending its content to the PromptGuard Guard API.

        Scans the skill's instruction body, manifest description, markdown
        files, and script files.  Each piece of content is sent as a separate
        API call and findings are aggregated.

        Args:
            skill: The skill to analyze.

        Returns:
            List of security findings.
        """
        findings: list[Finding] = []

        # 1. Scan SKILL.md instruction body
        if skill.instruction_body:
            findings.extend(self._scan_content(skill.instruction_body, skill.name, "SKILL.md"))

        # 2. Scan manifest name + description
        manifest_text = f"Name: {skill.manifest.name}\nDescription: {skill.manifest.description}"
        findings.extend(self._scan_content(manifest_text, skill.name, "manifest"))

        # 3. Scan markdown files (excluding SKILL.md already scanned above)
        for md_file in skill.get_markdown_files():
            if md_file.relative_path == "SKILL.md":
                continue
            content = md_file.read_content()
            if content:
                findings.extend(self._scan_content(content, skill.name, md_file.relative_path))

        # 4. Scan script files
        for script in skill.get_scripts():
            content = script.read_content()
            if content:
                findings.extend(self._scan_content(content, skill.name, script.relative_path))

        return findings

    # ── Internals ─────────────────────────────────────────────────────────

    def _scan_content(self, content: str, skill_name: str, file_path: str) -> list[Finding]:
        """Send content to the PromptGuard API and convert the response to findings."""
        try:
            response = httpx.post(
                self.api_url,
                json={"input": content},
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "skill-scanner-promptguard/1.0",
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            return self._parse_response(response.json(), skill_name, file_path)
        except Exception as exc:
            logger.debug(
                "PromptGuard API call failed for %s/%s (fail-open): %s",
                skill_name,
                file_path,
                exc,
            )
            return []

    def _parse_response(
        self,
        data: dict[str, Any],
        skill_name: str,
        file_path: str,
    ) -> list[Finding]:
        """Convert a PromptGuard Guard API response to Finding objects."""
        decision = data.get("decision", "allow")
        if decision == "allow":
            return []

        threat_type = data.get("threat_type", "unknown")
        reason = data.get("reason", "Threat detected by PromptGuard")
        confidence = data.get("confidence", 0.0)

        category = _THREAT_TO_CATEGORY.get(threat_type, ThreatCategory.POLICY_VIOLATION)
        severity = self._confidence_to_severity(
            confidence,
            _THREAT_TO_SEVERITY.get(threat_type, Severity.MEDIUM),
        )

        extra_meta = data.get("metadata") or {}

        return [
            Finding(
                id=self._generate_id(threat_type, file_path),
                rule_id=f"PG_{threat_type.upper()}",
                category=category,
                severity=severity,
                title=f"PromptGuard: {threat_type.replace('_', ' ').title()}",
                description=reason,
                file_path=file_path,
                line_number=None,
                snippet=None,
                remediation="Review the flagged content and remove or rewrite the problematic section.",
                analyzer="promptguard",
                metadata={
                    "confidence": confidence,
                    "threat_type": threat_type,
                    "decision": decision,
                    **extra_meta,
                },
            )
        ]

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _confidence_to_severity(confidence: float, default: Severity) -> Severity:
        """Refine severity using the API confidence score.

        High-confidence detections are promoted to at least HIGH / CRITICAL.
        The *default* severity (derived from threat type) is used otherwise.
        """
        if confidence >= 0.95:
            return Severity.CRITICAL
        if confidence >= 0.80:
            # Ensure at least HIGH — pick whichever is more severe.
            default_idx = _SEVERITY_ORDER.index(default)
            high_idx = _SEVERITY_ORDER.index(Severity.HIGH)
            return _SEVERITY_ORDER[min(default_idx, high_idx)]
        return default

    @staticmethod
    def _generate_id(threat_type: str, file_path: str) -> str:
        """Generate a deterministic finding ID."""
        raw = f"PG_{threat_type}:{file_path}"
        return f"PG_{hashlib.sha256(raw.encode()).hexdigest()[:12]}"
