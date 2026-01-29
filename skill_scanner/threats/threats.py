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
Threat mapping from scanner threat names to AITech Taxonomy.

This module provides mappings between different analyzers' threat names
and the standardized AITech industry taxonomy threat classifications.

Implements AITech codes (AITech-X.Y) for consistent threat categorization.
"""

from typing import Any


class ThreatMapping:
    """Mapping of threat names to AITech Taxonomy classifications with severity."""

    # LLM Analyzer Threats
    LLM_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, "
            "operational directives, or behavioral guidelines through direct user input.",
        },
        "PROMPT_INJECTION": {  # Underscore version
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, "
            "operational directives, or behavioral guidelines through direct user input.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, "
            "through exploitation of agent tools, integrations, or capabilities.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used by agents through data poisoning, configuration tampering, or behavioral manipulation.",
        },
        "TOOL SHADOWING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.5",
            "aisubtech_name": "Tool Shadowing",
            "description": "Disguising, substituting or duplicating legitimate tools within an agent, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as command sequences into skills that process model or user input, leading to remote code execution or compromise.",
        },
    }

    # YARA/Static Analyzer Threats
    YARA_THREATS = {
        "PROMPT_INJECTION": {  # Underscore version
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override system instructions through direct input.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious command sequences leading to remote code execution.",
        },
        "COMMAND_INJECTION": {  # Underscore version
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious command sequences leading to remote code execution.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized exposure or exfiltration of sensitive information.",
        },
        "DATA_EXFILTRATION": {  # Underscore version
            "scanner_category": "SECURITY VIOLATION",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized exposure or exfiltration of sensitive information.",
        },
        "SKILL DISCOVERY ABUSE": {
            "scanner_category": "SOCIAL ENGINEERING",
            "severity": "MEDIUM",
            "aitech": "AITech-2.1",  # Social Engineering (closest match)
            "aitech_name": "Social Engineering",
            "aisubtech": None,  # No exact subtech for skill discovery abuse
            "aisubtech_name": None,
            "description": "Manipulation of skill discovery to increase unwanted activation (keyword baiting, over-broad descriptions, impersonation).",
        },
        "TRANSITIVE TRUST ABUSE": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.2",  # Indirect Prompt Injection (exact match from Framework)
            "aitech_name": "Indirect Prompt Injection",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Delegating trust to untrusted external content - following webpage/file instructions, executing found code blocks.",
        },
        "AUTONOMY ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "HIGH",
            "aitech": "AITech-9.1",  # Model or Agentic System Manipulation (closest match)
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Excessive autonomy without bounds - keep retrying indefinitely, run without confirmation, ignore errors.",
        },
        "TOOL CHAINING ABUSE": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",  # Data Exfiltration / Exposure (from Framework)
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",  # Data Exfiltration via Agent Tooling (from Framework)
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Suspicious multi-step tool chaining to exfiltrate data - read→send, collect→post, traverse→upload patterns.",
        },
        "HARDCODED SECRETS": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.1",
            "aisubtech_name": "Sensitive Data Exposure",
            "description": "Hardcoded credentials, API keys, or secrets in code.",
        },
        "HARDCODED_SECRETS": {  # Underscore version
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.1",
            "aisubtech_name": "Sensitive Data Exposure",
            "description": "Hardcoded credentials, API keys, or secrets in code.",
        },
        "OBFUSCATION": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.3",
            "aisubtech_name": "Code Obfuscation",
            "description": "Deliberately obfuscated code to hide malicious intent.",
        },
        "UNAUTHORIZED TOOL USE": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "MEDIUM",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.1",
            "aisubtech_name": "Tool Abuse",
            "description": "Using tools or capabilities beyond declared permissions.",
        },
        "UNAUTHORIZED_TOOL_USE": {  # Underscore version
            "scanner_category": "SECURITY VIOLATION",
            "severity": "MEDIUM",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.1",
            "aisubtech_name": "Tool Abuse",
            "description": "Using tools or capabilities beyond declared permissions.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "DECEPTIVE CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Deceptive or Misleading Content",
            "description": "Misleading descriptions or deceptive metadata.",
        },
        "SOCIAL_ENGINEERING": {  # Underscore version
            "scanner_category": "DECEPTIVE CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Deceptive or Misleading Content",
            "description": "Misleading descriptions or deceptive metadata.",
        },
        "RESOURCE ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.3",
            "aitech_name": "Availability Disruption",
            "aisubtech": "AISubtech-13.3.2",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Excessive resource consumption or denial of service.",
        },
        "RESOURCE_ABUSE": {  # Underscore version
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.3",
            "aitech_name": "Availability Disruption",
            "aisubtech": "AISubtech-13.3.2",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Excessive resource consumption or denial of service.",
        },
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override system instructions through direct input.",
        },
        "CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution.",
        },
        "INJECTION ATTACK": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts.",
        },
        "CREDENTIAL HARVESTING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized exposure or exfiltration of credentials or sensitive information.",
        },
        "SYSTEM MANIPULATION": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization.",
        },
    }

    # Behavioral Analyzer Threats
    BEHAVIORAL_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation",
            "description": "Malicious manipulation of tool metadata or descriptions that mislead the LLM.",
        },
        "RESOURCE EXHAUSTION": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.3",
            "aitech_name": "Availability Disruption",
            "aisubtech": "AISubtech-13.3.2",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Overloading the system via repeated invocations or large payloads to cause denial of service.",
        },
    }

    @classmethod
    def get_threat_mapping(cls, analyzer: str, threat_name: str) -> dict[str, Any]:
        """
        Get the AITech Taxonomy mapping for a given threat.

        Args:
            analyzer: The analyzer type ('llm', 'yara', 'behavioral')
            threat_name: The threat name from the analyzer

        Returns:
            Dictionary containing the threat mapping information including severity

        Raises:
            ValueError: If analyzer or threat_name is not found
        """
        analyzer_map: dict[str, dict[str, dict[str, Any]]] = {
            "llm": cls.LLM_THREATS,
            "yara": cls.YARA_THREATS,
            "behavioral": cls.BEHAVIORAL_THREATS,
            "static": cls.YARA_THREATS,  # Static analyzer uses same taxonomy as YARA
        }

        analyzer_lower = analyzer.lower()
        if analyzer_lower not in analyzer_map:
            raise ValueError(f"Unknown analyzer: {analyzer}")

        threats: dict[str, dict[str, Any]] = analyzer_map[analyzer_lower]
        threat_upper = threat_name.upper()

        if threat_upper not in threats:
            # Return generic mapping if not found
            return {
                "scanner_category": "UNKNOWN",
                "severity": "MEDIUM",
                "aitech": "AITech-99.9",
                "aitech_name": "Unknown Threat",
                "aisubtech": "AISubtech-99.9.9",
                "aisubtech_name": "Unclassified",
                "description": f"Unclassified threat: {threat_name}",
            }

        return threats[threat_upper]

    @classmethod
    def get_threat_category_from_aitech(cls, aitech_code: str) -> str:
        """
        Map AITech code to ThreatCategory enum value.

        Args:
            aitech_code: AITech code (e.g., "AITech-1.1")

        Returns:
            ThreatCategory enum value string (e.g., "prompt_injection")
        """
        # Map AITech codes to ThreatCategory enum values
        # Based on scanner_category mappings from all threat dictionaries
        aitech_to_category = {
            "AITech-1.1": "prompt_injection",  # Direct Prompt Injection
            "AITech-1.2": "prompt_injection",  # Indirect Prompt Injection
            "AITech-2.1": "social_engineering",  # Social Engineering
            "AITech-8.2": "data_exfiltration",  # Data Exfiltration / Exposure
            "AITech-9.1": "command_injection",  # Model or Agentic System Manipulation (injection attacks)
            "AITech-12.1": "unauthorized_tool_use",  # Tool Exploitation
            "AITech-13.3": "resource_abuse",  # Availability Disruption
            "AITech-15.1": "social_engineering",  # Harmful / Misleading / Inaccurate Content
            "AITech-99.9": "policy_violation",  # Unknown Threat
        }

        return aitech_to_category.get(aitech_code, "policy_violation")

    @classmethod
    def get_threat_mapping_by_aitech(cls, aitech_code: str) -> dict[str, Any]:
        """
        Get threat mapping information by AITech code.

        Args:
            aitech_code: AITech code (e.g., "AITech-1.1")

        Returns:
            Dictionary containing threat mapping information
        """
        # Search through all threat dictionaries to find matching AITech code
        threat_dicts: list[dict[str, dict[str, Any]]] = [cls.LLM_THREATS, cls.YARA_THREATS, cls.BEHAVIORAL_THREATS]
        for threat_dict in threat_dicts:
            for threat_name, threat_info in threat_dict.items():
                if threat_info.get("aitech") == aitech_code:
                    return threat_info

        # Return generic mapping if not found
        return {
            "scanner_category": "UNKNOWN",
            "severity": "MEDIUM",
            "aitech": aitech_code,
            "aitech_name": "Unknown Threat",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": f"Unclassified threat with AITech code: {aitech_code}",
        }


def _create_simple_mapping(threats_dict):
    """Create simplified mapping with threat_category, threat_type, and severity."""
    return {
        name: {
            "threat_category": info["scanner_category"],
            "threat_type": name.lower().replace("_", " "),
            "severity": info.get("severity", "UNKNOWN"),
        }
        for name, info in threats_dict.items()
    }


# Simplified mappings for analyzers (includes severity, category, and type)
LLM_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.LLM_THREATS)
YARA_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.YARA_THREATS)
BEHAVIORAL_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.BEHAVIORAL_THREATS)
STATIC_THREAT_MAPPING = YARA_THREAT_MAPPING  # Static uses same as YARA


def get_threat_severity(analyzer: str, threat_name: str) -> str:
    """
    Get severity level for a threat.

    Args:
        analyzer: Analyzer type
        threat_name: Threat name

    Returns:
        Severity string
    """
    try:
        mapping = ThreatMapping.get_threat_mapping(analyzer, threat_name)
        severity = mapping.get("severity", "MEDIUM")
        return str(severity) if severity is not None else "MEDIUM"
    except ValueError:
        return "MEDIUM"


def get_threat_category(analyzer: str, threat_name: str) -> str:
    """
    Get scanner category for a threat.

    Args:
        analyzer: Analyzer type
        threat_name: Threat name

    Returns:
        Category string
    """
    try:
        mapping = ThreatMapping.get_threat_mapping(analyzer, threat_name)
        category = mapping.get("scanner_category", "UNKNOWN")
        return str(category) if category is not None else "UNKNOWN"
    except ValueError:
        return "UNKNOWN"
