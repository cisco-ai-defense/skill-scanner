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

The module is organized into two main sections:
1. THREAT DEFINITIONS: Complete threat definitions with taxonomy mappings, severity,
   and a description of how the threat shows up in a skill
2. CUSTOM MAPPINGS & HELPER FUNCTIONS: Overrides from SKILL_SCANNER_THREAT_MAPPING_PATH,
   lightweight mappings, and lookup helpers

Codes and names follow the bundled Cisco AI Security & Safety Taxonomy snapshot.
The taxonomy's own definition of each code is available from
``cisco_ai_taxonomy.get_aitech_definition`` and ``get_aisubtech_definition``.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# SECTION 1: THREAT DEFINITIONS
# =============================================================================


class ThreatMapping:
    """Mapping of threat names to AITech Taxonomy classifications with severity."""

    # LLM Analyzer Threats
    LLM_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation",
            "description": "Explicit attempts in a skill's SKILL.md instructions, frontmatter, or bundled reference "
            "files to override, replace, or reprioritize the agent's system instructions, developer directives, or "
            "safety rules, causing the agent to follow attacker-controlled instructions instead of its intended "
            'behavior once the skill is loaded (e.g., "Ignore all previous instructions").',
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such "
            "as credentials, source code, private files, or conversation data, through the tools, scripts, and "
            "integrations a skill gives the agent, where legitimate capabilities like file reads, shell commands, or "
            "network requests are used to move data to destinations the user did not intend.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools or "
            "scripts a skill provides or invokes, through tampered bundled code, poisoned configuration, or hidden "
            "instructions in tool descriptions, causing the agent to act on deceptive or malicious outputs, escalate "
            "privileges, or propagate altered data while appearing to run a legitimate skill.",
        },
        "TOOL SHADOWING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.4",
            "aisubtech_name": "Tool Shadowing",
            "description": "Disguising, substituting, or duplicating legitimate tools, commands, or skills within the "
            "agent's environment, enabling a malicious skill with an identical or similar name, trigger description, "
            "or script to intercept or replace trusted tool calls, leading to unauthorized actions, data "
            "exfiltration, or redirection of legitimate operations.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as shell command sequences, SQL queries, or scripts "
            "into skill scripts or instructions that process model or user input, so that unvalidated input reaches a "
            "shell, interpreter, or query engine, leading to data exposure, remote code execution, or compromise of "
            "the host running the agent.",
        },
    }

    # YARA/Static Analyzer Threats
    YARA_THREATS = {
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious command sequences into shell invocations made by a skill's scripts or "
            "instructions, typically through string concatenation, unquoted variables, or shell=True calls that carry "
            "model or user input, leading to remote code execution or compromise of the host running the agent.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized exposure or exfiltration of sensitive information through a skill's scripts "
            "or instructions, where files, environment variables, credentials, or agent context are read and then "
            "sent to external servers, uploaded to remote endpoints, or passed to third parties through hidden or "
            "undisclosed functionality.",
        },
        "SKILL DISCOVERY ABUSE": {
            "scanner_category": "PROTOCOL MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-4.3",
            "aitech_name": "Protocol Manipulation",
            "aisubtech": "AISubtech-4.3.5",
            "aisubtech_name": "Capability Inflation",
            "description": "Manipulation of skill discovery and activation through inflated or misleading metadata, "
            "where a skill's name or frontmatter description uses keyword baiting, over-broad trigger phrases, or "
            "brand impersonation so the agent loads it more often or for tasks it should not handle.",
        },
        "TRANSITIVE TRUST ABUSE": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.2",
            "aitech_name": "Indirect Prompt Injection",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Embedding or relaying malicious instructions through external data sources a skill tells "
            "the agent to trust, such as webpages, documents, API responses, or downloaded files, so the agent "
            "follows instructions found in that content, runs code blocks it encounters, or treats third-party text "
            "as if it came from the user or the skill author.",
        },
        "AUTONOMY ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "HIGH",
            "aitech": "AITech-2.1",
            "aitech_name": "Excessive Agency",
            "aisubtech": "AISubtech-2.1.1",
            "aisubtech_name": "Execution Approval Bypass",
            "description": "Granting the agent excessive autonomy without bounds, where skill instructions tell it to "
            "skip confirmation prompts, bypass approval steps, retry indefinitely, ignore errors, or run destructive "
            "or high-impact actions without the user's explicit consent, removing the human checkpoints the host "
            "normally enforces.",
        },
        "TOOL CHAINING ABUSE": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",  # Data Exfiltration / Exposure (from Framework)
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",  # Data Exfiltration via Agent Tooling (from Framework)
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Suspicious multi-step tool chaining in a skill's instructions or scripts that combines "
            "individually harmless steps into data exfiltration, such as read-then-send, collect-then-post, or "
            "traverse-then-upload sequences that move local files, secrets, or agent context to an external "
            "destination.",
        },
        "HARDCODED SECRETS": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "CRITICAL",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Credentials, API keys, tokens, private keys, or passwords hardcoded in a skill's "
            "SKILL.md, bundled scripts, or packaged configuration files, exposing them to anyone who installs or "
            "reads the skill and enabling unauthorized access to the services they protect.",
        },
        "OBFUSCATION": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "HIGH",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Deliberately obfuscated or encoded content in a skill, such as base64 or hex payloads, "
            "packed or minified scripts, commands assembled from string fragments, or invisible Unicode characters, "
            "used to hide malicious instructions or code from reviewers and scanners while the agent still decodes "
            "and runs it.",
        },
        "UNAUTHORIZED TOOL USE": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "MEDIUM",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.3",
            "aisubtech_name": "Unsafe System / Browser / File Execution",
            "description": "Using tools or capabilities beyond what a skill declares, such as running shell commands, "
            "writing files, launching browsers, or reaching system resources not covered by its allowed-tools or "
            "described purpose, causing system, browser, or file execution the user did not approve when installing "
            "the skill.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.12",
            "aisubtech_name": "Safety Harms and Toxicity: Scams and Deception",
            "description": "Misleading descriptions, deceptive metadata, or manipulative instructions in a skill that "
            "misrepresent what it does or who published it, using false claims, fake urgency, or impersonated "
            "authority to win the trust of the user or the agent and obtain approvals, data, or actions they would "
            "otherwise refuse.",
        },
        "RESOURCE ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Excessive consumption of compute, memory, disk, or API capacity by a skill's scripts or "
            "instructions, such as unbounded loops, fork bombs, recursive invocations, or processing oversized "
            "payloads without limits, degrading the host running the agent or causing denial of service.",
        },
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation",
            "description": "Explicit attempts in a skill's SKILL.md instructions, frontmatter, or bundled reference "
            "files to override, replace, or reprioritize the agent's system instructions, developer directives, or "
            "safety rules, causing the agent to follow attacker-controlled instructions instead of its intended "
            'behavior once the skill is loaded (e.g., "Ignore all previous instructions").',
        },
        "CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code through a skill, such as eval, "
            "exec, compile, dynamic imports, or scripts that download and run further code, leading to unsolicited or "
            "unauthorized code execution on the host running the agent.",
        },
        "INJECTION ATTACK": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into the "
            "scripts or tools a skill runs on model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "CREDENTIAL HARVESTING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Unauthorized collection or exfiltration of credentials by a skill, such as reading SSH "
            "keys, cloud provider credentials, browser-stored passwords, .env files, or token caches and then "
            "storing, printing, or sending them, enabling account takeover or access to the services those "
            "credentials protect.",
        },
        "SYSTEM MANIPULATION": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization through a "
            "skill's scripts or instructions, leading to unsolicited modification or deletion of files, permissions, "
            "shell profiles, scheduled tasks, or agent configuration through commands the agent runs on the user's "
            "behalf.",
        },
        "SUPPLY CHAIN ATTACK": {
            "scanner_category": "SUPPLY CHAIN ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.3",
            "aitech_name": "Dependency / Plugin Compromise",
            "aisubtech": "AISubtech-9.3.1",
            "aisubtech_name": "Malicious Package / Tool Injection",
            "description": "Introduction of malicious or tampered code into a skill package or its dependency chain, "
            "such as poisoned bytecode, archives that deliver payloads on extraction, or replaced dependencies and "
            "install steps, so the agent unknowingly runs compromised code when the skill is installed or used.",
        },
    }

    # Behavioral Analyzer Threats
    BEHAVIORAL_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation",
            "description": "Malicious manipulation of a skill's metadata, descriptions, or instruction text that "
            "misleads the agent into invoking tools incorrectly or exposing confidential context, combined with "
            "hidden or conflicting instructions that alter the agent's reasoning or bypass the host's content "
            "restrictions.",
        },
        "RESOURCE EXHAUSTION": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Overloading the host running the agent through a skill's code, such as repeated tool "
            "invocations, unbounded loops or recursion, or processing large files without rate limits or break "
            "conditions, degrading performance or causing denial of service.",
        },
    }

    # Canonical mapping from AITech code to internal ThreatCategory enum value.
    # This can be extended/overridden via SKILL_SCANNER_THREAT_MAPPING_PATH.
    AITECH_TO_CATEGORY = {
        "AITech-1.1": "prompt_injection",  # Direct Prompt Injection
        "AITech-1.2": "prompt_injection",  # Indirect Prompt Injection
        "AITech-1.3": "prompt_injection",  # Multimodal Injection and Manipulation
        "AITech-2.1": "autonomy_abuse",  # Excessive Agency
        "AITech-4.3": "skill_discovery_abuse",  # Protocol Manipulation / Capability Inflation
        "AITech-8.2": "data_exfiltration",  # Data Exfiltration / Exposure
        "AITech-8.4": "data_exfiltration",  # Prompt/Meta Extraction
        "AITech-9.1": "command_injection",  # Model or Agentic System Manipulation (injection attacks)
        "AITech-9.2": "obfuscation",  # Detection Evasion / Obfuscation Vulnerabilities
        "AITech-9.3": "supply_chain_attack",  # Dependency / Plugin Compromise
        "AITech-12.1": "unauthorized_tool_use",  # Tool Exploitation
        "AITech-13.1": "resource_abuse",  # Disruption of Availability (AISubtech-13.1.1: Compute Exhaustion)
        "AITech-14.1": "hardcoded_secrets",  # Unauthorized Access (credential theft)
        "AITech-15.1": "harmful_content",  # Harmful Content
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
        # Normalize: convert underscores to spaces for consistent lookup
        threat_upper = threat_name.upper().replace("_", " ")

        if threat_upper not in threats:
            # Unknown threats carry no taxonomy code rather than an invented one.
            return {
                "scanner_category": "UNKNOWN",
                "severity": "MEDIUM",
                "aitech": None,
                "aitech_name": None,
                "aisubtech": None,
                "aisubtech_name": None,
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
        return cls.AITECH_TO_CATEGORY.get(aitech_code, "policy_violation")

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

        from .cisco_ai_taxonomy import get_aitech_name

        # Return generic mapping if not found
        return {
            "scanner_category": "UNKNOWN",
            "severity": "MEDIUM",
            "aitech": aitech_code,
            "aitech_name": get_aitech_name(aitech_code),
            "aisubtech": None,
            "aisubtech_name": None,
            "description": f"Unclassified threat with AITech code: {aitech_code}",
        }

    @classmethod
    def get_framework_mappings_for_threat(cls, analyzer: str, threat_name: str) -> list[str]:
        """Get de-duplicated cross-framework mappings for a scanner threat."""
        from .cisco_ai_taxonomy import get_framework_mappings

        mapping = cls.get_threat_mapping(analyzer, threat_name)
        aitech_code = str(mapping.get("aitech") or "")
        aisubtech_code = str(mapping.get("aisubtech") or "")
        return get_framework_mappings(
            aitech_code=aitech_code if aitech_code.startswith("AITech-") else None,
            aisubtech_code=aisubtech_code if aisubtech_code.startswith("AISubtech-") else None,
        )


# =============================================================================
# SECTION 2: CUSTOM MAPPINGS & HELPER FUNCTIONS
# =============================================================================


_THREAT_MAPPING_ENV_VAR = "SKILL_SCANNER_THREAT_MAPPING_PATH"
_ACTIVE_THREAT_MAPPING_SOURCE = "builtin"

# Taxonomy codes set explicitly by a custom threat-mapping file, keyed by
# (threat table, threat name).  The scanner applies these to findings of the
# matching analyzer and category ahead of rule declarations, so an
# organization can remap bundled rules onto its own taxonomy.
_TAXONOMY_OVERRIDES: dict[tuple[str, str], tuple[str | None, str | None]] = {}
_ANALYZER_THREAT_TABLES = {
    "llm": "LLM_THREATS",
    "static": "YARA_THREATS",
    "yara": "YARA_THREATS",
    "behavioral": "BEHAVIORAL_THREATS",
}


def _load_custom_mapping_payload(path: Path) -> dict[str, Any]:
    """Load custom threat-mapping JSON payload."""
    if not path.exists():
        raise FileNotFoundError(f"Threat mapping file not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Threat mapping payload must be a JSON object")
    return payload


def _merge_threat_dict(base: dict[str, dict[str, Any]], override: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Merge per-threat overrides into a threat mapping dictionary."""
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in base.items()}
    for threat_name, threat_info in override.items():
        if not isinstance(threat_info, dict):
            raise ValueError(f"Threat override for {threat_name!r} must be an object")
        normalized = str(threat_name).upper().replace("_", " ")
        current = dict(merged.get(normalized, {}))
        current.update(threat_info)
        merged[normalized] = current
    return merged


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


# Built-in baseline copies (immutable) used for reset/reconfigure.
_BASE_LLM_THREATS: dict[str, dict[str, Any]] = {k: dict(v) for k, v in ThreatMapping.LLM_THREATS.items()}
_BASE_YARA_THREATS: dict[str, dict[str, Any]] = {k: dict(v) for k, v in ThreatMapping.YARA_THREATS.items()}
_BASE_BEHAVIORAL_THREATS: dict[str, dict[str, Any]] = {k: dict(v) for k, v in ThreatMapping.BEHAVIORAL_THREATS.items()}
_BASE_AITECH_TO_CATEGORY: dict[str, str] = dict(ThreatMapping.AITECH_TO_CATEGORY)


def _reset_threat_mapping_defaults() -> None:
    """Reset ThreatMapping class dictionaries to built-in defaults."""
    ThreatMapping.LLM_THREATS = {k: dict(v) for k, v in _BASE_LLM_THREATS.items()}
    ThreatMapping.YARA_THREATS = {k: dict(v) for k, v in _BASE_YARA_THREATS.items()}
    ThreatMapping.BEHAVIORAL_THREATS = {k: dict(v) for k, v in _BASE_BEHAVIORAL_THREATS.items()}
    ThreatMapping.AITECH_TO_CATEGORY = dict(_BASE_AITECH_TO_CATEGORY)
    _TAXONOMY_OVERRIDES.clear()


def _apply_custom_threat_mapping_payload(payload: dict[str, Any]) -> None:
    """Apply payload overrides on top of current ThreatMapping dictionaries."""
    key_map = {
        "llm_threats": "LLM_THREATS",
        "yara_threats": "YARA_THREATS",
        "behavioral_threats": "BEHAVIORAL_THREATS",
    }

    for key, value in payload.items():
        lower = key.lower()
        if lower in key_map:
            if not isinstance(value, dict):
                raise ValueError(f"{key} override must be an object")
            attr = key_map[lower]
            base = getattr(ThreatMapping, attr)
            setattr(ThreatMapping, attr, _merge_threat_dict(base, value))
            for threat_name, threat_info in value.items():
                if "aitech" in threat_info or "aisubtech" in threat_info:
                    normalized = str(threat_name).upper().replace("_", " ")
                    _TAXONOMY_OVERRIDES[(attr, normalized)] = (threat_info.get("aitech"), threat_info.get("aisubtech"))
        elif lower in {"aitech_to_category", "aitech_category_map"}:
            if not isinstance(value, dict):
                raise ValueError(f"{key} override must be an object")
            merged = dict(ThreatMapping.AITECH_TO_CATEGORY)
            merged.update({str(k): str(v) for k, v in value.items()})
            ThreatMapping.AITECH_TO_CATEGORY = merged


def configure_threat_mappings(path: str | Path | None = None) -> str:
    """Configure active threat mapping overrides from file or environment.

    Args:
        path: Optional JSON file path. If provided, it overrides
            SKILL_SCANNER_THREAT_MAPPING_PATH for the current process.

    Returns:
        Active source string ("builtin" or absolute mapping file path).
    """
    global LLM_THREAT_MAPPING
    global YARA_THREAT_MAPPING
    global BEHAVIORAL_THREAT_MAPPING
    global STATIC_THREAT_MAPPING
    global _ACTIVE_THREAT_MAPPING_SOURCE

    configured = str(path) if path is not None else os.getenv(_THREAT_MAPPING_ENV_VAR)
    if path is not None:
        if configured:
            os.environ[_THREAT_MAPPING_ENV_VAR] = configured
        else:
            os.environ.pop(_THREAT_MAPPING_ENV_VAR, None)

    _reset_threat_mapping_defaults()

    if configured:
        resolved = Path(configured).expanduser().resolve()
        payload = _load_custom_mapping_payload(resolved)
        _apply_custom_threat_mapping_payload(payload)
        _ACTIVE_THREAT_MAPPING_SOURCE = str(resolved)
        logger.info("Loaded custom threat mappings from %s", resolved)
    else:
        _ACTIVE_THREAT_MAPPING_SOURCE = "builtin"

    LLM_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.LLM_THREATS)
    YARA_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.YARA_THREATS)
    BEHAVIORAL_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.BEHAVIORAL_THREATS)
    STATIC_THREAT_MAPPING = YARA_THREAT_MAPPING
    return _ACTIVE_THREAT_MAPPING_SOURCE


def get_taxonomy_override(analyzer: str | None, category: str) -> tuple[str | None, str | None] | None:
    """Return ``(aitech, aisubtech)`` a custom threat-mapping file set for this analyzer and category."""
    table = _ANALYZER_THREAT_TABLES.get((analyzer or "").lower())
    if table is None:
        return None
    return _TAXONOMY_OVERRIDES.get((table, category.upper().replace("_", " ")))


def get_threat_mapping_source() -> str:
    """Return active threat-mapping source marker."""
    return _ACTIVE_THREAT_MAPPING_SOURCE


# Initialize runtime overrides once on module import.
try:
    configure_threat_mappings()
except Exception as e:
    logger.warning("Failed to load custom threat mapping overrides: %s", e)
    _reset_threat_mapping_defaults()
    _ACTIVE_THREAT_MAPPING_SOURCE = "builtin"
    LLM_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.LLM_THREATS)
    YARA_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.YARA_THREATS)
    BEHAVIORAL_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.BEHAVIORAL_THREATS)
    STATIC_THREAT_MAPPING = YARA_THREAT_MAPPING


# Simplified mappings for analyzers (includes severity, category, and type)
# These are initialized by configure_threat_mappings() above.


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
