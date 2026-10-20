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
from collections.abc import Iterable
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
        # Alignment checks: bundled code that does not match its documented purpose
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Bundled code in a skill whose behavior does not match its documented purpose because "
            "it moves data out, such as a function described as local formatting or analysis that reads files, "
            "environment variables, or credentials and sends them to an external endpoint.",
        },
        "CREDENTIAL THEFT": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Bundled code in a skill that reads credentials it has no documented reason to touch, "
            "such as SSH keys, cloud provider credentials, access tokens, or .env files, inside functions whose "
            "names and docstrings describe unrelated work.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Bundled code in a skill that builds shell commands or interpreter calls from model or "
            "user input inside functions documented as safe or read-only, so unvalidated input reaches a shell or "
            "subprocess call the description does not disclose.",
        },
        "HIDDEN FUNCTIONALITY": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "HIGH",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Bundled code in a skill that performs undisclosed actions alongside its documented "
            "purpose, such as decoding and running embedded payloads, contacting unlisted hosts, or changing "
            "system state, hidden behind names, docstrings, and SKILL.md text that describe only the benign "
            "behavior.",
        },
        "ALIGNMENT MISMATCH": {
            "scanner_category": "PROTOCOL MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-4.3",
            "aitech_name": "Protocol Manipulation",
            "aisubtech": "AISubtech-4.3.5",
            "aisubtech_name": "Capability Inflation",
            "description": "A general mismatch between what a skill's SKILL.md, docstrings, or function names "
            "claim and what its bundled code does, where the code reaches capabilities or resources the "
            "description never mentions, misleading the user and the agent about the skill's real behavior.",
        },
        # Cross-file correlations: steps of one attack split across a skill's files
        "EXFILTRATION CHAIN": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Data flow across a skill's bundled files that adds up to exfiltration, where one file "
            "collects local files, secrets, or environment data and another sends it to a network endpoint, so no "
            "single file looks malicious when reviewed on its own.",
        },
        "CREDENTIAL NETWORK SEPARATION": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Credential access and network transmission split across separate files of a skill, "
            "where one script reads keys, tokens, or credential files and a different script makes outbound "
            "requests, hiding a credential theft path from per-file review.",
        },
        "ENV VAR EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Environment variables collected in one part of a skill and sent out in another, such "
            "as a helper that reads API keys or tokens from os.environ and a separate script that posts them to a "
            "remote server, moving secrets off the host running the agent.",
        },
    }

    # AI Defense Analyzer Threats
    # Note: Keys are the AI Defense guardrail rule names, violation and vulnerability
    # labels the analyzer reads from the API response. Coarse classifications such as
    # SECURITY_VIOLATION name no technique and are left out, so those findings stay
    # unmapped. Findings take their severity from the API response; the severity here
    # is the usual level for the label.
    AI_DEFENSE_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Text-based prompt techniques in a skill's SKILL.md, frontmatter, or bundled files "
            "that manipulate the agent into bypassing its safeguards or following attacker-defined goals once the "
            "skill is loaded, such as instruction overrides, encoded payloads, or fabricated authority (e.g., "
            '"ignore all previous instructions").',
        },
        "JAILBREAK": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Instructions or role-play setups in a skill that try to free the agent from its "
            "safety rules, such as personas declared to have no restrictions, fictional or hypothetical framing "
            "used to request harmful output, or claimed authorization, so the agent produces content or takes "
            "actions it would otherwise refuse.",
        },
        "HARASSMENT": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.8",
            "aisubtech_name": "Safety Harms and Toxicity: Harassment",
            "description": "Prompts, instructions, or content in a skill that enable, promote, or facilitate "
            "harassment, intimidation, or targeted abuse, such as templates for threatening or demeaning messages "
            "aimed at a named person or workflows that repeatedly contact the same target.",
        },
        "HATE SPEECH": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.9",
            "aisubtech_name": "Safety Harms and Toxicity: Hate Speech",
            "description": "Prompts, instructions, or content in a skill that enable, promote, or facilitate "
            "hateful, discriminatory, or demeaning expression targeting individuals or groups based on protected "
            "characteristics such as race, ethnicity, religion, nationality, disability, gender, or sexual "
            "orientation.",
        },
        "PROFANITY": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.11",
            "aisubtech_name": "Safety Harms and Toxicity: Profanity",
            "description": "Prompts, instructions, or content in a skill that contain or promote profane, vulgar, "
            "or offensive language, such as response templates, persona instructions, or bundled text that make "
            "the agent use obscene wording in its outputs or in messages it sends on the user's behalf.",
        },
        "SEXUAL CONTENT & EXPLOITATION": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.14",
            "aisubtech_name": "Safety Harms and Toxicity: Sexual Content and Exploitation",
            "description": "Prompts, instructions, or content in a skill that enable, promote, or facilitate "
            "sexually explicit, exploitative, abusive, or non-consensual material, such as templates or bundled "
            "assets that make the agent generate or distribute adult content involving real people or content "
            "that violates platform policies.",
        },
        "SOCIAL DIVISION & POLARIZATION": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.15",
            "aisubtech_name": "Safety Harms and Toxicity: Social Division and Polarization",
            "description": "Prompts, instructions, or content in a skill that encourage or reinforce social "
            "division, inequality, or polarization, such as templates that make the agent write divisive "
            "political or identity-based messaging or workflows that publish one-sided content at scale through "
            "connected accounts.",
        },
        "VIOLENCE & PUBLIC SAFETY THREATS": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.17",
            "aisubtech_name": "Safety Harms and Toxicity: Violence and Public Safety Threat",
            "description": "Prompts, instructions, or content in a skill that enable, promote, or facilitate "
            "violence, physical harm, or threats to public safety, such as instructions for attacking people or "
            "property, threatening messages, or weapon-building guidance the agent is asked to produce or act on.",
        },
        "CODE DETECTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-12.2",
            "aitech_name": "Insecure Output Handling",
            "aisubtech": "AISubtech-12.2.1",
            "aisubtech_name": "Code Detection / Malicious Code Output",
            "description": "Code in a skill's instructions, examples, or the agent's outputs that carries "
            "malicious or unsafe behavior and that the agent may write to disk or run without review, turning "
            "generated or embedded code into an execution path on the host running the agent.",
        },
        "PII": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.5",
            "aitech_name": "Personally Identifiable Information",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Exposure, collection, or transmission of personally identifiable information through "
            "a skill, such as email addresses, phone numbers, names, postal addresses, usernames, passwords, or "
            "government ID numbers in packaged files, or instructions and scripts that make the agent gather, "
            "log, or send such data without authorization.",
        },
        "PCI": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.6",
            "aitech_name": "Payment Card Industry Data",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Exposure or transmission of payment card industry data through a skill, such as "
            "credit card numbers, bank account and routing numbers, or tax identification numbers in packaged "
            "files, or instructions and scripts that collect full card details in chat or send them to endpoints "
            "outside a payment provider.",
        },
        "PHI": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.7",
            "aitech_name": "Protected Health Information",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Exposure or transmission of protected health information through a skill, such as "
            "patient IDs, medical license numbers, medications, or diagnoses in packaged files, or instructions "
            "and scripts that make the agent collect, store, or send health records outside the systems "
            "authorized to hold them.",
        },
        "SAFETY VIOLATION": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.25",
            "aisubtech_name": "General Harms",
            "description": "Prompts, instructions, or content in a skill that contain or request harmful material "
            "outside a more specific harm category, such as step-by-step guidance for dangerous or illegal acts, "
            "persuasive harmful content, or prompt fragments the agent is asked to complete with harmful text.",
        },
        "PRIVACY VIOLATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Unauthorized exposure of private or sensitive information through a skill, where its "
            "instructions, scripts, or packaged data reveal personal, confidential, or regulated data to people "
            "or systems that should not receive it, through agent outputs, logs, generated files, or outbound "
            "requests.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the behavior of tools or scripts a skill provides "
            "or invokes, through tampered bundled code, poisoned configuration, or hidden instructions in tool "
            "descriptions, so the agent acts on deceptive or malicious outputs while appearing to run a "
            "legitimate skill.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized movement of sensitive information out of the user's environment through "
            "a skill's tools, scripts, or instructions, such as reading files, environment variables, "
            "credentials, or conversation data and sending them to external servers or third parties through "
            "hidden or undisclosed functionality.",
        },
        "DATA LEAK": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Unintentional or unauthorized exposure of sensitive information by a skill, such as "
            "secrets, internal documents, or user data appearing in agent outputs, logs, generated files, or "
            "error messages, without a deliberate transfer to an attacker-controlled destination.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious command sequences into shell invocations made by a skill's "
            "scripts or instructions, typically through string concatenation, unquoted variables, or shell=True "
            "calls that carry model or user input, leading to remote code execution or compromise of the host "
            "running the agent.",
        },
        "CODE INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting code that a skill's scripts evaluate or load, such as model or user input "
            "passed to eval, exec, dynamic imports, or template rendering, so attacker-supplied text runs as code "
            "with the skill's permissions on the host running the agent.",
        },
        "INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "the scripts or tools a skill runs on model or user input, leading to data exposure, remote code "
            "execution, or compromise of the underlying system environment.",
        },
        "SQL INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting SQL into queries that a skill's scripts build from model or user input "
            "through string concatenation or formatting instead of parameterized calls, letting attacker-supplied "
            "text read, modify, or delete data in the databases the skill connects to.",
        },
        "XSS": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting script or markup into HTML, reports, or web pages that a skill generates or "
            "serves, where model or user input is rendered without escaping, so the content runs in a viewer's "
            "browser and can steal session data or act on the user's behalf.",
        },
        "INSECURE FUNCTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Use of insecure functions in a skill's bundled code, such as eval, exec, unsafe "
            "deserialization, or shell execution helpers, that let model or user input decide what code runs, "
            "leading to unsolicited or unauthorized code execution on the host running the agent.",
        },
        "PATH TRAVERSAL": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Reading or writing files outside the paths a skill should touch, by passing model or "
            "user input such as ../ sequences or absolute paths into file operations, giving the agent access to "
            "credentials, configuration, or system files on the host without authorization.",
        },
        "CREDENTIAL THEFT": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Unauthorized collection or exfiltration of credentials by a skill, such as reading "
            "SSH keys, cloud provider credentials, browser-stored passwords, .env files, or token caches and then "
            "storing, printing, or sending them, enabling account takeover or access to the services those "
            "credentials protect.",
        },
        "HARDCODED SECRET": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Credentials, API keys, tokens, private keys, or passwords hardcoded in a skill's "
            "SKILL.md, bundled scripts, or packaged configuration files, exposing them to anyone who installs or "
            "reads the skill and enabling unauthorized access to the services they protect.",
        },
        "SENSITIVE DATA": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Sensitive data present in or handled by a skill, such as credentials, personal data, "
            "internal documents, or proprietary code in packaged files or in content the skill passes through the "
            "agent, where exposure would harm the user or the organization.",
        },
        "MALWARE": {
            "scanner_category": "MALWARE",
            "severity": "HIGH",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Cybersecurity and Hacking: Malware / Exploits",
            "description": "Prompts, instructions, or bundled code in a skill that create, deliver, or run "
            "malicious software, such as scripts that encrypt user files, open reverse shells, install "
            "persistence, or download and execute payloads, or instructions that make the agent write working "
            "malware or exploits.",
        },
        "OBFUSCATION": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "MEDIUM",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Deliberately obfuscated or encoded content in a skill, such as base64 or hex "
            "payloads, packed or minified scripts, commands assembled from string fragments, or invisible Unicode "
            "characters, used to hide malicious instructions or code from reviewers and scanners while the agent "
            "still decodes and runs it.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.12",
            "aisubtech_name": "Safety Harms and Toxicity: Scams and Deception",
            "description": "Misleading descriptions, deceptive metadata, or manipulative instructions in a skill "
            "that misrepresent what it does or who published it, using false claims, fake urgency, or "
            "impersonated authority to win the trust of the user or the agent and obtain approvals, data, or "
            "actions they would otherwise refuse.",
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
            analyzer: The analyzer type ('llm', 'yara', 'static', 'behavioral', 'ai_defense')
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
            "ai_defense": cls.AI_DEFENSE_THREATS,
            "aidefense": cls.AI_DEFENSE_THREATS,  # Analyzer name on AI Defense findings
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
_BUILTIN_THREAT_TABLES: dict[str, dict[str, dict[str, Any]]] = {
    "behavioral": _BASE_BEHAVIORAL_THREATS,
    "ai_defense": ThreatMapping.AI_DEFENSE_THREATS,
}


def get_threat_codes(analyzer: str, threat_names: Iterable[str] | None = None) -> dict[str, str]:
    """Return ``{threat name: taxonomy code}`` from an analyzer's built-in threat table.

    The code is the sub-technique when the threat has one, otherwise the
    technique.  The AI Defense analyzer and the behavioral alignment and
    cross-file checks choose a code per finding from these tables, so their
    codes are defined here next to every other threat.  Names keep the
    spelling the caller passes and are matched like ``get_threat_mapping``
    matches them.  Custom threat-mapping files do not change these codes.

    Raises:
        ValueError: If a requested name is not in the table.
    """
    table = _BUILTIN_THREAT_TABLES[analyzer]
    names = list(table) if threat_names is None else list(threat_names)
    codes: dict[str, str] = {}
    for name in names:
        info = table.get(name.upper().replace("_", " ").strip())
        if info is None:
            raise ValueError(f"Unknown threat {name!r} for analyzer {analyzer!r}")
        codes[name] = info["aisubtech"] or info["aitech"]
    return codes


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
# These are initialized by configure_threat_mappings() above, except the AI
# Defense mapping, which custom threat-mapping files do not override.
API_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.AI_DEFENSE_THREATS)


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
