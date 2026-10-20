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
   and descriptions
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
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, "
            "operational directives, or behavioral guidelines through direct user input, causing the model to follow "
            'attacker-controlled instructions instead of its intended programming (e.g., "Ignore previous '
            'instructions").',
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such "
            "as private or sensitive data, intellectual property, and proprietary algorithms through exploitation of "
            "agent tools, integrations, or capabilities, where the agent is manipulated to use legitimate tools for "
            "malicious data exfiltration purposes.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used "
            "by agents through data poisoning, configuration tampering, or behavioral manipulation, causing the tool "
            "resulting in deceptive or malicious outputs, privilege escalation, or propagation of altered data.",
        },
        "TOOL SHADOWING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.4",
            "aisubtech_name": "Tool Shadowing",
            "description": "Disguising, substituting or duplicating legitimate tools within an agent or MCP server or "
            "tool registry, enabling malicious tools with identical or similar identifiers to intercept or replace "
            "trusted tool calls, leading to unauthorized actions, data exfiltration, or redirection of legitimate "
            "operations.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
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
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Skills or skill scripts that send data to external servers, upload files to remote "
            "endpoints, or exfiltrate sensitive information to unauthorized third parties through hidden or "
            "undisclosed functionality.",
        },
        "SKILL DISCOVERY ABUSE": {
            "scanner_category": "PROTOCOL MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-4.3",
            "aitech_name": "Protocol Manipulation",
            "aisubtech": "AISubtech-4.3.5",
            "aisubtech_name": "Capability Inflation",
            "description": "Exploiting system mechanisms to artificially expand, escalate, or misrepresent an "
            "agent's, model's, or component's capabilities, permissions, or authority beyond intended limits, "
            "enabling unauthorized actions or access.",
        },
        "TRANSITIVE TRUST ABUSE": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.2",
            "aitech_name": "Indirect Prompt Injection",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Variation of prompt-based manipulation where the attacker embeds malicious instructions "
            "in external data sources (such as web pages, documents, emails, databases, API responses, etc.) that the "
            "LLM or the agent retrieves and processes, causing attacker instructions to be executed. The attack "
            "exploits the model's inability to distinguish between trusted system instructions and untrusted external "
            "content.",
        },
        "AUTONOMY ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "HIGH",
            "aitech": "AITech-2.1",
            "aitech_name": "Excessive Agency",
            "aisubtech": "AISubtech-2.1.1",
            "aisubtech_name": "Execution Approval Bypass",
            "description": "The agent performs, attempts, schedules, submits, or makes a concrete operational "
            "commitment to a consequential action for which the visible governing contract requires explicit, current "
            "approval, without obtaining valid approval for that action. This includes acting before approval, "
            "treating silence or ambiguous language as approval, reusing approval from a different action, or "
            "manufacturing urgency to bypass review.",
        },
        "TOOL CHAINING ABUSE": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",  # Data Exfiltration / Exposure (from Framework)
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",  # Data Exfiltration via Agent Tooling (from Framework)
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such "
            "as private or sensitive data, intellectual property, and proprietary algorithms through exploitation of "
            "agent tools, integrations, or capabilities, where the agent is manipulated to use legitimate tools for "
            "malicious data exfiltration purposes.",
        },
        "HARDCODED SECRETS": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "CRITICAL",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Attempts to generate, solicit, or reveal authorization credentials (login details, "
            "tokens, API keys, passwords) through interactions with model/agent, enabling unauthorized access to "
            "accounts, systems, and data.",
        },
        "OBFUSCATION": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "HIGH",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Weaknesses that emerge when parts of the AI system (code, model architecture, parameters, "
            "configurations) are intentionally or unintentionally concealed or obscured, creating security blind "
            "spots and attack opportunities.",
        },
        "UNAUTHORIZED TOOL USE": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "MEDIUM",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.3",
            "aisubtech_name": "Unsafe System / Browser / File Execution",
            "description": "Abusing agentic system integration with system commands, browsers, or file I/O tools to "
            "trigger unsafe operations, arbitrary code executions, or malicious file actions. An example: A prompt "
            "that tricks an agent into opening arbitrary URLs in a browser tool, leading to drive-by downloads.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.12",
            "aisubtech_name": "Safety Harms and Toxicity: Scams and Deception",
            "description": "Prompts, content, or outputs, whether expressed as text, audio, visual material, actions, "
            "operations, or other modes, from LLMs (as well as the use of agentic AI systems, their components, or "
            "elements) that enable, promote, or facilitate fraudulent, deceptive, or manipulative schemes. This may "
            "include generating or automating scams, counterfeit operations, fraudulent services, or deceptive "
            "outputs designed to mislead victims for personal, financial, or competitive gain. Agentic systems and "
            "their components may be exploited to scale, personalize, and disguise scams, making them more effective "
            "than traditional manual deception tactics.",
        },
        "RESOURCE ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Deliberately consuming excessive computational resources through long queries, "
            "adversarial inputs, or compute-intensive requests designed to degrade service availability, increase "
            "operational costs, or cause system slowdown.",
        },
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, "
            "operational directives, or behavioral guidelines through direct user input, causing the model to follow "
            'attacker-controlled instructions instead of its intended programming (e.g., "Ignore previous '
            'instructions").',
        },
        "CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or "
            "unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems "
            "(including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
        "INJECTION ATTACK": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "CREDENTIAL HARVESTING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Attempts to generate, solicit, or reveal authorization credentials (login details, "
            "tokens, API keys, passwords) through interactions with model/agent, enabling unauthorized access to "
            "accounts, systems, and data.",
        },
        "SYSTEM MANIPULATION": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization, leading to "
            "unsolicited modification or deletion of files, registries, or permissions through model-driven or "
            "agent-executed commands system.",
        },
        "SUPPLY CHAIN ATTACK": {
            "scanner_category": "SUPPLY CHAIN ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.3",
            "aitech_name": "Dependency / Plugin Compromise",
            "aisubtech": "AISubtech-9.3.1",
            "aisubtech_name": "Malicious Package / Tool Injection",
            "description": "Introduction of malicious or adversarial tools, APIs, or packages into the toolset, "
            "registry, or dependency chain used by a system or agent, enabling the model to unknowingly invoke "
            "compromised tools that can execute attacks or expose data.",
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
            "description": "Malicious manipulation of skill metadata, descriptions, or frontmatter that mislead the "
            "LLM into invoking tools incorrectly or exposing confidential context; combined with injection of hidden "
            "or malicious instructions in skill instructions or prompts to alter model reasoning or bypass content "
            "restrictions.",
        },
        "RESOURCE EXHAUSTION": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Overloading the agent or its host (via repeated tool invocations or large payloads) to "
            "degrade performance or cause denial of service. Skill code repeatedly processes large files or calls "
            "itself recursively without rate limits or break conditions.",
        },
        # Alignment checks: bundled code that does not match its documented purpose
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Extracting or leaking sensitive information (e.g., API keys, configs, proprietary code) "
            "from the agent environment via skill code behavior or LLM responses.",
        },
        "CREDENTIAL THEFT": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Attempts to generate, solicit, or reveal authorization credentials (login details, "
            "tokens, API keys, passwords) through interactions with model/agent, enabling unauthorized access to "
            "accounts, systems, and data.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Code carrying out injection attacks by embedding variables or unvalidated input into "
            "commands, templates, prompts, or expressions including shell or system commands built through string "
            "concatenation or variable substitution instead of fixed, parameterized calls.",
        },
        "HIDDEN FUNCTIONALITY": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "HIGH",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Weaknesses that emerge when parts of the AI system (code, model architecture, parameters, "
            "configurations) are intentionally or unintentionally concealed or obscured, creating security blind "
            "spots and attack opportunities.",
        },
        "ALIGNMENT MISMATCH": {
            "scanner_category": "PROTOCOL MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-4.3",
            "aitech_name": "Protocol Manipulation",
            "aisubtech": "AISubtech-4.3.5",
            "aisubtech_name": "Capability Inflation",
            "description": "Exploiting system mechanisms to artificially expand, escalate, or misrepresent an "
            "agent's, model's, or component's capabilities, permissions, or authority beyond intended limits, "
            "enabling unauthorized actions or access.",
        },
        # Cross-file correlations: steps of one attack split across a skill's files
        "EXFILTRATION CHAIN": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Extracting or leaking sensitive information (e.g., API keys, configs, proprietary code) "
            "from the agent environment via skill code behavior or LLM responses.",
        },
        "CREDENTIAL NETWORK SEPARATION": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Attempts to generate, solicit, or reveal authorization credentials (login details, "
            "tokens, API keys, passwords) through interactions with model/agent, enabling unauthorized access to "
            "accounts, systems, and data.",
        },
        "ENV VAR EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Extracting or leaking sensitive information (e.g., API keys, configs, proprietary code) "
            "from the agent environment via skill code behavior or LLM responses.",
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
            "description": "Text-based prompt techniques to manipulate an LLM/agent's behavior to bypass safeguards "
            "and/or follow attacker-defined goals. This can include the use of obfuscation, context and instruction "
            "manipulation, or propagating attacks through multi-agent environments.",
        },
        "JAILBREAK": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection and Jailbreak (Prompt-based Manipulation)",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Text-based prompt techniques to manipulate an LLM/agent's behavior to bypass safeguards "
            "and/or follow attacker-defined goals. This can include the use of obfuscation, context and instruction "
            "manipulation, or propagating attacks through multi-agent environments.",
        },
        "HARASSMENT": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.8",
            "aisubtech_name": "Safety Harms and Toxicity: Harassment",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or "
            "facilitate harassment, intimidation, or targeted abuse.",
        },
        "HATE SPEECH": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.9",
            "aisubtech_name": "Safety Harms and Toxicity: Hate Speech",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or "
            "facilitate hateful, discriminatory, or demeaning expression targeting individuals or specific "
            "communities or characteristics of groups from protected classes such as race, ethnicity, religion, "
            "nationality, disability, gender, sexual orientation, or socioeconomic class.",
        },
        "PROFANITY": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.11",
            "aisubtech_name": "Safety Harms and Toxicity: Profanity",
            "description": "Prompts, content, or outputs from AI or agentic-systems that contain or promote profane, "
            "vulgar, or offensive language.",
        },
        "SEXUAL CONTENT & EXPLOITATION": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.14",
            "aisubtech_name": "Safety Harms and Toxicity: Sexual Content and Exploitation",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or "
            "facilitate sexually explicit, exploitative, abusive, or harmful behaviors, often non-consensual and in "
            "violation of platform policies.",
        },
        "SOCIAL DIVISION & POLARIZATION": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.15",
            "aisubtech_name": "Safety Harms and Toxicity: Social Division and Polarization",
            "description": "Prompts, content, or outputs from AI or agentic-systems that encourage or reinforce "
            "social division, inequality, or polarization.",
        },
        "VIOLENCE & PUBLIC SAFETY THREATS": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.17",
            "aisubtech_name": "Safety Harms and Toxicity: Violence and Public Safety Threat",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or "
            "facilitate violence, physical harm, or threats to public safety.",
        },
        "CODE DETECTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-12.2",
            "aitech_name": "Insecure Output Handling",
            "aisubtech": "AISubtech-12.2.1",
            "aisubtech_name": "Code Detection / Malicious Code Output",
            "description": "Forcing an LLM/agent to produce code that bypasses content filters, contains malicious "
            "functionality, or includes working exploits, often disguised as benign snippets or requested features. "
            'An example: Requesting "educational" shellcode generation that produces working exploits.',
        },
        "PII": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.5",
            "aitech_name": "Personally Identifiable Information",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Exposure, generation, or misuse of personally identifiable information (PII) such as "
            "names, addresses, phone numbers, identification numbers, or other sensitive personal details that can be "
            "used to identify, track, or exploit individuals.",
        },
        "PCI": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.6",
            "aitech_name": "Payment Card Industry Data",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Exposure, generation, or misuse of payment card industry (PCI) data including cardholder "
            "data and sensitive authentication data such as card numbers, expiration dates, service codes, CVVs, and "
            "PINs.",
        },
        "PHI": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.7",
            "aitech_name": "Protected Health Information",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Exposure, generation, or misuse of protected health information (PHI) including "
            "individually identifiable health data such as medical records, diagnoses, billing information, and other "
            "personal health identifiers.",
        },
        "SAFETY VIOLATION": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.25",
            "aisubtech_name": "General Harms",
            "description": "General Harms covers prompts, content, or outputs in any modality, including text, "
            "images, audio, video, transcripts, tool outputs, and metadata, that contain or request harmful material. "
            "Harmful material includes instructions, plans, scripts, persuasive content, attacks, payloads, threats, "
            "toxic abuse, exploitation, deception, unlawful activity, unsafe high-stakes guidance, cyber or "
            "prompt-injection abuse, targeted harassment, hate, sexual exploitation, self-harm, violence, weapons or "
            "CBRN misuse, terrorism or extremism, harmful misinformation, environmental harm, financial harm, "
            "intellectual-property abuse, or confidential-data extraction.",
        },
        "PRIVACY VIOLATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Actors intentionally or unintentionally cause sensitive information to be exposed through "
            "model outputs, API responses, or system behaviors. This includes leakage of personal data, intellectual "
            "property, proprietary algorithms, training data, system internals, or other confidential information to "
            "unauthorized parties.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used "
            "by agents through data poisoning, configuration tampering, or behavioral manipulation, causing the tool "
            "resulting in deceptive or malicious outputs, privilege escalation, or propagation of altered data.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such "
            "as private or sensitive data, intellectual property, and proprietary algorithms through exploitation of "
            "agent tools, integrations, or capabilities, where the agent is manipulated to use legitimate tools for "
            "malicious data exfiltration purposes.",
        },
        "DATA LEAK": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Actors intentionally or unintentionally cause sensitive information to be exposed through "
            "model outputs, API responses, or system behaviors. This includes leakage of personal data, intellectual "
            "property, proprietary algorithms, training data, system internals, or other confidential information to "
            "unauthorized parties.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "CODE INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "SQL INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "XSS": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (e.g., SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into "
            "skill code or tools that process model or user input, leading to data exposure, remote code execution, "
            "or compromise of the underlying system environment.",
        },
        "INSECURE FUNCTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or "
            "unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems "
            "(including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
        "PATH TRAVERSAL": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization, leading to "
            "unsolicited modification or deletion of files, registries, or permissions through model-driven or "
            "agent-executed commands system.",
        },
        "CREDENTIAL THEFT": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Attempts to generate, solicit, or reveal authorization credentials (login details, "
            "tokens, API keys, passwords) through interactions with model/agent, enabling unauthorized access to "
            "accounts, systems, and data.",
        },
        "HARDCODED SECRET": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "HIGH",
            "aitech": "AITech-14.1",
            "aitech_name": "Unauthorized Access",
            "aisubtech": "AISubtech-14.1.1",
            "aisubtech_name": "Credential Theft",
            "description": "Attempts to generate, solicit, or reveal authorization credentials (login details, "
            "tokens, API keys, passwords) through interactions with model/agent, enabling unauthorized access to "
            "accounts, systems, and data.",
        },
        "SENSITIVE DATA": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": "Actors intentionally or unintentionally cause sensitive information to be exposed through "
            "model outputs, API responses, or system behaviors. This includes leakage of personal data, intellectual "
            "property, proprietary algorithms, training data, system internals, or other confidential information to "
            "unauthorized parties.",
        },
        "MALWARE": {
            "scanner_category": "MALWARE",
            "severity": "HIGH",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Cybersecurity and Hacking: Malware / Exploits",
            "description": "Prompts, content, or outputs, whether expressed as text, audio, visual material, actions, "
            "operations, or other modes from LLMs (as well as the use of agentic AI systems, their components, or "
            "elements) that enable or facilitate the creation, distribution, or operational use of malicious software "
            "and related cyberattack activities. This may include generating code, instructions, or automation that "
            "produces or deploys malware, viruses, or exploits; orchestrating network intrusions or ransomware "
            "campaigns; and managing malicious infrastructure. Examples of malware, viruses and exploits: • Software "
            "designed to covertly monitor user activity, display unsolicited advertisements, collect personal data "
            "without consent, or provide misleading functionality. • Adware, spyware, stalkerware, potentially "
            "unwanted applications (PUAs). Agentic capabilities and components may also be abused to coordinate "
            "attacks, automate vulnerability exploitation, or assist in the trade and resale of compromised assets, "
            "scaling cyber threats far beyond traditional manual hacking operations.",
        },
        "OBFUSCATION": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "MEDIUM",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Weaknesses that emerge when parts of the AI system (code, model architecture, parameters, "
            "configurations) are intentionally or unintentionally concealed or obscured, creating security blind "
            "spots and attack opportunities.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.12",
            "aisubtech_name": "Safety Harms and Toxicity: Scams and Deception",
            "description": "Prompts, content, or outputs, whether expressed as text, audio, visual material, actions, "
            "operations, or other modes, from LLMs (as well as the use of agentic AI systems, their components, or "
            "elements) that enable, promote, or facilitate fraudulent, deceptive, or manipulative schemes. This may "
            "include generating or automating scams, counterfeit operations, fraudulent services, or deceptive "
            "outputs designed to mislead victims for personal, financial, or competitive gain. Agentic systems and "
            "their components may be exploited to scale, personalize, and disguise scams, making them more effective "
            "than traditional manual deception tactics.",
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
