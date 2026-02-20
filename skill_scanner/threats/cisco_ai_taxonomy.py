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
Cisco AI Security Framework - Ground Truth Taxonomy.

Source: https://learn-cloudsecurity.cisco.com/ai-security-framework
Owner: Ankit Garg
Last Updated: 2026-02-02

This file contains the authoritative AITech and AISubtech codes from the
Cisco Integrated AI Security and Safety Framework. All threat mappings in
threats.py must use codes that exist in this taxonomy.

To update this file when the framework changes:
1. Export data from https://learn-cloudsecurity.cisco.com/ai-security-framework
2. Update the dictionaries below
3. Run tests to validate threats.py alignment
"""

# Valid AITech codes and their official names
AITECH_TAXONOMY: dict[str, str] = {
    # OB-001: Goal Hijacking
    "AITech-1.1": "Direct Prompt Injection",
    "AITech-1.2": "Indirect Prompt Injection",
    "AITech-1.3": "Goal Manipulation",
    "AITech-1.4": "Multi-Modal Injection and Manipulation",
    # OB-002: Jailbreak
    "AITech-2.1": "Jailbreak",
    # OB-003: Masquerading / Obfuscation / Impersonation
    "AITech-3.1": "Masquerading / Obfuscation / Impersonation",
    # OB-004: Communication Compromise
    "AITech-4.1": "Agent Injection",
    "AITech-4.2": "Context Boundary Attacks",
    "AITech-4.3": "Protocol Manipulation",
    # OB-005: Persistence
    "AITech-5.1": "Memory System Persistence",
    "AITech-5.2": "Configuration Persistence",
    # OB-006: Feedback Loop Manipulation
    "AITech-6.1": "Training Data Poisoning",
    # OB-007: Sabotage / Integrity Degradation
    "AITech-7.1": "Reasoning Corruption",
    "AITech-7.2": "Memory System Corruption",
    "AITech-7.3": "Data Source Abuse and Manipulation",
    "AITech-7.4": "Token Manipulation",
    # OB-008: Data Privacy Violations
    "AITech-8.1": "Membership Inference",
    "AITech-8.2": "Data Exfiltration / Exposure",
    "AITech-8.3": "Information Disclosure",
    "AITech-8.4": "Prompt/Meta Extraction",
    # OB-009: Supply Chain Compromise
    "AITech-9.1": "Model or Agentic System Manipulation",
    "AITech-9.2": "Detection Evasion",
    "AITech-9.3": "Dependency / Plugin Compromise",
    # OB-010: Model Theft / Extraction
    "AITech-10.1": "Model Extraction",
    "AITech-10.2": "Model Inversion",
    # OB-011: Adversarial Evasion
    "AITech-11.1": "Environment-Aware Evasion",
    "AITech-11.2": "Model-Selective Evasion",
    # OB-012: Action-Space and Integration Abuse
    "AITech-12.1": "Tool Exploitation",
    "AITech-12.2": "Insecure Output Handling",
    # OB-013: Availability Abuse
    "AITech-13.1": "Disruption of Availability",
    "AITech-13.2": "Cost Harvesting / Repurposing",
    # OB-014: Privilege Compromise
    "AITech-14.1": "Unauthorized Access",
    "AITech-14.2": "Abuse of Delegated Authority",
    # OB-015: Harmful / Misleading / Inaccurate Content
    "AITech-15.1": "Harmful Content",
    # OB-016: Surveillance
    "AITech-16.1": "Eavesdropping",
    # OB-017: Cyber-Physical / Sensor Attacks
    "AITech-17.1": "Sensor Spoofing",
    # OB-018: System Misuse / Malicious Application
    "AITech-18.1": "Fraudulent Use",
    "AITech-18.2": "Malicious Workflows",
    # OB-019: Multi-Modal / Cross-Modal Risks
    "AITech-19.1": "Cross-Modal Inconsistency Exploits",
    "AITech-19.2": "Fusion Payload Split",
}

# Valid AISubtech codes and their official names
AISUBTECH_TAXONOMY: dict[str, str] = {
    # AITech-1.1: Direct Prompt Injection
    "AISubtech-1.1.1": "Instruction Manipulation (Direct Prompt Injection)",
    "AISubtech-1.1.2": "Obfuscation (Direct Prompt Injection)",
    "AISubtech-1.1.3": "Multi-Agent Prompt Injection",
    # AITech-1.2: Indirect Prompt Injection
    "AISubtech-1.2.1": "Instruction Manipulation (Indirect Prompt Injection)",
    "AISubtech-1.2.2": "Obfuscation (Indirect Prompt Injection)",
    "AISubtech-1.2.3": "Multi-Agent (Indirect Prompt Injection)",
    # AITech-1.3: Goal Manipulation
    "AISubtech-1.3.1": "Goal Manipulation (Models, Agents)",
    "AISubtech-1.3.2": "Goal Manipulation (Tools, Prompts, Resources)",
    # AITech-1.4: Multi-Modal Injection
    "AISubtech-1.4.1": "Image-Text Injection",
    "AISubtech-1.4.2": "Image Manipulation",
    "AISubtech-1.4.3": "Audio Command Injection",
    "AISubtech-1.4.4": "Video Overlay Manipulation",
    # AITech-2.1: Jailbreak
    "AISubtech-2.1.1": "Context Manipulation (Jailbreak)",
    "AISubtech-2.1.2": "Obfuscation (Jailbreak)",
    "AISubtech-2.1.3": "Semantic Manipulation (Jailbreak)",
    "AISubtech-2.1.4": "Token Exploitation (Jailbreak)",
    "AISubtech-2.1.5": "Multi-Agent Jailbreak Collaboration",
    # AITech-3.1: Masquerading
    "AISubtech-3.1.1": "Identity Obfuscation",
    "AISubtech-3.1.2": "Trusted Agent Spoofing",
    # AITech-4.1: Agent Injection
    "AISubtech-4.1.1": "Rogue Agent Introduction",
    # AITech-4.2: Context Boundary Attacks
    "AISubtech-4.2.1": "Context Window Exploitation",
    "AISubtech-4.2.2": "Session Boundary Violation",
    # AITech-4.3: Protocol Manipulation
    "AISubtech-4.3.1": "Schema Inconsistencies",
    "AISubtech-4.3.2": "Namespace Collision",
    "AISubtech-4.3.3": "Server Rebinding Attack",
    "AISubtech-4.3.4": "Replay Exploitation",
    "AISubtech-4.3.5": "Capability Inflation",
    "AISubtech-4.3.6": "Cross-Origin Exploitation",
    # AITech-5.1: Memory System Persistence
    "AISubtech-5.1.1": "Long-term / Short-term Memory Injection",
    # AITech-5.2: Configuration Persistence
    "AISubtech-5.2.1": "Agent Profile Tampering",
    # AITech-6.1: Training Data Poisoning
    "AISubtech-6.1.1": "Knowledge Base Poisoning",
    "AISubtech-6.1.2": "Reinforcement Biasing",
    "AISubtech-6.1.3": "Reinforcement Signal Corruption",
    # AITech-7.2: Memory System Corruption
    "AISubtech-7.2.1": "Memory Anchor Attacks",
    "AISubtech-7.2.2": "Memory Index Manipulation",
    # AITech-7.3: Data Source Abuse
    "AISubtech-7.3.1": "Corrupted Third-Party Data",
    # AITech-7.4: Token Manipulation
    "AISubtech-7.4.1": "Token Theft",
    # AITech-8.1: Membership Inference
    "AISubtech-8.1.1": "Presence Detection",
    # AITech-8.2: Data Exfiltration / Exposure
    "AISubtech-8.2.1": "Training Data Exposure",
    "AISubtech-8.2.2": "LLM Data Leakage",
    "AISubtech-8.2.3": "Data Exfiltration via Agent Tooling",
    # AITech-8.3: Information Disclosure
    "AISubtech-8.3.1": "Tool Metadata Exposure",
    "AISubtech-8.3.2": "System Information Leakage",
    # AITech-8.4: Prompt/Meta Extraction
    "AISubtech-8.4.1": "System LLM Prompt Leakage",
    # AITech-9.1: Model or Agentic System Manipulation
    "AISubtech-9.1.1": "Code Execution",
    "AISubtech-9.1.2": "Unauthorized or Unsolicited System Access",
    "AISubtech-9.1.3": "Unauthorized or Unsolicited Network Access",
    "AISubtech-9.1.4": "Injection Attacks (SQL, Command Execution, XSS)",
    "AISubtech-9.1.5": "Template Injection (SSTI)",
    # AITech-9.2: Detection Evasion
    "AISubtech-9.2.1": "Obfuscation Vulnerabilities",
    "AISubtech-9.2.2": "Backdoors and Trojans",
    # AITech-9.3: Dependency / Plugin Compromise
    "AISubtech-9.3.1": "Malicious Package / Tool Injection",
    "AISubtech-9.3.2": "Dependency Name Squatting (Tools / Servers)",
    "AISubtech-9.3.3": "Dependency Replacement / Rug Pull",
    # AITech-10.1: Model Extraction
    "AISubtech-10.1.1": "API Query Stealing",
    "AISubtech-10.1.2": "Weight Reconstruction",
    "AISubtech-10.1.3": "Sensitive Data Reconstruction",
    # AITech-10.2: Model Inversion
    "AISubtech-10.2.1": "Model Inversion",
    # AITech-11.1: Environment-Aware Evasion
    "AISubtech-11.1.1": "Agent-Specific Evasion",
    "AISubtech-11.1.2": "Tool-Scoped Evasion",
    "AISubtech-11.1.3": "Environment-Scoped Payloads",
    "AISubtech-11.1.4": "Defense-Aware Payloads",
    # AITech-11.2: Model-Selective Evasion
    "AISubtech-11.2.1": "Targeted Model Fingerprinting",
    "AISubtech-11.2.2": "Conditional Attack Execution",
    # AITech-12.1: Tool Exploitation
    "AISubtech-12.1.1": "Parameter Manipulation",
    "AISubtech-12.1.2": "Tool Poisoning",
    "AISubtech-12.1.3": "Unsafe System / Browser / File Execution",
    "AISubtech-12.1.4": "Tool Shadowing",
    # AITech-12.2: Insecure Output Handling
    "AISubtech-12.2.1": "Code Detection / Malicious Code Output",
    # AITech-13.1: Disruption of Availability
    "AISubtech-13.1.1": "Compute Exhaustion",
    "AISubtech-13.1.2": "Memory Flooding",
    "AISubtech-13.1.3": "Model Denial of Service",
    "AISubtech-13.1.4": "Application Denial of Service",
    "AISubtech-13.1.5": "Decision Paralysis Attacks",
    # AITech-13.2: Cost Harvesting
    "AISubtech-13.2.1": "Service Misuse for Cost Inflation",
    # AITech-14.1: Unauthorized Access
    "AISubtech-14.1.1": "Credential Theft",
    "AISubtech-14.1.2": "Insufficient Access Controls",
    # AITech-14.2: Abuse of Delegated Authority
    "AISubtech-14.2.1": "Permission Escalation via Delegation",
    # AITech-15.1: Harmful Content (extensive sub-techniques)
    "AISubtech-15.1.1": "Cybersecurity and Hacking: Malware / Exploits",
    "AISubtech-15.1.2": "Cybersecurity and Hacking: Cyber Abuse",
    "AISubtech-15.1.3": "Safety Harms and Toxicity: Animal Abuse",
    "AISubtech-15.1.4": "Safety Harms and Toxicity: Child Abuse / Exploitation",
    "AISubtech-15.1.5": "Safety Harms and Toxicity: Disinformation",
    "AISubtech-15.1.6": "Safety Harms and Toxicity: Environmental Harm",
    "AISubtech-15.1.7": "Safety Harms and Toxicity: Financial Harm",
    "AISubtech-15.1.8": "Safety Harms and Toxicity: Harassment",
    "AISubtech-15.1.9": "Safety Harms and Toxicity: Hate Speech",
    "AISubtech-15.1.10": "Safety Harms and Toxicity: Non-Violent Crime",
    "AISubtech-15.1.11": "Safety Harms and Toxicity: Profanity",
    "AISubtech-15.1.12": "Safety Harms and Toxicity: Scams and Deception",
    "AISubtech-15.1.13": "Safety Harms and Toxicity: Self Harm",
    "AISubtech-15.1.14": "Safety Harms and Toxicity: Sexual Content and Exploitation",
    "AISubtech-15.1.15": "Safety Harms and Toxicity: Social Division and Polarization",
    "AISubtech-15.1.16": "Safety Harms and Toxicity: Terrorism / Extremism",
    "AISubtech-15.1.17": "Safety Harms and Toxicity: Violence and Public Safety Threat",
    "AISubtech-15.1.18": "Safety Harms and Toxicity: Weapons / CBRN Risks",
    "AISubtech-15.1.19": "Integrity: Hallucinations / Misinformation",
    "AISubtech-15.1.20": "Integrity: Unauthorized Financial Advice",
    "AISubtech-15.1.21": "Integrity: Unauthorized Legal Advice",
    "AISubtech-15.1.22": "Integrity: Unauthorized Medical Advice",
    "AISubtech-15.1.23": "Intellectual Property Compromise: Intellectual Property Infringement",
    "AISubtech-15.1.24": "Intellectual Property Compromise: Confidential Data",
    "AISubtech-15.1.25": "Privacy Attacks: PII / PHI / PCI",
    # AITech-16.1: Eavesdropping
    "AISubtech-16.1.1": "Logging Sensitive Conversations",
    # AITech-17.1: Sensor Spoofing
    "AISubtech-17.1.1": "Sensor Spoofing: Action Signals (audio, visual)",
    # AITech-18.1: Fraudulent Use
    "AISubtech-18.1.1": "Spam / Scam / Social Engineering Generation",
    # AITech-18.2: Malicious Workflows
    "AISubtech-18.2.1": "Abuse of APIs for Mass Automation",
    "AISubtech-18.2.2": "Dedicated Malicious Server or Infrastructure",
    # AITech-19.1: Cross-Modal Inconsistency
    "AISubtech-19.1.1": "Contradictory Inputs Attack",
    "AISubtech-19.1.2": "Modality Skewing",
    # AITech-19.2: Fusion Payload Split
    "AISubtech-19.2.1": "Convergence Payload Injection",
    "AISubtech-19.2.2": "Chained Payload Execution",
}

# Convenience sets for quick membership testing
VALID_AITECH_CODES: set[str] = set(AITECH_TAXONOMY.keys())
VALID_AISUBTECH_CODES: set[str] = set(AISUBTECH_TAXONOMY.keys())


def is_valid_aitech(code: str) -> bool:
    """Check if an AITech code exists in the official taxonomy."""
    return code in VALID_AITECH_CODES


def is_valid_aisubtech(code: str) -> bool:
    """Check if an AISubtech code exists in the official taxonomy."""
    return code in VALID_AISUBTECH_CODES


def get_aitech_name(code: str) -> str | None:
    """Get the official name for an AITech code."""
    return AITECH_TAXONOMY.get(code)


def get_aisubtech_name(code: str) -> str | None:
    """Get the official name for an AISubtech code."""
    return AISUBTECH_TAXONOMY.get(code)
