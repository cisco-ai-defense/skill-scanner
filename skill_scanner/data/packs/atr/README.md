# ATR Rule Pack for Cisco Skill Scanner

**Source:** [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
**ATR Version:** 0.4.0
**Rules:** 33 signatures across 3 signature files
**PINT Benchmark:** 62.7% recall, 99.7% precision

## Overview

This pack adds AI agent security detection rules from the open-source ATR project that are **not covered** by Cisco's built-in skill scanner ruleset. The rules target four attack categories unique to modern AI agent deployments.

## Attack Categories

### 1. MCP Tool Poisoning (`tool_poisoning.yaml` — 9 rules)

Cisco has zero MCP-specific rules. These rules address attacks that exploit the Model Context Protocol (MCP) tool layer:

| Rule ID | ATR ID | Severity | Description |
|---------|--------|----------|-------------|
| ATR_MCP_MALICIOUS_RESPONSE | ATR-2026-010 | CRITICAL | Shell commands, reverse shells, encoded payloads in MCP responses |
| ATR_TOOL_OUTPUT_INJECTION | ATR-2026-011 | HIGH | Hidden instructions in tool output manipulating agent behavior |
| ATR_TOOL_SSRF | ATR-2026-013 | CRITICAL | SSRF via tool calls to cloud metadata/internal endpoints |
| ATR_SUPPLY_CHAIN_POISONING | ATR-2026-095 | CRITICAL | Poisoned tool descriptions/schemas with malicious payloads |
| ATR_CONSENT_BYPASS_INSTRUCTION | ATR-2026-100 | HIGH | Tool descriptions bypassing user consent for data forwarding |
| ATR_TRUST_ESCALATION_OVERRIDE | ATR-2026-101 | HIGH | Tools claiming to override user preferences or safety policies |
| ATR_HIDDEN_SAFETY_BYPASS | ATR-2026-103 | CRITICAL | "NOTE TO AI: disregard safety" patterns in tool descriptions |
| ATR_SILENT_ACTION_CONCEALMENT | ATR-2026-105 | HIGH | Tools instructing agent to hide actions from users |
| ATR_SCHEMA_DESCRIPTION_CONTRADICTION | ATR-2026-106 | HIGH | Read-only claim with write_mode parameter in schema |

### 2. Multi-Agent Attacks (`agent_manipulation.yaml` — 10 rules)

Cisco has zero multi-agent attack rules. These rules detect attacks that exploit trust between agents in a multi-agent system:

| Rule ID | ATR ID | Severity | Description |
|---------|--------|----------|-------------|
| ATR_CROSS_AGENT_ATTACK | ATR-2026-030 | CRITICAL | Orchestrator impersonation, fake system messages between agents |
| ATR_CROSS_AGENT_PRIVILEGE_ESCALATION | ATR-2026-074 | CRITICAL | Privilege escalation using another agent's credentials |
| ATR_INSECURE_INTER_AGENT_COMMUNICATION | ATR-2026-076 | HIGH | Missing auth tokens, message replay, MITM on agent channels |
| ATR_HUMAN_TRUST_EXPLOITATION | ATR-2026-077 | HIGH | False certainty claims, urgency pressure, review bypass |
| ATR_CONSENSUS_SYBIL_ATTACK | ATR-2026-108 | CRITICAL | Fake agent identities to manipulate multi-agent consensus |
| ATR_A2A_MESSAGE_INJECTION | ATR-2026-116 | HIGH | Injection in agent-to-agent messages overriding instructions |
| ATR_AGENT_IDENTITY_SPOOFING | ATR-2026-117 | CRITICAL | Claims of being system/admin/specific AI model |
| ATR_APPROVAL_FATIGUE | ATR-2026-118 | MEDIUM | Patterns exploiting human approval fatigue |
| ATR_SOCIAL_ENGINEERING_VIA_AGENT | ATR-2026-119 | HIGH | Account suspension threats, authority impersonation via agent |
| ATR_CASUAL_AUTHORITY_CLAIM | ATR-2026-132 | HIGH | "The orchestrator said to skip the filter" style bypass |

### 3. Agent Autonomy Violations (`agent_manipulation.yaml` — 4 rules)

Cisco has minimal autonomy coverage. These rules detect agents acting beyond their sanctioned scope:

| Rule ID | ATR ID | Severity | Description |
|---------|--------|----------|-------------|
| ATR_RUNAWAY_AGENT_LOOP | ATR-2026-050 | HIGH | Unbounded retries, self-recursive calls, agent self-cloning |
| ATR_CASCADING_FAILURE | ATR-2026-052 | HIGH | Blind execution of upstream output with no human gates |
| ATR_UNAUTHORIZED_FINANCIAL_ACTION | ATR-2026-098 | CRITICAL | Agent-initiated payments/transfers without confirmation |
| ATR_HIGH_RISK_TOOL_GATE | ATR-2026-099 | HIGH | Financial/destructive/shell tools invoked without approval |

### 4. Advanced Injection (`advanced_injection.yaml` — 12 rules)

Unique detection patterns with no Cisco equivalent:

| Rule ID | ATR ID | Severity | Description |
|---------|--------|----------|-------------|
| ATR_GOAL_HIJACKING | ATR-2026-032 | HIGH | Mid-session task replacement via urgency or pivot directives |
| ATR_SCOPE_CREEP | ATR-2026-041 | MEDIUM | Agent self-extending beyond assigned task boundaries |
| ATR_CONSENSUS_POISONING | ATR-2026-092 | CRITICAL | Vote forging and ballot stuffing in multi-agent decisions |
| ATR_CJK_INJECTION_PATTERNS | ATR-2026-097 | CRITICAL | Prompt injection in Chinese, Japanese, and Korean |
| ATR_PERSONA_HIJACKING | ATR-2026-104 | CRITICAL | Mandatory persona adoption overriding system prompt |
| ATR_RAG_DATA_POISONING | ATR-2026-070 | HIGH | Malicious instructions in RAG knowledge base documents |
| ATR_MODEL_BEHAVIOR_EXTRACTION | ATR-2026-072 | CRITICAL | System prompt verbatim requests, training data extraction |
| ATR_DISGUISED_ANALYTICS_EXFILTRATION | ATR-2026-102 | HIGH | Conversation context exfiltrated as "usage analytics" |
| ATR_INDIRECT_AUTHORITY_CLAIM | ATR-2026-130 | HIGH | "Note to AI:" style headers in external content |
| ATR_FICTIONAL_FRAMING_ATTACK | ATR-2026-131 | MEDIUM | Fictional/academic framing for safety bypass requests |
| ATR_PARAPHRASE_INJECTION | ATR-2026-133 | HIGH | "Set aside your guidance" style paraphrased instruction override |

## File Structure

```
skill_scanner/data/packs/atr/
├── pack.yaml                          # Pack manifest with all rule entries
├── README.md                          # This file
└── signatures/
    ├── tool_poisoning.yaml            # 9 MCP tool poisoning rules
    ├── agent_manipulation.yaml        # 14 multi-agent + autonomy rules
    └── advanced_injection.yaml        # 12 advanced injection rules
```

## Pattern Provenance

All regex patterns are extracted verbatim from ATR YAML rule files. No patterns were invented for this pack. Each rule's `description` field includes the originating ATR rule ID and a direct link to the source YAML on GitHub.

## ATR Project Links

- Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- PINT Benchmark: see `evals/` directory in ATR repo
- License: Apache-2.0
