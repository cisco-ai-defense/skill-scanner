# ATR Rule Pack for Cisco Skill Scanner

**Source:** [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
**ATR Version:** 3.5.6
**Rules:** 712 signatures across 10 signature files
**License:** MIT
**Benchmarks:** measured on ATR 3.5.11 (this pack is built from 3.5.6, so treat them as indicative for the
shipped signatures rather than exact):

- 91.5% recall on NVIDIA garak (650 in-the-wild jailbreaks; 595 detected, 55 missed), re-measured 2026-07-28
- 100% recall / 97% precision on 498 labeled SKILL.md samples
- 99.7% precision, 63.6% recall on an 850-sample PINT-format corpus (deepset/prompt-injections + Lakera
  Gandalf; not Lakera's official PINT benchmark)
- **False positives are lane-dependent and ATR does not publish a single precision figure.** On the 65K-sample
  benign gate: ~0.24% FP on the enforce lane (stable, confirm-gated rules) and ~9% FP on the hunt lane, which
  is the default. A scanner running the full pack should expect the hunt-lane figure.
- OWASP Agentic Top 10: 10/10 categories mapped

## Overview

This pack adds AI-agent security detection rules from the open-source ATR
project, covering attack surfaces specific to modern AI-agent deployments
(MCP tool layer, multi-agent trust, skill manifests, agent autonomy). It is
the current ATR `3.5.6` static ruleset. The behavioral aggregation rule
`ATR-2026-00553` is excluded because this signature pack cannot evaluate its
per-session time window and tool-call count.

## Attack Categories

| Signature file | Category | Rules |
|---|---|---|
| `signatures/atr_prompt_injection.yaml` | Prompt injection | 242 |
| `signatures/atr_context_exfiltration.yaml` | Context exfiltration | 111 |
| `signatures/atr_agent_manipulation.yaml` | Agent manipulation (multi-agent, autonomy) | 106 |
| `signatures/atr_tool_poisoning.yaml` | MCP tool poisoning | 90 |
| `signatures/atr_skill_compromise.yaml` | Skill compromise | 45 |
| `signatures/atr_privilege_escalation.yaml` | Privilege escalation | 42 |
| `signatures/atr_model_abuse.yaml` | Model abuse | 37 |
| `signatures/atr_excessive_autonomy.yaml` | Excessive autonomy | 31 |
| `signatures/atr_data_poisoning.yaml` | Data poisoning | 5 |
| `signatures/atr_model_security.yaml` | Model security | 3 |
| **Total** | **10 categories** | **712** |

The full per-rule index (ATR id, category, severity, signature file) lives in
`pack.yaml`. Each signature carries an `atr_url` linking to the source rule
YAML on GitHub.

## File Structure

```text
skill_scanner/data/packs/atr/
├── pack.yaml            # Pack manifest — indexes all 712 rules
├── README.md            # This file
└── signatures/          # 10 category signature files (atr_<category>.yaml)
```

## Pattern Provenance

All regex patterns are extracted verbatim from ATR YAML rule files
(`detection.conditions[].value`). No patterns were invented for this pack.
Every signature records its originating ATR rule id and a direct link to the
source YAML.

## Staying current

ATR publishes stability guarantees for downstream consumers in its
[Downstream Sync Contract](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/DOWNSTREAM-SYNC-CONTRACT.md)
(permanent rule ids, no silent removal of stable rules, a public
false-positive reporting channel). Consumers that want only the
highest-confidence tier can filter to `maturity: stable`.

## ATR Project Links

- Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- License: MIT
