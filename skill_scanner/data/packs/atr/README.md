# ATR Rule Pack for Cisco Skill Scanner

**Source:** [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
**ATR Version:** 3.5.6
**Rules:** 712 signatures across 10 signature files
**License:** MIT
**Benchmarks:** see the [ATR benchmark table](https://github.com/Agent-Threat-Rule/agent-threat-rules#benchmarks),
which is version-pinned and regenerated from measurement files rather than
hand-copied. Selected rows:

| Corpus | Samples | Recall | Precision | ATR version |
|---|---:|---:|---:|---:|
| NVIDIA garak, in-the-wild jailbreaks | 650 | 92.5% | 100% | 3.5.11 |
| NVIDIA garak, all 23 probe families | 3,475 | 57.2% | 100% | 3.5.11 |
| PINT-format (deepset + Lakera Gandalf) | 850 | 60.3% | 100% | 3.5.11 |
| Labeled SKILL.md, internal | 498 | 100% (hunt) / 0% (enforce) | 97% | 3.5.0 |

**This pack ships ATR 3.5.6; the rows above were measured on 3.5.11 and 3.5.0.**
Treat them as indicative of the shipped signatures rather than exact. The
upstream table is the authority and carries the measurement file behind each
row.

Three caveats belong next to those numbers.

The PINT-format row is **not** a run of Lakera's official PINT benchmark. That
corpus is private and roughly five times larger. This is a self-built corpus in
the same format, and 226 of its 272 detections come from a single rule
(`ATR-2026-00001`), so it measures one rule family rather than overall coverage.

The SKILL.md split is structural, not a tuning gap. ATR's enforce lane loads
only `maturity: stable`, and all 38 rules carrying `scan_target: skill` are
currently `maturity: test` — so an enforce-lane deployment loads no
skill-scanning rule at all and detects 0 of the 32 malicious samples. This pack
loads the full static ruleset, which is the configuration the 100% figure
describes.

OWASP Agentic Top 10 coverage (10/10 categories, 1,179 mappings) is a taxonomy
mapping, not a detection benchmark, and is listed separately upstream for that
reason.

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
