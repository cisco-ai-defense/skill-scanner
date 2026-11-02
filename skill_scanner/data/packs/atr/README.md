# ATR Rule Pack for Cisco Skill Scanner

**Source:** [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
**ATR Version:** 4.2.3
**Rules:** 572 signatures across 10 signature files
**License:** MIT

## Report-only

Every signature in this pack is `LOW`, whatever the source rule's severity.
This scanner treats a skill as unsafe on any HIGH or CRITICAL finding
(`is_safe`, and `--fail-on-findings`), so this pack adds findings to a report
but with the static analyzers does not change whether a skill passes, unless
you run with `--fail-on-severity low` or `info`. Runs with the LLM or meta
analyzer, which see these findings, were not measured. Each finding's `atr_url` links to the
source rule, which carries ATR's own severity.

## Measured in this scanner

This scanner's static analyzers with the `balanced` policy, on
MaliciousSkillBench (`ProtectSkills/MaliciousSkillBench`, CC-BY-4.0)
train/validation (1,338 benign, 5,256 malicious) and the 2,000-record ClawHub
sample (`OpenClaw/clawhub-security-signals`), both materialized with
`evals/datasets/` and its lock. ClawHub is unlabelled, so its column is a rate, not an error rate.

| | Benign | Malicious | ClawHub |
|---|---:|---:|---:|
| Failed by core rules (HIGH or CRITICAL) | 0.8% | 31.7% | 3.6% |
| Verdicts this pack changes, at HIGH or at MEDIUM | 0 | 0 | 0 |
| Not failed by core, with an ATR finding | 5.4% | 12.6% | 14.5% |

Before this pack was reduced to the rules below and capped at `LOW`, core plus
the ATR 3.5.6 pack failed 69.5% of the benign skills.

The rules in this pack were selected with ATR data only (see Pattern
Provenance); these two corpora were used only to measure. Some ATR rules may
have been written from MaliciousSkillBench samples, so the malicious column
may read high. Per the MaliciousSkillBench terms, nothing here is measured on
its source-disjoint split.

ATR's own benchmark table measures ATR's engine, not this pack in this
scanner, and is not repeated here.

## Overview

This pack adds AI-agent security detection rules from the open-source ATR
project, covering attack surfaces specific to modern AI-agent deployments
(MCP tool layer, multi-agent trust, skill manifests, agent autonomy). It is
the subset of the ATR `4.2.3` ruleset whose patterns mean the same thing over
a skill's files as they do in ATR. Of the 844 rule files, 272 are left out:

- 244 rules with a regex condition on a field only a running agent has
  (`tool_name`, `tool_args`, `tool_response`, agent output, trace fields).
  This pack has no field concept and matches every line of every file, so
  such a condition matches whatever text looks like it.
- 24 rules that fired on at least one of ATR's 432 benign skills when run in
  this scanner.
- `ATR-2026-00553`, a behavioral rule this signature pack cannot evaluate,
  and `ATR-2026-00233`, `ATR-2026-00235` and `ATR-2026-00495`, which are
  deprecated upstream.

## Attack Categories

| Signature file | Category | Rules |
|---|---|---|
| `signatures/atr_prompt_injection.yaml` | Prompt injection | 195 |
| `signatures/atr_context_exfiltration.yaml` | Context exfiltration | 113 |
| `signatures/atr_tool_poisoning.yaml` | MCP tool poisoning | 86 |
| `signatures/atr_privilege_escalation.yaml` | Privilege escalation | 50 |
| `signatures/atr_skill_compromise.yaml` | Skill compromise | 36 |
| `signatures/atr_model_abuse.yaml` | Model abuse | 35 |
| `signatures/atr_excessive_autonomy.yaml` | Excessive autonomy | 31 |
| `signatures/atr_agent_manipulation.yaml` | Agent manipulation (multi-agent, autonomy) | 17 |
| `signatures/atr_data_poisoning.yaml` | Data poisoning | 5 |
| `signatures/atr_model_security.yaml` | Model security | 4 |
| **Total** | **10 categories** | **572** |

The full per-rule index (ATR id, category, severity, signature file) lives in
`pack.yaml`. Each signature carries an `atr_url` linking to the source rule
YAML on GitHub at the `v4.2.3` tag.

## File Structure

```text
skill_scanner/data/packs/atr/
├── pack.yaml            # Pack manifest — indexes all 572 rules
├── README.md            # This file
└── signatures/          # 10 category signature files (atr_<category>.yaml)
```

## Pattern Provenance

Rules are selected in ATR's exporter, `scripts/export-cisco-pack.ts`
(Agent-Threat-Rule/agent-threat-rules#764): only
rules whose regex conditions read `content`, `user_input` or
`tool_description` are exported, and `scripts/cisco-pack/benign-gate.py` runs
the result in this scanner over ATR's benign skills and drops every rule that
fires there. `--max-severity low` writes every signature at `LOW`.

Every regex pattern is taken from an ATR YAML rule file
(`detection.conditions[].value`); no patterns were invented for this pack.
ATR matches each pattern case-insensitively and gives a leading `(?m)`,
`(?s)` or `(?x)` no effect, while this scanner compiles patterns with no
flags. Each pattern is therefore written as `(?i)` followed by the rule's
pattern with any leading flag group removed, which is the pattern ATR's engine
compiles. A rule whose conditions must all match (`condition: all`) is
written as one pattern of anchored lookaheads, one per condition, so it fires
only where every condition matches; because this scanner matches most
patterns one line at a time, the conditions have to meet on one line.
Invisible characters that some patterns match (tag characters,
bidirectional controls, zero-width characters) are written as YAML `\u` /
`\U` escapes, so the files contain none of them raw.

One local edit sits on top of the generated output: the three
`ANTHROPIC_BASE_URL` patterns in `ATR-2026-00524` allow
`https://api.orcarouter.ai` (see `tests/test_orcarouter_provider.py`).

## Staying current

The pack is generated by `scripts/export-cisco-pack.ts` in the ATR repository
(`--downstream` reads this directory and keeps its schema_version 2 shape).
ATR publishes stability guarantees for downstream consumers in its
[Downstream Sync Contract](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/DOWNSTREAM-SYNC-CONTRACT.md)
(permanent rule ids and a public false-positive reporting channel). Rule maturity is not carried in this pack;
it is in each source rule linked by `atr_url`.

## ATR Project Links

- Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- License: MIT
