# ATR Rule Pack for Cisco Skill Scanner

**Source:** [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
**ATR Version:** 4.2.2
**Rules:** 840 signatures across 10 signature files
**License:** MIT
**Benchmarks:** see the [ATR benchmark table at v4.2.2](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/v4.2.2/README.md#8-evaluation),
which is regenerated from measurement files rather than hand-copied. Selected
rows:

| Corpus | Samples | Recall (hunt / enforce) | Precision | ATR version |
|---|---:|---:|---:|---:|
| NVIDIA garak, in-the-wild jailbreaks | 650 | 92.3% / 0.9% | n/a (attacks only) | 4.1.5 |
| NVIDIA garak, all 23 probe families | 3,475 | 57.2% / 0.5% | n/a (attacks only) | 4.1.5 |
| PINT-format (deepset + Lakera Gandalf) | 850 | 65.4% / 0.4% | 100% | 4.1.5 |
| Labeled SKILL.md, internal | 498 | 100% / 0% | 97% (hunt) | 4.1.5 |

**This pack ships ATR 4.2.2; the rows above were measured on 4.1.5.**
Treat them as indicative of the shipped signatures rather than exact. The
upstream table is the authority and carries the measurement file behind each
row.

Four caveats belong next to those numbers.

The two recall figures are ATR's two engine lanes. `hunt` loads rules of every
maturity; `enforce` loads only `maturity: stable` rules. This pack carries the
`hunt` rules plus four `status: draft` rules that ATR's engine skips in every
lane, and this scanner matches them with its own engine, so the figures
describe the rules, not a measurement of this scanner.

The garak rows are partly closed-book: many of the rules that fire on that
corpus were written from it. Upstream replays the in-the-wild row without
those rules at 65.4%. The garak corpora contain no benign samples, so they
measure recall only.

The PINT-format row is **not** a run of Lakera's official PINT benchmark. That
corpus is private and roughly five times larger. This is a self-built corpus in
the same format. At ATR 3.5.12, `ATR-2026-00001` alone accounted for 226 of its
295 detections, so the row measures one rule family more than overall
coverage; the per-rule split has not been re-measured since.

The SKILL.md split is structural, not a tuning gap. All 39 rules carrying
`scan_target: skill` in ATR 4.2.2 are `maturity: test`, so an enforce-lane
deployment loads no skill-scanning rule at all.

OWASP Agentic Top 10 coverage (10/10 categories) is a taxonomy mapping, not a
detection benchmark, and is listed separately upstream for that reason.

## Overview

This pack adds AI-agent security detection rules from the open-source ATR
project, covering attack surfaces specific to modern AI-agent deployments
(MCP tool layer, multi-agent trust, skill manifests, agent autonomy). It is
the ATR `4.2.2` static ruleset. Four rules are excluded: the behavioral
aggregation rule `ATR-2026-00553`, because this signature pack cannot evaluate
its per-session time window and tool-call count, and `ATR-2026-00233`,
`ATR-2026-00235` and `ATR-2026-00495`, which are deprecated upstream.

## Attack Categories

| Signature file | Category | Rules |
|---|---|---|
| `signatures/atr_prompt_injection.yaml` | Prompt injection | 255 |
| `signatures/atr_context_exfiltration.yaml` | Context exfiltration | 138 |
| `signatures/atr_tool_poisoning.yaml` | MCP tool poisoning | 118 |
| `signatures/atr_agent_manipulation.yaml` | Agent manipulation (multi-agent, autonomy) | 108 |
| `signatures/atr_privilege_escalation.yaml` | Privilege escalation | 77 |
| `signatures/atr_skill_compromise.yaml` | Skill compromise | 52 |
| `signatures/atr_model_abuse.yaml` | Model abuse | 41 |
| `signatures/atr_excessive_autonomy.yaml` | Excessive autonomy | 38 |
| `signatures/atr_data_poisoning.yaml` | Data poisoning | 9 |
| `signatures/atr_model_security.yaml` | Model security | 4 |
| **Total** | **10 categories** | **840** |

The full per-rule index (ATR id, category, severity, signature file) lives in
`pack.yaml`. Each signature carries an `atr_url` linking to the source rule
YAML on GitHub at the `v4.2.2` tag.

## File Structure

```text
skill_scanner/data/packs/atr/
├── pack.yaml            # Pack manifest — indexes all 840 rules
├── README.md            # This file
└── signatures/          # 10 category signature files (atr_<category>.yaml)
```

## Pattern Provenance

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
(permanent rule ids, no silent removal of stable rules, a public
false-positive reporting channel). Rule maturity is not carried in this pack;
it is in each source rule linked by `atr_url`.

## ATR Project Links

- Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- License: MIT
