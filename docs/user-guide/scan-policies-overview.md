# Scan Policies Overview

Scan policies define scanner behavior without code changes.

## Which Preset Should I Use?

[Recommended settings](recommended-settings.md) answers this per use case, with measured detection
and flag rates and the commands to run. In short:

| Scanning... | Preset | LLM judge |
|---|---|---|
| Your own skills, locally, in pre-commit or in CI | `low-noise` | not needed |
| Third-party skills before install | `balanced` (default) | on: block at HIGH, review MEDIUM |
| Third-party skills with little review capacity | `quiet` | on -- not without it |
| Audits and threat hunting | `strict` | on, triage only |
| Trusted internal skills where noise matters more than coverage | `permissive` | not needed |

`strict` and `permissive` were not part of the full-corpus measurements; measure them on your own
skills before using either as a gate.

## Built-In Presets

| Preset | Posture | CEL | Correlation | Typical use |
|---|---|---|---|---|
| `strict` | Maximum sensitivity | `shadow` | on | Untrusted content and audits |
| `balanced` | Default blend | `shadow` | on | General CI usage |
| `low-noise` | `balanced` with 11 rules reported at LOW and low-confidence LLM findings capped at LOW | `shadow` | on | Everyday scanning where alert volume matters |
| `quiet` | `low-noise` plus 8 more rules at LOW and contextual-risk LLM findings capped at LOW | `shadow` | on | Review queues limited by capacity, with the judge on |
| `permissive` | Lower noise | `off` | off | Trusted internal workflows |

## Quick Start

```bash
skill-scanner scan ./my-skill --policy strict
skill-scanner scan ./my-skill --policy balanced
skill-scanner scan ./my-skill --policy balanced --cel-mode off
skill-scanner generate-policy --preset balanced -o my_policy.yaml
```

`--cel-mode off|shadow|enforce` overrides the selected policy for one scan.
`shadow` records decisions in JSON metadata but retains every finding. All
bundled CEL rules currently have per-rule `rollout: shadow`, so choosing the
global `enforce` mode does not suppress them until they are individually
qualified and promoted.

## Merge Behavior

Custom policy files merge over defaults.

- Missing keys inherit defaults.
- Scalar fields override directly.
- Lists replace defaults (they do not append).

## High-Impact Sections

- `pipeline`: command-chain demotion and known installer handling
- `rule_scoping`: docs/code/scope gating
- `file_limits`: max files, file size, depth
- `analysis_thresholds`: thresholds for analyzability and unicode heuristics
- `analyzers.correlation`: bounded source/sink and staged-behavior correlation
- `cel.mode`: CEL decision behavior (`off`, `shadow`, or `enforce`)
- `severity_overrides`: per-rule severity remapping

The core pack is always selected. Additional bundled packs such as ATR remain
opt-in with `--rule-packs`; ATR is not part of the current core + CEL release
gate.

## Next Step

For exhaustive knob-by-knob documentation, see [Custom Policy Configuration](custom-policy-configuration.md).
