# Key Concepts and Security Model

## What Is an Agent Skill?

Skill Scanner targets **agent skill packages**: local file trees with a required `SKILL.md` plus optional scripts, prompts, and supporting assets.

Typical skill package shape:

```text
my-skill/
├── SKILL.md
├── scripts/
│   ├── main.py
│   └── helpers.sh
├── prompts/
│   └── system.md
└── docs/
    └── usage.md
```

`SKILL.md` contains two key parts:

1. YAML frontmatter: metadata, tools, permissions, and package-level declarations.
2. Markdown instructions: behavior guidance for the agent.

## Why Skills Are a Security Boundary

Skills can include executable logic and tool instructions, which introduces risk when consumed by agents automatically. Main risk classes:

- Prompt and instruction-layer manipulation.
- Command/code execution abuse.
- Data exfiltration and credential harvesting.
- Hidden or low-analyzability payloads in archives/binaries.
- Tool-chain abuse through indirect fetch-and-execute workflows.

## Defense-in-Depth Model

Skill Scanner intentionally uses multiple analyzers with different strengths and blind spots:

| Layer | Primary capability | Typical value |
|---|---|---|
| Static + YARA | Deterministic pattern matching | Fast broad coverage |
| Pipeline analyzer | Command chain taint heuristics | Shell risk context |
| Behavioral analyzer | Python AST/control-flow dataflow | Multi-step code behavior |
| LLM analyzer | Semantic intent analysis | Contextual threat reasoning |
| Meta analyzer | Second-pass triage | False-positive reduction |
| External analyzers | Threat intel / cloud models | Additional signal |

## Best-Effort Principle

Skill Scanner is a **best-effort detection tool**, not a formal proof of safety.

- No findings means “no known threats detected under current rules and analyzers.”
- False negatives and false positives are both possible.
- Human review remains required for high-impact deployments.

## Skills vs MCP Servers

Skill Scanner is built for **local skill packages** (directory paths or uploaded ZIPs extracted locally). It is not a remote protocol scanner for MCP server endpoints.

For details on this distinction, see [Remote Skills Analysis](remote-skills-analysis.md).

## Recommended Operating Profiles

| Environment | Suggested analyzers |
|---|---|
| Local developer loop | static + bytecode + pipeline |
| CI for untrusted contributions | + behavioral + strict policy |
| Pre-release security review | + LLM + meta + optional external analyzers |

## Deep Dives

- [Architecture](../architecture/index.md)
- [Scanning Pipeline](../architecture/scanning-pipeline.md)
- [Analyzer Internals](../architecture/analyzers/index.md)
- [Threat Taxonomy](../architecture/threat-taxonomy.md)
- [Policy System](../user-guide/scan-policies-overview.md)
