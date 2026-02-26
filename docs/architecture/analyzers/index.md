# Analyzers

> [!NOTE]
> **Looking to choose which analyzers to enable?**
>
> See the [Analyzer Selection Guide](meta-and-external-analyzers.md) for a decision matrix and recommended flag combinations. This page covers the technical details of all analyzers.

Analyzers implement independent detection strategies and return normalized `Finding` objects.

## Capability Matrix

| Analyzer | Type | Requires API key | Phase | Main target |
|---|---|---|---|---|
| Static | Deterministic | No | 1 | Signatures + YARA patterns |
| Bytecode | Deterministic | No | 1 | `.pyc` integrity |
| Pipeline | Heuristic | No | 1 | Shell chain risk |
| Behavioral | Static AST/dataflow | No | 1 | Python source behavior |
| VirusTotal | External intel | Yes | 1 | Binary hash/file reputation |
| AI Defense | External service | Yes | 1 | Prompt/content/code threat signal |
| Trigger | Heuristic | No | 1 | Vague or risky trigger descriptions |
| LLM | Semantic | Usually (not required for Bedrock IAM mode) | 2 | Intent-level threat reasoning |
| Meta | Semantic post-pass | Usually (not required for Bedrock IAM mode) | 2 | FP filtering and prioritization |
| Cross-Skill | Correlation | No | Post-scan | Cross-skill data relay and pattern sharing |

> [!NOTE]
> **Cross-Skill Scanner**
>
> `CrossSkillScanner` has a different interface from other analyzers. Instead of `analyze(skill)`, it uses `analyze_skill_set(skills)` and runs only during `scan_directory()` with `--check-overlap` enabled.

## Analyzer Lifecycle

1. Analyzer set is built via [`skill_scanner/core/analyzer_factory.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/analyzer_factory.py).
2. Phase 1: all non-LLM analyzers receive the `Skill` model and run independently.
3. Phase 2: LLM and meta analyzers receive enrichment context from Phase 1 findings before running.
4. All analyzers return findings in the common `Finding` schema.
5. Scanner merges, post-processes, and reports.

See [Scanning Pipeline](../scanning-pipeline.md) for the full execution flow.

## Deep Dives

- [Static Analyzer](static-analyzer.md)
- [Behavioral Analyzer](behavioral-analyzer.md)
- [LLM Analyzer](llm-analyzer.md)
- [Meta-Analyzer](meta-analyzer.md)
- [AI Defense Analyzer](aidefense-analyzer.md)
- [Analyzer Selection Guide](meta-and-external-analyzers.md)
- [Writing Custom Rules](writing-custom-rules.md)
