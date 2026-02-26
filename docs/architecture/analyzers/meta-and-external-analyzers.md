# Analyzer Selection Guide

> [!TIP]
> **TL;DR**
>
> Use this guide to choose which optional analyzers to enable. Quick CI gates need no extras; thorough reviews benefit from `--use-llm --use-behavioral --enable-meta`. See the [Recommended Combinations](#recommended-combinations) table for common scenarios.

This page helps you choose which optional analyzers to enable for your use case. Core analyzers (static, bytecode, pipeline) always run when enabled in policy. The analyzers below are opt-in via CLI flags or API parameters.

## Decision Matrix

| Need | Analyzer | Flag | Trade-off |
|---|---|---|---|
| Semantic intent analysis beyond patterns | LLM | `--use-llm` | Requires LLM provider; adds latency and cost |
| Reduce false positives from other analyzers | Meta | `--enable-meta` | Requires LLM provider; runs after all other analyzers |
| Binary file reputation checks | VirusTotal | `--use-virustotal` | Requires API key; rate-limited by VT tier |
| Cloud-based threat classification | AI Defense | `--use-aidefense` | Requires Cisco AI Defense API access |
| Catch vague/risky skill descriptions | Trigger | `--use-trigger` | Lightweight; no external dependencies |
| Python dataflow and cross-file analysis | Behavioral | `--use-behavioral` | CPU-intensive for large codebases |

## When to Use Each Analyzer

### LLM Analyzer

Best for: skills where pattern matching alone may miss intent-level threats (social engineering, subtle data exfiltration, complex multi-step attacks).

```bash
skill-scanner scan ./my-skill --use-llm
```

Skip when: you only need fast deterministic scans, have no LLM provider configured, or are scanning many skills in batch where latency matters.

See [LLM Analyzer deep dive](llm-analyzer.md) for configuration and supported models.

### Meta Analyzer

Best for: reducing noise in scan results by having an LLM review findings from all other analyzers for likely false positives, correlation groups, and prioritization.

```bash
skill-scanner scan ./my-skill --use-llm --enable-meta
```

> [!NOTE]
> **Prerequisite**
>
> Meta analyzer requires `--use-llm` because it uses an LLM to perform its second-pass analysis. It always runs after all other analyzers.

Skip when: you want raw unfiltered findings, or false positive rates are already acceptable.

See [Meta Analyzer deep dive](meta-analyzer.md) for authority hierarchy and output format.

### VirusTotal Analyzer

Best for: skills containing binary files where you want reputation-based validation. Files validated by VirusTotal have their `BINARY_FILE_DETECTED` findings suppressed.

```bash
skill-scanner scan ./my-skill --use-virustotal
```

Optional upload mode for unknown files:

```bash
skill-scanner scan ./my-skill --use-virustotal --vt-upload-files
```

Skip when: the skill has no binary files, or you are in an air-gapped environment.

### AI Defense Analyzer

Best for: leveraging Cisco AI Defense cloud services for additional threat signal on prompts, content, and code.

```bash
skill-scanner scan ./my-skill --use-aidefense
```

Skip when: you don't have Cisco AI Defense API access, or you want fully offline scanning.

See [AI Defense Analyzer deep dive](aidefense-analyzer.md) for configuration.

### Trigger Analyzer

Best for: catching overly broad, vague, or risky skill trigger descriptions that could lead to unintended activation.

```bash
skill-scanner scan ./my-skill --use-trigger
```

Skip when: you are scanning skills with well-defined, specific triggers.

### Behavioral Analyzer

Best for: Python-heavy skills where you want AST-level dataflow analysis, taint tracking, and cross-file correlation.

```bash
skill-scanner scan ./my-skill --use-behavioral
```

Skip when: the skill contains no Python source, or you need the fastest possible scan time.

See [Behavioral Analyzer deep dive](behavioral-analyzer.md) for detection patterns.

## Recommended Combinations

| Scenario | Flags |
|---|---|
| Quick CI gate | (defaults -- core analyzers only) |
| Thorough single-skill review | `--use-llm --use-behavioral --use-trigger --enable-meta` |
| Binary-heavy skill | `--use-virustotal` |
| Enterprise with AI Defense | `--use-aidefense --use-llm --enable-meta` |
| Maximum coverage | `--use-llm --use-behavioral --use-trigger --use-virustotal --enable-meta` |

## Bytecode Analyzer

The bytecode analyzer validates Python `.pyc` integrity and consistency with source. It is a core analyzer (not opt-in) and runs automatically when enabled in policy.

## Cross-Skill Scanner

The cross-skill scanner detects patterns across multiple skills (data relay, shared URLs, complementary triggers). It runs only during `scan-all` with `--check-overlap`:

```bash
skill-scanner scan-all ./skills-dir --check-overlap
```

## Canonical Deep Dives

- [Static Analyzer](static-analyzer.md)
- [Behavioral Analyzer](behavioral-analyzer.md)
- [LLM Analyzer](llm-analyzer.md)
- [Meta Analyzer](meta-analyzer.md)
- [AI Defense Analyzer](aidefense-analyzer.md)
- [Binary Handling](../binary-handling.md)
