# Development

This section covers repository setup, testing, and release/CI workflows.

## Quick Setup

```bash
git clone https://github.com/cisco-ai-defense/skill-scanner && cd skill-scanner
uv sync --all-extras
uv run pytest                                                   # run tests
uv run ruff check .                                             # lint
uv run skill-scanner scan evals/skills/safe-skills/simple-math  # smoke test
```

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `skill_scanner/` | Core package -- analyzers, CLI, API, models, policy engine |
| `skill_scanner/data/` | Detection packs (YAML signatures, YARA rules, LLM prompts) |
| `tests/` | pytest test suites (unit, integration, analyzer-specific) |
| `evals/` | Evaluation skills (safe and malicious) for benchmarking |
| `examples/` | Runnable Python scripts demonstrating SDK and API usage |
| `docs/` | Documentation |
| `scripts/` | Helper scripts (doc generation, pre-commit hooks) |

## Core Topics

- [Local setup and tests](setup-and-testing.md) -- detailed environment configuration, test commands, coverage
- [CI/CD & Integrations](integrations.md) -- GitHub Actions, pre-commit hooks, SARIF upload, build gates
- [Example usage patterns](../guides/examples-and-how-to.md) -- runnable examples and how-to walkthroughs

## Contribution Path

1. Set up environment with `uv sync --all-extras`.
2. Run quality checks: `uv run ruff check .` and `uv run pytest`.
3. Validate rules/docs when relevant: `uv run skill-scanner validate-rules`.
4. Open PR with reproducible test evidence.
