# Development Guide

This guide covers setting up your development environment, running tests, and contributing code to the Skill Scanner.

## Prerequisites

- **Python 3.10+** - Required for running the project
- **Git** - For version control
- **uv** - Fast Python package manager (installation instructions below)

## Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/cisco-ai-defense/skill-scanner
cd skill-scanner
```

### 2. Install uv

[uv](https://docs.astral.sh/uv/) is our recommended package manager for fast, reliable dependency management.

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 3. Install Dependencies

```bash
# Install all dependencies including dev extras
uv sync --all-extras
```

### 4. Install Pre-commit Hooks

```bash
uv run pre-commit install
```

This ensures code quality checks run automatically before each commit.

### 5. Verify Setup

```bash
# Run tests to verify everything works
uv run pytest tests/ -q

# Run linting
uv run pre-commit run --all-files
```

## Development Workflow

### Running Tests

```bash
# Run all tests
uv run pytest tests/ -v --tb=short

# Run specific test file
uv run pytest tests/test_scanner.py -v

# Run specific test
uv run pytest tests/test_scanner.py::test_scan_safe_skill -v

# Run with coverage report
uv run pytest tests/ -v --tb=short --cov=skill_scanner --cov-report=html
```

For detailed testing requirements, see [TESTING.md](https://github.com/cisco-ai-defense/skill-scanner/blob/main/TESTING.md).

### Code Quality

All checks run via pre-commit:

```bash
uv run pre-commit run --all-files
```

This runs:
- **ruff**: Linting and formatting
- **pre-commit-hooks**: Whitespace, file, and config hygiene checks
- **gitleaks**: Secret detection
- **addlicense**: Apache 2.0 license headers
- **check-taxonomy**: Validates taxonomy enum parity with Cisco taxonomy profile

Run mypy separately:

```bash
uv run mypy skill_scanner
```

### Before Submitting a PR

1. Ensure all pre-commit hooks pass
2. Add/update tests for your changes
3. Run the full test suite
4. Update documentation if needed
5. Follow commit message conventions

## Project Structure

```
skill_scanner/
├── __init__.py
├── api/               # FastAPI REST endpoints
├── cli/               # argparse-based CLI commands and policy TUI
├── config/            # Configuration and constants
├── core/
│   ├── analyzers/     # Security analyzers (static, bytecode, pipeline, behavioral, LLM)
│   ├── reporters/     # Output formatters (JSON, SARIF, Markdown)
│   ├── rules/         # Rule loaders (patterns.py, yara_scanner.py)
│   ├── rule_registry.py  # Centralized rule registry and pack loader
│   ├── static_analysis/  # AST parsing and dataflow analysis
│   ├── loader.py      # Skill package loader
│   ├── models.py      # Data models
│   ├── scan_policy.py # Policy engine (single source of truth for all knobs)
│   └── scanner.py     # Main scanner orchestrator
├── data/
│   ├── packs/
│   │   └── core/
│   │       ├── pack.yaml       # Rule pack manifest
│   │       ├── signatures/     # YAML regex detection rules
│   │       ├── yara/           # YARA detection rules
│   │       └── python/         # Python check modules
│   ├── prompts/                # LLM analysis prompts
│   ├── default_policy.yaml     # Balanced policy preset
│   ├── strict_policy.yaml      # Strict policy preset
│   └── permissive_policy.yaml  # Permissive policy preset
├── hooks/             # Pre-commit hooks
├── threats/           # Threat taxonomy
└── utils/             # Shared utilities
tests/
├── conftest.py        # Shared fixtures
└── test_*.py          # Test files
evals/
├── runners/           # Benchmark and eval runners
├── policies/          # Policy presets for benchmarking
└── skills/            # Evaluation skill samples
```

## Running Individual Analyzers

```bash
# Core analyzers only (default: static + bytecode + pipeline)
skill-scanner scan /path/to/skill

# With behavioral analysis
skill-scanner scan /path/to/skill --use-behavioral

# With LLM analysis (requires API key)
skill-scanner scan /path/to/skill --use-llm

# With trigger specificity analysis
skill-scanner scan /path/to/skill --use-trigger

# All analyzers
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-virustotal

# Cross-skill overlap analysis
skill-scanner scan-all /path/to/skills --check-overlap

# Lenient mode (tolerate malformed skills)
skill-scanner scan-all /path/to/skills --recursive --lenient
```

## Pre-commit Hook for External Repos

This project publishes a `.pre-commit-hooks.yaml` so other repos can use Skill Scanner as a [pre-commit](https://pre-commit.com/) hook:

```yaml
# In the consuming repo's .pre-commit-config.yaml
repos:
  - repo: https://github.com/cisco-ai-defense/skill-scanner
    rev: v1.0.0
    hooks:
      - id: skill-scanner
```

The hook entry point is `skill-scanner-pre-commit` (defined in `pyproject.toml`). It automatically detects staged skill directories via `git diff --cached` and only scans those.

## GitHub Actions Reusable Workflow

The file `.github/workflows/scan-skills.yml` is a reusable workflow that other repos can call via `workflow_call`. See [docs/github-actions.md](../github-actions.md) for full usage.

## Versioning

This project follows [Semantic Versioning](https://semver.org/).
