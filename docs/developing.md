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

For detailed testing requirements, see [TESTING.md](/TESTING.md).

### Code Quality

All checks run via pre-commit:

```bash
uv run pre-commit run --all-files
```

This runs:
- **ruff**: Linting and formatting
- **mypy**: Type checking (if configured)
- **gitleaks**: Secret detection
- **addlicense**: Apache 2.0 license headers

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
├── cli/               # Click CLI interface
├── config/            # Configuration and constants
├── core/
│   ├── analyzers/     # Security analyzers (static, behavioral, LLM)
│   ├── reporters/     # Output formatters (JSON, SARIF, Markdown)
│   ├── rules/         # YARA and pattern rules
│   ├── static_analysis/  # AST parsing and dataflow analysis
│   ├── loader.py      # Skill package loader
│   ├── models.py      # Data models
│   └── scanner.py     # Main scanner orchestrator
├── data/
│   ├── prompts/       # LLM analysis prompts
│   ├── rules/         # YAML detection rules
│   └── yara_rules/    # YARA detection rules
├── hooks/             # Pre-commit hooks
├── threats/           # Threat taxonomy
└── utils/             # Shared utilities
tests/
├── conftest.py        # Shared fixtures
└── test_*.py          # Test files
evals/
├── skills/            # Evaluation skill samples
└── benchmark_runner.py
```

## Running Individual Analyzers

```bash
# Static analysis only (default)
skill-scanner scan /path/to/skill

# With behavioral analysis
skill-scanner scan /path/to/skill --use-behavioral

# With LLM analysis (requires API key)
skill-scanner scan /path/to/skill --use-llm

# All analyzers
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-virustotal
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/).
