# Testing Guide

This document covers testing requirements and procedures for contributing to the Skill Scanner.

## Quick Reference

```bash
# Run all unit tests
uv run pytest tests/ -v

# Run tests with coverage
uv run pytest tests/ --cov=skill_scanner --cov-report=html

# Run evaluation benchmark
uv run python evals/benchmark_runner.py
```

## Test Categories

### Unit Tests (`tests/`)

Unit tests verify individual components work correctly in isolation.

```bash
# Run all unit tests
uv run pytest tests/ -v --tb=short

# Run specific test file
uv run pytest tests/test_scanner.py -v

# Run specific test class
uv run pytest tests/test_scanner.py::TestScanner -v

# Run specific test method
uv run pytest tests/test_scanner.py::TestScanner::test_scan_safe_skill -v

# Run tests matching a pattern
uv run pytest tests/ -k "behavioral" -v
```

### Test Files

| File | Description |
|------|-------------|
| `test_scanner.py` | Core scanner functionality |
| `test_loader.py` | Skill loading and parsing |
| `test_models.py` | Data model validation |
| `test_config.py` | Configuration handling |
| `test_cli_formats.py` | CLI output formats (JSON, SARIF, etc.) |
| `test_api_endpoints.py` | REST API endpoints |
| `test_reporters.py` | Report generation |
| `test_threats.py` | Threat taxonomy |
| `behavioral/` | Behavioral analyzer tests |
| `static_analysis/` | Static analysis tests |

### Integration Tests

Integration tests verify components work together correctly.

```bash
uv run pytest tests/test_integration.py -v
```

### Analyzer-Specific Tests

```bash
# Static analyzer
uv run pytest tests/static_analysis/ -v

# Behavioral analyzer
uv run pytest tests/behavioral/ -v

# LLM analyzer (may require API keys)
uv run pytest tests/test_llm_analyzer.py -v

# Meta analyzer
uv run pytest tests/test_meta_analyzer.py -v

# AI Defense analyzer
uv run pytest tests/test_aidefense_analyzer.py -v
```

## Evaluation Framework (`evals/`)

The evaluation framework tests detection accuracy against curated skill samples.

```bash
# Run full evaluation suite
uv run python evals/eval_runner.py --test-skills-dir evals/skills

# Run with LLM analyzer (requires API key)
GEMINI_API_KEY=xxx uv run python evals/eval_runner.py --test-skills-dir evals/skills --use-llm

# Run benchmark
uv run python evals/benchmark_runner.py
```

For detailed evaluation documentation, see [evals/README.md](/evals/README.md).

## Test Coverage

### Running Coverage Reports

```bash
# Generate HTML coverage report
uv run pytest tests/ --cov=skill_scanner --cov-report=html

# View report (opens in browser)
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Coverage Requirements

- New code should have test coverage
- Critical paths (analyzers, scanner, loader) should maintain high coverage
- Bug fixes should include regression tests

## Writing Tests

### Test Structure

```python
# tests/test_example.py
import pytest
from skill_scanner.core.scanner import SkillScanner

class TestExampleFeature:
    """Tests for example feature."""

    def test_basic_functionality(self):
        """Test that basic case works."""
        scanner = SkillScanner()
        result = scanner.scan("/path/to/skill")
        assert result is not None

    def test_edge_case(self):
        """Test edge case handling."""
        # Test implementation

    def test_error_handling(self):
        """Test that errors are handled gracefully."""
        with pytest.raises(ValueError):
            # Code that should raise
```

### Using Fixtures

Common fixtures are defined in `tests/conftest.py`:

```python
def test_with_fixture(safe_skill_dir, tmp_path):
    """Test using shared fixtures."""
    # safe_skill_dir provides a path to a safe test skill
    # tmp_path provides a temporary directory
```

### Async Tests

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    """Test async functionality."""
    result = await some_async_function()
    assert result is not None
```

## Required Tests Before PR

Before submitting a pull request, ensure:

1. **All existing tests pass**
   ```bash
   uv run pytest tests/ -v
   ```

2. **Pre-commit hooks pass**
   ```bash
   uv run pre-commit run --all-files
   ```

3. **New tests added for new functionality**
   - Each new feature should have corresponding tests
   - Bug fixes should include regression tests

4. **No test regressions**
   - Existing tests should not be broken
   - Test coverage should not decrease significantly

## CI/CD Testing

Tests run automatically in GitHub Actions on:
- Every push to `main`
- Every pull request

The CI pipeline runs:
1. Unit tests across Python 3.10, 3.11, 3.12
2. Pre-commit checks (linting, formatting)
3. Coverage reporting

## Troubleshooting

### Common Issues

**Tests fail with import errors:**
```bash
# Reinstall dependencies
uv sync --all-extras
```

**Tests hang or timeout:**
```bash
# Run with timeout
uv run pytest tests/ --timeout=60
```

**Flaky tests:**
- Tests involving timing should use normalized comparisons
- Network-dependent tests should use mocks
- File system tests should use `tmp_path` fixture

### Running Tests in Isolation

```bash
# Run single test in isolation
uv run pytest tests/test_scanner.py::test_scan_safe_skill -v --forked
```

## Related Documentation

- [Development Guide](/docs/developing.md) - Environment setup
- [Contributing Guide](/CONTRIBUTING.md) - Contribution process
- [Evaluation Framework](/evals/README.md) - Detection accuracy testing
