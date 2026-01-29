# Quick Start Guide

## Installation

### Using UV (Recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/cisco-ai-defense/skill-scanner
cd skill-scanner

# Install all dependencies
uv sync --all-extras
```

### Using pip

```bash
# Install the package
pip install cisco-ai-skill-scanner[all]
```

## Basic Usage

### Scan a Single Skill

```bash
# From source (with uv)
uv run skill-scanner scan evals/skills/safe-skills/simple-math

# Installed package
skill-scanner scan evals/skills/safe-skills/simple-math
```

### Scan Multiple Skills

```bash
# Scan all skills in a directory
skill-scanner scan-all evals/skills --format table

# Recursive scan with detailed markdown report
skill-scanner scan-all evals/skills --format markdown --detailed --output report.md
```

## Demo Results

The project includes test skills in `evals/skills/` for evaluation and testing:

### [OK] simple-math (SAFE)
```bash
$ skill-scanner scan evals/skills/safe-skills/simple-math
============================================================
Skill: safe-calculator
============================================================
Status: [OK] SAFE
Max Severity: SAFE
Total Findings: 0
Scan Duration: 0.00s
```

### [FAIL] multi-file-exfiltration (CRITICAL)
```bash
$ skill-scanner scan evals/skills/behavioral-analysis/multi-file-exfiltration
============================================================
Skill: data-analyzer
============================================================
Status: [FAIL] ISSUES FOUND
Max Severity: CRITICAL
Total Findings: 12
Scan Duration: 0.00s

Findings Summary:
  Critical: 5
  High:     3
  Medium:   3
  Low:      1
```

**Detected Threats:**
- ✅ Data exfiltration (HTTP POST to external server)
- ✅ Reading sensitive files (~/.aws/credentials)
- ✅ Environment variable theft (API_KEY, SECRET_TOKEN)
- ✅ Command injection (eval on user input)
- ✅ Base64 encoding + network (exfiltration pattern)

## Useful Commands

```bash
# List available analyzers
skill-scanner list-analyzers

# Validate rule signatures
skill-scanner validate-rules

# Get help
skill-scanner --help
skill-scanner scan --help
```

## Output Formats

### JSON (for CI/CD)
```bash
skill-scanner scan /path/to/skill --format json --output results.json
```

### SARIF (for GitHub Code Scanning)
```bash
skill-scanner scan /path/to/skill --format sarif --output results.sarif
```

### Markdown (human-readable report)
```bash
skill-scanner scan /path/to/skill --format markdown --detailed --output report.md
```

### Table (terminal-friendly)
```bash
skill-scanner scan-all evals/skills --format table
```

## Advanced Features

### Enable All Analyzers
```bash
skill-scanner scan /path/to/skill \
  --use-behavioral \
  --use-llm \
  --use-trigger \
  --use-aidefense \
  --use-virustotal
```

### Cross-Skill Analysis
```bash
skill-scanner scan-all /path/to/skills --check-overlap
```

### Pre-commit Hook
```bash
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Next Steps

1. **Review the documentation:**
   - [README.md](../README.md) - Project overview
   - [docs/architecture.md](architecture.md) - System design
   - [docs/threat-taxonomy.md](threat-taxonomy.md) - All threat categories

2. **Try scanning your own skills:**
   ```bash
   skill-scanner scan /path/to/your/skill
   ```

3. **Integrate with CI/CD:**
   ```bash
   skill-scanner scan-all ./skills --fail-on-findings
   # Exit code 1 if critical/high issues found
   ```

## Troubleshooting

### UV not found
Install UV:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Module not found errors
Sync dependencies:
```bash
uv sync --all-extras
```

### Permission errors
UV manages its own virtual environment - no need for manual venv activation.
