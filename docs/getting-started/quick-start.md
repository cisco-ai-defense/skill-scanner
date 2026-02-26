# Quick Start Guide

## Installation

### Using uv (Recommended)

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

### Environment Setup (Optional)

```bash
# For LLM analyzer and Meta-analyzer
export SKILL_SCANNER_LLM_API_KEY="your_api_key"
export SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"

# For VirusTotal binary scanning
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

# For Cisco AI Defense
export AI_DEFENSE_API_KEY="your_aidefense_api_key"
```

See [Configuration Reference](../reference/configuration-reference.md) for every available environment variable.

### Interactive Wizard

Not sure which flags to use? Run `skill-scanner` with no arguments to launch the interactive wizard:

```bash
skill-scanner
```

It walks you through selecting a scan target, analyzers, policy, and output format step by step.

### Scan a Single Skill

```bash
# From source (with uv)
uv run skill-scanner scan evals/skills/safe-skills/simple-math

# Installed package
skill-scanner scan evals/skills/safe-skills/simple-math
```

By default, `scan` runs the core analyzers: **static + bytecode + pipeline**.

### Scan Multiple Skills

```bash
# Scan all skills in a directory
skill-scanner scan-all evals/skills --format table

# Recursive scan with detailed markdown report
skill-scanner scan-all evals/skills --format markdown --detailed --output report.md
```

## Demo Results

The project includes test skills in [`evals/skills/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/evals/skills) for evaluation and testing:

### [OK] simple-math (SAFE)

```txt
$ skill-scanner scan evals/skills/safe-skills/simple-math
============================================================
Skill: simple-math
============================================================
Status: [OK] SAFE
Max Severity: SAFE
Total Findings: 0
Scan Duration: 0.12s

```

### [FAIL] multi-file-exfiltration (CRITICAL)

```txt
$ skill-scanner scan evals/skills/behavioral-analysis/multi-file-exfiltration --use-behavioral
============================================================
Skill: config-analyzer
============================================================
Status: [FAIL] ISSUES FOUND
Max Severity: CRITICAL
Total Findings: 11
Scan Duration: 0.37s

Findings Summary:
  CRITICAL: 3
      HIGH: 3
    MEDIUM: 4
       LOW: 1
      INFO: 0
```

**Detected Threats:**
- Data exfiltration (HTTP POST to external server)
- Reading sensitive files (`~/.aws/credentials`)
- Environment variable theft (`API_KEY`, `SECRET_TOKEN`)
- Command injection (`eval` on user input)
- Base64 encoding + network exfiltration pattern

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

See [CLI Command Reference](../reference/cli-command-reference.md) for detailed flags and options for every command.

## Output Formats

See [Output Formats Reference](../reference/output-formats.md) for sample outputs and a format decision guide.

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

### Scan Policies

Use built-in presets or a custom policy to tune detection sensitivity:

```bash
# Use a stricter preset
skill-scanner scan /path/to/skill --policy strict

# Use a more permissive preset
skill-scanner scan /path/to/skill --policy permissive

# Generate a custom policy YAML to edit
skill-scanner generate-policy -o my_policy.yaml

# Interactive policy configurator (TUI)
skill-scanner configure-policy
```

See [Scan Policy Guide](../user-guide/scan-policies-overview.md) for full details.

### Enable All Analyzers
```bash
skill-scanner scan /path/to/skill \
  --use-behavioral \
  --use-llm \
  --use-trigger \
  --use-aidefense \
  --use-virustotal
```

**LLM provider note:** `--llm-provider` currently accepts `anthropic` or `openai`.
For Bedrock, Vertex, Azure, Gemini, and other LiteLLM backends, set provider-specific model strings and environment variables (see [Dependencies and LLM Providers](../reference/dependencies-and-llm-providers.md)).

### Cross-Skill Analysis
```bash
skill-scanner scan-all /path/to/skills --check-overlap
```

### Lenient Mode

Tolerate malformed skills (missing fields, non-string descriptions) instead of failing:

```bash
skill-scanner scan /path/to/skill --lenient
skill-scanner scan-all /path/to/skills --recursive --lenient
```

### Pre-commit Hook

Using the [pre-commit](https://pre-commit.com/) framework (recommended):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/cisco-ai-defense/skill-scanner
    rev: v1.0.0  # use the latest release tag
    hooks:
      - id: skill-scanner
```

Or install the built-in hook directly:

```bash
skill-scanner-pre-commit install
```

The hook only scans skill directories with staged changes. Use `--all` to scan everything.

## Next Steps

1. **Review the documentation:**
   - [README.md](https://github.com/cisco-ai-defense/skill-scanner/blob/main/README.md) - Project overview
   - [/architecture/](../architecture/index.md) - System design
   - [/architecture/threat-taxonomy](../architecture/threat-taxonomy.md) - Threat taxonomy and mappings
   - [/user-guide/scan-policies-overview](../user-guide/scan-policies-overview.md) - Custom policies and tuning
   - [/reference/](../reference/index.md) - Configuration, CLI, API, and output format reference

2. **Try scanning your own skills:**
   ```bash
   skill-scanner scan /path/to/your/skill
   ```

3. **Integrate with CI/CD:**
   ```bash
   skill-scanner scan-all ./skills --fail-on-severity high
   # Exit code 1 if findings at or above HIGH severity
   ```
   See [GitHub Actions Integration](../github-actions.md) for a ready-made reusable workflow.

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
