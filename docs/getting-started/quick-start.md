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

### Environment Setup

Configure the LLM judge. Every recommended setup uses it, because the rules alone catch only about 8%
of held-out malicious skills. A local model works too; see
[LLM Providers](https://cisco-ai-defense.github.io/docs/skill-scanner/llm-providers).

```bash
# The LLM judge
export SKILL_SCANNER_LLM_API_KEY="your_api_key"
export SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-5-5"

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

By default, `scan` runs the core analyzers: **static + bytecode + pipeline + correlation**.
That is a first test that the install works. For real use, add the judge:

```bash
skill-scanner scan /path/to/skill --use-llm --policy balanced --fail-on-severity high
```

The correlation pass joins bounded, structured source/sink facts and never executes skill content.
Balanced/default mode then evaluates bundled CEL gates in shadow, recording
decisions without suppressing findings. Permissive mode uses CEL off and
disables correlation.

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

# Validate selected packs and compile/type-check CEL
skill-scanner validate-rules

# Inspect typed CEL decisions in JSON output
skill-scanner scan /path/to/skill --cel-mode shadow --format json

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

Five presets ship: `balanced` (default), `low-noise`, `quiet`, `strict` and `permissive`.
Which to use for which job, with measured recall, false-positive rate and F1, is in
[Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings).

```bash
# Your own skills: fewer harmless flags, same detections
skill-scanner scan /path/to/skill --use-llm --policy low-noise

# Third-party skills with the judge, fewest false positives (never without --use-llm)
skill-scanner scan /path/to/skill --use-llm --policy quiet

# Generate a custom policy YAML to edit, starting from a preset
skill-scanner generate-policy --preset low-noise -o my_policy.yaml

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

**LLM provider note:** `--llm-provider` accepts `anthropic`, `openai` or `openai-compatible`.
For Bedrock, Vertex, Azure, Gemini, Ollama, gateways and other LiteLLM backends, set provider-specific model strings and environment variables (see [Dependencies and LLM Providers](../reference/dependencies-and-llm-providers.md)).

### Cross-Skill Analysis
```bash
skill-scanner scan-all /path/to/skills --check-overlap
```

### Lenient Mode

Tolerate malformed skills (missing fields, non-string descriptions) instead of failing. When `SKILL.md` is absent, lenient mode falls back to scanning `.md` files in the directory as instruction bodies — enabling support for non-Codex/Cursor formats such as Claude Code `.claude/commands/*.md`:

```bash
skill-scanner scan /path/to/skill --lenient
skill-scanner scan-all /path/to/skills --recursive --lenient

# Scan a Claude Code commands directory (no SKILL.md)
skill-scanner scan .claude/commands/deploy --lenient

# Use a custom metadata filename instead of SKILL.md
skill-scanner scan /path/to/skill --skill-file README.md
```

### Pre-commit Hook

Using the [pre-commit](https://pre-commit.com/) framework, with the LLM judge:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/cisco-ai-defense/skill-scanner
    rev: 2.2.2  # the latest release tag (no "v" prefix)
    hooks:
      - id: skill-scanner
```

Turn the judge on in `.skill_scannerrc` at the repository root (`use_llm` is off by default):

```json
{
  "skills_path": ".claude/skills",
  "policy": "low-noise",
  "use_llm": true,
  "llm_model": "anthropic/claude-sonnet-5-5",
  "severity_threshold": "high",
  "fail_fast": true
}
```

The hook scans only the skills a commit touches. The key comes from `SKILL_SCANNER_LLM_API_KEY`,
or from cloud credentials for Bedrock and Vertex AI. `llm_model` and `llm_provider` fall back to
`SKILL_SCANNER_LLM_MODEL` and `SKILL_SCANNER_LLM_PROVIDER`, so the hook can point at a local model.
If the judge cannot be built, the commit is blocked with exit code 2 instead of passing on the rules
alone. For a `bedrock/` model, add `additional_dependencies: [boto3]` to the hook. Run
`pre-commit install` once, or `skill-scanner-pre-commit --install` without the pre-commit framework.

## Next Steps

1. **Review the documentation:**
   - [README.md](https://github.com/cisco-ai-defense/skill-scanner/blob/main/README.md) - Project overview
   - [/architecture/](../architecture/index.md) - System design
   - [/architecture/threat-taxonomy](../architecture/threat-taxonomy.md) - Threat taxonomy and mappings
   - [/user-guide/scan-policies-overview](../user-guide/scan-policies-overview.md) - Custom policies and tuning
   - [/reference/](../reference/index.md) - Configuration, CLI, API, and output format reference

2. **Pick a setup and scan your own skills:** see
   [Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings).
   ```bash
   skill-scanner scan /path/to/your/skill --use-llm --policy low-noise --fail-on-severity high
   ```

3. **Integrate with CI/CD:**
   ```bash
   skill-scanner scan-all ./skills --recursive --use-llm --policy low-noise --fail-on-severity high
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
