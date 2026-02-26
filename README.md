# Skill Scanner

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/cisco-ai-skill-scanner.svg)](https://pypi.org/project/cisco-ai-skill-scanner/)
[![CI](https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml/badge.svg)](https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da?logo=discord&logoColor=white)](https://discord.com/invite/nKWtDcXxtx)
[![Cisco AI Defense](https://img.shields.io/badge/Cisco-AI%20Defense-049fd9?logo=cisco&logoColor=white)](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
[![AI Security Framework](https://img.shields.io/badge/AI%20Security-Framework-orange)](https://learn-cloudsecurity.cisco.com/ai-security-framework)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cisco-ai-defense/skill-scanner)

A best-effort security scanner for AI Agent Skills that detects prompt injection, data exfiltration, and malicious code patterns. Combines **pattern-based detection** (YAML + YARA), **LLM-as-a-judge**, and **behavioral dataflow analysis** to maximize detection coverage of probable threats while minimizing false positives.

> **Important:** This scanner provides best-effort detection, not comprehensive or complete coverage. A scan that returns no findings does not guarantee that a skill is free of all threats. See [Scope and Limitations](#scope-and-limitations) below.

Supports [OpenAI Codex Skills](https://openai.github.io/codex/) and [Cursor Agent Skills](https://docs.cursor.com/context/rules) formats following the [Agent Skills specification](https://agentskills.io).

---

## Highlights

- **Multi-Engine Detection** - Static analysis, behavioral dataflow, LLM semantic analysis, and cloud-based scanning for layered, best-effort coverage
- **False Positive Filtering** - Meta-analyzer significantly reduces noise while preserving detection capability
- **CI/CD Ready** - SARIF output for GitHub Code Scanning, [reusable GitHub Actions workflow](docs/github-actions.md), exit codes for build failures
- **Pre-commit Hook** - [Standard pre-commit framework](https://pre-commit.com/) integration to scan skills before every commit
- **Extensible** - Plugin architecture for custom analyzers

**[Join the Cisco AI Discord](https://discord.com/invite/nKWtDcXxtx)** to discuss, share feedback, or connect with the team.

---

## Scope and Limitations

Skill Scanner is a detection tool. It identifies known and probable risk patterns, but it does not certify security.

**Key limitations:**

- **No findings ≠ no risk.** A scan that returns "No findings" indicates that no known threat patterns were detected. It does not guarantee that a skill is secure, benign, or free of vulnerabilities.
- **Coverage is inherently incomplete.** The scanner combines signature-based detection, LLM-based semantic analysis, behavioral dataflow analysis, optional cloud services, and configurable rule packs. While this approach improve coverage, no automated tool can detect every technique, especially novel or zero-day attacks.
- **False positives and false negatives can occur.** Consensus modes and meta-analysis reduce noise, but no configuration eliminates all incorrect classifications. Tune the [scan policy](docs/user-guide/custom-policy-configuration.md) to your risk tolerance.
- **Human review remains essential.** Automated scanning is one component of a defense-in-depth strategy. High-risk or production deployments should pair scanner results with manual code review and/or  threat modeling.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/getting-started/quick-start.md) | Get started in 5 minutes |
| [Architecture](docs/architecture/index.md) | System design and components |
| [Threat Taxonomy](docs/architecture/threat-taxonomy.md) | Complete AITech threat taxonomy with examples |
| [LLM Analyzer](docs/architecture/analyzers/llm-analyzer.md) | LLM configuration and usage |
| [Meta-Analyzer](docs/architecture/analyzers/meta-analyzer.md) | False positive filtering and prioritization |
| [Behavioral Analyzer](docs/architecture/analyzers/behavioral-analyzer.md) | Dataflow analysis details |
| [Scan Policy](docs/user-guide/custom-policy-configuration.md) | Custom policies, presets, and tuning guide |
| [Policy Quick Reference](docs/reference/policy-quick-reference.md) | Compact reference for policy sections and knobs |
| [Rule Authoring](docs/architecture/analyzers/writing-custom-rules.md) | How to add signature, YARA, and Python rules |
| [GitHub Actions](docs/github-actions.md) | Reusable workflow for CI/CD integration |
| [API Reference](docs/user-guide/api-server.md) | REST API documentation |
| [Development Guide](docs/development/setup-and-testing.md) | Contributing and development setup |

---

## Installation

**Prerequisites:** Python 3.10+ and [uv](https://docs.astral.sh/uv/) (recommended) or pip

```bash
# Using uv (recommended)
uv pip install cisco-ai-skill-scanner

# Using pip
pip install cisco-ai-skill-scanner
```

<details>
<summary><strong>Cloud Provider Extras</strong></summary>

```bash
# AWS Bedrock support
pip install cisco-ai-skill-scanner[bedrock]

# Google Vertex AI support
pip install cisco-ai-skill-scanner[vertex]

# Azure OpenAI support
pip install cisco-ai-skill-scanner[azure]

# All cloud providers
pip install cisco-ai-skill-scanner[all]
```

</details>

---

## Quick Start

### Environment Setup (Optional)

```bash
# For LLM analyzer and Meta-analyzer
export SKILL_SCANNER_LLM_API_KEY="your_api_key"
export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"

# For VirusTotal binary scanning
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

# For Cisco AI Defense
export AI_DEFENSE_API_KEY="your_aidefense_api_key"
```

### Interactive Wizard

Not sure which flags to use? Run `skill-scanner` with no arguments to launch the interactive wizard:

```bash
skill-scanner
```

The wizard walks you through selecting a scan target, analyzers, policy, and output format, then shows the assembled command before running it. Great for learning the CLI.

### CLI Usage

```bash
# Scan a single skill (core analyzers: static + bytecode + pipeline)
skill-scanner scan /path/to/skill

# Scan with behavioral analyzer (dataflow analysis)
skill-scanner scan /path/to/skill --use-behavioral

# Scan with all engines
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-aidefense

# Scan with meta-analyzer for false positive filtering
skill-scanner scan /path/to/skill --use-llm --enable-meta

# Scan with trigger analyzer for vague description checks
skill-scanner scan /path/to/skill --use-trigger

# Run LLM analyzer multiple times and keep majority-agreed findings
skill-scanner scan /path/to/skill --use-llm --llm-consensus-runs 3

# Scan multiple skills recursively
skill-scanner scan-all /path/to/skills --recursive --use-behavioral

# Scan multiple skills with cross-skill overlap detection
skill-scanner scan-all /path/to/skills --recursive --check-overlap

# Lenient mode: tolerate malformed skills instead of failing
skill-scanner scan /path/to/skill --lenient
skill-scanner scan-all /path/to/skills --recursive --lenient

# CI/CD: Fail build if threats found
skill-scanner scan-all ./skills --fail-on-severity high --format sarif --output results.sarif

# Generate interactive HTML report with attack correlation groups
skill-scanner scan /path/to/skill --use-llm --enable-meta --format html --output report.html

# Use custom YARA rules
skill-scanner scan /path/to/skill --custom-rules /path/to/my-rules/

# Use custom taxonomy + threat mapping profiles (JSON/YAML)
skill-scanner scan /path/to/skill --taxonomy /path/to/taxonomy.json --threat-mapping /path/to/threat_mapping.json

# VirusTotal hash scan with optional unknown-file uploads
skill-scanner scan /path/to/skill --use-virustotal --vt-upload-files

# Use a scan policy preset (strict, balanced, permissive)
skill-scanner scan /path/to/skill --policy strict

# Use a custom org policy file
skill-scanner scan /path/to/skill --policy my_org_policy.yaml

# Generate a policy file to customise
skill-scanner generate-policy -o my_org_policy.yaml

# Interactive policy configurator (TUI)
skill-scanner configure-policy
```

**LLM provider note:** `--llm-provider` currently accepts `anthropic` or `openai`.
For Bedrock, Vertex, Azure, Gemini, and other LiteLLM backends, set provider-specific model strings and environment variables (see [LLM Analyzer docs](docs/architecture/analyzers/llm-analyzer.md)).

### Python SDK

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import BehavioralAnalyzer

# Create scanner with analyzers
scanner = SkillScanner(analyzers=[
    BehavioralAnalyzer(),
])

# Scan a skill
result = scanner.scan_skill("/path/to/skill")

print(f"Findings: {len(result.findings)}")
print(f"Max severity: {result.max_severity}")

# Note: is_safe indicates no HIGH/CRITICAL findings were detected.
# It does not guarantee the skill is free of all risk.
if not result.is_safe:
    print("Issues detected -- review findings before deployment")
```

---

## Security Analyzers

| Analyzer | Detection Method | Scope | Requirements |
|----------|------------------|-------|--------------|
| **Static** | YAML + YARA patterns | All files | None |
| **Bytecode** | .pyc integrity verification | Python bytecode | None |
| **Pipeline** | Command taint analysis | Shell pipelines | None |
| **Behavioral** | AST dataflow analysis | Python files | None |
| **LLM** | Semantic analysis | SKILL.md + scripts | API key |
| **Meta** | False positive filtering | All findings | API key |
| **VirusTotal** | Hash-based malware | Binary files | API key |
| **AI Defense** | Cloud-based AI | Text content | API key |

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--policy` | Scan policy: preset name (`strict`, `balanced`, `permissive`) or path to custom YAML |
| `--use-behavioral` | Enable behavioral analyzer (dataflow analysis) |
| `--use-llm` | Enable LLM analyzer (requires API key) |
| `--llm-provider` | LLM provider for CLI routing: `anthropic` or `openai` |
| `--llm-consensus-runs N` | Run LLM analysis `N` times and keep majority-agreed findings |
| `--use-virustotal` | Enable VirusTotal binary scanner |
| `--vt-api-key KEY` | Provide VirusTotal API key directly (optional) |
| `--vt-upload-files` | Upload unknown binaries to VirusTotal (optional) |
| `--use-aidefense` | Enable Cisco AI Defense analyzer |
| `--aidefense-api-url URL` | Override AI Defense API URL (optional) |
| `--use-trigger` | Enable trigger specificity analyzer |
| `--enable-meta` | Enable meta-analyzer for false positive filtering |
| `--verbose` | Include per-finding policy fingerprints, co-occurrence metadata, and keep meta-analyzer false positives |
| `--format` | Output: `summary`, `json`, `markdown`, `table`, `sarif`, `html`. The `html` format produces a self-contained interactive report with collapsible correlation groups, expandable code snippets, and pipeline taint flow diagrams |
| `--detailed` | Include detailed findings in Markdown output |
| `--compact` | Compact JSON output |
| `--output PATH` | Save report to file |
| `--fail-on-findings` | Exit with error if HIGH/CRITICAL found (shorthand for `--fail-on-severity high`) |
| `--fail-on-severity LEVEL` | Exit with error if findings at or above LEVEL exist (critical, high, medium, low, info) |
| `--custom-rules PATH` | Use custom YARA rules from directory |
| `--taxonomy PATH` | Load custom taxonomy profile (JSON/YAML) for this run |
| `--threat-mapping PATH` | Load custom scanner threat mapping profile (JSON) for this run |
| `--lenient` | Tolerate malformed skills (coerce bad fields, fill defaults) instead of failing |
| `--check-overlap` | (`scan-all`) Enable cross-skill description overlap checks |

| Command | Description |
|---------|-------------|
| *(no command)* | Launch interactive scan wizard (when run in a terminal) |
| `interactive` | Launch interactive scan wizard (explicit) |
| `scan` | Scan a single skill directory |
| `scan-all` | Scan multiple skills (with `--recursive`, `--check-overlap`) |
| `generate-policy` | Generate a scan policy YAML for customisation |
| `configure-policy` | Interactive TUI to build/edit a custom scan policy (`--input` supported) |
| `list-analyzers` | Show available analyzers |
| `validate-rules` | Validate rule signatures (`--rules-file` supported) |

---

## Example Output

```
$ skill-scanner scan ./my-skill --use-behavioral

============================================================
Skill: my-skill
============================================================
Status: [OK] No findings
Max Severity: NONE
Total Findings: 0
Scan Duration: 0.15s
```

> **Note:** "No findings" means the scanner did not detect any known threat patterns -- it is not a guarantee that the skill is free of all risk. See [Scope and Limitations](#scope-and-limitations).

---

## GitHub Actions

Scan skills automatically on every push or PR using the [reusable workflow](docs/github-actions.md):

```yaml
# .github/workflows/scan-skills.yml
name: Scan Skills
on:
  pull_request:
    paths: [".cursor/skills/**"]
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@main
    with:
      skill_path: .cursor/skills
    permissions:
      security-events: write
      contents: read
```

Results appear as inline annotations in PRs via GitHub Code Scanning. See the [full guide](docs/github-actions.md) for LLM integration, secret configuration, and branch protection setup.

---

## Pre-commit Hook

Scan skills before every commit using the [pre-commit](https://pre-commit.com/) framework:

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

The hook automatically detects which skill directories have staged changes and only scans those, keeping commit times fast. Use `--all` to scan everything.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

Copyright 2026 Cisco Systems, Inc. and its affiliates

---

<p align="center">
  <a href="https://github.com/cisco-ai-defense/skill-scanner">GitHub</a> •
  <a href="https://discord.com/invite/nKWtDcXxtx">Discord</a> •
  <a href="https://pypi.org/project/cisco-ai-skill-scanner/">PyPI</a>
</p>
