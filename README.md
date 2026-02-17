# Skill Scanner

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/cisco-ai-skill-scanner.svg)](https://pypi.org/project/cisco-ai-skill-scanner/)
[![CI](https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml/badge.svg)](https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da?logo=discord&logoColor=white)](https://discord.com/invite/nKWtDcXxtx)
[![Cisco AI Defense](https://img.shields.io/badge/Cisco-AI%20Defense-049fd9?logo=cisco&logoColor=white)](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
[![AI Security Framework](https://img.shields.io/badge/AI%20Security-Framework-orange)](https://learn-cloudsecurity.cisco.com/ai-security-framework)

A security scanner for AI Agent Skills that detects prompt injection, data exfiltration, and malicious code patterns. Combines **pattern-based detection** (YAML + YARA), **LLM-as-a-judge**, and **behavioral dataflow analysis** for comprehensive threat detection.

Supports [OpenAI Codex Skills](https://openai.github.io/codex/) and [Cursor Agent Skills](https://docs.cursor.com/context/rules) formats following the [Agent Skills specification](https://agentskills.io).

---

## Highlights

- **Multi-Engine Detection** - Static analysis, behavioral dataflow, LLM semantic analysis, and cloud-based scanning
- **False Positive Filtering** - Meta-analyzer significantly reduces noise while preserving detection capability
- **CI/CD Ready** - SARIF output for GitHub Code Scanning, exit codes for build failures
- **Extensible** - Plugin architecture for custom analyzers

**[Join the Cisco AI Discord](https://discord.com/invite/nKWtDcXxtx)** to discuss, share feedback, or connect with the team.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/quickstart.md) | Get started in 5 minutes |
| [Architecture](docs/architecture.md) | System design and components |
| [Threat Taxonomy](docs/threat-taxonomy.md) | Complete AITech threat taxonomy with examples |
| [LLM Analyzer](docs/llm-analyzer.md) | LLM configuration and usage |
| [Meta-Analyzer](docs/meta-analyzer.md) | False positive filtering and prioritization |
| [Behavioral Analyzer](docs/behavioral-analyzer.md) | Dataflow analysis details |
| [API Reference](docs/api-server.md) | REST API documentation |
| [Development Guide](docs/developing.md) | Contributing and development setup |

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

### CLI Usage

```bash
# Scan a single skill (static analyzer only)
skill-scanner scan /path/to/skill

# Scan with behavioral analyzer (dataflow analysis)
skill-scanner scan /path/to/skill --use-behavioral

# Scan with all engines
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-aidefense

# Scan with meta-analyzer for false positive filtering
skill-scanner scan /path/to/skill --use-llm --enable-meta

# Scan multiple skills recursively
skill-scanner scan-all /path/to/skills --recursive --use-behavioral

# CI/CD: Fail build if threats found
skill-scanner scan-all ./skills --fail-on-findings --format sarif --output results.sarif

# Use custom YARA rules
skill-scanner scan /path/to/skill --custom-rules /path/to/my-rules/

# Disable specific noisy rules
skill-scanner scan /path/to/skill --disable-rule YARA_script_injection --disable-rule MANIFEST_MISSING_LICENSE

# Strict mode (more findings, higher FP rate)
skill-scanner scan /path/to/skill --yara-mode strict

# Permissive mode (fewer findings, may miss some threats)
skill-scanner scan /path/to/skill --yara-mode permissive
```

### Python SDK

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import StaticAnalyzer, BehavioralAnalyzer

# Create scanner with analyzers
scanner = SkillScanner(analyzers=[
    StaticAnalyzer(),
    BehavioralAnalyzer(use_static_analysis=True),
])

# Scan a skill
result = scanner.scan_skill("/path/to/skill")

print(f"Safe: {result.is_safe}")
print(f"Findings: {len(result.findings)}")
```

---

## Security Analyzers

| Analyzer | Detection Method | Scope | Requirements |
|----------|------------------|-------|--------------|
| **Static** | YAML + YARA patterns | All files | None |
| **Behavioral** | AST dataflow analysis | Python files | None |
| **LLM** | Semantic analysis | SKILL.md + scripts | API key |
| **Meta** | False positive filtering | All findings | API key |
| **VirusTotal** | Hash-based malware | Binary files | API key |
| **AI Defense** | Cloud-based AI | Text content | API key |

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--use-behavioral` | Enable behavioral analyzer (dataflow analysis) |
| `--use-llm` | Enable LLM analyzer (requires API key) |
| `--use-virustotal` | Enable VirusTotal binary scanner |
| `--use-aidefense` | Enable Cisco AI Defense analyzer |
| `--enable-meta` | Enable meta-analyzer for false positive filtering |
| `--format` | Output: `summary`, `json`, `markdown`, `table`, `sarif` |
| `--output PATH` | Save report to file |
| `--fail-on-findings` | Exit with error if HIGH/CRITICAL found |
| `--yara-mode` | Detection mode: `strict`, `balanced` (default), `permissive` |
| `--custom-rules PATH` | Use custom YARA rules from directory |
| `--disable-rule RULE` | Disable specific rule (can repeat) |

---

## Example Output

```
$ skill-scanner scan ./my-skill --use-behavioral

============================================================
Skill: my-skill
============================================================
Status: [OK] SAFE
Max Severity: SAFE
Total Findings: 0
Scan Duration: 0.15s
```

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
