# Skill Scanner

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CPython 3.11–3.14](https://img.shields.io/badge/CPython-3.11--3.14-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/cisco-ai-skill-scanner.svg)](https://pypi.org/project/cisco-ai-skill-scanner/)
[![CI](https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml/badge.svg)](https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da?logo=discord&logoColor=white)](https://discord.com/invite/nKWtDcXxtx)
[![Cisco AI Defense](https://img.shields.io/badge/Cisco-AI%20Defense-049fd9?logo=cisco&logoColor=white)](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
[![AI Security Framework](https://img.shields.io/badge/AI%20Security-Framework-orange)](https://learn-cloudsecurity.cisco.com/ai-security-framework)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cisco-ai-defense/skill-scanner)

A best-effort security scanner for AI Agent Skills that detects prompt injection, data exfiltration, and malicious code patterns. It combines **pattern-based detection** (YAML + YARA-X), **AST and dataflow analysis**, an optional **LLM-as-a-judge**, and a bounded **CEL decision layer** over typed detector facts.

> **Important:** This scanner provides best-effort detection, not comprehensive or complete coverage. A scan that returns no findings does not guarantee that a skill is free of all threats. See [Scope and Limitations](#scope-and-limitations) below.

Supports [OpenAI Codex Skills](https://openai.github.io/codex/) and [Cursor Agent Skills](https://docs.cursor.com/context/rules) formats following the [Agent Skills specification](https://agentskills.io). With `--lenient`, also scans non-standard formats such as Claude Code `.claude/commands/*.md` and flat markdown skill repos.

---

## Highlights

- **Multi-Engine Detection** - Static analysis, behavioral dataflow, LLM semantic analysis, and cloud-based scanning for layered, best-effort coverage
- **Typed CEL Decisions** - The core scanner uses the official `cel-go` v0.32.0 runtime to correlate bounded facts after deterministic detection and before optional LLM analysis
- **Measured Presets** - `low-noise` and `quiet` presets and LLM caps, with recall, false-positive rate and F1 published for each ([Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings))
- **CI/CD Ready** - SARIF output for GitHub Code Scanning, [reusable GitHub Actions workflow](docs/github-actions.md), exit codes for build failures
- **Pre-commit Hook** - [Standard pre-commit framework](https://pre-commit.com/) integration to scan skills before every commit
- **Extensible** - Plugin architecture for custom analyzers

**[Join the Cisco AI Discord](https://discord.com/invite/nKWtDcXxtx)** to discuss, share feedback, or connect with the team.

---

## Scope and Limitations

Skill Scanner is a detection tool. It identifies known and probable risk patterns, but it does not certify security.

**Key limitations:**

- **No findings ≠ no risk.** A scan that returns "No findings" indicates that no known threat patterns were detected. It does not guarantee that a skill is secure, benign, or free of vulnerabilities.
- **Coverage is inherently incomplete.** The scanner combines signature-based detection, LLM-based semantic analysis, behavioral dataflow analysis, optional cloud services, and configurable rule packs. While this approach improves coverage, no automated tool can detect every technique, especially novel or zero-day attacks.
- **False positives and false negatives can occur.** Presets, the LLM judge and scoped suppressions reduce noise, but no configuration eliminates all incorrect classifications. Pick a measured setup from [Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings) and tune the [scan policy](docs/user-guide/custom-policy-configuration.md) to your risk tolerance.
- **Human review remains essential.** Automated scanning is one component of a defense-in-depth strategy. High-risk or production deployments should pair scanner results with manual code review and/or  threat modeling.

### Measured results

On held-out skills (MaliciousSkillBench's frozen test split, 839 malicious and 545 harmless):

- **Rules alone** catch 7.7% of malicious skills at HIGH, at a 4.0% false-positive rate.
- **With the LLM judge** (Gemma 4 26B, `balanced`), 66.7% reach review at MEDIUM+ (15.4% FPR), and
  33.7% are blocked at HIGH (6.4% FPR).

Every figure, with its corpus and method, is in [Measured Results](docs/reference/measured-results.md)
and on the [evaluation Space](https://huggingface.co/spaces/Vineethsain/skill-scanner-vs-skillspector).

---

## Documentation

The documentation website is **[cisco-ai-defense.github.io/docs/skill-scanner](https://cisco-ai-defense.github.io/docs/skill-scanner)**.
Deep-dive pages live in [`docs/`](docs/README.md).

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/getting-started/quick-start.md) | Get started in 5 minutes |
| [Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings) | Pick a setup for the lowest FPR or the highest F1, with copy-paste configs |
| [LLM Providers](https://cisco-ai-defense.github.io/docs/skill-scanner/llm-providers) | Configure the LLM judge for any provider, gateway or local model |
| [Results and Tuning](https://cisco-ai-defense.github.io/docs/skill-scanner/results-and-tuning) | Read findings, build a review queue, lower false positives |
| [Architecture](docs/architecture/index.md) | System design and components |
| [CEL Decision Layer](docs/architecture/cel-decision-layer.md) | Typed facts, safety bounds, rollout modes, and telemetry |
| [Threat Taxonomy](docs/architecture/threat-taxonomy.md) | Complete AITech threat taxonomy with examples |
| [LLM Analyzer](docs/architecture/analyzers/llm-analyzer.md) | LLM configuration and usage |
| [System One Analyzer](docs/architecture/analyzers/system-one-analyzer.md) | Optional advisory screening tier, and why it cannot gate |
| [Meta-Analyzer](docs/architecture/analyzers/meta-analyzer.md) | Optional second-pass review (off by default; measured cost) |
| [Behavioral Analyzer](docs/architecture/analyzers/behavioral-analyzer.md) | Dataflow analysis details |
| [Scan Policy](docs/user-guide/custom-policy-configuration.md) | Custom policies, presets, and tuning guide |
| [Policy Quick Reference](docs/reference/policy-quick-reference.md) | Compact reference for policy sections and knobs |
| [Measured Results](docs/reference/measured-results.md) | Every published figure, with its corpus, population and model |
| [Rule Authoring](docs/architecture/analyzers/writing-custom-rules.md) | How to add signature, YARA, and Python rules |
| [GitHub Actions](docs/github-actions.md) | Reusable workflow for CI/CD integration |
| [API Reference](docs/user-guide/api-server.md) | REST API documentation |
| [Development Guide](docs/development/setup-and-testing.md) | Contributing and development setup |

---

## Installation

**Prerequisites:** CPython 3.11–3.14 and [uv](https://docs.astral.sh/uv/) (recommended) or pip.

Wheels include the CEL helper for glibc Linux x86-64/ARM64, macOS 14+ x86-64/ARM64 and Windows
x86-64. Other platforms build from the source distribution, which needs Go 1.27.1+. See
[Installation and Configuration](docs/user-guide/installation-and-configuration.md) for details.

```bash
# Using uv (recommended)
uv pip install cisco-ai-skill-scanner

# As a standalone tool
uv tool install cisco-ai-skill-scanner   # or: pipx install cisco-ai-skill-scanner

# Using pip
pip install cisco-ai-skill-scanner
```

The presets and settings in [Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings)
need 2.2.0 or newer (`skill-scanner --version`).

<details>
<summary><strong>Cloud Provider Extras</strong></summary>

```bash
# AWS Bedrock support (IAM credentials, no API key)
pip install cisco-ai-skill-scanner[bedrock]

# Google AI Studio / Gemini support
pip install cisco-ai-skill-scanner[google]

# Google Vertex AI support
pip install cisco-ai-skill-scanner[vertex]

# Azure OpenAI support
pip install cisco-ai-skill-scanner[azure]

# On-device Apple Foundation Model (experimental; macOS 26+, Apple Intelligence)
pip install "apple-fm-sdk>=0.2.1,<0.3"   # builds from source; needs full Xcode

# All cloud providers
pip install cisco-ai-skill-scanner[all]
```

</details>

---

## Quick Start

### Recommended settings

Every recommended setup runs the LLM judge (`--use-llm`): rules alone catch only about 8% of
held-out malicious skills.

| Goal | Command | Held-out recall / FPR / F1 |
|------|---------|----------------------------|
| Highest F1 | `skill-scanner scan ./skill --use-llm --policy balanced --fail-on-severity high`, and review everything at MEDIUM+ | 66.7% / 15.4% / 75.5% |
| Smaller review queue (your own skills) | `skill-scanner scan ./skill --use-llm --policy low-noise --fail-on-severity high` | 63.2% / 13.4% / 73.5% |
| Lowest false-positive rate | `skill-scanner scan ./skill --use-llm --policy quiet --fail-on-severity high` | 50.3% / 7.2% / 64.9% |
| Nothing leaves the machine | any of the above, with the judge on a [local model](https://cisco-ai-defense.github.io/docs/skill-scanner/llm-providers) | as above |

Rates are for the MEDIUM+ review queue on MaliciousSkillBench's held-out split, with Gemma 4 26B as
the judge. Measured precision for each, and the same setups for pre-commit, GitHub Actions, Python and
the REST API, are in [Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings).

### Environment Setup

```bash
# The LLM judge, used by every recommended setup (local models: see LLM Providers)
export SKILL_SCANNER_LLM_API_KEY="your_api_key"
export SKILL_SCANNER_LLM_MODEL="claude-sonnet-5-5"   # the default

# On-device Apple Foundation Model (experimental, no API key). Behavioral
# alignment verification is skipped with a warning on this model.
# export SKILL_SCANNER_LLM_MODEL="apple-fm/system"
# Optional: disabled, minimal, low, medium, high, xhigh, or max
export SKILL_SCANNER_LLM_REASONING_EFFORT="low"

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
# First test: core analyzers only (static + bytecode + pipeline + correlation)
skill-scanner scan /path/to/skill

# Real use: add the LLM judge
skill-scanner scan /path/to/skill --use-llm --policy balanced --fail-on-severity high

# Scan with behavioral analyzer (dataflow analysis)
skill-scanner scan /path/to/skill --use-behavioral

# Scan with all engines
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-aidefense

# Rules + LLM judge, with the preset that has the fewest false positives
skill-scanner scan /path/to/skill --use-llm --policy quiet

# Decomposed judge: three focused passes, about three times the tokens
skill-scanner scan /path/to/skill --use-llm --llm-decompose

# Scan with trigger analyzer for vague description checks
skill-scanner scan /path/to/skill --use-trigger

# Run LLM analyzer multiple times and keep majority-agreed findings
skill-scanner scan /path/to/skill --use-llm --llm-consensus-runs 3

# Scan multiple skills recursively
skill-scanner scan-all /path/to/skills --recursive --use-behavioral

# Scan multiple skills with cross-skill overlap detection
skill-scanner scan-all /path/to/skills --recursive --check-overlap

# Scan a GitHub repository (owner/repo shorthand or full URL)
skill-scanner scan-repo owner/repo
skill-scanner scan-repo https://github.com/owner/repo --use-llm

# Lenient mode: tolerate malformed skills instead of failing
skill-scanner scan /path/to/skill --lenient
skill-scanner scan-all /path/to/skills --recursive --lenient

# Lenient mode with non-standard skill formats (no SKILL.md required)
skill-scanner scan .claude/commands/deploy --lenient
skill-scanner scan-all .claude/commands --recursive --lenient

# Use a custom metadata filename instead of SKILL.md
skill-scanner scan /path/to/skill --skill-file README.md

# CI/CD: rules + judge, fail the build on HIGH
skill-scanner scan-all ./skills --recursive --use-llm --policy low-noise --fail-on-severity high --format sarif --output results.sarif

# Generate interactive HTML report with attack correlation groups
skill-scanner scan /path/to/skill --use-llm --format html --output report.html

# Use custom YARA rules
skill-scanner scan /path/to/skill --custom-rules /path/to/my-rules/

# Use custom taxonomy + threat mapping profiles (JSON/YAML)
skill-scanner scan /path/to/skill --taxonomy /path/to/taxonomy.json --threat-mapping /path/to/threat_mapping.json

# VirusTotal hash scan with optional unknown-file uploads
skill-scanner scan /path/to/skill --use-virustotal --vt-upload-files

# Use a scan policy preset (balanced, low-noise, quiet, strict, permissive) with the judge
skill-scanner scan /path/to/skill --use-llm --policy low-noise

# Inspect CEL decisions without suppressing findings
skill-scanner scan /path/to/skill --cel-mode shadow --format json

# Use a custom org policy file
skill-scanner scan /path/to/skill --policy my_org_policy.yaml

# Generate a policy file to customise, starting from a preset
skill-scanner generate-policy --preset low-noise -o my_org_policy.yaml

# Interactive policy configurator (TUI)
skill-scanner configure-policy
```

Consensus mode keeps a finding only when it appears in more than half of the
configured runs. When those votes disagree on severity, the highest observed
severity wins, independent of response order. Failed runs and successful runs
that omit the finding cast no vote but remain in the denominator. This makes
severity selection stable for majority-agreed findings. It does not make an
individual LLM sample deterministic, and descriptive fields from equal-severity
votes, single-run output, and non-majority findings can still vary between scans.

**LLM provider note:** `--llm-provider` accepts `anthropic`, `openai` or `openai-compatible`.
For Bedrock, Vertex AI, Azure, Gemini, Ollama, gateways and local servers, set provider-specific model
strings and environment variables (see [LLM Providers](https://cisco-ai-defense.github.io/docs/skill-scanner/llm-providers)).
If `--use-llm` is set and the judge cannot start, the scan stops with an error rather than passing with rules only.

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
| **Correlation** | Bounded structured source/sink correlation | Python, JavaScript, TypeScript, and package facts | None |
| **Behavioral** | AST dataflow analysis | Python files | None |
| **LLM** | Semantic analysis | SKILL.md + scripts | API key |
| **Meta** | Second-pass review (off by default) | All findings | API key |
| **VirusTotal** | Hash-based malware | Binary files | API key |
| **AI Defense** | Cloud-based AI | Text content | API key |

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--policy` | Scan policy: preset name (`strict`, `balanced`, `permissive`, `low-noise`, `quiet`) or path to custom YAML |
| `--use-behavioral` | Enable behavioral analyzer (dataflow analysis) |
| `--use-llm` | Enable LLM analyzer (requires API key) |
| `--llm-provider` | LLM provider for CLI routing: `anthropic`, `openai` or `openai-compatible` |
| `--llm-decompose` | Run the judge once per focus and union the findings (about three times the model calls) |
| `--adjudicate` | Demote-only LLM review of deterministic HIGH/CRITICAL literal-regex false positives |
| `--use-osv` | Query OSV.dev for known-vulnerable pinned dependencies (network, no key) |
| `--rule-packs PACK...` | Enable optional signature packs (e.g. `atr`, `promptguard`); `--rule-packs list` shows them |
| `--system-one-endpoint URL` | Optional advisory System One screen; never changes a finding (needs `--system-one-model`) |
| `--llm-consensus-runs N` | Run LLM analysis `N` times, keep majority-agreed findings, and retain their highest observed severity |
| `--llm-max-tokens N` | Maximum output tokens for LLM responses (default: 8192) |
| `--llm-reasoning-effort LEVEL` | Optional reasoning depth (`disabled`, `minimal`, `low`, `medium`, `high`, `xhigh`, or `max`); unset preserves the provider default |
| `--use-virustotal` | Enable VirusTotal binary scanner |
| `--vt-api-key KEY` | Provide VirusTotal API key directly (optional) |
| `--vt-upload-files` | Upload unknown binaries to VirusTotal (optional) |
| `--use-aidefense` | Enable Cisco AI Defense analyzer |
| `--aidefense-api-url URL` | Override AI Defense API URL (optional) |
| `--use-trigger` | Enable trigger specificity analyzer |
| `--enable-meta` | Enable the meta-analyzer. Off by default and not recommended: it cost 16.4 points of recall in measurement |
| `--verbose` | Include per-finding policy fingerprints, co-occurrence metadata, and keep meta-analyzer false positives |
| `--format` | Output: `summary`, `json`, `markdown`, `table`, `sarif`, `html`. The `html` format produces a self-contained interactive report with collapsible correlation groups, expandable code snippets, and pipeline taint flow diagrams |
| `--detailed` | Include detailed findings in Markdown output |
| `--compact` | Compact JSON output |
| `--output PATH` | Default output file path (overridden by `--output-<fmt>`) |
| `--fail-on-findings` | Exit with error if HIGH/CRITICAL found (shorthand for `--fail-on-severity high`) |
| `--fail-on-severity LEVEL` | Exit with error if findings at or above LEVEL exist (critical, high, medium, low, info) |
| `--custom-rules PATH` | Use custom YARA rules from directory |
| `--trusted-rule-pack PATH` | Load an administrator-trusted schema-v2 signature/YARA/CEL pack (repeatable) |
| `--cel-mode MODE` | Set the CEL decision layer to `off`, `shadow`, or `enforce` |
| `--taxonomy PATH` | Load custom taxonomy profile (JSON/YAML) for this run |
| `--threat-mapping PATH` | Load custom scanner threat mapping profile (JSON) for this run |
| `--lenient` | Tolerate malformed skills (coerce bad fields, fill defaults) instead of failing. When `SKILL.md` is absent, falls back to scanning `.md` files in the directory |
| `--skill-file FILENAME` | Custom metadata filename to use instead of `SKILL.md` (e.g. `README.md`) |
| `--check-overlap` | (`scan-all`) Enable cross-skill description overlap checks |

| Command | Description |
|---------|-------------|
| *(no command)* | Launch interactive scan wizard (when run in a terminal) |
| `interactive` | Launch interactive scan wizard (explicit) |
| `scan` | Scan a single skill directory |
| `scan-all` | Scan multiple skills (with `--recursive`, `--check-overlap`) |
| `scan-repo` | Clone a GitHub repository (`owner/repo` or URL) and scan its skills |
| `generate-policy` | Generate a scan policy YAML for customisation |
| `configure-policy` | Interactive TUI to build/edit a custom scan policy (`--input` supported) |
| `list-analyzers` | Show available analyzers |
| `validate-rules` | Validate bundled rules plus optional `--rules-file` signatures and repeatable `--trusted-rule-pack` v2 packs |

The `balanced` (default), `low-noise`, `quiet` and `strict` presets use CEL `shadow`; `permissive`
uses CEL `off`. Every bundled CEL rule currently has `rollout: shadow`, so even a
global `--cel-mode enforce` retains findings until an individual rule is
qualified and promoted. The ATR pack remains opt-in through
`--rule-packs atr` and is not part of the current core + CEL release gate.

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
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@2.2.0
    with:
      scanner_version: "2.2.0"
      skill_path: .cursor/skills
      policy: low-noise
      use_llm: true
      llm_model: anthropic/claude-sonnet-5-5
    secrets:
      llm_api_key: ${{ secrets.SKILL_SCANNER_LLM_API_KEY }}
    permissions:
      security-events: write
      contents: read
      actions: read
```

Results appear as inline annotations in PRs via GitHub Code Scanning. See the [full guide](docs/github-actions.md) for LLM integration, secret configuration, and branch protection setup.

---

## Pre-commit Hook

Scan skills, with the judge, before every commit using the [pre-commit](https://pre-commit.com/) framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skill-scanner
        name: Scan agent skills (rules + LLM judge)
        entry: skill-scanner scan-all .claude/skills --recursive --use-llm --policy low-noise --fail-on-severity high
        language: system
        pass_filenames: false
        files: ^\.claude/skills/
```

The hook uses the `skill-scanner` installed in your environment and the `SKILL_SCANNER_LLM_*`
variables from your shell. Run `pre-commit install` once.

The packaged hook (`id: skill-scanner` from this repository, or `skill-scanner-pre-commit --install`)
maps changed files to their nearest `SKILL.md` and scans only those skills, but with the rules alone.
Don't rely on it by itself: pair it with a judged scan in CI. Its options are documented in
[Integrations](docs/development/integrations.md).

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
