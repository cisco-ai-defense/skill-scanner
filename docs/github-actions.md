# GitHub Actions Integration

Skill Scanner provides a **reusable workflow** you can call from any repository to scan Agent Skills on every push or pull request. Results can be uploaded to GitHub Code Scanning for inline annotations.

## Quick Start (Static Analysis Only, No Keys Required)

Add this file to your repository at `.github/workflows/scan-skills.yml`:

```yaml
name: Scan Skills

on:
  push:
    paths: [".cursor/skills/**"]
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

This will:

1. Install `cisco-ai-skill-scanner` from PyPI on a fresh runner
2. Run `skill-scanner scan-all .cursor/skills --format sarif --recursive --check-overlap`
3. Upload SARIF results to GitHub Code Scanning (findings appear as annotations on PRs)
4. Fail the workflow if any findings at or above HIGH severity are detected (configurable via `fail_on_severity`)

## Reusable Workflow Inputs

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `skill_path` | string | *(required)* | Path to skills directory or single skill |
| `scan_mode` | string | `scan-all` | `scan` (single skill) or `scan-all` (directory) |
| `format` | string | `sarif` | Output format: summary, json, markdown, table, sarif, html |
| `policy` | string | `balanced` | Scan policy: strict, balanced, permissive, or path to YAML |
| `fail_on_severity` | string | `high` | Fail if findings at/above this severity |
| `python_version` | string | `3.12` | Python version for the runner |
| `upload_sarif` | boolean | `true` | Upload SARIF to Code Scanning |
| `use_llm` | boolean | `false` | Enable LLM semantic analysis |
| `llm_model` | string | `""` | LLM model name (maps to `SKILL_SCANNER_LLM_MODEL` env var, e.g. `gpt-4o`) |
| `use_behavioral` | boolean | `false` | Enable behavioral dataflow analysis |
| `lenient` | boolean | `false` | Tolerate malformed skills |
| `extra_args` | string | `""` | Additional CLI flags passed verbatim |

## Secrets

All secrets are optional and only needed for advanced analysis features.

| Secret | Maps to env var | Required for |
|--------|----------------|--------------|
| `llm_api_key` | `SKILL_SCANNER_LLM_API_KEY` | `use_llm: true` |
| `virustotal_api_key` | `VIRUSTOTAL_API_KEY` | `--use-virustotal` (via `extra_args`) |

To configure secrets, go to your repository's **Settings > Secrets and variables > Actions** and add them there. They are never exposed in logs.

## Configuration Tiers

### Tier 1: Static Analysis (No Keys)

Zero-config static scanning with YARA rules, behavioral analysis, and SARIF upload:

```yaml
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@main
    with:
      skill_path: .cursor/skills
```

### Tier 2: Static + LLM (One Key)

Add LLM-powered semantic analysis for deeper threat detection:

```yaml
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@main
    with:
      skill_path: .cursor/skills
      use_llm: true
      llm_model: gpt-4o
    secrets:
      llm_api_key: ${{ secrets.SKILL_SCANNER_LLM_API_KEY }}
```

### Tier 3: Full Stack (All Keys)

Enable every analyzer including VirusTotal binary scanning:

```yaml
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@main
    with:
      skill_path: .cursor/skills
      use_llm: true
      use_behavioral: true
      policy: strict
    secrets:
      llm_api_key: ${{ secrets.SKILL_SCANNER_LLM_API_KEY }}
      virustotal_api_key: ${{ secrets.VIRUSTOTAL_API_KEY }}
```

## Branch Protection

To block PRs with security findings:

1. Go to **Settings > Branches > Branch protection rules**
2. Enable **Require status checks to pass before merging**
3. Search for and select the **Skill Scanner** check
4. Save changes

Now any PR that touches skill files must pass the security scan before it can be merged.

## Self-Hosted Workflow (Copy-Paste)

If you prefer not to use the reusable workflow, copy this standalone workflow into your repo:

```yaml
name: Scan Skills

on:
  push:
    paths: [".cursor/skills/**"]
  pull_request:
    paths: [".cursor/skills/**"]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install cisco-ai-skill-scanner

      - name: Scan skills
        run: |
          skill-scanner scan-all .cursor/skills \
            --format sarif \
            --output results.sarif \
            --recursive \
            --check-overlap \
            --fail-on-severity high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```
