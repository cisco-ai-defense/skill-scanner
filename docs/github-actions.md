# GitHub Actions Integration

Skill Scanner provides a **reusable workflow** you can call from any repository to scan Agent Skills on every push or pull request. Results can be uploaded to GitHub Code Scanning for inline annotations.

## Quick Start

Every recommended setup runs the LLM judge (`use_llm: true`); the rules alone catch only about 8% of
held-out malicious skills. Add your model provider's key as the repository secret
`SKILL_SCANNER_LLM_API_KEY`, then add this file at `.github/workflows/scan-skills.yml`:

```yaml
name: Scan Skills

on:
  push:
    paths: [".cursor/skills/**"]
  pull_request:
    paths: [".cursor/skills/**"]

jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@2.2.2
    with:
      scanner_version: "2.2.2"
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

For Bedrock, Vertex AI or a self-hosted model, run the CLI in your own job instead (see
[GitHub Actions and Pre-commit](https://cisco-ai-defense.github.io/docs/skill-scanner/github-actions)).

This will:

1. Install `cisco-ai-skill-scanner` from PyPI on a fresh runner
2. Run `skill-scanner scan-all .cursor/skills --format sarif --recursive --check-overlap`
3. Upload SARIF results to GitHub Code Scanning (findings appear as annotations on PRs)
4. Fail the workflow if any findings at or above HIGH severity are detected (configurable via `fail_on_severity`)

Pin the workflow to a release tag (`@2.2.2`), and grant the caller job `security-events: write`,
`contents: read` and `actions: read`: a reusable workflow can only use the permissions its caller
grants. For which preset and threshold to use, see
[Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings).

## Reusable Workflow Inputs

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `scanner_version` | string | `""` (latest) | skill-scanner release to install, for example `2.2.0`. Pin it to the same release as the workflow ref so presets and flags match the docs |
| `skill_path` | string | *(required)* | Path to skills directory or single skill |
| `scan_mode` | string | `scan-all` | `scan` (single skill) or `scan-all` (directory) |
| `format` | string | `sarif` | Output format: summary, json, markdown, table, sarif, html |
| `policy` | string | `balanced` | Scan policy: strict, balanced, permissive, low-noise, quiet, or path to YAML. See [Recommended settings](user-guide/recommended-settings.md) |
| `fail_on_severity` | string | `high` | Fail if findings at/above this severity |
| `python_version` | string | `3.12` | Numeric CPython version from 3.11 through 3.14 |
| `upload_sarif` | boolean | `true` | Upload SARIF to Code Scanning |
| `use_llm` | boolean | `false` | Enable the LLM judge (recommended) |
| `llm_model` | string | `""` | LLM model name (maps to `SKILL_SCANNER_LLM_MODEL`, e.g. `claude-sonnet-5-5`). A `bedrock/` model installs the `[bedrock]` extra |
| `llm_provider` | string | `""` | LLM provider (maps to `SKILL_SCANNER_LLM_PROVIDER`, e.g. `openai-compatible` for a gateway) |
| `llm_base_url` | string | `""` | LLM endpoint base URL (maps to `SKILL_SCANNER_LLM_BASE_URL`) |
| `aws_region` | string | `us-east-1` | Region for `bedrock/` models (maps to `AWS_REGION`); pass a Bedrock API key as `llm_api_key` |
| `use_behavioral` | boolean | `false` | Enable behavioral dataflow analysis |
| `lenient` | boolean | `false` | Tolerate malformed skills |
| `extra_args` | string | `""` | Additional CLI flags from the workflow allowlist, including `--llm-decompose`, `--use-osv` and `--adjudicate` |

The job fails with "could not run as configured" when the scanner exits 2 (an unknown policy, or an
LLM judge that could not be built, for example a missing key), and with "found findings" when
findings reach `fail_on_severity`.

## Secrets

All secrets are optional and only needed for advanced analysis features.

| Secret | Maps to env var | Required for |
|--------|----------------|--------------|
| `llm_api_key` | `SKILL_SCANNER_LLM_API_KEY` | `use_llm: true` |
| `virustotal_api_key` | `VIRUSTOTAL_API_KEY` | `--use-virustotal` (via validated `extra_args`) |

`extra_args` is intentionally allowlisted because this reusable workflow can run
with API secrets in the environment. Supported extra flags are additive scanner
options such as `--use-virustotal`, `--vt-upload-files`, `--use-aidefense`,
`--use-trigger`, `--use-osv`, `--llm-decompose`, `--adjudicate`, `--enable-meta`,
selected LLM tuning flags, custom local rule paths, taxonomy paths, and
`--rule-packs`. Add new entries only after confirming
they cannot expose secrets or execute caller-controlled code.

To configure secrets, go to your repository's **Settings > Secrets and variables > Actions** and add them there. They are never exposed in logs.

## Configuration Tiers

### Tier 1: Rules + LLM Judge (One Key)

The recommended starting point. Use `policy: low-noise` for your own skills, `balanced` for the highest F1 on third-party skills, or `quiet` for the lowest false-positive rate:

```yaml
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@2.2.2
    with:
      scanner_version: "2.2.2"
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

### Tier 2: Full Stack (All Keys)

Enable every analyzer including VirusTotal binary scanning:

```yaml
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@2.2.2
    with:
      scanner_version: "2.2.2"
      skill_path: .cursor/skills
      use_llm: true
      use_behavioral: true
      extra_args: --use-virustotal --use-osv
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
