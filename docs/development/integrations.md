# CI/CD & Integrations

Cisco Skill Scanner integrates with CI/CD pipelines, pre-commit hooks, and GitHub Code Scanning.

## Built-In Workflows

Repository workflows under [`.github/workflows/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/.github/workflows):

- [python-tests.yml](https://github.com/cisco-ai-defense/skill-scanner/blob/main/.github/workflows/python-tests.yml) -- lint, test matrix, coverage, security checks
- [integration-tests.yml](https://github.com/cisco-ai-defense/skill-scanner/blob/main/.github/workflows/integration-tests.yml) -- external API-backed integration suites
- [release.yml](https://github.com/cisco-ai-defense/skill-scanner/blob/main/.github/workflows/release.yml) -- PyPI publish flow
- [deploy-docs.yml](https://github.com/cisco-ai-defense/skill-scanner/blob/main/.github/workflows/deploy-docs.yml) -- VitePress build and GitHub Pages deployment

## GitHub Actions

### Basic Scan

Add a scan step to your existing workflow:

```yaml
- name: Scan agent skills
  run: |
    pip install cisco-ai-skill-scanner
    skill-scanner scan-all ./skills --fail-on-findings
```

### SARIF Upload to GitHub Code Scanning

Generate SARIF output and upload it to GitHub's security tab:

```yaml
name: Skill Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Skill Scanner
        run: pip install cisco-ai-skill-scanner

      - name: Run scan
        run: |
          skill-scanner scan-all ./skills \
            --recursive \
            --format sarif \
            --output results.sarif \
            --fail-on-findings
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### With LLM Analysis

For deeper semantic analysis, add API keys as repository secrets:

```yaml
- name: Run scan with LLM
  env:
    SKILL_SCANNER_LLM_API_KEY: ${{ secrets.SKILL_SCANNER_LLM_API_KEY }}
    SKILL_SCANNER_LLM_MODEL: claude-3-5-sonnet-20241022
  run: |
    skill-scanner scan-all ./skills \
      --recursive \
      --use-behavioral \
      --use-llm \
      --enable-meta \
      --format sarif \
      --output results.sarif \
      --fail-on-findings
```

## Pre-commit Hook

Skill Scanner provides a pre-commit hook that scans skills before each commit.

### Using pre-commit framework

Add to your [`.pre-commit-config.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/.pre-commit-config.yaml):

```yaml
repos:
  - repo: https://github.com/cisco-ai-defense/skill-scanner
    rev: v0.1.0  # use latest version
    hooks:
      - id: skill-scanner
        args: ["--fail-on-findings"]
```

### Manual hook

```bash
# Copy the hook script
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook entry point is `skill-scanner-pre-commit`, which is installed alongside the main CLI.

## Policy-Aware CI

Keep preset strategy explicit by workflow stage:

- **Pull requests:** `balanced` or `strict` preset for fast feedback
- **Nightly / security sweep:** `strict` + optional semantic analyzers (`--use-llm`, `--use-behavioral`)

## Build Gate

Use `--fail-on-findings` to fail CI builds when critical or high severity findings are detected:

```bash
skill-scanner scan /path/to/skill --fail-on-findings
```

Exit codes:
- **0** — No critical/high findings
- **1** — Critical or high findings detected (build should fail)

## Output Formats

Choose the right format for your integration. See [Output Formats Reference](/reference/output-formats) for sample outputs and a format decision guide.

| Format | Use Case | Flag |
|--------|----------|------|
| `summary` | Terminal output, human review | `--format summary` (default) |
| `json` | Programmatic processing, APIs | `--format json` |
| `sarif` | GitHub Code Scanning, IDE integration | `--format sarif` |
| `markdown` | Pull request comments, reports | `--format markdown` |
| `table` | Terminal dashboards | `--format table` |
| `html` | Interactive reports with correlation groups | `--format html` |

### Saving to File

All formats support output to file:

```bash
skill-scanner scan /path/to/skill --format json --output results.json
skill-scanner scan /path/to/skill --format html --output report.html
```

## Python SDK

For programmatic integration:

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import BehavioralAnalyzer

scanner = SkillScanner(analyzers=[
    BehavioralAnalyzer(),
])

result = scanner.scan_skill("/path/to/skill")

print(f"Findings: {len(result.findings)}")
print(f"Max severity: {result.max_severity}")

if not result.is_safe:
    print("Issues detected — review findings before deployment")
```

## REST API

Skill Scanner also provides a FastAPI-based REST API for service-to-service integration:

```bash
skill-scanner-api --host 0.0.0.0 --port 8000
```

See the [REST API documentation](/user-guide/api-server) for endpoints and usage.

### API-First CI

For service-style scanning, use the `/scan-upload` or `/scan-batch` endpoints from the running API server instead of invoking the CLI:

```yaml
- name: Scan via API
  run: |
    curl -s -X POST http://localhost:8000/scan \
      -H "Content-Type: application/json" \
      -d '{"skill_path": "./skills/my-skill"}' \
      -o result.json
    # Fail if any critical/high findings
    python -c "
    import json, sys
    r = json.load(open('result.json'))
    if r.get('max_severity') in ('CRITICAL', 'HIGH'):
        print('Findings detected'); sys.exit(1)
    "
```

This pattern is useful when the scanner runs as a long-lived service (e.g., in a sidecar container) and you want to avoid cold-start overhead per CI job.
