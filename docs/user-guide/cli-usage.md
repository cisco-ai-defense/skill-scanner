# CLI Usage

This guide explains practical CLI usage patterns for local scans, CI gates, and policy-driven operation.

::: tip Most Common Command
```bash
skill-scanner scan ./my-skill
```
Runs the default static analyzers and prints a findings summary. Add `--use-behavioral`, `--use-llm`, or `--policy strict` to deepen the analysis.
:::

## Core Commands

- `skill-scanner scan <skill_directory>`
- `skill-scanner scan-all <skills_directory>`
- `skill-scanner list-analyzers`
- `skill-scanner validate-rules`
- `skill-scanner generate-policy`
- `skill-scanner configure-policy`

## Common Workflows

### Local smoke scan

```bash
skill-scanner scan ./my-skill
```

### Recursive CI scan with failure gate

```bash
skill-scanner scan-all ./skills --recursive --fail-on-findings
```

### Deep analysis profile

```bash
skill-scanner scan ./my-skill \
  --use-behavioral \
  --use-llm \
  --enable-meta
```

### Security reporting (SARIF)

```bash
skill-scanner scan-all ./skills \
  --recursive \
  --format sarif \
  --output results.sarif \
  --fail-on-findings
```

### Policy-based enforcement

```bash
skill-scanner scan ./my-skill --policy strict
skill-scanner scan ./my-skill --policy ./my-org-policy.yaml
```

## Choosing Analyzers

Not sure which flags to use? Pick the row that matches your situation:

| Scenario | Suggested flags |
|---|---|
| Fast local iteration | default analyzers |
| Suspicious third-party skill | `--use-behavioral --policy strict` |
| High-confidence triage | `--use-llm --enable-meta` |
| Binary-heavy package | `--use-virustotal` |

## Exit Code Behavior

- `0`: successful command (or no fail condition triggered)
- `1`: runtime error, or findings detected when `--fail-on-findings` is enabled

When `--fail-on-findings` is active:

- **`scan`**: exits `1` if `result.is_safe` is false (any CRITICAL or HIGH finding)
- **`scan-all`**: exits `1` if `critical_count > 0` or `high_count > 0` across all scanned skills

## Detailed Reference

For exhaustive argument tables and full `--help` snapshots, see:

- [CLI Command Reference](/reference/cli-command-reference)

## See Also

- [Configuration Reference](/reference/configuration-reference) — environment variables for LLM providers, analyzers, and feature toggles
- [Python SDK](/user-guide/python-sdk) — embed scanning directly in Python applications
- [API Server](/user-guide/api-server) — REST API for upload-driven and CI/CD workflows
