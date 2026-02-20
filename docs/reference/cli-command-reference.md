<!-- GENERATED FILE. DO NOT EDIT DIRECTLY.
     Regenerate with: uv run python scripts/generate_reference_docs.py -->

# CLI Command Reference

This page is generated from live `argparse` output and should match runtime behavior exactly.

## At a Glance

| Command | Purpose | Example |
|---|---|---|
| `skill-scanner scan` | Scan a single skill package | `skill-scanner scan ./my-skill` |
| `skill-scanner scan-all` | Scan multiple skill packages | `skill-scanner scan-all ./skills/ -r` |
| `skill-scanner list-analyzers` | Show available analyzers | `skill-scanner list-analyzers` |
| `skill-scanner validate-rules` | Validate YARA rule signatures | `skill-scanner validate-rules` |
| `skill-scanner generate-policy` | Generate a policy YAML file | `skill-scanner generate-policy --preset strict` |
| `skill-scanner configure-policy` | Interactive TUI policy editor | `skill-scanner configure-policy` |
| `skill-scanner-api` | Start the REST API server | `skill-scanner-api --port 8080` |
| `skill-scanner-pre-commit` | Git pre-commit hook | `skill-scanner-pre-commit install` |

## Common Flags

Flags shared by `scan` and `scan-all`:

| Flag | Default | Description |
|---|---|---|
| `--format FORMAT` | `summary` | Output format: `summary`, `json`, `markdown`, `table`, `sarif`, `html` |
| `--output FILE` | stdout | Write output to a file instead of stdout |
| `--policy POLICY` | `balanced` | Policy preset name or path to a custom YAML |
| `--use-llm` | off | Enable the LLM semantic analyzer |
| `--use-behavioral` | off | Enable the behavioral analyzer |
| `--use-virustotal` | off | Enable VirusTotal hash lookups |
| `--use-aidefense` | off | Enable Cisco AI Defense analyzer |
| `--enable-meta` | off | Enable the meta (cross-correlation) analyzer |
| `--fail-on-findings` | off | Exit non-zero if any findings are reported (CI gate) |
| `--detailed` | off | Include full evidence in output |
| `--compact` | off | Minimize output (JSON: no pretty-print) |
| `--verbose` | off | Verbose logging |

## Top-level CLI

Command: `python -m skill_scanner.cli.cli --help`

<details>
<summary>Full <code>top-level cli</code> help output</summary>

```text
usage: cli.py [-h]
              {scan,scan-all,list-analyzers,validate-rules,generate-policy,configure-policy}
              ...

Skill Scanner - Security scanner for agent skills packages

positional arguments:
  {scan,scan-all,list-analyzers,validate-rules,generate-policy,configure-policy}
                        Command to execute
    scan                Scan a single skill package
    scan-all            Scan multiple skill packages
    list-analyzers      List available analyzers
    validate-rules      Validate rule signatures
    generate-policy     Generate a default scan policy YAML
    configure-policy    Interactive TUI to build a custom scan policy

options:
  -h, --help            show this help message and exit

Examples:
  skill-scanner scan /path/to/skill
  skill-scanner scan /path/to/skill --use-behavioral --use-llm
  skill-scanner scan /path/to/skill --use-llm --enable-meta --format json
  skill-scanner scan /path/to/skill --format json --verbose
  skill-scanner scan /path/to/skill --policy strict
  skill-scanner scan-all /path/to/skills --recursive
  skill-scanner generate-policy -o my_policy.yaml
  skill-scanner configure-policy
  skill-scanner list-analyzers
```

</details>

## scan

Command: `python -m skill_scanner.cli.cli scan --help`

<details>
<summary>Full <code>scan</code> help output</summary>

```text
usage: cli.py scan [-h] [--format {summary,json,markdown,table,sarif,html}]
                   [--output OUTPUT] [--detailed] [--compact] [--verbose]
                   [--fail-on-findings] [--use-behavioral] [--use-llm]
                   [--use-virustotal] [--vt-api-key VT_API_KEY]
                   [--vt-upload-files] [--use-aidefense]
                   [--aidefense-api-key AIDEFENSE_API_KEY]
                   [--aidefense-api-url AIDEFENSE_API_URL]
                   [--llm-provider {anthropic,openai}]
                   [--llm-consensus-runs N] [--use-trigger] [--enable-meta]
                   [--policy PRESET_OR_PATH] [--custom-rules PATH]
                   [--taxonomy PATH] [--threat-mapping PATH]
                   skill_directory

positional arguments:
  skill_directory       Path to skill directory

options:
  -h, --help            show this help message and exit
  --format {summary,json,markdown,table,sarif,html}
                        Output format (default: summary). Use 'sarif' for
                        GitHub Code Scanning, 'html' for interactive report.
  --output OUTPUT, -o OUTPUT
                        Output file path
  --detailed            Include detailed findings (Markdown output only)
  --compact             Compact JSON output
  --verbose             Include per-finding policy fingerprints, co-occurrence
                        metadata, and keep meta-analyzer false positives in
                        output
  --fail-on-findings    Exit with error if critical/high findings
  --use-behavioral      Enable behavioral dataflow analysis
  --use-llm             Enable LLM-based semantic analysis (requires API key)
  --use-virustotal      Enable VirusTotal scanning (requires API key)
  --vt-api-key VT_API_KEY
                        VirusTotal API key (or set VIRUSTOTAL_API_KEY)
  --vt-upload-files     Upload unknown files to VirusTotal
  --use-aidefense       Enable AI Defense analyzer (requires API key)
  --aidefense-api-key AIDEFENSE_API_KEY
                        AI Defense API key (or set AI_DEFENSE_API_KEY)
  --aidefense-api-url AIDEFENSE_API_URL
                        AI Defense API URL (optional, defaults to US region)
  --llm-provider {anthropic,openai}
                        LLM provider
  --llm-consensus-runs N
                        Run LLM analysis N times and keep only findings with
                        majority agreement (reduces false positives, increases
                        cost)
  --use-trigger         Enable trigger specificity analysis
  --enable-meta         Enable meta-analysis FP filtering (2+ analyzers)
  --policy PRESET_OR_PATH
                        Scan policy: preset name (strict, balanced,
                        permissive) or path to custom YAML
  --custom-rules PATH   Path to directory containing custom YARA rules (.yara
                        files)
  --taxonomy PATH       Path to custom taxonomy JSON/YAML (overrides
                        SKILL_SCANNER_TAXONOMY_PATH)
  --threat-mapping PATH
                        Path to custom threat mapping JSON (overrides
                        SKILL_SCANNER_THREAT_MAPPING_PATH)
```

</details>

## scan-all

Command: `python -m skill_scanner.cli.cli scan-all --help`

<details>
<summary>Full <code>scan-all</code> help output</summary>

```text
usage: cli.py scan-all [-h] [--recursive] [--check-overlap]
                       [--format {summary,json,markdown,table,sarif,html}]
                       [--output OUTPUT] [--detailed] [--compact] [--verbose]
                       [--fail-on-findings] [--use-behavioral] [--use-llm]
                       [--use-virustotal] [--vt-api-key VT_API_KEY]
                       [--vt-upload-files] [--use-aidefense]
                       [--aidefense-api-key AIDEFENSE_API_KEY]
                       [--aidefense-api-url AIDEFENSE_API_URL]
                       [--llm-provider {anthropic,openai}]
                       [--llm-consensus-runs N] [--use-trigger]
                       [--enable-meta] [--policy PRESET_OR_PATH]
                       [--custom-rules PATH] [--taxonomy PATH]
                       [--threat-mapping PATH]
                       skills_directory

positional arguments:
  skills_directory      Directory containing skills

options:
  -h, --help            show this help message and exit
  --recursive, -r       Recursively search for skills
  --check-overlap       Enable cross-skill description overlap
  --format {summary,json,markdown,table,sarif,html}
                        Output format (default: summary). Use 'sarif' for
                        GitHub Code Scanning, 'html' for interactive report.
  --output OUTPUT, -o OUTPUT
                        Output file path
  --detailed            Include detailed findings (Markdown output only)
  --compact             Compact JSON output
  --verbose             Include per-finding policy fingerprints, co-occurrence
                        metadata, and keep meta-analyzer false positives in
                        output
  --fail-on-findings    Exit with error if critical/high findings
  --use-behavioral      Enable behavioral dataflow analysis
  --use-llm             Enable LLM-based semantic analysis (requires API key)
  --use-virustotal      Enable VirusTotal scanning (requires API key)
  --vt-api-key VT_API_KEY
                        VirusTotal API key (or set VIRUSTOTAL_API_KEY)
  --vt-upload-files     Upload unknown files to VirusTotal
  --use-aidefense       Enable AI Defense analyzer (requires API key)
  --aidefense-api-key AIDEFENSE_API_KEY
                        AI Defense API key (or set AI_DEFENSE_API_KEY)
  --aidefense-api-url AIDEFENSE_API_URL
                        AI Defense API URL (optional, defaults to US region)
  --llm-provider {anthropic,openai}
                        LLM provider
  --llm-consensus-runs N
                        Run LLM analysis N times and keep only findings with
                        majority agreement (reduces false positives, increases
                        cost)
  --use-trigger         Enable trigger specificity analysis
  --enable-meta         Enable meta-analysis FP filtering (2+ analyzers)
  --policy PRESET_OR_PATH
                        Scan policy: preset name (strict, balanced,
                        permissive) or path to custom YAML
  --custom-rules PATH   Path to directory containing custom YARA rules (.yara
                        files)
  --taxonomy PATH       Path to custom taxonomy JSON/YAML (overrides
                        SKILL_SCANNER_TAXONOMY_PATH)
  --threat-mapping PATH
                        Path to custom threat mapping JSON (overrides
                        SKILL_SCANNER_THREAT_MAPPING_PATH)
```

</details>

## validate-rules

Command: `python -m skill_scanner.cli.cli validate-rules --help`

<details>
<summary>Full <code>validate-rules</code> help output</summary>

```text
usage: cli.py validate-rules [-h] [--rules-file RULES_FILE]

options:
  -h, --help            show this help message and exit
  --rules-file RULES_FILE
                        Path to YAML rules file or directory (default: built-
                        in signatures)
```

</details>

## generate-policy

Command: `python -m skill_scanner.cli.cli generate-policy --help`

<details>
<summary>Full <code>generate-policy</code> help output</summary>

```text
usage: cli.py generate-policy [-h] [--output OUTPUT]
                              [--preset {strict,balanced,permissive}]

options:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file path
  --preset {strict,balanced,permissive}
                        Base preset
```

</details>

## configure-policy

Command: `python -m skill_scanner.cli.cli configure-policy --help`

<details>
<summary>Full <code>configure-policy</code> help output</summary>

```text
usage: cli.py configure-policy [-h] [--output OUTPUT] [--input INPUT]

options:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file path
  --input INPUT, -i INPUT
                        Load existing policy YAML for editing
```

</details>

## API server CLI

Command: `python -m skill_scanner.api.api_cli --help`

<details>
<summary>Full <code>api server cli</code> help output</summary>

```text
usage: api_cli.py [-h] [--host HOST] [--port PORT] [--reload]

Skill Scanner API Server

options:
  -h, --help   show this help message and exit
  --host HOST  Host to bind to (default: localhost)
  --port PORT  Port to bind to (default: 8000)
  --reload     Enable auto-reload for development

Examples:
  # Start server on default port
  skill-scanner-api

  # Start on custom port
  skill-scanner-api --port 8080

  # Start with auto-reload for development
  skill-scanner-api --reload

  # Custom host and port
  skill-scanner-api --host localhost --port 9000
```

</details>

## Pre-commit hook CLI

Command: `python -m skill_scanner.hooks.pre_commit --help`

<details>
<summary>Full <code>pre-commit hook cli</code> help output</summary>

```text
usage: pre_commit.py [-h] [--severity {critical,high,medium,low}]
                     [--skills-path SKILLS_PATH] [--all]
                     [install]

Pre-commit hook for scanning agent skills

positional arguments:
  install               Install pre-commit hook

options:
  -h, --help            show this help message and exit
  --severity {critical,high,medium,low}
                        Override severity threshold from config
  --skills-path SKILLS_PATH
                        Override skills path from config
  --all                 Scan all skills, not just staged ones
```

</details>
