# Skill Scanner Feature Reference

This document is a current-state feature map for the repository as implemented today.

## Core Purpose

Skill Scanner analyzes local AI agent skill packages to detect security risks such as prompt injection, code/command injection, data exfiltration, obfuscation, hidden binaries, and policy violations.

## Feature Matrix

| Area | Feature | Status | Notes |
|---|---|---|---|
| Detection Engines | Static analyzer (YAML signatures + YARA) | Available | Core analyzer |
| Detection Engines | Bytecode analyzer (`.pyc` integrity and source mismatch checks) | Available | Core analyzer |
| Detection Engines | Pipeline analyzer (shell pipeline taint and command-risk checks) | Available | Core analyzer |
| Detection Engines | Behavioral analyzer (static dataflow/correlation) | Available | Optional (`--use-behavioral`) |
| Detection Engines | LLM analyzer (semantic analysis with structured output) | Available | Optional (`--use-llm`) |
| Detection Engines | Meta-analyzer (second-pass filtering/prioritization) | Available | Optional (`--enable-meta`) |
| Detection Engines | VirusTotal analyzer | Available | Optional (`--use-virustotal`) |
| Detection Engines | Cisco AI Defense analyzer | Available | Optional (`--use-aidefense`) |
| Detection Engines | Trigger analyzer (description specificity) | Available | Optional (`--use-trigger`) |
| Multi-skill | Cross-skill overlap and attack-pattern checks | Available | `scan-all --check-overlap` |
| Policy | Presets (`strict`, `balanced`, `permissive`) | Available | `--policy` |
| Policy | Custom policy YAML | Available | `generate-policy`, `configure-policy` |
| Policy | Rule scoping, severity overrides, disabled rules | Available | Policy-driven |
| Output | Summary, JSON, Markdown, Table, SARIF | Available | `--format` |
| Output | Policy fingerprint + finding normalization controls | Available | `finding_output` policy section |
| API | FastAPI server endpoints for scan/upload/batch | Available | `skill-scanner-api` |
| Integrations | Pre-commit hook scanner | Available | `skill-scanner-pre-commit` |
| Evaluation | Eval runner + benchmark tooling | Available | `evals/runners/` |

## Scanner Architecture Features

### Analyzer Factory (centralized construction)

- `skill_scanner/core/analyzer_factory.py` is the single source of truth for analyzer composition.
- Core analyzers are built from policy toggles (`policy.analyzers.static|bytecode|pipeline`).
- Optional analyzers are appended from CLI/API/pre-commit/eval flags.

### Two-Phase Scan Execution

In `skill_scanner/core/scanner.py`, scans execute in two phases:

1. Non-LLM analyzers run first (static/bytecode/pipeline/behavioral/etc.).
2. LLM/meta analyzers run after enrichment context is assembled from phase-1 output.

Post-processing includes:

- policy-level disabled-rule enforcement
- severity overrides
- analyzability findings
- output dedupe/collapse
- same-path co-occurrence metadata
- policy fingerprint metadata

### Archive/embedded content handling

- `ContentExtractor` expands archives and selected embedded content safely.
- Temporary extraction artifacts are always cleaned up.

## Detection Features by Engine

### 1. Static Analyzer

- Signature-based detection (`skill_scanner/data/packs/core/signatures/*.yaml`)
- YARA-based detection (`skill_scanner/data/packs/core/yara/*.yara`)
- Manifest/body/script/reference/asset scanning passes
- Hidden file checks, homoglyph checks, binary/doc checks, and policy-aware filtering

### 2. Bytecode Analyzer

- Detects `.pyc` without expected source and source/bytecode mismatch scenarios
- Performs Python bytecode integrity checks

### 3. Pipeline Analyzer

- Parses shell command pipelines and classifies risk
- Detects fetch-and-execute and sensitive source-to-sink chains
- Uses `command_safety`, `pipeline`, and `sensitive_files` policy knobs

### 4. Behavioral Analyzer

- Static AST/dataflow analysis for Python files
- Bash taint tracking support
- Cross-file correlation support
- Optional alignment verification path (`use_alignment_verification=True`)

### 5. LLM Analyzer

- Structured-output semantic analysis
- Multi-provider model support (via model/env configuration)
- Optional consensus mode (`--llm-consensus-runs`)
- Prompt protection logic and retry handling

### 6. Meta Analyzer

- Reviews findings from prior analyzers
- Filters likely false positives and can add synthesized findings
- Runs only when enabled and when base findings exist

### 7. VirusTotal Analyzer

- Hash lookup for binaries
- Optional upload of unknown files (`--vt-upload-files`)

### 8. AI Defense Analyzer

- Cisco cloud inspection for prompt/content/code risks
- Configurable rules payload and API URL

### 9. Trigger Analyzer

- Flags overly generic skill descriptions and trigger surface risk

### 10. Cross-Skill Scanner

- Multi-skill overlap and chaining checks during `scan-all --check-overlap`

## Policy System Features

Implemented in `skill_scanner/core/scan_policy.py` with built-ins in `skill_scanner/data/*_policy.yaml`.

### Supported policy sections

- `policy_name`, `policy_version`, `preset_base`
- `hidden_files`
- `pipeline`
- `rule_scoping`
- `credentials`
- `system_cleanup`
- `file_classification`
- `file_limits`
- `analysis_thresholds`
- `sensitive_files`
- `command_safety`
- `analyzers`
- `finding_output`
- `severity_overrides`
- `disabled_rules`

### Policy capabilities

- Preset loading (`strict`, `balanced`, `permissive`)
- Deep-merge custom YAML overlays on defaults
- Rule severity remapping without rule removal
- Full rule disablement where required
- Output-level dedupe and metadata controls

## CLI Features

### Commands

- `scan`
- `scan-all`
- `list-analyzers`
- `validate-rules`
- `generate-policy`
- `configure-policy`

### Notable flags

- Analyzer toggles: `--use-behavioral`, `--use-llm`, `--use-virustotal`, `--use-aidefense`, `--use-trigger`, `--enable-meta`
- Policy: `--policy`, `--custom-rules`
- LLM: `--llm-provider` (shortcut), `--llm-consensus-runs`
- VirusTotal/AI Defense keys: `--vt-api-key`, `--aidefense-api-key`, `--aidefense-api-url`
- Output: `--format`, `--output`, `--detailed`, `--compact`, `--fail-on-findings`
- Multi-skill: `--recursive`, `--check-overlap`

## API Server Features

Exposed by `skill_scanner/api/router.py`:

- `GET /`
- `GET /health`
- `POST /scan`
- `POST /scan-upload`
- `POST /scan-batch`
- `GET /scan-batch/{scan_id}`
- `GET /analyzers`

Security controls in upload/batch flow include:

- max upload size
- zip entry count and uncompressed-size limits
- path traversal checks
- bounded TTL cache for batch results

## Reporting Features

Reporter implementations:

- `JSONReporter`
- `MarkdownReporter`
- `TableReporter`
- `SARIFReporter`

Supported outputs:

- terminal summary
- JSON (compact/pretty)
- Markdown (detailed or summary)
- table format
- SARIF (CI/code-scanning integrations)

## Integration Features

### Pre-commit hook

- Entry point: `skill-scanner-pre-commit`
- Scans staged or configured skill paths
- Blocks commits based on severity threshold

### Python SDK usage

- Build analyzers directly and pass into `SkillScanner(analyzers=[...], policy=...)`
- Call `scan_skill(...)` or `scan_directory(...)`

## Evaluation & Benchmark Features

Under `evals/runners/`:

- `eval_runner.py`: per-skill expected-vs-actual evaluation
- `benchmark_runner.py`: benchmark corpus workflow
- `policy_benchmark.py`: compare policy profiles
- `update_expected_findings.py`: refresh expected findings files

## Rule Authoring Features

Rule packs under `skill_scanner/data/packs/core/` include:

- `signatures/` (declarative YAML pattern rules)
- `yara/` (YARA rules)
- `python/` (code-based checks)
- `pack.yaml` (pack manifest)

See `docs/AUTHORING.md` for rule-authoring workflow and registration details.
