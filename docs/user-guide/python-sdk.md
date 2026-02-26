# Python SDK

Skill Scanner can be embedded directly in Python applications.

## Basic Usage

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import BehavioralAnalyzer

scanner = SkillScanner(analyzers=[BehavioralAnalyzer()])
result = scanner.scan_skill("/path/to/skill")

print(result.skill_name)
print(result.max_severity)
print(len(result.findings))
```

## `SkillScanner` Constructor

```python
SkillScanner(
    analyzers=None,           # List[BaseAnalyzer] — custom analyzers; None uses defaults
    use_virustotal=False,     # Enable VirusTotal binary scanning
    virustotal_api_key=None,  # VirusTotal API key (required when use_virustotal=True)
    virustotal_upload_files=False,  # Upload unknown files to VT (vs hash-only lookup)
    policy=None,              # ScanPolicy instance; None loads built-in defaults
)
```

When `analyzers` is `None`, the scanner builds the default core analyzer set (static, bytecode, pipeline). Pass an explicit list to control exactly which analyzers run.

## Instance Methods

### `scan_skill(skill_directory, *, lenient=False) → ScanResult`

Scan a single skill package directory. Pass `lenient=True` to coerce malformed manifests instead of raising an error.

```python
result = scanner.scan_skill("/path/to/skill")
```

### `scan_directory(skills_directory, recursive=False, check_overlap=False, *, lenient=False) → Report`

Scan all skill packages in a directory.

```python
report = scanner.scan_directory("/path/to/skills", recursive=True)
print(report.total_skills_scanned)
print(report.total_findings)
```

### `add_analyzer(analyzer)`

Add an analyzer to the scanner at runtime.

```python
import os
from skill_scanner.core.analyzers import LLMAnalyzer

scanner.add_analyzer(LLMAnalyzer(
    model="anthropic/claude-sonnet-4-20250514",
    api_key=os.environ["SKILL_SCANNER_LLM_API_KEY"],
))
```

> [!WARNING]
> Never hardcode API keys in source code. Use environment variables or a secrets manager. The LLM analyzer also reads `SKILL_SCANNER_LLM_API_KEY` from the environment automatically when no `api_key` is passed.

### `list_analyzers() → list[str]`

Return names of all configured analyzers.

```python
print(scanner.list_analyzers())
# ['static_analyzer', 'bytecode', 'pipeline']
```

## Module-Level Convenience Functions

For one-off scans without managing a scanner instance:

```python
from skill_scanner import scan_skill, scan_directory

result = scan_skill("/path/to/skill")
report = scan_directory("/path/to/skills", recursive=True, check_overlap=True)
```

Both functions accept an optional `analyzers` list and `policy` parameter.

## Working With Results

<details>
<summary>ScanResult attributes (single skill)</summary>

| Attribute | Type | Description |
|---|---|---|
| `skill_name` | `str` | Name from SKILL.md manifest |
| `skill_directory` | `str` | Absolute path to the scanned skill |
| `findings` | `list[Finding]` | All security findings |
| `scan_duration_seconds` | `float` | Wall-clock scan time |
| `analyzers_used` | `list[str]` | Analyzer names that ran |
| `analyzability_score` | `float \| None` | Percentage of content the scanner could inspect |
| `is_safe` | `bool` | `True` when no CRITICAL or HIGH findings |
| `max_severity` | `Severity` | Highest severity across all findings |

```python
result.get_findings_by_severity(Severity.HIGH)
result.get_findings_by_category(ThreatCategory.DATA_EXFILTRATION)
result.to_dict()  # Serialize to JSON-compatible dict
```

</details>

<details>
<summary>Report attributes (multi-skill)</summary>

| Attribute | Type | Description |
|---|---|---|
| `scan_results` | `list[ScanResult]` | Per-skill results |
| `total_skills_scanned` | `int` | Number of skills processed |
| `total_findings` | `int` | Sum of all findings |
| `critical_count` | `int` | Total CRITICAL findings |
| `high_count` | `int` | Total HIGH findings |
| `medium_count` | `int` | Total MEDIUM findings |
| `low_count` | `int` | Total LOW findings |
| `info_count` | `int` | Total INFO findings |
| `safe_count` | `int` | Skills with `is_safe == True` |

</details>

<details>
<summary>Finding attributes</summary>

| Attribute | Type | Description |
|---|---|---|
| `id` | `str` | Unique finding identifier (rule ID + content hash) |
| `rule_id` | `str` | Rule identifier (e.g. `DATA_EXFIL_HTTP_POST`) |
| `category` | `ThreatCategory` | Threat category enum |
| `severity` | `Severity` | Severity level |
| `title` | `str` | Human-readable title |
| `description` | `str` | Detailed explanation |
| `file_path` | `str \| None` | Relative path within the skill |
| `line_number` | `int \| None` | Line number (when available) |
| `snippet` | `str \| None` | Code snippet context |
| `remediation` | `str \| None` | Suggested fix |
| `analyzer` | `str \| None` | Which analyzer produced this finding |
| `metadata` | `dict` | Extra context (YARA rule name, matched pattern, threat type, etc.) |

```python
for finding in result.findings:
    print(finding.rule_id, finding.severity.value, finding.file_path)
```

</details>

### `Severity` Enum

Values in descending order: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `SAFE`.

## Using Policies in the SDK

```python
from skill_scanner import SkillScanner
from skill_scanner.core.scan_policy import ScanPolicy

# Use a built-in preset
policy = ScanPolicy.from_preset("strict")

# Or load a custom YAML file
policy = ScanPolicy.from_yaml("my_policy.yaml")

scanner = SkillScanner(policy=policy)
result = scanner.scan_skill("/path/to/skill")
```

## Programmatic Analyzer Composition

Typical analyzers are configured through `build_analyzers` in [`skill_scanner/core/analyzer_factory.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/analyzer_factory.py), but direct analyzer construction is also possible for custom runtime control.

## Example Scripts

- [examples/basic_scan.py](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/basic_scan.py)
- [examples/programmatic_usage.py](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/programmatic_usage.py)
- [examples/advanced_scanning.py](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/advanced_scanning.py)
- [examples/batch_scanning.py](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/batch_scanning.py)

## See Also

- [CLI Usage](cli-usage.md) — command-line interface for the same scanning engine
- [API Server](api-server.md) — REST API for upload-driven workflows
- [Configuration Reference](../reference/configuration-reference.md) — all configuration options
