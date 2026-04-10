# PromptGuard Analyzer

## Overview

The PromptGuard Analyzer sends skill content to the [PromptGuard](https://promptguard.co) Guard API for security analysis. PromptGuard detects prompt injection, jailbreaks, PII leaks, secret key exposure, data exfiltration, toxicity, fraud, malware, and tool injection patterns.

All detection runs server-side — this analyzer ships zero detection logic and acts as a thin API client.

## Features

- **Prompt Injection Detection**: ML ensemble + regex patterns for instruction overrides, role confusion, and semantic evasion
- **Jailbreak Detection**: LLM-based analysis across 7 attack categories
- **PII Detection**: 39+ entity types across 10+ countries with checksum validation
- **Secret Key Detection**: API keys, tokens, and credentials across 40+ providers
- **Data Exfiltration Detection**: System prompt extraction, training data probing
- **Tool Injection Detection**: Indirect prompt injection in agentic tool calls
- **Toxicity & Content Safety**: Hate speech, violence, self-harm, harassment
- **Fraud & Malware Detection**: Social engineering patterns, reverse shells, destructive commands
- **Fail-open**: Returns empty results on API errors so scanning continues

## Configuration

### API Key Setup

Get a free API key at [promptguard.co](https://promptguard.co), then set it via environment variable or pass it directly:

```bash
# Environment variable (recommended)
export PROMPTGUARD_API_KEY="your_api_key"

# Or via .env file
echo "PROMPTGUARD_API_KEY=your_key" >> .env
```

### Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| API Key | `PROMPTGUARD_API_KEY` | None (required) | PromptGuard API key |
| API URL | `PROMPTGUARD_API_URL` | `https://api.promptguard.co/api/v1/guard` | API endpoint |
| Timeout | - | 15s | Request timeout |

## Usage

### Command Line

```bash
# Enable PromptGuard analyzer
skill-scanner scan /path/to/skill --use-promptguard

# Provide API key directly
skill-scanner scan /path/to/skill --use-promptguard --promptguard-api-key your_key

# Combine with other analyzers
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-promptguard

# Scan multiple skills
skill-scanner scan-all /path/to/skills --recursive --use-promptguard
```

### Python API

```python
from skill_scanner.core.analyzers.promptguard_analyzer import PromptGuardAnalyzer
from skill_scanner.core.loader import SkillLoader

# Initialize analyzer
analyzer = PromptGuardAnalyzer(
    api_key="your_api_key",  # Or set PROMPTGUARD_API_KEY env var
    timeout=15
)

# Load and scan a skill
skill = SkillLoader().load_skill("/path/to/skill")
findings = analyzer.analyze(skill)

for finding in findings:
    print(f"[{finding.severity.value}] {finding.title}: {finding.description}")
```

### Integration with Scanner

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import StaticAnalyzer
from skill_scanner.core.analyzers.promptguard_analyzer import PromptGuardAnalyzer

analyzers = [
    StaticAnalyzer(),
    PromptGuardAnalyzer(api_key="your_key"),
]

scanner = SkillScanner(analyzers=analyzers)
result = scanner.scan_skill("/path/to/skill")
```

## How It Works

### Analysis Pipeline

1. **Content Extraction**: Extracts content from SKILL.md instructions, manifest metadata, markdown files, and script files
2. **API Request**: Sends each content piece to the PromptGuard Guard API
3. **Response Mapping**: Converts PromptGuard threat types and confidence scores to skill-scanner Finding objects
4. **Aggregation**: Collects findings from all content pieces into a single result list

### Content Types Analyzed

| Content Type | Source | Analysis Focus |
|--------------|--------|----------------|
| Instructions | SKILL.md body | Prompt injection, jailbreak attempts, hidden instructions |
| Manifest | Name, description | Social engineering, misleading descriptions |
| Markdown | *.md files | Embedded injection, data exfiltration patterns |
| Scripts | Python, Bash, JS, TS | Malware, reverse shells, credential theft |

### Threat Type Mapping

PromptGuard threat types are mapped to skill-scanner categories:

| PromptGuard Threat | skill-scanner Category | Default Severity |
|---|---|---|
| `prompt_injection` | `PROMPT_INJECTION` | CRITICAL |
| `jailbreak` | `PROMPT_INJECTION` | CRITICAL |
| `data_exfiltration` | `DATA_EXFILTRATION` | CRITICAL |
| `pii_leak` | `DATA_EXFILTRATION` | HIGH |
| `api_key_leak` | `HARDCODED_SECRETS` | CRITICAL |
| `secret_key_leak` | `HARDCODED_SECRETS` | CRITICAL |
| `toxicity` | `HARMFUL_CONTENT` | MEDIUM |
| `fraud_abuse` | `SOCIAL_ENGINEERING` | HIGH |
| `malware` | `MALWARE` | CRITICAL |
| `tool_injection` | `PROMPT_INJECTION` | HIGH |
| `mcp_violation` | `UNAUTHORIZED_TOOL_USE` | HIGH |

## Error Handling

The analyzer is fail-open — API errors never block the scan:

- **Network errors**: Logged at DEBUG level, empty findings returned
- **HTTP errors (4xx/5xx)**: Logged at DEBUG level, empty findings returned
- **Timeouts**: Configurable timeout (default 15s), logged on expiry

## Integration with Other Analyzers

For comprehensive coverage, combine PromptGuard with other analyzers:

```bash
skill-scanner scan /path/to/skill \
    --use-behavioral \
    --use-llm \
    --use-promptguard \
    --use-virustotal
```

| Analyzer | Detection Focus | Speed | Cost |
|----------|----------------|-------|------|
| Static | Pattern matching | Fast | Free |
| Behavioral | Dataflow analysis | Fast | Free |
| LLM | Semantic intent | Moderate | Paid |
| AI Defense | Enterprise threats | Moderate | Paid |
| **PromptGuard** | **Injection, PII, secrets, toxicity** | **Fast** | **Free tier available** |
| VirusTotal | Malware hashes | Fast | Free tier |

## Troubleshooting

### API Key Not Found

```
PromptGuard API key required. Set PROMPTGUARD_API_KEY environment variable.
```

Solution: Export the environment variable or pass `--promptguard-api-key` flag. Get a free key at [promptguard.co](https://promptguard.co).

### httpx Not Installed

```
httpx is required for the PromptGuard analyzer. Install with: pip install httpx
```

Solution: `pip install httpx`

## References

- [PromptGuard Documentation](https://docs.promptguard.co)
- [PromptGuard Guard API](https://docs.promptguard.co/api-reference/guard)

## Related Pages

- [Analyzer Selection Guide](meta-and-external-analyzers.md) -- When to enable `--use-promptguard`
- [Scanning Pipeline](../scanning-pipeline.md) -- How PromptGuard fits into Phase 1 analysis
