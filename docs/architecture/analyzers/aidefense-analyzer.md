# AI Defense Analyzer

## Overview

The AI Defense Analyzer integrates with Cisco AI Defense API to provide enterprise-grade security scanning for Agent Skills. It analyzes prompts, instructions, markdown content, and code files for threats including prompt injection, data exfiltration, and malicious patterns.

## Features

- **Prompt Injection Detection**: Identifies attempts to manipulate AI behavior through crafted inputs
- **Data Exfiltration Detection**: Flags patterns that could leak sensitive information
- **Tool Poisoning Detection**: Detects malicious tool descriptions and parameters
- **Code Security Analysis**: Scans Python and other code files for security vulnerabilities
- **Real-time API Analysis**: Leverages Cisco AI Defense cloud infrastructure
- **Retry Logic**: Built-in exponential backoff for rate limit handling

## Configuration

### API Key Setup

Set your API key via environment variable or pass it directly:

```bash
# Environment variable (recommended)
export AI_DEFENSE_API_KEY="your_api_key"

# Or via .env file
echo "AI_DEFENSE_API_KEY=your_key" >> .env
```

### Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| API Key | `AI_DEFENSE_API_KEY` | None (required) | Cisco AI Defense API key |
| API URL | `AI_DEFENSE_API_URL` | `https://us.api.inspect.aidefense.security.cisco.com/api/v1` | API endpoint |
| Enabled Rules | `enabled_rules` parameter | 8 default rules | List of security rules to enable |
| Include Rules | `include_rules` parameter | `True` | Whether to send rules config (set `False` for pre-configured API keys) |
| Timeout | - | 60s | Request timeout |
| Max Retries | - | 3 | Retry attempts on failure |

**Default Enabled Rules:**
- Prompt Injection
- Harassment
- Hate Speech
- Profanity
- Sexual Content & Exploitation
- Social Division & Polarization
- Violence & Public Safety Threats
- Code Detection (excluded for code files, included for prompts/markdown)

**Important**: The "Code Detection" rule is automatically excluded when analyzing actual code files (Python scripts) to avoid false positives, since skills legitimately contain code. Code Detection is still used for prompts, markdown, and manifest content where malicious code injection would be a security concern.

## Usage

### Command Line

```bash
# Enable AI Defense analyzer
skill-scanner scan /path/to/skill --use-aidefense

# Provide API key directly
skill-scanner scan /path/to/skill --use-aidefense --aidefense-api-key your_key

# Combine with other analyzers
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-aidefense

# Scan multiple skills
skill-scanner scan-all /path/to/skills --recursive --use-aidefense
```

### Python API

```python
from skill_scanner.core.analyzers import AIDefenseAnalyzer
from skill_scanner.core.loader import SkillLoader

# Initialize analyzer with default rules
analyzer = AIDefenseAnalyzer(
    api_key="your_api_key",  # Or set AI_DEFENSE_API_KEY env var
    timeout=60,
    max_retries=3
)

# Initialize with custom rules
from skill_scanner.core.analyzers.aidefense_analyzer import DEFAULT_ENABLED_RULES

custom_rules = [
    {"rule_name": "Prompt Injection"},
    {"rule_name": "Code Detection"},  # Will be excluded for code files automatically
]

analyzer = AIDefenseAnalyzer(
    api_key="your_api_key",
    enabled_rules=custom_rules,
    include_rules=True  # Set to False if API key has pre-configured rules
)

# Synchronous analysis
skill = SkillLoader().load_skill("/path/to/skill")
findings = analyzer.analyze(skill)

# Async analysis (preferred for batch operations)
import asyncio

async def scan_skill():
    findings = await analyzer.analyze_async(skill)
    return findings

findings = asyncio.run(scan_skill())
```

### Integration with Scanner

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import StaticAnalyzer, AIDefenseAnalyzer

# Combine analyzers
analyzers = [
    StaticAnalyzer(),
    AIDefenseAnalyzer(api_key="your_key"),
]

scanner = SkillScanner(analyzers=analyzers)
result = scanner.scan_skill("/path/to/skill")
```

## How It Works

### Analysis Pipeline

1. **Content Extraction**: Extracts content from SKILL.md, manifest, markdown files, and code files
2. **API Request**: Sends content to Cisco AI Defense `/inspect/chat` endpoint
3. **Response Processing**: Parses classifications, rules, and actions from API response
4. **Finding Generation**: Converts API results to standardized Finding objects

### Content Types Analyzed

| Content Type | Source | Analysis Focus |
|--------------|--------|----------------|
| Instructions | SKILL.md body | Prompt injection, jailbreak attempts |
| Manifest | Name, description | Social engineering, misleading descriptions |
| Markdown | *.md files | Hidden instructions, injection patterns |
| Code | Python, shell scripts | Command injection, data exfiltration (Code Detection rule excluded) |

### API Response Mapping

The analyzer maps Cisco AI Defense classifications to internal severity levels:

| Classification | Severity | Description |
|----------------|----------|-------------|
| SECURITY_VIOLATION | HIGH | Direct security threats |
| PRIVACY_VIOLATION | HIGH | Data privacy concerns |
| SAFETY_VIOLATION | MEDIUM | Content safety issues |
| RELEVANCE_VIOLATION | LOW | Off-topic or irrelevant content |

## Error Handling

The analyzer handles errors gracefully:

- **Rate Limits (429)**: Automatic retry with exponential backoff
- **Authentication (401/403)**: Clear error message for invalid API keys
- **Timeouts**: Configurable timeout with retry attempts
- **Network Errors**: Logged errors, partial results returned

## Integration with Other Analyzers

For comprehensive coverage, combine AI Defense with other analyzers:

```bash
# Maximum coverage
skill-scanner scan /path/to/skill \
    --use-behavioral \
    --use-llm \
    --use-aidefense \
    --use-virustotal
```

| Analyzer | Detection Focus | Speed | Cost |
|----------|----------------|-------|------|
| Static | Pattern matching | Fast | Free |
| Behavioral | Dataflow analysis | Fast | Free |
| LLM | Semantic intent | Moderate | Paid |
| AI Defense | Enterprise threats | Moderate | Paid |
| VirusTotal | Malware hashes | Fast | Free tier |

## Best Practices

1. **Set API key via environment**: Avoid hardcoding keys in scripts
2. **Use async for batch scans**: Improves throughput for multiple skills
3. **Combine with static analysis**: AI Defense complements pattern-based detection
4. **Monitor API usage**: Track requests to manage rate limits
5. **Handle partial failures**: The analyzer returns partial results on errors

## Troubleshooting

### API Key Not Found

```
AI Defense API key required. Set AI_DEFENSE_API_KEY environment variable.
```

Solution: Export the environment variable or pass `--aidefense-api-key` flag.

### Rate Limited

```
AI Defense API rate limited, retrying in 2s...
```

Solution: The analyzer automatically retries. For high-volume scanning, contact Cisco for rate limit increases.

### Authentication Failed

```
Invalid AI Defense API key
```

Solution: Verify your API key is correct and active.

### httpx Not Installed

```
httpx is required for AI Defense analyzer. Install with: pip install httpx
```

Solution: Install the required dependency:
```bash
pip install httpx
```

## References

- [Cisco AI Defense](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
- [AI Defense API Documentation](https://developer.cisco.com/docs/ai-defense/)

## Related Pages

- [Analyzer Selection Guide](meta-and-external-analyzers.md) -- When to enable `--use-aidefense`
- [Scanning Pipeline](../scanning-pipeline.md) -- How AI Defense fits into Phase 1 analysis
