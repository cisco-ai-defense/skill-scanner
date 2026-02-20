# Examples and How-To Guides

Quick walkthroughs to get you productive, plus a catalog of runnable example scripts.

## How-To: Your First Scan from Python

```python
from skill_scanner import SkillScanner

scanner = SkillScanner()
result = scanner.scan_skill("/path/to/skill")

print(f"Safe: {result.is_safe}")
print(f"Findings: {len(result.findings)}")

for f in result.findings:
    print(f"  [{f.severity}] {f.rule_id}: {f.message}")
```

For full SDK coverage (custom analyzers, policy objects, batch scanning), see the [Python SDK guide](/user-guide/python-sdk).

## How-To: Scan via the REST API

**1. Start the server**

```bash
skill-scanner-api
```

**2. Submit a scan**

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"skill_directory": "/path/to/skill"}'
```

**3. Inspect the response**

```json
{
  "is_safe": false,
  "max_severity": "HIGH",
  "findings_count": 3,
  "findings": [...]
}
```

For server setup, upload scanning, and batch operations, see the [API Server guide](/user-guide/api-server).

## Example Catalog

The [`examples/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/examples) directory contains runnable scripts covering progressively advanced scenarios:

| File | Focus |
|---|---|
| [`basic_scan.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/basic_scan.py) | Minimal single-skill scan |
| [`programmatic_usage.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/programmatic_usage.py) | SDK usage and result handling |
| [`advanced_scanning.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/advanced_scanning.py) | Multi-analyzer configuration |
| [`batch_scanning.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/batch_scanning.py) | Directory-level scanning workflows |
| [`behavioral_analyzer_example.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/behavioral_analyzer_example.py) | Behavioral analyzer usage |
| [`llm_analyzer_example.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/llm_analyzer_example.py) | Semantic analyzer usage |
| [`api_usage.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/api_usage.py) | API endpoint interaction patterns |
| [`integration_example.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/examples/integration_example.py) | CI/integration patterns |

### Recommended Learning Order

1. `basic_scan.py`
2. `programmatic_usage.py`
3. `advanced_scanning.py`
4. Analyzer-specific examples
5. API and integration examples

### Running Examples

From repository root:

```bash
uv run python examples/basic_scan.py
```

Some examples require API keys or optional analyzers -- see [Configuration Reference](/reference/configuration-reference) for the relevant environment variables.
