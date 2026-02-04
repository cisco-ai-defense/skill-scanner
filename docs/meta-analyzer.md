# Meta-Analyzer

The Meta-Analyzer is an optional second-pass LLM analysis feature that reviews findings from other analyzers to improve accuracy and provide actionable insights. In our testing, it significantly reduces false positives while preserving threat detection capability.

## Overview

When enabled via the `--enable-meta` CLI flag or `enable_meta` API parameter, the Meta-Analyzer performs:

- **False Positive Filtering**: Aggressively identifies and removes false positives based on full skill context
- **Finding Consolidation**: Merges redundant pattern-based findings into comprehensive threat descriptions
- **Priority Ranking**: Ranks findings by actual exploitability and business impact
- **Correlation**: Groups related findings representing the same root cause
- **Remediation Guidance**: Provides specific, actionable fixes with code examples
- **Confidence Enrichment**: Adds `meta_confidence`, `meta_exploitability`, and `meta_impact` to validated findings

> **Key Insight**: The Meta-Analyzer has full access to skill content (SKILL.md and all code files) allowing it to verify whether pattern-based detections represent actual threats.

## How It Works

1. **Collect Findings**: All selected analyzers (static, behavioral, LLM, etc.) run and produce findings
2. **Aggregate Full Context**: The meta-analyzer receives:
   - All findings from other analyzers
   - Complete SKILL.md content (up to 50KB)
   - All code files (.py, .js, .ts, .sh, .bash) with content (up to 30KB per file, 150KB total)
3. **Authority-Based Review**: Uses an analyzer authority hierarchy to weight findings:
   - LLM Analyzer (highest) > Behavioral > AI Defense > Static > Trigger (lowest)
4. **Filter & Consolidate**:
   - Redundant pattern-based findings are consolidated into comprehensive descriptions
   - False positives are removed based on actual code analysis
   - Validated findings are enriched with confidence scores and reasoning
5. **Enrich Findings**: Each validated finding receives:
   - `meta_confidence`: HIGH/MEDIUM/LOW with reasoning
   - `meta_exploitability`: How easy it is to exploit
   - `meta_impact`: Business/security impact assessment
   - Specific remediation recommendations

## CLI Usage

```bash
# Scan with static + LLM + meta-analysis
skill-scanner scan /path/to/skill --use-llm --enable-meta

# Scan with behavioral + LLM + meta-analysis (recommended for best results)
skill-scanner scan /path/to/skill --use-behavioral --use-llm --enable-meta

# Scan all skills in a directory
skill-scanner scan-all /path/to/skills --use-llm --enable-meta --recursive

# Output in JSON format
skill-scanner scan /path/to/skill --use-llm --enable-meta --format json
```

**Requirements:**
- **Minimum 2 analyzers**: Meta-analysis requires at least 2 analyzers (e.g., static + LLM, or behavioral + LLM). This ensures the meta-analyzer has multiple perspectives to correlate.
- **LLM API key**: An API key must be configured for the meta-analyzer's LLM calls (see Configuration section for supported providers)
- **Recommended**: Use `--use-llm` with meta-analysis for best results, as LLM findings provide the semantic understanding the meta-analyzer relies on

## API Usage

All scan endpoints support the `enable_meta` parameter:

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "skill_directory": "/path/to/skill",
    "use_llm": true,
    "use_behavioral": true,
    "enable_meta": true
  }'
```

## Configuration

The meta-analyzer can use a **separate LLM API key** from the primary LLM analyzer. This allows you to:
- Use a different model for meta-analysis (e.g., GPT-4 for meta, Claude for primary)
- Use separate rate limits/quotas
- Route through different endpoints

### Environment Variables

The scanner uses `SKILL_SCANNER_*` environment variables exclusively (no provider-specific fallbacks to avoid accidentally using other keys).

**Scanner-wide settings** (apply to both LLM and Meta analyzers):
```bash
export SKILL_SCANNER_LLM_API_KEY="your-api-key"
export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"
export SKILL_SCANNER_LLM_BASE_URL="https://..."  # For Azure/custom endpoints
export SKILL_SCANNER_LLM_API_VERSION="2025-01-01-preview"  # For Azure
```

**Meta-specific overrides** (optional - use different model/key for meta-analysis):
```bash
export SKILL_SCANNER_META_LLM_API_KEY="different-key"
export SKILL_SCANNER_META_LLM_MODEL="gpt-4o"
export SKILL_SCANNER_META_LLM_BASE_URL="https://..."
export SKILL_SCANNER_META_LLM_API_VERSION="..."
```

### Priority Order

| Setting | Priority Order |
|---------|---------------|
| API Key | `SKILL_SCANNER_META_LLM_API_KEY` → `SKILL_SCANNER_LLM_API_KEY` |
| Model | `SKILL_SCANNER_META_LLM_MODEL` → `SKILL_SCANNER_LLM_MODEL` → default |
| Base URL | `SKILL_SCANNER_META_LLM_BASE_URL` → `SKILL_SCANNER_LLM_BASE_URL` |
| API Version | `SKILL_SCANNER_META_LLM_API_VERSION` → `SKILL_SCANNER_LLM_API_VERSION` |

### Special Cases

| Provider | Auth Method | Notes |
|----------|-------------|-------|
| Google Vertex AI | Service account | Uses `GOOGLE_APPLICATION_CREDENTIALS` |
| Ollama | None | Local, no API key needed |
| All others | `SKILL_SCANNER_LLM_API_KEY` | Including Bedrock, Azure, OpenAI, Anthropic, Gemini |

### Setup Examples

```bash
# Standard setup (one key for everything)
export SKILL_SCANNER_LLM_API_KEY="sk-ant-..."
export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"

# Azure OpenAI setup
export SKILL_SCANNER_LLM_API_KEY="your-azure-key"
export SKILL_SCANNER_LLM_MODEL="azure/gpt-4.1"
export SKILL_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export SKILL_SCANNER_LLM_API_VERSION="2025-01-01-preview"

# Separate meta key for second opinion (advanced)
export SKILL_SCANNER_LLM_API_KEY="sk-ant-..."  # Primary: Claude
export SKILL_SCANNER_META_LLM_API_KEY="sk-..."  # Meta: OpenAI
export SKILL_SCANNER_META_LLM_MODEL="gpt-4o"
```

### Provider Examples

**Anthropic Claude:**
```bash
export SKILL_SCANNER_LLM_API_KEY="sk-ant-..."
export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"
```

**OpenAI:**
```bash
export SKILL_SCANNER_LLM_API_KEY="sk-..."
export SKILL_SCANNER_LLM_MODEL="gpt-4o"
```

**Azure OpenAI:**
```bash
export SKILL_SCANNER_LLM_API_KEY="your-azure-key"
export SKILL_SCANNER_LLM_MODEL="azure/gpt-4.1"
export SKILL_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export SKILL_SCANNER_LLM_API_VERSION="2025-01-01-preview"
```

**Google Gemini:**
```bash
export SKILL_SCANNER_LLM_API_KEY="your-gemini-key"
export SKILL_SCANNER_LLM_MODEL="gemini/gemini-1.5-pro"
```

**AWS Bedrock:**
```bash
export SKILL_SCANNER_LLM_API_KEY="bedrock-api-key-..."
export SKILL_SCANNER_LLM_MODEL="bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0"
```

**Google Vertex AI (uses service account):**
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
export SKILL_SCANNER_LLM_MODEL="vertex_ai/gemini-1.5-pro"
```

## Analyzer Authority Hierarchy

The meta-analyzer weights findings based on which analyzer produced them:

| Analyzer | Authority | Best At |
|----------|-----------|---------|
| LLM | Highest | Intent detection, semantic understanding, prompt injection |
| Behavioral | High | Dataflow tracking, source→sink analysis, multi-file chains |
| AI Defense | Medium-High | Known attack patterns, threat intelligence |
| Static | Medium | Pattern matching, hardcoded secrets, obvious violations |
| Trigger | Lower | Description specificity (informational) |
| VirusTotal | Specialized | Binary file malware (not code) |

### Authority-Based Rules

- **LLM + Behavioral agree** → HIGH confidence true positive
- **LLM says SAFE, Static flags** → Likely false positive (trust LLM)
- **LLM says THREAT, others missed** → True positive (trust LLM)
- **Only Static flagged (pattern match)** → Review carefully, may be false positive

## Output Format

Meta-analyzed findings include enriched metadata:

```json
{
  "id": "meta_finding_1",
  "rule_id": "META_VALIDATED",
  "category": "data_exfiltration",
  "severity": "HIGH",
  "title": "Credential Theft via Network Exfiltration",
  "description": "Skill reads AWS credentials and sends to external server",
  "file_path": "scripts/sync.py",
  "line_number": 42,
  "remediation": "Remove network call or use secure credential management",
  "analyzer": "meta",
  "metadata": {
    "meta_validated": true,
    "meta_confidence": "HIGH",
    "meta_confidence_reason": "Clear source→sink flow from credential file to external POST",
    "meta_exploitability": "Easy - no authentication required",
    "meta_impact": "Critical - AWS credential compromise",
    "aitech": "AITech-8.2"
  }
}
```

### Finding Consolidation

When multiple analyzers report overlapping threats, the meta-analyzer consolidates them into a single comprehensive finding. For example, if static analysis reports:
- "HTTP POST request detected"
- "Base64 encoding detected"
- "Network library import detected"

And LLM analysis reports:
- "Data exfiltration via network"

The meta-analyzer will keep only the LLM finding (which provides full context) and filter the redundant static pattern matches as they're covered by the comprehensive LLM finding.

## AITech Taxonomy

The meta-analyzer uses the AITech taxonomy for threat classification:

| AITech Code | Category | Description |
|-------------|----------|-------------|
| AITech-1.1 | Direct Prompt Injection | Explicit instruction override attempts |
| AITech-1.2 | Indirect Prompt Injection | Transitive trust abuse, external content execution |
| AITech-4.3 | Protocol Manipulation | Skill discovery abuse, capability inflation |
| AITech-8.2 | Data Exfiltration | Credential theft, unauthorized data transmission |
| AITech-9.1 | System Manipulation | Command injection, code injection, obfuscation |
| AITech-12.1 | Tool Exploitation | Tool poisoning, shadowing, unauthorized use |
| AITech-13.3 | Availability Disruption | Resource exhaustion, denial of service |
| AITech-15.1 | Harmful Content | Misleading or deceptive content |

## Evaluating Meta-Analyzer Performance

The eval runner supports comparing results with and without the meta-analyzer:

```bash
# Run comparison evaluation
uv run python evals/eval_runner.py --compare

# With detailed per-skill breakdown
uv run python evals/eval_runner.py --compare --show-details
```

### Sample Comparison Output

```
======================================================================
COMPARISON RESULTS
======================================================================

Metric                       Without Meta       With Meta       Change
----------------------------------------------------------------------
True Positives                         40              16          -24
False Positives                        17              11           -6
----------------------------------------------------------------------
Meta-Analyzer Impact:
  Total findings filtered: 50
  Total findings validated: 27
  Noise reduction rate: 64.9%

======================================================================
SUMMARY
======================================================================

Safe Skills Detection:   2/2 -> 2/2
Unsafe Skills Detection: 9/9 -> 9/9

Key Insight:
  Meta-Analyzer filtered 50 low-value findings
  while maintaining 9/9 unsafe skill detection rate

  ✓ Meta-Analyzer IMPROVED signal-to-noise without losing detection capability!
```

The comparison shows that while raw metrics like "true positives" decrease (because redundant pattern matches are consolidated), the threat detection capability is preserved. Results may vary depending on your specific skills and threat patterns.

## Best Practices

1. **Use multiple analyzers**: Meta-analysis is most effective when correlating findings from 2+ analyzers
2. **Include LLM analyzer**: The LLM analyzer provides the semantic understanding meta-analysis relies on
3. **Review filtered findings**: Check verbose output for false positives that were filtered
4. **Configure appropriate model**: Use a capable model (GPT-4, Claude 3.5+) for best results
5. **Consider latency**: Meta-analysis adds one LLM call, increasing scan time by ~5-15 seconds
6. **Use --compare for validation**: Run the eval comparison to verify meta-analyzer effectiveness on your skills

## Troubleshooting

**Meta-analyzer not running:**
- Ensure `--enable-meta` flag is provided
- Verify at least 2 analyzers are enabled
- Check that LLM API key is configured
- Look for "Using Meta-Analyzer" in output

**No findings after meta-analysis:**
- All findings may have been filtered as false positives
- Check verbose output: "X false positives filtered"
- This can be correct behavior for benign skills

**Slow scans with meta-analysis:**
- Meta-analysis adds one LLM API call per skill
- Consider using a faster model via `SKILL_SCANNER_META_LLM_MODEL`
- For batch scans, meta-analysis runs per-skill (not aggregated)

**Different results than expected:**
- Meta-analyzer uses authority hierarchy - LLM findings take precedence
- Pattern-only matches from static analyzer may be filtered as FPs
- Check `meta_confidence_reason` for explanation
