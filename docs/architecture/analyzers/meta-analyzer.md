# Meta-Analyzer

The Meta-Analyzer is an optional second-pass LLM analysis feature that reviews findings from other analyzers and enriches results with correlation, prioritization, and remediation context.

## Overview

When enabled via the `--enable-meta` CLI flag or `enable_meta` API parameter, the Meta-Analyzer performs:

- **False Positive Filtering**: Identifies genuinely benign findings based on full skill context (only marks FPs when code is actually safe)
- **Finding Correlation**: Groups related findings from different analyzers into logical threat groups (e.g., 4 autonomy-abuse YARA matches = 1 correlation group)
- **Priority Ranking**: Ranks findings by actual exploitability and business impact
- **Remediation Guidance**: Provides specific, actionable recommendations per correlation group
- **Risk Assessment**: Overall skill verdict (SAFE/SUSPICIOUS/MALICIOUS) with reasoning
- **Confidence Enrichment**: Adds `meta_confidence`, `meta_exploitability`, and `meta_impact` to every validated finding

The meta-analyzer is given `SKILL.md` and source content within policy-controlled prompt budgets, which it uses to validate whether detections are likely true threats.

## How It Works

1. **Collect Findings**: All selected analyzers (static, behavioral, LLM, etc.) run and produce findings
2. **Aggregate Full Context**: The meta-analyzer receives:
   - All findings from other analyzers
   - `SKILL.md` instruction body up to the policy-defined meta budget
   - Code/reference files up to per-file and total meta budgets
   - With default policy values: `60,000` chars for instruction body, `45,000` chars per code file, and `300,000` chars total (`llm_analysis.*` limits multiplied by `meta_budget_multiplier`)
3. **Authority-Based Review**: Uses an analyzer authority hierarchy to weight findings:
   - LLM Analyzer (highest) > Behavioral > AI Defense > Static > Trigger (informational), with VirusTotal treated as specialized for binary reputation
4. **Validate & Correlate**:
   - Each finding is verified against actual code content
   - Genuinely benign findings are marked as false positives
   - Related findings are grouped into correlation groups
   - A follow-up pass covers any findings the initial analysis missed
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
- **Analyzer count**: CLI enforces at least 2 analyzers for meta-analysis (`_build_meta_analyzer` guard). API endpoints expose `enable_meta` and apply meta-analysis when findings exist; using multiple analyzers is still recommended for correlation quality.
- **LLM credentials**: Configure `SKILL_SCANNER_META_LLM_API_KEY` / `SKILL_SCANNER_LLM_API_KEY`, or use a `bedrock/...` model with AWS credentials/IAM
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
export SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"
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

### Auth Behavior

| Provider | Auth Method | Notes |
|----------|-------------|-------|
| Bedrock (`bedrock/...` model) | AWS credentials/IAM **or** API key | API key is optional when Bedrock auth is available |
| Non-Bedrock models | `SKILL_SCANNER_META_LLM_API_KEY` or `SKILL_SCANNER_LLM_API_KEY` | Required by current meta-analyzer validation logic |

### Setup Examples

```bash
# Standard setup (one key for everything)
export SKILL_SCANNER_LLM_API_KEY="sk-ant-..."
export SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"

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
export SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"
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
export SKILL_SCANNER_LLM_MODEL="bedrock/anthropic.claude-sonnet-4-20250514-v1:0"
# Optional if using bearer auth:
export SKILL_SCANNER_LLM_API_KEY="bedrock-api-key-..."
# Or use AWS credentials/profile/role:
export AWS_REGION="us-east-1"
export AWS_PROFILE="security-prod"
```

## Analyzer Authority Hierarchy

The meta-analysis system prompt instructs the model to apply this authority order while reviewing findings:

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
- **LLM says SAFE, Static flags pattern-only (no malicious context)** → Likely false positive
- **LLM says THREAT, others missed** → True positive (trust LLM)
- **Only Static flagged, but code confirms the issue** → True positive (MEDIUM confidence)
- **Only Static flagged, keyword-only with no malicious context** → Likely false positive
- **Multiple analyzers flag different aspects of same issue** → Correlated — group, keep all

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

### Finding Correlation

When multiple analyzers report overlapping threats, the meta-analyzer groups them into correlation groups rather than removing them. All findings are preserved in `validated_findings`, and the `correlations` block shows how they relate. For example:

```json
{
  "correlations": [
    {
      "group_name": "Credential Theft Chain",
      "finding_indices": [3, 12, 13, 24, 46],
      "relationship": "Pipeline taint flows and static pattern matches all confirm credential exfiltration",
      "combined_severity": "CRITICAL",
      "consolidated_remediation": "Remove all credential exfiltration code and network calls to untrusted endpoints"
    }
  ]
}
```

This preserves the granular evidence from each analyzer (line numbers, exact patterns, taint chains) while providing the consolidated view for executive reporting. Use `--verbose` to also include findings the meta-analyzer marked as false positives.

### Visual Reports

Correlation groups are rendered in two output formats:

- **Markdown** (`--format markdown`): Correlation groups render with per-group findings tables, remediation text, and pipeline flow chains as ASCII arrows when available.
- **HTML** (`--format html`): A self-contained, interactive HTML report with:
  - Risk verdict banner and severity bar
  - Collapsible correlation group cards with inline pipeline flow steps
  - Prioritized recommendation cards with effort badges
  - Sortable findings table

```bash
# Generate an interactive HTML report
skill-scanner scan /path/to/skill --use-llm --enable-meta --format html --output report.html
```

## AITech Taxonomy

The meta-analyzer uses the AITech taxonomy for threat classification:

| AITech Code | Category | Description |
|-------------|----------|-------------|
| AITech-1.1 | Direct Prompt Injection | Explicit instruction override attempts |
| AITech-1.2 | Indirect Prompt Injection - Instruction Manipulation | Embedding malicious instructions in external data sources |
| AITech-4.3 | Protocol Manipulation - Capability Inflation | Skill discovery abuse, over-broad capability claims |
| AITech-8.2 | Data Exfiltration | Credential theft, unauthorized data transmission |
| AITech-9.1 | System Manipulation | Command injection, code injection |
| AITech-9.2 | Detection Evasion | Obfuscation and evasion patterns |
| AITech-12.1 | Tool Exploitation | Tool poisoning, shadowing, unauthorized use |
| AITech-13.1 | Disruption of Availability | Compute exhaustion, resource abuse |
| AITech-15.1 | Harmful Content | Misleading or deceptive content |

## Evaluating Meta-Analyzer Performance

The eval runner supports comparing results with and without the meta-analyzer:

```bash
# Run comparison evaluation
uv run python evals/runners/eval_runner.py --compare

# With detailed per-skill breakdown
uv run python evals/runners/eval_runner.py --compare --show-details
```

The comparison command prints per-run metrics (`true positives`, `false positives`, validated/filtered totals, and safe/unsafe detection summary) for your own evaluation set.

## Best Practices

1. **Use multiple analyzers**: Meta-analysis is most effective when correlating findings from 2+ analyzers
2. **Include LLM analyzer**: The LLM analyzer provides the semantic understanding meta-analysis relies on
3. **Review filtered findings**: Check verbose output for false positives that were filtered
4. **Configure appropriate model**: Use a capable model (GPT-4, Claude 3.5+) for best results
5. **Consider latency**: Meta-analysis adds one additional LLM request per skill
6. **Use --compare for validation**: Run the eval comparison to verify meta-analyzer effectiveness on your skills

## Troubleshooting

**Meta-analyzer not running:**
- Ensure `--enable-meta` flag is provided
- Verify at least 2 analyzers are enabled
- Check that LLM credentials are configured (`SKILL_SCANNER_META_LLM_API_KEY` or `SKILL_SCANNER_LLM_API_KEY`), or use Bedrock model + AWS credentials
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
- The model is prompted with an analyzer authority hierarchy
- Pattern-only matches from static analyzer may be filtered as FPs
- Check `meta_confidence_reason` for explanation

## Related Pages

- [LLM Analyzer](llm-analyzer.md) -- Primary semantic analysis (runs before meta)
- [Analyzer Selection Guide](meta-and-external-analyzers.md) -- When to enable `--enable-meta`
- [Scanning Pipeline](../scanning-pipeline.md) -- How meta-analysis fits into the two-phase pipeline
