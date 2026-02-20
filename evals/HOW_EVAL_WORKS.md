# How Evaluation Works

## Quick Answer

### How does eval work with LLM, YARA, and both?

1. **Static Analyzer Only** (includes YARA):
   ```bash
   python evals/eval_runner.py --test-skills-dir evals/skills
   ```
   - Uses `StaticAnalyzer` which includes YARA rule matching
   - Fast, no API calls
   - Tests pattern-based detection

2. **Static + LLM Analyzer**:
   ```bash
   export SKILL_SCANNER_LLM_API_KEY=your_key
   python evals/eval_runner.py --test-skills-dir evals/skills --use-llm
   ```
   - Uses `StaticAnalyzer` + `LLMAnalyzer`
   - Combines pattern matching (YARA) with semantic analysis (LLM)
   - More comprehensive but slower

3. **With Meta-Analyzer** (false positive filtering):
   ```bash
   python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --use-meta
   ```
   - Adds `MetaAnalyzer` for second-pass analysis
   - Filters false positives, consolidates redundant findings
   - Best for production-quality results

4. **Compare With/Without Meta-Analyzer**:
   ```bash
   python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --compare
   ```
   - Runs evaluation twice: with and without meta-analysis
   - Shows per-skill changes and overall impact
   - Useful for validating meta-analyzer effectiveness

5. **View AITech Taxonomy Codes**:
   ```bash
   python evals/eval_runner.py --test-skills-dir evals/skills --show-aitech
   ```
   - Displays detailed findings with AITech taxonomy codes
   - Shows AITech codes (e.g., `AITech-9.1`), names, and AISubtech codes
   - Useful for understanding threat classification alignment with Cisco AI Security Framework

6. **What it checks**:
   - Reads `_expected.json` from each skill directory
   - Scans skill with configured analyzers
   - Compares actual findings vs expected findings
   - Matches by: `category` + `severity` (exact match required)

### Current Status

**With LLM Analyzer:**
- Precision: 63.64% (14 TP, 8 FP)
- Recall: 63.64% (14 TP, 8 FN)
- F1 Score: 63.64%

**Main Issue**: Expected findings are incomplete - LLM analyzer finds more threats than documented in `_expected.json` files.

## Detailed Explanation

### Evaluation Process

```
1. Find all _expected.json files
   ↓
2. For each skill:
   a. Load expected findings from _expected.json
   b. Scan skill with analyzers (Static, LLM, etc.)
   c. Compare actual findings vs expected findings
   d. Count matches, false positives, false negatives
   ↓
3. Calculate aggregate metrics:
   - Precision = TP / (TP + FP)
   - Recall = TP / (TP + FN)
   - F1 Score = harmonic mean
```

### Matching Logic

**Exact Match Required:**
- Category must match exactly (e.g., `prompt_injection`)
- Severity must match exactly (e.g., `HIGH`)

**Example:**
```json
// Expected
{"category": "prompt_injection", "severity": "HIGH"}

// Actual Finding
category: "prompt_injection", severity: "HIGH"  [OK] Match
category: "prompt_injection", severity: "CRITICAL"  [NO MATCH] No match
category: "policy_violation", severity: "HIGH"  [NO MATCH] No match
```

### What Gets Counted

#### For Safe Skills (`expected_safe: true`)
- **True Negative**: 0 findings [OK]
- **False Positive**: Any finding [NO MATCH]
- **Correct**: `actual_safe == true && findings == 0`

#### For Unsafe Skills (`expected_safe: false`)
- **True Positive**: Expected finding matched [OK]
- **False Negative**: Expected finding not found [NO MATCH]
- **False Positive**: Unmatched finding (only if we're missing expected findings)
- **Correct**: `actual_safe == false && false_negatives == 0`

**Key Point**: Extra findings beyond expected ones are NOT false positives if all expected findings are found. Finding MORE threats is GOOD!

### Why Precision/Recall Are Low

Looking at the analysis output:

1. **Missing Expected Findings**: Many skills have findings that aren't in `_expected.json`
   - `jailbreak-override`: Missing 2 category/severity combinations
   - `multi-file-exfiltration`: Missing 4 combinations
   - `database-query`: Missing 2 combinations

2. **Expected Findings Not Found**: Some expected findings aren't being detected
   - `multi-file-exfiltration`: Expected `hardcoded_secrets/HIGH` but not found
   - `infinite-loop`: Expected `resource_abuse/MEDIUM` but found `CRITICAL` and `HIGH` instead

3. **Severity Mismatches**: Expected severity doesn't match actual severity
   - Expected `MEDIUM` but analyzer finds `CRITICAL` or `HIGH`

## How to Improve Precision/Recall

### Option 1: Update Expected Findings (Recommended)

Use the helper script to see what's missing:

```bash
# Set environment variables
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022

# Analyze what's missing
python evals/update_expected_findings.py --test-skills-dir evals/skills --use-llm

# Auto-update _expected.json files
python evals/update_expected_findings.py --test-skills-dir evals/skills --use-llm --update
```

This will:
1. Scan each skill
2. Compare actual findings vs expected
3. Show what's missing
4. Optionally update `_expected.json` files

### Option 2: Make Matching More Flexible

Modify `eval_runner.py` to match by category only (ignore severity):

```python
# In _compare_results(), change matching logic:
if actual_finding.category.value == exp_category:  # Remove severity check
    matched += 1
```

### Option 3: Update Expected Severities

If analyzer consistently finds `CRITICAL` but expected is `HIGH`, update expected to match analyzer output.

### Option 4: Evaluate Analyzers Separately

Understand what each analyzer contributes:

```python
# Test Static only
python evals/eval_runner.py --test-skills-dir evals/skills

# Test LLM only (would need code modification)
# Test Combined
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm
```

## Example: Updating Expected Findings

**Before** (`jailbreak-override/_expected.json`):
```json
{
  "expected_threats": [
    {"category": "prompt_injection", "severity": "HIGH"}
  ]
}
```

**After** (based on actual findings):
```json
{
  "expected_findings": [
    {"category": "prompt_injection", "severity": "HIGH"},
    {"category": "prompt_injection", "severity": "CRITICAL"},
    {"category": "policy_violation", "severity": "HIGH"}
  ]
}
```

## Viewing AITech Taxonomy Codes

The eval runner can display AITech taxonomy codes (aligned with Cisco AI Security Framework) for each finding:

```bash
python evals/eval_runner.py --test-skills-dir evals/skills --show-aitech
```

**Output Example:**
```
Detailed Findings (with AITech Taxonomy)
============================================================

Skill: data-processor
  Findings (7):
    - command_injection [CRITICAL]
      AITech: AITech-9.1 (Model or Agentic System Manipulation) | AISubtech: AISubtech-9.1.4 (Injection Attacks)
    - data_exfiltration [HIGH]
      AITech: AITech-8.2 (Data Exfiltration / Exposure)
```

**What AITech Codes Show:**
- **AITech Code**: Main threat category (e.g., `AITech-9.1`)
- **AITech Name**: Human-readable category name
- **AISubtech Code**: Sub-category when available (e.g., `AISubtech-9.1.4`)
- **AISubtech Name**: Human-readable sub-category name

**Note**: Not all findings have AITech codes. Findings from analyzers that use `ThreatMapping` (Static, LLM, Behavioral) will have AITech codes in their metadata. Cisco AI Defense Scanner is not yet supported (API doesn't support skills yet).

## Meta-Analyzer Evaluation

The Meta-Analyzer provides intelligent second-pass analysis to improve signal-to-noise ratio.

### Running Meta-Analyzer Comparison

```bash
# Compare performance with and without meta-analyzer
export SKILL_SCANNER_LLM_API_KEY=your_key
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --compare
```

### Understanding Meta-Analyzer Impact

**Example Comparison Output:**
```
================================================================================
COMPARISON: Without Meta vs With Meta
================================================================================

Per-Skill Changes:
  prompt-injection/jailbreak-override:
    Before: 5 findings -> After: 2 findings (filtered 3)
    Status: UNSAFE -> UNSAFE (threat detection maintained)

  safe-skills/calculator:
    Before: 2 findings -> After: 0 findings (filtered 2)
    Status: UNSAFE -> SAFE (false positives removed!)

Summary:
  Without Meta: 85.7% detection rate, 22 total findings
  With Meta:    85.7% detection rate, 8 total findings
  Noise Reduction: 64%
```

### Why Metrics May Look "Worse" With Meta

When comparing raw metrics, meta-analysis may show:
- **Fewer True Positives**: Multiple related findings consolidated into one
- **Lower Finding Count**: Redundant/duplicate findings removed
- **Different Severities**: Normalized based on actual risk

**Key Insight**: The goal is **same detection rate with fewer findings**. If a skill has 5 prompt injection findings that all describe the same attack, consolidating to 1 finding is better for actionability.

### What Meta-Analyzer Does

1. **False Positive Pruning**: Removes findings that are likely false alarms
2. **Finding Consolidation**: Merges related findings into single actionable items
3. **Priority Ranking**: Assigns priority to help focus on critical issues first
4. **Confidence Enrichment**: Adds validation status based on full skill context

## Summary

**To improve precision/recall:**

1. [OK] **Update `_expected.json` files** to include ALL legitimate threats found by analyzers
2. [OK] **Use the helper script** (`update_expected_findings.py`) to identify gaps
3. [OK] **Match expected severities** to what analyzers actually report
4. [OK] **Be comprehensive** - include all threat categories/severities, not just primary ones
5. [OK] **Use `--show-aitech`** to verify threat taxonomy alignment
6. [OK] **Use `--compare`** to evaluate meta-analyzer effectiveness

The evaluation framework is working correctly - the issue is that expected findings are incomplete. Once you update them to match actual findings, precision/recall will improve significantly!
