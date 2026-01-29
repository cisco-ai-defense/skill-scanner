# Evaluation Framework Guide

## How Evaluation Works

### Overview

The evaluation framework (`evals/eval_runner.py`) tests analyzer accuracy by comparing actual scan results against expected ground truth defined in `_expected.json` files.

### Evaluation Process

1. **Load Expected Results**: Reads `_expected.json` from each skill directory
2. **Run Scanners**: Scans skill with configured analyzers (Static, LLM, Behavioral)
3. **Compare Results**: Matches actual findings against expected findings
4. **Calculate Metrics**: Computes precision, recall, F1 score, etc.

### Analyzer Configuration

The evaluation can run with different analyzer combinations:

#### Static Analyzer Only (Default)
```bash
python evals/eval_runner.py --test-skills-dir evals/skills
```
- Uses `StaticAnalyzer` (includes YARA rules, pattern matching)
- Fast, no API calls needed
- Good for testing YARA rules and static patterns

#### Static + LLM Analyzer
```bash
export SKILL_SCANNER_LLM_API_KEY=your_key
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm
```
- Uses `StaticAnalyzer` + `LLMAnalyzer`
- Combines pattern matching with semantic analysis
- More comprehensive but slower (API calls)

#### With Meta-Analyzer (False Positive Filtering)
```bash
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --use-meta
```
- Adds `MetaAnalyzer` for second-pass analysis
- Filters false positives, consolidates redundant findings
- Best for production-quality results with reduced noise

#### Compare With/Without Meta-Analyzer
```bash
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --compare
```
- Runs evaluation twice: with and without meta-analysis
- Shows per-skill changes and overall impact
- Validates meta-analyzer is reducing noise without missing threats

#### Static + Behavioral Analyzer
```python
# Would need to add --use-behavioral flag
# Uses dataflow analysis for cross-file threats
```

### Expected Results Format

Each skill directory should have an `_expected.json` file:

```json
{
  "skill_name": "skill-name",
  "expected_safe": false,
  "expected_severity": "CRITICAL",
  "expected_findings": [
    {
      "category": "prompt_injection",
      "severity": "HIGH",
      "description": "Contains instruction override attempt"
    },
    {
      "category": "data_exfiltration",
      "severity": "CRITICAL",
      "description": "Sends data to external server"
    }
  ],
  "notes": "Additional context about the skill"
}
```

**Note**: The framework supports both `expected_findings` and `expected_threats` keys for backward compatibility.

### Matching Logic

The evaluation matches findings based on:

1. **Category Match**: Finding category must match expected category
2. **Severity Match**: Finding severity must match expected severity
3. **One-to-One Matching**: Each expected finding matches at most one actual finding

**Example**:
- Expected: `{category: "prompt_injection", severity: "HIGH"}`
- Actual: `{category: "prompt_injection", severity: "HIGH"}` [OK] Match
- Actual: `{category: "prompt_injection", severity: "CRITICAL"}` [NO MATCH] No match (severity mismatch)

### Metrics Calculation

#### For Safe Skills (`expected_safe: true`)
- **True Negative (TN)**: No findings detected [OK]
- **False Positive (FP)**: Any finding detected [NO MATCH]
- **Correct**: `actual_safe == true && false_positives == 0`

#### For Unsafe Skills (`expected_safe: false`)
- **True Positive (TP)**: Expected finding matched [OK]
- **False Negative (FN)**: Expected finding not found [NO MATCH]
- **False Positive (FP)**: Unmatched finding (only if we're also missing expected findings)
- **Correct**: `actual_safe == false && false_negatives == 0`

**Important**: Extra findings beyond expected ones are NOT counted as false positives if all expected findings are found. This is because finding MORE threats is actually GOOD!

### Precision and Recall

- **Precision** = TP / (TP + FP)
  - Measures: "Of all findings, how many were correct?"
  - High precision = Low false positive rate

- **Recall** = TP / (TP + FN)
  - Measures: "Of all expected threats, how many did we find?"
  - High recall = Low false negative rate

- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall)
  - Harmonic mean of precision and recall
  - Balanced metric

### Current Issues and Solutions

#### Issue 1: Low Precision/Recall

**Problem**: Expected findings might be incomplete - LLM analyzer finds more threats than documented.

**Solution**: Update `_expected.json` files to include all legitimate threats found by analyzers.

**Example**: If LLM finds 5 threats but `_expected.json` only lists 2, update it to include all 5.

#### Issue 2: Severity Mismatches

**Problem**: Expected severity might be "HIGH" but analyzer reports "CRITICAL".

**Solution**: Either:
- Update expected severity to match analyzer output
- Or make matching more flexible (category-only matching)

#### Issue 3: Category Variations

**Problem**: Analyzer uses different category names than expected.

**Solution**: The framework already has category mapping (e.g., `sql_injection` → `command_injection`).

### Improving Precision/Recall

#### 1. Update Expected Findings

Review actual findings and update `_expected.json`:

```bash
# Scan a skill and see what it finds
python -m skill_scanner.cli.cli scan evals/skills/prompt-injection/jailbreak-override --use-llm --format json > actual_findings.json

# Compare with expected and update _expected.json
```

#### 2. Use Flexible Matching

Consider matching by category only (ignore severity) for some evaluations:

```python
# In eval_runner.py, could add:
match_by_category_only = True  # Option to match by category only
```

#### 3. Separate Analyzer Evaluation

Evaluate each analyzer separately to understand their strengths:

```python
# Test Static only
python evals/eval_runner.py --test-skills-dir evals/skills

# Test LLM only (would need modification)
# Test Static + LLM
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm
```

#### 4. Expected Findings Best Practices

- **Be Comprehensive**: Include ALL legitimate threats, not just primary ones
- **Match Analyzer Output**: If analyzer finds CRITICAL, expect CRITICAL
- **Use Correct Categories**: Match the ThreatCategory enum values
- **Document Patterns**: Use `threat_patterns` array to document attack patterns

### Example: Updating Expected Findings

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

### Running Evaluations

```bash
# Set environment variables
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022

# Basic evaluation (Static analyzer only)
python evals/eval_runner.py --test-skills-dir evals/skills

# With LLM analyzer
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm

# With Meta-Analyzer (filters false positives)
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --use-meta

# Compare with and without meta-analyzer
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --compare

# Save results
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --output results.json
```

### Understanding Results

```
Metrics:
  accuracy: 90.91%      # Overall correctness
  precision: 66.67%     # TP / (TP + FP) - Low false positives
  recall: 66.67%        # TP / (TP + FN) - Low false negatives
  f1_score: 66.67%      # Balanced metric
  true_positives: 2     # Correctly found threats
  false_positives: 1    # Incorrect findings
  true_negatives: 2     # Correctly identified safe skills
  false_negatives: 1    # Missed threats
```

### Recommendations

1. **Update Expected Findings**: Review actual LLM findings and update `_expected.json` files to be comprehensive
2. **Test Separately**: Evaluate Static vs LLM vs Combined to understand each analyzer's contribution
3. **Use Meta-Analyzer**: Run with `--use-meta` for production-quality results with fewer false positives
4. **Compare Impact**: Use `--compare` to validate meta-analyzer is effective for your skill set
5. **Category Flexibility**: Consider matching by category only for some evaluations
6. **Document Patterns**: Use `threat_patterns` to document attack patterns even if not matching on them
