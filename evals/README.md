# Evaluation Framework

## Overview

The `evals/` directory contains the evaluation framework for testing the accuracy and effectiveness of the Skill Scanner's threat detection capabilities.

Mirrors the structure of [MCP Scanner's evals](https://github.com/cisco-ai-defense/mcp-scanner/tree/main/evals).

## Purpose

Evaluations measure:
1. **Detection Rate**: How many threats are caught
2. **False Positive Rate**: How many safe skills are flagged incorrectly
3. **Analyzer Accuracy**: Performance of each analyzer (static, LLM, behavioral, meta)
4. **Severity Calibration**: Whether severity levels are appropriate
5. **Meta-Analyzer Impact**: How much noise reduction while maintaining detection

## Structure

```
evals/
├── test_skills/           # Curated test skills with known threats
│   ├── safe/             # Skills that should pass
│   ├── malicious/        # Skills with known vulnerabilities
│   └── edge_cases/       # Tricky cases
├── eval_runner.py        # Main evaluation runner
├── metrics.py            # Accuracy metrics calculation
└── results/              # Evaluation results (gitignored)
```

## Running Evaluations

```bash
# Run full evaluation suite (static analyzer only)
python evals/eval_runner.py --test-skills-dir evals/skills

# Run with LLM analyzer
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm

# Run with Meta-Analyzer (filters false positives, consolidates findings)
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --use-meta

# Compare performance with and without Meta-Analyzer
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --compare

# Show AITech taxonomy codes in findings
python evals/eval_runner.py --test-skills-dir evals/skills --show-aitech

# Generate report
python evals/eval_runner.py --test-skills-dir evals/skills --output results/eval_report.json
```

### Environment Variables

```bash
# Required for LLM and Meta analyzers
export SKILL_SCANNER_LLM_API_KEY=your_api_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022

# For Azure OpenAI
export SKILL_SCANNER_LLM_BASE_URL=https://your-resource.openai.azure.com/
export SKILL_SCANNER_LLM_API_VERSION=2025-01-01-preview

# Optional: Use different model for meta-analysis
export SKILL_SCANNER_META_LLM_API_KEY=different_key
export SKILL_SCANNER_META_LLM_MODEL=gpt-4o
```

## Test Skill Categories

### Safe Skills (Should Pass)
- Simple calculator
- Text formatter
- File reader (safe paths only)
- Data validator

### Malicious Skills (Should Detect)
- Prompt injection attempts
- Data exfiltration
- Command injection
- Hardcoded secrets
- Binary executables

### Edge Cases
- Legitimate network usage (declared)
- Base64 for valid reasons
- Complex but safe code
- Borderline severity cases

## Metrics

### Detection Metrics
- **True Positives (TP)**: Correctly identified threats
- **False Positives (FP)**: Safe skills flagged as threats
- **True Negatives (TN)**: Correctly identified safe skills
- **False Negatives (FN)**: Missed threats

### Calculated Metrics
- **Precision**: TP / (TP + FP) - Accuracy of threat detection
- **Recall**: TP / (TP + FN) - Coverage of actual threats
- **F1 Score**: Harmonic mean of precision and recall
- **Accuracy**: (TP + TN) / Total

### Target Metrics
- Precision: > 90%
- Recall: > 95%
- F1 Score: > 92%
- False Negative Rate: < 5%

## Evaluation Process

1. **Load Test Skills**: Load curated skills with known ground truth
2. **Run Analyzers**: Scan each skill with configured analyzers
3. **Compare Results**: Match findings against expected threats
4. **Calculate Metrics**: Compute precision, recall, F1
5. **Generate Report**: Output detailed evaluation results

## Adding Test Skills

To add a new test skill:

1. Create skill directory in appropriate category
2. Add SKILL.md with known threats
3. Document expected findings in `_expected.json`:

```json
{
  "skill_name": "test-skill",
  "expected_safe": false,
  "expected_findings": [
    {
      "category": "prompt_injection",
      "severity": "HIGH",
      "description": "Contains 'ignore previous instructions'"
    }
  ]
}
```

4. Run evaluation to verify detection

## Meta-Analyzer Evaluation

The Meta-Analyzer provides a second-pass analysis to filter false positives and consolidate redundant findings.

### Running Meta-Analyzer Comparison

```bash
# Compare with and without meta-analyzer
python evals/eval_runner.py --test-skills-dir evals/skills --use-llm --compare
```

**Example Output:**
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
  Without Meta: 85.7% detection, 22 total findings
  With Meta:    85.7% detection, 8 total findings (64% noise reduction)
```

### Understanding Meta-Analyzer Metrics

When using `--compare`, metrics may appear "worse" with meta-analysis because:

1. **Finding Consolidation**: Multiple related findings are merged into one actionable item
2. **False Positive Removal**: Legitimate patterns flagged by static analysis are filtered
3. **Severity Normalization**: Redundant severity escalations are removed

**Key Insight**: The goal is maintaining **detection rate** (catching real threats) while reducing **noise** (fewer false positives). A lower finding count with the same detection rate is actually better.

## Future Enhancements

- Automated test skill generation
- Adversarial testing (evolving attacks)
- Benchmark against other scanners
- Continuous evaluation in CI/CD
- Performance benchmarking
- Meta-analyzer tuning based on evaluation results

## References

- MCP Scanner Evals: https://github.com/cisco-ai-defense/mcp-scanner/tree/main/evals
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
