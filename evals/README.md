# Evaluation Framework

## Directory Layout

```
evals/
  runners/                  # Executable scripts
    benchmark_runner.py     # Eval-skills benchmark (accuracy, precision, recall, F1)
    eval_runner.py          # Per-skill evaluation with optional LLM / Meta analyzers
    policy_benchmark.py     # Policy comparison on the large corpus
    update_expected_findings.py  # Helper to refresh _expected.json files
  results/                  # Generated reports (git-ignored)
  skills/                   # Curated eval skills with _expected.json ground truth
  test_skills/              # Extra test-only skills
  policies/                 # Custom policy YAML files for policy_benchmark

.local_benchmark/
  corpus/                   # ~119 real-world skills (owner_repo naming)
  checkpoints/              # Timestamped benchmark JSON/MD snapshots
  archive/                  # Old results and legacy checkpoints
```

## Quick Start

```bash
# Run the eval-skills benchmark (fast, ~30 s, no API key needed)
make benchmark-eval

# Run the full corpus policy benchmark (~9 min)
make benchmark-corpus

# Run both
make benchmark

# Run the test suite
make test
```

All benchmark results are automatically tagged with the current git commit hash
and stored in `.local_benchmark/checkpoints/`.

## Eval-Skills Benchmark

Tests scanner accuracy against a curated set of skills with known ground truth.

```bash
# Static analyzers only (default)
uv run python evals/runners/benchmark_runner.py

# Save JSON results
uv run python evals/runners/benchmark_runner.py --output results.json
```

### How It Works

1. Loads `_expected.json` from each skill in `evals/skills/`.
2. Scans the skill with the configured analyzers.
3. Compares actual findings vs. expected findings (category + severity exact match).
4. Computes aggregate metrics: accuracy, precision, recall, F1.

### Matching Rules

- **Category + severity** must match exactly.
- Extra findings beyond expected ones are **not** counted as false positives when
  all expected findings are found (finding more threats is good).
- For safe skills (`expected_safe: true`), any finding is a false positive.

## Policy Benchmark

Compares default, strict, and permissive policies (plus any custom policies in
`evals/policies/`) across the large corpus in `.local_benchmark/corpus/`.

```bash
# Default run (all policies, markdown + JSON output)
uv run python evals/runners/policy_benchmark.py

# Single policy
uv run python evals/runners/policy_benchmark.py \
  --policies evals/policies/04_compliance_audit.yaml

# Custom corpus path
uv run python evals/runners/policy_benchmark.py \
  --corpus /path/to/skills
```

## Eval Runner (detailed per-skill evaluation)

```bash
# Static analyzers only
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills

# With LLM analyzer
export SKILL_SCANNER_LLM_API_KEY=your_key
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills --use-llm

# With Meta-Analyzer (false-positive filtering)
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills --use-llm --use-meta

# Compare with/without Meta-Analyzer
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills --use-llm --compare

# Show AITech taxonomy codes
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills --show-aitech
```

## Updating Expected Findings

When analyzer output changes (new rules, improved detection), refresh the ground
truth so metrics stay meaningful:

```bash
# Dry-run: see what differs
uv run python evals/runners/update_expected_findings.py \
  --test-skills-dir evals/skills --use-llm

# Auto-update _expected.json files
uv run python evals/runners/update_expected_findings.py \
  --test-skills-dir evals/skills --use-llm --update
```

## Expected Results Format

Each eval skill directory contains an `_expected.json`:

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
    }
  ],
  "notes": "Optional context"
}
```

## Metrics Reference

| Metric    | Formula                       | Meaning                                |
|-----------|-------------------------------|----------------------------------------|
| Precision | TP / (TP + FP)                | Of all findings, how many were correct |
| Recall    | TP / (TP + FN)                | Of all expected threats, how many found|
| F1        | 2 * P * R / (P + R)          | Balanced precision/recall              |
| Accuracy  | (TP + TN) / (TP + TN + FP + FN) | Overall correctness                |
