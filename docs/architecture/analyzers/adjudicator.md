# Adjudicator

The Adjudicator is an optional pass that runs **between the deterministic analyzers and the LLM analyzer**. For each deterministic HIGH/CRITICAL finding it asks an LLM whether the file around the matched line actually contains the threat the rule was designed to catch, or whether the regex fired on benign content. Findings the LLM identifies as literal-regex false positives are demoted to `INFO` for downstream verdict computation.

## Overview

When enabled via the `--adjudicate` CLI flag (or `ScanPolicy.adjudicator.enabled = True` on the API), the Adjudicator performs:

- **False positive demotion**: Uses an LLM to reason about whether a deterministic HIGH/CRITICAL match represents a real instance of the threat, or a coincidental regex hit on benign prose.
- **Cascade prevention**: Because it runs before the LLM analyzer, demoted findings never enter the LLM analyzer's static-finding enrichment context — so a wrong deterministic HIGH cannot be amplified into LLM findings citing the same pattern hit.
- **Audit trail**: Every finding it considers is recorded in `scan_metadata.adjudicator.audit` with the LLM's verdict, confidence, and reason.

The adjudicator only touches deterministic findings (static, pipeline, behavioral, bytecode, yara analyzers) at HIGH or CRITICAL severity. LLM and other advisory findings are outside its scope.

## Safety property

**The Adjudicator is demote-only.** It can lower a finding's severity to `INFO`, and can never raise a finding's severity.

The demote-only constraint bounds the failure surface. On **error paths** — LLM unavailable, timeout, malformed JSON, unexpected verdict, out-of-range confidence, path-escape attempt — the finding stays at its original severity and no metadata is written. Those specific paths cannot introduce false negatives.

**A wrong `false_positive` verdict from the LLM itself can still demote a real threat.** That is a genuine failure mode and is why the pass is off by default, why the confidence threshold is configurable, and why every demotion is preserved in `finding.metadata["adjudication"]` for review and override. Adversarial content in the scanned skill can also attempt to bias the adjudicator (see the system-prompt hardening in the implementation) — again, the worst case is a real finding demoted to `INFO`, but this is a real (not zero-probability) risk that operators should weigh when enabling the pass.

## How It Works

1. **Deterministic analyzers run first** (static, pipeline, behavioral, bytecode, yara). This is unchanged.
2. **Adjudicator inspects HIGH/CRITICAL findings from those analyzers.** For each finding it:
   - Extracts the matched line and a wide surrounding context (whole file for files ≤ 600 lines, ± 25 lines otherwise). The wide window makes the adjudicator resilient to the scanner's occasional off-by-N line-number reports on markdown content.
   - Pulls the rule's `description`, `category`, and `default_severity` from the rule registry.
   - Sends both to the LLM with a fixed prompt asking `real` vs `false_positive`, a 1–5 confidence, and a one-sentence reason.
3. **Demotes on high-confidence FP verdicts.** If the LLM returns `verdict = "false_positive"` and `confidence >= min_fp_confidence` (default 3), the finding's severity is lowered to `INFO`. The original severity is preserved in `finding.metadata["adjudication"]["original_severity"]` for audit.
4. **LLM analyzer runs next** (if enabled). Its `static_findings_summary` enrichment now excludes demoted findings, so the LLM analyzer cannot cross-confirm a false-positive deterministic HIGH.
5. **The rest of the pipeline is unchanged**: severity overrides, disabled rules, analyzability, deduplication, policy fingerprinting.

## CLI Usage

```bash
# Basic — deterministic analyzers only, with adjudicator active
skill-scanner scan /path/to/skill --adjudicate

# Full stack — adjudicator gates the LLM analyzer's static enrichment
skill-scanner scan /path/to/skill --use-llm --adjudicate

# Full stack with meta-analysis
skill-scanner scan /path/to/skill --use-llm --enable-meta --adjudicate
```

**Requirements:**

- An LLM model must be configured via `SKILL_SCANNER_LLM_MODEL` (or `SKILL_SCANNER_ADJUDICATOR_LLM_MODEL` to override for the adjudicator specifically).
- API key via `SKILL_SCANNER_LLM_API_KEY` for providers that need one; AWS credentials for `bedrock/...` models.
- LiteLLM must be installed.

If any of the above are missing, the adjudicator logs a debug message and skips every finding — the scan behaves identically to a run with `--adjudicate` off. This is intentional: unavailability is not an error, it's a no-op.

## Configuration

The Adjudicator is configured via `AdjudicatorPolicy` on the `ScanPolicy`:

```yaml
adjudicator:
  enabled: false        # master toggle; --adjudicate CLI flag also sets this
  min_fp_confidence: 3  # 1-5; LLM confidence required to demote (default 3)
```

Environment variables (in order of precedence):

- `SKILL_SCANNER_ADJUDICATOR_LLM_MODEL` — model override specific to the adjudicator
- `SKILL_SCANNER_ADJUDICATOR_LLM_TEMPERATURE` — temperature override, or `"none"` to omit
- `SKILL_SCANNER_LLM_MODEL` — fallback if the adjudicator-specific var is unset
- `SKILL_SCANNER_LLM_TEMPERATURE` — fallback if the adjudicator-specific var is unset

## Output

Demoted findings appear in the final report with:

- `severity: "INFO"` (the effective severity used for verdict computation)
- `metadata.adjudication`:
  - `original_severity`: what it was before demotion (e.g. `"HIGH"`)
  - `verdict`: `"false_positive"`
  - `confidence`: `1-5`
  - `reason`: one-sentence rationale from the LLM
  - `demoted_to`: `"INFO"`
  - `model_id`: which model made the decision

The scan's `scan_metadata.adjudicator` section summarizes the pass:

```json
{
  "adjudicator": {
    "considered": 4,
    "demoted": 1,
    "audit": [
      {
        "rule_id": "PROMPT_INJECTION_CONCEALMENT",
        "verdict": "false_positive",
        "confidence": 5,
        "reason": "The phrase 'do not notify the user' refers to a routine pre-flight column-update succeeding silently; the write itself is visible.",
        "demoted_to": "INFO",
        "model_id": "bedrock/converse/anthropic.claude-opus-4-8-20240229-v1:0"
      },
      ...
    ]
  }
}
```

## Cost

Per skill: 0–3 LLM calls × ~200 input tokens + ~50 output tokens ≈ $0.005 on Opus 4.x. Negligible relative to the existing LLM analyzer + meta-analyzer cost.

## Concurrency

The adjudicator uses a module-level lock to serialize its LLM calls across parallel workers. This prevents adjudicator calls from competing with the main LLM analyzer's calls for backend rate limits. Because adjudicator calls are short (~250 output tokens) and rare (0–3 per skill), the serialization overhead is at most a few seconds per scan and eliminates a class of transient 5xx-induced regressions.

## When to enable

- **Yes**: when your policy treats deterministic HIGH+ as auto-reject and false positives on that class of finding are causing real friction for reviewers.
- **Yes**: when you're running the LLM analyzer and observing findings that cite deterministic pattern hits (the "confirmation cascade" failure mode).
- **Maybe**: for CI gating where you accept a small per-scan LLM cost in exchange for fewer benign auto-rejects.
- **No**: for pure deterministic gates that never enable LLM analysis anyway — the adjudicator has nothing to demote that would matter.

## Relation to other analyzers

- **Adjudicator vs. Meta-analyzer**: they solve different problems and can be enabled together. The adjudicator runs *before* the LLM analyzer and demotes deterministic false positives at their source. The meta-analyzer runs *after* all analyzers and re-scores or correlates the full finding set. Both can be on simultaneously; they don't conflict.
- **Adjudicator vs. `--llm-consensus-runs`**: consensus reduces run-to-run flap on LLM findings by voting across N runs of the LLM analyzer. Consensus does not affect deterministic findings and does not address the cross-analyzer confirmation cascade. The adjudicator addresses a different failure mode and is complementary.
