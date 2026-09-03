# Evaluation Framework

## Directory Layout

```
evals/
  runners/                  # Executable scripts
    benchmark_runner.py     # Eval-skills benchmark (accuracy, precision, recall, F1)
    eval_runner.py          # Per-skill evaluation with optional LLM / Meta analyzers
    policy_benchmark.py     # Policy comparison on the large corpus
    update_expected_findings.py  # Reviewer-only scanner observation report
  datasets/                 # Locked public-corpus metadata and safe adapters
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
uv run --no-sync python evals/runners/benchmark_runner.py

# Save JSON results
uv run --no-sync python evals/runners/benchmark_runner.py --output results.json
```

### How It Works

1. Loads `_expected.json` from each skill in `evals/skills/`.
2. Scans the skill with the configured analyzers.
3. Compares expected and actual findings with one-to-one identity matching.
4. Computes finding-level micro/macro metrics, exact per-category metrics,
   package block/signal recall, benign actionable false-positive rate, Wilson
   confidence intervals, and latency/CEL overhead.

### Matching Rules

- The canonical identity is `rule_id`, `category`, `severity`, `file_path`,
  `line_number` or `evidence_id`, and `analyzer`.
- Schema-v2 expectations use complete canonical identities. Historical files
  remain usable only when explicitly marked `legacy_degraded`; omitted fields
  are wildcards and every field that is present must match exactly.
- Matching is maximum-cardinality and one-to-one. One actual finding cannot
  satisfy two expectations.
- Every unmatched actual finding is a false positive and every unmatched
  expectation is a false negative, for both safe and unsafe skills.
- Fixture, scanner, and comparison errors remain in the skill denominator and
  fail the run. Once an expectation has loaded, a scan error counts all of its
  expected findings as false negatives.

## Policy Benchmark

Compares default, strict, and permissive policies (plus any custom policies in
`evals/policies/`) across the large corpus in `.local_benchmark/corpus/`.

```bash
# Default run (all policies, markdown + JSON output)
uv run --no-sync python evals/runners/policy_benchmark.py

# Single policy
uv run --no-sync python evals/runners/policy_benchmark.py \
  --policies evals/policies/04_compliance_audit.yaml

# Custom corpus path
uv run --no-sync python evals/runners/policy_benchmark.py \
  --corpus /path/to/skills
```

## Eval Runner (detailed per-skill evaluation)

For authoritative local LLM or Meta evidence, set `OLLAMA_MODEL_DIGEST` to
the exact 64-character lowercase SHA-256 digest reported by Ollama. A mutable
model tag alone is accepted only for non-authoritative exploration.

```bash
# Static analyzers only
uv run --no-sync python evals/runners/eval_runner.py --test-skills-dir evals/skills

# With the local Ollama LLM analyzer (hosted providers are rejected)
uv run --no-sync python evals/runners/eval_runner.py \
  --test-skills-dir evals/skills --use-llm \
  --ollama-model ollama/qwen3.5:9b-mlx \
  --ollama-model-digest "$OLLAMA_MODEL_DIGEST" \
  --ollama-base-url http://127.0.0.1:11434

# With Meta-Analyzer (false-positive filtering)
uv run --no-sync python evals/runners/eval_runner.py \
  --test-skills-dir evals/skills --use-llm --use-meta \
  --ollama-model ollama/qwen3.5:9b-mlx \
  --ollama-model-digest "$OLLAMA_MODEL_DIGEST" \
  --ollama-base-url http://127.0.0.1:11434 --meta-seed 0

# Compare with/without Meta-Analyzer
uv run --no-sync python evals/runners/eval_runner.py \
  --test-skills-dir evals/skills --use-llm --compare \
  --ollama-model ollama/qwen3.5:9b-mlx \
  --ollama-model-digest "$OLLAMA_MODEL_DIGEST" \
  --ollama-base-url http://127.0.0.1:11434 --meta-seed 0

# Show AITech taxonomy codes
uv run --no-sync python evals/runners/eval_runner.py --test-skills-dir evals/skills --show-aitech
```

## Reviewing Expected Findings

Ground truth must not be generated from the scanner being evaluated. The helper
produces a scanner-observation report for an independent attester; it never
rewrites an `_expected.json` file:

```bash
uv run --no-sync python evals/runners/update_expected_findings.py \
  --test-skills-dir evals/skills --output evals/results/review-candidates.json
```

Before editing ground truth, bind the source evidence and stable identity fields
to one supported attestation: an immutable public label, two-pass local Ollama
agreement, an independent agent label, or human review. Scanner output is
diagnostic evidence only and never the label source.

## Expected Results Format

Each eval skill directory contains an `_expected.json`:

The machine-readable contract is `evals/expectation.schema.json`; the Python
validator is authoritative for fixture hash verification and is invoked by both
evaluation runners before a scan begins.

```json
{
  "schema_version": 2,
  "evaluation_quality": "strict",
  "case_id": "prompt-injection.override-001",
  "skill_name": "skill-name",
  "package_label": "malicious",
  "expected_verdict": "unsafe",
  "expected_severity": "CRITICAL",
  "provenance": {
    "source": "first-party-inert-fixture",
    "license": "Apache-2.0",
    "fixture_sha256": "<canonical lowercase SHA-256>",
    "label_source": "agent_labeled",
    "scanner_independent": true,
    "label_provenance_sha256": "<canonical lowercase SHA-256>",
    "label_evidence_sha256": "<canonical lowercase SHA-256>"
  },
  "expected_findings": [
    {
      "rule_id": "PROMPT_INJECTION_OVERRIDE",
      "category": "prompt_injection",
      "severity": "HIGH",
      "file_path": "SKILL.md",
      "line_number": 12,
      "analyzer": "static",
      "description": "Contains instruction override attempt"
    }
  ],
  "notes": "Optional context"
}
```

Strict schema-v2 cases require `case_id`, `package_label` (`benign`,
`malicious`, or `contextual_risk`), `expected_verdict` (`safe` or `unsafe`),
complete finding identities, and provenance. `fixture_sha256` is calculated
over every fixture file except `_expected.json`, framing the relative path,
byte length, and content. `label_source` is exactly one of `public_labeled`,
`independent_ollama`, `agent_labeled`, or `human_reviewed`, and
`scanner_independent` must be exactly `true`; scanner output is not a label
source. The two label hashes independently bind the declared origin and the
asserted verdict/finding identities. Use `fixture_sha256()` and
`bind_label_attestation()` from `evals.runners.finding_matcher` when preparing
an attested expectation.

`evals/skills` contains 24 schema-v2 strict release goldens covering all 17
finding categories and every finding severity (CRITICAL, HIGH, MEDIUM, LOW,
and INFO). The separate `evals/test_skills` smoke corpus retains three explicit
schema-v1 `legacy_degraded` expectations; those fixtures remain visible in
legacy metrics but never count as release-grade ground truth. Do not add strict
fields to a legacy record piecemeal: migrate the complete expectation as one
attested schema-v2 change.

## Official Bundled-Skill Goodware Audit

`official_bundled_skills_benchmark.py` is an offline benign hard-negative
audit for locally installed, verifiably first-party agent-tool skill bundles.
Its strict profile and aggregate lock record source/revision/version/license
provenance plus file and package hashes; vendor source is scanned in place and
is never copied into this repository. Community and user-authored skills are
out of scope, even when they share the same marketplace or cache root.

```bash
uv run --no-sync python evals/runners/official_bundled_skills_benchmark.py run \
  --profile evals/datasets/official-bundled-skills.profile.json \
  --lock evals/datasets/official-bundled-skills.lock.json \
  --output /absolute/path/to/official-goodware.json
```

The runner defaults to the release-scoped core detector in CEL OFF and SHADOW;
an explicit full-pack run is optional supplemental evidence. It reports exact MEDIUM+ and HIGH+ per-rule,
analyzer, package, path, and line attribution; source-group Wilson intervals;
CEL decision/error/timing telemetry; and exact OFF/SHADOW finding and load-error
identity deltas. Scanner and loader failures remain in the denominator. A lock
or provenance mismatch fails before scanning. This corpus is authoritative
only for first-party compatibility and false-positive mining: it cannot measure
malicious recall, precision, or F1, and it must never justify vendor-name
allowlists.

## Public Dataset Inputs

Public dataset revisions, approved uses, licenses, row counts, and schemas are
locked in `evals/datasets/public-datasets.lock.json`. See
`evals/datasets/README.md` before adding or refreshing a corpus. Dataset helpers
are offline-only, reject schema/revision drift and unsafe paths, and materialize
text with non-executable permissions. Pull-request jobs must not download public
corpora.

The offline public runner reports package blocking (CRITICAL/HIGH) separately
from signal recall (LOW and above), actionable benign false positives (MEDIUM
and above), per-source/family/category results, Wilson intervals, stable sample
outcomes, and complete CEL shadow/runtime/generation telemetry. Use
`compare_benchmark_reports` for population-locked old/current comparisons and
`compare_repeated_benchmark_reports` for the required five-run stability and
per-rule candidate telemetry. Supply its explicit `promoted_rule_ids` set and a
matching `rule_fixture_evidence` mapping from the attested committed fixtures;
other shadow rules remain telemetry-audited but cannot accidentally enter the
promotion decision. Raw `would_suppress` or enforce-mode `cel_suppressed`
candidates do not prove that a normalized finding disappeared: equivalent
support may survive in the same normalized issue. The comparator reports those
observations under `observed_*_candidates`, marks normalized-loss evidence
unavailable, and makes the rule ineligible. Boundary coverage is never inferred
from a runtime fallback on the mandatory corpus. Every run revalidates the scanner build, policy,
rules, producer metadata, frozen snapshot manifest, and artifact inventory
after scanning; any mid-run identity drift fails comparison and release gates
without removing samples from metric denominators. Release promotion
requires exactly five clean frozen-generation runs with identical non-timing
output plus one complete pinned public release-corpus run through
`release_gate.py`. Private/source-disjoint evidence is optional and reported
separately; it never changes the hard public result.

Run the two lock-pinned detector configurations without network access:

```bash
uv run --no-sync python evals/runners/public_dataset_benchmark.py \
  --snapshot-dir /absolute/path/to/frozen-snapshot \
  --dataset-id ProtectSkills/MaliciousSkillBench \
  --cel-mode shadow \
  --output /absolute/path/to/public-shadow.json
```

### Non-release CEL promotion audit

`cel_promotion_audit.py` is a development-only shadow audit. It selects a row
only when both `source_disjoint` and `m_structural_disjoint` place it in
`train` or `validation`; `test` or `excluded` in either protocol excludes the
row. Declared rows and exact quarantined members are reported separately. The
runner launches one isolated CEL-OFF worker and five isolated CEL-SHADOW
workers, then writes bounded compact-v3 evidence:

```bash
SKILL_SCANNER_SOURCE_REVISION="$(git rev-parse HEAD)" \
uv run --no-sync python evals/runners/cel_promotion_audit.py run \
  --snapshot-dir /absolute/path/to/frozen-malicious-skill-bench \
  --dataset-id ProtectSkills/MaliciousSkillBench \
  --dataset-lock evals/datasets/public-datasets.lock.json \
  --expected-rule-count 8 \
  --output-dir /absolute/new/path/to/cel-promotion-audit
```

The explicit count is the current validated bundled CEL generation. Re-run
`uv run --no-sync skill-scanner validate-rules` and update the argument when that generation
changes; the audit fails closed if the observed set differs. The output
directory must not exist and contains `off.json`, `shadow-1.json` through
`shadow-5.json`, and `audit-summary.json`. This train/validation result can
guide rule tuning, but it is never release-blocking evidence and cannot replace
the frozen public holdout, source-disjoint release corpus, or attested fixture
requirements.

The optional attestation bundle is needed before a rule that would suppress a
HIGH/CRITICAL candidate in a malicious-labeled package can be considered for
promotion. Schema v1 binds the exact dataset snapshot and usable population,
scanner build/policy/rules/source revision, CEL generation and per-rule
expression hashes, candidate set, sample identity and content, normalized
finding/lineage identity, and model/prompt/options/rubric/provenance hashes.
Its `label_source` is exactly `independent_ollama` or `agent_labeled`; every
candidate carries two distinct seeded passes with request/response hashes.
The binding declares a nonempty per-rule expression scope. Every audited
candidate for each declared rule must be present; rules outside that explicit
scope remain `not_supplied` and ineligible rather than being mislabeled.
Only exact agreement on `benign_non_actionable`, with a matching benign
deterministic check, can satisfy the rule. Missing coverage makes affected
rules ineligible; partial coverage within a declared rule, duplicate, spoofed,
stale, or tampered supplied bundles fail assembly. Omit the option for an initial audit, generate the
bundle from the five identical shadow candidate sets, then rerun `assemble`
with the same `off.json` and five `shadow-*.json` files. These attestations are
development evidence only and cannot substitute for release or held-out
evidence.

```bash
uv run --no-sync python evals/runners/cel_promotion_audit.py assemble \
  --baseline /absolute/path/to/audit/off.json \
  --candidate /absolute/path/to/audit/shadow-1.json \
  --candidate /absolute/path/to/audit/shadow-2.json \
  --candidate /absolute/path/to/audit/shadow-3.json \
  --candidate /absolute/path/to/audit/shadow-4.json \
  --candidate /absolute/path/to/audit/shadow-5.json \
  --candidate-attestations /absolute/path/to/candidate-attestations.json \
  --expected-rule-count 8 \
  --output /absolute/new/path/to/attested-audit-summary.json
```

Administrator-approved schema-v2 packs can be measured as a third, explicitly
non-blocking configuration by repeating `--trusted-rule-pack`:

```bash
uv run --no-sync python evals/runners/public_dataset_benchmark.py \
  --snapshot-dir /absolute/path/to/frozen-snapshot \
  --dataset-id ProtectSkills/MaliciousSkillBench \
  --trusted-rule-pack /absolute/path/to/local-pack \
  --cel-mode shadow \
  --output /absolute/path/to/public-with-local-extension.json
```

The normal `tracks` and `summary` contain exactly the locked `core_only`
measurement. Local and optional bundled packs are added only under the separate
`locally_extended` report, which mirrors the locked core-only population and
records a path-independent content hash for the complete trusted-pack set.
Pack paths must be unique, non-symlink directories disjoint from the snapshot;
strict pack validation, a mid-run rehash, or any scanner error fails the run.
Locally extended data is deliberately excluded from compact mandatory release
evidence and never changes the public release result.

Mandatory release reports use the canonical `compact-v3` representation.
Full diagnostic findings retain complete CEL lineage. In compact evidence,
`track.cel.per_rule` is the immutable expression/pack/rollout identity table;
each retained finding references it with `rule_id`, decision, and exact
candidate multiplicity. Enforced removals additionally retain bounded category,
severity, and analyzer context. The gate requires one identity per rule and
reconciles every count and sample ID.
The domain-separated digest of the complete outcomes remains in the report,
and release JSON is serialized canonically without presentation whitespace so
repeated identity fields cannot exhaust the bounded artifact budget.

The one non-fatal scanner recovery is the bounded, inert manifest-loader path.
Evaluators recognize it only when the stable `SkillLoadError` entry, the single
`SKILL_LOAD_FALLBACK_USED` INFO finding, and both loader metadata projections
agree on an approved error code, an incomplete manifest, and untrusted
capability facts. Recognized samples remain in every metric denominator and are
reported as `loader_fallbacks`/`recovered_scan_errors` with stable sample IDs.
Missing, duplicate, spoofed, or inconsistent proof remains a fatal scan error.
This recovery is distinct from CEL/runtime/projection fallback, which remains
zero-gated on release corpora.

Metadata that exceeds the hard loader limit follows a different closed path:
the scanner stats the file without reading its content and emits one validated
HIGH `SKILL_LOAD_REJECTED_LIMIT` policy finding. Evaluators accept this as a
normal blocking result only when the exact size-limit code, marker identity,
size bounds, loader metadata, and zero-evaluation CEL telemetry agree. Reports
expose `loader_rejections` and stable `loader_rejection_sample_ids` separately
from recoveries and fatal errors; OFF and active-CEL release evidence must bind
the same rejected samples. Any missing or contradictory proof remains fatal.

An all-shadow bundled generation needs no per-rule promotion artifact. If any
bundled CEL rule has rollout `enforce`, the frozen release artifact must also
contain `rule-fixture-evidence.json` and `repeated-comparison.json`. The former
records distinct true-positive, benign-near-miss, and malformed/projection-
boundary fixture IDs for exactly the enforced rules. Every referenced fixture
has one schema-v2 attestation containing its role, content hash, package label,
expected verdict, `scanner_independent: true`, and one of the exact label-source
types `public_labeled`, `independent_ollama`, `agent_labeled`, or
`human_reviewed`. Each source has a bounded identity contract and an explicit
false scanner-output-use field. Public attestations bind an immutable dataset
revision and row; Ollama attestations bind the report, model, rubric, prompt,
and two passes; agent attestations bind the agent definition, run, model,
rubric, and prompt; human attestations bind 2-8 reviewers, a timestamp, and a
review protocol. Per-fixture provenance and attestation digests plus the
top-level evidence digest are recomputed before use. True-positive fixtures
must be `malicious`/`unsafe`, while benign near misses must be `benign`/`safe`.
Pass this artifact to the producer with `--attested-rule-fixtures`. The
latter must be the passing five-run comparison and bind the exact release
producer and evidence identities. Promotion additionally requires independently
bound, pre-compaction counterfactual evidence proving at least 20% relative
actionable false-positive reduction for each enforced rule. Compact-v3 raw
candidate suppression is explicitly insufficient; until exact normalized-loss
evidence is integrated into the release artifact, enforced-rule promotion fails
closed. Waiver files or waiver metadata are rejected rather than treated as a
release bypass.

For otherwise-unlabeled cases, use the scanner-independent local Ollama
adapter. The manifest must freeze the model digest, rubric, prompt, content
hashes, and two distinct pass seeds:

```bash
uv run --no-sync python evals/runners/independent_ollama_labeler.py \
  --manifest /absolute/path/labeling-manifest.json \
  --ollama-base-url http://127.0.0.1:11434 \
  --output /absolute/path/independent-labels.json
```

Both passes must agree on the same non-abstain label. The adapter rejects
hosted endpoints, credentials, scanner-output fields, authoritative labels,
and sealed labeled test cases. Its output is a separate supplemental label
stratum and is never merged into sealed Hugging Face benchmark metrics.
Authoritative local LLM/Meta benchmark evidence likewise requires
`--ollama-model-digest` with the exact 64-character lowercase SHA-256 model
digest; a model tag alone is mutable and is not sufficient provenance.
`ollama_meta_benchmark.py` accepts exactly five paired runs, each reusing one
primary-analyzer result as the input to the Meta pass. All five runs must bind
the same source, prompt, model name, and model digest and produce stable
outputs. Meta qualifies only with zero precision, recall, or F1 regression and
a material improvement in the configured target metric; a missing local model
or failed comparison is a hard evaluation failure, not a skipped success.

The manifest is strict and rejects unknown fields (including scanner output):

```json
{
  "schema_version": 1,
  "corpus_id": "committed-unlabeled-near-misses-v1",
  "evaluation_track": "model_labeled_supplemental",
  "contains_authoritative_labels": false,
  "model": {"name": "qwen3.5:9b-mlx", "digest": "<ollama-model-sha256>"},
  "rubric": {"text": "<frozen rubric>", "sha256": "<rubric-sha256>"},
  "prompt": {"text": "{rubric}\nCase {case_id}:\n{content}", "sha256": "<prompt-sha256>"},
  "passes": [{"pass_id": "pass-a", "seed": 101}, {"pass_id": "pass-b", "seed": 202}],
  "cases": [{
    "case_id": "near-miss-001",
    "content": "<inert package text>",
    "content_sha256": "<content-sha256>",
    "label_status": "unlabeled",
    "sealed_labeled_test": false
  }]
}
```

## Metrics Reference

| Metric | Meaning |
|---|---|
| Finding precision | Exact one-to-one matched findings / all actual findings |
| Finding recall | Exact one-to-one matched findings / all expected findings |
| Package block recall | Malicious packages with CRITICAL/HIGH findings / malicious packages |
| Signal recall | Malicious packages with LOW-or-higher findings / malicious packages |
| Benign actionable FPR | `package_label=benign` packages with MEDIUM-or-higher findings / all explicitly benign packages; contextual-risk fixtures are excluded |
| Macro-F1 | Mean class/category F1, reported separately from micro-F1 |
