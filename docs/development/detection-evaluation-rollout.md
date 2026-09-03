# Detection Evaluation and Rollout

Detection changes are accepted on finding-level evidence, not on scanner-
generated expectations or category-only matches. The release objective is to
reduce actionable false positives without losing any CRITICAL or HIGH findings
on the mandatory corpora.

The modernization release gate is **core + CEL only**. ATR remains an optional
bundled pack for separate supplemental diagnostics; ATR findings and metrics do
not pass or fail this release. This separation is also required for source-
disjoint interpretation because an ATR source overlaps the public benchmark.

## Evaluation tiers

| Tier | Required work |
|---|---|
| Pull request | Validate all selected packs, type-check CEL with the bundled helper, run the committed golden corpus and boundary cases, compare legacy and CEL-shadow output, and verify five-run determinism |
| Release | Run one complete pinned public labeled holdout, the committed exact goldens, five deterministic frozen-generation runs, and package/platform smoke tests; report private evidence separately when supplied |

An evaluation ingestion or scanner error is a failed run. It must not remove a
case from the denominator.

The required workflows are `detection-pr-gates.yml`,
`detection-release-evidence.yml`, and `detection-release-gates.yml`; there is
no scheduled detection gate. The
frozen release job always requires the pinned redistributable public labeled
artifact. Its CEL-off baseline still compiles and type-checks the selected
generation with the exact bundled cel-go helper, but performs no decisions.

The public-corpus acquisition job installs only the locked dataset dependency
group with `--no-install-project`. It therefore cannot trigger the scanner's
native CEL build hook and does not need a Go compiler; the isolated evaluation
job installs and validates the scanner after setting up the qualified toolchain.
Optional private evidence is ingested with the same safety checks and remains
explicitly nonblocking. A public lock with `hashes_pending`, a missing exact-
golden manifest, or incomplete repeated-run evidence fails closed. The release
job regenerates the exact-golden manifest from the checked-out fixtures and
requires the frozen public artifact's bundled manifest to match it exactly;
stale or subset golden evidence cannot satisfy the gate.

Package publication is directly dependent on this reusable gate. First,
dispatch `detection-release-evidence.yml` from the exact release tag and pass
that tag's full commit SHA. The protected producer downloads only the ten files
listed in the MaliciousSkillBench profile at the locked revision, verifies all
source hashes/schema/counts/quarantine metadata, and materializes the inert
snapshot. Its separate scan job receives no dataset credential, removes all
credential-bearing environment entries, installs IPv4 and IPv6 owner-based
egress rejection, and proves external sockets fail before scanning. It runs
one CEL-off release profile and exactly five active-mode profiles, then
self-validates `release_gate.py` before uploading
`detection-release-evidence-<full-sha>`.

The publication dispatch must provide that producer run ID and fixed artifact
name. The consumer requires the run to be a completed successful
`workflow_dispatch` of `detection-release-evidence.yml` in this repository,
with `head_sha` equal to the requested tag commit. The artifact contains the
compact canonical offline contract: `candidate.json`, `baseline.json`,
`repeated-runs.json`, `repeated-comparison.json`, `promotion-status.json`,
`golden-corpus.json`, `evidence-provenance.json`, and the producer's passing
`release-gate-result.json`. Candidate and baseline metadata record the exact
release commit; provenance is `status=release_evidence` and `shipping=true`.
Publication never downloads or rematerializes Hugging Face data. A missing,
failed, wrong-workflow, cross-revision, expired, renamed, or identity-mismatched
artifact blocks wheel building and therefore blocks PyPI and GitHub publication.

Go 1.27.1 is the source-build minimum. Pull requests, detection evidence,
release wheels, supply-chain exports, and Homebrew qualification pin exactly
Go 1.27.1. Older Go linkers cannot reproduce the required macOS 13 deployment
contract. The formula
is generated from the requested tag's hash-verified PyPI sdist and is installed
on both macOS ARM64 and x86-64 before it can be committed. Changing
that qualified version requires rebuilding and natively smoking all five
release helpers.

### Golden finding identity

Expected and actual findings are matched one to one using:

```text
(rule_id, category, severity, file_path, line-or-stable-evidence-id, analyzer)
```

One actual finding cannot satisfy multiple expectations. An unmatched expected
finding is a false negative; an unmatched actual finding is a false positive.
Each golden case records its source, license, provenance hash, package label,
expected verdict, and exact expected findings.

Every enforced rule needs at least one true positive, one benign near miss, and
one malformed or projection-boundary case. Golden fixtures must be inert and
redistributable. Labels may come from authoritative public ground truth, the
frozen two-pass local-Ollama protocol below, an independently bound agent run,
or human review. They never come from the scanner under test.

## Dataset roles

External corpus identity and permitted use are pinned in
`evals/datasets/public-datasets.lock.json`. Mandatory public source data is
downloaded only by the explicitly dispatched protected producer at its frozen
revision; pull-request and publication jobs do not fetch it.

| Dataset | Role | Release blocking? |
|---|---|---|
| Committed golden corpus | Exact finding regression tests across every threat category and severity | Yes |
| [ProtectSkills/MaliciousSkillBench](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench) | Primary core-only public classification benchmark | Yes |
| Private source-disjoint corpus | Optional independently reviewed real-world supplemental holdout | No |
| [Miaow-Lab/OpenSkillRisk](https://huggingface.co/datasets/Miaow-Lab/OpenSkillRisk) | Positive recall and category evidence in authorized environments | No |
| [TrustAIRLab/HarmfulSkillBench](https://huggingface.co/datasets/TrustAIRLab/HarmfulSkillBench) | All-positive supplemental static signal/block recall plus harmful-content and LLM-policy recall; it supplies no benign denominator | No |
| [ProtectSkills/MaliciousAgentSkillsBench](https://huggingface.co/datasets/ProtectSkills/MaliciousAgentSkillsBench) | Taxonomy, case mining, and de-overlapped sandbox-confirmed positive recall; its “safe” class is not benign gold | No |
| [OpenClaw/clawhub-security-signals](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) | Silver-label drift, disagreement, and false-positive mining | No |
| [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | Supplemental indirect-prompt-injection signal recall and paired enhanced-versus-base differential recall; not package-level ground truth | No |
| [SoheilKhodayari/in_page_prompt_injection_pub](https://github.com/SoheilKhodayari/in_page_prompt_injection_pub) | Supplemental positive indirect-injection signal recall over canonical deduplication groups; not a package accuracy gate | No |
| [InjecGuard NotInject](https://github.com/InjecGuard/InjecGuard) | Benign prompt-text hard-negative diagnostics and mining; not package-level benign gold or an FPR denominator | No |
| [LLM-LAT/harmful-dataset](https://huggingface.co/datasets/LLM-LAT/harmful-dataset) | Excluded: chat-preference data with no declared dataset license | Never downloaded |
| [DataDog malicious software packages](https://github.com/DataDog/malicious-software-packages-dataset) | Quarantined malicious-package recall evidence | No |

MaliciousSkillBench is pinned at revision
`d4b42ce5766a6e0359c987cf59c1007cb3795a90`. Run the core-only detector on its
source-disjoint test split. Optional pack analysis, including ATR, is a
separately labeled supplemental result and is never merged into the mandatory
core denominator. The ATR pack overlaps an ATR source, so results with ATR
enabled must not be presented as a source-disjoint generalization claim.
The split remains source-disjoint by construction, but its aggregate results
have already been observed during development. It is a frozen reproducible
release benchmark, not a pristine unseen holdout; do not tune against its
members or present it as never previously observed.

When available, a private corpus should group samples by source, repository,
actor/campaign, and structural family and freeze a source-disjoint holdout. Its
labels use the same scanner-independent public, two-pass Ollama, agent, or human
attestation classes and hash bindings as committed evidence; human review is
not mandatory. Private-corpus availability, size, or result never determines
the public release status.

Missing access to a gated supplemental dataset produces a visible skip, not a
pass or release failure. Supplemental results must not be folded into the
mandatory metric denominator.

### Independent labels for otherwise-unlabeled cases

`evals/runners/independent_ollama_labeler.py` labels only manifests explicitly
marked `model_labeled_supplemental`. It accepts an HTTP loopback literal
(`127.0.0.1` or `::1`) and rejects hosted endpoints and credentials. The
manifest freezes the exact Ollama model digest, rubric hash, prompt hash, every
input-content hash, and two distinct pass seeds. A case receives a label only
when both passes return the same non-abstain result; disagreement, an explicit
abstention, malformed output, or a provider failure cannot become a label.

The input schema has no scanner-output field and rejects authoritative or
sealed labeled test cases. The output is always marked ineligible for
authoritative Hugging Face metrics. Accepted labels may be committed as exact
goldens with their labeling manifest provenance, but they remain a separate
source stratum and are never merged into sealed public-test measurements.

Local LLM/Meta comparison evidence is likewise bound to an exact 64-character
Ollama model digest. The comparison runner requires exactly five paired
primary-to-Meta runs with stable source/model/prompt provenance, reuses each
primary result rather than rescanning it, and fails unless precision, recall,
and F1 have zero regression while the target metric improves materially.

## Safe ingestion

The dataset lock records the immutable revision, config and split, expected
schema and row count, hashes, license scope, permitted uses, and grouping
fields. An upstream schema or row-count change fails ingestion pending review.

Acquisition and analysis are separate stages. Download into a disposable
directory, verify the lock, then analyze with network disabled. Materializers
accept data only: they reject absolute or traversing paths, symlinks,
case-colliding or non-normalized names, unexpected fields, size/hash mismatch,
and executable modes. Samples are never imported, executed, or allowed to
follow embedded links.

Deduplicate and split on exact content, normalized content, structural family,
repository, actor/campaign, and lexical template. Mutations inherit their
parent's split. Frozen test members are never used to author rules, tune CEL,
or select thresholds.

## Metrics and promotion gates

Report finding precision, recall, and macro-F1; package block recall; signal
recall; benign actionable false-positive rate over explicitly benign packages
(not contextual-risk fixtures); and per-category, source, and
family results. Include 95% Wilson intervals. The mandatory result is core-
only; optional bundled-pack and locally extended results must remain separate,
nonblocking configurations.

`public_dataset_benchmark.py --trusted-rule-pack PATH` produces the locally
extended configuration without changing the locked core-only public track. It
emits a distinct `locally_extended` report, validates every local pack through
the strict schema-v2 trusted loader, records a path-independent pack-set
digest, and rehashes the set after scanning. The configuration is diagnostic
and nonblocking; compact mandatory release evidence rejects local extensions
so their results cannot contaminate the sealed public gate.

### Current core + CEL benchmark audit (not a release pass)

The final non-test MaliciousSkillBench development benchmark contains 6,594
packages: 5,256 malicious and 1,338 benign. It is development evidence that was
used during tuning, not a release holdout. Package-level actionable results are:

| Non-test development tree | TP | FP | TN | FN | Precision | Recall | F1 | Benign FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `origin/main` | 1,045 | 48 | 1,290 | 4,211 | 95.61% | 19.88% | 32.92% | 3.59% |
| Current core + CEL shadow | 1,653 | 14 | 1,324 | 3,603 | 99.16% | 31.45% | 47.75% | 1.05% |

The current development result improves F1 by 14.84 percentage points
(45.07% relative), recall by 11.57 points, and FPR by 2.54 points (70.83%
relative reduction). Current precision has a 98.60%-99.50% 95% Wilson interval,
recall 30.21%-32.72%, and FPR 0.62%-1.75%. Five shadow runs produced identical
normalized findings. CEL evaluated 154 candidates per run with zero
would-suppress decisions and zero fallbacks. Its maximum share of scan time was
0.0679%, and the measured shadow p95 was 2.18% above CEL-OFF. These results meet
the determinism and measured latency bounds, but they do not establish
suppression quality because no candidate was suppressed.

The locked source-disjoint split provides the relevant public holdout check:

| Source-disjoint tree | TP | FP | TN | FN | Precision | Recall | F1 | Benign FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `origin/main` | 33 | 20 | 525 | 806 | 62.26% | 3.93% | 7.40% | 3.67% |
| Current core + CEL shadow | 65 | 42 | 503 | 774 | 60.75% | 7.75% | 13.74% | 7.71% |

The current holdout precision has a 51.28%-69.47% 95% Wilson interval, recall
6.12%-9.75%, and FPR 5.75%-10.25%. Recall and F1 improve, but benign FPR rises
by 4.04 percentage points and precision declines slightly. This violates the
no-FPR-regression promotion requirement. The result therefore **fails the CEL
promotion gate and is not a release pass**. Every bundled CEL rule remains in
`shadow`, and no would-suppress decision is promoted by this change. The split
has already been observed during development, so it is frozen and must not be
used for further tuning.

The locked 111-package official Codex, Claude Code, and Cursor skill audit is a
compatibility and false-positive-mining check, not labeled benign gold. CEL-OFF
and CEL-SHADOW finding identities were identical across five stable runs. The
current scanner reported MEDIUM-or-higher findings on 30/111 packages (27.03%;
95% Wilson interval 19.64%-35.95%) and HIGH/CRITICAL findings on 8/111 (7.21%;
3.70%-13.58%). Shadow mode evaluated 36 candidates and recorded 28 potential
suppressions while retaining all findings. Official provenance does not make a
behavioral-risk finding false, and these counts cannot produce precision,
recall, or F1.

Supplemental corpus checks were kept separate from the labeled package gate:

| Supplemental corpus | Current result | Interpretation |
|---|---:|---|
| NotInject | 0 / 339 actionable matches | Benign prompt-text hard-negative check; not package-level FPR gold |
| HarmfulSkillBench | 7 / 200 actionable; 6 / 200 HIGH+ | Positive-only diagnostic with one known quarantined sample retained in the denominator |
| OpenSkillRisk | 76 / 263 actionable (28.90%) | Positive-only recall diagnostic with two host quarantines retained in the denominator |

HarmfulSkillBench and OpenSkillRisk contain no benign control population for
these runs, so neither can measure precision, F1, specificity, or false-positive
rate. Quarantined samples were not silently removed from their denominators.
NotInject is valuable hard-negative evidence, but its prompt-text examples are
not a substitute for independently labeled benign packages. Optional ATR
results remain outside the core + CEL release scope.

A CEL-gated rule moves from `shadow` to `enforce` only when all of the following
hold:

- pack parsing and CEL compilation/type checking succeed for every selected
  rule;
- mandatory corpora produce no evaluator or incomplete-projection fallback;
- no new CRITICAL/HIGH false negatives appear;
- malicious/actionable recall and macro-F1 do not regress;
- benign actionable false-positive rate does not increase;
- the targeted near-miss set shows at least a 20% relative actionable false-
  positive reduction;
- output is identical across five runs;
- total scan p95 latency regresses by no more than 10%; and
- CEL accounts for no more than 5% of scan time.

Per-rule promotion evidence keeps fixture coverage separate from runtime
telemetry. `compare_repeated_benchmark_reports` receives attested fixture IDs
for the true-positive, benign-near-miss, and malformed/projection-boundary
cases and an explicit set of rule IDs under promotion. Shadow-only rules remain
fully reconciled but cannot satisfy or contaminate another rule's promotion
evidence. A runtime `fallback` on the mandatory corpus is never accepted as
proof that a boundary fixture exists. Mandatory-corpus fallbacks and incomplete
projections remain hard failures, and sample CEL decisions must agree with
aggregate/per-rule telemetry. Promotion also fails if the candidate would
suppress any malicious HIGH or CRITICAL finding, including a candidate that is
visible only in enforce-mode suppression telemetry.
Release artifacts use `compact-v3`: complete lineage stays in diagnostic
reports, while `track.cel.per_rule` supplies the single immutable expression,
pack, and rollout identity for compact finding references. Those references
retain rule ID, decision, and multiplicity; suppressed references retain rule
ID, category, severity, analyzer, and multiplicity. The gate expands and
reconciles them against all per-rule counters and sample-ID sets. This bounded
context makes suppressed-only actionable near misses and malicious
HIGH/CRITICAL candidates auditable without retaining raw source text. A
domain-separated full-outcome digest preserves the complete evidence identity,
and canonical minified JSON keeps the frozen artifact within its existing size
bound without raising the limit.
The narrowly bounded manifest-loader recovery is reported separately and is
not a CEL fallback: it is accepted only with an exact stable `SkillLoadError`,
one `SKILL_LOAD_FALLBACK_USED` INFO marker, matching loader metadata, an
incomplete manifest, and untrusted capability facts. Such samples stay in the
denominator; candidate and baseline must recover the same stable sample IDs.
Any incomplete or contradictory recovery evidence remains a fatal scan error.
An oversized metadata file is instead a closed, normal HIGH verdict: the
scanner reads no content and emits exactly one `SKILL_LOAD_REJECTED_LIMIT`
finding with coherent size bounds and loader metadata. Evaluation records its
count and stable IDs separately, requires identical OFF/active-CEL rejection
identity, and treats any spoofed or partial rejection proof as fatal.
When every bundled CEL rule is still `shadow`, the release gate does not demand
promotion artifacts or manufacture fixture claims. As soon as any bundled rule
is `enforce`, the frozen public artifact must include attested
`rule-fixture-evidence.json` and the passing output of the five-run
`compare_repeated_benchmark_reports` comparison. Both artifacts are bound to
the exact rule, expression, producer, public-population, and golden-manifest
identities used for the release.

The complete gate requires exactly five clean runs with identical frozen
corpus, build, policy, rules, CEL generation, exact-golden manifest, and
normalized detection-output hash, plus one complete public release-corpus run.
Waivers cannot bypass these gates: waiver-named artifacts and embedded waiver
metadata are rejected. Keep a rule in `shadow` or fix the evidence instead; a
missing result is not a passing result.

## Delivery sequence

1. **Foundation:** require CPython 3.11–3.14, correct one-to-one evaluation, lock
   dataset inputs, make rule-pack validation strict, and land the typed fact
   schema and analyzer metadata contract.
2. **Shadow:** use the pinned official cel-go helper to observe selected noisy
   rules without suppression.
3. **Enforce:** after the promotion gates pass, enforce only individually
   promoted rules. Other rules stay in shadow.
4. **Expand detection:** add Python extractors for sensitive-read-to-network,
   download-to-execution, decode-to-execution, hidden executable combinations,
   cross-file staged flows, nested archives, and manifest capability mismatch;
   use CEL only for bounded correlation and context.

Initial precision targets are hidden-file globbing, hidden or unreferenced
executables, compound fetch-and-execute, `find -exec`, active-context
homoglyphs, unanalyzable binaries, embedded shebangs, and undeclared network or
tool use. The broad extractor remains in place so CEL can be evaluated against
the same candidate population before enforcement.

### Active dynamic-execution development evidence

`ACTIVE_DYNAMIC_EXECUTION` is a core Python/static rule that confirms calls in
active CommonMark instruction or code context with Python ASTs or a bounded
JavaScript/TypeScript token walker. The reviewed API set is intentionally
limited to `eval`, `exec`, `os.system`, `subprocess.run/call/Popen`, and
`child_process.exec`; broader process APIs remain candidate evidence until
source-to-sink analysis proves they are actionable.

The aggregate, non-test MaliciousSkillBench development measurement is frozen
in [the dated evidence artifact](../../tests/fixtures/active_dynamic_execution_msb_non_test_2026-09-02.json),
with its adjacent SHA-256 sidecar. It records the immutable dataset revision,
population and quarantine accounting, source/family coverage, zero new benign
actionable packages, net core blocker lift, and the identical five-run output
digest. This is development evidence only: it contains no raw samples or
sample IDs, did not access sealed test splits, and does not replace the
mandatory release-corpus promotion gates above.

### Rejected reverse-shell and generic C2 core candidates

The non-test MaliciousSkillBench audit found 116 malicious packages and no
materialized benign package containing an explicit reverse-shell term across
three sources and 113 declared structural families. All 116 already had a
bundled CRITICAL or HIGH finding, however, so a term-backed core rule added no
package-block recall. A term alone also cannot distinguish operational abuse
from a scanner, red-team guide, or defensive example.

A bounded three-class prototype requiring explicit C2 communication, payload
or content-binary delivery, and active runtime execution matched eight
malicious packages and no labeled benign package. Six were already blocked and
two were nominal new blockers, but all eight came from `SRC001`. More
importantly, the same prototype matched both an isolated-sandbox red-team guide
and a command-and-control exercise limited to a test lab. Adding template words
as YARA exclusions would memorize those examples rather than solve the missing
context classification, so the prototype was removed.

[The hash-bound no-go artifact](../../tests/fixtures/reverse_shell_c2_core_no_go_msb_non_test_2026-09-02.json)
records the locked non-test population, source/family support, blocker overlap,
and counterexample result without embedding dataset text or sample IDs. The two
benign counterexamples are permanent regression cases. A future attempt must
use analyzer-owned instruction context, reject both near misses, demonstrate
support beyond one source, and produce real package lift before adding a core
rule.

### Active Unicode-smuggling development evidence

`UNICODE_SMUGGLING_ACTIVE_INTENT` is a bounded core Python/static rule for
small zero-width sequences that the existing high-volume YARA threshold does
not classify on structure alone. It computes candidate-local count, density,
maximum run, character class, and distance to a paired override or execution
intent. A HIGH finding requires active CommonMark instruction or complete-code
context; examples, complete prohibitions, malformed regions, and unpaired
Unicode formatting remain non-actionable. The existing YARA threshold is not
lowered or otherwise changed.

The aggregate, non-test development measurement is frozen in [the dated
evidence artifact](../../tests/fixtures/unicode_smuggling_active_intent_msb_non_test_2026-09-02.json),
with its adjacent SHA-256 sidecar. Across 5,254 text-available malicious rows
and all 1,339 benign controls, the accepted predicate produced 16 malicious
package signals from two sources and 16 structural families, with zero benign
hits and zero new benign actionable packages. All 16 were already blocked by
other HIGH/CRITICAL evidence, so the measured net blocker lift is zero; this
rule adds a normalized Unicode-specific explanation rather than claiming new
package recall. A broader 52/0 development counterfactual was not adopted
because the production context parser reproduced 51/0, replaced rather than
strictly extended the accepted support set, and added no blocker lift.

The evidence contains only aggregate metrics and a five-run output digest: no
raw samples, decoded payloads, sample identifiers, or sealed test rows. It is
development evidence only and does not replace the release promotion gates.
