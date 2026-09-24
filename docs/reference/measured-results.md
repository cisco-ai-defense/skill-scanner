# Measured results

What the scanner has been measured at, on which corpus, and under which configuration. Every figure
here is tied to a named corpus and population, because none of them generalise across corpora on their
own.

Full tables, per-corpus breakdowns and the head-to-head against NVIDIA SkillSpector are published at
[Vineethsain/skill-scanner-vs-skillspector](https://huggingface.co/spaces/Vineethsain/skill-scanner-vs-skillspector).

## How to read these numbers

Three things change a figure materially, so all three are always stated.

**The corpus.** A result on MaliciousSkillBench's source-disjoint split says nothing about
OpenSkillRisk. The rule packs were tuned against MaliciousSkillBench during development, so figures on
its development partition are home ground; the source-disjoint split is the one that carries weight.

**The threshold.** "Detected" means a finding at or above a stated severity. Detection at MEDIUM and
detection at HIGH are different measurements, and the package-level gate is a third.

**Whether a model was enabled.** The deterministic rules, the LLM judge and the meta-analyzer are
separate stages. The published rule-only figures ran with the judge off.

## Deterministic rules only

Corpus: MaliciousSkillBench source-disjoint split, 839 malicious and 545 benign. Shipped core rule
pack, no model.

| Metric | Value |
|---|---|
| F1 | 13.7% |
| Precision | 60.7% |
| Recall | 7.7% |
| False-positive rate | 7.7% |

Enabling every community rule pack raises recall to 73.8% on an 80/80 sample of the same split, and
raises the benign flag rate from 7.5% to 92.5%. That configuration is a triage setting, not a gating
one. MaliciousSkillBench's terms additionally prohibit source-disjoint generalisation claims with the
ATR pack enabled.

## With the LLM judge

Same corpus and population, detection at MEDIUM or above.

| Configuration | F1 | Precision | Recall | FPR |
|---|---|---|---|---|
| Single-pass judge, Claude Haiku 4.5 | 58.7% | 82.0% | 45.8% | 15.6% |
| Single-pass judge, Gemma 4 26B | 61.2% | 81.5% | 49.0% | 17.6% |
| Three specialized passes, Haiku 4.5 | 81.4% | 86.9% | 76.6% | 17.8% |
| Three specialized passes, Gemma 4 26B | 68.3% | 85.5% | 56.9% | 14.9% |
| Five specialized passes, Gemma 4 26B | 71.0% | 85.2% | 60.9% | 16.3% |

Decomposing the judge into three passes with different focuses, and unioning the findings, is the
largest measured improvement. **The size of the gain depends on the model**, so the model has to be
quoted with the figure:

- On Claude Haiku 4.5, F1 goes from 58.7% to 81.4% and recall from 45.8% to 76.6%, with the
  false-positive rate close to unchanged.
- On Gemma 4 26B, the same change gives F1 61.2% to 68.3% and recall 49.0% to 56.9% — about a third of
  the improvement. Here the false-positive rate *falls*, 17.6% to 14.9%, and precision rises from
  81.5% to 85.5%.

Both directions are worth noting. Decomposition helps on both models and costs precision on neither,
but a headline drawn from one model does not transfer to the other.

### Does it generalise?

The same change measured per corpus on Gemma 4, detection at MEDIUM or above:

| Corpus (population) | F1 before → after | Recall before → after |
|---|---|---|
| msb-source-disjoint (839 / 545) | 61.2% → 71.0% | 49.0% → 60.9% |
| msb-balanced-800 (400 / 400) | 77.8% → 79.5% | 80.0% → 84.0% |
| openskillrisk (374 / 0) | 92.8% → 93.3% | 86.6% → 87.4% |
| harmfulskillbench (200 / 0) | not permitted | 60.0% → **57.0%** |

The gain tracks the headroom the single pass left: +9.8 F1 where baseline recall was 49%, +1.7 where it
was 80%, +0.5 where it was 86.6%. On HarmfulSkillBench recall *falls* by 3.0 points, so the change is
not uniformly beneficial — that corpus turns on harmful content rather than a technical capability,
which the added focuses were not written for. Its terms permit only recall.

Adding two further focuses — capability unjustified by the stated task, and covert persistence — takes
Gemma 4 to 71.0% F1 and 60.9% recall on source-disjoint. Those two were chosen from the records SkillSpector catches and
this scanner produces nothing for, rather than guessed. Against the single-pass Gemma 4 baseline all
four metrics improve together: F1 +9.8, recall +11.9, precision +3.7, and the false-positive rate falls
1.3 points.

A control arm matters when reading that. Running the *same* prompt three times and unioning accounts
for roughly two thirds of the gain on a 400-record subsample, so most of it is sampling variance
rather than prompt design: one pass misses findings a second pass returns.

The cost is 3x the model calls, and the false positives it adds are well priced: +46 true positives
for +7 net false positives on the subsample, with no single focus responsible.

## Where the remaining misses are

Of 196 malicious records still missed at MEDIUM+ by the three-pass judge:

- 161 produce no finding at all, which is a detection gap.
- 35 produce only an INFO finding. Those are **not** a calibration problem: every one is a record the
  judge never read — 31 `LLM_CONTEXT_BUDGET_EXCEEDED` and 4 `LLM_ANALYSIS_FAILED`.

Nothing lands at LOW, so severity assignment is effectively bimodal.

### Un-analysed skills pass the gate

The second bullet above is a fail-open worth stating plainly. Across the 1,384-record split the judge
could not read 92 records (6.6%) on the Haiku arm and 51 (3.7%) on Gemma 4. Most were malicious, 76 and
32 respectively. Counting the records that other rules gated anyway, **51 and 47 un-analysed skills
respectively still passed the gate**.

The failure is reported as an INFO finding, and INFO does not gate. So a skill can evade the semantic
stage simply by being large enough to exceed the context budget.

The fix is not a severity change. Un-analysed content should be surfaced as a coverage gap the caller
can gate on, which is what SkillSpector exposes through `analysis_completeness` and
`--fail-on-incomplete`. This scanner has the information and currently reports it in a form that
passes.

## Known gap: MCP tool poisoning

Corpus: `fevziegeyurtsevenler/mcp-tool-poisoning`, 25 matched benign/poisoned pairs. Each pair holds
the tool and its purpose constant and differs only in an injected instruction, so any asymmetry is
attributable to the poisoning.

| Configuration | Recall | Precision | FPR |
|---|---|---|---|
| Shipped static rules | 40.0% | 100% | 0% |
| LLM judge, single or specialized | 100% | 100% | 0% |

The static layer has no MCP-specific analyzer and catches less than half; the judge closes the gap
completely. Users running without a model are therefore materially weaker on this surface.

## Flag rate on real published skills

Corpus: 12,500 published skills sampled from `abersbail/ai-skill-md-dataset-500` (MIT) and
`FayeZC/SkillMD-138K` (CC-BY-4.0). These records carry no labels, so the flag rate is an upper bound
on the false-positive rate rather than an exact figure: the population is predominantly benign but
will contain some genuinely risky skills.

Static analysis only, no model. This scanner is measured on 12,498 records with Wilson 95% intervals;
the SkillSpector column is from the 4,500-record subset it was run on.

| Threshold | This scanner (n=12,498) | SkillSpector (n=4,379) |
|---|---|---|
| CRITICAL | 0.42% [0.32, 0.55] | 0.11% |
| HIGH or above | 2.46% [2.20, 2.74] | 12.90% |
| MEDIUM or above | 3.76% [3.44, 4.11] | 26.42% |
| INFO or above | 88.21% [87.64, 88.77] | 26.76% |

The estimate needed the larger sample. At 1,100 records MEDIUM+ read 2.00%, at 4,500 it read 3.40%,
and at 12,498 it settles at 3.76%: the first sample understated it by nearly half.

On the population users actually scan, the shipped rules are roughly seven times quieter at MEDIUM or
above.

The INFO row is the important one for tuning. Nearly every real skill receives an INFO finding, and
nothing at all lands at LOW, so severity assignment is effectively bimodal. On MaliciousSkillBench,
moving the gate down to INFO looks attractive: it raises F1 from 81.4% to 83.2%. On real skills the
same change would flag 93.5% of everything scanned. The MSB-only view would have justified a change
that is unusable in production, which is the reason to keep an unlabelled real-world population in the
evaluation set.

## A System One model does not replace the judge in this framing

A smaller calibrated "System One" model was tested as a cheaper screen, asked one overall question and
eight per-threat-family probes in a single request, over 189 source-disjoint records.

It does not work when handed raw skill source as its state:

- The answers barely depend on which question is asked. Within one record, the eight probes span 0.042
  on average, so asking per detection type is redundant.
- Every probe is inverted with respect to the label, at AUC 0.25 to 0.28: malicious records average
  0.568 and benign records 0.683.
- The probability correlates with input length (r=0.187), and benign records are longer here, so part
  of what it is reporting is text length.

The framing was then ruled out. Re-running 250 records with the structured packing the module
intends — files collected, role-classified, priority-ordered, bounded, oversize rejected rather than
truncated — reproduces the same behaviour: a within-record spread of 0.041 against 0.042, and AUC
0.29 to 0.31 against 0.25 to 0.28. Across two framings and 439 records the model does not separate
malicious from benign skills here, and asking one question per detection type adds nothing because the
answers barely depend on the question.

This is a negative result about using a small calibrated decision model as a security screen for
skills. It does not transfer to its intended domain of agent and browser state decisions.

## The meta-analyzer is off by default, and should stay that way

The meta-analyzer arbitrates findings the other stages produced and can only demote. Measured on a
strided one-in-five sample of the source-disjoint split with Gemma 4:

| Arm | F1 | Precision | Recall | FPR |
|---|---|---|---|---|
| Judge only | 61.9% | 83.9% | 49.1% | 15.0% |
| Judge plus meta | 46.0% | 77.1% | 32.7% | 14.7% |

It applied on 219 of 274 records and altered findings on 64, trading 16.4 points of recall for 0.3
points of false-positive rate. On this corpus and with this model it removes far more real detections
than false ones, so leaving it off is the right default.

Reaching that measurement required fixing a wiring bug first. On the Bedrock mantle route the meta path
constructed a request handler without supplying a schema, so the handler loaded its default — the LLM
*analyzer's* schema. Meta requests were constrained to the wrong shape, the model returned
`findings`/`verdict` instead of the meta delta, every batch failed contract validation, and each was
silently retained unchanged. Meta reported that it ran while changing nothing, which is
indistinguishable from meta agreeing with every finding. Any earlier result that enabled meta on that
route measured a no-op.

## Tokens per skill

Measured on 120 source-disjoint records with Gemma 4 26B:

| Configuration | Input tokens per skill | Output tokens per skill |
|---|---|---|
| Single judge pass | 4,838 | 300 |
| Five specialized passes | 24,703 | 1,548 |

Five passes cost 5.1x the input tokens, which is the expected ratio.

## Where the INFO tier comes from

Across 8,623 records from every static corpus, one rule dominates the INFO tier.
`MANIFEST_MISSING_LICENSE` fires on 7,203 of them and is the *only* finding on 5,258. Every one of
those 5,258 records tops out at INFO; none reaches MEDIUM or above. So it accounts for roughly 85% of
the real-world INFO flag rate and cannot, on its own, gate an install.

It is a metadata hygiene check rather than a security finding — the judge prompt already states that
missing optional manifest metadata is not a security threat — so reporting it as hygiene would clear
the INFO tier without affecting any gating decision.

## What rule-level suppression cannot fix

Suppressing any combination of up to four of the highest-volume rules changes F1 by at most +0.2
points. Benign records that flag fire 3.9 rules on average and essentially never a single rule alone,
so their rule profile is not separable from that of true positives. Reducing the false-positive rate
needs a per-record judgement, not a policy change.

## Reproducing

The evaluation harness lives in `evals/`. It is deliberately outside the blocking release path: the
release gate asserts that the analyzer factory keeps the judge off by default, and that assertion
holds. See `evals/results/IMPROVEMENT_TASKS.md` for the current state of each thread, including the
negative results.

## Related

- [Configuration reference](configuration-reference.md) — every environment variable, including the
  Bedrock mantle route and the opt-in verdict repair.
- [LLM analyzer](../architecture/analyzers/llm-analyzer.md) — provider schema constraints.
- [Dependencies and LLM providers](dependencies-and-llm-providers.md) — model naming per provider.
