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

Five specialized passes against one, measured per corpus on Gemma 4 26B, detection at MEDIUM or
above. The `msb-source-disjoint` row is the five-pass arm, not the three-pass arm quoted earlier in
this section:

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

Nothing lands at LOW on this corpus, so severity assignment is effectively bimodal here. That is not a
property of the scanner: on the gitskills sample below, 1.66% of records top out at LOW.

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
nothing at all lands at LOW on these two corpora, so severity assignment is effectively bimodal on them.
The gitskills sample below shows that is corpus-specific rather than structural. On MaliciousSkillBench,
moving the gate down to INFO looks attractive: it raises F1 from 81.4% to 83.2%. On real skills the
same change would flag 88.2% of everything scanned. The MSB-only view would have justified a change
that is unusable in production, which is the reason to keep an unlabelled real-world population in the
evaluation set.

## The real-world flag rate does not transfer between skill populations

Corpus: 200,000 skills from `mvaccargiu/gitskills` (CC-BY-4.0), which indexes skills found in public
git repositories. This is a *different population* from the two Hugging Face datasets behind the
12,498-record benchmark above, which is the point of running it: sampling more from the same two
sources tightens an interval, while sampling somewhere else tests whether the figure means anything.

Static rules only, no model. 18.3 minutes on 16 cores at 182 records/second, 2 errors.

| Threshold | gitskills (n=199,998) | HF skill datasets (n=12,498) |
|---|---|---|
| CRITICAL | 0.121% [0.106, 0.137] | 0.42% [0.32, 0.55] |
| HIGH or above | 0.522% [0.491, 0.555] | 2.46% [2.20, 2.74] |
| MEDIUM or above | **2.228% [2.164, 2.293]** | **3.76% [3.44, 4.11]** |
| INFO or above | 96.971% | 88.21% |

**The MEDIUM+ intervals do not overlap**, so the two populations genuinely differ and the earlier 3.76%
is not a general "real-world false-positive rate". On git-sourced skills the rate is about 1.7x lower at
MEDIUM+ and nearly 5x lower at HIGH+. The direction is favourable, but the lesson is that this figure
has to be quoted with its population every time.

Two things qualify the comparison, and both cut against treating gitskills as the better estimate:

- **These are not all well-formed skills.** `SKILL_LOAD_FALLBACK_USED` fires on 16.89% of records, and
  the run logged YAML frontmatter failures and missing `name`/`description` throughout. The dataset
  indexes candidate Markdown files from repositories, so the population differs in kind and not only in
  origin. A file that is barely a skill gives the security rules less to fire on.
- **The INFO tier is even more dominated by one hygiene rule here.** `MANIFEST_MISSING_LICENSE` fires on
  79.77% of records, which is what puts INFO+ at 97%. It remains a metadata check rather than a security
  finding.

Genuine security signals are correspondingly rare: taint flow on 0.16%, prompt-injection patterns on
0.14%, and correlated network-execution chains on 0.10%.

This sample also corrects an earlier reading. The LOW tier is not empty here: 1.66% of records top out
at LOW, against none on MaliciousSkillBench or the Hugging Face corpora. The bimodal severity
distribution noted above is a property of those corpora, not of the scanner.

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
skills.

The integration ships anyway, as `--system-one-endpoint` and `--system-one-model`, because the protocol
is model-agnostic and a future model may separate the classes. It is **advisory only**: the tier records
a probability and cannot emit a finding, change a severity, or alter the verdict. Enabling it and
demonstrating separation on a corpus is the precondition for anything acting on it. It does not transfer to its intended domain of agent and browser state decisions.

## What enabling the judge costs on real skills

Every judged figure above is from a labelled corpus. This is the judge on an unlabelled real-world
population, which is the number that tells a user what turning it on will do to their own scans. Run
through the Bedrock mantle route on Gemma 4 26B over a 1,000-record sample of the gitskills corpus, core
rule pack, meta off as it ships.

| Configuration | Population | MEDIUM+ | HIGH+ | LOW+ | INFO+ |
|---|---|---|---|---|---|
| Static rules only | 199,998 | 2.23% | 0.52% | 3.89% | 96.97% |
| Plus the judge, meta off | 884 | **4.30% [3.15, 5.85]** | 0.23% [0.06, 0.82] | **70.93%** | 100% |

Two things stand out, and one apparent finding is not one.

**The judge roughly doubles the MEDIUM+ flag rate on a predominantly benign population**, 2.23% to
4.30%. On labelled corpora the judge buys large recall gains; this is the other side of that trade,
measured on the population users actually scan rather than inferred from it.

**The LOW tier is where most of its output goes**: 3.89% to 70.93%. Roughly seven in ten real skills
receive a LOW finding once the judge runs. Combined with the LOW tier being empty on MaliciousSkillBench,
this settles the earlier "severity is effectively bimodal" observation as an artifact of that corpus. It
also means LOW carries almost no information on real skills and should not be gated on.

**HIGH+ does not fall.** It reads 0.23% judged against 0.52% static, but the judged interval is
[0.06, 0.82] on 884 records and contains the static figure, so the two are indistinguishable at this
sample size. Nothing here says the judge suppresses high-severity findings.

### The caveat that bounds this

The judge failed on **116 of 1,000 records (11.6%)**, reported as `analyzers_failed=llm_analyzer`, and
those records are excluded rather than scored as clean. That exclusion is the honest choice, but it also
means the estimate covers the records the judge could read. If failures correlate with size or
complexity — and the context-budget failures documented above suggest they do — the true flag rate on
the whole population is higher than 4.30%. The figure is a floor, not a point estimate.

An arm with the meta-analyzer enabled was also run and is not reported as a comparison: it had a
different usable population (999 records) and its responses mostly failed contract validation on this
corpus and were retained unchanged, so the difference between the arms is not attributable to meta.

Cost: 3.9M judge input tokens for 884 scored records, about 4,400 per skill, consistent with the
single-pass figure measured on MaliciousSkillBench.

## Llama Prompt Guard 2 does not screen skills

`meta-llama/Llama-Prompt-Guard-2-22M` was tested as a cheap pre-filter. It is a 22M-parameter
DeBERTa-v2 classifier, 283 MB, with a 512-token context, so it does not require a GPU: the large runs
below are CPU-only and took 45 minutes for 12,500 skills on 16 cores.

The source-disjoint measurement was also repeated on an Apple M4 Pro GPU through the Metal backend, and
the result is device-independent: AUC 0.6117 against 0.6110 on CPU, identical flag rate, a maximum
per-record probability difference of 1.6e-06 across 1,379 records, and **no** record changing side of the
0.5 threshold. The 1.15x speed difference is expected for a model this small, where tokenization and
Python overhead dominate the matrix work. A conclusion that moved with the backend would have been
suspect; this one does not. Each skill is split into 512-token windows
overlapping by 128 and scored by its **maximum** window probability, which favours detection, so a low
recall cannot be blamed on the chunking.

Corpus: MaliciousSkillBench source-disjoint split, 839 malicious and 545 benign.

| Threshold | Recall | Precision | FPR |
|---|---|---|---|
| 0.5 | 0.0% | 0.0% | 0.4% |
| 0.8 | 0.0% | — | 0.0% |
| 0.9 | 0.0% | — | 0.0% |

It is effectively silent. Two of 1,384 records fire at 0.5 and **both are benign**. AUC is 0.611, so
there is a faint signal and it points the right way — unlike the System One result below, which is
inverted — but the probabilities never reach a threshold anything could act on.

**One number here is misleading and worth stating explicitly.** Sweeping every threshold, the best
achievable F1 is 77.4%, which is higher than the shipped single judge's 61.2% on the same corpus. That
is an artifact of class balance, not a result. It occurs at a threshold of 0.0015 with a **89.0%
false-positive rate**, which is very nearly "flag everything", and the corpus is 60.6% malicious. The
trivial always-flag classifier scores 75.5% F1 here, so the model beats it by 1.9 points. At the
judge's own operating point of 17.6% FPR its recall is 22.3% against the judge's 49.0%, and at a 1%
false-positive rate its recall is 0.1%.

### It is not merely inert: its confident firings are systematically wrong

Corpus: the same 12,500 published skills used for the flag-rate table above.

| Threshold | Records flagged | Rate |
|---|---|---|
| 0.5 | 27 | 0.216% [0.148%, 0.314%] |
| 0.9 | 11 | 0.088% |
| 0.99 | 3 | 0.024% |

The three highest-scoring records — 0.998, 0.995 and 0.993 — are a Chinese-language novel-writing
checklist, a conversation-memory skill, and a prompt optimizer. All three are benign, and two causes
account for the pattern:

- **Non-English text.** Skills containing more than 2% CJK characters (976 of 12,500) are flagged at
  **1.64%** against **0.10%** for the rest, a 16-fold difference. Sixteen of the 27 flagged records are
  CJK-heavy, though such skills are only 7.8% of the corpus. Mean scores are nearly identical
  (0.036 against 0.034), so the effect is confined to the high-confidence tail.
- **Skills whose purpose is to instruct a model.** A prompt-engineering skill reads like an
  instruction-override attempt because directing a model *is* the product.

So enabling it as a screen would penalise non-English and prompt-engineering skills while detecting
essentially none of the labelled malicious ones.

### Its flag rate does not move between populations, where ours does

The same model over 60,000 of the gitskills records, CPU, 34 minutes:

| Population | Flag rate at 0.5 | 95% interval |
|---|---|---|
| Hugging Face skill datasets (n=12,500) | 0.216% | [0.149%, 0.314%] |
| gitskills (n=60,000) | 0.167% | [0.137%, 0.203%] |

**Those intervals overlap**, so Prompt Guard's flag rate is statistically indistinguishable across two
populations that this scanner separates clearly: our own MEDIUM+ rate is 3.76% [3.44, 4.11] against
2.228% [2.164, 2.293] on the same pair, which does not overlap. The underlying score distribution does
shift — mean probability 0.0066 on gitskills against 0.0343, about five times lower — but not enough to
change how often anything crosses a usable threshold.

A screen whose firing rate is flat across populations of visibly different composition is not tracking
what those populations differ in. That is the same conclusion the labelled corpus gives, arrived at
without labels.

**This is a statement about fit, not about the model.** Prompt Guard detects prompt-injection and
jailbreak attempts in text. Whether a skill is safe to install is a different question: a skill can be
malicious through a download-and-execute chain or a credential sink without containing anything an
injection classifier would recognise. The model is doing its job; its job is not this one. It is not
integrated.

### The same measurement, applied to this scanner

The CJK comparison above is worth running against our own output, on the same 12,498 records and the
same 2% threshold. Static rules only, no model:

| Group | Records | MEDIUM+ | HIGH+ | INFO+ |
|---|---|---|---|---|
| More than 2% CJK | 976 | 2.25% | 0.82% | 94.57% |
| Rest | 11,522 | 3.89% | 2.60% | 87.68% |

The deterministic rules flag CJK-heavy skills **less** often, not more: 0.58x at MEDIUM+ and 0.32x at
HIGH+, against Prompt Guard's 16x in the other direction. That is the expected shape for rules keyed on
code constructs — `curl | bash`, base64 decoding, credential paths — which do not care what language the
prose around them is in.

**It does not follow that the scanner is unbiased here, and the corpus cannot settle it.** These
records are unlabelled, so a lower flag rate is consistent with two different explanations: those
skills genuinely do less risky work, or the rules under-detect when the surrounding text is
non-English. Distinguishing them needs labelled non-English skills, which no corpus screened so far
provides. What can be said is the narrow claim: there is no evidence of *over*-flagging non-English
skills, and the direction of any error is towards silence rather than noise.

The INFO+ row moves the other way, 94.57% against 87.68%, which is consistent with
`MANIFEST_MISSING_LICENSE` dominating that tier on more informally published skills.

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

## A System One screen in front of the judge halves the false-positive rate

Both models served locally on H200s: OpenJev (the System One weights) and Gemma 4 26B-A4B as
the judge. Corpus: MaliciousSkillBench source-disjoint, 839 malicious and 545 benign.

**The judge reproduces locally.** Single pass, core rules, meta off, MEDIUM+ on 1,376 usable
records: F1 64.2%, precision 81.6%, recall 52.9%, FPR 18.2%. The Bedrock mantle measurement of
the same model gave 61.2%, 81.5%, 49.0% and 17.6%, so local and hosted agree.

Reaching that required a decoding fix. The first local run lost 46.5% of records to
`finish_reason=length`: under grammar-constrained JSON the model emitted a valid object and
then padded it with whitespace until it hit 8,192 tokens. Serving with
`--structured-outputs-config '{"backend": "xgrammar", "disable_any_whitespace": true}'` took
the failure rate to 0.6% (8 of 1,384). On eight records that had all failed, the patched
server answered 8 of 8 and an unpatched control 4 of 8.

**OpenJev asked choice questions, not `noul`.** Eight boolean threat probes, P(true) read from
the next-token distribution with reasoning disabled. Its `prompt_injection` probe is the
screen.

**The cascade.** Jev screens every record and the judge runs only on those above a threshold.
The threshold was chosen on one hash-selected half of the records (655) to keep recall within
two points of the judge alone while skipping the most benign records, then reported on the
other half (721):

| On the held-out half | F1 | Precision | Recall | FPR | Judge calls |
|---|---|---|---|---|---|
| Judge alone | 61.2% | 76.2% | 51.1% | 23.1% | 100% |
| Jev screen, then judge | **62.6%** | **86.1%** | 49.2% | **11.6%** | **60.7%** |

The screen skips 70.7% of benign records. It is not only a cost saving: records the judge
flags wrongly are often ones Jev scores as harmless, so the cascade vetoes judge false
positives, and precision rises ten points for 1.9 points of recall. The max-probe and
mean-probe screens are weaker (FPR 20.4% and 19.0%) and are not recommended.

This is one corpus, split in half. It has not been measured on the other labelled corpora, so
the threshold should not be assumed to transfer.

## Where the deterministic false positives come from

Earlier work could only say that rule-level suppression buys at most +0.2 F1. That analysis
worked from a record's *set* of rule ids, which has no analyzer attribution and no per-finding
severity. Recording one row per finding, with the analyzer that produced it, changes the
answer.

Corpus: MaliciousSkillBench source-disjoint, 839 malicious and 545 benign, shipped core pack,
no model. The record-level figures reproduce the published baseline — 7.71% FPR and 7.39%
recall at HIGH+ against 7.7% and 7.7% — which is the check that the new pipeline measures the
same thing the old one did.

**By analyzer, counting MEDIUM+ findings on harmless records:**

| Analyzer | On harmless | On malicious | Ratio |
|---|---|---|---|
| correlation | 35 | 29 | **1.21** |
| pipeline | 10 | 33 | 0.30 |
| static | 10 | 30 | 0.33 |

`correlation` is the only analyzer that fires *more* often on harmless records than malicious
ones, and one rule accounts for almost all of it.

**The worst rules by harmless fires**, counting every finding at MEDIUM or above whatever its
exact severity:

| Analyzer | Rule | Harmless | Malicious | Precision |
|---|---|---|---|---|
| correlation | `CORRELATED_NETWORK_EXECUTION_FLOW` | 31 | 7 | **18.4%** |
| pipeline | `PIPELINE_TAINT_FLOW` | 10 | 9 | 47.4% |
| correlation | `CORRELATED_SENSITIVE_NETWORK_FLOW` | 4 | 22 | 84.6% |
| static | `ACTIVE_DYNAMIC_EXECUTION` | 4 | 18 | 81.8% |

### One rule change removes 61% of the deterministic false-positive rate

Counterfactual, recomputed from the findings table by dropping a rule below the gate:

| Configuration | F1 | Precision | Recall | FPR |
|---|---|---|---|---|
| Shipped, all rules | 13.5% | 58.2% | 7.6% | 8.44% |
| Demote `CORRELATED_NETWORK_EXECUTION_FLOW` | 13.3% | **77.2%** | 7.3% | **3.30%** |
| Also demote `PIPELINE_TAINT_FLOW` | 11.5% | 80.0% | 6.2% | 2.39% |

Demoting the one rule cuts the false-positive rate from 8.44% to 3.30% and raises precision
19 points, for three lost true positives. F1 moves −0.2 points, which is flat: the
deterministic layer's recall is low either way, so F1 is insensitive here and precision is the
metric that moves. Taking `PIPELINE_TAINT_FLOW` as well costs 1.4 points of recall for a
further 0.9 of false-positive rate, which is a worse trade.

This is the finding the earlier "suppression cannot help" conclusion missed, and it was
missed because the data shape could not express it.

### The labelled corpus does not surface the rule that matters most in production

The same store over 200,000 gitskills records, MEDIUM+ by rule:

| Rule | Records | Rate |
|---|---|---|
| `FILE_MAGIC_MISMATCH` | 3,080 | **1.540%** |
| `PROMPT_INJECTION_IGNORE_INSTRUCTIONS` | 274 | 0.137% |
| `CORRELATED_NETWORK_EXECUTION_FLOW` | 205 | 0.103% |
| `PIPELINE_TAINT_FLOW` | 195 | 0.097% |

`FILE_MAGIC_MISMATCH` produces three quarters of the 2.071% static MEDIUM+ rate on real
skills, and it barely appears on MaliciousSkillBench. Tuning against the labelled corpus alone
would never have prioritised it. It is unlabelled data, so these are flag rates rather than
false-positive rates, but the ranking is what directs the next tuning pass.

### A measurement artifact worth recording

The first run of this analysis reported a 100% false-positive rate at HIGH+, driven entirely
by `LOW_ANALYZABILITY` and `UNANALYZABLE_BINARY` firing on every record. The cause was the
transfer, not the scanner: copying the corpus from macOS with `tar` carried an AppleDouble
`._SKILL.md` resource fork into all 1,384 record directories, and the scanner correctly
reported a hidden binary file in each one. Deleting the 2,763 sidecars restored agreement with
the published baseline. A corpus that travels between platforms needs checking for
platform-injected files before any figure from it is believed.

## Tuning the deterministic scanner against real skills

Three changes, each chosen from per-analyzer findings and each measured as an A/B against the
previous scanner on the same records. On the labelled split no malicious record changed severity,
so recall is unchanged throughout; every movement is a benign record moving down.

| Change | Labelled HIGH+ FPR (install gate) | Labelled MEDIUM+ FPR | Real skills |
|---|---|---|---|
| Before | 7.71% | 8.44% | MEDIUM+ 4.428% on 19,966 |
| Installer trust in correlation | **5.87%** | 8.44% | 0 records moved |
| Markdown is a text container | 5.87% | 8.26% | MEDIUM+ **3.371%**; 213 moved down, 0 up |
| Claims, not mentions, of Anthropic | 5.87% | **8.07%** | rule flags 4,460 -> 673 over 1.83M manifests |

**Installer trust in correlation.** `CORRELATED_NETWORK_EXECUTION_FLOW` ignored the policy's
`known_installer_domains`, so the pipeline analyzer demoted `curl https://astral.sh/... | sh` to LOW
while the correlation analyzer raised the same line to HIGH. A fenced, fixed-HTTPS download whose
every host is on the curated LOTS-aware legitimate list, or a configured installer, is now MEDIUM:
reported, but no longer blocking. Path scoping is kept, so `raw.githubusercontent.com/nvm-sh` trusts
nvm rather than every GitHub user, and one untrusted download in a block keeps every flow in it
HIGH. Twenty-nine of the thirty-one benign firings failed the old installer test on a single
condition, the role classifier.

**Markdown is a text container.** 85% of all `FILE_MAGIC_MISMATCH` findings on real skills were a
`SKILL.md` that Magika reads as YAML, because the skill format requires YAML frontmatter. A text or
code label in Markdown is no longer a mismatch; binary content in a `.md` file still is. On the
skills it used to flag, the LLM judge independently found nothing concerning in 96.1%.

**Claims, not mentions.** `SOCIAL_ENG_ANTHROPIC_IMPERSONATION` fired on any skill containing the word
"anthropic". It now fires on a claim of affiliation. The old exemption was a substring test that also
exempted real claims -- "...applies fixes. Official Anthropic skill." passed because it contained
"apply" -- and the new rule catches 221 such claims the old one missed.

### Candidates measured and rejected

- **Exempting read-only `find -exec`.** Twenty of 77 real skills flagged by `COMPOUND_FIND_EXEC` run
  only read-only tools through `-exec`, but every one of the six malicious skills this rule catches
  on the labelled split uses exactly those tools (`-exec file`, `-exec md5`) for reconnaissance. The
  exemption would have removed all of its detections.
- **Scoping `find` by search root.** Malicious skills search named directories and real skills most
  often search `~`, so the root does not separate the classes.
- **Trusting a host because it matches the skill's own name.** An attacker controls both, so it is not
  a trust signal; ordinary unknown hosts stay HIGH for fetch-and-execute.
- **Taking fetch-and-execute below MEDIUM.** A live fetch cannot prove its own integrity, and the
  existing design keeps such behaviour visible and actionable.

### What the labelled corpus cannot tell us

`SUPPLY_CHAIN_UNPINNED_DEPENDENCY`, `YARA_jailbreak_generic`, `YARA_autonomy_abuse_generic` and
`SECRET_CONNECTION_STRING` never fire on MaliciousSkillBench, whose records are a single `SKILL.md`
with no dependency files, so there is no labelled evidence of what they catch. On real skills the
judge clears 75% to 92% of their flags, but on 12 to 30 flags each. They are held for the full-corpus
adjudication rather than changed on that sample.

## What rule-level suppression cannot fix

Suppressing any combination of up to four of the highest-volume rules changes F1 by at most +0.2
points. Benign records that flag fire 3.9 rules on average and essentially never a single rule alone,
so their rule profile is not separable from that of true positives. Reducing the false-positive rate
needs a per-record judgement, not a policy change.

## Reproducing

The evaluation harness lives in `evals/`. It is deliberately outside the blocking release path: the
release gate asserts that the analyzer factory keeps the judge off by default, and that assertion
holds.

The same-model comparison needs one extra piece. Gemma 4 26B is reachable only through the Bedrock
mantle route, which authenticates with SigV4, and SkillSpector's OpenAI-compatible provider sends a
static bearer token. `evals/lib/mantle_proxy.py` bridges that: it accepts chat completions on
loopback, signs them, and forwards the body unchanged, so both tools send what their own code
produced. It binds to loopback only and requires a shared token.

`evals/results/` is not tracked, so the run tracker referenced during development is not in the
repository. The negative results it recorded are written up in the sections above, and the full
per-corpus tables are on the published Space linked at the top of this page.

## Related

- [Configuration reference](configuration-reference.md) — every environment variable, including the
  Bedrock mantle route and the opt-in verdict repair.
- [LLM analyzer](../architecture/analyzers/llm-analyzer.md) — provider schema constraints.
- [Dependencies and LLM providers](dependencies-and-llm-providers.md) — model naming per provider.
