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

These are the shipped rules before the tuning described
[below](#tuning-the-deterministic-scanner-against-real-skills). On the same split with the tuned
rules, at the same HIGH+ threshold: precision 73.0%, recall 7.7% (unchanged), false-positive rate
**4.4%**, F1 14.0%.

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

**This threshold was selected on test members.** MaliciousSkillBench's source-disjoint split used
here is the benchmark's frozen test partition, and the dataset forbids selecting thresholds on
frozen test members. Selecting on one half and reporting on the other keeps the reported half
unseen, but the half used for selection is test data. The cascade figures above should be read as
exploratory until the threshold is re-selected on the train/validation partition.

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

Every usable skill in the gitskills corpus -- 1,876,662 of 1,876,769 records; the 107 the loader cannot
read are excluded, not counted as clean -- scanned in full by every deterministic analyzer, once with
the shipped scanner (`5b696a1`) and once with the tuned one (`f3a42f3`). Each change was chosen from
the per-analyzer findings of the first scan, adjudicated against the local judge, and checked on every
labelled corpus before it was kept. The records are unlabelled, so these are flag rates, which bound
the false-positive rate from above.

| Threshold | Shipped | Tuned | Change |
|---|---|---|---|
| MEDIUM+ | 4.184% [4.155, 4.212] | **2.466%** [2.444, 2.488] | **−41.1%** |
| HIGH+ | 2.469% [2.447, 2.491] | 2.312% [2.291, 2.334] | −6.4% |
| CRITICAL | 0.629% [0.617, 0.640] | 0.598% [0.587, 0.609] | −4.9% |

32,243 records left MEDIUM+ and 7 entered it. The flags that remain are ones the judge agrees with
more often: it also flags 45.6% of the tuned scanner's MEDIUM+ records, against 28.0% of the shipped
scanner's.

**By rule, MEDIUM+ records on the full corpus:**

| Rule | Shipped | Tuned | Change | What changed |
|---|---|---|---|---|
| `FILE_MAGIC_MISMATCH` | 19,606 | 108 | −99% | A text label in Markdown is not a mismatch; binary content still is |
| `PIPELINE_TAINT_FLOW` | 10,082 | 5,438 | −46% | Benign-pipe rules match real commands; an interpreter reading data is not a sink |
| `CORRELATED_NETWORK_EXECUTION_FLOW` | 9,425 | 7,556 | −20% | Installer trust; piping into `python -m json.tool` is not execution |
| `ACTIVE_DYNAMIC_EXECUTION` | 7,743 | 7,150 | −8% | An empty call in code, or "eval (" in prose, is not a call |
| `SOCIAL_ENG_ANTHROPIC_IMPERSONATION` | 4,546 | 264 | −94% | A claim of affiliation, not a mention of the vendor |
| `SUPPLY_CHAIN_UNPINNED_DEPENDENCY` | 3,721 | 0 | −100% | Reported at LOW: hygiene, not a threat signal |
| `YARA_autonomy_abuse_generic` | 1,771 | 932 | −47% | "Do not proceed without user confirmation" is the opposite instruction |
| `YARA_sql_injection_generic` | 1,433 | 1,185 | −17% | `sleep(1);` in PHP, JS and k6 is not a time-based payload |
| `YARA_capability_inflation_generic` | 625 | 359 | −43% | "Easter egg" is UI copy |

**What each change rests on.**

- **Markdown is a text container.** 85% of `FILE_MAGIC_MISMATCH` findings were a `SKILL.md` that
  Magika reads as YAML, because the skill format requires YAML frontmatter. The judge cleared 95% of
  them.
- **Benign pipes match real commands.** `benign_pipe_targets` were matched against the whole string,
  so `curl ... | jq '.[] | .name'` never matched `curl\s.*\|\s*jq`, and `python -m json.tool` never
  matched `python3`. A rule now matches from the start, and whatever follows may only be the last
  command's arguments: another pipe, chaining, redirection or command substitution keeps the finding.
- **A piped interpreter runs stdin only when it has no program.** `curl URL | bash` and `| python -`
  execute what was fetched; `| python -m json.tool`, `| python script.py` and `| python3 -c
  "json.load(sys.stdin)"` read it as data. One rule, in `skill_scanner/core/shell_semantics.py`, is
  shared by the pipeline and correlation analyzers. It skips redirections (`| sh 2>/dev/null` still
  runs the payload), stops at shell control and Markdown text (`| sh && tool login`, `| bash #
  recommended`), and treats an inline program that executes what it reads (`python -c
  'exec(sys.stdin.read())'`) as running stdin. The first version missed the redirection and the
  trailing-text cases; measuring the removed chains on real skills is what found them.
- **Installer trust in correlation.** The correlation analyzer ignored the policy's
  `known_installer_domains`, so one `curl https://astral.sh/... | sh` was LOW in the pipeline analyzer
  and HIGH in this one. Trusted, path-scoped hosts now grade MEDIUM.
- **Claims, not mentions, of Anthropic.** The rule fired on the word "anthropic". It now fires on an
  authorship claim ("by/from/built by Anthropic", "Anthropic-verified") or on "official" qualifying the
  skill itself ("Anthropic official skill"), not Anthropic's own material ("Anthropic's official brand
  colors", "the official Anthropic specification"), "powered by Anthropic", or an identifier such as
  `anthropic-report.py`. "Imported skill ... from Anthropic" still counts: it asserts origin.
- **Negations and code in three YARA rules.** Most "proceed without user" and "retry forever" hits
  were "do not proceed without user confirmation" and "don't retry forever"; the phrase now counts only
  when it occurs more often than its negation. Generic `sleep(` counts as a time-based SQL payload only
  after a closing quote. Each new pattern matches a subset of the old one.
- **Empty calls.** In fenced code, `eval()` with nothing to run executes nothing. In prose the empty
  form is kept: a malicious development package says "EXECUTE its contents via `exec()`". This rule's
  promotion evidence is bound to its implementation hash, so the change was re-verified on the same
  6,597-package MaliciousSkillBench train/validation selection: output byte-identical, 180 hits, all
  malicious.

**One defect was introduced and fixed along the way.** The Markdown change made `FILE_MAGIC_MISMATCH`
emit LOW, which the core pack did not declare as an allowed demotion. The finding contract rejected
every such finding and marked the static analyzer failed, which on the first rescan excluded 904
records from the measurement. The unit test called the check directly, where no contract is enforced;
the regression test now scans through `SkillScanner`.

### The same change on labelled corpora

Shipped against tuned, static arm, MEDIUM+ unless stated:

| Corpus | Records | Recall | FPR | Precision |
|---|---|---|---|---|
| MaliciousSkillBench source-disjoint | 1,384 | 7.99% → 7.99% | 8.44% → **4.59%** | 59.3% → **72.8%** |
| ↳ at HIGH+ (install gate) | | 7.75% → 7.75% | 7.71% → **4.40%** | 60.7% → **73.0%** |
| MaliciousSkillBench balanced-800 | 800 | 33.00% → 31.00% | 2.00% → 1.25% | 94.3% → 96.1% |
| OpenSkillRisk (positives only) | 374 | 31.55% → 29.95% | — | — |
| MCP tool poisoning | 50 | 40.0% → 40.0% | 0% → 0% | 100% → 100% |

HarmfulSkillBench (200, unlabelled for this purpose) moves from a 4.0% to a 3.5% flag rate, the
12,498-skill real-world population from 3.76% to 2.59%, and a separate 200,000-record gitskills
sample from 2.23% to 0.53%.

**The recall cost is real and is stated rather than averaged away.** Sixteen positive records on
balanced-800 and OpenSkillRisk drop below MEDIUM. In every one, the finding that carried the record
was not the malicious behaviour: `curl ... | python3 -m json.tool` formatting, `cat <<JSON | node
script.js` passing data, a vendor mention of Anthropic, an unpinned dependency, a text label in
Markdown. These records are malicious for reasons the deterministic layer does not see; the judge is
the layer meant to catch them. Keeping a rule firing on the wrong evidence for its incidental recall
would keep the false positives that come with it.

### Candidates measured and rejected

- **Exempting read-only `find -exec`.** Twenty of 77 real skills flagged by `COMPOUND_FIND_EXEC` run
  only read-only tools through `-exec`, but every one of the six malicious skills this rule catches
  on the labelled split uses exactly those tools (`-exec file`, `-exec md5`) for reconnaissance. The
  exemption would have removed all of its detections.
- **Scoping `find` by search root.** Malicious skills search named directories and real skills most
  often search `~`, so the root does not separate the classes.
- **Trusting a host because it matches the skill's own name.** An attacker controls both, so it is not
  a trust signal; ordinary unknown hosts stay HIGH for fetch-and-execute.
- **Taking fetch-and-execute below MEDIUM.** A live fetch cannot prove its own integrity. Thirteen of
  the 25 benign MEDIUM+ records left on the source-disjoint split are vendor installers
  (`curl -fsSL https://cli.tavily.com/install.sh | bash`); separating those from a malicious `| sh`
  needs domain reputation, which is policy (`known_installer_domains`), not a rule change.
- **Dropping empty calls in prose.** It removed the only hit on a malicious development package.
- **Placeholder exemptions for `SECRET_CONNECTION_STRING`.** The judge's verdicts do not separate the
  shapes: it clears 93% of opaque passwords on local service hosts (docker-compose development
  credentials) and only 18% of placeholder passwords on placeholder hosts. A hardcoded development
  credential is still one, so this is left to policy.

### A second pass, from reading the flags one by one

Forty records per rule -- thirty the judge cleared, ten it agreed with -- were rescanned and read
line by line. Three rules had a shape that separates cleanly; each change was then measured on every
real skill it could touch and on MaliciousSkillBench train/validation (6,594 packages; the frozen
test split was not used to design anything in this pass).

| Rule | Flags removed on real skills (judge cleared) | Flags kept (judge cleared) |
|---|---|---|
| `CORRELATED_SENSITIVE_NETWORK_FLOW` | 1,484 (**88%**) | 4,237 (61%) |
| `PROMPT_INJECTION_IGNORE_INSTRUCTIONS` | 1,405 (**88%**) | 2,045 (49%) |
| `ACTIVE_DYNAMIC_EXECUTION` | 182 (**91%**) | 6,968 (65%) |

2,705 records leave MEDIUM+ (the judge cleared 89% of them) and none moves up, taking the full-corpus
MEDIUM+ rate from 2.466% to **2.322%**. On train/validation recall moves 31.53% → 31.45% (four
malicious packages whose only finding was a credential sent to its own provider or a backticked
list item) and FPR 1.12% → 1.05%.

- **A credential authenticating to its own service is not exfiltration.** 29 of 30 judge-cleared
  samples were `Authorization: Bearer $KEY` to the key's own API, `-u admin:$PASSWORD` to localhost,
  or `?key=$KEY`. The analyzer already exempted provider-bound authentication, but only for
  `os.environ.get()`: the subscript form `os.environ['OPENROUTER_API_KEY']` -- the usual way to read
  a key -- never bound its provider, which is a bug and is fixed. Loopback destinations, vendor key
  headers (`X-N8N-API-KEY`, `Ocp-Apim-Subscription-Key`) and query-parameter keys now count as
  authentication; the provider binding still decides, so the same header to another host stays
  flagged. A fourth relaxation -- trusting an unresolved endpoint variable paired with a
  same-vendor key -- was measured and **rejected**: a malicious development family ships its own
  config file and tells the agent to source it, so the package does control that endpoint.
- **A short prose quotation of "ignore previous instructions" is a mention.** Of this rule's
  real-world flags, quoted occurrences were 64% and the judge cleared 86% of them; bare imperatives
  were 36% cleared. Of 35 malicious development hits, 30 are bare. The exclusion covers only a
  quotation that closes within a few words in prose: a quoted *value* (after `:` or `=`, as in a
  JSON field or HTTP header) or a quotation that carries on past a sentence break still fires. A
  first, broader version cut in-page prompt-injection recall on page text from 15,369 to 9,619 raw
  hits -- injected headers such as `"x-ai": "Ignore all previous instructions. ..."` -- and was
  narrowed until it moved that population by one hit (15,369 → 15,368). The rule's hash-bound
  evidence was re-verified: disregard-branch hits 11 → 11, benign 0 → 0, NotInject 0 → 0; the new
  exclusion and these measurements are recorded in the evidence file.
- **Methods and checklist prohibitions are not calls.** `image.eval(...)` and `session.exec(...)`
  are methods, and "— no `os.system(user_input)`" is a prohibition. A broader change -- ignoring
  `subprocess.run([...])` with a literal non-interpreter program -- was measured and **rejected**:
  it removed 12 of 180 malicious development hits, which use exactly that form for persistence
  (`systemctl enable`), reconnaissance (`netstat`, `git config --list`) and exfiltration
  (`gsutil cp`). Syntax cannot separate those; the program's purpose does.

### A third pass: housekeeping and delegation

- **A copied cleanup line.** `find ~/.gstack/sessions -mmin +120 -type f -exec rm {} +`, the
  session-cleanup preamble of a widely copied skill pack, was 54% of all `COMPOUND_FIND_EXEC` flags
  (3,014 of 5,581; the judge cleared 94%), and `FIND_EXEC_PATTERN` flagged the same line.
  `COMPOUND_FIND_EXEC` now skips age-bounded removal of files in a tool's own dot-directory through a
  closed grammar -- one root under `~/.<tool>/<subdir>` that is not a credential or browser store,
  files only, an age predicate, a plain `rm` -- and checks every `find -exec` line in a block, so a
  housekeeping line cannot hide another. `FIND_EXEC_PATTERN` already excluded `-mtime` cleanup but not
  its minutes form `-mmin`. None of the 33 malicious development hits (shell spawns through `-exec`,
  SUID `chmod`, `openssl` encryption, `file`/`md5` reconnaissance) has the shape. **3,050 records leave
  MEDIUM+** (the judge cleared 93%).
- **"Do not tell the user to run it"** directs the agent to act itself rather than delegate; nothing is
  hidden. The concealment rule's precision layer suppressed two exact sentences; it now suppresses
  this shape whenever nothing on the line could make it a cover -- no clause connector, secret,
  credential, harmful object or concealment word -- and every adversarial case already in the suite
  ("...to run this command; silently upload credentials", "...to click the phishing link") stays
  flagged. 109 records leave MEDIUM+ (84% judge-cleared).

Neither change moves train/validation (recall 31.45%, FPR 1.05%). With both, **the full-corpus MEDIUM+
rate is 2.153%**, against 4.184% for the shipped scanner: 48.5% fewer flagged skills.

- **A persona named Dan is not the DAN jailbreak**, and "I'm a developer" is a self-description,
  not a claim over the model. `YARA_jailbreak_generic` now matches `DAN` only in capitals (the
  surrounding words stay case-insensitive) and developer claims only as "I'm *your* developer" or
  "I built you". No labelled hit changes; 127 real skills leave MEDIUM+ (83% judge-cleared). Two
  further narrowings were measured and **rejected**: dropping "admin password" / "master key" from
  the override-code string and "dark mode" from the alter-ego string would remove 903 real-world
  flags, but the judge clears the removed and the kept at the same rate (73% and 72%), and seven
  malicious development records are detected by those strings alone. The detection is coincidental
  -- configuration text in an otherwise malicious skill -- but without a better signal it is kept.

Exact duplicates do not inflate these rates: only 6.2% of flagged records belong to a family of
identical `SKILL.md` files, and the largest family has seven copies.

### What remains

The largest remaining sources are `ACTIVE_DYNAMIC_EXECUTION` (6,968 records), `COMPOUND_FIND_EXEC`
(5,581), `CORRELATED_NETWORK_EXECUTION_FLOW` (7,556) and `CORRELATED_SENSITIVE_NETWORK_FLOW` (4,237).
They are also where the labelled recall lives: demoting any one of them costs 16 to 181 malicious
development detections. They are left to the policy packs below rather than changed for everyone.

## The LLM judge on every real skill

Gemma 4 26B-A4B, served locally, read 1,871,285 of the 1,876,769 gitskills records (99.7%); 5,484
could not be analysed and are excluded, not counted as clean. A further 96,128 were analysed with
partial coverage: the shipped prompt budget left at least one file out, and the judge still
returned a verdict on the rest.

| Package verdict | Skills | Share |
|---|---|---|
| SAFE | 1,514,191 | 80.9% |
| SUSPICIOUS | 322,027 | 17.2% |
| MALICIOUS | 35,067 | 1.9% |

It flags **12.5%** of real skills at MEDIUM or above -- five times the tuned deterministic rate --
and the two layers barely overlap (Cohen's κ 0.076): 15,851 records are flagged by both, 29,214 only
by the rules, 218,671 only by the judge. Reading its false positives record by record, almost all
are `CONTEXTUAL_RISK` findings about what a skill is *for*: a browser-automation skill "can execute
arbitrary JavaScript", a payments skill "can execute financial transactions", a skill that needs an
API key "exposes credentials", a documented `npm install` "introduces supply-chain risk". The
largest single cell on real skills is `unauthorized_tool_use` / `CONTEXTUAL_RISK`.

### A prompt that separates capability from misuse

The threat-analysis prompt now lists what is not a finding on its own -- the capability the skill
exists to provide, the breadth of declared permissions, installing dependencies from a registry,
requiring API keys, hypothetical injection, quality issues -- and, equally explicitly, the misuse to
report even when it is phrased as routine: a bundled or downloaded script the agent must run
automatically or on a trigger, instructions to hide actions or override other instructions, and
data sent where the stated purpose does not need it.

The prompt was written from real skills and MaliciousSkillBench train/validation (600 malicious,
1,338 benign), then evaluated once on the frozen test split. A first version that also capped
`CONTEXTUAL_RISK` severity lost eight points of recall -- the model downgraded genuine "run this
setup script" instructions -- and was replaced.

| MEDIUM+, Gemma 4 via Bedrock | Recall | FPR | Precision | F1 |
|---|---|---|---|---|
| Train/validation, shipped prompt | 86.2% | 28.2% | 57.8% | 69.2% |
| Train/validation, new prompt | 88.8% | 23.6% | 62.8% | 73.6% |
| **Test (held out), shipped prompt** | 51.6% | 16.1% | 83.1% | 63.7% |
| **Test (held out), new prompt** | **65.8%** | **12.5%** | 89.0% | **75.7%** |

On 2,000 uniformly sampled real skills the MEDIUM+ flag rate falls from 12.8% to 10.5%. Analyses
lost to the verdict/findings consistency contract halve on the test split (27 → 13).

**The remaining contradictions are now repaired by default.** A model that returns `SAFE` while
listing findings contradicts itself, and the strict path discarded the whole analysis; 57 of 58 such
train/validation failures were benign records, so the judge went silent exactly where it would
produce false positives, and an un-analysed skill passes the gate. The escalate-only repair (`SAFE`
becomes `SUSPICIOUS`, findings kept) already existed behind
`SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT`; it is now on unless disabled. Scored with it on, the
figures above hold: train/validation FPR 24.0% (from 23.6%), test unchanged.

### The judge's own verdict is a strong gate

Each finding carries the model's `TRUE_POSITIVE` or `CONTEXTUAL_RISK` label. Counting only
`TRUE_POSITIVE` findings toward MEDIUM+ -- available as `llm_analysis.contextual_risk_max_severity:
LOW`, which reports contextual findings at LOW -- is an operating point, not a free win:

| New prompt, contextual findings capped at LOW | Recall | FPR | Real-skill flag rate |
|---|---|---|---|
| Train/validation | 83.8% | 6.9% | |
| Test (held out) | 49.6% | 4.2% | |
| 2,000 real skills | | | 3.0% |

It cuts the false-positive rate by two thirds or more on every population, and costs 5 points of
recall on train/validation but 16 on the test split, so it ships off by default and on in the
`quiet` pack. A middle point caps only findings the model rates LOW confidence
(`llm_analysis.low_confidence_max_severity: LOW`, on in `low-noise`):

| New prompt, MEDIUM+ | Train/val recall | Train/val FPR | Test recall | Test FPR | Real-skill flags |
|---|---|---|---|---|---|
| No cap | 88.8% | 24.0% | 65.9% | 12.5% | 10.45% |
| Low-confidence findings at LOW | 86.3% | 16.6% | 62.3% | 10.5% | 7.60% |
| Contextual findings at LOW | 83.8% | 6.9% | 49.6% | 4.2% | 3.00% |

## Policy packs instead of knobs

The scan policy has hundreds of settings. Most users need one decision: how much review capacity
they have. Two presets, chosen from data rather than by hand, sit beside `strict`, `balanced` and
`permissive`:

- **Selection.** Every rule was scored by how many real skills it alone drives to MEDIUM+ that the
  judge also cleared, against how many malicious train/validation packages it alone detects. Rules
  were demoted greedily in that order, and the path was cut at two points.
- **Demotion, not deletion.** A demoted rule is reported at LOW: still visible, not gating.

| Preset | Rules reported at LOW | LLM caps | Real-skill MEDIUM+ (rules) | Train/validation recall (rules) | FPR (rules) |
|---|---|---|---|---|---|
| `balanced` (default) | 0 | none | 2.153% | 31.45% | 1.05% |
| `low-noise` | 11 | low-confidence at LOW | 1.937% | 31.35% | 1.05% |
| `quiet` | 19 | low-confidence and contextual at LOW | 1.331% | 29.78% | 0.15% |

`low-noise` costs five malicious detections of 1,653 for a 10% cut in real-world flags. `quiet`
is for triage queues where review capacity is the binding constraint. Past that point every
further demotion costs dozens of detections -- `ACTIVE_DYNAMIC_EXECUTION` alone carries 109 -- so
the curve is cut there. Use them with `--policy low-noise` or `--policy quiet`, or pick them in
`configure-policy`.

## Evaluation hygiene

- **Endpoint protection edits a corpus silently.** Microsoft Defender quarantined `SKILL.md` files
  from local copies of MaliciousSkillBench -- five from the test split, nine from a development
  sample within hours of copying -- so a malicious record became an empty one and local runs
  understated recall. All figures in this and later sections were produced on a Linux analysis
  host; anyone reproducing them should keep sample corpora off endpoint-protected machines, and
  check record counts against the manifest before believing a result.
- **Frozen test members.** Two earlier steps used the test split in ways its terms forbid: the
  cascade threshold above was selected on half of it, and the `curl ... | python -m json.tool`
  finding behind the stdin-program change was first seen in its false positives. The change is
  independently supported on real skills (the judge cleared 55% of the removed flags against 29% of
  those kept), but its test-split improvement is not an unbiased estimate. Everything in the second
  pass, the new prompt and the policy packs was designed on train/validation and real skills only.
- **`msb-balanced-800` overlaps the test split.** 137 of its 800 records are source-disjoint test
  members, so its figures are not held out and it was not used to select anything.

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
