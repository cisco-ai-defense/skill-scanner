# Recommended Settings

Which configuration to run for which job, why, and how to set it up. Every number on this page is
measured -- see [Measured results](../reference/measured-results.md) for how -- and each one names
its population, because a flag rate measured on one set of skills does not transfer to another.

Three populations appear throughout:

- **Development**: 600 malicious and 1,338 benign MaliciousSkillBench train/validation packages,
  which the rules and the judge prompt were tuned on. Treat these as optimistic.
- **Held-out test**: MaliciousSkillBench's frozen source-disjoint split, 839 malicious and 545 benign,
  used to design nothing. This is the number to plan on.
- **Real skills**: the 1.88 million published skills of the gitskills corpus for the rules, and
  2,000 of them sampled uniformly for anything involving the judge. They are unlabelled, so the rate
  is how many would reach you -- an upper bound on the false-positive rate, not a measure of it.

"Recall" is the share of malicious skills flagged; "FPR" is the share of harmless ones flagged.

## The short version

| You are... | Configuration | Block on | Review | What reaches you |
|---|---|---|---|---|
| [Writing skills](#writing-skills-locally-and-in-pre-commit) | rules, `low-noise` | HIGH | -- | 1.9% of real skills blocked |
| [Gating your team's own skills in CI](#gating-your-own-skills-in-ci) | rules, `low-noise` | HIGH | MEDIUM annotations | 1.9% blocked |
| [Vetting third-party skills before install](#vetting-third-party-skills-before-install) | rules + LLM judge, `balanced` | HIGH | MEDIUM | 11.7% reviewed, 3.8% blocked |
| [Vetting with little review capacity](#vetting-with-limited-review-capacity) | rules + LLM judge, `quiet` | HIGH | MEDIUM | 3.9% reviewed, 2.9% blocked |
| [Scanning a registry or marketplace](#scanning-a-registry-or-marketplace) | rules, `low-noise`; judge where the budget allows | HIGH | MEDIUM | 1.9% of real skills from the rules |
| [Keeping skill content on your machines](#keeping-skill-content-on-your-own-machines) | as above, with a self-hosted judge | as above | as above | as above |
| [Hunting](#hunting-research-and-incident-response) | every rule pack, judge with `--llm-decompose` | never | everything | most skills flag; triage only |

Two things hold in every case:

- **Block at HIGH, review at MEDIUM.** With the judge on, a MEDIUM threshold catches twice the
  malicious skills that HIGH does (66.7% against 33.7% on the held-out test split) and also flags
  15.4% of harmless ones, against 6.4%. That is a review queue, not a gate. A HIGH gate with a MEDIUM
  review queue gets both.
- **Treat an unanalysed skill as unreviewed, not as clean.** A skill the judge could not read passes
  the gate today; see [Gaps to handle yourself](#gaps-to-handle-yourself).

## Writing skills: locally and in pre-commit

**Recommendation.** Deterministic rules only, with the `low-noise` preset, blocking at HIGH.

```bash
skill-scanner scan ./my-skill --policy low-noise
```

For the pre-commit hook, create `.skill_scannerrc` in the repository root and install the hook with
`skill-scanner-pre-commit --install`:

```json
{
  "skills_path": ".claude/skills",
  "severity_threshold": "high",
  "policy": "low-noise",
  "fail_fast": true
}
```

**Why.** The rules need no keys, send nothing anywhere and take milliseconds per skill, which is what
a pre-commit hook needs. `low-noise` reports at LOW the 11 rules that, on real skills, most often
drive a flag on their own that the LLM judge considers harmless, relative to the malicious
development packages they alone detect. On the held-out test split it gives up one detection of 839
(recall 8.0% to 7.9%) and leaves the false-positive rate unchanged; across 1.88 million real skills
it takes the MEDIUM+ flag rate from 2.14% to 1.93%.

**What to expect.** 1.85% of real skills blocked at HIGH, 1.93% flagged at MEDIUM+. Rules alone catch
7.7% of the held-out malicious skills at HIGH: they are there to catch unambiguous patterns --
fetch and execute, hardcoded credentials, injection strings -- while you write, not to judge intent.

## Gating your own skills in CI

**Recommendation.** Rules only, `low-noise`, fail the job on HIGH, and upload SARIF so MEDIUM
findings appear as pull-request annotations for a reviewer.

With the reusable workflow:

```yaml
jobs:
  scan:
    uses: cisco-ai-defense/skill-scanner/.github/workflows/scan-skills.yml@main
    with:
      skill_path: .claude/skills
      policy: low-noise
      fail_on_severity: high
    permissions:
      security-events: write
      contents: read
```

Or directly:

```bash
skill-scanner scan-all ./skills --recursive --policy low-noise \
  --fail-on-severity high --format sarif --output results.sarif
```

**Why.** Skills your team writes are trusted for intent, so the gate is for mistakes and for
copied-in patterns, which the rules catch cheaply and deterministically -- the same input always
gives the same answer, so a failing build is reproducible. The judge is worth adding here only if
your team imports skills from elsewhere; if it does, use the next section for those.

**What to expect.** The same rates as above: a HIGH gate at this setting fails on about 1.9 skills in
a hundred on the real-world population measured here. Expect more if your skills install software
or handle credentials, because that is what the rules look at.

## Vetting third-party skills before install

**Recommendation.** Rules plus the LLM judge, the default `balanced` preset, a HIGH gate and a
MEDIUM review queue.

```bash
export SKILL_SCANNER_LLM_MODEL="bedrock-mantle/google.gemma-4-26b-a4b"   # or your provider's model
export SKILL_SCANNER_LLM_API_KEY="..."                                  # not needed for Bedrock (IAM)
skill-scanner scan ./downloaded-skill --use-llm --fail-on-severity high --format json --output scan.json
```

Everything MEDIUM or above in `scan.json` goes to a person; anything HIGH or above is blocked
outright.

**Why.** Rules alone catch 8% of the held-out malicious skills, because most malicious skills contain
nothing a pattern can prove: an instruction to run a bundled script on a trigger, or to send data
somewhere the skill's purpose does not need it. That is what the judge reads for. The judge prompt
separates a skill's purpose from misuse, so a payments skill that moves money or a browser skill
that runs JavaScript is not a finding on its own.

**What to expect.**

| Rules + judge, `balanced` | Held-out recall | Held-out FPR | Real skills |
|---|---|---|---|
| Review at MEDIUM+ | 66.7% | 15.4% | 11.7% |
| Block at HIGH+ | 33.7% | 6.4% | 3.8% |

The judge costs about 3,800 input and 90 output tokens per skill, averaged over 1.88 million real
skills with Gemma 4 26B (see [Choosing the judge model](#choosing-the-judge-model)).

## Vetting with limited review capacity

**Recommendation.** The same, with `--policy quiet` -- or `low-noise` for a middle point.

```bash
skill-scanner scan ./downloaded-skill --use-llm --policy quiet --fail-on-severity high
```

**Why.** Both presets demote rules and cap the judge's weakest findings at LOW. Each judge finding
carries the model's own confidence and its label: `TRUE_POSITIVE` when the cited evidence establishes
the behaviour, `CONTEXTUAL_RISK` when it describes a risky capability whose intent is not
established. `low-noise` caps findings the model rates low-confidence; `quiet` also caps contextual
ones and demotes 19 rules instead of 11. Nothing is hidden -- capped findings are still reported, at
LOW -- but they no longer gate or queue.

**What to expect.**

| Rules + judge, MEDIUM+ review queue | Held-out recall | Held-out FPR | Real skills reviewed |
|---|---|---|---|
| `balanced` | 66.7% | 15.4% | 11.7% |
| `low-noise` | 63.2% | 13.4% | 8.7% |
| `quiet` | 50.3% | 7.2% | 3.9% |

At the HIGH gate the three are close (33.7%, 33.7% and 33.1% recall; 3.8%, 3.6% and 2.9% of real
skills blocked), so the choice is about the review queue. `quiet` more than halves it relative to
`low-noise`, and misses about a quarter of the malicious skills `balanced` would have queued.
Choose it when the queue, not the attacker, is the binding constraint.

**Do not use `quiet` without the judge.** Its extra rule demotions were chosen on development data
and real skills; on the held-out test split they halve what the rules alone catch (8.0% to 4.2% at
MEDIUM+). With the judge on, the judge carries that recall.

## Scanning a registry or marketplace

**Recommendation.** Rules on every skill with `low-noise`; the judge either on every skill if the
budget allows, or on the skills the rules flag plus a random sample of the rest, so the judge's own
flag rate on your population is measured rather than assumed.

```bash
skill-scanner scan-all ./registry --recursive --policy low-noise --format json --output rules.json
```

**Why.** At registry scale the judge is the cost: judging all 1.88 million skills took 7.1 billion
input tokens. The rules scanned them in about ninety minutes with ten processes on one 16-core host.
Across all of them the tuned rules flag 2.14% at MEDIUM+ (1.93% with `low-noise`, 1.33% with
`quiet`), and where the judge could read the whole skill it agrees with 47% of what they flag.

**Measured, not yet shipped: a small model in front of the judge.** Screening every skill with the
OpenJev System One model and sending only those it scores above a threshold to the judge flagged
1.75% of real skills with only 3.1% of them reaching the judge, at 61.3% held-out recall and 2.4%
FPR. The shipped `--system-one-endpoint` tier is advisory only -- it records a probability and
cannot change a finding -- so this is not a configuration yet; the measurement is in
[Measured results](../reference/measured-results.md#re-selected-on-trainvalidation).

## Keeping skill content on your own machines

**Recommendation.** Any of the configurations above with a self-hosted judge. Gemma 4 26B-A4B
served locally with vLLM reproduces its hosted results (held-out F1 64.2% locally against 61.2%
hosted, same prompt).

```bash
export SKILL_SCANNER_LLM_PROVIDER=openai
export SKILL_SCANNER_LLM_BASE_URL=http://127.0.0.1:8000/v1
export SKILL_SCANNER_LLM_MODEL=gemma-4-26b-a4b     # the name vLLM serves the model under
export SKILL_SCANNER_LLM_API_KEY=unused              # required by the route; vLLM ignores it
skill-scanner scan ./skill --use-llm --policy balanced --fail-on-severity high
```

**Serve it with whitespace disabled in constrained decoding.** Under grammar-constrained JSON the
model emitted a complete object and then padded it with whitespace to the token limit, losing 46.5%
of analyses. Starting vLLM with
`--structured-outputs-config '{"backend": "xgrammar", "disable_any_whitespace": true}'` took that to
0.6%.

For rules only, nothing leaves the machine by default: the VirusTotal, Cisco AI Defense and OSV
analyzers are off unless you pass `--use-virustotal`, `--use-aidefense` or `--use-osv`.

## Hunting: research and incident response

**Recommendation.** Everything on, and read the output; never gate on it.

```bash
skill-scanner scan ./suspect-skill --policy strict --rule-packs atr promptguard \
  --use-llm --llm-decompose --use-behavioral --format json --detailed
```

**Why.** Enabling every community rule pack raised recall to 73.8% on a sample of the test split
and raised the benign flag rate from 7.5% to 92.5%: useful for finding everything a skill might do,
useless as a gate. `--llm-decompose` runs the judge once per focus and unions the findings; measured
with the earlier prompt it raised held-out recall from 49.0% to 60.9% at five times the tokens, and a
control arm attributed about two thirds of the gain to sampling variance rather than the focuses.

## Choosing the judge model

- **Measure your model.** The judge's figures on this page are for Gemma 4 26B-A4B through Bedrock.
  With the earlier prompt, a single pass of Claude Haiku 4.5 scored F1 58.7% against Gemma 4's 61.2%
  on the same split; the size of every gain depends on the model.
- **Keep verdict repair on.** It is on by default. A model that says `SAFE` while listing findings
  contradicts itself, and the strict path discarded the whole analysis -- almost always on benign
  skills, so the judge went silent exactly where it would produce false positives. Setting
  `SKILL_SCANNER_LLM_REPAIR_INCONSISTENT_VERDICT=0` restores the strict path.
- **Keep the meta-analyzer off** (`--enable-meta` is off by default). Once it worked, it cost 16.4
  points of recall for 0.3 points of false-positive rate.
- **Budget for tokens, not requests.** About 3,800 input and 90 output tokens per skill per pass on
  real skills; `--llm-decompose` multiplies that by the number of focuses.

## Gaps to handle yourself

**A skill the judge could not analyse passes the gate.** The failure is reported as an INFO finding,
`LLM_ANALYSIS_FAILED`, and INFO never gates. Route those skills to review. With `scan-all` JSON:

```bash
jq -e '[.results[].findings[] | select(.rule_id == "LLM_ANALYSIS_FAILED")] | length == 0' scan.json \
  || echo "some skills were not analysed by the judge: review them"
```

For a single `scan`, the findings are at the top level: `.findings[]`.

**A skill too large for the prompt budget is judged on part of its content.** The judge still answers,
and an INFO `LLM_CONTEXT_BUDGET_EXCEEDED` finding names each file it left out. On real skills this
was 5% of judged skills, and where a file was left out the judge agreed with only 7% of what the
rules flagged, often because it never saw the flagged file. Either raise the budgets in
`llm_analysis` (`max_total_prompt_chars`, `max_instruction_body_chars`, `max_code_file_chars`,
`max_referenced_file_chars`) or send those skills to review.

## Building a custom policy from a recommendation

Start from the nearest preset and change only what you need:

```bash
skill-scanner generate-policy --preset low-noise -o my-policy.yaml
skill-scanner scan ./skill --policy my-policy.yaml
```

The settings the presets differ by:

```yaml
severity_overrides:            # a demoted rule is reported at LOW: visible, not gating
  - rule_id: FILE_MAGIC_MISMATCH
    severity: LOW
    reason: "mostly a text label in Markdown on real skills"

llm_analysis:
  low_confidence_max_severity: LOW     # cap findings the model rates LOW confidence
  contextual_risk_max_severity: ""     # "LOW" caps findings labelled CONTEXTUAL_RISK (on in quiet)
```

In Python:

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzer_factory import build_analyzers
from skill_scanner.core.scan_policy import ScanPolicy

policy = ScanPolicy.from_preset("low-noise")          # or ScanPolicy.from_yaml("my-policy.yaml")
analyzers = build_analyzers(policy, use_llm=True)      # model and key from SKILL_SCANNER_LLM_*
with SkillScanner(analyzers=analyzers, policy=policy) as scanner:
    result = scanner.scan_skill("./downloaded-skill")
```

## Measure on your own skills

The real-skill rates above come from one population; on a 200,000-skill sample from a different
source the same rules flagged 0.5% rather than 2.1%. Before relying on a queue size, scan a sample
of your own skills with two presets and compare:

```bash
skill-scanner scan-all ./sample --recursive --policy balanced --format json --output balanced.json
skill-scanner scan-all ./sample --recursive --policy low-noise --format json --output low-noise.json
jq '[.results[] | select(.max_severity == "HIGH" or .max_severity == "CRITICAL")] | length' balanced.json
```

## Related

- [Measured results](../reference/measured-results.md) -- every figure on this page, with its method
- [Scan policies overview](scan-policies-overview.md) and
  [custom policy configuration](custom-policy-configuration.md) -- every policy setting
- [GitHub Actions](../github-actions.md) -- the reusable workflow's inputs
- [Configuration reference](../reference/configuration-reference.md) -- environment variables
