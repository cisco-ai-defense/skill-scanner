# Detection Impact Check

A pull request that touches detection -- rule packs (signatures, YARA, CEL), rule or analyzer code,
or a preset policy -- gets a comment saying what the change does to detection, measured, before
anyone reviews it. The check is `.github/workflows/detection-impact.yml` and runs on ordinary
GitHub-hosted runners.

## What it does

The same records are scanned twice, once with the base branch and once with the pull request, using
the static arm of `evals/runners/cross_tool_benchmark.py` with the core pack. Both sides run the
pull request's harness, so only the scanner differs. `evals/runners/detection_impact.py` then
compares the rows and posts:

| Section | What it reports |
|---|---|
| Development split | Recall, FPR, precision and F1 at MEDIUM+, base and head, each with a 95% interval, and a paired-bootstrap interval on each difference |
| Real skills | The MEDIUM+ flag rate on a fixed sample, which bounds the false-positive rate from above rather than measuring it |
| Rules whose output changed | For each changed or new rule: records it fires on, records it alone lifts to MEDIUM+, records where it is the only MEDIUM+ rule, and its malicious/benign split |
| Tier movement | Records that moved up or down a severity tier |
| Scan health | Scan errors, capability-degraded rows and lenient-loader fallbacks |
| Hash-bound evidence | Every evidence fixture that records a rule's hits on the development selection, re-verified against the head tree |

## What fails it

| Condition | Why |
|---|---|
| Development-split recall falls, or FPR rises, by more than 0.5 points | The trade needs a decision, not a merge by default |
| Any capability-degraded row on the head tree | An analyzer failed while the row still looked scanned -- how the `FILE_MAGIC_MISMATCH` LOW-demotion bug silently failed 904 records |
| More scan errors than the base | A record the scanner used to read and now cannot |
| A hash-bound evidence fixture whose recorded hits the head tree no longer reproduces | The rule changed; its evidence must be re-verified and rebound, not just its hash |

A maintainer can accept a deliberate recall-for-FPR trade by adding the `detection-impact-accepted`
label; the check then reports the change and passes. The label never waives degraded rows, new scan
errors or an evidence mismatch -- those are defects, not trades.

## Where the data comes from

Corpus content cannot live in the repository. The acquire job downloads it at job time, as the
release-evidence workflow does, under an explicit per-dataset allowance in
`evals/datasets/public-datasets.lock.json`:

| Corpus | Source | Materialized | Metrics allowed |
|---|---|---|---|
| `msb-trainval` | MaliciousSkillBench, the ten lock-pinned files | Records whose every split protocol is train or validation: 5,256 malicious and 1,338 benign | Recall, FPR, precision, F1 |
| `clawhub-sample` | OpenClaw ClawHub signals, the pinned `data/validation.jsonl` | A fixed 2,000-skill sample, label-free | Flag rate only |

Every downloaded byte is checked against the lock before it is read. The lock keeps
`network_fetch_in_pull_requests: false` for the harness and the scanner; the only pull-request
fetch is the one each entry's `pull_request_acquisition` names, and the validator allows it only
for public datasets, only for train and validation partitions, and only with the scan's network
denied. Scans run with credentials removed and outbound network blocked. Nothing is executed.

## Rules it is built around

- **The frozen test split is never scored.** MaliciousSkillBench forbids designing rules or choosing
  thresholds on its test members, and iterating on test F1 in every pull request would do exactly
  that. The acquire job writes no test member; the runner refuses the source-disjoint and
  balanced-800 corpora outright. The held-out split is scored in the release gate only.
- **Each corpus reports only what its terms allow.** HarmfulSkillBench would get flag rates only and
  is not downloaded automatically; NotInject is never a package-level benign denominator; real-skill
  rates are flag rates. The runner refuses any corpus it does not know.
- **The ClawHub verdict is not ground truth.** The sample is written without labels.
- **Aggregates only.** The comment and job summary carry counts, rates and rule identifiers; the
  report builder refuses record identifiers, paths, credentials and free text before anything is
  published.
- **Forks.** Fork pull requests run the check with a read-only token and see the result in the job
  summary. Only same-repository pull requests get the comment, posted by a job that reads the report
  artifact and never runs pull-request code.

## Runtime and scope

The development split plus the 2,000-skill sample take roughly ten minutes on GitHub-hosted runners,
with the base and head scans in parallel. The full 1.88-million-skill corpus is 25 GB and took about
ninety minutes on 16 cores; it belongs in a pre-release measurement, not in every pull request --
see [Measured results](../reference/measured-results.md#reproducing).

## Running it locally

```bash
# Scan the same corpora with each tree (a clean root holding msb-trainval and clawhub-sample):
python evals/runners/cross_tool_benchmark.py --tool skill-scanner --arm static --profile core \
  --clean-root CLEAN --corpus msb-trainval --corpus clawhub-sample --output-dir rows/head
# ... and again from the base tree into rows/base, then:
python evals/runners/detection_impact.py --base-rows rows/base --head-rows rows/head \
  --report report.json --comment comment.md --base-sha BASE --head-sha HEAD
```
