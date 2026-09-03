# Archived-versus-current benchmark

`evals/runners/archived_current_benchmark.py` compares an archived scanner with
the current scanner over the committed strict golden corpus. It is a regression
benchmark, not a substitute for the independent public and private release
corpora.

The two scanners must be installed in distinct virtual environments with the
same exact Python version, analyzer configuration, and ordered pack selection.
The archived arm runs with CEL off. The driver starts five fresh processes
from each environment, in alternating
baseline/current order, and rejects any scan error, CEL fallback, identity
drift, or semantic difference between repeats of the same arm. Worker
environments contain no inherited hosted-service credentials, use isolated
home/cache directories, and install socket denial before scanner imports.

## 1. Freeze the corpus and harness

```bash
CURRENT_PY=/absolute/path/to/current/.venv/bin/python
SCRIPT=/absolute/path/to/skill-scanner/evals/runners/archived_current_benchmark.py
CORPUS=/absolute/path/to/skill-scanner/evals/skills

"$CURRENT_PY" -I -B "$SCRIPT" corpus-lock \
  --corpus-root "$CORPUS" \
  --output /absolute/path/to/corpus-lock.json

shasum -a 256 "$SCRIPT"
```

Review and retain the corpus lock and harness digest. Pass exactly those
digests to the driver; the harness and corpus are checked before, during, and
after the matrix.

## 2. Produce reviewed arm locks

Run `probe` with each arm's own interpreter. The revision is an explicit label
for the archived source or current worktree and is bound to hashes of the
imported scanner source, shared committed metric runner, effective policy,
exact resolved rule packs, CEL helper, interpreter, and installed-environment
metadata. Active CEL locks require an explicit helper; CEL-off locks omit it.

```bash
BASELINE_PY=/absolute/path/to/archived/.venv/bin/python
CURRENT_HELPER=/absolute/path/to/rebuilt/qualified/cel-helper

"$BASELINE_PY" -I -B "$SCRIPT" probe \
  --repository-root /absolute/path/to/skill-scanner \
  --source-revision 367cdc02a1ecc0fdb86e127614a5dd13f3c904eb \
  --config full --pack atr --pack promptguard --cel-mode off \
  --output /absolute/path/to/baseline-lock.json

SKILL_SCANNER_CEL_GO_HELPER="$CURRENT_HELPER" \
"$CURRENT_PY" -I -B "$SCRIPT" probe \
  --repository-root /absolute/path/to/skill-scanner \
  --source-revision reviewed-current-worktree \
  --config full --pack atr --pack promptguard --cel-mode shadow \
  --helper "$CURRENT_HELPER" \
  --output /absolute/path/to/current-lock.json
```

Review both JSON locks before running the comparison. A lock is intentionally
invalidated by any policy, rule, helper, environment, or scanner-source change.

## 3. Run the five-pair matrix

```bash
"$CURRENT_PY" -I -B "$SCRIPT" driver \
  --repository-root /absolute/path/to/skill-scanner \
  --corpus-root "$CORPUS" \
  --expected-corpus-sha256 SHA_FROM_CORPUS_LOCK \
  --expected-harness-sha256 REVIEWED_SCRIPT_SHA \
  --baseline-python "$BASELINE_PY" \
  --current-python "$CURRENT_PY" \
  --baseline-lock /absolute/path/to/baseline-lock.json \
  --current-lock /absolute/path/to/current-lock.json \
  --current-helper "$CURRENT_HELPER" \
  --output /absolute/path/to/archived-current-report.json
```

An active CEL arm is valid only if at least one candidate was evaluated. The
run fails on a fallback or incomplete scanner execution instead of converting
it into apparent detection improvement. The report retains the existing
golden runner's metrics and adds provenance, timing-free semantic hashes,
counterbalanced wall timings, metric and performance deltas, and a
finding-identity delta. Complete finding payloads, analyzer outcomes, scan
metadata, and CEL decisions participate in the five-run stability hash; only
timing fields are excluded.

The Python socket guard is defense in depth for local runs. Release jobs should
also place workers in the platform's operating-system network sandbox, because
native code outside CPython's audit surface cannot be blocked portably here.
