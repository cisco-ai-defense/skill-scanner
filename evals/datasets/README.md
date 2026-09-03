# Public Evaluation Datasets

`public-datasets.lock.json` is the source of truth for external corpus identity
and permitted use. Every entry pins a full commit SHA and records access,
license scope, download policy, blocking status, and prohibited uses.
`public-datasets.profile.json` records the latest non-gating inspection of the
candidate Hugging Face datasets, including observed schemas, distributions,
source-artifact hashes, suitability, and limitations. It contains no samples.
Each entry also requires a canonical `path-sha256-size-v1` artifact manifest.
Acquisition must persist that manifest's SHA-256 independently, then call
`validate_artifact_manifest` before handing files to an isolated scan stage.
Until that digest has been reviewed and copied into the lock, the entry stays
`hashes_pending: true` and validation forbids it from being a blocking gate.

MaliciousSkillBench additionally pins
`source_artifact_manifest_sha256=3d64779dc972759ede61717ac5cc7f4e87289add8feabff1e83c4289094ce300`
for the ten upstream Parquet/CSV/schema artifacts recorded in the profile. This
proves the acquisition inputs, not the bytes of the derived evaluation
snapshot. The two digests are deliberately separate: the complete materialized
9,740-sample manifest is pinned as
`ae542800a95a893a0ae724bdc625d5a1e19d81ff08ae1f846ddb54d77bfb0b9a`.
The usable 9,737-member inventory and exact three-member train-only quarantine
are pinned separately. Neither quarantine intersects a selected blocking test
track.

The blocking public benchmark is the core detector with CEL on
`ProtectSkills/MaliciousSkillBench`'s frozen source-disjoint test partition.
The lock pins its 1,384 samples (839 malicious and 545 benign) plus a canonical
population digest under `core-only-source-disjoint`. Release validation rejects
denominator shrinkage or membership substitution. Full-pack/ATR,
malicious-structural-disjoint, whole-corpus, and train-population runs remain
optional supplementals and never determine release status. The pinned upstream
source digest alone is not a release corpus identity.

Other locked datasets are supplemental, gated, silver-labeled, metadata-only,
or excluded. In particular, OpenClaw signals are for supplemental drift and
disagreement mining—not ground truth—and LLM-LAT is excluded because it is
generic harmful-chat data with no declared dataset license.

The lock also records the supplemental sources selected for later conversion
into inert fixtures:

- DataDog's malicious-package corpus is quarantined positive-recall evidence.
- InjecAgent and the sanitized public In-Page Prompt Injection corpus are
  indirect-prompt-injection references, not package-level accuracy gates.
- The NotInject data included with InjecGuard supplies benign prompt-injection
  hard negatives, not package-level benign ground truth.

### GitHub prompt-injection supplementals

`evals.datasets.github_prompt_injection` accepts only offline checkouts with
the exact locked file layouts: InjecAgent's four paired
`data/test_cases_{dh,ds}_{base,enhanced}.json` files, In-Page's sanitized
`data/dataset_tp.csv`, or InjecGuard's three
`datasets/NotInject_{one,two,three}.json` files. The adapter rejects every
other path, symlink, device, executable, archive, schema, row count, revision,
or byte manifest. It never imports repository code or acquires data.

Run one already-acquired snapshot with deterministic local analyzers:

```bash
python -m evals.runners.github_prompt_injection_benchmark \
  --dataset in-page \
  --snapshot /absolute/path/to/pinned-checkout \
  --detector-profile core_only \
  --cel-mode shadow \
  --output /absolute/path/to/report.json
```

InjecAgent reports enhanced-versus-base differential signal recall. In-Page
reports positive indirect-injection signal recall over canonical deduplication
groups with raw-row diagnostics. NotInject reports diagnostic flagged rate and
hard-negative candidates only; it is never eligible for release FPR or benign
package-gold metrics. Missing snapshots produce an explicit nonblocking skip.

## Offline validation

The helpers perform no network requests and never execute content:

```python
from pathlib import Path

from evals.datasets.public_datasets import (
    validate_artifact_manifest,
    materialize_locked_skill_row,
    validate_snapshot_metadata,
    validate_source_artifact_manifest,
)

validate_snapshot_metadata(
    "OpenClaw/clawhub-security-signals",
    revision="69dcbd323c155312fb000ec89ea0b1efdf6a5757",
    config="default",
    split="test",
    fields=locked_exact_fields,
    row_count=6747,
)

validate_artifact_manifest(
    "OpenClaw/clawhub-security-signals",
    acquired_file_manifest,
    manifest_sha256=persisted_manifest_sha256,
)

# For datasets with a separately pinned upstream-input manifest. This proves
# acquisition provenance and deliberately does not approve a release snapshot.
validate_source_artifact_manifest(
    "ProtectSkills/MaliciousSkillBench",
    acquired_source_file_manifest,
)

# `row` was decoded from the already-fetched pinned artifact.
skill_dir = materialize_locked_skill_row(
    "OpenClaw/clawhub-security-signals",
    row,
    Path("/isolated/new-output-directory"),
)
```

Materialization accepts text only and creates a new directory. It rejects:

- absolute, traversing, non-normalized, Windows-ambiguous, and case-colliding
  paths;
- Unicode-normalization collisions, symlink metadata, symlinked destination
  ancestors, or an existing destination;
- attempts to replace `SKILL.md`;
- missing/additional row or bundle fields;
- content whose declared byte size or SHA-256 does not match; and
- file/directory prefix collisions;
- binary/archive file types, NUL-containing content, and non-portable paths;
  and
- inputs exceeding the 32 MiB per-file, 128 MiB per-sample, or 4,096-file
  safety bounds.

Files are mode `0600`; directories are mode `0700`. The adapter never imports,
runs, follows links from, or makes executable any sample.
If a filesystem write fails, the partially created destination is removed.

The dedicated locked MaliciousSkillBench producer byte-preserves five reviewed
rows containing Unicode/C0 control code points (including the 21 MB hard
negative), because rewriting or dropping them would change the pinned artifact
and track identities. This exception applies only after the complete ten-file
source manifest has matched its locked SHA-256. NUL remains forbidden, every
output is valid UTF-8 and non-executable, evidence reports do not include raw
sample text, and the network-denied scanner never executes sample content.

The MaliciousSkillBench classification snapshot is narrower still: it accepts
exactly one inert `SKILL.md` for every locked sample. Extra scripts, dataset
loading hooks, package files, archives, and unmanaged files fail validation
even when they are declared in a self-consistent pending manifest.

Gated supplemental data is never a release input. If credentials or the
authorized artifact are absent, the supplemental runner emits an explicit
`status: skipped` report. If an artifact is present, the skip path still rejects
symlinks, devices, and unsafe tree shapes; it never parses or executes samples.

### HarmfulSkillBench supplemental static diagnostic

At pinned revision `0a30e25f20a391e1b6956c55d6806867944c2232`, the
declared evaluation-used tree contains 401 artifacts: the 200-row task file,
200 metadata files, and 200 declared `SKILL.md` files. Its manifest SHA-256 is
`5611f603419299312f90d045b843f494801f2baa44369d61c1bbf4995297e089`.
Endpoint protection quarantined `clawhub_d2bee9b8/SKILL.md` (16,409 bytes),
leaving a 400-artifact usable inventory with manifest
`3b769e4c6c2aaa63c944682a8273c9ccab1709c7fca6c34b71b5b33fe1400b42`.
The canonical one-record quarantine manifest is
`d2e17d3093dcca780bad35c49858abc77e9fba2ab32e5a0646309c345007beda`;
the unavailable member remains in the 200-row denominator.

The full-pack CEL-shadow diagnostic report
(`ee1a0239b000e00708423be81340b4ddad9ed1f96c50a8d780956851e824cc62`)
scanned 199 rows and retained one scan error in the denominator. It detected
any signal for 196/200 (98%), an actionable finding for 174/200 (87%), and a
blocking finding for 160/200 (80%); direct `harmful_content` detections were
0/200. CEL-Go v0.32.0 evaluated 3,283 candidates and recorded 88
would-suppress decisions, with zero suppression, fallback,
incomplete-projection, or circuit-breaker events in shadow mode.

HarmfulSkillBench is all-positive, nonblocking supplemental recall evidence.
It cannot support precision, false-positive-rate, true-negative, F1, or
release-authoritative claims. Acquisition remains manual; missing gated access
produces a skipped supplemental report and never triggers automatic download.

### OpenSkillRisk static adapter

`evals/datasets/openskillrisk.py` accepts only an already-acquired snapshot at
the locked `Miaow-Lab/OpenSkillRisk` revision. It never authenticates to or
downloads from Hugging Face. The snapshot may use the upstream `src/`,
`tasks/`, and `skills/` layout (or the documented flat install layout), but
exactly one approved location must exist for each required item.

The two Python task-spec files are data, not modules. The adapter reads them
with `ast.parse` and a closed literal grammar; it never imports, compiles, or
executes them. Only `TaskSpec`, `CheckSpec`, and the four upstream literal text
helpers are recognized. Dynamic calls, f-strings, comprehensions, attribute
access outside the static `Path(__file__)` declaration, positional task
construction, extra fields, duplicate identities, and count drift all fail
closed. The locked denominators are 139 obviously-malicious and 124
contextually-risky tasks. Prompt, policy, and sandbox-fixture text is validated
as inert bounded literals, then discarded.

Each accepted task contributes only its task ID, skill ID, attack type, split,
and a confined package directory. A skill ID must be one portable path
component. The adapter resolves the task-referenced skill tree, requires one
supported `SKILL.md`, rejects symlinks and non-regular members, and bounds path,
file-count, and byte usage (32 MiB per file, 128 MiB per referenced skill,
4,096 files, and 8,192 total entries). Case-folding and Unicode path collisions
also fail closed. Unreferenced skill directories are not returned to the runner.
`evals/runners/openskillrisk_benchmark.py` revalidates every package immediately
before calling a caller-supplied static scanner and retains scan errors in the
positive-recall denominator. Its results are supplemental only; they cannot
supply a benign precision denominator or affect a release gate.

The current artifact-manifest hash remains pending. An authorized snapshot can
therefore be used only for supplemental compatibility checks until its complete
`path-sha256-size-v1` manifest has been reviewed and pinned. Schema, population,
or tree drift must update the lock through the refresh procedure below rather
than weakening the adapter.

### MaliciousAgentSkillsBench metadata adapter

`evals/datasets/malicious_agent_skills_bench.py` consumes exactly two inert CSV
files from `ProtectSkills/MaliciousAgentSkillsBench` revision
`422bf3401845f6c1378bf4599dc2cdb3451978cf`. Their closed
`path-sha256-size-v1` manifest is pinned as
`562dfc290f167622b0660950607b054709aff6604b18500cab49662914a49e20`.
The adapter verifies exact headers, byte hashes, sizes, row counts, label
counts, the 14-value taxonomy, and aligned pattern/severity instances. Exact
upstream URL redaction sentinels remain unavailable metadata and never become
shared overlap keys.

The 94,093 upstream `safe` rows are retained only as a provenance count; they
are not exposed as benign gold or used for precision or false-positive-rate
metrics. Taxonomy and case-mining reports remain supplemental. Static recall is
allowed only for separately materialized packages with external
`sandbox_behavior_confirmed` evidence, content hashes, and explicit
MaliciousSkillBench de-overlap keys. The metadata adapter never resolves URLs,
downloads linked repositories, imports dataset code, or executes packages.

## Refresh procedure

1. Review the upstream card, license, schema, provenance, and split method.
2. Record a full immutable revision—not `main`—and the canonical source-file
   manifest plus its SHA-256 in the scheduled job's provenance output.
3. Review and pin the artifact-manifest digest before activating a mandatory
   gate; pending hashes are structurally prohibited from blocking.
4. Update locked schema and row counts only after explaining any drift.
5. Run the focused dataset-input tests.
6. Keep public downloads out of pull requests; scheduled and release jobs use
   an isolated, network-disabled analysis stage after acquisition.

The canonical release acquisition/materialization entry point is:

```bash
uv sync --frozen --no-default-groups --group datasets
uv run --no-sync python evals/datasets/materialize_malicious_skill_bench.py \
  --source-dir /disposable/pinned-hf-files \
  --output-dir /disposable/inert-snapshot \
  --dataset-lock evals/datasets/public-datasets.lock.json \
  --dataset-profile evals/datasets/public-datasets.profile.json
```

The protected `detection-release-evidence.yml` workflow is authoritative for
release use. It supplies the exact file list to `hf download`; it never invokes
`datasets.load_dataset`, dataset scripts, package archives, or source pointers.

At the pinned OpenClaw revision, the four raw JSONL files contain 67,453 rows
and exactly three verdicts. Their bytes were independently checked against the
pinned LFS SHA-256 values. Hugging Face's `refs/convert/parquet` artifact is
stale: it contains only 66,192 rows plus an undocumented `unknown` verdict.
Scheduled ingestion must use the raw files and reject that converted view so a
stale service-side conversion cannot silently change an evaluation denominator.
