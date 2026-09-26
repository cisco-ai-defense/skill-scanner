# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""F1: build the full-corpus Parquet store from the raw run files.

The full-corpus figures in ``docs/reference/measured-results.md`` come from one store holding
every deterministic run, the LLM judge and OpenJev over the same records::

    python evals/experiments/f1_full_corpus_store.py --store STORE \\
        --static static-base='RUN/static-gitskills-full/*.jsonl' \\
        --static static-tuned='RUN/static-final-full/*.jsonl' \\
        --static static-head='RUN/static-head-full/*.jsonl' \\
        --judge 'RUN/judge-full/*.jsonl' --judge 'RUN/judge-retry/*.jsonl' \\
        --jev 'RUN/jev-full/*.jsonl'

Static runs are the ``cross_tool_benchmark`` rows of each tree, judge rows come from
``evals/runners/judge_only.py`` and OpenJev rows from ``c3_openjev_local.py``. Three rules keep
the comparison honest:

* **Every static run covers the same records.** A run that scanned fewer records would move
  the flag rate by what it left out, so a coverage mismatch stops the build.
* **One judge row per record.** Retries append rows; a genuine answer beats a failed one, and
  otherwise the latest wins.
* **A budget notice is not a failure.** A row whose only problem is
  ``LLM_CONTEXT_BUDGET_EXCEEDED`` was answered: the prompt budget left a file out and the judge
  still returned a verdict on the rest. It is kept as an analysed record with partial coverage
  (``complete=False``), which is what a user of the shipped policy gets.

The store is written by ``evals/lib/results_store.py``; the judge's package verdict, which the
store's scan table does not carry, is kept beside it as ``judge_verdicts.json``.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.results_store import convert  # noqa: E402

SEVERITY_ORDER = ("NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}
BUDGET_ONLY = "LLM_CONTEXT_BUDGET_EXCEEDED"


def expand(patterns: Iterable[str]) -> list[Path]:
    """Sorted files for the glob patterns, refusing a pattern that matches nothing."""
    paths: list[Path] = []
    for pattern in patterns:
        matched = sorted(glob.glob(str(Path(pattern).expanduser())))
        if not matched:
            raise SystemExit(f"no files match {pattern!r}")
        paths.extend(Path(p) for p in matched)
    return paths


def rows(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def max_of(findings: Iterable[dict[str, Any]]) -> str:
    return max(
        ((f.get("severity") or "NONE").upper() for f in findings),
        key=lambda s: SEVERITY_RANK.get(s, 0),
        default="NONE",
    )


def check_static(name: str, paths: Sequence[Path]) -> set[str]:
    """Record ids of one static run, refusing duplicates and reporting severity drift."""
    ids: set[str] = set()
    inconsistent = checked = 0
    for row in rows(paths):
        record_id = row["record_id"]
        if record_id in ids:
            raise SystemExit(f"{name}: record {record_id} appears twice")
        ids.add(record_id)
        if row.get("error"):
            continue
        checked += 1
        # Tier rates read max_severity; it must agree with the findings it summarises.
        if (row.get("max_severity") or "NONE").upper() != max_of(row.get("findings") or []):
            inconsistent += 1
    print(f"{name}: {len(ids):,} records; max_severity disagrees with findings on {inconsistent:,} of {checked:,}")
    return ids


def merge_judge(paths: Sequence[Path]) -> tuple[dict[str, dict[str, Any]], int]:
    """One row per record: a genuine answer beats a failed one, otherwise the latest wins."""
    judged: dict[str, dict[str, Any]] = {}
    reclassified = 0
    for row in rows(paths):
        if not row.get("capability_ok") and row.get("capability_detail") == BUDGET_ONLY and row.get("verdict"):
            row["capability_ok"], row["complete"] = True, False
            reclassified += 1
        previous = judged.get(row["record_id"])
        if previous is None or row.get("capability_ok") or not previous.get("capability_ok"):
            judged[row["record_id"]] = row
    return judged, reclassified


def verdict_cells(judged: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Package verdict against the most severe finding, for analysed records only."""
    cells: dict[str, int] = {}
    for row in judged.values():
        if row.get("capability_ok"):
            key = f"{(row.get('verdict') or 'NONE').upper()}|{(row.get('max_severity') or 'NONE').upper()}"
            cells[key] = cells.get(key, 0) + 1
    return cells


def latest_jev(paths: Sequence[Path]) -> dict[str, dict[str, Any]]:
    """One OpenJev row per record: an answered row beats an errored one, otherwise the latest wins."""
    latest: dict[str, dict[str, Any]] = {}
    for row in rows(paths):
        previous = latest.get(row["record_id"])
        if previous is None or not row.get("errors") or previous.get("errors"):
            latest[row["record_id"]] = row
    return latest


def write_jsonl(path: Path, items: Iterable[dict[str, Any]]) -> int:
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
            count += 1
    return count


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", type=Path, required=True, help="output directory; must not exist")
    parser.add_argument("--static", action="append", default=[], help="RUN_ID=GLOB for one static run; repeatable")
    parser.add_argument("--judge", action="append", default=[], help="judge row files in merge order; repeatable")
    parser.add_argument("--judge-run", default="judge-full")
    parser.add_argument("--jev", action="append", default=[], help="OpenJev row files; repeatable")
    parser.add_argument("--work", type=Path, default=None, help="scratch directory for the merged judge rows")
    args = parser.parse_args(argv)

    store = args.store.expanduser()
    if store.exists():
        raise SystemExit(f"{store} exists; refusing to append a second copy of every run")
    static: list[tuple[str, list[Path]]] = []
    for spec in args.static:
        name, _, pattern = spec.partition("=")
        if not name or not pattern:
            raise SystemExit(f"--static wants RUN_ID=GLOB, got {spec!r}")
        static.append((name, expand([pattern])))

    coverage = [(name, check_static(name, paths)) for name, paths in static]
    for name, ids in coverage[1:]:
        if ids != coverage[0][1]:
            raise SystemExit(
                f"{name} covers {len(ids):,} records, {coverage[0][0]} covers {len(coverage[0][1]):,}: "
                "every static run must scan the same records"
            )

    work = (args.work or store.with_name(store.name + "-work")).expanduser()
    work.mkdir(parents=True, exist_ok=True)
    sources = list(static)
    if args.judge:
        judged, reclassified = merge_judge(expand(args.judge))
        print(f"{args.judge_run}: {len(judged):,} records; {reclassified:,} budget-only rows kept as partial coverage")
        judge_path = work / f"{args.judge_run}.jsonl"
        write_jsonl(judge_path, judged.values())
        sources.append((args.judge_run, [judge_path]))
    for run_id, paths in sources:
        print(run_id, convert(paths, store, run_id=run_id))
    if args.judge:
        (store / "judge_verdicts.json").write_text(json.dumps(verdict_cells(judged), indent=1, sort_keys=True))

    if args.jev:
        import pyarrow as pa
        import pyarrow.parquet as pq

        latest = latest_jev(expand(args.jev))
        probes = sorted({name for row in latest.values() for name in (row.get("probes") or {})})
        table = [
            {
                "record_id": row["record_id"],
                "errors": row.get("errors", 0),
                "truncated": row.get("truncated"),
                "chars": row.get("chars"),
                **{f"p_{name}": (row.get("probes") or {}).get(name) for name in probes},
            }
            for row in latest.values()
        ]
        (store / "jev").mkdir(parents=True, exist_ok=True)
        pq.write_table(pa.Table.from_pylist(table), store / "jev" / "jev_full.parquet", compression="zstd")
        print(f"jev: {len(table):,} records, {sum(1 for t in table if not t['errors']):,} answered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
