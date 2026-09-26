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

"""Convert per-record scan rows into Parquet for analysis with DuckDB.

**Size is not the reason for this.**  Measured on the 200,000-record gitskills run, a
row costs 702 bytes of JSONL, so even the full 9.5M-record corpus is about 6.7 GB --
large but not unmanageable.  The reason is that the JSONL shape resists the questions
we actually ask of it:

* ``unique_rules`` and ``severities_present`` are nested arrays, so "which rules fire
  on records that reach MEDIUM" needs an unnest that JSON lines cannot express and a
  full re-parse every time it is asked.
* There is no column pruning. Counting rule frequencies reads all nineteen fields of
  every row.
* There is no predicate pushdown. Restricting to one corpus or one arm still parses
  every line of every file.

So the rows are written out three times, in the shapes the analysis wants:

``scans``
    One row per (run, record, arm), scalar columns only. Tier rates, flag rates and
    per-arm comparisons are a single aggregate over a few narrow columns.

``scan_rules``
    One row per (record, rule). This is the join table that makes rule-level questions
    cheap: which rules fire together, which fire alone on benign records, what a
    suppression would cost. Asking that of the array form means unnesting 9.5M rows.

``findings``
    One row per individual finding, carrying the **analyzer** that produced it alongside
    the rule, category, severity and location. This is the table a false-positive
    reduction pass works from: "rank analyzers by how often they fire on harmless
    records", "which rule in which analyzer costs the most precision", "does this
    analyzer ever fire alone". ``scan_rules`` cannot answer those because a record's
    rule set has no analyzer attribution and no per-finding severity.

All three are partitioned by ``corpus`` and ``arm``, and ``findings`` additionally by
``analyzer``, so a query against one arm or one analyzer opens only those files. Low-cardinality columns -- corpus, arm, tool, rule_id, severity --
dictionary-encode well, which is where the compression comes from.

Deliberately *not* a database: DuckDB reads Parquet in place, so there is no import
step to keep in sync and no server to run. The files are the store.

    duckdb -c "SELECT arm, count(*) FROM read_parquet('store/scans/**/*.parquet') GROUP BY 1"
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

# Severity ladder, ordered. Stored as an integer alongside the label so a threshold
# query is an integer comparison rather than a CASE expression repeated in every query.
SEVERITY_ORDER = ("NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

# Columns kept on the narrow table. Anything array-valued is excluded by construction:
# it belongs in scan_rules instead.
SCAN_COLUMNS = (
    "run_id",
    "record_id",
    "corpus",
    "tool",
    "arm",
    "arm_label",
    "model",
    "label",
    "is_positive",
    "max_severity",
    "max_severity_rank",
    "finding_count",
    "rule_count",
    "gate_blocked",
    "gate_detail",
    "complete",
    "capability_ok",
    "duration_seconds",
    "input_tokens",
    "output_tokens",
    "error",
)

POSITIVE_LABELS = frozenset({"malicious", "contextually_risky", "obviously_malicious"})


def _scan_row(raw: dict[str, Any], *, run_id: str, model: str | None, arm_label: str | None) -> dict[str, Any]:
    severity = str(raw.get("max_severity") or "NONE").upper()
    rules = [str(r) for r in (raw.get("unique_rules") or []) if r]
    label = raw.get("label")
    return {
        "run_id": run_id,
        "record_id": str(raw.get("record_id") or ""),
        "corpus": str(raw.get("corpus") or ""),
        "tool": str(raw.get("tool") or ""),
        "arm": str(raw.get("arm") or ""),
        "arm_label": arm_label,
        "model": model,
        "label": label,
        # Materialised rather than derived per query: the positive-class vocabulary
        # differs by corpus and getting it wrong has silently emptied a population before.
        "is_positive": label in POSITIVE_LABELS,
        "max_severity": severity,
        "max_severity_rank": SEVERITY_RANK.get(severity, 0),
        "finding_count": int(raw.get("finding_count") or 0),
        "rule_count": len(rules),
        "gate_blocked": raw.get("gate_blocked"),
        "gate_detail": raw.get("gate_detail"),
        "complete": raw.get("complete"),
        "capability_ok": raw.get("capability_ok"),
        "duration_seconds": float(raw.get("duration_seconds") or 0.0),
        "input_tokens": int(raw.get("input_tokens") or 0),
        "output_tokens": int(raw.get("output_tokens") or 0),
        "error": raw.get("error"),
    }


def _finding_rows(raw: dict[str, Any], *, run_id: str) -> Iterator[dict[str, Any]]:
    """One row per finding, with analyzer attribution preserved."""

    record_id = str(raw.get("record_id") or "")
    corpus = str(raw.get("corpus") or "")
    arm = str(raw.get("arm") or "")
    label = raw.get("label")
    is_positive = label in POSITIVE_LABELS
    for finding in raw.get("findings") or []:
        severity = str(finding.get("severity") or "").upper()
        yield {
            "run_id": run_id,
            "record_id": record_id,
            "corpus": corpus,
            "arm": arm,
            "analyzer": str(finding.get("analyzer") or "unknown"),
            "rule_id": str(finding.get("rule_id") or ""),
            "category": str(finding.get("category") or ""),
            "severity": severity,
            "severity_rank": SEVERITY_RANK.get(severity, 0),
            "file_path": finding.get("file_path"),
            "line_number": finding.get("line_number"),
            "confidence": finding.get("confidence"),
            "label": label,
            # Carried so the central question -- did this finding fire on a harmless
            # record -- is a filter rather than a join.
            "is_positive": is_positive,
            "is_false_positive_candidate": (not is_positive) and severity not in ("", "NONE"),
        }


def _rule_rows(raw: dict[str, Any], *, run_id: str) -> Iterator[dict[str, Any]]:
    severity = str(raw.get("max_severity") or "NONE").upper()
    record_id = str(raw.get("record_id") or "")
    corpus = str(raw.get("corpus") or "")
    arm = str(raw.get("arm") or "")
    label = raw.get("label")
    for rule in raw.get("unique_rules") or []:
        if not rule:
            continue
        yield {
            "run_id": run_id,
            "record_id": record_id,
            "corpus": corpus,
            "arm": arm,
            "rule_id": str(rule),
            "label": label,
            "is_positive": label in POSITIVE_LABELS,
            # Carried so a rule-level query does not have to join back for the common
            # "did this record gate" filter.
            "record_max_severity": severity,
            "record_max_severity_rank": SEVERITY_RANK.get(severity, 0),
        }


def convert(
    sources: Sequence[Path],
    out_root: Path,
    *,
    run_id: str,
    model: str | None = None,
    arm_label: str | None = None,
    batch_rows: int = 200_000,
) -> dict[str, int]:
    """Write ``sources`` into ``out_root`` as two partitioned Parquet datasets."""

    import pyarrow as pa
    import pyarrow.parquet as pq

    scans: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    counts = {"scans": 0, "scan_rules": 0, "findings": 0, "files": 0}

    def flush() -> None:
        # Written per batch rather than accumulated: a 9.5M-record conversion must not
        # depend on holding every row in memory at once.
        if scans:
            pq.write_to_dataset(
                pa.Table.from_pylist(scans),
                root_path=str(out_root / "scans"),
                partition_cols=["corpus", "arm"],
                compression="zstd",
            )
            counts["scans"] += len(scans)
            scans.clear()
        if rules:
            pq.write_to_dataset(
                pa.Table.from_pylist(rules),
                root_path=str(out_root / "scan_rules"),
                partition_cols=["corpus", "arm"],
                compression="zstd",
            )
            counts["scan_rules"] += len(rules)
            rules.clear()
        if findings:
            pq.write_to_dataset(
                pa.Table.from_pylist(findings),
                root_path=str(out_root / "findings"),
                # Partitioned by analyzer as well: a pass targeting one analyzer's false
                # positives then reads only that analyzer's files.
                partition_cols=["corpus", "arm", "analyzer"],
                compression="zstd",
            )
            counts["findings"] += len(findings)
            findings.clear()

    for source in sources:
        counts["files"] += 1
        with source.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                scans.append(_scan_row(raw, run_id=run_id, model=model, arm_label=arm_label))
                rules.extend(_rule_rows(raw, run_id=run_id))
                findings.extend(_finding_rows(raw, run_id=run_id))
                if len(scans) >= batch_rows:
                    flush()
    flush()
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", help="Row JSONL files written by the benchmark runners.")
    parser.add_argument("--out", required=True, help="Store root. Two datasets are created under it.")
    parser.add_argument("--run-id", required=True, help="Identifier for this collection, carried on every row.")
    parser.add_argument("--model", default=None)
    parser.add_argument("--arm-label", default=None)
    args = parser.parse_args(argv)

    out_root = Path(args.out).expanduser()
    out_root.mkdir(parents=True, exist_ok=True)
    counts = convert(
        [Path(s).expanduser() for s in args.sources],
        out_root,
        run_id=args.run_id,
        model=args.model,
        arm_label=args.arm_label,
    )
    print(
        f"read {counts['files']} file(s) -> {counts['scans']:,} scans, "
        f"{counts['scan_rules']:,} rule rows, {counts['findings']:,} findings"
    )
    print(f"store: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
