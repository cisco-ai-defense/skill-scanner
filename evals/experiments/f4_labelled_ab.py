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

"""F4: shipped against final on every labelled corpus, and what the tuning cost.

    python evals/experiments/f4_labelled_ab.py --output labelled-ab.json \\
        --pair msb-trainval=shipped/msb-trainval.jsonl,final/msb-trainval.jsonl \\
        --pair msb-source-disjoint=shipped/msb-source-disjoint.jsonl,final/msb-source-disjoint.jsonl \\
        --role msb-trainval='development split (rules were designed on it)' \\
        --attribute msb-trainval \\
        --preset balanced=final/msb-trainval.jsonl --preset low-noise=low-noise/msb-trainval.jsonl

Each pair is the static arm of ``cross_tool_benchmark`` for the same corpus under two trees. Only
records both runs could read are compared. Unlabelled records get a flag rate, never a place in
recall or FPR, and a positives-only corpus reports recall alone.

``--attribute`` names the corpus whose lost detections are explained: for every positive record
that reached MEDIUM+ under the shipped tree and does not under the final one, the rules that
carried it. That is the recall cost, stated rather than averaged away. ``--preset`` scores each
policy preset's own scan of one corpus.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.experiments.f1_full_corpus_store import SEVERITY_RANK, rows  # noqa: E402

POSITIVE_LABELS = frozenset({"malicious", "obviously_malicious", "contextually_risky"})
NEGATIVE_LABELS = frozenset({"benign"})


def load(path: Path) -> dict[str, tuple[str | None, list[dict[str, Any]]]]:
    """Readable records: label and findings by record id."""
    out = {}
    for row in rows([path]):
        if row.get("error") or row.get("capability_ok") is False:
            continue
        out[row["record_id"]] = (row.get("label"), row.get("findings") or [])
    return out


def top(findings: Sequence[dict[str, Any]]) -> int:
    return max((SEVERITY_RANK.get(str(f.get("severity") or "NONE").upper(), 0) for f in findings), default=0)


def tally(
    records: dict[str, tuple[str | None, list[dict[str, Any]]]], ids: Sequence[str], threshold: int
) -> dict[str, int]:
    counts = {"positives": 0, "tp": 0, "negatives": 0, "fp": 0, "unlabelled": 0, "flagged_unlabelled": 0}
    for record_id in ids:
        label, findings = records[record_id]
        fired = top(findings) >= threshold
        if label in POSITIVE_LABELS:
            counts["positives"] += 1
            counts["tp"] += fired
        elif label in NEGATIVE_LABELS:
            counts["negatives"] += 1
            counts["fp"] += fired
        else:
            counts["unlabelled"] += 1
            counts["flagged_unlabelled"] += fired
    return counts


def compare(base: dict, final: dict, role: str | None = None) -> dict[str, Any]:
    ids = sorted(set(base) & set(final))
    block: dict[str, Any] = {"records": len(ids), "role": role}
    for tier, threshold in (("medium_plus", 3), ("high_plus", 4)):
        block[f"{tier}_base"] = tally(base, ids, threshold)
        block[f"{tier}_final"] = tally(final, ids, threshold)
    return block


def recall_cost(base: dict, final: dict) -> dict[str, Any]:
    """The positive records the change stopped detecting at MEDIUM+, and what carried them."""
    lost = [
        record_id
        for record_id, (label, findings) in base.items()
        if label in POSITIVE_LABELS and record_id in final and top(findings) >= 3 and top(final[record_id][1]) < 3
    ]
    carried = collections.Counter(
        " + ".join(
            sorted({f["rule_id"] for f in base[r][1] if SEVERITY_RANK.get(str(f.get("severity")).upper(), 0) >= 3})
        )
        for r in lost
    )
    return {"records": len(lost), "carried_by": carried.most_common()}


def preset_metrics(path: Path) -> dict[str, Any]:
    records = load(path)
    counts = tally(records, sorted(records), 3)
    return {
        "recall": counts["tp"] / counts["positives"] if counts["positives"] else None,
        "fpr": counts["fp"] / counts["negatives"] if counts["negatives"] else None,
        **{k: counts[k] for k in ("tp", "positives", "fp", "negatives")},
    }


def _pair(spec: str) -> tuple[str, Path, Path]:
    corpus, _, paths = spec.partition("=")
    shipped, _, final = paths.partition(",")
    if not (corpus and shipped and final):
        raise SystemExit(f"--pair wants CORPUS=SHIPPED,FINAL, got {spec!r}")
    return corpus, Path(shipped).expanduser(), Path(final).expanduser()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", action="append", required=True, help="CORPUS=SHIPPED.jsonl,FINAL.jsonl; repeatable")
    parser.add_argument("--role", action="append", default=[], help="CORPUS=TEXT describing the corpus's role")
    parser.add_argument("--attribute", default=None, help="corpus whose lost detections are attributed")
    parser.add_argument("--preset", action="append", default=[], help="NAME=JSONL, one preset's scan of a corpus")
    parser.add_argument("--base-commit", default=None)
    parser.add_argument("--final-commit", default=None)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    roles = dict(spec.partition("=")[::2] for spec in args.role)
    report: dict[str, Any] = {
        "experiment": "labelled-ab-shipped-vs-final",
        "base_commit": args.base_commit,
        "final_commit": args.final_commit,
        "arm": "static core",
        "blocking": False,
        "complete": True,
        "corpora": {},
    }
    for spec in args.pair:
        corpus, shipped, final = _pair(spec)
        base_rows, final_rows = load(shipped), load(final)
        report["corpora"][corpus] = compare(base_rows, final_rows, roles.get(corpus))
        if corpus == args.attribute:
            report["recall_cost"] = recall_cost(base_rows, final_rows)
        block = report["corpora"][corpus]["medium_plus_final"]
        print(f"{corpus:26s} n={report['corpora'][corpus]['records']:7,d} final {block}")
    if args.preset:
        report["presets"] = {
            name: preset_metrics(Path(path).expanduser()) for name, _, path in (s.partition("=") for s in args.preset)
        }
    args.output.write_text(json.dumps(report, indent=1))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
