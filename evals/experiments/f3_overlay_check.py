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

"""F3: check an overlay estimate against a full scan, record by record.

Rescanning 1.9 million records for every rule change is slow, so a tuning pass is first
measured by rescanning only the records the change can touch and overlaying those rows on the
previous full scan. That is only sound if the rescan sets were chosen correctly. This script
compares the overlay with a full scan of the same tree at MEDIUM+::

    python evals/experiments/f3_overlay_check.py --output check.json \\
        --base 'RUN/static-final-full/*.jsonl' \\
        --overlay 'RUN/next6/*.jsonl' --overlay 'RUN/next7/*.jsonl' --overlay 'RUN/next9/*.jsonl' \\
        --full 'RUN/static-head-full/*.jsonl'

Overlays apply in the order given, so a record rescanned twice takes its latest row. Records
flagged only by the overlay are the changes it missed or that landed after it; records flagged
only by the full scan are ones the rescan sets should have included and did not.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.experiments.f1_full_corpus_store import expand, rows  # noqa: E402

MEDIUM_PLUS = frozenset({"MEDIUM", "HIGH", "CRITICAL"})


def usable(row: dict[str, Any]) -> bool:
    return not row.get("error") and row.get("capability_ok") is not False


def flagging_rules(row: dict[str, Any]) -> frozenset[str]:
    return frozenset(
        f["rule_id"] for f in row.get("findings") or [] if str(f.get("severity") or "").upper() in MEDIUM_PLUS
    )


def flagged(paths: Iterable[Path]) -> tuple[dict[str, frozenset[str]], int]:
    """MEDIUM+ rule sets by record, and the number of usable records."""
    out: dict[str, frozenset[str]] = {}
    usable_records = 0
    for row in rows(paths):
        if not usable(row):
            continue
        usable_records += 1
        rules = flagging_rules(row)
        if rules:
            out[row["record_id"]] = rules
    return out, usable_records


def overlay(base: dict[str, frozenset[str]], layers: Sequence[Sequence[Path]]) -> dict[str, frozenset[str]]:
    composed = dict(base)
    for layer in layers:
        for row in rows(layer):
            if not usable(row):
                continue
            rules = flagging_rules(row)
            if rules:
                composed[row["record_id"]] = rules
            else:
                composed.pop(row["record_id"], None)
    return composed


def compare(
    composed: dict[str, frozenset[str]], exact: dict[str, frozenset[str]], n_composed: int, n_exact: int
) -> dict[str, Any]:
    both = set(composed) & set(exact)
    only_composed = set(composed) - set(exact)
    only_exact = set(exact) - set(composed)
    return {
        "composed_records": n_composed,
        "exact_records": n_exact,
        "composed_medium_plus": len(composed),
        "exact_medium_plus": len(exact),
        "composed_rate": len(composed) / n_composed if n_composed else None,
        "exact_rate": len(exact) / n_exact if n_exact else None,
        "both": len(both),
        "same_rule_set": sum(1 for i in both if composed[i] == exact[i]),
        "only_composed": len(only_composed),
        "only_exact": len(only_exact),
        "only_composed_by_rules": collections.Counter(
            " + ".join(sorted(composed[i])) for i in only_composed
        ).most_common(15),
        "only_exact_by_rules": collections.Counter(" + ".join(sorted(exact[i])) for i in only_exact).most_common(15),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", action="append", required=True, help="the previous full scan")
    parser.add_argument("--overlay", action="append", default=[], help="rescan rows, applied in order")
    parser.add_argument("--full", action="append", required=True, help="the new tree scanned in full")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    base, n_base = flagged(expand(args.base))
    composed = overlay(base, [expand([pattern]) for pattern in args.overlay])
    exact, n_exact = flagged(expand(args.full))
    report = compare(composed, exact, n_base, n_exact)
    args.output.write_text(json.dumps(report, indent=1))
    print(json.dumps({k: v for k, v in report.items() if not k.endswith("by_rules")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
