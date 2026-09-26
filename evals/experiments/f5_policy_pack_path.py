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

"""F5: the greedy demotion path the ``low-noise`` and ``quiet`` presets were cut from.

    python evals/experiments/f5_policy_pack_path.py --store STORE --run static-head \\
        --dev final/msb-trainval.skill-scanner.static.jsonl --output pack-path.json

A demoted rule is reported at LOW, so a record stays flagged under a pack while some MEDIUM+
finding belongs to a rule the pack does not demote. Each step demotes the rule that clears the
most real skills the judge also cleared, per malicious train/validation package it would stop
detecting::

    score = judge_cleared_removed / (1 + recall_weight * dev_tp_lost + agree_weight * judge_agreed_removed)

and a rule must clear at least ``--min-gain`` judge-cleared records to be considered. The shipped
presets were cut from this path during the second tuning pass, at 11 and 19 rules. On the final tree
the path reproduces ``low-noise`` exactly and 18 of ``quiet``'s 19 rules: ``COMPOUND_FIND_EXEC``
now ranks 20th, behind ``YARA_system_manipulation_generic``, because the third pass removed most of
its false positives. The presets' measured effect is reported separately, and exactly, by F2.
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

from evals.experiments.f2_full_corpus_analysis import literal, run_id  # noqa: E402
from evals.experiments.f4_labelled_ab import load  # noqa: E402

MEDIUM_PLUS = frozenset({"MEDIUM", "HIGH", "CRITICAL"})


def real_skill_rules(store: Path, run: str, judge_run: str) -> tuple[dict[str, set[str]], dict[str, bool], int]:
    import duckdb

    con = duckdb.connect()
    findings = f"read_parquet({literal(store / 'findings' / '**' / '*.parquet')}, hive_partitioning=true)"
    scans = f"read_parquet({literal(store / 'scans' / '**' / '*.parquet')}, hive_partitioning=true)"
    rules: dict[str, set[str]] = collections.defaultdict(set)
    for record_id, rule in con.execute(
        f"SELECT record_id, rule_id FROM {findings} WHERE run_id='{run}' AND severity_rank>=3"
    ).fetchall():
        rules[record_id].add(rule)
    judge = dict(
        con.execute(
            f"SELECT record_id, max_severity_rank>=3 FROM {scans} "
            f"WHERE run_id='{judge_run}' AND error IS NULL AND capability_ok"
        ).fetchall()
    )
    records = con.execute(
        f"SELECT count(*) FROM {scans} WHERE run_id='{run}' AND error IS NULL AND coalesce(capability_ok, true)"
    ).fetchone()[0]
    return dict(rules), judge, records


def state(
    real: dict[str, set[str]],
    judge: dict[str, bool],
    n_real: int,
    positives: list[set[str]],
    negatives: list[set[str]],
    demoted: set[str],
) -> dict[str, Any]:
    flagged = [record_id for record_id, rules in real.items() if rules - demoted]
    tp = sum(1 for rules in positives if rules - demoted)
    fp = sum(1 for rules in negatives if rules - demoted)
    return {
        "real_flag_rate": len(flagged) / n_real,
        "real_flagged": len(flagged),
        "real_flagged_judge_cleared": sum(1 for record_id in flagged if judge.get(record_id) is False),
        "dev_recall": tp / len(positives) if positives else None,
        "dev_tp": tp,
        "dev_fpr": fp / len(negatives) if negatives else None,
        "dev_fp": fp,
    }


def greedy_path(
    real: dict[str, set[str]],
    judge: dict[str, bool],
    n_real: int,
    positives: list[set[str]],
    negatives: list[set[str]],
    *,
    steps: int,
    min_gain: int,
    recall_weight: float,
    agree_weight: float,
) -> list[dict[str, Any]]:
    demoted: set[str] = set()
    path = [{"demote": None, **state(real, judge, n_real, positives, negatives, demoted)}]
    candidates = sorted({rule for rules in real.values() for rule in rules})
    for _ in range(steps):
        best = None
        for rule in candidates:
            if rule in demoted:
                continue
            after = demoted | {rule}
            cleared = [record_id for record_id, rules in real.items() if rules - demoted and not rules - after]
            gain = sum(1 for record_id in cleared if judge.get(record_id) is False)
            agreed = sum(1 for record_id in cleared if judge.get(record_id) is True)
            tp_lost = sum(1 for rules in positives if rules - demoted and not rules - after)
            if gain < min_gain:
                continue
            score = gain / (1 + recall_weight * tp_lost + agree_weight * agreed)
            if best is None or score > best[0]:
                best = (score, rule, gain, agreed, tp_lost)
        if best is None:
            break
        demoted.add(best[1])
        path.append(
            {
                "demote": best[1],
                "judge_cleared_removed": best[2],
                "judge_agreed_removed": best[3],
                "dev_tp_lost": best[4],
                **state(real, judge, n_real, positives, negatives, demoted),
            }
        )
    return path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--run", default="static-head")
    parser.add_argument("--judge-run", default="judge-full")
    parser.add_argument("--dev", type=Path, required=True, help="static scan of MSB train/validation")
    parser.add_argument("--steps", type=int, default=40)
    parser.add_argument("--min-gain", type=int, default=50)
    parser.add_argument("--recall-weight", type=float, default=25.0)
    parser.add_argument("--agree-weight", type=float, default=0.5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    real, judge, n_real = real_skill_rules(args.store.expanduser(), run_id(args.run), run_id(args.judge_run))
    dev = load(args.dev.expanduser())

    def medium_plus(findings: list[dict[str, Any]]) -> set[str]:
        return {f["rule_id"] for f in findings if str(f.get("severity") or "").upper() in MEDIUM_PLUS}

    positives = [medium_plus(findings) for label, findings in dev.values() if label == "malicious"]
    negatives = [medium_plus(findings) for label, findings in dev.values() if label == "benign"]
    path = greedy_path(
        real,
        judge,
        n_real,
        positives,
        negatives,
        steps=args.steps,
        min_gain=args.min_gain,
        recall_weight=args.recall_weight,
        agree_weight=args.agree_weight,
    )
    args.output.write_text(json.dumps(path, indent=1))
    for step in path:
        print(
            f"{str(step['demote']):42s} real {step['real_flag_rate']:.3%}  "
            f"dev recall {step['dev_recall']:.2%} (-{step.get('dev_tp_lost', 0)})  dev FPR {step['dev_fpr']:.2%}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
