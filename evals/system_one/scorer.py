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

"""Score tiers and their cascades under both lenses.

Two lenses, reported side by side, because they reorder the ranking and a figure
without its lens is meaningless.  **Block-only** counts just a hard block as a
catch, which is the production question when a block is the enforcement action.
**Any-intervention** counts a confirm as a catch too, which is the right question
when a confirm routes to review.

Cascade semantics, carried over deliberately:

*Short-circuit only on a block.*  A deterministic confirm escalates to the next
tier rather than ending the chain, then rejoins with a never-downgrade merge. The
prior programme measured the cost of always short-circuiting at 0.014 block F1 on
its broad stage and 0.046 at production weighting.

*A later tier may raise but never lower.*  Downgrades are counted and reported,
because a silent one is how a cascade loses a true detection.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.lib.metrics import binary_metrics, wilson_interval  # noqa: E402
from evals.system_one.answers import ACTION_RANK  # noqa: E402

INTERVENTION_ACTIONS = frozenset({"confirm", "block", "alert"})
BLOCK_ACTIONS = frozenset({"block", "deny"})


def read_predictions(path: Path) -> dict[str, dict[str, Any]]:
    """Load a prediction file, refusing one that did not attest completion."""
    meta_path = path.with_suffix(path.suffix + ".meta.json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("complete") is False:
            raise ValueError(f"{path} is attested incomplete; refusing to score it")
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            rows[row["case_id"]] = row
    return rows


def _usable(row: Mapping[str, Any] | None) -> bool:
    if row is None:
        return False
    if row.get("error_code"):
        return False
    return ACTION_RANK.get(str(row.get("action")), -1) >= 0


def merge(actions: Sequence[str]) -> str:
    """Never-downgrade merge across tiers."""
    best = "allow"
    for action in actions:
        rank = ACTION_RANK.get(action, -1)
        if rank > ACTION_RANK[best]:
            best = action
    return best


def compose(
    case_ids: Sequence[str],
    tiers: Sequence[dict[str, dict[str, Any]]],
    *,
    escalate_on_confirm: bool = True,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Run the cascade per case and return decisions plus invocation telemetry."""
    decisions: dict[str, str] = {}
    invocations = [0] * len(tiers)
    downgrades_prevented = 0
    short_circuits = 0

    for case_id in case_ids:
        seen: list[str] = []
        for index, tier in enumerate(tiers):
            row = tier.get(case_id)
            if not _usable(row):
                # A tier that could not decide is skipped rather than counted as allow.
                continue
            invocations[index] += 1
            action = str(row["action"])
            seen.append(action)
            if action in BLOCK_ACTIONS:
                short_circuits += 1
                break
            if action == "confirm" and not escalate_on_confirm:
                break
        merged = merge(seen)
        if seen and ACTION_RANK.get(seen[-1], -1) < ACTION_RANK[merged]:
            downgrades_prevented += 1
        decisions[case_id] = merged

    total = len(case_ids) or 1
    return decisions, {
        "tier_invocations": invocations,
        "tier_invocation_rates": [round(value / total, 6) for value in invocations],
        "short_circuits": short_circuits,
        "downgrades_prevented": downgrades_prevented,
        "escalate_on_confirm": escalate_on_confirm,
    }


def score(decisions: Mapping[str, str], labels: Mapping[str, str], *, lens: str) -> dict[str, Any]:
    """Score decisions under one lens."""
    positive = BLOCK_ACTIONS if lens == "block_only" else INTERVENTION_ACTIONS
    tp = fp = fn = tn = 0
    for case_id, action in decisions.items():
        label = labels.get(case_id)
        if label is None:
            continue
        flagged = action in positive
        if label == "malicious":
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
            tn += not flagged
    metrics = binary_metrics(tp, fp, fn, tn)
    metrics["lens"] = lens
    metrics["intervention_rate"] = sum(1 for action in decisions.values() if action in INTERVENTION_ACTIONS) / (
        len(decisions) or 1
    )
    return metrics


def score_chain(
    name: str,
    tier_paths: Sequence[Path],
    labels: Mapping[str, str],
    *,
    escalate_on_confirm: bool = True,
) -> dict[str, Any]:
    """Score one named chain under both lenses."""
    tiers = [read_predictions(path) for path in tier_paths]
    case_ids = sorted(set(labels) & {case for tier in tiers for case in tier})
    decisions, telemetry = compose(case_ids, tiers, escalate_on_confirm=escalate_on_confirm)
    return {
        "chain": name,
        "tiers": [path.name for path in tier_paths],
        "cases": len(case_ids),
        "telemetry": telemetry,
        "block_only": score(decisions, labels, lens="block_only"),
        "any_intervention": score(decisions, labels, lens="any_intervention"),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument(
        "--chain",
        action="append",
        required=True,
        metavar="NAME=path1,path2",
        help="named chain of prediction files in tier order; repeatable",
    )
    parser.add_argument("--no-escalate-on-confirm", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    chains = []
    for spec in args.chain:
        if "=" not in spec:
            parser.error(f"chain must be NAME=path1,path2: {spec}")
        name, paths = spec.split("=", 1)
        chains.append(
            score_chain(
                name,
                [Path(part) for part in paths.split(",") if part],
                labels,
                escalate_on_confirm=not args.no_escalate_on_confirm,
            )
        )

    report = {
        "schema_version": 1,
        "kind": "skill-scanner-cascade-score",
        "blocking": False,
        "labels_file": str(args.labels),
        "population": len(labels),
        "chains": chains,
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(f"{'chain':<34} {'lens':<17} {'P':>6} {'R':>6} {'F1':>6} {'FPR':>6}  invocation rates")
    for chain in chains:
        for lens in ("block_only", "any_intervention"):
            block = chain[lens]
            rates = ",".join(f"{rate:.2f}" for rate in chain["telemetry"]["tier_invocation_rates"])
            print(
                f"{chain['chain']:<34} {lens:<17} {block['precision']:>6.3f} {block['recall']:>6.3f} "
                f"{block['f1']:>6.3f} {block['false_positive_rate']:>6.3f}  {rates}"
            )
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
