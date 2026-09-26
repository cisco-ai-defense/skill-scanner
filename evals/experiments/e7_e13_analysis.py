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

"""E7 conservatism calibration and E13 rule-candidate mining.

Both read predictions already on disk, so neither costs a model call.

**E7** asks whether intervention can be bought at zero cost to recall. It sweeps
the confidence floor a tier must clear before it is allowed to intervene, and
reports the highest floor that still catches everything the unfiltered tier caught.
If no floor removes false positives without losing a true detection, the honest
answer is that the tier should not be gated on confidence at all, and that is a
publishable result rather than a failure.

**E13** finds where a rule would pay for itself: the cases a model blocks
confidently and the deterministic rules allow. Anything promoted into a rule then
runs at zero model cost forever. It emits a ranked review queue and never an
executable rule, because a mined rule that nobody read is how a false-positive
wave starts.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.lib.metrics import wilson_interval  # noqa: E402
from evals.system_one.scorer import read_predictions  # noqa: E402

THRESHOLDS = (0.0, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 0.99)
INTERVENTION = frozenset({"confirm", "block"})


def sweep_threshold(
    model_rows: Mapping[str, dict[str, Any]],
    labels: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Score the tier at each confidence floor."""
    out: list[dict[str, Any]] = []
    for floor in THRESHOLDS:
        tp = fp = fn = tn = 0
        gated = 0
        for case_id, label in labels.items():
            row = model_rows.get(case_id)
            if row is None or row.get("error_code"):
                continue
            action = str(row.get("action"))
            confidence = float(row.get("confidence") or 0.0)
            intervenes = action in INTERVENTION and confidence >= floor
            if action in INTERVENTION and confidence < floor:
                gated += 1
            if label == "malicious":
                tp += intervenes
                fn += not intervenes
            else:
                fp += intervenes
                tn += not intervenes
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        out.append(
            {
                "threshold": floor,
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "gated_interventions": gated,
                "precision": precision,
                "recall": recall,
                "f1": (2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
                "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
                "recall_95": list(wilson_interval(tp, tp + fn)),
            }
        )
    return out


def best_zero_loss_threshold(sweep: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Highest floor that keeps every true positive the ungated tier found."""
    baseline = sweep[0]
    best = baseline
    for row in sweep:
        if row["true_positives"] >= baseline["true_positives"] and row["threshold"] >= best["threshold"]:
            best = row
    removed = baseline["false_positives"] - best["false_positives"]
    return {
        "threshold": best["threshold"],
        "false_positives_removed": removed,
        "false_positive_rate_before": baseline["false_positive_rate"],
        "false_positive_rate_after": best["false_positive_rate"],
        "recall_preserved": best["true_positives"] == baseline["true_positives"],
        "verdict": (
            "confidence gating removes false positives at no cost to recall"
            if removed > 0
            else "no floor removes a false positive without losing a detection, so gating buys nothing here"
        ),
    }


def mine_rule_candidates(
    model_rows: Mapping[str, dict[str, Any]],
    deterministic_rows: Mapping[str, dict[str, Any]],
    labels: Mapping[str, str],
    *,
    block_threshold: float,
    top: int,
) -> dict[str, Any]:
    """Cluster confident model blocks the rules allowed."""
    considered = 0
    missed: list[dict[str, Any]] = []
    for case_id, row in model_rows.items():
        if row.get("error_code"):
            continue
        if str(row.get("action")) != "block" or float(row.get("confidence") or 0.0) < block_threshold:
            continue
        considered += 1
        deterministic = deterministic_rows.get(case_id)
        if deterministic is None:
            continue
        if str(deterministic.get("action")) in INTERVENTION:
            continue
        missed.append(
            {
                "case_id": case_id,
                "label": labels.get(case_id, "unknown"),
                "model_confidence": round(float(row.get("confidence") or 0.0), 4),
                "deterministic_finding_count": int(deterministic.get("finding_count") or 0),
                "deterministic_severities": deterministic.get("severities") or [],
            }
        )

    by_label = collections.Counter(entry["label"] for entry in missed)
    missed.sort(key=lambda entry: -entry["model_confidence"])
    return {
        "block_threshold": block_threshold,
        "confident_blocks_considered": considered,
        "confident_blocks_rules_allowed": len(missed),
        # The headline: how much of the model tier's contribution is currently
        # re-derived on every call because no rule encodes it.
        "share_rules_missed": (len(missed) / considered) if considered else 0.0,
        "by_label": dict(by_label),
        "true_positive_share_of_queue": (by_label.get("malicious", 0) / len(missed)) if missed else 0.0,
        "review_queue": missed[:top],
        "note": "Candidates and evidence only. Rules stay human-authored.",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--deterministic", type=Path, required=True)
    parser.add_argument("--model", action="append", required=True, metavar="NAME=path")
    parser.add_argument("--block-threshold", type=float, default=0.75)
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    deterministic = read_predictions(args.deterministic)

    arms: dict[str, Any] = {}
    for spec in args.model:
        if "=" not in spec:
            parser.error(f"model must be NAME=path: {spec}")
        name, path = spec.split("=", 1)
        rows = read_predictions(Path(path))
        sweep = sweep_threshold(rows, labels)
        arms[name] = {
            "predictions": path,
            "e7_threshold_sweep": sweep,
            "e7_best_zero_loss": best_zero_loss_threshold(sweep),
            "e13_rule_candidates": mine_rule_candidates(
                rows, deterministic, labels, block_threshold=args.block_threshold, top=args.top
            ),
        }

    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e7-e13",
        "blocking": False,
        "population": len(labels),
        "arms": arms,
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    for name, arm in arms.items():
        best = arm["e7_best_zero_loss"]
        mined = arm["e13_rule_candidates"]
        print(f"{name}:")
        print(
            f"  E7  best zero-loss floor={best['threshold']:.2f} "
            f"FPR {best['false_positive_rate_before']:.3f} -> {best['false_positive_rate_after']:.3f} "
            f"({best['false_positives_removed']} removed)"
        )
        print(f"      {best['verdict']}")
        print(
            f"  E13 confident blocks={mined['confident_blocks_considered']} "
            f"rules missed={mined['confident_blocks_rules_allowed']} "
            f"({mined['share_rules_missed']:.1%}) malicious share of queue="
            f"{mined['true_positive_share_of_queue']:.1%}"
        )
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
