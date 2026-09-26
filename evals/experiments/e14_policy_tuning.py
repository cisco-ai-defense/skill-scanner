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

"""E14: can the policy be fitted without losing a detection?

Measures the package-level effect of two kinds of policy change, one rule at a
time: disabling a rule outright, and demoting it below the actionable threshold.
Both are scored on a labelled population so the cost is visible rather than
assumed.

The gate is the part that matters. A change is proposed only if it leaves every
package that was caught on a HIGH or CRITICAL malicious finding still caught.
Improving aggregate F1 while dropping one real detection is not a win, and a
tuner optimising F1 alone would happily make that trade.

The output is a proposed diff and the measured effect of each line, never an
applied change.
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

from evals.experiments.e11_suppression_candidates import observe
from skill_scanner.core.scan_policy import ScanPolicy

ACTIONABLE = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
PROTECTED = frozenset({"CRITICAL", "HIGH"})


def _package_view(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Collapse findings to one row per package."""
    packages: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = packages.setdefault(row["case_id"], {"label": row["label"], "findings": [], "protected_rules": set()})
        entry["findings"].append((row["rule_id"], row["severity"]))
        if row["severity"] in PROTECTED:
            entry["protected_rules"].add(row["rule_id"])
    return packages


def _score(packages: Mapping[str, Mapping[str, Any]], *, disabled: set[str], demoted: set[str]) -> dict[str, Any]:
    """Score the population under a candidate policy."""
    tp = fp = fn = tn = 0
    caught_protected: set[str] = set()
    for case_id, entry in packages.items():
        actionable = False
        protected_hit = False
        for rule_id, severity in entry["findings"]:
            if rule_id in disabled:
                continue
            effective = "LOW" if rule_id in demoted else severity
            if effective in ACTIONABLE:
                actionable = True
            if effective in PROTECTED:
                protected_hit = True
        if entry["label"] == "malicious":
            tp += actionable
            fn += not actionable
            if protected_hit:
                caught_protected.add(case_id)
        else:
            fp += actionable
            tn += not actionable
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": (2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "packages_caught_on_protected_findings": caught_protected,
    }


def evaluate_changes(packages: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Score every single-rule change against the baseline and the gate."""
    baseline = _score(packages, disabled=set(), demoted=set())
    baseline_protected = baseline["packages_caught_on_protected_findings"]

    rules = sorted({rule_id for entry in packages.values() for rule_id, _ in entry["findings"]})
    proposals: list[dict[str, Any]] = []
    for rule_id in rules:
        for kind, disabled, demoted in (
            ("disable", {rule_id}, set()),
            ("demote_below_actionable", set(), {rule_id}),
        ):
            candidate = _score(packages, disabled=disabled, demoted=demoted)
            lost = baseline_protected - candidate["packages_caught_on_protected_findings"]
            delta_f1 = candidate["f1"] - baseline["f1"]
            accepted = not lost and delta_f1 > 0
            proposals.append(
                {
                    "rule_id": rule_id,
                    "change": kind,
                    "delta_f1": delta_f1,
                    "delta_precision": candidate["precision"] - baseline["precision"],
                    "delta_recall": candidate["recall"] - baseline["recall"],
                    "delta_false_positive_rate": candidate["false_positive_rate"] - baseline["false_positive_rate"],
                    "packages_no_longer_caught_on_protected_findings": sorted(lost),
                    "accepted": accepted,
                    "reason": (
                        "improves F1 and leaves every package caught on a protected finding still caught"
                        if accepted
                        else (
                            f"would drop {len(lost)} package(s) caught on a HIGH or CRITICAL finding"
                            if lost
                            else "does not improve F1"
                        )
                    ),
                }
            )

    proposals.sort(key=lambda entry: -entry["delta_f1"])

    # At most one change per rule, preferring the least invasive that achieves the
    # gain. Disabling subsumes demoting, so proposing both is contradictory advice.
    invasiveness = {"demote_below_actionable": 0, "disable": 1}
    best_per_rule: dict[str, dict[str, Any]] = {}
    for entry in proposals:
        if not entry["accepted"]:
            continue
        current = best_per_rule.get(entry["rule_id"])
        if current is None:
            best_per_rule[entry["rule_id"]] = entry
            continue
        # Keep the clearly better gain; otherwise keep the gentler change.
        if entry["delta_f1"] > current["delta_f1"] + 1e-12:
            best_per_rule[entry["rule_id"]] = entry
        elif abs(entry["delta_f1"] - current["delta_f1"]) <= 1e-12 and (
            invasiveness[entry["change"]] < invasiveness[current["change"]]
        ):
            best_per_rule[entry["rule_id"]] = entry
    for entry in proposals:
        if entry["accepted"] and best_per_rule.get(entry["rule_id"]) is not entry:
            entry["accepted"] = False
            entry["reason"] = "superseded by a less invasive change to the same rule with the same effect"

    accepted = [entry for entry in proposals if entry["accepted"]]
    combined = _score(
        packages,
        disabled={entry["rule_id"] for entry in accepted if entry["change"] == "disable"},
        demoted={entry["rule_id"] for entry in accepted if entry["change"] == "demote_below_actionable"},
    )
    combined_lost = baseline_protected - combined["packages_caught_on_protected_findings"]

    def public(block: Mapping[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in block.items() if key != "packages_caught_on_protected_findings"}

    return {
        "baseline": public(baseline),
        "rules_examined": len(rules),
        "changes_examined": len(proposals),
        "changes_accepted": len(accepted),
        "changes_rejected_for_losing_a_protected_detection": sum(
            1 for entry in proposals if entry["packages_no_longer_caught_on_protected_findings"]
        ),
        "combined": public(combined),
        "combined_delta_f1": combined["f1"] - baseline["f1"],
        "combined_lost_protected_packages": sorted(combined_lost),
        "gate_passed": not combined_lost,
        "proposed_diff": {
            "disabled_rules": sorted(entry["rule_id"] for entry in accepted if entry["change"] == "disable"),
            "severity_overrides": [
                {"rule_id": entry["rule_id"], "severity": "LOW"}
                for entry in accepted
                if entry["change"] == "demote_below_actionable"
            ],
        },
        "top_changes": proposals[:20],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    directories = [path for path in sorted(args.corpus.iterdir()) if path.is_dir()]
    rows = observe(directories, labels, policy=ScanPolicy.default())
    if not rows:
        print("no findings observed; refusing to emit", file=sys.stderr)
        return 1

    packages = _package_view(rows)
    result = evaluate_changes(packages)
    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e14-policy-tuning",
        "blocking": False,
        "population": len(packages),
        "findings_observed": len(rows),
        "label_mix": dict(collections.Counter(entry["label"] for entry in packages.values())),
        **result,
        "note": "Proposed diff only. Nothing is applied, and every line carries its measured effect.",
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    baseline = result["baseline"]
    combined = result["combined"]
    print(
        f"baseline  P={baseline['precision']:.3f} R={baseline['recall']:.3f} "
        f"F1={baseline['f1']:.3f} FPR={baseline['false_positive_rate']:.3f}"
    )
    print(
        f"tuned     P={combined['precision']:.3f} R={combined['recall']:.3f} "
        f"F1={combined['f1']:.3f} FPR={combined['false_positive_rate']:.3f}  "
        f"(dF1={result['combined_delta_f1']:+.3f})"
    )
    print(
        f"changes   examined={result['changes_examined']} accepted={result['changes_accepted']} "
        f"rejected_for_losing_a_detection={result['changes_rejected_for_losing_a_protected_detection']}"
    )
    print(f"gate      {'passed' if result['gate_passed'] else 'FAILED'}")
    for entry in result["proposed_diff"]["disabled_rules"][:6]:
        print(f"  disable {entry}")
    for entry in result["proposed_diff"]["severity_overrides"][:6]:
        print(f"  demote  {entry['rule_id']}")
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
