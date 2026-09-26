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

"""C4: choose an OpenJev screen for the judge on train/validation, then score the test split once.

A record is flagged by the cascade only when the screen passes it *and* the judge flags it at
MEDIUM or above, so the screen can veto judge false positives and save judge calls. Two screens:

* the ``prompt_injection`` probe alone, thresholded on its logit;
* a logistic regression over the logits of all eight probes, fitted on train/validation.

For every judge run and LLM cap, the threshold keeps at least ``--keep-recall`` of the judge's
own train/validation recall at the lowest train/validation false-positive rate, ties broken by
fewer judge calls. The frozen test split is then scored once with that threshold; nothing is
chosen on it, which is what the MaliciousSkillBench terms require. An optional unlabelled sample
of real skills gives the flag rate and the share of skills the screen still sends to the judge.

Inputs are the JSONL written by ``c3_openjev_local.py`` (every probe) and judge rows from
``evals/runners/judge_only.py`` or any rows carrying ``record_id``, ``label`` and ``findings``::

    python evals/experiments/c4_openjev_screen.py \\
        --jev-dev jev-dev.jsonl --jev-test jev-test.jsonl --jev-real jev-real.jsonl \\
        --judge new=dev-new.jsonl,test-new.jsonl,real-new.jsonl \\
        --judge shipped=dev-shipped.jsonl,test-shipped.jsonl,real-shipped.jsonl \\
        --output jev-screen.json

The logistic fit is L2-regularised with balanced class weights (the same objective as
scikit-learn's ``LogisticRegression(C=1.0, class_weight="balanced")``), solved by Newton's method
so the experiment needs only numpy.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.metrics import wilson_interval  # noqa: E402

PROBES = (
    "data_exfiltration",
    "destructive_command",
    "obfuscation",
    "prompt_injection",
    "remote_hidden_execution",
    "security_control_change",
    "sensitive_data_access",
    "supply_chain",
)
SEVERITY_RANK = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
CAPS = (None, "low-confidence", "contextual")


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def load_jev(path: Path) -> dict[str, dict[str, Any]]:
    """Answered records only: a record with a probe error has no score to screen on."""
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        probes = row.get("probes") or {}
        if row.get("errors") or any(name not in probes for name in PROBES):
            continue
        rows[row["record_id"]] = row
    return rows


def load_judge(path: Path, cap: str | None) -> dict[str, tuple[str | None, bool]]:
    """``record_id -> (label, flagged at MEDIUM+)`` after applying an LLM severity cap."""
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("error") or row.get("capability_ok") is False:
            continue
        flagged = False
        for finding in row.get("findings") or []:
            rank = SEVERITY_RANK.get(str(finding.get("severity") or "NONE").upper(), 0)
            confidence = finding.get("llm_confidence", finding.get("confidence"))
            if cap == "contextual" and finding.get("llm_verdict") == "CONTEXTUAL_RISK":
                rank = min(rank, 2)
            if cap == "low-confidence" and str(confidence or "").upper() == "LOW":
                rank = min(rank, 2)
            flagged = flagged or rank >= 3
        rows[row["record_id"]] = (row.get("label"), flagged)
    return rows


def fit_logistic(x: Any, y: Any, *, c: float = 1.0, iterations: int = 100) -> tuple[Any, float]:
    """Balanced-weight, L2-regularised logistic regression; the intercept is not penalised."""
    import numpy as np

    n, d = x.shape
    weights = np.where(y, n / (2 * y.sum()), n / (2 * (n - y.sum())))
    design = np.hstack([x, np.ones((n, 1))])
    penalty = np.diag([1.0] * d + [0.0])
    beta = np.zeros(d + 1)
    for _ in range(iterations):
        prob = 1 / (1 + np.exp(-(design @ beta)))
        gradient = penalty @ beta + c * design.T @ (weights * (prob - y))
        hessian = penalty + c * (design * (weights * prob * (1 - prob))[:, None]).T @ design
        step = np.linalg.solve(hessian, gradient)
        beta -= step
        if np.abs(step).max() < 1e-10:
            break
    return beta[:d], float(beta[d])


def auc(scores: Sequence[float], positive: Sequence[bool]) -> float | None:
    """Mann-Whitney AUC with tied scores given their average rank."""
    import numpy as np

    scores, positive = np.asarray(scores, dtype=float), np.asarray(positive, dtype=bool)
    n1 = int(positive.sum())
    n0 = len(positive) - n1
    if not n1 or not n0:
        return None
    _, inverse, counts = np.unique(scores, return_inverse=True, return_counts=True)
    starts = np.cumsum(counts) - counts
    ranks = (starts + (counts + 1) / 2)[inverse]
    return float((ranks[positive].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def _rate(k: int, n: int) -> dict[str, Any]:
    return {"rate": k / n if n else None, "ci95": list(wilson_interval(k, n, digits=4)) if n else None}


def labelled(ids: Sequence[str], scores: Sequence[float], judge: dict, threshold: float) -> dict[str, Any]:
    tp = fp = fn = tn = calls = 0
    for record_id, score in zip(ids, scores):
        if record_id not in judge:
            continue
        label, judge_flag = judge[record_id]
        malicious = label == "malicious"
        passed = bool(score >= threshold)
        flagged = passed and judge_flag
        calls += passed
        tp += flagged and malicious
        fp += flagged and not malicious
        fn += malicious and not flagged
        tn += not malicious and not flagged
    positives, negatives = tp + fn, fp + tn
    recall, fpr = _rate(tp, positives), _rate(fp, negatives)
    precision = tp / (tp + fp) if tp + fp else None
    return {
        "records": positives + negatives,
        "recall": recall["rate"],
        "recall_ci95": recall["ci95"],
        "fpr": fpr["rate"],
        "fpr_ci95": fpr["ci95"],
        "precision": precision,
        "f1": 2 * precision * recall["rate"] / (precision + recall["rate"]) if precision and recall["rate"] else None,
        "judge_calls": calls / (positives + negatives) if positives + negatives else None,
        "tp": tp,
        "fp": fp,
    }


def unlabelled(ids: Sequence[str], scores: Sequence[float], judge: dict, threshold: float) -> dict[str, Any]:
    records = calls = flagged = 0
    for record_id, score in zip(ids, scores):
        if record_id not in judge:
            continue
        passed = bool(score >= threshold)
        records += 1
        calls += passed
        flagged += passed and judge[record_id][1]
    flag = _rate(flagged, records)
    return {
        "records": records,
        "judge_calls": calls / records if records else None,
        "flag_rate": flag["rate"],
        "flag_rate_ci95": flag["ci95"],
    }


def select(
    dev_ids: Sequence[str], dev_scores: Any, judge: dict, *, keep_recall: float, alone_recall: float
) -> tuple[float, dict[str, Any]] | None:
    import numpy as np

    best: tuple[float, dict[str, Any]] | None = None
    for threshold in np.quantile(dev_scores, np.linspace(0, 0.95, 400)):
        metrics = labelled(dev_ids, dev_scores, judge, float(threshold))
        if metrics["recall"] is None or metrics["recall"] < keep_recall * alone_recall:
            continue
        key = (metrics["fpr"], metrics["judge_calls"])
        if best is None or key < (best[1]["fpr"], best[1]["judge_calls"]):
            best = (float(threshold), metrics)
    return best


def run(args: argparse.Namespace) -> dict[str, Any]:
    import numpy as np

    splits = {"dev": load_jev(args.jev_dev), "test": load_jev(args.jev_test)}
    if args.jev_real:
        splits["real"] = load_jev(args.jev_real)
    ids = {name: sorted(rows) for name, rows in splits.items()}
    features = {
        name: np.array([[_logit(splits[name][i]["probes"][p]) for p in PROBES] for i in ids[name]]) for name in splits
    }
    labels = {
        name: np.array([splits[name][i].get("label") == "malicious" for i in ids[name]]) for name in ("dev", "test")
    }
    coef, intercept = fit_logistic(features["dev"], labels["dev"])
    scores = {
        "prompt_injection": {name: features[name][:, PROBES.index("prompt_injection")] for name in splits},
        "logistic": {name: features[name] @ coef + intercept for name in splits},
    }
    report: dict[str, Any] = {
        "experiment": "c4-openjev-screen",
        "blocking": False,
        "complete": True,
        "selection": f"train/validation; keep >= {args.keep_recall:.0%} of the judge's recall at minimum FPR",
        "records": {name: len(rows) for name, rows in splits.items()},
        "logistic": {
            "features": [f"logit(p_{p})" for p in PROBES],
            "coef": [round(float(v), 4) for v in coef],
            "intercept": round(intercept, 4),
            "c": 1.0,
            "class_weight": "balanced",
        },
        "standalone_auc": {},
        "results": [],
    }
    for index, probe in enumerate(PROBES):
        report["standalone_auc"][probe] = {
            name: auc(features[name][:, index], labels[name]) for name in ("dev", "test")
        }
    for name, per_split in scores.items():
        report["standalone_auc"][name] = {split: auc(per_split[split], labels[split]) for split in ("dev", "test")}

    for spec in args.judge:
        prompt, _, paths = spec.partition("=")
        judge_paths = [Path(p) for p in paths.split(",")]
        for cap in CAPS:
            judged = {split: load_judge(path, cap) for split, path in zip(("dev", "test", "real"), judge_paths)}
            always = {split: np.zeros(len(ids[split])) for split in splits}
            alone = {
                "dev": labelled(ids["dev"], always["dev"], judged["dev"], -1.0),
                "test": labelled(ids["test"], always["test"], judged["test"], -1.0),
            }
            if "real" in judged and "real" in splits:
                alone["real"] = unlabelled(ids["real"], always["real"], judged["real"], -1.0)
            report["results"].append({"prompt": prompt, "cap": cap, "screen": None, **alone})
            for screen, per_split in scores.items():
                chosen = select(
                    ids["dev"],
                    per_split["dev"],
                    judged["dev"],
                    keep_recall=args.keep_recall,
                    alone_recall=alone["dev"]["recall"] or 0.0,
                )
                if chosen is None:
                    continue
                threshold, dev_metrics = chosen
                row: dict[str, Any] = {
                    "prompt": prompt,
                    "cap": cap,
                    "screen": screen,
                    "threshold": round(threshold, 4),
                    "dev": dev_metrics,
                    "test": labelled(ids["test"], per_split["test"], judged["test"], threshold),
                }
                if screen == "prompt_injection":
                    row["threshold_probability"] = round(1 / (1 + math.exp(-threshold)), 5)
                if "real" in judged and "real" in splits:
                    row["real"] = unlabelled(ids["real"], per_split["real"], judged["real"], threshold)
                report["results"].append(row)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jev-dev", type=Path, required=True, help="c3 output on train/validation")
    parser.add_argument("--jev-test", type=Path, required=True, help="c3 output on the frozen test split")
    parser.add_argument("--jev-real", type=Path, default=None, help="c3 output on an unlabelled real-skill sample")
    parser.add_argument(
        "--judge",
        action="append",
        required=True,
        help="NAME=DEV,TEST[,REAL] judge rows for one judge configuration; repeatable",
    )
    parser.add_argument("--keep-recall", type=float, default=0.97)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    report = run(args)
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    for row in report["results"]:
        if row["cap"] is not None:
            continue
        test, real = row["test"], row.get("real") or {}
        print(
            f"{row['prompt']:10s} {str(row['screen']):17s} test recall {test['recall']:.1%} FPR {test['fpr']:.1%} "
            f"calls {test['judge_calls']:.0%}"
            + (f" | real flags {real['flag_rate']:.2%} calls {real['judge_calls']:.1%}" if real else "")
        )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
