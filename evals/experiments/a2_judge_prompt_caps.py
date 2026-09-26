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

"""A2: the judge alone, per prompt and per LLM severity cap, on every population.

    python evals/experiments/a2_judge_prompt_caps.py --output judge-prompt.json \\
        --judge shipped=dev-shipped.jsonl,test-shipped.jsonl,real-shipped.jsonl \\
        --judge new=dev-new.jsonl,test-new.jsonl,real-new.jsonl

Each ``--judge`` names one prompt's rows on MaliciousSkillBench train/validation, the frozen test
split and an unlabelled real-skill sample, as written by ``evals/runners/judge_only.py``. Every
answered record counts; a failed one is counted and excluded, never scored as clean. The caps
are the policy's ``llm_analysis.low_confidence_max_severity`` and
``contextual_risk_max_severity`` at LOW, applied to the stored findings, which is exactly what
the analyzer does with them.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.experiments.c4_openjev_screen import CAPS, load_judge  # noqa: E402
from evals.lib.metrics import wilson_interval  # noqa: E402


def failures(path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            count += bool(row.get("error") or row.get("capability_ok") is False)
    return count


def labelled_metrics(judged: dict[str, tuple[str | None, bool]]) -> dict[str, Any]:
    tp = sum(1 for label, flag in judged.values() if label == "malicious" and flag)
    positives = sum(1 for label, _ in judged.values() if label == "malicious")
    fp = sum(1 for label, flag in judged.values() if label == "benign" and flag)
    negatives = sum(1 for label, _ in judged.values() if label == "benign")
    recall = tp / positives if positives else None
    fpr = fp / negatives if negatives else None
    precision = tp / (tp + fp) if tp + fp else None
    return {
        "records": positives + negatives,
        "recall": recall,
        "recall_ci95": list(wilson_interval(tp, positives, digits=4)) if positives else None,
        "fpr": fpr,
        "fpr_ci95": list(wilson_interval(fp, negatives, digits=4)) if negatives else None,
        "precision": precision,
        "f1": 2 * precision * recall / (precision + recall) if precision and recall else None,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--judge", action="append", required=True, help="NAME=DEV,TEST,REAL; repeatable")
    parser.add_argument("--model", default="Gemma 4 26B-A4B via Bedrock mantle")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    report: dict[str, Any] = {
        "experiment": "judge-prompt",
        "model": args.model,
        "verdict_repair": True,
        "blocking": False,
        "complete": True,
        "rows": [],
    }
    for spec in args.judge:
        prompt, _, paths = spec.partition("=")
        dev, test, real = (Path(p).expanduser() for p in paths.split(","))
        for cap in CAPS:
            real_rows = load_judge(real, cap)
            flagged = sum(1 for _, flag in real_rows.values() if flag)
            row = {
                "prompt": prompt,
                "cap": cap,
                "dev": {**labelled_metrics(load_judge(dev, cap)), "failed": failures(dev)},
                "test": {**labelled_metrics(load_judge(test, cap)), "failed": failures(test)},
                "real": {
                    "records": len(real_rows),
                    "flag_rate": flagged / len(real_rows) if real_rows else None,
                    "flag_rate_ci95": list(wilson_interval(flagged, len(real_rows), digits=4)) if real_rows else None,
                    "failed": failures(real),
                },
            }
            report["rows"].append(row)
            test_block = row["test"]
            print(
                f"{prompt:10s} cap={str(cap):15s} test recall {test_block['recall']:.1%} FPR {test_block['fpr']:.1%} "
                f"| real {row['real']['flag_rate']:.2%}"
            )
    args.output.write_text(json.dumps(report, indent=1))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
