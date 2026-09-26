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

"""A3: what each recommended configuration catches and flags, rules and judge together.

    python evals/experiments/a3_recommended_profiles.py --output profiles.json \\
        --rules dev=final/msb-trainval.jsonl --rules test=final/msb-source-disjoint.jsonl \\
        --rules 'real=RUN/static-head-full/*.jsonl' \\
        --judge dev=dev-new.jsonl --judge test=test-new.jsonl --judge real=real-new.jsonl

A scan with ``--use-llm`` flags a skill when either the rules or the judge report MEDIUM or above,
so a recommendation has to be measured as that union, on the records both layers read. Each
policy preset contributes its rule demotions and its LLM caps: ``balanced`` neither, ``low-noise``
11 demotions and the low-confidence cap, ``quiet`` 19 demotions and both caps (the stricter wins).
Both are applied to stored findings exactly as the scanner applies them.

Rule rows are the static arm of ``cross_tool_benchmark``; judge rows come from
``evals/runners/judge_only.py``. Splits: ``dev`` (MaliciousSkillBench train/validation), ``test``
(its frozen test split) and ``real`` (an unlabelled sample of real skills, whose flag rate bounds
the false-positive rate from above).
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

from evals.experiments.f1_full_corpus_store import SEVERITY_RANK, expand, rows  # noqa: E402
from evals.lib.metrics import wilson_interval  # noqa: E402

PRESETS = {
    "balanced": (None, ()),
    "low-noise": ("low_noise_policy.yaml", ("low-confidence",)),
    "quiet": ("quiet_policy.yaml", ("low-confidence", "contextual")),
}


def demotions(pack_dir: Path, filename: str | None) -> frozenset[str]:
    if filename is None:
        return frozenset()
    import yaml

    overrides = yaml.safe_load((pack_dir / filename).read_text()).get("severity_overrides") or []
    return frozenset(o["rule_id"] for o in overrides if o.get("severity") in ("INFO", "LOW"))


def rule_flags(
    patterns: Sequence[str], wanted: set[str] | None, demoted: frozenset[str], threshold: int
) -> dict[str, tuple[Any, bool]]:
    out = {}
    for row in rows(expand(patterns)):
        if row.get("error") or row.get("capability_ok") is False:
            continue
        if wanted is not None and row["record_id"] not in wanted:
            continue
        flagged = any(
            SEVERITY_RANK.get(str(f.get("severity") or "").upper(), 0) >= threshold and f.get("rule_id") not in demoted
            for f in row.get("findings") or []
        )
        out[row["record_id"]] = (row.get("label"), flagged)
    return out


def judge_flags(path: Path, caps: Sequence[str], threshold: int) -> dict[str, tuple[Any, bool]]:
    out = {}
    for row in rows([path]):
        if row.get("error") or row.get("capability_ok") is False:
            continue
        flagged = False
        for finding in row.get("findings") or []:
            rank = SEVERITY_RANK.get(str(finding.get("severity") or "NONE").upper(), 0)
            confidence = str(finding.get("llm_confidence", finding.get("confidence")) or "").upper()
            if "contextual" in caps and finding.get("llm_verdict") == "CONTEXTUAL_RISK":
                rank = min(rank, 2)
            if "low-confidence" in caps and confidence == "LOW":
                rank = min(rank, 2)
            flagged = flagged or rank >= threshold
        out[row["record_id"]] = (row.get("label"), flagged)
    return out


def measure(flags: dict[str, tuple[Any, bool]]) -> dict[str, Any]:
    tp = sum(1 for label, f in flags.values() if label == "malicious" and f)
    positives = sum(1 for label, _ in flags.values() if label == "malicious")
    fp = sum(1 for label, f in flags.values() if label == "benign" and f)
    negatives = sum(1 for label, _ in flags.values() if label == "benign")
    flagged = sum(1 for _, f in flags.values() if f)
    out: dict[str, Any] = {"records": len(flags)}
    if positives:
        out["recall"] = tp / positives
        out["recall_ci95"] = list(wilson_interval(tp, positives, digits=4))
    if negatives:
        out["fpr"] = fp / negatives
        out["fpr_ci95"] = list(wilson_interval(fp, negatives, digits=4))
    if not positives and not negatives:
        out["flag_rate"] = flagged / len(flags) if flags else None
        out["flag_rate_ci95"] = list(wilson_interval(flagged, len(flags), digits=4)) if flags else None
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules", action="append", required=True, help="SPLIT=GLOB of static rows; repeatable")
    parser.add_argument("--judge", action="append", required=True, help="SPLIT=JSONL of judge rows; repeatable")
    parser.add_argument("--pack-dir", type=Path, default=_REPO_ROOT / "skill_scanner" / "data")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    rules = {split: pattern for split, _, pattern in (s.partition("=") for s in args.rules)}
    judges = {split: Path(path).expanduser() for split, _, path in (s.partition("=") for s in args.judge)}
    report: dict[str, Any] = {"experiment": "recommended-profiles", "blocking": False, "complete": True, "profiles": []}
    for preset, (filename, caps) in PRESETS.items():
        demoted = demotions(args.pack_dir.expanduser(), filename)
        for with_judge in (False, True):
            row: dict[str, Any] = {
                "preset": preset,
                "judge": with_judge,
                "rules_demoted": len(demoted),
                "caps": list(caps),
            }
            for tier, threshold in (("medium_plus", 3), ("high_plus", 4)):
                row[tier] = {}
                for split in rules:
                    judged = judge_flags(judges[split], caps, threshold) if split in judges else {}
                    # Only records both layers read are compared, with or without the judge.
                    wanted = set(judged) if split in judges else None
                    ruled = rule_flags([rules[split]], wanted, demoted, threshold)
                    if with_judge:
                        ruled = {
                            record_id: (label, flag or judged[record_id][1])
                            for record_id, (label, flag) in ruled.items()
                            if record_id in judged
                        }
                    row[tier][split] = measure(ruled)
            report["profiles"].append(row)
            summary = {
                split: {
                    m: round(v, 4) for m, v in row["medium_plus"][split].items() if m in ("recall", "fpr", "flag_rate")
                }
                for split in rules
            }
            print(json.dumps({"preset": preset, "judge": with_judge, "medium_plus": summary}))
    args.output.write_text(json.dumps(report, indent=1))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
