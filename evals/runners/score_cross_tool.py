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

"""Score a collected head-to-head run under several explicitly separated lenses.

Kept apart from collection so the lenses can change without re-scanning.

Three rules shape everything here.

**Only paired records are scored.**  A record counts for a tool only if *both*
tools produced a usable result for it.  Comparing a tool's 1,384 records against
another's 1,302 would let the tool that failed more often look better, because the
records it failed on are exactly the awkward ones.

**A corpus's own licence decides which metrics may exist.**  HarmfulSkillBench
forbids F1 and false-positive-rate claims; corpora with no harmless class cannot
support precision or a false-positive rate at all.  Those cells are refused rather
than computed against an empty denominator.

**A tool's package decision is read, never re-derived.**  SkillSpector bands a
0-100 score into a recommendation and rewrites ``SAFE`` to ``CAUTION`` under some
conditions, so recomputing the band from the score would disagree with the tool
about its own output.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.cross_tool import SEVERITY_ORDER, ToolRow, read_rows, severity_rank  # noqa: E402
from evals.lib.metrics import (  # noqa: E402
    binary_metrics,
    paired_bootstrap_difference,
    safe_divide,
    wilson_interval,
)

# Labels that mean "this record carries real risk". Everything else with a label is
# the harmless class.
POSITIVE_LABELS = frozenset({"malicious", "obviously_malicious", "contextually_risky"})
NEGATIVE_LABELS = frozenset({"benign"})

# HarmfulSkillBench's lock forbids F1 and false-positive-rate claims outright, over
# and above the fact that it has no harmless class.
_F1_FPR_PROHIBITED = frozenset({"harmfulskillbench-corpus"})

# Thresholds for the severity-detection lens. Both tools emit these names with the
# same meaning, which is what makes the lens comparable at all.
DETECTION_THRESHOLDS = ("MEDIUM", "HIGH")


@dataclass(frozen=True)
class PairedRecord:
    """One record with both tools' results, plus its ground-truth label."""

    record_id: str
    label: str | None
    rows: dict[str, ToolRow]

    @property
    def is_positive(self) -> bool:
        return (self.label or "") in POSITIVE_LABELS

    @property
    def is_negative(self) -> bool:
        return (self.label or "") in NEGATIVE_LABELS


def usable(row: ToolRow) -> bool:
    """Whether a row may be scored at all.

    An unusable row is not a negative result.  A crashed scan, an unparsable
    payload and a run with analyzers switched off all present as "no findings", and
    scoring them as clean would award free specificity.
    """

    return row.error is None and row.capability_ok


def pair_rows(per_tool: dict[str, Sequence[ToolRow]]) -> tuple[list[PairedRecord], dict[str, Any]]:
    """Intersect tools on usable records, reporting what the intersection cost."""

    tools = sorted(per_tool)
    by_tool_usable = {tool: {row.record_id: row for row in rows if usable(row)} for tool, rows in per_tool.items()}
    all_ids = {row.record_id for rows in per_tool.values() for row in rows}
    shared = set.intersection(*(set(mapping) for mapping in by_tool_usable.values())) if by_tool_usable else set()

    paired = []
    for record_id in sorted(shared):
        rows = {tool: by_tool_usable[tool][record_id] for tool in tools}
        labels = {row.label for row in rows.values()}
        if len(labels) != 1:
            # Label disagreement means the two runs were not fed the same record.
            raise ValueError(f"{record_id}: tools disagree on the label: {labels}")
        paired.append(PairedRecord(record_id=record_id, label=labels.pop(), rows=rows))

    integrity = {
        "records_seen": len(all_ids),
        "records_scored": len(paired),
        "dropped_not_shared": len(all_ids) - len(shared),
        "per_tool": {
            tool: {
                "rows": len(per_tool[tool]),
                "usable": len(by_tool_usable[tool]),
                "errors": sum(1 for row in per_tool[tool] if row.error),
                "capability_degraded": sum(1 for row in per_tool[tool] if not row.capability_ok),
                "incomplete": sum(1 for row in per_tool[tool] if not row.complete),
            }
            for tool in tools
        },
    }
    return paired, integrity


def _confusion(records: Sequence[PairedRecord], tool: str, predicate: Callable[[ToolRow], bool]) -> dict[str, Any]:
    """Score ``predicate`` as a detector, refusing undefined cells.

    A corpus with no harmless class has no false positives to count, so precision,
    F1 and false-positive rate are omitted rather than reported as figures computed
    against zero negatives.
    """

    tp = fp = fn = tn = 0
    for record in records:
        fired = predicate(record.rows[tool])
        if record.is_positive:
            tp += fired
            fn += not fired
        elif record.is_negative:
            fp += fired
            tn += not fired
        else:
            # Unlabelled records (e.g. HarmfulSkillBench, all positive-risk by
            # construction) are treated as positives by the caller via labels; an
            # unlabelled record here would silently vanish, so surface it.
            tp += fired
            fn += not fired

    has_negatives = (fp + tn) > 0
    if has_negatives:
        result = dict(binary_metrics(tp, fp, fn, tn))
    else:
        recall = safe_divide(tp, tp + fn)
        result = {
            "true_positives": tp,
            "false_negatives": fn,
            "recall": recall,
            "recall_95": list(wilson_interval(tp, tp + fn)),
            "precision": None,
            "f1": None,
            "false_positive_rate": None,
            "undefined_reason": "corpus has no harmless class; precision and FPR are undefined",
        }
    result["has_negative_class"] = has_negatives
    return result


def _apply_licence(corpus: str, block: dict[str, Any]) -> dict[str, Any]:
    """Strip metrics a corpus's licence forbids, leaving a stated reason."""

    if corpus in _F1_FPR_PROHIBITED:
        for key in ("f1", "false_positive_rate", "false_positive_rate_95", "precision"):
            block.pop(key, None)
        block["licence_restriction"] = "dataset lock prohibits F1 and false-positive-rate claims"
    return block


def _detection_predicate(threshold: str) -> Callable[[ToolRow], bool]:
    return lambda row: row.flagged_at(threshold)


def _gate_predicate(row: ToolRow) -> bool:
    return bool(row.gate_blocked)


def _aggressive_gate_predicate(row: ToolRow) -> bool:
    """Block on any finding at all, defined identically for both tools.

    Deliberately computed from the finding count rather than from SkillSpector's
    ``--fail-on-findings`` exit code. That flag was only passed on the static run, so
    trusting the recorded exit code made every LLM-arm row read as "did not block"
    and reported a flat 0.0% recall for a lens where the tool in fact fires on almost
    everything.
    """

    return row.finding_count > 0


def score_corpus(corpus: str, per_tool: dict[str, Sequence[ToolRow]], *, resamples: int) -> dict[str, Any]:
    """Score one corpus under every lens."""

    paired, integrity = pair_rows(per_tool)
    tools = sorted(per_tool)
    label_counts: dict[str, int] = {}
    for record in paired:
        key = record.label or "unlabelled"
        label_counts[key] = label_counts.get(key, 0) + 1

    lenses: dict[str, Any] = {}

    for threshold in DETECTION_THRESHOLDS:
        predicate = _detection_predicate(threshold)
        lenses[f"detection_at_{threshold.lower()}"] = {
            "description": f"any finding at or above {threshold}; the ladders are identical on both sides",
            "per_tool": {tool: _apply_licence(corpus, _confusion(paired, tool, predicate)) for tool in tools},
            "paired_difference": _paired_differences(paired, tools, predicate, resamples=resamples),
        }

    lenses["shipped_gate"] = {
        "description": "each tool's own install decision, read from the field it emits",
        "per_tool": {tool: _apply_licence(corpus, _confusion(paired, tool, _gate_predicate)) for tool in tools},
        "paired_difference": _paired_differences(paired, tools, _gate_predicate, resamples=resamples),
    }
    lenses["aggressive_gate"] = {
        "description": "block on any finding at all; SkillSpector's --fail-on-findings, "
        "and the counterpart to our any-intervention lens",
        "per_tool": {
            tool: _apply_licence(corpus, _confusion(paired, tool, _aggressive_gate_predicate)) for tool in tools
        },
        "paired_difference": _paired_differences(paired, tools, _aggressive_gate_predicate, resamples=resamples),
    }

    return {
        "corpus": corpus,
        "tools": tools,
        "integrity": integrity,
        "label_counts": label_counts,
        "has_negative_class": any(label in NEGATIVE_LABELS for label in label_counts),
        "severity_threshold_sweep": _threshold_sweep(paired, tools, corpus),
        "agreement": _agreement(paired, tools),
        "throughput": {
            tool: {
                "mean_seconds": round(safe_divide(sum(r.rows[tool].duration_seconds for r in paired), len(paired)), 4),
                "total_seconds": round(sum(r.rows[tool].duration_seconds for r in paired), 1),
                "input_tokens": sum(r.rows[tool].input_tokens for r in paired),
                "output_tokens": sum(r.rows[tool].output_tokens for r in paired),
            }
            for tool in tools
        },
        "lenses": lenses,
    }


def _paired_differences(
    records: Sequence[PairedRecord],
    tools: Sequence[str],
    predicate: Callable[[ToolRow], bool],
    *,
    resamples: int,
) -> dict[str, Any]:
    """Bootstrap the recall difference between each tool pair on shared records.

    Recall is used because it is defined on every corpus here, including the
    positive-only ones.  Both arms are resampled together so shared corpus
    difficulty cancels instead of widening both intervals.
    """

    positives = [record for record in records if record.is_positive or not record.is_negative]
    if len(tools) != 2 or not positives:
        return {}

    first, second = tools

    def recall_for(tool: str) -> Callable[[Sequence[PairedRecord]], float]:
        def statistic(sample: Sequence[PairedRecord]) -> float:
            if not sample:
                return 0.0
            return sum(1 for record in sample if predicate(record.rows[tool])) / len(sample)

        return statistic

    result = paired_bootstrap_difference(positives, recall_for(first), recall_for(second), resamples=resamples)
    result["metric"] = "recall"
    result["order"] = f"{first} minus {second}"
    return result


def _threshold_sweep(records: Sequence[PairedRecord], tools: Sequence[str], corpus: str) -> dict[str, Any]:
    """Recall and false-positive rate at every severity threshold, per tool.

    This is the lens immune to the two tools having chosen different default
    aggressiveness: it shows the whole curve rather than one operating point.
    """

    sweep: dict[str, Any] = {}
    for tool in tools:
        points = []
        for threshold in SEVERITY_ORDER[1:]:
            predicate = _detection_predicate(threshold)
            fired_positive = sum(
                1
                for record in records
                if (record.is_positive or not record.is_negative) and predicate(record.rows[tool])
            )
            positives = sum(1 for record in records if record.is_positive or not record.is_negative)
            fired_negative = sum(1 for record in records if record.is_negative and predicate(record.rows[tool]))
            negatives = sum(1 for record in records if record.is_negative)
            point = {
                "threshold": threshold,
                "recall": safe_divide(fired_positive, positives),
                "false_positive_rate": safe_divide(fired_negative, negatives) if negatives else None,
            }
            if corpus in _F1_FPR_PROHIBITED:
                point.pop("false_positive_rate", None)
            points.append(point)
        sweep[tool] = points
    return sweep


def _agreement(records: Sequence[PairedRecord], tools: Sequence[str]) -> dict[str, Any]:
    """How often the tools reach the same conclusion, and where they diverge."""

    if len(tools) != 2:
        return {}
    first, second = tools
    both = only_first = only_second = neither = 0
    for record in records:
        a = record.rows[first].flagged_at("MEDIUM")
        b = record.rows[second].flagged_at("MEDIUM")
        both += a and b
        only_first += a and not b
        only_second += b and not a
        neither += not a and not b

    total = len(records) or 1
    return {
        "threshold": "MEDIUM",
        "both_flagged": both,
        f"only_{first}": only_first,
        f"only_{second}": only_second,
        "neither_flagged": neither,
        "agreement_rate": (both + neither) / total,
        # A record only one tool catches is the interesting population: it is where
        # one engine sees something the other does not.
        "complementarity": (only_first + only_second) / total,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a collected cross-tool comparison.")
    parser.add_argument("--rows-dir", action="append", required=True, help="Repeatable collection directory.")
    parser.add_argument("--arm", default="static")
    parser.add_argument("--resamples", type=int, default=2000)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    by_corpus: dict[str, dict[str, list[ToolRow]]] = {}
    sources = []
    for rows_dir in args.rows_dir:
        directory = Path(rows_dir)
        # ``*`` after the arm so sharded outputs (``...full_llm.shard0of6.jsonl``) are
        # picked up and merged with any unsharded file for the same column.
        for path in sorted(directory.glob(f"*.{args.arm}*.jsonl")):
            rows = read_rows(path)
            if not rows:
                continue
            corpus = rows[0].corpus
            tool = rows[0].tool
            # A profile is a different configuration of the same tool, so it has to
            # be a distinct column or the two would silently overwrite each other.
            arm = rows[0].arm
            column = tool if ":" not in arm else f"{tool}[{arm.split(':', 1)[1]}]"
            existing = by_corpus.setdefault(corpus, {}).setdefault(column, [])
            seen = {row.record_id for row in existing}
            duplicates = [row.record_id for row in rows if row.record_id in seen]
            if duplicates:
                raise ValueError(
                    f"{path}: {len(duplicates)} record ids already present for {column}; shards must be disjoint"
                )
            existing.extend(rows)
            sources.append({"path": str(path), "corpus": corpus, "column": column, "rows": len(rows)})

    report: dict[str, Any] = {
        "track": "cross-tool-comparison",
        "blocking": False,
        "arm": args.arm,
        "sources": sources,
        "corpora": {},
        "complete": True,
    }
    for corpus, per_tool in sorted(by_corpus.items()):
        if len(per_tool) < 2:
            report["corpora"][corpus] = {
                "skipped": "needs at least two columns to compare",
                "columns": sorted(per_tool),
            }
            continue
        report["corpora"][corpus] = score_corpus(corpus, per_tool, resamples=args.resamples)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
