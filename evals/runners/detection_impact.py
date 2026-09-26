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

"""Detection impact: the same records scanned by the base and the head tree, compared.

The pull-request check behind ``.github/workflows/detection-impact.yml``. Both trees scan the same
records with the static arm of ``cross_tool_benchmark.py``; this compares the rows and decides::

    python evals/runners/detection_impact.py --base-rows base/ --head-rows head/ \\
        --report report.json --comment comment.md --base-sha SHA --head-sha SHA

It reports, as aggregates only:

* recall, FPR, precision and F1 on the labelled development split, before and after, each with a
  95% interval, and paired-bootstrap intervals on the differences;
* the flag rate on a fixed real-skill sample -- an upper bound on the false-positive rate, not a
  measure of it;
* for every rule whose output changed, and every new rule: the records it fires on, the records it
  alone lifts to MEDIUM+, and its malicious/benign split;
* how many records moved up or down a severity tier, and scan errors and degraded rows.

It fails on a development-split recall drop or FPR rise beyond the tolerance, on any
capability-degraded row, on a new scan error, and on a hash-bound evidence fixture whose recorded
rule hits the head tree no longer reproduces. Only the corpora registered below are accepted, each
with the metrics its terms allow: the frozen test split is refused outright, because choosing rules
or thresholds on it is exactly what its terms forbid.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.metrics import (  # noqa: E402
    binary_metrics,
    bootstrap_interval,
    f1,
    paired_bootstrap_difference,
    safe_divide,
    wilson_interval,
)

SEVERITY_RANK = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
TIERS = ("NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
MEDIUM = 3
POSITIVE_LABELS = frozenset({"malicious"})
NEGATIVE_LABELS = frozenset({"benign"})

# The only corpora a pull request may score, and what each may report. Anything else is refused
# rather than scored, so a mis-wired job cannot quietly publish a metric a corpus forbids.
CORPORA: Mapping[str, str] = {
    # MaliciousSkillBench train/validation: every split protocol train or validation.
    "msb-trainval": "labelled",
    # A fixed ClawHub sample of real published skills, unlabelled.
    "clawhub-sample": "flag_rate",
}
REFUSED: Mapping[str, str] = {
    "msb-source-disjoint": "the frozen test split is scored only in the release gate, never in a pull request",
    "msb-balanced-800": "overlaps the frozen test split",
    "harmfulskillbench-corpus": "HarmfulSkillBench allows flag rates only and forbids automatic download",
    "notinject": "NotInject is not a package-level benign denominator",
    "openskillrisk-corpus": "OpenSkillRisk forbids automatic download",
}

# Evidence fixtures whose recorded rule hits on the development selection the head tree must
# reproduce. Each binds a rule implementation's hash to what it detected.
EVIDENCE_GLOB = "tests/fixtures/*_msb_non_test_*.json"

_ROWS_SUFFIX = ".skill-scanner.static.jsonl"
# A report is published on a public pull request: no record identifier, path, secret or free text.
_REFUSED_OUTPUT = (
    (re.compile(r"\b[A-Z]{2,6}\d{2}_\d{6}\b"), "a benchmark record identifier"),
    (re.compile(r"\bc_[0-9a-f]{20}\b"), "a sample record identifier"),
    (re.compile(r"/(?:home|Users|runner|tmp|private)/"), "a host path"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"), "a credential"),
    (re.compile(r'"(?:description|title|snippet|evidence|content)"\s*:'), "a free-text field"),
)


@dataclass(frozen=True)
class Tolerance:
    recall_drop: float
    fpr_rise: float
    # A maintainer can accept a deliberate trade -- recall for false positives -- with a PR label.
    # It never waives degraded rows, new scan errors or an evidence mismatch: those are defects.
    accept_metric_changes: bool = False


class DetectionImpactError(RuntimeError):
    """Raised when the comparison cannot be made honestly."""


def load_rows(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row["record_id"] in rows:
            raise DetectionImpactError(f"{path.name}: a record appears twice")
        rows[row["record_id"]] = row
    return rows


def rank(row: Mapping[str, Any]) -> int:
    return SEVERITY_RANK.get(str(row.get("max_severity") or "NONE").upper(), 0)


def degraded(row: Mapping[str, Any]) -> bool:
    """A row an analyzer failed on. It is not a clean result: the FILE_MAGIC_MISMATCH contract bug
    marked the static analyzer failed on 904 records while every row still looked scanned.

    A strict-loader failure the harness recovered from by loading leniently is not degradation --
    every analyzer still ran -- so it is counted separately, as a loader fallback.
    """
    if row.get("capability_ok") is False:
        return True
    return any(
        not isinstance(failure, Mapping) or failure.get("analyzer") != "skill_loader"
        for failure in (row.get("extra") or {}).get("analyzers_failed") or []
    )


def loader_fallback(row: Mapping[str, Any]) -> bool:
    return any(
        isinstance(failure, Mapping) and failure.get("analyzer") == "skill_loader"
        for failure in (row.get("extra") or {}).get("analyzers_failed") or []
    )


def errored(row: Mapping[str, Any]) -> bool:
    return bool(row.get("error"))


def rules_at(row: Mapping[str, Any], threshold: int) -> set[str]:
    return {
        str(f["rule_id"])
        for f in row.get("findings") or []
        if SEVERITY_RANK.get(str(f.get("severity") or "").upper(), 0) >= threshold
    }


def fired(row: Mapping[str, Any]) -> set[str]:
    return {str(f["rule_id"]) for f in row.get("findings") or []}


def _rate(k: int, n: int) -> dict[str, Any]:
    return {"count": k, "of": n, "rate": safe_divide(k, n), "ci95": list(wilson_interval(k, n)) if n else None}


def _class(label: Any) -> bool | None:
    if label in POSITIVE_LABELS:
        return True
    if label in NEGATIVE_LABELS:
        return False
    return None


def _confusion(units: Sequence[tuple[bool, bool, bool]], side: int) -> tuple[int, int, int, int]:
    tp = fp = fn = tn = 0
    for unit in units:
        positive, flagged = unit[0], unit[side]
        if positive:
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
            tn += not flagged
    return tp, fp, fn, tn


def _metric(units: Sequence[tuple[bool, bool, bool]], side: int, name: str) -> float:
    tp, fp, fn, tn = _confusion(units, side)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    return {
        "recall": recall,
        "fpr": safe_divide(fp, fp + tn),
        "precision": precision,
        "f1": f1(precision, recall),
    }[name]


def labelled_comparison(pairs: Sequence[tuple[Any, Mapping, Mapping]], *, resamples: int) -> dict[str, Any]:
    """Recall, FPR, precision and F1 at MEDIUM+ for base and head on the same records."""

    # Only records with a known class; an unlabelled record is never counted as a negative.
    units = [
        (cls, rank(base) >= MEDIUM, rank(head) >= MEDIUM)
        for label, base, head in pairs
        if (cls := _class(label)) is not None
    ]
    if not any(u[0] for u in units) or all(u[0] for u in units):
        raise DetectionImpactError("the labelled split needs both malicious and benign records")
    out: dict[str, Any] = {"records": len(units), "unlabelled_skipped": len(pairs) - len(units)}
    for side, name in ((1, "base"), (2, "head")):
        tp, fp, fn, tn = _confusion(units, side)
        metrics = binary_metrics(tp, fp, fn, tn)
        metrics["precision_95"] = list(wilson_interval(tp, tp + fp)) if tp + fp else None
        f1_interval = bootstrap_interval(units, lambda sample, s=side: _metric(sample, s, "f1"), resamples=resamples)
        metrics["f1_95"] = [f1_interval["low"], f1_interval["high"]]
        out[name] = metrics
    out["delta"] = {
        name: paired_bootstrap_difference(
            units,
            lambda sample, n=name: _metric(sample, 2, n),
            lambda sample, n=name: _metric(sample, 1, n),
            resamples=resamples,
        )
        for name in ("recall", "fpr", "precision", "f1")
    }
    return out


def flag_rate_comparison(pairs: Sequence[tuple[Any, Mapping, Mapping]], *, resamples: int) -> dict[str, Any]:
    units = [(False, rank(base) >= MEDIUM, rank(head) >= MEDIUM) for _, base, head in pairs]
    n = len(units)
    base_k = sum(u[1] for u in units)
    head_k = sum(u[2] for u in units)
    return {
        "records": n,
        "base": _rate(base_k, n),
        "head": _rate(head_k, n),
        "delta": paired_bootstrap_difference(
            units,
            lambda sample: safe_divide(sum(u[2] for u in sample), len(sample)),
            lambda sample: safe_divide(sum(u[1] for u in sample), len(sample)),
            resamples=resamples,
        ),
    }


def tier_moves(pairs: Sequence[tuple[Any, Mapping, Mapping]]) -> dict[str, Any]:
    up = down = 0
    transitions: dict[str, int] = {}
    for _, base, head in pairs:
        before, after = rank(base), rank(head)
        if before == after:
            continue
        up += after > before
        down += after < before
        key = f"{TIERS[before]}->{TIERS[after]}"
        transitions[key] = transitions.get(key, 0) + 1
    return {"up": up, "down": down, "transitions": dict(sorted(transitions.items(), key=lambda kv: (-kv[1], kv[0])))}


def rule_changes(
    pairs: Sequence[tuple[Any, Mapping, Mapping]], *, labelled: bool, limit: int = 25
) -> list[dict[str, Any]]:
    """Per rule: records fired on, records it alone lifts to MEDIUM+, and the class split."""

    stats: dict[str, dict[str, Any]] = {}

    def bump(rule: str, key: str, label: Any) -> None:
        entry = stats.setdefault(
            rule,
            {
                "rule_id": rule,
                "fires_base": 0,
                "fires_head": 0,
                "medium_plus_base": 0,
                "medium_plus_head": 0,
                "sole_driver_head": 0,
                "lifted_head": 0,
                "fires_head_malicious": 0,
                "fires_head_benign": 0,
                "sole_driver_head_malicious": 0,
                "sole_driver_head_benign": 0,
            },
        )
        entry[key] += 1
        if labelled and key in ("fires_head", "sole_driver_head"):
            cls = _class(label)
            if cls is not None:
                entry[f"{key}_{'malicious' if cls else 'benign'}"] += 1

    for label, base, head in pairs:
        for rule in fired(base):
            bump(rule, "fires_base", label)
        for rule in fired(head):
            bump(rule, "fires_head", label)
        for rule in rules_at(base, MEDIUM):
            bump(rule, "medium_plus_base", label)
        head_medium = rules_at(head, MEDIUM)
        for rule in head_medium:
            bump(rule, "medium_plus_head", label)
        if len(head_medium) == 1:
            (rule,) = head_medium
            bump(rule, "sole_driver_head", label)
            if rank(base) < MEDIUM:
                bump(rule, "lifted_head", label)

    changed = []
    for entry in stats.values():
        entry["new_rule"] = entry["fires_base"] == 0 and entry["fires_head"] > 0
        if (
            entry["new_rule"]
            or entry["fires_base"] != entry["fires_head"]
            or (entry["medium_plus_base"] != entry["medium_plus_head"])
        ):
            changed.append(entry)
    changed.sort(key=lambda e: (-abs(e["medium_plus_head"] - e["medium_plus_base"]), e["rule_id"]))
    if not labelled:
        for entry in changed:
            for key in [k for k in entry if k.endswith(("_malicious", "_benign"))]:
                del entry[key]
    return changed[:limit]


def evidence_checks(head_rows: Mapping[str, Mapping[str, Any]], repo: Path) -> list[dict[str, Any]]:
    """Re-verify every hash-bound fixture that records rule hits on the development selection."""

    checks = []
    for fixture in sorted(repo.glob(EVIDENCE_GLOB)):
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        rule = (payload.get("rule") or {}).get("id")
        results = payload.get("package_results") or {}
        selection = str((payload.get("dataset") or payload.get("malicious_skill_bench") or {}).get("selection") or "")
        if (
            not rule
            or "rule_hits_malicious" not in results
            or "train/validation" not in selection.replace("{train,validation}", "train/validation")
        ):
            continue
        observed = {"malicious": 0, "benign": 0}
        for row in head_rows.values():
            if rule in fired(row):
                cls = _class(row.get("label"))
                if cls is not None:
                    observed["malicious" if cls else "benign"] += 1
        expected = {"malicious": int(results["rule_hits_malicious"]), "benign": int(results["rule_hits_benign"])}
        checks.append(
            {
                "fixture": fixture.name,
                "rule_id": rule,
                "implementation_sha256": str((payload.get("rule") or {}).get("implementation_sha256") or "")[:12],
                "expected": expected,
                "observed": observed,
                "matches": observed == expected,
            }
        )
    return checks


def compare(
    base_dir: Path, head_dir: Path, *, tolerance: Tolerance, repo: Path, resamples: int = 1_000
) -> dict[str, Any]:
    corpora = sorted(p.name[: -len(_ROWS_SUFFIX)] for p in head_dir.glob(f"*{_ROWS_SUFFIX}"))
    for name in corpora:
        if name in REFUSED:
            raise DetectionImpactError(f"{name}: {REFUSED[name]}")
        if name not in CORPORA:
            raise DetectionImpactError(f"{name}: not a corpus a pull request may score")
    if "msb-trainval" not in corpora:
        raise DetectionImpactError("the labelled development split is missing: nothing to compare")

    report: dict[str, Any] = {"corpora": {}, "failures": [], "tolerance": vars(tolerance)}
    for name in corpora:
        base_path = base_dir / f"{name}{_ROWS_SUFFIX}"
        if not base_path.is_file():
            raise DetectionImpactError(f"{name}: the base scan is missing")
        base, head = load_rows(base_path), load_rows(head_dir / f"{name}{_ROWS_SUFFIX}")
        if set(base) != set(head):
            raise DetectionImpactError(f"{name}: base and head scanned different records")
        health = {
            "records": len(head),
            "base_errors": sum(errored(r) for r in base.values()),
            "head_errors": sum(errored(r) for r in head.values()),
            "base_degraded": sum(degraded(r) for r in base.values()),
            "head_degraded": sum(degraded(r) for r in head.values()),
            "head_loader_fallbacks": sum(loader_fallback(r) for r in head.values()),
        }
        # The same records on both sides; a record either tree could not read is left out of both.
        pairs = [
            (head[i].get("label"), base[i], head[i])
            for i in sorted(head)
            if not (errored(base[i]) or errored(head[i]) or degraded(base[i]) or degraded(head[i]))
        ]
        block: dict[str, Any] = {"role": CORPORA[name], "health": health, "compared": len(pairs)}
        if CORPORA[name] == "labelled":
            block["metrics"] = labelled_comparison(pairs, resamples=resamples)
        else:
            block["flag_rate"] = flag_rate_comparison(pairs, resamples=resamples)
        block["tiers"] = tier_moves(pairs)
        block["rules"] = rule_changes(pairs, labelled=CORPORA[name] == "labelled")
        report["corpora"][name] = block

        if health["head_degraded"]:
            report["failures"].append(f"{name}: {health['head_degraded']} capability-degraded rows on the head tree")
        if health["head_errors"] > health["base_errors"]:
            report["failures"].append(
                f"{name}: scan errors rose from {health['base_errors']} to {health['head_errors']}"
            )
        if name == "msb-trainval":
            metrics = block["metrics"]
            recall_drop = metrics["base"]["recall"] - metrics["head"]["recall"]
            fpr_rise = metrics["head"]["false_positive_rate"] - metrics["base"]["false_positive_rate"]
            metric_failures = []
            if recall_drop > tolerance.recall_drop:
                metric_failures.append(
                    f"{name}: recall fell {recall_drop * 100:.2f} points (tolerance {tolerance.recall_drop * 100:.2f})"
                )
            if fpr_rise > tolerance.fpr_rise:
                metric_failures.append(
                    f"{name}: FPR rose {fpr_rise * 100:.2f} points (tolerance {tolerance.fpr_rise * 100:.2f})"
                )
            if tolerance.accept_metric_changes:
                report["accepted"] = metric_failures
            else:
                report["failures"].extend(metric_failures)
            report["evidence_checks"] = evidence_checks(head, repo)
            for check in report["evidence_checks"]:
                if not check["matches"]:
                    report["failures"].append(
                        f"{check['rule_id']}: head hits {check['observed']} differ from the hash-bound evidence "
                        f"{check['expected']} in {check['fixture']}; re-verify and rebind it"
                    )
    report["passed"] = not report["failures"]
    return report


def _pct(value: Any, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value * 100:.{digits}f}%"


def _interval(bounds: Any, digits: int = 1) -> str:
    if not bounds or bounds[0] is None:
        return ""
    return f" ({bounds[0] * 100:.{digits}f}–{bounds[1] * 100:.{digits}f})"


def _delta(d: Mapping[str, Any]) -> str:
    return f"{d['difference'] * 100:+.2f} pts [{d['low'] * 100:+.2f}, {d['high'] * 100:+.2f}]" + (
        " *" if d.get("excludes_zero") else ""
    )


def render_comment(report: Mapping[str, Any], *, base_sha: str, head_sha: str) -> str:
    lines = ["<!-- detection-impact -->", "## Detection impact", ""]
    lines.append(
        ("**Passed.**" if report["passed"] else "**Failed:** " + "; ".join(report["failures"]))
        + f" Base `{base_sha[:10]}` → head `{head_sha[:10]}`, static arm, core pack, MEDIUM+."
    )
    if report.get("accepted"):
        lines += ["", "Accepted with the `detection-impact-accepted` label: " + "; ".join(report["accepted"])]
    lines.append("")
    dev = report["corpora"].get("msb-trainval")
    if dev:
        m = dev["metrics"]
        lines += [
            f"**Development split** — MaliciousSkillBench train/validation, {dev['compared']:,} records "
            "(the frozen test split is scored only at release)",
            "",
            "| Metric | Base | Head | Change (paired 95% interval) |",
            "|---|---|---|---|",
        ]
        for label, key, interval_key, delta_key in (
            ("Recall", "recall", "recall_95", "recall"),
            ("FPR", "false_positive_rate", "false_positive_rate_95", "fpr"),
            ("Precision", "precision", "precision_95", "precision"),
            ("F1", "f1", "f1_95", "f1"),
        ):
            lines.append(
                f"| {label} | {_pct(m['base'][key])}{_interval(m['base'].get(interval_key))} | "
                f"{_pct(m['head'][key])}{_interval(m['head'].get(interval_key))} | {_delta(m['delta'][delta_key])} |"
            )
        lines.append("")
    real = report["corpora"].get("clawhub-sample")
    if real:
        fr = real["flag_rate"]
        lines += [
            f"**Real skills** — fixed ClawHub sample, {real['compared']:,} skills. A flag rate bounds the "
            "false-positive rate from above; it is not one.",
            "",
            f"Flag rate {_pct(fr['base']['rate'])} → {_pct(fr['head']['rate'])} ({_delta(fr['delta'])}).",
            "",
        ]
    lines += [
        "**Tier movement and scan health**",
        "",
        "| Corpus | Up | Down | Errors (base → head) | Degraded (head) | Lenient-loader fallbacks (head) |",
        "|---|---|---|---|---|---|",
    ]
    for name, block in report["corpora"].items():
        h = block["health"]
        lines.append(
            f"| {name} | {block['tiers']['up']:,} | {block['tiers']['down']:,} | "
            f"{h['base_errors']} → {h['head_errors']} | {h['head_degraded']} | {h['head_loader_fallbacks']} |"
        )
    lines.append("")
    changed = [(name, rule) for name, block in report["corpora"].items() for rule in block["rules"]]
    if changed:
        lines += [
            "**Rules whose output changed**",
            "",
            "| Corpus | Rule | Fires (base → head) | MEDIUM+ (base → head) | Sole MEDIUM+ driver | Lifted to MEDIUM+ | "
            "Malicious / benign fires |",
            "|---|---|---|---|---|---|---|",
        ]
        for name, rule in changed[:30]:
            split = (
                f"{rule['fires_head_malicious']:,} / {rule['fires_head_benign']:,}"
                if "fires_head_malicious" in rule
                else "unlabelled"
            )
            lines.append(
                f"| {name} | `{rule['rule_id']}`{' (new)' if rule['new_rule'] else ''} | "
                f"{rule['fires_base']:,} → {rule['fires_head']:,} | {rule['medium_plus_base']:,} → "
                f"{rule['medium_plus_head']:,} | {rule['sole_driver_head']:,} | {rule['lifted_head']:,} | {split} |"
            )
        lines.append("")
    else:
        lines += ["No rule's output changed on these records.", ""]
    evidence = report.get("evidence_checks") or []
    if evidence:
        lines += ["**Hash-bound evidence, re-verified on the development split**", ""]
        for check in evidence:
            lines.append(
                f"- `{check['rule_id']}` (implementation `{check['implementation_sha256']}`): "
                f"{check['observed']['malicious']} malicious / {check['observed']['benign']} benign hits, "
                f"evidence records {check['expected']['malicious']} / {check['expected']['benign']} — "
                + ("matches" if check["matches"] else "**differs**")
            )
        lines.append("")
    lines.append(
        "<sub>Aggregates only: no record identifier, skill text or finding text is published. "
        "* marks a difference whose interval excludes zero.</sub>"
    )
    return "\n".join(lines) + "\n"


def refuse_leaks(text: str) -> None:
    for pattern, what in _REFUSED_OUTPUT:
        match = pattern.search(text)
        if match:
            raise DetectionImpactError(f"refusing to publish {what}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-rows", type=Path, required=True)
    parser.add_argument("--head-rows", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--comment", type=Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--recall-tolerance", type=float, default=0.005, help="largest allowed recall drop")
    parser.add_argument("--fpr-tolerance", type=float, default=0.005, help="largest allowed FPR rise")
    parser.add_argument(
        "--accept-metric-changes",
        action="store_true",
        help="report, but do not fail on, a recall or FPR change beyond tolerance (the PR carries the label)",
    )
    parser.add_argument("--resamples", type=int, default=1_000)
    parser.add_argument("--repo", type=Path, default=_REPO_ROOT, help="the head checkout, for its evidence fixtures")
    args = parser.parse_args(argv)

    try:
        report = compare(
            args.base_rows,
            args.head_rows,
            tolerance=Tolerance(
                recall_drop=args.recall_tolerance,
                fpr_rise=args.fpr_tolerance,
                accept_metric_changes=args.accept_metric_changes,
            ),
            repo=args.repo,
            resamples=args.resamples,
        )
        comment = render_comment(report, base_sha=args.base_sha, head_sha=args.head_sha)
        report_text = json.dumps(report, indent=1, sort_keys=True, default=str)
        refuse_leaks(comment)
        refuse_leaks(report_text)
    except DetectionImpactError as exc:
        print(f"detection impact: {exc}", file=sys.stderr)
        return 2
    args.report.write_text(report_text, encoding="utf-8")
    args.comment.write_text(comment, encoding="utf-8")
    digest = hashlib.sha256(comment.encode("utf-8")).hexdigest()[:12]
    print(f"detection impact: {'passed' if report['passed'] else 'failed'} (comment {digest})")
    for failure in report["failures"]:
        print(f"::error::{failure}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
