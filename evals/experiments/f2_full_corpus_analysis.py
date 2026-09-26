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

"""F2: the full-corpus analysis over the store F1 builds. Writes one JSON report.

    python evals/experiments/f2_full_corpus_analysis.py --store STORE --output report.json \\
        --runs static-base,static-tuned,static-head

Every figure is computed from stored rows:

* tier rates for each deterministic run, the records each change moved, and the overall move
  from the first run to the last;
* per analyzer and per rule, the records a rule alone drives to MEDIUM+ ("sole driver") and the
  share the judge clears -- what a suppression would buy, which raw frequency does not say;
* the judge at full coverage: tiers, failures, package verdicts, and its agreement with each
  deterministic run;
* OpenJev: its ranking of the judge's flags and the cascade sweep, at the threshold selected on
  MaliciousSkillBench train/validation (``c4_openjev_screen.py``);
* the policy presets, exact rather than simulated, because a preset only lowers the severity of
  the rules it lists.

gitskills is unlabelled, so a flag rate bounds the false-positive rate from above rather than
measuring it, and the judge is not ground truth: on the labelled split its own false-positive
rate is about 18% and its recall about 53%, so "the judge clears it" is evidence, not proof.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_ID = re.compile(r"[A-Za-z0-9_.-]+")
# Selected on train/validation for the shipped judge prompt, the prompt the full corpus was
# judged with: keep at least 97% of the judge's recall at the lowest false-positive rate.
DEFAULT_CASCADE_THRESHOLD = 0.0609
# The same rule for the new judge prompt.
NEW_PROMPT_THRESHOLD = 0.0484
DEFAULT_SWEEP = (0.005, 0.01, 0.02, 0.035, NEW_PROMPT_THRESHOLD, DEFAULT_CASCADE_THRESHOLD, 0.1, 0.2, 0.35, 0.5)
PRESET_FILES = (("low-noise", "low_noise_policy.yaml"), ("quiet", "quiet_policy.yaml"))


def wilson(k: int, n: int, z: float = 1.96) -> list[float | None]:
    if not n:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [(c - m) / d, (c + m) / d]


def rate(k: int, n: int) -> dict[str, Any]:
    return {"count": k, "of": n, "rate": k / n if n else None, "ci95": wilson(k, n)}


def run_id(value: str) -> str:
    """A run id is interpolated into SQL, so it must be a plain identifier."""
    if not _RUN_ID.fullmatch(value):
        raise SystemExit(f"not a run id: {value!r}")
    return value


def literal(path: Path) -> str:
    """A path as a SQL string literal."""
    return "'" + str(path).replace("'", "''") + "'"


class Analysis:
    def __init__(self, store: Path, *, judge_run: str, threads: int) -> None:
        import duckdb

        self.con = duckdb.connect()
        self.con.execute(f"SET threads TO {int(threads)}")
        self.con.execute(
            f"CREATE VIEW s AS SELECT * FROM read_parquet({literal(store / 'scans' / '**' / '*.parquet')}, "
            "hive_partitioning=true)"
        )
        self.con.execute(
            f"CREATE VIEW f AS SELECT * FROM read_parquet({literal(store / 'findings' / '**' / '*.parquet')}, "
            "hive_partitioning=true)"
        )
        try:
            self.con.execute(f"CREATE VIEW j AS SELECT * FROM read_parquet({literal(store / 'jev' / '*.parquet')})")
        except duckdb.Error:  # no OpenJev rows: the deterministic and judge sections still stand
            self.con.execute(
                "CREATE TABLE j (record_id VARCHAR, errors BIGINT, truncated BOOLEAN, chars BIGINT, "
                "p_prompt_injection DOUBLE)"
            )
        # A row the analyzer could not read is excluded, never counted as a clean record.
        self.con.execute("CREATE VIEW ok AS SELECT * FROM s WHERE error IS NULL AND coalesce(capability_ok, true)")
        self.con.execute(
            "CREATE TABLE judged AS SELECT record_id, max_severity_rank >= 3 AS jflag, max_severity_rank AS jrank "
            f"FROM s WHERE run_id='{judge_run}' AND error IS NULL AND capability_ok"
        )
        self.judge_run = judge_run

    def q(self, sql: str) -> list[tuple[Any, ...]]:
        return self.con.execute(sql).fetchall()

    def deterministic(self, runs: Sequence[str]) -> dict[str, Any]:
        det: dict[str, Any] = {}
        for run in runs:
            n = self.q(f"SELECT count(*) FROM ok WHERE run_id='{run}'")[0][0]
            errors = self.q(f"SELECT count(*) FROM s WHERE run_id='{run}' AND error IS NOT NULL")[0][0]
            tiers = {}
            for label, t in (("CRITICAL", 5), ("HIGH+", 4), ("MEDIUM+", 3), ("LOW+", 2), ("INFO+", 1)):
                tiers[label] = rate(
                    self.q(f"SELECT count(*) FROM ok WHERE run_id='{run}' AND max_severity_rank>={t}")[0][0], n
                )
            det[run] = {"records": n, "errors": errors, "tiers": tiers}
        steps = []
        for a, b in zip(runs, runs[1:]):
            down, up = self.q(
                f"""SELECT count(*) FILTER (WHERE y.max_severity_rank < x.max_severity_rank),
                           count(*) FILTER (WHERE y.max_severity_rank > x.max_severity_rank)
                    FROM ok x JOIN ok y USING (record_id) WHERE x.run_id='{a}' AND y.run_id='{b}'"""
            )[0]
            unflag, newflag = self._moved(a, b)
            steps.append(
                {
                    "from": a,
                    "to": b,
                    "records_moved_down": down,
                    "records_moved_up": up,
                    "medium_plus_cleared": unflag,
                    "medium_plus_added": newflag,
                    "medium_plus_rate_delta": det[b]["tiers"]["MEDIUM+"]["rate"] - det[a]["tiers"]["MEDIUM+"]["rate"],
                }
            )
        det["waterfall"] = steps
        unflag, newflag = self._moved(runs[0], runs[-1])
        det["overall"] = {"from": runs[0], "to": runs[-1], "medium_plus_cleared": unflag, "medium_plus_added": newflag}
        b0, b1 = det[runs[0]]["tiers"]["MEDIUM+"]["rate"], det[runs[-1]]["tiers"]["MEDIUM+"]["rate"]
        det["medium_plus_relative_reduction"] = (b0 - b1) / b0 if b0 else None
        return det

    def _moved(self, a: str, b: str) -> tuple[int, int]:
        unflag, newflag = self.q(
            f"""SELECT count(*) FILTER (WHERE x.max_severity_rank>=3 AND y.max_severity_rank<3),
                       count(*) FILTER (WHERE x.max_severity_rank<3 AND y.max_severity_rank>=3)
                FROM ok x JOIN ok y USING (record_id) WHERE x.run_id='{a}' AND y.run_id='{b}'"""
        )[0]
        return unflag, newflag

    def by_analyzer(self, run: str, n: int) -> list[dict[str, Any]]:
        return [
            {"analyzer": a, "medium_plus_records": r, "rate": r / n, "findings": c}
            for a, r, c in self.q(
                f"""SELECT analyzer, count(DISTINCT record_id), count(*) FROM f
                    WHERE run_id='{run}' AND severity_rank>=3 GROUP BY 1 ORDER BY 2 DESC, 1"""
            )
        ]

    def by_rule(self, run: str, n: int) -> list[dict[str, Any]]:
        # Sole driver: the record reaches MEDIUM+ through this rule alone, so removing or
        # demoting the rule would clear it. This, not raw frequency, is what a suppression buys.
        self.con.execute(
            f"""CREATE OR REPLACE TABLE rr AS
                SELECT record_id, analyzer, rule_id, max(severity_rank) AS rk FROM f
                WHERE run_id='{run}' AND severity_rank>=3 GROUP BY 1,2,3"""
        )
        self.con.execute("CREATE OR REPLACE TABLE nrules AS SELECT record_id, count(*) AS k FROM rr GROUP BY 1")
        rules = self.q(
            """SELECT rr.analyzer, rr.rule_id, count(*) AS recs,
                      count(*) FILTER (WHERE nrules.k=1) AS sole,
                      count(*) FILTER (WHERE rr.rk>=4) AS high_plus,
                      count(judged.record_id) AS judged,
                      count(*) FILTER (WHERE judged.jflag) AS agree,
                      count(*) FILTER (WHERE nrules.k=1 AND judged.record_id IS NOT NULL AND NOT judged.jflag) AS sole_cleared,
                      count(*) FILTER (WHERE nrules.k=1 AND judged.record_id IS NOT NULL) AS sole_judged
               FROM rr JOIN nrules USING (record_id) LEFT JOIN judged USING (record_id)
               GROUP BY 1,2 ORDER BY recs DESC, 1, 2"""
        )
        return [
            {
                "analyzer": a,
                "rule_id": r,
                "medium_plus_records": recs,
                "rate": recs / n,
                "high_plus_records": hp,
                "sole_driver_records": sole,
                "judged": jd,
                "judge_clears": (1 - g / jd) if jd else None,
                "judge_clears_ci95": wilson(jd - g, jd),
                "sole_driver_judge_clears": (sc / sj) if sj else None,
                # Records that would clear if the rule went AND the judge agrees they are benign:
                # the best available estimate of the false positives a change to this rule removes.
                "est_removable_false_positives": round(sole * (sc / sj)) if sj else None,
            }
            for a, r, recs, sole, hp, jd, g, sc, sj in rules
        ]

    def judge(self, store: Path) -> dict[str, Any]:
        jr = self.judge_run
        jok = self.q("SELECT count(*) FROM judged")[0][0]
        full_cov = self.q(
            f"""SELECT count(*), count(*) FILTER (WHERE max_severity_rank>=3) FROM s
                WHERE run_id='{jr}' AND error IS NULL AND capability_ok AND coalesce(complete, true)"""
        )[0]
        report: dict[str, Any] = {
            "rows": self.q(f"SELECT count(*) FROM s WHERE run_id='{jr}'")[0][0],
            "genuine": jok,
            "partial_coverage": self.q(
                f"SELECT count(*) FROM s WHERE run_id='{jr}' AND error IS NULL AND capability_ok AND complete = false"
            )[0][0],
            "medium_plus_full_coverage_only": rate(full_cov[1], full_cov[0]),
            "failed": self.q(f"SELECT count(*) FROM s WHERE run_id='{jr}' AND NOT (error IS NULL AND capability_ok)")[
                0
            ][0],
            # Grouped by kind: an error message ends with the record's path, which is not a kind.
            "failure_kinds": self.q(
                f"""SELECT coalesce(gate_detail, regexp_replace(error, ':\\s*/\\S*$', ''), 'capability') AS k, count(*)
                    FROM s WHERE run_id='{jr}' AND NOT (error IS NULL AND capability_ok)
                    GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10"""
            ),
            "tiers": {
                label: rate(self.q(f"SELECT count(*) FROM judged WHERE jrank>={t}")[0][0], jok)
                for label, t in (("CRITICAL", 5), ("HIGH+", 4), ("MEDIUM+", 3), ("LOW+", 2))
            },
            "tokens": dict(
                zip(
                    ("input", "output"),
                    self.q(f"SELECT sum(input_tokens), sum(output_tokens) FROM s WHERE run_id='{jr}'")[0],
                )
            ),
            "top_rules": self.q(
                f"""SELECT rule_id, count(DISTINCT record_id) FROM f WHERE run_id='{jr}' AND severity_rank>=3
                    GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 20"""
            ),
        }
        cells_path = store / "judge_verdicts.json"
        if cells_path.exists():
            report["verdicts"] = verdict_summary(json.loads(cells_path.read_text()))
        return report

    def agreement(self, run: str) -> dict[str, Any]:
        tt, tf, ft, ff = self.q(
            f"""SELECT count(*) FILTER (WHERE d.max_severity_rank>=3 AND judged.jflag),
                       count(*) FILTER (WHERE d.max_severity_rank>=3 AND NOT judged.jflag),
                       count(*) FILTER (WHERE d.max_severity_rank<3 AND judged.jflag),
                       count(*) FILTER (WHERE d.max_severity_rank<3 AND NOT judged.jflag)
                FROM ok d JOIN judged USING (record_id) WHERE d.run_id='{run}'"""
        )[0]
        n = tt + tf + ft + ff
        po = (tt + ff) / n
        pe = ((tt + tf) * (tt + ft) + (ft + ff) * (tf + ff)) / (n * n)
        return {
            "both": tt,
            "det_only": tf,
            "judge_only": ft,
            "neither": ff,
            "records": n,
            "det_flags_judge_agrees": rate(tt, tt + tf),
            "judge_flags_det_agrees": rate(tt, tt + ft),
            "cohen_kappa": (po - pe) / (1 - pe) if pe < 1 else None,
            "either_flag_rate": (tt + tf + ft) / n,
        }

    def jev(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "rows": self.q("SELECT count(*) FROM j")[0][0],
            "genuine": self.q("SELECT count(*) FROM j WHERE errors=0 AND p_prompt_injection IS NOT NULL")[0][0],
            "truncated": self.q("SELECT count(*) FROM j WHERE truncated")[0][0],
            "quantiles": dict(
                zip(
                    ("p10", "p25", "p50", "p75", "p90", "p99"),
                    self.q(
                        "SELECT quantile_cont(p_prompt_injection, [0.1,0.25,0.5,0.75,0.9,0.99]) FROM j WHERE errors=0"
                    )[0][0]
                    or (),
                )
            ),
        }
        pairs = self.q(
            """SELECT j.p_prompt_injection, judged.jflag FROM j JOIN judged USING (record_id)
               WHERE j.errors=0 AND j.p_prompt_injection IS NOT NULL"""
        )
        if pairs:
            report["auc_vs_judge_flag"] = rank_auc(pairs)
            report["paired_with_judge"] = len(pairs)
        return report

    def sweep(self, thresholds: Sequence[float]) -> list[dict[str, Any]]:
        out = []
        for t in thresholds:
            n, calls, jflag, kept = self.q(
                f"""SELECT count(*), count(*) FILTER (WHERE j.p_prompt_injection >= {float(t)}),
                           count(*) FILTER (WHERE judged.jflag),
                           count(*) FILTER (WHERE judged.jflag AND j.p_prompt_injection >= {float(t)})
                    FROM j JOIN judged USING (record_id) WHERE j.errors=0 AND j.p_prompt_injection IS NOT NULL"""
            )[0]
            out.append(
                {
                    "threshold": t,
                    "records": n,
                    "judge_calls": calls / n if n else None,
                    "judge_flag_rate": jflag / n if n else None,
                    "cascade_flag_rate": kept / n if n else None,
                    "judge_flags_retained": kept / jflag if jflag else None,
                    "cascade_flag_rate_ci95": wilson(kept, n),
                }
            )
        return out

    def combined(self, run: str, threshold: float) -> dict[str, Any]:
        """The posture after tuning: deterministic flags, plus the judge only where OpenJev screens in."""
        n, detf, casc, union = self.q(
            f"""SELECT count(*), count(*) FILTER (WHERE d.max_severity_rank>=3),
                   count(*) FILTER (WHERE judged.jflag AND j.p_prompt_injection >= {float(threshold)}),
                   count(*) FILTER (WHERE d.max_severity_rank>=3 OR (judged.jflag AND j.p_prompt_injection >= {float(threshold)}))
                FROM ok d JOIN judged USING (record_id) JOIN j USING (record_id)
                WHERE d.run_id='{run}' AND j.errors=0 AND j.p_prompt_injection IS NOT NULL"""
        )[0]
        return {
            "records": n,
            "deterministic": rate(detf, n),
            "cascade": rate(casc, n),
            "deterministic_or_cascade": rate(union, n),
        }

    def packs(self, run: str, n: int, pack_dir: Path) -> dict[str, Any]:
        """Preset flag rates, exact from the findings: a preset only demotes the rules it lists."""
        import yaml

        packs: dict[str, set[str]] = {"balanced": set()}
        for name, filename in PRESET_FILES:
            overrides = yaml.safe_load((pack_dir / filename).read_text()).get("severity_overrides") or []
            packs[name] = {o["rule_id"] for o in overrides if o.get("severity") in ("INFO", "LOW")}
        out = {}
        for name, demoted in packs.items():
            excluded = ",".join("'" + rule.replace("'", "''") + "'" for rule in sorted(demoted)) or "''"
            k = self.q(
                f"""SELECT count(DISTINCT f.record_id) FROM f JOIN ok USING (record_id, run_id)
                    WHERE f.run_id='{run}' AND f.severity_rank>=3 AND f.rule_id NOT IN ({excluded})"""
            )[0][0]
            out[name] = {"rules_demoted": sorted(demoted), "medium_plus": rate(k, n)}
        return out


def rank_auc(pairs: Sequence[tuple[float, bool]]) -> float | None:
    """Mann-Whitney AUC of the score against the judge's flag, ties given their average rank."""
    try:
        from scipy.stats import rankdata

        ranks = list(rankdata([p for p, _ in pairs]))
    except ImportError:  # ties then break arbitrarily; the AUC is approximate
        order = sorted(range(len(pairs)), key=lambda i: pairs[i][0])
        ranks = [0.0] * len(pairs)
        for position, index in enumerate(order, 1):
            ranks[index] = position
    n1 = sum(1 for _, y in pairs if y)
    n0 = len(pairs) - n1
    s1 = sum(r for r, (_, y) in zip(ranks, pairs) if y)
    return (s1 - n1 * (n1 + 1) / 2) / (n1 * n0) if n1 and n0 else None


def verdict_summary(cells: dict[str, int]) -> dict[str, Any]:
    total = sum(cells.values())
    by_verdict: dict[str, int] = {}
    crosstab: dict[str, dict[str, int]] = {}
    for key, n in cells.items():
        verdict, severity = key.split("|")
        by_verdict[verdict] = by_verdict.get(verdict, 0) + n
        crosstab.setdefault(verdict, {})[severity] = n

    def flagged(verdict: str) -> int:
        return sum(n for sev, n in crosstab.get(verdict, {}).items() if sev in ("MEDIUM", "HIGH", "CRITICAL"))

    return {
        "counts": by_verdict,
        "rates": {v: n / total for v, n in by_verdict.items()},
        "crosstab": crosstab,
        # A SAFE verdict carrying a MEDIUM+ finding, and a non-SAFE verdict with none, are the two
        # ways the verdict and the findings disagree.
        "safe_with_medium_plus_finding": flagged("SAFE"),
        "unsafe_without_medium_plus_finding": sum(
            by_verdict.get(v, 0) - flagged(v) for v in ("SUSPICIOUS", "MALICIOUS")
        ),
        "non_safe_rate": rate(by_verdict.get("SUSPICIOUS", 0) + by_verdict.get("MALICIOUS", 0), total),
    }


def analyse(args: argparse.Namespace) -> dict[str, Any]:
    store = args.store.expanduser()
    runs = [run_id(r) for r in args.runs.split(",")]
    final_run = runs[-1]
    analysis = Analysis(store, judge_run=run_id(args.judge_run), threads=args.threads)
    report: dict[str, Any] = {
        "experiment": "full-corpus-analysis",
        "store": store.name,
        "blocking": False,
        "caveat": "gitskills is unlabelled: flag rates bound FPR from above; the judge is not ground truth.",
    }
    det = analysis.deterministic(runs)
    report["deterministic"] = det
    report["by_analyzer"] = {run: analysis.by_analyzer(run, det[run]["records"]) for run in runs}
    report["by_rule"] = {run: analysis.by_rule(run, det[run]["records"]) for run in runs}
    report["judge"] = analysis.judge(store)
    report["agreement"] = {run: analysis.agreement(run) for run in runs}
    report["jev"] = analysis.jev()
    thresholds = sorted(set(DEFAULT_SWEEP) | {args.cascade_threshold})
    sweep = analysis.sweep(thresholds)
    report["cascade"] = {
        "threshold": args.cascade_threshold,
        "sweep": sweep,
        "at_threshold": next(x for x in sweep if x["threshold"] == args.cascade_threshold),
    }
    report["combined"] = analysis.combined(final_run, args.cascade_threshold)
    report["next_candidates"] = sorted(
        (
            r
            for r in report["by_rule"][final_run]
            if r["medium_plus_records"] >= 200
            and (r["judge_clears"] or 0) >= 0.6
            and r["est_removable_false_positives"]
        ),
        key=lambda r: (-r["est_removable_false_positives"], r["rule_id"]),
    )[:15]
    if not args.no_packs:
        report["packs"] = analysis.packs(final_run, det[final_run]["records"], args.pack_dir.expanduser())
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", default="static-base,static-tuned,static-head", help="deterministic runs, in order")
    parser.add_argument("--judge-run", default="judge-full")
    parser.add_argument("--cascade-threshold", type=float, default=DEFAULT_CASCADE_THRESHOLD)
    parser.add_argument("--pack-dir", type=Path, default=_REPO_ROOT / "skill_scanner" / "data")
    parser.add_argument("--no-packs", action="store_true")
    parser.add_argument("--threads", type=int, default=16)
    args = parser.parse_args(argv)

    report = analyse(args)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    det = report["deterministic"]
    for run in args.runs.split(","):
        t = det[run]["tiers"]["MEDIUM+"]
        print(
            f"  {run:24s} MEDIUM+ {t['rate']:.3%} [{t['ci95'][0]:.3%}, {t['ci95'][1]:.3%}]  n={det[run]['records']:,}"
        )
    print(f"  judge MEDIUM+ {report['judge']['tiers']['MEDIUM+']['rate']:.3%}")
    print(f"  cascade at {args.cascade_threshold}: {report['cascade']['at_threshold']['cascade_flag_rate']:.3%}")
    for name, pack in (report.get("packs") or {}).items():
        print(f"  preset {name:10s} MEDIUM+ {pack['medium_plus']['rate']:.3%}")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
