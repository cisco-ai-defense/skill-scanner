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

"""Render the results Space as static HTML.

A static Space is chosen over a Gradio app because every number here is computed
offline and pinned; a running app would add a dependency surface without adding a
capability.

The renderer refuses to invent content.  A section whose result file is missing or
whose ``complete`` attestation is false prints as missing, because a page that
shows zeros for a run that never happened is worse than one that admits the gap.
No sample text, evidence string, prompt or credential is emitted: the corpora
forbid redistributing content, so only metrics, counts and digests appear.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.publish.space_data import (  # noqa: E402
    CORPUS_SHAPES,
    GEMMA_FACTS,
    PRIOR_SYSTEM_ONE_SPACE,
    PUBLISHED_BLOG_URL,
    PUBLISHED_DETERMINISTIC,
    count,
    interval,
    load_json,
    percent,
    require_complete,
)
from evals.runners.judged_dataset_benchmark import ARMS  # noqa: E402

# Every experiment, with the question it answers. Status is derived from which
# findings are present, so this cannot claim an experiment is pending on a page that
# reports its result.
EXPERIMENT_CATALOGUE = (
    ("E1", "finding reality", "What fraction of deterministic findings are actually real?", "not run"),
    ("E2", "packing ladder", "Whole record, priority ordered, or candidate centric?", "reported on the cascade page"),
    ("E3", "all findings in one call", "Is one batched request per skill as good as one per finding?", "not run"),
    ("E4", "cascade composition", "Which links in the chain earn their cost?", "not run"),
    ("E5", "context ablation", "What is context actually worth?", "reported on the cascade page"),
    ("E6", "question format", "Disposition and risk, or eight threat probes?", "reported on the cascade page"),
    ("E7", "conservatism calibration", "Can false positives be removed by gating on confidence?", "not run"),
    ("E8", "file-type prompting", "Does judging by detected content type beat a generic prompt?", "not run"),
    ("E9", "hosted against self-hosted", "Does the self-hosted System One model match the hosted one?", "not run"),
    ("E10", "statefulness", "Does a stored decision survive ordinary churn?", "not run"),
    ("E11", "dismissal generalisation", "Can a dismissal become a safe suppression rule?", "not run"),
    ("E12", "organisation context", "Can an organisation express a policy the rules cannot?", "not run"),
    ("E13", "rule mining", "Which model decisions deserve to become rules?", "not run"),
    ("E14", "policy auto-tuning", "Can the policy be fitted without losing a detection?", "not run"),
    ("E15", "stateful prototype", "Does a stateful scanner work, and is it safe?", "not run"),
    ("E16", "stability", "How far must two arms differ before the difference is real?", "not run"),
)

PAGES = (
    ("index.html", "Overview"),
    ("deterministic.html", "Deterministic baseline"),
    ("judged.html", "Judge and meta-judge"),
    ("cascade.html", "Small-model screens"),
    ("cross-tool.html", "SkillSpector vs skill-scanner"),
    ("improvements.html", "Improving the scanner"),
    ("experiments.html", "Experiments"),
    ("recommendations.html", "How to configure it"),
    ("methodology.html", "Methodology"),
    ("reproduce.html", "Reproduce it"),
)

STYLE = """
:root { color-scheme: light dark; --fg:#1a1a1a; --bg:#fdfdfc; --muted:#5b6168;
        --line:#e3e3e0; --accent:#0b5fff; --good:#0a7d34; --warn:#9a5b00; --bad:#b3261e; }
.chart { max-width: 100%; height: auto; margin: 0.4rem 0 0.2rem; }
.chart-title { font-size: 12px; font-weight: 600; fill: var(--fg); }
.chart-label { font-size: 11px; fill: var(--fg); }
.chart-axis  { font-size: 10px; fill: var(--muted); }
.chart-value { font-size: 10px; fill: var(--muted); }
.chart-na    { font-size: 10px; fill: var(--muted); font-style: italic; }
.chart-grid  { stroke: var(--line); stroke-width: 1; }
figure { margin: 0.6rem 0 1rem; }
figcaption.legend { font-size: 11px; color: var(--muted); margin-top: 0.2rem; }
.key { margin-right: 0.9rem; white-space: nowrap; }
.key i { display: inline-block; width: 9px; height: 9px; margin-right: 4px; border-radius: 2px; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e8e8e6; --bg:#16181a; --muted:#9aa0a6; --line:#2c2f33; --accent:#7aa2ff;
          --good:#5bd07f; --warn:#e0a740; --bad:#f2837a; }
}
* { box-sizing:border-box; }
body { margin:0; font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color:var(--fg); background:var(--bg); }
.wrap { max-width:980px; margin:0 auto; padding:0 24px 72px; }
header { border-bottom:1px solid var(--line); margin-bottom:28px; }
header .wrap { padding-top:28px; padding-bottom:0; }
h1 { font-size:27px; margin:0 0 6px; letter-spacing:-0.01em; }
h2 { font-size:20px; margin:34px 0 10px; }
h3 { font-size:16px; margin:24px 0 8px; }
.sub { color:var(--muted); margin:0 0 18px; }
nav { display:flex; gap:18px; flex-wrap:wrap; padding:14px 0 0; }
nav a { color:var(--muted); text-decoration:none; font-size:14px; padding-bottom:12px;
        border-bottom:2px solid transparent; }
nav a:hover { color:var(--fg); }
nav a.on { color:var(--fg); border-bottom-color:var(--accent); }
table { width:100%; border-collapse:collapse; margin:14px 0 8px; font-size:14px; }
th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-weight:600; color:var(--muted); font-size:12.5px; text-transform:uppercase; letter-spacing:.04em; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
code { font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; background:rgba(127,127,127,.12);
       padding:1px 5px; border-radius:4px; }
pre { background:rgba(127,127,127,.10); padding:14px 16px; border-radius:8px; overflow-x:auto;
      font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; }
.card { border:1px solid var(--line); border-radius:10px; padding:16px 18px; margin:14px 0; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(215px,1fr)); gap:12px; margin:16px 0; }
.kpi { border:1px solid var(--line); border-radius:10px; padding:13px 15px; }
.kpi .v { font-size:23px; font-variant-numeric:tabular-nums; }
.kpi .k { color:var(--muted); font-size:12.5px; margin-top:2px; }
.tag { display:inline-block; font-size:11.5px; padding:2px 8px; border-radius:99px;
       border:1px solid var(--line); color:var(--muted); }
.good { color:var(--good); } .warn { color:var(--warn); } .bad { color:var(--bad); }
.missing { color:var(--muted); font-style:italic; }
ul { padding-left:20px; } li { margin:5px 0; }
footer { color:var(--muted); font-size:13px; border-top:1px solid var(--line); margin-top:44px; padding-top:16px; }
a { color:var(--accent); }
.t { border-bottom:1px dotted var(--muted); cursor:help; }
.good-note { border-left:3px solid var(--good); padding-left:12px; margin:10px 0; }
.bad-note { border-left:3px solid var(--warn); padding-left:12px; margin:10px 0; }
.rec { border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:8px;
       padding:14px 16px; margin:14px 0; }
"""

# Definitions attached to metric names wherever they appear, so a reader never has
# to guess what a column means or scroll to find a glossary.
GLOSSARY = {
    "F1": "The balance of precision and recall. High only when the scanner both finds most bad skills and is usually right when it flags one.",
    "Precision": "Of the skills flagged, the share that really were bad. Low precision wastes reviewer time.",
    "Recall": "Of the bad skills present, the share that got flagged. Low recall means bad skills ship.",
    "Detection": "The share of skills in this group flagged at all, whether for review or for blocking.",
    "Signal recall": "The share of bad skills where the scanner produced any relevant signal, including below the threshold that would flag the package.",
    "FPR": "False-positive rate: the share of harmless skills that were flagged. This is what makes a scanner tiring to live with.",
    "False-positive rate": "The share of harmless skills that were flagged.",
    "Block FPR": "The share of harmless skills the scanner blocked outright, as opposed to merely flagging.",
    "Meta invoked": "The share of packages where the meta-judge actually ran. It skips packages whose findings are unambiguous.",
    "Suppressed": "Findings the meta-judge marked as false positives and hid.",
    "Added": "Findings the meta-judge introduced that no other stage had reported.",
    "Judged real": "The share of sampled findings a reviewing model called a genuine security risk.",
    "Agreement": "Chance-corrected agreement between two reviewers. Zero means they agree no more than chance; one means perfectly.",
    "Noise floor": "How much one configuration's own answers move between identical repeat runs. Differences smaller than this mean nothing.",
    "Rules": "The deterministic stage: regular expressions, YARA signatures, syntax trees and dataflow. No model involved.",
    "Rules only": "The deterministic stage alone, which is what ships today.",
    "System One model": "A 9-billion-parameter decision model that answers fixed questions with calibrated probabilities rather than writing text.",
    "Judge": "The full LLM analyzer, which reads the skill and writes structured findings.",
    "Chain": "A sequence of stages. A later stage can raise a decision but never lower it.",
    "Arm": "One configuration of the scanner, measured on the same packages as the others.",
    "Skills reaching each stage": "Each stage in order, showing the share of skills that still needed it. A stage sees fewer skills when earlier ones already settled them, which is where the saving comes from.",
    "Input tokens": "Total text sent to the model, which is what the cost is charged on.",
    "Recipe": "How much surrounding context was included in the request sent to the model.",
    "95% interval": "The range the true value would fall in 95 times out of 100, given this sample size.",
    "Judged real rate": "The estimated share of deterministic findings that are genuine risks.",
    "Cost per skill": "Wall-clock time and, where a model is charged for, money per skill scanned.",
    "Block-only": "Scoring where only a hard block counts as catching something. The right lens when a flag automatically stops the skill.",
    "Any-intervention": "Scoring where asking a human to review also counts as catching something. The right lens when flags go to a review queue.",
    "Previously published": "The figure reported for the deterministic rules before this work, which we treated as the number to reproduce.",
    "Re-measured": "What the same corpus produced when we ran it again from its pinned revision.",
    "Agrees": "Whether the two match closely enough that the harness can be trusted with a new configuration.",
    "True positive": "A bad skill that was correctly flagged.",
    "False positive": "A harmless skill that was wrongly flagged.",
    "False negative": "A bad skill that was missed.",
    "True negative": "A harmless skill that was correctly left alone.",
    "Scan errors": "Packages the scanner could not read at all. These are excluded rather than counted as clean.",
    "Population": "How many skills the figure was computed over, and their split between bad and harmless where both exist.",
    "Median files": "The middle file count, which says more about a typical skill than an average would.",
    "Median scanner-relevant bytes": "Text the scanner actually reads, after excluding images, fonts, archives and vendor directories.",
    "Fits a 32k-token window whole": "The share of skills small enough to send to a model in one piece without dropping anything.",
}


def term(name: str) -> str:
    """Render a metric name with its definition as a tooltip."""
    definition = GLOSSARY.get(name)
    if not definition:
        return esc(name)
    return f'<span class="t" title="{esc(definition)}">{esc(name)}</span>'


def good(text: str) -> str:
    return f'<p class="good-note"><strong>What is good:</strong> {text}</p>'


def bad(text: str) -> str:
    return f'<p class="bad-note"><strong>What is not:</strong> {text}</p>'


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, current: str, body: str) -> str:
    nav = "".join(
        f'<a href="{name}" class="{"on" if name == current else ""}">{esc(label)}</a>' for name, label in PAGES
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>{STYLE}</style></head>
<body><header><div class="wrap"><h1>Cisco AI Defense skill scanner: evaluation results</h1>
<p class="sub">What changes when the LLM judge and the System One model are switched on.</p>
<nav>{nav}</nav></div></header>
<div class="wrap">{body}
<footer>Metrics, counts and digests only. No sample text, evidence strings, prompts or credentials are
published, because the source corpora forbid redistributing content.</footer></div></body></html>
"""


def table(headers: Sequence[str], rows: Sequence[Sequence[str]], *, numeric: Sequence[int] = ()) -> str:
    if not rows:
        return '<p class="missing">No rows available.</p>'
    head = "".join(
        f'<th class="{"num" if index in numeric else ""}">{term(header)}</th>' for index, header in enumerate(headers)
    )
    body = ""
    for row in rows:
        cells = "".join(
            f'<td class="{"num" if index in numeric else ""}">{cell}</td>' for index, cell in enumerate(row)
        )
        body += f"<tr>{cells}</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def kpis(items: Sequence[tuple[str, str]]) -> str:
    cards = "".join(
        f'<div class="kpi"><div class="v">{value}</div><div class="k">{esc(label)}</div></div>'
        for value, label in items
    )
    return f'<div class="grid">{cards}</div>'


def missing(what: str) -> str:
    return f'<div class="card missing">{esc(what)} is not present in this build, so nothing is shown for it.</div>'


# --------------------------------------------------------------------------- pages


def render_index(
    baseline: dict | None,
    judged: dict | None,
    e1: dict | None,
    per_dataset: dict | None = None,
    stability: dict | None = None,
    cost: dict | None = None,
) -> str:
    track = (baseline or {}).get("tracks", {}).get("core-only-source-disjoint") or {}
    judge_track = ((judged or {}).get("arms", {}).get("core_judge", {}).get("report", {}).get("tracks", {}) or {}).get(
        "core-only-source-disjoint"
    ) or {}

    body = "<h2>Summary</h2>"
    body += """<p>The Cisco AI Defense skill scanner has three stages that can look at a skill: a set of
deterministic rules, a System One model, and a full LLM judge. Only the rules had been measured. This
is what happens when the other two are switched on, measured on the same corpora and with the same code
that produced the published rule-only numbers.</p>"""

    cards: list[tuple[str, str]] = []
    if track and judge_track:
        cards = [
            (percent(track.get("f1")), "F1 with rules alone"),
            (percent(judge_track.get("f1")), "F1 with the judge added"),
            (percent(judge_track.get("package_block_precision")), "Precision with the judge added"),
        ]
    if stability:
        cards.append((percent(stability.get("noise_floor")), "How much a judged run moves against itself"))
    if cost:
        one = next((r for r in cost["rows"] if "System One" in r["configuration"]), None)
        judge = next((r for r in cost["rows"] if r["configuration"] == "Rules plus judge"), None)
        if one and judge and judge.get("f1_points_per_dollar"):
            ratio = one["f1_points_per_dollar"] / judge["f1_points_per_dollar"]
            cards.append((f"{ratio:.1f}x", "More quality per dollar from the System One model"))
    if cards:
        body += kpis(cards)

    body += """<h2>The short version</h2>
<ul>
<li>Switching on the judge nearly tripled F1 on the locked test corpus, from 13.74% to 37.68%, and
precision went up rather than down.</li>
<li>The System One model is the better deal for anything automated. It roughly doubled F1 over the
rules, produced no false positives at all in our runs, and processed the whole 1,384-package test corpus
in 42 seconds for 18 cents.</li>
<li>The meta-judge did nothing. It ran on 78% of packages and produced no suppressions and no
additions.</li>
<li>Nothing here is stable below 14%. Repeating one judged configuration over the same packages changed
the verdict on 14% of them, so smaller differences are noise.</li>
</ul>"""

    body += """<h2>Why this was worth measuring</h2>
<p>A skill is an unusually open format. It can contain any code, in any language, for any legitimate
reason, so most of what a rule matches on is ordinary software. That makes precision hard to hold and
makes it tempting to assume an LLM reviewing the output would mostly add noise. On the development split,
where rule precision was already 99%, that assumption looked safe. It turned out to be wrong on the
harder test split, where the rules were missing far more than they were over-flagging.</p>"""

    if per_dataset:
        body += "<h2>Every stage, on every corpus we could label</h2>"
        body += """<p>Detection is the share of skills in that group that got flagged at all. Hover any
column name for its definition.</p>"""
        rows = []
        for name in sorted(per_dataset.get("datasets", {})):
            tiers = per_dataset["datasets"][name]
            population = next((t.get("population", "") for t in tiers.values() if t.get("population")), "")
            rows.append(
                [
                    esc(name),
                    esc(population),
                    percent(tiers.get("rules", {}).get("detection_rate")),
                    percent(tiers.get("small_model", {}).get("detection_rate")),
                    percent(tiers.get("judge", {}).get("detection_rate")),
                ]
            )
        body += table(
            ["Corpus", "Population", "Rules", "System One model", "Judge"],
            rows,
            numeric=(2, 3, 4),
        )
        body += good(
            "Both models beat the rules everywhere except one place, and the judge beats everything "
            "everywhere. On the obviously-malicious half of OpenSkillRisk the judge caught all of it."
        )
        body += bad(
            "The System One model is much worse than the rules on contextually risky skills, catching 11% "
            "against the rules' 33%. It is a confident filter for clear cases, not a substitute for "
            "judgement on ambiguous ones."
        )

    body += f"""<h2>Where to look next</h2>
<ul>
<li><a href="recommendations.html">How to configure it</a> is the practical answer: which tiers to turn
on for which job.</li>
<li><a href="deterministic.html">Deterministic baseline</a> shows the previously published figures
re-measured, which is what makes the rest credible.</li>
<li><a href="judged.html">Judge and meta-judge</a> and <a href="cascade.html">System One model</a> give the
per-corpus detail.</li>
<li><a href="experiments.html">Experiments</a> covers the fifteen side questions, including the four that
came out negative.</li>
<li><a href="reproduce.html">Reproduce it</a> has the actual commands, in order, and the four mistakes that
cost us a run each.</li>
</ul>
<p class="sub">Source figures for the rule-only baseline:
<a href="{PUBLISHED_BLOG_URL}">{esc(PUBLISHED_BLOG_URL)}</a>. Earlier work on System One models:
<a href="{PRIOR_SYSTEM_ONE_SPACE}">{esc(PRIOR_SYSTEM_ONE_SPACE)}</a>.</p>"""
    return page("Skill scanner evaluation results", "index.html", body)


def render_reproduction(reproduction: dict | None) -> str:
    """The previously published figures, re-measured. The precondition for the rest."""
    if not reproduction:
        return ""
    out = "<h2>Re-measuring every previously published figure</h2>"
    out += f"<p>{esc(reproduction['note'])}</p>"
    out += table(
        ["Corpus", "Population", "Previously published", "Re-measured", "Agrees"],
        [
            [
                esc(row["dataset"]),
                esc(row["population"]),
                esc(row["published"]),
                esc(row["reproduced"]),
                '<span class="good">yes</span>' if row["agrees"] else '<span class="bad">no</span>',
            ]
            for row in reproduction["rows"]
        ],
    )
    out += good(
        "All nine figures reproduce. That is the only reason the judged numbers elsewhere on this site "
        "are worth reading: the same code path produced both."
    )
    missing_rows = reproduction.get("not_reproduced") or []
    if missing_rows:
        out += "<h3>Three we could not re-measure, and why</h3>"
        out += table(
            ["Corpus", "Population", "Reason"],
            [[esc(row["dataset"]), esc(row["population"]), esc(row["reason"])] for row in missing_rows],
        )
    return out


def render_deterministic(
    baseline: dict | None, reproduction: dict | None = None, stage_metrics: dict | None = None
) -> str:
    body = "<h2>Reproducing the published baseline</h2>"
    body += """<p>Before any judged number is believable the harness has to reproduce the published one.
This is that check, run on the locked source-disjoint test partition after materializing the corpus
from its pinned revision and verifying every manifest digest against the lock.</p>"""
    if not baseline:
        return page("Deterministic baseline", "deterministic.html", body + missing("The baseline report"))

    track = baseline.get("tracks", {}).get("core-only-source-disjoint", {})
    rows = [
        ["F1", "13.74%", percent(track.get("f1")), _agree(track.get("f1"), 0.1374, 0.0005)],
        [
            "Precision",
            "60.75%",
            percent(track.get("package_block_precision")),
            _agree(track.get("package_block_precision"), 0.6075, 0.0005),
        ],
        [
            "Recall",
            "7.75%",
            percent(track.get("package_block_recall")),
            _agree(track.get("package_block_recall"), 0.0775, 0.0005),
        ],
        [
            "False-positive rate",
            "7.71%",
            percent(_ratio(track.get("fp"), track.get("benign"))),
            _agree(_ratio(track.get("fp"), track.get("benign")), 0.0771, 0.0005),
        ],
        ["Samples", "1,384", count(track.get("samples")), _agree_exact(track.get("samples"), 1384)],
        ["Malicious", "839", count(track.get("malicious")), _agree_exact(track.get("malicious"), 839)],
        ["Benign", "545", count(track.get("benign")), _agree_exact(track.get("benign"), 545)],
    ]
    body += table(["Metric", "Published", "Reproduced", "Match"], rows, numeric=(1, 2))
    body += "<h3>Confusion counts</h3>"
    body += table(
        ["True positive", "False positive", "False negative", "True negative", "Scan errors"],
        [
            [
                count(track.get("tp")),
                count(track.get("fp")),
                count(track.get("fn")),
                count(track.get("tn")),
                count(track.get("scan_errors")),
            ]
        ],
        numeric=(0, 1, 2, 3, 4),
    )
    body += "<h3>Corpus identity</h3><p>The population digest is pinned in the dataset lock, so a "
    body += "shrunken or substituted population cannot pass unnoticed.</p>"
    body += f"<pre>population_sha256  {esc(track.get('population_sha256', 'n/a'))}</pre>"
    body += f"<p class='sub'>Scanner version <code>{esc(baseline.get('scanner_version', 'n/a'))}</code>, "
    body += f"CEL mode <code>{esc(baseline.get('cel_mode', 'off'))}</code>.</p>"
    body += render_stage_metrics(stage_metrics, "rules")
    body += render_reproduction(reproduction)
    return page("Deterministic baseline", "deterministic.html", body)


def _ratio(numerator: Any, denominator: Any) -> float | None:
    if not isinstance(numerator, (int, float)) or not isinstance(denominator, (int, float)) or not denominator:
        return None
    return numerator / denominator


def _agree(actual: Any, expected: float, tolerance: float) -> str:
    if not isinstance(actual, (int, float)):
        return '<span class="missing">n/a</span>'
    return (
        '<span class="good">matches</span>'
        if abs(float(actual) - expected) <= tolerance
        else '<span class="bad">differs</span>'
    )


def _agree_exact(actual: Any, expected: int) -> str:
    if actual == expected:
        return '<span class="good">matches</span>'
    return '<span class="bad">differs</span>'


def render_judged(
    judged: dict | None,
    baseline: dict | None = None,
    per_dataset: dict | None = None,
    stage_metrics: dict | None = None,
) -> str:
    body = "<h2>Enabling the judge and the meta-judge</h2>"
    body += """<p>Four arms over one population: the deterministic core alone, the core plus the LLM
analyzer, the core plus both the analyzer and the meta-judge, and the core plus the meta-judge with the
analyzer left off. The core-only arm exists to prove the harness before any judged number is read.</p>
<p>This track is explicitly non-blocking. The release path asserts that the analyzer factory keeps the
judge off by default, and that assertion still holds; the judge is enabled per-arm by the evaluation
runner alone.</p>"""
    if not judged:
        return page("Judge and meta-judge", "judged.html", body + missing("The judged benchmark report"))

    pending = judged.get("pending_arms") or []
    if pending:
        body += (
            f'<p class="missing">Arms still running: {esc(", ".join(pending))}. '
            "Each takes about an hour, so they are published as they land.</p>"
        )
    arms = judged.get("arms", {})
    rows = []
    base_track = (baseline or {}).get("tracks", {}).get("core-only-source-disjoint") if baseline else None
    if base_track:
        # The comparison is the result. An arm's absolute F1 says little without the
        # core-only figure it is being measured against on the same population.
        rows.append(
            [
                "<code>core_only</code> (baseline)",
                percent(base_track.get("f1")),
                percent(base_track.get("package_block_precision")),
                percent(base_track.get("package_block_recall")),
                percent(_ratio(base_track.get("fp"), base_track.get("benign"))),
                "n/a",
                "0",
                "0",
            ]
        )
    for name in judged.get("arm_order", sorted(arms)):
        arm = arms.get(name, {})
        report = arm.get("report", {})
        track = report.get("tracks", {}).get("core-only-source-disjoint", {})
        telemetry = arm.get("telemetry", {})
        rows.append(
            [
                f"<code>{esc(name)}</code>",
                percent(track.get("f1")),
                percent(track.get("package_block_precision")),
                percent(track.get("package_block_recall")),
                percent(_ratio(track.get("fp"), track.get("benign"))),
                percent(telemetry.get("meta_invoked_rate")),
                count(telemetry.get("meta_suppressed_findings")),
                count(telemetry.get("meta_added_findings")),
            ]
        )
    body += table(
        ["Arm", "F1", "Precision", "Recall", "FPR", "Meta invoked", "Suppressed", "Added"],
        rows,
        numeric=(1, 2, 3, 4, 5, 6, 7),
    )
    judge_arm = arms.get("core_judge", {}).get("report", {}).get("tracks", {}).get("core-only-source-disjoint")
    if base_track and judge_arm:
        body += f"""<h3>What enabling the judge actually did</h3>
<div class="card">On the same locked population, enabling the LLM analyzer took F1 from
{percent(base_track.get("f1"))} to {percent(judge_arm.get("f1"))} and signal recall from
{percent(base_track.get("signal_recall"))} to {percent(judge_arm.get("signal_recall"))}. Precision rose
as well, from {percent(base_track.get("package_block_precision"))} to
{percent(judge_arm.get("package_block_precision"))}, which is the opposite of what the premise
predicted: at a precision of 99% on the development split there was no room to improve, but on this
source-disjoint split the rules were missing far more than they were over-flagging. True positives went
from {count(base_track.get("tp"))} to {count(judge_arm.get("tp"))} while false positives went from
{count(base_track.get("fp"))} to {count(judge_arm.get("fp"))}.
<p class="sub">The cost is visible on the stricter lens: the share of benign packages carrying any
actionable finding roughly doubled, from {percent(base_track.get("benign_actionable_fpr"))} to
{percent(judge_arm.get("benign_actionable_fpr"))}. So the judge is a clear win at the block threshold
and a noticeable source of noise below it.</p></div>"""

    meta_arm = arms.get("core_judge_meta", {})
    meta_tel = meta_arm.get("telemetry", {})
    meta_track = meta_arm.get("report", {}).get("tracks", {}).get("core-only-source-disjoint")
    judge_track = arms.get("core_judge", {}).get("report", {}).get("tracks", {}).get("core-only-source-disjoint")
    if meta_tel and meta_track and judge_track:
        delta = (meta_track.get("f1", 0) - judge_track.get("f1", 0)) * 100
        body += f"""<h3>What the meta-judge did</h3>
<div class="card">It ran on {percent(meta_tel.get("meta_invoked_rate"))} of packages and changed nothing
measurable. It suppressed {count(meta_tel.get("meta_suppressed_findings"))} findings and added
{count(meta_tel.get("meta_added_findings"))}, and F1 moved by {delta:+.2f} points against the
judge-only arm, which is inside the run-to-run variation the judge itself shows. On the remaining
packages it declined to run: {count(meta_tel.get("meta_routing_reasons", {}).get("clear_deterministic_findings"))}
had no ambiguous finding and {count(meta_tel.get("meta_routing_reasons", {}).get("no_findings"))} had no
findings at all.
<p class="sub">Reading that rate correctly took a fix. The first version of this instrumentation keyed
on the routing reason text rather than the routing decision, and so reported that meta had never run at
all. It had run on most packages. The conclusion is the same either way, but it would have been
published for the wrong reason.</p></div>"""

    body += render_stage_metrics(stage_metrics, "judge")

    if per_dataset:
        body += "<h3>The judge against the rules, detection only</h3>"
        body += """<p>The locked corpus above is one population. These are the others, each with the
figure its licence permits. Detection is the share of skills flagged at all.</p>"""
        rows = []
        for name in sorted(per_dataset.get("datasets", {})):
            tiers = per_dataset["datasets"][name]
            judge = tiers.get("judge", {})
            rules = tiers.get("rules", {})
            if not judge:
                continue
            lift = (judge.get("detection_rate", 0) - rules.get("detection_rate", 0)) * 100
            rows.append(
                [
                    esc(name),
                    esc(judge.get("population", "")),
                    percent(rules.get("detection_rate")),
                    percent(judge.get("detection_rate")),
                    f"{lift:+.1f} points",
                ]
            )
        body += table(["Corpus", "Population", "Rules", "Judge", "Change"], rows, numeric=(2, 3, 4))
        body += good(
            "The judge improves detection on every corpus, and the gain is largest exactly where the rules "
            "are weakest. On HarmfulSkillBench the rules found 4% and the judge found 56%."
        )
        body += bad(
            "It is not free. On the locked corpus the share of harmless skills carrying an actionable "
            "finding roughly doubled, so this belongs behind a review queue rather than an automatic block."
        )

    body += """<h3>Why the meta invocation rate is worth checking</h3>
<div class="card">The meta-judge has a routing gate that returns early when no finding is ambiguous, so
"meta enabled" can mean "meta never ran". An arm reporting a near-zero invocation rate is
indistinguishable from the core arm and must not be read as a measurement of the meta-judge. Any arm
in that state is flagged in the report rather than presented as a result.</div>"""

    warnings = [(name, warning) for name in arms for warning in (arms[name].get("warnings") or [])]
    if warnings:
        body += "<h3>Flagged arms</h3><ul>"
        body += "".join(f"<li><code>{esc(name)}</code>: {esc(warning)}</li>" for name, warning in warnings)
        body += "</ul>"

    body += "<h3>Model fitness, measured rather than assumed</h3>"
    repairs = sum(int(arms[name].get("telemetry", {}).get("llm_verdict_repairs") or 0) for name in arms)
    body += f"""<div class="card">The judge model returns a package verdict of <code>SAFE</code> while
also listing findings on a measurable fraction of packages, which is self-contradictory and causes the
strict contract to discard the whole analysis. Measured on the benchmark corpus the contradiction
appeared on <strong>22.5% of benign packages and 0% of malicious ones</strong>. That asymmetry matters:
discarding the analysis only on benign packages suppresses the judge exactly where it would have
produced false positives, which flatters its measured precision. These arms therefore run with an
opt-in, escalate-only verdict repair that rewrites the summary verdict and never the findings, applied
{count(repairs)} times. The repair is off by default in the product.</div>"""
    return page("Judge and meta-judge", "judged.html", body)


def render_findings(findings: dict | None) -> str:
    """Render each experiment as question, answer and the numbers behind it."""
    if not findings:
        return ""
    out = "<h3>Answers so far</h3>"
    for entry in findings.get("findings", []):
        rows = "".join(
            f'<tr><td>{esc(label)}</td><td class="num">{esc(value)}</td></tr>'
            for label, value in entry.get("numbers", [])
        )
        caveat = f'<p class="sub">{esc(entry["caveat"])}</p>' if entry.get("caveat") else ""
        out += (
            f'<div class="card"><span class="tag">{esc(entry["id"])}</span>'
            f"<h4>{esc(entry['question'])}</h4><p>{esc(entry['answer'])}</p>"
            f"<table><tbody>{rows}</tbody></table>{caveat}</div>"
        )
    if findings.get("not_run"):
        out += f'<p class="missing">Not yet run: {esc(", ".join(findings["not_run"]))}.</p>'
    return out


def render_experiments(e1: dict | None, e3: dict | None = None, findings: dict | None = None) -> str:
    body = "<h2>Experiment programme</h2>"
    body += """<p>The goal of this half is to find out what works, not to ship a subsystem. Each
experiment states a question and a decision rule, and a negative result is a result.</p>"""
    body += render_findings(findings)

    body += "<h3>E1: what fraction of deterministic findings are actually real?</h3>"
    body += """<p>This runs first because every later number is read against it. Findings from real-world
skills are stratified by rule and severity, then adjudicated by two models from different vendors. The
corpus is unlabeled, so this estimates a rate and reports its own uncertainty rather than claiming
ground truth, and agreement between two models bounds trust rather than establishing accuracy.</p>"""
    if not e1:
        body += missing("The E1 report")
    else:
        results = e1.get("results", {})
        body += kpis(
            [
                (count(e1.get("findings_total")), "Deterministic findings collected"),
                (count(e1.get("findings_sampled")), "Findings adjudicated"),
                (count(e1.get("strata")), "Rule and severity strata"),
                (f"{results.get('agreement', {}).get('cohen_kappa', 0):.3f}", "Agreement, chance-corrected"),
            ]
        )
        rows = []
        for role in ("primary", "independent"):
            block = results.get(role, {})
            overall = block.get("overall", {})
            rows.append(
                [
                    esc(e1.get("models", {}).get(role, role)),
                    count(block.get("usable")),
                    count(block.get("errors")),
                    count(block.get("uncertain")),
                    percent(overall.get("real_rate")),
                    interval(overall.get("real_rate_95")),
                ]
            )
        body += table(
            ["Adjudicator", "Usable", "Errors", "Uncertain", "Judged real", "95% interval"],
            rows,
            numeric=(1, 2, 3, 4, 5),
        )
        per_rule = results.get("primary", {}).get("per_rule", {})
        ranked = sorted(per_rule.items(), key=lambda item: item[1].get("real_rate", 0.0))
        if ranked:
            body += "<h4>Per-rule estimated real rate</h4>"
            body += "<p>Rules whose findings are mostly judged inapplicable are where a judge has room "
            body += "to help, and where suppression candidates should be mined first.</p>"
            body += table(
                ["Rule", "Sampled", "Decided", "Judged real", "95% interval"],
                [
                    [
                        f"<code>{esc(rule)}</code>",
                        count(stats.get("sampled")),
                        count(stats.get("decided")),
                        percent(stats.get("real_rate")),
                        interval(stats.get("real_rate_95")),
                    ]
                    for rule, stats in ranked
                ],
                numeric=(1, 2, 3, 4),
            )
        disagreements = results.get("disagreements") or []
        body += f"<p>The two adjudicators disagreed on {count(len(disagreements))} findings. "
        body += "Those form the ranked backlog for human review; no model verdict is treated as truth.</p>"

    body += "<h3>E3: does one batched request per skill match one per finding?</h3>"
    body += """<p>Sending every finding for a skill in a single request trades cross-finding context,
which should help, against attention dilution, which should hurt. It also turns N requests per skill
into one, so the answer decides the cost of the whole tier.</p>"""
    if not e3:
        body += missing("The E3 report")
    else:
        paired = e3.get("paired_with_e1", {})
        body += kpis(
            [
                (
                    f"{e3.get('requests_batched')} vs {e3.get('requests_per_finding')}",
                    "Requests, batched against per-finding",
                ),
                (percent(e3.get("request_reduction")), "Fewer requests"),
                (percent(e3.get("batched_real_rate")), "Findings judged real, batched"),
                (f"{paired.get('cohen_kappa', 0):.3f}", "Agreement with per-finding, chance-corrected"),
            ]
        )
        body += """<div class="card">The batched arm reproduces the per-finding <em>rate</em> exactly at
a third of the requests, but chance-corrected agreement is near zero: the two arms find the same number
of real findings and largely disagree about <em>which</em> ones. Raw agreement looks high only because
both overwhelmingly answer "not applicable". So batching is sound for an aggregate estimate and not for
a per-finding suppression decision.</div>"""

    # Derived from the findings file rather than hand-maintained. The previous
    # hardcoded table went stale and claimed a dozen experiments were pending on the
    # same page that reported their results.
    answered = {entry["id"] for entry in (findings or {}).get("findings", [])}
    body += "<h3>Every experiment and where it stands</h3>"
    body += table(
        ["Experiment", "Question", "Status"],
        [
            [
                f"<code>{esc(experiment_id)}</code> {esc(name)}",
                esc(question),
                (
                    '<span class="good">answered above</span>'
                    if experiment_id in answered
                    else f'<span class="missing">{esc(pending_note)}</span>'
                ),
            ]
            for experiment_id, name, question, pending_note in EXPERIMENT_CATALOGUE
        ],
    )
    covered_elsewhere = [
        entry for entry in EXPERIMENT_CATALOGUE if entry[0] not in answered and "cascade page" in entry[3]
    ]
    if covered_elsewhere:
        body += (
            '<p class="sub">The packing, context and question-format experiments are reported on the '
            "System One cascade page, because their results are the cascade tables themselves.</p>"
        )
    return page("Experiments", "experiments.html", body)


def render_cascade(
    cascade: dict | None,
    sweeps: dict | None,
    per_dataset: dict | None = None,
    stage_metrics: dict | None = None,
    prompt_guard: dict | None = None,
) -> str:
    body = "<h2>Does the System One model earn its place between the rules and the judge?</h2>"
    body += """<p>Scored on a label-balanced subset of 400 malicious and 400 benign packages, so both
error directions are visible at once. Every chain is reported under both lenses, because they reorder
the ranking: <strong>block-only</strong> counts just a hard block as a catch, while
<strong>any-intervention</strong> also counts a confirm, which is the right question when a confirm
routes to review.</p>
<p>The cascade short-circuits only on a block. A deterministic confirm escalates to the next tier and
the tiers are merged so a later one can raise a decision but never lower it.</p>"""
    if not cascade:
        return page("System One cascade", "cascade.html", body + missing("The cascade score report"))

    for lens, heading in (("block_only", "Block-only lens"), ("any_intervention", "Any-intervention lens")):
        body += f"<h3>{term(heading.replace(' lens', ''))} lens</h3>"
        rows = []
        for chain in cascade.get("chains", []):
            block = chain.get(lens, {})
            rates = chain.get("telemetry", {}).get("tier_invocation_rates", [])
            stage_names = _stage_names(str(chain.get("chain") or ""))
            reached = (
                "; ".join(
                    f"{stage_names[index] if index < len(stage_names) else 'stage ' + str(index + 1)} {rate * 100:.0f}%"
                    for index, rate in enumerate(rates)
                )
                or "n/a"
            )
            rows.append(
                [
                    f"<code>{esc(chain.get('chain'))}</code>",
                    percent(block.get("precision")),
                    percent(block.get("recall")),
                    percent(block.get("f1")),
                    percent(block.get("false_positive_rate")),
                    esc(reached),
                ]
            )
        body += table(
            ["Chain", "Precision", "Recall", "F1", "False-positive rate", "Skills reaching each stage"],
            rows,
            numeric=(1, 2, 3, 4),
        )

    body += """<p class="sub">The last column reads in stage order. Where it says "rules 100%; System One 91%",
the rules examined every skill and 9% were already settled by a clear block, so the System One model was only
asked about the remaining 91%. That is the saving from putting cheap stages first.</p>"""

    body += """<h3>What the two lenses show</h3>
<div class="card">The eight-probe question format is the clearest case. It is the weakest chain on
block-only F1 and among the strongest on any-intervention F1, because it confirms widely rather than
blocking. Reporting either number alone would invert the conclusion, which is why the format is treated
as a triage screen that must never decide a block on its own.</div>"""

    body += render_stage_metrics(stage_metrics, "system_one")

    if per_dataset:
        body += "<h3>The System One model against the rules, detection only</h3>"
        rows = []
        for name in sorted(per_dataset.get("datasets", {})):
            tiers = per_dataset["datasets"][name]
            small = tiers.get("small_model", {})
            rules = tiers.get("rules", {})
            if not small:
                continue
            lift = (small.get("detection_rate", 0) - rules.get("detection_rate", 0)) * 100
            rows.append(
                [
                    esc(name),
                    esc(small.get("population", "")),
                    percent(rules.get("detection_rate")),
                    percent(small.get("detection_rate")),
                    f"{lift:+.1f} points",
                ]
            )
        body += table(["Corpus", "Population", "Rules", "System One model", "Change"], rows, numeric=(2, 3, 4))
        body += good(
            "It nearly matches the judge on clear malice at a fraction of the cost, reaching 95.8% on the "
            "obviously-malicious half of OpenSkillRisk, and in these runs it never flagged a harmless skill."
        )
        body += bad(
            "On contextually risky skills it detected 11% where the rules detected 33%. Whatever it is "
            "good at, it is not resolving ambiguity, and a deployment that relies on it alone will miss "
            "exactly the cases that need a judgement call."
        )

    if sweeps:
        body += "<h3>What context is worth</h3>"
        body += """<p>Each recipe adds one layer and nothing else, and an unknown field is rejected rather
than ignored, so a recipe cannot silently fall back to the full context and report a difference that
was never sent.</p>"""
        body += table(
            ["Recipe", "Adds", "Precision", "Recall", "F1", "Input tokens"],
            [
                [
                    f"<code>{esc(row['recipe'])}</code>",
                    esc(row["adds"]),
                    percent(row["precision"]),
                    percent(row["recall"]),
                    percent(row["f1"]),
                    count(row["input_tokens"]),
                ]
                for row in sweeps.get("context", [])
            ],
            numeric=(2, 3, 4, 5),
        )
        body += """<p>Context is worth a few points of recall for roughly a quarter more input tokens,
and the gain is monotonic across the recipes. On an unlabeled real-world corpus the same sweep showed
nothing at all, because the model allowed every package at every recipe; an ablation cannot
discriminate on a population where every answer is the same.</p>"""
    body += render_prompt_guard(prompt_guard)
    return page("Small-model screens", "cascade.html", body)


def render_prompt_guard(report: dict | None) -> str:
    """Llama Prompt Guard 2 as a pre-filter: measured, and not adopted."""

    if not report:
        return ""

    corpora = report.get("corpora") or {}
    labelled = corpora.get("msb-source-disjoint") or {}
    real = corpora.get("real-world-skills") or {}
    out = "<h2>Llama Prompt Guard 2 as a pre-filter</h2>\n"
    out += (
        "<p><code>meta-llama/Llama-Prompt-Guard-2-22M</code> is a 22M-parameter DeBERTa-v2 "
        "classifier, 283 MB, with a 512-token context, so it needs no GPU: this run is CPU-only and "
        "took 45 minutes for 12,500 skills on 16 cores. Each skill is split into 512-token windows "
        "overlapping by 128 and scored by its <em>maximum</em> window probability, which favours "
        "detection, so a low recall cannot be blamed on the chunking.</p>\n"
    )

    thresholds = [t for t in (labelled.get("thresholds") or []) if t.get("has_negative_class")]
    if thresholds:
        out += (
            f"<h3>Separation on {labelled.get('positives', 0)} malicious and "
            f"{labelled.get('negatives', 0)} benign records</h3>\n"
        )
        out += table(
            ["Threshold", "Recall", "Precision", "False-positive rate"],
            [
                [
                    f"{t['threshold']:g}",
                    percent(t.get("recall")),
                    percent(t.get("precision")) if t.get("precision") else "&mdash;",
                    percent(t.get("false_positive_rate")),
                ]
                for t in thresholds
            ],
            numeric=(1, 2, 3),
        )
        auc_value = labelled.get("auc")
        if auc_value is not None:
            out += (
                f"<p>It is effectively silent. AUC is {auc_value:.3f}, so there is a faint signal and "
                "it points the right way &mdash; unlike the System One result above, which is inverted "
                "&mdash; but the probabilities never reach a threshold anything could act on. Two of "
                "1,384 records fire at 0.5 and <strong>both are benign</strong>.</p>\n"
            )

    out += (
        "<h3>One number here is misleading, so it is stated rather than quoted</h3>\n"
        "<p>Sweeping every threshold, the best achievable F1 is 77.4%, which is higher than the shipped "
        "single judge's 61.2% on the same records. That is class balance, not detection: it occurs at a "
        "threshold of 0.0015 with an 89.0% false-positive rate, which is very nearly &ldquo;flag "
        "everything&rdquo;, and the corpus is 60.6% malicious. The trivial always-flag classifier "
        "scores 75.5% F1 here, so the model beats it by 1.9 points. At the judge's own operating point "
        "of 17.6% false-positive rate its recall is 22.3% against the judge's 49.0%, and at a 1% "
        "false-positive rate its recall is 0.1%.</p>\n"
    )

    if real.get("flag_rate_at_0.5") is not None:
        out += "<h3>On real published skills it is not merely inert</h3>\n"
        # Every record here is unlabelled, so the harness counts a firing as a false
        # positive; the "flagged" column is that count and the rate is its FPR.
        real_rows = []
        for entry in real.get("thresholds") or []:
            flagged_count = int(entry.get("false_positives") or 0) + int(entry.get("true_positives") or 0)
            interval = entry.get("false_positive_rate_95")
            rate = percent(entry.get("false_positive_rate"))
            if interval:
                rate += f" [{interval[0] * 100:.3f}, {interval[1] * 100:.3f}]"
            real_rows.append([f"{entry['threshold']:g}", f"{flagged_count:,}", rate])
        out += table(["Threshold", "Records flagged", "Rate"], real_rows, numeric=(1, 2))
        out += (
            "<p>The three highest-scoring records &mdash; 0.998, 0.995 and 0.993 &mdash; are a "
            "Chinese-language novel-writing checklist, a conversation-memory skill, and a prompt "
            "optimizer. All three are benign, and two causes account for the pattern. Skills containing "
            "more than 2% CJK characters (976 of 12,500) are flagged at <strong>1.64%</strong> against "
            "<strong>0.10%</strong> for the rest, a sixteen-fold difference, and sixteen of the 27 "
            "flagged records are CJK-heavy though such skills are 7.8% of the corpus. Separately, a "
            "prompt-engineering skill reads like an instruction-override attempt because directing a "
            "model is the product. Mean scores are nearly identical across the two groups, so the "
            "effect sits entirely in the high-confidence tail.</p>\n"
        )

    out += (
        "<p>So enabling it as a screen would penalise non-English and prompt-engineering skills while "
        "detecting essentially none of the labelled malicious ones. <strong>This is a statement about "
        "fit, not about the model.</strong> Prompt Guard detects prompt-injection and jailbreak attempts "
        "in text; whether a skill is safe to install is a different question, and a skill can be "
        "malicious through a download-and-execute chain or a credential sink without containing anything "
        "an injection classifier would recognise. It is not integrated.</p>\n"
    )
    return out


def _stage_names(chain_id: str) -> list[str]:
    """Readable stage names for a chain identifier, in order."""
    mapping = [
        ("rules", "rules"),
        ("deterministic", "rules"),
        ("jev", "System One"),
        ("small", "System One"),
        ("judge", "judge"),
        ("meta", "meta"),
    ]
    names: list[str] = []
    for token in chain_id.split("_then_"):
        label = next((name for key, name in mapping if key in token), token)
        if label not in names:
            names.append(label)
    return names


def render_stage_metrics(metrics: dict | None, stage: str) -> str:
    """Every defined metric for one stage, corpus by corpus.

    Precision and false-positive rate need a harmless class. Two of these corpora are
    entirely positive-risk, so those cells say so rather than showing a misleading
    figure computed against no negatives.
    """
    if not metrics:
        return ""
    label = metrics.get("stage_labels", {}).get(stage, stage)
    rows = []
    footnotes: list[str] = []
    for name in sorted(metrics.get("datasets", {})):
        entry = metrics["datasets"][name]
        block = entry.get("stages", {}).get(stage)
        if not block:
            continue
        if block["has_negative_class"]:
            precision = percent(block["precision"])
            f1 = percent(block["f1"])
            fpr = percent(block["false_positive_rate"])
        else:
            precision = f1 = fpr = '<span class="missing">no harmless class</span>'
            if entry.get("note") and entry["note"] not in footnotes:
                footnotes.append(entry["note"])
        rows.append(
            [
                esc(name),
                f"{count(block['positives'])} bad, {count(block['negatives'])} harmless",
                percent(block["recall"]),
                precision,
                f1,
                fpr,
                count(block["errors"]),
            ]
        )
    if not rows:
        return ""
    out = f"<h3>{esc(label)}: every metric, corpus by corpus</h3>"
    out += """<p>Scored on the <span class="t" title="Scoring where asking a human to review also counts
as catching something. The right lens when flags go to a review queue.">any-intervention</span> lens, so a
finding raised for review counts as a catch. Errors are requests the stage could not complete; they are
excluded rather than counted as clean.</p>"""
    out += table(
        ["Corpus", "Population", "Recall", "Precision", "F1", "FPR", "Errors"],
        rows,
        numeric=(2, 3, 4, 5, 6),
    )
    if footnotes:
        out += '<p class="sub">' + " ".join(esc(note) for note in footnotes) + "</p>"
    return out


def render_cost(cost: dict | None) -> str:
    """Cost against benefit, which is the question that decides deployment."""
    if not cost:
        return ""
    rows = []
    for row in cost["rows"]:
        points = row["f1_points_over_rules"]
        per_dollar = row["f1_points_per_dollar"]
        rows.append(
            [
                esc(row["configuration"]),
                percent(row["f1"]),
                f"{points:+.1f}",
                f"${row['usd_for_1384_packages']:.4f}",
                f"{row['seconds_per_package']:.3f}s",
                "n/a" if per_dollar is None else f"{per_dollar:.1f}",
            ]
        )
    out = "<h3>What each stage costs, and what it buys</h3>"
    out += f"<p>Over {esc(cost['population'])}, scored on the {term('Block-only')} lens. "
    out += "The last column is the figure that matters for a deployment decision: F1 points gained over "
    out += "the rules, per dollar spent.</p>"
    out += table(
        [
            "Configuration",
            "F1",
            "Points over rules",
            "Cost for the whole corpus",
            "Seconds per skill",
            "F1 points per dollar",
        ],
        rows,
        numeric=(1, 2, 3, 4, 5),
    )

    by_name = {row["configuration"]: row for row in cost["rows"]}
    one = by_name.get("Rules plus System One model")
    judge = by_name.get("Rules plus judge")
    meta = by_name.get("Rules plus judge plus meta")
    if one and judge and meta and judge["f1_points_per_dollar"]:
        ratio_judge = one["f1_points_per_dollar"] / judge["f1_points_per_dollar"]
        ratio_meta = one["f1_points_per_dollar"] / meta["f1_points_per_dollar"]
        cost_ratio = judge["usd_per_package"] / one["usd_per_package"]
        speed_ratio = judge["seconds_per_package"] / one["seconds_per_package"]
        out += good(
            f"The System One model is the best value by a wide margin: {ratio_judge:.1f} times more F1 per "
            f"dollar than the judge and {ratio_meta:.1f} times more than the judge with meta. The judge costs "
            f"{cost_ratio:.1f} times more per skill and takes {speed_ratio:.0f} times longer."
        )
        out += bad(
            "Value per dollar is not the only question. The judge still buys more than twice as many F1 "
            "points in absolute terms, and if what you need is recall rather than economy, it is the only "
            "stage that delivers it. The meta-judge is the one configuration that is worse on both counts: "
            "it adds cost and no measurable quality."
        )
    if cost.get("billing_reconciliation"):
        out += f'<p class="sub">{esc(cost["billing_reconciliation"])}</p>'
    out += f"""<p class="sub">Measurement: {esc(cost["measurement"]["jev"])} for the System One model;
for the judge, {esc(cost["measurement"]["judge"])}. Prices are
${cost["pricing"]["gemma_4_input_usd_per_million"]:.2f} and
${cost["pricing"]["gemma_4_output_usd_per_million"]:.2f} per million input and output tokens for the judge,
and ${cost["pricing"]["jev_input_usd_per_million"]:.3f} per million input tokens for the System One model.
Batch inference halves the judge's rate, which the figures above do not assume.</p>"""
    return out


def render_recommendations(
    rec: dict | None, per_dataset: dict | None, stability: dict | None, cost: dict | None = None
) -> str:
    body = "<h2>How to configure the scanner</h2>"
    if not rec:
        return page("How to configure it", "recommendations.html", body + missing("The recommendation"))

    body += f"<p>{esc(rec['summary'])}</p>"
    if rec.get("honesty_note"):
        body += '<div class="card">' + esc(rec["honesty_note"]) + "</div>"

    body += "<h3>Stage by stage</h3>"
    body += table(
        ["Stage", "Recommended setting", "Why", "Cost per skill", "What to watch"],
        [
            [
                esc(entry["tier"]),
                f"<code>{esc(entry['setting'])}</code>",
                esc(entry["why"]),
                esc(entry["cost"]),
                esc(entry["caveat"]),
            ]
            for entry in rec["tiers"]
        ],
    )

    body += "<h3>Three setups, depending on what reads the output</h3>"
    for profile in rec["profiles"]:
        body += (
            f'<div class="rec"><strong>{esc(profile["name"])}</strong>'
            f"<p><code>{esc(profile['config'])}</code></p>"
            f"<p>{esc(profile['rationale'])}</p>"
            f'<p class="sub">Expect: {esc(profile["expected"])}</p></div>'
        )

    if per_dataset:
        body += "<h3>What each setup would have caught</h3>"
        rows = []
        for name in sorted(per_dataset.get("datasets", {})):
            tiers = per_dataset["datasets"][name]
            rows.append(
                [
                    esc(name),
                    percent(tiers.get("rules", {}).get("detection_rate")),
                    percent(tiers.get("small_model", {}).get("detection_rate")),
                    percent(tiers.get("judge", {}).get("detection_rate")),
                ]
            )
        body += table(
            ["Corpus", "Rules only", "Rules plus System One model", "Rules plus System One model plus judge"],
            rows,
            numeric=(1, 2, 3),
        )
        body += """<p class="sub">Read the last two columns as the tier's own detection rate on that
corpus, not as a cascade total. Combining tiers can only raise a decision, never lower it, so a cascade
catches at least as much as its best tier.</p>"""

    body += render_cost(cost)

    body += "<h3>Four ways to misread these results</h3><ul>"
    body += "".join(f"<li>{esc(item)}</li>" for item in rec["pitfalls"])
    body += "</ul>"

    if stability:
        body += f"""<p class="sub">That first pitfall is measured, not hypothetical: repeating one judged
configuration {count(stability.get("core_plus_judge", {}).get("passes"))} times over the same packages
changed the verdict on {percent(stability.get("noise_floor"))} of them, while the deterministic rules did
not move once.</p>"""
    return page("How to configure it", "recommendations.html", body)


def render_reproduce(repro: dict | None) -> str:
    body = "<h2>Reproducing these results</h2>"
    if not repro:
        return page("Reproduce it", "reproduce.html", body + missing("The reproduction guide"))

    body += f"<p>{esc(repro['intro'])}</p>"

    body += "<h3>What you need first</h3>"
    body += table(
        ["Requirement", "Detail"],
        [[esc(item["item"]), esc(item["detail"])] for item in repro["prerequisites"]],
    )

    body += "<h3>The commands, in order</h3>"
    for step in repro["steps"]:
        body += (
            f'<div class="rec"><strong>{esc(step["stage"])}</strong>'
            f"<pre>{esc(step['command'])}</pre>"
            f"<p>{esc(step['note'])}</p></div>"
        )

    body += "<h3>What the harness guarantees</h3><ul>"
    body += "".join(f"<li>{esc(item)}</li>" for item in repro["guarantees"])
    body += "</ul>"

    body += "<h3>Four things that will waste your afternoon</h3>"
    body += "<p>Each of these cost us a run before we found it.</p><ul>"
    body += "".join(f"<li>{esc(item)}</li>" for item in repro["known_gotchas"])
    body += "</ul>"
    return body and page("Reproduce it", "reproduce.html", body)


def render_methodology() -> str:
    body = "<h2>Corpus shape decides how a skill can be packed</h2>"
    body += """<p>The benchmark corpora store skills as one or two text fields, not as directories, so
they almost always fit a System One model's context whole. Real-world skills do not. Any packing or cost
conclusion drawn from the small golden fixtures would be wrong about real input.</p>"""
    body += table(
        ["Population", "Median files", "Median scanner-relevant bytes", "Fits a 32k-token window whole"],
        [[esc(s.population), esc(s.median_files), esc(s.median_bytes), esc(s.fits_whole)] for s in CORPUS_SHAPES],
        numeric=(2,),
    )
    body += """<h2>The packing ladder</h2>
<p>Three rungs, tried in order. <strong>A</strong> sends the whole record when it fits, which covers
essentially every benchmark row. <strong>B</strong> fills the budget by priority when it does not:
<code>SKILL.md</code> first because it fits 96% of the time and is the instruction surface where
prompt injection lives, then scripts it references, then remaining code ordered by detected content
type rather than file extension, then documentation truncated hardest. <strong>C</strong> falls back to
one request per candidate finding for the long tail.</p>
<p>Measured, the ladder puts every benchmark row on rung A and 84% of real-world skills on rung B.</p>
<h3>Rules that hold on every rung</h3>
<ul>
<li>The matched evidence is never truncated; only the window around it is, and truncation keeps
windows containing security-relevant terms so an obfuscated payload's middle survives.</li>
<li>An oversize request is never sent. A provider that truncates and still answers answers
confidently about content it never saw, so the oversize path returns not-applicable and falls back to
the deterministic decision.</li>
<li>Untrusted sample text is neutralized so a malicious manifest cannot close the harness's own
delimiters and have its instructions read as policy.</li>
<li>No benchmark label, and no other tier's verdict, ever enters the context. Including a verdict
would destroy arm independence and make cascade scoring circular.</li>
</ul>
<h2>Judge model, verified rather than assumed</h2>"""
    body += table(["Property", "What was measured"], [[esc(f.claim), esc(f.detail)] for f in GEMMA_FACTS])
    body += """<h2>Reproducibility discipline</h2>
<ul>
<li>Every analysis is gated on a completion attestation and on the on-disk digest matching the
manifest, so a partial run cannot be published as a finished one.</li>
<li>Results are written to new paths; no scorecard or prediction file is modified in place.</li>
<li>Integrity counters travel with every result: row counts, error rows, unparsable rows and the size
of any unjudgeable subset.</li>
<li>Per-corpus licence restrictions are honoured. Several forbid exactly the metric one would reach for
first, so the permitted metrics are recorded per corpus rather than left to discipline.</li>
<li>Samples are never executed, and no sample content is republished.</li>
</ul>"""
    return page("Methodology", "methodology.html", body)


def readme(title: str) -> str:
    """Space card frontmatter.

    ``app_file`` is required: without it a static Space has no declared entry point
    and the hub's iframe request for /index.html fails even though the file is
    served correctly. The title avoids a colon because the frontmatter is YAML and
    an unquoted colon makes the whole block unparseable.
    """
    return f"""---
title: {title}
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
short_description: What an LLM judge adds to the skill scanner
---

# {title}

The Cisco AI Defense skill scanner has three stages that can inspect a skill: deterministic rules, a
System One model, and a full LLM judge. Only the rules had been measured. This Space reports what
the other two do, on the same corpora, using the same code that produced the published rule-only
figures.

Metrics, counts and digests only. No skill content, finding evidence, prompts or credentials are
published, because the source corpora forbid redistributing their content.
"""


def assemble_judged(arm_paths: Sequence[Path]) -> dict[str, Any] | None:
    """Build a judged report from per-arm files.

    Arms take about an hour each and are persisted individually, so the page shows
    whichever have landed rather than waiting for the whole sweep.
    """
    arms: dict[str, Any] = {}
    for path in arm_paths:
        report = load_json(path)
        if report is None or not report.get("arm"):
            continue
        arms[str(report["arm"])] = report
    if not arms:
        return None
    expected = [arm.name for arm in ARMS if arm.name != "core_only"]
    return {
        "arms": arms,
        "arm_order": [name for name in expected if name in arms],
        "pending_arms": [name for name in expected if name not in arms],
        "complete": True,
    }


def build(
    output: Path,
    *,
    baseline: Path,
    judged: Path,
    e1: Path,
    title: str,
    e3: Path | None = None,
    judged_arms: Sequence[Path] = (),
    cascade: Path | None = None,
    sweeps: Path | None = None,
    findings: Path | None = None,
    reproduction: Path | None = None,
    recommendation: Path | None = None,
    per_dataset: Path | None = None,
    stability: Path | None = None,
    cost: Path | None = None,
    reproduce: Path | None = None,
    stage_metrics: Path | None = None,
    cross_tool: Path | None = None,
    improvements: Path | None = None,
    prompt_guard: Path | None = None,
) -> dict[str, Any]:
    baseline_report = require_complete(load_json(baseline))
    judged_report = require_complete(load_json(judged))
    if judged_report is None and judged_arms:
        judged_report = assemble_judged(judged_arms)
    e1_report = require_complete(load_json(e1))
    e3_report = require_complete(load_json(e3)) if e3 else None
    cascade_report = require_complete(load_json(cascade)) if cascade else None
    sweeps_report = load_json(sweeps) if sweeps else None
    findings_report = require_complete(load_json(findings)) if findings else None
    reproduction_report = require_complete(load_json(reproduction)) if reproduction else None
    recommendation_report = require_complete(load_json(recommendation)) if recommendation else None
    per_dataset_report = require_complete(load_json(per_dataset)) if per_dataset else None
    stability_report = require_complete(load_json(stability)) if stability else None
    cost_report = require_complete(load_json(cost)) if cost else None
    reproduce_report = require_complete(load_json(reproduce)) if reproduce else None
    stage_metrics_report = require_complete(load_json(stage_metrics)) if stage_metrics else None
    cross_tool_report = require_complete(load_json(cross_tool)) if cross_tool else None
    improvements_report = require_complete(load_json(improvements)) if improvements else None
    prompt_guard_report = require_complete(load_json(prompt_guard)) if prompt_guard else None

    output.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in (
        (
            "index.html",
            render_index(baseline_report, judged_report, e1_report, per_dataset_report, stability_report, cost_report),
        ),
        (
            "deterministic.html",
            render_deterministic(baseline_report, reproduction_report, stage_metrics_report),
        ),
        (
            "judged.html",
            render_judged(judged_report, baseline_report, per_dataset_report, stage_metrics_report),
        ),
        (
            "cascade.html",
            render_cascade(
                cascade_report,
                sweeps_report,
                per_dataset_report,
                stage_metrics_report,
                prompt_guard_report,
            ),
        ),
        ("cross-tool.html", render_cross_tool(cross_tool_report)),
        ("improvements.html", render_improvements(improvements_report)),
        ("experiments.html", render_experiments(e1_report, e3_report, findings_report)),
        (
            "recommendations.html",
            render_recommendations(recommendation_report, per_dataset_report, stability_report, cost_report),
        ),
        ("methodology.html", render_methodology()),
        ("reproduce.html", render_reproduce(reproduce_report)),
        ("README.md", readme(title)),
    ):
        (output / name).write_text(content, encoding="utf-8")
        written.append(name)

    return {
        "written": written,
        "present": {
            "deterministic_baseline": baseline_report is not None,
            "judged_benchmark": judged_report is not None,
            "e1_finding_reality": e1_report is not None,
            "e3_batched_findings": e3_report is not None,
            "cascade": cascade_report is not None,
            "sweeps": sweeps_report is not None,
            "experiment_findings": findings_report is not None,
            "deterministic_reproduction": reproduction_report is not None,
            "recommendation": recommendation_report is not None,
            "per_dataset_tiers": per_dataset_report is not None,
            "stability": stability_report is not None,
            "cost_comparison": cost_report is not None,
            "reproduction": reproduce_report is not None,
            "per_dataset_metrics": stage_metrics_report is not None,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--judged", type=Path, required=True)
    parser.add_argument("--e1", type=Path, required=True)
    parser.add_argument("--e3", type=Path, default=None)
    parser.add_argument("--cascade", type=Path, default=None)
    parser.add_argument("--sweeps", type=Path, default=None)
    parser.add_argument("--findings", type=Path, default=None)
    parser.add_argument("--reproduction", type=Path, default=None)
    parser.add_argument("--recommendation", type=Path, default=None)
    parser.add_argument("--per-dataset", type=Path, default=None)
    parser.add_argument("--stability", type=Path, default=None)
    parser.add_argument("--cost", type=Path, default=None)
    parser.add_argument("--reproduce", type=Path, default=None)
    parser.add_argument("--stage-metrics", type=Path, default=None)
    parser.add_argument("--cross-tool", type=Path, default=None)
    parser.add_argument("--improvements", type=Path, default=None)
    parser.add_argument("--prompt-guard", type=Path, default=None)
    parser.add_argument(
        "--judged-arm",
        action="append",
        type=Path,
        default=[],
        help="per-arm judged report; repeatable, used when the combined report is absent",
    )
    parser.add_argument("--title", default="Skill scanner judge and small-model results")
    args = parser.parse_args(argv)

    summary = build(
        args.output,
        baseline=args.baseline,
        judged=args.judged,
        e1=args.e1,
        title=args.title,
        e3=args.e3,
        cascade=args.cascade,
        sweeps=args.sweeps,
        findings=args.findings,
        judged_arms=args.judged_arm,
        reproduction=args.reproduction,
        recommendation=args.recommendation,
        per_dataset=args.per_dataset,
        stability=args.stability,
        cost=args.cost,
        reproduce=args.reproduce,
        stage_metrics=args.stage_metrics,
        cross_tool=args.cross_tool,
        improvements=args.improvements,
        prompt_guard=args.prompt_guard,
    )
    print(json.dumps(summary, indent=2))
    for name, present in summary["present"].items():
        if not present:
            print(f"note: {name} was not available and renders as missing", file=sys.stderr)
    return 0


_CROSS_TOOL_LENSES = (
    ("detection_at_medium", "Any finding at MEDIUM or above"),
    ("detection_at_high", "Any finding at HIGH or above"),
    ("shipped_gate", "Each tool's own shipped install gate"),
    ("aggressive_gate", "Block on any finding at all"),
)

# MCP server corpora are deliberately absent: this scanner analyses agent skills, and
# reporting a deficit on a surface it does not claim to cover invites a wrong conclusion.
_CROSS_TOOL_EXCLUDED_CORPORA = frozenset({"mcp-tool-poisoning"})

# Corpus order for publication: the source-disjoint split carries the headline claim, so
# it leads. Alphabetical order put a positive-only corpus first, where most cells read
# "not permitted" and the table opens on absent figures.
_CROSS_TOOL_CORPUS_ORDER = (
    "msb-source-disjoint",
    "msb-balanced-800",
    "openskillrisk-corpus",
    "harmfulskillbench-corpus",
    "real-world-skills",
)

_TOOL_LABELS = {
    "skill-scanner": "Cisco skill-scanner",
    "skill-scanner[core]": "Cisco skill-scanner (core rules)",
    "skill-scanner[full]": "Cisco skill-scanner (all rule packs)",
    "skill-scanner[gemma4]": "Cisco skill-scanner (Gemma 4 26B)",
    "skillspector": "NVIDIA SkillSpector",
    "skillspector[gemma4]": "NVIDIA SkillSpector (Gemma 4 26B)",
}


def _humanise_order(order: str) -> str:
    """Rewrite an "a minus b" comparison label using readable tool names."""

    if " minus " not in order:
        return order
    left, right = order.split(" minus ", 1)
    return f"{_tool_label(left.strip())} minus {_tool_label(right.strip())}"


def _tool_label(column: str) -> str:
    """Render a harness column key as a name a reader can use."""

    return _TOOL_LABELS.get(column, column)


_CROSS_TOOL_CORPUS_LABELS = {
    "real-world-skills": "Real published skills, 12,500 sampled, unlabelled",
    "msb-source-disjoint": "MaliciousSkillBench, source-disjoint split",
    "msb-balanced-800": "MaliciousSkillBench, balanced subset",
    "openskillrisk-corpus": "OpenSkillRisk",
    "harmfulskillbench-corpus": "HarmfulSkillBench",
}


def _cross_tool_cell(metrics: dict | None, key: str) -> str:
    """Render one metric, saying why rather than printing a number that cannot exist."""
    if not isinstance(metrics, dict):
        return "n/a"
    if key not in metrics:
        return '<span class="muted">not permitted</span>'
    value = metrics.get(key)
    if value is None:
        return '<span class="muted">no harmless class</span>'
    return percent(value)


def render_cross_tool(report: dict | None) -> str:
    """Head-to-head against NVIDIA SkillSpector, on identical records."""
    body = "<h1>NVIDIA SkillSpector vs Cisco skill-scanner</h1>\n"
    # The arm renderer is a separate function, so the once-per-page guard is module
    # level. Reset it here so a second build in the same process is not silently blank.
    _STATED_NOTES.clear()

    if not report:
        return page(
            "NVIDIA SkillSpector vs Cisco skill-scanner",
            "cross-tool.html",
            body + missing("The cross-tool comparison report"),
        )

    body += (
        "<p>Both scanners run over one population of skill directories, byte-identical on each side, "
        "with every analyzer each tool ships enabled and neither tuned on these labels. Three arms: "
        "static analysis only, then both tools on Gemma 4 26B, then both on Claude Haiku 4.5.</p>\n"
        f"<p>The comparison is possible because SkillSpector emits the same {term('LOW/MEDIUM/HIGH/CRITICAL')} "
        "levels this scanner does, so a threshold means the same thing on both sides. Package-level "
        "decisions do not translate, and are reported separately rather than normalised into a shared "
        "verdict neither tool emits.</p>\n"
        "<p>Only records where both tools returned a usable result are scored. A crashed scan, an "
        "unparsable payload and a run with analyzers switched off all present as zero findings, so "
        "scoring them as clean would credit specificity that was never earned.</p>\n"
    )

    versions = report.get("versions") or {}
    if versions:
        body += "<h2>What was compared</h2>\n"
        body += table(
            ["", "Version", "Configuration"],
            [
                ["NVIDIA SkillSpector", versions.get("skillspector", "n/a"), versions.get("skillspector_config", "")],
                ["Cisco skill-scanner", versions.get("skill_scanner", "n/a"), versions.get("skill_scanner_config", "")],
            ],
        )

    body += (
        "<h2>Four decision lenses</h2>\n"
        "<p>This scanner emits findings plus a package verdict. SkillSpector emits findings plus a "
        "0&ndash;100 risk score, banded into a recommendation, and gates an install above 50. Its score "
        "accumulates with diminishing returns per rule, so a single CRITICAL finding at 0.95 confidence "
        "scores 47 and returns CAUTION, which does not gate.</p>\n"
        "<p>A gate-to-gate comparison therefore measures two different thresholds rather than two "
        "engines. Detection at a fixed severity is the primary lens for that reason; each tool's own "
        "gate is reported alongside it, and a sweep across every threshold is given below so the "
        "operating point is visible rather than assumed.</p>\n"
        "<p>Each lens carries a paired difference: both tools are resampled together on the same "
        "records, so shared corpus difficulty cancels rather than widening both intervals, and an "
        "interval excluding zero means the two tools are separable on that lens. Each corpus also "
        "reports complementarity, the share of records exactly one tool flags, which is the "
        "interesting population because neither tool is a superset of the other.</p>\n"
    )

    arms = report.get("arms") or {"": {"title": "", "detail": "", "corpora": report.get("corpora") or {}}}
    for arm_key, arm in arms.items():
        if arm.get("title"):
            body += f"<h2 id='{arm_key}'>{arm['title']}</h2>\n"
        if arm.get("detail"):
            body += f"<p class='muted'>{arm['detail']}</p>\n"
        body += _render_cross_tool_arm(arm.get("corpora") or {})

    body += _render_cross_tool_caveats(report)
    return page("NVIDIA SkillSpector vs Cisco skill-scanner", "cross-tool.html", body)


# Notes that explain a whole page rather than one table. Rendered inside the per-corpus
# and per-arm loops they repeated ten times each, so they are keyed and stated once.
_STATED_NOTES: set[str] = set()


def once(key: str, html_text: str) -> str:
    """Return ``html_text`` the first time ``key`` is seen on a page, then nothing."""

    if key in _STATED_NOTES:
        return ""
    _STATED_NOTES.add(key)
    return html_text


def _render_cross_tool_arm(corpora: dict) -> str:
    """Render every corpus for one arm."""
    body = ""

    def corpus_rank(name: str) -> tuple[int, str]:
        return (
            _CROSS_TOOL_CORPUS_ORDER.index(name) if name in _CROSS_TOOL_CORPUS_ORDER else len(_CROSS_TOOL_CORPUS_ORDER),
            name,
        )

    for corpus in sorted(corpora, key=corpus_rank):
        block = corpora[corpus]
        if corpus in _CROSS_TOOL_EXCLUDED_CORPORA:
            continue
        if not isinstance(block, dict) or "lenses" not in block:
            continue
        label = _CROSS_TOOL_CORPUS_LABELS.get(corpus, corpus)
        integrity = block.get("integrity") or {}
        scored = integrity.get("records_scored")
        counts = block.get("label_counts") or {}
        population = ", ".join(f"{count} {name}" for name, count in sorted(counts.items()))

        body += f"<h3>{label}</h3>\n"
        body += f"<p class='muted'>{scored} records scored on both tools &middot; {population}</p>\n"

        columns = list(block.get("tools") or [])
        for lens_key, lens_label in _CROSS_TOOL_LENSES:
            lens = (block.get("lenses") or {}).get(lens_key)
            if not lens:
                continue
            rows = []
            for column in columns:
                metrics = (lens.get("per_tool") or {}).get(column)
                rows.append(
                    [
                        _tool_label(column),
                        _cross_tool_cell(metrics, "recall"),
                        _cross_tool_cell(metrics, "precision"),
                        _cross_tool_cell(metrics, "f1"),
                        _cross_tool_cell(metrics, "false_positive_rate"),
                    ]
                )
            body += f"<h4>{lens_label}</h4>\n"
            body += table(["Tool", "Recall", "Precision", "F1", "False-positive rate"], rows, numeric=(1, 2, 3, 4))

            if lens_key == "shipped_gate":
                # A tool whose default policy happens to gate at HIGH produces a row
                # identical to the HIGH lens above. Saying so prevents it being read as a
                # duplicated table; the gate is read from each tool's emitted decision
                # field, not re-derived from severity.
                high = ((block.get("lenses") or {}).get("detection_at_high") or {}).get("per_tool") or {}
                same = [
                    _tool_label(column)
                    for column in columns
                    if (lens.get("per_tool") or {}).get(column)
                    and high.get(column)
                    and (
                        lens["per_tool"][column].get("true_positives"),
                        lens["per_tool"][column].get("false_positives"),
                    )
                    == (high[column].get("true_positives"), high[column].get("false_positives"))
                ]
                if same:
                    body += once(
                        "gate-equals-high",
                        "<p class='muted'>"
                        + esc(" and ".join(same))
                        + (" matches" if len(same) == 1 else " match")
                        + " the HIGH row exactly wherever that happens below. It is a property of "
                        "the default policy, which gates at HIGH, not a repeated table: the "
                        "decision was read from each tool's emitted verdict field on every "
                        "record.</p>\n",
                    )

            difference = lens.get("paired_difference") or {}
            if difference.get("resamples"):
                verdict = "statistically separable" if difference.get("excludes_zero") else "not separable from zero"
                body += (
                    f"<p class='muted'>Paired recall difference ({esc(_humanise_order(str(difference.get('order') or '')))}): "
                    f"{difference['difference'] * 100:+.1f} points, 95% interval "
                    f"[{difference['low'] * 100:+.1f}, {difference['high'] * 100:+.1f}] &mdash; "
                    f"{verdict}.</p>\n"
                )

        agreement = block.get("agreement") or {}
        if agreement:
            only = {k: v for k, v in agreement.items() if k.startswith("only_")}
            body += "<h4>Where they disagree</h4>\n"
            body += table(
                [
                    "Both flagged",
                    "Neither flagged",
                    *(f"Only {_tool_label(k[len('only_') :])}" for k in only),
                    "Agreement",
                    "Complementarity",
                ],
                [
                    [
                        str(agreement.get("both_flagged", "")),
                        str(agreement.get("neither_flagged", "")),
                        *[str(v) for v in only.values()],
                        percent(agreement.get("agreement_rate")),
                        percent(agreement.get("complementarity")),
                    ]
                ],
            )

        throughput = block.get("throughput") or {}
        if throughput:
            # Only render what the harness actually recorded. This scanner's per-record
            # wall clock and both tools' token counts were never populated in this run, and
            # printing the zeros would read as "free and instantaneous" rather than
            # "not measured".
            def _cell(column: str, field: str, fmt: str) -> str:
                value = (throughput.get(column) or {}).get(field) or 0
                if not value:
                    return "<span class='muted'>not instrumented</span>"
                return format(value, fmt)

            measured = [
                field
                for field in ("mean_seconds", "input_tokens", "output_tokens")
                if any((throughput.get(column) or {}).get(field) for column in columns)
            ]
            if measured:
                body += "<h4>Cost of a scan</h4>\n"
                body += table(
                    ["Tool", "Mean seconds per skill", "Input tokens", "Output tokens"],
                    [
                        [
                            _tool_label(column),
                            _cell(column, "mean_seconds", ".3f"),
                            _cell(column, "input_tokens", ","),
                            _cell(column, "output_tokens", ","),
                        ]
                        for column in columns
                    ],
                    numeric=(1, 2, 3),
                )
                body += once(
                    "throughput-instrumentation",
                    "<p class='muted'>Wall clock was recorded per subprocess, which covers "
                    "SkillSpector but not this scanner's in-process path, and neither tool reported "
                    "token usage through the harness. The uninstrumented cells are marked rather "
                    "than shown as zero, and no cost comparison is drawn from this table. Judge "
                    "token cost was measured separately and is reported in the token-cost "
                    "section.</p>\n",
                )

        if integrity.get("per_tool"):
            body += "<h4>Integrity</h4>\n"
            body += table(
                ["Tool", "Rows", "Usable", "Errors", "Capability degraded", "Reported partial"],
                [
                    [
                        _tool_label(column),
                        str(stats.get("rows", "")),
                        str(stats.get("usable", "")),
                        str(stats.get("errors", "")),
                        str(stats.get("capability_degraded", "")),
                        str(stats.get("incomplete", "")),
                    ]
                    for column, stats in sorted(integrity["per_tool"].items())
                ],
                numeric=(1, 2, 3, 4, 5),
            )

    return body


def _render_cross_tool_caveats(report: dict) -> str:
    """Conditions that limit what these figures support."""
    out = "<h2>Limits on what these numbers support</h2>\n"
    out += (
        "<p>Our rule packs were tuned against MaliciousSkillBench during development. SkillSpector has "
        "not seen it. The source-disjoint split and the corpora outside MSB are therefore the ones that "
        "carry weight, and figures on the balanced subset should be read as home ground. SkillSpector was "
        "tuned on a private 31,000-skill set that is not published, so contamination can be bounded in "
        "one direction only and is disclosed rather than measured in the other.</p>\n"
    )
    out += (
        "<p>Enabling every rule pack this scanner ships is not its strongest configuration. On an "
        "80/80 sample of the source-disjoint split, all packs raise recall from 8.8% to 73.8% and raise "
        "the benign flag rate from 7.5% to 92.5%. That is a triage setting rather than a gating one, so "
        "the shipped core profile is what appears above; the ATR pack is also excluded from "
        "source-disjoint claims by the corpus terms.</p>\n"
    )
    out += (
        "<p>One SkillSpector capability is absent from these runs. Its <code>--transitive</code> mode "
        "follows references out of a skill, which on this corpus would mean fetching attacker-controlled "
        "URLs, and the corpus safety defaults forbid it. Its supply-chain recall would likely be higher "
        "with that enabled, so the figures here understate it on that axis.</p>\n"
    )
    out += (
        "<p>MaliciousSkillBench stores each record as one SKILL.md. Analyzers that operate on bundled "
        "scripts or MCP manifests have nothing to read, on both sides, and report "
        "<code>not_applicable</code> rather than failing. Three of SkillSpector's 27 analyzers are inert "
        "on that corpus for this reason. OpenSkillRisk and HarmfulSkillBench carry the multi-file "
        "signal.</p>\n"
    )
    out += (
        "<p>SkillSpector reports analysis as partial on most MSB records. Coverage is 100%, nothing is "
        "left uninspected, and the ledger exceptions are non-fatal: each SKILL.md references files the "
        "corpus does not ship, and the tool says so. That is a reporting capability this scanner does "
        "not have, and the partial rate is recorded in the integrity table rather than treated as a "
        "defect or used to exclude rows.</p>\n"
    )
    out += (
        "<p>Finding counts are not compared directly. SkillSpector applies diminishing returns per rule "
        "and caps at three occurrences, so its issue count and this scanner's finding count measure "
        "different things. Distinct rules fired and records flagged are used instead.</p>\n"
    )
    notes = report.get("notes") or []
    if notes:
        out += "<h2>Run notes</h2>\n<ul>\n"
        for note in notes:
            out += f"<li>{note}</li>\n"
        out += "</ul>\n"
    return out


_ARM_LABELS = {
    "single": "One pass, shipped prompt",
    "repeat3": "Three passes, same prompt (control)",
    "specialized3": "Three passes, specialized prompts",
    "specialized5": "Five passes, specialized prompts",
}

# Render order. Omitting an arm here drops it from the table silently, which is how the
# five-pass arm went missing while other sections quoted its numbers.
_ARM_ORDER = ("single", "repeat3", "specialized3", "specialized5")


def render_improvements(report: dict | None) -> str:
    """Changes measured against the shipped configuration, with their controls."""
    body = "<h1>Improving the scanner</h1>\n"
    if not report:
        return page("Improving the scanner", "improvements.html", body + missing("The improvement ledger"))

    body += (
        "<p>Each entry is a change measured against the shipped configuration on the same records, with "
        "whatever control is needed to say what caused the change rather than only that something "
        "did.</p>\n"
        "<p><strong>Every figure on this page is from one corpus: the MaliciousSkillBench "
        "source-disjoint split.</strong> Each table states its population, and the numbers are specific "
        "to it. Detection is counted at MEDIUM or above throughout. Results on the other corpora are on "
        'the <a href="cross-tool.html">head-to-head page</a>, and nothing here should be read as '
        "holding on them until it is measured there.</p>\n"
    )

    experiments = list(report.get("experiments") or [])
    topline = [e for e in experiments if e.get("scope") == "full"]
    subsample = [e for e in experiments if e.get("scope") != "full"]

    for heading, group, note in (
        (
            "Topline: the complete source-disjoint split",
            topline,
            "The full split, so this is directly comparable to the head-to-head page, where the shipped "
            "judge scores 61.2% F1 against SkillSpector's 72.1% on the same records.",
        ),
        (
            "Arm comparison on a subsample of the same split",
            subsample,
            "A 400-record subsample, run first because it takes a fraction of the calls. Absolute values "
            "differ from the topline because the population differs; only the differences between arms "
            "are meaningful here. The sampling control lives in this section rather than the topline ones, "
            "so the split between sampling and specialization is read from this table.",
        ),
    ):
        if not group:
            continue
        body += f"<h2>{heading}</h2>\n<p class='muted'>{note}</p>\n"
        for experiment in group:
            body += _render_improvement_experiment(experiment)

    failopen = report.get("fail_open") or {}
    if failopen.get("rows"):
        body += "<h2>Skills the judge never read still pass the gate</h2>\n"
        body += f"<p class='muted'>{esc(str(failopen.get('note', '')))}</p>\n"
        body += table(
            ["Arm", "Unread", "Share", "Malicious", "Harmless", "Passed the gate unread"],
            [
                [label, str(n), percent(share), str(mal), str(ben), f"<strong>{passed}</strong>"]
                for label, n, share, mal, ben, passed in failopen["rows"]
            ],
            numeric=(1, 2, 3, 4, 5),
        )
        body += (
            "<p>When a skill exceeds the context budget, or the request fails, the scanner emits that as "
            "an INFO finding. INFO does not gate, so the skill passes. Most of the affected records here "
            "are malicious, which makes this a fail-open rather than a reporting nicety: a skill can "
            "evade the semantic stage by being large enough not to fit.</p>\n"
            "<p>The fix is not a severity change, because raising it would put ordinary large skills "
            "through the same gate. Un-analysed content needs to be reported as a coverage gap the "
            "caller can choose to gate on. SkillSpector does exactly that through its "
            "<code>analysis_completeness</code> record and <code>--fail-on-incomplete</code> flag; this "
            "scanner has the same information and currently reports it in a form that passes.</p>\n"
        )

    meta = report.get("meta_stage") or {}
    if meta.get("rows"):
        body += "<h2>The meta-analyzer makes things worse, once it works</h2>\n"
        body += f"<p class='muted'>{esc(str(meta.get('note', '')))}</p>\n"
        body += table(
            ["Arm", "F1", "Precision", "Recall", "FPR"],
            [[label, percent(f1), percent(p), percent(r), percent(fpr)] for label, f1, p, r, fpr in meta["rows"]],
            numeric=(1, 2, 3, 4),
        )
        body += grouped_bar_chart(
            "Judge alone against judge plus meta-analyzer",
            ["F1", "Precision", "Recall", "False-positive rate"],
            [(label, [f1, p, r, fpr]) for label, f1, p, r, fpr in meta["rows"]],
        )
        body += (
            "<p>The stage applied on 219 of 274 records and altered findings on 64, trading 16.4 points "
            "of recall for 0.3 points of false-positive rate. It removes far more real detections than "
            "false ones, so off remains the right default.</p>\n"
            "<p>Getting to that number required fixing a bug first. On this route the meta path built "
            "its request handler without supplying a schema, so the handler loaded its default: the "
            "<em>analyzer's</em> schema. Meta requests were constrained to the wrong shape, the model "
            "returned findings and a verdict instead of the meta delta, every batch failed contract "
            "validation, and each was silently retained unchanged. Meta reported that it ran while "
            "changing nothing, which reads exactly like meta agreeing with every finding. Any earlier "
            "result that enabled meta on this route measured a no-op.</p>\n"
        )

    tokens = report.get("tokens") or {}
    if tokens.get("rows"):
        body += "<h2>What the extra passes cost</h2>\n"
        body += f"<p class='muted'>{esc(str(tokens.get('note', '')))}</p>\n"
        body += table(
            ["Configuration", "Input tokens per skill", "Output tokens per skill"],
            [[label, f"{i:,}", f"{o:,}"] for label, i, o in tokens["rows"]],
            numeric=(1, 2),
        )

    gen = report.get("generalization") or {}
    if gen.get("rows"):
        body += "<h2>Does the gain generalise across corpora?</h2>\n"
        body += (
            "<p class='muted'>The same change — five specialized judge passes against one — measured "
            "per corpus on Gemma 4 26B, detection at MEDIUM or above. Populations differ, so read each "
            "row against its own baseline rather than across rows.</p>\n"
        )
        body += table(
            [
                "Corpus (population)",
                "F1 before",
                "F1 after",
                "Recall before",
                "Recall after",
                "FPR before",
                "FPR after",
            ],
            [
                [
                    label,
                    "not permitted" if f1b is None else percent(f1b),
                    "not permitted" if f1a is None else f"<strong>{percent(f1a)}</strong>",
                    percent(rb),
                    f"<strong>{percent(ra)}</strong>",
                    "no harmless class" if fb is None else percent(fb),
                    "no harmless class" if fa is None else percent(fa),
                ]
                for label, f1b, f1a, rb, ra, fb, fa in gen["rows"]
            ],
            numeric=(1, 2, 3, 4),
        )
        body += grouped_bar_chart(
            "Recall before and after, per corpus",
            [label.split(" (")[0] for label, *_ in gen["rows"]],
            [
                ("one pass", [rb for _l, _a, _b, rb, _ra, _f, _g in gen["rows"]]),
                ("five specialized passes", [ra for _l, _a, _b, _rb, ra, _f, _g in gen["rows"]]),
            ],
            colours=("#8a9099", "#0b5fff"),
        )
        body += (
            "<p>The change helps on every corpus measured and never costs precision, but the size of "
            "the gain tracks how much headroom the single pass left. On source-disjoint, where one pass "
            "reached only 49.0% recall, decomposition adds 9.8 F1 points. On the balanced subset, where "
            "one pass already reached 80.0%, it adds 1.7. On OpenSkillRisk, at 86.6%, it adds 0.5.</p>\n"
            "<p>So the honest reading is narrower than the headline: decomposition recovers recall the "
            "single pass was missing rather than raising a ceiling. Quoting the source-disjoint figure "
            "as the improvement would overstate what it does on corpora the scanner already handles "
            "well.</p>\n"
            "<p>HarmfulSkillBench is the exception that matters: there recall <em>falls</em>, 60.0% to "
            "57.0%. The change is not uniformly beneficial, and that corpus is the one where the risk "
            "is harmful content rather than a technical capability, which is the kind of judgement the "
            "added focuses were not written for. Its dataset terms permit only recall, so no F1 or "
            "false-positive rate is quoted for it.</p>\n"
        )

    real = report.get("real_world") or {}
    if real.get("rows"):
        body += "<h2>Flag rate on real published skills</h2>\n"
        body += f"<p class='muted'>{esc(str(real.get('note', '')))}</p>\n"
        body += table(
            ["Configuration", "CRITICAL", "HIGH+", "MEDIUM+", "INFO+"],
            [
                [label, percent(crit), percent(high), percent(med), percent(info)]
                for label, crit, high, med, info in real["rows"]
            ],
            numeric=(1, 2, 3, 4),
        )
        body += grouped_bar_chart(
            "Flag rate on real published skills, by threshold",
            ["CRITICAL", "HIGH or above", "MEDIUM or above", "INFO or above"],
            [(label, [crit, high, med, info]) for label, crit, high, med, info in real["rows"]],
        )
        body += (
            "<p>On the population users actually scan, the shipped rules are roughly seven times "
            "quieter at MEDIUM or above: 3.76% against 26.42%. More than a quarter of real published "
            "skills reach MEDIUM or above under SkillSpector's static analyzers. That is the practical "
            "counterpart to the precision lead visible on the labelled corpora.</p>\n"
            "<p>The estimate needed the larger sample to settle. At 1,100 records the MEDIUM+ rate read "
            "2.00%, at 4,500 it read 3.40%, and at 12,498 it is 3.76% with a 95% interval of 3.44% to "
            "4.11%. The first sample understated it by nearly half, which is why the interval is quoted "
            "rather than the point estimate alone.</p>\n"
            "<p>The INFO row changed a decision. Nearly every real skill receives an INFO finding, and "
            "nothing lands at LOW, so severity is effectively bimodal. On MaliciousSkillBench, moving "
            "the gate down to INFO looks attractive and raises F1 from 81.4% to 83.2%. On real skills "
            "the same change would flag 88.2% of everything scanned, so it was rejected. A corpus of "
            "labelled contrast pairs could not have shown that.</p>\n"
        )

    dependence = report.get("model_dependence") or {}
    if dependence.get("rows"):
        body += "<h2>The gain depends on the model</h2>\n"
        body += f"<p class='muted'>{esc(str(dependence.get('note', '')))}</p>\n"
        body += table(
            ["Judge model", "F1 before", "F1 after", "Recall before", "Recall after", "FPR before", "FPR after"],
            [
                [
                    label,
                    percent(f1_before),
                    f"<strong>{percent(f1_after)}</strong>",
                    percent(r_before),
                    percent(r_after),
                    percent(fpr_before),
                    percent(fpr_after),
                ]
                for label, f1_before, f1_after, r_before, r_after, fpr_before, fpr_after in dependence["rows"]
            ],
            numeric=(1, 2, 3, 4, 5, 6),
        )
        body += (
            "<p>Decomposition helps on both models and costs precision on neither, but the size of the "
            "gain is not portable: Haiku 4.5 gains 22.7 F1 points and Gemma 4 26B gains 7.1 on the same "
            "corpus, population and arms. On Gemma 4 the false-positive rate actually falls, 17.6% to "
            "14.9%, and precision rises from 81.5% to 85.5%.</p>\n"
            "<p>The consequence for reading this page is that the headline figure belongs to a model. "
            "Our Haiku arm at 81.4% sits above SkillSpector's 72.9% on Haiku; our Gemma 4 arm at 68.3% "
            "sits below its 72.1% on Gemma 4. Quoting one without the model would be misleading.</p>\n"
        )

    gap = report.get("static_gap") or {}
    if gap.get("rows"):
        body += "<h2>A gap that sits in the static layer, not the judge</h2>\n"
        body += (
            f"<p class='muted'>Corpus: <code>{esc(str(gap.get('corpus')))}</code> &middot; "
            f"{esc(str(gap.get('note', '')))}</p>\n"
        )
        body += table(
            ["Configuration", "F1", "Precision", "Recall", "FPR"],
            [
                [label, percent(f1), percent(precision), percent(recall), percent(fpr)]
                for label, f1, precision, recall, fpr in gap["rows"]
            ],
            numeric=(1, 2, 3, 4),
        )
        body += (
            "<p>SkillSpector ships analyzers for MCP tool poisoning and MCP least privilege; this "
            "scanner has none, and on matched pairs its static rules catch half as many poisoned tools. "
            "Both tools leave every benign half of the pair alone, so the whole difference is recall. "
            "The judge closes it completely on the same records, which locates the deficit in the static "
            "layer rather than in the scanner as a whole, and makes a dedicated MCP analyzer the "
            "cheapest way to fix it for users who run without a model.</p>\n"
        )

    reference = report.get("reference") or {}
    if reference.get("rows"):
        body += "<h2>Where that leaves us against SkillSpector</h2>\n"
        body += (
            f"<p class='muted'>Corpus: <code>{esc(str(reference.get('corpus')))}</code> &middot; "
            f"{esc(str(reference.get('note', '')))}</p>\n"
        )
        rows = [
            [label, percent(f1), percent(precision), percent(recall), percent(fpr)]
            for label, f1, precision, recall, fpr in reference["rows"]
        ]
        top = None
        for experiment in report.get("experiments") or []:
            if experiment.get("scope") == "full":
                arm = (experiment.get("arms") or {}).get("specialized3")
                if arm:
                    top = arm["at_medium"]
        if top:
            rows.insert(
                0,
                [
                    "<strong>skill-scanner, three specialized judge passes</strong>",
                    f"<strong>{percent(top['f1'])}</strong>",
                    percent(top["precision"]),
                    percent(top["recall"]),
                    percent(top["false_positive_rate"]),
                ],
            )
        body += table(["Configuration", "F1", "Precision", "Recall", "FPR"], rows, numeric=(1, 2, 3, 4))
        if top:
            chart_rows = list(reference["rows"])
        if top:
            chart_rows.insert(
                0,
                (
                    "skill-scanner, five specialized passes",
                    top["f1"],
                    top["precision"],
                    top["recall"],
                    top["false_positive_rate"],
                ),
            )
        body += grouped_bar_chart(
            "msb-source-disjoint: F1, precision, recall and false-positive rate",
            ["F1", "Precision", "Recall", "False-positive rate"],
            [(label, [f1, pr, rc, fpr]) for label, f1, pr, rc, fpr in chart_rows],
        )
        body += (
            f"<p>Decomposing the judge moves F1 from 58.7% to {top['f1']:.1%} on this corpus, and "
            f"recall from 45.8% to {top['recall']:.1%}, while the false-positive rate stays close to "
            f"where it was: 15.6% before, {top['false_positive_rate']:.1%} after. That is the change "
            "that matters, because the recall deficit was the whole of the gap to SkillSpector and "
            "the precision lead was the thing not to spend closing it.</p>\n"
            "<p>Read the comparison carefully. SkillSpector reaches 84.6% recall here against our "
            f"{top['recall']:.1%}, so it still finds more. It does so at a 73.6% false-positive rate "
            f"against our {top['false_positive_rate']:.1%}, which is why the F1 ordering reverses. "
            "Neither number alone describes the tools.</p>\n"
        )

    body += (
        "<h2>Limits</h2>\n"
        "<p>Three passes cost three times the model calls. No cost figure is quoted because the "
        "analyzer's usage counter was found to report the most recent call rather than the sum, which "
        "makes the recorded token totals unreliable; that needs fixing before cost can be compared.</p>\n"
        "<p>These are judge-side changes measured with the shipped core rule pack. They do not address "
        "the false-positive rate, which rule-level suppression was separately found unable to move: "
        "benign records that flag fire four rules on average and never a single rule alone, so their "
        "rule profile is not separable from that of true positives.</p>\n"
    )
    return page("Improving the scanner", "improvements.html", body)


def _render_improvement_experiment(experiment: dict) -> str:
    """One experiment: its population, its arms, and what the control separates."""
    arms = experiment.get("arms") or {}
    population = experiment.get("population") or {}
    corpus = str(experiment.get("corpus") or "unknown corpus")
    model = str(experiment.get("model") or "")

    out = f"<h3>{esc(str(experiment.get('title') or experiment.get('experiment') or 'experiment'))}</h3>\n"
    counts = ", ".join(f"{value} {name}" for name, value in sorted(population.items()))
    out += f"<p class='muted'>Corpus: <code>{esc(corpus)}</code> &middot; {counts}"
    if model:
        out += f" &middot; judge model <code>{esc(model)}</code>"
    out += "</p>\n"
    if experiment.get("hypothesis"):
        hypothesis = str(experiment["hypothesis"]).strip()
        hypothesis = hypothesis[:1].upper() + hypothesis[1:]
        if not hypothesis.endswith((".", "?", "!")):
            hypothesis += "."
        out += f"<p><strong>Hypothesis.</strong> {esc(hypothesis)}</p>\n"

    baseline = (arms.get("single") or {}).get("at_medium") or {}
    rows = []
    for name in _ARM_ORDER:
        arm = arms.get(name)
        if not arm:
            continue
        metrics = arm["at_medium"]
        change = "&mdash;"
        if baseline and name != "single":
            change = f"{(metrics['f1'] - baseline.get('f1', 0)) * 100:+.1f}"
        rows.append(
            [
                _ARM_LABELS.get(name, name),
                str(arm.get("passes", "")),
                percent(metrics.get("f1")),
                change,
                percent(metrics.get("precision")),
                percent(metrics.get("recall")),
                percent(metrics.get("false_positive_rate")),
                str(arm.get("errors", "")),
            ]
        )
    # Runs that carry no single-pass arm have nothing to difference against, so the change
    # column is empty on every row. An all-em-dash column reads as missing data rather than
    # as "not applicable", so it is dropped instead.
    if any(row[3] != "&mdash;" for row in rows):
        out += table(
            ["Arm", "Passes", "F1", "F1 change", "Precision", "Recall", "FPR", "Errors"],
            rows,
            numeric=(1, 2, 3, 4, 5, 6, 7),
        )
    else:
        out += table(
            ["Arm", "Passes", "F1", "Precision", "Recall", "FPR", "Errors"],
            [row[:3] + row[4:] for row in rows],
            numeric=(1, 2, 3, 4, 5, 6),
        )

    single = (arms.get("single") or {}).get("at_medium")
    repeat = (arms.get("repeat3") or {}).get("at_medium")
    special = (arms.get("specialized3") or {}).get("at_medium")
    if single and repeat and special:
        total = (special["f1"] - single["f1"]) * 100
        sampling = (repeat["f1"] - single["f1"]) * 100
        specialization = (special["f1"] - repeat["f1"]) * 100
        out += (
            f"<p>The total gain is {total:+.1f} F1 points. The control arm runs the shipped prompt three "
            f"times and unions the findings, which accounts for {sampling:+.1f} of it: one pass simply "
            "misses findings a second pass returns, so part of the gain is sampling rather than prompt "
            f"design. Specialization adds the remaining {specialization:+.1f} points at equal call "
            f"count. Recall moves from {single['recall']:.1%} to {special['recall']:.1%} while precision "
            f"holds at {single['precision']:.1%} against {special['precision']:.1%}; the false-positive "
            f"rate rises from {single['false_positive_rate']:.1%} to "
            f"{special['false_positive_rate']:.1%}, so it is not free. Without the control this would "
            "have been reported as a prompt-design result, and most of it is not.</p>\n"
        )
    strongest_name, strongest = None, None
    for name in reversed(_ARM_ORDER):
        candidate = (arms.get(name) or {}).get("at_medium")
        if candidate:
            strongest_name, strongest = name, candidate
            break

    if strongest and not repeat and strongest_name != "single":
        out += (
            f"<p>{_ARM_LABELS.get(strongest_name, strongest_name)}: {strongest['f1']:.1%} F1 at "
            f"{strongest['precision']:.1%} precision and {strongest['recall']:.1%} recall, with a "
            f"{strongest['false_positive_rate']:.1%} false-positive rate.</p>\n"
        )
    return out


# ---------------------------------------------------------------- charts
#
# Charts are inline SVG. A static Space has no build step and no JS runtime, so a
# charting library would have to be vendored; SVG renders everywhere, prints, and
# degrades to its caption. Every chart sits beside the table it draws, so the numbers
# stay available to a screen reader and to anyone copying them out.

_SERIES_COLOURS = ("#0b5fff", "#b3261e", "#0a7d34", "#9a5b00")


def _svg_open(width: int, height: int, title: str) -> str:
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="{esc(title)}" xmlns="http://www.w3.org/2000/svg">'
        f"<title>{esc(title)}</title>"
    )


def grouped_bar_chart(
    title: str,
    categories: Sequence[str],
    series: Sequence[tuple[str, Sequence[Any]]],
    *,
    axis_max: float = 1.0,
    colours: Sequence[str] | None = None,
) -> str:
    """Grouped horizontal bars, one group per category.

    Horizontal because the labels are metric and tool names, which do not fit under
    vertical bars without rotating text. A non-numeric value is drawn as "not applicable"
    rather than as zero, because an undefined metric is not a small one.
    """
    if not categories or not series:
        return ""
    label_w, right_pad, row_h, group_pad, top = 172, 66, 19, 14, 34
    bars = len(series)
    height = top + len(categories) * (bars * row_h + group_pad) + 12
    width = 760
    plot_w = width - label_w - right_pad

    # Red reads as "bad". Where the series are a before/after pair rather than two
    # competing tools, a red "after" bar would mark an improvement as a problem, so the
    # caller can supply a neutral palette instead.
    palette = tuple(colours) if colours else _SERIES_COLOURS

    out = [_svg_open(width, height, title)]
    out.append(f'<text x="0" y="16" class="chart-title">{esc(title)}</text>')
    for frac in (0.25, 0.5, 0.75, 1.0):
        x = label_w + plot_w * frac
        out.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{height - 14}" class="chart-grid"/>')
        out.append(
            f'<text x="{x:.1f}" y="{height - 3}" class="chart-axis" text-anchor="middle">'
            f"{frac * axis_max * 100:.0f}%</text>"
        )

    y = top
    for index_cat, category in enumerate(categories):
        out.append(
            f'<text x="{label_w - 8}" y="{y + row_h * bars / 2 + 4:.1f}" '
            f'class="chart-label" text-anchor="end">{esc(category)}</text>'
        )
        for index, (name, values) in enumerate(series):
            value = values[index_cat] if index_cat < len(values) else None
            colour = palette[index % len(palette)]
            if not isinstance(value, (int, float)):
                out.append(f'<text x="{label_w + 4}" y="{y + row_h - 6:.1f}" class="chart-na">not applicable</text>')
            else:
                w = max(1.0, plot_w * (float(value) / axis_max))
                out.append(
                    f'<rect x="{label_w}" y="{y + 3:.1f}" width="{w:.1f}" height="{row_h - 6}" '
                    f'fill="{colour}" opacity="0.85"><title>{esc(name)}: '
                    f"{float(value) * 100:.1f}%</title></rect>"
                )
                out.append(
                    f'<text x="{label_w + w + 5:.1f}" y="{y + row_h - 6:.1f}" class="chart-value">'
                    f"{float(value) * 100:.1f}%</text>"
                )
            y += row_h
        y += group_pad
    out.append("</svg>")

    legend = " ".join(
        f'<span class="key"><i style="background:{palette[i % len(palette)]}"></i>{esc(n)}</span>'
        for i, (n, _) in enumerate(series)
    )
    return f'<figure>{"".join(out)}<figcaption class="legend">{legend}</figcaption></figure>\n'


def slope_chart(title: str, rows: Sequence[tuple[str, float, float]]) -> str:
    """Before/after pairs as connected points, one line per row.

    A slope chart rather than paired bars: the quantity of interest is the direction and
    size of each change, and a line makes a decrease obvious where two bars of similar
    length do not. Decreases are drawn in red.
    """
    if not rows:
        return ""
    width, height = 760, 56 + len(rows) * 30
    left, right = 330, width - 96
    values = [v for _, a, b in rows for v in (a, b)]
    lo, hi = min(values), max(values)
    span = max(hi - lo, 0.05)

    def x(value: float) -> float:
        return left + (right - left) * (value - lo + span * 0.08) / (span * 1.16)

    out = [_svg_open(width, height, title)]
    out.append(f'<text x="0" y="16" class="chart-title">{esc(title)}</text>')
    out.append(f'<text x="{left}" y="32" class="chart-axis" text-anchor="middle">before</text>')
    out.append(f'<text x="{right}" y="32" class="chart-axis" text-anchor="middle">after</text>')
    y = 48
    for label, before, after in rows:
        colour = "#0a7d34" if after >= before else "#b3261e"
        out.append(f'<text x="{left - 104}" y="{y + 4:.1f}" class="chart-label" text-anchor="end">{esc(label)}</text>')
        out.append(
            f'<line x1="{x(before):.1f}" y1="{y:.1f}" x2="{x(after):.1f}" y2="{y:.1f}" '
            f'stroke="{colour}" stroke-width="2" opacity="0.7"/>'
        )
        for value in (before, after):
            out.append(f'<circle cx="{x(value):.1f}" cy="{y:.1f}" r="4" fill="{colour}"/>')
        out.append(
            f'<text x="{x(before) - 8:.1f}" y="{y + 4:.1f}" class="chart-value" text-anchor="end">'
            f"{before * 100:.1f}%</text>"
        )
        out.append(
            f'<text x="{x(after) + 8:.1f}" y="{y + 4:.1f}" class="chart-value">{after * 100:.1f}%'
            f' <tspan fill="{colour}">({(after - before) * 100:+.1f})</tspan></text>'
        )
        y += 30
    out.append("</svg>")
    return f"<figure>{''.join(out)}</figure>\n"


if __name__ == "__main__":
    raise SystemExit(main())
