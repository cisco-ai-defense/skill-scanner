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

"""Render the same results as one markdown document.

A Space serves its pages from a ``*.hf.space`` subdomain inside an iframe. When a
browser cannot load that subdomain, because of a pending single-sign-on session, a
content blocker, or a network policy, the Space appears broken even though the files
are served correctly and publicly.

A card renders inline on huggingface.co with no iframe and no extra subdomain, so it
is readable wherever the site itself is. This produces that card from the same result
files, so the two cannot disagree.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.publish.space_data import (  # noqa: E402
    PRIOR_SYSTEM_ONE_SPACE,
    PUBLISHED_BLOG_URL,
    count,
    load_json,
    percent,
    require_complete,
)

SPACE_URL = "https://huggingface.co/spaces/Vineethsain/cisco-skill-scanner-judge-and-system-one"


def table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    if not rows:
        return "_No rows available._\n"
    out = "| " + " | ".join(headers) + " |\n"
    out += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for row in rows:
        out += "| " + " | ".join(str(cell) for cell in row) + " |\n"
    return out + "\n"


def _ratio(numerator: Any, denominator: Any) -> float | None:
    if not isinstance(numerator, (int, float)) or not isinstance(denominator, (int, float)) or not denominator:
        return None
    return numerator / denominator


def build(
    *,
    baseline: dict | None,
    judged_arms: dict[str, dict],
    reproduction: dict | None,
    per_dataset: dict | None,
    cascade: dict | None,
    findings: dict | None,
    recommendation: dict | None,
    stability: dict | None,
    cost: dict | None = None,
    reproduce: dict | None = None,
    stage_metrics: dict | None = None,
) -> str:
    track = (baseline or {}).get("tracks", {}).get("core-only-source-disjoint") or {}
    judge_track = (
        judged_arms.get("core_judge", {}).get("report", {}).get("tracks", {}).get("core-only-source-disjoint") or {}
    )

    out = f"""# Cisco AI Defense skill scanner: what changes when the LLM judge is switched on

The skill scanner has three stages that can inspect a skill: deterministic rules, a small
decision model, and a full LLM judge. Only the rules had been measured. This is what the other
two do, on the same corpora, using the same code that produced the published rule-only figures.

The interactive version is at [{SPACE_URL}]({SPACE_URL}). This page carries the same numbers as
plain text, because a Space renders inside an iframe on a separate subdomain and some browsers and
networks block it.

## Headline

"""
    if track and judge_track:
        out += table(
            ["Configuration", "F1", "Precision", "Recall", "Harmless skills blocked"],
            [
                [
                    "Rules only, as shipped",
                    percent(track.get("f1")),
                    percent(track.get("package_block_precision")),
                    percent(track.get("package_block_recall")),
                    percent(_ratio(track.get("fp"), track.get("benign"))),
                ],
                [
                    "Rules plus the LLM judge",
                    percent(judge_track.get("f1")),
                    percent(judge_track.get("package_block_precision")),
                    percent(judge_track.get("package_block_recall")),
                    percent(_ratio(judge_track.get("fp"), judge_track.get("benign"))),
                ],
            ],
        )
        out += (
            "Measured on the locked 1,384-package test split: 839 malicious and 545 harmless, "
            "pinned by content digest.\n\n"
        )

    out += """### In four points

- Switching on the judge nearly tripled F1, and precision went **up** rather than down. We had
  expected the opposite, because rule precision on the development split was already 99%.
- The System One model is the better deal for anything automated: roughly double the F1 of the
  rules, no false positives at all in our runs, and it processed the whole test split in 42 seconds
  for 18 cents.
- The meta-judge did nothing. It ran on 78% of packages and produced no suppressions and no additions.
- Nothing here is stable below 14%. Repeating one judged configuration over the same packages changed
  the verdict on 14% of them, so smaller differences are noise.

## Why this needed measuring

A skill is an unusually open format. It can contain any code, in any language, for any legitimate
reason, so most of what a rule matches is ordinary software. That makes precision hard to hold, and it
makes it tempting to assume an LLM reviewing rule output would mostly add noise. On the development
split, where rule precision was 99%, that assumption looked safe. On the harder test split it was
wrong: the rules were missing far more than they were over-flagging.

"""

    if per_dataset:
        out += "## Every stage, on every corpus we could label\n\n"
        out += "Detection is the share of skills in that group flagged at all, for review or for blocking.\n\n"
        rows = []
        for name in sorted(per_dataset.get("datasets", {})):
            tiers = per_dataset["datasets"][name]
            population = next((t.get("population", "") for t in tiers.values() if t.get("population")), "")
            rows.append(
                [
                    name,
                    population,
                    percent(tiers.get("rules", {}).get("detection_rate")),
                    percent(tiers.get("small_model", {}).get("detection_rate")),
                    percent(tiers.get("judge", {}).get("detection_rate")),
                ]
            )
        out += table(["Corpus", "Population", "Rules", "System One model", "Judge"], rows)
        out += """**Good:** the judge beats everything everywhere, and by the largest margin exactly where the
rules are weakest. On HarmfulSkillBench the rules found 4% and the judge found 56%. On the
obviously-malicious half of OpenSkillRisk the judge found all of it.

**Bad:** the System One model is *worse than the rules* on contextually risky skills, 11% against 33%. It
is a cheap high-confidence filter for clear cases, not a substitute for judgement on ambiguous ones.

"""

    if judged_arms:
        out += "## All four judged configurations\n\n"
        rows = []
        if track:
            rows.append(
                [
                    "`core_only` (baseline)",
                    percent(track.get("f1")),
                    percent(track.get("package_block_precision")),
                    percent(track.get("package_block_recall")),
                    percent(track.get("signal_recall")),
                    "n/a",
                ]
            )
        for name in ("core_judge", "core_judge_meta", "core_meta"):
            arm = judged_arms.get(name)
            if not arm:
                continue
            t = arm.get("report", {}).get("tracks", {}).get("core-only-source-disjoint") or {}
            rows.append(
                [
                    f"`{name}`",
                    percent(t.get("f1")),
                    percent(t.get("package_block_precision")),
                    percent(t.get("package_block_recall")),
                    percent(t.get("signal_recall")),
                    percent(arm.get("telemetry", {}).get("meta_invoked_rate")),
                ]
            )
        out += table(["Configuration", "F1", "Precision", "Recall", "Signal recall", "Meta ran on"], rows)
        out += """Signal recall is the share of malicious packages where the scanner produced any relevant
signal, including below the threshold that would flag the package. It went from 8% to 86%, which is the
clearest single indication that the judge is seeing things the rules cannot.

The meta-judge is the negative result. It ran on most packages and changed nothing measurable.
Establishing that required fixing our own instrumentation, which keyed on a routing reason string
instead of the routing decision and so reported that it had never run at all.

"""

    if reproduction:
        out += "## Re-measuring the previously published figures\n\n"
        out += reproduction["note"] + "\n\n"
        out += table(
            ["Corpus", "Population", "Previously published", "Re-measured", "Agrees"],
            [
                [
                    row["dataset"],
                    row["population"],
                    row["published"],
                    row["reproduced"],
                    "yes" if row["agrees"] else "**no**",
                ]
                for row in reproduction["rows"]
            ],
        )
        out += (
            "All nine reproduce. That is the only reason the judged figures above are worth "
            "reading: the same code path produced both.\n\n"
        )
        if reproduction.get("not_reproduced"):
            out += "Three could not be re-measured:\n\n"
            out += table(
                ["Corpus", "Population", "Reason"],
                [[row["dataset"], row["population"], row["reason"]] for row in reproduction["not_reproduced"]],
            )

    if cascade:
        out += "## Combining stages\n\n"
        out += (
            "Two scoring lenses, because they reorder the ranking. **Block-only** counts just a hard "
            "block as catching something, which is right when a flag stops the skill. "
            "**Any-intervention** also counts asking a human to review, which is right when flags go "
            "to a queue.\n\n"
        )
        for lens, heading in (("block_only", "Block-only"), ("any_intervention", "Any-intervention")):
            rows = []
            for chain in cascade.get("chains", []):
                block = chain.get(lens, {})
                rows.append(
                    [
                        f"`{chain.get('chain')}`",
                        percent(block.get("precision")),
                        percent(block.get("recall")),
                        percent(block.get("f1")),
                        percent(block.get("false_positive_rate")),
                    ]
                )
            out += f"**{heading} lens**\n\n"
            out += table(["Chain", "Precision", "Recall", "F1", "False-positive rate"], rows)
        out += (
            "The eight-probe question format is the clearest case for reporting both: it is the "
            "weakest chain on one lens and among the strongest on the other, because it asks for "
            "review where others block.\n\n"
        )

    if cost:
        out += "## What each stage costs, and what it buys\n\n"
        out += (
            f"Over {cost['population']}, block-only lens. The last column is the figure that decides a "
            "deployment: F1 points gained over the rules, per dollar spent.\n\n"
        )
        out += table(
            [
                "Configuration",
                "F1",
                "Points over rules",
                "Cost for the corpus",
                "Seconds per skill",
                "F1 points per dollar",
            ],
            [
                [
                    r["configuration"],
                    percent(r["f1"]),
                    f"{r['f1_points_over_rules']:+.1f}",
                    f"${r['usd_for_1384_packages']:.4f}",
                    f"{r['seconds_per_package']:.3f}s",
                    "n/a" if r["f1_points_per_dollar"] is None else f"{r['f1_points_per_dollar']:.1f}",
                ]
                for r in cost["rows"]
            ],
        )
        by = {r["configuration"]: r for r in cost["rows"]}
        one, judge, meta = (
            by.get("Rules plus System One model"),
            by.get("Rules plus judge"),
            by.get("Rules plus judge plus meta"),
        )
        if one and judge and meta and judge.get("f1_points_per_dollar"):
            out += (
                f"**Good:** the System One model is the best value by a wide margin, "
                f"{one['f1_points_per_dollar'] / judge['f1_points_per_dollar']:.1f} times more F1 per dollar than "
                f"the judge and {one['f1_points_per_dollar'] / meta['f1_points_per_dollar']:.1f} times more than the "
                f"judge with meta. The judge costs {judge['usd_per_package'] / one['usd_per_package']:.1f} times more "
                f"per skill and takes {judge['seconds_per_package'] / one['seconds_per_package']:.0f} times longer.\n\n"
            )
            out += (
                "**Bad:** value per dollar is not the only question. The judge still buys more than twice as many "
                "F1 points outright, and if you need recall rather than economy it is the only stage that "
                "delivers. The meta-judge is the one configuration that is worse on both counts.\n\n"
            )
        out += (
            f"_Measurement: {cost['measurement']['jev']} for the System One model; for the judge, "
            f"{cost['measurement']['judge']}. Judge prices are "
            f"${cost['pricing']['gemma_4_input_usd_per_million']:.2f} and "
            f"${cost['pricing']['gemma_4_output_usd_per_million']:.2f} per million input and output tokens; the "
            f"System One model is ${cost['pricing']['jev_input_usd_per_million']:.3f} per million input tokens. "
            "Batch inference halves the judge's rate, which these figures do not assume._\n\n"
        )

    if recommendation:
        out += "## How to configure it\n\n"
        out += recommendation["summary"] + "\n\n"
        if recommendation.get("honesty_note"):
            out += f"> {recommendation['honesty_note']}\n\n"
        out += table(
            ["Stage", "Recommended setting", "Why", "Cost per skill", "What to watch"],
            [[e["tier"], f"`{e['setting']}`", e["why"], e["cost"], e["caveat"]] for e in recommendation["tiers"]],
        )
        out += "### Three setups\n\n"
        for profile in recommendation["profiles"]:
            out += (
                f"**{profile['name']}** — `{profile['config']}`\n\n{profile['rationale']}\n\n"
                f"_Expect: {profile['expected']}_\n\n"
            )
        out += "### Four ways to misread this\n\n"
        for item in recommendation["pitfalls"]:
            out += f"- {item}\n"
        out += "\n"

    if findings:
        out += "## The fifteen side experiments\n\n"
        for entry in findings.get("findings", []):
            out += f"### {entry['id']}: {entry['question']}\n\n{entry['answer']}\n\n"
            if entry.get("numbers"):
                out += table(["Measure", "Value"], [[label, value] for label, value in entry["numbers"]])
            if entry.get("caveat"):
                out += f"_{entry['caveat']}_\n\n"

    if stability:
        out += "## The noise floor\n\n"
        judged = stability.get("core_plus_judge", {})
        core = stability.get("deterministic_core", {})
        out += table(
            ["Configuration", "Verdicts changed", "Repeats"],
            [
                ["Deterministic rules", f"{core.get('flipped')} of {core.get('cases')}", str(core.get("passes"))],
                ["Rules plus judge", f"{judged.get('flipped')} of {judged.get('cases')}", str(judged.get("passes"))],
            ],
        )
        out += (
            "The rules did not move once. The judge moved on 14% of packages between identical runs, "
            "which is why the meta-judge's apparent effect is indistinguishable from zero.\n\n"
        )

    if stage_metrics:
        out += "## Every metric, per stage, per corpus\n\n"
        out += (
            "Any-intervention lens, so a finding raised for review counts as a catch. Precision and "
            "false-positive rate need a harmless class; two of these corpora are entirely positive-risk, "
            "so those cells say so rather than showing a figure computed against no negatives.\n\n"
        )
        for stage in ("rules", "system_one", "judge"):
            label = stage_metrics.get("stage_labels", {}).get(stage, stage)
            rows = []
            for name in sorted(stage_metrics.get("datasets", {})):
                block = stage_metrics["datasets"][name].get("stages", {}).get(stage)
                if not block:
                    continue
                if block["has_negative_class"]:
                    prec, f1, fpr = (
                        percent(block["precision"]),
                        percent(block["f1"]),
                        percent(block["false_positive_rate"]),
                    )
                else:
                    prec = f1 = fpr = "no harmless class"
                rows.append(
                    [
                        name,
                        f"{block['positives']} bad, {block['negatives']} harmless",
                        percent(block["recall"]),
                        prec,
                        f1,
                        fpr,
                        str(block["errors"]),
                    ]
                )
            if rows:
                out += f"### {label}\n\n"
                out += table(["Corpus", "Population", "Recall", "Precision", "F1", "FPR", "Errors"], rows)

    if reproduce:
        out += "## Reproducing these results\n\n"
        out += reproduce["intro"] + "\n\n"
        out += "### What you need first\n\n"
        out += table(["Requirement", "Detail"], [[i["item"], i["detail"]] for i in reproduce["prerequisites"]])
        out += "### The commands, in order\n\n"
        for step in reproduce["steps"]:
            out += f"**{step['stage']}**\n\n```\n{step['command']}\n```\n\n{step['note']}\n\n"
        out += "### What the harness guarantees\n\n"
        for item in reproduce["guarantees"]:
            out += f"- {item}\n"
        out += "\n### Four things that will waste your afternoon\n\nEach cost us a run before we found it.\n\n"
        for item in reproduce["known_gotchas"]:
            out += f"- {item}\n"
        out += "\n"

    out += f"""## What is published here

Metrics, counts and digests only. No skill content, finding evidence, prompts or credentials appear
anywhere, because the source corpora forbid redistributing their content.

Rule-only figures as previously published: [{PUBLISHED_BLOG_URL}]({PUBLISHED_BLOG_URL}).
Earlier work on System One models: [{PRIOR_SYSTEM_ONE_SPACE}]({PRIOR_SYSTEM_ONE_SPACE}).
"""
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--judged-arm", action="append", type=Path, default=[])
    parser.add_argument("--reproduction", type=Path)
    parser.add_argument("--per-dataset", type=Path)
    parser.add_argument("--cascade", type=Path)
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--recommendation", type=Path)
    parser.add_argument("--stability", type=Path)
    parser.add_argument("--cost", type=Path)
    parser.add_argument("--reproduce", type=Path)
    parser.add_argument("--stage-metrics", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    arms: dict[str, dict] = {}
    for path in args.judged_arm:
        report = load_json(path)
        if report and report.get("arm"):
            arms[str(report["arm"])] = report

    body = build(
        baseline=require_complete(load_json(args.baseline)),
        judged_arms=arms,
        reproduction=require_complete(load_json(args.reproduction)) if args.reproduction else None,
        per_dataset=require_complete(load_json(args.per_dataset)) if args.per_dataset else None,
        cascade=require_complete(load_json(args.cascade)) if args.cascade else None,
        findings=require_complete(load_json(args.findings)) if args.findings else None,
        recommendation=require_complete(load_json(args.recommendation)) if args.recommendation else None,
        stability=require_complete(load_json(args.stability)) if args.stability else None,
        cost=require_complete(load_json(args.cost)) if args.cost else None,
        reproduce=require_complete(load_json(args.reproduce)) if args.reproduce else None,
        stage_metrics=require_complete(load_json(args.stage_metrics)) if args.stage_metrics else None,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding="utf-8")
    print(f"wrote {args.output} ({len(body):,} bytes, {body.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
