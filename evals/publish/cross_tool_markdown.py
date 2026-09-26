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

"""Render the cross-tool comparison as markdown.

The HTML pages are served from ``*.static.hf.space``, which measured one success in
five connection attempts from the author's network while ``huggingface.co`` answered
every time.  A result nobody can open is not published, so the same figures are
mirrored into markdown, which renders directly from ``huggingface.co`` and does not
depend on the Space's iframe host.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

LENSES = (
    ("detection_at_medium", "Any finding at MEDIUM or above"),
    ("detection_at_high", "Any finding at HIGH or above"),
    ("shipped_gate", "Each tool's own shipped install gate"),
    ("aggressive_gate", "Block on any finding at all"),
)

# Harness column keys encode tool plus profile or model. That is right for a data file
# and wrong for a published table.
TOOL_LABELS = {
    "skill-scanner": "Cisco skill-scanner",
    "skill-scanner[core]": "Cisco skill-scanner (core rules)",
    "skill-scanner[full]": "Cisco skill-scanner (all rule packs)",
    "skill-scanner[gemma4]": "Cisco skill-scanner (Gemma 4 26B)",
    "skillspector": "NVIDIA SkillSpector",
    "skillspector[gemma4]": "NVIDIA SkillSpector (Gemma 4 26B)",
}

CORPUS_ORDER = (
    "msb-source-disjoint",
    "msb-balanced-800",
    "openskillrisk-corpus",
    "harmfulskillbench-corpus",
    "real-world-skills",
)

CORPUS_LABELS = {
    "msb-source-disjoint": "MaliciousSkillBench, source-disjoint split",
    "msb-balanced-800": "MaliciousSkillBench, balanced subset",
    "openskillrisk-corpus": "OpenSkillRisk",
    "harmfulskillbench-corpus": "HarmfulSkillBench",
}


def pct(metrics: dict[str, Any], key: str) -> str:
    if key not in metrics:
        return "not permitted"
    value = metrics.get(key)
    if value is None:
        return "no harmless class"
    return f"{float(value) * 100:.1f}%"


def table(headers: list[str], rows: list[list[str]]) -> str:
    out = "| " + " | ".join(headers) + " |\n"
    out += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for row in rows:
        out += "| " + " | ".join(row) + " |\n"
    return out + "\n"


def render(report: dict[str, Any]) -> str:
    out = "# NVIDIA SkillSpector vs Cisco skill-scanner\n\n"
    out += (
        "Both scanners run over one population of skill directories, byte-identical on each side, with "
        "every analyzer each tool ships enabled and neither tuned on these labels. Three arms: static "
        "analysis only, then both tools on Gemma 4 26B, then both on Claude Haiku 4.5.\n\n"
        "The comparison is possible because SkillSpector emits the same `LOW/MEDIUM/HIGH/CRITICAL` "
        "levels this scanner does, so a threshold means the same thing on both sides. Package-level "
        "decisions do not translate, and are reported separately rather than normalised into a shared "
        "verdict neither tool emits.\n\n"
        "Only records where both tools returned a usable result are scored. A crashed scan, an "
        "unparsable payload and a run with analyzers switched off all present as zero findings, so "
        "scoring them as clean would credit specificity that was never earned.\n\n"
    )

    versions = report.get("versions") or {}
    if versions:
        out += "## What was compared\n\n"
        out += table(
            ["", "Version", "Configuration"],
            [
                ["NVIDIA SkillSpector", versions.get("skillspector", ""), versions.get("skillspector_config", "")],
                ["Cisco skill-scanner", versions.get("skill_scanner", ""), versions.get("skill_scanner_config", "")],
            ],
        )

    out += (
        "## Four decision lenses\n\n"
        "This scanner emits findings plus a package verdict. SkillSpector emits findings plus a 0-100 "
        "risk score, banded into a recommendation, and gates an install above 50. Its score accumulates "
        "with diminishing returns per rule, so a single CRITICAL finding at 0.95 confidence scores 47 "
        "and returns CAUTION, which does not gate.\n\n"
        "A gate-to-gate comparison therefore measures two different thresholds rather than two engines. "
        "Detection at a fixed severity is the primary lens for that reason; each tool's own gate is "
        "reported alongside it.\n\n"
    )

    for arm_key, arm in (report.get("arms") or {}).items():
        out += f"## {arm.get('title', arm_key)}\n\n"
        if arm.get("detail"):
            out += f"{arm['detail']}\n\n"

        def corpus_rank(name: str) -> tuple[int, str]:
            return (CORPUS_ORDER.index(name) if name in CORPUS_ORDER else len(CORPUS_ORDER), name)

        for corpus in sorted(arm.get("corpora") or {}, key=corpus_rank):
            block = (arm.get("corpora") or {})[corpus]
            # MCP server corpora are out of scope: this scanner analyses agent skills.
            if corpus in {"mcp-tool-poisoning"}:
                continue
            if not isinstance(block, dict) or "lenses" not in block:
                continue
            integrity = block.get("integrity") or {}
            counts = block.get("label_counts") or {}
            population = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
            out += f"### {CORPUS_LABELS.get(corpus, corpus)}\n\n"
            out += f"{integrity.get('records_scored')} records scored on both tools — {population}\n\n"

            columns = list(block.get("tools") or [])
            rows = []
            for lens_key, lens_label in LENSES:
                lens = (block.get("lenses") or {}).get(lens_key)
                if not lens:
                    continue
                for column in columns:
                    metrics = (lens.get("per_tool") or {}).get(column) or {}
                    rows.append(
                        [
                            lens_label,
                            TOOL_LABELS.get(column, column),
                            pct(metrics, "recall"),
                            pct(metrics, "precision"),
                            pct(metrics, "f1"),
                            pct(metrics, "false_positive_rate"),
                        ]
                    )
            out += table(["Lens", "Tool", "Recall", "Precision", "F1", "False-positive rate"], rows)

            for lens_key, lens_label in LENSES:
                lens = (block.get("lenses") or {}).get(lens_key)
                difference = (lens or {}).get("paired_difference") or {}
                if difference.get("resamples"):
                    verdict = "separable" if difference.get("excludes_zero") else "not separable from zero"
                    out += (
                        f"- **{lens_label}** paired recall difference ({difference.get('order')}): "
                        f"{difference['difference'] * 100:+.1f} points, 95% CI "
                        f"[{difference['low'] * 100:+.1f}, {difference['high'] * 100:+.1f}] — {verdict}.\n"
                    )
            out += "\n"

            agreement = block.get("agreement") or {}
            if agreement:
                only = {k: v for k, v in agreement.items() if k.startswith("only_")}
                out += (
                    f"Agreement at MEDIUM: {agreement.get('agreement_rate', 0) * 100:.1f}%; "
                    f"complementarity {agreement.get('complementarity', 0) * 100:.1f}% "
                    f"({', '.join(f'{k} {v}' for k, v in only.items())}). Complementarity is the share "
                    "of records exactly one tool flags: neither tool is a superset of the other.\n\n"
                )

            throughput = block.get("throughput") or {}
            if throughput:
                out += table(
                    ["Tool", "Mean seconds per skill", "Input tokens", "Output tokens"],
                    [
                        [
                            TOOL_LABELS.get(column, column),
                            f"{(throughput.get(column) or {}).get('mean_seconds', 0):.3f}",
                            f"{(throughput.get(column) or {}).get('input_tokens', 0):,}",
                            f"{(throughput.get(column) or {}).get('output_tokens', 0):,}",
                        ]
                        for column in columns
                    ],
                )

            if integrity.get("per_tool"):
                out += table(
                    ["Tool", "Rows", "Usable", "Errors", "Capability degraded", "Reported partial"],
                    [
                        [
                            TOOL_LABELS.get(column, column),
                            str(stats.get("rows", "")),
                            str(stats.get("usable", "")),
                            str(stats.get("errors", "")),
                            str(stats.get("capability_degraded", "")),
                            str(stats.get("incomplete", "")),
                        ]
                        for column, stats in sorted(integrity["per_tool"].items())
                    ],
                )

    out += "## Limits on what these numbers support\n\n"
    out += (
        "Our rule packs were tuned against MaliciousSkillBench during development. SkillSpector has not "
        "seen it. The source-disjoint split and the corpora outside MSB are therefore the ones that "
        "carry weight, and figures on the balanced subset should be read as home ground. SkillSpector "
        "was tuned on a private 31,000-skill set that is not published, so contamination can be bounded "
        "in one direction only and is disclosed rather than measured in the other.\n\n"
        "Enabling every rule pack this scanner ships is not its strongest configuration. On an 80/80 "
        "sample of the source-disjoint split, all packs raise recall from 8.8% to 73.8% and raise the "
        "benign flag rate from 7.5% to 92.5%. That is a triage setting rather than a gating one, so the "
        "shipped core profile is what appears above; the ATR pack is also excluded from source-disjoint "
        "claims by the corpus terms.\n\n"
        "One SkillSpector capability is absent from these runs. Its `--transitive` mode follows "
        "references out of a skill, which on this corpus would mean fetching attacker-controlled URLs, "
        "and the corpus safety defaults forbid it. Its supply-chain recall would likely be higher with "
        "that enabled, so the figures here understate it on that axis.\n\n"
        "MaliciousSkillBench stores each record as one SKILL.md. Analyzers that operate on bundled "
        "scripts or MCP manifests have nothing to read, on both sides, and report `not_applicable` "
        "rather than failing. Three of SkillSpector's 27 analyzers are inert on that corpus for this "
        "reason. OpenSkillRisk and HarmfulSkillBench carry the multi-file signal.\n\n"
        "SkillSpector reports analysis as partial on most MSB records. Coverage is 100%, nothing is left "
        "uninspected, and the ledger exceptions are non-fatal: each SKILL.md references files the corpus "
        "does not ship, and the tool says so. That is a reporting capability this scanner does not have, "
        "and the partial rate is recorded in the integrity table rather than treated as a defect or used "
        "to exclude rows.\n\n"
        "Finding counts are not compared directly. SkillSpector applies diminishing returns per rule and "
        "caps at three occurrences, so its issue count and this scanner's finding count measure "
        "different things. Distinct rules fired and records flagged are used instead.\n\n"
    )

    notes = report.get("notes") or []
    if notes:
        out += "## Run notes\n\n"
        for note in notes:
            out += (
                f"- {note}\n".replace("<em>", "*")
                .replace("</em>", "*")
                .replace("<code>", "`")
                .replace("</code>", "`")
                .replace("&ldquo;", '"')
                .replace("&rdquo;", '"')
            )
        out += "\n"
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cross-tool", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    report = json.loads(args.cross_tool.read_text())
    if not report.get("complete"):
        raise SystemExit("cross-tool report is not marked complete")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    body = render(report)
    args.output.write_text(body, encoding="utf-8")
    print(f"wrote {args.output} ({len(body):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
