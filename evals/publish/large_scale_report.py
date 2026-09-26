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

"""Assemble the large-scale report the Space renders, from metric files only, and refuse leaks.

    python evals/publish/large_scale_report.py --output results/large-scale.json \\
        --prior large-scale-local-gpu.json --analysis f2.json --labelled f4.json \\
        --overlay f3.json --jev-screen c4.json --judge-prompt a2.json --profiles a3.json

Every input is aggregate: counts, rates, rule identifiers, thresholds, model coefficients. The
report is still checked before it is written, because it is published: a host path, a record
identifier, a credential-shaped string or a free-text field that could carry corpus content or a
model's rationale stops the build. The corpora forbid redistributing their content, and a
per-record identifier is the first step to re-identifying it.

Alongside the report, ``--sums`` writes a ``SHA256SUMS`` file so a reader can check the published
file is the one the page was rendered from.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]

CASCADE_SELECTION = (
    "selected on MaliciousSkillBench train/validation for the prompt this corpus was judged with: keep at least 97% "
    "of the judge's recall at the lowest false-positive rate"
)
NOTES = (
    "Judge figures on the labelled splits are single pass, core rules, meta-analyzer off, detection at MEDIUM or above.",
    "The first cascade threshold was selected on half of the frozen test split; it is re-selected on "
    "train/validation, and those figures supersede it.",
    "The deterministic rules and the judge prompt were designed on MaliciousSkillBench train/validation and real "
    "skills; the frozen test split was scored once and used to design nothing in the later passes.",
    "Unlabelled populations give flag rates, which bound the false-positive rate from above.",
    "An early deterministic run read 100% false-positive rate because copying the corpus from macOS added an "
    "AppleDouble '._SKILL.md' to every record, which the scanner correctly flagged; the sidecars were removed.",
    "Endpoint protection quarantined malicious SKILL.md files from local copies of the benchmark, silently turning "
    "malicious records into empty ones; every figure here was produced on a Linux analysis host.",
)
# Anything matching these must not be published.
_REFUSED = (
    (re.compile(r"/(?:home|Users|teamspace|root|tmp|var|private)/"), "a host path"),
    (re.compile(r"\bg_\d{8}\b|\bb\d{5}/|\bgit_\d{6}\b"), "a gitskills record identifier"),
    (re.compile(r"\b(?:hf_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})"), "a credential"),
    (re.compile(r'"(?:description|title|evidence|snippet|rationale|explanation|content)"\s*:'), "a free-text field"),
)


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.expanduser().read_text(encoding="utf-8"))


def refuse_leaks(text: str) -> None:
    for pattern, what in _REFUSED:
        match = pattern.search(text)
        if match:
            raise SystemExit(f"refusing to publish: {what} ({match.group(0)!r})")


def scrub_failure_kinds(kinds: Sequence[Sequence[Any]]) -> list[list[Any]]:
    """An error message can end with the record's path; the kind is what comes before it."""
    return [[re.sub(r":\s*/\S*$", "", str(kind)), n] for kind, n in kinds]


def git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(_REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def assemble(args: argparse.Namespace) -> dict[str, Any]:
    prior = load(args.prior)
    full = load(args.analysis)
    labelled = load(args.labelled)
    full.pop("store", None)
    judge = full.setdefault("judge", {})
    judge["failure_kinds"] = scrub_failure_kinds(judge.get("failure_kinds") or [])
    full["labelled_ab"] = {
        key: labelled[key] for key in ("base_commit", "final_commit", "arm", "corpora") if key in labelled
    }
    if labelled.get("recall_cost"):
        full["recall_cost"] = labelled["recall_cost"]
    if labelled.get("presets"):
        full["packs_trainval"] = labelled["presets"]
    if args.overlay:
        full["composition_check"] = load(args.overlay)
    full.setdefault("cascade", {})["selection"] = CASCADE_SELECTION

    report = {
        key: prior[key] for key in ("experiment", "hardware", "judge", "cascade", "deterministic") if key in prior
    }
    report.setdefault("experiment", "large-scale-local-gpu")
    if "cascade" in report:
        report["cascade"] = dict(report["cascade"], selected_on_test_members=True)
    report["full"] = full
    report["jev_screen"] = load(args.jev_screen)
    report["judge_prompt"] = load(args.judge_prompt)
    if args.profiles:
        report["profiles"] = load(args.profiles).get("profiles") or []
    report["notes"] = list(NOTES)
    report["provenance"] = {
        "scanner_commits": {
            "shipped": args.shipped_commit,
            "first_pass": args.first_pass_commit,
            "final": args.final_commit,
        },
        "report_builder_commit": git_commit(),
        "published_as": args.published_as,
    }
    report["published_as"] = args.published_as
    report["digests_file"] = args.sums_name
    report["blocking"] = False
    report["complete"] = True
    return report


def readme(report: dict[str, Any], digest: str) -> str:
    """What the published results folder holds, and what it deliberately does not."""
    commits = (report.get("provenance") or {}).get("scanner_commits") or {}
    name = Path(report["published_as"]).name
    shipped, first_pass, final = (commits.get(key) for key in ("shipped", "first_pass", "final"))
    return f"""# Published results

`{name}` is the machine-readable form of the Space's large-scale page:
every usable skill in the gitskills corpus scanned by the deterministic analyzers with three
scanner trees (shipped `{shipped}`, first tuning pass `{first_pass}`,
final `{final}`), read by the LLM judge and screened by OpenJev, plus the labelled
MaliciousSkillBench, OpenSkillRisk, HarmfulSkillBench and MCP tool-poisoning comparisons.

SHA-256: `{digest}` (also in `SHA256SUMS`).

## What it contains

Counts, rates with 95% Wilson intervals, rule identifiers, thresholds and the OpenJev logistic
screen's coefficients. Every figure on the page is computed from it.

## What it does not contain, by design

- No skill content, file path, record identifier or finding text.
- No prompt, model output or model rationale.
- No credential, token or host detail.

The build refuses to write the file if any of these appears. The source corpora forbid
redistributing their content, so only derived metrics are published.

## Terms that bind these figures

- MaliciousSkillBench: figures are from the core rule pack; nothing here was selected on its frozen
  test split except where a section says so and supersedes it.
- HarmfulSkillBench: flag rates only; its terms forbid F1 and false-positive-rate claims.
- OpenJev: research use (CC BY-NC); only metrics about the model are published.
- gitskills and the other real-skill samples are unlabelled: a flag rate bounds the false-positive
  rate from above rather than measuring it.

The scripts that produce every number are in `evals/experiments/` and `evals/publish/` of
https://github.com/cisco-ai-defense/skill-scanner.
"""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--prior", type=Path, required=True, help="the earlier local-GPU sections of the report")
    parser.add_argument("--analysis", type=Path, required=True, help="f2_full_corpus_analysis output")
    parser.add_argument("--labelled", type=Path, required=True, help="f4_labelled_ab output")
    parser.add_argument("--overlay", type=Path, default=None, help="f3_overlay_check output")
    parser.add_argument("--jev-screen", type=Path, required=True, help="c4_openjev_screen output")
    parser.add_argument("--judge-prompt", type=Path, required=True, help="a2_judge_prompt_caps output")
    parser.add_argument("--profiles", type=Path, default=None, help="a3_recommended_profiles output")
    parser.add_argument("--shipped-commit", default="5b696a1")
    parser.add_argument("--first-pass-commit", default="f3a42f3")
    parser.add_argument("--final-commit", default="9c08673")
    parser.add_argument("--published-as", default="results/large-scale.json")
    parser.add_argument("--sums-name", default="results/SHA256SUMS")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sums", type=Path, default=None, help="write a SHA256SUMS file for the output here")
    parser.add_argument("--readme", type=Path, default=None, help="write a README for the published folder here")
    args = parser.parse_args(argv)

    report = assemble(args)
    text = json.dumps(report, indent=1)
    refuse_leaks(text)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if args.sums:
        args.sums.write_text(f"{digest}  {Path(args.published_as).name}\n", encoding="utf-8")
    if args.readme:
        notes = readme(report, digest)
        refuse_leaks(notes)
        args.readme.write_text(notes, encoding="utf-8")
    print(f"wrote {args.output} ({len(text):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
