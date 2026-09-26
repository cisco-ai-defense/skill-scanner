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

"""Collapse experiment reports into one findings list for publication.

Each experiment answers a question, so the published form is the question, the
answer, and the number that supports it.  A report whose file is missing is
recorded as not run rather than omitted, because a reader cannot tell the
difference between "we did not measure this" and "we measured nothing" unless the
page says which.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _e1(report: dict[str, Any]) -> dict[str, Any]:
    results = report["results"]
    primary = results["primary"]["overall"]
    independent = results["independent"]["overall"]
    agreement = results["agreement"]
    return {
        "id": "E1",
        "question": "What fraction of deterministic findings are actually real?",
        "answer": (
            "Two adjudicators from different vendors differ by roughly fivefold with non-overlapping "
            "intervals, and chance-corrected agreement is near zero, so no single model can serve as "
            "the arbiter."
        ),
        "numbers": [
            ["Primary judged real", f"{primary['real_rate'] * 100:.1f}%"],
            ["Independent judged real", f"{independent['real_rate'] * 100:.1f}%"],
            ["Raw agreement", f"{agreement['raw_agreement'] * 100:.1f}%"],
            ["Chance-corrected agreement", f"{agreement['cohen_kappa']:.3f}"],
            ["Findings adjudicated", str(report["findings_sampled"])],
        ],
        "caveat": "The corpus is unlabeled real-world content, so this estimates a rate rather than establishing truth.",
    }


def _e3(report: dict[str, Any]) -> dict[str, Any]:
    paired = report["paired_with_e1"]
    return {
        "id": "E3",
        "question": "Does one batched request per skill match one request per finding?",
        "answer": (
            "The batched form reproduces the aggregate rate at a third of the requests, but agrees with "
            "the per-finding arm no better than chance on which findings are real. Sound for an estimate, "
            "unsound for a per-finding suppression decision."
        ),
        "numbers": [
            ["Requests", f"{report['requests_batched']} against {report['requests_per_finding']}"],
            ["Fewer requests", f"{report['request_reduction'] * 100:.1f}%"],
            ["Batched real rate", f"{report['batched_real_rate'] * 100:.1f}%"],
            ["Agreement with per-finding", f"{paired['cohen_kappa']:.3f}"],
        ],
    }


def _e7_e13(report: dict[str, Any]) -> list[dict[str, Any]]:
    arms = report["arms"]
    primary = arms.get("jev_K7_SQ2") or next(iter(arms.values()))
    probes = arms.get("jev_K7_SQ3")
    best = primary["e7_best_zero_loss"]
    mined = primary["e13_rule_candidates"]
    out = [
        {
            "id": "E7",
            "question": "Can false positives be removed by gating on the model's own confidence?",
            "answer": (
                "No. The disposition format already produces no false positives, so there is nothing to "
                "gate, and on the eight-probe format no confidence floor removes a false positive without "
                "also losing a true detection. The model's confidence does not separate its own mistakes."
            ),
            "numbers": [
                ["Best zero-loss floor", f"{best['threshold']:.2f}"],
                ["False positives removed", str(best["false_positives_removed"])],
            ],
        },
        {
            "id": "E13",
            "question": "Which model decisions deserve to become deterministic rules?",
            "answer": (
                "A large share of what the model confidently blocks has no matching rule, so the same "
                "judgement is re-derived on every call. On the disposition format every single such case "
                "is genuinely malicious, which makes it a clean rule-authoring queue."
            ),
            "numbers": [
                ["Confident blocks considered", str(mined["confident_blocks_considered"])],
                ["Blocks the rules allowed", str(mined["confident_blocks_rules_allowed"])],
                ["Share the rules missed", f"{mined['share_rules_missed'] * 100:.1f}%"],
                ["Malicious share of the queue", f"{mined['true_positive_share_of_queue'] * 100:.1f}%"],
            ],
            "caveat": "Candidates and evidence only. Rules stay human-authored.",
        },
    ]
    if probes:
        out[0]["numbers"].append(
            [
                "Eight-probe false-positive rate",
                f"{probes['e7_best_zero_loss']['false_positive_rate_after'] * 100:.1f}%",
            ]
        )
    return out


def _e10(report: dict[str, Any]) -> dict[str, Any]:
    after = report["after_realistic_edits"]
    return {
        "id": "E10",
        "question": "Does remembering a decision save work on a re-scan?",
        "answer": report["verdict"],
        "numbers": [
            ["Existing identity reuse after edits", f"{after['existing_finding_id_reuse'] * 100:.1f}%"],
            ["Drift-tolerant fingerprint reuse", f"{after['fingerprint_reuse'] * 100:.1f}%"],
            ["Identical re-scan reuse", f"{report['identical_rescan']['fingerprint_reuse'] * 100:.1f}%"],
            ["Skills compared", str(report["skills_compared"])],
        ],
        "caveat": report["perturbation"],
    }


def _e8(report: dict[str, Any]) -> dict[str, Any]:
    by_name = {chain["chain"]: chain for chain in report["chains"]}
    best = max(report["chains"], key=lambda chain: chain["any_intervention"]["f1"])
    rows = [
        [name.replace("instr_", ""), f"{chain['any_intervention']['f1'] * 100:.1f}%"]
        for name, chain in sorted(by_name.items())
    ]
    return {
        "id": "E8",
        "question": "Does telling the model to judge by detected content type beat a generic prompt?",
        "answer": (
            "Yes. Naming the instruction surface explicitly and directing the model to judge each file by its "
            "detected content type rather than its name gave the best any-intervention F1 and the highest "
            "recall, at no cost to precision."
        ),
        "numbers": [
            *[["Any-intervention F1, " + label, value] for label, value in rows],
            ["Best variant", best["chain"].replace("instr_", "")],
            ["Its recall", f"{best['any_intervention']['recall'] * 100:.1f}%"],
            ["Its false-positive rate", f"{best['any_intervention']['false_positive_rate'] * 100:.1f}%"],
        ],
        "caveat": "The generic variant still wins on the block-only lens, because it blocks where the others confirm.",
    }


def _e11(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "E11",
        "question": "Can a dismissal be generalised into a safe suppression rule?",
        "answer": (
            "Rarely, at this granularity. Most candidates would have silenced real detections: replaying them "
            "over a labelled population rejected the large majority for suppressing findings on malicious "
            "packages at HIGH or CRITICAL severity. Only a small fraction of benign findings can be suppressed "
            "safely by rule and file role, so useful generalisation needs finer typed facts than that."
        ),
        "numbers": [
            ["Candidates considered", str(report["candidates_considered"])],
            ["Accepted", str(report["candidates_accepted"])],
            [
                "Rejected for touching protected findings",
                str(report["candidates_rejected_for_touching_protected_findings"]),
            ],
            ["Benign findings safely suppressible", f"{report['benign_findings_suppressible_share'] * 100:.1f}%"],
            ["Protected findings suppressed", str(report["protected_findings_suppressed_by_accepted"])],
        ],
        "caveat": report["note"],
    }


def _e14(report: dict[str, Any]) -> dict[str, Any]:
    baseline = report["baseline"]
    tuned = report["combined"]
    return {
        "id": "E14",
        "question": "Can the policy be fitted automatically without losing a detection?",
        "answer": (
            "Barely. Only one single-rule change both improved F1 and left every package caught on a HIGH or "
            "CRITICAL malicious finding still caught, and the gain was within rounding. Meanwhile a large "
            "share of the tempting changes would have dropped a real detection, which is exactly the trade a "
            "tuner optimising F1 alone would have made."
        ),
        "numbers": [
            ["Baseline F1", f"{baseline['f1'] * 100:.1f}%"],
            ["Tuned F1", f"{tuned['f1'] * 100:.1f}%"],
            ["Change in F1", f"{report['combined_delta_f1'] * 100:+.1f} points"],
            ["Changes examined", str(report["changes_examined"])],
            ["Changes accepted", str(report["changes_accepted"])],
            ["Rejected for losing a detection", str(report["changes_rejected_for_losing_a_protected_detection"])],
        ],
        "caveat": report["note"],
    }


def _e4(report: dict[str, Any]) -> dict[str, Any]:
    by_chain = {chain["chain"]: chain for chain in report["chains"]}
    three = by_chain.get("rules_then_jev_then_judge", {}).get("any_intervention", {})
    small = by_chain.get("rules_then_jev", {}).get("any_intervention", {})
    rules = by_chain.get("rules_only", {}).get("any_intervention", {})
    f1_share = (small.get("f1", 0) / three["f1"] * 100) if three.get("f1") else 0.0
    fpr_share = (
        small.get("false_positive_rate", 0) / three["false_positive_rate"] * 100
        if three.get("false_positive_rate")
        else 0.0
    )
    return {
        "id": "E4",
        "question": "Which links in the cascade earn their cost?",
        "answer": (
            "The full chain of rules, System One model and judge scores highest on both lenses, but the judge buys "
            "its recall with an order-of-magnitude rise in false positives. Stopping after the System One model "
            "retains almost all of the quality at a fraction of the false-positive rate, which is the better "
            "trade when most content is legitimate. The System One model also absorbs some of the judge's calls."
        ),
        "numbers": [
            ["Rules alone, any-intervention F1", f"{rules.get('f1', 0) * 100:.1f}%"],
            ["Rules then System One model, F1", f"{small.get('f1', 0) * 100:.1f}%"],
            ["Full three-tier chain, F1", f"{three.get('f1', 0) * 100:.1f}%"],
            ["Rules then System One model, false-positive rate", f"{small.get('false_positive_rate', 0) * 100:.1f}%"],
            ["Full three-tier chain, false-positive rate", f"{three.get('false_positive_rate', 0) * 100:.1f}%"],
            ["Quality retained by stopping early", f"{f1_share:.0f}%"],
            ["False-positive rate retained", f"{fpr_share:.0f}%"],
        ],
        "caveat": (
            "Scored on 400 malicious and 400 benign packages drawn from the whole snapshot, so these are not "
            "directly comparable to the published test-partition figures."
        ),
    }


def _e15(report: dict[str, Any]) -> dict[str, Any]:
    reuse = report["reuse"]
    safety = report["safety"]
    return {
        "id": "E15",
        "question": "Does a stateful scanner work, and is it safe?",
        "answer": (
            "It works, and the first version was unsafe. A drift-tolerant fingerprint means one dismissal "
            "generalises across the corpus, which is the point of it: a bounded set of model dismissals hid "
            "most findings on a re-scan. But unrestricted, that generalisation also silenced dozens of HIGH "
            "and CRITICAL detections on malicious packages. Adding a ceiling, so a model dismissal can never "
            "suppress a high-severity finding while a human review still can, keeps almost all of the saving "
            "and loses none of those detections."
        ),
        "numbers": [
            ["Findings before", str(reuse["findings_before"])],
            ["Findings after reuse", str(reuse["findings_after"])],
            ["Decision reuse rate", f"{reuse['reuse_rate'] * 100:.0f}%"],
            ["Findings suppressed", str(reuse["suppressed"])],
            ["High-severity detections lost, before the ceiling", "56"],
            [
                "High-severity detections lost, after the ceiling",
                str(safety["protected_findings_suppressed_on_malicious"]),
            ],
            ["Empty store leaves output unchanged", "yes" if report["empty_store_leaves_output_unchanged"] else "no"],
        ],
        "caveat": report["note"],
    }


def _e16(report: dict[str, Any]) -> dict[str, Any]:
    core = report["deterministic_core"]
    judged = report["core_plus_judge"]
    return {
        "id": "E16",
        "question": "How far must two judged arms differ before the difference is real?",
        "answer": (
            "Further than most of the differences worth arguing about. Repeating one configuration over the "
            "same packages changed the package verdict on a substantial minority of them, almost always "
            "between allowing and asking for review. The deterministic core did not move at all, so the "
            "variation is the model rather than the harness. Any gap between two judged arms smaller than "
            "this cannot be distinguished from run-to-run noise, which is what makes the meta-judge's "
            "apparent effect indistinguishable from nothing."
        ),
        "numbers": [
            ["Deterministic core, verdicts changed", f"{core['flipped']}/{core['cases']}"],
            ["Core plus judge, verdicts changed", f"{judged['flipped']}/{judged['cases']}"],
            ["Noise floor", f"{judged['flip_rate'] * 100:.1f}%"],
            ["Repeats", str(judged["passes"])],
            ["Most common change", "allow to confirm"],
        ],
        "caveat": report["note"],
    }


def _osr(report: dict[str, Any]) -> dict[str, Any]:
    arms = report["arms"]
    det = arms.get("deterministic", {})
    judge = arms.get("core_plus_judge", {})

    def rate(arm: dict, group: str) -> str:
        return f"{arm.get(group, {}).get('detection_rate', 0) * 100:.1f}%"

    return {
        "id": "OpenSkillRisk",
        "question": "What does the judge do on a corpus built to separate clear risk from contextual risk?",
        "answer": (
            "It closes almost the whole gap on the clear cases and behaves as it should on the ambiguous "
            "ones. On skills the corpus authors labelled obviously malicious, the rules caught under a third "
            "and the judge caught every one. On skills labelled contextually risky, where the right answer "
            "genuinely depends on context, it caught a large majority but not all, which is the discrimination "
            "you would want rather than a flat improvement."
        ),
        "numbers": [
            ["Obviously malicious skills", str(det.get("obviously_malicious", {}).get("skills", 0))],
            ["Rules alone", rate(det, "obviously_malicious")],
            ["Rules plus judge", rate(judge, "obviously_malicious")],
            ["Contextually risky skills", str(det.get("contextually_risky", {}).get("skills", 0))],
            ["Rules alone, contextual", rate(det, "contextually_risky")],
            ["Rules plus judge, contextual", rate(judge, "contextually_risky")],
        ],
        "caveat": (
            "Both groups are positive-risk, so this corpus supports a detection rate and not a "
            "false-positive rate. Its licence permits exactly that use."
        ),
    }


def _hsb(report: dict[str, Any]) -> dict[str, Any]:
    arms = report["arms"]
    det = arms.get("deterministic", {})
    judge = arms.get("core_plus_judge", {})
    return {
        "id": "HarmfulSkillBench",
        "question": "What does the judge do on a corpus the rules almost entirely miss?",
        "answer": (
            "It finds most of what the rules cannot see. The deterministic core flagged a few percent of these "
            "skills, matching the figure published for it, and adding the judge raised detection more than "
            "tenfold. This corpus is the clearest case for the judge earning its cost, because the rules have "
            "almost no purchase on it at all."
        ),
        "numbers": [
            ["Skills", str(det.get("skills", 0))],
            ["Rules alone, detection", f"{det.get('detection_rate', 0) * 100:.1f}%"],
            ["Rules plus judge, detection", f"{judge.get('detection_rate', 0) * 100:.1f}%"],
            ["Rules alone, block rate", f"{det.get('block_rate', 0) * 100:.1f}%"],
            ["Rules plus judge, block rate", f"{judge.get('block_rate', 0) * 100:.1f}%"],
        ],
        "caveat": report["note"],
    }


def _e12() -> dict[str, Any]:
    return {
        "id": "E12",
        "question": "Can an organisation express a policy the generic rules cannot?",
        "answer": (
            "Yes. Every other domain control is an allowlist that demotes; a denied-destination section "
            "was added that promotes instead, matching on the registrable domain at label boundaries so a "
            "lookalike domain is not flagged. Asked to generalise one observed host, the model widened it "
            "to the wildcard form, named the owning entity, and identified a sibling domain the same entity "
            "owns that a naive registrable-domain extraction would have missed."
        ),
        "numbers": [
            ["Observed host", "api.paloalto.com"],
            ["Generalised entry", "*.paloalto.com"],
            ["Sibling domain found", "paloaltonetworks.com"],
        ],
        "caveat": "Inert unless an organisation configures it, so the default scan is unchanged. Proposals go to review, never applied silently.",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--e1", type=Path)
    parser.add_argument("--e3", type=Path)
    parser.add_argument("--e7-e13", type=Path)
    parser.add_argument("--e10", type=Path)
    parser.add_argument("--e8", type=Path)
    parser.add_argument("--e11", type=Path)
    parser.add_argument("--e14", type=Path)
    parser.add_argument("--e4", type=Path)
    parser.add_argument("--e15", type=Path)
    parser.add_argument("--e16", type=Path)
    parser.add_argument("--openskillrisk", type=Path)
    parser.add_argument("--harmfulskillbench", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    def load(path: Path | None) -> dict[str, Any] | None:
        if path is None or not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return None if data.get("complete") is False else data

    findings: list[dict[str, Any]] = []
    not_run: list[str] = []

    for label, path, builder in (
        ("E1", args.e1, _e1),
        ("E3", args.e3, _e3),
        ("E10", args.e10, _e10),
        ("E8", args.e8, _e8),
        ("E11", args.e11, _e11),
        ("E14", args.e14, _e14),
        ("E4", args.e4, _e4),
        ("E15", args.e15, _e15),
        ("E16", args.e16, _e16),
    ):
        report = load(path)
        if report is None:
            not_run.append(label)
            continue
        findings.append(builder(report))

    combined = load(args.e7_e13)
    if combined is None:
        not_run.extend(["E7", "E13"])
    else:
        findings.extend(_e7_e13(combined))

    findings.append(_e12())
    findings.append(
        {
            "id": "E9",
            "question": "Does the self-hosted System One model match the hosted one?",
            "answer": (
                "Not answered, and the reason is infrastructure rather than the model. The self-hosted model "
                "does speak the same protocol, and on a clear case it agreed with the hosted one at lower "
                "confidence. But a full sweep returned usable answers for only a sixth of requests, and a "
                "single real request later timed out entirely at two minutes. The serving process was also "
                "replaced partway through by a different one on the same ports. Every usable answer was "
                "'allow', which does not match the hosted model's behaviour on the same packages and is a "
                "further sign the deployment rather than the model was being measured. Publishing any figure "
                "from that would describe the machine, so none is published."
            ),
            "numbers": [
                ["Requests attempted", "800"],
                ["Usable answers", "134 (17%)"],
                ["Provider failures", "666 (83%)"],
                ["Median latency of a usable answer", "8.6 seconds"],
                ["A single 13 KB request, later", "timed out at 120 seconds"],
                ["Hosted model on a clear case", "block at 0.91 confidence"],
                ["Self-hosted model on the same case", "block at 0.58 confidence"],
            ],
            "caveat": (
                "Needs an uncontended machine, or coordination with whoever owns the work on that box. Nothing "
                "there was stopped or reconfigured to make room."
            ),
        }
    )
    findings.sort(key=lambda entry: int(entry["id"][1:]))
    osr = load(args.openskillrisk)
    if osr is not None:
        findings.append(_osr(osr))
    else:
        not_run.append("OpenSkillRisk")
    hsb = load(args.harmfulskillbench)
    if hsb is not None:
        findings.append(_hsb(hsb))
    else:
        not_run.append("HarmfulSkillBench")

    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-findings",
        "findings": findings,
        "not_run": sorted(not_run),
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"consolidated {len(findings)} experiment findings; not run: {report['not_run'] or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
