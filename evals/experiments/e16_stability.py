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

"""E16: how much does the judge's verdict move between identical runs?

Temperature zero is not determinism. If a configuration flips its verdict on some
packages between byte-identical runs, then any difference between two arms smaller
than that flip rate is noise, and reporting it as a result would be wrong.

So this repeats one configuration several times over the same packages and reports
how often the package-level verdict changes. The deterministic core is repeated
alongside it as a control: it must not move at all, and if it does the harness is at
fault rather than the model.

The output is the noise floor that every other comparison in this programme has to
clear.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.system_one.deterministic import action_for
from evals.system_one.runner import resolve_skill_root
from skill_scanner.core.analyzer_factory import build_analyzers, build_core_analyzers
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner

DEFAULT_MODEL = "bedrock-mantle/google.gemma-4-26b-a4b"


def one_pass(scanner: SkillScanner, roots: Sequence[tuple[str, Path]]) -> dict[str, str]:
    """Scan every skill once, returning the package-level action per case."""
    out: dict[str, str] = {}
    for case_id, root in roots:
        try:
            result = scanner.scan_skill(root)
        except Exception:  # noqa: BLE001 - counted by absence, never fatal
            continue
        action, _ = action_for(list(getattr(result, "findings", None) or []))
        out[case_id] = action
    return out


def flip_rate(passes: Sequence[dict[str, str]]) -> dict[str, Any]:
    """How many cases did not hold the same action across every pass?"""
    if len(passes) < 2:
        return {"cases": 0, "flipped": 0, "flip_rate": 0.0, "passes": len(passes)}
    shared = set(passes[0])
    for entry in passes[1:]:
        shared &= set(entry)
    flipped = [case for case in sorted(shared) if len({entry[case] for entry in passes}) > 1]
    transitions = collections.Counter()
    for case in flipped:
        transitions[" -> ".join(sorted({entry[case] for entry in passes}))] += 1
    return {
        "cases": len(shared),
        "flipped": len(flipped),
        "flip_rate": (len(flipped) / len(shared)) if shared else 0.0,
        "passes": len(passes),
        "transitions": dict(transitions.most_common()),
        "examples": flipped[:10],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--max-skills", type=int, default=200)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    roots: list[tuple[str, Path]] = []
    for directory in sorted(args.corpus.iterdir()):
        if not directory.is_dir():
            continue
        root = resolve_skill_root(directory)
        if root is not None:
            roots.append((directory.name, root))
        if len(roots) >= args.max_skills:
            break
    if not roots:
        print("no skill roots resolved; refusing to emit", file=sys.stderr)
        return 1

    policy = ScanPolicy.default()

    # Control: the deterministic core must not move at all.
    core = SkillScanner(analyzers=build_core_analyzers(policy), policy=policy)
    core_passes = [one_pass(core, roots) for _ in range(min(args.repeats, 3))]

    judged = SkillScanner(analyzers=build_analyzers(policy, use_llm=True, llm_model=args.model), policy=policy)
    judged_passes = []
    for index in range(args.repeats):
        judged_passes.append(one_pass(judged, roots))
        print(f"judged pass {index + 1}/{args.repeats} done", file=sys.stderr)

    core_result = flip_rate(core_passes)
    judged_result = flip_rate(judged_passes)
    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e16-stability",
        "blocking": False,
        "model": args.model,
        "skills": len(roots),
        "deterministic_core": core_result,
        "core_plus_judge": judged_result,
        # Anything smaller than this in a comparison of two judged arms is noise.
        "noise_floor": judged_result["flip_rate"],
        "control_passed": core_result["flipped"] == 0,
        "note": (
            "Temperature zero is not determinism. A difference between two judged arms smaller than the "
            "flip rate here cannot be distinguished from run-to-run variation."
        ),
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"deterministic core: {core_result['flipped']}/{core_result['cases']} flipped "
        f"over {core_result['passes']} passes -> control {'PASSED' if report['control_passed'] else 'FAILED'}"
    )
    print(
        f"core plus judge  : {judged_result['flipped']}/{judged_result['cases']} flipped "
        f"over {judged_result['passes']} passes = {judged_result['flip_rate']:.4f}"
    )
    if judged_result.get("transitions"):
        print(f"transitions      : {judged_result['transitions']}")
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
