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

"""Emit deterministic and judge decisions in the shared prediction shape.

The cascade scorer composes tiers by reading rows of one shape, so the scanner's
own verdicts have to be expressed in it too.  Severity maps to an action rather
than to a raw score: a HIGH or CRITICAL finding is a block, anything else
actionable is a confirm, and no findings is an allow.  That mapping is the same
one the package-level metrics already use, which keeps the composed numbers
comparable with the published ones.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.system_one.runner import resolve_skill_root  # noqa: E402
from skill_scanner.core.analyzer_factory import build_analyzers, build_core_analyzers  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402

BLOCK_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})


def _severity(finding: Any) -> str:
    name = getattr(getattr(finding, "severity", None), "name", None)
    return str(name or getattr(finding, "severity", "")).upper()


def action_for(findings: Sequence[Any]) -> tuple[str, float]:
    """Map a finding set onto an action and a coarse confidence."""
    severities = {_severity(finding) for finding in findings}
    if severities & BLOCK_SEVERITIES:
        return "block", 1.0
    if severities & ACTIONABLE_SEVERITIES:
        return "confirm", 0.6
    if findings:
        # Informational only: visible but not actionable, so it is not an intervention.
        return "allow", 0.4
    return "allow", 1.0


def run(
    skill_dirs: Sequence[Path],
    *,
    output: Path,
    tier: str,
    judge_model: str | None = None,
) -> dict[str, Any]:
    """Scan each skill and write one prediction row per package."""
    policy = ScanPolicy.default()
    if judge_model:
        analyzers = build_analyzers(policy, use_llm=True, llm_model=judge_model)
    else:
        analyzers = build_core_analyzers(policy)
    scanner = SkillScanner(analyzers=analyzers, policy=policy)

    started = time.time()
    rows: list[dict[str, Any]] = []
    errors = 0
    for directory in skill_dirs:
        root = resolve_skill_root(directory)
        if root is None:
            continue
        try:
            result = scanner.scan_skill(root)
        except Exception:  # noqa: BLE001 - counted, never fatal
            errors += 1
            continue
        findings = list(getattr(result, "findings", None) or [])
        action, confidence = action_for(findings)
        rows.append(
            {
                "schema_version": 1,
                "case_id": directory.name,
                "model": tier,
                "model_revision": tier,
                "context_variant": "full_package",
                "question_variant": "severity_mapping",
                "action": action,
                "confidence": confidence,
                "detected": action in {"confirm", "block"},
                "probabilities": {},
                "route": tier,
                "finding_count": len(findings),
                "severities": sorted({_severity(finding) for finding in findings}),
            }
        )

    rows.sort(key=lambda row: row["case_id"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    os.chmod(output, 0o600)

    meta = {
        "kind": "skill-scanner-tier-run",
        "tier": tier,
        "judge_model": judge_model,
        "skills_offered": len(skill_dirs),
        "rows": len(rows),
        "scan_errors": errors,
        "duration_s": round(time.time() - started, 1),
        "complete": True,
    }
    output.with_suffix(output.suffix + ".meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8"
    )
    return meta


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tier", default="deterministic", help="tier label recorded on every row")
    parser.add_argument("--judge-model", default=None, help="enable the LLM analyzer with this model")
    parser.add_argument("--max-skills", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    directories = sorted(path for path in args.corpus.iterdir() if path.is_dir())
    if args.max_skills:
        directories = directories[: args.max_skills]
    meta = run(directories, output=args.output, tier=args.tier, judge_model=args.judge_model)
    print(json.dumps({key: meta[key] for key in ("tier", "rows", "scan_errors", "duration_s")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
