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

"""E11: can a dismissal be generalised into a safe suppression rule?

A dismissal is only useful if it generalises, and generalising is only safe if the
generalisation is checked against the cases it must never touch.  So each candidate
is replayed over a labelled population and rejected outright if it would suppress
a finding on a malicious package at HIGH or CRITICAL severity.  That test is the
whole point: a suppression that silences a real detection is worse than the false
positive it was meant to remove.

Candidates are keyed on a rule and a bounded, checkable property, never on raw
text, so a reviewer can tell exactly what a proposal would silence.  Nothing is
applied: the output is a review queue with the measured cost of each entry.
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

from evals.lib.metrics import wilson_interval  # noqa: E402
from evals.system_one.runner import resolve_skill_root  # noqa: E402
from skill_scanner.core.analyzer_factory import build_core_analyzers  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402

PROTECTED_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
# Below this many benign-only observations a candidate is an anecdote, not a pattern.
MIN_SUPPORT = 3


def _severity(finding: Any) -> str:
    name = getattr(getattr(finding, "severity", None), "name", None)
    return str(name or getattr(finding, "severity", "")).upper()


def _file_role(finding: Any) -> str:
    path = str(getattr(finding, "file_path", "") or "").lower()
    if path.endswith("skill.md"):
        return "skill_md"
    if any(part in path for part in ("/doc", "docs/", "example", "test", "fixture")):
        return "documentation"
    return "code"


def observe(skill_dirs: Sequence[Path], labels: dict[str, str], *, policy: ScanPolicy) -> list[dict[str, Any]]:
    """Scan the labelled population and record one row per finding."""
    scanner = SkillScanner(analyzers=build_core_analyzers(policy), policy=policy)
    rows: list[dict[str, Any]] = []
    for directory in skill_dirs:
        label = labels.get(directory.name)
        if label is None:
            continue
        root = resolve_skill_root(directory)
        if root is None:
            continue
        try:
            result = scanner.scan_skill(root)
        except Exception:  # noqa: BLE001 - one bad skill must not end the sweep
            continue
        for finding in getattr(result, "findings", None) or []:
            metadata = getattr(finding, "metadata", None) or {}
            rows.append(
                {
                    "case_id": directory.name,
                    "label": label,
                    "rule_id": str(metadata.get("rule_id") or getattr(finding, "rule_id", "") or "unknown"),
                    "severity": _severity(finding),
                    "file_role": _file_role(finding),
                }
            )
    return rows


def propose(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build candidates keyed on (rule, file role) and measure what each would cost."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        grouped[(row["rule_id"], row["file_role"])].append(row)

    candidates: list[dict[str, Any]] = []
    for (rule_id, file_role), group in sorted(grouped.items()):
        benign = [row for row in group if row["label"] == "benign"]
        malicious = [row for row in group if row["label"] == "malicious"]
        protected = [row for row in malicious if row["severity"] in PROTECTED_SEVERITIES]

        if protected:
            reason = f"would suppress {len(protected)} finding(s) on malicious packages at HIGH or CRITICAL severity"
            accepted = False
        elif len(benign) < MIN_SUPPORT:
            reason = f"only {len(benign)} benign observation(s), below the support floor of {MIN_SUPPORT}"
            accepted = False
        elif malicious:
            reason = f"also fires on {len(malicious)} malicious package(s), so it is not benign-only"
            accepted = False
        else:
            reason = "fires only on benign packages in this population, with enough support to be a pattern"
            accepted = True

        low, high = wilson_interval(len(benign), len(group))
        candidates.append(
            {
                "rule_id": rule_id,
                "file_role": file_role,
                # A CEL keep-predicate: true keeps the finding, so suppression is the
                # negation of the matched shape. Shadow rollout means it is measured
                # before it ever silences anything.
                "proposed_predicate": f'!(f.candidate.rule_id == "{rule_id}" && f.candidate.file_role == "{file_role}")',
                "rollout": "shadow",
                "observations": len(group),
                "benign_observations": len(benign),
                "malicious_observations": len(malicious),
                "protected_observations": len(protected),
                "benign_share": len(benign) / len(group) if group else 0.0,
                "benign_share_95": [low, high],
                "accepted": accepted,
                "reason": reason,
            }
        )
    return candidates


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    directories = [path for path in sorted(args.corpus.iterdir()) if path.is_dir()]
    rows = observe(directories, labels, policy=ScanPolicy.default())
    if not rows:
        print("no findings observed; refusing to emit", file=sys.stderr)
        return 1

    candidates = propose(rows)
    accepted = [entry for entry in candidates if entry["accepted"]]
    rejected_protected = [entry for entry in candidates if entry["protected_observations"]]
    suppressible = sum(entry["benign_observations"] for entry in accepted)
    benign_total = sum(1 for row in rows if row["label"] == "benign")

    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e11-suppression-candidates",
        "blocking": False,
        "population": len(labels),
        "findings_observed": len(rows),
        "benign_findings": benign_total,
        "candidates_considered": len(candidates),
        "candidates_accepted": len(accepted),
        "candidates_rejected_for_touching_protected_findings": len(rejected_protected),
        "benign_findings_suppressible": suppressible,
        "benign_findings_suppressible_share": (suppressible / benign_total) if benign_total else 0.0,
        # The safety claim: no accepted candidate touches a protected finding.
        "protected_findings_suppressed_by_accepted": sum(entry["protected_observations"] for entry in accepted),
        "candidates": candidates,
        "note": "Shadow-mode proposals only. Nothing is applied; every entry goes to human review.",
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"findings={len(rows)} candidates={len(candidates)} accepted={len(accepted)} "
        f"rejected_for_protected={len(rejected_protected)}"
    )
    print(
        f"would silence {suppressible}/{benign_total} benign findings "
        f"({report['benign_findings_suppressible_share']:.1%}) and "
        f"{report['protected_findings_suppressed_by_accepted']} protected findings"
    )
    for entry in accepted[:8]:
        print(f"  accept {entry['rule_id']} in {entry['file_role']}: {entry['benign_observations']} benign only")
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
