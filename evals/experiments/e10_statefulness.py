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

"""E10: does remembering a decision actually save work on a re-scan?

Statefulness is only worth building if a stored decision survives the edits a real
repository sees between scans.  An identical re-scan proving 100% reuse would prove
nothing, because nothing moved.  So this measures reuse across a perturbation that
mimics ordinary churn: a header comment inserted at the top of every file, which
shifts every line number, plus re-indentation, which changes every evidence string
byte-for-byte without changing meaning.

Two identities are compared on the same perturbed corpus.  The scanner's existing
finding id includes the line number, so it is the control.  The fingerprint
deliberately excludes it.  The gap between them is the value of the design choice.

Decision rule: if reuse across perturbation is low for both, the memory expires
faster than analysts can use it and statefulness is not worth building.  That would
be a useful negative result.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.system_one.runner import resolve_skill_root  # noqa: E402
from skill_scanner.core.analyzer_factory import build_core_analyzers  # noqa: E402
from skill_scanner.core.finding_identity import finding_fingerprint  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402

TEXT_SUFFIXES = frozenset({".md", ".py", ".js", ".ts", ".sh", ".bash", ".rb", ".txt", ".json", ".yaml", ".yml"})

HEADER = "\n".join(f"# housekeeping note line {index}" for index in range(1, 6)) + "\n\n"


def perturb(source: Path, destination: Path) -> int:
    """Copy *source* to *destination* applying edits that do not change meaning."""
    shutil.copytree(source, destination)
    touched = 0
    for path in sorted(destination.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Shift every line number, and re-space every line, so a line-keyed or
        # byte-keyed identity breaks while the meaning is untouched.
        respaced = "\n".join("  " + line.strip() if line.strip() else line for line in text.splitlines())
        try:
            path.write_text(HEADER + respaced + "\n", encoding="utf-8")
            touched += 1
        except OSError:
            continue
    return touched


def _identities(result: Any) -> tuple[set[str], set[str]]:
    """Return (existing finding ids, drift-tolerant fingerprints) for one scan."""
    ids: set[str] = set()
    fingerprints: set[str] = set()
    for finding in getattr(result, "findings", None) or []:
        metadata = getattr(finding, "metadata", None) or {}
        ids.add(str(getattr(finding, "id", "")))
        fingerprints.add(
            finding_fingerprint(
                rule_id=str(metadata.get("rule_id") or getattr(finding, "rule_id", "") or ""),
                category=str(getattr(getattr(finding, "category", None), "name", "") or ""),
                file_role="skill_md"
                if str(getattr(finding, "file_path", "")).lower().endswith("skill.md")
                else "other",
                evidence=str(getattr(finding, "snippet", "") or getattr(finding, "title", "") or ""),
            )
        )
    return ids, fingerprints


def _verdict(fingerprint_rate: float, id_rate: float) -> str:
    """State both facts, because either alone is misleading.

    A large relative improvement does not make the absolute rate sufficient, and a
    middling absolute rate does not make the design choice wrong.
    """
    ratio = (fingerprint_rate / id_rate) if id_rate else float("inf")
    relative = (
        f"excluding the line number reuses {ratio:.1f} times more decisions than the existing identity"
        if id_rate
        else "the existing identity reused nothing, so every surviving decision is due to excluding the line number"
    )
    if fingerprint_rate >= 0.8:
        absolute = "and survives ordinary churn well enough to rely on"
    elif fingerprint_rate >= 0.5:
        absolute = (
            "but still loses a substantial minority of decisions, so memory reduces judge calls "
            "without eliminating re-adjudication"
        )
    else:
        absolute = "and still expires too quickly to be worth building on"
    return f"{relative}, {absolute}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--max-skills", type=int, default=40)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    directories = [path for path in sorted(args.corpus.iterdir()) if path.is_dir()][: args.max_skills]
    policy = ScanPolicy.default()
    scanner = SkillScanner(analyzers=build_core_analyzers(policy), policy=policy)

    identical_id_hits = identical_fp_hits = 0
    perturbed_id_hits = perturbed_fp_hits = 0
    baseline_ids_total = 0
    baseline_fps_total = 0
    skills = 0
    files_touched = 0

    with tempfile.TemporaryDirectory() as workspace:
        for directory in directories:
            root = resolve_skill_root(directory)
            if root is None:
                continue
            try:
                first = scanner.scan_skill(root)
            except Exception:  # noqa: BLE001 - one bad skill must not end the sweep
                continue
            base_ids, base_fps = _identities(first)
            if not base_fps:
                continue
            skills += 1
            # Separate denominators: fingerprints deliberately collapse duplicate
            # hits, so dividing id hits by the fingerprint count can exceed 1.0.
            baseline_ids_total += len(base_ids)
            baseline_fps_total += len(base_fps)

            # An identical re-scan is the sanity check, not the result.
            try:
                repeat = scanner.scan_skill(root)
                repeat_ids, repeat_fps = _identities(repeat)
                identical_id_hits += len(base_ids & repeat_ids)
                identical_fp_hits += len(base_fps & repeat_fps)
            except Exception:  # noqa: BLE001
                pass

            target = Path(workspace) / f"perturbed-{skills}"
            try:
                files_touched += perturb(root, target)
                after = scanner.scan_skill(target)
            except Exception:  # noqa: BLE001
                continue
            after_ids, after_fps = _identities(after)
            perturbed_id_hits += len(base_ids & after_ids)
            perturbed_fp_hits += len(base_fps & after_fps)
            shutil.rmtree(target, ignore_errors=True)

    def id_reuse(hits: int) -> float:
        return (hits / baseline_ids_total) if baseline_ids_total else 0.0

    def fp_reuse(hits: int) -> float:
        return (hits / baseline_fps_total) if baseline_fps_total else 0.0

    fingerprint_rate = fp_reuse(perturbed_fp_hits)
    id_rate = id_reuse(perturbed_id_hits)
    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e10-statefulness",
        "blocking": False,
        "skills_compared": skills,
        "files_perturbed": files_touched,
        "baseline_finding_ids": baseline_ids_total,
        "baseline_fingerprints": baseline_fps_total,
        "identical_rescan": {
            "existing_finding_id_reuse": id_reuse(identical_id_hits),
            "fingerprint_reuse": fp_reuse(identical_fp_hits),
            "note": "Sanity check only: nothing moved, so high reuse proves nothing.",
        },
        "after_realistic_edits": {
            "existing_finding_id_reuse": id_rate,
            "fingerprint_reuse": fingerprint_rate,
            "advantage": fingerprint_rate - id_rate,
        },
        "judge_calls_avoidable": perturbed_fp_hits,
        "relative_improvement": (fingerprint_rate / id_rate) if id_rate else None,
        "perturbation": (
            "a five-line header inserted in every text file plus re-indentation of every line, "
            "which is more aggressive than typical churn"
        ),
        "verdict": _verdict(fingerprint_rate, id_rate),
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"skills={skills} finding_ids={baseline_ids_total} fingerprints={baseline_fps_total} "
        f"files_perturbed={files_touched}"
    )
    print(
        f"identical rescan : id reuse={report['identical_rescan']['existing_finding_id_reuse']:.3f} "
        f"fingerprint reuse={report['identical_rescan']['fingerprint_reuse']:.3f}"
    )
    print(f"after edits      : id reuse={id_rate:.3f} fingerprint reuse={fingerprint_rate:.3f}")
    print(f"verdict: {report['verdict']}")
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
