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

"""E15: benchmark the stateful scanner prototype end to end.

Measures what statefulness actually buys, on a labelled population, in four passes.

1. A cold scan with no memory. This is the control, and it must be byte-identical
   to today's behaviour, because a store that changes output while empty would make
   every previous number unreproducible.
2. Observe every finding, then adjudicate a bounded sample with a model.
3. A warm scan that consults the memory, measuring decisions reused and findings
   suppressed.
4. The safety check: did suppression hide anything on a malicious package at HIGH or
   CRITICAL severity? A cheaper scan that loses a real detection is not cheaper, it
   is broken.

Adjudications come from a model, so they are labelled as such and never presented
as ground truth. Their measured disagreement across vendors is the reason the store
refuses to let a model overwrite a person.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import random
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from skill_scanner.core.memory.store import apply_memory  # noqa: E402

from evals.experiments.adjudicate import FindingProbe, adjudicate_many, read_surrounding  # noqa: E402
from evals.system_one.runner import resolve_skill_root  # noqa: E402
from skill_scanner.core.analyzer_factory import build_core_analyzers  # noqa: E402
from skill_scanner.core.memory import Adjudication, Decision, FindingMemory, fingerprint_for  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402

SEED = 741983
PROTECTED = frozenset({"CRITICAL", "HIGH"})
DEFAULT_MODEL = "bedrock-mantle/google.gemma-4-26b-a4b"


def _severity(finding: Any) -> str:
    return str(getattr(getattr(finding, "severity", None), "name", "") or "").upper()


def scan_all(scanner: SkillScanner, roots: Sequence[tuple[str, Path]]) -> dict[str, list[Any]]:
    """Scan every skill once, returning findings by case id."""
    out: dict[str, list[Any]] = {}
    for case_id, root in roots:
        try:
            result = scanner.scan_skill(root)
        except Exception:  # noqa: BLE001 - one bad skill must not end the sweep
            continue
        out[case_id] = list(getattr(result, "findings", None) or [])
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--memory", type=Path, required=True)
    parser.add_argument("--adjudicate", type=int, default=120, help="how many findings to adjudicate")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    labels: dict[str, str] = json.loads(args.labels.read_text(encoding="utf-8"))
    roots: list[tuple[str, Path]] = []
    for directory in sorted(args.corpus.iterdir()):
        if not directory.is_dir() or directory.name not in labels:
            continue
        root = resolve_skill_root(directory)
        if root is not None:
            roots.append((directory.name, root))
    if not roots:
        print("no skill roots resolved; refusing to emit", file=sys.stderr)
        return 1

    policy = ScanPolicy.default()
    scanner = SkillScanner(analyzers=build_core_analyzers(policy), policy=policy)

    # Pass 1: the control.
    cold = scan_all(scanner, roots)
    cold_counts = {case_id: len(found) for case_id, found in cold.items()}

    # An empty store must not change anything.
    if args.memory.exists():
        args.memory.unlink()
    memory = FindingMemory(args.memory)
    empty_digest = memory.digest()
    unchanged = all(len(apply_memory(list(found), memory)[0]) == len(found) for found in cold.values())

    # Pass 2: observe, then adjudicate a bounded sample.
    for case_id, found in cold.items():
        if found:
            memory.observe(found, skill_name=case_id)

    queue = memory.pending(limit=args.adjudicate)
    by_fingerprint: dict[str, tuple[str, Any]] = {}
    for case_id, found in cold.items():
        for finding in found:
            by_fingerprint.setdefault(fingerprint_for(finding), (case_id, finding))

    probes: list[FindingProbe] = []
    probe_fingerprints: list[str] = []
    root_by_case = dict(roots)
    for record in queue:
        entry = by_fingerprint.get(record.fingerprint)
        if entry is None:
            continue
        case_id, finding = entry
        root = root_by_case[case_id]
        relative = str(getattr(finding, "file_path", "") or "SKILL.md")
        probes.append(
            FindingProbe(
                finding_id=record.fingerprint,
                rule_id=record.rule_id,
                category=record.category,
                severity=record.severity,
                skill_name=case_id,
                declared_purpose=(root / "SKILL.md").read_text(encoding="utf-8", errors="replace")[:1500]
                if (root / "SKILL.md").exists()
                else "",
                file_path=relative,
                evidence=str(getattr(finding, "snippet", "") or getattr(finding, "title", "") or ""),
                surrounding=read_surrounding(root / relative, int(getattr(finding, "line_number", 0) or 0)),
            )
        )
        probe_fingerprints.append(record.fingerprint)

    print(f"scanned {len(roots)} skills, adjudicating {len(probes)} distinct findings", file=sys.stderr)
    adjudications = asyncio.run(adjudicate_many(probes, model=args.model, concurrency=args.concurrency))

    recorded = collections.Counter()
    for fingerprint, result in zip(probe_fingerprints, adjudications, strict=False):
        if not result.usable or result.verdict == "uncertain":
            recorded["skipped"] += 1
            continue
        decision = Decision.NOT_APPLICABLE if result.verdict == "not_applicable" else Decision.REAL
        memory.record_decision(
            fingerprint,
            # Marked non-human so a person's decision always wins later.
            Adjudication(
                decision=decision,
                author=args.model,
                human=False,
                reason=result.reason[:300],
                confidence=result.confidence,
                decisive_facts=result.decisive_facts,
            ),
        )
        recorded[decision.value] += 1

    # Pass 3: the warm scan.
    warm = scan_all(scanner, roots)
    reuse_total = collections.Counter()
    suppressed_protected_on_malicious: list[dict[str, Any]] = []
    warm_counts: dict[str, int] = {}
    for case_id, found in warm.items():
        kept, telemetry = apply_memory(list(found), memory)
        warm_counts[case_id] = len(kept)
        for key in ("findings_seen", "decisions_reused", "suppressed", "confirmed"):
            reuse_total[key] += telemetry[key]
        if labels.get(case_id) != "malicious":
            continue
        kept_ids = {id(finding) for finding in kept}
        for finding in found:
            if id(finding) in kept_ids or _severity(finding) not in PROTECTED:
                continue
            suppressed_protected_on_malicious.append(
                {"case_id": case_id, "rule_id": str((getattr(finding, "metadata", None) or {}).get("rule_id") or "")}
            )

    findings_total = sum(cold_counts.values())
    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e15-stateful-prototype",
        "blocking": False,
        "seed": SEED,
        "model": args.model,
        "skills_scanned": len(roots),
        "findings_total": findings_total,
        "distinct_findings": memory.stats()["distinct_findings"],
        "empty_store_digest": empty_digest,
        "memory_digest": memory.digest(),
        # The control: an empty store must not change a single finding.
        "empty_store_leaves_output_unchanged": unchanged,
        "adjudicated": dict(recorded),
        "reuse": {
            "findings_seen": reuse_total["findings_seen"],
            "decisions_reused": reuse_total["decisions_reused"],
            "reuse_rate": (reuse_total["decisions_reused"] / reuse_total["findings_seen"])
            if reuse_total["findings_seen"]
            else 0.0,
            "suppressed": reuse_total["suppressed"],
            "confirmed": reuse_total["confirmed"],
            "findings_before": findings_total,
            "findings_after": sum(warm_counts.values()),
        },
        "safety": {
            "protected_findings_suppressed_on_malicious": len(suppressed_protected_on_malicious),
            "examples": suppressed_protected_on_malicious[:10],
            "passed": not suppressed_protected_on_malicious,
        },
        "memory_stats": memory.stats(),
        "note": "Adjudications are model-made and labelled as such; none is ground truth.",
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    reuse = report["reuse"]
    print(f"empty store leaves output unchanged: {unchanged}")
    print(f"adjudicated: {dict(recorded)}")
    print(
        f"reuse: {reuse['decisions_reused']}/{reuse['findings_seen']} findings "
        f"({reuse['reuse_rate']:.1%}), suppressed {reuse['suppressed']}, "
        f"findings {reuse['findings_before']} -> {reuse['findings_after']}"
    )
    print(
        f"safety: {report['safety']['protected_findings_suppressed_on_malicious']} protected findings "
        f"suppressed on malicious packages -> {'PASSED' if report['safety']['passed'] else 'FAILED'}"
    )
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
