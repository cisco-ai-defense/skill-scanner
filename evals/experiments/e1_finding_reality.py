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

"""E1: what fraction of deterministic findings are actually real?

This runs first because every later number is read against it.  A skill is an
open specification, so the prior that any given rule hit is genuinely a security
problem is not high, and a judge asked to confirm findings is operating in that
regime.  Until the base rate is known, "the judge removed 30% of findings" cannot
be read as either a win or a regression.

Method: scan real-world skills with the deterministic core, stratify the findings
by rule and severity, then adjudicate a bounded sample with two models from
different vendors.  Report the estimated real rate per rule with Wilson
intervals, plus chance-corrected agreement between the adjudicators.

Two honesty constraints.  The corpus is unlabeled real-world content, so nothing
here is ground truth; this estimates a rate and reports its own uncertainty.  And
agreement between two models is not accuracy: it bounds how much either can be
trusted, which is why a human pass over a subset is the intended follow-up and
the output is shaped to support one.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.experiments.adjudicate import (  # noqa: E402
    Adjudication,
    FindingProbe,
    adjudicate_many,
    cohen_kappa,
    read_surrounding,
)
from evals.lib.metrics import wilson_interval  # noqa: E402
from skill_scanner import __version__ as scanner_version  # noqa: E402
from skill_scanner.core.analyzer_factory import build_core_analyzers  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_PRIMARY_MODEL = "bedrock-mantle/google.gemma-4-26b-a4b"
# Deliberately a different vendor and architecture from the primary. An arbiter
# that shares the primary's failure modes contributes nothing.
DEFAULT_INDEPENDENT_MODEL = "bedrock/openai.gpt-oss-120b-1:0"

SEED = 741983


def resolve_skill_root(directory: Path, *, max_depth: int = 3) -> Path | None:
    """Find the directory that actually holds SKILL.md.

    Corpus layouts vary: some mirror the upstream repository name twice, so the
    manifest sits at ``<name>/<name>/SKILL.md``.  Scanning the outer directory
    silently yields zero findings, which reads as a clean corpus rather than a
    path bug, so resolve the real root instead of assuming one.
    """
    if (directory / "SKILL.md").is_file():
        return directory
    for depth in range(1, max_depth + 1):
        matches = sorted(directory.glob("/".join(["*"] * depth) + "/SKILL.md"))
        if matches:
            return matches[0].parent
    return None


def collect_findings(skill_dirs: list[Path], *, policy: ScanPolicy) -> list[dict[str, Any]]:
    """Scan with the deterministic core and flatten every finding."""
    scanner = SkillScanner(analyzers=build_core_analyzers(policy), policy=policy)
    rows: list[dict[str, Any]] = []
    for raw_directory in skill_dirs:
        directory = resolve_skill_root(raw_directory)
        if directory is None:
            logger.warning("no SKILL.md found under %s; skipping", raw_directory.name)
            continue
        try:
            result = scanner.scan_skill(directory)
        except Exception as error:  # noqa: BLE001 - one bad skill must not end the sweep
            logger.warning("scan failed for %s: %s", directory.name, error)
            continue
        purpose = ""
        skill_md = directory / "SKILL.md"
        if skill_md.exists():
            purpose = skill_md.read_text(encoding="utf-8", errors="replace")[:2000]
        for index, finding in enumerate(result.findings or []):
            severity = getattr(getattr(finding, "severity", None), "name", None) or str(
                getattr(finding, "severity", "")
            )
            metadata = getattr(finding, "metadata", None) or {}
            rows.append(
                {
                    "finding_id": f"{directory.name}#{index}",
                    "skill_dir": str(directory),
                    "skill_name": getattr(finding, "skill_name", None) or directory.name,
                    "declared_purpose": purpose,
                    "rule_id": str(metadata.get("rule_id") or getattr(finding, "rule_id", "") or "unknown"),
                    "category": str(getattr(getattr(finding, "category", None), "name", None) or "unknown"),
                    "severity": str(severity).upper(),
                    "file_path": str(getattr(finding, "file_path", "") or ""),
                    "line_number": int(getattr(finding, "line_number", 0) or 0),
                    "evidence": str(getattr(finding, "evidence", "") or "")[:4000],
                    "title": str(getattr(finding, "title", "") or ""),
                }
            )
    return rows


def stratified_sample(rows: list[dict[str, Any]], *, per_stratum: int, seed: int = SEED) -> list[dict[str, Any]]:
    """Sample per (rule, severity) so high-volume rules cannot dominate.

    Without stratification the estimate would describe whichever rule fires most,
    not the rule set, and the per-rule rates are the actionable output.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        grouped[(row["rule_id"], row["severity"])].append(row)
    generator = random.Random(seed)
    sampled: list[dict[str, Any]] = []
    for key in sorted(grouped):
        group = grouped[key]
        generator.shuffle(group)
        sampled.extend(group[:per_stratum])
    return sampled


def build_probes(rows: list[dict[str, Any]]) -> list[FindingProbe]:
    """Attach a bounded context window to each sampled finding."""
    probes: list[FindingProbe] = []
    for row in rows:
        path = Path(row["skill_dir"]) / row["file_path"] if row["file_path"] else Path(row["skill_dir"]) / "SKILL.md"
        probes.append(
            FindingProbe(
                finding_id=row["finding_id"],
                rule_id=row["rule_id"],
                category=row["category"],
                severity=row["severity"],
                skill_name=row["skill_name"],
                declared_purpose=row["declared_purpose"],
                file_path=row["file_path"] or "SKILL.md",
                evidence=row["evidence"] or row["title"],
                surrounding=read_surrounding(path, row["line_number"]),
            )
        )
    return probes


def _rate_block(real: int, decided: int) -> dict[str, Any]:
    low, high = wilson_interval(real, decided)
    return {
        "decided": decided,
        "real": real,
        "real_rate": (real / decided) if decided else 0.0,
        "real_rate_95": [low, high],
    }


def summarize(
    rows: list[dict[str, Any]],
    primary: list[Adjudication],
    independent: list[Adjudication],
) -> dict[str, Any]:
    """Aggregate adjudications into per-rule rates and agreement."""
    by_id = {row["finding_id"]: row for row in rows}
    primary_by_id = {a.finding_id: a for a in primary}
    independent_by_id = {a.finding_id: a for a in independent}

    def per_model(adjudications: list[Adjudication]) -> dict[str, Any]:
        usable = [a for a in adjudications if a.usable]
        counts = collections.Counter(a.verdict for a in usable)
        # "uncertain" is excluded from the denominator on purpose: it is a refusal
        # to decide, and folding it into either side would invent a decision.
        decided = counts["real"] + counts["not_applicable"]
        by_rule: dict[str, dict[str, Any]] = {}
        grouped: dict[str, list[Adjudication]] = collections.defaultdict(list)
        for adjudication in usable:
            row = by_id.get(adjudication.finding_id)
            if row:
                grouped[row["rule_id"]].append(adjudication)
        for rule_id, group in sorted(grouped.items()):
            rule_counts = collections.Counter(a.verdict for a in group)
            rule_decided = rule_counts["real"] + rule_counts["not_applicable"]
            by_rule[rule_id] = {
                "sampled": len(group),
                "uncertain": rule_counts["uncertain"],
                **_rate_block(rule_counts["real"], rule_decided),
            }
        failures = [a for a in adjudications if not a.usable]
        error_kinds = collections.Counter((a.error or "unusable").split(":")[0] for a in failures)
        return {
            "attempted": len(adjudications),
            "usable": len(usable),
            "errors": len(failures),
            # Published rather than summarized away: an arm with a high error rate
            # is a harness result, not a quality result.
            "error_kinds": dict(error_kinds.most_common()),
            "error_samples": [a.error for a in failures[:5]],
            "uncertain": counts["uncertain"],
            "overall": _rate_block(counts["real"], decided),
            "per_rule": by_rule,
        }

    shared = [
        (primary_by_id[key].verdict, independent_by_id[key].verdict)
        for key in sorted(set(primary_by_id) & set(independent_by_id))
        if primary_by_id[key].usable and independent_by_id[key].usable
    ]
    raw_agreement = (sum(1 for a, b in shared if a == b) / len(shared)) if shared else 0.0

    disagreements = [
        {
            "finding_id": key,
            "rule_id": by_id[key]["rule_id"],
            "severity": by_id[key]["severity"],
            "primary": primary_by_id[key].verdict,
            "independent": independent_by_id[key].verdict,
            "primary_reason": primary_by_id[key].reason,
            "independent_reason": independent_by_id[key].reason,
        }
        for key in sorted(set(primary_by_id) & set(independent_by_id))
        if primary_by_id[key].usable
        and independent_by_id[key].usable
        and primary_by_id[key].verdict != independent_by_id[key].verdict
    ]

    return {
        "primary": per_model(primary),
        "independent": per_model(independent),
        "agreement": {
            "compared": len(shared),
            "raw_agreement": raw_agreement,
            # Chance-corrected, because two models that both mostly say "real"
            # agree often by construction.
            "cohen_kappa": cohen_kappa(shared),
        },
        # The ranked backlog a human reviewer should work through first.
        "disagreements": disagreements[:200],
        # Value-free per-finding verdicts: identity, rule and verdict only, no
        # evidence text. Published so a later experiment can pair against this
        # arm exactly instead of approximating from the aggregates.
        "per_finding": {
            key: {
                "rule_id": by_id[key]["rule_id"],
                "severity": by_id[key]["severity"],
                "primary": primary_by_id[key].verdict if primary_by_id[key].usable else None,
                "independent": (
                    independent_by_id[key].verdict
                    if key in independent_by_id and independent_by_id[key].usable
                    else None
                ),
            }
            for key in sorted(primary_by_id)
            if key in by_id
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True, help="directory of skill directories")
    parser.add_argument("--max-skills", type=int, default=60)
    parser.add_argument("--per-stratum", type=int, default=3)
    parser.add_argument("--max-probes", type=int, default=200)
    parser.add_argument("--primary-model", default=DEFAULT_PRIMARY_MODEL)
    parser.add_argument("--independent-model", default=DEFAULT_INDEPENDENT_MODEL)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument(
        "--independent-concurrency",
        type=int,
        default=1,
        help="separate limit; the independent route throttles at lower concurrency than the primary",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    directories = sorted(path for path in args.corpus.iterdir() if path.is_dir())
    random.Random(SEED).shuffle(directories)
    directories = directories[: args.max_skills]

    policy = ScanPolicy.default()
    resolved = [directory for directory in directories if resolve_skill_root(directory) is not None]
    if not resolved:
        print("no skill roots resolved under the corpus; check the layout", file=sys.stderr)
        return 1
    rows = collect_findings(directories, policy=policy)
    if not rows:
        # Zero findings across real-world skills means a path or policy problem,
        # not a clean corpus. Fail loudly rather than emit an empty result.
        print(
            f"resolved {len(resolved)}/{len(directories)} skill roots but produced no findings; refusing to emit",
            file=sys.stderr,
        )
        return 1
    sampled = stratified_sample(rows, per_stratum=args.per_stratum)[: args.max_probes]
    probes = build_probes(sampled)
    print(f"scanned {len(directories)} skills, {len(rows)} findings, adjudicating {len(probes)}", file=sys.stderr)

    primary = asyncio.run(adjudicate_many(probes, model=args.primary_model, concurrency=args.concurrency))
    independent = asyncio.run(
        adjudicate_many(probes, model=args.independent_model, concurrency=args.independent_concurrency)
    )

    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e1-finding-reality",
        "blocking": False,
        "scanner_version": scanner_version,
        "seed": SEED,
        "corpus": str(args.corpus),
        "corpus_note": "Unlabeled real-world skills. Nothing here is ground truth; this estimates a rate.",
        "skills_scanned": len(directories),
        "skill_roots_resolved": len(resolved),
        "findings_total": len(rows),
        "findings_sampled": len(sampled),
        "strata": len({(row["rule_id"], row["severity"]) for row in rows}),
        "models": {"primary": args.primary_model, "independent": args.independent_model},
        "results": summarize(sampled, primary, independent),
        "complete": True,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    results = report["results"]
    for name in ("primary", "independent"):
        block = results[name]
        overall = block["overall"]
        print(
            f"{name:12s} usable={block['usable']:4d} errors={block['errors']:3d} "
            f"uncertain={block['uncertain']:3d} real_rate={overall['real_rate']:.3f} "
            f"95%=[{overall['real_rate_95'][0]:.3f},{overall['real_rate_95'][1]:.3f}]"
        )
    agreement = results["agreement"]
    print(
        f"agreement    compared={agreement['compared']} raw={agreement['raw_agreement']:.3f} kappa={agreement['cohen_kappa']:.3f}"
    )
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
