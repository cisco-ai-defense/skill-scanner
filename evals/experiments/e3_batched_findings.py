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

"""E3: does one batched request per skill match one request per finding?

Sending every deterministic finding for a skill in a single request trades two
effects against each other.  Cross-finding context should help, because several
weak signals in one file often are the story.  Attention dilution and a much
longer prompt should hurt, because the model has to hold every finding at once.
Which dominates is an empirical question, and the answer decides the cost of the
whole tier: batching turns N requests per skill into one.

The comparison reuses E1's per-finding verdicts as the reference, so both arms see
the same findings with the same context budget and differ only in grouping.

Decision rule: if agreement with the per-finding arm is high, batch, because it is
far cheaper.  If the batched arm systematically finds less, the saving is being
paid for in recall and per-finding wins.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.experiments.adjudicate import _request, cohen_kappa  # noqa: E402
from evals.experiments.e1_finding_reality import (  # noqa: E402
    DEFAULT_PRIMARY_MODEL,
    SEED,
    collect_findings,
    stratified_sample,
)
from evals.lib.metrics import wilson_interval  # noqa: E402
from evals.system_one.state import bound_value  # noqa: E402
from skill_scanner import __version__ as scanner_version  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402

MAX_BATCH_BYTES = 12288
MAX_EVIDENCE_PER_FINDING = 512

# The batch contract differs from the per-finding one: one entry per index.
_BATCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings", "skill_assessment"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["index", "verdict", "confidence"],
                "properties": {
                    "index": {"type": "integer"},
                    "verdict": {"type": "string", "enum": ["real", "not_applicable", "uncertain"]},
                    "confidence": {"type": "number"},
                },
            },
        },
        "skill_assessment": {"type": "string"},
    },
}

_BATCH_INSTRUCTIONS = """You review the complete list of security findings a static scanner reported for
one agent skill.

A skill is an open specification: it may contain any code, in any language, for any legitimate purpose.
Ordinary development, build, test and example code is normal and is not a security finding.

Important: SKILL.md is not documentation. It is the instruction surface the agent reads and acts on, so
a command written there is closer to executable content than to prose.

You see every finding at once, so use the whole picture: several weak signals in one skill may together
indicate a real problem, and a finding that looks alarming alone may be routine given the rest.

Reply with JSON: {"findings": [{"index": <int>, "verdict": "real"|"not_applicable"|"uncertain",
"confidence": <0..1>}], "skill_assessment": "<one sentence>"}
Return exactly one entry per finding index shown, and no others.
"""


def build_batch_prompt(skill_name: str, purpose: str, rows: list[dict[str, Any]]) -> str:
    """Render one skill's whole finding list inside the batch byte budget."""
    header, _ = bound_value(f"Skill: {skill_name}\nDeclared purpose: {purpose or '(none)'}\n", 1536)
    parts = [header, f"\n{len(rows)} findings:\n"]
    used = sum(len(part.encode()) for part in parts)
    for index, row in enumerate(rows):
        evidence, _ = bound_value(row.get("evidence") or row.get("title") or "", MAX_EVIDENCE_PER_FINDING)
        block = (
            f"\n[{index}] rule={row['rule_id']} severity={row['severity']} "
            f"file={row['file_path'] or 'SKILL.md'}\n  evidence: {evidence}\n"
        )
        cost = len(block.encode())
        if used + cost > MAX_BATCH_BYTES:
            # Bounded rather than silently dropped: the omission is reported.
            parts.append(f"\n[... {len(rows) - index} further findings omitted for budget ...]\n")
            break
        parts.append(block)
        used += cost
    return "".join(parts)


def _parse_batch(payload: str, expected: int) -> dict[int, tuple[str, float]]:
    """Parse a batch answer into index -> (verdict, confidence)."""
    text = payload.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    parsed = json.loads(text)
    out: dict[int, tuple[str, float]] = {}
    for entry in parsed.get("findings") or []:
        try:
            index = int(entry["index"])
        except (KeyError, TypeError, ValueError):
            continue
        verdict = str(entry.get("verdict", "")).strip().lower()
        if verdict not in {"real", "not_applicable", "uncertain"} or not 0 <= index < expected:
            continue
        confidence = entry.get("confidence")
        out[index] = (verdict, float(confidence) if isinstance(confidence, (int, float)) else 0.0)
    return out


async def adjudicate_batch(
    skill_name: str,
    purpose: str,
    rows: list[dict[str, Any]],
    *,
    model: str,
) -> tuple[dict[int, tuple[str, float]], str | None]:
    """Adjudicate one skill's whole finding list in a single request."""
    prompt = build_batch_prompt(skill_name, purpose, rows)
    try:
        raw = await _request(
            model,
            prompt,
            timeout=180,
            instructions=_BATCH_INSTRUCTIONS,
            schema=_BATCH_SCHEMA,
            max_tokens=4096,
        )
        return _parse_batch(raw, len(rows)), None
    except Exception as error:  # noqa: BLE001 - recorded, never dropped
        return {}, f"{type(error).__name__}: {error}"[:300]


async def run_batches(
    grouped: dict[str, list[dict[str, Any]]],
    purposes: dict[str, str],
    *,
    model: str,
    concurrency: int,
) -> tuple[dict[str, dict[int, tuple[str, float]]], dict[str, str]]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: dict[str, dict[int, tuple[str, float]]] = {}
    errors: dict[str, str] = {}

    async def run(skill: str) -> None:
        async with semaphore:
            verdicts, error = await adjudicate_batch(skill, purposes.get(skill, ""), grouped[skill], model=model)
        if error:
            errors[skill] = error
        else:
            results[skill] = verdicts

    await asyncio.gather(*(run(skill) for skill in grouped))
    return results, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--e1-report", type=Path, required=True, help="per-finding reference from E1")
    parser.add_argument("--max-skills", type=int, default=119)
    parser.add_argument("--per-stratum", type=int, default=6)
    parser.add_argument("--max-probes", type=int, default=240)
    parser.add_argument("--model", default=DEFAULT_PRIMARY_MODEL)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    reference = json.loads(args.e1_report.read_text(encoding="utf-8"))
    if reference.get("complete") is False:
        print("E1 reference is incomplete; refusing to compare against it", file=sys.stderr)
        return 1

    directories = sorted(path for path in args.corpus.iterdir() if path.is_dir())
    import random

    random.Random(SEED).shuffle(directories)
    directories = directories[: args.max_skills]

    policy = ScanPolicy.default()
    rows = collect_findings(directories, policy=policy)
    # The same stratified sample E1 adjudicated, so the arms are paired.
    sampled = stratified_sample(rows, per_stratum=args.per_stratum)[: args.max_probes]
    if not sampled:
        print("no findings sampled; refusing to emit", file=sys.stderr)
        return 1

    grouped: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    purposes: dict[str, str] = {}
    for row in sampled:
        grouped[row["skill_name"]].append(row)
        purposes.setdefault(row["skill_name"], row["declared_purpose"])

    print(f"batching {len(sampled)} findings across {len(grouped)} skills", file=sys.stderr)
    batched, batch_errors = asyncio.run(run_batches(grouped, purposes, model=args.model, concurrency=args.concurrency))

    # E1 publishes value-free per-finding verdicts, so the pairing is exact.
    e1_primary: dict[str, str] = {
        finding_id: entry["primary"]
        for finding_id, entry in (reference.get("results", {}).get("per_finding") or {}).items()
        if entry.get("primary")
    }
    if not e1_primary:
        print("E1 reference carries no per-finding verdicts; rerun E1 before comparing", file=sys.stderr)
        return 1

    per_finding: dict[str, str] = {}
    pairs: list[tuple[str, str]] = []
    batch_counts: collections.Counter[str] = collections.Counter()
    missing_entries = 0
    for skill, skill_rows in grouped.items():
        verdicts = batched.get(skill)
        if verdicts is None:
            continue
        for index, row in enumerate(skill_rows):
            entry = verdicts.get(index)
            if entry is None:
                missing_entries += 1
                continue
            verdict = entry[0]
            batch_counts[verdict] += 1
            per_finding[row["finding_id"]] = verdict

    for finding_id, verdict in per_finding.items():
        if finding_id in e1_primary:
            pairs.append((e1_primary[finding_id], verdict))

    decided = batch_counts["real"] + batch_counts["not_applicable"]
    low, high = wilson_interval(batch_counts["real"], decided)
    report = {
        "schema_version": 1,
        "kind": "skill-scanner-experiment-e3-batched-findings",
        "blocking": False,
        "scanner_version": scanner_version,
        "seed": SEED,
        "model": args.model,
        "skills_batched": len(grouped),
        "findings_offered": len(sampled),
        "findings_answered": sum(batch_counts.values()),
        "missing_entries": missing_entries,
        "batch_errors": len(batch_errors),
        "batch_error_samples": list(batch_errors.values())[:5],
        "requests_batched": len(grouped),
        "requests_per_finding": len(sampled),
        "request_reduction": 1 - (len(grouped) / len(sampled)) if sampled else 0.0,
        "batched_verdicts": dict(batch_counts),
        "batched_real_rate": (batch_counts["real"] / decided) if decided else 0.0,
        "batched_real_rate_95": [low, high],
        "paired_with_e1": {
            "compared": len(pairs),
            "raw_agreement": (sum(1 for a, b in pairs if a == b) / len(pairs)) if pairs else 0.0,
            "cohen_kappa": cohen_kappa(pairs),
            "note": "Paired over every finding both arms decided, using E1's published per-finding verdicts.",
        },
        "complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"batched {report['findings_answered']}/{report['findings_offered']} findings in "
        f"{report['requests_batched']} requests instead of {report['requests_per_finding']} "
        f"({report['request_reduction']:.1%} fewer), real_rate={report['batched_real_rate']:.3f} "
        f"errors={report['batch_errors']} missing={report['missing_entries']}"
    )
    print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
