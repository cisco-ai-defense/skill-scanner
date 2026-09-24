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

"""Run only the LLM judge over a corpus, resumably, for whole-corpus measurement.

The judged arm of ``cross_tool_benchmark`` runs the full scanner per record -- every
static analyzer plus the LLM call. That is right for measuring the product end to end,
but at corpus scale it makes the *client* the bottleneck: the static pipeline costs
about 6.7 cores per record in flight, so the GPUs serving the judge sat mostly idle
waiting for requests. The static findings for these corpora are already stored, so this
runner makes only the model call and the rows are joined to the static rows afterwards
on ``record_id``.

Rows are written in the ``ToolRow`` shape (``tool="skill-scanner"``,
``arm="llm_only"``, findings attributed to the ``llm`` analyzer) so that
``evals/lib/results_store.py`` converts them unchanged.

Two properties matter for a run measured in hours:

* **Resumable.** Rows are appended and flushed as they complete, and on start every
  record id already in the output file is skipped. An interruption costs only the
  requests in flight.
* **Failures are rows, not gaps.** A record the judge could not read is written with
  its diagnostic and ``capability_ok=False``, so a later analysis can count and exclude
  it rather than mistake a missing row for a clean skill.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections.abc import Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.cross_tool import max_severity  # noqa: E402

_DIAGNOSTIC_RULES = frozenset({"LLM_ANALYSIS_FAILED", "LLM_CONTEXT_BUDGET_EXCEEDED"})

_local = threading.local()


def _analyzer(model: str, base_url: str, provider: str) -> Any:
    """One analyzer per thread: it carries per-call state (usage, last_error)."""

    analyzer = getattr(_local, "analyzer", None)
    if analyzer is None:
        from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
        from skill_scanner.core.scan_policy import ScanPolicy

        analyzer = LLMAnalyzer(
            model=model, api_key="local", base_url=base_url, provider=provider, policy=ScanPolicy.default()
        )
        _local.analyzer = analyzer
    loader = getattr(_local, "loader", None)
    if loader is None:
        from skill_scanner.core.loader import SkillLoader

        loader = SkillLoader()
        _local.loader = loader
    return analyzer, loader


def judge_record(record: Any, corpus: str, *, model: str, base_url: str, provider: str) -> dict[str, Any]:
    analyzer, loader = _analyzer(model, base_url, provider)
    started = time.monotonic()
    row: dict[str, Any] = {
        "record_id": record.record_id,
        "corpus": corpus,
        "tool": "skill-scanner",
        "arm": "llm_only",
        "label": record.label,
        "error": None,
    }
    try:
        skill = loader.load_skill(record.directory, lenient=True)
        findings = analyzer.analyze(skill) or []
    except Exception as error:  # noqa: BLE001 - recorded as a row, never silently dropped
        row.update(
            {
                "max_severity": "NONE",
                "severities_present": [],
                "finding_count": 0,
                "unique_rules": [],
                "findings": [],
                "capability_ok": False,
                "capability_detail": "judge raised",
                "complete": False,
                "error": f"{type(error).__name__}: {str(error)[:300]}",
                "duration_seconds": round(time.monotonic() - started, 3),
            }
        )
        return row

    diagnostics = [f for f in findings if str(getattr(f, "rule_id", "")) in _DIAGNOSTIC_RULES]
    real = [f for f in findings if f not in diagnostics]
    severities = [str(getattr(f.severity, "value", f.severity)).upper() for f in real]
    usage = getattr(analyzer, "llm_usage", None) or {}
    row.update(
        {
            "max_severity": max_severity(severities),
            "severities_present": sorted({s for s in severities if s}),
            "finding_count": len(real),
            "unique_rules": sorted({str(f.rule_id) for f in real if f.rule_id}),
            "findings": [
                {
                    "analyzer": "llm",
                    "rule_id": str(f.rule_id),
                    "category": str(getattr(f.category, "value", f.category) or ""),
                    "severity": str(getattr(f.severity, "value", f.severity)).upper(),
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "confidence": (f.metadata or {}).get("confidence"),
                }
                for f in real
            ],
            # The judge's package verdict, kept separately from the findings: the two can
            # disagree, and how often they do is part of measuring the judge.
            "verdict": str(getattr(analyzer, "last_overall_verdict", "") or ""),
            "capability_ok": not diagnostics,
            "capability_detail": ",".join(sorted({str(f.rule_id) for f in diagnostics})),
            "complete": not diagnostics,
            "diagnostic_error": (str(analyzer.last_error)[:300] if diagnostics and analyzer.last_error else None),
            "input_tokens": int(usage.get("input_tokens") or 0),
            "output_tokens": int(usage.get("output_tokens") or 0),
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    )
    return row


@dataclass(frozen=True)
class _Record:
    record_id: str
    label: str | None
    directory: Path


def _load_records(clean_root: Path, name: str) -> list[_Record]:
    """Read the label manifest without stat-ing every record directory.

    ``CleanCorpus.load`` verifies each directory exists before returning, which is the
    right default for a benchmark but takes several minutes per process over 1.88M
    records on a network filesystem. Here a missing directory surfaces when the record
    is loaded and is written as an error row, so nothing is lost by skipping the check.
    """

    manifest = json.loads((clean_root / f"{name}.labels.json").read_text())
    if not manifest.get("complete"):
        raise SystemExit(f"label manifest for {name} is not marked complete")
    root = clean_root / name
    return [
        _Record(str(e["record_id"]), e.get("label"), root / str(e["record_id"])) for e in manifest.get("records") or ()
    ]


def _done_ids(output: Path) -> set[str]:
    done: set[str] = set()
    if not output.exists():
        return done
    with output.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                done.add(json.loads(line)["record_id"])
            except (ValueError, KeyError):
                # A torn final line from an interrupted write; that record is redone.
                continue
    return done


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--clean-root", default="~/.skill-scanner-data/clean")
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--model", default="openai/gemma4")
    parser.add_argument("--provider", default="openai-compatible")
    parser.add_argument("--endpoint", required=True, help="OpenAI-compatible base URL, e.g. http://127.0.0.1:8003/v1")
    parser.add_argument("--shard", default=None, help="'index/count', the same stride rule as the benchmark runner.")
    parser.add_argument(
        "--ids-file",
        default=None,
        help="Judge only these record ids, one per line; used to adjudicate a rule's flags early.",
    )
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    records = _load_records(Path(args.clean_root).expanduser(), args.corpus)
    if args.ids_file:
        wanted = {line.strip() for line in Path(args.ids_file).expanduser().read_text().splitlines() if line.strip()}
        records = [r for r in records if r.record_id in wanted]
    if args.shard:
        index, _, count = args.shard.partition("/")
        records = [r for offset, r in enumerate(records) if offset % int(count) == int(index)]

    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    done = _done_ids(output)
    todo = [r for r in records if r.record_id not in done]
    print(
        f"{args.corpus} shard={args.shard}: {len(records):,} records, {len(done):,} already done, "
        f"{len(todo):,} to judge via {args.endpoint}",
        flush=True,
    )

    started = time.monotonic()
    completed = failed = 0
    lock = threading.Lock()
    with output.open("a", encoding="utf-8") as handle, ThreadPoolExecutor(max_workers=args.workers) as pool:
        # Bounded submission: queueing 1.8M futures up front would hold every record's
        # future in memory for the whole run.
        pending: set[Any] = set()
        iterator = iter(todo)

        def submit_next() -> bool:
            record = next(iterator, None)
            if record is None:
                return False
            pending.add(
                pool.submit(
                    judge_record, record, args.corpus, model=args.model, base_url=args.endpoint, provider=args.provider
                )
            )
            return True

        for _ in range(args.workers * 2):
            if not submit_next():
                break
        while pending:
            finished, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                pending.discard(future)
                row = future.result()
                with lock:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
                    completed += 1
                    failed += 0 if row.get("capability_ok") else 1
                    if completed % 500 == 0:
                        handle.flush()
                        rate = completed / (time.monotonic() - started)
                        remaining = (len(todo) - completed) / rate if rate else 0
                        print(
                            f"  {completed:,}/{len(todo):,}  {rate:.1f} rec/s  eta {remaining / 3600:.1f}h  "
                            f"failed={failed:,}",
                            flush=True,
                        )
                submit_next()
    print(f"done: {completed:,} judged, {failed:,} failed, {time.monotonic() - started:.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
