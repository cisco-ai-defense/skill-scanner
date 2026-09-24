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

"""Head-to-head collection runner: this scanner against NVIDIA SkillSpector.

Non-blocking and supplemental, like ``judged_dataset_benchmark.py``.  Nothing here
may feed a release gate, so every row is stamped ``blocking: false``.

This module only *collects*.  Scoring lives in ``score_cross_tool.py`` so that the
decision lenses can be changed, or argued about, without re-running a scan.  That
split is deliberate: the expensive half should not have to be repeated because
someone wants to look at the numbers a different way.

Both tools run at full capability on byte-identical records, and every row carries
its own proof that the capability actually executed.  A scan that mechanically
succeeded while half its analyzers sat disabled is recorded as ``capability_ok:
false`` rather than as a clean bill of health.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.cross_tool import (  # noqa: E402
    CleanCorpus,
    CrossToolError,
    ToolRow,
    write_rows,
)
from evals.lib.cross_tool_adapters import (  # noqa: E402
    SkillScannerAdapter,
    SkillSpectorAdapter,
)

DEFAULT_CORPORA = (
    "msb-source-disjoint",
    "msb-balanced-800",
    "openskillrisk-corpus",
    "harmfulskillbench-corpus",
)

# Corpora with a harmless class, so precision and false-positive rate are defined.
# The positive-only corpora carry recall only; the scorer enforces that.
LABEL_COMPLETE_CORPORA = frozenset({"msb-source-disjoint", "msb-balanced-800"})

# MaliciousSkillBench lists ``claim_source_disjoint_generalization_with_atr_pack_enabled``
# among its prohibited uses. Our ``full`` profile enables every community pack,
# ATR included, so that combination may not be collected for this corpus at all --
# a number that exists is a number that eventually gets quoted. The source-disjoint
# headline therefore runs on the ``core`` profile, which is also the configuration
# the published results used.
_ATR_PROHIBITED_CORPORA = frozenset({"msb-source-disjoint"})


class ProhibitedUseError(CrossToolError):
    """Raised when a requested run would violate a corpus's stated prohibited use."""


def enforce_corpus_prohibitions(corpus: str, tool: str, profile: str) -> None:
    """Refuse a run the corpus licence forbids, rather than trusting discipline."""

    if tool != "skill-scanner":
        return
    if profile == "full" and corpus in _ATR_PROHIBITED_CORPORA:
        raise ProhibitedUseError(
            f"{corpus} prohibits claim_source_disjoint_generalization_with_atr_pack_enabled; "
            f"the 'full' profile enables the ATR pack. Use --profile core for this corpus."
        )


def _git_sha(repo: Path) -> str:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _skillspector_version(executable: Path) -> str:
    try:
        out = subprocess.run(  # noqa: S603
            [str(executable), "--version"], capture_output=True, text=True, timeout=120
        )
        return out.stdout.strip().splitlines()[0] if out.stdout.strip() else "unknown"
    except (OSError, subprocess.SubprocessError, IndexError):
        return "unknown"


def _read_token(path: str | None) -> str | None:
    """Read a bearer token from a file so it never appears in the process list."""

    if not path:
        return None
    return Path(os.path.expanduser(path)).read_text(encoding="utf-8").strip() or None


# Models that the standard bedrock-runtime route cannot serve.
_MANTLE_ONLY_MODELS = re.compile(r"^google\.gemma-4\b")


def our_model_id(model: str | None) -> str | None:
    """Return ``model`` in the form our scanner expects.

    ``--model`` carries the bare Bedrock id because that is what SkillSpector's
    provider wants. Ours reaches Bedrock through LiteLLM, which needs the
    ``bedrock/`` prefix to route at all, so it is added here rather than asking the
    caller to pass the same model twice in two spellings and keep them in step.
    """

    if not model:
        return None
    if "/" in model:
        return model
    if _MANTLE_ONLY_MODELS.match(model):
        # Gemma 4 lives solely behind the mantle route. Prefixing it with plain
        # "bedrock/" produces an id LiteLLM accepts and then fails on per request, so a
        # whole arm runs, reports every record as capability-degraded, and the cause is
        # only visible in the per-record log. Fail at startup instead.
        raise SystemExit(
            f"--model {model} is reachable only through the Bedrock mantle route; pass it as bedrock-mantle/{model}"
        )
    return f"bedrock/{model}"


def build_adapter(tool: str, *, args: argparse.Namespace, use_llm: bool) -> Any:
    """Construct the adapter for ``tool`` at the requested capability."""

    if tool == "skillspector":
        return SkillSpectorAdapter(
            Path(args.skillspector),
            use_llm=use_llm,
            model=(args.model.split("/", 1)[-1] if args.model else None) if use_llm else None,
            region=args.region,
            model_registry=Path(args.model_registry) if args.model_registry else None,
            fail_on_findings=args.fail_on_findings,
            compat_base_url=args.skillspector_compat_base_url,
            compat_token=_read_token(args.skillspector_compat_token_file),
            arm_suffix=args.arm_label,
        )
    if tool == "skill-scanner":
        return SkillScannerAdapter(
            use_llm=use_llm,
            model=our_model_id(args.model) if use_llm else None,
            provider=args.provider,
            use_meta=not args.no_meta,
            profile=args.profile,
        )
    raise CrossToolError(f"unknown tool: {tool}")


def run_tool_on_corpus(
    tool: str,
    corpus: CleanCorpus,
    *,
    args: argparse.Namespace,
    use_llm: bool,
    workers: int,
    limit: int | None,
    progress_every: int,
    shard: tuple[int, int] | None = None,
) -> list[ToolRow]:
    """Scan every record in ``corpus`` with ``tool`` and return the rows.

    SkillSpector runs as a subprocess so threads are the right shape: the work is
    outside our interpreter.  Our own scanner is in-process and rule-pack
    construction is expensive, so it runs single-threaded with one prebuilt
    scanner unless explicitly parallelised, which keeps the comparison's timing
    numbers honest about what each tool costs per skill.
    """

    records = list(corpus.records)
    if limit is not None:
        records = records[:limit]
    if shard is not None:
        index, count = shard
        # Strided rather than contiguous so every shard sees a similar mix of record
        # sizes, which keeps shard wall-clocks comparable.
        records = [record for offset, record in enumerate(records) if offset % count == index]

    rows: list[ToolRow] = []
    started = time.monotonic()

    if workers > 1:
        # One adapter per *thread*, bound through thread-local storage. Indexing adapters
        # by submission offset does not bind them to a thread: a worker that finishes a
        # short record dequeues a later task, and that task can map to an adapter still
        # scanning on another thread. Ours owns a live scanner and mutable per-record
        # state, so two threads inside one adapter can attribute one record's state to
        # another. Thread-local storage makes the binding the code already assumed.
        local = threading.local()

        def scan_with_local_adapter(record: Any) -> ToolRow:
            own = getattr(local, "adapter", None)
            if own is None:
                own = build_adapter(tool, args=args, use_llm=use_llm)
                local.adapter = own
            return own.scan(record.record_id, corpus.name, record.directory, record.label)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scan_with_local_adapter, record): record for record in records}
            for index, future in enumerate(as_completed(futures), start=1):
                rows.append(future.result())
                if progress_every and index % progress_every == 0:
                    _report_progress(tool, corpus.name, index, len(records), started, rows)
    else:
        adapter = build_adapter(tool, args=args, use_llm=use_llm)
        for index, record in enumerate(records, start=1):
            rows.append(adapter.scan(record.record_id, corpus.name, record.directory, record.label))
            if progress_every and index % progress_every == 0:
                _report_progress(tool, corpus.name, index, len(records), started, rows)

    rows.sort(key=lambda row: row.record_id)
    return rows


def _report_progress(tool: str, corpus: str, done: int, total: int, started: float, rows: Sequence[ToolRow]) -> None:
    elapsed = time.monotonic() - started
    rate = done / elapsed if elapsed else 0.0
    remaining = (total - done) / rate if rate else 0.0
    errors = sum(1 for row in rows if row.error)
    degraded = sum(1 for row in rows if not row.capability_ok)
    print(
        f"  [{tool}/{corpus}] {done}/{total} "
        f"{rate:.2f}/s eta {remaining / 60:.1f}m errors={errors} degraded={degraded}",
        flush=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect head-to-head rows for this scanner against NVIDIA SkillSpector."
    )
    parser.add_argument(
        "--clean-root",
        default=os.path.expanduser("~/.skill-scanner-data/clean"),
        help="Directory holding the label-free corpora and their sibling label manifests.",
    )
    parser.add_argument("--corpus", action="append", dest="corpora", help="Repeatable. Defaults to all four.")
    parser.add_argument(
        "--tool",
        action="append",
        dest="tools",
        choices=("skillspector", "skill-scanner"),
        help="Repeatable. Defaults to both.",
    )
    parser.add_argument("--arm", choices=("static", "full_llm"), default="static")
    parser.add_argument("--skillspector", default=os.path.expanduser("~/ssenv/bin/skillspector"))
    parser.add_argument(
        "--model",
        default="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        help="Shared judge model for the LLM arm, as a bare Bedrock id. SkillSpector "
        "receives it unchanged; ours gets a 'bedrock/' prefix for LiteLLM routing. "
        "Gemma 3 cannot be used here: it has no tool-use support, so SkillSpector's "
        "semantic analyzers fail with 'requires a structured assessment response'.",
    )
    parser.add_argument("--provider", default=None, help="Provider override for our scanner.")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--model-registry", default=None, help="SKILLSPECTOR_MODEL_REGISTRY path.")
    parser.add_argument(
        "--skillspector-compat-base-url",
        default=None,
        help="Point SkillSpector at an OpenAI-compatible endpoint instead of Bedrock. "
        "Needed to reach google.gemma-4-26b-a4b, which exists only behind the mantle "
        "route; pair with evals/lib/mantle_proxy.py.",
    )
    parser.add_argument("--skillspector-compat-token-file", default=None)
    parser.add_argument(
        "--arm-label",
        default=None,
        help="Tag distinguishing two runs of the same tool at the same capability on "
        "different models, e.g. 'gemma4'. Becomes the scorer's column suffix.",
    )
    parser.add_argument("--no-meta", action="store_true", help="Disable our meta-analyzer.")
    parser.add_argument(
        "--profile",
        choices=("core", "full"),
        default="core",
        help="Our scanner's rule-pack profile. 'core' is the shipped, recommended and "
        "published configuration; 'full' adds every community pack including ATR. "
        "Defaults to 'core' because 'full' is measurably noisier, and because MSB "
        "source-disjoint forbids ATR-enabled generalization claims.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Record SkillSpector's aggressive gate (exit non-zero on any finding) as well.",
    )
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int, default=None, help="First N records per corpus, for smoke runs.")
    parser.add_argument(
        "--shard",
        default=None,
        help="Process only one stride of the corpus, as 'index/count'. Lets several "
        "processes share a long LLM arm without coordinating.",
    )
    parser.add_argument("--progress-every", type=int, default=50)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)

    clean_root = Path(args.clean_root)
    corpora_names = args.corpora or list(DEFAULT_CORPORA)
    tools = args.tools or ["skill-scanner", "skillspector"]
    use_llm = args.arm == "full_llm"
    shard = None
    if args.shard:
        raw_index, _, raw_count = args.shard.partition("/")
        shard = (int(raw_index), int(raw_count))
        if not 0 <= shard[0] < shard[1]:
            parser.error(f"--shard index out of range: {args.shard}")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    skillspector_path = Path(args.skillspector)
    # One manifest per arm label and shard. Several processes share an arm when --shard is
    # used, and a single manifest.{arm}.json meant each overwrote the others, leaving one
    # shard's record counts standing for the whole run.
    manifest_suffix = f".{args.arm_label}" if args.arm_label else ""
    if shard:
        manifest_suffix += f".shard{shard[0]}of{shard[1]}"
    manifest_path = output_dir / f"manifest.{args.arm}{manifest_suffix}.json"
    manifest: dict[str, Any] = {
        "track": "cross-tool-comparison",
        "blocking": False,
        "blocking_eligible": False,
        "arm": args.arm,
        "generated_at": datetime.now(UTC).isoformat(),
        "host": platform.node(),
        "python": platform.python_version(),
        "skill_scanner_sha": _git_sha(_REPO_ROOT),
        "skillspector_version": _skillspector_version(skillspector_path) if skillspector_path.exists() else "absent",
        "model": args.model if use_llm else None,
        "region": args.region if use_llm else None,
        # Recorded so a partial collection cannot be mistaken for a whole one. A shard
        # covers a stride of the corpus and --limit truncates it, and a manifest that
        # omitted both read as a complete run either way.
        "shard": f"{shard[0]}of{shard[1]}" if shard else None,
        "limit": args.limit,
        # The fairness contract, recorded so a reader can check it rather than
        # trust it.
        "configuration": {
            "both_tools_at_shipped_defaults": True,
            "neither_tool_tuned_on_these_labels": True,
            "suppressions_disabled_both_sides": True,
            "skillspector_transitive_enabled": False,
            "skillspector_transitive_reason": "follows attacker-controlled URLs out of malicious "
            "samples; corpus safety_defaults forbid follow_embedded_links",
            "skillspector_custom_yara_injected": False,
            "labels_outside_scan_scope": True,
            "skill_scanner_profile": args.profile,
            "skill_scanner_virustotal_enabled": False,
            "skill_scanner_virustotal_reason": "needs a credential we do not hold, and its "
            "upload path would redistribute corpus content",
        },
        "corpora": {},
        "runs": [],
    }

    for corpus_name in corpora_names:
        corpus = CleanCorpus.load(clean_root, corpus_name)
        manifest["corpora"][corpus_name] = {
            "records": len(corpus.records),
            "label_counts": dict(corpus.label_counts),
            "tree_sha256": corpus.tree_sha256,
            "label_complete": corpus_name in LABEL_COMPLETE_CORPORA,
        }
        for tool in tools:
            enforce_corpus_prohibitions(corpus_name, tool, args.profile)
            print(
                f"[{args.arm}] {tool} on {corpus_name} ({len(corpus.records)} records)",
                flush=True,
            )
            workers = args.workers
            started = time.monotonic()
            rows = run_tool_on_corpus(
                tool,
                corpus,
                args=args,
                use_llm=use_llm,
                workers=workers,
                limit=args.limit,
                progress_every=args.progress_every,
                shard=shard,
            )
            elapsed = time.monotonic() - started

            # Persist per tool per corpus, immediately. A multi-hour run must not
            # be able to lose completed work to a later failure.
            suffix = f".{args.arm_label}" if args.arm_label else ""
            suffix += f".shard{shard[0]}of{shard[1]}" if shard else ""
            out_path = output_dir / f"{corpus_name}.{tool}.{args.arm}{suffix}.jsonl"
            write_rows(out_path, rows)

            errors = sum(1 for row in rows if row.error)
            degraded = sum(1 for row in rows if not row.capability_ok)
            summary = {
                "tool": tool,
                "corpus": corpus_name,
                "arm": args.arm,
                "rows": len(rows),
                "errors": errors,
                "capability_degraded": degraded,
                "incomplete": sum(1 for row in rows if not row.complete),
                "wall_seconds": round(elapsed, 2),
                "seconds_per_record": round(elapsed / len(rows), 3) if rows else None,
                "input_tokens": sum(row.input_tokens for row in rows),
                "output_tokens": sum(row.output_tokens for row in rows),
                "path": str(out_path),
            }
            manifest["runs"].append(summary)
            print(
                f"  -> {len(rows)} rows, {errors} errors, {degraded} capability-degraded, "
                f"{elapsed / 60:.1f}m ({summary['seconds_per_record']}s/record)",
                flush=True,
            )
            # Written after every run so a crash still leaves a readable manifest.
            manifest["complete"] = False
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    manifest["complete"] = True
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\ncollection complete -> {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
