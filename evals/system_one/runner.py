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

"""Sweep System One arms over a materialized skill corpus.

Writes one value-free prediction row per request plus a completion attestation, so
downstream scoring can refuse to read a partial run.  Sharding is external by
index, because the scanner is sequential per skill and parallelism has to come
from running several processes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.system_one.client import (  # noqa: E402
    DEFAULT_API_KEY_ENV,
    DEFAULT_ENDPOINT,
    Budget,
    Prediction,
    ProviderError,
    evaluate,
    validate_endpoint,
)
from evals.system_one.packing import load_config as load_contexts  # noqa: E402
from evals.system_one.packing import pack_skill, render_state  # noqa: E402
from evals.system_one.questions import build_questions  # noqa: E402
from evals.system_one.questions import load_config as load_questions  # noqa: E402

# Pessimistic guard budget: 32,768 tokens at 2 bytes per token.
GUARD_BUDGET_BYTES = 65536


def resolve_skill_root(directory: Path, *, max_depth: int = 3) -> Path | None:
    """Find the directory holding SKILL.md, which is not always the top level."""
    if (directory / "SKILL.md").is_file():
        return directory
    for depth in range(1, max_depth + 1):
        matches = sorted(directory.glob("/".join(["*"] * depth) + "/SKILL.md"))
        if matches:
            return matches[0].parent
    return None


def declared_purpose(skill_root: Path, *, limit: int = 2000) -> str:
    manifest = skill_root / "SKILL.md"
    if not manifest.is_file():
        return ""
    return manifest.read_text(encoding="utf-8", errors="replace")[:limit]


def _one(
    skill_root: Path,
    *,
    case_id: str,
    contexts: dict[str, Any],
    questions: dict[str, Any],
    model: str,
    model_revision: str,
    question_variant: str,
    context_variant: str,
    api_key: str,
    endpoint: str,
    timeout: int,
    budget: Budget,
) -> Prediction:
    packed = pack_skill(
        skill_root,
        budget_bytes=min(GUARD_BUDGET_BYTES, contexts["hard_reject_bytes"] * 4),
        hard_reject_bytes=contexts["hard_reject_bytes"] * 8,
    )
    if not packed.is_sendable:
        # Never send: a truncated request is answered blind, so fall through to the
        # deterministic decision instead and record why.
        return Prediction(
            case_id=case_id,
            model=model,
            model_revision=model_revision,
            context_variant=context_variant,
            question_variant=question_variant,
            action="not_applicable",
            confidence=0.0,
            detected=False,
            route="error",
            packing_tier=packed.tier.value,
            error_code="oversize_candidate",
        )

    variant = contexts["variants"].get(context_variant)
    if variant is None:
        raise ValueError(f"unknown context variant {context_variant!r}")
    state = render_state(
        packed,
        skill_name=skill_root.name,
        declared_purpose=declared_purpose(skill_root),
        fields=variant["fields"],
    )
    return evaluate(
        case_id=case_id,
        state=state,
        questions=questions,
        model=model,
        model_revision=model_revision,
        question_variant=question_variant,
        context_variant=context_variant,
        api_key=api_key,
        endpoint=endpoint,
        timeout=timeout,
        budget=budget,
        packing_tier=packed.tier.value,
        context_bytes=packed.context_bytes,
        truncated=packed.truncated,
    )


def run(
    skill_dirs: Sequence[Path],
    *,
    model: str,
    model_revision: str,
    question_variant: str,
    instruction_variant: str,
    context_variant: str,
    api_key: str,
    endpoint: str,
    output: Path,
    concurrency: int = 4,
    timeout: int = 60,
    max_usd: float = 20.0,
    input_usd_per_million: float = 0.042,
) -> dict[str, Any]:
    """Run one arm and write predictions plus an attestation."""
    validate_endpoint(endpoint)
    contexts = load_contexts()
    questions = build_questions(load_questions(), instruction_id=instruction_variant, question_id=question_variant)
    budget = Budget(max_usd=max_usd, input_usd_per_million=input_usd_per_million)

    roots: list[tuple[str, Path]] = []
    for directory in skill_dirs:
        root = resolve_skill_root(directory)
        if root is not None:
            roots.append((directory.name, root))

    started = time.time()
    predictions: list[Prediction] = []
    aborted: str | None = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {
            pool.submit(
                _one,
                root,
                case_id=case_id,
                contexts=contexts,
                questions=questions,
                model=model,
                model_revision=model_revision,
                question_variant=question_variant,
                context_variant=context_variant,
                api_key=api_key,
                endpoint=endpoint,
                timeout=timeout,
                budget=budget,
            ): case_id
            for case_id, root in roots
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                predictions.append(future.result())
            except ProviderError as error:
                aborted = str(error)
                break

    predictions.sort(key=lambda prediction: prediction.case_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for prediction in predictions:
            handle.write(json.dumps(prediction.as_row(), sort_keys=True) + "\n")
    os.chmod(output, 0o600)

    errors = sum(1 for prediction in predictions if prediction.error_code)
    meta = {
        "kind": "skill-scanner-system-one-run",
        "model": model,
        "model_revision": model_revision,
        "endpoint": endpoint,
        "context_variant": context_variant,
        "instruction_variant": instruction_variant,
        "question_variant": question_variant,
        "skills_offered": len(skill_dirs),
        "skills_resolved": len(roots),
        "rows": len(predictions),
        "errors": errors,
        "error_rate": (errors / len(predictions)) if predictions else 0.0,
        "input_tokens": budget.actual_tokens,
        "estimated_usd": budget.estimated_usd,
        "duration_s": round(time.time() - started, 1),
        # A run that aborted is explicitly incomplete so scoring refuses it.
        "complete": aborted is None,
        "aborted": aborted,
    }
    meta_path = output.with_suffix(output.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    return meta


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--model", default="jev-1.13.0")
    parser.add_argument("--model-revision", default="jev-1.13.0")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--api-key-env", default=DEFAULT_API_KEY_ENV)
    parser.add_argument("--context", default="K7")
    parser.add_argument("--instruction", default="I3")
    parser.add_argument("--question", default="SQ2")
    parser.add_argument("--max-skills", type=int, default=0)
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-usd", type=float, default=20.0)
    parser.add_argument("--input-usd-per-million", type=float, default=0.042)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    api_key = os.getenv(args.api_key_env, "")
    if not api_key:
        # Names the flag rather than interpolating the argument: the message never needs
        # to carry anything derived from the credential's configuration.
        print("the API key environment variable named by --api-key-env is not set", file=sys.stderr)
        return 1

    directories = sorted(path for path in args.corpus.iterdir() if path.is_dir())
    if args.shards > 1:
        directories = [path for index, path in enumerate(directories) if index % args.shards == args.shard]
    if args.max_skills:
        directories = directories[: args.max_skills]

    meta = run(
        directories,
        model=args.model,
        model_revision=args.model_revision,
        question_variant=args.question,
        instruction_variant=args.instruction,
        context_variant=args.context,
        api_key=api_key,
        endpoint=args.endpoint,
        output=args.output,
        concurrency=args.concurrency,
        timeout=args.timeout,
        max_usd=args.max_usd,
        input_usd_per_million=args.input_usd_per_million,
    )
    print(
        json.dumps(
            {key: meta[key] for key in ("rows", "errors", "error_rate", "estimated_usd", "duration_s", "complete")}
        )
    )
    if not meta["complete"]:
        print(f"run aborted: {meta['aborted']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
