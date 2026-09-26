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

"""Experiment C1: does Llama Prompt Guard 2 screen skills usefully?

``meta-llama/Llama-Prompt-Guard-2-22M`` is a 22M-parameter DeBERTa-v2 sequence
classifier, 283 MB, 512-token context.  It runs on CPU in this experiment: it needs
no GPU, and keeping it local means no skill content leaves our infrastructure.

**What it was trained for matters more than its size.** Prompt Guard detects prompt
injection and jailbreak *attempts in text*.  "Is this skill safe to install" is a
different question: a skill can be malicious through a download-and-execute chain or
a credential exfiltration sink without containing anything an injection classifier
would recognise, and a benign security-education skill can be full of text that looks
exactly like an attack.  So a weak result here is a statement about fit, not about the
model, and the write-up has to say which.

Two things are measured, the same frame used for the System One tier so the results
are comparable:

* **Separation** on a labelled corpus -- AUC, and precision/recall/FPR at thresholds.
* **Flag rate** on unlabelled real published skills, which bounds what enabling it
  would cost users.

The 512-token limit is the sharp edge.  A skill is far longer than that, so each one
is split into overlapping windows and scored by its **maximum** window probability:
an injection occupies one part of a file, and averaging would dilute it away.  That
choice favours detection, so it cannot be blamed for a low recall.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.cross_tool import CleanCorpus  # noqa: E402
from evals.lib.metrics import binary_metrics, wilson_interval  # noqa: E402

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-22M"

# The model's positional limit, special tokens included.
WINDOW_TOKENS = 512
# Tokens of overlap between consecutive windows, so an injection split across a window
# boundary still lands whole in one of them. Without it a chunk edge could hide exactly
# what is being looked for.
WINDOW_OVERLAP = 128

POSITIVE_LABELS = frozenset({"malicious", "contextually_risky", "obviously_malicious"})
NEGATIVE_LABELS = frozenset({"benign"})


def label_class(label: str | None) -> bool | None:
    """True for a positive label, False for a negative one, None when the record is unlabelled.

    An absent or unrecognised label is not a negative: counting it as one would give an
    unlabelled corpus false positives and true negatives it does not have.
    """
    if label in POSITIVE_LABELS:
        return True
    if label in NEGATIVE_LABELS:
        return False
    return None


def spread(records: Sequence[Any], limit: int) -> list[Any]:
    """``limit`` records evenly spaced across the whole list, in order.

    The corpora are ordered harmless-first, so a prefix selects one class only. A stride
    of ``len // limit`` degenerates to a prefix once ``limit`` exceeds half the corpus,
    which is why the indices are spread explicitly.
    """
    if limit <= 0 or limit >= len(records):
        return list(records)
    return [records[(index * len(records)) // limit] for index in range(limit)]


def select_device(requested: str) -> str:
    """Resolve the device to run on, preferring an accelerator when one exists.

    The model is small enough to run on CPU, so a missing GPU is not a blocker. It is
    still worth using one when present: the throughput difference decides whether a
    sweep over millions of records is hours or days.
    """

    import torch

    if requested != "auto":
        return requested
    if torch.cuda.is_available():
        return "cuda"
    if getattr(torch.backends, "mps", None) is not None and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def load_model(model_id: str, device: str = "cpu") -> tuple[Any, Any, str]:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()
    model.to(device)
    return tokenizer, model, device


def read_skill_text(directory: Path) -> str:
    """Concatenate the skill's readable text, largest-signal files included."""

    parts: list[str] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name.startswith("_meta"):
            continue
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n\n".join(parts)


def score_text(text: str, tokenizer: Any, model: Any, *, batch_size: int = 16) -> dict[str, Any]:
    """Return the maximum jailbreak probability over overlapping windows."""

    import torch

    if not text.strip():
        return {"probability": None, "windows": 0, "reason": "no readable text"}

    # The tokenizer's own overflow chunking, rather than hand-sliced id lists: it places
    # the special tokens and pads correctly, and transformers 5 removed the manual
    # build_inputs_with_special_tokens path this first used.
    encoded = tokenizer(
        text,
        truncation=True,
        max_length=WINDOW_TOKENS,
        stride=WINDOW_OVERLAP,
        return_overflowing_tokens=True,
        padding=True,
        return_tensors="pt",
    )
    input_ids = encoded["input_ids"]
    attention_mask = encoded.get("attention_mask")
    count = int(input_ids.shape[0])
    if count == 0:
        return {"probability": None, "windows": 0, "reason": "tokenized to nothing"}

    device = next(model.parameters()).device
    best = 0.0
    with torch.no_grad():
        for offset in range(0, count, batch_size):
            batch = {"input_ids": input_ids[offset : offset + batch_size].to(device)}
            if attention_mask is not None:
                batch["attention_mask"] = attention_mask[offset : offset + batch_size].to(device)
            logits = model(**batch).logits
            # Binary head: index 1 is the malicious/jailbreak class.
            probs = torch.softmax(logits, dim=-1)[:, 1]
            best = max(best, float(probs.max()))
    return {"probability": best, "windows": count, "reason": None}


def auc(scores: Sequence[tuple[float, bool]]) -> float | None:
    """Rank-based AUC, ties averaged. None when a class is absent."""

    positives = [s for s, y in scores if y]
    negatives = [s for s, y in scores if not y]
    if not positives or not negatives:
        return None
    better = ties = 0
    for p in positives:
        for n in negatives:
            if p > n:
                better += 1
            elif p == n:
                ties += 1
    return (better + 0.5 * ties) / (len(positives) * len(negatives))


def score_at(rows: list[dict[str, Any]], threshold: float) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for row in rows:
        probability = row.get("probability")
        if probability is None:
            continue
        fired = probability >= threshold
        if row["positive"] is None:
            # Unlabelled: it has a flag rate, not a place in the confusion matrix.
            continue
        if row["positive"]:
            tp += fired
            fn += not fired
        else:
            fp += fired
            tn += not fired
    if (fp + tn) == 0:
        # Positive-only corpus: precision, F1 and FPR have no denominator, and
        # reporting 1.0/0.0 would read as perfect rather than undefined.
        return {
            "threshold": threshold,
            "true_positives": tp,
            "false_negatives": fn,
            "recall": tp / (tp + fn) if (tp + fn) else 0.0,
            "precision": None,
            "f1": None,
            "false_positive_rate": None,
            "has_negative_class": False,
        }
    metrics = dict(binary_metrics(tp, fp, fn, tn))
    metrics.update({"threshold": threshold, "has_negative_class": True})
    return metrics


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-root", default="~/.skill-scanner-data/clean")
    parser.add_argument("--corpus", action="append", dest="corpora", required=True)
    parser.add_argument("--model", default=MODEL_ID)
    parser.add_argument("--limit", type=int, default=0, help="0 means every record")
    parser.add_argument(
        "--device",
        default="auto",
        help="auto, cpu, cuda, or mps. auto prefers an accelerator when one is present.",
    )
    parser.add_argument("--batch-size", type=int, default=0, help="0 picks 16 on CPU and 128 otherwise.")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    device = select_device(args.device)
    batch_size = args.batch_size or (16 if device == "cpu" else 128)
    print(f"loading {args.model} on {device} (batch {batch_size})", flush=True)
    tokenizer, model, device = load_model(args.model, device)

    report: dict[str, Any] = {
        "experiment": "c1-prompt-guard",
        "blocking": False,
        "model": args.model,
        "device": device,
        "batch_size": batch_size,
        "hypothesis": "a prompt-injection classifier can screen skills for install risk",
        "scoring": {
            "window_tokens": WINDOW_TOKENS,
            "window_overlap": WINDOW_OVERLAP,
            "aggregation": "max over windows",
            "note": "max, not mean: an injection occupies part of a file and averaging would dilute it",
        },
        "corpora": {},
        "complete": False,
    }
    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)

    for name in args.corpora:
        corpus = CleanCorpus.load(Path(args.clean_root).expanduser(), name)
        records = list(corpus.records)
        if args.limit:
            records = spread(records, args.limit)

        rows: list[dict[str, Any]] = []
        started = time.monotonic()
        for index, record in enumerate(records, start=1):
            text = read_skill_text(record.directory)
            result = score_text(text, tokenizer, model, batch_size=batch_size)
            rows.append(
                {
                    "record_id": record.record_id,
                    "label": record.label,
                    "positive": label_class(record.label),
                    "chars": len(text),
                    **result,
                }
            )
            if index % 100 == 0:
                rate = index / (time.monotonic() - started)
                print(f"  [{name}] {index}/{len(records)}  {rate:.1f}/s", flush=True)

        scored = [
            (r["probability"], r["positive"])
            for r in rows
            if r["probability"] is not None and r["positive"] is not None
        ]
        labelled = any(r["positive"] is True for r in rows) and any(r["positive"] is False for r in rows)
        flagged = sum(1 for r in rows if (r["probability"] or 0) >= 0.5)
        usable = sum(1 for r in rows if r["probability"] is not None)

        report["corpora"][name] = {
            "records": len(rows),
            "usable": usable,
            "unreadable": len(rows) - usable,
            "positives": sum(1 for r in rows if r["positive"] is True),
            "negatives": sum(1 for r in rows if r["positive"] is False),
            "unlabelled": sum(1 for r in rows if r["positive"] is None),
            "has_labels": labelled,
            "auc": auc(scored),
            "flag_rate_at_0.5": flagged / usable if usable else None,
            "flag_rate_at_0.5_95": list(wilson_interval(flagged, usable)) if usable else None,
            "thresholds": [score_at(rows, t) for t in (0.5, 0.8, 0.9, 0.99)],
            "wall_seconds": round(time.monotonic() - started, 1),
            "per_record": rows,
        }
        block = report["corpora"][name]
        print(
            f"  -> {name}: AUC {block['auc']} | flag@0.5 "
            f"{(block['flag_rate_at_0.5'] or 0):.2%} | {block['wall_seconds']}s",
            flush=True,
        )
        # Persisted after each corpus so a later one failing cannot lose an earlier one.
        output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))

    report["complete"] = True
    output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
