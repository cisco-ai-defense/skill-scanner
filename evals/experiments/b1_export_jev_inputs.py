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

"""Export the inputs an OpenJev suppression run needs, for transport to the GPU box.

The scanner and the corpora live on the controller; OpenJev lives on a shared GPU
studio reached through a job queue.  Rather than install the scanner there, the
deterministic half runs here and only what the model needs crosses over: the packed
skill text and the categories the rules already fired.  The GPU job then answers
questions about those and writes a value-free prediction file, which is scored back
here.

``value-free`` is the load-bearing property: the exported record carries no label, no
severity, and no verdict.  If the label travelled with the input, a model could score
well by reading it, and the suppression result would be meaningless.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.lib.cross_tool import CleanCorpus, read_rows  # noqa: E402

# OpenJev accepts prompts up to 16,384 tokens. Guard at a pessimistic 2 bytes per
# token: a provider that silently truncates would answer confidently about content it
# never saw, which is a fail-open rather than a low score.
MAX_STATE_BYTES = 28_000


def truncate_middle(text: str, limit: int) -> tuple[str, bool]:
    """Keep the head and tail, drop the middle, and say whether anything was dropped.

    Middle-out because a malicious SKILL.md tends to open with plausible framing and
    carry the payload later; keeping only the head would systematically hide it.
    """

    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    keep = (limit - 64) // 2
    head = encoded[:keep].decode("utf-8", errors="ignore")
    tail = encoded[-keep:].decode("utf-8", errors="ignore")
    return f"{head}\n...[{len(encoded) - 2 * keep} bytes omitted]...\n{tail}", True


def read_skill_text(directory: Path) -> str:
    """Concatenate the skill's text files, SKILL.md first."""

    parts = []
    skill_md = directory / "SKILL.md"
    if skill_md.is_file():
        parts.append(f"=== SKILL.md ===\n{skill_md.read_text(encoding='utf-8', errors='replace')}")
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SKILL.md"):
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parts.append(f"=== {path.relative_to(directory)} ===\n{body}")
    return "\n\n".join(parts)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-root", required=True)
    parser.add_argument("--corpus", default="msb-source-disjoint")
    parser.add_argument(
        "--rows",
        required=True,
        help="Our scanner's rows for this corpus, supplying the categories already fired.",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", required=True)
    parser.add_argument("--labels-output", required=True, help="Labels, kept on this side only.")
    args = parser.parse_args(argv)

    corpus = CleanCorpus.load(Path(args.clean_root), args.corpus)
    by_id = {record.record_id: record for record in corpus.records}

    rows = [row for row in read_rows(Path(args.rows)) if row.capability_ok and not row.error]
    if args.limit:
        rows = rows[: args.limit]

    inputs: list[dict[str, Any]] = []
    labels: dict[str, Any] = {}
    truncated = 0

    for row in rows:
        record = by_id.get(row.record_id)
        if record is None:
            continue
        text = read_skill_text(record.directory)
        state, was_truncated = truncate_middle(text, MAX_STATE_BYTES)
        truncated += was_truncated
        categories = list((row.extra or {}).get("categories") or [])
        inputs.append(
            {
                "record_id": row.record_id,
                "state": state,
                # What the rules already claimed, so the model can be asked per claim.
                "fired_categories": categories,
                "finding_count": row.finding_count,
                "state_sha256": hashlib.sha256(state.encode("utf-8")).hexdigest(),
                "truncated": was_truncated,
            }
        )
        # Labels and severities stay here. Nothing in the exported input reveals them.
        labels[row.record_id] = {
            "label": row.label,
            "max_severity": row.max_severity,
            "finding_count": row.finding_count,
            "categories": categories,
            "unique_rules": list(row.unique_rules),
        }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for item in inputs:
            handle.write(json.dumps(item, sort_keys=True) + "\n")

    labels_path = Path(args.labels_output)
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    labels_path.write_text(
        json.dumps({"corpus": args.corpus, "records": labels, "complete": True}, indent=2, sort_keys=True)
    )

    leaked = [k for k in ("label", "max_severity", "verdict") if any(k in item for item in inputs)]
    print(f"wrote {out} ({len(inputs)} records, {truncated} truncated)")
    print(f"wrote {labels_path} (labels held back)")
    print(f"label leakage check: {'FAILED ' + str(leaked) if leaked else 'clean'}")
    return 1 if leaked else 0


if __name__ == "__main__":
    raise SystemExit(main())
