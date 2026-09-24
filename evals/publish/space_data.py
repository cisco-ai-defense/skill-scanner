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

"""Published reference numbers and result loading for the results Space.

Everything here is value-free by construction.  The corpora forbid
redistributing sample text, and the evidence reports deliberately exclude it, so
this module carries metrics, counts and digests only.  A loader that cannot find
a result returns ``None`` rather than a placeholder, because a page that silently
shows zeros for a run that never happened is worse than a page that says the run
is missing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Published deterministic figures, transcribed from the write-up they accompany.
# Held as reference so the reproduction can be compared line for line.
PUBLISHED_BLOG_URL = "https://huggingface.co/blog/Vineethsain/tuning-cisco-skill-scanner"
PRIOR_SYSTEM_ONE_SPACE = "https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one"


@dataclass(frozen=True)
class PublishedRow:
    """One published deterministic result, with the headroom it implies."""

    dataset: str
    samples: str
    metric: str
    headroom: str


PUBLISHED_DETERMINISTIC: tuple[PublishedRow, ...] = (
    PublishedRow(
        "MaliciousSkillBench development",
        "6,594 packages",
        "F1 47.73%, precision 99.16%, recall 31.43%, FPR 1.05%",
        "Recall only. At 99.16% precision a demote-only tier cannot improve the headline.",
    ),
    PublishedRow(
        "MaliciousSkillBench source-disjoint",
        "1,384 packages",
        "F1 13.74%, precision 60.75%, recall 7.75%, FPR 7.71%",
        "Both directions. The most informative corpus.",
    ),
    PublishedRow(
        "HarmfulSkillBench",
        "200 positive-risk packages",
        "3.00% HIGH+, 3.50% MEDIUM+",
        "Recall. Its licence forbids F1 and false-positive-rate claims.",
    ),
    PublishedRow(
        "OpenSkillRisk",
        "263 positive-risk packages",
        "28.90% HIGH+, 35.74% MEDIUM+, 8.37% CRITICAL",
        "Recall. Carries a per-task safety policy, so contextual cases are labelled as such.",
    ),
    PublishedRow(
        "NotInject",
        "339 benign text cases",
        "0.00% target injection flag rate at MEDIUM+",
        "Saturated. A regression check only.",
    ),
    PublishedRow(
        "InjecAgent",
        "1,054 canonical signals",
        "100.00% signal recall",
        "Saturated. A regression check only.",
    ),
    PublishedRow(
        "In-Page Prompt Injection",
        "1,101 canonical groups",
        "99.36% signal recall",
        "Saturated. A regression check only.",
    ),
    PublishedRow(
        "DataDog malicious packages",
        "5 selected positives",
        "Signal on 5/5, HIGH+ on 4/5",
        "Too small to move.",
    ),
    PublishedRow(
        "Golden corpus",
        "24 curated packages",
        "24/24 package verdicts, 23/23 finding identities",
        "Regression check.",
    ),
    PublishedRow(
        "Bundled skills snapshot",
        "111 installed skills",
        "27.03% MEDIUM+, 7.21% HIGH+",
        "Precision. A quarter of legitimate installed skills flag.",
    ),
)


@dataclass(frozen=True)
class CorpusShape:
    """Measured size characteristics that decide how a skill can be packed."""

    population: str
    median_files: str
    median_bytes: str
    fits_whole: str


CORPUS_SHAPES: tuple[CorpusShape, ...] = (
    CorpusShape("MaliciousSkillBench rows", "1 (single text field)", "2,936", "essentially all"),
    CorpusShape("ClawHub rows", "2 (skill_md + bundle)", "24,173", "most"),
    CorpusShape("Golden fixtures", "3", "1,797", "100%"),
    CorpusShape("Real-world skills", "80", "576,745", "16%"),
)


@dataclass(frozen=True)
class GemmaFact:
    """A verified property of the only reachable Gemma 4 route."""

    claim: str
    detail: str


GEMMA_FACTS: tuple[GemmaFact, ...] = (
    GemmaFact(
        "One model, one route",
        "google.gemma-4-26b-a4b is reachable only on the Bedrock mantle OpenAI-compatible route. "
        "It is absent from list-foundation-models, there is no model-listing endpoint, and no other "
        "Gemma 4 size exists, so the model id is a pinned constant.",
    ),
    GemmaFact(
        "Strict schema works, after one removal",
        "Schema-constrained JSON succeeds once uniqueItems is stripped; the mantle validator rejects "
        "it outright and the request would otherwise degrade silently to loose JSON mode.",
    ),
    GemmaFact(
        "Context is ample",
        "A 124,989-byte request was accepted at 40,855 prompt tokens, so the scanner's 100,000-character "
        "budget fits with headroom.",
    ),
    GemmaFact(
        "Prompt caching does not engage",
        "cached_tokens and cache_write_tokens stayed at zero across two byte-identical 4,859-token "
        "requests, so the largest assumed cost lever is unavailable on this route.",
    ),
    GemmaFact(
        "Code tokenizes worse than prose",
        "Measured at 3.06 bytes per token on repetitive Python, not the 4.0 a naive estimator assumes, "
        "which is why budgets are enforced in bytes at a pessimistic 2 bytes per token.",
    ),
)


def load_json(path: Path) -> dict[str, Any] | None:
    """Load a result file, or None when it is absent or unreadable."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def require_complete(report: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop a report that does not attest completion.

    An interrupted run's partial numbers look exactly like finished ones once
    rendered, so completion is checked before anything is published.
    """
    if report is None:
        return None
    if report.get("complete") is False:
        return None
    return report


def percent(value: Any, digits: int = 2) -> str:
    """Render a rate as a percentage, or an em-free placeholder when absent."""
    if not isinstance(value, (int, float)):
        return "n/a"
    return f"{float(value) * 100:.{digits}f}%"


def interval(bounds: Any, digits: int = 2) -> str:
    """Render a 95% interval as a percentage range."""
    if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
        return "n/a"
    low, high = bounds
    if not isinstance(low, (int, float)) or not isinstance(high, (int, float)):
        return "n/a"
    return f"{float(low) * 100:.{digits}f} to {float(high) * 100:.{digits}f}"


def count(value: Any) -> str:
    """Render an integer with thousands separators."""
    if not isinstance(value, (int, float)):
        return "n/a"
    return f"{int(value):,}"
