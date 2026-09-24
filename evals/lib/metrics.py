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

"""Shared scoring primitives for the evaluation harnesses.

``_wilson`` was independently reimplemented in three runners and ``_f1`` in a
fourth.  The three Wilson variants are algebraically identical but disagree on
surface details -- one rounds to six decimals, one returns a tuple where the
others return a list -- so this module exposes the canonical form with those
choices as explicit arguments.  Existing callers are deliberately left alone:
migrating them is optional and must not change any published number.

Everything here is pure and deterministic.  The bootstrap draws from a seeded
generator and uses common random numbers so paired comparisons share draws,
which is what makes a difference interval meaningful rather than a comparison of
two independently resampled numbers.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

# Two-sided 95% normal quantile, matching every existing runner.
Z_95 = 1.959963984540054

# Fixed so bootstrap intervals are reproducible across runs and machines.
DEFAULT_BOOTSTRAP_SEED = 741983


def safe_divide(numerator: float, denominator: float) -> float:
    """Return ``numerator / denominator``, or 0.0 when the denominator is zero."""
    if not denominator:
        return 0.0
    return numerator / denominator


def wilson_interval(
    successes: int,
    total: int,
    *,
    z: float = Z_95,
    digits: int | None = None,
) -> tuple[float, float]:
    """Return the Wilson score interval for *successes* out of *total*.

    Preferred over the normal approximation because it stays inside [0, 1] and
    remains usable at the extremes, which matters here: several corpora sit at
    0% or 100%, where a Wald interval is degenerate.

    ``digits`` rounds both bounds, reproducing the one existing caller that
    rounds to six decimals.  Left as ``None`` the full precision is returned.
    """
    if total <= 0:
        return (0.0, 0.0)

    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)) / denominator

    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    if digits is not None:
        return (round(low, digits), round(high, digits))
    return (low, high)


def f1(precision: float, recall: float) -> float:
    """Harmonic mean of *precision* and *recall*, 0.0 when both are zero."""
    return safe_divide(2.0 * precision * recall, precision + recall)


def binary_metrics(true_positives: int, false_positives: int, false_negatives: int, true_negatives: int) -> dict:
    """Precision, recall, F1 and false-positive rate with Wilson intervals."""
    precision = safe_divide(true_positives, true_positives + false_positives)
    recall = safe_divide(true_positives, true_positives + false_negatives)
    negatives = false_positives + true_negatives
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1(precision, recall),
        "false_positive_rate": safe_divide(false_positives, negatives),
        "recall_95": list(wilson_interval(true_positives, true_positives + false_negatives)),
        "false_positive_rate_95": list(wilson_interval(false_positives, negatives)),
    }


def macro_f1(per_class: Mapping[str, Mapping[str, float]]) -> float:
    """Unweighted mean F1 across classes.

    Unweighted on purpose: the malicious class is the minority in every corpus
    here, and a support-weighted average would let the benign class hide a
    collapse in malicious detection.
    """
    if not per_class:
        return 0.0
    return sum(float(metrics.get("f1", 0.0)) for metrics in per_class.values()) / len(per_class)


def multiclass_metrics(pairs: Iterable[tuple[str, str]], labels: Sequence[str]) -> dict:
    """Accuracy, macro F1, confusion counts and per-class metrics."""
    observations = list(pairs)
    confusion: dict[str, dict[str, int]] = {truth: dict.fromkeys(labels, 0) for truth in labels}
    for truth, predicted in observations:
        if truth in confusion and predicted in confusion[truth]:
            confusion[truth][predicted] += 1

    per_class: dict[str, dict[str, float]] = {}
    for label in labels:
        true_positives = confusion[label][label]
        false_positives = sum(confusion[other][label] for other in labels if other != label)
        false_negatives = sum(count for predicted, count in confusion[label].items() if predicted != label)
        precision = safe_divide(true_positives, true_positives + false_positives)
        recall = safe_divide(true_positives, true_positives + false_negatives)
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1(precision, recall)}

    correct = sum(1 for truth, predicted in observations if truth == predicted)
    return {
        "count": len(observations),
        "accuracy": safe_divide(correct, len(observations)),
        "macro_f1": macro_f1(per_class),
        "confusion": confusion,
        "per_class": per_class,
    }


def calibration(predictions: Iterable[tuple[float, bool]], *, bins: int = 10) -> dict:
    """Brier score, negative log likelihood and expected calibration error.

    A judge that is accurate but badly calibrated cannot be used for confidence
    routing, so these travel with every arm that reports a probability.
    """
    observations = [(min(1.0, max(0.0, float(p))), bool(outcome)) for p, outcome in predictions]
    if not observations:
        return {"count": 0, "brier": 0.0, "nll": 0.0, "ece": 0.0, "bins": []}

    brier = sum((p - outcome) ** 2 for p, outcome in observations) / len(observations)
    epsilon = 1e-12
    nll = -sum(
        math.log(max(p, epsilon)) if outcome else math.log(max(1.0 - p, epsilon)) for p, outcome in observations
    ) / len(observations)

    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for p, outcome in observations:
        index = min(bins - 1, int(p * bins))
        buckets[index].append((p, outcome))

    ece = 0.0
    bin_report = []
    for index, bucket in enumerate(buckets):
        if not bucket:
            bin_report.append({"bin": index, "count": 0, "confidence": 0.0, "accuracy": 0.0})
            continue
        confidence = sum(p for p, _ in bucket) / len(bucket)
        accuracy = sum(1 for _, outcome in bucket if outcome) / len(bucket)
        ece += (len(bucket) / len(observations)) * abs(confidence - accuracy)
        bin_report.append({"bin": index, "count": len(bucket), "confidence": confidence, "accuracy": accuracy})

    return {"count": len(observations), "brier": brier, "nll": nll, "ece": ece, "bins": bin_report}


def bootstrap_interval(
    units: Sequence[Any],
    statistic: Any,
    *,
    resamples: int = 2000,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    percentiles: tuple[float, float] = (2.5, 97.5),
) -> dict:
    """Percentile bootstrap over independent *units*.

    Resampling is over units -- packages or families, never findings -- because
    findings inside one package are correlated and treating them as independent
    understates the interval.
    """
    population = list(units)
    if not population:
        return {"point": 0.0, "low": 0.0, "high": 0.0, "resamples": 0, "unit_count": 0}

    point = float(statistic(population))
    generator = random.Random(seed)
    size = len(population)
    draws: list[float] = []
    for _ in range(resamples):
        sample = [population[generator.randrange(size)] for _ in range(size)]
        draws.append(float(statistic(sample)))
    draws.sort()

    return {
        "point": point,
        "low": _percentile(draws, percentiles[0]),
        "high": _percentile(draws, percentiles[1]),
        "resamples": resamples,
        "unit_count": size,
        "seed": seed,
    }


def paired_bootstrap_difference(
    units: Sequence[Any],
    statistic_a: Any,
    statistic_b: Any,
    *,
    resamples: int = 2000,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    percentiles: tuple[float, float] = (2.5, 97.5),
) -> dict:
    """Interval for ``statistic_a - statistic_b`` using common random numbers.

    Both arms are evaluated on the *same* resample, so shared corpus difficulty
    cancels.  Comparing two independently bootstrapped intervals instead would
    inflate the spread and hide real differences between arms.
    """
    population = list(units)
    if not population:
        return {"difference": 0.0, "low": 0.0, "high": 0.0, "resamples": 0, "unit_count": 0}

    difference = float(statistic_a(population)) - float(statistic_b(population))
    generator = random.Random(seed)
    size = len(population)
    draws: list[float] = []
    for _ in range(resamples):
        sample = [population[generator.randrange(size)] for _ in range(size)]
        draws.append(float(statistic_a(sample)) - float(statistic_b(sample)))
    draws.sort()

    low = _percentile(draws, percentiles[0])
    high = _percentile(draws, percentiles[1])
    return {
        "difference": difference,
        "low": low,
        "high": high,
        "excludes_zero": (low > 0.0) or (high < 0.0),
        "resamples": resamples,
        "unit_count": size,
        "seed": seed,
    }


def _percentile(sorted_values: Sequence[float], percentile: float) -> float:
    """Linear-interpolated percentile over an already-sorted sequence."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = (percentile / 100.0) * (len(sorted_values) - 1)
    lower = int(math.floor(position))
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return float(sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight)
