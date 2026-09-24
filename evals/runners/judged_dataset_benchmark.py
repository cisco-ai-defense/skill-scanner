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

"""Supplemental, non-blocking benchmark with the LLM judge and meta-judge on.

The published deterministic results ran core-only, so the scanner's two most
expensive stages have never been measured on the corpora those results came
from.  This runner closes that gap.

It is deliberately a thin layer over ``public_dataset_benchmark``.  That module
already owns snapshot validation, population hashing, the confusion counts and
the Wilson intervals, and it exposes ``scanner_factory`` as an injection point,
so every metric here is computed by the same code that produced the published
numbers.  The only difference between an arm and the published baseline is which
analyzers are enabled.

**This track is never release evidence.**  Every report is stamped
``blocking: false``.  The release path asserts that ``build_analyzers`` keeps
``use_llm=False`` by default, and nothing here changes that default; the judge is
enabled per-arm, locally, by this runner alone.

Two subtleties that decide whether the numbers mean anything:

*Meta can be skipped entirely.*  Its routing gate returns early when no finding
is ambiguous, so "meta enabled" can mean "meta never ran".  The meta invocation
rate and the routing-reason histogram are therefore reported as first-class
fields, and an arm that requested meta but never invoked it is flagged.

*Meta does not only suppress.*  ``apply_meta_analysis_to_results`` annotates
false positives rather than removing them, and it also appends
``missed_threats``.  So meta can raise recall as well as precision.  This runner
records suppressions and additions separately, because a single F1 hides both,
then strips annotated false positives before scoring so the scored verdict
matches what a user actually sees.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Permit direct execution from the repository checkout.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.runners.public_dataset_benchmark import (  # noqa: E402
    PublicBenchmarkError,
    _core_registry,
    run_public_benchmark,
)
from skill_scanner import __version__ as scanner_version  # noqa: E402
from skill_scanner.core.analyzer_factory import build_analyzers  # noqa: E402
from skill_scanner.core.cel.models import CelMode  # noqa: E402
from skill_scanner.core.rule_registry import PackLoader  # noqa: E402
from skill_scanner.core.scan_policy import ScanPolicy  # noqa: E402
from skill_scanner.core.scanner import SkillScanner  # noqa: E402
from skill_scanner.data import list_available_packs, resolve_rule_packs  # noqa: E402

logger = logging.getLogger(__name__)

TRACK_NAME = "judged-supplemental"

# Default judge model. Gemma 4 is reachable only through the Bedrock mantle
# OpenAI-compatible route, which is why it carries the routing prefix.
DEFAULT_JUDGE_MODEL = "bedrock-mantle/google.gemma-4-26b-a4b"


class JudgedBenchmarkError(ValueError):
    """Raised when a judged arm is misconfigured or produced unusable output."""


@dataclass(frozen=True)
class ArmSpec:
    """One measurement arm: which expensive stages are switched on."""

    name: str
    use_llm: bool
    use_meta: bool
    description: str


ARMS: tuple[ArmSpec, ...] = (
    ArmSpec(
        name="core_only",
        use_llm=False,
        use_meta=False,
        description="Deterministic core. Reproduces the published baseline and validates the harness.",
    ),
    ArmSpec(
        name="core_judge",
        use_llm=True,
        use_meta=False,
        description="Core plus the LLM analyzer, which can add findings the rules missed.",
    ),
    ArmSpec(
        name="core_judge_meta",
        use_llm=True,
        use_meta=True,
        description="Core plus the LLM analyzer plus the meta-judge.",
    ),
    ArmSpec(
        name="core_meta",
        use_llm=False,
        use_meta=True,
        description="Core plus the meta-judge, with the LLM analyzer left off.",
    ),
)

ARMS_BY_NAME: Mapping[str, ArmSpec] = {arm.name: arm for arm in ARMS}


@dataclass
class JudgeTelemetry:
    """Per-arm counters that decide whether an arm's metrics are meaningful."""

    samples: int = 0
    samples_with_findings: int = 0
    llm_analyzer_invocations: int = 0
    llm_failures: int = 0
    llm_verdict_repairs: int = 0
    meta_requested: int = 0
    meta_invoked: int = 0
    meta_failures: int = 0
    meta_routing_reasons: dict[str, int] = field(default_factory=dict)
    meta_suppressed_findings: int = 0
    meta_added_findings: int = 0
    meta_correlation_groups: int = 0
    samples_with_suppression: int = 0
    samples_with_addition: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def record_routing_reason(self, reason: str) -> None:
        self.meta_routing_reasons[reason] = self.meta_routing_reasons.get(reason, 0) + 1

    def as_report(self) -> dict[str, Any]:
        """Render counters plus the rates that make them interpretable."""
        return {
            "samples": self.samples,
            "samples_with_findings": self.samples_with_findings,
            "llm_analyzer_invocations": self.llm_analyzer_invocations,
            "llm_invocation_rate": _rate(self.llm_analyzer_invocations, self.samples),
            "llm_failures": self.llm_failures,
            # A model that contradicts itself loses the analyzer entirely on that
            # package. Measured on Gemma 4 the contradiction is concentrated on
            # benign packages, so this rate is a validity check, not a footnote.
            "llm_failure_rate": _rate(self.llm_failures, self.samples),
            "llm_verdict_repairs": self.llm_verdict_repairs,
            "meta_requested": self.meta_requested,
            "meta_invoked": self.meta_invoked,
            # The headline guard: a low rate means the arm barely differs from core.
            "meta_invoked_rate": _rate(self.meta_invoked, self.samples),
            "meta_invoked_rate_given_findings": _rate(self.meta_invoked, self.samples_with_findings),
            "meta_failures": self.meta_failures,
            "meta_routing_reasons": dict(sorted(self.meta_routing_reasons.items())),
            "meta_suppressed_findings": self.meta_suppressed_findings,
            "meta_added_findings": self.meta_added_findings,
            "meta_correlation_groups": self.meta_correlation_groups,
            "samples_with_suppression": self.samples_with_suppression,
            "samples_with_addition": self.samples_with_addition,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
        }


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


class JudgedScanner:
    """Scanner wrapper that adds the meta-judge pass and records telemetry.

    ``public_dataset_benchmark`` requires only ``scan_skill``, so wrapping rather
    than subclassing keeps this runner independent of scanner internals.
    """

    def __init__(
        self,
        scanner: SkillScanner,
        *,
        arm: ArmSpec,
        telemetry: JudgeTelemetry,
        meta_analyzer: Any = None,
        llm_analyzer: Any = None,
    ) -> None:
        self._scanner = scanner
        self._arm = arm
        self._telemetry = telemetry
        self._meta_analyzer = meta_analyzer
        self._llm_analyzer = llm_analyzer

    # Forwarded so callers that reach for the loader keep working.
    @property
    def loader(self) -> Any:
        return self._scanner.loader

    def scan_skill(self, skill_directory: Path) -> Any:
        result = self._scanner.scan_skill(skill_directory)
        self._telemetry.samples += 1

        findings = list(getattr(result, "findings", None) or [])
        if findings:
            self._telemetry.samples_with_findings += 1
        if self._arm.use_llm and "llm_analyzer" in (getattr(result, "analyzers_used", None) or []):
            self._telemetry.llm_analyzer_invocations += 1
        if self._llm_analyzer is not None:
            if getattr(self._llm_analyzer, "last_error", None):
                self._telemetry.llm_failures += 1
            self._telemetry.llm_verdict_repairs = int(getattr(self._llm_analyzer, "verdict_repairs", 0) or 0)
            # The analyzer reports its own usage per scan. Reading only the meta
            # analyzer's usage, as this did, reported zero tokens for the judge arm
            # and so made its cost unmeasurable.
            usage = getattr(self._llm_analyzer, "llm_usage", None)
            if callable(usage):
                usage = usage()
            if isinstance(usage, Mapping):
                self._telemetry.input_tokens += int(usage.get("input_tokens") or 0)
                self._telemetry.output_tokens += int(usage.get("output_tokens") or 0)

        if self._meta_analyzer is not None:
            self._apply_meta(result, skill_directory)

        # Production semantics: annotated false positives are hidden from the
        # user, so they must not count toward the scored verdict either.  The
        # counts were captured above, before stripping.
        result.findings = [
            finding
            for finding in (getattr(result, "findings", None) or [])
            if not _finding_metadata(finding).get("meta_false_positive", False)
        ]
        return result

    def _apply_meta(self, result: Any, skill_directory: Path) -> None:
        from skill_scanner.core.analyzers.meta_analyzer import apply_meta_analysis_to_results

        findings = list(getattr(result, "findings", None) or [])
        self._telemetry.meta_requested += 1
        if not findings:
            # Mirrors the analyzer's own early return; recorded so the invocation
            # rate cannot be mistaken for a model decision.
            self._telemetry.record_routing_reason("no_findings")
            return

        try:
            skill = self._scanner.loader.load_skill(skill_directory, lenient=True)
            meta_result = asyncio.run(
                self._meta_analyzer.analyze_with_findings(
                    skill=skill,
                    findings=findings,
                    analyzers_used=list(getattr(result, "analyzers_used", None) or []),
                )
            )
        except Exception as error:  # noqa: BLE001 - one bad sample must not void the arm
            self._telemetry.meta_failures += 1
            self._telemetry.record_routing_reason("meta_exception")
            logger.warning("meta-analysis failed for %s: %s", skill_directory.name, error)
            return

        routing = getattr(meta_result, "routing", None) or {}
        if not isinstance(routing, Mapping):
            routing = {}
        reason = str(routing.get("reason") or "unreported")
        self._telemetry.record_routing_reason(reason)
        # The authoritative signal is ``decision``, which is "run" or "skip". Keying
        # on the reason string instead silently reported a zero invocation rate for a
        # sweep where meta had in fact run on most packages.
        if str(routing.get("decision") or "") == "run":
            self._telemetry.meta_invoked += 1

        suppressed = len(getattr(meta_result, "false_positives", None) or [])
        added = len(getattr(meta_result, "missed_threats", None) or [])
        self._telemetry.meta_suppressed_findings += suppressed
        self._telemetry.meta_added_findings += added
        self._telemetry.meta_correlation_groups += len(getattr(meta_result, "correlations", None) or [])
        if suppressed:
            self._telemetry.samples_with_suppression += 1
        if added:
            self._telemetry.samples_with_addition += 1

        result.findings = apply_meta_analysis_to_results(
            original_findings=findings, meta_result=meta_result, skill=skill
        )
        analyzers_used = getattr(result, "analyzers_used", None)
        if isinstance(analyzers_used, list) and "meta_analyzer" not in analyzers_used:
            analyzers_used.append("meta_analyzer")

        usage = getattr(self._meta_analyzer, "llm_usage", None)
        if callable(usage):
            usage = usage()
        if isinstance(usage, Mapping):
            self._telemetry.input_tokens += int(usage.get("input_tokens") or 0)
            self._telemetry.output_tokens += int(usage.get("output_tokens") or 0)


def _finding_metadata(finding: Any) -> Mapping[str, Any]:
    metadata = getattr(finding, "metadata", None)
    return metadata if isinstance(metadata, Mapping) else {}


def _build_meta_analyzer(*, model: str, policy: ScanPolicy, provider: str | None) -> Any:
    """Construct the meta-analyzer the way the CLI does, minus argparse."""
    from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

    return MetaAnalyzer(
        model=model,
        api_key=os.getenv("SKILL_SCANNER_META_LLM_API_KEY") or os.getenv("SKILL_SCANNER_LLM_API_KEY"),
        base_url=os.getenv("SKILL_SCANNER_META_LLM_BASE_URL") or os.getenv("SKILL_SCANNER_LLM_BASE_URL"),
        api_version=os.getenv("SKILL_SCANNER_META_LLM_API_VERSION") or os.getenv("SKILL_SCANNER_LLM_API_VERSION"),
        provider=provider,
        policy=policy,
        max_tokens=policy.llm_analysis.max_output_tokens,
    )


def make_scanner_factory(
    arm: ArmSpec,
    telemetry: JudgeTelemetry,
    *,
    judge_model: str,
    provider: str | None = None,
) -> Callable[[str, CelMode], Any]:
    """Build the ``scanner_factory`` that ``run_public_benchmark`` will call."""

    def factory(detector_profile: str, cel_mode: CelMode) -> Any:
        if detector_profile == "core_only":
            extra_rule_dirs = None
            registry = _core_registry()
        elif detector_profile == "full_packs":
            extra_rule_dirs = resolve_rule_packs(list(list_available_packs()))
            registry = PackLoader().build_registry()
        else:
            raise JudgedBenchmarkError(f"unsupported detector profile for a judged arm: {detector_profile}")

        policy = ScanPolicy.default()
        policy.cel.mode = cel_mode
        analyzers = build_analyzers(
            policy,
            extra_rules_dirs=extra_rule_dirs,
            use_llm=arm.use_llm,
            llm_model=judge_model if arm.use_llm else None,
            llm_provider=provider,
        )
        scanner = SkillScanner(analyzers=analyzers, policy=policy, rule_registry=registry)

        meta_analyzer = None
        if arm.use_meta:
            if len(analyzers) < 2:
                raise JudgedBenchmarkError("meta-analysis requires at least two analyzers")
            meta_analyzer = _build_meta_analyzer(model=judge_model, policy=policy, provider=provider)

        llm_analyzer = next((a for a in analyzers if a.get_name() == "llm_analyzer"), None)
        return JudgedScanner(
            scanner,
            arm=arm,
            telemetry=telemetry,
            meta_analyzer=meta_analyzer,
            llm_analyzer=llm_analyzer,
        )

    return factory


def run_arm(
    arm: ArmSpec,
    *,
    snapshot_dir: Path,
    dataset_id: str | None,
    dataset_lock: Path | None,
    cel_mode: CelMode,
    judge_model: str,
    provider: str | None,
) -> dict[str, Any]:
    """Run one arm and return its report plus telemetry."""
    telemetry = JudgeTelemetry()
    factory = make_scanner_factory(arm, telemetry, judge_model=judge_model, provider=provider)

    report = run_public_benchmark(
        snapshot_dir,
        dataset_id=dataset_id,
        dataset_lock=dataset_lock,
        profile="release",
        cel_mode=cel_mode,
        scanner_factory=factory,
    )

    telemetry_report = telemetry.as_report()
    warnings: list[str] = []
    if arm.use_meta and telemetry_report["meta_invoked"] == 0:
        # Not fatal, but the arm is then indistinguishable from core and must not
        # be presented as a measurement of the meta-judge.
        warnings.append(
            "meta was enabled but never invoked; this arm does not measure the meta-judge. "
            f"routing reasons: {telemetry_report['meta_routing_reasons']}"
        )
    if arm.use_llm and telemetry_report["llm_analyzer_invocations"] == 0:
        warnings.append("the LLM analyzer was enabled but never contributed a finding")

    return {
        "arm": arm.name,
        "description": arm.description,
        "use_llm": arm.use_llm,
        "use_meta": arm.use_meta,
        "judge_model": judge_model if (arm.use_llm or arm.use_meta) else None,
        "telemetry": telemetry_report,
        "warnings": warnings,
        "report": report,
    }


def run_judged_benchmark(
    snapshot_dir: Path,
    *,
    dataset_id: str | None = None,
    dataset_lock: Path | None = None,
    cel_mode: CelMode | str = CelMode.OFF,
    judge_model: str = DEFAULT_JUDGE_MODEL,
    provider: str | None = None,
    arms: Sequence[str] | None = None,
    on_arm_complete: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run the requested arms over one locked snapshot.

    ``on_arm_complete`` is invoked after each arm so a caller can persist partial
    results; an arm can take an hour, and a later failure must not discard it.
    """
    selected = [ARMS_BY_NAME[name] for name in (arms or [arm.name for arm in ARMS])]
    mode = CelMode(cel_mode)

    arm_reports: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for arm in selected:
        try:
            arm_reports.append(
                run_arm(
                    arm,
                    snapshot_dir=snapshot_dir,
                    dataset_id=dataset_id,
                    dataset_lock=dataset_lock,
                    cel_mode=mode,
                    judge_model=judge_model,
                    provider=provider,
                )
            )
        except Exception as error:  # noqa: BLE001 - one arm must not discard the others
            # Arms cost an hour each. Losing three because the fourth was
            # misconfigured is a harness failure, not a result.
            logger.error("arm %s failed: %s", arm.name, error)
            failures.append({"arm": arm.name, "error": f"{type(error).__name__}: {error}"[:300]})
            if on_arm_complete is not None:
                on_arm_complete({"arm": arm.name, "failed": True, "error": failures[-1]["error"]})
            continue
        if on_arm_complete is not None:
            on_arm_complete(arm_reports[-1])

    return {
        "schema_version": 1,
        "kind": "skill-scanner-judged-benchmark",
        # Stamped so this can never be mistaken for release evidence.
        "blocking": False,
        "track": TRACK_NAME,
        "blocking_eligible": False,
        "scanner_version": scanner_version,
        "judge_model": judge_model,
        "cel_mode": mode.value,
        "arms": {report["arm"]: report for report in arm_reports},
        "arm_order": [report["arm"] for report in arm_reports],
        "failed_arms": failures,
        # False when any requested arm failed, so scoring refuses a partial sweep.
        "complete": not failures,
    }


def _unknown_arms(names: Sequence[str]) -> list[str]:
    return [name for name in names if name not in ARMS_BY_NAME]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--dataset-id")
    parser.add_argument("--dataset-lock", type=Path, default=None)
    parser.add_argument("--cel-mode", choices=tuple(mode.value for mode in CelMode), default="off")
    parser.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL)
    parser.add_argument("--provider", default=None)
    parser.add_argument(
        "--arm",
        action="append",
        default=[],
        help=f"arm to run; repeatable. choices: {', '.join(ARMS_BY_NAME)}. default: all",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    unknown = _unknown_arms(args.arm)
    if unknown:
        parser.error(f"unknown arm(s): {', '.join(unknown)}")

    args.output.parent.mkdir(parents=True, exist_ok=True)

    def persist(arm_report: dict[str, Any]) -> None:
        """Write each arm as it finishes, so an hour of work survives a later failure."""
        name = str(arm_report.get("arm") or "unknown")
        path = args.output.with_name(f"{args.output.stem}.{name}{args.output.suffix}")
        path.write_text(json.dumps(arm_report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"  persisted arm {name} to {path}")

    try:
        report = run_judged_benchmark(
            args.snapshot_dir,
            dataset_id=args.dataset_id,
            dataset_lock=args.dataset_lock,
            cel_mode=args.cel_mode,
            judge_model=args.judge_model,
            provider=args.provider,
            arms=args.arm or None,
            on_arm_complete=persist,
        )
    except (PublicBenchmarkError, JudgedBenchmarkError) as error:
        print(f"judged benchmark failed: {error}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    for name in report["arm_order"]:
        arm_report = report["arms"][name]
        telemetry = arm_report["telemetry"]
        print(
            f"{name}: samples={telemetry['samples']} "
            f"llm_rate={telemetry['llm_invocation_rate']:.4f} "
            f"meta_rate={telemetry['meta_invoked_rate']:.4f} "
            f"suppressed={telemetry['meta_suppressed_findings']} "
            f"llm_fail={telemetry['llm_failure_rate']:.4f} "
            f"added={telemetry['meta_added_findings']}"
        )
        for warning in arm_report["warnings"]:
            print(f"  warning: {warning}")
    print(f"judged benchmark written to {args.output} (non-blocking supplemental track)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
