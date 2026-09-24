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

"""Adapters that reduce one scanner's output to a :class:`ToolRow`.

Each adapter owns one tool's quirks so nothing downstream has to know them.  The
recurring hazard both adapters guard against is the same: a scan that fails in a
way that *looks* like a clean bill of health.  A malformed payload, a crashed
subprocess, or a set of analyzers that never ran all produce "no findings", and
treating any of them as a true negative would hand the tool perfect specificity
for free.  So both adapters distinguish three outcomes — a real result, a
mechanical error, and a result whose capability preconditions were not met — and
never collapse the last two into the first.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from evals.lib.cross_tool import CrossToolError, ToolRow, max_severity

# SkillSpector's own workflow deadline defaults to 600s and we raise it so its
# fail-closed ceilings do not truncate large skills.  Our subprocess timeout must
# sit above whatever it is given, so that a slow scan is reported by *its*
# incompleteness machinery rather than killed by us and recorded as our error.
SKILLSPECTOR_WORKFLOW_SECONDS = 1800
_SUBPROCESS_TIMEOUT_SECONDS = SKILLSPECTOR_WORKFLOW_SECONDS + 300

# Statuses that mean "this analyzer did its job or had nothing to do".  Anything
# else -- notably ``disabled`` and ``failed`` -- means the tool was not running at
# the capability we intend to credit it with.
_ACCEPTABLE_ANALYZER_STATUSES = frozenset({"completed", "not_applicable"})

# The analyzers SkillSpector only wires when LLM analysis is enabled. In an LLM arm
# these must report ``completed``; if they report ``disabled_by_configuration`` the
# credentials never reached the tool and the arm measures its static engine while
# claiming to measure its semantic one.
SKILLSPECTOR_SEMANTIC_ANALYZERS = (
    "semantic_developer_intent",
    "semantic_quality_policy",
    "semantic_security_discovery",
)

# Their meta-analyzer arbitrates findings the other analyzers produced, so with
# nothing to arbitrate it correctly reports ``not_applicable`` -- the same early
# return ours makes. Requiring ``completed`` from it flagged every clean record as
# degraded, on both sides of the comparison.
SKILLSPECTOR_CONDITIONAL_ANALYZERS = ("meta_analyzer",)


def _skillspector_env(
    *,
    use_llm: bool,
    model: str | None,
    region: str,
    model_registry: Path | None,
    compat_base_url: str | None = None,
    compat_token: str | None = None,
) -> dict[str, str]:
    """Environment for a maximum-capability SkillSpector run.

    Two provider routes are supported.  By default it talks to standard
    ``bedrock-runtime``.  When ``compat_base_url`` is given it instead speaks
    OpenAI-compatible to a loopback signing proxy, which is the only way it can
    reach ``google.gemma-4-26b-a4b`` -- that model lives solely behind the mantle
    route, which wants SigV4 rather than the static bearer token this tool sends.
    """

    env = dict(os.environ)
    env["SKILLSPECTOR_MAX_WORKFLOW_SECONDS"] = str(SKILLSPECTOR_WORKFLOW_SECONDS)
    env["SKILLSPECTOR_MAX_STATIC_ANALYSIS_SECONDS_PER_ARTIFACT"] = str(SKILLSPECTOR_WORKFLOW_SECONDS // 2)
    # Their OSV client is a live CVE lookup; give it room rather than letting a
    # slow network read look like an absent capability.
    env.setdefault("SKILLSPECTOR_OSV_TIMEOUT", "30")
    env["SKILLSPECTOR_LOG_LEVEL"] = "ERROR"

    if use_llm:
        if compat_base_url:
            env["SKILLSPECTOR_PROVIDER"] = "openai_compatible"
            env["SKILLSPECTOR_COMPAT_BASE_URL"] = compat_base_url
            # Not an AWS credential: it only stops other local processes from using
            # the signer. Passed through the environment of this child alone.
            env["SKILLSPECTOR_COMPAT_API_KEY"] = compat_token or ""
        else:
            # Same model as our judge, reached through the same standard Bedrock
            # runtime, so any measured gap is engine rather than model.
            env["SKILLSPECTOR_PROVIDER"] = "bedrock"
        env["AWS_REGION"] = region
        env["SKILLSPECTOR_TEMPERATURE"] = "0"
        env["SKILLSPECTOR_SEED"] = "0"
        # A silent model substitution would invalidate the whole same-model arm.
        env["SKILLSPECTOR_STRICT_MODEL_VALIDATION"] = "1"
        if model:
            env["SKILLSPECTOR_MODEL"] = model
        if model_registry is not None:
            env["SKILLSPECTOR_MODEL_REGISTRY"] = str(model_registry)
    return env


def _check_analyzer_capability(statuses: Sequence[Mapping[str, Any]], *, use_llm: bool) -> tuple[bool, str]:
    """Return whether every analyzer ran, and a description when one did not."""

    if not statuses:
        return False, "no analyzer_statuses reported"

    problems = []
    by_id = {}
    for status in statuses:
        analyzer_id = str(status.get("analyzer_id") or "?")
        state = str(status.get("status") or "?")
        by_id[analyzer_id] = state
        if state in _ACCEPTABLE_ANALYZER_STATUSES:
            continue
        # In a static arm the semantic analyzers are meant to be off, so
        # ``disabled_by_configuration`` there is the tool working as asked, not a
        # degraded run. Treating it as degraded flagged every static record.
        if (
            not use_llm
            and analyzer_id in (*SKILLSPECTOR_SEMANTIC_ANALYZERS, *SKILLSPECTOR_CONDITIONAL_ANALYZERS)
            and state == "disabled"
        ):
            continue
        reason = status.get("reason_code") or ""
        problems.append(f"{analyzer_id}={state}{f'({reason})' if reason else ''}")

    if use_llm:
        for analyzer_id in SKILLSPECTOR_CONDITIONAL_ANALYZERS:
            observed = by_id.get(analyzer_id)
            if observed not in {"completed", "not_applicable"}:
                problems.append(f"{analyzer_id}={observed or 'absent'}")
        for analyzer_id in SKILLSPECTOR_SEMANTIC_ANALYZERS:
            observed = by_id.get(analyzer_id)
            if observed is None:
                problems.append(f"{analyzer_id}=absent")
            elif observed != "completed":
                # not_applicable is acceptable for a static analyzer with no
                # matching files, but a semantic analyzer in an LLM arm that did
                # not complete means the arm is not measuring what it claims.
                problems.append(f"{analyzer_id}={observed}")

    if problems:
        return False, "; ".join(sorted(set(problems)))
    return True, ""


class SkillSpectorAdapter:
    """Run NVIDIA SkillSpector over a record directory and normalize the result.

    Invoked as a subprocess because that is its supported interface and it keeps
    its LangGraph runtime, YARA compilation and global logging out of our
    process.  Paths are passed as argv entries, never interpolated into a shell
    string, because at least one corpus directory name contains a space.
    """

    tool_name = "skillspector"

    def __init__(
        self,
        executable: Path,
        *,
        use_llm: bool,
        model: str | None = None,
        region: str = "us-east-1",
        model_registry: Path | None = None,
        fail_on_findings: bool = False,
        compat_base_url: str | None = None,
        compat_token: str | None = None,
        arm_suffix: str | None = None,
    ) -> None:
        self.executable = Path(executable)
        if not self.executable.exists():
            raise CrossToolError(f"skillspector executable not found: {self.executable}")
        self.use_llm = use_llm
        self.model = model
        self.region = region
        self.model_registry = model_registry
        # Their aggressive gate: exit non-zero on any active finding. Recorded as
        # a separate lens rather than replacing their shipped score-based gate.
        self.fail_on_findings = fail_on_findings
        self.compat_base_url = compat_base_url
        # Distinguishes two runs of the same tool at the same capability but on
        # different models, so the scorer keeps them as separate columns instead of
        # silently overwriting one with the other.
        self.arm_suffix = arm_suffix
        self._env = _skillspector_env(
            use_llm=use_llm,
            model=model,
            region=region,
            model_registry=model_registry,
            compat_base_url=compat_base_url,
            compat_token=compat_token,
        )

    @property
    def arm(self) -> str:
        stage = "full_llm" if self.use_llm else "static"
        return f"{stage}:{self.arm_suffix}" if self.arm_suffix else stage

    def _argv(self, directory: Path) -> list[str]:
        argv = [str(self.executable), "scan", str(directory), "--format", "json"]
        if not self.use_llm:
            argv.append("--no-llm")
        # Make a partial analysis announce itself in the exit code instead of
        # resembling a clean pass.
        argv.append("--fail-on-incomplete")
        if self.fail_on_findings:
            argv.append("--fail-on-findings")
        # Deliberately absent: --baseline and --use-shipped-baseline (suppression
        # would hide findings), --yara-rules-dir (injecting our rules would
        # confound engine with content), and --transitive (it fetches
        # attacker-controlled URLs out of malicious samples, which the corpus
        # safety defaults forbid).
        return argv

    def scan(self, record_id: str, corpus: str, directory: Path, label: str | None) -> ToolRow:
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - fixed executable, argv list, no shell
                self._argv(directory),
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
                env=self._env,
            )
        except subprocess.TimeoutExpired:
            return self._error_row(record_id, corpus, label, time.monotonic() - started, "timeout")
        duration = time.monotonic() - started

        if not completed.stdout.strip():
            return self._error_row(
                record_id,
                corpus,
                label,
                duration,
                f"empty stdout (rc={completed.returncode}): {completed.stderr.strip()[:200]}",
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            # Never fall back to "no findings" here: that would read as a
            # confident clean verdict on a record we failed to measure.
            return self._error_row(record_id, corpus, label, duration, f"unparsable json: {exc}")

        return self._row_from_payload(record_id, corpus, label, duration, payload, completed.returncode)

    def _row_from_payload(
        self,
        record_id: str,
        corpus: str,
        label: str | None,
        duration: float,
        payload: Mapping[str, Any],
        return_code: int,
    ) -> ToolRow:
        issues = payload.get("issues")
        if not isinstance(issues, list):
            return self._error_row(record_id, corpus, label, duration, "payload has no issues list")

        risk = payload.get("risk_assessment") or {}
        completeness = payload.get("analysis_completeness") or {}
        statuses = completeness.get("analyzer_statuses") or []

        severities = [str(issue.get("severity") or "") for issue in issues]
        # Their per-rule diminishing returns mean a raw issue count is not
        # comparable to ours, so carry the distinct rules as the volume measure.
        rules = sorted({str(issue.get("id") or issue.get("rule_id") or "").strip() for issue in issues} - {""})

        capability_ok, capability_detail = _check_analyzer_capability(statuses, use_llm=self.use_llm)

        # ``is_complete`` is not a trustworthiness signal on these corpora. It goes
        # false whenever a SKILL.md references a file that is not in the bundle, and
        # MaliciousSkillBench stores every record as a lone SKILL.md, so roughly
        # three quarters of records report "partial" with coverage at 100%, nothing
        # uninspected and a non-fatal exception. That is the tool correctly noticing
        # the corpus is truncated, not a degraded scan, so it must not quarantine the
        # row. A *fatal* ledger exception is different and does degrade the result.
        exceptions = completeness.get("ledger_exceptions") or []
        reason_codes = sorted({str(item.get("reason_code") or "?") for item in exceptions})
        fatal = [item for item in exceptions if item.get("fatal") is True]
        if fatal:
            capability_ok = False
            fatal_codes = sorted({str(item.get("reason_code") or "?") for item in fatal})
            detail = f"fatal ledger exception: {','.join(fatal_codes)}"
            capability_detail = f"{capability_detail}; {detail}" if capability_detail else detail

        # Read their decision from the field they emit. It is not a pure function
        # of the score: report.py rewrites SAFE to CAUTION under some conditions,
        # so re-deriving it from the number would disagree with the tool.
        recommendation = str(risk.get("recommendation") or "")
        gate_blocked = recommendation == "DO_NOT_INSTALL"

        return ToolRow(
            record_id=record_id,
            corpus=corpus,
            tool=self.tool_name,
            arm=self.arm,
            label=label,
            max_severity=max_severity(severities),
            severities_present=tuple(sorted({s.upper() for s in severities if s})),
            finding_count=len(issues),
            unique_rules=tuple(rules),
            gate_blocked=gate_blocked,
            gate_detail=recommendation,
            complete=bool(completeness.get("is_complete", False)),
            capability_ok=capability_ok,
            capability_detail=capability_detail,
            duration_seconds=duration,
            error=None,
            extra={
                "risk_score": risk.get("score"),
                "risk_severity": risk.get("severity"),
                "max_issue_severity": risk.get("max_issue_severity"),
                "coverage_percent": completeness.get("coverage_percent"),
                "completeness_status": completeness.get("status"),
                "ledger_exception_reasons": reason_codes,
                "ledger_exceptions_fatal": len(fatal),
                "entirely_uninspected_files": completeness.get("entirely_uninspected_files"),
                "return_code": return_code,
                "analyzer_status_counts": _status_counts(statuses),
                "fail_on_findings_gate": bool(self.fail_on_findings and return_code != 0),
            },
        )

    def _error_row(self, record_id: str, corpus: str, label: str | None, duration: float, error: str) -> ToolRow:
        return ToolRow(
            record_id=record_id,
            corpus=corpus,
            tool=self.tool_name,
            arm=self.arm,
            label=label,
            max_severity="NONE",
            severities_present=(),
            finding_count=0,
            unique_rules=(),
            gate_blocked=None,
            gate_detail="",
            complete=False,
            capability_ok=False,
            capability_detail="scan did not produce a usable result",
            duration_seconds=duration,
            error=error,
        )


def _status_counts(statuses: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for status in statuses:
        state = str(status.get("status") or "?")
        counts[state] = counts.get(state, 0) + 1
    return counts


def _finding_row(finding: Any) -> dict[str, Any]:
    """Flatten one Finding to the fields a false-positive analysis needs.

    ``analyzer`` is the point of this: reducing the deterministic false-positive rate
    means knowing which analyzer and rule fired, not just that the record was flagged.
    Snippets and descriptions are deliberately omitted -- they carry corpus content,
    which the source licences forbid redistributing, and they are not needed to rank a
    rule by how often it fires on harmless records.
    """

    category = getattr(finding, "category", None)
    return {
        "analyzer": str(getattr(finding, "analyzer", None) or "unknown"),
        "rule_id": str(getattr(finding, "rule_id", "") or ""),
        "category": str(getattr(category, "value", category) or ""),
        "severity": _enum_value(getattr(finding, "severity", None)),
        "file_path": getattr(finding, "file_path", None),
        "line_number": getattr(finding, "line_number", None),
        # Confidence lives in metadata for some analyzers and as an attribute for others.
        "confidence": getattr(finding, "confidence", None)
        or (getattr(finding, "metadata", None) or {}).get("confidence"),
    }


class SkillScannerAdapter:
    """Run this scanner over a record directory at full capability.

    Built once per worker process rather than per record: constructing the
    analyzer set compiles rule packs and is far more expensive than a scan.
    """

    tool_name = "skill-scanner"

    # ``core`` is the shipped, recommended configuration and the one the published
    # results used.  ``full`` adds every community rule pack, notably ATR.  Both are
    # measured because "every capability on" turns out not to be the strongest
    # configuration: ATR raises recall steeply and costs far more precision than it
    # buys, so reporting only one of these would misrepresent the tool.
    PROFILES = ("core", "full")

    def __init__(
        self,
        *,
        use_llm: bool,
        model: str | None = None,
        provider: str | None = None,
        use_meta: bool = True,
        profile: str = "full",
    ) -> None:
        if profile not in self.PROFILES:
            raise CrossToolError(f"unknown profile: {profile}")
        self.use_llm = use_llm
        self.use_meta = use_llm and use_meta
        self.model = model
        self.provider = provider
        self.profile = profile
        self._scanner: Any = None
        self._meta: Any = None
        self._llm_analyzer: Any = None
        self._policy: Any = None
        # Meta runs as a separate provider call, so its usage is not inside the
        # scan result. Reading only the scan's usage once reported zero tokens for
        # a judged arm and made its cost unmeasurable.
        self._meta_tokens: tuple[int, int] = (0, 0)
        # Meta can be invoked, degrade on an unparsable response, and still report
        # "ran". Recording its actual effect keeps the report from crediting a stage
        # that changed nothing.
        self._meta_effect: dict[str, Any] = {}

    @property
    def arm(self) -> str:
        stage = "full_llm" if self.use_llm else "static"
        return f"{stage}:{self.profile}"

    def _ensure_built(self) -> None:
        if self._scanner is not None:
            return

        # Imported lazily so a worker process pays the import cost once and a
        # static-only run does not drag in the LLM stack at module import time.
        from evals.runners.public_dataset_benchmark import _core_registry
        from skill_scanner.core.analyzer_factory import build_analyzers
        from skill_scanner.core.rule_registry import PackLoader
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.scanner import SkillScanner
        from skill_scanner.data import list_available_packs, resolve_rule_packs

        policy = ScanPolicy.default()
        if self.profile == "full":
            # Every shipped rule pack, including the community ATR pack.
            extra_rule_dirs = resolve_rule_packs(list(list_available_packs()))
            registry = PackLoader().build_registry()
        else:
            extra_rule_dirs = None
            # The bundled core pack must be registered, not an empty registry: our
            # analyzers emit findings whose rule ids are validated against it, and a
            # bare RuleRegistry() made 82 of 1384 records report
            # FindingContract:...:UNKNOWN_BUNDLED_PYTHON_RULE. Reuse the same helper
            # the public benchmark uses so this profile means the same thing here as
            # it does in the published results.
            registry = _core_registry()

        analyzers = build_analyzers(
            policy,
            extra_rules_dirs=extra_rule_dirs,
            # Static dataflow/AST analysis, the counterpart to SkillSpector's
            # behavioral_ast and behavioral_taint_tracking analyzers. It reads code
            # without executing it, so it is compatible with the corpus rule
            # against running samples.
            use_behavioral=self.profile == "full",
            use_trigger=self.profile == "full",
            # Parity with their SC4 live OSV lookups.
            use_osv=self.profile == "full",
            use_llm=self.use_llm,
            llm_model=self.model if self.use_llm else None,
            llm_provider=self.provider,
        )
        # Deliberately off: VirusTotal and Cisco AI Defense. Both need credentials
        # we do not have here, and the VirusTotal path can upload file content,
        # which the corpus terms forbid for these samples. Recorded as a disclosed
        # gap rather than silently skipped.
        self._policy = policy
        self._scanner = SkillScanner(analyzers=analyzers, policy=policy, rule_registry=registry)
        self._llm_analyzer = next((a for a in analyzers if a.get_name() == "llm_analyzer"), None)

        if self.use_meta:
            from evals.runners.judged_dataset_benchmark import _build_meta_analyzer

            if not self.model:
                # The meta-analyzer has no default model to fall back on, and a
                # silently unconfigured meta stage would be recorded as "ran".
                raise CrossToolError("meta-analysis requires an explicit model id")
            self._meta = _build_meta_analyzer(model=self.model, policy=policy, provider=self.provider)

    def scan(self, record_id: str, corpus: str, directory: Path, label: str | None) -> ToolRow:
        self._ensure_built()
        self._meta_tokens = (0, 0)
        self._meta_effect = {}
        started = time.monotonic()
        try:
            result = self._scanner.scan_skill(directory)
        except Exception as exc:  # noqa: BLE001 - a crash must not read as a clean scan
            return ToolRow(
                record_id=record_id,
                corpus=corpus,
                tool=self.tool_name,
                arm=self.arm,
                label=label,
                max_severity="NONE",
                severities_present=(),
                finding_count=0,
                unique_rules=(),
                gate_blocked=None,
                gate_detail="",
                complete=False,
                capability_ok=False,
                capability_detail="scan raised",
                duration_seconds=time.monotonic() - started,
                error=f"{type(exc).__name__}: {exc}",
            )

        meta_applied = False
        meta_had_work = bool(getattr(result, "findings", None))
        if self._meta is not None:
            try:
                meta_applied = self._apply_meta(result, directory)
            except Exception as exc:  # noqa: BLE001
                return ToolRow(
                    record_id=record_id,
                    corpus=corpus,
                    tool=self.tool_name,
                    arm=self.arm,
                    label=label,
                    max_severity="NONE",
                    severities_present=(),
                    finding_count=0,
                    unique_rules=(),
                    gate_blocked=None,
                    gate_detail="",
                    complete=False,
                    capability_ok=False,
                    capability_detail="meta-analysis raised",
                    duration_seconds=time.monotonic() - started,
                    error=f"meta: {type(exc).__name__}: {exc}",
                )
        duration = time.monotonic() - started

        findings = list(getattr(result, "findings", None) or [])
        severities = [_enum_value(f.severity) for f in findings]
        rules = sorted({str(getattr(f, "rule_id", "") or "").strip() for f in findings} - {""})
        analyzers_used = list(getattr(result, "analyzers_used", None) or [])
        # Per-finding detail, so a false-positive pass can attribute a flag to the
        # analyzer and rule that produced it. The aggregate fields cannot: they collapse
        # every finding on a record into one severity and a set of rule ids.
        finding_rows = tuple(_finding_row(f) for f in findings)

        usage = getattr(result, "llm_usage", None) or {}
        capability_ok, capability_detail = self._check_capability(
            result, analyzers_used, meta_applied, meta_had_work=meta_had_work
        )

        return ToolRow(
            record_id=record_id,
            corpus=corpus,
            tool=self.tool_name,
            arm=self.arm,
            label=label,
            max_severity=max_severity(severities),
            severities_present=tuple(sorted({s for s in severities if s and s != "SAFE"})),
            finding_count=len(findings),
            unique_rules=tuple(rules),
            gate_blocked=not bool(getattr(result, "is_safe", True)),
            gate_detail=_enum_value(getattr(result, "max_severity", None)),
            complete=not bool(getattr(result, "analyzers_failed", None)),
            capability_ok=capability_ok,
            capability_detail=capability_detail,
            duration_seconds=duration,
            input_tokens=int(usage.get("input_tokens") or 0) + self._meta_tokens[0],
            output_tokens=int(usage.get("output_tokens") or 0) + self._meta_tokens[1],
            error=None,
            findings=finding_rows,
            extra={
                "analyzers_used": analyzers_used,
                "analyzers_failed": [dict(f) for f in (getattr(result, "analyzers_failed", None) or [])],
                "meta_applied": meta_applied,
                "meta_effect": dict(self._meta_effect),
                "meta_changed_findings": bool(
                    self._meta_effect.get("false_positives") or self._meta_effect.get("missed_threats")
                ),
                "loader_fallback": any(
                    str(entry.get("analyzer", "")) == "skill_loader"
                    for entry in (getattr(result, "analyzers_failed", None) or [])
                ),
                "categories": sorted({_enum_value(f.category) for f in findings} - {""}),
            },
        )

    def _check_capability(
        self,
        result: Any,
        analyzers_used: Sequence[str],
        meta_applied: bool,
        *,
        meta_had_work: bool = True,
    ) -> tuple[bool, str]:
        """Mirror of the SkillSpector capability check, applied to our own run."""

        problems = []
        # ``skill_loader`` reports a manifest fallback here, which is a property of
        # the corpus rather than a failure of the scan: about 2% of MSB records have
        # no YAML frontmatter, the loader falls back, and analysis proceeds and
        # produces findings. Counting that as a capability failure would quarantine
        # roughly thirty perfectly good records per corpus. A genuine analyzer crash
        # still counts, because that analyzer really did not run.
        failed_analyzers = sorted(
            {str(entry.get("analyzer", "?")) for entry in (getattr(result, "analyzers_failed", None) or [])}
        )
        crashed = [name for name in failed_analyzers if name != "skill_loader"]
        if crashed:
            problems.append(f"analyzers_failed={','.join(crashed)}")
        if not analyzers_used:
            problems.append("no analyzers reported")
        if self.use_llm and "llm_analyzer" not in analyzers_used:
            problems.append("llm_analyzer did not run")
        # Meta may legitimately not run for two reasons: there were no findings to
        # arbitrate, or its own routing gate chose to skip. Both are the stage working
        # as designed, so only a raised exception -- handled by the caller -- counts as
        # a capability failure. The routing decision is recorded on the row instead, so
        # the report can state how often meta actually engaged rather than implying it
        # always did.
        if self.use_meta and meta_had_work and not meta_applied:
            decision = self._meta_effect.get("routing_decision")
            if decision is None:
                problems.append("meta-analysis produced no result")
        if problems:
            return False, "; ".join(problems)
        return True, ""

    def _apply_meta(self, result: Any, directory: Path) -> bool:
        """Run the meta-analyzer over the scan result, returning whether it ran.

        Mirrors the judged benchmark's invocation so this arm means the same thing
        there and here.  Two details are load-bearing.  ``decision`` is the
        authoritative signal for "meta actually ran": keying on the reason string
        once reported a zero invocation rate for a sweep where meta had run on most
        packages.  And ``meta_false_positive`` findings are stripped afterwards
        because production hides them, so leaving them in would score a verdict the
        user would never see.
        """

        from skill_scanner.core.analyzers.meta_analyzer import apply_meta_analysis_to_results

        findings = list(getattr(result, "findings", None) or [])
        if not findings:
            # The analyzer returns early with nothing to arbitrate. Not a failure,
            # and not an invocation either.
            return False

        skill = self._scanner.loader.load_skill(directory, lenient=True)
        meta_result = asyncio.run(
            self._meta.analyze_with_findings(
                skill=skill,
                findings=findings,
                analyzers_used=list(getattr(result, "analyzers_used", None) or []),
            )
        )

        self._meta_effect = {
            "false_positives": len(getattr(meta_result, "false_positives", None) or []),
            "missed_threats": len(getattr(meta_result, "missed_threats", None) or []),
            "correlations": len(getattr(meta_result, "correlations", None) or []),
        }
        result.findings = apply_meta_analysis_to_results(
            original_findings=findings, meta_result=meta_result, skill=skill
        )
        # Production semantics: annotated false positives are hidden from the user,
        # so they must not count toward the scored verdict either.
        result.findings = [
            finding
            for finding in result.findings
            if not (getattr(finding, "metadata", None) or {}).get("meta_false_positive", False)
        ]
        analyzers_used = getattr(result, "analyzers_used", None)
        if isinstance(analyzers_used, list) and "meta_analyzer" not in analyzers_used:
            analyzers_used.append("meta_analyzer")

        usage = getattr(self._meta, "llm_usage", None)
        if callable(usage):
            usage = usage()
        if isinstance(usage, Mapping):
            self._meta_tokens = (
                int(usage.get("input_tokens") or 0),
                int(usage.get("output_tokens") or 0),
            )

        routing = getattr(meta_result, "routing", None) or {}
        if isinstance(routing, Mapping):
            self._meta_effect["routing_decision"] = str(routing.get("decision") or "unreported")
            self._meta_effect["routing_reason"] = str(routing.get("reason") or "unreported")
            return str(routing.get("decision") or "") == "run"
        return True


def _enum_value(value: Any) -> str:
    """Return the plain string for an enum-or-string severity/category."""

    if value is None:
        return ""
    return str(getattr(value, "value", value)).upper()
