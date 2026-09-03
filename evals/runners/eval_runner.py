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

"""
Evaluation runner for testing analyzer accuracy.

Mirrors MCP Scanner's evaluation framework.
"""

import hashlib
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.runners.finding_matcher import fixture_sha256, match_findings, validate_expectation_document
from skill_scanner.core.analyzer_factory import build_analyzers
from skill_scanner.core.models import Severity
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner


@dataclass
class EvalResult:
    """Result from evaluating a single skill."""

    skill_name: str
    expected_safe: bool | None
    actual_safe: bool | None
    expected_findings_count: int
    actual_findings_count: int
    matched_findings: int
    false_positives: int
    false_negatives: int
    correct: bool
    evaluation_quality: str = "unavailable"
    legacy_degraded_findings: int = 0
    error: str | None = None
    scan_result: Any = field(default=None, repr=False)  # Store the actual scan result for displaying AITech codes


_DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
_OLLAMA_META_BENCHMARK_TEMPERATURE = 0.0
_OLLAMA_META_BENCHMARK_MAX_TOKENS = 16_384
_OLLAMA_META_BENCHMARK_TIMEOUT_SECONDS = 120
_SOURCE_DIGEST_SUFFIXES = frozenset({".go", ".json", ".md", ".proto", ".py", ".yaml", ".yara", ".yml"})
_PROMPT_FILES = (
    "skill_scanner/data/prompts/skill_threat_analysis_prompt.md",
    "skill_scanner/data/prompts/skill_meta_analysis_prompt.md",
    "skill_scanner/data/prompts/llm_response_schema.json",
)


def _sha256_file(path: Path) -> str:
    """Return the exact digest of one benchmark input."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_identity_sha256(test_root: Path, expected_file: Path) -> str:
    """Hash a fixture's stable relative identity without exposing its path."""

    relative = expected_file.relative_to(test_root).as_posix().encode("utf-8")
    digest = hashlib.sha256(b"skill-scanner-eval-fixture-identity-v1\0")
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    return digest.hexdigest()


def _scanner_source_sha256(repository_root: Path) -> str:
    """Hash scanner sources that can influence an LLM/Meta evaluation.

    The working tree is intentionally supported: hashing file names and bytes
    gives an immutable identity even when the benchmark is run before a commit.
    User workspace files, caches, samples, and evaluation payloads are outside
    this narrow source allowlist.
    """

    candidates = [
        path
        for path in (repository_root / "skill_scanner").rglob("*")
        if path.is_file() and path.suffix in _SOURCE_DIGEST_SUFFIXES and "__pycache__" not in path.parts
    ]
    candidates.append(Path(__file__).resolve())
    digest = hashlib.sha256()
    for path in sorted(set(candidates), key=lambda item: item.relative_to(repository_root).as_posix()):
        relative = path.relative_to(repository_root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _evaluation_provenance(model: str | None, model_digest: str | None) -> dict[str, Any]:
    """Build a bounded, secret-free identity for one local benchmark arm."""

    repository_root = Path(__file__).resolve().parents[2]
    supplied_digest = model_digest.strip() if isinstance(model_digest, str) else ""
    normalized_digest = supplied_digest.lower()
    if normalized_digest and (
        len(normalized_digest) != 64
        or any(character not in "0123456789abcdef" for character in normalized_digest)
        or supplied_digest != normalized_digest
    ):
        raise ValueError("Ollama model digest must be exactly 64 lowercase hexadecimal characters")
    return {
        "scanner_source_sha256": _scanner_source_sha256(repository_root),
        "prompt_sha256": {relative: _sha256_file(repository_root / relative) for relative in _PROMPT_FILES},
        "ollama_model": model,
        "ollama_model_digest": normalized_digest or None,
        "ollama_model_digest_status": "supplied" if normalized_digest else "not_supplied",
    }


def _validate_local_ollama_config(model: str | None, base_url: str | None) -> tuple[str, str]:
    """Return a normalized Ollama configuration that cannot target a remote host."""

    if not model or not model.strip():
        raise ValueError(
            "LLM/meta evaluation requires an explicit local Ollama model; pass "
            "--ollama-model ollama/<model> or set SKILL_SCANNER_META_LLM_MODEL"
        )
    normalized_model = model.strip()
    if not normalized_model.lower().startswith("ollama/"):
        raise ValueError("LLM/meta evaluation only permits local Ollama models (model must start with 'ollama/')")

    normalized_base_url = (base_url or _DEFAULT_OLLAMA_BASE_URL).strip().rstrip("/")
    parsed = urlsplit(normalized_base_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("LLM/meta evaluation received an invalid loopback Ollama port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or (port is not None and port == 0)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "LLM/meta evaluation only permits a loopback Ollama endpoint "
            "(http://127.0.0.1:11434, http://localhost:11434, or IPv6 ::1)"
        )
    return normalized_model, normalized_base_url


class EvaluationRunner:
    """Runs evaluation tests on analyzer accuracy."""

    def __init__(
        self,
        test_skills_dir: Path,
        use_llm: bool = False,
        use_meta: bool = False,
        *,
        ollama_model: str | None = None,
        ollama_base_url: str | None = None,
        ollama_model_digest: str | None = None,
        meta_seed: int = 0,
    ):
        """
        Initialize evaluation runner.

        Args:
            test_skills_dir: Directory containing test skills
            use_llm: Whether to use LLM analyzer
            use_meta: Whether to use Meta-Analyzer for false positive filtering
            ollama_model: Explicit ``ollama/<model>`` identifier used by a
                requested meta evaluation (and its primary LLM analyzer).
            ollama_base_url: Loopback-only Ollama endpoint.
            ollama_model_digest: Exact local model digest recorded in the
                benchmark artifact. It is provenance only and is never sent to
                the model provider.
            meta_seed: Reproducibility seed to record with the run. The
                current MetaAnalyzer API cannot pass it to Ollama, so this is
                reported as an explicit reproducibility limitation.
        """
        self.test_skills_dir = test_skills_dir
        self.use_llm = use_llm
        self.use_meta = use_meta
        self.meta_analyzer = None
        self._initialization_error: str | None = None
        self._run_errors: list[dict[str, Any]] = []

        if isinstance(meta_seed, bool) or not isinstance(meta_seed, int):
            self._initialization_error = "meta_seed must be an integer"

        effective_model = ollama_model
        effective_base_url = ollama_base_url
        if use_llm or use_meta:
            if use_meta:
                effective_model = effective_model or os.getenv("SKILL_SCANNER_META_LLM_MODEL")
                effective_base_url = effective_base_url or os.getenv("SKILL_SCANNER_META_LLM_BASE_URL")
            effective_model = effective_model or os.getenv("SKILL_SCANNER_LLM_MODEL")
            effective_base_url = (
                effective_base_url or os.getenv("SKILL_SCANNER_LLM_BASE_URL") or _DEFAULT_OLLAMA_BASE_URL
            )
            if self._initialization_error is None:
                try:
                    effective_model, effective_base_url = _validate_local_ollama_config(
                        effective_model, effective_base_url
                    )
                except ValueError as exc:
                    self._initialization_error = str(exc)

        self.meta_configuration: dict[str, Any] = {
            "requested": use_meta,
            "provider": "ollama" if use_meta else None,
            "model": effective_model if use_meta else None,
            "base_url": effective_base_url if use_meta else None,
            "loopback_only": bool(use_meta),
            "seed": meta_seed if isinstance(meta_seed, int) and not isinstance(meta_seed, bool) else None,
            "seed_applied_to_model": False,
            "reproducibility_limitations": (
                [
                    "MetaAnalyzer does not currently expose an Ollama seed parameter; "
                    "the recorded seed is not applied to model sampling."
                ]
                if use_meta
                else []
            ),
            "status": "not_requested" if not use_meta else "initializing",
        }
        self.llm_configuration: dict[str, Any] = {
            "requested": use_llm,
            "provider": "ollama" if use_llm else None,
            "model": effective_model if use_llm else None,
            "base_url": effective_base_url if use_llm else None,
            "loopback_only": bool(use_llm),
            "status": "not_requested" if not use_llm else "initializing",
        }
        try:
            self.evaluation_provenance = _evaluation_provenance(
                effective_model if use_llm or use_meta else None,
                ollama_model_digest if use_llm or use_meta else None,
            )
        except ValueError as exc:
            if self._initialization_error is None:
                self._initialization_error = str(exc)
                self._record_run_error("initialization", self._initialization_error)
            self.evaluation_provenance = _evaluation_provenance(None, None)

        if self._initialization_error is not None:
            self._record_run_error("initialization", self._initialization_error)
            self.meta_configuration["status"] = "initialization_failed"
            if use_llm:
                self.llm_configuration["status"] = "initialization_failed"

        # Delegate to the centralized factory so eval results match
        # real-world CLI/API scans (same analyzers, same policy).
        policy = ScanPolicy.default()
        analyzers = build_analyzers(
            policy,
            use_llm=use_llm and self._initialization_error is None,
            llm_model=effective_model,
            llm_base_url=effective_base_url,
            llm_provider="ollama" if use_llm or use_meta else None,
        )

        if (
            use_llm
            and self._initialization_error is None
            and not any(analyzer.get_name() == "llm_analyzer" for analyzer in analyzers)
        ):
            self._initialization_error = "Requested local Ollama LLM analyzer could not be initialized"
            self._record_run_error("initialization", self._initialization_error)
            if use_meta:
                self.meta_configuration["status"] = "initialization_failed"
            self.llm_configuration["status"] = "initialization_failed"
        elif use_llm and self._initialization_error is None:
            self.llm_configuration["status"] = "ready"

        # Initialize Meta-Analyzer if requested
        if use_meta and self._initialization_error is None:
            try:
                from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

                self.meta_analyzer = MetaAnalyzer(
                    model=effective_model,
                    base_url=effective_base_url,
                    policy=policy,
                    temperature=_OLLAMA_META_BENCHMARK_TEMPERATURE,
                    max_tokens=_OLLAMA_META_BENCHMARK_MAX_TOKENS,
                    timeout=_OLLAMA_META_BENCHMARK_TIMEOUT_SECONDS,
                )
                self.meta_configuration.update(
                    {
                        "status": "ready",
                        "temperature": self.meta_analyzer.temperature,
                        "max_tokens": self.meta_analyzer.max_tokens,
                        "timeout_seconds": self.meta_analyzer.timeout,
                    }
                )
                repair_policy = getattr(self.meta_analyzer, "contract_repair_policy", None)
                if isinstance(repair_policy, Mapping):
                    policy_identity = dict(repair_policy)
                    self.meta_configuration["contract_repair_policy"] = policy_identity
                    self.evaluation_provenance["meta_contract_repair_policy"] = policy_identity
                response_schema_sha256 = getattr(self.meta_analyzer, "response_schema_sha256", None)
                if isinstance(response_schema_sha256, str):
                    self.meta_configuration["response_schema_sha256"] = response_schema_sha256
                    self.evaluation_provenance["meta_response_schema_sha256"] = response_schema_sha256
                request_options_sha256 = getattr(self.meta_analyzer, "request_options_sha256", None)
                if isinstance(request_options_sha256, str):
                    self.meta_configuration["request_options_sha256"] = request_options_sha256
                    self.evaluation_provenance["meta_request_options_sha256"] = request_options_sha256
                print(
                    "Using local Ollama Meta-Analyzer for false positive filtering and prioritization "
                    f"(model={effective_model}, base_url={effective_base_url}, recorded_seed={meta_seed})"
                )
            except Exception as e:
                self._initialization_error = f"Could not initialize local Ollama Meta-Analyzer: {e}"
                self._record_run_error("initialization", self._initialization_error)
                self.meta_configuration["status"] = "initialization_failed"
                print(f"Error: {self._initialization_error}")

        self.scanner = SkillScanner(analyzers=analyzers, policy=policy)

    def _record_run_error(
        self,
        phase: str,
        message: str,
        *,
        skill_name: str | None = None,
        fixture_identity_sha256: str | None = None,
        fixture_content_sha256: str | None = None,
        failure_diagnostics: list[dict[str, Any]] | None = None,
    ) -> None:
        """Record a stable, JSON-safe error without silently degrading an evaluation."""

        error: dict[str, Any] = {"phase": phase, "message": message}
        if skill_name is not None:
            error["skill_name"] = skill_name
        if fixture_identity_sha256 is not None:
            error["fixture_identity_sha256"] = fixture_identity_sha256
        if fixture_content_sha256 is not None:
            error["fixture_content_sha256"] = fixture_content_sha256
        if failure_diagnostics:
            error["failure_diagnostics"] = [dict(item) for item in failure_diagnostics]
        if error not in self._run_errors:
            self._run_errors.append(error)

    def close(self) -> None:
        """Release the scanner and any persistent CEL helper it owns."""

        close = getattr(getattr(self, "scanner", None), "close", None)
        if callable(close):
            close()

    def run_evaluation(self) -> dict[str, Any]:
        """Run one evaluation and release scanner-owned resources."""

        try:
            return self._run_evaluation()
        finally:
            self.close()

    def _run_evaluation(self) -> dict[str, Any]:
        """
        Run full evaluation suite.

        Returns:
            Evaluation results with metrics
        """
        # A small number of legacy tests construct the runner without calling
        # __init__. Keep that narrow testing seam while making real runs use
        # the fail-closed state initialized above.
        if not hasattr(self, "_run_errors"):
            self._run_errors = []
        if not hasattr(self, "_initialization_error"):
            self._initialization_error = None
        if not hasattr(self, "meta_configuration"):
            self.meta_configuration = {"requested": bool(self.use_meta), "status": "unavailable"}
        if not hasattr(self, "llm_configuration"):
            self.llm_configuration = {"requested": bool(getattr(self, "use_llm", False)), "status": "unavailable"}

        results = []
        paired_primary_results: list[EvalResult] = []
        meta_stats: dict[str, Any] = {
            "total_filtered": 0,
            "total_validated": 0,
            "skills_attempted": 0,
            "skills_processed": 0,
            "skills_failed": 0,
            "contract_repairs_attempted": 0,
            "contract_repairs_succeeded": 0,
            "contract_repairs_failed": 0,
            "contract_repair_error_codes": {},
        }

        # Find all test skills with expected results. Every discovered file
        # contributes to the denominator, including malformed fixtures and
        # scanner failures.
        for expected_file in sorted(self.test_skills_dir.rglob("_expected.json")):
            skill_dir = expected_file.parent
            fixture_identity = _fixture_identity_sha256(self.test_skills_dir, expected_file)
            try:
                fixture_content = fixture_sha256(skill_dir)
            except Exception:
                fixture_content = None
            expected: dict[str, Any] | None = None
            expected_findings: list[Any] = []
            expected_safe: bool | None = None
            evaluation_quality = "unavailable"
            meta_failure_diagnostics: list[dict[str, Any]] = []

            try:
                # Load expected results
                with open(expected_file, encoding="utf-8") as f:
                    loaded_expected = json.load(f)
                expected = loaded_expected if isinstance(loaded_expected, dict) else None
                if expected and isinstance(expected.get("expected_findings"), list):
                    expected_findings = expected["expected_findings"]
                if expected and expected.get("evaluation_quality") in {"strict", "legacy_degraded"}:
                    evaluation_quality = expected["evaluation_quality"]
                validated = validate_expectation_document(loaded_expected, fixture_dir=skill_dir)
                assert expected is not None  # JSON objects validate only after being assigned above.
                expected_safe = validated.expected_safe
                expected_findings = list(validated.expected_findings)
                evaluation_quality = validated.evaluation_quality

                if self._initialization_error is not None:
                    if self.use_meta:
                        meta_stats["skills_failed"] += 1
                    raise RuntimeError(self._initialization_error)
                if self.use_meta and self.meta_analyzer is None:
                    meta_stats["skills_failed"] += 1
                    raise RuntimeError(
                        "Meta evaluation was requested, but the local Ollama Meta-Analyzer is unavailable"
                    )

                # Scan the skill
                scan_result = self.scanner.scan_skill(skill_dir)
                analyzer_failures = getattr(scan_result, "analyzers_failed", None) or []
                if analyzer_failures:
                    raise RuntimeError(
                        f"scanner reported {len(analyzer_failures)} analyzer failure(s): {analyzer_failures}"
                    )

                # Apply requested meta-analysis to every successful scan. An
                # empty candidate set is still a completed meta decision; it
                # must not be silently skipped and presented as "with meta".
                if self.use_meta and self.meta_analyzer:
                    # Capture the exact primary result before Meta mutates the
                    # finding list. This makes the comparison paired: both
                    # arms use one identical primary LLM response rather than
                    # two independently sampled scans.
                    primary_eval_result = self._compare_results(expected, scan_result)
                    primary_eval_result.scan_result = None
                    paired_primary_results.append(primary_eval_result)
                    try:
                        import asyncio

                        from skill_scanner.core.analyzers.meta_analyzer import apply_meta_analysis_to_results
                        from skill_scanner.core.loader import SkillLoader

                        # Load skill for meta-analysis context
                        loader = SkillLoader()
                        skill = loader.load_skill(skill_dir)

                        original_count = len(scan_result.findings)
                        meta_stats["skills_attempted"] += 1

                        # Run meta-analysis asynchronously
                        meta_result = asyncio.run(
                            self.meta_analyzer.analyze_with_findings(
                                skill=skill,
                                findings=scan_result.findings,
                                analyzers_used=scan_result.analyzers_used,
                            )
                        )

                        analysis_warnings = getattr(meta_result, "analysis_warnings", None) or []
                        repair_telemetry = getattr(meta_result, "routing", {}).get("contract_repair", {})
                        if isinstance(repair_telemetry, Mapping):
                            meta_stats["contract_repairs_attempted"] += int(repair_telemetry.get("attempted", 0))
                            meta_stats["contract_repairs_succeeded"] += int(repair_telemetry.get("succeeded", 0))
                            meta_stats["contract_repairs_failed"] += int(repair_telemetry.get("failed", 0))
                            repair_codes = repair_telemetry.get("error_codes", {})
                            if isinstance(repair_codes, Mapping):
                                code_totals = meta_stats["contract_repair_error_codes"]
                                for code, count in sorted(repair_codes.items()):
                                    if isinstance(code, str) and type(count) is int and count >= 0:
                                        code_totals[code] = int(code_totals.get(code, 0)) + count
                        if analysis_warnings:
                            for warning in analysis_warnings:
                                if not isinstance(warning, Mapping):
                                    continue
                                diagnostic = warning.get("failure_diagnostic")
                                if isinstance(diagnostic, Mapping):
                                    meta_failure_diagnostics.append(dict(diagnostic))
                                    continue
                                warning_code = warning.get("code")
                                if isinstance(warning_code, str):
                                    meta_failure_diagnostics.append(
                                        {
                                            "outer_error_code": warning_code,
                                            "inner_error_code": warning_code,
                                            "repair_attempted": int(repair_telemetry.get("attempted", 0)),
                                            "repair_succeeded": int(repair_telemetry.get("succeeded", 0)),
                                        }
                                    )
                            warning_codes = sorted(
                                {
                                    str(warning.get("code", "META_ANALYSIS_DEGRADED"))
                                    for warning in analysis_warnings
                                    if isinstance(warning, dict)
                                }
                            )
                            raise RuntimeError(
                                "Meta-analysis returned an incomplete/degraded result"
                                + (f" ({', '.join(warning_codes)})" if warning_codes else "")
                            )

                        validated_findings = apply_meta_analysis_to_results(
                            original_findings=scan_result.findings,
                            meta_result=meta_result,
                            skill=skill,
                        )
                        filtered_count = original_count - len(validated_findings)

                        # Update scan result with filtered findings
                        scan_result.findings = validated_findings
                        # Note: is_safe is a computed property based on findings
                        scan_result.analyzers_used.append("meta_analyzer")

                        # Track meta stats
                        meta_stats["total_filtered"] += filtered_count
                        meta_stats["total_validated"] += len(validated_findings)
                        meta_stats["skills_processed"] += 1

                        print(
                            f"  Meta-analysis for {scan_result.skill_name}: "
                            f"{len(validated_findings)} validated, {filtered_count} filtered"
                        )
                    except Exception as e:
                        meta_stats["skills_failed"] += 1
                        message = f"Meta-analysis failed for {scan_result.skill_name}: {e}"
                        print(f"  Error: {message}")
                        raise RuntimeError(message) from e

                # Compare with expected
                eval_result = self._compare_results(expected, scan_result)
                results.append(eval_result)

            except Exception as e:
                print(f"Error evaluating {skill_dir}: {e}")
                phase = "meta_analysis" if self.use_meta else "evaluation"
                self._record_run_error(
                    phase,
                    str(e),
                    skill_name=skill_dir.name,
                    fixture_identity_sha256=fixture_identity,
                    fixture_content_sha256=fixture_content,
                    failure_diagnostics=meta_failure_diagnostics,
                )
                if expected_safe is None and expected:
                    if isinstance(expected.get("expected_safe"), bool):
                        expected_safe = expected["expected_safe"]
                    elif isinstance(expected.get("is_malicious"), bool):
                        expected_safe = not expected["is_malicious"]
                    elif expected.get("expected_verdict") in {"safe", "unsafe"}:
                        expected_safe = expected["expected_verdict"] == "safe"
                results.append(
                    EvalResult(
                        skill_name=expected.get("skill_name", skill_dir.name) if expected else skill_dir.name,
                        expected_safe=expected_safe,
                        actual_safe=None,
                        expected_findings_count=len(expected_findings),
                        actual_findings_count=0,
                        matched_findings=0,
                        false_positives=0,
                        false_negatives=len(expected_findings),
                        correct=False,
                        evaluation_quality=evaluation_quality,
                        legacy_degraded_findings=(
                            len(expected_findings) if evaluation_quality == "legacy_degraded" else 0
                        ),
                        error=str(e),
                    )
                )

        # Calculate aggregate metrics
        metrics = self._calculate_metrics(results)

        # Convert results to dict, excluding scan_result from serialization
        individual_results = []
        for r in results:
            result_dict = asdict(r)
            # Remove scan_result from dict (it's not JSON serializable easily)
            result_dict.pop("scan_result", None)
            individual_results.append(result_dict)

        repair_totals = getattr(self.meta_analyzer, "contract_repair_telemetry", None)
        if self.use_meta and isinstance(repair_totals, Mapping):
            repair_telemetry = dict(repair_totals)
            error_codes = repair_telemetry.get("error_codes")
            if isinstance(error_codes, Mapping):
                repair_telemetry["error_codes"] = dict(error_codes)
            self.meta_configuration["contract_repair_telemetry"] = repair_telemetry
            self.evaluation_provenance["meta_contract_repair_telemetry"] = repair_telemetry

        result = {
            "individual_results": individual_results,
            "metrics": metrics,
            "total_skills": len(results),
            "provenance": dict(self.evaluation_provenance),
            "eval_results_with_scan": results,  # Keep full results for display
        }

        complete = not self._run_errors and metrics.get("errors", 0) == 0
        result["run_status"] = {
            "status": "complete" if complete else "incomplete",
            "complete": complete,
            "errors": list(self._run_errors),
        }
        if getattr(self, "use_llm", False):
            if complete:
                self.llm_configuration["status"] = "complete"
            elif self.llm_configuration["status"] != "initialization_failed":
                self.llm_configuration["status"] = "incomplete"
            result["llm_analysis"] = dict(self.llm_configuration)

        # Always expose requested meta state, including initialization and
        # per-skill failures. This prevents a no-meta fallback from looking
        # like a successful with-meta evaluation.
        if self.use_meta:
            if complete:
                self.meta_configuration["status"] = "complete"
            elif self.meta_configuration["status"] != "initialization_failed":
                self.meta_configuration["status"] = "incomplete"
            result["meta_analysis"] = dict(self.meta_configuration)
            result["meta_analysis_stats"] = meta_stats

            primary_complete = len(paired_primary_results) == len(results) and all(
                paired.error is None for paired in paired_primary_results
            )
            primary_configuration = dict(self.llm_configuration)
            primary_configuration["status"] = "complete" if primary_complete else "incomplete"
            result["paired_primary"] = {
                "individual_results": [
                    {key: value for key, value in asdict(paired).items() if key != "scan_result"}
                    for paired in paired_primary_results
                ],
                "metrics": self._calculate_metrics(paired_primary_results),
                "total_skills": len(paired_primary_results),
                "provenance": dict(self.evaluation_provenance),
                "run_status": {
                    "status": "complete" if primary_complete else "incomplete",
                    "complete": primary_complete,
                    "errors": (
                        []
                        if primary_complete
                        else [
                            {
                                "phase": "paired_primary",
                                "message": "A primary result was unavailable for at least one discovered fixture",
                            }
                        ]
                    ),
                },
                "llm_analysis": primary_configuration,
                "eval_results_with_scan": paired_primary_results,
            }

        return result

    def _compare_results(self, expected: dict, scan_result) -> EvalResult:
        """Compare expected vs actual results."""

        quality = expected.get("evaluation_quality")
        if quality == "strict":
            expected_safe = expected.get("expected_verdict") == "safe"
        elif "expected_safe" in expected:
            expected_safe = expected["expected_safe"]
        elif "is_malicious" in expected:
            expected_safe = not expected["is_malicious"]
        else:
            expected_safe = True
        actual_safe = scan_result.is_safe

        expected_findings = expected.get("expected_findings", [])
        actual_findings = scan_result.findings

        match_result = match_findings(expected_findings, actual_findings)
        matched = match_result.matched_count
        false_positives = len(match_result.unmatched_actual_indices)
        false_negatives = len(match_result.unmatched_expected_indices)

        # Overall correctness
        # Exact fixture correctness requires the verdict and both sides of the
        # one-to-one finding set to match.
        correct = expected_safe == actual_safe and false_positives == 0 and false_negatives == 0

        return EvalResult(
            skill_name=scan_result.skill_name,
            expected_safe=expected_safe,
            actual_safe=actual_safe,
            expected_findings_count=len(expected_findings),
            actual_findings_count=len(actual_findings),
            matched_findings=matched,
            false_positives=false_positives,
            false_negatives=false_negatives,
            correct=correct,
            evaluation_quality=quality or "unavailable",
            legacy_degraded_findings=(len(expected_findings) if quality == "legacy_degraded" else 0),
            scan_result=scan_result,  # Store scan result for AITech display
        )

    def _calculate_metrics(self, results: list[EvalResult]) -> dict[str, float | int]:
        """Calculate aggregate metrics."""
        if not results:
            return {}

        total = len(results)
        correct = sum(1 for r in results if r.correct)

        total_tp = sum(r.matched_findings for r in results)
        total_fp = sum(r.false_positives for r in results)
        total_fn = sum(r.false_negatives for r in results)
        total_tn = sum(1 for r in results if r.expected_safe is True and r.actual_safe is True and r.correct)
        total_errors = sum(1 for r in results if r.error is not None)
        strict_identity_skills = sum(1 for r in results if r.evaluation_quality == "strict")
        legacy_degraded_skills = sum(1 for r in results if r.evaluation_quality == "legacy_degraded")
        legacy_degraded_findings = sum(r.legacy_degraded_findings for r in results)

        # Calculate metrics
        accuracy = correct / total if total > 0 else 0
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "true_positives": total_tp,
            "false_positives": total_fp,
            "true_negatives": total_tn,
            "false_negatives": total_fn,
            "errors": total_errors,
            "strict_identity_skills": strict_identity_skills,
            "legacy_degraded_skills": legacy_degraded_skills,
            "legacy_degraded_findings": legacy_degraded_findings,
        }


def print_metrics(results: dict, title: str = "Evaluation Results"):
    """Print evaluation metrics."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    print(f"Total Skills: {results['total_skills']}")
    print("\nMetrics:")
    for key, value in results["metrics"].items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2%}")
        else:
            print(f"  {key}: {value}")

    # Print meta-analysis stats if available
    if "meta_analysis_stats" in results:
        meta_stats = results["meta_analysis_stats"]
        print("\nMeta-Analysis Stats:")
        print(f"  Skills processed: {meta_stats['skills_processed']}")
        print(f"  Total findings validated: {meta_stats['total_validated']}")
        print(f"  Total false positives filtered: {meta_stats['total_filtered']}")
        if meta_stats["total_validated"] + meta_stats["total_filtered"] > 0:
            filter_rate = meta_stats["total_filtered"] / (meta_stats["total_validated"] + meta_stats["total_filtered"])
            print(f"  Filter rate: {filter_rate:.1%}")


def _serializable_evaluation_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Remove display-only objects from an evaluation result recursively."""

    serialized = {key: value for key, value in result.items() if key != "eval_results_with_scan"}
    paired = serialized.get("paired_primary")
    if isinstance(paired, Mapping):
        serialized["paired_primary"] = {key: value for key, value in paired.items() if key != "eval_results_with_scan"}
    return serialized


def run_comparison(
    test_dir: Path,
    show_details: bool = False,
    *,
    ollama_model: str | None = None,
    ollama_base_url: str | None = None,
    ollama_model_digest: str | None = None,
    meta_seed: int = 0,
):
    """Run one primary evaluation and compare its exact pre/post-Meta result."""
    print("=" * 70)
    print("PAIRED META ANALYZER COMPARISON EVALUATION")
    print("Running one primary scan, then applying Meta to that exact result...")
    print("=" * 70)

    print("\n[1/1] Running paired primary + Meta evaluation...")
    runner_with_meta = EvaluationRunner(
        test_dir,
        use_llm=True,
        use_meta=True,
        ollama_model=ollama_model,
        ollama_base_url=ollama_base_url,
        ollama_model_digest=ollama_model_digest,
        meta_seed=meta_seed,
    )
    results_with_meta = runner_with_meta.run_evaluation()
    paired_primary = results_with_meta.get("paired_primary")
    if isinstance(paired_primary, dict):
        results_no_meta = paired_primary
    else:
        results_no_meta = {
            "individual_results": [],
            "metrics": {},
            "total_skills": 0,
            "eval_results_with_scan": [],
            "run_status": {
                "status": "incomplete",
                "complete": False,
                "errors": [
                    {
                        "phase": "paired_primary",
                        "message": "Meta evaluation did not expose its exact primary result",
                    }
                ],
            },
        }

    comparison_complete = bool(results_no_meta["run_status"]["complete"]) and bool(
        results_with_meta["run_status"]["complete"]
    )
    comparison_status = {
        "status": "complete" if comparison_complete else "incomplete",
        "complete": comparison_complete,
        "reason": (
            None
            if comparison_complete
            else "At least one evaluation arm was incomplete; no before/after metric comparison is valid."
        ),
    }
    if not comparison_complete:
        print("\n" + "=" * 70)
        print("COMPARISON INCOMPLETE")
        print("=" * 70)
        print(comparison_status["reason"])
        print("The with-meta arm is not being presented as a successful meta result.")
        return {
            "without_meta": results_no_meta,
            "with_meta": results_with_meta,
            "comparison_status": comparison_status,
        }

    # Print comparison
    print("\n" + "=" * 70)
    print("COMPARISON RESULTS")
    print("=" * 70)

    # Side-by-side metrics
    m1 = results_no_meta["metrics"]
    m2 = results_with_meta["metrics"]

    print("\n{:<25} {:>15} {:>15} {:>12}".format("Metric", "Without Meta", "With Meta", "Change"))
    print("-" * 70)

    for key in ["accuracy", "precision", "recall", "f1_score"]:
        v1 = m1.get(key, 0)
        v2 = m2.get(key, 0)
        change = v2 - v1
        sign = "+" if change >= 0 else ""
        print("{:<25} {:>14.1%} {:>14.1%} {:>11}".format(key.replace("_", " ").title(), v1, v2, f"{sign}{change:.1%}"))

    print("-" * 70)
    for key in ["true_positives", "false_positives", "true_negatives", "false_negatives"]:
        v1 = m1.get(key, 0)
        v2 = m2.get(key, 0)
        change = v2 - v1
        sign = "+" if change >= 0 else ""
        print("{:<25} {:>15} {:>15} {:>12}".format(key.replace("_", " ").title(), v1, v2, f"{sign}{change}"))

    # Meta stats
    if "meta_analysis_stats" in results_with_meta:
        meta_stats = results_with_meta["meta_analysis_stats"]
        print("\n" + "-" * 70)
        print("Meta-Analyzer Impact:")
        print(f"  Total findings filtered: {meta_stats['total_filtered']}")
        print(f"  Total findings validated: {meta_stats['total_validated']}")
        total = meta_stats["total_filtered"] + meta_stats["total_validated"]
        if total > 0:
            print(f"  Noise reduction rate: {meta_stats['total_filtered'] / total:.1%}")

    # Per-skill comparison
    print("\n" + "=" * 70)
    print("PER-SKILL COMPARISON")
    print("=" * 70)
    print("\n{:<30} {:>8} {:>8} {:>10} {:>10}".format("Skill", "Before", "After", "Filtered", "Status"))
    print("-" * 70)

    results_no_meta_by_name = {r.skill_name: r for r in results_no_meta.get("eval_results_with_scan", [])}
    results_with_meta_by_name = {r.skill_name: r for r in results_with_meta.get("eval_results_with_scan", [])}

    for skill_name in results_no_meta_by_name:
        r1 = results_no_meta_by_name.get(skill_name)
        r2 = results_with_meta_by_name.get(skill_name)

        if r1 and r2:
            before = r1.actual_findings_count
            after = r2.actual_findings_count
            filtered = before - after

            # Determine status
            if r2.error:
                status = "✗ EVAL ERROR"
            elif r1.expected_safe:
                if r2.actual_safe:
                    status = "✓ SAFE (correct)"
                else:
                    status = "✗ FP detected"
            else:
                if not r2.actual_safe:
                    status = "✓ UNSAFE (correct)"
                else:
                    status = "✗ MISSED!"

            print(f"{skill_name[:30]:<30} {before:>8} {after:>8} {filtered:>10} {status:>10}")

    # Detailed per-skill analysis if requested
    if show_details:
        print("\n" + "=" * 70)
        print("DETAILED SKILL ANALYSIS")
        print("=" * 70)

        for skill_name in results_no_meta_by_name:
            r1 = results_no_meta_by_name.get(skill_name)
            r2 = results_with_meta_by_name.get(skill_name)

            if not r1 or not r2:
                continue

            print(f"\n--- {skill_name} ---")
            print(f"Expected: {'SAFE' if r1.expected_safe else 'UNSAFE'}")

            # Show what was filtered
            if r1.scan_result and r2.scan_result:
                before_ids = {f.id for f in r1.scan_result.findings}
                after_ids = {f.id for f in r2.scan_result.findings}
                filtered_ids = before_ids - after_ids

                if filtered_ids:
                    print("Filtered out:")
                    for f in r1.scan_result.findings:
                        if f.id in filtered_ids:
                            print(f"  - [{f.analyzer}] {f.category.value} [{f.severity.value}]: {f.title[:45]}...")

                print("Kept:")
                for f in r2.scan_result.findings:
                    conf = f.metadata.get("meta_confidence", "N/A")
                    print(f"  + [{f.analyzer}] {f.category.value} [{f.severity.value}] (conf: {conf})")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Count correctly classified
    safe_correct_before = sum(
        1 for r in results_no_meta.get("eval_results_with_scan", []) if r.expected_safe and r.actual_safe
    )
    safe_correct_after = sum(
        1 for r in results_with_meta.get("eval_results_with_scan", []) if r.expected_safe and r.actual_safe
    )
    unsafe_correct_before = sum(
        1
        for r in results_no_meta.get("eval_results_with_scan", [])
        if r.expected_safe is False and r.actual_safe is False and r.error is None
    )
    unsafe_correct_after = sum(
        1
        for r in results_with_meta.get("eval_results_with_scan", [])
        if r.expected_safe is False and r.actual_safe is False and r.error is None
    )

    total_safe = sum(1 for r in results_no_meta.get("eval_results_with_scan", []) if r.expected_safe)
    total_unsafe = sum(1 for r in results_no_meta.get("eval_results_with_scan", []) if r.expected_safe is False)

    print(f"\nSafe Skills Detection:   {safe_correct_before}/{total_safe} -> {safe_correct_after}/{total_safe}")
    print(f"Unsafe Skills Detection: {unsafe_correct_before}/{total_unsafe} -> {unsafe_correct_after}/{total_unsafe}")

    # Key insight
    if "meta_analysis_stats" in results_with_meta:
        meta_stats = results_with_meta["meta_analysis_stats"]
        print("\nKey Insight:")
        print(f"  Meta-Analyzer filtered {meta_stats['total_filtered']} low-value findings")
        print(f"  while maintaining {unsafe_correct_after}/{total_unsafe} unsafe skill detection rate")

        improved = safe_correct_after > safe_correct_before or unsafe_correct_after > unsafe_correct_before
        if improved and safe_correct_after >= safe_correct_before and unsafe_correct_after >= unsafe_correct_before:
            print("\n  ✓ Meta-Analyzer IMPROVED signal-to-noise without losing detection capability!")
        elif safe_correct_after == safe_correct_before and unsafe_correct_after == unsafe_correct_before:
            print("\n  Meta-Analyzer did not change the paired classification outcome.")
        elif unsafe_correct_after < unsafe_correct_before:
            print("\n  ⚠ Warning: Meta-Analyzer may have filtered some true positives")

    return {
        "without_meta": results_no_meta,
        "with_meta": results_with_meta,
        "comparison_status": comparison_status,
    }


def main():
    """Main entry point for evaluation."""
    import argparse

    parser = argparse.ArgumentParser(description="Run Skill Scanner evaluations")
    parser.add_argument("--test-skills-dir", default="evals/skills", help="Directory containing test skills")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM analyzer in evaluation")
    parser.add_argument(
        "--use-meta",
        action="store_true",
        help="Use Meta-Analyzer to filter false positives and prioritize findings (requires --use-llm)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run both with and without Meta-Analyzer and show comparison",
    )
    parser.add_argument(
        "--ollama-model",
        help=(
            "Local Ollama model identifier, including the ollama/ prefix "
            "(required for --use-llm, --use-meta, and --compare)"
        ),
    )
    parser.add_argument(
        "--ollama-base-url",
        default=None,
        help=f"Loopback Ollama endpoint (default: {_DEFAULT_OLLAMA_BASE_URL})",
    )
    parser.add_argument(
        "--ollama-model-digest",
        help="Exact 64-character SHA-256 digest of the installed local Ollama model",
    )
    parser.add_argument(
        "--meta-seed",
        type=int,
        default=0,
        help="Seed recorded for meta-evaluation provenance (currently not applied to model sampling)",
    )
    parser.add_argument("--show-aitech", action="store_true", help="Show AITech taxonomy codes in detailed findings")
    parser.add_argument("--show-details", action="store_true", help="Show detailed per-skill analysis in compare mode")

    args = parser.parse_args()

    # Run evaluation
    test_dir = Path(args.test_skills_dir)
    if not test_dir.exists():
        print(f"Test skills directory not found: {test_dir}")
        print("Create test skills with _expected.json files")
        return 1

    # Compare mode - run both and compare
    if args.compare:
        comparison_results = run_comparison(
            test_dir,
            show_details=args.show_details,
            ollama_model=args.ollama_model,
            ollama_base_url=args.ollama_base_url,
            ollama_model_digest=args.ollama_model_digest,
            meta_seed=args.meta_seed,
        )

        # Save if requested
        if args.output:
            # Make results JSON serializable
            output_data = {
                "without_meta": _serializable_evaluation_result(comparison_results["without_meta"]),
                "with_meta": _serializable_evaluation_result(comparison_results["with_meta"]),
                "comparison_status": comparison_results["comparison_status"],
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            print(f"\nResults saved to: {args.output}")

        if not comparison_results["comparison_status"]["complete"]:
            return 1
        return 0

    # Single run mode
    # Validate args
    if args.use_meta and not args.use_llm:
        print("Warning: --use-meta requires --use-llm. Enabling LLM analyzer.")
        args.use_llm = True

    runner = EvaluationRunner(
        test_dir,
        use_llm=args.use_llm,
        use_meta=args.use_meta,
        ollama_model=args.ollama_model,
        ollama_base_url=args.ollama_base_url,
        ollama_model_digest=args.ollama_model_digest,
        meta_seed=args.meta_seed,
    )
    results = runner.run_evaluation()

    # Print results
    mode = "With Meta-Analyzer" if args.use_meta else "Without Meta-Analyzer"
    print_metrics(results, f"Evaluation Results ({mode})")

    # Print detailed findings with AITech codes for each skill (if requested)
    if args.show_aitech:
        print("\n" + "=" * 60)
        print("Detailed Findings (with AITech Taxonomy)")
        print("=" * 60)
        eval_results = results.get("eval_results_with_scan", [])
        for eval_result in eval_results:
            print(f"\nSkill: {eval_result.skill_name}")
            print(f"  Expected Safe: {eval_result.expected_safe}, Actual Safe: {eval_result.actual_safe}")
            print(
                f"  Matched: {eval_result.matched_findings}, FP: {eval_result.false_positives}, FN: {eval_result.false_negatives}"
            )

            # Display findings with AITech codes from stored scan result
            if eval_result.scan_result and eval_result.scan_result.findings:
                print(f"  Findings ({len(eval_result.scan_result.findings)}):")
                for finding in eval_result.scan_result.findings[:5]:  # Show first 5 findings
                    aitech = finding.metadata.get("aitech", "N/A")
                    aitech_name = finding.metadata.get("aitech_name", "N/A")
                    aisubtech = finding.metadata.get("aisubtech")
                    print(f"    - {finding.category.value} [{finding.severity.value}]")
                    if aitech != "N/A":
                        aitech_info = f"AITech: {aitech} ({aitech_name})"
                        if aisubtech:
                            aisubtech_name = finding.metadata.get("aisubtech_name", "")
                            aitech_info += f" | AISubtech: {aisubtech}"
                            if aisubtech_name:
                                aitech_info += f" ({aisubtech_name})"
                        print(f"      {aitech_info}")
                if len(eval_result.scan_result.findings) > 5:
                    print(f"    ... and {len(eval_result.scan_result.findings) - 5} more findings")

    # Save if requested
    if args.output:
        # Remove non-serializable data
        output_results = _serializable_evaluation_result(results)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_results, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    return 0 if results["run_status"]["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
