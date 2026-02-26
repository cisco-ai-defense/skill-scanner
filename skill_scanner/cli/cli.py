# Copyright 2026 Cisco Systems, Inc.
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

"""Command-line interface for the Skill Scanner."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

from .. import __version__
from ..core.analyzer_factory import build_analyzers
from ..core.loader import SkillLoadError
from ..core.reporters.html_reporter import HTMLReporter
from ..core.reporters.json_reporter import JSONReporter
from ..core.reporters.markdown_reporter import MarkdownReporter
from ..core.reporters.sarif_reporter import SARIFReporter
from ..core.reporters.table_reporter import TableReporter
from ..core.scan_policy import ScanPolicy
from ..core.scanner import SkillScanner

# Optional LLM analyzer (needed only for LLM_AVAILABLE check)
LLMAnalyzer: type | None
try:
    from ..core.analyzers.llm_analyzer import LLMAnalyzer  # noqa: F401

    LLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LLM_AVAILABLE = False
    LLMAnalyzer = None

# Optional Meta analyzer
MetaAnalyzer: type | None
apply_meta_analysis_to_results: Callable[..., list] | None
try:
    from ..core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None

logger = logging.getLogger("skill_scanner.cli")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_policy(args: argparse.Namespace) -> ScanPolicy:
    """Load scan policy from ``--policy`` flag or return the default."""
    policy_value = getattr(args, "policy", None)

    if policy_value:
        presets = ScanPolicy.preset_names()
        if policy_value.lower() in presets:
            policy = ScanPolicy.from_preset(policy_value)
            logger.info("Using %s scan policy (preset)", policy.policy_name)
        else:
            try:
                policy = ScanPolicy.from_yaml(policy_value)
                logger.info("Using scan policy: %s (%s)", policy_value, policy.policy_name)
            except FileNotFoundError:
                print(f"Error: Policy file not found: {policy_value}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error loading policy file: {e}", file=sys.stderr)
                sys.exit(1)
    else:
        policy = ScanPolicy.default()

    # When --verbose is NOT set, disable per-finding metadata bloat
    if not getattr(args, "verbose", False):
        policy.finding_output.attach_policy_fingerprint = False
        policy.finding_output.annotate_same_path_rule_cooccurrence = False

    return policy


def _build_analyzers(policy: ScanPolicy, args: argparse.Namespace, status: Callable[[str], None]) -> list:
    """Build the full analyzer list from *policy* and CLI *args*.

    Delegates to the centralized :func:`build_analyzers` factory so that
    core analyzer construction is defined in exactly one place.
    """
    analyzers = build_analyzers(
        policy,
        custom_yara_rules_path=getattr(args, "custom_rules", None),
        use_behavioral=getattr(args, "use_behavioral", False),
        use_llm=getattr(args, "use_llm", False),
        use_virustotal=getattr(args, "use_virustotal", False),
        vt_api_key=getattr(args, "vt_api_key", None),
        vt_upload_files=getattr(args, "vt_upload_files", False),
        use_aidefense=getattr(args, "use_aidefense", False),
        aidefense_api_key=getattr(args, "aidefense_api_key", None),
        aidefense_api_url=getattr(args, "aidefense_api_url", None),
        use_trigger=getattr(args, "use_trigger", False),
        llm_provider=getattr(args, "llm_provider", None),
        llm_consensus_runs=getattr(args, "llm_consensus_runs", 1),
    )

    # Emit status messages for the optional analyzers that were activated.
    for a in analyzers:
        name = a.get_name()
        if name == "behavioral":
            status("Using behavioral analyzer (static dataflow analysis)")
        elif name == "llm":
            status(f"Using LLM analyzer with model: {getattr(a, 'model', 'unknown')}")
        elif name == "virustotal":
            mode = "with file uploads" if getattr(a, "upload_files", False) else "hash-only mode"
            status(f"Using VirusTotal binary file scanner ({mode})")
        elif name == "aidefense":
            status("Using AI Defense analyzer")
        elif name == "trigger":
            status("Using Trigger analyzer (description specificity analysis)")

    return analyzers


def _build_meta_analyzer(args: argparse.Namespace, analyzer_count: int, status: Callable[[str], None], policy=None):
    """Optionally build a MetaAnalyzer if ``--enable-meta`` is set."""
    if not getattr(args, "enable_meta", False):
        return None

    if not META_AVAILABLE:
        logger.warning("Meta-analyzer requested but dependencies not installed.  pip install litellm")
        return None
    if analyzer_count < 2:
        logger.warning("Meta-analysis requires at least 2 analyzers.  Skipping.")
        return None
    if MetaAnalyzer is None:
        return None

    try:
        meta_api_key = os.getenv("SKILL_SCANNER_META_LLM_API_KEY") or os.getenv("SKILL_SCANNER_LLM_API_KEY")
        meta_model = os.getenv("SKILL_SCANNER_META_LLM_MODEL") or os.getenv("SKILL_SCANNER_LLM_MODEL")
        meta_base_url = os.getenv("SKILL_SCANNER_META_LLM_BASE_URL") or os.getenv("SKILL_SCANNER_LLM_BASE_URL")
        meta_api_version = os.getenv("SKILL_SCANNER_META_LLM_API_VERSION") or os.getenv("SKILL_SCANNER_LLM_API_VERSION")
        meta = MetaAnalyzer(
            model=meta_model,
            api_key=meta_api_key,
            base_url=meta_base_url,
            api_version=meta_api_version,
            policy=policy,
        )
        status("Using Meta-Analyzer for false positive filtering and finding prioritization")
        return meta
    except Exception as e:
        logger.warning("Could not initialise Meta-Analyzer: %s", e)
        return None


def _make_status_printer(args: argparse.Namespace) -> Callable[[str], None]:
    """Return a printer that sends to stderr when JSON output is active."""
    formats = _get_formats(args)
    is_machine = any(f in formats for f in ("json", "sarif"))

    def _print(msg: str) -> None:
        print(msg, file=sys.stderr if is_machine else sys.stdout)

    return _print


def _get_formats(args: argparse.Namespace) -> list[str]:
    """Return the list of output formats from ``--format`` flags."""
    raw = getattr(args, "format", None)
    if not raw:
        return ["summary"]
    if isinstance(raw, list):
        return raw
    return [raw]


def _format_single(fmt: str, args: argparse.Namespace, result_or_report) -> str:
    """Generate the formatted output string for one format."""
    if fmt == "json":
        return JSONReporter(pretty=not args.compact).generate_report(result_or_report)
    if fmt == "markdown":
        return MarkdownReporter(detailed=args.detailed).generate_report(result_or_report)
    if fmt == "table":
        return TableReporter().generate_report(result_or_report)
    if fmt == "sarif":
        return SARIFReporter().generate_report(result_or_report)
    if fmt == "html":
        return HTMLReporter().generate_report(result_or_report)
    # summary (default)
    from ..core.models import Report

    if isinstance(result_or_report, Report):
        return _generate_multi_skill_summary(result_or_report)
    return _generate_summary(result_or_report)


def _format_output(args: argparse.Namespace, result_or_report) -> str:
    """Generate the formatted output string for the primary format."""
    formats = _get_formats(args)
    return _format_single(formats[0], args, result_or_report)


def _configure_taxonomy_and_threat_mapping(args: argparse.Namespace, status: Callable[[str], None]) -> None:
    """Apply runtime taxonomy and threat-mapping overrides from CLI flags."""
    from ..threats.cisco_ai_taxonomy import reload_taxonomy
    from ..threats.threats import configure_threat_mappings

    taxonomy_source = reload_taxonomy(getattr(args, "taxonomy", None))
    threat_mapping_source = configure_threat_mappings(getattr(args, "threat_mapping", None))

    if taxonomy_source != "builtin":
        status(f"Using custom taxonomy profile: {taxonomy_source}")
    if threat_mapping_source != "builtin":
        status(f"Using custom threat mapping profile: {threat_mapping_source}")


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _has_findings_at_or_above(findings, threshold: str) -> bool:
    """Return True if *findings* contains any at or above *threshold*."""
    idx = _SEVERITY_ORDER.index(threshold.lower())
    failing_levels = {s.upper() for s in _SEVERITY_ORDER[: idx + 1]}
    return any(f.severity.value in failing_levels for f in findings)


def _report_has_findings_at_or_above(report, threshold: str) -> bool:
    """Return True if *report* has any finding at or above *threshold*."""
    idx = _SEVERITY_ORDER.index(threshold.lower())
    counts = [
        ("critical", report.critical_count),
        ("high", report.high_count),
        ("medium", report.medium_count),
        ("low", report.low_count),
        ("info", report.info_count),
    ]
    return any(count > 0 for level, count in counts if _SEVERITY_ORDER.index(level) <= idx)


def _resolve_fail_severity(args: argparse.Namespace) -> str | None:
    """Determine the effective severity threshold from CLI flags.

    ``--fail-on-severity LEVEL`` takes precedence.  ``--fail-on-findings``
    (legacy boolean flag) is treated as ``--fail-on-severity high``.
    Returns ``None`` when neither flag is set.
    """
    if getattr(args, "fail_on_severity", None):
        return args.fail_on_severity
    if getattr(args, "fail_on_findings", False):
        return "high"
    return None


def _write_output(args: argparse.Namespace, output: str) -> None:
    """Write *output* to a file or stdout, and emit any additional formats."""
    formats = _get_formats(args)

    # Primary format: write to --output file or stdout
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)

    # Additional formats beyond the first: each gets its own --output-<fmt> file
    # or is printed to stdout if no file path is given.
    if len(formats) > 1:
        # We already emitted formats[0] above.
        result_or_report = getattr(args, "_result_or_report", None)
        if result_or_report is not None:
            for fmt in formats[1:]:
                formatted = _format_single(fmt, args, result_or_report)
                output_key = f"output_{fmt}"
                file_path = getattr(args, output_key, None)
                if file_path:
                    with open(file_path, "w", encoding="utf-8") as fh:
                        fh.write(formatted)
                    print(f"{fmt.upper()} report saved to: {file_path}")
                else:
                    print(formatted)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def scan_command(args: argparse.Namespace) -> int:
    """Handle the ``scan`` command for a single skill."""
    skill_dir = Path(args.skill_directory)
    if not skill_dir.exists():
        print(f"Error: Directory does not exist: {skill_dir}", file=sys.stderr)
        return 1

    status = _make_status_printer(args)
    try:
        _configure_taxonomy_and_threat_mapping(args, status)
    except Exception as e:
        print(f"Error loading taxonomy configuration: {e}", file=sys.stderr)
        return 1

    policy = _load_policy(args)
    analyzers = _build_analyzers(policy, args, status)
    meta_analyzer = _build_meta_analyzer(args, len(analyzers), status, policy=policy)

    scanner = SkillScanner(analyzers=analyzers, policy=policy)
    lenient = getattr(args, "lenient", False)

    try:
        result = scanner.scan_skill(skill_dir, lenient=lenient)

        # Meta-analysis
        if meta_analyzer and result.findings and apply_meta_analysis_to_results is not None:
            status("Running meta-analysis to filter false positives...")
            try:
                skill = scanner.loader.load_skill(skill_dir, lenient=lenient)
                original_count = len(result.findings)
                meta_result = asyncio.run(
                    meta_analyzer.analyze_with_findings(
                        skill=skill, findings=result.findings, analyzers_used=result.analyzers_used
                    )
                )
                filtered = apply_meta_analysis_to_results(
                    original_findings=result.findings, meta_result=meta_result, skill=skill
                )
                result.findings = filtered
                result.analyzers_used.append("meta_analyzer")

                # Surface meta-analysis insights into scan_metadata
                if result.scan_metadata is None:
                    result.scan_metadata = {}
                if meta_result.correlations:
                    result.scan_metadata["meta_correlations"] = meta_result.correlations
                if meta_result.recommendations:
                    result.scan_metadata["meta_recommendations"] = meta_result.recommendations
                if meta_result.overall_risk_assessment:
                    result.scan_metadata["meta_risk_assessment"] = meta_result.overall_risk_assessment

                fp_count = len(meta_result.false_positives)
                retained = original_count - fp_count
                new = len(meta_result.missed_threats)
                corr = len(meta_result.correlations)
                parts = [f"{fp_count} false positives removed", f"{retained} findings retained"]
                if corr:
                    parts.append(f"{corr} correlation groups")
                if new:
                    parts.append(f"{new} new threats detected")
                status(f"Meta-analysis complete: {', '.join(parts)}")
            except Exception as e:
                logger.warning("Meta-analysis failed: %s", e)

        # Strip false positives from output unless --verbose
        if not getattr(args, "verbose", False):
            result.findings = [f for f in result.findings if not f.metadata.get("meta_false_positive", False)]

        args._result_or_report = result
        _write_output(args, _format_output(args, result))

        fail_severity = _resolve_fail_severity(args)
        if fail_severity and _has_findings_at_or_above(result.findings, fail_severity):
            return 1
        return 0

    except SkillLoadError as e:
        print(f"Error loading skill: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


def scan_all_command(args: argparse.Namespace) -> int:
    """Handle the ``scan-all`` command for multiple skills."""
    skills_dir = Path(args.skills_directory)
    if not skills_dir.exists():
        print(f"Error: Directory does not exist: {skills_dir}", file=sys.stderr)
        return 1

    status = _make_status_printer(args)
    try:
        _configure_taxonomy_and_threat_mapping(args, status)
    except Exception as e:
        print(f"Error loading taxonomy configuration: {e}", file=sys.stderr)
        return 1

    policy = _load_policy(args)
    analyzers = _build_analyzers(policy, args, status)
    meta_analyzer = _build_meta_analyzer(args, len(analyzers), status, policy=policy)

    scanner = SkillScanner(analyzers=analyzers, policy=policy)

    lenient = getattr(args, "lenient", False)

    try:
        check_overlap = getattr(args, "check_overlap", False)
        report = scanner.scan_directory(
            skills_dir, recursive=args.recursive, check_overlap=check_overlap, lenient=lenient
        )

        if report.total_skills_scanned == 0:
            print("No skills found to scan.", file=sys.stderr)
            return 1

        # Per-skill meta-analysis
        if meta_analyzer and apply_meta_analysis_to_results is not None:
            status("Running meta-analysis on scan results...")
            total_original, total_fp, total_new = 0, 0, 0
            for result in report.scan_results:
                if not result.findings:
                    continue
                try:
                    skill = scanner.loader.load_skill(Path(result.skill_directory), lenient=lenient)
                    original_count = len(result.findings)
                    meta_result = asyncio.run(
                        meta_analyzer.analyze_with_findings(
                            skill=skill, findings=result.findings, analyzers_used=result.analyzers_used
                        )
                    )
                    filtered = apply_meta_analysis_to_results(
                        original_findings=result.findings, meta_result=meta_result, skill=skill
                    )
                    total_original += original_count
                    total_fp += len(meta_result.false_positives)
                    total_new += len(meta_result.missed_threats)
                    result.findings = filtered
                    result.analyzers_used.append("meta_analyzer")

                    # Surface meta-analysis insights
                    if result.scan_metadata is None:
                        result.scan_metadata = {}
                    if meta_result.correlations:
                        result.scan_metadata["meta_correlations"] = meta_result.correlations
                    if meta_result.recommendations:
                        result.scan_metadata["meta_recommendations"] = meta_result.recommendations
                    if meta_result.overall_risk_assessment:
                        result.scan_metadata["meta_risk_assessment"] = meta_result.overall_risk_assessment
                except Exception as e:
                    logger.warning("Meta-analysis failed for %s: %s", result.skill_name, e)

            retained = total_original - total_fp
            parts = [f"{total_fp} false positives removed", f"{retained} findings retained"]
            if total_new:
                parts.append(f"{total_new} new threats detected")
            status(f"Meta-analysis complete: {', '.join(parts)}")

        # Strip false positives from output unless --verbose
        if not getattr(args, "verbose", False):
            for result in report.scan_results:
                result.findings = [f for f in result.findings if not f.metadata.get("meta_false_positive", False)]
            report.cross_skill_findings = [
                f for f in report.cross_skill_findings if not f.metadata.get("meta_false_positive", False)
            ]

        # Recalculate report totals after meta-analysis and FP stripping
        all_findings = [f for r in report.scan_results for f in r.findings] + report.cross_skill_findings
        report.total_findings = len(all_findings)
        report.critical_count = sum(1 for f in all_findings if f.severity.value == "CRITICAL")
        report.high_count = sum(1 for f in all_findings if f.severity.value == "HIGH")
        report.medium_count = sum(1 for f in all_findings if f.severity.value == "MEDIUM")
        report.low_count = sum(1 for f in all_findings if f.severity.value == "LOW")
        report.info_count = sum(1 for f in all_findings if f.severity.value == "INFO")
        report.safe_count = sum(1 for r in report.scan_results if r.is_safe)

        args._result_or_report = report
        _write_output(args, _format_output(args, report))

        fail_severity = _resolve_fail_severity(args)
        if fail_severity and _report_has_findings_at_or_above(report, fail_severity):
            return 1
        return 0

    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


def list_analyzers_command(_args: argparse.Namespace) -> int:
    """Handle the ``list-analyzers`` command."""
    entries = [
        ("static_analyzer", True, "Default", "Pattern-based detection using YAML + YARA rules", "--policy"),
        ("bytecode_analyzer", True, "Default", "Python .pyc integrity verification", "--policy"),
        ("pipeline_analyzer", True, "Default", "Command pipeline taint analysis", "--policy"),
        (
            "behavioral_analyzer",
            True,
            "Available",
            "Static dataflow analysis (AST + taint tracking)",
            "--use-behavioral",
        ),
        (
            "virustotal_analyzer",
            True,
            "Available (optional)",
            "Hash-based malware detection via VirusTotal API",
            "--use-virustotal --vt-api-key KEY",
        ),
        (
            "aidefense_analyzer",
            True,
            "Available (optional)",
            "Cisco AI Defense cloud-based threat detection",
            "--use-aidefense --aidefense-api-key KEY",
        ),
        (
            "llm_analyzer",
            LLM_AVAILABLE,
            "Available" if LLM_AVAILABLE else "Not installed",
            "Semantic analysis using LLMs as judges",
            "--use-llm",
        ),
        ("trigger_analyzer", True, "Available", "Detects overly generic skill descriptions", "--use-trigger"),
        (
            "meta_analyzer",
            META_AVAILABLE,
            "Available" if META_AVAILABLE else "Not installed",
            "Second-pass LLM FP filtering & prioritization",
            "--enable-meta",
        ),
    ]

    print("Available Analyzers:\n")
    for i, (name, available, badge, desc, usage) in enumerate(entries, 1):
        ok = "[OK]" if available else "[WARNING]"
        print(f"  {i}. {name} {ok} {badge}")
        print(f"     {desc}")
        print(f"     Usage: {usage}")
        print()

    return 0


def validate_rules_command(args: argparse.Namespace) -> int:
    """Handle the ``validate-rules`` command."""
    from ..core.rules.patterns import RuleLoader

    try:
        loader = RuleLoader(Path(args.rules_file)) if args.rules_file else RuleLoader()
        rules = loader.load_rules()
        print(f"[OK] Successfully loaded {len(rules)} rules\n")
        print("Rules by category:")
        for category, category_rules in loader.rules_by_category.items():
            print(f"  - {category.value}: {len(category_rules)} rules")
        return 0
    except Exception as e:
        print(f"[FAIL] Error validating rules: {e}", file=sys.stderr)
        return 1


def generate_policy_command(args: argparse.Namespace) -> int:
    """Handle the ``generate-policy`` command."""
    output_path = Path(args.output)
    preset = getattr(args, "preset", "balanced")
    try:
        policy = ScanPolicy.from_preset(preset)
        policy.to_yaml(output_path)
        print(f"Generated {preset} scan policy: {output_path}\n")
        print("Edit the file to customise, then use:")
        print(f"  skill-scanner scan --policy {output_path} /path/to/skill\n")
        print("Or use the interactive configurator:")
        print("  skill-scanner configure-policy\n")
        print("Available presets: strict | balanced (default) | permissive")
        return 0
    except Exception as e:
        print(f"Error generating policy: {e}", file=sys.stderr)
        return 1


def configure_policy_command(args: argparse.Namespace) -> int:
    """Handle the ``configure-policy`` command (interactive TUI)."""
    from .policy_tui import run_policy_tui

    return run_policy_tui(
        output_path=getattr(args, "output", "scan_policy.yaml"),
        input_path=getattr(args, "input", None),
    )


# ---------------------------------------------------------------------------
# Summary formatters
# ---------------------------------------------------------------------------


def _generate_summary(result) -> str:
    from ..core.models import Severity

    lines = [
        "=" * 60,
        f"Skill: {result.skill_name}",
        "=" * 60,
        f"Status: {'[OK] SAFE' if result.is_safe else '[FAIL] ISSUES FOUND'}",
        f"Max Severity: {result.max_severity.value}",
        f"Total Findings: {len(result.findings)}",
        f"Scan Duration: {result.scan_duration_seconds:.2f}s",
        "",
    ]
    if result.findings:
        lines.append("Findings Summary:")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            lines.append(f"  {sev.value:>8s}: {len(result.get_findings_by_severity(sev))}")
    return "\n".join(lines)


def _generate_multi_skill_summary(report) -> str:
    lines = [
        "=" * 60,
        "Agent Skills Security Scan Report",
        "=" * 60,
        f"Skills Scanned: {report.total_skills_scanned}",
        f"Safe Skills: {report.safe_count}",
        f"Total Findings: {report.total_findings}",
    ]
    if report.skills_skipped:
        lines.append(f"Skills Skipped: {len(report.skills_skipped)}")
    lines += [
        "",
        "Findings by Severity:",
        f"  Critical: {report.critical_count}",
        f"     High: {report.high_count}",
        f"   Medium: {report.medium_count}",
        f"      Low: {report.low_count}",
        f"     Info: {report.info_count}",
        "",
        "Individual Skills:",
    ]
    for r in report.scan_results:
        tag = "[OK]" if r.is_safe else "[FAIL]"
        lines.append(f"  {tag} {r.skill_name} - {len(r.findings)} findings ({r.max_severity.value})")
    if report.cross_skill_findings:
        lines.append("")
        lines.append("Cross-Skill Findings:")
        for f in report.cross_skill_findings:
            lines.append(f"  [{f.severity.value}] {f.title}")
    if report.skills_skipped:
        lines.append("")
        lines.append("Skipped Skills:")
        for entry in report.skills_skipped:
            lines.append(f"  [SKIP] {entry['skill']} - {entry['reason']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Shared argparse helpers
# ---------------------------------------------------------------------------


_VALID_FORMATS = ("summary", "json", "markdown", "table", "sarif", "html")


def _add_common_scan_flags(parser: argparse.ArgumentParser) -> None:
    """Add flags shared between ``scan`` and ``scan-all``."""
    parser.add_argument(
        "--format",
        action="append",
        choices=list(_VALID_FORMATS),
        default=None,
        dest="format",
        help=(
            "Output format (default: summary). May be specified multiple times "
            "to produce several reports in one run, e.g. --format markdown --format sarif. "
            "Use 'sarif' for GitHub Code Scanning, 'html' for interactive report."
        ),
    )
    parser.add_argument("--output", "-o", help="Output file path (for the first --format)")
    parser.add_argument("--output-json", help="Write JSON report to this file (when using multiple --format)")
    parser.add_argument("--output-sarif", help="Write SARIF report to this file (when using multiple --format)")
    parser.add_argument("--output-markdown", help="Write Markdown report to this file (when using multiple --format)")
    parser.add_argument("--output-html", help="Write HTML report to this file (when using multiple --format)")
    parser.add_argument("--output-table", help="Write Table report to this file (when using multiple --format)")
    parser.add_argument("--detailed", action="store_true", help="Include detailed findings (Markdown output only)")
    parser.add_argument("--compact", action="store_true", help="Compact JSON output")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include per-finding policy fingerprints, co-occurrence metadata, and keep meta-analyzer false positives in output",
    )
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with error if critical/high findings")
    parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        metavar="LEVEL",
        help="Exit with error if findings at or above LEVEL exist (critical, high, medium, low, info)",
    )
    parser.add_argument("--use-behavioral", action="store_true", help="Enable behavioral dataflow analysis")
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM-based semantic analysis (requires API key)")
    parser.add_argument("--use-virustotal", action="store_true", help="Enable VirusTotal scanning (requires API key)")
    parser.add_argument("--vt-api-key", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY)")
    parser.add_argument("--vt-upload-files", action="store_true", help="Upload unknown files to VirusTotal")
    parser.add_argument("--use-aidefense", action="store_true", help="Enable AI Defense analyzer (requires API key)")
    parser.add_argument("--aidefense-api-key", help="AI Defense API key (or set AI_DEFENSE_API_KEY)")
    parser.add_argument("--aidefense-api-url", help="AI Defense API URL (optional, defaults to US region)")
    parser.add_argument("--llm-provider", choices=["anthropic", "openai"], default="anthropic", help="LLM provider")
    parser.add_argument(
        "--llm-consensus-runs",
        type=int,
        default=1,
        metavar="N",
        help="Run LLM analysis N times and keep only findings with majority agreement (reduces false positives, increases cost)",
    )
    parser.add_argument("--use-trigger", action="store_true", help="Enable trigger specificity analysis")
    parser.add_argument("--enable-meta", action="store_true", help="Enable meta-analysis FP filtering (2+ analyzers)")
    parser.add_argument(
        "--policy",
        metavar="PRESET_OR_PATH",
        help="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    parser.add_argument(
        "--lenient",
        action="store_true",
        help="Tolerate malformed skills: coerce bad fields, fill defaults, and continue instead of failing",
    )
    parser.add_argument(
        "--custom-rules",
        metavar="PATH",
        help="Path to directory containing custom YARA rules (.yara files)",
    )
    parser.add_argument(
        "--taxonomy",
        metavar="PATH",
        help="Path to custom taxonomy JSON/YAML (overrides SKILL_SCANNER_TAXONOMY_PATH)",
    )
    parser.add_argument(
        "--threat-mapping",
        metavar="PATH",
        help="Path to custom threat mapping JSON (overrides SKILL_SCANNER_THREAT_MAPPING_PATH)",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Skill Scanner - Security scanner for agent skills packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  skill-scanner scan /path/to/skill
  skill-scanner scan /path/to/skill --use-behavioral --use-llm
  skill-scanner scan /path/to/skill --use-llm --enable-meta --format json
  skill-scanner scan /path/to/skill --format json --verbose
  skill-scanner scan /path/to/skill --policy strict
  skill-scanner scan /path/to/skill --format markdown --format sarif --output-sarif report.sarif
  skill-scanner scan-all /path/to/skills --recursive
  skill-scanner generate-policy -o my_policy.yaml
  skill-scanner configure-policy
  skill-scanner list-analyzers
        """,
    )
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # -- scan --------------------------------------------------------------
    scan_p = subparsers.add_parser("scan", help="Scan a single skill package")
    scan_p.add_argument("skill_directory", help="Path to skill directory")
    _add_common_scan_flags(scan_p)

    # -- scan-all ----------------------------------------------------------
    scan_all_p = subparsers.add_parser("scan-all", help="Scan multiple skill packages")
    scan_all_p.add_argument("skills_directory", help="Directory containing skills")
    scan_all_p.add_argument("--recursive", "-r", action="store_true", help="Recursively search for skills")
    scan_all_p.add_argument("--check-overlap", action="store_true", help="Enable cross-skill description overlap")
    _add_common_scan_flags(scan_all_p)

    # -- list-analyzers ----------------------------------------------------
    subparsers.add_parser("list-analyzers", help="List available analyzers")

    # -- validate-rules ----------------------------------------------------
    vr_p = subparsers.add_parser("validate-rules", help="Validate rule signatures")
    vr_p.add_argument("--rules-file", help="Path to YAML rules file or directory (default: built-in signatures)")

    # -- generate-policy ---------------------------------------------------
    gp_p = subparsers.add_parser("generate-policy", help="Generate a default scan policy YAML")
    gp_p.add_argument("--output", "-o", default="scan_policy.yaml", help="Output file path")
    gp_p.add_argument("--preset", choices=["strict", "balanced", "permissive"], default="balanced", help="Base preset")

    # -- configure-policy --------------------------------------------------
    cp_p = subparsers.add_parser("configure-policy", help="Interactive TUI to build a custom scan policy")
    cp_p.add_argument("--output", "-o", default="scan_policy.yaml", help="Output file path")
    cp_p.add_argument("--input", "-i", default=None, help="Load existing policy YAML for editing")

    # -- interactive -------------------------------------------------------
    subparsers.add_parser("interactive", help="Launch the interactive scan wizard")

    return parser


def _run_interactive_wizard() -> int:
    from .wizard import run_wizard

    return run_wizard()


def main() -> int:
    """Main CLI entry point."""
    parser = build_parser()

    # -- dispatch ----------------------------------------------------------
    args = parser.parse_args()

    if not args.command:
        if sys.stdin.isatty():
            return _run_interactive_wizard()
        parser.print_help()
        return 1

    if args.command == "interactive":
        return _run_interactive_wizard()

    dispatch = {
        "scan": scan_command,
        "scan-all": scan_all_command,
        "list-analyzers": list_analyzers_command,
        "validate-rules": validate_rules_command,
        "generate-policy": generate_policy_command,
        "configure-policy": configure_policy_command,
    }
    handler = dispatch.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
