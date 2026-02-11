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

"""
Command-line interface for the Skill Scanner.
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.json import JSON
from rich.markdown import Markdown

from ..core.analyzers import BaseAnalyzer
from ..core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from ..core.analyzers.static import StaticAnalyzer
from ..core.loader import SkillLoadError
from ..core.models import Report, ScanResult
from ..core.reporters.json_reporter import JSONReporter
from ..core.reporters.markdown_reporter import MarkdownReporter
from ..core.reporters.sarif_reporter import SARIFReporter
from ..core.reporters.table_reporter import TableReporter
from ..core.scanner import SkillScanner
from ..utils import set_verbose_logging, setup_logger

logger = logging.getLogger(__name__)

# Optional LLM analyzer
try:
    from ..core.analyzers.llm_analyzer import LLMAnalyzer

    LLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LLM_AVAILABLE = False
    LLMAnalyzer = None

# Optional Meta analyzer
try:
    from ..core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None


def scan(args):
    """Handle 'scan' and 'scan-all' commands"""

    if args.command == "scan-all":
        skills_dir = Path(args.skills_directory)

        if not skills_dir.exists():
            logger.error(f"Error: Directory does not exist: {skills_dir}")
            return 1
    elif args.command == "scan":
        skill_dir = Path(args.skill_directory)

        if not skill_dir.exists():
            logger.error(f"Error: Directory does not exist: {skill_dir}")
            return 1

    # Get YARA mode and custom rules from args
    yara_mode = getattr(args, "yara_mode", "balanced")
    custom_rules_path = getattr(args, "custom_rules", None)
    disabled_rules = set(getattr(args, "disabled_rules", None) or [])

    # Create scanner with configured analyzers
    analyzers: list[BaseAnalyzer] = [
        StaticAnalyzer(
            yara_mode=yara_mode,
            custom_yara_rules_path=custom_rules_path,
            disabled_rules=disabled_rules,
        )
    ]

    # Helper to print status messages - go to stderr when JSON output to avoid breaking parsing
    is_json_output = getattr(args, "format", "summary") == "json"

    # Add behavioral analyzer if requested
    if hasattr(args, "use_behavioral") and args.use_behavioral:
        try:
            behavioral_analyzer = BehavioralAnalyzer(use_static_analysis=True)
            analyzers.append(behavioral_analyzer)
            _status_print("Using behavioral analyzer (static dataflow analysis)", is_json_output)
        except Exception as e:
            logger.warning("Warning: Could not initialize behavioral analyzer: %s", e)

    # Add LLM analyzer if requested and available
    if hasattr(args, "use_llm") and args.use_llm:
        if not LLM_AVAILABLE:
            print("Warning: LLM analyzer requested but dependencies not installed.", file=sys.stderr)
            print("Install with: pip install anthropic openai", file=sys.stderr)
        else:
            try:
                # Get API key and model from environment
                # Use SKILL_SCANNER_* env vars only (no provider-specific fallbacks)
                api_key = os.getenv("SKILL_SCANNER_LLM_API_KEY")
                model = os.getenv("SKILL_SCANNER_LLM_MODEL") or "claude-3-5-sonnet-20241022"
                base_url = os.getenv("SKILL_SCANNER_LLM_BASE_URL")
                api_version = os.getenv("SKILL_SCANNER_LLM_API_VERSION")

                llm_analyzer = LLMAnalyzer(
                    model=model,
                    api_key=api_key,
                    base_url=base_url,
                    api_version=api_version,
                )
                analyzers.append(llm_analyzer)
                _status_print(f"Using LLM analyzer with model: {model}", is_json_output)
            except Exception as e:
                logger.warning("Warning: Could not initialize LLM analyzer: %s", e)

    # Add VirusTotal analyzer if requested
    if hasattr(args, "use_virustotal") and args.use_virustotal:
        vt_api_key = args.vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_api_key:
            print("Warning: VirusTotal requested but no API key provided.", file=sys.stderr)
            print("Set VIRUSTOTAL_API_KEY environment variable or use --vt-api-key", file=sys.stderr)
        else:
            try:
                from ..core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

                vt_upload = getattr(args, "vt_upload_files", False)
                vt_analyzer = VirusTotalAnalyzer(api_key=vt_api_key, enabled=True, upload_files=vt_upload)
                analyzers.append(vt_analyzer)
                mode = "with file uploads" if vt_upload else "hash-only mode"
                _status_print(f"Using VirusTotal binary file scanner ({mode})", is_json_output)
            except Exception as e:
                logger.warning("Warning: Could not initialize VirusTotal analyzer: %s", e)

    # Add AI Defense analyzer if requested
    if hasattr(args, "use_aidefense") and args.use_aidefense:
        aidefense_api_key = getattr(args, "aidefense_api_key", None) or os.getenv("AI_DEFENSE_API_KEY")
        if not aidefense_api_key:
            print("Warning: AI Defense requested but no API key provided.", file=sys.stderr)
            print("Set AI_DEFENSE_API_KEY environment variable or use --aidefense-api-key", file=sys.stderr)
        else:
            try:
                from ..core.analyzers.aidefense_analyzer import AIDefenseAnalyzer

                aidefense_api_url = getattr(args, "aidefense_api_url", None) or os.getenv("AI_DEFENSE_API_URL")
                aidefense_analyzer = AIDefenseAnalyzer(api_key=aidefense_api_key, api_url=aidefense_api_url)
                analyzers.append(aidefense_analyzer)
                _status_print("Using AI Defense analyzer", is_json_output)
            except Exception as e:
                logger.warning("Warning: Could not initialize AI Defense analyzer: %s", e)

    # Add Trigger analyzer if requested
    if hasattr(args, "use_trigger") and args.use_trigger:
        try:
            from ..core.analyzers.trigger_analyzer import TriggerAnalyzer

            trigger_analyzer = TriggerAnalyzer()
            analyzers.append(trigger_analyzer)
            _status_print("Using Trigger analyzer (description specificity analysis)", is_json_output)
        except Exception as e:
            logger.warning("Warning: Could not initialize Trigger analyzer: %s", e)

    # Initialize meta-analyzer if requested
    meta_analyzer = None
    enable_meta = hasattr(args, "enable_meta") and args.enable_meta
    if enable_meta:
        if not META_AVAILABLE:
            print("Warning: Meta-analyzer requested but dependencies not installed.", file=sys.stderr)
            print("Install with: pip install litellm", file=sys.stderr)
        elif len(analyzers) < 2:
            print("Warning: Meta-analysis requires at least 2 analyzers. Skipping meta-analysis.", file=sys.stderr)
        else:
            try:
                # Use SKILL_SCANNER_* env vars only (no provider-specific fallbacks)
                # Priority: meta-specific > scanner-wide
                meta_api_key = os.getenv("SKILL_SCANNER_META_LLM_API_KEY") or os.getenv("SKILL_SCANNER_LLM_API_KEY")
                meta_model = os.getenv("SKILL_SCANNER_META_LLM_MODEL") or os.getenv("SKILL_SCANNER_LLM_MODEL")
                meta_base_url = os.getenv("SKILL_SCANNER_META_LLM_BASE_URL") or os.getenv("SKILL_SCANNER_LLM_BASE_URL")
                meta_api_version = os.getenv("SKILL_SCANNER_META_LLM_API_VERSION") or os.getenv(
                    "SKILL_SCANNER_LLM_API_VERSION"
                )
                meta_analyzer = MetaAnalyzer(
                    model=meta_model,
                    api_key=meta_api_key,
                    base_url=meta_base_url,
                    api_version=meta_api_version,
                )
                _status_print(
                    "Using Meta-Analyzer for false positive filtering and finding prioritization", is_json_output
                )
            except Exception as e:
                logger.warning("Warning: Could not initialize Meta-Analyzer: %s", e)

    scanner = SkillScanner(analyzers=analyzers)

    # Run the scan, either for single or multi skill
    if args.command == "scan-all":
        skills_dir = Path(args.skills_directory)
        return _scan_multi(args, scanner, skills_dir, meta_analyzer, is_json_output)
    elif args.command == "scan":
        skill_dir = Path(args.skill_directory)
        return _scan_single(args, scanner, skill_dir, meta_analyzer, is_json_output)
    else:  # The impossible case yet ...
        logger.error("Use 'scan' or 'scan-all' as per the help")
        return 1


def list_analyzers_command(args):
    """Handle the list-analyzers command."""
    print("Available Analyzers:")
    print("")
    print("1. static_analyzer (Default)")
    print("   - Pattern-based detection using YAML + YARA rules")
    print("   - Scans SKILL.md instructions and scripts")
    print("   - Detects 80+ security patterns across 12+ threat categories")
    print("")

    print("2. behavioral_analyzer [OK] Available")
    print("   - Static dataflow analysis (AST + taint tracking)")
    print("   - Tracks data from sources to sinks without execution")
    print("   - Detects multi-file exfiltration chains")
    print("   - Cross-file correlation analysis")
    print("   - Usage: --use-behavioral")
    print("")

    print("3. virustotal_analyzer [OK] Available (optional)")
    print("   - Scans binary files (images, PDFs, archives) using VirusTotal")
    print("   - Hash-based malware detection via VirusTotal API")
    print("   - Excludes code files (.py, .js, .md, etc.)")
    print("   - Requires VirusTotal API key")
    print("   - Usage: --use-virustotal --vt-api-key YOUR_KEY")
    print("")

    print("4. aidefense_analyzer [OK] Available (optional)")
    print("   - Enterprise-grade threat detection via Cisco AI Defense API")
    print("   - Analyzes prompts, instructions, markdown, and code files")
    print("   - Detects prompt injection, data exfiltration, tool poisoning")
    print("   - Requires Cisco AI Defense API key")
    print("   - Usage: --use-aidefense --aidefense-api-key YOUR_KEY")
    print("")

    if LLM_AVAILABLE:
        print("5. llm_analyzer [OK] Available")
        print("   - Semantic analysis using LLMs as judges")
        print("   - Context-aware threat detection")
        print("   - Understands code intent beyond patterns")
        print("   - Usage: --use-llm")
        print("")
    else:
        print("5. llm_analyzer [WARNING] Not installed")
        print("   - Install with: pip install litellm anthropic openai")
        print("")

    print("6. trigger_analyzer [OK] Available")
    print("   - Detects overly generic skill descriptions")
    print("   - Identifies trigger hijacking risks")
    print("   - Checks description specificity and keyword baiting")
    print("   - Usage: --use-trigger")
    print("")

    if META_AVAILABLE:
        print("7. meta_analyzer [OK] Available")
        print("   - Second-pass LLM analysis on findings from other analyzers")
        print("   - Filters false positives using contextual understanding")
        print("   - Prioritizes findings by actual exploitability")
        print("   - Detects threats other analyzers missed")
        print("   - Usage: --enable-meta (requires 2+ analyzers)")
        print("")
    else:
        print("7. meta_analyzer [WARNING] Not installed")
        print("   - Install with: pip install litellm")
        print("")

    print("Future Analyzers (not yet implemented):")
    print("  - policy_checker: Organization-specific policy validation")
    print("  - runtime_monitor: Live execution monitoring (sandbox)")
    print("")
    return 0


def validate_rules_command(args):
    """Handle the validate-rules command."""
    from ..core.rules.patterns import RuleLoader

    try:
        if args.rules_file:
            loader = RuleLoader(Path(args.rules_file))
        else:
            loader = RuleLoader()

        rules = loader.load_rules()

        print(f"[OK] Successfully loaded {len(rules)} rules")
        print("")
        print("Rules by category:")

        for category, category_rules in loader.rules_by_category.items():
            print(f"  - {category.value}: {len(category_rules)} rules")

        return 0

    except Exception as e:
        logger.warning("[FAIL] Error validating rules: %s", e)
        return 1


def _scan_single(args, scanner, skill_dir, meta_analyzer, is_json_output) -> int:
    """Scan a single skill and generate the report"""
    try:
        # Scan the skill
        result = scanner.scan_skill(skill_dir)

        # Run meta-analysis if enabled and we have findings
        if meta_analyzer and result.findings:
            _status_print("Running meta-analysis to filter false positives...", is_json_output)
            try:
                # Load the skill for context
                skill = scanner.loader.load_skill(skill_dir)

                # Run meta-analysis asynchronously
                meta_result = asyncio.run(
                    meta_analyzer.analyze_with_findings(
                        skill=skill,
                        findings=result.findings,
                        analyzers_used=result.analyzers_used,
                    )
                )

                # Apply meta-analysis results
                filtered_findings = apply_meta_analysis_to_results(
                    original_findings=result.findings,
                    meta_result=meta_result,
                    skill=skill,
                )

                # Update result with filtered findings
                original_count = len(result.findings)
                result.findings = filtered_findings
                result.analyzers_used.append("meta_analyzer")

                fp_count = original_count - len([f for f in filtered_findings if f.analyzer != "meta"])
                new_count = len([f for f in filtered_findings if f.analyzer == "meta"])
                _status_print(
                    f"Meta-analysis complete: {fp_count} false positives filtered, {new_count} new threats detected",
                    is_json_output,
                )

            except Exception as e:
                logger.warning("Warning: Meta-analysis failed: %s", e)
                logger.warning("Continuing with original findings.")

        # Generate report based on format
        output = _generate_report(args, result)

        # Output
        _save_or_print_report(args, output)

        # Exit with error code if critical/high issues found
        if not result.is_safe and args.fail_on_findings:
            return 1

        # No issues, normal execution
        return 0

    except SkillLoadError as e:
        logger.warning("Error loading skill: %s", e)
        return 1
    except Exception as e:
        logger.warning("Unexpected error: %s", e)
        return 1


def _scan_multi(args, scanner, skills_dir, meta_analyzer, is_json_output) -> int:
    """Scan multiple skills and generate the report"""
    try:
        # Scan all skills
        check_overlap = hasattr(args, "check_overlap") and args.check_overlap
        report = scanner.scan_directory(skills_dir, recursive=args.recursive, check_overlap=check_overlap)

        if report.total_skills_scanned == 0:
            logger.error("No skills found to scan.")
            return 1

        # Run meta-analysis on each skill's results if enabled
        if meta_analyzer:
            _status_print("Running meta-analysis on scan results...", is_json_output)
            total_fp_filtered = 0
            total_new_threats = 0

            for result in report.scan_results:
                if result.findings:
                    try:
                        # Load the skill for context
                        skill_dir = Path(result.skill_directory)
                        skill = scanner.loader.load_skill(skill_dir)

                        # Run meta-analysis asynchronously
                        meta_result = asyncio.run(
                            meta_analyzer.analyze_with_findings(
                                skill=skill,
                                findings=result.findings,
                                analyzers_used=result.analyzers_used,
                            )
                        )

                        # Apply meta-analysis results
                        original_count = len(result.findings)
                        filtered_findings = apply_meta_analysis_to_results(
                            original_findings=result.findings,
                            meta_result=meta_result,
                            skill=skill,
                        )

                        # Track statistics
                        fp_count = original_count - len([f for f in filtered_findings if f.analyzer != "meta"])
                        new_count = len([f for f in filtered_findings if f.analyzer == "meta"])
                        total_fp_filtered += fp_count
                        total_new_threats += new_count

                        # Update result
                        result.findings = filtered_findings
                        result.analyzers_used.append("meta_analyzer")

                    except Exception as e:
                        logger.warning("Warning: Meta-analysis failed for %s: %s", result.skill_name, e)

            _status_print(
                f"Meta-analysis complete: {total_fp_filtered} total false positives filtered, {total_new_threats} new threats detected",
                is_json_output,
            )

            # Recalculate report totals
            report.total_findings = sum(len(r.findings) for r in report.scan_results)
            report.critical_count = sum(
                1 for r in report.scan_results for f in r.findings if f.severity.value == "CRITICAL"
            )
            report.high_count = sum(1 for r in report.scan_results for f in r.findings if f.severity.value == "HIGH")
            report.medium_count = sum(
                1 for r in report.scan_results for f in r.findings if f.severity.value == "MEDIUM"
            )
            report.low_count = sum(1 for r in report.scan_results for f in r.findings if f.severity.value == "LOW")
            report.info_count = sum(1 for r in report.scan_results for f in r.findings if f.severity.value == "INFO")
            report.safe_count = sum(1 for r in report.scan_results if r.is_safe)

        # Generate report based on format
        output = _generate_report(args, report)

        # Output
        _save_or_print_report(args, output)

        # Exit with error code if any skills have issues
        if args.fail_on_findings and (report.critical_count > 0 or report.high_count > 0):
            return 1

        # No issues, normal execution
        return 0

    except Exception as e:
        logger.warning("Unexpected error: %s", e)
        return 1


def _generate_report(args, resport: ScanResult | Report) -> str:
    """Generate report(s) based on format; and summary based on single / multi scan"""
    # Generate report based on format
    if args.format == "json":
        reporter = JSONReporter(pretty=not args.compact)
        output = reporter.generate_report(resport)
    elif args.format == "markdown":
        reporter = MarkdownReporter(detailed=args.detailed)
        output = reporter.generate_report(resport)
    elif args.format == "table":
        reporter = TableReporter()
        output = reporter.generate_report(resport)
    elif args.format == "sarif":
        reporter = SARIFReporter()
        output = reporter.generate_report(resport)
    elif isinstance(resport, Report):  # summary for scan-all
        output = _generate_multi_skill_summary(resport)
    else:  # summary
        output = _generate_summary(resport)

    return output


def _generate_summary(result: ScanResult) -> str:
    """Generate a simple summary output."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"Skill: {result.skill_name}")
    lines.append("=" * 60)
    lines.append(f"Status: {'[OK] SAFE' if result.is_safe else '[FAIL] ISSUES FOUND'}")
    lines.append(f"Max Severity: {result.max_severity.value}")
    lines.append(f"Total Findings: {len(result.findings)}")
    lines.append(f"Scan Duration: {result.scan_duration_seconds:.2f}s")
    lines.append("")

    if result.findings:
        from ..core.models import Severity

        lines.append("Findings Summary:")
        lines.append(f"  Critical: {len(result.get_findings_by_severity(Severity.CRITICAL))}")
        lines.append(f"  High:     {len(result.get_findings_by_severity(Severity.HIGH))}")
        lines.append(f"  Medium:   {len(result.get_findings_by_severity(Severity.MEDIUM))}")
        lines.append(f"  Low:      {len(result.get_findings_by_severity(Severity.LOW))}")
        lines.append(f"  Info:     {len(result.get_findings_by_severity(Severity.INFO))}")

    return "\n".join(lines)


def _generate_multi_skill_summary(report: Report) -> str:
    """Generate a simple summary for multiple skills."""
    lines = []
    lines.append("=" * 60)
    lines.append("Agent Skills Security Scan Report")
    lines.append("=" * 60)
    lines.append(f"Skills Scanned: {report.total_skills_scanned}")
    lines.append(f"Safe Skills: {report.safe_count}")
    lines.append(f"Total Findings: {report.total_findings}")
    lines.append("")
    lines.append("Findings by Severity:")
    lines.append(f"  Critical: {report.critical_count}")
    lines.append(f"  High:     {report.high_count}")
    lines.append(f"  Medium:   {report.medium_count}")
    lines.append(f"  Low:      {report.low_count}")
    lines.append(f"  Info:     {report.info_count}")
    lines.append("")

    lines.append("Individual Skills:")
    for result in report.scan_results:
        status = "[OK]" if result.is_safe else "[FAIL]"
        lines.append(f"  {status} {result.skill_name} - {len(result.findings)} findings ({result.max_severity.value})")

    return "\n".join(lines)


def _save_or_print_report(args, report: str) -> None:
    """Save or print the report based on '--output / -o' flag."""
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
    else:
        if args.format == "json" and not args.compact:
            # rich JSON
            console = Console()
            markdown = JSON(report)
            console.print(markdown)
        elif args.format == "markdown" and not args.compact:
            # rich markdown
            console = Console()
            markdown = Markdown(report)
            console.print(markdown)
        else:
            print(report)


def _status_print(msg: str, is_json_output: bool) -> None:
    if is_json_output:
        print(msg, file=sys.stderr)
    else:
        print(msg)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Sets the common arguments for the parser"""
    parser.add_argument(
        "--format",
        choices=["summary", "json", "markdown", "table", "sarif"],
        default="summary",
        help="Output format (default: summary). Use 'sarif' for GitHub Code Scanning integration.",
    )
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--detailed", action="store_true", help="Include detailed findings")
    parser.add_argument("--compact", action="store_true", help="Compact JSON/Markdown output")
    parser.add_argument(
        "--fail-on-findings", action="store_true", help="Exit with error code if critical/high findings exist"
    )
    parser.add_argument("--use-behavioral", action="store_true", help="Enable behavioral dataflow analysis")
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM-based semantic analysis (requires API key)")
    parser.add_argument(
        "--use-virustotal", action="store_true", help="Enable VirusTotal binary file scanning (requires API key)"
    )
    parser.add_argument("--vt-api-key", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY environment variable)")
    parser.add_argument(
        "--vt-upload-files",
        action="store_true",
        help="Upload unknown files to VirusTotal (default: hash-only lookup for privacy)",
    )
    parser.add_argument("--use-aidefense", action="store_true", help="Enable AI Defense analyzer (requires API key)")
    parser.add_argument(
        "--aidefense-api-key", help="AI Defense API key (or set AI_DEFENSE_API_KEY environment variable)"
    )
    parser.add_argument("--aidefense-api-url", help="AI Defense API URL (optional, defaults to US region)")
    parser.add_argument(
        "--llm-provider",
        choices=["anthropic", "openai"],
        default="anthropic",
        help="LLM provider (default: anthropic)",
    )
    parser.add_argument(
        "--use-trigger",
        action="store_true",
        help="Enable trigger specificity analysis (detects overly generic descriptions)",
    )
    parser.add_argument(
        "--enable-meta",
        action="store_true",
        help="Enable meta-analysis for false positive filtering and finding prioritization (requires 2+ analyzers including LLM)",
    )
    parser.add_argument(
        "--yara-mode",
        choices=["strict", "balanced", "permissive"],
        default="balanced",
        help="YARA detection mode: strict (max security, more FPs), balanced (default), permissive (fewer FPs, may miss threats)",
    )
    parser.add_argument(
        "--custom-rules",
        metavar="PATH",
        help="Path to directory containing custom YARA rules (.yara files) to use instead of built-in rules",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        metavar="RULE_NAME",
        dest="disabled_rules",
        help="Disable a specific rule by name (can be used multiple times). Example: --disable-rule YARA_script_injection",
    )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Skill Scanner - Security scanner for agent skills packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single skill
  skill-scanner scan /path/to/skill

  # Scan with behavioral analysis (dataflow tracking)
  skill-scanner scan /path/to/skill --use-behavioral

  # Scan with all engines (static + behavioral + LLM)
  skill-scanner scan /path/to/skill --use-behavioral --use-llm

  # Scan with JSON output
  skill-scanner scan /path/to/skill --format json

  # Scan all skills in a directory
  skill-scanner scan-all /path/to/skills

  # Scan recursively with all engines
  skill-scanner scan-all /path/to/skills --recursive --use-behavioral --use-llm

  # List available analyzers
  skill-scanner list-analyzers

  # Validate rule signatures
  skill-scanner validate-rules
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a single skill package")
    _add_common_arguments(scan_parser)
    # scan specific arguments
    scan_parser.add_argument("skill_directory", help="Path to skill directory")

    # Scan-all command
    scan_all_parser = subparsers.add_parser("scan-all", help="Scan multiple skill packages")
    _add_common_arguments(scan_all_parser)

    # scan-all specific arguments
    scan_all_parser.add_argument("skills_directory", help="Directory containing skills")
    scan_all_parser.add_argument("--recursive", "-r", action="store_true", help="Recursively search for skills")
    scan_all_parser.add_argument(
        "--check-overlap", action="store_true", help="Enable cross-skill description overlap detection"
    )

    # List analyzers command
    subparsers.add_parser("list-analyzers", help="List available analyzers")

    # Validate rules command
    validate_parser = subparsers.add_parser("validate-rules", help="Validate rule signatures")
    validate_parser.add_argument("--rules-file", help="Path to custom rules file")

    # Global options
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging to stdout")

    # Parse arguments
    args = parser.parse_args()

    # Enable verbose logging if set
    if args.verbose:
        setup_logger("skill_scanner", level=logging.DEBUG)
        set_verbose_logging(True)

        if not args.output:
            logger.warning(
                "'--output' is not set for report generation while '--verbose' is enabled."
                "Consider using --output <path> with --verbose."
            )

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    if args.command == "scan" or args.command == "scan-all":
        return scan(args)
    elif args.command == "list-analyzers":
        return list_analyzers_command(args)
    elif args.command == "validate-rules":
        return validate_rules_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
