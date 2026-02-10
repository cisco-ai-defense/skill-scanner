# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Interactive TUI for configuring a scan policy.

Uses ``rich`` (already a project dependency) for a clean terminal experience.
Run via:  skill-scanner configure-policy [-o my_policy.yaml]
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from ..core.scan_policy import ScanPolicy

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pick_one(prompt_text: str, options: list[str], default: str | None = None) -> str:
    """Prompt user to pick one option by number."""
    for i, opt in enumerate(options, 1):
        marker = " (default)" if opt == default else ""
        console.print(f"  [cyan]{i}[/cyan]. {opt}{marker}")
    while True:
        raw = Prompt.ask(
            f"{prompt_text} [1-{len(options)}]", default=str(options.index(default) + 1) if default else None
        )
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except ValueError:
            pass
        console.print(f"  [red]Please enter a number between 1 and {len(options)}[/red]")


def _edit_set(title: str, current: set[str]) -> set[str]:
    """Let the user add/remove items from a set."""
    items = sorted(current)
    while True:
        console.print(f"\n  [bold]{title}[/bold] ({len(items)} items)")
        if items:
            for i, item in enumerate(items[:15], 1):
                console.print(f"    {i:>3}. {item}")
            if len(items) > 15:
                console.print(f"    ... and {len(items) - 15} more")
        else:
            console.print("    [dim](empty)[/dim]")

        action = _pick_one("Action", ["keep as-is", "add item", "remove item", "clear all"], default="keep as-is")

        if action == "keep as-is":
            return set(items)
        elif action == "add item":
            val = Prompt.ask("  Value to add").strip()
            if val:
                items.append(val)
                items.sort()
                console.print(f"  [green]Added:[/green] {val}")
        elif action == "remove item":
            val = Prompt.ask("  Value to remove (or number)").strip()
            try:
                idx = int(val) - 1
                if 0 <= idx < len(items):
                    removed = items.pop(idx)
                    console.print(f"  [red]Removed:[/red] {removed}")
                    continue
            except ValueError:
                pass
            if val in items:
                items.remove(val)
                console.print(f"  [red]Removed:[/red] {val}")
            else:
                console.print(f"  [yellow]Not found:[/yellow] {val}")
        elif action == "clear all":
            if Confirm.ask("  Clear all items?", default=False):
                items.clear()


def _edit_list(title: str, current: list[str]) -> list[str]:
    """Let the user add/remove items from a list."""
    items = list(current)
    while True:
        console.print(f"\n  [bold]{title}[/bold] ({len(items)} items)")
        if items:
            for i, item in enumerate(items[:15], 1):
                console.print(f"    {i:>3}. {item}")
            if len(items) > 15:
                console.print(f"    ... and {len(items) - 15} more")
        else:
            console.print("    [dim](empty)[/dim]")

        action = _pick_one("Action", ["keep as-is", "add item", "remove item", "clear all"], default="keep as-is")

        if action == "keep as-is":
            return items
        elif action == "add item":
            val = Prompt.ask("  Value to add").strip()
            if val:
                items.append(val)
                console.print(f"  [green]Added:[/green] {val}")
        elif action == "remove item":
            val = Prompt.ask("  Value to remove (or number)").strip()
            try:
                idx = int(val) - 1
                if 0 <= idx < len(items):
                    removed = items.pop(idx)
                    console.print(f"  [red]Removed:[/red] {removed}")
                    continue
            except ValueError:
                pass
            if val in items:
                items.remove(val)
                console.print(f"  [red]Removed:[/red] {val}")
            else:
                console.print(f"  [yellow]Not found:[/yellow] {val}")
        elif action == "clear all":
            if Confirm.ask("  Clear all items?", default=False):
                items.clear()


def _edit_file_limits(policy: ScanPolicy) -> None:
    """Let the user adjust numeric file limits."""
    fl = policy.file_limits
    console.print("\n  [bold]File Limits[/bold]")
    fl.max_file_count = IntPrompt.ask("  Max file count", default=fl.max_file_count)
    fl.max_file_size_bytes = IntPrompt.ask("  Max file size (bytes)", default=fl.max_file_size_bytes)
    fl.max_reference_depth = IntPrompt.ask("  Max reference depth", default=fl.max_reference_depth)
    fl.max_name_length = IntPrompt.ask("  Max skill name length", default=fl.max_name_length)
    fl.max_description_length = IntPrompt.ask("  Max description length", default=fl.max_description_length)
    fl.min_description_length = IntPrompt.ask("  Min description length", default=fl.min_description_length)


def _edit_analysis_thresholds(policy: ScanPolicy) -> None:
    """Let the user adjust analysis thresholds."""
    at = policy.analysis_thresholds
    console.print("\n  [bold]Analysis Thresholds[/bold]")
    at.zerowidth_threshold_with_decode = IntPrompt.ask(
        "  Zero-width threshold (with decode context)", default=at.zerowidth_threshold_with_decode
    )
    at.zerowidth_threshold_alone = IntPrompt.ask(
        "  Zero-width threshold (standalone)", default=at.zerowidth_threshold_alone
    )
    at.analyzability_low_risk = IntPrompt.ask(
        "  Analyzability score for LOW risk (%)", default=at.analyzability_low_risk
    )
    at.analyzability_medium_risk = IntPrompt.ask(
        "  Analyzability score for MEDIUM risk (%)", default=at.analyzability_medium_risk
    )


def _edit_severity_overrides(policy: ScanPolicy) -> None:
    """Let the user add/remove severity overrides."""
    while True:
        console.print(f"\n  [bold]Severity Overrides[/bold] ({len(policy.severity_overrides)} rules)")
        if policy.severity_overrides:
            for ovr in policy.severity_overrides:
                console.print(f"    {ovr.rule_id} → [bold]{ovr.severity}[/bold]  ({ovr.reason})")
        else:
            console.print("    [dim](none)[/dim]")

        action = _pick_one(
            "Action", ["keep as-is", "add override", "remove override", "clear all"], default="keep as-is"
        )

        if action == "keep as-is":
            return
        elif action == "add override":
            from ..core.scan_policy import SeverityOverride

            rule_id = Prompt.ask("  Rule ID (e.g. BINARY_FILE_DETECTED)")
            severity = _pick_one("  Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
            reason = Prompt.ask("  Reason", default="")
            policy.severity_overrides.append(SeverityOverride(rule_id=rule_id, severity=severity, reason=reason))
            console.print(f"  [green]Added:[/green] {rule_id} → {severity}")
        elif action == "remove override":
            if not policy.severity_overrides:
                continue
            rule_id = Prompt.ask("  Rule ID to remove")
            policy.severity_overrides = [o for o in policy.severity_overrides if o.rule_id != rule_id]
        elif action == "clear all":
            if Confirm.ask("  Clear all overrides?", default=False):
                policy.severity_overrides.clear()


# ---------------------------------------------------------------------------
# Main TUI flow
# ---------------------------------------------------------------------------


def run_policy_tui(output_path: str = "scan_policy.yaml") -> int:
    """Run the interactive policy configurator."""
    console.print()
    console.print(
        Panel.fit(
            "[bold blue]Skill Scanner – Policy Configurator[/bold blue]\n"
            "[dim]Build a custom scan policy for your organisation[/dim]",
            border_style="blue",
        )
    )
    console.print()

    # Step 1: Choose starting point
    console.print("[bold]Step 1: Choose a starting point[/bold]")
    console.print()

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Preset", style="cyan", width=12)
    table.add_column("Description", width=50)
    table.add_column("Use when", style="dim")
    table.add_row("strict", "Narrow allowlists, no suppressions", "Auditing untrusted skills")
    table.add_row("balanced", "Sensible defaults, moderate filtering", "CI/CD, everyday scanning")
    table.add_row("permissive", "Broad allowlists, aggressive suppression", "Trusted internal skills")
    console.print(table)
    console.print()

    preset = _pick_one("Start from", ["strict", "balanced", "permissive"], default="balanced")
    policy = ScanPolicy.from_preset(preset)
    console.print(f"\n  [green]Loaded [bold]{preset}[/bold] preset as starting point[/green]\n")

    # Step 2: Policy name & version
    console.print("[bold]Step 2: Name your policy[/bold]")
    policy.policy_name = Prompt.ask("  Policy name", default=f"{preset}-custom")
    policy.policy_version = Prompt.ask("  Policy version", default=policy.policy_version)
    console.print()

    # Step 3: Customise sections
    console.print("[bold]Step 3: Customise sections[/bold]")
    console.print("  [dim]Choose which sections to review. Skip any to keep the preset defaults.[/dim]\n")

    sections = [
        ("Hidden files – benign dotfiles", "dotfiles"),
        ("Hidden files – benign directories", "dotdirs"),
        ("Pipeline – known installer URLs", "installers"),
        ("Pipeline – benign pipe targets (regex)", "pipe_targets"),
        ("Pipeline – documentation path indicators", "pipe_docpaths"),
        ("Rule scoping – rules limited to SKILL.md + scripts", "rule_skillmd"),
        ("Rule scoping – rules skipped in documentation", "rule_docs"),
        ("Rule scoping – code-only rules", "rule_code_only"),
        ("Rule scoping – documentation directory names", "rule_docpaths"),
        ("Rule scoping – doc filename patterns (regex)", "rule_doc_filenames"),
        ("Credentials – suppressed test values", "creds"),
        ("Credentials – placeholder markers", "cred_placeholders"),
        ("System cleanup – safe rm targets", "safe_rm"),
        ("File classification – inert/structured/archive/code extensions", "file_class"),
        ("File limits – counts, sizes, lengths", "file_limits"),
        ("Analysis thresholds – steganography, analyzability", "thresholds"),
        ("Sensitive file patterns – taint upgrade regex", "sensitive"),
        ("Command safety – safe/caution/risky/dangerous tiers", "cmd_safety"),
        ("Analyzers – enable/disable analysis passes", "analyzers"),
        ("Severity overrides", "severity"),
        ("Disabled rules", "disabled"),
    ]

    for label, key in sections:
        if Confirm.ask(f"  Customise [cyan]{label}[/cyan]?", default=False):
            if key == "dotfiles":
                policy.hidden_files.benign_dotfiles = _edit_set("Benign dotfiles", policy.hidden_files.benign_dotfiles)
            elif key == "dotdirs":
                policy.hidden_files.benign_dotdirs = _edit_set("Benign dotdirs", policy.hidden_files.benign_dotdirs)
            elif key == "installers":
                policy.pipeline.known_installer_domains = _edit_set(
                    "Known installer domains", policy.pipeline.known_installer_domains
                )
            elif key == "pipe_targets":
                policy.pipeline.benign_pipe_targets = _edit_list(
                    "Benign pipe targets (regex)", policy.pipeline.benign_pipe_targets
                )
            elif key == "pipe_docpaths":
                policy.pipeline.doc_path_indicators = _edit_set(
                    "Pipeline doc path indicators", policy.pipeline.doc_path_indicators
                )
            elif key == "rule_skillmd":
                policy.rule_scoping.skillmd_and_scripts_only = _edit_set(
                    "SKILL.md + scripts only", policy.rule_scoping.skillmd_and_scripts_only
                )
            elif key == "rule_docs":
                policy.rule_scoping.skip_in_docs = _edit_set("Skip in docs", policy.rule_scoping.skip_in_docs)
            elif key == "rule_code_only":
                policy.rule_scoping.code_only = _edit_set("Code-only rules", policy.rule_scoping.code_only)
            elif key == "rule_docpaths":
                policy.rule_scoping.doc_path_indicators = _edit_set(
                    "Doc path names", policy.rule_scoping.doc_path_indicators
                )
            elif key == "rule_doc_filenames":
                policy.rule_scoping.doc_filename_patterns = _edit_list(
                    "Doc filename patterns (regex)", policy.rule_scoping.doc_filename_patterns
                )
            elif key == "creds":
                policy.credentials.known_test_values = _edit_set(
                    "Test credential values", policy.credentials.known_test_values
                )
            elif key == "cred_placeholders":
                policy.credentials.placeholder_markers = _edit_set(
                    "Placeholder markers", policy.credentials.placeholder_markers
                )
            elif key == "safe_rm":
                policy.system_cleanup.safe_rm_targets = _edit_set(
                    "Safe rm targets", policy.system_cleanup.safe_rm_targets
                )
            elif key == "file_class":
                policy.file_classification.inert_extensions = _edit_set(
                    "Inert extensions", policy.file_classification.inert_extensions
                )
                policy.file_classification.structured_extensions = _edit_set(
                    "Structured extensions", policy.file_classification.structured_extensions
                )
                policy.file_classification.archive_extensions = _edit_set(
                    "Archive extensions", policy.file_classification.archive_extensions
                )
                policy.file_classification.code_extensions = _edit_set(
                    "Code extensions", policy.file_classification.code_extensions
                )
            elif key == "file_limits":
                _edit_file_limits(policy)
            elif key == "thresholds":
                _edit_analysis_thresholds(policy)
            elif key == "sensitive":
                policy.sensitive_files.patterns = _edit_list(
                    "Sensitive file patterns (regex)", policy.sensitive_files.patterns
                )
            elif key == "cmd_safety":
                policy.command_safety.safe_commands = _edit_set("Safe commands", policy.command_safety.safe_commands)
                policy.command_safety.caution_commands = _edit_set(
                    "Caution commands", policy.command_safety.caution_commands
                )
                policy.command_safety.risky_commands = _edit_set("Risky commands", policy.command_safety.risky_commands)
                policy.command_safety.dangerous_commands = _edit_set(
                    "Dangerous commands", policy.command_safety.dangerous_commands
                )
            elif key == "analyzers":
                console.print("\n  [bold]Analyzers[/bold]")
                policy.analyzers.static = Confirm.ask("  Enable static analyzer?", default=policy.analyzers.static)
                policy.analyzers.bytecode = Confirm.ask(
                    "  Enable bytecode analyzer?", default=policy.analyzers.bytecode
                )
                policy.analyzers.pipeline = Confirm.ask(
                    "  Enable pipeline analyzer?", default=policy.analyzers.pipeline
                )
            elif key == "severity":
                _edit_severity_overrides(policy)
            elif key == "disabled":
                policy.disabled_rules = _edit_set("Disabled rules", policy.disabled_rules)

    # Step 4: Summary
    console.print()
    console.print("[bold]Step 4: Review[/bold]")

    summary = Table(show_header=False, box=None, pad_edge=True, padding=(0, 2))
    summary.add_column("Key", style="cyan")
    summary.add_column("Value")
    summary.add_row("Policy name", policy.policy_name)
    summary.add_row("Policy version", policy.policy_version)
    summary.add_row("Based on", preset)
    summary.add_row("Benign dotfiles", str(len(policy.hidden_files.benign_dotfiles)))
    summary.add_row("Benign dotdirs", str(len(policy.hidden_files.benign_dotdirs)))
    summary.add_row("Known installers", str(len(policy.pipeline.known_installer_domains)))
    summary.add_row("Benign pipe targets", str(len(policy.pipeline.benign_pipe_targets)))
    summary.add_row("Pipeline doc paths", str(len(policy.pipeline.doc_path_indicators)))
    summary.add_row(
        "Rules (SKILL.md only)", ", ".join(sorted(policy.rule_scoping.skillmd_and_scripts_only)) or "(none)"
    )
    summary.add_row("Rules (skip in docs)", ", ".join(sorted(policy.rule_scoping.skip_in_docs)) or "(none)")
    summary.add_row("Rules (code only)", ", ".join(sorted(policy.rule_scoping.code_only)) or "(none)")
    summary.add_row("Doc path indicators", str(len(policy.rule_scoping.doc_path_indicators)))
    summary.add_row("Doc filename patterns", str(len(policy.rule_scoping.doc_filename_patterns)))
    summary.add_row("Test creds suppressed", str(len(policy.credentials.known_test_values)))
    summary.add_row("Placeholder markers", str(len(policy.credentials.placeholder_markers)))
    summary.add_row("Safe rm targets", str(len(policy.system_cleanup.safe_rm_targets)))
    summary.add_row("Inert extensions", str(len(policy.file_classification.inert_extensions)))
    summary.add_row("Structured extensions", str(len(policy.file_classification.structured_extensions)))
    summary.add_row("Archive extensions", str(len(policy.file_classification.archive_extensions)))
    summary.add_row("Code extensions", str(len(policy.file_classification.code_extensions)))
    summary.add_row("Max file count", str(policy.file_limits.max_file_count))
    summary.add_row("Max file size", f"{policy.file_limits.max_file_size_bytes / 1024 / 1024:.0f} MB")
    summary.add_row("Sensitive file patterns", str(len(policy.sensitive_files.patterns)))
    summary.add_row("Safe commands", str(len(policy.command_safety.safe_commands)))
    summary.add_row("Caution commands", str(len(policy.command_safety.caution_commands)))
    summary.add_row("Risky commands", str(len(policy.command_safety.risky_commands)))
    summary.add_row("Dangerous commands", str(len(policy.command_safety.dangerous_commands)))
    summary.add_row(
        "Analyzers",
        ", ".join(
            a
            for a, enabled in [
                ("static", policy.analyzers.static),
                ("bytecode", policy.analyzers.bytecode),
                ("pipeline", policy.analyzers.pipeline),
            ]
            if enabled
        )
        or "(none)",
    )
    summary.add_row("Severity overrides", str(len(policy.severity_overrides)))
    summary.add_row("Disabled rules", ", ".join(sorted(policy.disabled_rules)) or "(none)")
    console.print(summary)

    # Step 5: Save
    console.print()
    output_path = Prompt.ask("  Save to", default=output_path)

    if Path(output_path).exists():
        if not Confirm.ask(f"  [yellow]{output_path} already exists. Overwrite?[/yellow]", default=False):
            console.print("  [dim]Cancelled.[/dim]")
            return 0

    policy.to_yaml(output_path)
    console.print(f"\n  [bold green]Saved policy to {output_path}[/bold green]")
    console.print("\n  Use it with:")
    console.print(f"    [cyan]skill-scanner scan --policy {output_path} /path/to/skill[/cyan]")
    console.print()
    return 0
