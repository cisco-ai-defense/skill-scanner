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

"""Interactive scan wizard for Skill Scanner.

Provides a step-by-step Rich-based prompt flow that guides users through
selecting a scan target, analyzers, policy, and output options.  Assembles
the equivalent CLI command and offers to run it directly.

Launch via ``skill-scanner`` (no subcommand) or ``skill-scanner interactive``.
"""

from __future__ import annotations

import os
import platform
import shlex
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

console = Console()

# ── Constants ────────────────────────────────────────────────────────────────

_ACTIONS = {
    "1": ("scan", "Scan a single skill package"),
    "2": ("scan-all", "Scan a directory of skills"),
    "3": ("configure-policy", "Interactive policy configurator (TUI)"),
    "4": ("list-analyzers", "Show available analyzers"),
    "5": ("generate-policy", "Generate a default policy YAML file"),
}

_FORMATS = ["summary", "json", "markdown", "table", "sarif", "html"]
_POLICIES = ["balanced", "strict", "permissive"]
_SEVERITIES = ["none", "critical", "high", "medium", "low", "info"]

_LOGO = r"""
 ___  _    _  _  _   ___
/ __|| | _(_)| || | / __|  ___  __ _  _ _   _ _   ___  _ _
\__ \| |/ / || || | \__ \ / _| / _` || ' \ | ' \ / -_)| '_|
|___/|_\_\|_| \__/  |___/ \__| \__,_||_||_||_||_|\___||_|
"""

_SKILL_MARKERS = ("SKILL.md", "skill.md", "manifest.json", "manifest.yaml", "README.md")
_SKILL_DIR_CANDIDATES = (".cursor/skills", "skills", ".codex/skills", "codex_skills")

_ENV_KEYS = {
    "SKILL_SCANNER_LLM_API_KEY": "LLM semantic analysis",
    "VIRUSTOTAL_API_KEY": "VirusTotal binary scanning",
    "AI_DEFENSE_API_KEY": "Cisco AI Defense",
}


# ── Environment detection ────────────────────────────────────────────────────


def _list_skills(directory: Path) -> list[Path]:
    """Return subdirectories that look like individual skill packages."""
    if not directory.is_dir():
        return []
    skills: list[Path] = []
    try:
        for child in sorted(directory.iterdir()):
            if child.is_dir() and any((child / m).exists() for m in _SKILL_MARKERS):
                skills.append(child)
    except PermissionError:
        pass
    return skills


def _detect_environment() -> dict:
    """Scan environment variables and filesystem for useful context."""
    keys: dict[str, bool] = {k: bool(os.environ.get(k)) for k in _ENV_KEYS}

    detected_dirs: list[tuple[str, int, list[Path]]] = []
    cwd = Path.cwd()
    for candidate in _SKILL_DIR_CANDIDATES:
        candidate_path = cwd / candidate
        if candidate_path.is_dir():
            skills = _list_skills(candidate_path)
            detected_dirs.append((candidate, len(skills), skills))

    python_version = platform.python_version()

    return {
        "keys": keys,
        "detected_dirs": detected_dirs,
        "python_version": python_version,
    }


# ── UI helpers ───────────────────────────────────────────────────────────────


def _print_banner() -> None:
    logo_text = Text(_LOGO.rstrip(), style="bold cyan")
    subtitle = Text.assemble(
        ("\n  Interactive Wizard\n\n", "bold white"),
        ("  Answer a few questions to build your scan command.\n", ""),
        ("  Press ", "dim"),
        ("Ctrl+C", "bold yellow"),
        (" at any time to quit.", "dim"),
    )
    content = Text()
    content.append_text(logo_text)
    content.append_text(subtitle)
    console.print(Panel(content, border_style="cyan", padding=(0, 2)))
    console.print()


def _print_env_panel(env: dict) -> None:
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=False)
    table.add_column("Category", style="bold", width=12)
    table.add_column("Item", min_width=32)
    table.add_column("Status")

    for key_name, label in _ENV_KEYS.items():
        is_set = env["keys"].get(key_name, False)
        status = "[green]set[/]" if is_set else "[dim]not set[/]"
        marker = "[green]\u2714[/]" if is_set else "[dim]\u2718[/]"
        table.add_row("", f"[dim]{key_name}[/]", f"{marker} {status}")

    if env["detected_dirs"]:
        for rel_path, skill_count, _skills in env["detected_dirs"]:
            count_str = (
                f"[green]{skill_count} skill{'s' if skill_count != 1 else ''}[/]" if skill_count else "[dim]empty[/]"
            )
            table.add_row("", f"{rel_path}/", f"[green]\u2714[/] found ({count_str})")
    else:
        table.add_row("", "[dim]No common skill directories found[/]", "")

    table.add_row("", f"Python {env['python_version']}", "")

    console.print(Panel(table, title="[bold]Environment[/]", border_style="dim", padding=(0, 1)))
    console.print()


def _step_header(step: int, total: int, title: str) -> None:
    console.print()
    console.print(
        Rule(
            f"[bold cyan]Step {step}[/] [dim]of {total}[/]  \u2500  [bold]{title}[/]",
            style="dim",
        )
    )
    console.print()


def _print_preview(cmd: list[str]) -> None:
    """Print the command assembled so far as an inline preview."""
    cmd_str = shlex.join(cmd)
    console.print(f"\n  [dim]\u25b6 Command so far:[/] [green]{cmd_str}[/]")


# ── Question helpers ─────────────────────────────────────────────────────────


def _ask_action() -> str:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=4)
    table.add_column("Action", style="bold")
    table.add_column("Description", style="dim")
    for key, (action, desc) in _ACTIONS.items():
        table.add_row(key, action, desc)
    console.print(table)
    console.print()

    choice = Prompt.ask(
        "[bold]Select an action[/]",
        choices=list(_ACTIONS.keys()),
        default="1",
    )
    return _ACTIONS[choice][0]


def _ask_path_smart(action: str, env: dict) -> str:
    """Path selector with auto-discovered skill directories.

    For ``scan`` (single skill) this lists individual skill packages found
    inside the detected directories.  For ``scan-all`` it lists the parent
    directories themselves.
    """
    detected = env.get("detected_dirs", [])

    if action == "scan":
        return _ask_path_smart_single(detected)
    return _ask_path_smart_multi(detected)


def _ask_path_smart_single(detected: list) -> str:
    """List individual skills for the ``scan`` action."""
    all_skills: list[tuple[str, Path]] = []
    for rel_parent, _count, skills in detected:
        for skill_path in skills:
            display = f"{rel_parent}/{skill_path.name}"
            all_skills.append((display, skill_path))

    if not all_skills:
        return _ask_path_manual("scan")

    console.print("[bold]Detected skills:[/]\n")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=4)
    table.add_column("Skill", style="bold")

    for i, (display, _path) in enumerate(all_skills, 1):
        table.add_row(str(i), display)

    custom_key = str(len(all_skills) + 1)
    table.add_row(custom_key, "[dim]Custom path\u2026[/]")
    console.print(table)
    console.print()

    valid = [str(i) for i in range(1, len(all_skills) + 2)]
    choice = Prompt.ask("[bold]Select a skill[/]", choices=valid, default="1")

    if choice == custom_key:
        return _ask_path_manual("scan")

    idx = int(choice) - 1
    return str(all_skills[idx][1].resolve())


def _ask_path_smart_multi(detected: list) -> str:
    """List parent directories for the ``scan-all`` action."""
    if not detected:
        return _ask_path_manual("scan-all")

    console.print("[bold]Detected skill directories:[/]\n")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=4)
    table.add_column("Path", style="bold")
    table.add_column("Info", style="dim")

    for i, (rel_path, count, _skills) in enumerate(detected, 1):
        count_label = f"{count} skill{'s' if count != 1 else ''}" if count else "empty"
        table.add_row(str(i), rel_path + "/", f"({count_label})")

    custom_key = str(len(detected) + 1)
    table.add_row(custom_key, "[dim]Custom path\u2026[/]", "")
    console.print(table)
    console.print()

    valid = [str(i) for i in range(1, len(detected) + 2)]
    choice = Prompt.ask("[bold]Select[/]", choices=valid, default="1")

    if choice == custom_key:
        return _ask_path_manual("scan-all")

    idx = int(choice) - 1
    resolved = (Path.cwd() / detected[idx][0]).resolve()
    return str(resolved)


def _ask_path_manual(action: str) -> str:
    label = "Path to skill directory" if action == "scan" else "Path to skills directory"
    while True:
        path = Prompt.ask(f"[bold]{label}[/]", default=".")
        resolved = Path(path).expanduser().resolve()
        if resolved.is_dir():
            return str(resolved)
        console.print(f"[red]Directory not found:[/] {resolved}")


def _ask_recursive() -> bool:
    return Confirm.ask("[bold]Search recursively for skills?[/]", default=True)


def _ask_check_overlap() -> bool:
    return Confirm.ask("[bold]Enable cross-skill overlap detection?[/]", default=False)


def _ask_analyzers(env: dict) -> dict[str, bool]:
    analyzers: dict[str, bool] = {}

    console.print("[bold]Free:[/]")
    analyzers["use_behavioral"] = Confirm.ask(
        "  Behavioral dataflow analysis",
        default=False,
    )

    console.print()
    console.print("[bold]Requires API Key:[/]")

    llm_set = env["keys"].get("SKILL_SCANNER_LLM_API_KEY", False)
    llm_tag = "[green]\u2714 key set[/]" if llm_set else "[dim]\u2718 key not set[/]"
    analyzers["use_llm"] = Confirm.ask(
        f"  LLM semantic analysis  {llm_tag}",
        default=llm_set,
    )

    vt_set = env["keys"].get("VIRUSTOTAL_API_KEY", False)
    vt_tag = "[green]\u2714 key set[/]" if vt_set else "[dim]\u2718 key not set[/]"
    analyzers["use_virustotal"] = Confirm.ask(
        f"  VirusTotal binary scanning  {vt_tag}",
        default=vt_set,
    )

    aid_set = env["keys"].get("AI_DEFENSE_API_KEY", False)
    aid_tag = "[green]\u2714 key set[/]" if aid_set else "[dim]\u2718 key not set[/]"
    analyzers["use_aidefense"] = Confirm.ask(
        f"  Cisco AI Defense  {aid_tag}",
        default=aid_set,
    )

    active = sum(1 for k, v in analyzers.items() if v and k != "enable_meta")
    console.print()
    console.print("[bold]Post-processing:[/]")
    meta_viable = active >= 2
    meta_hint = "" if meta_viable else "  [dim](enable 2+ analyzers first)[/]"
    analyzers["enable_meta"] = Confirm.ask(
        f"  Meta-analysis false-positive filtering{meta_hint}",
        default=meta_viable,
    )

    return analyzers


def _ask_llm_details(env: dict) -> dict[str, str]:
    details: dict[str, str] = {}

    if not env["keys"].get("SKILL_SCANNER_LLM_API_KEY", False):
        console.print(
            "\n[yellow]\u26a0  SKILL_SCANNER_LLM_API_KEY not set.[/] "
            "Set it in your environment or the LLM analyzer will fail."
        )

    provider = Prompt.ask(
        "  LLM provider",
        choices=["anthropic", "openai"],
        default="anthropic",
    )
    details["llm_provider"] = provider
    return details


def _ask_policy() -> str:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Preset", style="bold", width=14)
    table.add_column("Description", style="dim")
    table.add_row("[cyan]balanced[/]", "Recommended \u2014 good balance of coverage and noise")
    table.add_row("[yellow]strict[/]", "Maximum detection \u2014 fewer false negatives")
    table.add_row("[green]permissive[/]", "Minimal noise \u2014 fewer false positives")
    console.print(table)
    console.print()

    return Prompt.ask(
        "[bold]Policy preset[/]",
        choices=_POLICIES,
        default="balanced",
    )


def _ask_format() -> str:
    return Prompt.ask(
        "[bold]Output format[/]",
        choices=_FORMATS,
        default="summary",
    )


def _ask_output_file(fmt: str) -> str | None:
    extensions = {
        "json": ".json",
        "sarif": ".sarif",
        "markdown": ".md",
        "html": ".html",
        "table": ".txt",
    }
    if fmt in extensions:
        default_name = f"results{extensions[fmt]}"
        if Confirm.ask(f"[bold]Save output to file?[/] [dim](default: {default_name})[/]", default=False):
            return Prompt.ask("  Output file path", default=default_name)
    return None


def _ask_severity() -> str | None:
    sev_display = "[red]critical[/]  [yellow]high[/]  [blue]medium[/]  [dim]low[/]  [dim]info[/]  [dim italic]none[/]"
    console.print(f"  Severity levels: {sev_display}")
    sev = Prompt.ask(
        "[bold]Fail on severity threshold[/] [dim](for CI gating)[/]",
        choices=_SEVERITIES,
        default="none",
    )
    return None if sev == "none" else sev


def _ask_lenient() -> bool:
    return Confirm.ask(
        "[bold]Lenient mode?[/] [dim](tolerate malformed skills)[/]",
        default=False,
    )


# ── Command builder ──────────────────────────────────────────────────────────


def _build_command(
    action: str,
    path: str,
    *,
    recursive: bool = False,
    check_overlap: bool = False,
    analyzers: dict[str, bool] | None = None,
    llm_details: dict[str, str] | None = None,
    policy: str = "balanced",
    fmt: str = "summary",
    output_file: str | None = None,
    severity: str | None = None,
    lenient: bool = False,
) -> list[str]:
    """Assemble a CLI argv list from wizard answers."""
    cmd = ["skill-scanner", action, path]

    if action == "scan-all":
        if recursive:
            cmd.append("--recursive")
        if check_overlap:
            cmd.append("--check-overlap")

    if policy != "balanced":
        cmd.extend(["--policy", policy])

    if analyzers:
        if analyzers.get("use_behavioral"):
            cmd.append("--use-behavioral")
        if analyzers.get("use_llm"):
            cmd.append("--use-llm")
        if analyzers.get("use_virustotal"):
            cmd.append("--use-virustotal")
        if analyzers.get("use_aidefense"):
            cmd.append("--use-aidefense")
        if analyzers.get("enable_meta"):
            cmd.append("--enable-meta")

    if llm_details:
        provider = llm_details.get("llm_provider", "anthropic")
        if provider != "anthropic":
            cmd.extend(["--llm-provider", provider])

    if fmt != "summary":
        cmd.extend(["--format", fmt])

    if output_file:
        cmd.extend(["--output", output_file])

    if severity:
        cmd.extend(["--fail-on-severity", severity])

    if lenient:
        cmd.append("--lenient")

    return cmd


def _build_partial_command(
    action: str,
    path: str | None = None,
    **kwargs,
) -> list[str]:
    """Build a partial command for the live preview (path may be unset)."""
    return _build_command(action, path or "...", **kwargs)


def _show_review(cmd: list[str]) -> None:
    cmd_str = shlex.join(cmd)
    console.print()
    console.print(
        Panel(
            Syntax(cmd_str, "bash", theme="monokai", word_wrap=True),
            title="[bold]Generated Command[/]",
            border_style="green",
            padding=(1, 2),
        )
    )
    console.print()


def _execute_scan(cmd: list[str]) -> int:
    """Run the scan by dispatching through the CLI parser."""
    from .cli import build_parser

    parser = build_parser()
    args = parser.parse_args(cmd[1:])

    from .cli import (
        configure_policy_command,
        generate_policy_command,
        list_analyzers_command,
        scan_all_command,
        scan_command,
    )

    dispatch = {
        "scan": scan_command,
        "scan-all": scan_all_command,
        "list-analyzers": list_analyzers_command,
        "generate-policy": generate_policy_command,
        "configure-policy": configure_policy_command,
    }
    handler = dispatch.get(args.command)
    if handler:
        try:
            return handler(args)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
        except Exception as exc:
            console.print(f"\n[red bold]Scan error:[/] {exc}")
            return 1
    return 1


# ── Main wizard flow ─────────────────────────────────────────────────────────

_SCAN_TOTAL_STEPS = 7


def run_wizard() -> int:
    """Run the interactive scan wizard. Returns a CLI exit code."""
    try:
        _print_banner()
        env = _detect_environment()
        _print_env_panel(env)

        # Step 1 — Action
        _step_header(1, _SCAN_TOTAL_STEPS, "Action")
        action = _ask_action()

        if action in ("configure-policy", "list-analyzers", "generate-policy"):
            cmd = ["skill-scanner", action]
            if action == "generate-policy":
                preset = Prompt.ask("Base preset", choices=_POLICIES, default="balanced")
                out = Prompt.ask("Output file", default="scan_policy.yaml")
                cmd.extend(["--preset", preset, "--output", out])
            _show_review(cmd)
            if Confirm.ask("[bold]Run now?[/]", default=True):
                return _execute_scan(cmd)
            return 0

        # Step 2 — Scan Target
        _step_header(2, _SCAN_TOTAL_STEPS, "Scan Target")
        path = _ask_path_smart(action, env)
        preview_kw: dict = {}

        recursive = False
        check_overlap = False
        if action == "scan-all":
            recursive = _ask_recursive()
            check_overlap = _ask_check_overlap()
            preview_kw.update(recursive=recursive, check_overlap=check_overlap)

        _print_preview(_build_partial_command(action, path, **preview_kw))

        # Step 3 — Analyzers
        _step_header(3, _SCAN_TOTAL_STEPS, "Analyzers")
        analyzers = _ask_analyzers(env)
        preview_kw["analyzers"] = analyzers

        llm_details: dict[str, str] | None = None
        if analyzers.get("use_llm"):
            llm_details = _ask_llm_details(env)
            preview_kw["llm_details"] = llm_details

        _print_preview(_build_partial_command(action, path, **preview_kw))

        # Step 4 — Policy
        _step_header(4, _SCAN_TOTAL_STEPS, "Policy")
        policy = _ask_policy()
        preview_kw["policy"] = policy
        _print_preview(_build_partial_command(action, path, **preview_kw))

        # Step 5 — Output
        _step_header(5, _SCAN_TOTAL_STEPS, "Output")
        fmt = _ask_format()
        output_file = _ask_output_file(fmt)
        preview_kw["fmt"] = fmt
        if output_file:
            preview_kw["output_file"] = output_file
        _print_preview(_build_partial_command(action, path, **preview_kw))

        # Step 6 — CI / Severity
        _step_header(6, _SCAN_TOTAL_STEPS, "CI Gating")
        severity = _ask_severity()
        if severity:
            preview_kw["severity"] = severity
        _print_preview(_build_partial_command(action, path, **preview_kw))

        # Step 7 — Extra Options
        _step_header(7, _SCAN_TOTAL_STEPS, "Extra Options")
        lenient = _ask_lenient()
        if lenient:
            preview_kw["lenient"] = lenient

        cmd = _build_command(
            action,
            path,
            recursive=recursive,
            check_overlap=check_overlap,
            analyzers=analyzers,
            llm_details=llm_details,
            policy=policy,
            fmt=fmt,
            output_file=output_file,
            severity=severity,
            lenient=lenient,
        )

        _show_review(cmd)

        while True:
            choice = Prompt.ask(
                "[bold]What next?[/]",
                choices=["run", "copy", "edit-path", "quit"],
                default="run",
            )

            if choice == "copy":
                cmd_str = shlex.join(cmd)
                console.print(f"\n[green]Copy this command:[/]\n\n  {cmd_str}\n")
                return 0

            if choice == "quit":
                return 0

            if choice == "edit-path":
                path = _ask_path_manual(action)
                cmd = _build_command(
                    action,
                    path,
                    recursive=recursive,
                    check_overlap=check_overlap,
                    analyzers=analyzers,
                    llm_details=llm_details,
                    policy=policy,
                    fmt=fmt,
                    output_file=output_file,
                    severity=severity,
                    lenient=lenient,
                )
                _show_review(cmd)
                continue

            # choice == "run"
            console.print("[dim]Running scan\u2026[/]\n")
            rc = _execute_scan(cmd)
            if rc == 0:
                return 0

            console.print(
                f"\n[yellow bold]Scan exited with code {rc}.[/]  You can edit the path, copy the command, or quit.\n"
            )
            _show_review(cmd)

    except KeyboardInterrupt:
        console.print("\n[dim]Wizard cancelled.[/]")
        return 130
