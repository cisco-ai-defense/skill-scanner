# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Interactive TUI for configuring a scan policy.

Uses ``textual`` for a mouse-friendly, widget-based terminal experience
with checkboxes, radio buttons, scrollable lists, and clickable buttons.

Run via:  skill-scanner configure-policy [-o my_policy.yaml]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Rule,
    TextArea,
)

from ..core.scan_policy import ScanPolicy, SeverityOverride

# ─── Utility ──────────────────────────────────────────────────────────────────


def _set_to_text(s: set[str] | list[str]) -> str:
    """Convert a set/list to newline-separated text for a TextArea."""
    items = sorted(s) if isinstance(s, set) else list(s)
    return "\n".join(items)


def _text_to_set(text: str) -> set[str]:
    """Convert newline-separated text back to a set."""
    return {line.strip() for line in text.splitlines() if line.strip()}


def _text_to_list(text: str) -> list[str]:
    """Convert newline-separated text back to a list."""
    return [line.strip() for line in text.splitlines() if line.strip()]


# ─── Set Editor Modal ────────────────────────────────────────────────────────


class SetEditorScreen(ModalScreen[set[str] | list[str] | None]):
    """Modal for editing a set or list of strings (one per line)."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    SetEditorScreen {
        align: center middle;
    }
    SetEditorScreen > Vertical {
        width: 80;
        max-height: 85%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    SetEditorScreen TextArea {
        height: 1fr;
        min-height: 10;
    }
    SetEditorScreen .buttons {
        height: 3;
        align: right middle;
        margin-top: 1;
    }
    SetEditorScreen .buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, title: str, items: set[str] | list[str], as_list: bool = False) -> None:
        super().__init__()
        self.editor_title = title
        self.items = items
        self.as_list = as_list

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"[bold]{self.editor_title}[/bold]  [dim](one item per line)[/dim]")
            yield TextArea(_set_to_text(self.items), id="editor")
            with Horizontal(classes="buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", variant="default", id="cancel")

    @on(Button.Pressed, "#save")
    def on_save(self) -> None:
        text = self.query_one("#editor", TextArea).text
        if self.as_list:
            self.dismiss(_text_to_list(text))
        else:
            self.dismiss(_text_to_set(text))

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


# ─── Main App ────────────────────────────────────────────────────────────────


class PolicyConfigApp(App[str | None]):
    """Interactive policy configurator with mouse-friendly widgets."""

    TITLE = "Skill Scanner – Policy Configurator"
    SUB_TITLE = "Build a custom scan policy for your organisation"

    BINDINGS = [
        Binding("q", "quit_app", "Quit without saving"),
        Binding("s", "save_policy", "Save policy"),
    ]

    DEFAULT_CSS = """
    Screen {
        background: $surface;
    }
    #main-scroll {
        height: 1fr;
        padding: 1 2;
    }
    .section-title {
        margin-top: 1;
        text-style: bold;
        color: $primary;
    }
    .section-desc {
        color: $text-muted;
        margin-bottom: 1;
    }
    .field-row {
        height: 3;
        margin-bottom: 0;
    }
    .field-row Label {
        width: 35;
        content-align: left middle;
    }
    .field-row Input {
        width: 1fr;
    }
    .field-row Button {
        width: auto;
        min-width: 20;
    }
    .edit-btn {
        margin-left: 1;
    }
    .preset-row {
        height: auto;
        margin-bottom: 1;
    }
    .preset-row RadioSet {
        width: 100%;
    }
    .analyzer-checks {
        height: auto;
        margin-bottom: 1;
    }
    .action-bar {
        height: 3;
        dock: bottom;
        align: center middle;
        background: $primary-background;
        padding: 0 2;
    }
    .action-bar Button {
        margin: 0 1;
    }
    #policy-name-input, #policy-version-input {
        width: 1fr;
    }
    """

    def __init__(
        self,
        output_path: str = "scan_policy.yaml",
        input_path: str | None = None,
    ) -> None:
        super().__init__()
        self.output_path = output_path
        self.input_path = input_path
        self.policy = ScanPolicy.default()
        self.preset_name = "balanced"
        # Track which field an edit-modal result should update
        self._pending_field: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="main-scroll"):
            # ── Preset ────────────────────────────────────────────────
            yield Label("Starting Preset", classes="section-title")
            yield Label("Choose a base policy to customise from.", classes="section-desc")
            with RadioSet(id="preset-radio"):
                yield RadioButton("Strict – narrow allowlists, no suppressions", id="preset-strict")
                yield RadioButton("Balanced – sensible defaults (recommended)", id="preset-balanced", value=True)
                yield RadioButton("Permissive – broad allowlists, aggressive suppression", id="preset-permissive")

            yield Rule()

            # ── Identity ──────────────────────────────────────────────
            yield Label("Policy Identity", classes="section-title")
            with Horizontal(classes="field-row"):
                yield Label("Policy name")
                yield Input(value="balanced-custom", id="policy-name-input")
            with Horizontal(classes="field-row"):
                yield Label("Policy version")
                yield Input(value="1.0", id="policy-version-input")

            yield Rule()

            # ── Hidden Files ──────────────────────────────────────────
            yield Label("Hidden Files", classes="section-title")
            yield Label(
                "Dotfiles/dirs NOT in these lists trigger HIDDEN_DATA_FILE / HIDDEN_DATA_DIR findings.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Benign dotfiles")
                yield Button("Edit list...", id="edit-dotfiles", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Benign dotdirs")
                yield Button("Edit list...", id="edit-dotdirs", classes="edit-btn")

            yield Rule()

            # ── Pipeline ──────────────────────────────────────────────
            yield Label("Pipeline Analysis", classes="section-title")
            yield Label(
                "Trusted installer URLs, benign pipe patterns, and tool-chaining detection tuning.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Known installer domains")
                yield Button("Edit list...", id="edit-installers", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Benign pipe targets (regex)")
                yield Button("Edit list...", id="edit-pipes", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Doc path indicators")
                yield Button("Edit list...", id="edit-pipe-docpaths", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Exfil hint words")
                yield Button("Edit list...", id="edit-exfil-hints", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("API doc tokens (suppress FP)")
                yield Button("Edit list...", id="edit-api-doc-tokens", classes="edit-btn")
            with Vertical(classes="analyzer-checks"):
                yield Checkbox("Demote findings in docs", value=True, id="chk-demote-in-docs")
                yield Checkbox("Demote instructional examples", value=True, id="chk-demote-instructional")
                yield Checkbox("Demote known installer URLs", value=True, id="chk-check-known-installers")

            yield Rule()

            # ── Rule Scoping ──────────────────────────────────────────
            yield Label("Rule Scoping", classes="section-title")
            yield Label(
                "Restrict rules to specific file types. Reduces noise in doc-heavy skills.", classes="section-desc"
            )
            with Horizontal(classes="field-row"):
                yield Label("SKILL.md + scripts only")
                yield Button("Edit list...", id="edit-rule-skillmd", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Skip in documentation")
                yield Button("Edit list...", id="edit-rule-docs", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Code-only rules")
                yield Button("Edit list...", id="edit-rule-code", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Doc path names")
                yield Button("Edit list...", id="edit-rule-docpaths", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Doc filename patterns")
                yield Button("Edit list...", id="edit-rule-docfiles", classes="edit-btn")

            yield Rule()

            # ── Credentials ───────────────────────────────────────────
            yield Label("Credentials", classes="section-title")
            yield Label(
                "Suppress well-known test credentials and placeholders to avoid false positives.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Known test values")
                yield Button("Edit list...", id="edit-creds", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Placeholder markers")
                yield Button("Edit list...", id="edit-placeholders", classes="edit-btn")

            yield Rule()

            # ── System Cleanup ────────────────────────────────────────
            yield Label("System Cleanup", classes="section-title")
            yield Label("Safe rm targets that won't trigger DANGEROUS_CLEANUP findings.", classes="section-desc")
            with Horizontal(classes="field-row"):
                yield Label("Safe rm targets")
                yield Button("Edit list...", id="edit-safe-rm", classes="edit-btn")

            yield Rule()

            # ── File Classification ───────────────────────────────────
            yield Label("File Classification", classes="section-title")
            yield Label(
                "Extension-based categorisation. Inert files are skipped; code files get deeper analysis.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Inert extensions")
                yield Button("Edit list...", id="edit-inert-ext", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Structured extensions")
                yield Button("Edit list...", id="edit-struct-ext", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Archive extensions")
                yield Button("Edit list...", id="edit-archive-ext", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Code extensions")
                yield Button("Edit list...", id="edit-code-ext", classes="edit-btn")
            with Vertical(classes="analyzer-checks"):
                yield Checkbox("Skip inert extension checks", value=True, id="chk-skip-inert-ext")

            yield Rule()

            # ── File Limits ───────────────────────────────────────────
            yield Label("File Limits", classes="section-title")
            yield Label(
                "Max sizes/counts before flagging. Affects EXCESSIVE_FILE_COUNT and OVERSIZED_FILE rules.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Max file count")
                yield Input(value="100", id="max-file-count", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max file size (bytes)")
                yield Input(value="5242880", id="max-file-size", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max reference depth")
                yield Input(value="5", id="max-ref-depth", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max name length")
                yield Input(value="64", id="max-name-len", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max description length")
                yield Input(value="1024", id="max-desc-len", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Min description length")
                yield Input(value="20", id="min-desc-len", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max YARA scan file size (bytes)")
                yield Input(value="52428800", id="max-yara-scan-size", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max loader file size (bytes)")
                yield Input(value="10485760", id="max-loader-file-size", type="integer")

            yield Rule()

            # ── Analysis Thresholds ───────────────────────────────────
            yield Label("Analysis Thresholds", classes="section-title")
            yield Label(
                "Tune detection sensitivity. Lower values = more sensitive, higher = more permissive.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Zero-width (with decode)")
                yield Input(value="50", id="zw-decode", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Zero-width (standalone)")
                yield Input(value="200", id="zw-alone", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Analyzability LOW risk (%)")
                yield Input(value="90", id="anal-low", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Analyzability MEDIUM risk (%)")
                yield Input(value="70", id="anal-med", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Min dangerous lines (HOMOGLYPH)")
                yield Input(value="5", id="min-dangerous-lines", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Min confidence % (FILE_MAGIC)")
                yield Input(value="80", id="min-confidence-pct", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Exception handler context lines")
                yield Input(value="20", id="exception-handler-context-lines", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Short match max chars (steg)")
                yield Input(value="2", id="short-match-max-chars", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Cyrillic/CJK min chars (steg)")
                yield Input(value="10", id="cyrillic-cjk-min-chars", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max regex pattern length")
                yield Input(value="1000", id="max-regex-pattern-length", type="integer")

            yield Rule()

            # ── Sensitive Files ────────────────────────────────────────
            yield Label("Sensitive Files", classes="section-title")
            yield Label(
                "Regex patterns matching sensitive filenames. Upgrades pipeline taint to SENSITIVE_DATA.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Patterns (regex)")
                yield Button("Edit list...", id="edit-sensitive", classes="edit-btn")

            yield Rule()

            # ── Command Safety ────────────────────────────────────────
            yield Label("Command Safety Tiers", classes="section-title")
            yield Label(
                "Classify shell commands into tiers. Dangerous arg patterns are regex matching risky flags.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Safe commands")
                yield Button("Edit list...", id="edit-cmd-safe", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Caution commands")
                yield Button("Edit list...", id="edit-cmd-caution", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Risky commands")
                yield Button("Edit list...", id="edit-cmd-risky", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Dangerous commands")
                yield Button("Edit list...", id="edit-cmd-dangerous", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Dangerous arg patterns (regex)")
                yield Button("Edit list...", id="edit-dangerous-arg-patterns", classes="edit-btn")

            yield Rule()

            # ── Analyzers ─────────────────────────────────────────────
            yield Label("Analyzers", classes="section-title")
            yield Label(
                "Enable or disable built-in analysis passes (static, pipeline, bytecode).", classes="section-desc"
            )
            with Vertical(classes="analyzer-checks"):
                yield Checkbox("Static analyzer (YAML + YARA patterns)", value=True, id="chk-static")
                yield Checkbox("Bytecode analyzer (.pyc integrity)", value=True, id="chk-bytecode")
                yield Checkbox("Pipeline analyzer (command taint)", value=True, id="chk-pipeline")

            yield Rule()

            # ── LLM Analysis ─────────────────────────────────────────
            yield Label("LLM Analysis – Context Budgets", classes="section-title")
            yield Label(
                "Controls how much content is sent to LLM and meta analyzers. "
                "Content exceeding these limits is skipped (not truncated) with an INFO finding.",
                classes="section-desc",
            )
            with Horizontal(classes="field-row"):
                yield Label("Max instruction body (chars)")
                yield Input(value="20000", id="llm-max-instruction", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max code file (chars)")
                yield Input(value="15000", id="llm-max-code-file", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max referenced file (chars)")
                yield Input(value="10000", id="llm-max-ref-file", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Max total prompt (chars)")
                yield Input(value="100000", id="llm-max-total-prompt", type="integer")
            with Horizontal(classes="field-row"):
                yield Label("Meta budget multiplier")
                yield Input(value="3.0", id="llm-meta-multiplier")

            yield Rule()

            # ── Disabled Rules ────────────────────────────────────────
            yield Label("Disabled Rules & Severity Overrides", classes="section-title")
            yield Label("Suppress specific rules entirely or override their severity level.", classes="section-desc")
            with Horizontal(classes="field-row"):
                yield Label("Disabled rules")
                yield Button("Edit list...", id="edit-disabled", classes="edit-btn")
            with Horizontal(classes="field-row"):
                yield Label("Severity overrides")
                yield Button("Edit list...", id="edit-overrides", classes="edit-btn")

        # ── Bottom action bar ─────────────────────────────────────
        with Horizontal(classes="action-bar"):
            yield Button("Save Policy", variant="primary", id="btn-save")
            yield Button("Quit", variant="error", id="btn-quit")

        yield Footer()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        """Load an existing policy file or the balanced preset into the form."""
        if self.input_path and Path(self.input_path).exists():
            self.policy = ScanPolicy.from_yaml(Path(self.input_path))
            self.preset_name = getattr(self.policy, "preset_base", "balanced") or "balanced"
            self._sync_form_from_policy()
        else:
            self._load_preset("balanced")

    # ── Preset switching ──────────────────────────────────────────────────

    @on(RadioSet.Changed, "#preset-radio")
    def on_preset_change(self, event: RadioSet.Changed) -> None:
        idx = event.radio_set.pressed_index
        presets = ["strict", "balanced", "permissive"]
        if 0 <= idx < len(presets):
            self._load_preset(presets[idx])

    def _load_preset(self, name: str) -> None:
        self.preset_name = name
        self.policy = ScanPolicy.from_preset(name)
        self._sync_form_from_policy()

    def _sync_form_from_policy(self) -> None:
        """Push policy values into form widgets."""
        p = self.policy

        self.query_one("#policy-name-input", Input).value = p.policy_name or f"{self.preset_name}-custom"
        self.query_one("#policy-version-input", Input).value = p.policy_version or "1.0"

        # File limits
        self.query_one("#max-file-count", Input).value = str(p.file_limits.max_file_count)
        self.query_one("#max-file-size", Input).value = str(p.file_limits.max_file_size_bytes)
        self.query_one("#max-ref-depth", Input).value = str(p.file_limits.max_reference_depth)
        self.query_one("#max-name-len", Input).value = str(p.file_limits.max_name_length)
        self.query_one("#max-desc-len", Input).value = str(p.file_limits.max_description_length)
        self.query_one("#min-desc-len", Input).value = str(p.file_limits.min_description_length)
        self.query_one("#max-yara-scan-size", Input).value = str(p.file_limits.max_yara_scan_file_size_bytes)
        self.query_one("#max-loader-file-size", Input).value = str(p.file_limits.max_loader_file_size_bytes)

        # Thresholds
        self.query_one("#zw-decode", Input).value = str(p.analysis_thresholds.zerowidth_threshold_with_decode)
        self.query_one("#zw-alone", Input).value = str(p.analysis_thresholds.zerowidth_threshold_alone)
        self.query_one("#anal-low", Input).value = str(p.analysis_thresholds.analyzability_low_risk)
        self.query_one("#anal-med", Input).value = str(p.analysis_thresholds.analyzability_medium_risk)
        self.query_one("#min-dangerous-lines", Input).value = str(p.analysis_thresholds.min_dangerous_lines)
        self.query_one("#min-confidence-pct", Input).value = str(p.analysis_thresholds.min_confidence_pct)
        self.query_one("#exception-handler-context-lines", Input).value = str(
            p.analysis_thresholds.exception_handler_context_lines
        )
        self.query_one("#short-match-max-chars", Input).value = str(p.analysis_thresholds.short_match_max_chars)
        self.query_one("#cyrillic-cjk-min-chars", Input).value = str(p.analysis_thresholds.cyrillic_cjk_min_chars)
        self.query_one("#max-regex-pattern-length", Input).value = str(p.analysis_thresholds.max_regex_pattern_length)

        # Pipeline checkboxes
        self.query_one("#chk-demote-in-docs", Checkbox).value = p.pipeline.demote_in_docs
        self.query_one("#chk-demote-instructional", Checkbox).value = p.pipeline.demote_instructional
        self.query_one("#chk-check-known-installers", Checkbox).value = p.pipeline.check_known_installers

        # File classification checkbox
        self.query_one("#chk-skip-inert-ext", Checkbox).value = p.file_classification.skip_inert_extensions

        # Analyzers
        self.query_one("#chk-static", Checkbox).value = p.analyzers.static
        self.query_one("#chk-bytecode", Checkbox).value = p.analyzers.bytecode
        self.query_one("#chk-pipeline", Checkbox).value = p.analyzers.pipeline

        # LLM Analysis budgets
        self.query_one("#llm-max-instruction", Input).value = str(p.llm_analysis.max_instruction_body_chars)
        self.query_one("#llm-max-code-file", Input).value = str(p.llm_analysis.max_code_file_chars)
        self.query_one("#llm-max-ref-file", Input).value = str(p.llm_analysis.max_referenced_file_chars)
        self.query_one("#llm-max-total-prompt", Input).value = str(p.llm_analysis.max_total_prompt_chars)
        self.query_one("#llm-meta-multiplier", Input).value = str(p.llm_analysis.meta_budget_multiplier)

    def _sync_policy_from_form(self) -> None:
        """Pull form widget values back into the policy object."""
        p = self.policy

        p.policy_name = self.query_one("#policy-name-input", Input).value.strip() or "custom"
        p.policy_version = self.query_one("#policy-version-input", Input).value.strip() or "1.0"

        # File limits
        try:
            p.file_limits.max_file_count = int(self.query_one("#max-file-count", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.max_file_size_bytes = int(self.query_one("#max-file-size", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.max_reference_depth = int(self.query_one("#max-ref-depth", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.max_name_length = int(self.query_one("#max-name-len", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.max_description_length = int(self.query_one("#max-desc-len", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.min_description_length = int(self.query_one("#min-desc-len", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.max_yara_scan_file_size_bytes = int(self.query_one("#max-yara-scan-size", Input).value)
        except ValueError:
            pass
        try:
            p.file_limits.max_loader_file_size_bytes = int(self.query_one("#max-loader-file-size", Input).value)
        except ValueError:
            pass

        # Thresholds
        try:
            p.analysis_thresholds.zerowidth_threshold_with_decode = int(self.query_one("#zw-decode", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.zerowidth_threshold_alone = int(self.query_one("#zw-alone", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.analyzability_low_risk = int(self.query_one("#anal-low", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.analyzability_medium_risk = int(self.query_one("#anal-med", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.min_dangerous_lines = int(self.query_one("#min-dangerous-lines", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.min_confidence_pct = int(self.query_one("#min-confidence-pct", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.exception_handler_context_lines = int(
                self.query_one("#exception-handler-context-lines", Input).value
            )
        except ValueError:
            pass
        try:
            p.analysis_thresholds.short_match_max_chars = int(self.query_one("#short-match-max-chars", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.cyrillic_cjk_min_chars = int(self.query_one("#cyrillic-cjk-min-chars", Input).value)
        except ValueError:
            pass
        try:
            p.analysis_thresholds.max_regex_pattern_length = int(
                self.query_one("#max-regex-pattern-length", Input).value
            )
        except ValueError:
            pass

        # Pipeline checkboxes
        p.pipeline.demote_in_docs = self.query_one("#chk-demote-in-docs", Checkbox).value
        p.pipeline.demote_instructional = self.query_one("#chk-demote-instructional", Checkbox).value
        p.pipeline.check_known_installers = self.query_one("#chk-check-known-installers", Checkbox).value

        # File classification checkbox
        p.file_classification.skip_inert_extensions = self.query_one("#chk-skip-inert-ext", Checkbox).value

        # Analyzers
        p.analyzers.static = self.query_one("#chk-static", Checkbox).value
        p.analyzers.bytecode = self.query_one("#chk-bytecode", Checkbox).value
        p.analyzers.pipeline = self.query_one("#chk-pipeline", Checkbox).value

        # LLM Analysis budgets
        try:
            p.llm_analysis.max_instruction_body_chars = int(self.query_one("#llm-max-instruction", Input).value)
        except ValueError:
            pass
        try:
            p.llm_analysis.max_code_file_chars = int(self.query_one("#llm-max-code-file", Input).value)
        except ValueError:
            pass
        try:
            p.llm_analysis.max_referenced_file_chars = int(self.query_one("#llm-max-ref-file", Input).value)
        except ValueError:
            pass
        try:
            p.llm_analysis.max_total_prompt_chars = int(self.query_one("#llm-max-total-prompt", Input).value)
        except ValueError:
            pass
        try:
            p.llm_analysis.meta_budget_multiplier = float(self.query_one("#llm-meta-multiplier", Input).value)
        except ValueError:
            pass

    # ── Edit-list button handlers ─────────────────────────────────────────

    # Map button IDs to (policy attribute path, title, is_list)
    _FIELD_MAP: dict[str, tuple[str, str, bool]] = {
        "edit-dotfiles": ("hidden_files.benign_dotfiles", "Benign Dotfiles", False),
        "edit-dotdirs": ("hidden_files.benign_dotdirs", "Benign Dot-directories", False),
        "edit-installers": ("pipeline.known_installer_domains", "Known Installer Domains", False),
        "edit-pipes": ("pipeline.benign_pipe_targets", "Benign Pipe Targets (regex)", True),
        "edit-pipe-docpaths": ("pipeline.doc_path_indicators", "Pipeline Doc Path Indicators", False),
        "edit-exfil-hints": ("pipeline.exfil_hints", "Exfil Hint Words", True),
        "edit-api-doc-tokens": ("pipeline.api_doc_tokens", "API Doc Tokens (suppress FP)", True),
        "edit-rule-skillmd": ("rule_scoping.skillmd_and_scripts_only", "Rules: SKILL.md + scripts only", False),
        "edit-rule-docs": ("rule_scoping.skip_in_docs", "Rules: Skip in documentation", False),
        "edit-rule-code": ("rule_scoping.code_only", "Rules: Code-only", False),
        "edit-rule-docpaths": ("rule_scoping.doc_path_indicators", "Doc Path Names", False),
        "edit-rule-docfiles": ("rule_scoping.doc_filename_patterns", "Doc Filename Patterns (regex)", True),
        "edit-creds": ("credentials.known_test_values", "Test Credential Values", False),
        "edit-placeholders": ("credentials.placeholder_markers", "Placeholder Markers", False),
        "edit-safe-rm": ("system_cleanup.safe_rm_targets", "Safe rm Targets", False),
        "edit-inert-ext": ("file_classification.inert_extensions", "Inert Extensions", False),
        "edit-struct-ext": ("file_classification.structured_extensions", "Structured Extensions", False),
        "edit-archive-ext": ("file_classification.archive_extensions", "Archive Extensions", False),
        "edit-code-ext": ("file_classification.code_extensions", "Code Extensions", False),
        "edit-sensitive": ("sensitive_files.patterns", "Sensitive File Patterns (regex)", True),
        "edit-cmd-safe": ("command_safety.safe_commands", "Safe Commands", False),
        "edit-cmd-caution": ("command_safety.caution_commands", "Caution Commands", False),
        "edit-cmd-risky": ("command_safety.risky_commands", "Risky Commands", False),
        "edit-cmd-dangerous": ("command_safety.dangerous_commands", "Dangerous Commands", False),
        "edit-dangerous-arg-patterns": (
            "command_safety.dangerous_arg_patterns",
            "Dangerous Arg Patterns (regex)",
            True,
        ),
        "edit-disabled": ("disabled_rules", "Disabled Rules", False),
        "edit-overrides": ("severity_overrides", "Severity Overrides (rule_id:SEVERITY:reason)", True),
    }

    def _get_field(self, path: str) -> set[str] | list[str]:
        """Get a policy field value by dotted path."""
        parts = path.split(".")
        obj: Any = self.policy
        for part in parts:
            obj = getattr(obj, part)
        if path == "severity_overrides":
            return [f"{o.rule_id}:{o.severity}:{o.reason}" for o in obj]
        return cast(set[str] | list[str], obj)

    def _set_field(self, path: str, value: set[str] | list[str]) -> None:
        """Set a policy field value by dotted path."""
        if path == "severity_overrides":
            overrides = []
            for line in value:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    overrides.append(
                        SeverityOverride(
                            rule_id=parts[0].strip(),
                            severity=parts[1].strip(),
                            reason=parts[2].strip() if len(parts) > 2 else "",
                        )
                    )
            self.policy.severity_overrides = overrides
            return

        parts = path.split(".")
        obj = self.policy
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        if btn_id == "btn-save":
            self.action_save_policy()
            return
        if btn_id == "btn-quit":
            self.action_quit_app()
            return

        if btn_id in self._FIELD_MAP:
            attr_path, title, is_list = self._FIELD_MAP[btn_id]
            current = self._get_field(attr_path)
            self._pending_field = attr_path

            def on_result(result: set[str] | list[str] | None) -> None:
                if result is not None and self._pending_field:
                    self._set_field(self._pending_field, result)
                self._pending_field = None

            self.push_screen(
                SetEditorScreen(title, current, as_list=is_list),
                callback=on_result,
            )

    # ── Actions ───────────────────────────────────────────────────────────

    def action_quit_app(self) -> None:
        self.exit(None)

    def action_save_policy(self) -> None:
        self._sync_policy_from_form()
        path = self.output_path
        if Path(path).exists():
            # Overwrite silently in TUI (user chose Save)
            pass
        self.policy.to_yaml(path)
        self.exit(path)


# ─── Entry point (called by CLI) ─────────────────────────────────────────────


def run_policy_tui(
    output_path: str = "scan_policy.yaml",
    input_path: str | None = None,
) -> int:
    """Run the interactive policy configurator."""
    app = PolicyConfigApp(output_path=output_path, input_path=input_path)
    result = app.run()

    if result:
        from rich.console import Console

        console = Console()
        console.print(f"\n  [bold green]Saved policy to {result}[/bold green]")
        console.print(f"  Use it with: [cyan]skill-scanner scan --policy {result} /path/to/skill[/cyan]\n")
        return 0
    else:
        from rich.console import Console

        console = Console()
        console.print("\n  [dim]Quit without saving.[/dim]\n")
        return 0
