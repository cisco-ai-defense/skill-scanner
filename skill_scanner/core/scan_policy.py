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
Scan policy: org-customisable allowlists, severity overrides, and rule scoping.

Every organisation has a different security bar.  A ``ScanPolicy`` captures what
counts as benign, which rules fire on which file types, which installer URLs are
trusted, and so on.

Usage
-----
    from skill_scanner.core.scan_policy import ScanPolicy

    # Load built-in defaults
    policy = ScanPolicy.default()

    # Load an org policy (merges on top of defaults)
    policy = ScanPolicy.from_yaml("my_policy.yaml")

    # Dump the current (including default) policy for editing
    policy.to_yaml("generated_policy.yaml")

Analysers receive the policy at construction time and use it in place of their
previously-hardcoded sets/lists.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any  # used in _from_dict / _deep_merge signatures

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Where the built-in default policy lives (ships with the package)
# ---------------------------------------------------------------------------
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_POLICY_PATH = _DATA_DIR / "default_policy.yaml"

# Named preset policies
_PRESET_POLICIES: dict[str, Path] = {
    "strict": _DATA_DIR / "strict_policy.yaml",
    "balanced": _DEFAULT_POLICY_PATH,
    "permissive": _DATA_DIR / "permissive_policy.yaml",
}


# ---------------------------------------------------------------------------
# Data classes for each policy section
# ---------------------------------------------------------------------------


@dataclass
class HiddenFilePolicy:
    """Controls which dotfiles/dotdirs are treated as benign."""

    benign_dotfiles: set[str] = field(default_factory=set)
    benign_dotdirs: set[str] = field(default_factory=set)


@dataclass
class PipelinePolicy:
    """Controls pipeline taint analysis behaviour."""

    known_installer_domains: set[str] = field(default_factory=set)
    benign_pipe_targets: list[str] = field(default_factory=list)
    doc_path_indicators: set[str] = field(default_factory=set)
    # Demote pipeline findings found in documentation paths
    demote_in_docs: bool = True
    # Demote findings that look like instructional examples (e.g. SKILL.md)
    demote_instructional: bool = True
    # Check URLs against known_installer_domains and demote matches to LOW
    check_known_installers: bool = True
    # Collapse equivalent pipelines discovered via multiple extraction paths
    dedupe_equivalent_pipelines: bool = True
    # COMPOUND_FETCH_EXECUTE heuristics
    compound_fetch_require_download_intent: bool = True
    compound_fetch_filter_api_requests: bool = True
    compound_fetch_filter_shell_wrapped_fetch: bool = True
    # Wrapper commands allowed before execution sinks (e.g. sudo bash script.sh)
    compound_fetch_exec_prefixes: list[str] = field(
        default_factory=lambda: ["sudo", "env", "command", "time", "nohup", "nice"]
    )
    # Commands considered "execution sinks" for fetch+execute detection
    compound_fetch_exec_commands: list[str] = field(
        default_factory=lambda: ["bash", "sh", "zsh", "source", "python", "python3", "."]
    )
    # Hint words that suggest data exfiltration in tool-chaining detection
    exfil_hints: list[str] = field(
        default_factory=lambda: ["send", "upload", "transmit", "webhook", "slack", "exfil", "forward"]
    )
    # Tokens that indicate API/framework documentation (suppress tool-chaining FP)
    api_doc_tokens: list[str] = field(default_factory=lambda: ["@app.", "app.", "router.", "route", "endpoint"])


@dataclass
class RuleScopingPolicy:
    """Controls which rule sets fire on which file categories."""

    # Rule names → only fire on SKILL.md + scripts
    skillmd_and_scripts_only: set[str] = field(default_factory=set)
    # Rule names → skip when file is in a documentation path
    skip_in_docs: set[str] = field(default_factory=set)
    # Rule names → only fire on code files (.py, .sh, etc.)
    code_only: set[str] = field(default_factory=set)
    # Path components that mark a directory as "documentation"
    doc_path_indicators: set[str] = field(default_factory=set)
    # Regex patterns that match educational/example filenames
    doc_filename_patterns: list[str] = field(default_factory=list)
    # De-duplicate reference aliases that resolve to the same physical file
    dedupe_reference_aliases: bool = True
    # De-duplicate identical findings emitted by multiple static scan passes
    dedupe_duplicate_findings: bool = True
    # Skip ASSET_PROMPT_INJECTION findings for files in documentation paths
    asset_prompt_injection_skip_in_docs: bool = True


@dataclass
class CredentialPolicy:
    """Controls which well-known test credentials are auto-suppressed."""

    known_test_values: set[str] = field(default_factory=set)
    placeholder_markers: set[str] = field(default_factory=set)


@dataclass
class SystemCleanupPolicy:
    """Controls safe cleanup targets for destructive rm patterns."""

    safe_rm_targets: set[str] = field(default_factory=set)


@dataclass
class FileClassificationPolicy:
    """Controls how file extensions are classified for analysis routing."""

    # Extensions treated as inert (images, fonts, etc.) – no binary scan needed
    inert_extensions: set[str] = field(default_factory=set)
    # Extensions treated as structured data (SVG, PDF) – not flagged as unknown binary
    structured_extensions: set[str] = field(default_factory=set)
    # Extensions treated as archives – flagged at policy severity
    archive_extensions: set[str] = field(default_factory=set)
    # Extensions considered executable code (for hidden-file checks)
    code_extensions: set[str] = field(default_factory=set)
    # Skip binary/shebang checks on files with inert extensions
    skip_inert_extensions: bool = True
    # Treat shebang scripts (e.g. .js with #!/usr/bin/env node) as compatible
    # with text/code extensions for FILE_MAGIC_MISMATCH.
    allow_script_shebang_text_extensions: bool = True
    # Script-like extensions allowed to carry shebang headers.
    script_shebang_extensions: set[str] = field(default_factory=set)


@dataclass
class FileLimitsPolicy:
    """Numeric thresholds for file inventory checks."""

    # Maximum files before EXCESSIVE_FILE_COUNT fires
    max_file_count: int = 100
    # Maximum single file size in bytes before OVERSIZED_FILE fires
    max_file_size_bytes: int = 5_242_880  # 5 MB
    # Max recursion depth for reference resolution
    max_reference_depth: int = 5
    # Max skill name length
    max_name_length: int = 64
    # Max description length
    max_description_length: int = 1024
    # Min description length (below → SOCIAL_ENG_MISLEADING_DESC)
    min_description_length: int = 20


@dataclass
class AnalysisThresholdsPolicy:
    """Numeric thresholds for YARA and analyzability scoring."""

    # Unicode steganography – zero-width character thresholds
    zerowidth_threshold_with_decode: int = 50
    zerowidth_threshold_alone: int = 200
    # Analyzability risk-level thresholds (percentage)
    analyzability_low_risk: int = 90  # score >= this → LOW risk
    analyzability_medium_risk: int = 70  # score >= this → MEDIUM risk
    # Minimum lines containing confusable chars to fire HOMOGLYPH_ATTACK
    min_dangerous_lines: int = 5
    # Minimum confidence % for FILE_MAGIC_MISMATCH detection
    min_confidence_pct: int = 80
    # Lines of context around exception handlers for RESOURCE_ABUSE_INFINITE_LOOP
    exception_handler_context_lines: int = 20
    # Max matched chars to still count as "short match" in unicode steganography
    short_match_max_chars: int = 2
    # Minimum Cyrillic/CJK chars to suppress false-positive unicode steganography
    cyrillic_cjk_min_chars: int = 10
    # HOMOGLYPH_ATTACK: suppress scientific/mathematical unicode contexts
    homoglyph_filter_math_context: bool = True
    # Confusable aliases considered low-risk in formula/math context.
    homoglyph_math_aliases: list[str] = field(default_factory=lambda: ["COMMON", "GREEK"])


@dataclass
class SensitiveFilesPolicy:
    """Regex patterns for sensitive file paths in pipeline taint analysis."""

    # Patterns that upgrade taint to SENSITIVE_DATA when seen in command arguments
    patterns: list[str] = field(default_factory=list)


@dataclass
class CommandSafetyPolicy:
    """Controls which commands are in each safety tier.

    The tiers mirror ``command_safety.CommandRisk``:
    - safe:      read-only / informational, no side effects
    - caution:   generally safe but context-dependent
    - risky:     can modify system or exfiltrate data
    - dangerous: direct code execution, network exfiltration

    ``dangerous_arg_patterns`` is a list of regex strings that, when matched
    against a full command line, immediately classify it as DANGEROUS.  These
    are checked **in addition to** the built-in patterns in
    ``command_safety._DANGEROUS_ARG_PATTERNS``.
    """

    safe_commands: set[str] = field(default_factory=set)
    caution_commands: set[str] = field(default_factory=set)
    risky_commands: set[str] = field(default_factory=set)
    dangerous_commands: set[str] = field(default_factory=set)
    dangerous_arg_patterns: list[str] = field(default_factory=list)


@dataclass
class AnalyzersPolicy:
    """Controls which analyzer passes are enabled."""

    static: bool = True
    bytecode: bool = True
    pipeline: bool = True


@dataclass
class LLMAnalysisPolicy:
    """Controls LLM context budget thresholds for LLM and meta analyzers.

    Both the LLM analyzer and the meta analyzer read from this single policy
    section.  The meta analyzer multiplies the base limits by
    ``meta_budget_multiplier`` so it always has more headroom for
    cross-correlation.

    Content that fits within budget is sent in full — **no truncation**.
    Content that exceeds the budget is skipped entirely and an
    ``LLM_CONTEXT_BUDGET_EXCEEDED`` INFO finding is emitted with guidance
    on which policy knob to increase.
    """

    # -- Per-item limits (LLM analyzer uses these directly) --
    max_instruction_body_chars: int = 20_000
    max_code_file_chars: int = 15_000
    max_referenced_file_chars: int = 10_000
    max_total_prompt_chars: int = 100_000

    # -- Meta analyzer multiplier --
    # Meta analyzer multiplies the above limits by this factor.
    # e.g. 3× means meta gets 60 K instruction, 45 K/file, 300 K total.
    meta_budget_multiplier: float = 3.0

    # -- Convenience helpers for the meta analyzer --

    @property
    def meta_max_instruction_body_chars(self) -> int:
        return int(self.max_instruction_body_chars * self.meta_budget_multiplier)

    @property
    def meta_max_code_file_chars(self) -> int:
        return int(self.max_code_file_chars * self.meta_budget_multiplier)

    @property
    def meta_max_referenced_file_chars(self) -> int:
        return int(self.max_referenced_file_chars * self.meta_budget_multiplier)

    @property
    def meta_max_total_prompt_chars(self) -> int:
        return int(self.max_total_prompt_chars * self.meta_budget_multiplier)


@dataclass
class FindingOutputPolicy:
    """Controls final finding normalization and traceability metadata."""

    # Drop exact duplicates emitted by overlapping analyzers/passes
    dedupe_exact_findings: bool = True
    # Collapse same issue repeated on the same file/line/snippet/category
    dedupe_same_issue_per_location: bool = True
    # Preferred analyzer order when collapsing same-issue duplicates.
    # Earlier entries win (for richer remediation/context), while max severity
    # from the merged set is still preserved.
    same_issue_preferred_analyzers: list[str] = field(
        default_factory=lambda: [
            "meta_analyzer",
            "llm_analyzer",
            "meta",
            "llm",
            "behavioral",
            "pipeline",
            "static",
            "yara",
            "analyzability",
        ]
    )
    # Also collapse same-issue findings emitted by one analyzer
    # (usually disabled to preserve distinct static rule signals).
    same_issue_collapse_within_analyzer: bool = True
    # Attach per-finding context about other rules that fired on same file path
    annotate_same_path_rule_cooccurrence: bool = True
    # Add policy metadata fingerprint to each finding for auditability
    attach_policy_fingerprint: bool = True


@dataclass
class SeverityOverride:
    """A per-rule severity override."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    reason: str = ""


# ---------------------------------------------------------------------------
# The top-level policy object
# ---------------------------------------------------------------------------


@dataclass
class ScanPolicy:
    """Organisational scan policy – everything that should be customisable."""

    # Metadata
    policy_name: str = "default"
    policy_version: str = "1.0"
    # The preset this policy was derived from ("strict", "balanced",
    # "permissive").  Separate from ``policy_name`` so that renaming the
    # policy (e.g. "acme-corp") does not silently change YARA mode behaviour.
    preset_base: str = "balanced"

    # Sections
    hidden_files: HiddenFilePolicy = field(default_factory=HiddenFilePolicy)
    pipeline: PipelinePolicy = field(default_factory=PipelinePolicy)
    rule_scoping: RuleScopingPolicy = field(default_factory=RuleScopingPolicy)
    credentials: CredentialPolicy = field(default_factory=CredentialPolicy)
    system_cleanup: SystemCleanupPolicy = field(default_factory=SystemCleanupPolicy)
    file_classification: FileClassificationPolicy = field(default_factory=FileClassificationPolicy)
    file_limits: FileLimitsPolicy = field(default_factory=FileLimitsPolicy)
    analysis_thresholds: AnalysisThresholdsPolicy = field(default_factory=AnalysisThresholdsPolicy)
    sensitive_files: SensitiveFilesPolicy = field(default_factory=SensitiveFilesPolicy)
    command_safety: CommandSafetyPolicy = field(default_factory=CommandSafetyPolicy)
    analyzers: AnalyzersPolicy = field(default_factory=AnalyzersPolicy)
    llm_analysis: LLMAnalysisPolicy = field(default_factory=LLMAnalysisPolicy)
    finding_output: FindingOutputPolicy = field(default_factory=FindingOutputPolicy)
    severity_overrides: list[SeverityOverride] = field(default_factory=list)
    disabled_rules: set[str] = field(default_factory=set)

    # -----------------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------------

    def get_severity_override(self, rule_id: str) -> str | None:
        """Return the overridden severity for *rule_id*, or ``None``."""
        for ovr in self.severity_overrides:
            if ovr.rule_id == rule_id:
                return ovr.severity
        return None

    @property
    def _compiled_doc_filename_re(self) -> re.Pattern | None:
        """Lazy-compiled regex from ``rule_scoping.doc_filename_patterns``."""
        if not hasattr(self, "_doc_fn_re_cache"):
            patterns = self.rule_scoping.doc_filename_patterns
            if patterns:
                combined = "|".join(f"(?:{p})" for p in patterns)
                object.__setattr__(self, "_doc_fn_re_cache", re.compile(combined, re.IGNORECASE))
            else:
                object.__setattr__(self, "_doc_fn_re_cache", None)
        return self._doc_fn_re_cache  # type: ignore[attr-defined, no-any-return]

    @property
    def _compiled_benign_pipes(self) -> list[re.Pattern]:
        """Lazy-compiled regexes from ``pipeline.benign_pipe_targets``."""
        if not hasattr(self, "_benign_pipe_cache"):
            compiled = [re.compile(p) for p in self.pipeline.benign_pipe_targets]
            object.__setattr__(self, "_benign_pipe_cache", compiled)
        return self._benign_pipe_cache  # type: ignore[attr-defined, no-any-return]

    # -----------------------------------------------------------------------
    # Construction helpers
    # -----------------------------------------------------------------------

    @classmethod
    def default(cls) -> ScanPolicy:
        """Load the built-in default policy that ships with the package."""
        return cls.from_yaml(_DEFAULT_POLICY_PATH)

    @classmethod
    def from_preset(cls, name: str) -> ScanPolicy:
        """Load a named preset policy: ``strict``, ``balanced``, or ``permissive``."""
        name_lower = name.lower()
        if name_lower not in _PRESET_POLICIES:
            raise ValueError(f"Unknown preset '{name}'. Available: {', '.join(sorted(_PRESET_POLICIES))}")
        return cls.from_yaml(_PRESET_POLICIES[name_lower])

    @classmethod
    def preset_names(cls) -> list[str]:
        """Return available preset policy names."""
        return sorted(_PRESET_POLICIES.keys())

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanPolicy:
        """
        Load a policy from a YAML file.

        The YAML is first merged on top of the built-in defaults so that
        users only need to specify the sections they want to override.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path) as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}

        # If this IS the default file, just parse directly
        is_default = path.resolve() == _DEFAULT_POLICY_PATH.resolve()
        if is_default:
            policy = cls._from_dict(raw)
        else:
            # Otherwise, load defaults first, then overlay the user's file
            default_raw = cls._load_default_raw()
            merged = cls._deep_merge(default_raw, raw)
            policy = cls._from_dict(merged)

        return policy

    def to_yaml(self, path: str | Path) -> None:
        """Dump the full policy to a YAML file for editing."""
        data = self._to_dict()
        with open(path, "w") as fh:
            fh.write("# Skill Scanner – Scan Policy\n")
            fh.write("# Customise this file to match your organisation's security bar.\n")
            fh.write("# Only include sections you want to override; omitted sections\n")
            fh.write("# will use the built-in defaults.\n\n")
            yaml.dump(data, fh, default_flow_style=False, sort_keys=False, width=120)

    # -----------------------------------------------------------------------
    # Internal parsing
    # -----------------------------------------------------------------------

    @classmethod
    def _load_default_raw(cls) -> dict[str, Any]:
        if _DEFAULT_POLICY_PATH.exists():
            with open(_DEFAULT_POLICY_PATH) as fh:
                return yaml.safe_load(fh) or {}
        return {}

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Recursively merge *override* into *base*.

        For lists and sets (represented as lists in YAML) the override
        **replaces** the base – this is intentional so that an org can
        narrow or expand a list without having to repeat every entry.
        """
        result = dict(base)
        for key, val in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(val, dict):
                result[key] = ScanPolicy._deep_merge(result[key], val)
            else:
                result[key] = val
        return result

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> ScanPolicy:
        hf = d.get("hidden_files", {})
        pl = d.get("pipeline", {})
        ys = d.get("rule_scoping", {})
        cr = d.get("credentials", {})
        sc = d.get("system_cleanup", {})
        fc = d.get("file_classification", {})
        fl = d.get("file_limits", {})
        at = d.get("analysis_thresholds", {})
        sf = d.get("sensitive_files", {})
        cs = d.get("command_safety", {})
        az = d.get("analyzers", {})
        la = d.get("llm_analysis", {})
        fo = d.get("finding_output", {})

        severity_overrides = [SeverityOverride(**ovr) for ovr in d.get("severity_overrides", [])]

        return cls(
            policy_name=d.get("policy_name", "default"),
            policy_version=d.get("policy_version", "1.0"),
            preset_base=d.get("preset_base", "balanced"),
            hidden_files=HiddenFilePolicy(
                benign_dotfiles=set(hf.get("benign_dotfiles", [])),
                benign_dotdirs=set(hf.get("benign_dotdirs", [])),
            ),
            pipeline=PipelinePolicy(
                known_installer_domains=set(pl.get("known_installer_domains", [])),
                benign_pipe_targets=pl.get("benign_pipe_targets", []),
                doc_path_indicators=set(pl.get("doc_path_indicators", [])),
                demote_in_docs=pl.get("demote_in_docs", True),
                demote_instructional=pl.get("demote_instructional", True),
                check_known_installers=pl.get("check_known_installers", True),
                dedupe_equivalent_pipelines=pl.get("dedupe_equivalent_pipelines", True),
                compound_fetch_require_download_intent=pl.get("compound_fetch_require_download_intent", True),
                compound_fetch_filter_api_requests=pl.get("compound_fetch_filter_api_requests", True),
                compound_fetch_filter_shell_wrapped_fetch=pl.get("compound_fetch_filter_shell_wrapped_fetch", True),
                compound_fetch_exec_prefixes=pl.get(
                    "compound_fetch_exec_prefixes", ["sudo", "env", "command", "time", "nohup", "nice"]
                ),
                compound_fetch_exec_commands=pl.get(
                    "compound_fetch_exec_commands", ["bash", "sh", "zsh", "source", "python", "python3", "."]
                ),
                exfil_hints=pl.get(
                    "exfil_hints", ["send", "upload", "transmit", "webhook", "slack", "exfil", "forward"]
                ),
                api_doc_tokens=pl.get("api_doc_tokens", ["@app.", "app.", "router.", "route", "endpoint"]),
            ),
            rule_scoping=RuleScopingPolicy(
                skillmd_and_scripts_only=set(ys.get("skillmd_and_scripts_only", [])),
                skip_in_docs=set(ys.get("skip_in_docs", [])),
                code_only=set(ys.get("code_only", [])),
                doc_path_indicators=set(ys.get("doc_path_indicators", [])),
                doc_filename_patterns=ys.get("doc_filename_patterns", []),
                dedupe_reference_aliases=ys.get("dedupe_reference_aliases", True),
                dedupe_duplicate_findings=ys.get("dedupe_duplicate_findings", True),
                asset_prompt_injection_skip_in_docs=ys.get("asset_prompt_injection_skip_in_docs", True),
            ),
            credentials=CredentialPolicy(
                known_test_values=set(cr.get("known_test_values", [])),
                placeholder_markers=set(cr.get("placeholder_markers", [])),
            ),
            system_cleanup=SystemCleanupPolicy(
                safe_rm_targets=set(sc.get("safe_rm_targets", [])),
            ),
            file_classification=FileClassificationPolicy(
                inert_extensions=set(fc.get("inert_extensions", [])),
                structured_extensions=set(fc.get("structured_extensions", [])),
                archive_extensions=set(fc.get("archive_extensions", [])),
                code_extensions=set(fc.get("code_extensions", [])),
                skip_inert_extensions=fc.get("skip_inert_extensions", True),
                allow_script_shebang_text_extensions=fc.get("allow_script_shebang_text_extensions", True),
                script_shebang_extensions=set(fc.get("script_shebang_extensions", [])),
            ),
            file_limits=FileLimitsPolicy(
                max_file_count=fl.get("max_file_count", 100),
                max_file_size_bytes=fl.get("max_file_size_bytes", 5_242_880),
                max_reference_depth=fl.get("max_reference_depth", 5),
                max_name_length=fl.get("max_name_length", 64),
                max_description_length=fl.get("max_description_length", 1024),
                min_description_length=fl.get("min_description_length", 20),
            ),
            analysis_thresholds=AnalysisThresholdsPolicy(
                zerowidth_threshold_with_decode=at.get("zerowidth_threshold_with_decode", 50),
                zerowidth_threshold_alone=at.get("zerowidth_threshold_alone", 200),
                analyzability_low_risk=at.get("analyzability_low_risk", 90),
                analyzability_medium_risk=at.get("analyzability_medium_risk", 70),
                min_dangerous_lines=at.get("min_dangerous_lines", 5),
                min_confidence_pct=at.get("min_confidence_pct", 80),
                exception_handler_context_lines=at.get("exception_handler_context_lines", 20),
                short_match_max_chars=at.get("short_match_max_chars", 2),
                cyrillic_cjk_min_chars=at.get("cyrillic_cjk_min_chars", 10),
                homoglyph_filter_math_context=at.get("homoglyph_filter_math_context", True),
                homoglyph_math_aliases=at.get("homoglyph_math_aliases", ["COMMON", "GREEK"]),
            ),
            sensitive_files=SensitiveFilesPolicy(
                patterns=sf.get("patterns", []),
            ),
            command_safety=CommandSafetyPolicy(
                safe_commands=set(cs.get("safe_commands", [])),
                caution_commands=set(cs.get("caution_commands", [])),
                risky_commands=set(cs.get("risky_commands", [])),
                dangerous_commands=set(cs.get("dangerous_commands", [])),
                dangerous_arg_patterns=list(cs.get("dangerous_arg_patterns", [])),
            ),
            analyzers=AnalyzersPolicy(
                static=az.get("static", True),
                bytecode=az.get("bytecode", True),
                pipeline=az.get("pipeline", True),
            ),
            llm_analysis=LLMAnalysisPolicy(
                max_instruction_body_chars=la.get("max_instruction_body_chars", 20_000),
                max_code_file_chars=la.get("max_code_file_chars", 15_000),
                max_referenced_file_chars=la.get("max_referenced_file_chars", 10_000),
                max_total_prompt_chars=la.get("max_total_prompt_chars", 100_000),
                meta_budget_multiplier=la.get("meta_budget_multiplier", 3.0),
            ),
            finding_output=FindingOutputPolicy(
                dedupe_exact_findings=fo.get("dedupe_exact_findings", True),
                dedupe_same_issue_per_location=fo.get("dedupe_same_issue_per_location", True),
                same_issue_preferred_analyzers=fo.get(
                    "same_issue_preferred_analyzers",
                    [
                        "meta_analyzer",
                        "llm_analyzer",
                        "meta",
                        "llm",
                        "behavioral",
                        "pipeline",
                        "static",
                        "yara",
                        "analyzability",
                    ],
                ),
                same_issue_collapse_within_analyzer=fo.get("same_issue_collapse_within_analyzer", True),
                annotate_same_path_rule_cooccurrence=fo.get("annotate_same_path_rule_cooccurrence", True),
                attach_policy_fingerprint=fo.get("attach_policy_fingerprint", True),
            ),
            severity_overrides=severity_overrides,
            disabled_rules=set(d.get("disabled_rules", [])),
        )

    def _to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "preset_base": self.preset_base,
            "hidden_files": {
                "benign_dotfiles": sorted(self.hidden_files.benign_dotfiles),
                "benign_dotdirs": sorted(self.hidden_files.benign_dotdirs),
            },
            "pipeline": {
                "known_installer_domains": sorted(self.pipeline.known_installer_domains),
                "benign_pipe_targets": self.pipeline.benign_pipe_targets,
                "doc_path_indicators": sorted(self.pipeline.doc_path_indicators),
                "demote_in_docs": self.pipeline.demote_in_docs,
                "demote_instructional": self.pipeline.demote_instructional,
                "check_known_installers": self.pipeline.check_known_installers,
                "dedupe_equivalent_pipelines": self.pipeline.dedupe_equivalent_pipelines,
                "compound_fetch_require_download_intent": self.pipeline.compound_fetch_require_download_intent,
                "compound_fetch_filter_api_requests": self.pipeline.compound_fetch_filter_api_requests,
                "compound_fetch_filter_shell_wrapped_fetch": self.pipeline.compound_fetch_filter_shell_wrapped_fetch,
                "compound_fetch_exec_prefixes": self.pipeline.compound_fetch_exec_prefixes,
                "compound_fetch_exec_commands": self.pipeline.compound_fetch_exec_commands,
                "exfil_hints": self.pipeline.exfil_hints,
                "api_doc_tokens": self.pipeline.api_doc_tokens,
            },
            "rule_scoping": {
                "skillmd_and_scripts_only": sorted(self.rule_scoping.skillmd_and_scripts_only),
                "skip_in_docs": sorted(self.rule_scoping.skip_in_docs),
                "code_only": sorted(self.rule_scoping.code_only),
                "doc_path_indicators": sorted(self.rule_scoping.doc_path_indicators),
                "doc_filename_patterns": self.rule_scoping.doc_filename_patterns,
                "dedupe_reference_aliases": self.rule_scoping.dedupe_reference_aliases,
                "dedupe_duplicate_findings": self.rule_scoping.dedupe_duplicate_findings,
                "asset_prompt_injection_skip_in_docs": self.rule_scoping.asset_prompt_injection_skip_in_docs,
            },
            "credentials": {
                "known_test_values": sorted(self.credentials.known_test_values),
                "placeholder_markers": sorted(self.credentials.placeholder_markers),
            },
            "system_cleanup": {
                "safe_rm_targets": sorted(self.system_cleanup.safe_rm_targets),
            },
            "file_classification": {
                "inert_extensions": sorted(self.file_classification.inert_extensions),
                "structured_extensions": sorted(self.file_classification.structured_extensions),
                "archive_extensions": sorted(self.file_classification.archive_extensions),
                "code_extensions": sorted(self.file_classification.code_extensions),
                "skip_inert_extensions": self.file_classification.skip_inert_extensions,
                "allow_script_shebang_text_extensions": self.file_classification.allow_script_shebang_text_extensions,
                "script_shebang_extensions": sorted(self.file_classification.script_shebang_extensions),
            },
            "file_limits": {
                "max_file_count": self.file_limits.max_file_count,
                "max_file_size_bytes": self.file_limits.max_file_size_bytes,
                "max_reference_depth": self.file_limits.max_reference_depth,
                "max_name_length": self.file_limits.max_name_length,
                "max_description_length": self.file_limits.max_description_length,
                "min_description_length": self.file_limits.min_description_length,
            },
            "analysis_thresholds": {
                "zerowidth_threshold_with_decode": self.analysis_thresholds.zerowidth_threshold_with_decode,
                "zerowidth_threshold_alone": self.analysis_thresholds.zerowidth_threshold_alone,
                "analyzability_low_risk": self.analysis_thresholds.analyzability_low_risk,
                "analyzability_medium_risk": self.analysis_thresholds.analyzability_medium_risk,
                "min_dangerous_lines": self.analysis_thresholds.min_dangerous_lines,
                "min_confidence_pct": self.analysis_thresholds.min_confidence_pct,
                "exception_handler_context_lines": self.analysis_thresholds.exception_handler_context_lines,
                "short_match_max_chars": self.analysis_thresholds.short_match_max_chars,
                "cyrillic_cjk_min_chars": self.analysis_thresholds.cyrillic_cjk_min_chars,
                "homoglyph_filter_math_context": self.analysis_thresholds.homoglyph_filter_math_context,
                "homoglyph_math_aliases": self.analysis_thresholds.homoglyph_math_aliases,
            },
            "sensitive_files": {
                "patterns": self.sensitive_files.patterns,
            },
            "command_safety": {
                "safe_commands": sorted(self.command_safety.safe_commands),
                "caution_commands": sorted(self.command_safety.caution_commands),
                "risky_commands": sorted(self.command_safety.risky_commands),
                "dangerous_commands": sorted(self.command_safety.dangerous_commands),
                "dangerous_arg_patterns": self.command_safety.dangerous_arg_patterns,
            },
            "analyzers": {
                "static": self.analyzers.static,
                "bytecode": self.analyzers.bytecode,
                "pipeline": self.analyzers.pipeline,
            },
            "llm_analysis": {
                "max_instruction_body_chars": self.llm_analysis.max_instruction_body_chars,
                "max_code_file_chars": self.llm_analysis.max_code_file_chars,
                "max_referenced_file_chars": self.llm_analysis.max_referenced_file_chars,
                "max_total_prompt_chars": self.llm_analysis.max_total_prompt_chars,
                "meta_budget_multiplier": self.llm_analysis.meta_budget_multiplier,
            },
            "finding_output": {
                "dedupe_exact_findings": self.finding_output.dedupe_exact_findings,
                "dedupe_same_issue_per_location": self.finding_output.dedupe_same_issue_per_location,
                "same_issue_preferred_analyzers": self.finding_output.same_issue_preferred_analyzers,
                "same_issue_collapse_within_analyzer": self.finding_output.same_issue_collapse_within_analyzer,
                "annotate_same_path_rule_cooccurrence": self.finding_output.annotate_same_path_rule_cooccurrence,
                "attach_policy_fingerprint": self.finding_output.attach_policy_fingerprint,
            },
            "severity_overrides": [
                {"rule_id": o.rule_id, "severity": o.severity, "reason": o.reason} for o in self.severity_overrides
            ],
            "disabled_rules": sorted(self.disabled_rules),
        }
