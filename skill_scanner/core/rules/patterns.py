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
Pattern matching utilities for security rules.
"""

import logging
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

import yaml

from ...core.models import Severity, ThreatCategory

logger = logging.getLogger(__name__)

CategoryResolution = Literal["native", "legacy_mapped", "unknown_fallback"]

# Reviewed compatibility map for the two bundled legacy taxonomies.  This is
# intentionally not consulted in strict mode: schema-v2 packs must use the
# canonical ThreatCategory enum and fail startup on every unknown value.
LEGACY_SIGNATURE_CATEGORY_MAP = MappingProxyType(
    {
        # ATR categories
        "agent_manipulation": ThreatCategory.SOCIAL_ENGINEERING,
        "context_exfiltration": ThreatCategory.DATA_EXFILTRATION,
        "data_poisoning": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
        "excessive_autonomy": ThreatCategory.AUTONOMY_ABUSE,
        "model_abuse": ThreatCategory.HARMFUL_CONTENT,
        "model_security": ThreatCategory.POLICY_VIOLATION,
        "privilege_escalation": ThreatCategory.UNAUTHORIZED_TOOL_USE,
        "skill_compromise": ThreatCategory.SUPPLY_CHAIN_ATTACK,
        "tool_poisoning": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
        # PromptGuard category
        "pii_exposure": ThreatCategory.DATA_EXFILTRATION,
    }
)


@dataclass(frozen=True)
class CategoryNormalizationMetrics:
    """Per-generation accounting for signature category normalization."""

    native_rules: int = 0
    legacy_mapped_rules: int = 0
    unknown_fallback_rules: int = 0
    mapped_source_categories: tuple[tuple[str, int], ...] = ()
    unknown_source_categories: tuple[tuple[str, int], ...] = ()

    @property
    def total_rules(self) -> int:
        return self.native_rules + self.legacy_mapped_rules + self.unknown_fallback_rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "native_rules": self.native_rules,
            "legacy_mapped_rules": self.legacy_mapped_rules,
            "unknown_fallback_rules": self.unknown_fallback_rules,
            "mapped_source_categories": dict(self.mapped_source_categories),
            "unknown_source_categories": dict(self.unknown_source_categories),
            "total_rules": self.total_rules,
        }


SIGNATURE_CONTEXT_KINDS = frozenset(
    {
        "active_instruction",
        "code",
        "documentation",
        "example",
        "instruction",
        "negative_example",
        "package",
        "prohibition",
        "unknown",
    }
)
SIGNATURE_POLARITIES = frozenset({"active", "illustrative", "negative", "unknown"})

# Matches a regex character class like [^\n] or [a-z0-9].
# Used to strip character-class contents before checking whether a pattern
# contains \n for genuine multiline spanning (vs single-line [^\n] anchoring).
_CHAR_CLASS_RE = re.compile(r"\[[^\]]*\]")

_CODE_SUFFIXES = frozenset({".bash", ".js", ".py", ".sh", ".ts", ".zsh"})
_EXAMPLE_PATH_PARTS = frozenset(
    {
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "reference",
        "references",
        "test",
        "tests",
    }
)
_EXAMPLE_FILENAMES = frozenset(
    {
        "changelog.md",
        "contributing.md",
        "readme.md",
        "security.md",
    }
)
_INSTRUCTION_PATH_PARTS = frozenset({"agent", "agents", "command", "commands", "instruction", "instructions"})
# CommonMark fenced code blocks may be indented by at most three spaces.  The
# marker run is captured separately so the structural walker can require a
# matching delimiter and a closing run at least as long as the opener.
_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+")
_NEGATIVE_EXAMPLE_RE = re.compile(
    r"\b(?:bad|dangerous|insecure|negative|unsafe|vulnerable)\s+(?:code\s+)?examples?\b"
    r"|\b(?:anti[- ]?pattern|incorrect example|what not to do)\b",
    re.IGNORECASE,
)
_SCOPED_PROHIBITION_PREFIX_RE = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't|avoid|forbidden|prohibited)"
    r"\s+(?:(?:ever\s+)?(?:use|call|invoke|run|execute|permit|allow)(?:ing)?\s+)?$",
    re.IGNORECASE,
)
_SCOPED_NO_PREFIX_RE = re.compile(
    r"(?:^|\s)(?:(?:[-*+>]\s+)|(?://|#)\s*)*no\s+"
    r"(?:calls?\s+to\s+|execut(?:e|ing|ion)\s+|invok(?:e|ing)\s+|use\s+(?:of\s+)?)?$",
    re.IGNORECASE,
)
_CLAUSE_BOUNDARY_RE = re.compile(
    r"[;.!?]|\b(?:but|except|however|instead|then|unless)\b",
    re.IGNORECASE,
)
_UNSAFE_TRAILING_CLAUSE_RE = re.compile(
    r"(?<!\\)[;?]|&&|\|\||\b(?:but|except|however|instead|then|unless)\b",
    re.IGNORECASE,
)
# A slash is ambiguous list punctuation only when separated as punctuation.
# Treating every slash as coordination makes ordinary absolute and relative
# paths (for example ``find /tmp``) impossible to classify as prohibitions.
_LIST_COORDINATION_RE = re.compile(r",|\s+/\s+|\b(?:and|or)\b", re.IGNORECASE)

# A deliberately narrow grammar for a complete, coordinated prohibition.
# Broad command-execution patterns can match both members of a benign
# instruction such as ``No eval() or exec()``.  Merely seeing a negation before
# the first match is not enough: every remaining clause must be another known
# execution primitive joined only by a list separator.  Anything mixed,
# contrastive, exceptionally long, or otherwise ambiguous remains active.
_NEGATIVE_EXECUTION_PRIMITIVE_NAME = r"""
    (?:
        eval|exec|execute|run_command|shell|bash|cmd|powershell|system_call|os_exec|
        subprocess(?:\.(?:run|call|Popen))?|child_process(?:\.exec)?|
        spawn|execFile|system|popen|os\.(?:system|popen|exec)|
        new\s+Function|vm\.(?:runIn\w*|createContext|compileFunction)
    )
"""
_NEGATIVE_EXECUTION_PRIMITIVE = rf"""
    (?:
        `\s*{_NEGATIVE_EXECUTION_PRIMITIVE_NAME}\s*\(\s*\)\s*`|
        {_NEGATIVE_EXECUTION_PRIMITIVE_NAME}\s*\(\s*\)
    )
"""
_PURE_NEGATIVE_EXECUTION_LIST_RE = re.compile(
    rf"""
    ^\s*(?:(?:[-*+>]\s+)|(?://|\#)\s*)*
    (?:
        no\s+(?:(?:calls?\s+to|execution\s+of|invocation\s+of|use\s+of)\s+)?|
        (?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't|avoid|forbid(?:den)?)
        \s+(?:(?:ever\s+)?(?:use|call|invoke|run|execute)(?:ing)?\s+)?
    )
    {_NEGATIVE_EXECUTION_PRIMITIVE}
    (?:
        \s*(?:,\s*(?:or\s+)?|\s+or\s+)\s*
        {_NEGATIVE_EXECUTION_PRIMITIVE}
    )+
    [.!]?\s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _is_pure_negative_execution_list(line: str) -> bool:
    """Return true only for a bounded, complete list of prohibited primitives."""

    # Avoid spending regex time on attacker-controlled pathological lines. A
    # long or compound instruction is ambiguous and must fail open anyway.
    return len(line) <= 512 and bool(_PURE_NEGATIVE_EXECUTION_LIST_RE.fullmatch(line))


def _is_example_path(file_path: str | None) -> bool:
    if not file_path:
        return False
    path = Path(file_path.replace("\\", "/"))
    lowered_parts = {part.lower() for part in path.parts}
    return bool(lowered_parts & _EXAMPLE_PATH_PARTS) or path.name.lower() in _EXAMPLE_FILENAMES


def _classify_signature_context(
    line: str,
    file_path: str | None,
    *,
    in_fence: bool,
    negative_example_section: bool,
    match_start: int,
    match_end: int,
    additional_active_match: bool,
) -> tuple[str, str]:
    """Return bounded execution-context and polarity classifications.

    The return values are deliberately small enums. The matching line remains
    ordinary finding evidence and is never copied into the CEL fact model.
    Unknown or ambiguous cases remain active (fail-open) at the CEL gate.
    """

    prefix = line[:match_start]
    local_prefix = _CLAUSE_BOUNDARY_RE.split(prefix)[-1]
    scoped_prohibition = bool(
        _SCOPED_PROHIBITION_PREFIX_RE.search(local_prefix) or _SCOPED_NO_PREFIX_RE.search(local_prefix)
    )
    # Inspect from the beginning of the match, not merely after it. Some broad
    # extractors greedily absorb a semicolon or contrastive clause into the
    # match itself (for example ``eval(); exec(x)``). Such content must remain
    # active even when the matched span is preceded by a scoped negation.
    trailing_clause = bool(_UNSAFE_TRAILING_CLAUSE_RE.search(line[match_start:]))
    coordinated_clause = bool(_LIST_COORDINATION_RE.search(line[match_start:]))
    explicit_negative_example = bool(_NEGATIVE_EXAMPLE_RE.search(prefix))
    safe_negative = not trailing_clause and not coordinated_clause and not additional_active_match

    if not in_fence and _is_pure_negative_execution_list(line):
        return "prohibition", "negative"
    if safe_negative and (explicit_negative_example or (negative_example_section and in_fence)):
        return "negative_example", "negative"
    if scoped_prohibition and safe_negative:
        return "prohibition", "negative"

    path = Path((file_path or "").replace("\\", "/"))
    if _is_example_path(file_path):
        return "example", "illustrative"
    if in_fence:
        return "code", "active"
    if path.name.lower() == "skill.md":
        return "active_instruction", "active"
    if path.suffix.lower() in _CODE_SUFFIXES:
        return "code", "active"
    # Signature rules scan the whole package, including auxiliary Markdown and
    # configuration files.  A valid package path is a structured file-role
    # fact, not an unknown execution context.  Keep operational agent/command
    # documents distinct from documentation; all remaining package files use
    # the neutral ``package`` role.  The CEL projector consumes this bounded
    # classification directly and never reparses the matched snippet.
    lowered_parts = {part.lower() for part in path.parts}
    if path.suffix.lower() == ".md" and lowered_parts & _INSTRUCTION_PATH_PARTS:
        return "instruction", "active"
    if file_path:
        return "package", "active"
    return "unknown", "unknown"


def _build_signature_line_contexts(lines: Sequence[str]) -> tuple[tuple[bool, bool], ...]:
    """Return structural flags for already-split content lines."""
    contexts: list[tuple[bool, bool]] = []
    fence_marker: str | None = None
    fence_length = 0
    negative_example_section = False
    for line in lines:
        fence_match = _FENCE_RE.match(line)

        if fence_marker is not None:
            # Everything through a valid closing delimiter belongs to the
            # fenced block. In particular, heading-looking source comments
            # must not mutate the surrounding Markdown section state.
            contexts.append((True, negative_example_section))
            if fence_match is not None:
                marker = fence_match.group("marker")
                tail = fence_match.group("tail")
                if marker[0] == fence_marker and len(marker) >= fence_length and not tail.strip(" \t\r"):
                    fence_marker = None
                    fence_length = 0
            continue

        if _HEADING_RE.match(line):
            negative_example_section = bool(_NEGATIVE_EXAMPLE_RE.search(line))

        if fence_match is not None:
            marker = fence_match.group("marker")
            tail = fence_match.group("tail")
            # CommonMark forbids backticks in a backtick fence's info string.
            # Treat malformed/ambiguous candidates as ordinary active text
            # rather than expanding the negative-example suppression region.
            if marker[0] != "`" or "`" not in tail:
                contexts.append((True, negative_example_section))
                fence_marker = marker[0]
                fence_length = len(marker)
                continue

        contexts.append((False, negative_example_section))
    return tuple(contexts)


def _signature_line_contexts(content: str) -> list[tuple[bool, bool]]:
    """Return structural context flags without retaining source text."""

    return list(_build_signature_line_contexts(content.split("\n")))


@dataclass(frozen=True, slots=True, eq=False)
class SignatureScanContext:
    """Transient, per-content state shared across signature rules.

    Previously, splitting a large file and walking all Markdown headings and
    fences repeated once per matching rule. The static analyzer creates one
    context for each content scan and passes it to every rule. Structural flags
    stay lazy, so files with no candidates pay only for one shared line split
    and never run the Markdown context walk.
    """

    content: str = field(repr=False)
    lines: tuple[str, ...] = field(init=False, repr=False)
    _line_contexts: tuple[tuple[bool, bool], ...] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "lines", tuple(self.content.split("\n")))

    def line_context(self, zero_based_line: int) -> tuple[bool, bool]:
        """Return cached fence/section flags for one physical line."""

        contexts = self._line_contexts
        if contexts is None:
            contexts = _build_signature_line_contexts(self.lines)
            object.__setattr__(self, "_line_contexts", contexts)
        return contexts[zero_based_line]


def _has_additional_pattern_match(
    patterns: list[re.Pattern[str]],
    line: str,
    current_pattern: re.Pattern[str],
    current_span: tuple[int, int],
) -> bool:
    """Conservatively detect another active signature primitive on a line."""

    for pattern in patterns:
        for candidate in pattern.finditer(line):
            if pattern is current_pattern and candidate.span() == current_span:
                continue
            return True
    return False


class SecurityRule:
    """Represents a security detection rule."""

    def __init__(self, rule_data: dict[str, Any], *, strict: bool = False):
        self.id = rule_data["id"]
        raw_category = rule_data.get("category")
        self.source_category = raw_category if isinstance(raw_category, str) else None
        try:
            self.category = ThreatCategory(raw_category)
            self.category_resolution: CategoryResolution = "native"
        except (TypeError, ValueError):
            if strict:
                raise ValueError(f"Rule {self.id} uses unknown category {raw_category!r}") from None
            mapped_category = LEGACY_SIGNATURE_CATEGORY_MAP.get(raw_category) if isinstance(raw_category, str) else None
            if mapped_category is not None:
                self.category = mapped_category
                self.category_resolution = "legacy_mapped"
            else:
                self.category = ThreatCategory.POLICY_VIOLATION
                self.category_resolution = "unknown_fallback"
        try:
            self.severity = Severity(rule_data["severity"])
        except (TypeError, ValueError):
            if strict:
                raise ValueError(f"Rule {self.id} uses unknown severity {rule_data.get('severity')!r}") from None
            logger.warning(
                "Rule %s uses unknown severity '%s'; falling back to HIGH",
                self.id,
                rule_data["severity"],
            )
            self.severity = Severity.HIGH
        self.patterns = rule_data["patterns"]
        self.exclude_patterns = rule_data.get("exclude_patterns", [])
        self.file_types = rule_data.get("file_types", [])
        self.description = rule_data["description"]
        self.remediation = rule_data.get("remediation", "")

        # Compile regex patterns
        self.compiled_patterns = []
        for pattern in self.patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                if strict:
                    raise ValueError(f"Invalid regex {pattern!r} for rule {self.id}: {e}") from e
                logger.warning("Failed to compile pattern '%s' for rule %s: %s", pattern, self.id, e)

        # Compile exclude patterns
        self.compiled_exclude_patterns = []
        for pattern in self.exclude_patterns:
            try:
                self.compiled_exclude_patterns.append(re.compile(pattern))
            except re.error as e:
                if strict:
                    raise ValueError(f"Invalid exclude regex {pattern!r} for rule {self.id}: {e}") from e
                logger.warning("Failed to compile exclude pattern '%s' for rule %s: %s", pattern, self.id, e)

    def matches_file_type(self, file_type: str) -> bool:
        """Check if this rule applies to the given file type."""
        if not self.file_types:
            return True  # Rule applies to all file types
        return file_type in self.file_types

    def scan_content(
        self,
        content: str,
        file_path: str | None = None,
        *,
        scan_context: SignatureScanContext | None = None,
    ) -> list[dict[str, Any]]:
        """
        Scan content for rule violations.

        Returns:
            List of matches with line numbers and snippets
        """
        matches = []
        # A caller-provided context is valid only for the exact immutable
        # string object it prepared. Rebuild defensively on accidental reuse
        # with different content rather than returning mismatched line data.
        if scan_context is None or scan_context.content is not content:
            scan_context = SignatureScanContext(content)
        lines = scan_context.lines
        for line_num, line in enumerate(lines, start=1):
            # Check exclude patterns first
            excluded = False
            for exclude_pattern in self.compiled_exclude_patterns:
                if exclude_pattern.search(line):
                    excluded = True
                    break

            if excluded:
                continue

            for pattern_index, pattern in enumerate(self.compiled_patterns):
                match = pattern.search(line)
                if match:
                    stripped_line = line.strip()
                    leading_space = len(line) - len(line.lstrip())
                    relative_match_start = max(0, match.start() - leading_space)
                    relative_match_end = min(len(stripped_line), match.end() - leading_space)
                    in_fence, negative_example_section = scan_context.line_context(line_num - 1)
                    context_kind, polarity = _classify_signature_context(
                        line,
                        file_path,
                        in_fence=in_fence,
                        negative_example_section=negative_example_section,
                        match_start=match.start(),
                        match_end=match.end(),
                        additional_active_match=_has_additional_pattern_match(
                            self.compiled_patterns,
                            line,
                            pattern,
                            match.span(),
                        ),
                    )
                    result: dict[str, Any] = {
                        "line_number": line_num,
                        "line_content": stripped_line,
                        "pattern_index": pattern_index,
                        "match_start": relative_match_start,
                        "match_end": relative_match_end,
                        "matched_pattern": pattern.pattern,
                        "matched_text": match.group(0),
                        "file_path": file_path,
                        "context_kind": context_kind,
                        "polarity": polarity,
                    }
                    matches.append(result)

        # Some rules intentionally span lines (for example "...\\n...open(...)").
        # The primary pass above is line-based for speed; this pass captures
        # multiline-only regexes and maps matches back to starting line number.
        for pattern_index, pattern in enumerate(self.compiled_patterns):
            # Check for \\n *outside* character classes.  Patterns that use
            # [^\\n] (negated newline inside a character class) are still
            # single-line patterns — they must NOT enter the multiline pass
            # or they will duplicate every match already found in pass 1.
            stripped = _CHAR_CLASS_RE.sub("", pattern.pattern)
            if "\\n" not in stripped:
                continue
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                excluded = False
                for exclude_pattern in self.compiled_exclude_patterns:
                    if exclude_pattern.search(matched_text):
                        excluded = True
                        break
                if excluded:
                    continue

                start_line = content.count("\n", 0, match.start()) + 1
                snippet = lines[start_line - 1].strip() if 0 <= start_line - 1 < len(lines) else ""
                line_start = content.rfind("\n", 0, match.start()) + 1
                relative_start = match.start() - line_start
                relative_end = min(len(snippet), match.end() - line_start)
                in_fence, negative_example_section = scan_context.line_context(start_line - 1)
                context_kind, polarity = _classify_signature_context(
                    snippet,
                    file_path,
                    in_fence=in_fence,
                    negative_example_section=negative_example_section,
                    match_start=relative_start,
                    match_end=relative_end,
                    additional_active_match=False,
                )
                result = {
                    "line_number": start_line,
                    "line_content": snippet,
                    "pattern_index": pattern_index,
                    "match_start": relative_start,
                    "match_end": relative_end,
                    "matched_pattern": pattern.pattern,
                    "matched_text": matched_text[:200],
                    "file_path": file_path,
                    "context_kind": context_kind,
                    "polarity": polarity,
                }
                matches.append(result)

        return matches


class RuleLoader:
    """Loads security rules from YAML files."""

    def __init__(
        self,
        rules_file: Path | None = None,
        extra_rules_dirs: list[Path] | None = None,
        trusted_pack_dirs: list[Path] | None = None,
        strict: bool = False,
    ):
        """
        Initialize rule loader.

        Args:
            rules_file: Path to a single YAML file **or** a directory
                containing multiple ``*.yaml`` category files.  If *None*,
                defaults to the core pack's ``signatures/`` directory.
            extra_rules_dirs: Additional directories of ``*.yaml`` signature
                files to load (e.g. from community rule packs).  Rules are
                appended after the primary ``rules_file`` rules.
            trusted_pack_dirs: Explicit schema-v2 pack roots.  These are
                validated atomically and loaded fail-fast after legacy rules.
            strict: Fail instead of warning on malformed regex rules and
                duplicate IDs. Intended for rule validation commands.
        """
        if rules_file is None:
            from ...data import DATA_DIR

            sigs_dir = DATA_DIR / "packs" / "core" / "signatures"
            rules_file = sigs_dir

        self.rules_file = rules_file
        self.extra_rules_dirs = extra_rules_dirs or []
        self.trusted_pack_dirs = trusted_pack_dirs or []
        self.strict = strict
        self.rules: list[SecurityRule] = []
        self.rules_by_id: dict[str, SecurityRule] = {}
        self.rules_by_category: dict[ThreatCategory, list[SecurityRule]] = {}
        self.category_normalization_metrics = CategoryNormalizationMetrics()

    @staticmethod
    def _extract_rules_list(data: Any, source_path: Path) -> list[dict]:
        """Extract a list of rule dicts from parsed YAML data.

        Handles both flat-list format (core) and dict-with-``signatures``
        key format (community packs like ATR).
        """
        if data is None:
            raise RuntimeError(f"Failed to load rules from {source_path}: file is empty")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "signatures" in data:
            sigs = data["signatures"]
            if isinstance(sigs, list):
                return sigs
        raise RuntimeError(
            f"Failed to load rules from {source_path}: expected a YAML list "
            "of rule objects or a dict with a 'signatures' key"
        )

    def _load_from_path(self, rules_path: Path) -> list[dict]:
        """Load raw rule dicts from a file or directory of YAML files."""
        rules_data: list[dict] = []
        if rules_path.is_dir():
            yaml_files = sorted(rules_path.glob("*.yaml"))
            if not yaml_files:
                raise RuntimeError(f"No .yaml rule files found in {rules_path}")

            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception as e:
                    raise RuntimeError(f"Failed to load rules from {yaml_file}: {e}") from e
                rules_data.extend(self._extract_rules_list(data, yaml_file))
        else:
            try:
                with open(rules_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception as e:
                raise RuntimeError(f"Failed to load rules from {rules_path}: {e}")
            rules_data.extend(self._extract_rules_list(data, rules_path))
        return rules_data

    def load_rules(self) -> list[SecurityRule]:
        """
        Load rules from the primary source and any extra pack directories.

        Returns:
            List of SecurityRule objects
        """
        rules_data = self._load_from_path(Path(self.rules_file))

        for extra_dir in self.extra_rules_dirs:
            extra_path = Path(extra_dir)
            if extra_path.is_dir():
                try:
                    rules_data.extend(self._load_from_path(extra_path))
                except Exception as e:
                    if self.strict:
                        raise
                    logger.warning("Failed to load extra rule pack from %s: %s", extra_path, e)

        loaded_rules: list[SecurityRule] = []
        loaded_by_id: dict[str, SecurityRule] = {}
        loaded_by_category: dict[ThreatCategory, list[SecurityRule]] = {}
        resolution_counts: Counter[str] = Counter()
        mapped_source_categories: Counter[str] = Counter()
        unknown_source_categories: Counter[str] = Counter()

        def record_category_resolution(rule: SecurityRule) -> None:
            resolution_counts[rule.category_resolution] += 1
            source_category = rule.source_category or "<missing-or-non-string>"
            if rule.category_resolution == "legacy_mapped":
                mapped_source_categories[source_category] += 1
            elif rule.category_resolution == "unknown_fallback":
                unknown_source_categories[source_category] += 1

        for rule_data in rules_data:
            if self.strict:
                if not isinstance(rule_data, dict):
                    raise ValueError("Every signature rule must be a mapping")
                rule = SecurityRule(rule_data, strict=True)
                if rule.id in loaded_by_id:
                    raise ValueError(f"Duplicate signature rule ID: {rule.id}")
                loaded_rules.append(rule)
                loaded_by_id[rule.id] = rule
                loaded_by_category.setdefault(rule.category, []).append(rule)
                record_category_resolution(rule)
                continue
            try:
                rule = SecurityRule(rule_data)
                loaded_rules.append(rule)
                loaded_by_id[rule.id] = rule

                if rule.category not in loaded_by_category:
                    loaded_by_category[rule.category] = []
                loaded_by_category[rule.category].append(rule)
                record_category_resolution(rule)
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", rule_data.get("id", "unknown"), e)

        if self.trusted_pack_dirs:
            # Import lazily to avoid a module cycle: the registry validates
            # raw signature implementations, while this module instantiates
            # the runtime SecurityRule objects.
            from ..rule_registry import PackLoader

            pack_loader = PackLoader()
            for pack_dir in self.trusted_pack_dirs:
                pack = pack_loader.load_trusted_pack(pack_dir)
                for rule_data in pack.signature_rules:
                    rule = SecurityRule(rule_data, strict=True)
                    if rule.id in loaded_by_id:
                        raise ValueError(f"Rule ID collision: trusted pack '{pack.name}' redefines rule '{rule.id}'")
                    loaded_rules.append(rule)
                    loaded_by_id[rule.id] = rule
                    loaded_by_category.setdefault(rule.category, []).append(rule)
                    record_category_resolution(rule)

        if unknown_source_categories:
            details = ", ".join(f"{category}={count}" for category, count in sorted(unknown_source_categories.items()))
            logger.warning(
                "%d signature rule(s) use unmapped categories; falling back to POLICY_VIOLATION (%s)",
                sum(unknown_source_categories.values()),
                details,
            )

        metrics = CategoryNormalizationMetrics(
            native_rules=resolution_counts["native"],
            legacy_mapped_rules=resolution_counts["legacy_mapped"],
            unknown_fallback_rules=resolution_counts["unknown_fallback"],
            mapped_source_categories=tuple(sorted(mapped_source_categories.items())),
            unknown_source_categories=tuple(sorted(unknown_source_categories.items())),
        )

        # Publish only a completely loaded generation.
        self.rules = loaded_rules
        self.rules_by_id = loaded_by_id
        self.rules_by_category = loaded_by_category
        self.category_normalization_metrics = metrics

        return self.rules

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        """Get a specific rule by ID."""
        return self.rules_by_id.get(rule_id)

    def get_rules_for_file_type(self, file_type: str) -> list[SecurityRule]:
        """Get all rules that apply to a specific file type."""
        return [rule for rule in self.rules if rule.matches_file_type(file_type)]

    def get_rules_for_category(self, category: ThreatCategory) -> list[SecurityRule]:
        """Get all rules in a specific threat category."""
        return self.rules_by_category.get(category, [])
