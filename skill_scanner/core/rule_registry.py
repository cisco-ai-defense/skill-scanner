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
Rule Pack system – self-describing rules with metadata and knobs.

Architecture
~~~~~~~~~~~~

Rules in Skill Scanner come from three implementation sources:

* **Signature rules** – regex patterns in ``signatures.yaml``
* **YARA rules** – compiled ``.yara`` files
* **Python rules** – hardcoded detection logic in analyzer classes

The Rule Pack system unifies metadata for **all** rules into a single
``pack.yaml`` manifest.  Each pack is a directory containing:

.. code-block:: text

    my-rules/
        pack.yaml           # Manifest – declares all rules + default knobs
        signatures.yaml     # (optional) regex pattern rules
        *.yara              # (optional) YARA rules

At startup the :class:`PackLoader` discovers built-in and external packs,
the :class:`RuleRegistry` collects every :class:`RuleDefinition`, and the
policy system merges pack defaults with user overrides.
"""

from __future__ import annotations

import ast
import copy
import logging
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .cel.models import CelRollout, CelRule
from .cel.validator import CelValidationError, validate_cel_expression
from .models import Finding, Severity, ThreatCategory
from .python_rule_inventory import (
    BUNDLED_INDIRECT_PYTHON_IMPLEMENTATIONS,
    BundledPythonImplementation,
)

logger = logging.getLogger(__name__)

_TRUSTED_PACK_SCHEMA_VERSION = 2
_TRUSTED_PACK_FIELDS = frozenset(
    {
        "schema_version",
        "name",
        "version",
        "description",
        "author",
        "license",
        "source_url",
        "rules",
    }
)
_TRUSTED_RULE_FIELDS = frozenset(
    {
        "source",
        "knobs",
        "description",
        "category",
        "severity",
        "file_types",
        "remediation",
        "cel",
    }
)
_BUNDLED_V2_RULE_FIELDS = _TRUSTED_RULE_FIELDS | {"allowed_severity_demotions", "analyzer"}
_TRUSTED_KNOB_FIELDS = frozenset({"enabled"})
_BUNDLED_V2_KNOB_FIELDS = frozenset(
    {
        "enabled",
        "allow_script_shebang_text_extensions",
        "annotate_same_path_rule_cooccurrence",
        "api_doc_tokens",
        "asset_prompt_injection_skip_in_docs",
        "attach_policy_fingerprint",
        "check_known_installers",
        "compound_fetch_exec_commands",
        "compound_fetch_exec_prefixes",
        "compound_fetch_filter_api_requests",
        "compound_fetch_filter_shell_wrapped_fetch",
        "compound_fetch_require_download_intent",
        "cyrillic_cjk_min_chars",
        "dedupe_exact_findings",
        "dedupe_same_issue_per_location",
        "demote_in_docs",
        "demote_instructional",
        "exception_handler_context_lines",
        "exfil_hints",
        "homoglyph_filter_math_context",
        "homoglyph_math_aliases",
        "max_description_length",
        "max_file_count",
        "max_file_size_bytes",
        "max_name_length",
        "max_reference_depth",
        "min_confidence_pct",
        "min_dangerous_lines",
        "min_description_length",
        "same_issue_collapse_within_analyzer",
        "same_issue_preferred_analyzers",
        "script_shebang_extensions",
        "short_match_max_chars",
        "skip_in_docs",
        "skip_inert_extensions",
        "zerowidth_threshold_alone",
        "zerowidth_threshold_with_decode",
    }
)
_TRUSTED_CEL_FIELDS = frozenset({"fact_schema", "rollout", "expression"})
_SIGNATURE_FIELDS = frozenset(
    {
        "id",
        "category",
        "severity",
        "patterns",
        "exclude_patterns",
        "file_types",
        "description",
        "remediation",
    }
)
_TRUSTED_SOURCES = frozenset({"signature", "yara"})
_BUNDLED_SOURCES = frozenset({"signature", "yara", "python"})
_BUNDLED_ANALYZERS = frozenset(
    {
        "aidefense",
        "analyzability",
        "behavioral",
        "bytecode",
        "content_extractor",
        "correlation",
        "cross_skill",
        "llm",
        "meta",
        "osv",
        "pipeline",
        "scanner",
        "skill_loader",
        "static",
        "trigger",
        "virustotal",
    }
)
_THREAT_CATEGORIES = frozenset(item.value for item in ThreatCategory)
_SEVERITIES = frozenset(item.value for item in Severity)
_SEVERITY_RANK = {
    Severity.SAFE.value: 0,
    Severity.INFO.value: 1,
    Severity.LOW.value: 2,
    Severity.MEDIUM.value: 3,
    Severity.HIGH.value: 4,
    Severity.CRITICAL.value: 5,
}

# The installed bundled packs are immutable release artifacts for the life of
# a scanner process.  Validate their complete implementation generation once,
# then hand each caller an isolated deep copy so registry mutation cannot
# poison the process-wide snapshot.
_BUILT_IN_PACK_SNAPSHOT: tuple[RulePack, ...] | None = None
_BUILT_IN_PACK_SNAPSHOT_LOCK = threading.Lock()


class _DuplicateKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: _DuplicateKeySafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ValueError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise ValueError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_strict_yaml(path: Path) -> Any:
    """Load rule-pack YAML while retaining duplicate-key failures."""

    try:
        with path.open(encoding="utf-8") as fh:
            return yaml.load(fh, Loader=_DuplicateKeySafeLoader)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ValueError(f"Invalid rule-pack YAML {path}: {exc}") from exc


def _unknown_fields(data: dict[Any, Any], allowed: frozenset[str], context: str) -> None:
    unknown = sorted(str(key) for key in set(data) - allowed)
    if unknown:
        raise ValueError(f"Unknown field(s) in {context}: {', '.join(unknown)}")


def _required_string(data: dict[str, Any], field_name: str, context: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{field_name} must be a non-empty string")
    return value


def _optional_pack_metadata(raw: dict[str, Any], context: str) -> dict[str, str]:
    """Validate bounded human/provenance metadata on a schema-v2 pack."""

    result: dict[str, str] = {}
    for field_name in ("author", "license", "source_url"):
        value = raw.get(field_name, "")
        if not isinstance(value, str):
            raise ValueError(f"{context}.{field_name} must be a string")
        if field_name in raw and not value.strip():
            raise ValueError(f"{context}.{field_name} must be a non-empty string when present")
        result[field_name] = value
    return result


def _normalise_severity(value: Any, context: str) -> str:
    if not isinstance(value, str) or value.upper() not in _SEVERITIES:
        raise ValueError(f"Unknown severity {value!r} in {context}")
    return value.upper()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleDefinition:
    """Metadata for a single detection rule.

    This is the canonical description of a rule – its identity, default
    knobs, and implementation source.  Instances are created by loading a
    ``pack.yaml`` manifest.
    """

    id: str
    """Unique rule identifier, e.g. ``FIND_EXEC_PATTERN``."""

    source_type: str
    """Implementation source: ``"signature"``, ``"yara"``, or ``"python"``."""

    pack_name: str
    """Name of the pack that provides this rule."""

    knobs: dict[str, Any] = field(default_factory=lambda: {"enabled": True})
    """Default tuning knobs.  Every rule must have at least ``enabled``."""

    description: str = ""
    """Human-readable one-liner explaining the detection."""

    category: str = ""
    """Threat category value (e.g. ``"command_injection"``)."""

    default_severity: str = ""
    """Default severity level (e.g. ``"HIGH"``)."""

    allowed_severity_demotions: frozenset[str] = frozenset()
    """Manifest-owned runtime severities permitted below ``default_severity``.

    The maximum/default severity is always permitted.  Any lower runtime
    severity must be listed explicitly so a detector cannot silently drift
    away from the reviewed pack contract.
    """

    analyzer: str = ""
    """For ``python`` rules – the analyzer class that implements the check."""

    file_types: list[str] = field(default_factory=list)
    """For ``signature`` rules – which file types the rule applies to."""

    remediation: str = ""
    """Suggested fix for a true positive."""

    cel: CelRule | None = None
    """Optional bounded CEL decision gate for this concrete rule."""


@dataclass(frozen=True)
class FindingContractViolation:
    """One stable mismatch between a Python finding and its v2 manifest."""

    code: str
    rule_id: str
    expected: str
    actual: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "rule_id": self.rule_id,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class _LiteralPythonFinding:
    """Statically available metadata from one literal ``Finding`` call."""

    rule_id: str
    source_path: Path
    line_number: int
    analyzer: str | None
    category: str | None
    severity: str | None


@dataclass(frozen=True)
class PackValidationReport:
    """Truthful validation status for one loaded rule-pack generation.

    Schema-v2 packs report strict validation. The compatibility loader reports
    its narrower legacy scope and any blockers without presenting those packs
    as reviewed schema-v2 generations.
    """

    schema_status: str
    validation_scope: str
    signature_implementation_count: int = 0
    yara_implementation_count: int = 0
    python_implementation_count: int = 0
    metadata_incomplete_rule_ids: tuple[str, ...] = ()
    promotion_blockers: tuple[str, ...] = ()


@dataclass
class RulePack:
    """A collection of rules loaded from a single pack directory.

    Attributes:
        name: Pack name from ``pack.yaml`` (e.g. ``"core"``).
        version: Semantic version string.
        description: Human-readable description.
        path: Filesystem path to the pack directory.
        author: Optional reviewed author or maintainer provenance.
        license: Optional SPDX-style license provenance.
        source_url: Optional immutable upstream source reference.
        rules: Mapping of rule ID → :class:`RuleDefinition`.
        signatures_file: Resolved path to a single ``signatures.yaml``
            if the pack uses the legacy flat layout.  Mutually exclusive
            with *signatures_dir*.
        signatures_dir: Resolved path to a ``signatures/`` directory
            containing multiple ``*.yaml`` category files.  Preferred
            over *signatures_file*.
        yara_dirs: List of directories containing ``.yara`` files.
    """

    name: str
    version: str
    description: str
    path: Path
    rules: dict[str, RuleDefinition] = field(default_factory=dict)
    signatures_file: Path | None = None
    signatures_dir: Path | None = None
    yara_dirs: list[Path] = field(default_factory=list)
    schema_version: int | None = None
    trusted: bool = False
    signature_rules: list[dict[str, Any]] = field(default_factory=list, repr=False)
    validation_report: PackValidationReport | None = None
    author: str = ""
    license: str = ""
    source_url: str = ""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class RuleRegistry:
    """Central catalog of all known rule definitions across packs.

    The registry is built once at startup and made available to analyzers
    and the policy system.  It is **read-only** after construction.
    """

    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}
        self._packs: dict[str, RulePack] = {}

    # -- Mutation (used during startup) ------------------------------------

    def register_pack(self, pack: RulePack) -> None:
        """Register all rules from *pack*.

        Raises :class:`ValueError` if a rule ID collides with an
        already-registered rule from a different pack.
        """
        existing_pack = self._packs.get(pack.name)
        if existing_pack is pack:
            return
        if existing_pack is not None:
            raise ValueError(
                f"Rule pack name collision: '{pack.name}' is provided by both '{existing_pack.path}' and '{pack.path}'"
            )

        # Validate the complete pack before publishing any part of it.  A
        # late collision must not leave earlier rules from the rejected pack
        # in the active registry generation.
        for rule_id, rule_def in pack.rules.items():
            if rule_id != rule_def.id:
                raise ValueError(
                    f"Rule mapping identity mismatch in pack '{pack.name}': "
                    f"key {rule_id!r} contains definition {rule_def.id!r}"
                )
            if rule_def.pack_name != pack.name:
                raise ValueError(
                    f"Rule {rule_id!r} declares pack {rule_def.pack_name!r}, "
                    f"but is registered through pack {pack.name!r}"
                )
            if rule_id in self._rules:
                existing = self._rules[rule_id]
                raise ValueError(
                    f"Rule ID collision: '{rule_id}' is defined in both "
                    f"pack '{existing.pack_name}' and pack '{pack.name}'"
                )

        self._rules.update(pack.rules)
        self._packs[pack.name] = pack

    def register(self, rule: RuleDefinition) -> None:
        """Register a single rule (convenience for tests)."""
        existing = self._rules.get(rule.id)
        if existing is not None:
            raise ValueError(
                f"Rule ID collision: '{rule.id}' is defined in both "
                f"pack '{existing.pack_name}' and pack '{rule.pack_name}'"
            )
        self._rules[rule.id] = rule

    # -- Read-only accessors ------------------------------------------------

    def get(self, rule_id: str) -> RuleDefinition | None:
        """Look up a rule by ID."""
        return self._rules.get(rule_id)

    def all_rules(self) -> dict[str, RuleDefinition]:
        """Return a shallow copy of the full rule catalog."""
        return dict(self._rules)

    def all_packs(self) -> dict[str, RulePack]:
        """Return a shallow copy of the loaded packs."""
        return dict(self._packs)

    def get_default_knobs(self) -> dict[str, dict[str, Any]]:
        """Return a mapping of rule ID → default knobs from pack manifests.

        This is the baseline that the policy system merges user overrides
        into.
        """
        return {rule_id: dict(rule.knobs) for rule_id, rule in self._rules.items()}

    def rule_ids(self) -> set[str]:
        """Return the set of all registered rule IDs."""
        return set(self._rules.keys())

    def validate_bundled_python_finding(
        self,
        finding: Finding,
        *,
        require_known: bool = False,
    ) -> tuple[FindingContractViolation, ...]:
        """Validate a runtime finding against the authoritative core v2 rule.

        Only release-owned Python rules participate.  Trusted local packs
        cannot contain Python and legacy/custom signature or YARA findings are
        intentionally left alone.  ``require_known`` is reserved for
        closed-world bundled Python producers (pipeline, correlation, bytecode,
        and scanner-owned findings); mixed producers such as ``static`` may
        also emit administrator-supplied signatures or legacy custom YARA.

        The function never mutates or drops a finding.  Callers retain invalid
        findings fail-open, record the returned stable errors, and make them
        ineligible for CEL suppression.
        """

        definition = self._rules.get(finding.rule_id)
        if definition is None:
            if not require_known:
                return ()
            return (
                FindingContractViolation(
                    code="UNKNOWN_BUNDLED_PYTHON_RULE",
                    rule_id=finding.rule_id,
                    expected="declared core schema-v2 Python rule",
                    actual="missing",
                ),
            )

        if definition.pack_name != "core":
            return ()
        if definition.source_type != "python":
            if not require_known:
                return ()
            return (
                FindingContractViolation(
                    code="BUNDLED_PYTHON_SOURCE_MISMATCH",
                    rule_id=finding.rule_id,
                    expected="python",
                    actual=definition.source_type,
                ),
            )

        violations: list[FindingContractViolation] = []
        actual_analyzer = finding.analyzer or ""
        if actual_analyzer != definition.analyzer:
            violations.append(
                FindingContractViolation(
                    code="BUNDLED_PYTHON_ANALYZER_MISMATCH",
                    rule_id=finding.rule_id,
                    expected=definition.analyzer,
                    actual=actual_analyzer,
                )
            )

        actual_category = finding.category.value
        if actual_category != definition.category:
            violations.append(
                FindingContractViolation(
                    code="BUNDLED_PYTHON_CATEGORY_MISMATCH",
                    rule_id=finding.rule_id,
                    expected=definition.category,
                    actual=actual_category,
                )
            )

        actual_severity = finding.severity.value
        expected_severity = definition.default_severity.upper()
        if actual_severity != expected_severity:
            actual_rank = _SEVERITY_RANK.get(actual_severity, -1)
            expected_rank = _SEVERITY_RANK.get(expected_severity, -1)
            if actual_rank > expected_rank:
                code = "BUNDLED_PYTHON_SEVERITY_ESCALATION"
            elif actual_severity not in definition.allowed_severity_demotions:
                code = "BUNDLED_PYTHON_UNDECLARED_SEVERITY_DEMOTION"
            else:
                code = ""
            if code:
                allowed = ",".join(
                    sorted(definition.allowed_severity_demotions, key=lambda value: _SEVERITY_RANK[value])
                )
                violations.append(
                    FindingContractViolation(
                        code=code,
                        rule_id=finding.rule_id,
                        expected=(
                            expected_severity
                            if not allowed
                            else f"{expected_severity} or declared demotion {{{allowed}}}"
                        ),
                        actual=actual_severity,
                    )
                )

        return tuple(violations)

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules


# ---------------------------------------------------------------------------
# Pack loader
# ---------------------------------------------------------------------------


class PackLoader:
    """Discovers and loads rule packs from filesystem directories."""

    # Default location of the built-in core pack
    _BUILT_IN_PACKS_DIR: Path = Path(__file__).parent.parent / "data" / "packs"

    @staticmethod
    def _locate_implementations(path: Path, *, strict: bool = False) -> tuple[Path | None, Path | None, list[Path]]:
        """Locate signature and YARA implementations in a pack."""

        signatures_file: Path | None = None
        signatures_dir: Path | None = None
        sigs_dir_path = path / "signatures"
        sigs_file_path = path / "signatures.yaml"
        if strict and sigs_dir_path.exists() and sigs_file_path.exists():
            raise ValueError("Trusted pack cannot contain both signatures/ and signatures.yaml")
        if sigs_dir_path.is_dir() and list(sigs_dir_path.glob("*.yaml")):
            signatures_dir = sigs_dir_path
        elif sigs_file_path.exists():
            signatures_file = sigs_file_path

        yara_dirs: list[Path] = []
        yara_sub = path / "yara"
        root_yara_files = list(path.glob("*.yara"))
        if strict and yara_sub.exists() and root_yara_files:
            raise ValueError("Trusted pack cannot contain YARA files both at its root and in yara/")
        if yara_sub.is_dir() and list(yara_sub.glob("*.yara")):
            yara_dirs.append(yara_sub)
        elif root_yara_files:
            yara_dirs.append(path)
        return signatures_file, signatures_dir, yara_dirs

    @staticmethod
    def _validate_local_member(pack_path: Path, member: Path) -> Path:
        """Require an implementation file to be a non-symlink inside its pack."""

        pack_root = pack_path.resolve(strict=True)
        if member.is_symlink():
            raise ValueError(f"Trusted pack implementation may not be a symlink: {member}")
        try:
            resolved = member.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Trusted pack implementation is unavailable: {member}") from exc
        if not resolved.is_relative_to(pack_root):
            raise ValueError(f"Trusted pack implementation escapes pack directory: {member}")

        relative = member.relative_to(pack_path)
        current = pack_path
        for part in relative.parts[:-1]:
            current /= part
            if current.is_symlink():
                raise ValueError(f"Trusted pack implementation uses a symlinked directory: {member}")
        return resolved

    @staticmethod
    def _parse_cel(rule_id: str, pack_name: str, raw: Any) -> CelRule | None:
        if raw is None:
            return None
        context = f"rule {rule_id}.cel"
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be a mapping")
        _unknown_fields(raw, _TRUSTED_CEL_FIELDS, context)
        expression = _required_string(raw, "expression", context)
        fact_schema = _required_string(raw, "fact_schema", context)
        if fact_schema != "v1":
            raise ValueError(f"Unsupported fact schema {fact_schema!r} in {context}")
        rollout_raw = _required_string(raw, "rollout", context)
        try:
            rollout = CelRollout(rollout_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Unknown CEL rollout {rollout_raw!r} in {context}") from exc
        try:
            validate_cel_expression(expression)
        except CelValidationError as exc:
            raise ValueError(f"Invalid CEL expression for rule {rule_id}: {exc}") from exc
        return CelRule(
            rule_id=rule_id,
            expression=expression,
            fact_schema=fact_schema,
            rollout=rollout,
            pack_name=pack_name,
        )

    def _load_trusted_signatures(
        self,
        pack_path: Path,
        signatures_file: Path | None,
        signatures_dir: Path | None,
        definitions: dict[str, RuleDefinition],
        manifest_rules: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        files: list[Path] = []
        if signatures_dir is not None:
            self._validate_local_member(pack_path, signatures_dir)
            files = sorted(signatures_dir.glob("*.yaml"))
        elif signatures_file is not None:
            files = [signatures_file]

        implementations: dict[str, dict[str, Any]] = {}
        for source_path in files:
            source_path = self._validate_local_member(pack_path, source_path)
            data = _load_strict_yaml(source_path)
            raw_rules: Any
            if isinstance(data, list):
                raw_rules = data
            elif isinstance(data, dict):
                _unknown_fields(data, frozenset({"signatures"}), str(source_path))
                raw_rules = data.get("signatures")
            else:
                raw_rules = None
            if not isinstance(raw_rules, list):
                raise ValueError(
                    f"Trusted signature file {source_path} must be a list or a mapping with a signatures list"
                )

            for index, implementation in enumerate(raw_rules):
                context = f"{source_path} signature[{index}]"
                if not isinstance(implementation, dict):
                    raise ValueError(f"{context} must be a mapping")
                _unknown_fields(implementation, _SIGNATURE_FIELDS, context)
                rule_id = _required_string(implementation, "id", context)
                if rule_id != rule_id.strip():
                    raise ValueError(f"{context}.id may not contain surrounding whitespace")
                if rule_id in implementations:
                    raise ValueError(f"Duplicate signature implementation for rule {rule_id!r}")

                definition = definitions.get(rule_id)
                if definition is None:
                    raise ValueError(f"Signature implementation {rule_id!r} is not declared in pack.yaml")
                if definition.source_type != "signature":
                    raise ValueError(
                        f"Rule {rule_id!r} is implemented as a signature but declared as {definition.source_type!r}"
                    )

                patterns = implementation.get("patterns")
                if (
                    not isinstance(patterns, list)
                    or not patterns
                    or not all(isinstance(item, str) and item for item in patterns)
                ):
                    raise ValueError(f"{context}.patterns must be a non-empty list of non-empty strings")
                excludes = implementation.get("exclude_patterns", [])
                if not isinstance(excludes, list) or not all(isinstance(item, str) and item for item in excludes):
                    raise ValueError(f"{context}.exclude_patterns must be a list of non-empty strings")
                for field_name, values in (("patterns", patterns), ("exclude_patterns", excludes)):
                    for pattern in values:
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            raise ValueError(
                                f"Invalid regex in {context}.{field_name} for rule {rule_id}: {exc}"
                            ) from exc

                manifest_data = manifest_rules[rule_id]
                if "category" in implementation and implementation["category"] != definition.category:
                    raise ValueError(
                        f"Category metadata mismatch for rule {rule_id}: "
                        f"pack.yaml={definition.category!r}, signature={implementation['category']!r}"
                    )
                if "severity" in implementation:
                    implementation_severity = _normalise_severity(implementation["severity"], context)
                    if implementation_severity != definition.default_severity:
                        raise ValueError(
                            f"Severity metadata mismatch for rule {rule_id}: "
                            f"pack.yaml={definition.default_severity!r}, signature={implementation_severity!r}"
                        )
                for field_name in ("description", "file_types", "remediation"):
                    if field_name in manifest_data and field_name in implementation:
                        if implementation[field_name] != manifest_data[field_name]:
                            raise ValueError(f"{field_name} metadata mismatch for rule {rule_id}")

                for field_name in ("description", "remediation"):
                    value = implementation.get(field_name, "")
                    if not isinstance(value, str):
                        raise ValueError(f"{context}.{field_name} must be a string")

                file_types = manifest_data.get("file_types", implementation.get("file_types", []))
                if not isinstance(file_types, list) or not all(
                    isinstance(item, str) and item.strip() for item in file_types
                ):
                    raise ValueError(f"Rule {rule_id}.file_types must be a list of non-empty strings")
                effective = dict(implementation)
                effective.update(
                    {
                        "category": definition.category,
                        "severity": definition.default_severity,
                        "description": manifest_data.get("description", implementation.get("description", "")),
                        "file_types": list(file_types),
                        "remediation": manifest_data.get("remediation", implementation.get("remediation", "")),
                    }
                )
                implementations[rule_id] = effective

        declared = {rule_id for rule_id, definition in definitions.items() if definition.source_type == "signature"}
        actual = set(implementations)
        missing = sorted(declared - actual)
        if missing:
            raise ValueError(f"Missing signature implementation(s): {', '.join(missing)}")
        return list(implementations.values())

    def _validate_trusted_yara(
        self,
        pack_path: Path,
        yara_dirs: list[Path],
        definitions: dict[str, RuleDefinition],
    ) -> None:
        yara_files: list[Path] = []
        for yara_dir in yara_dirs:
            self._validate_local_member(pack_path, yara_dir)
            yara_files.extend(sorted(yara_dir.glob("*.yara")))

        sources: list[tuple[Path, str]] = []
        for yara_file in yara_files:
            resolved = self._validate_local_member(pack_path, yara_file)
            try:
                source = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ValueError(f"Unable to read trusted YARA implementation {resolved}: {exc}") from exc
            sources.append((resolved, source))
        if not sources:
            declared = {rule_id for rule_id, definition in definitions.items() if definition.source_type == "yara"}
            if declared:
                raise ValueError(f"Missing YARA implementation(s): {', '.join(sorted(declared))}")
            return

        try:
            import yara_x
        except (ImportError, ModuleNotFoundError) as exc:
            raise ValueError("Validating a trusted YARA pack requires the yara-x runtime") from exc
        # Trusted packs are self-contained.  Do not let an implementation
        # bypass pack-member validation through a YARA include, and reject
        # patterns that YARA-X identifies as intrinsically slow.
        compiler = yara_x.Compiler(error_on_slow_pattern=True, includes_enabled=False)
        source_namespaces: dict[str, Path] = {}
        try:
            for index, (source_path, source) in enumerate(sources):
                # Use a generated namespace instead of the filename.  It is
                # unique even on case-sensitive filesystems where names that
                # differ only by case may coexist, and it lets us verify that
                # every implementation file contributed at least one rule.
                namespace = f"trusted_{index:04d}"
                source_namespaces[namespace] = source_path
                compiler.new_namespace(namespace)
                compiler.add_source(source, origin=str(source_path))
            compiled_rules = compiler.build()
        except Exception as exc:
            raise ValueError(f"Invalid YARA implementation in trusted pack {pack_path}: {exc}") from exc

        implementation_ids: set[str] = set()
        populated_namespaces: set[str] = set()
        for compiled_rule in compiled_rules:
            rule_id = f"YARA_{compiled_rule.identifier}"
            if rule_id in implementation_ids:
                raise ValueError(f"Duplicate YARA implementation for rule {rule_id!r}")
            implementation_ids.add(rule_id)
            populated_namespaces.add(compiled_rule.namespace)

            definition = definitions.get(rule_id)
            if definition is None:
                raise ValueError(f"YARA implementation {rule_id!r} is not declared in pack.yaml")
            metadata = dict(compiled_rule.metadata)
            category = metadata.get("category", metadata.get("threat_type"))
            if category is not None and category != definition.category:
                raise ValueError(
                    f"Category metadata mismatch for rule {rule_id}: "
                    f"pack.yaml={definition.category!r}, YARA={category!r}"
                )
            if "severity" in metadata:
                yara_severity = _normalise_severity(metadata["severity"], f"YARA rule {rule_id}")
                if yara_severity != definition.default_severity:
                    raise ValueError(
                        f"Severity metadata mismatch for rule {rule_id}: "
                        f"pack.yaml={definition.default_severity!r}, YARA={yara_severity!r}"
                    )
            if definition.description and "description" in metadata:
                if metadata["description"] != definition.description:
                    raise ValueError(f"description metadata mismatch for rule {rule_id}")

        empty_sources = [
            str(path) for namespace, path in source_namespaces.items() if namespace not in populated_namespaces
        ]
        if empty_sources:
            raise ValueError(f"Trusted YARA file contains no rules: {', '.join(empty_sources)}")

        declared = {rule_id for rule_id, definition in definitions.items() if definition.source_type == "yara"}
        missing = sorted(declared - implementation_ids)
        if missing:
            raise ValueError(f"Missing YARA implementation(s): {', '.join(missing)}")

    def _load_bundled_signature_metadata(
        self,
        pack_path: Path,
        signatures_file: Path | None,
        signatures_dir: Path | None,
    ) -> dict[str, tuple[dict[str, Any], Path]]:
        """Read bundled signature metadata without narrowing legacy fields.

        ATR and PromptGuard carry provenance fields that are not part of the v2
        trusted-pack schema.  Preserve those legacy fields while still rejecting
        duplicate keys/IDs and malformed identity or metadata fields.
        """

        files: list[Path] = []
        if signatures_dir is not None:
            files = sorted(signatures_dir.glob("*.yaml"))
        elif signatures_file is not None:
            files = [signatures_file]

        implementations: dict[str, tuple[dict[str, Any], Path]] = {}
        for source_path in files:
            data = _load_strict_yaml(source_path)
            if isinstance(data, list):
                raw_rules: Any = data
            elif isinstance(data, dict):
                raw_rules = data.get("signatures")
            else:
                raw_rules = None
            if not isinstance(raw_rules, list):
                raise ValueError(
                    f"Bundled signature file {source_path} must be a list or a mapping with a signatures list"
                )

            for index, implementation in enumerate(raw_rules):
                context = f"{source_path} signature[{index}]"
                if not isinstance(implementation, dict):
                    raise ValueError(f"{context} must be a mapping")
                rule_id = _required_string(implementation, "id", context)
                if rule_id in implementations:
                    raise ValueError(f"Duplicate signature implementation for rule {rule_id!r}")
                category = implementation.get("category")
                if not isinstance(category, str) or not category:
                    raise ValueError(f"{context}.category must be a non-empty string")
                _normalise_severity(implementation.get("severity"), context)

                patterns = implementation.get("patterns")
                if (
                    not isinstance(patterns, list)
                    or not patterns
                    or not all(isinstance(item, str) and item for item in patterns)
                ):
                    raise ValueError(f"{context}.patterns must be a non-empty list of non-empty strings")
                excludes = implementation.get("exclude_patterns", [])
                if not isinstance(excludes, list) or not all(isinstance(item, str) and item for item in excludes):
                    raise ValueError(f"{context}.exclude_patterns must be a list of non-empty strings")
                for field_name, values in (("patterns", patterns), ("exclude_patterns", excludes)):
                    for pattern_index, pattern in enumerate(values):
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            raise ValueError(
                                f"Invalid regex in bundled signature rule {rule_id!r} "
                                f"at {source_path}:{field_name}[{pattern_index}]: {exc}"
                            ) from exc
                implementations[rule_id] = (implementation, source_path)
        return implementations

    def _compile_bundled_yara(
        self,
        pack_path: Path,
        yara_dirs: list[Path],
    ) -> list[Any]:
        """Compile bundled YARA sources and return their parsed rules."""

        sources: list[tuple[Path, str]] = []
        for yara_dir in yara_dirs:
            for yara_file in sorted(yara_dir.glob("*.yara")):
                try:
                    source = yara_file.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    raise ValueError(f"Unable to read bundled YARA implementation {yara_file}: {exc}") from exc
                sources.append((yara_file, source))
        if not sources:
            return []

        try:
            import yara_x
        except (ImportError, ModuleNotFoundError) as exc:
            raise ValueError("Validating bundled YARA packs requires the yara-x runtime") from exc

        # Bundled generations are self-contained release artifacts.  Includes
        # and intrinsically slow patterns are invalid rather than implicit
        # compile-time inputs or runtime denial-of-service hazards.
        compiler = yara_x.Compiler(error_on_slow_pattern=True, includes_enabled=False)
        source_namespaces: dict[str, Path] = {}
        try:
            for index, (source_path, source) in enumerate(sources):
                namespace = f"bundled_{index:04d}"
                source_namespaces[namespace] = source_path
                compiler.new_namespace(namespace)
                compiler.add_source(source, origin=str(source_path))
            compiled_rules = list(compiler.build())
        except Exception as exc:
            raise ValueError(f"Invalid YARA implementation in bundled pack {pack_path}: {exc}") from exc

        populated_namespaces = {rule.namespace for rule in compiled_rules}
        empty_sources = [
            str(path) for namespace, path in source_namespaces.items() if namespace not in populated_namespaces
        ]
        if empty_sources:
            raise ValueError(f"Bundled YARA file contains no rules: {', '.join(empty_sources)}")
        return compiled_rules

    @staticmethod
    def _validate_bundled_python_implementations(
        definitions: dict[str, RuleDefinition],
        *,
        source_root: Path | None = None,
        indirect_implementations: Mapping[str, BundledPythonImplementation] | None = None,
    ) -> int:
        """Match core's fixed Python finding identities and literal metadata.

        Most implementations pass a literal ``rule_id`` to ``Finding`` and
        can be inventoried without importing or executing analyzer modules.
        Bounded table/dispatcher implementations live in the import-safe
        :mod:`python_rule_inventory`; category-derived Meta identities are
        enumerated there as concrete manifest-owned rules. Literal and
        inventory analyzer/category/severity values are compared with the
        manifest as part of the same startup invariant. Dynamic literal values
        are left to the runtime finding contract, while declared severity
        demotions remain valid.
        """

        declared = {rule_id for rule_id, definition in definitions.items() if definition.source_type == "python"}
        if not declared:
            return 0
        pack_names = {definition.pack_name for definition in definitions.values()}
        if pack_names != {"core"}:
            raise ValueError("Only the release-owned core pack may declare bundled Python implementations")

        source_root = source_root or Path(__file__).parent
        indirect_implementations = (
            BUNDLED_INDIRECT_PYTHON_IMPLEMENTATIONS if indirect_implementations is None else indirect_implementations
        )
        literal_ids: set[str] = set()
        literal_findings: list[_LiteralPythonFinding] = []

        argument_positions = {
            "rule_id": 1,
            "category": 2,
            "severity": 3,
            "analyzer": 10,
        }

        def argument_value(call: ast.Call, name: str) -> ast.expr | None:
            keyword = next((keyword.value for keyword in call.keywords if keyword.arg == name), None)
            if keyword is not None:
                return keyword
            position = argument_positions[name]
            return call.args[position] if len(call.args) > position else None

        def literal_string(value: ast.expr | None) -> str | None:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            return None

        def qualified_name(value: ast.expr) -> str | None:
            if isinstance(value, ast.Name):
                return value.id
            if isinstance(value, ast.Attribute):
                parent = qualified_name(value.value)
                return f"{parent}.{value.attr}" if parent else None
            return None

        def literal_enum(value: ast.expr | None, enum_type: type[Severity] | type[ThreatCategory]) -> str | None:
            string_value = literal_string(value)
            if string_value is not None:
                return string_value
            if not isinstance(value, ast.Attribute):
                return None
            owner = qualified_name(value.value)
            if owner is None or owner.rsplit(".", 1)[-1] != enum_type.__name__:
                return None
            member = enum_type.__members__.get(value.attr)
            return member.value if member is not None else f"{enum_type.__name__}.{value.attr}"

        for source_path in sorted(source_root.rglob("*.py")):
            try:
                tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
            except (OSError, UnicodeDecodeError, SyntaxError) as exc:
                raise ValueError(f"Unable to inventory bundled Python implementation {source_path}: {exc}") from exc
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function_name = ""
                if isinstance(node.func, ast.Name):
                    function_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    function_name = node.func.attr
                if function_name != "Finding":
                    continue
                rule_id = literal_string(argument_value(node, "rule_id"))
                if rule_id is None:
                    continue
                literal_ids.add(rule_id)
                literal_findings.append(
                    _LiteralPythonFinding(
                        rule_id=rule_id,
                        source_path=source_path,
                        line_number=node.lineno,
                        analyzer=literal_string(argument_value(node, "analyzer")),
                        category=literal_enum(argument_value(node, "category"), ThreatCategory),
                        severity=literal_enum(argument_value(node, "severity"), Severity),
                    )
                )

        for implementation in literal_findings:
            definition = definitions.get(implementation.rule_id)
            if definition is None or definition.source_type != "python":
                continue
            location = f"{implementation.source_path}:{implementation.line_number}"
            if implementation.analyzer is not None and implementation.analyzer != definition.analyzer:
                raise ValueError(
                    f"Bundled Python analyzer metadata mismatch for {implementation.rule_id!r} at {location}: "
                    f"pack.yaml={definition.analyzer!r}, implementation={implementation.analyzer!r}"
                )
            if implementation.category is not None and implementation.category != definition.category:
                raise ValueError(
                    f"Bundled Python category metadata mismatch for {implementation.rule_id!r} at {location}: "
                    f"pack.yaml={definition.category!r}, implementation={implementation.category!r}"
                )
            if implementation.severity is not None:
                accepted_severities = {definition.default_severity, *definition.allowed_severity_demotions}
                if implementation.severity not in accepted_severities:
                    raise ValueError(
                        f"Bundled Python severity metadata mismatch for {implementation.rule_id!r} at {location}: "
                        f"pack.yaml={sorted(accepted_severities)!r}, implementation={implementation.severity!r}"
                    )

        for rule_id, indirect_implementation in indirect_implementations.items():
            if rule_id != indirect_implementation.rule_id:
                raise ValueError(
                    f"Bundled indirect Python inventory identity mismatch: key={rule_id!r}, "
                    f"implementation={indirect_implementation.rule_id!r}"
                )
            definition = definitions.get(rule_id)
            if definition is None or definition.source_type != "python":
                continue
            if indirect_implementation.analyzer != definition.analyzer:
                raise ValueError(
                    f"Bundled indirect Python analyzer metadata mismatch for {rule_id!r}: "
                    f"pack.yaml={definition.analyzer!r}, implementation={indirect_implementation.analyzer!r}"
                )
            if indirect_implementation.category.value != definition.category:
                raise ValueError(
                    f"Bundled indirect Python category metadata mismatch for {rule_id!r}: "
                    f"pack.yaml={definition.category!r}, implementation={indirect_implementation.category.value!r}"
                )
            if indirect_implementation.max_severity.value != definition.default_severity:
                raise ValueError(
                    f"Bundled indirect Python severity metadata mismatch for {rule_id!r}: "
                    f"pack.yaml={definition.default_severity!r}, "
                    f"implementation={indirect_implementation.max_severity.value!r}"
                )
            implementation_demotions = frozenset(
                severity.value for severity in indirect_implementation.allowed_severity_demotions
            )
            if implementation_demotions != definition.allowed_severity_demotions:
                raise ValueError(
                    f"Bundled indirect Python severity-demotion metadata mismatch for {rule_id!r}: "
                    f"pack.yaml={sorted(definition.allowed_severity_demotions)!r}, "
                    f"implementation={sorted(implementation_demotions)!r}"
                )

        actual = literal_ids | set(indirect_implementations)
        missing = sorted(declared - actual)
        orphaned = sorted(actual - declared)
        if missing:
            raise ValueError(f"Missing bundled Python implementation(s): {', '.join(missing)}")
        if orphaned:
            raise ValueError("Bundled Python implementation(s) not declared in pack.yaml: " + ", ".join(orphaned))
        return len(actual)

    def _validate_bundled_implementations(
        self,
        pack_path: Path,
        definitions: dict[str, RuleDefinition],
        manifest_rules: dict[str, dict[str, Any]],
        signatures_file: Path | None,
        signatures_dir: Path | None,
        yara_dirs: list[Path],
    ) -> PackValidationReport:
        """Validate bundled implementation identity and declared metadata.

        The implementation inventory is shared by strict schema-v2 loading and
        the compatibility reporter. Missing category/severity values remain
        visible promotion blockers on the compatibility path.
        """

        signature_implementations = self._load_bundled_signature_metadata(
            pack_path,
            signatures_file,
            signatures_dir,
        )
        declared_signatures = {
            rule_id for rule_id, definition in definitions.items() if definition.source_type == "signature"
        }
        actual_signatures = set(signature_implementations)
        missing_signatures = sorted(declared_signatures - actual_signatures)
        orphaned_signatures = sorted(actual_signatures - declared_signatures)
        if missing_signatures:
            raise ValueError(f"Missing bundled signature implementation(s): {', '.join(missing_signatures)}")
        if orphaned_signatures:
            raise ValueError(
                f"Bundled signature implementation(s) not declared in pack.yaml: {', '.join(orphaned_signatures)}"
            )

        for rule_id in sorted(declared_signatures):
            implementation, source_path = signature_implementations[rule_id]
            definition = definitions[rule_id]
            if definition.category and implementation["category"] != definition.category:
                raise ValueError(
                    f"Category metadata mismatch for bundled rule {rule_id}: "
                    f"pack.yaml={definition.category!r}, signature={implementation['category']!r}"
                )
            implementation_severity = _normalise_severity(implementation["severity"], str(source_path))
            if definition.default_severity and implementation_severity != definition.default_severity.upper():
                raise ValueError(
                    f"Severity metadata mismatch for bundled rule {rule_id}: "
                    f"pack.yaml={definition.default_severity!r}, signature={implementation_severity!r}"
                )

            declared_file = manifest_rules[rule_id].get("file")
            if declared_file is not None:
                if not isinstance(declared_file, str):
                    raise ValueError(f"Bundled rule {rule_id}.file must be a string")
                actual_file = source_path.relative_to(pack_path).as_posix()
                if declared_file != actual_file:
                    raise ValueError(
                        f"Implementation file mismatch for bundled rule {rule_id}: "
                        f"pack.yaml={declared_file!r}, actual={actual_file!r}"
                    )

        compiled_yara = self._compile_bundled_yara(pack_path, yara_dirs)
        yara_implementations: dict[str, Any] = {}
        for compiled_rule in compiled_yara:
            rule_id = f"YARA_{compiled_rule.identifier}"
            if rule_id in yara_implementations:
                raise ValueError(f"Duplicate bundled YARA implementation for rule {rule_id!r}")
            yara_implementations[rule_id] = compiled_rule

        declared_yara = {rule_id for rule_id, definition in definitions.items() if definition.source_type == "yara"}
        actual_yara = set(yara_implementations)
        missing_yara = sorted(declared_yara - actual_yara)
        orphaned_yara = sorted(actual_yara - declared_yara)
        if missing_yara:
            raise ValueError(f"Missing bundled YARA implementation(s): {', '.join(missing_yara)}")
        if orphaned_yara:
            raise ValueError(f"Bundled YARA implementation(s) not declared in pack.yaml: {', '.join(orphaned_yara)}")

        for rule_id in sorted(declared_yara):
            definition = definitions[rule_id]
            metadata = dict(yara_implementations[rule_id].metadata)
            implementation_category = metadata.get("category")
            if definition.category and implementation_category is not None:
                if implementation_category != definition.category:
                    raise ValueError(
                        f"Category metadata mismatch for bundled rule {rule_id}: "
                        f"pack.yaml={definition.category!r}, YARA={implementation_category!r}"
                    )
            if definition.default_severity and "severity" in metadata:
                implementation_severity = _normalise_severity(metadata["severity"], f"YARA rule {rule_id}")
                if implementation_severity != definition.default_severity.upper():
                    raise ValueError(
                        f"Severity metadata mismatch for bundled rule {rule_id}: "
                        f"pack.yaml={definition.default_severity!r}, YARA={implementation_severity!r}"
                    )

        incomplete_metadata = tuple(
            sorted(
                rule_id
                for rule_id, definition in definitions.items()
                if not definition.category or not definition.default_severity
            )
        )
        blockers = ["manifest does not declare schema_version: 2"]
        if incomplete_metadata:
            counts: dict[str, int] = {}
            for rule_id in incomplete_metadata:
                source = definitions[rule_id].source_type
                counts[source] = counts.get(source, 0) + 1
            breakdown = ", ".join(f"{source}={count}" for source, count in sorted(counts.items()))
            blockers.append(f"{len(incomplete_metadata)} rule(s) lack manifest category/severity ({breakdown})")
        unsupported_categories = sorted(
            {
                definition.category
                for definition in definitions.values()
                if definition.category and definition.category not in _THREAT_CATEGORIES
            }
        )
        if unsupported_categories:
            affected_count = sum(definition.category in unsupported_categories for definition in definitions.values())
            blockers.append(
                f"{affected_count} rule(s) use categories outside the schema-v2 enum "
                f"({', '.join(unsupported_categories)})"
            )

        return PackValidationReport(
            schema_status="legacy",
            validation_scope="implementation_identity_and_declared_metadata",
            signature_implementation_count=len(signature_implementations),
            yara_implementation_count=len(yara_implementations),
            metadata_incomplete_rule_ids=incomplete_metadata,
            promotion_blockers=tuple(blockers),
        )

    def load_bundled_pack(self, path: Path | str) -> RulePack:
        """Load one release-owned schema-v2 pack with strict validation.

        Bundled packs may declare Python implementations and reviewed tuning
        knobs.  That is the only difference from administrator-trusted local
        packs: local packs continue to reject imported Python code.  Both
        paths reject unknown fields, unknown enums, malformed implementations,
        duplicate IDs, and manifest/implementation metadata drift.
        """

        requested_path = Path(path)
        try:
            pack_path = requested_path.resolve(strict=True)
        except OSError as exc:
            raise FileNotFoundError(f"Bundled rule-pack path not found: {requested_path}") from exc
        if not pack_path.is_dir():
            raise ValueError(f"Bundled rule-pack path is not a directory: {requested_path}")

        manifest_path = pack_path / "pack.yaml"
        if not manifest_path.is_file():
            raise FileNotFoundError(f"Pack manifest not found: {manifest_path}")
        if manifest_path.is_symlink():
            raise ValueError(f"Bundled pack manifest may not be a symlink: {manifest_path}")

        raw = _load_strict_yaml(manifest_path)
        if not isinstance(raw, dict):
            raise ValueError(f"Bundled pack manifest must be a mapping: {manifest_path}")
        _unknown_fields(raw, _TRUSTED_PACK_FIELDS, "bundled pack manifest")
        schema_version = raw.get("schema_version")
        if type(schema_version) is not int or schema_version != _TRUSTED_PACK_SCHEMA_VERSION:
            raise ValueError(
                f"Bundled pack requires schema_version: {_TRUSTED_PACK_SCHEMA_VERSION}; got {schema_version!r}"
            )

        pack_name = _required_string(raw, "name", "bundled pack manifest")
        if pack_name != pack_name.strip():
            raise ValueError("bundled pack manifest.name may not contain surrounding whitespace")
        version = raw.get("version", "0.0")
        if not isinstance(version, (str, int, float)) or isinstance(version, bool):
            raise ValueError("bundled pack manifest.version must be a string or number")
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise ValueError("bundled pack manifest.description must be a string")
        pack_metadata = _optional_pack_metadata(raw, "bundled pack manifest")
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, dict) or not raw_rules:
            raise ValueError("bundled pack manifest.rules must be a non-empty mapping keyed by rule ID")

        definitions: dict[str, RuleDefinition] = {}
        manifest_rules: dict[str, dict[str, Any]] = {}
        for raw_rule_id, raw_rule in raw_rules.items():
            if not isinstance(raw_rule_id, str) or not raw_rule_id.strip():
                raise ValueError("Bundled rule IDs must be non-empty strings")
            rule_id = raw_rule_id
            if rule_id != rule_id.strip():
                raise ValueError(f"Bundled rule ID {rule_id!r} may not contain surrounding whitespace")
            context = f"bundled rule {rule_id}"
            if not isinstance(raw_rule, dict):
                raise ValueError(f"{context} must be a mapping")
            _unknown_fields(raw_rule, _BUNDLED_V2_RULE_FIELDS, context)

            source = _required_string(raw_rule, "source", context)
            if source not in _BUNDLED_SOURCES:
                raise ValueError(f"Unknown rule source {source!r} in {context}")
            category = _required_string(raw_rule, "category", context)
            if category not in _THREAT_CATEGORIES:
                raise ValueError(f"Unknown category {category!r} in {context}")
            severity = _normalise_severity(raw_rule.get("severity"), context)
            raw_demotions = raw_rule.get("allowed_severity_demotions", [])
            if not isinstance(raw_demotions, list):
                raise ValueError(f"{context}.allowed_severity_demotions must be a list")
            demotions = [_normalise_severity(value, context) for value in raw_demotions]
            if len(set(demotions)) != len(demotions):
                raise ValueError(f"{context}.allowed_severity_demotions contains duplicates")
            for demotion in demotions:
                if _SEVERITY_RANK[demotion] >= _SEVERITY_RANK[severity]:
                    raise ValueError(
                        f"{context}.allowed_severity_demotions must contain only severities below {severity}"
                    )

            knobs_raw = raw_rule.get("knobs", {"enabled": True})
            if not isinstance(knobs_raw, dict):
                raise ValueError(f"{context}.knobs must be a mapping")
            _unknown_fields(knobs_raw, _BUNDLED_V2_KNOB_FIELDS, f"{context}.knobs")
            knobs = dict(knobs_raw)
            knobs.setdefault("enabled", True)
            if type(knobs["enabled"]) is not bool:
                raise ValueError(f"{context}.knobs.enabled must be a boolean")

            analyzer = raw_rule.get("analyzer", "")
            if source == "python":
                if not isinstance(analyzer, str) or analyzer not in _BUNDLED_ANALYZERS:
                    raise ValueError(f"{context}.analyzer must name a supported built-in analyzer")
            elif analyzer:
                raise ValueError(f"{context}.analyzer is only valid for source: python")

            description_value = raw_rule.get("description", "")
            remediation = raw_rule.get("remediation", "")
            if not isinstance(description_value, str) or not isinstance(remediation, str):
                raise ValueError(f"{context}.description and remediation must be strings")
            file_types = raw_rule.get("file_types", [])
            if not isinstance(file_types, list) or not all(
                isinstance(item, str) and item.strip() for item in file_types
            ):
                raise ValueError(f"{context}.file_types must be a list of non-empty strings")

            cel_rule = self._parse_cel(rule_id, pack_name, raw_rule.get("cel"))
            definitions[rule_id] = RuleDefinition(
                id=rule_id,
                source_type=source,
                pack_name=pack_name,
                knobs=knobs,
                description=description_value,
                category=category,
                default_severity=severity,
                allowed_severity_demotions=frozenset(demotions),
                analyzer=analyzer,
                file_types=list(file_types),
                remediation=remediation,
                cel=cel_rule,
            )
            manifest_rules[rule_id] = raw_rule

        signatures_file, signatures_dir, yara_dirs = self._locate_implementations(pack_path, strict=True)
        implementation_report = self._validate_bundled_implementations(
            pack_path,
            definitions,
            manifest_rules,
            signatures_file,
            signatures_dir,
            yara_dirs,
        )
        python_implementation_count = self._validate_bundled_python_implementations(definitions)
        signature_metadata = self._load_bundled_signature_metadata(
            pack_path,
            signatures_file,
            signatures_dir,
        )
        return RulePack(
            name=pack_name,
            version=str(version),
            description=description,
            path=pack_path,
            **pack_metadata,
            rules=definitions,
            signatures_file=signatures_file,
            signatures_dir=signatures_dir,
            yara_dirs=yara_dirs,
            schema_version=schema_version,
            trusted=False,
            signature_rules=[item for item, _source in signature_metadata.values()],
            validation_report=PackValidationReport(
                schema_status="v2",
                validation_scope="strict_bundled_v2",
                signature_implementation_count=implementation_report.signature_implementation_count,
                yara_implementation_count=implementation_report.yara_implementation_count,
                python_implementation_count=python_implementation_count,
            ),
        )

    def load_pack(self, path: Path | str, *, validate_implementations: bool = False) -> RulePack:
        """Load a single rule pack from *path*.

        The directory must contain a ``pack.yaml`` manifest.

        Returns:
            A fully populated :class:`RulePack`.

        Raises:
            FileNotFoundError: If the directory or ``pack.yaml`` is missing.
            ValueError: On malformed manifest data.
        """
        path = Path(path)
        manifest_path = path / "pack.yaml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Pack manifest not found: {manifest_path}")

        loaded = _load_strict_yaml(manifest_path) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Pack manifest must be a mapping: {manifest_path}")
        raw: dict[str, Any] = loaded
        if "schema_version" in raw:
            declared_schema = raw["schema_version"]
            if declared_schema == _TRUSTED_PACK_SCHEMA_VERSION:
                raise ValueError(
                    "schema_version: 2 manifests require the strict trusted-pack loader; use load_trusted_pack()"
                )
            raise ValueError(f"Unsupported rule-pack schema_version: {declared_schema!r}")

        # Core's original manifest uses top-level metadata and a rules
        # mapping.  The bundled ATR and PromptGuard manifests use a nested
        # ``pack`` mapping and a rules list.  Both remain supported on the
        # legacy path while trusted local packs require schema v2.
        pack_value = raw.get("pack")
        pack_metadata: dict[str, Any] = pack_value if isinstance(pack_value, dict) else {}
        pack_name = raw.get("name") or pack_metadata.get("id") or path.name
        pack_version = str(raw.get("version") or pack_metadata.get("version") or "0.0")
        pack_desc = raw.get("description") or pack_metadata.get("description") or ""

        # Build RuleDefinition objects from the ``rules:`` section
        rules: dict[str, RuleDefinition] = {}
        manifest_rules: dict[str, dict[str, Any]] = {}
        rules_section = raw.get("rules") or {}
        if isinstance(rules_section, dict):
            rule_entries = list(rules_section.items())
        elif isinstance(rules_section, list):
            rule_entries = [(entry.get("id", "") if isinstance(entry, dict) else "", entry) for entry in rules_section]
        else:
            raise ValueError(f"Pack rules must be a mapping or list: {manifest_path}")

        seen_rule_ids: set[str] = set()
        for rule_id, rule_data in rule_entries:
            if not isinstance(rule_data, dict):
                if validate_implementations:
                    raise ValueError(f"Rule entry {rule_id!r} in pack {pack_name!r} must be a mapping")
                logger.warning("Skipping non-dict rule entry '%s' in pack '%s'", rule_id, pack_name)
                continue
            if not isinstance(rule_id, str) or not rule_id.strip():
                if validate_implementations:
                    raise ValueError(f"Every rule in bundled pack {pack_name!r} must have a non-empty string ID")
                logger.warning("Skipping rule without an ID in pack '%s'", pack_name)
                continue
            if rule_id != rule_id.strip():
                raise ValueError(f"Rule ID {rule_id!r} in pack {pack_name!r} may not contain surrounding whitespace")
            declared_id = rule_data.get("id")
            if declared_id is not None and declared_id != rule_id:
                raise ValueError(
                    f"Rule identity mismatch in pack {pack_name!r}: mapping key {rule_id!r} declares id {declared_id!r}"
                )
            if rule_id in seen_rule_ids:
                raise ValueError(f"Duplicate rule ID {rule_id!r} in pack {pack_name!r}")
            seen_rule_ids.add(rule_id)

            knobs_raw = rule_data.get("knobs") or {"enabled": True}
            if not isinstance(knobs_raw, dict):
                raise ValueError(f"Rule {rule_id}.knobs must be a mapping")
            knobs = dict(knobs_raw)
            # Guarantee every rule has an ``enabled`` knob
            knobs.setdefault("enabled", True)
            if validate_implementations and type(knobs["enabled"]) is not bool:
                raise ValueError(f"Rule {rule_id}.knobs.enabled must be a boolean")

            source_type = rule_data.get("source")
            if not source_type:
                # Bundled community manifests enumerate signature files in
                # their nested pack metadata and identify each rule's file.
                source_type = "signature" if rule_data.get("file") else "python"
            if not isinstance(source_type, str) or source_type not in _BUNDLED_SOURCES:
                raise ValueError(f"Unknown rule source {source_type!r} in bundled rule {rule_id}")

            if validate_implementations:
                category = rule_data.get("category", "")
                if category and not isinstance(category, str):
                    raise ValueError(f"Rule {rule_id}.category must be a string")
                severity = rule_data.get("severity", "")
                if severity:
                    _normalise_severity(severity, f"bundled rule {rule_id}")
                analyzer = rule_data.get("analyzer", "")
                if source_type == "python" and (not isinstance(analyzer, str) or not analyzer.strip()):
                    raise ValueError(f"Bundled Python rule {rule_id}.analyzer must be a non-empty string")

            description = rule_data.get("description", "")
            remediation = rule_data.get("remediation", "")
            file_types = rule_data.get("file_types", [])
            if not isinstance(description, str) or not isinstance(remediation, str):
                raise ValueError(f"Rule {rule_id}.description and remediation must be strings")
            if not isinstance(file_types, list) or not all(isinstance(item, str) for item in file_types):
                raise ValueError(f"Rule {rule_id}.file_types must be a list of strings")

            rules[rule_id] = RuleDefinition(
                id=rule_id,
                source_type=source_type,
                pack_name=str(pack_name),
                knobs=knobs,
                description=description,
                category=rule_data.get("category", ""),
                default_severity=rule_data.get("severity", ""),
                analyzer=rule_data.get("analyzer", ""),
                file_types=file_types,
                remediation=remediation,
            )
            manifest_rules[rule_id] = rule_data

        signatures_file, signatures_dir, yara_dirs = self._locate_implementations(path)
        validation_report = PackValidationReport(
            schema_status="legacy",
            validation_scope="not_run",
            promotion_blockers=("manifest does not declare schema_version: 2",),
        )
        if validate_implementations:
            validation_report = self._validate_bundled_implementations(
                path,
                rules,
                manifest_rules,
                signatures_file,
                signatures_dir,
                yara_dirs,
            )

        return RulePack(
            name=str(pack_name),
            version=pack_version,
            description=pack_desc,
            path=path,
            rules=rules,
            signatures_file=signatures_file,
            signatures_dir=signatures_dir,
            yara_dirs=yara_dirs,
            validation_report=validation_report,
        )

    def load_trusted_pack(self, path: Path | str) -> RulePack:
        """Load and fully validate an administrator-approved local v2 pack.

        Unlike :meth:`load_pack`, this entry point is deliberately fail-fast:
        unknown schema fields, metadata drift, missing or duplicate
        implementations, malformed regex/YARA, and out-of-policy CEL all make
        the complete pack unusable.
        """

        requested_path = Path(path)
        try:
            pack_path = requested_path.resolve(strict=True)
        except OSError as exc:
            raise FileNotFoundError(f"Trusted rule-pack path not found: {requested_path}") from exc
        if not pack_path.is_dir():
            raise ValueError(f"Trusted rule-pack path is not a directory: {requested_path}")

        manifest_path = pack_path / "pack.yaml"
        if not manifest_path.is_file():
            raise FileNotFoundError(f"Pack manifest not found: {manifest_path}")
        if manifest_path.is_symlink():
            raise ValueError(f"Trusted pack manifest may not be a symlink: {manifest_path}")
        raw = _load_strict_yaml(manifest_path)
        if not isinstance(raw, dict):
            raise ValueError(f"Trusted pack manifest must be a mapping: {manifest_path}")
        _unknown_fields(raw, _TRUSTED_PACK_FIELDS, "trusted pack manifest")

        schema_version = raw.get("schema_version")
        if type(schema_version) is not int or schema_version != _TRUSTED_PACK_SCHEMA_VERSION:
            raise ValueError(
                f"Trusted pack requires schema_version: {_TRUSTED_PACK_SCHEMA_VERSION}; got {schema_version!r}"
            )
        pack_name = _required_string(raw, "name", "trusted pack manifest")
        if pack_name != pack_name.strip():
            raise ValueError("trusted pack manifest.name may not contain surrounding whitespace")
        version = raw.get("version", "0.0")
        if not isinstance(version, (str, int, float)) or isinstance(version, bool):
            raise ValueError("trusted pack manifest.version must be a string or number")
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise ValueError("trusted pack manifest.description must be a string")
        pack_metadata = _optional_pack_metadata(raw, "trusted pack manifest")
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, dict):
            raise ValueError("trusted pack manifest.rules must be a mapping keyed by rule ID")
        if not raw_rules:
            raise ValueError("trusted pack manifest.rules must contain at least one rule")

        definitions: dict[str, RuleDefinition] = {}
        manifest_rules: dict[str, dict[str, Any]] = {}
        for raw_rule_id, raw_rule in raw_rules.items():
            if not isinstance(raw_rule_id, str) or not raw_rule_id.strip():
                raise ValueError("Trusted rule IDs must be non-empty strings")
            rule_id = raw_rule_id
            if rule_id != rule_id.strip():
                raise ValueError(f"Trusted rule ID {rule_id!r} may not contain surrounding whitespace")
            context = f"rule {rule_id}"
            if not isinstance(raw_rule, dict):
                raise ValueError(f"{context} must be a mapping")
            _unknown_fields(raw_rule, _TRUSTED_RULE_FIELDS, context)
            source = _required_string(raw_rule, "source", context)
            if source == "python":
                raise ValueError(f"Trusted local pack rule {rule_id} may not load Python implementations")
            if source not in _TRUSTED_SOURCES:
                raise ValueError(f"Unknown rule source {source!r} in {context}")

            category = _required_string(raw_rule, "category", context)
            if category not in _THREAT_CATEGORIES:
                raise ValueError(f"Unknown category {category!r} in {context}")
            severity = _normalise_severity(raw_rule.get("severity"), context)

            knobs_raw = raw_rule.get("knobs", {"enabled": True})
            if not isinstance(knobs_raw, dict):
                raise ValueError(f"{context}.knobs must be a mapping")
            _unknown_fields(knobs_raw, _TRUSTED_KNOB_FIELDS, f"{context}.knobs")
            knobs = dict(knobs_raw)
            knobs.setdefault("enabled", True)
            if type(knobs["enabled"]) is not bool:
                raise ValueError(f"{context}.knobs.enabled must be a boolean")

            description_value = raw_rule.get("description", "")
            remediation = raw_rule.get("remediation", "")
            if not isinstance(description_value, str) or not isinstance(remediation, str):
                raise ValueError(f"{context}.description and remediation must be strings")
            file_types = raw_rule.get("file_types", [])
            if not isinstance(file_types, list) or not all(
                isinstance(item, str) and item.strip() for item in file_types
            ):
                raise ValueError(f"{context}.file_types must be a list of non-empty strings")

            cel_rule = self._parse_cel(rule_id, pack_name, raw_rule.get("cel"))
            definitions[rule_id] = RuleDefinition(
                id=rule_id,
                source_type=source,
                pack_name=pack_name,
                knobs=knobs,
                description=description_value,
                category=category,
                default_severity=severity,
                file_types=list(file_types),
                remediation=remediation,
                cel=cel_rule,
            )
            manifest_rules[rule_id] = raw_rule

        signatures_file, signatures_dir, yara_dirs = self._locate_implementations(pack_path, strict=True)
        signature_rules = self._load_trusted_signatures(
            pack_path,
            signatures_file,
            signatures_dir,
            definitions,
            manifest_rules,
        )
        self._validate_trusted_yara(pack_path, yara_dirs, definitions)

        return RulePack(
            name=pack_name,
            version=str(version),
            description=description,
            path=pack_path,
            **pack_metadata,
            rules=definitions,
            signatures_file=signatures_file,
            signatures_dir=signatures_dir,
            yara_dirs=yara_dirs,
            schema_version=schema_version,
            trusted=True,
            signature_rules=signature_rules,
            validation_report=PackValidationReport(
                schema_status="v2",
                validation_scope="strict_v2",
                signature_implementation_count=len(signature_rules),
                yara_implementation_count=sum(definition.source_type == "yara" for definition in definitions.values()),
            ),
        )

    def discover_packs(
        self,
        built_in_dir: Path | None = None,
        extra_dirs: list[Path | str] | None = None,
        trusted_dirs: list[Path | str] | None = None,
    ) -> list[RulePack]:
        """Discover and load all rule packs.

        Packs are loaded in order:

        1. Built-in packs from *built_in_dir* (default:
           ``skill_scanner/data/packs/``).
        2. Extra packs from each directory in *extra_dirs*.

        Returns:
            Ordered list of loaded packs (built-in first).
        """
        packs: list[RulePack] = []

        if built_in_dir is None:
            packs.extend(_get_validated_built_in_packs())
        elif built_in_dir.is_dir():
            for child in sorted(built_in_dir.iterdir()):
                if child.is_dir() and (child / "pack.yaml").exists():
                    # An explicit directory is commonly used by tests and
                    # development tools, so validate it fresh instead of
                    # mixing it into the installed-artifact process cache.
                    packs.append(self.load_bundled_pack(child))

        for extra in extra_dirs or []:
            extra = Path(extra)
            if not extra.is_dir():
                logger.warning("Extra rule-pack path is not a directory: %s", extra)
                continue
            # If the directory itself is a pack, load it directly
            if (extra / "pack.yaml").exists():
                try:
                    packs.append(self.load_pack(extra))
                except Exception as exc:
                    logger.warning("Failed to load extra pack '%s': %s", extra, exc)
            else:
                # Otherwise iterate subdirectories
                for child in sorted(extra.iterdir()):
                    if child.is_dir() and (child / "pack.yaml").exists():
                        try:
                            packs.append(self.load_pack(child))
                        except Exception as exc:
                            logger.warning("Failed to load extra pack '%s': %s", child.name, exc)

        # Trusted paths are explicit pack roots, never discovery roots.  Their
        # validation errors are intentionally allowed to abort startup.
        for trusted in trusted_dirs or []:
            packs.append(self.load_trusted_pack(trusted))

        return packs

    def build_registry(
        self,
        built_in_dir: Path | None = None,
        extra_dirs: list[Path | str] | None = None,
        trusted_dirs: list[Path | str] | None = None,
    ) -> RuleRegistry:
        """Convenience: discover packs and build a populated registry."""
        registry = RuleRegistry()
        for pack in self.discover_packs(
            built_in_dir=built_in_dir,
            extra_dirs=extra_dirs,
            trusted_dirs=trusted_dirs,
        ):
            registry.register_pack(pack)
        return registry


def _get_validated_built_in_packs() -> list[RulePack]:
    """Return isolated copies of the once-validated bundled generation."""

    global _BUILT_IN_PACK_SNAPSHOT
    if _BUILT_IN_PACK_SNAPSHOT is None:
        with _BUILT_IN_PACK_SNAPSHOT_LOCK:
            if _BUILT_IN_PACK_SNAPSHOT is None:
                loader = PackLoader()
                pack_root = loader._BUILT_IN_PACKS_DIR
                loaded: list[RulePack] = []
                if pack_root.is_dir():
                    for child in sorted(pack_root.iterdir()):
                        if child.is_dir() and (child / "pack.yaml").exists():
                            loaded.append(loader.load_bundled_pack(child))
                _BUILT_IN_PACK_SNAPSHOT = tuple(loaded)

    # RulePack and RuleDefinition expose mutable dict/list fields for legacy
    # compatibility.  Never return the cached objects themselves.
    return copy.deepcopy(list(_BUILT_IN_PACK_SNAPSHOT))
