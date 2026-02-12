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

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

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

    analyzer: str = ""
    """For ``python`` rules – the analyzer class that implements the check."""

    file_types: list[str] = field(default_factory=list)
    """For ``signature`` rules – which file types the rule applies to."""

    remediation: str = ""
    """Suggested fix for a true positive."""


@dataclass
class RulePack:
    """A collection of rules loaded from a single pack directory.

    Attributes:
        name: Pack name from ``pack.yaml`` (e.g. ``"core"``).
        version: Semantic version string.
        description: Human-readable description.
        path: Filesystem path to the pack directory.
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
        for rule_id, rule_def in pack.rules.items():
            if rule_id in self._rules:
                existing = self._rules[rule_id]
                if existing.pack_name != pack.name:
                    raise ValueError(
                        f"Rule ID collision: '{rule_id}' is defined in both "
                        f"pack '{existing.pack_name}' and pack '{pack.name}'"
                    )
                # Same pack re-registered (idempotent) – overwrite silently
            self._rules[rule_id] = rule_def
        self._packs[pack.name] = pack

    def register(self, rule: RuleDefinition) -> None:
        """Register a single rule (convenience for tests)."""
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

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules


# ---------------------------------------------------------------------------
# Pack loader
# ---------------------------------------------------------------------------

# Pattern to extract YARA rule names from source (e.g. "rule foo_bar {")
_YARA_RULE_NAME_RE = re.compile(r"^rule\s+(\w+)", re.MULTILINE)


class PackLoader:
    """Discovers and loads rule packs from filesystem directories."""

    # Default location of the built-in core pack
    _BUILT_IN_PACKS_DIR: Path = Path(__file__).parent.parent / "data" / "packs"

    def load_pack(self, path: Path) -> RulePack:
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

        with open(manifest_path, encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}

        pack_name = raw.get("name", path.name)
        pack_version = str(raw.get("version", "0.0"))
        pack_desc = raw.get("description", "")

        # Build RuleDefinition objects from the ``rules:`` section
        rules: dict[str, RuleDefinition] = {}
        for rule_id, rule_data in (raw.get("rules") or {}).items():
            rule_id = str(rule_id)
            if not isinstance(rule_data, dict):
                logger.warning("Skipping non-dict rule entry '%s' in pack '%s'", rule_id, pack_name)
                continue

            knobs = dict(rule_data.get("knobs") or {"enabled": True})
            # Guarantee every rule has an ``enabled`` knob
            knobs.setdefault("enabled", True)

            rules[rule_id] = RuleDefinition(
                id=rule_id,
                source_type=rule_data.get("source", "python"),
                pack_name=pack_name,
                knobs=knobs,
                description=rule_data.get("description", ""),
                category=rule_data.get("category", ""),
                default_severity=rule_data.get("severity", ""),
                analyzer=rule_data.get("analyzer", ""),
                file_types=rule_data.get("file_types", []),
                remediation=rule_data.get("remediation", ""),
            )

        # Locate signature rule files.
        # Prefer a ``signatures/`` directory (new layout) over a single
        # ``signatures.yaml`` (legacy layout).
        signatures_file: Path | None = None
        signatures_dir: Path | None = None
        sigs_dir_path = path / "signatures"
        sigs_file_path = path / "signatures.yaml"
        if sigs_dir_path.is_dir() and list(sigs_dir_path.glob("*.yaml")):
            signatures_dir = sigs_dir_path
        elif sigs_file_path.exists():
            signatures_file = sigs_file_path

        yara_dirs: list[Path] = []
        # Check for a ``yara/`` subdirectory or ``.yara`` files in the root
        yara_sub = path / "yara"
        if yara_sub.is_dir() and list(yara_sub.glob("*.yara")):
            yara_dirs.append(yara_sub)
        elif list(path.glob("*.yara")):
            yara_dirs.append(path)

        return RulePack(
            name=pack_name,
            version=pack_version,
            description=pack_desc,
            path=path,
            rules=rules,
            signatures_file=signatures_file,
            signatures_dir=signatures_dir,
            yara_dirs=yara_dirs,
        )

    def discover_packs(
        self,
        built_in_dir: Path | None = None,
        extra_dirs: list[Path | str] | None = None,
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

        search_dir = built_in_dir or self._BUILT_IN_PACKS_DIR
        if search_dir.is_dir():
            for child in sorted(search_dir.iterdir()):
                if child.is_dir() and (child / "pack.yaml").exists():
                    try:
                        packs.append(self.load_pack(child))
                    except Exception as exc:
                        logger.warning("Failed to load built-in pack '%s': %s", child.name, exc)

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

        return packs

    def build_registry(
        self,
        built_in_dir: Path | None = None,
        extra_dirs: list[Path | str] | None = None,
    ) -> RuleRegistry:
        """Convenience: discover packs and build a populated registry."""
        registry = RuleRegistry()
        for pack in self.discover_packs(built_in_dir=built_in_dir, extra_dirs=extra_dirs):
            registry.register_pack(pack)
        return registry
