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
Cisco AI Security and Safety Taxonomy.

The scanner ships a pinned, reduced snapshot of the taxonomy in
``skill_scanner/data/taxonomy/cisco_ai_taxonomy.json``.  The snapshot keeps
objective, AITech and AISubtech codes, their official names, the parent/child
structure, and the external framework crosswalks (OWASP, MITRE ATLAS,
NIST AML).  ``provenance.yaml`` next to it records the source commit and the
SHA-256 of both the source file and the snapshot.  The snapshot is read once
at import and is never fetched or refreshed at runtime.

Rules select an AISubtech code (or an AITech code when no sub-technique
applies); the snapshot supplies the parent AITech, the names and the
crosswalks.  Every code the scanner emits must exist in the active taxonomy.

To update the bundled snapshot, run ``scripts/update_taxonomy_snapshot.py``.
A different taxonomy can be loaded at runtime with ``--taxonomy`` or
``SKILL_SCANNER_TAXONOMY_PATH``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "taxonomy"
BUILTIN_SNAPSHOT_PATH = _DATA_DIR / "cisco_ai_taxonomy.json"
BUILTIN_PROVENANCE_PATH = _DATA_DIR / "provenance.yaml"

_AISUBTECH_CODE_RE = re.compile(r"^AISubtech-(\d+\.\d+)\.\d+$")


@dataclass(frozen=True)
class _ParsedTaxonomy:
    """Canonical in-memory form of one taxonomy payload."""

    aitech: dict[str, str]
    aisubtech: dict[str, str]
    aitech_framework_mappings: dict[str, list[str]]
    aisubtech_framework_mappings: dict[str, list[str]]
    aisubtech_parents: dict[str, str]
    version: str | None = None
    provenance: dict[str, str] = field(default_factory=dict)


def _read_taxonomy_file(path: Path) -> dict[str, Any]:
    """Read taxonomy JSON/YAML file into a dictionary."""
    if not path.exists():
        raise FileNotFoundError(f"Taxonomy file not found: {path}")

    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        import yaml

        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        loaded = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(loaded, dict):
        raise ValueError("Taxonomy file must parse to a JSON/YAML object")
    return loaded


def _normalize_mapping_list(value: Any) -> list[str]:
    """Normalize framework mapping payload values to a list of strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Framework mappings must be a list of strings")

    mappings: list[str] = []
    for raw in value:
        text = str(raw).strip()
        if text and text not in mappings:
            mappings.append(text)
    return mappings


def _coerce_framework_mapping_dict(value: Any, field_name: str) -> dict[str, list[str]]:
    """Parse code -> framework mapping dictionary."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object mapping codes to lists")

    out: dict[str, list[str]] = {}
    for code, mappings in value.items():
        out[str(code)] = _normalize_mapping_list(mappings)
    return out


def _numbered_parent(aisubtech_code: str, aitech_codes: dict[str, str]) -> str | None:
    """Return the AITech that ``AISubtech-X.Y.Z`` is numbered under, if it exists."""
    match = _AISUBTECH_CODE_RE.match(aisubtech_code)
    if match is None:
        return None
    candidate = f"AITech-{match.group(1)}"
    return candidate if candidate in aitech_codes else None


def _flatten_framework_taxonomy(data: dict[str, Any]) -> _ParsedTaxonomy:
    """Flatten OB-* framework taxonomy into AITech/AISubtech maps.

    Supports the full Cisco framework shape:
      OB-001 -> ai_tech[] -> ai_subtech[]
    """
    aitech: dict[str, str] = {}
    aisubtech: dict[str, str] = {}
    aitech_framework_mappings: dict[str, list[str]] = {}
    aisubtech_framework_mappings: dict[str, list[str]] = {}
    parents: dict[str, str] = {}

    for ob_code, ob in data.items():
        if not ob_code.startswith("OB-") or not isinstance(ob, dict):
            continue

        techniques = ob.get("ai_tech", [])
        if not isinstance(techniques, list):
            continue

        for tech in techniques:
            if not isinstance(tech, dict):
                continue
            tech_code = tech.get("code")
            tech_desc = tech.get("description")
            tech_mappings = _normalize_mapping_list(tech.get("mappings"))
            if isinstance(tech_code, str) and isinstance(tech_desc, str):
                if tech_code in aitech and aitech[tech_code] != tech_desc:
                    raise ValueError(
                        f"Conflicting AITech description for {tech_code}: {aitech[tech_code]!r} vs {tech_desc!r}"
                    )
                aitech[tech_code] = tech_desc
                merged = list(aitech_framework_mappings.get(tech_code, []))
                for entry in tech_mappings:
                    if entry not in merged:
                        merged.append(entry)
                aitech_framework_mappings[tech_code] = merged

            subtechs = tech.get("ai_subtech", [])
            if not isinstance(subtechs, list):
                continue
            for sub in subtechs:
                if not isinstance(sub, dict):
                    continue
                sub_code = sub.get("code")
                sub_desc = sub.get("description")
                sub_mappings = _normalize_mapping_list(sub.get("mappings"))
                if isinstance(sub_code, str) and isinstance(sub_desc, str):
                    if sub_code in aisubtech and aisubtech[sub_code] != sub_desc:
                        raise ValueError(
                            f"Conflicting AISubtech description for {sub_code}: {aisubtech[sub_code]!r} vs {sub_desc!r}"
                        )
                    if isinstance(tech_code, str) and tech_code in aitech:
                        if sub_code in parents and parents[sub_code] != tech_code:
                            raise ValueError(
                                f"AISubtech {sub_code} is listed under both {parents[sub_code]} and {tech_code}"
                            )
                        parents[sub_code] = tech_code
                    aisubtech[sub_code] = sub_desc
                    merged = list(aisubtech_framework_mappings.get(sub_code, []))
                    for entry in sub_mappings:
                        if entry not in merged:
                            merged.append(entry)
                    aisubtech_framework_mappings[sub_code] = merged

    if not aitech:
        raise ValueError("No AITech codes found in OB-* framework taxonomy")
    if not aisubtech:
        raise ValueError("No AISubtech codes found in OB-* framework taxonomy")
    for code in aitech:
        aitech_framework_mappings.setdefault(code, [])
    for code in aisubtech:
        aisubtech_framework_mappings.setdefault(code, [])
    version = data.get("version")
    return _ParsedTaxonomy(
        aitech=aitech,
        aisubtech=aisubtech,
        aitech_framework_mappings=aitech_framework_mappings,
        aisubtech_framework_mappings=aisubtech_framework_mappings,
        aisubtech_parents=parents,
        version=str(version) if version is not None else None,
    )


def _parse_flat_taxonomy(
    data: dict[str, Any],
    *,
    aitech_key: str,
    aisubtech_key: str,
    aitech_mapping_keys: tuple[str, str],
    aisubtech_mapping_keys: tuple[str, str],
    parents_key: str,
) -> _ParsedTaxonomy:
    """Parse one of the flattened ``{code: name}`` dictionary formats."""
    aitech = {str(k): str(v) for k, v in data[aitech_key].items()}
    aisubtech = {str(k): str(v) for k, v in data[aisubtech_key].items()}
    aitech_framework_mappings = _coerce_framework_mapping_dict(
        data.get(aitech_mapping_keys[0]) or data.get(aitech_mapping_keys[1]),
        aitech_mapping_keys[0],
    )
    aisubtech_framework_mappings = _coerce_framework_mapping_dict(
        data.get(aisubtech_mapping_keys[0]) or data.get(aisubtech_mapping_keys[1]),
        aisubtech_mapping_keys[0],
    )
    for code in aitech:
        aitech_framework_mappings.setdefault(code, [])
    for code in aisubtech:
        aisubtech_framework_mappings.setdefault(code, [])

    # Flattened payloads carry no tree.  An explicit parent map wins; otherwise
    # a sub-technique belongs to the AITech its number is nested under, but
    # only when that AITech is present in the same payload.
    explicit = data.get(parents_key)
    if explicit is not None and not isinstance(explicit, dict):
        raise ValueError(f"{parents_key} must be an object mapping AISubtech codes to AITech codes")
    parents: dict[str, str] = {}
    for code in aisubtech:
        parent = str(explicit[code]) if explicit and code in explicit else _numbered_parent(code, aitech)
        if parent is None:
            continue
        if parent not in aitech:
            raise ValueError(f"{parents_key}[{code!r}] names unknown AITech {parent!r}")
        parents[code] = parent

    version = data.get("version")
    return _ParsedTaxonomy(
        aitech=aitech,
        aisubtech=aisubtech,
        aitech_framework_mappings=aitech_framework_mappings,
        aisubtech_framework_mappings=aisubtech_framework_mappings,
        aisubtech_parents=parents,
        version=str(version) if version is not None else None,
    )


def _parse_taxonomy_payload(data: dict[str, Any]) -> _ParsedTaxonomy:
    """Parse supported taxonomy payload formats into canonical maps."""
    # Format 1: flattened dictionaries
    if isinstance(data.get("AITECH_TAXONOMY"), dict) and isinstance(data.get("AISUBTECH_TAXONOMY"), dict):
        return _parse_flat_taxonomy(
            data,
            aitech_key="AITECH_TAXONOMY",
            aisubtech_key="AISUBTECH_TAXONOMY",
            aitech_mapping_keys=("AITECH_FRAMEWORK_MAPPINGS", "AITECH_MAPPINGS"),
            aisubtech_mapping_keys=("AISUBTECH_FRAMEWORK_MAPPINGS", "AISUBTECH_MAPPINGS"),
            parents_key="AISUBTECH_PARENTS",
        )

    # Format 2: lower-case flattened dictionaries
    if isinstance(data.get("aitech_taxonomy"), dict) and isinstance(data.get("aisubtech_taxonomy"), dict):
        return _parse_flat_taxonomy(
            data,
            aitech_key="aitech_taxonomy",
            aisubtech_key="aisubtech_taxonomy",
            aitech_mapping_keys=("aitech_framework_mappings", "aitech_mappings"),
            aisubtech_mapping_keys=("aisubtech_framework_mappings", "aisubtech_mappings"),
            parents_key="aisubtech_parents",
        )

    # Format 3: full framework shape (OB-* entries with ai_tech/ai_subtech)
    if any(str(k).startswith("OB-") for k in data.keys()):
        return _flatten_framework_taxonomy(data)

    raise ValueError(
        "Unsupported taxonomy format. Expected either "
        "{AITECH_TAXONOMY, AISUBTECH_TAXONOMY} maps or OB-* framework taxonomy."
    )


def _load_builtin_taxonomy() -> _ParsedTaxonomy:
    """Load the bundled snapshot and attach its provenance record."""
    import yaml

    parsed = _parse_taxonomy_payload(_read_taxonomy_file(BUILTIN_SNAPSHOT_PATH))
    provenance_raw = yaml.safe_load(BUILTIN_PROVENANCE_PATH.read_text(encoding="utf-8"))
    if not isinstance(provenance_raw, dict):
        raise ValueError(f"Taxonomy provenance must be a mapping: {BUILTIN_PROVENANCE_PATH}")
    provenance = {
        key: str(provenance_raw[key])
        for key in ("name", "version", "repository", "revision", "source_sha256", "snapshot_sha256")
        if provenance_raw.get(key) is not None
    }
    if provenance.get("version") != parsed.version:
        raise ValueError(
            f"Bundled taxonomy version {parsed.version!r} does not match provenance {provenance.get('version')!r}"
        )
    return _ParsedTaxonomy(
        aitech=parsed.aitech,
        aisubtech=parsed.aisubtech,
        aitech_framework_mappings=parsed.aitech_framework_mappings,
        aisubtech_framework_mappings=parsed.aisubtech_framework_mappings,
        aisubtech_parents=parsed.aisubtech_parents,
        version=parsed.version,
        provenance=provenance,
    )


# Built-in snapshot shipped with the package.  It stays immutable and is used
# when no external taxonomy is configured, and to validate bundled rule packs.
_BUILTIN = _load_builtin_taxonomy()

# Active taxonomy.  Declared at module scope for static typing and re-assigned
# by reload_taxonomy(); read these through the module (or the helpers below)
# so a reload is visible.
AITECH_TAXONOMY: dict[str, str] = dict(_BUILTIN.aitech)
AISUBTECH_TAXONOMY: dict[str, str] = dict(_BUILTIN.aisubtech)
AITECH_FRAMEWORK_MAPPINGS: dict[str, list[str]] = {}
AISUBTECH_FRAMEWORK_MAPPINGS: dict[str, list[str]] = {}
AISUBTECH_PARENTS: dict[str, str] = {}
VALID_AITECH_CODES: set[str] = set(AITECH_TAXONOMY.keys())
VALID_AISUBTECH_CODES: set[str] = set(AISUBTECH_TAXONOMY.keys())

# Optional runtime override path for loading custom taxonomy profiles.
TAXONOMY_ENV_VAR = "SKILL_SCANNER_TAXONOMY_PATH"

# Active source marker (builtin or external path).
_ACTIVE_TAXONOMY_SOURCE = "builtin"
_ACTIVE_TAXONOMY_VERSION: str | None = _BUILTIN.version
_ACTIVE_TAXONOMY_SHA256: str | None = None


def _activate(parsed: _ParsedTaxonomy, source: str, sha256: str | None = None) -> None:
    global AITECH_TAXONOMY
    global AISUBTECH_TAXONOMY
    global AITECH_FRAMEWORK_MAPPINGS
    global AISUBTECH_FRAMEWORK_MAPPINGS
    global AISUBTECH_PARENTS
    global VALID_AITECH_CODES
    global VALID_AISUBTECH_CODES
    global _ACTIVE_TAXONOMY_SOURCE
    global _ACTIVE_TAXONOMY_VERSION
    global _ACTIVE_TAXONOMY_SHA256

    AITECH_TAXONOMY = dict(parsed.aitech)
    AISUBTECH_TAXONOMY = dict(parsed.aisubtech)
    AITECH_FRAMEWORK_MAPPINGS = {code: list(m) for code, m in parsed.aitech_framework_mappings.items()}
    AISUBTECH_FRAMEWORK_MAPPINGS = {code: list(m) for code, m in parsed.aisubtech_framework_mappings.items()}
    AISUBTECH_PARENTS = dict(parsed.aisubtech_parents)
    VALID_AITECH_CODES = set(AITECH_TAXONOMY.keys())
    VALID_AISUBTECH_CODES = set(AISUBTECH_TAXONOMY.keys())
    _ACTIVE_TAXONOMY_SOURCE = source
    _ACTIVE_TAXONOMY_VERSION = parsed.version
    _ACTIVE_TAXONOMY_SHA256 = sha256


def reload_taxonomy(path: str | Path | None = None) -> str:
    """Reload active taxonomy from custom path or reset to built-in defaults.

    Args:
        path: Optional path to taxonomy JSON/YAML. If omitted, uses
            SKILL_SCANNER_TAXONOMY_PATH. If neither is set, uses built-in defaults.

    Returns:
        Active taxonomy source string ("builtin" or absolute file path).
    """
    configured = str(path) if path is not None else os.getenv(TAXONOMY_ENV_VAR)
    if not configured:
        _activate(_BUILTIN, "builtin")
        return _ACTIVE_TAXONOMY_SOURCE

    taxonomy_path = Path(configured).expanduser().resolve()
    parsed = _parse_taxonomy_payload(_read_taxonomy_file(taxonomy_path))
    _activate(parsed, str(taxonomy_path), hashlib.sha256(taxonomy_path.read_bytes()).hexdigest())
    return _ACTIVE_TAXONOMY_SOURCE


def get_taxonomy_source() -> str:
    """Return the active taxonomy source marker."""
    return _ACTIVE_TAXONOMY_SOURCE


def get_taxonomy_version() -> str | None:
    """Return the version declared by the active taxonomy, if any."""
    return _ACTIVE_TAXONOMY_VERSION


def get_taxonomy_info() -> dict[str, str]:
    """Describe the active taxonomy for scan metadata.

    A custom taxonomy is identified by its SHA-256, never by its path, since
    scan results leave the machine (reports, API responses).
    """
    builtin = _ACTIVE_TAXONOMY_SOURCE == "builtin"
    info: dict[str, str] = {"source": "builtin" if builtin else "custom"}
    if _ACTIVE_TAXONOMY_VERSION is not None:
        info["version"] = _ACTIVE_TAXONOMY_VERSION
    if builtin:
        for key in ("name", "revision", "snapshot_sha256"):
            if key in _BUILTIN.provenance:
                info[key] = _BUILTIN.provenance[key]
    elif _ACTIVE_TAXONOMY_SHA256 is not None:
        info["sha256"] = _ACTIVE_TAXONOMY_SHA256
    return info


# Initialize active taxonomy once on module import.
reload_taxonomy()


def is_valid_aitech(code: str) -> bool:
    """Check if an AITech code exists in the active taxonomy."""
    return code in VALID_AITECH_CODES


def is_valid_aisubtech(code: str) -> bool:
    """Check if an AISubtech code exists in the active taxonomy."""
    return code in VALID_AISUBTECH_CODES


def is_builtin_taxonomy_code(code: str) -> bool:
    """Check a code against the bundled snapshot, ignoring runtime overrides."""
    return code in _BUILTIN.aitech or code in _BUILTIN.aisubtech


def get_aitech_name(code: str) -> str | None:
    """Get the official name for an AITech code."""
    return AITECH_TAXONOMY.get(code)


def get_aisubtech_name(code: str) -> str | None:
    """Get the official name for an AISubtech code."""
    return AISUBTECH_TAXONOMY.get(code)


def get_aisubtech_parent(code: str) -> str | None:
    """Get the parent AITech code of an AISubtech code."""
    return AISUBTECH_PARENTS.get(code)


def get_aitech_framework_mappings(code: str) -> list[str]:
    """Get framework mappings for an AITech code."""
    return list(AITECH_FRAMEWORK_MAPPINGS.get(code, []))


def get_aisubtech_framework_mappings(code: str) -> list[str]:
    """Get framework mappings for an AISubtech code."""
    return list(AISUBTECH_FRAMEWORK_MAPPINGS.get(code, []))


def get_framework_mappings(aitech_code: str | None = None, aisubtech_code: str | None = None) -> list[str]:
    """Get de-duplicated framework mappings for one or both taxonomy codes."""
    out: list[str] = []
    if aitech_code:
        for entry in AITECH_FRAMEWORK_MAPPINGS.get(aitech_code, []):
            if entry not in out:
                out.append(entry)
    if aisubtech_code:
        for entry in AISUBTECH_FRAMEWORK_MAPPINGS.get(aisubtech_code, []):
            if entry not in out:
                out.append(entry)
    return out


def resolve_taxonomy_code(code: str | None) -> tuple[str | None, str | None]:
    """Resolve one selected code to ``(aitech, aisubtech)`` in the active taxonomy.

    An AISubtech resolves to its parent AITech.  Unknown codes, and
    sub-techniques whose parent is not known, resolve to ``(None, None)``;
    nothing is guessed.
    """
    if not code:
        return None, None
    if code in VALID_AISUBTECH_CODES:
        parent = AISUBTECH_PARENTS.get(code)
        return (parent, code) if parent in VALID_AITECH_CODES else (None, None)
    if code in VALID_AITECH_CODES:
        return code, None
    return None, None
