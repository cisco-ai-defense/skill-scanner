#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
Regenerate the bundled Cisco AI Security and Safety Taxonomy snapshot.

The scanner ships a reduced copy of the taxonomy: objective, technique and
sub-technique codes, their names and definitions, the parent/child structure,
and the external framework crosswalks (OWASP, MITRE ATLAS, NIST AML).  Threat
indicators and labeling constitutions are intentionally dropped.

Usage:
    python scripts/update_taxonomy_snapshot.py SOURCE_TAXONOMY_JSON \\
        --revision <git sha of the taxonomy repository> \\
        --expect-sha256 <sha256 of SOURCE_TAXONOMY_JSON>

The command rewrites ``skill_scanner/data/taxonomy/cisco_ai_taxonomy.json``,
``skill_scanner/data/taxonomy/provenance.yaml`` and the generated
``docs/architecture/taxonomy-reference.md``.  Review the diff and run
``pytest tests/test_taxonomy_snapshot.py`` before committing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TAXONOMY_DIR = REPO_ROOT / "skill_scanner" / "data" / "taxonomy"
SNAPSHOT_NAME = "cisco_ai_taxonomy.json"
PROVENANCE_NAME = "provenance.yaml"
REFERENCE_DOC = REPO_ROOT / "docs" / "architecture" / "taxonomy-reference.md"

SOURCE_REPOSITORY = "https://github.com/cisco-ai-defense/ai-security-safety-taxonomy"
SOURCE_PATH = "src/ai_safety_taxonomy/data/taxonomy.json"

_OBJECTIVE_RE = re.compile(r"^OB-\d{3}$")
_AITECH_RE = re.compile(r"^AITech-\d+\.\d+$")
_AISUBTECH_RE = re.compile(r"^AISubtech-\d+\.\d+\.\d+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mappings(node: dict[str, Any], context: str) -> list[str]:
    raw = node.get("mappings", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise ValueError(f"{context}.mappings must be a list of non-empty strings")
    out: list[str] = []
    for item in raw:
        text = item.strip()
        if text not in out:
            out.append(text)
    return out


def _named(node: Any, pattern: re.Pattern[str], context: str) -> tuple[str, str, str]:
    if not isinstance(node, dict):
        raise ValueError(f"{context} must be an object")
    code = node.get("code")
    description = node.get("description")
    definition = node.get("definition")
    if not isinstance(code, str) or not pattern.match(code):
        raise ValueError(f"{context}.code is malformed: {code!r}")
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"{context}.description must be a non-empty string")
    if not isinstance(definition, str) or not definition.strip():
        raise ValueError(f"{code}.definition must be a non-empty string")
    lines = (" ".join(line.split()) for line in definition.strip().splitlines())
    return code, description.strip(), "\n".join(line for line in lines if line)


def build_snapshot(source: dict[str, Any]) -> dict[str, Any]:
    """Reduce the full taxonomy to the fields the scanner ships."""
    version = source.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("source taxonomy has no version")

    snapshot: dict[str, Any] = {"version": version}
    seen: set[str] = set()
    for key, objective in source.items():
        if key == "version":
            continue
        if not _OBJECTIVE_RE.match(key):
            raise ValueError(f"unexpected top-level key in source taxonomy: {key!r}")
        ob_code, ob_name, ob_definition = _named(objective, _OBJECTIVE_RE, key)
        if ob_code != key:
            raise ValueError(f"{key}.code does not match its key: {ob_code!r}")

        techniques: list[dict[str, Any]] = []
        for tech in objective.get("ai_tech", []):
            tech_code, tech_name, tech_definition = _named(tech, _AITECH_RE, f"{key}.ai_tech")
            if tech_code in seen:
                raise ValueError(f"duplicate taxonomy code: {tech_code}")
            seen.add(tech_code)
            subtechs: list[dict[str, Any]] = []
            for sub in tech.get("ai_subtech", []):
                sub_code, sub_name, sub_definition = _named(sub, _AISUBTECH_RE, f"{tech_code}.ai_subtech")
                if sub_code in seen:
                    raise ValueError(f"duplicate taxonomy code: {sub_code}")
                if not sub_code.removeprefix("AISubtech-").startswith(tech_code.removeprefix("AITech-") + "."):
                    raise ValueError(f"{sub_code} is not numbered under its parent {tech_code}")
                seen.add(sub_code)
                subtechs.append(
                    {
                        "code": sub_code,
                        "description": sub_name,
                        "definition": sub_definition,
                        "mappings": _mappings(sub, sub_code),
                    }
                )
            techniques.append(
                {
                    "code": tech_code,
                    "description": tech_name,
                    "definition": tech_definition,
                    "mappings": _mappings(tech, tech_code),
                    "ai_subtech": subtechs,
                }
            )
        snapshot[key] = {"code": ob_code, "description": ob_name, "definition": ob_definition, "ai_tech": techniques}
    return snapshot


def render_snapshot(snapshot: dict[str, Any]) -> bytes:
    return (json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _anchor(heading: str) -> str:
    """GitHub's heading anchor: lower-case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")


def _definition_markdown(definition: str) -> str:
    """Render a definition as paragraphs, turning its bullet lines into a list."""
    blocks: list[str] = []
    for line in definition.splitlines():
        if line.startswith("\u2022"):
            item = "- " + line.lstrip("\u2022").strip()
            if blocks and blocks[-1].startswith("- "):
                blocks[-1] += "\n" + item
            else:
                blocks.append(item)
        else:
            blocks.append(line)
    return "\n\n".join(blocks)


def _definition_cell(definition: str) -> str:
    """Render a definition inside one Markdown table cell."""
    return "<br>".join(line.replace("|", "\\|") for line in definition.splitlines())


def render_reference(snapshot: dict[str, Any]) -> str:
    """Render the taxonomy reference page from a snapshot."""
    objectives = [ob for key, ob in snapshot.items() if key != "version"]
    techniques = [tech for ob in objectives for tech in ob["ai_tech"]]
    subtechniques = [sub for tech in techniques for sub in tech["ai_subtech"]]
    version = snapshot["version"]

    lines = [
        f"# Cisco AI Security & Safety Taxonomy {version}",
        "",
        "<!-- Generated by scripts/update_taxonomy_snapshot.py from the bundled snapshot. Do not edit by hand. -->",
        "",
        "Every objective, technique (`AITech`) and sub-technique (`AISubtech`) in the taxonomy snapshot bundled "
        "with Skill Scanner, with its definition. The OWASP, MITRE ATLAS and NIST AML crosswalks for each code are "
        "in [`cisco_ai_taxonomy.json`](../../skill_scanner/data/taxonomy/cisco_ai_taxonomy.json) and on every "
        "finding. How findings get their codes is described in [Threat Taxonomy](threat-taxonomy.md).",
        "",
        f"{len(objectives)} objectives, {len(techniques)} techniques, {len(subtechniques)} sub-techniques.",
        "",
        "## Contents",
        "",
    ]
    for ob in objectives:
        ob_heading = f"{ob['code']} {ob['description']}"
        codes = ", ".join(
            f"[{tech['code']}](#{_anchor(tech['code'] + ' ' + tech['description'])})" for tech in ob["ai_tech"]
        )
        lines.append(f"- [{ob_heading}](#{_anchor(ob_heading)}): {codes}")
    for ob in objectives:
        lines += ["", f"## {ob['code']} {ob['description']}", "", _definition_markdown(ob["definition"])]
        for tech in ob["ai_tech"]:
            lines += ["", f"### {tech['code']} {tech['description']}", "", _definition_markdown(tech["definition"])]
            if not tech["ai_subtech"]:
                lines += ["", "This technique has no sub-techniques."]
                continue
            lines += ["", "| Sub-technique | Name | Definition |", "|---|---|---|"]
            for sub in tech["ai_subtech"]:
                lines.append(f"| `{sub['code']}` | {sub['description']} | {_definition_cell(sub['definition'])} |")
    return "\n".join(lines) + "\n"


def render_provenance(*, version: str, revision: str, source_sha256: str, snapshot_sha256: str) -> str:
    return (
        "# Provenance for the bundled taxonomy snapshot.\n"
        "# Regenerate with scripts/update_taxonomy_snapshot.py; do not edit by hand.\n"
        "schema_version: 1\n"
        "name: Cisco AI Security and Safety Taxonomy\n"
        f'version: "{version}"\n'
        f"repository: {SOURCE_REPOSITORY}\n"
        f"revision: {revision}\n"
        f"source_path: {SOURCE_PATH}\n"
        f"source_sha256: {source_sha256}\n"
        f"snapshot_file: {SNAPSHOT_NAME}\n"
        f"snapshot_sha256: {snapshot_sha256}\n"
        "fields:\n"
        "  objective: [code, description, definition]\n"
        "  ai_tech: [code, description, definition, mappings]\n"
        "  ai_subtech: [code, description, definition, mappings]\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path, help="Full taxonomy.json from the taxonomy repository")
    parser.add_argument("--revision", required=True, help="Taxonomy repository commit the source was taken from")
    parser.add_argument("--expect-sha256", required=True, help="Expected SHA-256 of the source file")
    args = parser.parse_args(argv)

    if not _SHA_RE.match(args.revision):
        parser.error("--revision must be a full 40-character git commit sha")

    raw = args.source.read_bytes()
    source_sha256 = _sha256(raw)
    if source_sha256 != args.expect_sha256.lower():
        print(
            f"error: source sha256 {source_sha256} does not match --expect-sha256 {args.expect_sha256}",
            file=sys.stderr,
        )
        return 1

    source = json.loads(raw)
    if not isinstance(source, dict):
        print("error: source taxonomy must be a JSON object", file=sys.stderr)
        return 1
    snapshot = build_snapshot(source)
    rendered = render_snapshot(snapshot)

    TAXONOMY_DIR.mkdir(parents=True, exist_ok=True)
    (TAXONOMY_DIR / SNAPSHOT_NAME).write_bytes(rendered)
    (TAXONOMY_DIR / PROVENANCE_NAME).write_text(
        render_provenance(
            version=snapshot["version"],
            revision=args.revision,
            source_sha256=source_sha256,
            snapshot_sha256=_sha256(rendered),
        ),
        encoding="utf-8",
    )
    REFERENCE_DOC.write_text(render_reference(snapshot), encoding="utf-8")
    techniques = sum(len(ob["ai_tech"]) for key, ob in snapshot.items() if key != "version")
    subtechniques = sum(len(t["ai_subtech"]) for key, ob in snapshot.items() if key != "version" for t in ob["ai_tech"])
    print(f"wrote taxonomy {snapshot['version']}: {techniques} AITech, {subtechniques} AISubtech")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
