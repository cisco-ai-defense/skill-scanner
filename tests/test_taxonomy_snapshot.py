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

"""Integrity of the bundled Cisco AI Security and Safety Taxonomy snapshot."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import yaml

from skill_scanner.threats import cisco_ai_taxonomy as taxonomy

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = taxonomy.BUILTIN_SNAPSHOT_PATH
PROVENANCE = taxonomy.BUILTIN_PROVENANCE_PATH


def _load_update_script():
    spec = importlib.util.spec_from_file_location(
        "update_taxonomy_snapshot", REPO_ROOT / "scripts" / "update_taxonomy_snapshot.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _provenance() -> dict:
    return yaml.safe_load(PROVENANCE.read_text(encoding="utf-8"))


def _snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def test_snapshot_bytes_match_provenance_hash():
    assert hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest() == _provenance()["snapshot_sha256"]


def test_provenance_pins_source_commit_and_hash():
    provenance = _provenance()
    assert provenance["version"] == _snapshot()["version"] == "2.0.0"
    assert re.fullmatch(r"[0-9a-f]{40}", provenance["revision"])
    assert re.fullmatch(r"[0-9a-f]{64}", provenance["source_sha256"])
    assert provenance["snapshot_file"] == SNAPSHOT.name


def test_snapshot_keeps_only_codes_names_and_crosswalks():
    """Definitions, threat indicators and labeling constitutions are not shipped."""
    snapshot = _snapshot()
    for key, objective in snapshot.items():
        if key == "version":
            continue
        assert set(objective) == {"code", "description", "ai_tech"}, key
        for tech in objective["ai_tech"]:
            assert set(tech) == {"code", "description", "mappings", "ai_subtech"}, tech["code"]
            for sub in tech["ai_subtech"]:
                assert set(sub) == {"code", "description", "mappings"}, sub["code"]


def test_update_script_output_is_stable_for_the_shipped_snapshot():
    script = _load_update_script()
    assert script.render_snapshot(script.build_snapshot(_snapshot())) == SNAPSHOT.read_bytes()


def test_update_script_drops_everything_but_codes_names_and_crosswalks():
    script = _load_update_script()
    source = {
        "version": "9.9.9",
        "OB-001": {
            "code": "OB-001",
            "description": "Goal Hijacking",
            "objective_group": "Common Manipulation Risks",
            "definition": "not shipped",
            "mappings": ["OWASP: LLM01:2026: Prompt Injection"],
            "ai_tech": [
                {
                    "code": "AITech-1.1",
                    "description": "Tech",
                    "definition": "not shipped",
                    "mappings": ["OWASP: LLM01:2026: Prompt Injection", "OWASP: LLM01:2026: Prompt Injection"],
                    "threat_indicators": {"agentic": True},
                    "constitution": "not shipped",
                    "ai_subtech": [
                        {"code": "AISubtech-1.1.1", "description": "Sub", "definition": "x", "mappings": ["ASI01"]}
                    ],
                }
            ],
        },
    }
    assert script.build_snapshot(source) == {
        "version": "9.9.9",
        "OB-001": {
            "code": "OB-001",
            "description": "Goal Hijacking",
            "ai_tech": [
                {
                    "code": "AITech-1.1",
                    "description": "Tech",
                    "mappings": ["OWASP: LLM01:2026: Prompt Injection"],
                    "ai_subtech": [{"code": "AISubtech-1.1.1", "description": "Sub", "mappings": ["ASI01"]}],
                }
            ],
        },
    }


def test_every_subtechnique_has_its_numbered_parent():
    assert taxonomy.AISUBTECH_PARENTS.keys() == taxonomy.VALID_AISUBTECH_CODES
    for sub, parent in taxonomy.AISUBTECH_PARENTS.items():
        assert parent in taxonomy.VALID_AITECH_CODES
        assert sub.removeprefix("AISubtech-").startswith(parent.removeprefix("AITech-") + ".")


def test_every_code_carries_crosswalks():
    for code in taxonomy.VALID_AITECH_CODES:
        assert taxonomy.get_aitech_framework_mappings(code), code
    for code in taxonomy.VALID_AISUBTECH_CODES:
        assert taxonomy.get_aisubtech_framework_mappings(code), code


def test_known_entry_resolves_with_owasp_crosswalks():
    assert taxonomy.resolve_taxonomy_code("AISubtech-1.1.1") == ("AITech-1.1", "AISubtech-1.1.1")
    mappings = taxonomy.get_aisubtech_framework_mappings("AISubtech-1.1.1")
    assert "OWASP: LLM01:2026: Prompt Injection" in mappings
    assert "OWASP: ASI01: Agent Goal Hijack" in mappings


def test_unknown_codes_resolve_to_nothing():
    assert taxonomy.resolve_taxonomy_code("AITech-99.9") == (None, None)
    assert taxonomy.resolve_taxonomy_code("AISubtech-1.2.1") == (None, None)  # removed in 2.0.0
    assert taxonomy.resolve_taxonomy_code("AITech-1.2") == ("AITech-1.2", None)  # no sub-techniques


def test_taxonomy_info_reports_builtin_provenance():
    info = taxonomy.get_taxonomy_info()
    assert info["source"] == "builtin"
    assert info["version"] == "2.0.0"
    assert info["revision"] == _provenance()["revision"]
    assert info["snapshot_sha256"] == _provenance()["snapshot_sha256"]


def test_custom_taxonomy_is_reported_by_hash_not_path(monkeypatch, tmp_path):
    directory = tmp_path / "private-dir"
    directory.mkdir()
    path = directory / "taxonomy.json"
    path.write_text(json.dumps({"AITECH_TAXONOMY": {"AITech-60.1": "T"}, "AISUBTECH_TAXONOMY": {}}), encoding="utf-8")
    try:
        taxonomy.reload_taxonomy(path)
        info = taxonomy.get_taxonomy_info()
        assert info["source"] == "custom"
        assert info["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert "private-dir" not in json.dumps(info)
    finally:
        monkeypatch.delenv(taxonomy.TAXONOMY_ENV_VAR, raising=False)
        taxonomy.reload_taxonomy()


def test_flat_custom_taxonomy_derives_parents_from_numbering(monkeypatch, tmp_path):
    payload = {
        "AITECH_TAXONOMY": {"AITech-60.1": "Custom Tech"},
        "AISUBTECH_TAXONOMY": {"AISubtech-60.1.1": "Numbered child", "AISubtech-61.1.1": "Orphan"},
    }
    path = tmp_path / "flat.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        taxonomy.reload_taxonomy(path)
        assert taxonomy.resolve_taxonomy_code("AISubtech-60.1.1") == ("AITech-60.1", "AISubtech-60.1.1")
        # A sub-technique without a known parent is never given a guessed one.
        assert taxonomy.resolve_taxonomy_code("AISubtech-61.1.1") == (None, None)
    finally:
        monkeypatch.delenv(taxonomy.TAXONOMY_ENV_VAR, raising=False)
        taxonomy.reload_taxonomy()
