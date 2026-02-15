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

"""Tests for taxonomy and threat-mapping runtime customization."""

from __future__ import annotations

import importlib
import json


def _write_json(path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _reload_taxonomy_module():
    import skill_scanner.threats.cisco_ai_taxonomy as taxonomy

    return importlib.reload(taxonomy)


def _reload_threats_module():
    import skill_scanner.threats.threats as threats

    return importlib.reload(threats)


def test_custom_taxonomy_ob_framework_format(monkeypatch, tmp_path):
    taxonomy_payload = {
        "version": "1.0.0",
        "OB-001": {
            "ai_tech": [
                {
                    "code": "AITech-77.1",
                    "description": "Custom Goal Hijack",
                    "mappings": [
                        "OWASP: LLM01:2025: Prompt Injection",
                        "MITRE ATLAS: AML.T0051: LLM Prompt Injection",
                    ],
                    "ai_subtech": [
                        {
                            "code": "AISubtech-77.1.1",
                            "description": "Custom Subtech",
                            "mappings": ["NIST AML: NISTAML.018: Prompt Injection"],
                        }
                    ],
                }
            ]
        },
    }
    taxonomy_file = tmp_path / "custom_framework_taxonomy.json"
    _write_json(taxonomy_file, taxonomy_payload)

    monkeypatch.setenv("SKILL_SCANNER_TAXONOMY_PATH", str(taxonomy_file))
    taxonomy = _reload_taxonomy_module()

    assert taxonomy.get_taxonomy_source().endswith("custom_framework_taxonomy.json")
    assert taxonomy.AITECH_TAXONOMY["AITech-77.1"] == "Custom Goal Hijack"
    assert taxonomy.AISUBTECH_TAXONOMY["AISubtech-77.1.1"] == "Custom Subtech"
    assert taxonomy.get_aitech_framework_mappings("AITech-77.1") == [
        "OWASP: LLM01:2025: Prompt Injection",
        "MITRE ATLAS: AML.T0051: LLM Prompt Injection",
    ]
    assert taxonomy.get_aisubtech_framework_mappings("AISubtech-77.1.1") == ["NIST AML: NISTAML.018: Prompt Injection"]

    monkeypatch.delenv("SKILL_SCANNER_TAXONOMY_PATH", raising=False)
    taxonomy = _reload_taxonomy_module()
    assert taxonomy.get_taxonomy_source() == "builtin"
    assert "AITech-1.1" in taxonomy.VALID_AITECH_CODES


def test_custom_taxonomy_flattened_format(monkeypatch, tmp_path):
    taxonomy_payload = {
        "AITECH_TAXONOMY": {
            "AITech-50.1": "Custom Tech",
        },
        "AISUBTECH_TAXONOMY": {
            "AISubtech-50.1.1": "Custom Subtech",
        },
        "AITECH_FRAMEWORK_MAPPINGS": {
            "AITech-50.1": ["OWASP: LLM10:2025: Unbounded Consumption"],
        },
        "AISUBTECH_FRAMEWORK_MAPPINGS": {
            "AISubtech-50.1.1": ["MITRE ATLAS: AML.T0034: Cost Harvesting"],
        },
    }
    taxonomy_file = tmp_path / "custom_flat_taxonomy.json"
    _write_json(taxonomy_file, taxonomy_payload)

    monkeypatch.setenv("SKILL_SCANNER_TAXONOMY_PATH", str(taxonomy_file))
    taxonomy = _reload_taxonomy_module()

    assert taxonomy.AITECH_TAXONOMY == {"AITech-50.1": "Custom Tech"}
    assert taxonomy.AISUBTECH_TAXONOMY == {"AISubtech-50.1.1": "Custom Subtech"}
    assert taxonomy.get_framework_mappings("AITech-50.1", "AISubtech-50.1.1") == [
        "OWASP: LLM10:2025: Unbounded Consumption",
        "MITRE ATLAS: AML.T0034: Cost Harvesting",
    ]

    monkeypatch.delenv("SKILL_SCANNER_TAXONOMY_PATH", raising=False)
    _reload_taxonomy_module()


def test_custom_threat_mapping_override(monkeypatch, tmp_path):
    mapping_payload = {
        "llm_threats": {
            "PROMPT INJECTION": {
                "aitech": "AITech-1.2",
                "aitech_name": "Indirect Prompt Injection",
                "aisubtech": "AISubtech-1.2.1",
                "aisubtech_name": "Instruction Manipulation (Indirect Prompt Injection)",
            }
        },
        "aitech_to_category": {
            "AITech-1.2": "transitive_trust_abuse",
        },
    }
    mapping_file = tmp_path / "custom_threat_mapping.json"
    _write_json(mapping_file, mapping_payload)

    monkeypatch.setenv("SKILL_SCANNER_THREAT_MAPPING_PATH", str(mapping_file))
    threats = _reload_threats_module()

    prompt_mapping = threats.ThreatMapping.LLM_THREATS["PROMPT INJECTION"]
    assert prompt_mapping["aitech"] == "AITech-1.2"
    assert threats.ThreatMapping.get_threat_category_from_aitech("AITech-1.2") == "transitive_trust_abuse"

    monkeypatch.delenv("SKILL_SCANNER_THREAT_MAPPING_PATH", raising=False)
    threats = _reload_threats_module()
    assert threats.ThreatMapping.LLM_THREATS["PROMPT INJECTION"]["aitech"] == "AITech-1.1"


def test_threat_mapping_to_cross_framework_mappings(monkeypatch, tmp_path):
    taxonomy_payload = {
        "AITECH_TAXONOMY": {
            "AITech-1.1": "Direct Prompt Injection",
        },
        "AISUBTECH_TAXONOMY": {
            "AISubtech-1.1.1": "Instruction Manipulation (Direct Prompt Injection)",
        },
        "AITECH_FRAMEWORK_MAPPINGS": {
            "AITech-1.1": [
                "OWASP: LLM01:2025: Prompt Injection",
                "MITRE ATLAS: AML.T0051.000: LLM Prompt Injection (Direct)",
            ]
        },
        "AISUBTECH_FRAMEWORK_MAPPINGS": {
            "AISubtech-1.1.1": ["NIST AML: NISTAML.018: Prompt Injection"],
        },
    }
    taxonomy_file = tmp_path / "framework_mapping_taxonomy.json"
    _write_json(taxonomy_file, taxonomy_payload)

    monkeypatch.setenv("SKILL_SCANNER_TAXONOMY_PATH", str(taxonomy_file))
    _reload_taxonomy_module()
    threats = _reload_threats_module()

    mappings = threats.ThreatMapping.get_framework_mappings_for_threat("llm", "prompt injection")
    assert mappings == [
        "OWASP: LLM01:2025: Prompt Injection",
        "MITRE ATLAS: AML.T0051.000: LLM Prompt Injection (Direct)",
        "NIST AML: NISTAML.018: Prompt Injection",
    ]

    monkeypatch.delenv("SKILL_SCANNER_TAXONOMY_PATH", raising=False)
    _reload_taxonomy_module()


def test_llm_schema_enum_tracks_active_taxonomy(monkeypatch, tmp_path):
    taxonomy_payload = {
        "AITECH_TAXONOMY": {
            "AITech-42.1": "Custom LLM Code",
        },
        "AISUBTECH_TAXONOMY": {
            "AISubtech-42.1.1": "Custom LLM Subtech",
        },
    }
    taxonomy_file = tmp_path / "schema_taxonomy.json"
    _write_json(taxonomy_file, taxonomy_payload)

    monkeypatch.setenv("SKILL_SCANNER_TAXONOMY_PATH", str(taxonomy_file))
    _reload_taxonomy_module()

    from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

    handler = object.__new__(LLMRequestHandler)
    schema = LLMRequestHandler._load_response_schema(handler)

    assert schema is not None
    enum_values = schema["properties"]["findings"]["items"]["properties"]["aitech"]["enum"]
    assert enum_values == ["AITech-42.1"]

    monkeypatch.delenv("SKILL_SCANNER_TAXONOMY_PATH", raising=False)
    _reload_taxonomy_module()
