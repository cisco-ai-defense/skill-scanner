# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Audit the authoritative metadata in the bundled core v2 manifest."""

from __future__ import annotations

import ast
from pathlib import Path

import yaml

from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.python_rule_inventory import (
    BUNDLED_INDIRECT_PYTHON_IMPLEMENTATIONS,
    meta_detected_rule_id,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CORE_MANIFEST = _REPO_ROOT / "skill_scanner" / "data" / "packs" / "core" / "pack.yaml"
_CORE_SOURCE = _REPO_ROOT / "skill_scanner" / "core"

# These declarations intentionally record the maximum/base identity before
# analyzers apply evidence-specific or documentation-context demotions. CEL and
# reporting consumers therefore have one stable manifest identity without
# preventing a finding from carrying its more precise runtime severity.
_DYNAMIC_BASE_IDENTITIES = {
    "SOCIAL_ENG_ANTHROPIC_IMPERSONATION": ("social_engineering", "HIGH"),
    "SUPPLY_CHAIN_UNPINNED_DEPENDENCY": ("supply_chain_attack", "MEDIUM"),
    "FILE_MAGIC_MISMATCH": ("obfuscation", "CRITICAL"),
    "PDF_STRUCTURAL_THREAT": ("command_injection", "CRITICAL"),
    "OFFICE_DOCUMENT_THREAT": ("supply_chain_attack", "CRITICAL"),
    "ASSET_PROMPT_INJECTION": ("prompt_injection", "HIGH"),
    "PIPELINE_TAINT_FLOW": ("data_exfiltration", "CRITICAL"),
    "COMPOUND_FIND_EXEC": ("command_injection", "CRITICAL"),
    "COMPOUND_EXTRACT_EXECUTE": ("supply_chain_attack", "HIGH"),
    "COMPOUND_FETCH_EXECUTE": ("command_injection", "CRITICAL"),
    "COMPOUND_LAUNDERING_CHAIN": ("command_injection", "HIGH"),
    "LOW_ANALYZABILITY": ("policy_violation", "HIGH"),
    "BEHAVIOR_BASH_TAINT_FLOW": ("data_exfiltration", "CRITICAL"),
    "CORRELATED_SENSITIVE_NETWORK_FLOW": ("data_exfiltration", "HIGH"),
    "CORRELATED_NETWORK_EXECUTION_FLOW": ("command_injection", "HIGH"),
    "CORRELATED_NETWORK_FILE_WRITE_FLOW": ("malware", "HIGH"),
    "CORRELATED_OBFUSCATION_EXECUTION_FLOW": ("obfuscation", "HIGH"),
    "CORRELATED_HIDDEN_EXECUTABLE": ("malware", "HIGH"),
    "CORRELATED_CONFIG_URL_EXECUTION": ("supply_chain_attack", "HIGH"),
    "CORRELATED_NESTED_ARCHIVE_SCRIPT": ("malware", "HIGH"),
    "CORRELATED_MANIFEST_CAPABILITY_MISMATCH": ("unauthorized_tool_use", "HIGH"),
    "VIRUSTOTAL_MALICIOUS_FILE": ("malware", "CRITICAL"),
    **{meta_detected_rule_id(category): (category.value, "CRITICAL") for category in ThreatCategory},
}

_ALLOWED_SEVERITY_DEMOTIONS = {
    "SOCIAL_ENG_ANTHROPIC_IMPERSONATION": ["MEDIUM"],
    "SUPPLY_CHAIN_UNPINNED_DEPENDENCY": ["LOW"],
    "FILE_MAGIC_MISMATCH": ["HIGH", "MEDIUM"],
    "PICKLE_FILE_DETECTED": ["HIGH"],
    "PDF_STRUCTURAL_THREAT": ["HIGH", "MEDIUM", "LOW"],
    "OFFICE_DOCUMENT_THREAT": ["HIGH", "MEDIUM"],
    "ASSET_PROMPT_INJECTION": ["MEDIUM"],
    "PIPELINE_TAINT_FLOW": ["HIGH", "MEDIUM", "LOW"],
    "COMPOUND_FIND_EXEC": ["MEDIUM"],
    "COMPOUND_EXTRACT_EXECUTE": ["LOW"],
    "COMPOUND_FETCH_EXECUTE": ["MEDIUM"],
    "COMPOUND_LAUNDERING_CHAIN": ["LOW"],
    "LOW_ANALYZABILITY": ["MEDIUM"],
    "BEHAVIOR_BASH_TAINT_FLOW": ["HIGH", "MEDIUM"],
    "CORRELATED_SENSITIVE_NETWORK_FLOW": ["MEDIUM"],
    "CORRELATED_NETWORK_EXECUTION_FLOW": ["MEDIUM"],
    "CORRELATED_OBFUSCATION_EXECUTION_FLOW": ["MEDIUM"],
    "CORRELATED_HIDDEN_EXECUTABLE": ["MEDIUM"],
    "CORRELATED_CONFIG_URL_EXECUTION": ["MEDIUM"],
    "CORRELATED_NESTED_ARCHIVE_SCRIPT": ["MEDIUM"],
    "CORRELATED_MANIFEST_CAPABILITY_MISMATCH": ["MEDIUM"],
    "VIRUSTOTAL_MALICIOUS_FILE": ["HIGH", "MEDIUM"],
    **{meta_detected_rule_id(category): ["HIGH", "MEDIUM", "LOW", "INFO"] for category in ThreatCategory},
}


def _manifest_rules() -> tuple[dict, dict[str, dict]]:
    manifest = yaml.safe_load(_CORE_MANIFEST.read_text(encoding="utf-8"))
    return manifest, manifest["rules"]


def _literal_finding_rule_ids() -> set[str]:
    rule_ids: set[str] = set()
    for source_path in _CORE_SOURCE.rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
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
            rule_id = next((keyword.value for keyword in node.keywords if keyword.arg == "rule_id"), None)
            if isinstance(rule_id, ast.Constant) and isinstance(rule_id.value, str):
                rule_ids.add(rule_id.value)
    return rule_ids


def test_core_manifest_v2_has_complete_typed_metadata() -> None:
    manifest, rules = _manifest_rules()

    assert manifest["schema_version"] == 2
    assert rules
    valid_categories = {category.value for category in ThreatCategory}
    valid_severities = {severity.value for severity in Severity}

    for rule_id, declaration in rules.items():
        assert declaration["category"] in valid_categories, rule_id
        assert declaration["severity"] in valid_severities, rule_id
        assert declaration["source"] in {"signature", "yara", "python"}, rule_id
        assert type(declaration["knobs"]["enabled"]) is bool, rule_id
        if declaration["source"] == "python":
            assert declaration["analyzer"].strip(), rule_id


def test_every_fixed_literal_finding_id_is_declared() -> None:
    _, rules = _manifest_rules()
    emitted = _literal_finding_rule_ids()

    missing = emitted - rules.keys()
    assert not missing, f"Fixed Finding rule IDs missing from core pack: {sorted(missing)}"


def test_indirect_python_inventory_is_fully_manifest_owned() -> None:
    _, rules = _manifest_rules()

    for rule_id, implementation in BUNDLED_INDIRECT_PYTHON_IMPLEMENTATIONS.items():
        declaration = rules[rule_id]
        assert declaration["source"] == "python"
        assert declaration["analyzer"] == implementation.analyzer
        assert declaration["category"] == implementation.category.value
        assert declaration["severity"] == implementation.max_severity.value
        assert declaration.get("allowed_severity_demotions", []) == [
            severity.value
            for severity in sorted(
                implementation.allowed_severity_demotions,
                key=lambda item: list(Severity).index(item),
            )
        ]


def test_contextual_rules_publish_reviewed_base_identities() -> None:
    _, rules = _manifest_rules()

    actual = {rule_id: (rules[rule_id]["category"], rules[rule_id]["severity"]) for rule_id in _DYNAMIC_BASE_IDENTITIES}
    assert actual == _DYNAMIC_BASE_IDENTITIES

    declared_demotions = {
        rule_id: declaration["allowed_severity_demotions"]
        for rule_id, declaration in rules.items()
        if "allowed_severity_demotions" in declaration
    }
    assert declared_demotions == _ALLOWED_SEVERITY_DEMOTIONS
