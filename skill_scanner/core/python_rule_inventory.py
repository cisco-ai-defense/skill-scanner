# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Declarative implementation identities for table-driven Python rules.

Literal ``Finding(...)`` calls are inventoried directly from the Python AST at
pack startup.  Rules emitted through tables, dispatchers, or a category-derived
identity need an equally strict, import-safe description that the pack loader
can compare with the authoritative schema-v2 manifest.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .models import Severity, ThreatCategory


@dataclass(frozen=True)
class BundledPythonImplementation:
    """One statically knowable table/dispatcher implementation identity."""

    rule_id: str
    analyzer: str
    category: ThreatCategory
    max_severity: Severity
    allowed_severity_demotions: frozenset[Severity] = frozenset()


def meta_detected_rule_id(category: ThreatCategory) -> str:
    """Return the manifest-owned identity for one Meta-detected category."""

    return f"META_DETECTED_{category.value.upper()}"


def _implementation(
    rule_id: str,
    analyzer: str,
    category: ThreatCategory,
    max_severity: Severity,
    *demotions: Severity,
) -> BundledPythonImplementation:
    return BundledPythonImplementation(
        rule_id=rule_id,
        analyzer=analyzer,
        category=category,
        max_severity=max_severity,
        allowed_severity_demotions=frozenset(demotions),
    )


_IMPLEMENTATIONS = {
    item.rule_id: item
    for item in (
        _implementation(
            "ASSET_PROMPT_INJECTION",
            "static",
            ThreatCategory.PROMPT_INJECTION,
            Severity.HIGH,
            Severity.MEDIUM,
        ),
        _implementation(
            "ASSET_SUSPICIOUS_URL",
            "static",
            ThreatCategory.POLICY_VIOLATION,
            Severity.MEDIUM,
        ),
        _implementation(
            "ACTIVE_OS_PERSISTENCE_DIRECTIVE",
            "static",
            ThreatCategory.MALWARE,
            Severity.HIGH,
        ),
        _implementation(
            "ACTIVE_REMOTE_ACQUIRE_EXECUTE",
            "static",
            ThreatCategory.COMMAND_INJECTION,
            Severity.HIGH,
        ),
        _implementation(
            "ACTIVE_SENSITIVE_EXFILTRATION",
            "static",
            ThreatCategory.DATA_EXFILTRATION,
            Severity.HIGH,
        ),
        _implementation(
            "MANDATORY_AUTOMATIC_HELPER_EXECUTION",
            "static",
            ThreatCategory.AUTONOMY_ABUSE,
            Severity.HIGH,
        ),
        _implementation(
            "COMPOUND_EXTRACT_EXECUTE",
            "pipeline",
            ThreatCategory.SUPPLY_CHAIN_ATTACK,
            Severity.HIGH,
            Severity.LOW,
        ),
        _implementation(
            "COMPOUND_FETCH_EXECUTE",
            "pipeline",
            ThreatCategory.COMMAND_INJECTION,
            Severity.CRITICAL,
            Severity.MEDIUM,
        ),
        _implementation(
            "COMPOUND_FIND_EXEC",
            "pipeline",
            ThreatCategory.COMMAND_INJECTION,
            Severity.CRITICAL,
            Severity.MEDIUM,
        ),
        _implementation(
            "COMPOUND_LAUNDERING_CHAIN",
            "pipeline",
            ThreatCategory.COMMAND_INJECTION,
            Severity.HIGH,
            Severity.LOW,
        ),
        _implementation(
            "CORRELATED_NETWORK_EXECUTION_FLOW",
            "correlation",
            ThreatCategory.COMMAND_INJECTION,
            Severity.HIGH,
            Severity.MEDIUM,
        ),
        _implementation(
            "CORRELATED_NETWORK_FILE_WRITE_FLOW",
            "correlation",
            ThreatCategory.MALWARE,
            Severity.HIGH,
        ),
        _implementation(
            "CORRELATED_OBFUSCATION_EXECUTION_FLOW",
            "correlation",
            ThreatCategory.OBFUSCATION,
            Severity.HIGH,
            Severity.MEDIUM,
        ),
        _implementation(
            "CORRELATED_SENSITIVE_NETWORK_FLOW",
            "correlation",
            ThreatCategory.DATA_EXFILTRATION,
            Severity.HIGH,
            Severity.MEDIUM,
        ),
        _implementation(
            "FINDING_OUTPUT_NORMALIZATION",
            "scanner",
            ThreatCategory.POLICY_VIOLATION,
            Severity.INFO,
        ),
        _implementation(
            "MDBLOCK_PYTHON_EVAL_EXEC",
            "behavioral",
            ThreatCategory.COMMAND_INJECTION,
            Severity.HIGH,
        ),
        _implementation(
            "MDBLOCK_PYTHON_HTTP_POST",
            "behavioral",
            ThreatCategory.DATA_EXFILTRATION,
            Severity.MEDIUM,
        ),
        _implementation(
            "MDBLOCK_PYTHON_SUBPROCESS",
            "behavioral",
            ThreatCategory.COMMAND_INJECTION,
            Severity.MEDIUM,
        ),
        *(
            _implementation(
                meta_detected_rule_id(category),
                "meta",
                category,
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            )
            for category in ThreatCategory
        ),
    )
}

BUNDLED_INDIRECT_PYTHON_IMPLEMENTATIONS: Mapping[str, BundledPythonImplementation] = MappingProxyType(_IMPLEMENTATIONS)
