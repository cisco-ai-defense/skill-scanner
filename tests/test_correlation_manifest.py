# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Audit correlation candidates against their rule-pack declarations."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import yaml

from skill_scanner.core.analyzers.correlation_analyzer import CorrelationAnalyzer
from skill_scanner.core.scan_policy import ScanPolicy

_CORE_MANIFEST = Path(__file__).resolve().parent.parent / "skill_scanner" / "data" / "packs" / "core" / "pack.yaml"


def _correlation_rule_ids() -> set[str]:
    """Return every statically declared correlation finding ID."""

    tree = ast.parse(inspect.getsource(CorrelationAnalyzer))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("CORRELATED_")
    }


def test_correlation_analyzer_preset_promotion() -> None:
    assert ScanPolicy.default().analyzers.correlation is True
    assert ScanPolicy.from_preset("strict").analyzers.correlation is True
    assert ScanPolicy.from_preset("permissive").analyzers.correlation is False


def test_every_correlation_candidate_is_declared_in_core_manifest() -> None:
    manifest = yaml.safe_load(_CORE_MANIFEST.read_text(encoding="utf-8"))
    rules = manifest["rules"]
    emitted = _correlation_rule_ids()

    missing = emitted - rules.keys()
    assert emitted, "CorrelationAnalyzer audit found no statically declared rule IDs"
    assert not missing, f"CorrelationAnalyzer rules missing from pack.yaml: {sorted(missing)}"

    for rule_id in emitted:
        declaration = rules[rule_id]
        assert declaration["source"] == "python"
        assert declaration["analyzer"] == "correlation"
        assert declaration["knobs"]["enabled"] is True
