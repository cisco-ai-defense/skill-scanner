# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""General precision regressions mined from first-party bundled goodware."""

from __future__ import annotations

from pathlib import Path

import yaml

from skill_scanner.core.models import Severity
from skill_scanner.core.rules.patterns import RuleLoader

_ROOT = Path(__file__).resolve().parents[1]
_DATA_EXFIL = _ROOT / "skill_scanner/data/packs/core/signatures/data_exfiltration.yaml"
_CORE_MANIFEST = _ROOT / "skill_scanner/data/packs/core/pack.yaml"


def _rule(rule_id: str):
    loader = RuleLoader(rules_file=_DATA_EXFIL, strict=True)
    loader.load_rules()
    rule = loader.get_rule(rule_id)
    assert rule is not None
    return rule


def test_generic_node_filesystem_access_is_a_low_severity_correlation_candidate() -> None:
    rule = _rule("DATA_EXFIL_JS_FS_ACCESS")

    matches = rule.scan_content("const value = fs.readFileSync(metaPath, 'utf8');", "scripts/report.mjs")

    assert len(matches) == 1
    assert rule.severity is Severity.LOW


def test_sensitive_file_access_retains_independent_high_severity_rule() -> None:
    rule = _rule("DATA_EXFIL_SENSITIVE_FILES")

    matches = rule.scan_content("data = open('/home/user/.aws/credentials').read()", "collector.py")

    assert matches
    assert rule.severity is Severity.HIGH


def test_core_manifest_matches_filesystem_candidate_metadata() -> None:
    manifest = yaml.safe_load(_CORE_MANIFEST.read_text(encoding="utf-8"))

    assert manifest["rules"]["DATA_EXFIL_JS_FS_ACCESS"] == {
        "source": "signature",
        "category": "data_exfiltration",
        "severity": "LOW",
        "knobs": {"enabled": True},
        "description": "Node.js filesystem access candidate for sensitive-flow correlation",
    }
