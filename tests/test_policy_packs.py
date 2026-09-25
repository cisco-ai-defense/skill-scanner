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

"""The low-noise and quiet presets, and the LLM contextual-risk cap they rely on."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
from skill_scanner.core.models import Severity
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner


def test_presets_are_registered_and_load() -> None:
    names = ScanPolicy.preset_names()
    assert {"strict", "balanced", "permissive", "low-noise", "quiet"} <= set(names)
    for name in names:
        assert ScanPolicy.from_preset(name).policy_name == ("default" if name == "balanced" else name)


def test_quiet_extends_low_noise_and_caps_contextual_llm_findings() -> None:
    low = {o.rule_id for o in ScanPolicy.from_preset("low-noise").severity_overrides}
    quiet = ScanPolicy.from_preset("quiet")
    quiet_rules = {o.rule_id for o in quiet.severity_overrides}
    assert low < quiet_rules
    assert all(o.severity == "LOW" for o in quiet.severity_overrides)
    assert quiet.llm_analysis.contextual_risk_max_severity == "LOW"
    assert ScanPolicy.from_preset("low-noise").llm_analysis.contextual_risk_max_severity == ""
    assert ScanPolicy.default().llm_analysis.contextual_risk_max_severity == ""


def test_a_demoted_rule_is_still_reported_at_low(tmp_path: Path) -> None:
    skill = tmp_path / "pack-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: pack-skill\ndescription: Checks things.\n---\n\nRun `scripts/db.py`.\n", encoding="utf-8"
    )
    (skill / "scripts").mkdir()
    (skill / "scripts" / "db.py").write_text(
        'DSN = "postgres://app:Z9q2Lr8x@db.acme-internal.net:5432/app"\n', encoding="utf-8"
    )
    default = [f for f in SkillScanner().scan_skill(skill).findings if f.rule_id == "SECRET_CONNECTION_STRING"]
    low_noise = [
        f
        for f in SkillScanner(policy=ScanPolicy.from_preset("low-noise")).scan_skill(skill).findings
        if f.rule_id == "SECRET_CONNECTION_STRING"
    ]
    assert default and default[0].severity != Severity.LOW
    assert low_noise and {f.severity for f in low_noise} == {Severity.LOW}


@pytest.mark.parametrize(
    ("cap", "severity", "verdict", "expected"),
    [
        ("LOW", Severity.HIGH, "CONTEXTUAL_RISK", Severity.LOW),
        ("LOW", Severity.MEDIUM, "CONTEXTUAL_RISK", Severity.LOW),
        ("LOW", Severity.HIGH, "TRUE_POSITIVE", Severity.HIGH),
        ("LOW", Severity.INFO, "CONTEXTUAL_RISK", Severity.INFO),
        ("MEDIUM", Severity.CRITICAL, "CONTEXTUAL_RISK", Severity.MEDIUM),
        ("", Severity.HIGH, "CONTEXTUAL_RISK", Severity.HIGH),
    ],
)
def test_contextual_risk_cap(cap: str, severity: Severity, verdict: str, expected: Severity) -> None:
    policy = ScanPolicy.default()
    policy.llm_analysis.contextual_risk_max_severity = cap
    analyzer = LLMAnalyzer(model="openai/placeholder", api_key="unused", policy=policy)
    capped, before = analyzer._cap_contextual_risk(severity, verdict)
    assert capped == expected
    assert (before is not None) == (expected != severity)
