# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.cel.validator import validate_cel_expression
from skill_scanner.core.models import Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import PRECISION_GATES


@pytest.mark.parametrize(("rule_id", "expression"), sorted(PRECISION_GATES.items()))
def test_precision_gate_is_in_bounded_typed_subset(rule_id: str, expression: str) -> None:
    assert rule_id
    validate_cel_expression(expression)


def _analyzer() -> StaticAnalyzer:
    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    analyzer._unreferenced_scripts = []
    return analyzer


def _network_skill(
    tmp_path: Path,
    *,
    compatibility: str | None,
    allowed_tools: list[str] | None = None,
) -> Skill:
    directory = tmp_path / "network-skill"
    script_path = directory / "scripts" / "client.py"
    script_path.parent.mkdir(parents=True)
    script = (
        "import glob\n"
        "import re\n"
        "import requests\n"
        "import subprocess\n"
        "open('input.txt', 'r').read()\n"
        "open('output.txt', 'w').write('result')\n"
        "subprocess.run(['bash', '-lc', 'echo ok'])\n"
        "re.search('result', 'result')\n"
        "glob.glob('*.txt')\n"
        "requests.get('https://example.test/status')\n"
    )
    script_path.write_text(script, encoding="utf-8")
    skill_md = directory / "SKILL.md"
    skill_md.write_text("# Network skill\n", encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name="network-skill",
            description="Exercises network capability projection",
            compatibility=compatibility,
            allowed_tools=allowed_tools or ["Read"],
        ),
        skill_md_path=skill_md,
        instruction_body="# Network skill\n",
        files=[
            SkillFile(
                path=script_path,
                relative_path="scripts/client.py",
                file_type="python",
                content=script,
                size_bytes=script_path.stat().st_size,
            )
        ],
        referenced_files=[],
    )


def test_capability_candidates_project_with_relative_manifest_path(tmp_path: Path) -> None:
    skill = _network_skill(tmp_path, compatibility=None, allowed_tools=["Unknown"])
    findings = _analyzer()._check_consistency(skill)
    expected_rule_ids = {
        "TOOL_ABUSE_UNDECLARED_NETWORK",
        "ALLOWED_TOOLS_READ_VIOLATION",
        "ALLOWED_TOOLS_WRITE_VIOLATION",
        "ALLOWED_TOOLS_BASH_VIOLATION",
        "ALLOWED_TOOLS_GREP_VIOLATION",
        "ALLOWED_TOOLS_GLOB_VIOLATION",
        "ALLOWED_TOOLS_NETWORK_USAGE",
    }
    candidates = [finding for finding in findings if finding.rule_id in expected_rule_ids]

    assert {finding.rule_id for finding in candidates} == expected_rule_ids
    assert {finding.file_path for finding in candidates} == {"SKILL.md"}
    for finding in candidates:
        facts = ScanFactProjector().project(skill, finding, findings)
        assert facts.projection.complete, list(facts.projection.error_codes)
        assert facts.candidate.file_path == "SKILL.md"


def test_network_declaration_matches_manifest_compatibility(tmp_path: Path) -> None:
    skill = _network_skill(tmp_path, compatibility="Requires internet access")
    findings = _analyzer()._check_consistency(skill)
    candidate = next(finding for finding in findings if finding.rule_id == "ALLOWED_TOOLS_NETWORK_USAGE")

    facts = ScanFactProjector().project(skill, candidate, findings)

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert facts.skill.declares_network
    assert not any(finding.rule_id == "TOOL_ABUSE_UNDECLARED_NETWORK" for finding in findings)
