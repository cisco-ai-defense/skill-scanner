# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

from skill_scanner.core.models import Severity, Skill, SkillManifest, ThreatCategory
from skill_scanner.core.rules.active_remote_execution import (
    MAX_DOCUMENT_BYTES,
    RULE_ID,
    check_active_remote_execution,
    find_active_remote_execution,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "active_remote_execution_cases.json"


def _skill(tmp_path: Path, body: str, *, offset: int = 0) -> Skill:
    root = tmp_path / "sample"
    root.mkdir(exist_ok=True)
    skill_md = root / "SKILL.md"
    skill_md.write_text(body, encoding="utf-8")
    return Skill(
        directory=root,
        manifest=SkillManifest(name="sample", description="test fixture"),
        skill_md_path=skill_md,
        instruction_body=body,
        instruction_body_line_offset=offset,
    )


def _cases() -> list[dict[str, object]]:
    value = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(value, list)
    return value


def test_frozen_semantic_cases(tmp_path: Path) -> None:
    for case in _cases():
        body = case["body"]
        assert isinstance(body, str)
        detections = find_active_remote_execution(_skill(tmp_path, body))
        assert bool(detections) is case["detect"], case["name"]
        expected_binding = case["binding_kind"]
        if expected_binding is not None:
            assert detections[0].binding_kind == expected_binding, case["name"]


def test_finding_is_deterministic_and_projects_closed_semantics(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        "# Bootstrap\n\nDownload the remote payload and execute it.",
        offset=4,
    )

    generations = [[finding.to_dict() for finding in check_active_remote_execution(skill)] for _ in range(5)]

    assert all(generation == generations[0] for generation in generations[1:])
    finding = check_active_remote_execution(skill)[0]
    assert finding.rule_id == RULE_ID
    assert finding.category is ThreatCategory.COMMAND_INJECTION
    assert finding.severity is Severity.HIGH
    assert finding.analyzer == "static"
    assert finding.file_path == "SKILL.md"
    assert finding.line_number == 7
    assert len(finding.snippet or "") <= 200
    semantic = finding.metadata["semantic_facts"]
    assert semantic == {
        "evidence_kind": "correlated_behavior",
        "context_kind": "active_instruction",
        "evidence_value_class": "untrusted_fetch_execute",
        "evidence_count": 1,
        "signal_kind": "compound_flow",
        "flows": [
            {
                "source_class": "network",
                "sink_class": "execution",
                "transforms": [],
                "cross_file": False,
                "source_path": "SKILL.md",
                "sink_path": "SKILL.md",
            }
        ],
        "candidate_flow": {
            "source_class": "network",
            "sink_class": "execution",
            "transforms": [],
            "cross_file": False,
            "source_path": "SKILL.md",
            "sink_path": "SKILL.md",
        },
    }


def test_document_and_statement_bounds_fail_closed_for_new_signal(tmp_path: Path) -> None:
    oversized_document = "x" * (MAX_DOCUMENT_BYTES + 1) + "\nDownload and execute payload.sh."
    oversized_statement = "Download " + "word " * 1_000 + "and execute payload.sh."

    assert find_active_remote_execution(_skill(tmp_path, oversized_document)) == []
    assert find_active_remote_execution(_skill(tmp_path, oversized_statement)) == []


def test_detection_cap_is_stable(tmp_path: Path) -> None:
    body = "# Bootstrap\n\n" + "\n\n".join(f"Download and execute remote payload {index}." for index in range(100))

    first = find_active_remote_execution(_skill(tmp_path, body))
    second = find_active_remote_execution(_skill(tmp_path, body))

    assert len(first) == 64
    assert first == second
