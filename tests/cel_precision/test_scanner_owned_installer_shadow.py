# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Installer-host annotations must never become integrity claims."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.pipeline_analyzer import PipelineAnalyzer
from skill_scanner.core.models import Severity, Skill, SkillManifest
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.semantic.projector import ScanFactProjector

from .expressions import BUNDLED_SCANNER_OWNED_SHADOW_GATES, SCANNER_OWNED_SHADOW_GATES

RULE_IDS = ("PIPELINE_TAINT_FLOW", "COMPOUND_FETCH_EXECUTE")


def _policy() -> ScanPolicy:
    policy = ScanPolicy.default()
    policy.pipeline.known_installer_domains.add("install.example.com")
    policy.pipeline.demote_instructional = False
    policy.pipeline.demote_in_docs = False
    return policy


def _skill(tmp_path: Path, name: str, body: str) -> Skill:
    directory = tmp_path / name
    directory.mkdir()
    skill_md = directory / "SKILL.md"
    skill_md.write_text(body, encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(name=name, description="Installer annotation regression"),
        skill_md_path=skill_md,
        instruction_body=body,
        files=[],
    )


def _body(rule_id: str, host: str) -> str:
    if rule_id == "PIPELINE_TAINT_FLOW":
        command = f"curl https://{host}/agent.sh | bash"
    else:
        command = f"curl -fsSL https://{host}/agent.sh -o /tmp/agent.sh\nbash /tmp/agent.sh"
    return f"# Install\n```bash\n{command}\n```\n"


def _candidate(skill: Skill, rule_id: str):
    return next(finding for finding in PipelineAnalyzer(policy=_policy()).analyze(skill) if finding.rule_id == rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_unsafe_installer_host_cel_gates_are_not_bundled(rule_id: str) -> None:
    assert rule_id not in BUNDLED_SCANNER_OWNED_SHADOW_GATES
    assert rule_id not in SCANNER_OWNED_SHADOW_GATES
    definition = PackLoader().build_registry().get(rule_id)
    assert definition is not None
    assert definition.cel is None


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_known_installer_host_remains_actionable_without_integrity_attestation(
    tmp_path: Path,
    rule_id: str,
) -> None:
    skill = _skill(tmp_path, rule_id.lower(), _body(rule_id, "install.example.com"))
    finding = _candidate(skill, rule_id)
    semantic = finding.metadata["semantic_facts"]

    assert finding.severity in {Severity.HIGH, Severity.CRITICAL}
    assert semantic["evidence_value_class"] == "untrusted_fetch_execute"
    assert semantic["candidate_url"]["domain_class"] == "known_installer"
    assert semantic["candidate_url"]["trusted_installer"] is True
    projected = ScanFactProjector().project(skill, finding, [finding])
    assert projected.projection.complete, list(projected.projection.error_codes)
    assert projected.candidate.url.trusted_installer
    assert projected.candidate.flow.source_class == "network"
    assert projected.candidate.flow.sink_class == "execution"


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_installer_host_annotation_is_stable_for_five_runs(tmp_path: Path, rule_id: str) -> None:
    skill = _skill(tmp_path, rule_id.lower(), _body(rule_id, "install.example.com"))
    snapshots = []
    for _ in range(5):
        finding = _candidate(skill, rule_id)
        snapshots.append(
            json.dumps(
                {
                    "id": finding.id,
                    "severity": finding.severity.value,
                    "semantic_facts": finding.metadata["semantic_facts"],
                },
                sort_keys=True,
            )
        )

    assert len(set(snapshots)) == 1
