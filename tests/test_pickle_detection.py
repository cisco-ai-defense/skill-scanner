# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for untrusted pickle detection."""

import os
import pickle
from datetime import datetime

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Severity
from skill_scanner.core.scan_policy import ScanPolicy


def _write_skill(skill_dir, payload: bytes):
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: pickle-skill\ndescription: Test serialized configuration\n---\n\n# Skill\n"
    )
    (skill_dir / "config.pkl").write_bytes(payload)


def test_pickle_file_is_never_considered_safe(tmp_path):
    """Even an ordinary pickle must produce a blocking finding."""
    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, pickle.dumps({"enabled": True}))

    skill = SkillLoader().load_skill(skill_dir)
    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    pickle_findings = [f for f in findings if f.rule_id == "PICKLE_FILE_DETECTED"]
    assert len(pickle_findings) == 1
    assert pickle_findings[0].severity == Severity.HIGH


def test_pickle_code_execution_opcode_is_critical(tmp_path):
    """A pickle referring to an execution primitive receives CRITICAL severity."""

    class Execute:
        def __reduce__(self):
            return os.system, ("echo should-not-run",)

    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, pickle.dumps(Execute()))

    skill = SkillLoader().load_skill(skill_dir)
    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    pickle_finding = next(f for f in findings if f.rule_id == "PICKLE_FILE_DETECTED")
    assert pickle_finding.severity == Severity.CRITICAL
    assert any(reference.endswith(" system") for reference in pickle_finding.metadata["dangerous_opcodes"])
    assert "STACK_GLOBAL" in pickle_finding.metadata["observed_executable_opcodes"]


def test_benign_reduce_opcode_is_not_automatically_critical(tmp_path):
    """STACK_GLOBAL and REDUCE alone do not prove a dangerous callable."""
    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, pickle.dumps(datetime(2026, 1, 1)))

    skill = SkillLoader().load_skill(skill_dir)
    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    pickle_finding = next(f for f in findings if f.rule_id == "PICKLE_FILE_DETECTED")
    assert pickle_finding.severity == Severity.HIGH
    assert pickle_finding.metadata["dangerous_opcodes"] == []
    assert {"STACK_GLOBAL", "REDUCE"}.issubset(pickle_finding.metadata["observed_executable_opcodes"])


def test_pickle_inspection_respects_policy_size_limit(tmp_path):
    """Oversized pickle files remain blocking without being read in full."""
    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, pickle.dumps({"payload": "x" * 200}))
    policy = ScanPolicy.default()
    policy.file_limits.max_loader_file_size_bytes = 16

    skill = SkillLoader().load_skill(skill_dir)
    findings = StaticAnalyzer(policy=policy, use_yara=False).analyze(skill)

    pickle_finding = next(f for f in findings if f.rule_id == "PICKLE_FILE_DETECTED")
    assert pickle_finding.severity == Severity.HIGH
    assert pickle_finding.metadata["inspection_skipped_reason"] == "size-limit"
    assert pickle_finding.metadata["inspection_limit_bytes"] == 16


def test_pickle_parser_failure_does_not_abort_scan(tmp_path, monkeypatch):
    """Unexpected parser exceptions are converted into a blocking finding."""
    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, pickle.dumps({"enabled": True}))

    def fail_parser(_payload):
        raise RuntimeError("unexpected parser failure")

    monkeypatch.setattr("skill_scanner.core.analyzers.static.pickletools.genops", fail_parser)
    skill = SkillLoader().load_skill(skill_dir)
    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    pickle_finding = next(f for f in findings if f.rule_id == "PICKLE_FILE_DETECTED")
    assert pickle_finding.severity == Severity.HIGH
    assert pickle_finding.metadata["parse_error"] == "RuntimeError"
