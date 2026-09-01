# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for issue #190 multiline command matching."""

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity


def test_multiline_dynamic_subprocess_call_remains_critical(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

def run(download_path):
    subprocess.call(
        f'chmod +x {download_path}',
        shell=True,
    )
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_OS_SYSTEM"]
    assert matches
    assert matches[0].severity == Severity.CRITICAL


def test_multiline_literal_subprocess_call_retains_shell_true_finding(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

subprocess.call(
    ['chmod', '+x', 'tool'],
    shell=True,
)
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert matches
    assert matches[0].severity == Severity.HIGH


def test_single_line_dynamic_subprocess_call_still_matches(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

subprocess.run(f'chmod +x {download_path}', shell=True)
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_OS_SYSTEM"]
    assert matches
    assert matches[0].severity == Severity.CRITICAL
