# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for command-injection detection through import aliases."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.scan_policy import ScanPolicy


@pytest.mark.parametrize(
    "embedded_code",
    [
        "import os; os.system('pip install -r requirements.txt')",
        "import os as _o; _o.system('pip install -r requirements.txt')",
    ],
    ids=["canonical-module", "aliased-module"],
)
def test_embedded_python_import_aliases_are_detected(make_skill, embedded_code):
    """Python command payloads must not evade the os.system signature via aliases."""
    skill = make_skill(
        {"scripts/run.py": (f'import subprocess\nsubprocess.run(["python", "-c", {embedded_code!r}])\n')}
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    shell_findings = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert shell_findings, "both canonical and aliased os.system calls must be reported"


def test_direct_aliased_subprocess_shell_is_detected(make_skill):
    """Aliases in normal Python code must preserve subprocess shell=True detection."""
    skill = make_skill({"scripts/run.py": ("import subprocess as sp\nsp.run(user_command, shell=True)\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_nested_aliased_subprocess_shell_is_detected(make_skill):
    """Nested call arguments must not hide shell=True from alias detection."""
    skill = make_skill({"scripts/run.py": ("import subprocess as sp\nsp.run(build_command(user_input), shell=True)\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


@pytest.mark.parametrize("command", ["sp.run('{user_input}', shell=True)", "sp.run(f'{user_input}', shell=True)"])
def test_aliased_dynamic_detection_requires_fstring(make_skill, command):
    """Braces in ordinary strings must not be treated as f-string interpolation."""
    skill = make_skill({"scripts/run.py": (f"import subprocess as sp\n{command}\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    dynamic = [f for f in findings if f.rule_id == "COMMAND_INJECTION_OS_SYSTEM"]

    assert bool(dynamic) is command.startswith("sp.run(f")


def test_aliased_findings_respect_documentation_scoping(make_skill):
    """Alias findings use the same skip_in_docs policy as regular signatures."""
    policy = ScanPolicy.default()
    policy.rule_scoping.skip_in_docs = {"COMMAND_INJECTION_SHELL_TRUE"}
    skill = make_skill({"docs/example.py": ("import subprocess as sp\nsp.run(command, shell=True)\n")})

    findings = StaticAnalyzer(policy=policy, use_yara=False).analyze(skill)

    assert not any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)
