# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for command-injection detection through import aliases."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer


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
