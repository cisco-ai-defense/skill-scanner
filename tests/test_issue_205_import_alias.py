# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for issue #205: os.system() detection bypassed via import alias."""

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity
from skill_scanner.core.scan_policy import ScanPolicy


def test_aliased_os_system_call_is_detected(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import os as _o

_o.system('pip install -r requirements.txt')
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert matches
    assert matches[0].severity == Severity.HIGH
    assert matches[0].file_path == "scripts/main.py"
    assert matches[0].line_number == 4


def test_unaliased_os_system_call_still_detected_by_signature(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import os

os.system('pip install -r requirements.txt')
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert matches


def test_unaliased_os_system_call_not_double_reported(make_skill):
    """The AST check must not fire for the literal case -- only the regex signature should."""
    skill = make_skill(
        {
            "scripts/main.py": """
import os

os.system('pip install -r requirements.txt')
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert len(matches) == 1
    assert matches[0].metadata.get("analysis_method") != "import_alias_resolution"


def test_self_aliased_import_treated_as_unaliased(make_skill):
    """``import os as os`` should behave like the unaliased case, not double-fire."""
    skill = make_skill(
        {
            "scripts/main.py": """
import os as os

os.system('pip install -r requirements.txt')
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert len(matches) == 1
    assert matches[0].metadata.get("analysis_method") != "import_alias_resolution"


def test_unrelated_module_alias_does_not_false_positive(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import sys as _o

_o.exit(1)
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert not matches


def test_function_parameter_shadowing_the_alias_is_not_flagged(make_skill):
    """CodeRabbit-flagged case: a parameter reusing the alias name shadows it."""
    skill = make_skill(
        {
            "scripts/main.py": """
import os as _o

def safe(_o):
    _o.system()
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert not matches


def test_local_reassignment_shadowing_the_alias_is_not_flagged(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import os as _o

def handler():
    _o = SomeUnrelatedThing()
    _o.system()
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert not matches


def test_function_local_os_import_is_scoped_to_that_function(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
def run():
    import os as _o
    _o.system('pip install -r requirements.txt')

def unrelated(_o):
    return _o.upper()
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert len(matches) == 1
    assert matches[0].line_number == 4


def test_sibling_function_still_detected_after_shadowing_function(make_skill):
    """A parameter shadow in one function must not leak into a sibling function."""
    skill = make_skill(
        {
            "scripts/main.py": """
import os as _o

def safe(_o):
    _o.system()

def unsafe():
    _o.system('pip install -r requirements.txt')
"""
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert len(matches) == 1
    assert matches[0].line_number == 8


def test_syntax_error_file_does_not_crash_scan(make_skill):
    skill = make_skill(
        {
            "scripts/broken.py": """
def f(:
    pass
"""
        }
    )

    # Should not raise.
    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    assert isinstance(findings, list)


def test_disabled_rule_suppresses_aliased_detection(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import os as _o

_o.system('pip install -r requirements.txt')
"""
        }
    )

    policy = ScanPolicy()
    policy.disabled_rules = {"COMMAND_INJECTION_SHELL_TRUE"}

    findings = StaticAnalyzer(use_yara=False, policy=policy).analyze(skill)
    matches = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert not matches
