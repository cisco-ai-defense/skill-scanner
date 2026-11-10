# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Security regression coverage for precise Python subprocess argv handling."""

import pytest

from skill_scanner.core.rules import patterns as rule_patterns
from skill_scanner.core.rules.patterns import RuleLoader


@pytest.fixture(scope="module")
def command_rule():
    return next(rule for rule in RuleLoader().load_rules() if rule.id == "COMMAND_INJECTION_OS_SYSTEM")


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True)',
        'subprocess.call(("lsof", "-ti", f":{port}"), shell=False)',
        'subprocess.Popen(["gh", "api", f"repos/{repo}/pulls/{pr_number}/reviews"])',
    ],
)
def test_fixed_direct_argv_is_not_reported_as_shell_injection(command_rule, call):
    source = f"import subprocess\n{call}\n"
    assert command_rule.scan_content(source, "scripts/post_review.py") == []


def test_multiline_gh_api_argv_is_not_reported(command_rule):
    # A multiline direct argv call with a fixed subcommand and route prefix.
    source = """import subprocess
def post_batch_review(repo, pr_number, payload_json):
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/pulls/{pr_number}/reviews",
         "--method", "POST", "--input", "-"],
        input=payload_json, capture_output=True, text=True,
    )
"""
    assert command_rule.scan_content(source, "scripts/post_review.py") == []


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run(["lsof", "-ti", f":{port}"], shell=True)',
        'subprocess.run(["lsof", "-ti", f":{port}"], shell=use_shell)',
        'subprocess.run(["lsof", "-ti", f":{port}"], **options)',
        'subprocess.run(["lsof", "-ti", f":{port}"], executable=program)',
        'subprocess.run(["sh", "-c", f"echo {user}"])',
        'subprocess.run(["/bin/bash", "-c", f"echo {user}"])',
        'subprocess.run(["python3", "-c", f"print({user})"])',
        'subprocess.run(["ssh", "host", f"echo {user}"])',
        'subprocess.run([program, f"file:{user}"])',
        'subprocess.run(["grep", f"{pattern}", "file.txt"])',
        'subprocess.run(["grep", f"-{option}", "file.txt"])',
        'subprocess.run(["gh", *args, f"repos/{repo}"])',
        'subprocess.run(["gh", "alias", f"name-{user}"])',
        'subprocess.run(["docker-compose", "run", f"service-{user}"])',
        'subprocess.run(["gh", "api", f"repos/{repo}"], env={"PATH": bad_path})',
        'subprocess.run(["gh", "api", f"repos/{repo}"], cwd=working_dir)',
        'subprocess.run(["gh", "api", f"repos/{repo}"], preexec_fn=hook)',
        'subprocess.run(f"echo {user}", shell=True)',
    ],
)
def test_shell_or_ambiguous_calls_keep_critical_finding(command_rule, call):
    source = f"import subprocess\n{call}\n"
    matches = command_rule.scan_content(source, "scripts/main.py")
    assert matches
    assert matches[0]["line_number"] == 2
    assert matches[0]["context_kind"] == "code"
    assert matches[0]["polarity"] == "active"


def test_shadowed_subprocess_keeps_finding(command_rule):
    source = 'import subprocess\nsubprocess = wrapper\nsubprocess.run(["gh", "api", f"repos/{repo}"])\n'
    assert command_rule.scan_content(source, "scripts/main.py")


@pytest.mark.parametrize(
    "rebind",
    [
        'globals()["subprocess"] = other',
        'globals().update({"subprocess": other})',
        "subprocess.run = other",
        'subprocess.__dict__["run"] = other',
        'setattr(subprocess, "run", other)',
        'exec("subprocess = other")',
        "match other:\n    case subprocess:\n        pass",
        'sys.modules["subprocess"] = other',
        'from builtins import globals as g\ng()["subprocess"] = other',
        'from sys import modules as m\nm["subprocess"] = other\nimport subprocess',
        'import importlib\nimportlib.import_module("subprocess").run = other',
    ],
)
def test_dynamic_rebinding_keeps_finding(command_rule, rebind):
    source = f'import subprocess\nimport sys\n{rebind}\nsubprocess.run(["gh", "api", f"repos/{{repo}}"])\n'
    assert command_rule.scan_content(source, "scripts/main.py")


@pytest.mark.parametrize("target", ['"subprocess.run"', '"subprocess" + ".run"'])
def test_string_target_patch_keeps_finding(command_rule, target):
    source = """import subprocess
from unittest.mock import patch
with patch(TARGET, new=other):
    subprocess.run(["gh", "api", f"repos/{repo}"])
""".replace("TARGET", target)
    assert command_rule.scan_content(source, "scripts/main.py")


@pytest.mark.parametrize(
    "environment_change",
    [
        'import os\nos.environ["PATH"] = user_path',
        'import os\nos.putenv("PATH", user_path)',
        'from os import environ as env\nenv["PATH"] = user_path',
        "import os\nos.chdir(user_directory)",
    ],
)
def test_process_environment_changes_keep_finding(command_rule, environment_change):
    source = f'import subprocess\n{environment_change}\nsubprocess.run(["gh", "api", f"repos/{{repo}}"])\n'
    assert command_rule.scan_content(source, "scripts/main.py")


def test_malformed_source_keeps_regex_finding(command_rule):
    source = 'import subprocess\nsubprocess.run(["gh", f"repos/{repo}"])\nif (\n'
    assert command_rule.scan_content(source, "scripts/main.py")


def test_source_and_ast_limits_keep_regex_finding(command_rule, monkeypatch):
    source = 'import subprocess\nsubprocess.run(["gh", f"repos/{repo}"])\n'
    monkeypatch.setattr(rule_patterns, "_MAX_SUBPROCESS_SOURCE_BYTES", 20)
    assert command_rule.scan_content(source, "scripts/main.py")
    monkeypatch.setattr(rule_patterns, "_MAX_SUBPROCESS_SOURCE_BYTES", 1024 * 1024)
    monkeypatch.setattr(rule_patterns, "_MAX_SUBPROCESS_AST_NODES", 5)
    assert command_rule.scan_content(source, "scripts/main.py")


def test_safe_first_call_does_not_hide_unsafe_second_call(command_rule):
    source = (
        "import subprocess\n"
        'subprocess.run(["gh", "api", f"repos/{repo}"]); subprocess.run(f"echo {user}", shell=True)\n'
    )
    assert command_rule.scan_content(source, "scripts/main.py")


def test_crlf_source_is_still_precisely_classified(command_rule):
    source = 'import subprocess\r\nsubprocess.run(\r\n ["gh", "api", f"repos/{repo}"],\r\n)\r\n'
    assert command_rule.scan_content(source, "scripts/main.py") == []
