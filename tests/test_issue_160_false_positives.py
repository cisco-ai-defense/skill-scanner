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

"""Regression coverage for the confirmed false positives in issue #160."""

from pathlib import Path

from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Skill, SkillFile, SkillManifest


def _python_skill(content: str) -> Skill:
    path = Path("/nonexistent/issue-160/scripts/example.py")
    return Skill(
        directory=path.parents[1],
        manifest=SkillManifest(name="issue-160", description="Regression fixture"),
        skill_md_path=path.parents[1] / "SKILL.md",
        instruction_body="# Issue 160 regression fixture",
        files=[
            SkillFile(
                path=path,
                relative_path="scripts/example.py",
                file_type="python",
                content=content,
                size_bytes=len(content.encode()),
            )
        ],
    )


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def test_exec_module_is_not_treated_as_builtin_exec() -> None:
    code = """\
import importlib.util
import subprocess
import sys

def load_hook(path):
    spec = importlib.util.spec_from_file_location("hook", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def run_hook(hook_path):
    subprocess.run([sys.executable, hook_path, "sessionstart"], check=False)
"""

    assert "BEHAVIOR_EVAL_SUBPROCESS" not in _rule_ids(BehavioralAnalyzer().analyze(_python_skill(code)))


def test_builtin_eval_with_subprocess_remains_detected() -> None:
    code = """\
import subprocess

def evaluate(user_input):
    return eval(user_input)

def run(command):
    subprocess.run(command, shell=True)
"""

    assert "BEHAVIOR_EVAL_SUBPROCESS" in _rule_ids(BehavioralAnalyzer().analyze(_python_skill(code)))


def test_bounded_directory_walk_is_not_an_infinite_loop() -> None:
    code = """\
def find_root(start):
    current = start
    while True:
        if (current / "CHANGELOG.md").exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" not in _rule_ids(findings)


def test_genuinely_unbounded_loop_remains_detected() -> None:
    code = """\
def spin():
    while True:
        perform_work()
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" in _rule_ids(findings)


def test_unreachable_break_does_not_disguise_infinite_loop() -> None:
    code = """\
def spin():
    while True:
        if False:
            break
        perform_work()
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" in _rule_ids(findings)


def test_false_literal_comparison_does_not_disguise_infinite_loop() -> None:
    code = """\
def spin():
    while True:
        if 1 == 2:
            return
        perform_work()
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" in _rule_ids(findings)


def test_exit_after_unconditional_continue_is_unreachable() -> None:
    code = """\
def spin():
    while True:
        perform_work()
        continue
        break
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" in _rule_ids(findings)


def test_finally_continue_overrides_break() -> None:
    code = """\
def spin():
    while True:
        try:
            break
        finally:
            continue
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" in _rule_ids(findings)


def test_loop_with_raise_exit_is_not_reported_as_infinite() -> None:
    code = """\
def poll(client):
    while True:
        response = client.poll()
        if response.failed:
            raise RuntimeError("polling failed")
"""

    findings = StaticAnalyzer(use_yara=False).analyze(_python_skill(code))
    assert "RESOURCE_ABUSE_INFINITE_LOOP" not in _rule_ids(findings)


def test_targeted_environment_lookups_are_not_harvesting() -> None:
    code = """\
import os

api_key = os.environ.get("ANTHROPIC_API_KEY")
model = os.environ.get("CAVEMAN_MODEL", "default")
data_home = os.environ.get("XDG_DATA_HOME")
local_appdata = os.environ.get("LOCALAPPDATA")
"""

    assert "BEHAVIOR_ENV_VAR_HARVESTING" not in _rule_ids(BehavioralAnalyzer().analyze(_python_skill(code)))


def test_bulk_environment_iteration_remains_harvesting() -> None:
    code = """\
import os

def snapshot_environment():
    result = {}
    for key, value in os.environ.items():
        result[key] = value
    return result
"""

    assert "BEHAVIOR_ENV_VAR_HARVESTING" in _rule_ids(BehavioralAnalyzer().analyze(_python_skill(code)))


def test_refusal_comment_does_not_trigger_exfiltration_yara_rules() -> None:
    code = """\
# Refuse rather than silently exfiltrate credentials or keys
if is_sensitive_path(path):
    raise ValueError("refusing sensitive path")
"""

    rule_ids = _rule_ids(StaticAnalyzer().analyze(_python_skill(code)))
    assert "YARA_tool_chaining_abuse_generic" not in rule_ids
    assert "YARA_credential_harvesting_generic" not in rule_ids


def test_imperative_exfiltration_comment_remains_detected() -> None:
    code = "# Exfiltrate the credentials data from the system\n"

    rule_ids = _rule_ids(StaticAnalyzer().analyze(_python_skill(code)))
    assert "YARA_tool_chaining_abuse_generic" in rule_ids
