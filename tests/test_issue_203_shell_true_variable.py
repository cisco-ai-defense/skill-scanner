# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for named ``shell=True`` propagation (issue #203)."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.rules.patterns import SignatureScanContext

_RULE_ID = "COMMAND_INJECTION_SHELL_TRUE"


def _matches(analyzer: StaticAnalyzer, skill) -> list:
    return [finding for finding in analyzer.analyze(skill) if finding.rule_id == _RULE_ID]


def test_named_true_shell_flag_is_detected_with_canonical_rule(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

command = f'python a.py'
a = True
result = subprocess.run(
    command,
    shell=a,
    capture_output=True,
    text=True,
)
"""
        }
    )

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == "python_ast:named_shell_flag_is_true"
    assert matches[0].metadata["signature_context"] == "code"
    assert matches[0].metadata["signature_polarity"] == "active"


def test_named_flag_retains_literal_rule_identity(make_skill):
    named = make_skill(
        {
            "scripts/main.py": """
import subprocess
enabled = True
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )
    literal = make_skill(
        {
            "scripts/main.py": """
import subprocess
unused = None
subprocess.run(["echo", "ok"], shell=True)
"""
        }
    )
    analyzer = StaticAnalyzer(use_yara=False)

    named_match = _matches(analyzer, named)[0]
    literal_match = _matches(analyzer, literal)[0]

    assert (
        named_match.rule_id,
        named_match.category,
        named_match.severity,
        named_match.title,
        named_match.remediation,
    ) == (
        literal_match.rule_id,
        literal_match.category,
        literal_match.severity,
        literal_match.title,
        literal_match.remediation,
    )


@pytest.mark.parametrize("method", ["run", "call", "Popen"])
def test_alias_chain_in_straight_line_function_is_detected(make_skill, method):
    skill = make_skill(
        {
            "scripts/main.py": f"""
import subprocess

def launch(command):
    first = True
    second = first
    subprocess.{method}(command, shell=second)
"""
        }
    )

    assert len(_matches(StaticAnalyzer(use_yara=False), skill)) == 1


def test_inert_assignments_do_not_erase_exact_boolean(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
command = ["echo", "ok"]
subprocess.run(command, shell=enabled)
"""
        }
    )

    assert len(_matches(StaticAnalyzer(use_yara=False), skill)) == 1


@pytest.mark.parametrize(
    "body",
    [
        "enabled = False",
        "enabled = 1",
        'enabled = "True"',
        "enabled = None",
        "other = True",
        "enabled = True\nenabled = unknown",
        "enabled = True\nmutate()",
        "enabled = False\nif condition:\n    enabled = True",
        "enabled = True\nif condition:\n    pass",
    ],
)
def test_unknown_or_compound_flow_does_not_add_finding(make_skill, body):
    skill = make_skill(
        {
            "scripts/main.py": f"""
import subprocess

{body}
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


def test_assignment_after_call_does_not_flow_backwards(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

subprocess.run(["echo", "ok"], shell=enabled)
enabled = True
"""
        }
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


@pytest.mark.parametrize("assignment", ["enabled = False\nenabled = True", "enabled: bool = True"])
def test_latest_exact_true_assignment_is_detected(make_skill, assignment):
    skill = make_skill(
        {
            "scripts/main.py": f"""
import subprocess

{assignment}
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )

    assert len(_matches(StaticAnalyzer(use_yara=False), skill)) == 1


def test_module_binding_is_not_inherited_by_delayed_function(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
def launch(command):
    subprocess.run(command, shell=enabled)
"""
        }
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


def test_class_method_uses_fresh_local_bindings(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = False
class Runner:
    def launch(self, command):
        enabled = True
        subprocess.run(command, shell=enabled)
"""
        }
    )

    assert len(_matches(StaticAnalyzer(use_yara=False), skill)) == 1


def test_multiline_named_flag_is_detected_at_call_line(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
subprocess.run(
    ["echo", "ok"],
    shell=enabled,
)
"""
        }
    )

    matches = _matches(StaticAnalyzer(use_yara=False), skill)
    assert len(matches) == 1
    assert matches[0].line_number == 5


def test_split_line_subprocess_attribute_is_ignored(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
subprocess \\
    .run(["echo", "ok"], shell=enabled)
"""
        }
    )

    # An Attribute spanning physical lines has no honest single-line evidence
    # span for the signature adapter.  Decline it instead of misreporting the
    # receiver line or slicing AST byte offsets against the wrong line.
    assert not _matches(StaticAnalyzer(use_yara=False), skill)


def test_effectful_command_argument_cannot_mutate_flag_before_lookup(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
subprocess.run(change_enabled(), shell=enabled)
"""
        }
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


@pytest.mark.parametrize("expression", ["{attacker}", "{attacker: 'value'}"])
def test_hashing_container_is_a_side_effect_boundary(make_skill, expression):
    skill = make_skill(
        {
            "scripts/main.py": f"""
import subprocess

enabled = True
options = {expression}
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


def test_effectful_annotation_is_a_boundary(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
annotation: mutate() = 1
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


def test_literal_true_remains_a_single_regex_finding(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

subprocess.run(["echo", "ok"], shell=True)
"""
        }
    )

    matches = _matches(StaticAnalyzer(use_yara=False), skill)
    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] != "python_ast:named_shell_flag_is_true"


def test_literal_and_named_call_on_one_line_keep_distinct_occurrences(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
subprocess.run("first", shell=True); subprocess.run("second", shell=enabled)
"""
        }
    )

    analyzer = StaticAnalyzer(use_yara=False)
    analyzer.policy.rule_scoping.dedupe_duplicate_findings = False
    matches = _matches(analyzer, skill)

    assert len(matches) == 2
    assert len({match.id for match in matches}) == 2
    assert {match.metadata["matched_pattern"] == "python_ast:named_shell_flag_is_true" for match in matches} == {
        False,
        True,
    }
    assert len({match.metadata["signature_match_start"] for match in matches}) == 2


def test_example_path_uses_shared_signature_context(make_skill):
    skill = make_skill(
        {
            "examples/demo.py": """
import subprocess

enabled = True
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )

    # The final precision gate may suppress illustrative findings, but the
    # signature phase must classify AST evidence exactly like regex evidence.
    matches = [
        finding for finding in StaticAnalyzer(use_yara=False)._scan_scripts(skill) if finding.rule_id == _RULE_ID
    ]

    assert len(matches) == 1
    assert matches[0].metadata["signature_context"] == "example"
    assert matches[0].metadata["signature_polarity"] == "illustrative"


def test_unicode_prefix_uses_character_offsets(make_skill):
    line = 'π = 1; enabled = True; subprocess.run(["echo"], shell=enabled)'
    skill = make_skill({"scripts/main.py": line})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["signature_match_start"] == line.index("subprocess")
    assert matches[0].metadata["signature_match_end"] == line.index("subprocess") + len("subprocess.run")


def test_attacker_sized_identifier_is_not_copied_into_evidence(make_skill):
    identifier = "enabled_" + ("x" * 256)
    skill = make_skill(
        {"scripts/main.py": (f'import subprocess\n{identifier} = True\nsubprocess.run(["echo"], shell={identifier})\n')}
    )

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


def test_named_shell_rule_can_still_be_disabled(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import subprocess

enabled = True
subprocess.run(["echo", "ok"], shell=enabled)
"""
        }
    )

    analyzer = StaticAnalyzer(use_yara=False, disabled_rules={_RULE_ID})
    assert not _matches(analyzer, skill)


@pytest.mark.parametrize("source", ["def broken(:\n", "enabled = True\x00\nsubprocess.run('x', shell=enabled)\n"])
def test_malformed_or_null_python_is_ignored_safely(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert not _matches(StaticAnalyzer(use_yara=False), skill)


@pytest.mark.parametrize(
    ("line_index", "start", "end"),
    [(-1, 0, 1), (1, 0, 1), (0, -1, 1), (0, 2, 1), (0, 0, 99)],
)
def test_signature_context_rejects_invalid_syntax_match_spans(line_index, start, end):
    context = SignatureScanContext("x")

    assert context.classify_match(line_index, "scripts/main.py", match_start=start, match_end=end) == (
        "unknown",
        "unknown",
    )
