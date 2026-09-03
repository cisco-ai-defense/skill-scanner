# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for command-injection detection through import aliases."""

import ast
import tokenize
from unittest.mock import patch

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


def test_aliased_subprocess_check_true_is_not_shell_true(make_skill):
    """Unrelated boolean keywords must not be mistaken for shell=True."""
    skill = make_skill({"scripts/run.py": ("import subprocess as sp\nsp.run(command, check=True)\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert not any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_embedded_aliased_call_with_triple_quoted_argument_is_detected(make_skill):
    """Balanced scanning must close triple-quoted call arguments correctly."""
    embedded = 'import subprocess as sp; sp.run("""build_command(user_input)""", shell=True)'
    skill = make_skill({"scripts/run.py": (f"import subprocess\nsubprocess.run(['python', '-c', {embedded!r}])\n")})

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


def test_malformed_python_uses_textual_alias_fallback(make_skill):
    """Textual snippets remain detectable when the surrounding file is invalid Python."""
    skill = make_skill({"scripts/run.py": ('import subprocess as sp\nsp.run(f"{user_input}", shell=True)\nif\n')})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_fallback_fstring_detection_handles_string_tokens(make_skill):
    """Fallback f-string detection recognizes the pre-3.14 STRING token shape."""
    content = 'import subprocess as sp\nsp.run(f"{user_input}", shell=True)\nif\n'
    skill = make_skill({"scripts/run.py": content})
    token = tokenize.TokenInfo(tokenize.STRING, 'f"{user_input}"', (1, 1), (1, 15), "")

    with patch("skill_scanner.core.analyzers.static.tokenize.generate_tokens", return_value=iter([token])):
        findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_OS_SYSTEM" for f in findings)


def test_fallback_scanner_handles_escaped_quotes_and_unclosed_calls(make_skill):
    """Balanced scanning handles escapes and ignores calls without a closing parenthesis."""
    skill = make_skill(
        {
            "scripts/run.py": (
                'import subprocess as sp\nsp.run("escaped \\" quote", shell=True)\nsp.run(command, shell=True\nif\n'
            )
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_unsupported_aliased_methods_are_ignored(make_skill):
    """Only the documented os/subprocess sinks are considered."""
    skill = make_skill(
        {
            "scripts/run.py": (
                "import os as operating_system\n"
                "import subprocess as process\n"
                "operating_system.getenv('HOME')\n"
                "process.check(command)\n"
                "get_process().run(command, shell=True)\n"
            )
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert not any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_alias_scanner_handles_missing_ast_metadata_and_source_segment(make_skill):
    """Defensive handling keeps malformed AST metadata from aborting a scan."""
    content = 'import os as operating_system\noperating_system.system("id")\n'
    analyzer = StaticAnalyzer(use_yara=False)
    tree = ast.parse(content)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    call.end_lineno = None

    with patch("skill_scanner.core.analyzers.static.ast.parse", return_value=tree):
        findings = analyzer._scan_python_import_aliases(content, "scripts/run.py")

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)

    tree = ast.parse(content)
    with patch("skill_scanner.core.analyzers.static.ast.get_source_segment", return_value=None):
        findings = analyzer._scan_python_import_aliases(content, "scripts/run.py")

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_alias_scanner_ignores_missing_rules_and_tokenizer_errors(make_skill):
    """Optional rule configuration and malformed token streams are handled safely."""
    content = 'import subprocess as sp\nsp.run(f"{user_input}", shell=True)\nif\n'
    skill = make_skill({"scripts/run.py": content})
    analyzer = StaticAnalyzer(use_yara=False)
    analyzer.rule_loader.rules_by_id.pop("COMMAND_INJECTION_OS_SYSTEM", None)
    token = tokenize.TokenInfo(tokenize.STRING, 'f"{user_input}"', (1, 1), (1, 15), "")

    with patch(
        "skill_scanner.core.analyzers.static.tokenize.generate_tokens",
        return_value=iter([token]),
    ):
        findings = analyzer._scan_python_import_aliases(content, "scripts/run.py")

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)
    assert not any(f.rule_id == "COMMAND_INJECTION_OS_SYSTEM" for f in findings)

    with patch(
        "skill_scanner.core.analyzers.static.tokenize.generate_tokens",
        side_effect=tokenize.TokenError("incomplete", (1, 0)),
    ):
        findings = analyzer._scan_python_import_aliases(content, "scripts/run.py")

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)
