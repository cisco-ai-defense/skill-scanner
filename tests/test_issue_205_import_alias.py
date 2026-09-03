# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for command-injection detection through import aliases."""

import ast
import tokenize
from unittest.mock import patch

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.scan_policy import ScanPolicy


def test_embedded_python_import_aliases_are_detected(make_skill):
    """Python command payloads must not evade the os.system signature via aliases."""

    def scan(embedded_code):
        skill = make_skill(
            {"scripts/run.py": (f'import subprocess\nsubprocess.run(["python", "-c", {embedded_code!r}])\n')}
        )
        return next(
            f for f in StaticAnalyzer(use_yara=False).analyze(skill) if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"
        )

    canonical = scan("import os; os.system('pip install -r requirements.txt')")
    aliased = scan("import os as _o; _o.system('pip install -r requirements.txt')")

    assert aliased.category == canonical.category
    assert aliased.severity == canonical.severity
    assert aliased.remediation == canonical.remediation
    assert aliased.analyzer == canonical.analyzer
    for key in ("aitech", "aitech_name", "scanner_category", "source_category", "category_normalization"):
        assert aliased.metadata[key] == canonical.metadata[key]


def test_direct_aliased_subprocess_shell_is_detected(make_skill):
    """Aliases in normal Python code must preserve subprocess shell=True detection."""
    skill = make_skill({"scripts/run.py": ("import subprocess as sp\nsp.run(user_command, shell=True)\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    shell_findings = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 2


def test_nested_aliased_subprocess_shell_is_detected(make_skill):
    """Nested call arguments must not hide shell=True from alias detection."""
    skill = make_skill({"scripts/run.py": ("import subprocess as sp\nsp.run(build_command(user_input), shell=True)\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


def test_embedded_nested_aliased_call_is_not_suppressed(make_skill):
    """An aliased call inside an outer aliased call must remain visible."""
    embedded = "import os as o; o.system('id')"
    skill = make_skill({"scripts/run.py": (f"import subprocess as sp\nsp.run(['python', '-c', {embedded!r}])\n")})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    nested = [
        finding
        for finding in findings
        if finding.rule_id == "COMMAND_INJECTION_SHELL_TRUE" and "o.system" in finding.metadata.get("matched_text", "")
    ]

    assert len(nested) == 1


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
    assert any(f.rule_id == "COMMAND_INJECTION_OS_SYSTEM" for f in findings)


def test_fallback_fstring_detection_handles_string_tokens(make_skill):
    """Fallback f-string detection recognizes the pre-3.14 STRING token shape."""
    content = 'import subprocess as sp\nsp.run(f"{user_input}", shell=True)\nif\n'
    skill = make_skill({"scripts/run.py": content})
    token = tokenize.TokenInfo(tokenize.STRING, 'f"{user_input}"', (1, 1), (1, 15), "")

    with patch("skill_scanner.core.analyzers.static.tokenize.generate_tokens", return_value=iter([token])):
        findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_OS_SYSTEM" for f in findings)


def test_fallback_fstring_detection_handles_pep701_tokens(make_skill):
    """Fallback f-string detection recognizes Python 3.12+ token streams."""
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    fstring_middle = getattr(tokenize, "FSTRING_MIDDLE", None)
    fstring_end = getattr(tokenize, "FSTRING_END", None)
    if None in (fstring_start, fstring_middle, fstring_end):
        pytest.skip("Python 3.12+ f-string tokens are unavailable")

    content = 'import subprocess as sp\nsp.run(f"{user_input}", shell=True)\nif\n'
    skill = make_skill({"scripts/run.py": content})
    token_stream = iter(
        [
            tokenize.TokenInfo(fstring_start, 'f"', (1, 1), (1, 3), ""),
            tokenize.TokenInfo(fstring_middle, "prefix ", (1, 3), (1, 10), ""),
            tokenize.TokenInfo(tokenize.OP, "{", (1, 10), (1, 11), ""),
            tokenize.TokenInfo(tokenize.NAME, "user_input", (1, 11), (1, 21), ""),
            tokenize.TokenInfo(tokenize.OP, "}", (1, 21), (1, 22), ""),
            tokenize.TokenInfo(fstring_end, '"', (1, 22), (1, 23), ""),
        ]
    )

    with patch("skill_scanner.core.analyzers.static.tokenize.generate_tokens", return_value=token_stream):
        findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert any(f.rule_id == "COMMAND_INJECTION_OS_SYSTEM" for f in findings)


def test_fallback_shell_true_requires_outer_keyword(make_skill):
    """Fallback scanning ignores shell=True text in strings, comments, and nested calls."""
    content = (
        "import subprocess as sp\n"
        'sp.run("literal shell=True")\n'
        "sp.run(build_command(shell=True), check=True)\n"
        "sp.run(command, # shell=True\n"
        ")\n"
        "sp.run(command, shell=True)\n"
        "if\n"
    )
    skill = make_skill({"scripts/run.py": content})

    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    shell_findings = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]

    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


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

    shell_findings = [f for f in findings if f.rule_id == "COMMAND_INJECTION_SHELL_TRUE"]
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 2
    assert 'escaped \\" quote' in shell_findings[0].metadata["matched_text"]


def test_fallback_scanner_ignores_nested_and_quoted_shell_text(make_skill):
    """Fallback matching only accepts a top-level shell keyword argument."""
    skill = make_skill(
        {
            "scripts/run.py": (
                "import subprocess as sp\n"
                'sp.run("literal shell=True", check=True)\n'
                "sp.run(build_command(shell=True), check=True)\n"
                "if\n"
            )
        }
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert not any(f.rule_id == "COMMAND_INJECTION_SHELL_TRUE" for f in findings)


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
