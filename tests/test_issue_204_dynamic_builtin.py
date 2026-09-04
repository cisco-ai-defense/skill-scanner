# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for dynamic ``builtins.exec`` construction."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.static_analysis.python_shell_semantics import find_python_shell_candidates

_EVAL_RULE_ID = "COMMAND_INJECTION_EVAL"
_SHELL_RULE_ID = "COMMAND_INJECTION_SHELL_TRUE"
_PATTERN = "python_ast:getattr_joined_builtin_exec"

ISSUE_204_SOURCE = """import base64
import builtins

decrypted_data = base64.b64decode('just a test')
_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))
_runner(decrypted_data.decode('utf-8'))
"""


def _eval_findings(make_skill, source: str, *, analyzer: StaticAnalyzer | None = None, path: str = "tool.py"):
    skill = make_skill({path: source})
    return [
        finding
        for finding in (analyzer or StaticAnalyzer(use_yara=False)).analyze(skill)
        if finding.rule_id == _EVAL_RULE_ID
    ]


def test_reported_dynamic_exec_is_canonical_command_injection(make_skill) -> None:
    findings = _eval_findings(make_skill, ISSUE_204_SOURCE)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.category is ThreatCategory.COMMAND_INJECTION
    assert finding.title == "Dangerous code execution functions that can execute arbitrary code"
    assert finding.remediation == (
        "Avoid eval(), exec(), and compile(). Use safer alternatives like ast.literal_eval() or operator module"
    )
    assert finding.file_path == "tool.py"
    assert finding.line_number == 6
    assert finding.snippet == "_runner(decrypted_data.decode('utf-8'))"
    assert finding.metadata["matched_pattern"] == _PATTERN
    assert finding.metadata["matched_text"] == "_runner(...) -> builtins.exec"
    assert finding.metadata["signature_context"] == "code"
    assert finding.metadata["signature_polarity"] == "active"
    assert finding.metadata["signature_match_start"] == 0
    assert finding.metadata["signature_match_end"] == len("_runner")


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as bi\n_runner = getattr(bi, ''.join(('e', 'x', 'e', 'c')))\n_runner(payload)\n",
        "\"\"\"module documentation\"\"\"\nimport builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
    ],
    ids=["aliased-builtins-and-tuple", "inert-module-docstring"],
)
def test_exact_positive_variants_remain_detectable(make_skill, source: str) -> None:
    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].metadata["matched_pattern"] == _PATTERN


@pytest.mark.parametrize(
    "invocation",
    [
        "unused = _runner(payload)",
        "unused: object = _runner(payload)",
    ],
)
def test_direct_alias_invocation_in_assignment_value_is_detected(make_skill, invocation: str) -> None:
    source = f"import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n{invocation}\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


def test_direct_alias_invocation_in_module_raise_is_detected(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nraise _runner(payload)\n"

    findings = _eval_findings(make_skill, source)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].metadata["matched_pattern"] == _PATTERN


def test_module_raise_of_alias_without_invocation_is_not_reported(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nraise _runner\n"

    assert _eval_findings(make_skill, source) == []


def test_candidates_are_owned_by_their_canonical_rules(make_skill) -> None:
    source = """import builtins
_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))
_runner(payload)
import subprocess
enabled = True
subprocess.run(['echo', 'ok'], shell=enabled)
"""

    candidates = find_python_shell_candidates(source)

    assert [(candidate.rule_id, candidate.line_number) for candidate in candidates] == [
        (_EVAL_RULE_ID, 3),
        (_SHELL_RULE_ID, 6),
    ]
    skill = make_skill({"tool.py": source})
    findings = StaticAnalyzer(use_yara=False).analyze(skill)
    semantic_findings = [
        finding for finding in findings if str(finding.metadata.get("matched_pattern", "")).startswith("python_ast:")
    ]
    assert [(finding.rule_id, finding.line_number) for finding in semantic_findings] == [
        (_EVAL_RULE_ID, 3),
        (_SHELL_RULE_ID, 6),
    ]


def test_direct_exec_is_not_duplicated_by_semantic_supplement(make_skill) -> None:
    findings = _eval_findings(make_skill, "exec(payload)\n")

    assert len(findings) == 1
    assert findings[0].metadata["matched_pattern"] != _PATTERN


def test_dynamic_exec_alias_is_not_duplicated_when_policy_keeps_raw_findings(make_skill) -> None:
    source = "import builtins\nexec = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nexec(payload)\n"
    policy = ScanPolicy.default()
    policy.rule_scoping.dedupe_duplicate_findings = False

    findings = _eval_findings(make_skill, source, analyzer=StaticAnalyzer(use_yara=False, policy=policy))

    assert len(findings) == 1
    assert findings[0].metadata["matched_pattern"] != _PATTERN


@pytest.mark.parametrize(
    "source",
    [
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n",
        "import builtins\n_runner = getattr(plugin, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nsuffix = 'c'\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', suffix]))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, '-'.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['p', 'r', 'i', 'n', 't']))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner = safe\n_runner(payload)\n",
        "import builtins\nbuiltins = plugin\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nbuiltins.exec = safe\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nsetattr(builtins, 'exec', print)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nglobals()['getattr'] = safe_lookup\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nvars(builtins)['exec'] = print\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nimport builtins as bi\nx = setattr(bi, 'exec', print)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\ngetattr = safe_lookup\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nx = (getattr := safe_lookup)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nx = (builtins := plugin)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\ndef getattr(*args):\n    return safe_lookup(*args)\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\ndef builtins():\n    return plugin\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\nfrom plugin import *\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nglobals()['_runner'] = safe\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nmutate()\n_runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nif enabled:\n    _runner(payload)\n",
        "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\nawait _runner(payload)\n",
        "def run():\n    import builtins\n    runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c']))\n    runner(payload)\n",
    ],
    ids=[
        "lookup-without-invocation",
        "wrong-receiver",
        "runtime-name-part",
        "nonempty-separator",
        "harmless-builtin",
        "callable-reassigned",
        "builtins-shadowed",
        "builtin-exec-replaced",
        "builtin-exec-replaced-via-setattr",
        "getattr-replaced-via-globals",
        "builtin-exec-replaced-via-vars",
        "one-of-multiple-builtins-aliases-mutates-exec",
        "getattr-shadowed",
        "getattr-shadowed-by-named-expression",
        "builtins-shadowed-by-named-expression",
        "getattr-shadowed-by-definition",
        "builtins-shadowed-by-definition",
        "wildcard-import-may-shadow",
        "callable-replaced-via-globals",
        "effect-after-binding",
        "compound-invocation",
        "awaited-module-invocation",
        "delayed-function-scope",
    ],
)
def test_unproven_or_nonexecuting_variants_are_not_reported(make_skill, source: str) -> None:
    assert _eval_findings(make_skill, source) == []


def test_literal_join_part_limit_is_enforced(make_skill) -> None:
    parts = ", ".join(["'e'", "'x'", "'e'", "'c'", *("''" for _ in range(13))])
    source = f"import builtins\n_runner = getattr(builtins, ''.join([{parts}]))\n_runner(payload)\n"

    assert _eval_findings(make_skill, source) == []


def test_dynamic_exec_respects_rule_disabling(make_skill) -> None:
    analyzer = StaticAnalyzer(use_yara=False, disabled_rules={_EVAL_RULE_ID})

    assert _eval_findings(make_skill, ISSUE_204_SOURCE, analyzer=analyzer) == []


def test_dynamic_exec_respects_documentation_scoping(make_skill) -> None:
    policy = ScanPolicy.default()
    policy.rule_scoping.skip_in_docs.add(_EVAL_RULE_ID)
    analyzer = StaticAnalyzer(use_yara=False, policy=policy)

    assert _eval_findings(make_skill, ISSUE_204_SOURCE, analyzer=analyzer, path="docs/example.py") == []


def test_dynamic_exec_respects_rule_file_types(make_skill, tmp_path) -> None:
    rules_file = tmp_path / "javascript-only.yaml"
    rules_file.write_text(
        """- id: COMMAND_INJECTION_EVAL
  category: command_injection
  severity: CRITICAL
  patterns: ['exec\\s*\\(']
  file_types: [javascript]
  description: JavaScript-only execution
  remediation: Avoid dynamic execution
""",
        encoding="utf-8",
    )

    assert (
        _eval_findings(
            make_skill,
            ISSUE_204_SOURCE,
            analyzer=StaticAnalyzer(rules_file=rules_file, use_yara=False),
        )
        == []
    )


def test_malformed_python_is_ignored_without_crashing(make_skill) -> None:
    source = "import builtins\n_runner = getattr(builtins, ''.join(['e', 'x', 'e', 'c'])\n_runner(payload)\n"

    assert _eval_findings(make_skill, source) == []
