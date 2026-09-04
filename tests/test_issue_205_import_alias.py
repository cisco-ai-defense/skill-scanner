# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for import-resolved os.system calls (issue #205)."""

import sys

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import ScanResult, Severity
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.static_analysis import python_shell_semantics

_RULE_ID = "COMMAND_INJECTION_SHELL_TRUE"
_DIRECT_PATTERN = "python_ast:resolved_os_system_alias"
_EMBEDDED_PATTERN = "python_ast:embedded_python_c_resolved_os_system"
_PAYLOAD = "import os as o; o.system('id')"


def _shell_findings(make_skill, source: str, *, path: str = "scripts/run.py", policy=None) -> list:
    skill = make_skill({path: source})
    analyzer = StaticAnalyzer(policy=policy, use_yara=False)
    return [finding for finding in analyzer.analyze(skill) if finding.rule_id == _RULE_ID]


def _semantic_findings(make_skill, source: str, *, path: str = "scripts/run.py", policy=None) -> list:
    return [
        finding
        for finding in _shell_findings(make_skill, source, path=path, policy=policy)
        if str(finding.metadata.get("matched_pattern", "")).startswith("python_ast:")
    ]


def _python_c_source(payload: str, *, caller: str = "subprocess.run") -> str:
    return f'import subprocess\n{caller}([\n    "python",\n    "-c",\n    {payload!r},\n])\n'


def _assert_canonical_rule_parity(canonical, aliased) -> None:
    assert (
        aliased.rule_id,
        aliased.category,
        aliased.severity,
        aliased.title,
        aliased.remediation,
        aliased.analyzer,
    ) == (
        canonical.rule_id,
        canonical.category,
        canonical.severity,
        canonical.title,
        canonical.remediation,
        canonical.analyzer,
    )
    provenance_keys = {
        "matched_pattern",
        "matched_text",
        "signature_pattern_index",
        "signature_match_start",
        "signature_match_end",
        "signature_pattern_sha256",
    }
    assert {key: value for key, value in aliased.metadata.items() if key not in provenance_keys} == {
        key: value for key, value in canonical.metadata.items() if key not in provenance_keys
    }


def test_issue_205_embedded_alias_matches_canonical_rule_and_safety(make_skill):
    canonical = _shell_findings(
        make_skill,
        _python_c_source("import os; os.system('pip install -r requirements.txt')"),
    )
    aliased = _shell_findings(
        make_skill,
        _python_c_source("import os as _o; _o.system('pip install -r requirements.txt')"),
    )

    assert len(canonical) == len(aliased) == 1
    _assert_canonical_rule_parity(canonical[0], aliased[0])
    assert aliased[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN
    assert aliased[0].metadata["matched_text"] == (
        "subprocess.run(... Python -c payload invokes import-resolved os.system)"
    )
    assert "pip install" not in aliased[0].metadata["matched_text"]

    canonical_result = ScanResult("canonical", "/tmp/canonical", findings=canonical)
    aliased_result = ScanResult("aliased", "/tmp/aliased", findings=aliased)
    assert canonical_result.is_safe is aliased_result.is_safe is False
    assert canonical_result.max_severity is aliased_result.max_severity is Severity.HIGH


def test_direct_alias_matches_canonical_rule_metadata(make_skill):
    canonical = _shell_findings(make_skill, "import os\nos.system('id')\n")
    aliased = _shell_findings(make_skill, "import os as operating_system\noperating_system.system('id')\n")

    assert len(canonical) == len(aliased) == 1
    _assert_canonical_rule_parity(canonical[0], aliased[0])
    assert aliased[0].metadata["matched_pattern"] == _DIRECT_PATTERN
    assert aliased[0].metadata["matched_text"] == "import-resolved alias invokes os.system(...)"


@pytest.mark.parametrize(
    ("source", "line_number"),
    [
        ("import os as o\no.system('id')\n", 2),
        ("from os import system as execute\nexecute('id')\n", 2),
        ("def launch():\n    import os as o\n    o.system('id')\n", 3),
        ("class Runner:\n    import os as o\n    o.system('id')\n", 3),
    ],
)
def test_direct_alias_forms_are_resolved_in_their_scope(make_skill, source, line_number):
    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == line_number
    assert matches[0].metadata["matched_pattern"] == _DIRECT_PATTERN


@pytest.mark.parametrize(
    "compound_body",
    [
        "if __name__ == '__main__':\n    import os as o\n    o.system('id')",
        "for item in [0]:\n    import os as o\n    o.system('id')",
        "while condition:\n    import os as o\n    o.system('id')\n    break",
        "with manager:\n    import os as o\n    o.system('id')",
        "try:\n    import os as o\n    o.system('id')\nexcept Exception:\n    pass",
        "match value:\n    case _:\n        import os as o\n        o.system('id')",
    ],
    ids=["if", "for", "while", "with", "try", "match"],
)
def test_self_contained_compound_body_is_scanned_with_fresh_identity(make_skill, compound_body):
    matches = _semantic_findings(make_skill, compound_body + "\n")

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _DIRECT_PATTERN


@pytest.mark.parametrize(
    "compound_body",
    [
        "if False:\n    import os as o\n    o.system('id')",
        "while False:\n    import os as o\n    o.system('id')",
        "for item in ():\n    import os as o\n    o.system('id')",
    ],
    ids=["false-if", "false-while", "empty-for"],
)
def test_statically_unreachable_compound_body_is_not_scanned(make_skill, compound_body):
    assert not _semantic_findings(make_skill, compound_body + "\n")


def test_embedded_self_contained_compound_body_is_scanned(make_skill):
    payload = "if True:\n    import os as o\n    o.system('id')"

    matches = _semantic_findings(make_skill, _python_c_source(payload))

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN


@pytest.mark.parametrize(
    "source",
    [
        "# import os as o\no.system('id')\n",
        "'import os as o'\no.system('id')\n",
        "import os.path as o\no.system('id')\n",
        "from os import path as o\no.system('id')\n",
        "import os as o\no = helper\no.system('id')\n",
        "import os as o\ndef launch(o):\n    o.system('id')\n",
        "import os as o\ndef launch():\n    o = helper\n    o.system('id')\n",
        "import os as o\nimport sys as o\no.system('id')\n",
        "import os as o\no.getenv('HOME')\n",
    ],
)
def test_unproven_direct_aliases_are_rejected(make_skill, source):
    assert not _semantic_findings(make_skill, source)


def test_later_alias_poisoning_does_not_hide_an_earlier_call(make_skill):
    source = "import os as o\no.system('first')\nimport sys as o\no.system('second')\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == 2


@pytest.mark.parametrize(
    "invalid_statement",
    ["return", "consume(value=o.system('id'), value=1)"],
    ids=["top-level-return", "duplicate-keyword"],
)
def test_compile_time_invalid_outer_source_has_no_semantic_findings(make_skill, invalid_statement):
    source = f"import os as o\no.system('id')\n{invalid_statement}\n"

    assert not _semantic_findings(make_skill, source)


def test_reviewed_inert_calls_preserve_identity_for_later_calls(make_skill):
    source = "import os as o\no.system('first')\no.system('second')\n"

    matches = _semantic_findings(make_skill, source)

    assert [finding.line_number for finding in matches] == [2, 3]


def test_annotation_only_declaration_preserves_imported_identity(make_skill):
    source = "import os as o\no: object\no.system('id')\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == 3


@pytest.mark.parametrize(
    ("source", "line_number"),
    [
        ("def launch():\n    global o\n    import os as o\n    o.system('id')\n", 4),
        (
            "def outer():\n"
            "    execute = None\n"
            "    def launch():\n"
            "        nonlocal execute\n"
            "        from os import system as execute\n"
            "        execute('id')\n",
            6,
        ),
    ],
    ids=["global-import", "nonlocal-import-from"],
)
def test_explicit_import_tracks_declared_external_name(make_skill, source, line_number):
    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == line_number


@pytest.mark.parametrize(
    "assignment",
    [
        'result = sp.run(["echo"])',
        'result: object = sp.run(["echo"])',
    ],
    ids=["assign", "annotated-assign"],
)
def test_reviewed_call_assignment_preserves_unrelated_identity(make_skill, assignment):
    source = f"import os as o\nimport subprocess as sp\n{assignment}\no.system('id')\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == 4


@pytest.mark.parametrize(
    "assignment",
    [
        'o = sp.run(["echo"])',
        'o: object = sp.run(["echo"])',
    ],
    ids=["assign", "annotated-assign"],
)
def test_reviewed_call_assignment_replaces_target_identity(make_skill, assignment):
    source = f"import os as o\nimport subprocess as sp\n{assignment}\no.system('id')\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize("embedded", [False, True])
def test_module_method_mutation_poison_survives_reimport(make_skill, embedded):
    body = "import os; os.system = fake; import os as o; o.system('id')"
    source = _python_c_source(body) if embedded else body

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize("embedded", [False, True])
def test_module_mapping_mutation_poison_survives_reimport(make_skill, embedded):
    body = "import os; os.__dict__['system'] = fake; import os as o; o.system('id')"
    source = _python_c_source(body) if embedded else body

    assert not _semantic_findings(make_skill, source)


def test_adjacent_literals_cannot_hide_canonical_embedded_call(make_skill):
    source = "import subprocess\nsubprocess.run(['python', '-c', \"import os; os.\" \"system('id')\"])\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN


@pytest.mark.parametrize(
    "source",
    [
        f"commands = ['python', '-c', {_PAYLOAD!r}]\n",
        f"runner(['python', '-c', {_PAYLOAD!r}])\n",
        f"import subprocess\nsubprocess.run(['bash', '-c', {_PAYLOAD!r}])\n",
        f"import subprocess\nsubprocess.run(['python', {_PAYLOAD!r}])\n",
        f"import subprocess\npayload = {_PAYLOAD!r}\nsubprocess.run(['python', '-c', payload])\n",
        "import subprocess\nsubprocess.run('python -c payload')\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], executable='bash')\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], env={{'PATH': '/tmp/fake'}})\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], cwd='/definitely/missing')\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], preexec_fn=hook)\n",
        f"import subprocess\nsubprocess.Popen(['python', '-c', {_PAYLOAD!r}], check=True)\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], check=missing)\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], check=1 / 0)\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], -1, 'bash')\n",
        f"import subprocess\nsubprocess.run(['python', '-c', {_PAYLOAD!r}], shell=True)\n",
    ],
)
def test_embedded_scan_requires_an_exact_literal_python_c_execution(make_skill, source):
    assert not [
        finding
        for finding in _semantic_findings(make_skill, source)
        if finding.metadata["matched_pattern"] == _EMBEDDED_PATTERN
    ]


@pytest.mark.parametrize(
    "source",
    [
        f"import subprocess as sp\nsp.run(args=['python3', '-c', {_PAYLOAD!r}], check=True)\n",
        (
            "from subprocess import Popen as launch\n"
            "launch(('python3.13.exe', '-c', "
            + repr("from os import system as execute; execute('id')")
            + "), shell=False)\n"
        ),
    ],
)
def test_exact_python_c_execution_accepts_resolved_outer_call_forms(make_skill, source):
    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN


@pytest.mark.parametrize(
    "payload",
    [
        "# import os as o\no.system('id')",
        "marker = 'import os as o'; o.system('id')",
        "import os.path as o; o.system('id')",
        "import os as o; o = helper; o.system('id')",
        "import os as o; import sys as o; o.system('id')",
        "import os as o; o.system('id'); return",
        "def launch(o): o.system('id')",
        "import os as o; o.system(",
        "\x00import os as o; o.system('id')",
    ],
)
def test_embedded_alias_requires_valid_source_ordered_positive_evidence(make_skill, payload):
    assert not _semantic_findings(make_skill, _python_c_source(payload))


def test_embedded_later_poisoning_keeps_only_the_earlier_evidence(make_skill):
    payload = "import os as o; o.system('first'); import sys as o; o.system('second')"

    matches = _semantic_findings(make_skill, _python_c_source(payload))

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN


def test_unicode_prefix_uses_character_offsets_for_outer_evidence(make_skill):
    source = f"import subprocess\ncafé = 1; subprocess.run(['python', '-c', {_PAYLOAD!r}])\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    finding = matches[0]
    line = source.splitlines()[1]
    expected_start = line.index("subprocess.run")
    assert finding.line_number == 2
    assert finding.metadata["signature_match_start"] == expected_start
    assert finding.metadata["signature_match_end"] == expected_start + len("subprocess.run")


def test_malformed_outer_source_and_nul_have_no_textual_fallback():
    forged = ("# import os as o\no.system('id')\n" * 1_000) + "if\n"

    assert python_shell_semantics.find_python_shell_candidates(forged) == ()
    assert python_shell_semantics.find_python_shell_candidates("\x00" + forged) == ()


def test_embedded_payloads_share_the_same_cumulative_byte_budget(monkeypatch):
    payload_bytes = len(_PAYLOAD.encode("utf-8"))
    source = _python_c_source(_PAYLOAD) + f"subprocess.run(['python', '-c', {_PAYLOAD!r}])\n"
    monkeypatch.setattr(
        python_shell_semantics,
        "MAX_PYTHON_SHELL_EMBEDDED_BYTES",
        payload_bytes,
    )

    candidates = python_shell_semantics.find_python_shell_candidates(source)
    embedded = [candidate for candidate in candidates if candidate.matched_pattern == _EMBEDDED_PATTERN]

    assert len(embedded) == 1


def test_alias_findings_respect_documentation_scoping(make_skill):
    policy = ScanPolicy.default()
    policy.rule_scoping.skip_in_docs = {_RULE_ID}
    source = "import os as operating_system\noperating_system.system('id')\n"

    assert not _shell_findings(make_skill, source, path="docs/example.py", policy=policy)


def test_same_line_regex_match_does_not_hide_distinct_alias(make_skill):
    source = "import os, os as o; os.system('first'); o.system('second')\n"

    matches = _shell_findings(make_skill, source)

    assert len(matches) == 2
    assert {str(match.metadata["matched_pattern"]).startswith("python_ast:") for match in matches} == {False, True}


@pytest.mark.parametrize(
    "statement",
    [
        "if o.system('id'): pass",
        "while o.system('id'): break",
        "for item in [o.system('id')]: pass",
        "with o.system('id'): pass",
        "match o.system('id'):\n    case _: pass",
    ],
    ids=["if", "while", "for", "with", "match"],
)
def test_compound_headers_scan_resolved_calls_before_clearing_aliases(make_skill, statement):
    matches = _semantic_findings(make_skill, f"import os as o\n{statement}\n")

    assert len(matches) == 1
    assert matches[0].line_number == 2


@pytest.mark.parametrize(
    "expression",
    [
        "[o.system('id')]",
        "(o.system('id'),)",
        "consume(o.system('id'))",
        "(result := o.system('id'))",
    ],
    ids=["list", "tuple", "call-argument", "named-expression"],
)
def test_eager_nested_expressions_scan_resolved_calls(make_skill, expression):
    matches = _semantic_findings(make_skill, f"import os as o\nresult = {expression}\n")

    assert len(matches) == 1
    assert matches[0].line_number == 2


@pytest.mark.parametrize(
    ("definition", "line_number"),
    [
        ("@o.system('id')\ndef launch(): pass", 2),
        ("def launch(value=o.system('id')): pass", 2),
        ("class Runner(o.system('id')): pass", 2),
    ],
    ids=["decorator", "default", "class-base"],
)
def test_definition_time_expressions_scan_current_aliases(make_skill, definition, line_number):
    matches = _semantic_findings(make_skill, f"import os as o\n{definition}\n")

    assert len(matches) == 1
    assert matches[0].line_number == line_number


def test_eager_annotations_follow_the_running_python_semantics(make_skill):
    source = "import os as o\ndef launch(value: o.system('id')): pass\n"

    matches = _semantic_findings(make_skill, source)

    assert bool(matches) is (sys.version_info < (3, 14))


def test_future_annotations_are_not_scanned_as_definition_time_calls(make_skill):
    source = "from __future__ import annotations\nimport os as o\ndef launch(value: o.system('id')): pass\n"

    assert not _semantic_findings(make_skill, source)


def test_earlier_definition_expression_effect_invalidates_later_alias(make_skill):
    source = "import os as o\n@mutate()\ndef launch(value=o.system('id')): pass\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "expression",
    [
        "False and o.system('id')",
        "True or o.system('id')",
        "o.system('id') if False else None",
        "lambda: o.system('id')",
        "(o.system('id') for _ in [1])",
        "[o.system('id') for _ in []]",
    ],
    ids=["false-and", "true-or", "false-if-expression", "lambda", "generator", "empty-comprehension"],
)
def test_deferred_or_unreachable_nested_calls_are_not_scanned(make_skill, expression):
    assert not _semantic_findings(make_skill, f"import os as o\nresult = {expression}\n")


def test_zero_argument_immediate_lambda_is_scanned(make_skill):
    source = "import os as o\nresult = (lambda: o.system('id'))()\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_expression_depth_limit_drops_overdeep_candidate(monkeypatch):
    monkeypatch.setattr(python_shell_semantics, "MAX_PYTHON_SHELL_SCOPE_DEPTH", 2)
    source = "import os as o\nresult = [[[o.system('id')]]]\n"

    assert python_shell_semantics.find_python_shell_candidates(source) == ()
