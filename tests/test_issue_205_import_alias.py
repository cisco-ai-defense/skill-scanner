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


@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n"], ids=["lf", "cr", "crlf"])
def test_unicode_prefix_uses_character_offsets_for_outer_evidence(make_skill, newline):
    source = newline.join(["import subprocess", f"café = 1; subprocess.run(['python', '-c', {_PAYLOAD!r}])", ""])

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


@pytest.mark.parametrize("keyword", ["def", "async def"])
def test_embedded_unused_function_body_is_deferred(make_skill, keyword):
    payload = f"{keyword} launch():\n    import os as o\n    o.system('id')"

    assert not _semantic_findings(make_skill, _python_c_source(payload))


def test_embedded_function_default_still_executes_at_definition_time(make_skill):
    payload = "import os as o\ndef launch(value=o.system('id')): pass"

    matches = _semantic_findings(make_skill, _python_c_source(payload))

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred on Python 3.14+")
@pytest.mark.parametrize(
    ("source", "line_number"),
    [
        ("import os as o\nx: o.system('id') = 1\n", 2),
        ("import os as o\nx: o.system('id')\n", 2),
        ("import os as o\nclass C:\n    x: o.system('id') = 1\n", 3),
    ],
    ids=["module-value", "module-annotation-only", "class-value"],
)
def test_module_and_class_annotations_execute_after_the_store(make_skill, source, line_number):
    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == line_number


@pytest.mark.parametrize(
    "source",
    [
        "import os as o\no: o.system('id') = 1\n",
        "from __future__ import annotations\nimport os as o\nx: o.system('id') = 1\n",
        "def launch():\n    import os as o\n    x: o.system('id') = 1\n",
    ],
    ids=["store-hides-alias", "future-annotations", "function-local-annotation"],
)
def test_non_runtime_annotations_do_not_create_alias_findings(make_skill, source):
    assert not _semantic_findings(make_skill, source)


def test_eager_class_body_resolves_enclosing_global_alias(make_skill):
    source = "import os as o\nclass Runner:\n    o.system('id')\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == 3


@pytest.mark.parametrize(
    "source",
    [
        "import os as o\nclass Outer:\n    o = object()\n    class Inner:\n        o.system('id')\n",
        "import os as o\n@mutate()\nclass Runner:\n    o.system('id')\n",
        "import os as o\nclass Runner(Base):\n    o.system('id')\n",
    ],
    ids=["nested-class-local", "decorator-effect", "base-protocol"],
)
def test_class_body_does_not_inherit_unproven_aliases(make_skill, source):
    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "source",
    [
        "import os as o\no.system(input())\n",
        "from os import system as execute\nexecute(build_command())\n",
        "from os import system as run\nrun((run := 'id'))\n",
        "import os as o\nconsume(x=mutate(), *[o.system('id')])\n",
    ],
    ids=["module-alias", "callable-alias", "callee-captured", "star-before-keyword"],
)
def test_resolved_callee_is_recorded_before_effectful_arguments(make_skill, source):
    assert len(_semantic_findings(make_skill, source)) == 1


def test_positional_expansion_invalidates_alias_before_keyword_value(make_skill):
    source = "import os as o\nconsume(x=o.system('id'), *mutate())\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    ("initial", "later", "expected"),
    [("True", "False", 1), ("False", "True", 0)],
    ids=["snapshot-true", "snapshot-false"],
)
def test_named_shell_flag_is_snapshotted_at_keyword_evaluation(make_skill, initial, later, expected):
    source = f"import subprocess\nenabled = {initial}\nsubprocess.run([], shell=enabled, later=(enabled := {later}))\n"

    assert len(_semantic_findings(make_skill, source)) == expected


def test_reviewed_subprocess_name_argument_invalidates_later_alias(make_skill):
    source = "import os as o\nimport subprocess as sp\nsp.run([command])\no.system('id')\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "nested",
    [
        "if True:\n    import os as o\n    o.system('id')",
        "if False:\n    pass\nelse:\n    import os as o\n    o.system('id')",
        "while True:\n    import os as o\n    o.system('id')\n    break",
        "while False:\n    pass\nelse:\n    import os as o\n    o.system('id')",
        "for _ in [1]:\n    import os as o\n    o.system('id')",
        "for _ in '':\n    pass\nelse:\n    import os as o\n    o.system('id')",
        "try:\n    import os as o\n    o.system('id')\nexcept Exception:\n    pass",
        "try:\n    raise RuntimeError\nexcept:\n    import os as o\n    o.system('id')",
        "try:\n    pass\nelse:\n    import os as o\n    o.system('id')",
        "try:\n    pass\nfinally:\n    import os as o\n    o.system('id')",
        "class Runner:\n    import os as o\n    o.system('id')",
    ],
)
def test_poisoned_module_state_reaches_nested_runtime_suites(make_skill, nested):
    source = f"import os\nos.system = fake\n{nested}\n"

    assert not _semantic_findings(make_skill, source)


def test_binding_limit_poisons_discarded_module_identity(make_skill, monkeypatch):
    monkeypatch.setattr(python_shell_semantics, "MAX_PYTHON_SHELL_BINDINGS", 1)
    source = "import os, subprocess\nos.system = fake\nimport os as o\no.system('id')\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "source",
    [
        "import os as o\nif True:\n    o.system('id')\n",
        "import os as o\nwhile True:\n    o.system('id')\n    break\n",
        "import os as o\nfor _ in [1]:\n    o.system('id')\n",
        "import os as o\ntry:\n    raise RuntimeError\nexcept:\n    o.system('id')\n",
        "import os as o\ntry:\n    pass\nexcept:\n    pass\nelse:\n    o.system('id')\n",
        "import os as o\ntry:\n    pass\nfinally:\n    o.system('id')\n",
        "import os as o\nmatch 1:\n    case _ if o.system('id'):\n        pass\n",
    ],
)
def test_guaranteed_runtime_suites_retain_alias_facts(make_skill, source):
    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "import os as o\nif []:\n    o.system('id')\n",
        "import os as o\nif True:\n    pass\nelse:\n    o.system('id')\n",
        "import os as o\nfor _ in '':\n    o.system('id')\n",
        "import os as o\nwhile False:\n    o.system('id')\n",
        "for _ in [1]:\n    import os as o\n    break\n    o.system('id')\n",
        "for _ in [1]:\n    import os as o\n    continue\n    o.system('id')\n",
    ],
)
def test_unreachable_suite_calls_are_pruned(make_skill, source):
    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "expression",
    [
        "(lambda value=None: o.system('id'))()",
        "[o.system('id') for _ in [1] for item in [1]]",
        "{1: o.system('id')}",
    ],
    ids=["immediate-defaulted-lambda", "multi-generator-comprehension", "dict-value-order"],
)
def test_additional_eager_expression_positions_are_scanned(make_skill, expression):
    source = f"import os as o\nresult = {expression}\n"

    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "if [*[]]: o.system('unreachable')",
        "[*[]] and o.system('unreachable')",
    ],
    ids=["if", "boolop"],
)
def test_starred_empty_literals_are_falsey(make_skill, statement):
    assert not _semantic_findings(make_skill, f"import os as o\n{statement}\n")


def test_async_generator_failure_does_not_preserve_alias_for_later_code(make_skill):
    source = "import os as o\nvalues = (item async for item in [])\no.system('unreachable')\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    ("mapping", "expected_count"),
    [("{'shell': False}", 0), ("{'cwd': None}", 1)],
    ids=["duplicate-shell", "nonconflicting"],
)
def test_named_shell_flag_waits_for_keyword_expansion_validation(make_skill, mapping, expected_count):
    source = f"import subprocess\nenabled = True\nsubprocess.run([], shell=enabled, **{mapping})\n"

    assert len(_semantic_findings(make_skill, source)) == expected_count


def test_provably_failing_star_expansion_does_not_report_alias_invocation(make_skill):
    source = "from os import system as run\nrun(*None)\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "display",
    ["{evil, o.system('id')}", "{evil: 0, 1: o.system('id')}"],
    ids=["set", "dict"],
)
def test_display_expressions_run_before_hashing(make_skill, display):
    source = f"evil = object()\nimport os as o\n{display}\n"

    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "assert o.system('id')",
        "holder[o.system('id')] = 1",
        "del holder[o.system('id')]",
        "holder[o.system('id')] += 1",
        "value += o.system('id')",
    ],
    ids=["assert", "assignment-target", "delete-target", "augassign-target", "augassign-rhs"],
)
def test_additional_eager_statement_positions_are_scanned(make_skill, statement):
    source = f"import os as o\n{statement}\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_failing_comprehension_destructuring_does_not_reach_element(make_skill):
    source = "import os as o\n[o.system('id') for left, right in [1]]\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize("multiline", [False, True], ids=["one-line", "multiline"])
def test_payload_suffix_regex_is_replaced_by_stronger_semantic_finding(make_skill, multiline):
    payload = "import os as chaos; chaos.system('id')"
    source = (
        _python_c_source(payload) if multiline else f"import subprocess as sp; sp.run(['python', '-c', {payload!r}])\n"
    )

    matches = _shell_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _EMBEDDED_PATTERN


def test_unresolved_suffix_name_is_not_a_legacy_os_system_match(make_skill):
    assert not _shell_findings(make_skill, "chaos.system('id')\n")


def test_distinct_same_line_alias_sinks_keep_occurrence_identity(make_skill):
    source = "import os as a, os as b; a.system('first'); b.system('second')\n"

    matches = _shell_findings(make_skill, source)

    assert len(matches) == 2
    assert len({finding.id for finding in matches}) == 2
    assert len({finding.metadata["signature_match_start"] for finding in matches}) == 2


def test_distinct_same_line_named_shell_sinks_keep_occurrence_identity(make_skill):
    source = (
        "import subprocess; enabled = True; subprocess.run([], shell=enabled); subprocess.call([], shell=enabled)\n"
    )

    matches = _shell_findings(make_skill, source)

    assert len(matches) == 2
    assert len({finding.id for finding in matches}) == 2


@pytest.mark.parametrize(
    "middle",
    [
        "if True:\n    pass",
        "if False:\n    o.system('unreachable')",
        "while False:\n    o.system('unreachable')",
        "for _ in '':\n    o.system('unreachable')",
        "try:\n    pass\nexcept:\n    pass",
        "try:\n    raise RuntimeError\nexcept:\n    pass",
    ],
)
def test_inert_deterministic_compound_preserves_later_alias(make_skill, middle):
    source = f"import os as o\n{middle}\no.system('id')\n"

    matches = _semantic_findings(make_skill, source)

    assert len(matches) == 1
    assert matches[0].line_number == len(source.splitlines())


def test_mutually_exclusive_branch_poison_does_not_suppress_other_branch(make_skill):
    source = "if condition:\n    import os\n    os.system = fake\nelse:\n    import os as o\n    o.system('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_deferred_function_poison_does_not_escape_to_module(make_skill):
    source = "def unused():\n    import os\n    os.system = fake\nimport os as o\no.system('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.skipif(sys.version_info < (3, 12), reason="generic type parameters require Python 3.12+")
def test_generic_class_type_parameter_shadows_alias_in_base(make_skill):
    source = "import os as o\nclass Runner[o](o.system('id')): pass\n"

    assert not _semantic_findings(make_skill, source)


def test_class_mapping_expansion_invalidates_alias_before_later_keyword(make_skill):
    source = "import os as o\nclass Runner(**mapping, marker=o.system('id')): pass\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred on Python 3.14+")
@pytest.mark.parametrize(
    ("annotations", "expected"),
    [
        ("left: mutate(), /, right: o.system('id')", 1),
        ("left: o.system('id'), /, right: mutate()", 0),
    ],
)
def test_function_annotation_evaluation_uses_cpython_parameter_order(make_skill, annotations, expected):
    source = f"import os as o\ndef launch({annotations}): pass\n"

    assert len(_semantic_findings(make_skill, source)) == expected


@pytest.mark.parametrize(
    "terminal_suite",
    [
        "if True:\n        return",
        "while False:\n        pass\n    else:\n        return",
        "for _ in '':\n        pass\n    else:\n        raise RuntimeError",
        "try:\n        return\n    finally:\n        pass",
    ],
)
def test_selected_terminal_suite_prunes_following_function_code(make_skill, terminal_suite):
    source = f"def launch():\n    {terminal_suite}\n    import os as o\n    o.system('unreachable')\n"

    assert not _semantic_findings(make_skill, source)


def test_safe_return_keeps_alias_visible_to_finally(make_skill):
    source = "def launch():\n    import os as o\n    try: return\n    finally: o.system('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.parametrize("loop_body", ["pass", "continue"])
def test_constant_true_loop_prunes_following_code(make_skill, loop_body):
    source = f"def launch():\n    while True:\n        {loop_body}\n    import os as o\n    o.system('unreachable')\n"

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize("loop_body", ["break", "return"])
def test_tracked_true_loop_skips_unreachable_else(make_skill, loop_body):
    source = (
        "def launch():\n"
        "    flag = True\n"
        "    while flag:\n"
        f"        {loop_body}\n"
        "    else:\n"
        "        import os as o\n"
        "        o.system('unreachable')\n"
    )

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize("transfer", ["break", "continue"])
def test_try_finally_propagates_loop_transfer(make_skill, transfer):
    source = (
        "for _ in [1]:\n"
        "    try:\n"
        f"        {transfer}\n"
        "    finally:\n"
        "        pass\n"
        "    import os as o\n"
        "    o.system('unreachable')\n"
    )

    assert not _semantic_findings(make_skill, source)


def test_selected_safe_terminal_keeps_alias_visible_to_finally(make_skill):
    source = (
        "def launch():\n    import os as o\n    try:\n        if True: return\n    finally:\n        o.system('id')\n"
    )

    assert len(_semantic_findings(make_skill, source)) == 1


def test_literal_destructuring_reaches_known_nonempty_for_body(make_skill):
    source = "for left, right in [(1, 2)]:\n    import os as o\n    o.system('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_unknown_while_poison_isolated_from_zero_iteration_else(make_skill):
    source = (
        "while condition:\n"
        "    import os\n"
        "    os.system = fake\n"
        "    break\n"
        "else:\n"
        "    import os as o\n"
        "    o.system('id')\n"
    )

    assert len(_semantic_findings(make_skill, source)) == 1


def test_exact_literal_match_scans_guard_with_outer_alias(make_skill):
    source = "import os as o\nmatch 1:\n    case 1 if o.system('id'):\n        pass\n"

    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.parametrize(
    "case",
    ["case o if o.system('id'):\n        pass", "case o:\n        o.system('id')"],
    ids=["guard", "body"],
)
def test_match_capture_shadows_outer_alias(make_skill, case):
    source = f"import os as o\nmatch 1:\n    {case}\n"

    assert not _semantic_findings(make_skill, source)


def test_known_not_expression_controls_reachability(make_skill):
    positive = "import os as o\nnot False and o.system('id')\n"
    negative = "import os as o\nwhile not True:\n    o.system('unreachable')\n"

    assert len(_semantic_findings(make_skill, positive)) == 1
    assert not _semantic_findings(make_skill, negative)


@pytest.mark.parametrize(
    "source",
    [
        "import os as o\ntry:\n    pass\nexcept:\n    o.system('unreachable')\n",
        "def launch():\n    import os as o\n    try: return\n    except: o.system('unreachable')\n",
    ],
)
def test_impossible_try_handlers_are_not_scanned(make_skill, source):
    assert not _semantic_findings(make_skill, source)


def test_simple_zero_division_reaches_exception_type(make_skill):
    source = "import os as o\ntry:\n    1 / 0\nexcept o.system('id'):\n    pass\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_both_terminal_if_arms_prune_following_code(make_skill):
    source = (
        "def launch(condition):\n"
        "    if condition:\n"
        "        return\n"
        "    else:\n"
        "        raise RuntimeError\n"
        "    import os as o\n"
        "    o.system('unreachable')\n"
    )

    assert not _semantic_findings(make_skill, source)


@pytest.mark.parametrize(
    "assignment",
    ["alias = o", "o = o", "alias: object = o", "alias = (o := o)"],
    ids=["copy", "self", "annotated", "walrus"],
)
def test_identity_preserving_assignment_keeps_alias(make_skill, assignment):
    called_name = "o" if assignment == "o = o" else "alias"
    source = f"import os as o\n{assignment}\n{called_name}.system('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_callable_self_assignment_keeps_alias(make_skill):
    source = "from os import system as run\nrun = run\nrun('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


@pytest.mark.parametrize("definition", ["def idle(): pass", "class Idle: pass"])
def test_inert_definition_preserves_unrelated_alias(make_skill, definition):
    source = f"import os as o\n{definition}\no.system('id')\n"

    assert len(_semantic_findings(make_skill, source)) == 1


def test_directly_called_embedded_function_executes_body(make_skill):
    payload = "def launch():\n import os as o\n o.system('id')\nlaunch()"

    assert len(_semantic_findings(make_skill, _python_c_source(payload))) == 1


def test_comprehension_depth_bound_retains_prior_candidate():
    source = "import os as o\no.system('first')\n[value" + " for value in [1]" * 1_000 + "]\n"

    candidates = python_shell_semantics.find_python_shell_candidates(source)

    assert len(candidates) == 1
    assert candidates[0].line_number == 2
