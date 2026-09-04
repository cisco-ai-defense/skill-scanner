# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for constructed sensitive paths (issue #206)."""

import pytest

from skill_scanner.core.analyzers import static as static_module
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.static_analysis.python_sensitive_file_reads import (
    MAX_PYTHON_PATH_SOURCE_BYTES,
    find_constructed_sensitive_file_reads,
)

_RULE_ID = "DATA_EXFIL_SENSITIVE_FILES"
_SEMANTIC_PATTERN = "python_ast:constructed_sensitive_file_read"


def _matches(analyzer: StaticAnalyzer, skill) -> list:
    return [finding for finding in analyzer.analyze(skill) if finding.rule_id == _RULE_ID]


def test_issue_reproduction_is_detected_at_with_header_with_canonical_metadata(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import os

path = os.path.join('/etc', 'passwd')

with open(path) as handle:
    passwd_data = handle.read()
"""
        }
    )
    analyzer = StaticAnalyzer(use_yara=False)

    matches = _matches(analyzer, skill)

    assert len(matches) == 1
    finding = matches[0]
    canonical_rule = analyzer.rule_loader.get_rule(_RULE_ID)
    assert canonical_rule is not None
    assert finding.severity == canonical_rule.severity == Severity.HIGH
    assert finding.category == canonical_rule.category == ThreatCategory.DATA_EXFILTRATION
    assert finding.title == canonical_rule.description
    assert finding.remediation == canonical_rule.remediation
    assert finding.line_number == 6
    assert finding.snippet == "with open(path) as handle:"
    assert finding.metadata["matched_pattern"] == _SEMANTIC_PATTERN
    assert finding.metadata["matched_text"] == "/etc/passwd"
    assert finding.metadata["resolved_path"] == "/etc/passwd"
    assert finding.metadata["detection_method"] == "ast_constructed_sensitive_file_read"
    assert finding.metadata["signature_context"] == "code"
    assert finding.metadata["signature_polarity"] == "active"
    assert finding.metadata["signature_match_start"] == 5
    assert finding.metadata["signature_match_end"] == 9
    assert finding.metadata["source_category"] == canonical_rule.source_category
    assert finding.metadata["category_normalization"] == canonical_rule.category_resolution


@pytest.mark.parametrize(
    "source",
    [
        "root='/etc'\nname='passwd'\npath=root + '/' + name\nopen(path)\n",
        "first='/etc/' + 'pass'\nsecond=first\npath=second + 'wd'\nopen(path, 'r')\n",
        "import os\nroot='/etc'\npath=os.path.join(root, 'shadow')\nopen(path, mode='rb')\n",
    ],
)
def test_reviewed_exact_string_forms_are_detected(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["matched_pattern"] == _SEMANTIC_PATTERN


@pytest.mark.parametrize("mode", ["r", "rb", "br", "rt", "tr"])
def test_all_valid_read_only_mode_spellings_are_detected(make_skill, mode):
    skill = make_skill({"scripts/main.py": f"path='/etc/'+'passwd'\nopen(path, {mode!r})\n"})

    assert len(_matches(StaticAnalyzer(use_yara=False), skill)) == 1


@pytest.mark.parametrize("mode", ["w", "wb", "a", "x", "r+", "unknown"])
def test_write_update_and_ambiguous_modes_are_not_reported(make_skill, mode):
    mode_expression = "get_mode()" if mode == "unknown" else repr(mode)
    skill = make_skill({"scripts/main.py": f"path='/etc/'+'passwd'\nopen(path, {mode_expression})\n"})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "call",
    [
        "open(path, **{'mode': 'w'})",
        "open(path, **{'opener': redirect})",
        "open(path, 'r', -1, None, None, None, True, redirect)",
        "open(path, opener=redirect)",
    ],
)
def test_kwargs_and_custom_openers_are_not_treated_as_proven_reads(make_skill, call):
    skill = make_skill({"scripts/main.py": f"path='/etc/'+'passwd'\n{call}\n"})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize("root", ["//etc", "///etc", "////etc"])
def test_repeated_root_slashes_do_not_bypass_sensitive_path_matching(make_skill, root):
    skill = make_skill({"scripts/main.py": f"import os\npath=os.path.join({root!r}, 'passwd')\nopen(path)\n"})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["resolved_path"] == "/etc/passwd"


@pytest.mark.parametrize(
    "source",
    [
        "path='/etc/'+'passwd'\nmutate()\nopen(path)\n",
        "import os\npath=os.path.join('/etc','passwd')\nos.path.join=lambda *parts: '/tmp/safe'\nopen(path)\n",
        "path='/etc/'+'passwd'\nfor item in [1]:\n    path='/tmp/safe'\nopen(path)\n",
        "path='/etc/'+'passwd'\nmatch 1:\n    case 1:\n        path='/tmp/safe'\nopen(path)\n",
        "path='/etc/'+'passwd'\nreader=lambda: open(path)\npath='/tmp/safe'\nreader()\n",
    ],
)
def test_effects_compound_flow_and_delayed_lambdas_do_not_reuse_stale_paths(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_function_scope_detects_self_contained_flow(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
def load():
    import os
    path = os.path.join('/etc', 'passwd')
    return open(path)
"""
        }
    )

    assert len(_matches(StaticAnalyzer(use_yara=False), skill)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "import os\ndef load():\n    path=os.path.join('/etc','passwd')\n    return open(path)\n",
        "path='/etc/'+'passwd'\ndef load():\n    return open(path)\n",
    ],
)
def test_delayed_scopes_do_not_inherit_module_path_or_import_facts(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "source",
    [
        "def load(open):\n    import os\n    path=os.path.join('/etc','passwd')\n    return open(path)\n",
        "def load():\n    import os\n    path=os.path.join('/etc','passwd')\n    open(path)\n    open=lambda value: value\n",
        "open=lambda value: value\npath='/etc/'+'passwd'\nopen(path)\n",
        "open=lambda *args: None\ndef load():\n    path='/etc/'+'passwd'\n    return open(path)\n",
        "def load():\n    path='/etc/'+'passwd'\n    return open(path)\nopen=lambda *args: None\n",
        "open=lambda *args: None\nclass Loader:\n    path='/etc/'+'passwd'\n    handle=open(path)\n",
    ],
)
def test_shadowed_open_is_not_treated_as_the_builtin(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_pathlib_and_purepath_are_out_of_scope(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
from pathlib import Path, PurePath
Path('/etc', 'passwd').read_text()
PurePath('/etc', 'shadow').read_text()
"""
        }
    )

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "expression",
    [
        "payload = open(path).read()",
        "payload = json.load(open(path))",
    ],
)
def test_nested_open_expressions_are_deliberately_out_of_scope(make_skill, expression):
    skill = make_skill({"scripts/main.py": (f"import json\npath='/etc/'+'passwd'\n{expression}\n")})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_literal_regex_owned_line_has_no_semantic_duplicate(make_skill):
    skill = make_skill({"scripts/main.py": "open('/etc/passwd')\n"})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert matches
    assert all(finding.metadata["matched_pattern"] != _SEMANTIC_PATTERN for finding in matches)


def test_existing_name_heuristic_and_semantic_path_do_not_duplicate(make_skill):
    skill = make_skill(
        {
            "scripts/main.py": """
import os
credentials_path = os.path.join('/etc', 'passwd')
open(credentials_path)
"""
        }
    )

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert len({finding.id for finding in matches}) == 1


def test_semantic_candidates_are_limited_to_one_per_physical_line(make_skill):
    source = "first='/etc/'+'passwd'; second='/etc/'+'shadow'; open(first); open(second)\n"
    candidates = find_constructed_sensitive_file_reads(source)
    skill = make_skill({"scripts/main.py": source})

    assert len(candidates) == 1
    matches = _matches(StaticAnalyzer(use_yara=False), skill)
    assert len(matches) == 1
    assert len({finding.id for finding in matches}) == 1


def test_exclude_pattern_suppresses_semantic_candidate(make_skill):
    skill = make_skill({"scripts/main.py": "DEFAULT_PATH='/etc/'+'passwd'\nopen(DEFAULT_PATH)\n"})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_disabled_rule_does_not_run_semantic_parser(make_skill, monkeypatch):
    skill = make_skill({"scripts/main.py": "path='/etc/'+'passwd'\nopen(path)\n"})

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("disabled semantic rule should not parse Python")

    monkeypatch.setattr(static_module, "find_constructed_sensitive_file_reads", fail_if_called)
    analyzer = StaticAnalyzer(use_yara=False, disabled_rules={_RULE_ID})

    assert _matches(analyzer, skill) == []


def test_unicode_before_open_uses_character_offsets(make_skill):
    source = "label='é'; path='/etc/'+'passwd'; open(path)\n"
    skill = make_skill({"scripts/main.py": source})

    match = _matches(StaticAnalyzer(use_yara=False), skill)[0]

    assert match.metadata["signature_match_start"] == source.index("open")
    assert match.metadata["signature_match_end"] == source.index("open") + len("open")


def test_deep_unrelated_expression_cannot_erase_earlier_candidate():
    source = "path='/etc/'+'passwd'\nopen(path)\nvalue=root" + ".child" * 500

    candidates = find_constructed_sensitive_file_reads(source)

    assert len(candidates) == 1
    assert candidates[0].path == "/etc/passwd"


@pytest.mark.parametrize("source", ["path =", "path='x'\x00open(path)"])
def test_malformed_and_binary_like_sources_are_ignored(source):
    assert find_constructed_sensitive_file_reads(source) == ()


def test_oversized_source_is_ignored():
    source = "#" * (MAX_PYTHON_PATH_SOURCE_BYTES + 1)

    assert find_constructed_sensitive_file_reads(source) == ()
