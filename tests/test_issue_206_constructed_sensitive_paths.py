# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for constructed sensitive paths (issue #206)."""

import ast
import time

import pytest

from skill_scanner.core.analyzers import static as static_module
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.static_analysis import python_sensitive_file_reads as sensitive_reads
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


def test_unrelated_import_does_not_erase_reviewed_os_identity(make_skill):
    source = """
import os
import json

path = os.path.join('/etc', 'passwd')
with open(path) as handle:
    value = json.load(handle)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["resolved_path"] == "/etc/passwd"


def test_import_rebinding_os_invalidates_path_join_identity(make_skill):
    source = "import os\nimport plugin as os\npath=os.path.join('/etc','passwd')\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


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


def test_eager_module_read_preceding_late_open_binding_is_detected(make_skill):
    source = "path='/etc/'+'passwd'\nopen(path)\nopen=lambda value: value\n"
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 2


def test_class_attribute_named_open_does_not_shadow_method_builtin(make_skill):
    source = """
class Loader:
    open = lambda value: value

    def load(self):
        path = '/etc/' + 'passwd'
        return open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 7


def test_comprehension_target_does_not_shadow_enclosing_builtin(make_skill):
    source = """
def load():
    [None for open in ()]
    path = '/etc/' + 'passwd'
    return open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 5


def test_exact_string_augmented_assignment_is_detected(make_skill):
    skill = make_skill({"scripts/main.py": "path='/etc/'\npath += 'passwd'\nopen(path)\n"})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["resolved_path"] == "/etc/passwd"


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


@pytest.mark.parametrize(
    "replacement",
    [
        "globals()['open'] = lambda value: value",
        "import builtins\nbuiltins.open = lambda value: value",
        "import builtins as bi\nsetattr(bi, 'open', lambda value: value)",
    ],
)
def test_explicit_runtime_open_replacement_invalidates_builtin(make_skill, replacement):
    source = f"{replacement}\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "alias_assignment",
    [
        "helper = builtins",
        "helper: object = builtins",
        "first = builtins\nhelper = first",
    ],
    ids=["assignment", "annotated-assignment", "alias-chain"],
)
def test_assigned_runtime_helper_alias_invalidates_builtin(make_skill, alias_assignment):
    source = f"import builtins\n{alias_assignment}\nhelper.open = replacement\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_rebound_assigned_runtime_helper_is_not_trusted(make_skill):
    source = """\
import builtins
helper = builtins
helper = holder
helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 6


@pytest.mark.parametrize(
    "alias_assignment",
    [
        "(helper,) = (builtins,)",
        "helper = (builtins,)[0]",
    ],
    ids=["destructuring", "subscript"],
)
def test_unsupported_runtime_helper_alias_assignment_fails_closed(make_skill, alias_assignment):
    source = f"import builtins\n{alias_assignment}\nhelper.open=replacement\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_runtime_helper_alias_limit_fails_closed(monkeypatch):
    monkeypatch.setattr(sensitive_reads, "MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES", 2)
    source = """\
import builtins as first_builtins
import builtins as second_builtins
path = '/etc/' + 'passwd'
open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_assigned_runtime_helper_alias_limit_fails_closed(monkeypatch):
    monkeypatch.setattr(sensitive_reads, "MAX_PYTHON_PATH_RUNTIME_HELPER_ALIASES", 2)
    source = "import builtins\nhelper=builtins\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "replacement",
    [
        "builtins.open = open(path)",
        "builtins.open: object = open(path)",
        "builtins.open += open(path)",
    ],
    ids=["assignment", "annotated-assignment", "augmented-assignment"],
)
def test_runtime_open_replacement_records_supported_rhs_read_first(make_skill, replacement):
    source = f"import builtins\npath='/etc/'+'passwd'\n{replacement}\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 3


@pytest.mark.parametrize(
    "definition",
    [
        "def configure(value=(open := lambda value: value)):\n    pass",
        "@(open := (lambda function: function))\ndef configure():\n    pass",
        "import builtins\ndef configure(value: setattr(builtins, 'open', lambda value: value)):\n    pass",
        "class Configure((open := object)):\n    pass",
        "class Configure(metaclass=(open := type)):\n    pass",
        "configure = lambda value=(open := (lambda value: value)): None",
    ],
    ids=["default", "decorator", "annotation", "class-base", "class-keyword", "lambda-default"],
)
def test_eager_definition_expressions_that_replace_open_are_honored(make_skill, definition):
    source = f"{definition}\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_open_binding_in_delayed_function_body_does_not_shadow_module_builtin(make_skill):
    source = "def configure():\n    open=lambda value: value\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 4


def test_class_local_eager_open_binding_does_not_shadow_method_builtin(make_skill):
    source = """\
class Loader:
    def configure(value=(open := lambda value: value)):
        pass

    def load(self):
        path = '/etc/' + 'passwd'
        return open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 7


def test_with_body_open_binding_invalidates_later_builtin_assumption(make_skill):
    source = "with context():\n    open=lambda value: value\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_class_with_open_binding_does_not_shadow_later_method_builtin(make_skill):
    source = """\
class Loader:
    with manager:
        open = lambda value: value
    path = '/etc/' + 'passwd'
    handle = open(path)

    def load(self):
        path = '/etc/' + 'shadow'
        return open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 9
    assert matches[0].metadata["resolved_path"] == "/etc/shadow"


def test_class_with_runtime_open_replacement_invalidates_later_method_builtin(make_skill):
    source = """\
class Loader:
    with manager:
        import builtins as helper
        helper.open = lambda value: value

    def load(self):
        path = '/etc/' + 'shadow'
        return open(path)

path = '/etc/' + 'passwd'
open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "compound",
    [
        "with manager:\n    with other:\n        import builtins as helper\n        helper.open = replacement",
        "if enabled:\n    import builtins as helper\n    helper.open = replacement",
    ],
    ids=["nested-with", "conditional"],
)
def test_compound_runtime_open_replacement_invalidates_outer_builtin(make_skill, compound):
    source = f"{compound}\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_runtime_helper_alias_from_with_body_is_tracked_afterward(make_skill):
    source = """\
with manager:
    import builtins as helper
helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "source",
    [
        """\
class Dummy:
    pass
helper = Dummy()
for _ in (0, 1):
    helper.open = replacement
    import builtins as helper
path = '/etc/' + 'passwd'
open(path)
""",
        """\
try:
    import builtins as helper
    raise RuntimeError
except RuntimeError:
    helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
import builtins
for _ in (1,):
    helper = builtins
    helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
    ],
    ids=["loop-carried-alias", "exception-edge-alias", "loop-assigned-alias"],
)
def test_unsupported_compound_runtime_helper_flow_fails_closed(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_class_body_runtime_open_replacement_invalidates_outer_and_method_builtin(make_skill):
    source = """\
class Loader:
    import builtins as helper
    helper.open = lambda value: value

    def load(self):
        path = '/etc/' + 'shadow'
        return open(path)

path = '/etc/' + 'passwd'
open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    ("source", "expected_line"),
    [
        (
            """\
with manager:
    import builtins
    path = '/etc/' + 'passwd'
    open(path)
    if False:
        builtins.open = replacement
""",
            4,
        ),
        (
            """\
class Loader:
    import builtins
    path = '/etc/' + 'passwd'
    handle = open(path)
    builtins.open = replacement
""",
            4,
        ),
        (
            """\
async def load():
    async with manager:
        import builtins
        path = '/etc/' + 'passwd'
        open(path)
        builtins.open = replacement
""",
            5,
        ),
    ],
    ids=["with-dead-nested-mutation", "class", "async-with"],
)
def test_child_body_read_precedes_later_runtime_open_replacement(make_skill, source, expected_line):
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == expected_line


@pytest.mark.parametrize(
    "source",
    [
        """\
import builtins
with manager:
    builtins.open = replacement
    path = '/etc/' + 'passwd'
    open(path)
""",
        """\
import builtins
class Loader:
    builtins.open = replacement
    path = '/etc/' + 'passwd'
    handle = open(path)
""",
    ],
    ids=["with", "class"],
)
def test_child_body_runtime_open_replacement_precedes_later_read(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "definition",
    [
        "class Loader((open := object)):\n    path='/etc/'+'passwd'\n    handle=open(path)",
        "@(open := (lambda cls: cls))\nclass Loader:\n    path='/etc/'+'passwd'\n    handle=open(path)",
    ],
    ids=["base", "decorator"],
)
def test_eager_class_open_binding_applies_before_class_body(make_skill, definition):
    skill = make_skill({"scripts/main.py": f"{definition}\n"})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_nested_class_skips_outer_class_eager_open_binding(make_skill):
    source = """\
class Outer:
    @(open := (lambda cls: cls))
    class Inner:
        path = '/etc/' + 'passwd'
        handle = open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 5


@pytest.mark.parametrize(
    "replacement",
    [
        "builtins.open = replacement",
        "with manager:\n        builtins.open = replacement",
    ],
    ids=["direct", "with-body"],
)
def test_nested_class_read_precedes_later_outer_runtime_replacement(make_skill, replacement):
    source = f"""\
class Outer:
    import builtins
    class Inner:
        path = '/etc/' + 'passwd'
        handle = open(path)
        def load(self):
            path = '/etc/' + 'shadow'
            return open(path)
    {replacement}
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 5


def test_outer_runtime_replacement_precedes_nested_class_read(make_skill):
    source = """\
class Outer:
    import builtins
    builtins.open = replacement
    class Inner:
        path = '/etc/' + 'passwd'
        handle = open(path)
"""
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "source",
    [
        """\
import builtins
with (helper := builtins, manager)[1]:
    helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
import builtins
def configure(value=(helper := builtins)):
    pass
helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
    ],
    ids=["with-context", "function-default"],
)
def test_eager_runtime_helper_alias_expression_fails_closed(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "header",
    [
        "with (setattr(builtins, 'open', replacement) or manager), open('/etc/' + 'passwd'):",
        "with manager as builtins.open, open('/etc/' + 'passwd'):",
    ],
    ids=["context-expression", "optional-target"],
)
def test_with_header_runtime_open_replacement_precedes_later_context_read(make_skill, header):
    source = f"import builtins\n{header}\n    pass\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_with_header_read_precedes_later_runtime_open_replacement(make_skill):
    source = """\
import builtins
with open('/etc/' + 'passwd'), manager as builtins.open:
    pass
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 2


def test_unrelated_open_attribute_does_not_disable_builtin_detection(make_skill):
    source = "settings.open = False\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 3


def test_shadowed_globals_helper_does_not_disable_builtin_detection(make_skill):
    source = "globals=lambda: {}\nglobals()['open']=safe\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 4


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


@pytest.mark.parametrize(
    "eager_escape",
    [
        "mutate(builtins)",
        "with mutate(builtins):\n    pass",
        "class C(mutate(builtins)):\n    pass",
        "def f(value=mutate(builtins)):\n    pass",
        "def f(value: mutate(builtins)):\n    pass",
        "@mutate(builtins)\ndef f():\n    pass",
        "with nullcontext(builtins) as helper:\n    helper.open = replacement",
        "payload = {'runtime': builtins}",
    ],
    ids=[
        "call-argument",
        "with-context",
        "class-base",
        "function-default",
        "function-annotation",
        "decorator-factory",
        "with-target",
        "container",
    ],
)
def test_eager_runtime_helper_escape_fails_closed(eager_escape):
    source = f"import builtins\n{eager_escape}\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_runtime_helper_escape_preserves_an_earlier_read():
    source = "path='/etc/'+'passwd'\nopen(path)\nimport builtins\nmutate(builtins)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


def test_immediate_lambda_runtime_mutation_fails_closed():
    source = """\
import builtins
(lambda: setattr(builtins, 'open', replacement))()
path = '/etc/' + 'passwd'
open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "callee",
    [
        "[(lambda: setattr(builtins, 'open', replacement))][0]",
        "(lambda: setattr(builtins, 'open', replacement)).__call__",
        "((lambda: setattr(builtins, 'open', replacement)) if enabled else noop)",
    ],
    ids=["subscript", "dunder-call", "conditional"],
)
def test_wrapped_immediate_lambda_runtime_mutation_fails_closed(callee):
    source = f"import builtins\n{callee}()\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_immediate_lambda_parameter_shadow_does_not_escape_helper():
    source = """\
import builtins
(lambda builtins: consume(builtins))(safe)
path = '/etc/' + 'passwd'
open(path)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [4]


@pytest.mark.parametrize(
    "mutation",
    [
        "builtins.__dict__['open'] = replacement",
        "bi.__dict__['open'] = replacement",
        "builtins.__dict__.update(open=replacement)",
        "vars(builtins).update(open=replacement)",
    ],
    ids=["dict", "aliased-dict", "dict-update", "vars-update"],
)
def test_runtime_helper_mapping_mutation_fails_closed(mutation):
    source = f"import builtins\nimport builtins as bi\n{mutation}\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_imported_builtins_mapping_fails_closed():
    source = (
        "from builtins import __dict__ as namespace\nnamespace['open']=replacement\npath='/etc/'+'passwd'\nopen(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "setup",
    [
        "vars()['open']=replacement",
        "locals()['open']=replacement",
        "vars().update(open=replacement)",
        "locals().__setitem__('open', replacement)",
        "from builtins import vars as helper\nhelper()['open']=replacement",
        "helper=vars\nhelper()['open']=replacement",
        "helper=(vars,)[0]\nhelper()['open']=replacement",
        "helper=(lambda: vars)()\nhelper()['open']=replacement",
        "helper=vars if enabled else safe\nhelper()['open']=replacement",
    ],
    ids=[
        "vars",
        "locals",
        "vars-update",
        "locals-setitem",
        "imported-vars",
        "assigned-vars",
        "tuple-alias",
        "lambda-alias",
        "conditional-alias",
    ],
)
def test_runtime_namespace_mapping_mutation_fails_closed(setup):
    source = f"{setup}\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("shadow", ["globals=lambda: {}", "import plugin as globals"])
def test_deleting_globals_shadow_fails_closed(shadow):
    source = f"{shadow}\ndel globals\nglobals()['open']=replacement\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_augassign_address_effect_precedes_rhs_read():
    source = """\
import builtins
values[setattr(builtins, 'open', replacement)] += open('/etc/' + 'passwd')
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_augassign_runtime_target_store_follows_rhs_read():
    source = "import builtins\npath='/etc/'+'passwd'\nbuiltins.open += open(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [3]


@pytest.mark.parametrize(
    "source",
    [
        """\
import builtins as helper
class Outer:
    helper = object()
    class Inner:
        helper.open = replacement
    path = '/etc/' + 'passwd'
    handle = open(path)
""",
        """\
class Outer:
    globals = lambda: {}
    class Inner:
        globals()['open'] = replacement
    path = '/etc/' + 'passwd'
    handle = open(path)
""",
        """\
import builtins
class C:
    global helper
    helper = builtins
helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
class C:
    global helper
    import builtins as helper
helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
class C:
    global open
    open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
import builtins
class C:
    helper = builtins
C.helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
import builtins as helper
class C:
    helper = holder
    del helper
    helper.open = replacement
    path = '/etc/' + 'passwd'
    handle = open(path)
""",
        """\
import builtins as helper
class C:
    helper = holder
    [setattr(helper, 'open', replacement) for _ in (1,)]
    path = '/etc/' + 'passwd'
    handle = open(path)
""",
    ],
    ids=[
        "nested-class-shadow",
        "nested-class-globals-shadow",
        "global-alias-export",
        "global-import-export",
        "global-open-export",
        "class-attribute-escape",
        "class-delete-fallback",
        "class-comprehension-fallback",
    ],
)
def test_ambiguous_class_runtime_provenance_fails_closed(source):
    assert find_constructed_sensitive_file_reads(source) == ()


def test_inline_lambda_class_decorator_applies_after_class_body():
    source = """\
import builtins
@(lambda cls: (setattr(builtins, 'open', replacement), cls)[1])
class C:
    path = '/etc/' + 'shadow'
    handle = open(path)
path = '/etc/' + 'passwd'
open(path)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


def test_inline_lambda_function_decorator_invalidates_delayed_body():
    source = """\
import builtins
@(lambda function: (setattr(builtins, 'open', replacement), function)[1])
def load():
    path = '/etc/' + 'shadow'
    return open(path)
path = '/etc/' + 'passwd'
open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "decorator",
    [
        "[(lambda function: (setattr(builtins, 'open', replacement), function)[1])][0]",
        "((lambda function: (setattr(builtins, 'open', replacement), function)[1]) if enabled else identity)",
        "(decorator := (lambda function: (setattr(builtins, 'open', replacement), function)[1]))",
        "((lambda: (lambda function: (setattr(builtins, 'open', replacement), function)[1]))())",
    ],
    ids=["subscript", "conditional", "walrus", "factory"],
)
def test_wrapped_lambda_decorator_invalidates_delayed_body(decorator):
    source = f"import builtins\n@{decorator}\ndef load():\n    path='/etc/'+'passwd'\n    return open(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "header",
    ["class C(Base):", "class C(metaclass=Meta):", "class C(**{'metaclass': Meta}):"],
)
def test_unreviewed_class_namespace_provider_fails_closed(header):
    source = f"{header}\n    path='/etc/'+'passwd'\n    handle=open(path)\npath='/etc/'+'shadow'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("import_position", ["before", "after"])
def test_delayed_function_runtime_helper_alias_fails_closed(import_position):
    definition = "def load():\n    helper.open=replacement\n    path='/etc/'+'passwd'\n    return open(path)"
    import_line = "import builtins as helper"
    source = f"{import_line}\n{definition}\n" if import_position == "before" else f"{definition}\n{import_line}\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "compound",
    [
        "for helper in []:\n    pass",
        "while False:\n    helper = safe",
        "try:\n    pass\nexcept Exception as helper:\n    pass",
        "match value:\n    case helper:\n        pass",
    ],
    ids=["empty-for", "false-while", "unused-handler", "nonmatching-case"],
)
def test_unsupported_conditional_runtime_helper_binding_fails_closed(compound):
    source = f"import builtins as helper\n{compound}\nhelper.open=replacement\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_runtime_provenance_budget_exhaustion_voids_earlier_candidates(monkeypatch):
    monkeypatch.setattr(sensitive_reads, "MAX_PYTHON_PATH_RUNTIME_PROVENANCE_WORK", 8)
    source = "path='/etc/'+'passwd'\nopen(path)\nvalue=(1, 2, 3, 4, 5)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_runtime_alias_edge_overflow_stops_before_scanning(monkeypatch):
    monkeypatch.setattr(sensitive_reads, "MAX_PYTHON_PATH_BINDINGS", 1)

    def fail_if_scanned(*_args, **_kwargs):
        raise AssertionError("an exhausted provenance preflight must not scan")

    monkeypatch.setattr(sensitive_reads._StraightLineSensitiveReadScanner, "scan", fail_if_scanned)

    assert find_constructed_sensitive_file_reads("first=value\nsecond=value\n") == ()


def test_runtime_budget_is_not_attached_to_shared_ast_singletons():
    first = ast.parse("first + second")
    second = ast.parse("third + fourth")

    sensitive_reads._prepare_bounded_ast(first)
    sensitive_reads._prepare_bounded_ast(second)
    first_expression = first.body[0]
    second_expression = second.body[0]

    assert isinstance(first_expression, ast.Expr)
    assert isinstance(second_expression, ast.Expr)
    assert isinstance(first_expression.value, ast.BinOp)
    assert isinstance(second_expression.value, ast.BinOp)
    assert first_expression.value.op is second_expression.value.op
    assert not hasattr(first_expression.value.op, sensitive_reads._RUNTIME_BUDGET_ATTR)


def test_runtime_provenance_work_is_bounded_for_adversarial_aliases():
    aliases = ["import builtins as helper0", *(f"helper{i}=helper{i - 1}" for i in range(1, 63))]
    source = "\n".join(aliases) + "\n"
    for depth in range(10):
        source += "    " * depth + "with manager:\n"
    indent = "    " * 10
    source += indent + "values=(" + ",".join("0" for _ in range(20_000)) + ",)\n"
    source += indent + "path='/etc/'+'passwd'\n" + indent + "open(path)\n"

    started = time.monotonic()
    candidates = find_constructed_sensitive_file_reads(source)

    assert candidates == ()
    assert time.monotonic() - started < 3


def test_unrelated_name_aliases_do_not_consume_runtime_helper_limit():
    aliases = "\n".join(f"name{i}=value{i}" for i in range(100))
    source = aliases + "\npath='/etc/'+'passwd'\nopen(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [102]
