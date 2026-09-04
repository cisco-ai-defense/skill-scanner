# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for constructed sensitive paths (issue #206)."""

import ast
import sys

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


@pytest.mark.parametrize("filename", ["id_ecdsa", "id_ecdsa_sk", "id_ed25519_sk"])
def test_constructed_opens_cover_standard_ssh_private_key_names(filename):
    source = f"root='/home/user/.ssh/'\npath=root+{filename!r}\nopen(path)\n"

    candidates = find_constructed_sensitive_file_reads(source)

    assert len(candidates) == 1
    assert candidates[0].path == f"/home/user/.ssh/{filename}"


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


@pytest.mark.parametrize("closefd", ["False", "flag"])
def test_filename_open_requires_proven_true_closefd(closefd):
    source = f"path='/etc/'+'passwd'\nopen(path, closefd={closefd})\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_filename_open_accepts_explicit_true_closefd():
    source = "path='/etc/'+'passwd'\nopen(path, closefd=True)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


@pytest.mark.parametrize(
    "options",
    [
        "buffering=buffer",
        "buffering=-2",
        "buffering=0",
        "mode='rb', encoding='utf-8'",
        "mode='rb', newline=None",
        "newline='invalid'",
    ],
)
def test_open_requires_valid_non_dispatching_optional_arguments(options):
    source = f"path='/etc/'+'passwd'\nopen(path, {options})\n"

    assert find_constructed_sensitive_file_reads(source) == ()


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


def test_unreviewed_eager_call_invalidates_builtin_open_before_rebuilt_path():
    source = "mutate()\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "source",
    [
        "with mutate(), open('/etc/' + 'passwd'):\n    pass\n",
        "with mutate():\n    open('/etc/' + 'passwd')\n",
    ],
    ids=["later-header", "body"],
)
def test_unreviewed_with_context_invalidates_builtin_open_before_later_execution(source):
    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "import os\nos.path.join = replacement",
        "import os as helper\nhelper.path.join = replacement",
        "from os import path as path_helper\npath_helper.join = replacement",
        "import os as imported\nhelper = imported\nhelper.path.join = replacement",
        "import os\npath_helper = os.path\npath_helper.join = replacement",
        "import os\nos.path = replacement",
        "import os\ndel os.path.join",
        "import os\nos.path.join += replacement",
        "import os\nos.path.__dict__['join'] = replacement",
        "import os\nvars(os.path)['join'] = replacement",
        "import os\nsetattr(os.path, 'join', replacement)",
        "import os\nos.path.__dict__.update(join=replacement)",
        "import os\nvars(os.path).update(join=replacement)",
        "import os\nos.__dict__.update(path=replacement)",
        "import os\nsetattr(os.path, attribute_name, replacement)",
        "import os\nmutate(os.path)",
        "import os\npayload = {'path': os.path}",
        "import os\npath_helper = os.path\nmutate(path_helper)",
        "import os\n(lambda path_helper=os.path: setattr(path_helper, 'join', replacement))()",
        "import os\nos.path.__setattr__('join', replacement)",
        "import os\nos.__setattr__('path', replacement)",
        "import os\nos.path.mutate()",
        "import os\nhelper = os.path.join\nhelper.__globals__['join'] = replacement",
        "import os\n(lambda: mutate(os.path))()",
        "from os.path import __dict__ as namespace\nnamespace['join'] = replacement",
        "from os.path import join as helper\nhelper.__globals__['join'] = replacement",
        "from os import __dict__ as namespace\nnamespace['path'] = replacement",
        "import posixpath as path_helper\npath_helper.join = replacement",
        "import ntpath as path_helper\npath_helper.join = replacement",
    ],
    ids=[
        "direct",
        "module-alias",
        "from-path-alias",
        "module-alias-chain",
        "path-alias",
        "path-replacement",
        "delete",
        "augassign",
        "dict",
        "vars",
        "setattr",
        "dict-update",
        "vars-update",
        "module-dict-update",
        "dynamic-setattr",
        "argument-escape",
        "container-escape",
        "alias-escape",
        "immediate-lambda-default",
        "path-dunder-setattr",
        "module-dunder-setattr",
        "unknown-path-method",
        "join-callable-escape",
        "immediate-lambda-escape",
        "imported-path-mapping",
        "imported-join-function",
        "imported-os-mapping",
        "posixpath-module",
        "ntpath-module",
    ],
)
def test_reimport_does_not_restore_mutated_os_path_join(mutation):
    source = f"{mutation}\nimport os\npath = os.path.join('/etc', 'passwd')\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "eager_mutation",
    [
        "class Patch:\n    os.path.join = replacement",
        "with manager:\n    os.path.join = replacement",
        "if enabled:\n    import os as helper\n    helper.path.join = replacement",
        "class Patch((setattr(os.path, 'join', replacement) or object)):\n    pass",
        "@(setattr(os.path, 'join', replacement) or (lambda cls: cls))\nclass Patch:\n    pass",
        "with (setattr(os.path, 'join', replacement) or manager):\n    pass",
        "with manager as os.path.join:\n    pass",
        "with manager as os.path.__dict__['join']:\n    pass",
        "with mutate(os.path):\n    pass",
        "with manager as container[os.path]:\n    pass",
        "@register(os.path)\nclass Patch:\n    pass",
    ],
    ids=[
        "class",
        "with",
        "conditional-alias",
        "class-base",
        "class-decorator-expression",
        "with-context",
        "with-target",
        "with-mapping-target",
        "with-context-escape",
        "with-target-escape",
        "class-decorator-escape",
    ],
)
def test_eager_compound_os_path_mutation_survives_reimport(eager_mutation):
    source = f"import os\n{eager_mutation}\nimport os\npath = os.path.join('/etc', 'passwd')\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("patch_first", [False, True], ids=["patch-after-definition", "patch-before-definition"])
def test_delayed_function_does_not_retrust_later_mutated_os_path_join(patch_first):
    patch = "import os\nos.path.join = replacement\n"
    definition = "def load():\n    import os\n    path=os.path.join('/etc','passwd')\n    return open(path)\n"
    source = f"{patch}{definition}" if patch_first else f"{definition}{patch}"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_os_path_join_mutation_preserves_only_the_earlier_read():
    source = """\
import os
first = os.path.join('/etc', 'passwd')
open(first)
os.path.join = replacement
import os
second = os.path.join('/etc', 'shadow')
open(second)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [3]


def test_repeated_os_import_without_mutation_remains_trusted():
    source = "import os\nimport os\npath=os.path.join('/etc','passwd')\nopen(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [4]


@pytest.mark.parametrize("component", [r"C:\tmp", r"\tmp", r"D:\tmp", r"C:passwd"])
def test_os_path_join_requires_cross_platform_path_agreement(component):
    source = f"import os\npath=os.path.join('/etc', {component!r})\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "compound",
    [
        "if False:\n    helper = holder",
        "for helper in []:\n    pass",
        "try:\n    pass\nexcept Exception as helper:\n    pass",
        "match value:\n    case helper:\n        pass",
    ],
    ids=["if", "for", "try", "match"],
)
def test_compound_rebinding_cannot_hide_a_live_os_alias(compound):
    source = (
        "import os as helper\n"
        f"{compound}\n"
        "helper.path.join = replacement\n"
        "import os\n"
        "path = os.path.join('/etc', 'passwd')\n"
        "open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "compound",
    [
        "if enabled:\n    helper = os.path",
        "with manager:\n    helper = os.path",
        "try:\n    helper = os.path\nexcept Exception:\n    pass",
    ],
    ids=["if", "with", "try"],
)
def test_alias_introduced_in_compound_flow_cannot_restore_join_trust(compound):
    source = (
        "import os\n"
        f"{compound}\n"
        "helper.join = replacement\n"
        "import os\n"
        "path = os.path.join('/etc', 'passwd')\n"
        "open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("identity", ["os", "os.path"])
def test_class_attribute_os_identity_escape_is_not_retrusted(identity):
    suffix = ".path.join" if identity == "os" else ".join"
    source = (
        "import os\n"
        "class Cache:\n"
        f"    helper = {identity}\n"
        f"Cache.helper{suffix} = replacement\n"
        "import os\n"
        "path = os.path.join('/etc', 'passwd')\n"
        "open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


def test_nested_class_identity_export_invalidates_an_earlier_delayed_scope():
    source = """\
def load():
    import os
    path = os.path.join('/etc', 'passwd')
    return open(path)
class Outer:
    class Inner:
        import os as helper
Outer.Inner.helper.path.join = replacement
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_class_identity_export_nested_under_compound_flow_is_not_retrusted():
    source = """\
import os
if enabled:
    class Cache:
        import os as helper
Cache.helper.path.join = replacement
import os
path = os.path.join('/etc', 'passwd')
open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "class_effect",
    [
        "helper = holder\n    del helper\n    helper.path.join = replacement",
        "os = holder\n    (lambda: setattr(os.path, 'join', replacement))()",
        "os = holder\n    [setattr(os.path, 'join', replacement) for _ in (1,)]",
    ],
    ids=["delete-fallback", "lambda-lexical-lookup", "comprehension-lexical-lookup"],
)
def test_class_scope_os_lookup_ambiguity_fails_closed(class_effect):
    source = (
        "import os\n"
        "import os as helper\n"
        "class Cache:\n"
        f"    {class_effect}\n"
        "import os\n"
        "path = os.path.join('/etc', 'passwd')\n"
        "open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


def test_rebound_os_alias_does_not_taint_shared_module():
    source = """\
import os as helper
helper = holder
helper.path.join = replacement
import os
path = os.path.join('/etc', 'passwd')
open(path)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [6]


def test_self_contained_delayed_os_path_mutation_is_not_retrusted():
    source = """\
def load():
    import os
    os.path.join = replacement
    import os
    path = os.path.join('/etc', 'passwd')
    return open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_class_decorator_application_taints_only_after_the_body():
    source = """\
import os
@(lambda cls: (setattr(os.path, 'join', replacement), cls)[1])
class Loader:
    import os
    path = os.path.join('/etc', 'passwd')
    handle = open(path)
import os
later = os.path.join('/etc', 'shadow')
open(later)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [6]


@pytest.mark.parametrize(
    "decorator",
    [
        "(lambda function: (setattr(os.path, 'join', replacement), function)[1])",
        "[(lambda function: (setattr(os.path, 'join', replacement), function)[1])][0]",
        "((lambda function: (setattr(os.path, 'join', replacement), function)[1]) if enabled else identity)",
        "(decorator := (lambda function: (setattr(os.path, 'join', replacement), function)[1]))",
        "((lambda: (lambda function: (setattr(os.path, 'join', replacement), function)[1]))())",
    ],
    ids=["direct", "subscript", "conditional", "walrus", "factory"],
)
def test_function_decorator_application_taints_later_reimport(decorator):
    source = (
        "import os\n"
        f"@{decorator}\n"
        "def load():\n"
        "    pass\n"
        "import os\n"
        "path = os.path.join('/etc', 'passwd')\n"
        "open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "decorator",
    [
        "(lambda function: (mutate(os.path), function)[1])",
        "((lambda: (lambda function: (mutate(os.path), function)[1]))())",
    ],
    ids=["direct", "factory"],
)
def test_function_decorator_os_path_escape_taints_later_reimport(decorator):
    source = (
        "import os\n"
        f"@{decorator}\n"
        "def load():\n"
        "    pass\n"
        "import os\n"
        "path = os.path.join('/etc', 'passwd')\n"
        "open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "setup",
    [
        "import os as helper",
        "from os import path as helper",
        "import os as imported\nhelper = imported",
    ],
    ids=["module-alias", "path-alias", "alias-chain"],
)
def test_delayed_function_tracks_module_os_alias_mutation(setup):
    target = "helper.path.join" if "path as helper" not in setup else "helper.join"
    source = (
        f"{setup}\n"
        "def load():\n"
        f"    {target} = replacement\n"
        "    import os\n"
        "    path = os.path.join('/etc', 'passwd')\n"
        "    return open(path)\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


def test_nested_delayed_scope_inherits_enclosing_future_os_path_mutation():
    source = """\
def outer():
    def inner():
        import os
        path = os.path.join('/etc', 'passwd')
        return open(path)
    import os
    os.path.join = replacement
    return inner()
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "invocation",
    [
        "(lambda: setattr(os.path, 'join', replacement))()",
        "[(lambda: setattr(os.path, 'join', replacement))][0]()",
        "(lambda: setattr(os.path, 'join', replacement)).__call__()",
        "((lambda: setattr(os.path, 'join', replacement)) if enabled else noop)()",
        "((lambda: (lambda: setattr(os.path, 'join', replacement)))())()",
    ],
    ids=["direct", "subscript", "dunder-call", "conditional", "factory"],
)
def test_immediate_lambda_os_path_mutation_survives_reimport(invocation):
    source = f"import os\n{invocation}\nimport os\npath = os.path.join('/etc', 'passwd')\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_augassign_os_path_target_address_effect_precedes_rhs_read():
    source = """\
import os
values[setattr(os.path, 'join', replacement)] += open(os.path.join('/etc', 'passwd'))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "statement",
    [
        "os.path.join = open(os.path.join('/etc', 'passwd'))",
        "os.path.join += open(os.path.join('/etc', 'passwd'))",
    ],
    ids=["assign", "augassign"],
)
def test_os_path_join_store_follows_rhs_read(statement):
    source = f"import os\n{statement}\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


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
        "class Configure((open := object)):\n    pass",
        "class Configure(metaclass=(open := type)):\n    pass",
        "configure = lambda value=(open := (lambda value: value)): None",
    ],
    ids=["default", "decorator", "class-base", "class-keyword", "lambda-default"],
)
def test_eager_definition_expressions_that_replace_open_are_honored(make_skill, definition):
    source = f"{definition}\npath='/etc/'+'passwd'\nopen(path)\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_annotation_open_replacement_matches_runtime_evaluation(make_skill):
    definition = "import builtins\ndef configure(value: setattr(builtins, 'open', lambda value: value)):\n    pass"
    source = f"{definition}\npath='/etc/'+'passwd'\nopen(path)\n"
    matches = _matches(StaticAnalyzer(use_yara=False), make_skill({"scripts/main.py": source}))

    if sys.version_info >= (3, 14):
        assert len(matches) == 1
        assert matches[0].line_number == 5
    else:
        assert matches == []


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
    with open('/tmp/safe'):
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
        "print(open(path).read())",
    ],
)
def test_nested_open_expressions_are_detected(make_skill, expression):
    skill = make_skill({"scripts/main.py": (f"import json\npath='/etc/'+'passwd'\n{expression}\n")})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 3


@pytest.mark.parametrize(
    "expression",
    [
        "False and open(path)",
        "True or open(path)",
        "None if True else open(path)",
        "lambda: open(path)",
        "(open(path) for _ in values)",
        "((path := '/tmp/safe'), open(path))",
        "((open := replacement), open(path))",
    ],
    ids=[
        "false-and",
        "true-or",
        "dead-if-expression",
        "lambda",
        "generator",
        "path-walrus",
        "open-walrus",
    ],
)
def test_nested_open_traversal_skips_delayed_unreachable_and_rebound_calls(expression):
    source = f"path='/etc/'+'passwd'\nresult={expression}\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "expression",
    [
        "(setattr(os.path, 'join', replacement), open(os.path.join('/etc', 'passwd')))[1]",
        "consume(setattr(os.path, 'join', replacement), open(os.path.join('/etc', 'passwd')))",
    ],
)
def test_nested_open_does_not_cross_an_earlier_os_path_mutation(expression):
    assert find_constructed_sensitive_file_reads(f"import os\nresult={expression}\n") == ()


def test_nested_open_does_not_cross_an_earlier_builtin_mutation():
    source = "import builtins\npath='/etc/'+'passwd'\nresult=(setattr(builtins, 'open', replacement), open(path))[1]\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "definition",
    [
        "def load(handle=open(path)):\n    pass",
        "async def load(handle=open(path)):\n    pass",
        "@register(open(path))\ndef load():\n    pass",
        "def load(*, handle=open(path)):\n    pass",
        "class Load(open(path)):\n    pass",
        "@register(open(path))\nclass Load:\n    pass",
    ],
    ids=["default", "async-default", "decorator", "kw-default", "class-base", "class-decorator"],
)
def test_definition_creation_records_eager_sensitive_reads(definition):
    source = f"path='/etc/'+'passwd'\n{definition}\n"

    assert len(find_constructed_sensitive_file_reads(source)) == 1


def test_function_default_records_inline_os_path_join_read():
    source = "import os\ndef load(handle=open(os.path.join('/etc', 'passwd'))):\n    pass\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


def test_future_annotations_are_not_treated_as_eager_bindings():
    source = """\
from __future__ import annotations
path = '/etc/' + 'passwd'
def configure(value: open(path)):
    pass
open(path)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="annotations are deferred by default")
def test_eager_function_annotation_records_a_sensitive_read():
    source = "path='/etc/'+'passwd'\ndef load(value: consume(open(path))):\n    pass\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


@pytest.mark.parametrize(
    "expression",
    [
        "[] or open(path)",
        "open('/tmp/safe') and open(path)",
        "(lambda: None) and open(path)",
    ],
    ids=["empty-or", "reviewed-open-and", "lambda-and"],
)
def test_nested_open_scans_definitely_executed_boolean_operands(expression):
    source = f"path='/etc/'+'passwd'\nresult={expression}\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


@pytest.mark.parametrize(
    ("initial_path", "expression", "expected"),
    [
        ("'/etc/'+'passwd'", "(lambda value: open(value))(path)", True),
        ("'/etc/'+'passwd'", "(lambda *, value: open(value))(value=path)", True),
        (
            "'/etc/'+'passwd'",
            "(lambda captured=path, ignored=(path:='/tmp/safe'): open(captured))()",
            True,
        ),
        (
            "'/tmp/safe'",
            "(lambda captured=path, ignored=(path:='/etc/'+'passwd'): open(captured))()",
            False,
        ),
    ],
    ids=["positional", "keyword-only", "default-capture", "default-capture-safe"],
)
def test_immediate_lambda_arguments_and_defaults_follow_runtime_order(initial_path, expression, expected):
    source = f"path={initial_path}\nresult={expression}\n"

    assert bool(find_constructed_sensitive_file_reads(source)) is expected


def test_inline_lambda_decorator_application_is_scanned():
    source = "path='/etc/'+'passwd'\n@(lambda function:(open(path), function)[1])\ndef load():\n    pass\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


def test_bare_module_annotations_do_not_bind_runtime_names():
    source = "open: int\nimport os\nos: int\npath=os.path.join('/etc','passwd')\nopen(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax requires Python 3.12")
def test_type_alias_value_is_lazy_until_explicitly_forced():
    source = "type Alias = mutate()\npath='/etc/'+'passwd'\nopen(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [3]


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
        "@mutate(builtins)\ndef f():\n    pass",
        "with nullcontext(builtins) as helper:\n    helper.open = replacement",
        "payload = {'runtime': builtins}",
    ],
    ids=[
        "call-argument",
        "with-context",
        "class-base",
        "function-default",
        "decorator-factory",
        "with-target",
        "container",
    ],
)
def test_eager_runtime_helper_escape_fails_closed(eager_escape):
    source = f"import builtins\n{eager_escape}\npath='/etc/'+'passwd'\nopen(path)\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_runtime_helper_annotation_escape_matches_runtime_evaluation():
    source = "import builtins\ndef f(value: mutate(builtins)):\n    pass\npath='/etc/'+'passwd'\nopen(path)\n"
    candidates = find_constructed_sensitive_file_reads(source)

    if sys.version_info >= (3, 14):
        assert [candidate.line_number for candidate in candidates] == [5]
    else:
        assert candidates == ()


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


def test_immediate_lambda_parameter_shadow_with_unreviewed_call_fails_closed():
    source = """\
import builtins
(lambda builtins: consume(builtins))(safe)
path = '/etc/' + 'passwd'
open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


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

    candidates = find_constructed_sensitive_file_reads(source)

    assert candidates == ()


def test_unrelated_name_aliases_do_not_consume_runtime_helper_limit():
    aliases = "\n".join(f"name{i}=value{i}" for i in range(100))
    source = aliases + "\npath='/etc/'+'passwd'\nopen(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [102]


@pytest.mark.parametrize(
    "source",
    [
        """\
import builtins as helper
def configure():
    global helper
    helper.open = replacement
    path = '/etc/' + 'passwd'
    open(path)
""",
        """\
def configure():
    import builtins as helper
    def nested():
        nonlocal helper
        helper.open = replacement
        path = '/etc/' + 'passwd'
        open(path)
""",
        """\
import builtins as helper
class C:
    global helper
    helper.open = replacement
path = '/etc/' + 'passwd'
open(path)
""",
        """\
class C:
    global globals
    globals()['open'] = replacement
path = '/etc/' + 'passwd'
open(path)
""",
    ],
    ids=["function-global", "nested-nonlocal", "class-global-helper", "class-global-globals"],
)
def test_external_runtime_helper_declarations_preserve_mutation_provenance(source):
    assert find_constructed_sensitive_file_reads(source) == ()


def test_unrelated_class_global_declaration_preserves_builtin_open():
    source = "class C:\n    global unrelated\n    unrelated = safe\npath='/etc/'+'passwd'\nopen(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.parametrize(
    "source",
    [
        "exec(\"import builtins; builtins.open=lambda value:value\")\npath='/etc/'+'passwd'\nopen(path)\n",
        "def configure():\n    exec(\"import builtins; builtins.open=lambda value:value\")\n    path='/etc/'+'passwd'\n    open(path)\n",
        "__import__('builtins').open=replacement\npath='/etc/'+'passwd'\nopen(path)\n",
        "path='/etc/'+'passwd'\nresult=(exec(\"import builtins; builtins.open=lambda value:value\"), open(path))\n",
    ],
    ids=["module-exec", "function-exec", "direct-builtins-import", "same-expression-exec"],
)
def test_explicit_dynamic_runtime_open_replacement_invalidates_later_reads(source):
    assert find_constructed_sensitive_file_reads(source) == ()


def test_read_before_dynamic_runtime_open_replacement_is_preserved():
    source = "path='/etc/'+'passwd'\nresult=(open(path), exec(\"pass\"))\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


@pytest.mark.parametrize(
    "expression",
    [
        "((helper := builtins), setattr(helper, 'open', safe), open('/etc/'+'passwd'))",
        "((helper := builtins), helper.__dict__.__setitem__('open', safe), open('/etc/'+'passwd'))",
    ],
    ids=["setattr", "dict-setitem"],
)
def test_named_expression_helper_mutation_precedes_open(expression):
    source = f"import builtins\nresult={expression}\n"

    assert find_constructed_sensitive_file_reads(source) == ()


def test_open_before_named_expression_helper_mutation_is_preserved():
    source = "import builtins\nresult=(open('/etc/'+'passwd'), (helper := builtins), setattr(helper, 'open', safe))\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


def test_named_expression_helper_mutation_in_defaults_precedes_open():
    source = (
        "import builtins\n"
        "def load(first=(helper:=builtins), second=setattr(helper,'open',safe), "
        "third=open('/etc/'+'passwd')):\n"
        "    pass\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "invocation",
    [
        "(lambda helper: (setattr(helper,'open',safe), open('/etc/'+'passwd')))(builtins)",
        "(lambda helper=builtins: (setattr(helper,'open',safe), open('/etc/'+'passwd')))()",
    ],
    ids=["argument", "default"],
)
def test_immediate_lambda_runtime_helper_binding_preserves_mutation_order(invocation):
    source = f"import builtins\n{invocation}\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "source",
    [
        "(lambda: (open('/etc/'+'passwd'), (open := safe)))()\n",
        "path='/etc/'+'passwd'\n(lambda: (open(path), (path := '/tmp/safe')))()\n",
        "import os\n(lambda: (open(os.path.join('/etc','passwd')), (os := safe)))()\n",
    ],
    ids=["open", "path", "os"],
)
def test_immediate_lambda_compile_scope_locals_are_not_inherited(source):
    assert find_constructed_sensitive_file_reads(source) == ()


def test_comprehension_target_does_not_bind_immediate_lambda_scope():
    source = "(lambda: ([open for open in ()], open('/etc/'+'passwd')))()\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [1]


@pytest.mark.parametrize(
    "target",
    [
        "holder[open('/etc/'+'passwd')]",
        "(open('/etc/'+'passwd')).attribute",
    ],
    ids=["subscript", "attribute"],
)
def test_with_assignment_target_addresses_are_evaluated(target):
    source = f"with manager as {target}:\n    pass\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [1]


def test_with_context_read_precedes_assignment_target_read():
    source = "with open('/etc/'+'shadow') as holder[\n    open('/etc/'+'passwd')\n]:\n    pass\n"

    assert [candidate.path for candidate in find_constructed_sensitive_file_reads(source)] == [
        "/etc/shadow",
        "/etc/passwd",
    ]


def test_direct_lambda_class_decorator_application_is_scanned_after_body():
    source = "path='/etc/'+'passwd'\n@(lambda cls:(open(path),cls)[1])\nclass C:\n    pass\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


@pytest.mark.parametrize("import_name", ["patch", "patch as mock_patch"])
def test_reviewed_patch_decorator_preserves_constructed_path_for_eager_default(import_name):
    decorator_name = "mock_patch" if " as " in import_name else "patch"
    source = (
        f"from unittest.mock import {import_name}\n"
        "path='/etc/'+'passwd'\n"
        f"@{decorator_name}('builtins.open')\n"
        "def load(mock_open, handle=open(path)):\n"
        "    pass\n"
    )

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [4]


def test_reviewed_patch_decorator_preserves_os_path_join_for_eager_default():
    source = (
        "import os\n"
        "from unittest.mock import patch\n"
        "@patch('builtins.open')\n"
        "def load(mock_open, handle=open(os.path.join('/etc', 'passwd'))):\n"
        "    pass\n"
    )

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [4]


@pytest.mark.parametrize(
    "statement",
    [
        "patch = replacement",
        "mutate_runtime()",
    ],
    ids=["rebound", "ambiguous-runtime-mutation"],
)
def test_untrusted_patch_decorator_does_not_preserve_eager_default_facts(statement):
    source = (
        "from unittest.mock import patch\n"
        f"{statement}\n"
        "path='/etc/'+'passwd'\n"
        "@patch('builtins.open')\n"
        "def load(mock_open, handle=open(path)):\n"
        "    pass\n"
    )

    assert find_constructed_sensitive_file_reads(source) == ()


def test_effectful_patch_decorator_argument_is_scanned():
    source = (
        "from unittest.mock import patch\n"
        "path='/etc/'+'passwd'\n"
        "@patch('builtins.open', replacement=open(path))\n"
        "def load(mock_open):\n"
        "    pass\n"
    )

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [3]


def test_earlier_decorator_rebinding_prevents_later_patch_factory_trust():
    source = """\
import builtins
from unittest.mock import patch
path='/etc/'+'passwd'
@(patch := (lambda target: (setattr(builtins, 'open', lambda *args: None), (lambda function: function))[1]))
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_later_decorator_rebinding_does_not_change_earlier_default_evaluation():
    source = """\
from unittest.mock import patch
path='/etc/'+'passwd'
@patch('builtins.open')
@(patch := None)
def load(handle=open(path)):
    pass
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.parametrize(
    "mutation",
    [
        "patch.__code__ = evil.__code__",
        "alias = patch\nalias.__code__ = evil.__code__",
    ],
    ids=["direct", "escaped-alias"],
)
def test_mutable_patch_factory_identity_is_not_trusted(mutation):
    source = f"""\
from unittest.mock import patch
def evil(*args, **kwargs):
    setattr(__import__('builtins'), 'open', lambda *args: None)
    return lambda function: function
{mutation}
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_prior_unittest_mock_module_exposure_disables_patch_factory_trust():
    source = """\
import unittest.mock
unittest.mock.patch = replacement
from unittest.mock import patch
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_mutable_patch_decorator_application_does_not_preserve_later_facts():
    source = """\
import builtins
from unittest.mock import patch, _patch
def evil(self, function):
    builtins.open = lambda *args: None
    return function
_patch.__call__ = evil
path='/etc/'+'passwd'
@patch('builtins.open')
def first(handle=open(path)):
    pass
path='/etc/'+'shadow'
@patch('builtins.open')
def second(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_inert_earlier_decorator_does_not_hide_later_patch_default_read():
    source = """\
from unittest.mock import patch
path='/etc/'+'passwd'
@(lambda function: function)
@patch('builtins.open')
def load(mock_open, handle=open(path)):
    pass
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax requires Python 3.12")
@pytest.mark.parametrize("type_parameter", ["open", "path"])
def test_type_parameter_does_not_shadow_direct_lambda_decorator_closure(type_parameter):
    source = (
        "path='/etc/'+'passwd'\n"
        "@(lambda function:(open(path), function)[1])\n"
        f"def load[{type_parameter}]():\n"
        "    pass\n"
    )

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


@pytest.mark.parametrize(
    "body",
    [
        "global path\n    path='/dev/null'",
        "global open\n    open=lambda *args: None",
    ],
    ids=["path", "open"],
)
def test_class_body_external_mutation_precedes_lambda_decorator_application(body):
    source = f"path='/etc/'+'passwd'\n@(lambda cls:(open(path), cls)[1])\nclass C:\n    {body}\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "class_body",
    [
        "patch.__code__ = evil.__code__",
        "import unittest.mock\n    unittest.mock.patch = replacement",
    ],
    ids=["direct-patch-mutation", "module-poisoning"],
)
def test_eager_class_body_invalidates_later_patch_factory_trust(class_body):
    source = f"""\
from unittest.mock import patch
def evil(*args, **kwargs):
    setattr(__import__('builtins'), 'open', lambda *args: None)
    return lambda function: function
class Poison:
    {class_body}
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_immediate_lambda_result_invalidates_patch_factory_trust():
    source = """\
from unittest.mock import patch
def evil(*args, **kwargs):
    setattr(__import__('builtins'), 'open', lambda *args: None)
    return lambda function: function
(lambda: patch)().__code__ = evil.__code__
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "patch = evil",
        "del patch",
    ],
    ids=["assignment", "deletion"],
)
def test_class_body_external_patch_rebinding_invalidates_later_factory_trust(mutation):
    source = f"""\
from unittest.mock import patch
def evil(*args, **kwargs):
    setattr(__import__('builtins'), 'open', lambda *args: None)
    return lambda function: function
class Poison:
    global patch
    {mutation}
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "class_body",
    [
        "global patch\n    pass",
        "patch = replacement",
    ],
    ids=["declaration-only", "class-local-shadow"],
)
def test_class_body_without_external_patch_write_preserves_later_factory_trust(class_body):
    source = f"""\
from unittest.mock import patch
class Harmless:
    {class_body}
path='/etc/'+'passwd'
@patch('builtins.open')
def load(mock_open, handle=open(path)):
    pass
"""

    assert [candidate.path for candidate in find_constructed_sensitive_file_reads(source)] == ["/etc/passwd"]


def test_nested_class_body_nonlocal_patch_rebinding_invalidates_later_factory_trust():
    source = """\
def outer():
    from unittest.mock import patch
    def evil(*args, **kwargs):
        setattr(__import__('builtins'), 'open', lambda *args: None)
        return lambda function: function
    class Poison:
        nonlocal patch
        patch = evil
    path='/etc/'+'passwd'
    @patch('builtins.open')
    def load(handle=open(path)):
        pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("definition", ["def load(mock_open):\n    pass", "class Load:\n    pass"])
@pytest.mark.parametrize("lambda_is_outer", [False, True], ids=["lambda-inner", "lambda-outer"])
def test_direct_lambda_application_is_scanned_across_reviewed_patch_decorator(
    definition,
    lambda_is_outer,
):
    decorators = [
        "@(lambda value:(open(path), value)[1])",
        "@patch('builtins.open')",
    ]
    if not lambda_is_outer:
        decorators.reverse()
    decorator_source = "\n".join(decorators)
    source = f"from unittest.mock import patch\npath='/etc/'+'passwd'\n{decorator_source}\n{definition}\n"

    expected_paths = [] if definition.startswith("class ") and lambda_is_outer else ["/etc/passwd"]
    assert [candidate.path for candidate in find_constructed_sensitive_file_reads(source)] == expected_paths


def test_nested_class_global_path_mutation_precedes_outer_lambda_decorator_application():
    source = """\
path='/etc/'+'passwd'
@(lambda cls:(open(path), cls)[1])
class Outer:
    class Inner:
        global path
        path='/dev/null'
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_nested_class_nonlocal_path_mutation_precedes_outer_lambda_decorator_application():
    source = """\
def enclosing():
    path='/etc/'+'passwd'
    @(lambda cls:(open(path), cls)[1])
    class Outer:
        class Inner:
            nonlocal path
            path='/dev/null'
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "from unittest.mock import _patch\n    _patch.__call__ = evil",
        "patch.__globals__['_patch'].__call__ = evil",
    ],
    ids=["private-patcher-import", "patch-globals"],
)
def test_class_body_patch_application_mutation_precedes_mixed_decorators(mutation):
    source = f"""\
import builtins
from unittest.mock import patch
def evil(self, value):
    builtins.open = lambda *args, **kwargs: None
    return value
path='/etc/'+'passwd'
@(lambda value:(open(path), value)[1])
@patch('builtins.open')
class Load:
    {mutation}
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_inner_lambda_patch_application_mutation_precedes_outer_lambda_read():
    source = """\
from unittest.mock import patch
def evil(self, value):
    setattr(__import__('builtins'), 'open', lambda *args, **kwargs: None)
    return value
path='/etc/'+'passwd'
@(lambda value:(open(path), value)[1])
@patch('builtins.open')
@(lambda value:(setattr(patch.__globals__['_patch'], '__call__', evil), value)[1])
def load():
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "base_expression",
    [
        "(path := '/dev/null') and object",
        "(open := lambda *args: None) and object",
    ],
    ids=["path-rebinding", "open-rebinding"],
)
def test_class_base_effects_precede_direct_lambda_decorator_application(base_expression):
    source = f"""\
path='/etc/'+'passwd'
@(lambda cls:(open(path), cls)[1])
class Load({base_expression}):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_class_patch_descriptor_effect_precedes_outer_lambda_decorator_application():
    source = """\
def outer(descriptor):
    from unittest.mock import patch
    path='/etc/'+'passwd'
    @(lambda value:(open(path), value)[1])
    @patch('builtins.open')
    class Load:
        test_probe = descriptor
    return Load
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "earlier_expression",
    [
        "mutate()",
        "obj.trigger",
        "obj[0]",
        "1 / 0",
    ],
    ids=["call", "attribute", "subscript", "guaranteed-exception"],
)
def test_unreviewed_eager_default_prevents_later_default_read(earlier_expression):
    source = f"""\
path='/etc/'+'passwd'
def load(first={earlier_expression}, handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_unreviewed_inner_lambda_prevents_outer_lambda_read():
    source = """\
path='/etc/'+'passwd'
@(lambda value:(open(path), value)[1])
@(lambda value:(obj.trigger, value)[1])
def load():
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "earlier_statement",
    [
        "obj.trigger",
        "obj[0]",
        "proxy.attr = 1",
        "proxy[0] = 1",
        "del proxy.attr",
        "del proxy[0]",
        "import attacker",
        "holder.__globals__['patch'] = evil",
        "obj + 1",
        "obj == 1",
        "not obj",
        "{obj}",
        "{obj: 1}",
        "[*obj]",
        "f'{obj}'",
    ],
)
def test_unreviewed_hooks_retire_patch_factory_provenance(earlier_statement):
    source = f"""\
from unittest.mock import patch
{earlier_statement}
path='/etc/'+'passwd'
@(lambda value:(open(path), value)[1])
@patch('builtins.open')
def load():
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_inert_string_work_preserves_patch_factory_provenance():
    source = """\
from unittest.mock import patch
label='safe'+'value'
path='/etc/'+'passwd'
@(lambda value:(open(path), value)[1])
@patch('builtins.open')
def load():
    pass
"""

    assert [candidate.path for candidate in find_constructed_sensitive_file_reads(source)] == ["/etc/passwd"]


@pytest.mark.parametrize(
    "mutation_target",
    ["json", "alias"],
    ids=["direct", "escaped-alias"],
)
def test_json_module_mutation_precedes_nested_open_argument(mutation_target):
    alias = "alias=json\n" if mutation_target == "alias" else ""
    source = f"""\
import json
{alias}{mutation_target}.__getattr__ = hook
del {mutation_target}.load
path='/etc/'+'passwd'
json.load(open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_shadowed_globals_call_retires_patch_factory_provenance():
    source = """\
from unittest.mock import patch
globals = fake_helper
globals()
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "class_body",
    [
        "global json\n    json = None",
        "class Inner:\n        global json\n        json = None",
    ],
    ids=["direct", "nested-class"],
)
def test_class_external_json_rebinding_precedes_nested_open_argument(class_body):
    source = f"""\
import json
class Poison:
    {class_body}
path='/etc/'+'passwd'
json.load(open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_named_expression_json_rebinding_precedes_nested_open_argument():
    source = """\
import json
path='/etc/'+'passwd'
payload=((json := None), json.load(open(path)))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_comprehension_target_shadows_reviewed_json_module():
    source = """\
import json
path='/etc/'+'passwd'
payload=[json.load(open(path)) for json in (None,)]
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "earlier_statement",
    [
        "()[0]",
        "[][0]",
        "(1,)[0] = 2",
        "[][0] = 2",
        "del (1,)[0]",
        "del [][0]",
    ],
)
def test_failing_literal_subscript_retires_patch_factory_provenance(earlier_statement):
    source = f"""\
from unittest.mock import patch
{earlier_statement}
path='/etc/'+'passwd'
@patch('builtins.open')
def load(handle=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("statement", ["assign", "delete"])
def test_ordered_target_json_rebinding_precedes_nested_open_address(statement):
    operation = (
        "json, sink[json.load(open(path))] = (None, 1)"
        if statement == "assign"
        else "del json, sink[json.load(open(path))]"
    )
    source = f"""\
import json
path='/etc/'+'passwd'
{operation}
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "setup",
    [
        "import sys\nsys.modules['json'] = sys",
        "alias = __import__('json')\ndel alias.load",
    ],
    ids=["module-cache-replacement", "preimport-identity-escape"],
)
def test_compromised_json_import_is_not_retrusted(setup):
    source = f"""\
{setup}
import json
path='/etc/'+'passwd'
json.load(open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "poison",
    [
        "import sys\nsys.modules['os'] = sys",
        "import sys\ncache = sys.modules\ncache['os'] = sys",
    ],
    ids=["direct-write", "escaped-cache"],
)
def test_compromised_os_import_is_not_retrusted(poison):
    source = f"""\
{poison}
import os
path=os.path.join('/etc','passwd')
open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("replacement", ["os", "builtins"])
def test_later_same_statement_import_alias_replaces_json(replacement):
    source = f"""\
import json as helper, {replacement} as helper
path='/etc/'+'passwd'
helper.load(open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "comprehension",
    [
        "{item for item in (obj,)}",
        "{item: 1 for item in (obj,)}",
    ],
    ids=["set", "dict"],
)
def test_comprehension_hash_hooks_precede_later_open(comprehension):
    source = f"""\
def outer(obj):
    @(lambda value:({comprehension}, open('/etc/'+'passwd'), value)[-1])
    def load():
        pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "source",
    [
        "import sys\nsys.modules['json'] = sys\nclass C:\n"
        "    import json\n    path='/etc/'+'passwd'\n    payload=json.load(open(path))",
        "def load():\n    import json\n    path='/etc/'+'passwd'\n    return json.load(open(path))\n"
        "import sys\nsys.modules['json'] = sys\nload()",
    ],
    ids=["class", "delayed-function"],
)
def test_future_module_cache_poisoning_invalidates_nested_json_import(source):
    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "comprehension",
    [
        "[(json := None) for _ in (0,)]",
        "{0: (json := None) for _ in (0,)}",
    ],
    ids=["list", "inert-key-dict"],
)
def test_comprehension_walrus_rebinding_precedes_later_json_lookup(comprehension):
    source = f"""\
import json
path='/etc/'+'passwd'
payload=({comprehension}, json.load(open(path)))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_container_wrapped_json_identity_escape_taints_future_local_import():
    source = """\
def consumer():
    import json
    return json.load(open('/etc/'+'passwd'))
def expose():
    import json
    return (json,)
holder=expose()
del holder[0].load
consumer()
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "poison",
    [
        "cache=__import__('sys').modules\ncache['json']=__import__('sys')",
        "import sys\nsys.modules.update({'json': sys})",
    ],
    ids=["cache-alias", "mapping-update"],
)
def test_module_cache_alias_poisoning_taints_future_local_import(poison):
    source = f"""\
def consumer():
    import json
    return json.load(open('/etc/'+'passwd'))
{poison}
consumer()
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_keyword_unpack_precedes_later_open_keyword():
    source = """\
import json
mapping = None
path='/etc/'+'passwd'
json.load(**mapping, fp=open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("value", ["()", "(1, 2, 3)", "None"])
def test_failing_unpack_precedes_nested_target_address(value):
    source = f"""\
path='/etc/'+'passwd'
safe, sink[open(path)] = {value}
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "first_default",
    [
        "open('/dev/null', buffering=0)",
        "open('/dev/null', mode='rb', encoding='utf-8')",
        "open('/dev/null', closefd=False)",
        "open('/dev/null', newline='invalid')",
        "open('/dev/null', buffering=2147483648)",
        "open('/dev/'+'\\x00null')",
        "open('/dev/null', encoding='definitely-not-a-codec')",
    ],
)
def test_invalid_open_default_precedes_later_sensitive_default(first_default):
    source = f"""\
from unittest.mock import patch
path='/etc/'+'passwd'
@patch('builtins.open')
def load(first={first_default}, second=open(path)):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_invalid_inner_lambda_arity_precedes_outer_lambda_read():
    source = """\
from unittest.mock import patch
path='/etc/'+'passwd'
@(lambda value:(open(path), value)[1])
@(lambda: None)
@patch('builtins.open')
def load():
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_class_keyword_failure_precedes_decorator_application():
    source = """\
from unittest.mock import patch
path='/etc/'+'passwd'
@patch('builtins.open')
@(lambda value:(open(path), value)[1])
class Load(foo=1):
    pass
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_future_arbitrary_import_invalidates_delayed_patch_factory_import():
    source = """\
def consumer():
    from unittest.mock import patch
    path='/etc/'+'passwd'
    @patch('builtins.open')
    def load(handle=open(path)):
        pass
from attacker import trigger
consumer()
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_delayed_json_import_is_not_trusted_after_alternate_module_resolution():
    source = """\
def consumer():
    import json
    path='/etc/'+'passwd'
    return json.load(open(path))
import pkgutil
alias=pkgutil.resolve_name('json')
del alias.load
consumer()
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "statement",
    [
        "assert open(path)",
        "assert False, open(path)",
    ],
    ids=["test", "message"],
)
def test_assert_expressions_are_scanned_in_runtime_order(statement):
    source = f"path='/etc/'+'passwd'\n{statement}\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


def test_raise_cause_expression_is_scanned_after_the_exception():
    source = "path='/etc/'+'passwd'\nraise ValueError from open(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]


def test_load_of_definitely_deleted_name_precedes_later_open():
    source = """\
path='/etc/'+'passwd'
missing=1
del missing
payload=(missing, open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_rebinding_a_deleted_name_restores_straight_line_scanning():
    source = """\
path='/etc/'+'passwd'
missing=1
del missing
missing=2
payload=(missing, open(path))
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.parametrize(
    "invalid_statement",
    [
        "consume(value=open(path), value=1)",
        "return open(path)",
    ],
    ids=["duplicate-keyword", "top-level-return"],
)
def test_compile_time_invalid_source_cannot_report_a_read(invalid_statement):
    source = f"path='/etc/'+'passwd'\n{invalid_statement}\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "container",
    ["[1]", "(1,)", "{1}", "{1: 2}"],
    ids=["list", "tuple", "set", "dict"],
)
def test_nonempty_literal_truth_allows_guaranteed_boolean_operand(container):
    source = f"path='/etc/'+'passwd'\nresult={container} and open(path)\n"

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [2]
