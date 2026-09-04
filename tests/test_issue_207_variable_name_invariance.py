# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for sensitive-path alias invariance (issue #207)."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.static_analysis.python_sensitive_file_reads import (
    find_constructed_sensitive_file_reads,
)

_RULE_ID = "DATA_EXFIL_SENSITIVE_FILES"
_SEMANTIC_PATTERN = "python_ast:constructed_sensitive_file_read"


def _matches(analyzer: StaticAnalyzer, skill) -> list:
    return [finding for finding in analyzer.analyze(skill) if finding.rule_id == _RULE_ID]


@pytest.mark.parametrize("path_name", ["credentials_path", "ss"])
def test_resolved_sensitive_path_is_detected_independently_of_alias_name(make_skill, path_name):
    source = f"""
import os

CONFIG_DIR = '/home/user/.aws'
CREDENTIALS_FILE = 'credentials'
{path_name} = os.path.join(CONFIG_DIR, CREDENTIALS_FILE)

if os.path.exists({path_name}):
    with open({path_name}, 'r') as f:
        credentials = f.read()
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 9
    assert matches[0].metadata["matched_pattern"] == _SEMANTIC_PATTERN
    assert matches[0].metadata["resolved_path"] == "/home/user/.aws/credentials"


@pytest.mark.parametrize("path_name", ["config_path", "ss"])
def test_exact_sensitive_concat_bypasses_only_regex_alias_exclusions(make_skill, path_name):
    source = f"{path_name} = '/etc/' + 'passwd'\nopen({path_name})\n"
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].line_number == 2
    assert matches[0].metadata["matched_pattern"] == _SEMANTIC_PATTERN
    assert matches[0].metadata["resolved_path"] == "/etc/passwd"


@pytest.mark.parametrize("path_name", ["config_path", "ss"])
def test_benign_exact_path_stays_clean_for_equivalent_aliases(make_skill, path_name):
    source = f"{path_name} = '/tmp/' + 'public.txt'\nopen({path_name})\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize("path_name", ["credentials_path", "ss"])
def test_exact_unresolved_issue_variant_is_name_invariant(make_skill, path_name):
    source = f"""
import os
import json

{path_name} = os.path.join(CONFIG_DIR, CREDENTIALS_FILE)

if os.path.exists({path_name}):
    with open({path_name}, 'r') as f:
        credentials = json.load(f)
"""
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "name",
    ["credentials_path", "credential_path", "secret_path", "keys_path", "tokens_path"],
)
def test_sensitive_sounding_name_with_benign_value_is_not_flagged(make_skill, name):
    skill = make_skill({"scripts/main.py": f"{name}='/tmp/public.txt'\nopen({name})\n"})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_alias_chain_inside_exists_guard_is_detected(make_skill):
    source = """
import os
root = '/etc'
name = 'passwd'
p = os.path.join(root, name)
q = p
if os.path.exists(q):
    with open(q, mode='rb') as handle:
        value = handle.read()
"""
    skill = make_skill({"scripts/main.py": source})

    matches = _matches(StaticAnalyzer(use_yara=False), skill)

    assert len(matches) == 1
    assert matches[0].metadata["resolved_path"] == "/etc/passwd"


@pytest.mark.parametrize("json_import", ["import json", "import json as codec"])
def test_guard_preserves_reviewed_json_load_wrapper(json_import):
    json_name = "codec" if "codec" in json_import else "json"
    source = f"""\
{json_import}
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    data = {json_name}.load(open(path))
"""

    candidates = find_constructed_sensitive_file_reads(source)

    assert [(candidate.path, candidate.line_number) for candidate in candidates] == [
        ("/etc/passwd", 5),
    ]


def test_guarded_json_rebind_does_not_preserve_stale_module_provenance():
    source = """\
import json
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    json = replacement
    data = json.load(open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_guard_can_establish_reviewed_json_alias_in_source_order():
    source = """\
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    import json as codec
    data = codec.load(open(path))
"""

    candidates = find_constructed_sensitive_file_reads(source)

    assert [(candidate.path, candidate.line_number) for candidate in candidates] == [
        ("/etc/passwd", 5),
    ]


@pytest.mark.parametrize(
    ("imports", "json_name"),
    [
        ("import json\nimport os.path", "json"),
        ("import json\nfrom unittest.mock import patch\nimport os", "json"),
        ("from __future__ import annotations\nimport json\nimport os", "json"),
        ("import builtins, os.path, json as codec", "codec"),
    ],
    ids=["os-path", "patch", "future", "mixed-import"],
)
def test_reviewed_imports_preserve_guarded_json_provenance(imports, json_name):
    source = f"""\
{imports}
path = '/etc/' + 'passwd'
if os.path.exists(path):
    {json_name}.load(open(path))
"""

    candidates = find_constructed_sensitive_file_reads(source)

    assert [candidate.path for candidate in candidates] == ["/etc/passwd"]


def test_reviewed_import_from_rebinding_retires_json_provenance():
    source = """\
import json
from unittest.mock import patch as json
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    json.load(open(path))
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "unreviewed_import",
    ["import attacker_hook", "from attacker_hook import marker"],
    ids=["import", "import-from"],
)
@pytest.mark.parametrize(
    "setup",
    [
        "import os\npath = '/etc/' + 'passwd'\n{unreviewed_import}",
        "import os\n{unreviewed_import}\npath = '/etc/' + 'passwd'",
        "{unreviewed_import}\nimport os\npath = '/etc/' + 'passwd'",
    ],
    ids=["after-path", "before-path", "before-reviewed-reimport"],
)
def test_unreviewed_import_invalidates_exists_guard_provenance(
    unreviewed_import,
    setup,
):
    source = f"""\
{setup.format(unreviewed_import=unreviewed_import)}
if os.path.exists(path):
    open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_reviewed_os_path_import_preserves_positive_provenance():
    source = """\
import os.path
path = os.path.join('/etc', 'passwd')
if os.path.exists(path):
    open(path)
"""

    candidates = find_constructed_sensitive_file_reads(source)

    assert [(candidate.path, candidate.line_number) for candidate in candidates] == [
        ("/etc/passwd", 4),
    ]


@pytest.mark.parametrize(
    "compound_import",
    [
        "if True:\n    import attacker_hook",
        "try:\n    import attacker_hook\nexcept ImportError:\n    pass",
        "for _ in (0,):\n    import attacker_hook",
    ],
    ids=["if", "try", "for"],
)
def test_nested_unreviewed_import_invalidates_runtime_open_provenance(compound_import):
    source = f"{compound_import}\nopen('/etc/' + 'passwd')\n"

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize("call", ["poison()", "alias()"], ids=["direct", "alias"])
def test_called_local_function_invalidates_runtime_open_provenance(call):
    alias = "alias = poison\n" if call == "alias()" else ""
    source = f"""\
def poison(replacement=print):
    import builtins
    builtins.open = replacement
{alias}{call}
open('/etc/' + 'passwd')
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_dormant_local_function_does_not_invalidate_runtime_open_provenance():
    source = """\
def poison(replacement=print):
    import builtins
    builtins.open = replacement
open('/etc/' + 'passwd')
"""

    assert [candidate.path for candidate in find_constructed_sensitive_file_reads(source)] == ["/etc/passwd"]


def test_transitive_local_function_call_invalidates_runtime_open_provenance():
    source = """\
def poison(replacement=print):
    import builtins
    builtins.open = replacement
def wrapper():
    poison()
wrapper()
open('/etc/' + 'passwd')
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_static_method_call_invalidates_runtime_open_provenance():
    source = """\
class Hooks:
    @staticmethod
    def poison(replacement=print):
        import builtins
        builtins.open = replacement
Hooks.poison()
open('/etc/' + 'passwd')
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_called_function_global_open_rebinding_invalidates_provenance():
    source = """\
def poison():
    global open
    open = print
poison()
open('/etc/' + 'passwd')
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "binding",
    ["import builtins as open", "from unittest.mock import patch as open"],
    ids=["import", "import-from"],
)
def test_called_function_external_open_import_rebinding_invalidates_provenance(binding):
    source = f"""\
def poison():
    global open
    {binding}
poison()
open('/etc/' + 'passwd')
"""

    assert find_constructed_sensitive_file_reads(source) == ()


@pytest.mark.parametrize(
    "later_mutation",
    [
        "builtins.open = replacement",
        "if False:\n        builtins.open = replacement",
    ],
    ids=["direct", "dead-nested"],
)
def test_guarded_read_precedes_later_runtime_open_mutation(later_mutation):
    source = (
        "import builtins\n"
        "import os\n"
        "path = '/etc/' + 'passwd'\n"
        "if os.path.exists(path):\n"
        "    open(path)\n"
        f"    {later_mutation}\n"
    )

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


def test_guarded_runtime_open_mutation_precedes_later_read():
    source = """\
import builtins
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    builtins.open = replacement
    open(path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_guarded_runtime_open_mutation_suppresses_only_later_read():
    source = """\
import builtins
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    open(path)
    builtins.open = replacement
    open(path)
"""

    assert [candidate.line_number for candidate in find_constructed_sensitive_file_reads(source)] == [5]


@pytest.mark.parametrize(
    "shadow",
    [
        "import builtins as helper\nhelper = lambda: None",
        "globals = lambda: {}",
    ],
    ids=["rebound-helper", "shadowed-globals"],
)
def test_guarded_body_preserves_shadowed_runtime_helper_state(shadow):
    helper_mutation = "helper.open = replacement" if "helper" in shadow else "globals()['open'] = replacement"
    source = (
        f"{shadow}\n"
        "import os\n"
        "path = '/etc/' + 'passwd'\n"
        "if os.path.exists(path):\n"
        f"    {helper_mutation}\n"
        "    guarded_path = '/etc/' + 'shadow'\n"
        "    open(guarded_path)\n"
    )

    candidates = find_constructed_sensitive_file_reads(source)

    assert len(candidates) == 1
    assert candidates[0].path == "/etc/shadow"


def test_guarded_nested_class_uses_lexical_runtime_helper_state():
    source = """\
import builtins as helper
import os
path = '/etc/' + 'passwd'
if os.path.exists(path):
    class Outer:
        helper = object()
        class Inner:
            helper.open = replacement
            nested_path = '/etc/' + 'shadow'
            handle = open(nested_path)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_exists_check_without_open_is_not_reported(make_skill):
    source = "import os\np='/etc/'+'passwd'\nif os.path.exists(p):\n    available=True\n"
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


@pytest.mark.parametrize(
    "source",
    [
        "import os\np='/etc/'+'passwd'\np='/tmp/public'\nif os.path.exists(p):\n    open(p)\n",
        "import os\np=get_path()\nif os.path.exists(p):\n    open(p)\n",
        "import os\np='/etc/'+'passwd'\nif check(p):\n    open(p)\n",
        "import os\np='/etc/'+'passwd'\nif os.path.exists(p):\n    open(p, 'w')\n",
        "import os\np='/etc/'+'passwd'\nif os.path.exists(p, follow=True):\n    open(p)\n",
        "import os\np='/etc/'+'passwd'\nif os.path.exists(p):\n    open(p)\nelse:\n    pass\n",
    ],
)
def test_unproven_or_non_read_guarded_flows_are_not_reported(make_skill, source):
    skill = make_skill({"scripts/main.py": source})

    assert _matches(StaticAnalyzer(use_yara=False), skill) == []


def test_guard_body_does_not_leak_aliases_to_following_code():
    source = """
import os
p = '/etc/' + 'passwd'
if os.path.exists(p):
    q = p
open(q)
"""

    assert find_constructed_sensitive_file_reads(source) == ()


def test_guarded_flow_with_malformed_source_is_ignored():
    assert find_constructed_sensitive_file_reads("if os.path.exists(path):\x00\n    open(path)\n") == ()
