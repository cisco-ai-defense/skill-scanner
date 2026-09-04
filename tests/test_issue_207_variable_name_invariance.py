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
