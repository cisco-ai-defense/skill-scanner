# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Security boundaries for the scanner's single YARA-X backend."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement

from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.rules.yara_scanner import YaraScanner

_REPOSITORY_ROOT = Path(__file__).parents[1]


def _write_rule(rules_dir: Path, source: str) -> None:
    rules_dir.mkdir()
    (rules_dir / "rules.yara").write_text(source, encoding="utf-8")


def test_runtime_and_lock_declare_only_the_yara_x_backend() -> None:
    project = tomllib.loads((_REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependency_names = {Requirement(value).name for value in project["project"]["dependencies"]}
    lock = tomllib.loads((_REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked_names = {package["name"] for package in lock["package"]}

    assert "yara-x" in dependency_names
    assert "yara-python" not in dependency_names
    assert "yara-x" in locked_names
    assert "yara-python" not in locked_names


def test_runtime_rejects_yara_include_directives_even_when_target_exists(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yara"
    outside.write_text("private rule imported { condition: true }\n", encoding="utf-8")
    rules_dir = tmp_path / "rules"
    _write_rule(
        rules_dir,
        f'''\
include "{outside}"
rule declared {{
    strings:
        $marker = "DECLARED_MARKER"
    condition:
        imported and $marker
}}
''',
    )

    with pytest.raises(RuntimeError, match="include statements not allowed"):
        YaraScanner(rules_dir)


def test_trusted_pack_validation_rejects_yara_include_directives(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yara"
    outside.write_text("private rule imported { condition: true }\n", encoding="utf-8")
    pack = tmp_path / "trusted-pack"
    rules_dir = pack / "yara"
    pack.mkdir()
    (pack / "pack.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "name": "trusted-pack",
                "version": "1.0",
                "description": "Test-only trusted YARA pack",
                "rules": {
                    "YARA_declared": {
                        "source": "yara",
                        "category": "malware",
                        "severity": "high",
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _write_rule(
        rules_dir,
        f'''\
include "{outside}"
rule declared {{
    strings:
        $marker = "DECLARED_MARKER"
    condition:
        imported and $marker
}}
''',
    )

    with pytest.raises(ValueError, match="include statements not allowed"):
        PackLoader().load_trusted_pack(pack)


def test_runtime_rejects_patterns_yara_x_classifies_as_slow(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(
        rules_dir,
        """\
rule slow_pattern {
    strings:
        $one_byte_atom = /[a-z]/
    condition:
        $one_byte_atom
}
""",
    )

    with pytest.raises(RuntimeError, match="slow pattern"):
        YaraScanner(rules_dir)


def test_runtime_bounds_repeated_evidence_without_losing_rule_match(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(
        rules_dir,
        """\
rule repeated_marker {
    strings:
        $marker = "REPEATED_MARKER"
    condition:
        $marker
}
""",
    )
    scanner = YaraScanner(rules_dir, max_matches_per_pattern=7)

    matches = scanner.scan_content("REPEATED_MARKER " * 10_000, "large.txt")

    assert [match["rule_name"] for match in matches] == ["repeated_marker"]
    assert len(matches[0]["strings"]) == 7


def test_runtime_rejects_non_positive_match_limit(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir, "rule marker { condition: true }\n")

    with pytest.raises(ValueError, match="at least 1"):
        YaraScanner(rules_dir, max_matches_per_pattern=0)
