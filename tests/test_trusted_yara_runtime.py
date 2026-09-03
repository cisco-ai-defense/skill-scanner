# Copyright 2026 Cisco Systems, Inc.
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

"""Runtime coverage for trusted schema-v2 YARA rule packs."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from skill_scanner.core.analyzer_factory import build_core_analyzers
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.rules.yara_scanner import YaraScanner
from skill_scanner.core.scan_policy import ScanPolicy


def _write_yara_rule(directory: Path, filename: str, rule_id: str, marker: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(
        f'''\
rule {rule_id} {{
    strings:
        $marker = "{marker}" ascii
    condition:
        $marker
}}
''',
        encoding="utf-8",
    )
    return path


def _write_trusted_yara_pack(root: Path, pack_name: str, rule_id: str, marker: str) -> Path:
    root.mkdir()
    manifest = {
        "schema_version": 2,
        "name": pack_name,
        "version": "1.0",
        "description": "Test-only trusted YARA pack",
        "rules": {
            f"YARA_{rule_id}": {
                "source": "yara",
                "category": "malware",
                "severity": "high",
            }
        },
    }
    (root / "pack.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    _write_yara_rule(root / "yara", "shared-name.yara", rule_id, marker)
    return root


def test_single_directory_preserves_legacy_namespaces(tmp_path: Path) -> None:
    rules_dir = tmp_path / "legacy"
    _write_yara_rule(rules_dir, "z-last.yara", "z_rule", "Z_MARKER")
    _write_yara_rule(rules_dir, "a-first.yara", "a_rule", "A_MARKER")

    scanner = YaraScanner(rules_dir)

    assert scanner.rules_dir == rules_dir
    assert scanner.rules_dirs == (rules_dir,)
    assert scanner.get_loaded_rules() == ["a-first", "z-last"]
    matches = scanner.scan_content("A_MARKER Z_MARKER")
    assert {(match["rule_name"], match["namespace"]) for match in matches} == {
        ("a_rule", "a-first"),
        ("z_rule", "z-last"),
    }


def test_multi_directory_namespaces_remain_unique_after_sanitization(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    additional = tmp_path / "additional"
    _write_yara_rule(primary, "shared-name.yara", "first_rule", "FIRST_MARKER")
    _write_yara_rule(additional, "name-with-dash.yara", "dash_rule", "DASH_MARKER")
    _write_yara_rule(additional, "name_with_dash.yara", "underscore_rule", "UNDERSCORE_MARKER")

    scanner = YaraScanner(primary, additional_rules_dirs=[additional])

    namespaces = scanner.get_loaded_rules()
    assert len(namespaces) == len(set(namespaces)) == 3
    assert namespaces == [
        "source_000_primary__0000_shared_name",
        "source_001_additional__0000_name_with_dash",
        "source_001_additional__0001_name_with_dash",
    ]


def test_runtime_rejects_yara_source_without_a_compiled_rule(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_yara_rule(rules_dir, "active.yara", "active_rule", "ACTIVE_MARKER")
    (rules_dir / "comments-only.yara").write_text("/* no active rules */\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="source file contains no rules"):
        YaraScanner(rules_dir)


def test_text_files_above_yara_size_limit_are_not_scanned(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_yara_rule(rules_dir, "marker.yara", "marker_rule", "LARGE_MARKER")
    large_text = tmp_path / "large.txt"
    large_text.write_text("LARGE_MARKER " * 20, encoding="utf-8")

    scanner = YaraScanner(rules_dir, max_scan_file_size=32)

    assert scanner.scan_file(large_text) == []


def test_in_memory_content_above_yara_size_limit_is_not_scanned(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_yara_rule(rules_dir, "marker.yara", "marker_rule", "LARGE_MARKER")
    scanner = YaraScanner(rules_dir, max_scan_file_size=32)

    assert scanner.scan_content("LARGE_MARKER " * 20, "virtual.txt") == []


def test_unknown_manifest_metadata_override_fails_generation(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_yara_rule(rules_dir, "active.yara", "active_rule", "ACTIVE_MARKER")

    with pytest.raises(RuntimeError, match="do not have compiled implementations"):
        YaraScanner(rules_dir, metadata_overrides={"missing_rule": {"severity": "HIGH"}})


def test_trusted_runtime_rejects_implementation_added_after_validation(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    trusted = tmp_path / "trusted"
    _write_yara_rule(primary, "base.yara", "base_rule", "BASE_MARKER")
    _write_yara_rule(trusted, "declared.yara", "declared_rule", "DECLARED_MARKER")
    _write_yara_rule(trusted, "injected.yara", "injected_rule", "INJECTED_MARKER")

    with pytest.raises(RuntimeError, match=r"implementation drift .*unexpected: injected_rule"):
        YaraScanner(
            primary,
            additional_rules_dirs=[trusted],
            metadata_overrides={
                "declared_rule": {"category": "malware", "severity": "HIGH"},
            },
        )


def test_static_analyzer_compiles_multiple_trusted_yara_dirs_with_custom_base(tmp_path: Path) -> None:
    custom_dir = tmp_path / "custom"
    _write_yara_rule(custom_dir, "shared-name.yara", "custom_rule", "CUSTOM_MARKER")
    first_pack = _write_trusted_yara_pack(tmp_path / "first-pack", "first-pack", "trusted_one", "ONE_MARKER")
    second_pack = _write_trusted_yara_pack(
        tmp_path / "second-pack",
        "second-pack",
        "trusted_two",
        "TWO_MARKER",
    )

    analyzer = StaticAnalyzer(
        custom_yara_rules_path=custom_dir,
        trusted_pack_dirs=[first_pack, second_pack],
    )

    assert analyzer.yara_scanner is not None
    namespaces = analyzer.yara_scanner.get_loaded_rules()
    assert namespaces == [
        "source_000_custom__0000_shared_name",
        "source_001_yara__0000_shared_name",
        "source_002_yara__0000_shared_name",
    ]
    assert len(namespaces) == len(set(namespaces))
    matches = analyzer.yara_scanner.scan_content("CUSTOM_MARKER ONE_MARKER TWO_MARKER")
    assert {match["rule_name"] for match in matches} == {"custom_rule", "trusted_one", "trusted_two"}


def test_trusted_yara_manifest_category_and_severity_are_authoritative(tmp_path: Path) -> None:
    pack = _write_trusted_yara_pack(tmp_path / "trusted-pack", "trusted-pack", "trusted_rule", "MARKER")
    manifest_path = pack / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["rules"]["YARA_trusted_rule"]["category"] = "data_exfiltration"
    manifest["rules"]["YARA_trusted_rule"]["severity"] = "critical"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    analyzer = StaticAnalyzer(trusted_pack_dirs=[pack])

    assert analyzer.yara_scanner is not None
    match = next(
        match
        for match in analyzer.yara_scanner.scan_content("MARKER", "SKILL.md")
        if match["rule_name"] == "trusted_rule"
    )
    metadata = match["meta"]["meta"]
    assert metadata["category"] == "data_exfiltration"
    assert metadata["severity"] == "CRITICAL"
    assert analyzer._map_yara_rule_to_threat("trusted_rule", metadata) == (
        ThreatCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    )


def test_duplicate_rule_identifier_across_trusted_packs_fails_startup(tmp_path: Path) -> None:
    custom_dir = tmp_path / "custom"
    _write_yara_rule(custom_dir, "custom.yara", "custom_rule", "CUSTOM_MARKER")
    first_pack = _write_trusted_yara_pack(tmp_path / "first-pack", "first-pack", "duplicate", "ONE_MARKER")
    second_pack = _write_trusted_yara_pack(tmp_path / "second-pack", "second-pack", "duplicate", "TWO_MARKER")

    with pytest.raises(RuntimeError, match="Duplicate YARA rule identifier 'duplicate'"):
        StaticAnalyzer(
            custom_yara_rules_path=custom_dir,
            trusted_pack_dirs=[first_pack, second_pack],
        )


def test_legacy_custom_yara_compile_failure_remains_soft(tmp_path: Path) -> None:
    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    (custom_dir / "invalid.yara").write_text("rule invalid { condition: not valid !!! }", encoding="utf-8")

    analyzer = StaticAnalyzer(custom_yara_rules_path=custom_dir)

    assert analyzer.yara_scanner is None


def test_bundled_yara_compile_failure_is_not_silently_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_to_compile(*args, **kwargs):
        raise RuntimeError("broken bundled generation")

    monkeypatch.setattr("skill_scanner.core.analyzers.static.YaraScanner", fail_to_compile)

    with pytest.raises(RuntimeError, match="broken bundled generation"):
        StaticAnalyzer()


def test_correlation_analyzer_toggle_is_honored_at_factory_boundary() -> None:
    policy = ScanPolicy.default()
    policy.analyzers.static = False
    policy.analyzers.bytecode = False
    policy.analyzers.pipeline = False
    policy.analyzers.correlation = False

    assert build_core_analyzers(policy) == []

    policy.analyzers.correlation = True
    analyzers = build_core_analyzers(policy)

    assert [analyzer.get_name() for analyzer in analyzers] == ["correlation"]
    assert analyzers[0].policy is policy
