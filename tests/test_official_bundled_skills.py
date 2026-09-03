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

from __future__ import annotations

import json
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path

import pytest

from evals.datasets.official_bundled_skills import (
    OfficialBundleError,
    OfficialPackage,
    OfficialSource,
    build_lock,
    inventory_profile,
    load_and_verify_lock,
)
from evals.runners.official_bundled_skills_benchmark import (
    _accumulate_cel_per_rule,
    _cel_contract_errors,
    _cel_record,
    _compare_off_shadow,
    _run_one,
    _wilson,
    main,
)
from skill_scanner.core.cel.go_runtime import CEL_GO_VERSION
from skill_scanner.core.cel.models import CelMode
from skill_scanner.core.models import ScanResult


def _profile(root: Path, selector: dict[str, str]) -> dict[str, object]:
    return {
        "profile_version": 1,
        "observed_at": "2026-09-02",
        "purpose": "test-only inert first-party inventory",
        "safety": {
            "content_executed": False,
            "content_copied": False,
            "network_acquisition": False,
            "vendor_allowlists": False,
        },
        "sources": [
            {
                "id": "vendor/tool",
                "vendor": "Vendor",
                "tool": "Tool",
                "source_group": "vendor/tool",
                "root_locator": str(root),
                "observed_root": str(root.resolve()),
                "selector": selector,
                "provenance": {"revision": "test-revision", "license": "Apache-2.0"},
            }
        ],
    }


def _write_profile(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_skill(root: Path, relative: str, *, body: str = "Use this test skill.\n") -> Path:
    package = root / relative
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: inert fixture\n---\n\n" + body,
        encoding="utf-8",
    )
    return package


def test_recursive_inventory_lock_detects_content_drift(tmp_path: Path) -> None:
    root = tmp_path / "official"
    package = _write_skill(root, "one")
    profile_path = tmp_path / "profile.json"
    lock_path = tmp_path / "lock.json"
    _write_profile(profile_path, _profile(root, {"kind": "recursive_first_party"}))

    lock = build_lock(profile_path)
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    sources = load_and_verify_lock(lock_path, profile_path)
    assert len(sources) == 1
    assert len(sources[0].packages) == 1
    assert sources[0].packages[0].relative_path == "one"

    (package / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: inert fixture\n---\n\nChanged.\n",
        encoding="utf-8",
    )
    with pytest.raises(OfficialBundleError, match="differs from the immutable lock"):
        load_and_verify_lock(lock_path, profile_path)


def test_codex_selector_includes_only_exact_first_party_author(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    first = root / "first" / "1.0.0"
    third = root / "third" / "1.0.0"
    for plugin, author in ((first, "OpenAI"), (third, "Community")):
        (plugin / ".codex-plugin").mkdir(parents=True)
        (plugin / ".codex-plugin" / "plugin.json").write_text(
            json.dumps(
                {
                    "name": plugin.parent.name,
                    "version": "1.0.0",
                    "author": {"name": author},
                    "license": "MIT",
                    "skills": "./skills",
                }
            ),
            encoding="utf-8",
        )
        _write_skill(plugin, "skills/example")
    profile_path = tmp_path / "profile.json"
    _write_profile(
        profile_path,
        _profile(root, {"kind": "codex_plugin_author", "author": "OpenAI"}),
    )

    sources = inventory_profile(profile_path)
    assert [package.relative_path for package in sources[0].packages] == ["first/1.0.0/skills/example"]
    assert sources[0].packages[0].version == "1.0.0"
    assert sources[0].packages[0].license == "MIT"


def test_anthropic_selector_excludes_non_anthropic_and_remote_sources(tmp_path: Path) -> None:
    root = tmp_path / "marketplace"
    marketplace = root / ".claude-plugin" / "marketplace.json"
    marketplace.parent.mkdir(parents=True)
    marketplace.write_text(
        json.dumps(
            {
                "owner": {"name": "Anthropic"},
                "plugins": [
                    {
                        "name": "first",
                        "author": {"name": "Anthropic"},
                        "source": "./plugins/first",
                        "license": "MIT",
                    },
                    {
                        "name": "third",
                        "author": {"name": "Third Party"},
                        "source": "./plugins/third",
                    },
                    {
                        "name": "remote",
                        "author": {"name": "Anthropic"},
                        "source": {"source": "url", "url": "https://example.invalid/plugin"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    _write_skill(root, "plugins/first/skills/example")
    _write_skill(root, "plugins/third/skills/example")
    profile_path = tmp_path / "profile.json"
    _write_profile(
        profile_path,
        _profile(
            root,
            {
                "kind": "anthropic_marketplace_author",
                "author": "Anthropic",
                "marketplace_relative_path": ".claude-plugin/marketplace.json",
            },
        ),
    )

    sources = inventory_profile(profile_path)
    assert [package.relative_path for package in sources[0].packages] == ["plugins/first/skills/example"]


def test_anthropic_owned_repository_selects_all_local_plugins_only(tmp_path: Path) -> None:
    root = tmp_path / "owned-marketplace"
    marketplace = root / ".claude-plugin" / "marketplace.json"
    marketplace.parent.mkdir(parents=True)
    marketplace.write_text(
        json.dumps(
            {
                "owner": {"name": "Anthropic"},
                "plugins": [
                    {
                        "name": "employee-authored",
                        "author": {"name": "Employee", "email": "employee@anthropic.com"},
                        "source": "./plugins/employee-authored",
                    },
                    {
                        "name": "remote",
                        "author": {"name": "Anthropic"},
                        "source": {"source": "url", "url": "https://example.invalid/plugin"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    _write_skill(root, "plugins/employee-authored/skills/example")
    profile_path = tmp_path / "profile.json"
    _write_profile(
        profile_path,
        _profile(
            root,
            {
                "kind": "anthropic_owned_marketplace_all_local",
                "owner": "Anthropic",
                "marketplace_relative_path": ".claude-plugin/marketplace.json",
            },
        ),
    )

    sources = inventory_profile(profile_path)
    assert [package.relative_path for package in sources[0].packages] == ["plugins/employee-authored/skills/example"]


def test_package_symlink_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "official"
    package = _write_skill(root, "one")
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    (package / "linked.txt").symlink_to(target)
    profile_path = tmp_path / "profile.json"
    _write_profile(profile_path, _profile(root, {"kind": "recursive_first_party"}))

    with pytest.raises(OfficialBundleError, match="contains a symlink"):
        inventory_profile(profile_path)


def test_off_shadow_comparison_reports_exact_identity_deltas() -> None:
    finding = {
        "package_id": "vendor/tool:skill",
        "rule_id": "RULE",
        "category": "command_injection",
        "severity": "HIGH",
        "analyzer": "static",
        "path": "SKILL.md",
        "line": 9,
        "finding_id": "RULE:9",
    }
    base = {"medium_plus_findings": [finding], "load_errors": [], "cel": {"would_suppress": 0}}
    same = _compare_off_shadow(base, base)
    assert same["finding_identities_equal"] is True
    assert same["load_error_identities_equal"] is True

    changed = {"medium_plus_findings": [], "load_errors": [], "cel": {"would_suppress": 1}}
    delta = _compare_off_shadow(base, changed)
    assert delta["finding_identities_equal"] is False
    assert delta["removed_finding_identities"]
    assert delta["shadow_would_suppress"] == 1


def test_off_shadow_comparison_covers_all_severities_and_cel_generation() -> None:
    low = {
        "package_id": "vendor/tool:skill",
        "rule_id": "LOW_RULE",
        "category": "policy_violation",
        "severity": "LOW",
        "analyzer": "static",
        "path": "SKILL.md",
        "line": 2,
        "finding_id": "LOW_RULE:2",
    }
    identity = {
        "runtime": ["cel-go"],
        "runtime_version": [f"{CEL_GO_VERSION};helper=test"],
        "fact_schema": ["v1"],
        "expression_set_hash": ["a" * 64],
    }
    off = {
        "retained_findings": [low],
        "medium_plus_findings": [],
        "load_errors": [],
        "cel": {"identities": identity},
    }
    shadow = deepcopy(off)
    shadow["retained_findings"] = []
    shadow["cel"]["identities"]["expression_set_hash"] = ["b" * 64]

    comparison = _compare_off_shadow(off, shadow)

    assert comparison["finding_identities_equal"] is False
    assert comparison["removed_finding_identities"]
    assert comparison["cel_generation_identity_equal"] is False


def test_wilson_interval_is_bounded_and_non_degenerate() -> None:
    assert _wilson(0, 0) == [0.0, 0.0]
    lower, upper = _wilson(2, 10)
    assert 0.0 < lower < 0.2 < upper < 1.0


def test_cel_error_list_is_aggregated_by_stable_rule_and_code() -> None:
    result = ScanResult(
        skill_name="fixture",
        skill_directory="fixture",
        scan_metadata={
            "cel": {
                "errors": [
                    {"rule_id": "RULE", "code": "EVAL_ERROR"},
                    {"rule_id": "RULE", "code": "EVAL_ERROR"},
                    {"rule_id": "OTHER", "code": "TIMEOUT"},
                ]
            }
        },
    )

    assert _cel_record(result)["errors"] == {"OTHER:TIMEOUT": 1, "RULE:EVAL_ERROR": 2}
    assert _cel_record(ScanResult("fixture", "fixture", scan_metadata={"cel": {"errors": []}}))["errors"] == {}


def test_cel_per_rule_uses_runtime_decision_names() -> None:
    aggregate: dict[str, Counter[str]] = defaultdict(Counter)
    hashes: dict[str, set[str]] = defaultdict(set)

    _accumulate_cel_per_rule(
        aggregate,
        hashes,
        {
            "RULE": {
                "keep": 2,
                "would_suppress": 3,
                "fallback": 1,
                "suppressed": 0,
                "expression_hash": "sha256:test",
                # These invalid aliases must not double count decisions.
                "retained": 99,
                "fallbacks": 99,
            }
        },
    )

    assert dict(aggregate["RULE"]) == {
        "keep": 2,
        "would_suppress": 3,
        "fallback": 1,
        "suppressed": 0,
    }
    assert hashes == {"RULE": {"sha256:test"}}


def _valid_cel_result(mode: CelMode = CelMode.SHADOW) -> ScanResult:
    evaluated = 0 if mode is CelMode.OFF else 1
    per_rule = (
        {}
        if mode is CelMode.OFF
        else {
            "RULE": {
                "keep": 1,
                "would_suppress": 0,
                "fallback": 0,
                "suppressed": 0,
                "expression_hash": "b" * 64,
                "pack": "core",
                "rollout": "shadow",
            }
        }
    )
    return ScanResult(
        skill_name="fixture",
        skill_directory="fixture",
        scan_metadata={
            "cel": {
                "mode": mode.value,
                "runtime": "cel-go",
                "runtime_version": f"{CEL_GO_VERSION};helper=test-build",
                "fact_schema": "v1",
                "expression_set_hash": "a" * 64,
                "evaluated": evaluated,
                "retained": 1,
                "would_suppress": 0,
                "suppressed": 0,
                "fallbacks": 0,
                "projection_incomplete": 0,
                "elapsed_ms": 0.1,
                "projection_ms": 0.04,
                "evaluation_ms": 0.05,
                "errors": [],
                "per_rule": per_rule,
            }
        },
    )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("mode", "enforce", "MODE_MISMATCH"),
        ("runtime", "python", "RUNTIME_MISMATCH"),
        ("runtime_version", "v0.1.0", "RUNTIME_VERSION_INVALID"),
        ("fact_schema", "v2", "FACT_SCHEMA_MISMATCH"),
        ("expression_set_hash", "invalid", "GENERATION_INVALID"),
        ("fallbacks", 1, "FALLBACK_PRESENT"),
        ("projection_incomplete", 1, "PROJECTION_INCOMPLETE"),
    ),
)
def test_cel_contract_rejects_invalid_or_fail_open_evidence(field: str, value: object, expected: str) -> None:
    result = _valid_cel_result()
    assert result.scan_metadata is not None
    result.scan_metadata["cel"][field] = value

    assert expected in _cel_contract_errors(_cel_record(result), CelMode.SHADOW)


def test_cel_contract_rejects_runtime_evaluation_errors() -> None:
    result = _valid_cel_result()
    assert result.scan_metadata is not None
    result.scan_metadata["cel"]["errors"] = [{"rule_id": "RULE", "code": "EVALUATION_ERROR"}]

    assert "EVALUATION_ERRORS_PRESENT" in _cel_contract_errors(_cel_record(result), CelMode.SHADOW)


def _official_source(package_path: Path) -> OfficialSource:
    package = OfficialPackage(
        source_id="vendor/tool",
        vendor="Vendor",
        tool="Tool",
        relative_path="skill",
        absolute_path=package_path,
        tree_sha256="1" * 64,
        skill_sha256="2" * 64,
        file_count=1,
        total_bytes=1,
        version="test",
        license="MIT",
        provenance_manifest=None,
    )
    return OfficialSource(
        source_id="vendor/tool",
        vendor="Vendor",
        tool="Tool",
        source_group="vendor/tool",
        root=package_path.parent,
        root_locator=str(package_path.parent),
        selector={},
        provenance={},
        packages=(package,),
        inventory_sha256="3" * 64,
        file_count=1,
        total_bytes=1,
    )


def test_run_contract_fails_on_scanner_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenScanner:
        def scan_skill(self, _path: Path) -> ScanResult:
            raise RuntimeError("scanner failed")

    monkeypatch.setattr("evals.runners.official_bundled_skills_benchmark._scanner", lambda *_args: BrokenScanner())
    run = _run_one([_official_source(tmp_path / "skill")], "core_only", CelMode.OFF)

    assert run["contract_passed"] is False
    assert run["scanner_error_count"] == 1
    assert "SCANNER_FAILURES_PRESENT" in run["contract_errors"]


def test_run_contract_fails_on_loader_or_analyzer_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _valid_cel_result()
    result.analyzers_failed = [{"analyzer": "static", "error_type": "RuntimeError"}]
    assert result.scan_metadata is not None
    result.scan_metadata["loader"] = {"fallback_used": True, "strict_error_code": "MALFORMED_YAML_FRONTMATTER"}

    class PartialScanner:
        def scan_skill(self, _path: Path) -> ScanResult:
            return result

    monkeypatch.setattr("evals.runners.official_bundled_skills_benchmark._scanner", lambda *_args: PartialScanner())
    run = _run_one([_official_source(tmp_path / "skill")], "core_only", CelMode.SHADOW)

    assert run["contract_passed"] is False
    assert run["loader_failure_count"] == 1
    assert run["analyzer_partial_failure_count"] == 1
    assert {"LOADER_FAILURES_PRESENT", "ANALYZER_FAILURES_PRESENT"} <= set(run["contract_errors"])


def test_cli_writes_failed_contract_report_and_exits_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        "evals.runners.official_bundled_skills_benchmark.run_benchmark",
        lambda **_kwargs: {"contract_passed": False, "contract_checks": {"all_runs_complete_and_error_free": False}},
    )

    exit_code = main(["run", "--output", str(output)])

    assert exit_code == 2
    assert json.loads(output.read_text(encoding="utf-8"))["contract_passed"] is False
