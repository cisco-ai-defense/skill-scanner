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

"""CLI coverage for the staged CEL and trusted local rule-pack surface."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, patch

import pytest

from skill_scanner.cli.cli import (
    _build_analyzers,
    _create_skill_scanner,
    _load_policy,
    build_parser,
    validate_rules_command,
)
from skill_scanner.core.cel.models import CelMode, CelRule
from skill_scanner.core.cel.runtime import CelRuntimeUnavailable
from skill_scanner.core.scan_policy import ScanPolicy


@pytest.mark.parametrize(
    ("command", "target"),
    [
        ("scan", "/tmp/skill"),
        ("scan-all", "/tmp/skills"),
        ("scan-repo", "owner/repository"),
    ],
)
def test_scan_commands_accept_cel_and_repeatable_trusted_pack_flags(command: str, target: str) -> None:
    args = build_parser().parse_args(
        [
            command,
            target,
            "--cel-mode",
            "shadow",
            "--trusted-rule-pack",
            "/tmp/pack-one",
            "--trusted-rule-pack",
            "/tmp/pack-two",
        ]
    )

    assert args.cel_mode == "shadow"
    assert args.trusted_rule_pack == ["/tmp/pack-one", "/tmp/pack-two"]


def test_cel_mode_flag_overrides_loaded_policy() -> None:
    args = Namespace(policy=None, cel_mode="enforce", verbose=True)

    policy = _load_policy(args)

    assert policy.cel.mode is CelMode.ENFORCE


def test_omitting_cel_mode_preserves_policy_value(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("cel:\n  mode: shadow\n", encoding="utf-8")
    args = Namespace(policy=str(policy_path), cel_mode=None, verbose=True)

    policy = _load_policy(args)

    assert policy.cel.mode is CelMode.SHADOW


def test_build_analyzers_forwards_trusted_pack_directories(tmp_path: Path) -> None:
    trusted_pack = tmp_path / "trusted-pack"
    trusted_pack.mkdir()
    args = Namespace(rule_packs=None, trusted_rule_pack=[str(trusted_pack)])

    with patch("skill_scanner.cli.cli.build_analyzers", return_value=[]) as factory:
        assert _build_analyzers(ScanPolicy.default(), args, lambda _message: None) == []

    assert factory.call_args.kwargs["trusted_pack_dirs"] == [trusted_pack]


def test_create_scanner_attaches_validated_registry(tmp_path: Path) -> None:
    trusted_pack = tmp_path / "trusted-pack"
    trusted_pack.mkdir()
    args = Namespace(trusted_rule_pack=[str(trusted_pack)])
    registry = MagicMock()
    status_messages: list[str] = []

    with (
        patch(
            "skill_scanner.core.rule_registry.PackLoader.build_registry",
            return_value=registry,
        ) as build_registry,
        patch("skill_scanner.cli.cli.SkillScanner") as scanner_class,
    ):
        scanner = _create_skill_scanner([], ScanPolicy.default(), args, status_messages.append)

    assert scanner is scanner_class.return_value
    build_registry.assert_called_once_with(trusted_dirs=[trusted_pack])
    scanner_class.assert_called_once_with(analyzers=[], policy=ANY, rule_registry=registry)
    assert status_messages == [f"Loaded trusted rule packs: {trusted_pack}"]


def test_create_scanner_loads_builtin_registry_for_active_cel_mode() -> None:
    args = Namespace(trusted_rule_pack=None)
    policy = ScanPolicy.default()
    policy.cel.mode = CelMode.SHADOW
    registry = MagicMock()

    with (
        patch(
            "skill_scanner.core.rule_registry.PackLoader.build_registry",
            return_value=registry,
        ) as build_registry,
        patch("skill_scanner.cli.cli.SkillScanner") as scanner_class,
    ):
        _create_skill_scanner([], policy, args, lambda _message: None)

    build_registry.assert_called_once_with(trusted_dirs=[])
    scanner_class.assert_called_once_with(analyzers=[], policy=policy, rule_registry=registry)


def test_create_scanner_validates_builtin_registry_when_cel_is_off() -> None:
    args = Namespace(trusted_rule_pack=None)
    policy = ScanPolicy.default()
    registry = MagicMock()

    with (
        patch(
            "skill_scanner.core.rule_registry.PackLoader.build_registry",
            return_value=registry,
        ) as build_registry,
        patch("skill_scanner.cli.cli.SkillScanner") as scanner_class,
    ):
        _create_skill_scanner([], policy, args, lambda _message: None)

    build_registry.assert_called_once_with(trusted_dirs=[])
    scanner_class.assert_called_once_with(analyzers=[], policy=policy, rule_registry=registry)


def test_validate_rules_validates_repeatable_trusted_packs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    args = Namespace(rules_file=None, trusted_rule_pack=[str(first), str(second)])

    registry = MagicMock()
    registry.__len__.return_value = 12
    registry.all_packs.return_value = {
        "core": SimpleNamespace(trusted=False),
        "first": SimpleNamespace(trusted=True),
        "second": SimpleNamespace(trusted=True),
    }
    signature_loader = MagicMock()
    signature_loader.load_rules.return_value = [object(), object()]
    signature_loader.rules_by_category = {}

    with (
        patch("skill_scanner.core.rule_registry.PackLoader.build_registry", return_value=registry) as build_registry,
        patch("skill_scanner.core.rules.patterns.RuleLoader", return_value=signature_loader),
    ):
        exit_code = validate_rules_command(args)

    assert exit_code == 0
    build_registry.assert_called_once_with(trusted_dirs=[first, second])
    output = capsys.readouterr().out
    assert "Successfully validated 12 manifest rules" in output
    assert "Successfully validated 2 trusted rule pack(s)" in output


def test_validate_rules_reports_missing_trusted_pack(capsys: pytest.CaptureFixture[str]) -> None:
    missing = Path("/definitely/not/a/trusted-rule-pack")
    args = Namespace(rules_file=None, trusted_rule_pack=[str(missing)])

    exit_code = validate_rules_command(args)

    assert exit_code == 1
    stderr = capsys.readouterr().err
    assert "Error validating rules" in stderr
    assert str(missing) in stderr


def test_validate_rules_fails_on_bundled_legacy_promotion_blocker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = Namespace(rules_file=None, trusted_rule_pack=None)
    report = SimpleNamespace(
        schema_status="legacy",
        signature_implementation_count=45,
        yara_implementation_count=18,
        promotion_blockers=(
            "manifest does not declare schema_version: 2",
            "78 rule(s) lack manifest category/severity (python=60, yara=18)",
        ),
    )
    registry = MagicMock()
    registry.__len__.return_value = 130
    registry.all_packs.return_value = {
        "core": SimpleNamespace(trusted=False, validation_report=report),
    }
    registry.all_rules.return_value = {}
    signature_loader = MagicMock()
    signature_loader.load_rules.return_value = []
    signature_loader.rules_by_category = {}

    with (
        patch("skill_scanner.core.rule_registry.PackLoader.build_registry", return_value=registry),
        patch("skill_scanner.core.rules.patterns.RuleLoader", return_value=signature_loader),
    ):
        exit_code = validate_rules_command(args)

    assert exit_code == 1
    captured = capsys.readouterr()
    output = captured.out
    assert "[LEGACY] Bundled pack 'core'" in output
    assert "validated exact identity and declared metadata for 63" in output
    assert "[PROMOTION BLOCKER] manifest does not declare schema_version: 2" in output
    assert "78 rule(s) lack manifest category/severity (python=60, yara=18)" in output
    assert "selected rule packs have unresolved promotion blockers" in captured.err


def _mock_validation_inputs() -> tuple[MagicMock, MagicMock, list[CelRule]]:
    cel_rules = [
        CelRule(rule_id="CEL_B", expression='f.candidate.rule_id == "CEL_B"', pack_name="core"),
        CelRule(rule_id="CEL_A", expression='f.candidate.rule_id == "CEL_A"', pack_name="core"),
    ]
    registry = MagicMock()
    registry.__len__.return_value = 2
    registry.all_packs.return_value = {"core": SimpleNamespace(trusted=False)}
    registry.all_rules.return_value = {rule.rule_id: SimpleNamespace(cel=rule) for rule in cel_rules}
    signature_loader = MagicMock()
    signature_loader.load_rules.return_value = []
    signature_loader.rules_by_category = {}
    return registry, signature_loader, cel_rules


def test_validate_rules_compiles_complete_generation_with_cel_go(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = Namespace(rules_file=None, trusted_rule_pack=None)
    registry, signature_loader, _ = _mock_validation_inputs()
    runtime_context = MagicMock()
    runtime_context.__enter__.return_value = SimpleNamespace(version="v0.32.0;helper=test")

    with (
        patch("skill_scanner.core.rule_registry.PackLoader.build_registry", return_value=registry),
        patch("skill_scanner.core.rules.patterns.RuleLoader", return_value=signature_loader),
        patch(
            "skill_scanner.core.cel.go_runtime.CelGoRuntime",
            return_value=runtime_context,
        ) as runtime_class,
    ):
        exit_code = validate_rules_command(args)

    assert exit_code == 0
    compiled_rules = runtime_class.call_args.args[0]
    assert [rule.rule_id for rule in compiled_rules] == ["CEL_A", "CEL_B"]
    runtime_context.__exit__.assert_called_once()
    output = capsys.readouterr().out
    assert "Bounded protobuf descriptor validation passed for 2 CEL expression(s)" in output
    assert "atomically type-checked 2 expression(s) with cel-go v0.32.0;helper=test" in output


def test_validate_rules_fails_when_cel_go_compilation_is_unavailable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = Namespace(rules_file=None, trusted_rule_pack=None)
    registry, signature_loader, _ = _mock_validation_inputs()

    with (
        patch("skill_scanner.core.rule_registry.PackLoader.build_registry", return_value=registry),
        patch("skill_scanner.core.rules.patterns.RuleLoader", return_value=signature_loader),
        patch(
            "skill_scanner.core.cel.go_runtime.CelGoRuntime",
            side_effect=CelRuntimeUnavailable("cel-go helper unavailable"),
        ),
    ):
        exit_code = validate_rules_command(args)

    assert exit_code == 1
    stderr = capsys.readouterr().err
    assert "Error validating rules: cel-go helper unavailable" in stderr
