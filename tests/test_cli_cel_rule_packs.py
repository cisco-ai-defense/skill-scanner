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
    _STATUS_MESSAGE_MAX_CHARS,
    _build_analyzers,
    _create_skill_scanner,
    _load_policy,
    _make_status_printer,
    _redact_status_message,
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
    assert status_messages == ["Loaded trusted rule pack configuration"]


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
    assert "Successfully validated trusted rule pack configuration" in output


def test_trusted_rule_pack_status_does_not_echo_administrator_path(tmp_path: Path) -> None:
    secret = "credential-" + "value-123456789"
    trusted_pack = tmp_path / f"pack-password={secret}"
    trusted_pack.mkdir()
    args = Namespace(trusted_rule_pack=[str(trusted_pack)])
    status_messages: list[str] = []

    with (
        patch("skill_scanner.core.rule_registry.PackLoader.build_registry", return_value=MagicMock()),
        patch("skill_scanner.cli.cli.SkillScanner"),
    ):
        _create_skill_scanner([], ScanPolicy.default(), args, status_messages.append)

    combined = "\n".join(status_messages)
    assert combined == "Loaded trusted rule pack configuration"
    assert secret not in combined
    assert str(trusted_pack) not in combined


@pytest.mark.parametrize(
    "message",
    [
        "Using behavioral analyzer (static dataflow analysis)",
        "Using LLM analyzer with model: qwen3:8b",
        "Meta-analysis complete: 2 false positives removed, 5 findings retained",
    ],
)
def test_status_redaction_preserves_normal_messages(message: str) -> None:
    assert _redact_status_message(message) == message


def test_status_redaction_removes_common_secret_forms() -> None:
    labeled = "label-" + "secret-value-123456789"
    bearer = "bearer-" + "value-123456789"
    url_password = "url-" + "password-123456789"
    query_token = "query-" + "token-123456789"
    provider_token = "gh" + "p_" + "A" * 24
    jwt = ".".join(("eyJ" + "A" * 12, "B" * 12, "C" * 12))
    message = (
        f'api_key="{labeled}" Authorization: Bearer {bearer} '
        f"https://user:{url_password}@example.invalid/path?token={query_token} "
        f"provider={provider_token} jwt={jwt}"
    )

    redacted = _redact_status_message(message)

    for secret in (labeled, bearer, url_password, query_token, provider_token, jwt):
        assert secret not in redacted
    assert redacted.count("<redacted>") == 6
    assert 'api_key="<redacted>"' in redacted
    assert "https://user:<redacted>@example.invalid/path?token=<redacted>" in redacted


def test_status_redaction_handles_cli_env_labels_and_additional_token_forms() -> None:
    cli_key = "cli-" + "value-123456789"
    env_key = "env-" + "value-123456789"
    basic = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    token_userinfo = "token-userinfo-123456789"
    fragment_token = "fragment-token-123456789"
    providers = (
        "hf_" + "A" * 24,
        "glpat-" + "B" * 24,
        "npm_" + "C" * 24,
        "pypi-" + "D" * 24,
    )
    message = (
        f"vt_api_key={cli_key} SKILL_SCANNER_LLM_API_KEY='{env_key}' "
        f"Authorization: Basic {basic} https://{token_userinfo}@example.invalid/path"
        f"#token={fragment_token} {' '.join(providers)}"
    )

    redacted = _redact_status_message(message)

    for secret in (cli_key, env_key, basic, token_userinfo, fragment_token, *providers):
        assert secret not in redacted
    assert "vt_api_key=<redacted>" in redacted
    assert "SKILL_SCANNER_LLM_API_KEY='<redacted>'" in redacted
    assert "Authorization: Basic <redacted>" in redacted


def test_status_redaction_escapes_multiline_and_terminal_controls() -> None:
    message = "ordinary\nnext\r\x1b[31mred\x1b[0m"

    assert _redact_status_message(message) == r"ordinary\nnext\r\x1b[31mred\x1b[0m"


def test_status_redaction_keeps_escaped_output_bounded() -> None:
    message = "\x00" * _STATUS_MESSAGE_MAX_CHARS

    assert _redact_status_message(message) == "[status message omitted: exceeds safe length]"


def test_status_redaction_omits_oversized_message_without_partial_output() -> None:
    secret = "oversized-" + "secret-123456789"
    message = "x" * _STATUS_MESSAGE_MAX_CHARS + f" password={secret}"

    redacted = _redact_status_message(message)

    assert redacted == "[status message omitted: exceeds safe length]"
    assert secret not in redacted


def test_status_printer_redacts_before_writing_machine_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    opaque_value = "status-value-123456789"
    status = _make_status_printer(Namespace(format=["json"]))

    status(f"Connecting with auth_token={opaque_value}")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Connecting with auth_token=<redacted>\n"
    assert opaque_value not in captured.err


def test_validate_rules_reports_missing_trusted_pack(capsys: pytest.CaptureFixture[str]) -> None:
    missing = Path("/definitely/not/a/trusted-rule-pack")
    args = Namespace(rules_file=None, trusted_rule_pack=[str(missing)])

    exit_code = validate_rules_command(args)

    assert exit_code == 1
    stderr = capsys.readouterr().err
    assert "Error validating rules" in stderr
    assert str(missing) in stderr


def test_missing_trusted_pack_error_redacts_secret_path(capsys: pytest.CaptureFixture[str]) -> None:
    secret = "path-" + "secret-value-123456789"
    missing = Path(f"/definitely/not/a/pack-password={secret}")
    args = Namespace(rules_file=None, trusted_rule_pack=[str(missing)])

    exit_code = validate_rules_command(args)

    assert exit_code == 1
    stderr = capsys.readouterr().err
    assert "Error validating rules" in stderr
    assert secret not in stderr
    assert "password=<redacted>" in stderr


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
