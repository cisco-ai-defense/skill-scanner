# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Tests for CLI, TUI, and API fixes.

Covers:
  11a. --llm-provider forwarding from CLI to build_analyzers
  11b. TUI _FIELD_MAP entries for exfil_hints, api_doc_tokens, dangerous_arg_patterns
  11c. --input flag for configure-policy
  11d. API llm_consensus_runs field
  11e. Policy knob tests for exfil_hints, api_doc_tokens, dangerous_arg_patterns
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from skill_scanner.core.scan_policy import ScanPolicy

# ===================================================================
# 11a — --llm-provider forwarding from CLI
# ===================================================================


class TestLLMProviderForwarding:
    """Verify that --llm-provider is passed from CLI to build_analyzers."""

    def test_llm_provider_passed_to_build_analyzers(self):
        """_build_analyzers in cli.py should pass llm_provider to build_analyzers."""
        from skill_scanner.cli.cli import _build_analyzers

        policy = ScanPolicy.default()
        args = argparse.Namespace(
            custom_rules=None,
            use_behavioral=False,
            use_llm=False,
            use_virustotal=False,
            vt_api_key=None,
            vt_upload_files=False,
            use_aidefense=False,
            aidefense_api_key=None,
            aidefense_api_url=None,
            use_trigger=False,
            llm_provider="openai",
            llm_consensus_runs=1,
        )

        with patch("skill_scanner.cli.cli.build_analyzers") as mock_build:
            mock_build.return_value = []
            _build_analyzers(policy, args, lambda s: None)

            mock_build.assert_called_once()
            call_kwargs = mock_build.call_args
            assert call_kwargs.kwargs.get("llm_provider") == "openai"

    def test_llm_provider_defaults_to_none_when_missing(self):
        """When --llm-provider is not in args, None should be passed."""
        from skill_scanner.cli.cli import _build_analyzers

        policy = ScanPolicy.default()
        # Namespace without llm_provider attribute
        args = argparse.Namespace(
            custom_rules=None,
            use_behavioral=False,
            use_llm=False,
            use_virustotal=False,
            vt_api_key=None,
            vt_upload_files=False,
            use_aidefense=False,
            aidefense_api_key=None,
            aidefense_api_url=None,
            use_trigger=False,
            llm_consensus_runs=1,
        )

        with patch("skill_scanner.cli.cli.build_analyzers") as mock_build:
            mock_build.return_value = []
            _build_analyzers(policy, args, lambda s: None)

            call_kwargs = mock_build.call_args
            assert call_kwargs.kwargs.get("llm_provider") is None

    def test_llm_max_tokens_passed_to_build_analyzers(self):
        """_build_analyzers should forward llm_max_tokens to build_analyzers."""
        from skill_scanner.cli.cli import _build_analyzers

        policy = ScanPolicy.default()
        args = argparse.Namespace(
            custom_rules=None,
            use_behavioral=False,
            use_llm=False,
            use_virustotal=False,
            vt_api_key=None,
            vt_upload_files=False,
            use_aidefense=False,
            aidefense_api_key=None,
            aidefense_api_url=None,
            use_trigger=False,
            llm_provider=None,
            llm_consensus_runs=1,
            llm_max_tokens=16384,
        )

        with patch("skill_scanner.cli.cli.build_analyzers") as mock_build:
            mock_build.return_value = []
            _build_analyzers(policy, args, lambda s: None)

            assert mock_build.call_args.kwargs.get("llm_max_tokens") == 16384

    def test_llm_max_tokens_defaults_to_none_when_missing(self):
        """When --llm-max-tokens is not in args, None should be passed."""
        from skill_scanner.cli.cli import _build_analyzers

        policy = ScanPolicy.default()
        args = argparse.Namespace(
            custom_rules=None,
            use_behavioral=False,
            use_llm=False,
            use_virustotal=False,
            vt_api_key=None,
            vt_upload_files=False,
            use_aidefense=False,
            aidefense_api_key=None,
            aidefense_api_url=None,
            use_trigger=False,
            llm_consensus_runs=1,
        )

        with patch("skill_scanner.cli.cli.build_analyzers") as mock_build:
            mock_build.return_value = []
            _build_analyzers(policy, args, lambda s: None)

            assert mock_build.call_args.kwargs.get("llm_max_tokens") is None


class TestMaxOutputTokensPolicy:
    """Verify max_output_tokens in scan policy and YAML round-trip."""

    def test_default_policy_has_max_output_tokens(self):
        """Default policy should set max_output_tokens to 8192."""
        policy = ScanPolicy.default()
        assert policy.llm_analysis.max_output_tokens == 8192

    def test_max_output_tokens_roundtrip_yaml(self, tmp_path):
        """max_output_tokens should survive YAML serialization round-trip."""
        policy = ScanPolicy.default()
        policy.llm_analysis.max_output_tokens = 32768

        yaml_path = tmp_path / "test_policy.yaml"
        policy.to_yaml(yaml_path)

        loaded = ScanPolicy.from_yaml(str(yaml_path))
        assert loaded.llm_analysis.max_output_tokens == 32768

    def test_max_output_tokens_in_to_dict(self):
        """_to_dict should include max_output_tokens."""
        policy = ScanPolicy.default()
        d = policy._to_dict()
        assert d["llm_analysis"]["max_output_tokens"] == 8192

    def test_presets_have_max_output_tokens(self):
        """All presets should have max_output_tokens set."""
        for preset in ("strict", "balanced", "permissive"):
            policy = ScanPolicy.from_preset(preset)
            assert policy.llm_analysis.max_output_tokens == 8192, f"{preset} preset missing max_output_tokens"

    def test_custom_yaml_overrides_max_output_tokens(self, tmp_path):
        """A user YAML with a custom max_output_tokens should override the default."""
        yaml_path = tmp_path / "custom.yaml"
        yaml_path.write_text("llm_analysis:\n  max_output_tokens: 16384\n")

        loaded = ScanPolicy.from_yaml(str(yaml_path))
        assert loaded.llm_analysis.max_output_tokens == 16384

    def test_cli_override_beats_policy_in_build_analyzers(self):
        """CLI llm_max_tokens should override the policy max_output_tokens."""
        from skill_scanner.core.analyzer_factory import build_analyzers

        policy = ScanPolicy.default()
        policy.llm_analysis.max_output_tokens = 4096

        with patch("skill_scanner.core.analyzers.llm_analyzer.LLMAnalyzer") as MockLLM:
            MockLLM.return_value = MagicMock()
            build_analyzers(
                policy=policy,
                use_llm=True,
                llm_max_tokens=32768,
            )
            call_kwargs = MockLLM.call_args.kwargs
            assert call_kwargs["max_tokens"] == 32768

    def test_policy_used_when_cli_is_none_in_build_analyzers(self):
        """When CLI llm_max_tokens is None, policy max_output_tokens should be used."""
        from skill_scanner.core.analyzer_factory import build_analyzers

        policy = ScanPolicy.default()
        policy.llm_analysis.max_output_tokens = 4096

        with patch("skill_scanner.core.analyzers.llm_analyzer.LLMAnalyzer") as MockLLM:
            MockLLM.return_value = MagicMock()
            build_analyzers(
                policy=policy,
                use_llm=True,
                llm_max_tokens=None,
            )
            call_kwargs = MockLLM.call_args.kwargs
            assert call_kwargs["max_tokens"] == 4096

    def test_meta_analyzer_receives_max_tokens_from_cli(self):
        """_build_meta_analyzer should forward max_tokens to MetaAnalyzer."""
        from skill_scanner.cli.cli import _build_meta_analyzer

        policy = ScanPolicy.default()
        args = argparse.Namespace(enable_meta=True)

        with patch("skill_scanner.cli.cli.MetaAnalyzer") as MockMeta:
            MockMeta.return_value = MagicMock()
            _build_meta_analyzer(args, 2, lambda s: None, policy=policy, max_tokens=16384)
            call_kwargs = MockMeta.call_args.kwargs
            assert call_kwargs["max_tokens"] == 16384

    def test_meta_analyzer_uses_policy_when_no_cli_override(self):
        """_build_meta_analyzer should use policy max_output_tokens when max_tokens is None."""
        from skill_scanner.cli.cli import _build_meta_analyzer

        policy = ScanPolicy.default()
        policy.llm_analysis.max_output_tokens = 4096
        args = argparse.Namespace(enable_meta=True)

        with patch("skill_scanner.cli.cli.MetaAnalyzer") as MockMeta:
            MockMeta.return_value = MagicMock()
            _build_meta_analyzer(args, 2, lambda s: None, policy=policy, max_tokens=None)
            call_kwargs = MockMeta.call_args.kwargs
            assert call_kwargs["max_tokens"] == 4096


# ===================================================================
# 11b — TUI _FIELD_MAP entries
# ===================================================================


class TestTUIFieldMap:
    """Verify the TUI's _FIELD_MAP contains new field entries."""

    @pytest.fixture
    def field_map(self):
        from skill_scanner.cli.policy_tui import PolicyConfigApp

        return PolicyConfigApp._FIELD_MAP

    def test_exfil_hints_in_field_map(self, field_map):
        """edit-exfil-hints should be mapped to pipeline.exfil_hints."""
        assert "edit-exfil-hints" in field_map
        path, title, as_list = field_map["edit-exfil-hints"]
        assert path == "pipeline.exfil_hints"
        assert as_list is True

    def test_api_doc_tokens_in_field_map(self, field_map):
        """edit-api-doc-tokens should be mapped to pipeline.api_doc_tokens."""
        assert "edit-api-doc-tokens" in field_map
        path, title, as_list = field_map["edit-api-doc-tokens"]
        assert path == "pipeline.api_doc_tokens"
        assert as_list is True

    def test_dangerous_arg_patterns_in_field_map(self, field_map):
        """edit-dangerous-arg-patterns should be mapped to command_safety.dangerous_arg_patterns."""
        assert "edit-dangerous-arg-patterns" in field_map
        path, title, as_list = field_map["edit-dangerous-arg-patterns"]
        assert path == "command_safety.dangerous_arg_patterns"
        assert as_list is True

    def test_field_map_get_set_roundtrip(self):
        """_get_field and _set_field should round-trip for the new fields."""
        from skill_scanner.cli.policy_tui import PolicyConfigApp

        app = PolicyConfigApp.__new__(PolicyConfigApp)
        app.policy = ScanPolicy.default()
        app.preset_name = "balanced"
        app._pending_field = None

        # Test exfil_hints round-trip
        original = app._get_field("pipeline.exfil_hints")
        assert isinstance(original, (list, set))
        assert len(original) > 0

        # Test api_doc_tokens round-trip
        tokens = app._get_field("pipeline.api_doc_tokens")
        assert isinstance(tokens, (list, set))
        assert len(tokens) > 0

        # Test dangerous_arg_patterns round-trip
        patterns = app._get_field("command_safety.dangerous_arg_patterns")
        assert isinstance(patterns, (list, set))
        assert len(patterns) > 0

        # Test set and get back
        new_val = ["new_val_1", "new_val_2"]
        app._set_field("pipeline.exfil_hints", new_val)
        result = app._get_field("pipeline.exfil_hints")
        assert "new_val_1" in result
        assert "new_val_2" in result


# ===================================================================
# 11c — --input flag for configure-policy
# ===================================================================


class TestConfigurePolicyInput:
    """Verify the --input flag for configure-policy."""

    def test_input_flag_registered(self):
        """configure-policy subparser should accept --input/-i."""
        result = subprocess.run(
            [sys.executable, "-m", "skill_scanner.cli.cli", "configure-policy", "--help"],
            capture_output=True,
            text=True,
        )
        assert "--input" in result.stdout or "-i" in result.stdout

    def test_run_policy_tui_accepts_input_path(self):
        """run_policy_tui should accept input_path parameter."""
        import inspect

        from skill_scanner.cli.policy_tui import run_policy_tui

        sig = inspect.signature(run_policy_tui)
        assert "input_path" in sig.parameters

    def test_policy_config_app_accepts_input_path(self):
        """PolicyConfigApp should accept input_path in __init__."""
        from skill_scanner.cli.policy_tui import PolicyConfigApp

        app = PolicyConfigApp(output_path="test.yaml", input_path="input.yaml")
        assert app.input_path == "input.yaml"

    def test_policy_config_app_loads_input(self, tmp_path):
        """PolicyConfigApp should load policy from input_path if it exists."""
        from skill_scanner.cli.policy_tui import PolicyConfigApp

        # Create a test policy YAML
        policy = ScanPolicy.from_preset("strict")
        policy_file = tmp_path / "test_input.yaml"
        policy.to_yaml(policy_file)

        app = PolicyConfigApp(
            output_path=str(tmp_path / "output.yaml"),
            input_path=str(policy_file),
        )
        assert app.input_path == str(policy_file)


# ===================================================================
# 11d — API llm_consensus_runs field
# ===================================================================

# Only run API tests if fastapi is available
try:
    from fastapi.testclient import TestClient

    from skill_scanner.api.api import app
    from skill_scanner.api.router import BatchScanRequest, ScanRequest

    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False
    ScanRequest = None
    BatchScanRequest = None


@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not available")
class TestAPIConsensusRuns:
    """Verify llm_consensus_runs in API models and router."""

    def test_scan_request_accepts_llm_consensus_runs(self):
        """ScanRequest should accept llm_consensus_runs field."""
        req = ScanRequest(
            skill_directory="/tmp/test",
            llm_consensus_runs=3,
        )
        assert req.llm_consensus_runs == 3

    def test_scan_request_defaults_to_1(self):
        """ScanRequest.llm_consensus_runs should default to 1."""
        req = ScanRequest(skill_directory="/tmp/test")
        assert req.llm_consensus_runs == 1

    def test_batch_scan_request_accepts_llm_consensus_runs(self):
        """BatchScanRequest should accept llm_consensus_runs field."""
        req = BatchScanRequest(
            skills_directory="/tmp/test",
            llm_consensus_runs=5,
        )
        assert req.llm_consensus_runs == 5

    def test_batch_scan_request_defaults_to_1(self):
        """BatchScanRequest.llm_consensus_runs should default to 1."""
        req = BatchScanRequest(skills_directory="/tmp/test")
        assert req.llm_consensus_runs == 1

    def test_build_analyzers_receives_consensus_runs(self):
        """_build_analyzers in router should pass llm_consensus_runs."""
        from skill_scanner.api.router import _build_analyzers

        policy = ScanPolicy.default()

        with patch("skill_scanner.api.router.build_analyzers") as mock_build:
            mock_build.return_value = []
            _build_analyzers(policy, llm_consensus_runs=3)

            call_kwargs = mock_build.call_args
            assert call_kwargs.kwargs.get("llm_consensus_runs") == 3


# ===================================================================
# 11e — Policy knob tests for new fields
# ===================================================================


class TestExfilHints:
    """Verify exfil_hints is correctly read from policy."""

    def test_default_policy_has_exfil_hints(self):
        """Default policy should have exfil_hints with expected values."""
        policy = ScanPolicy.default()
        hints = policy.pipeline.exfil_hints
        assert isinstance(hints, list)
        assert len(hints) > 0
        assert "send" in hints
        assert "upload" in hints

    def test_strict_policy_has_exfil_hints(self):
        """Strict policy should have exfil_hints."""
        policy = ScanPolicy.from_preset("strict")
        hints = policy.pipeline.exfil_hints
        assert isinstance(hints, list)
        assert len(hints) > 0

    def test_permissive_policy_has_exfil_hints(self):
        """Permissive policy should have exfil_hints."""
        policy = ScanPolicy.from_preset("permissive")
        hints = policy.pipeline.exfil_hints
        assert isinstance(hints, list)
        assert len(hints) > 0

    def test_exfil_hints_roundtrip_yaml(self, tmp_path):
        """exfil_hints should survive YAML serialization round-trip."""
        policy = ScanPolicy.default()
        policy.pipeline.exfil_hints = ["custom_hint_1", "custom_hint_2"]

        yaml_path = tmp_path / "test_policy.yaml"
        policy.to_yaml(yaml_path)

        loaded = ScanPolicy.from_yaml(str(yaml_path))
        assert "custom_hint_1" in loaded.pipeline.exfil_hints
        assert "custom_hint_2" in loaded.pipeline.exfil_hints


class TestApiDocTokens:
    """Verify api_doc_tokens is correctly read from policy."""

    def test_default_policy_has_api_doc_tokens(self):
        """Default policy should have api_doc_tokens with expected values."""
        policy = ScanPolicy.default()
        tokens = policy.pipeline.api_doc_tokens
        assert isinstance(tokens, list)
        assert len(tokens) > 0
        assert "@app." in tokens

    def test_strict_policy_has_api_doc_tokens(self):
        """Strict policy should have api_doc_tokens."""
        policy = ScanPolicy.from_preset("strict")
        tokens = policy.pipeline.api_doc_tokens
        assert isinstance(tokens, list)
        assert len(tokens) > 0

    def test_permissive_policy_has_api_doc_tokens(self):
        """Permissive policy should have api_doc_tokens."""
        policy = ScanPolicy.from_preset("permissive")
        tokens = policy.pipeline.api_doc_tokens
        assert isinstance(tokens, list)
        assert len(tokens) > 0

    def test_api_doc_tokens_roundtrip_yaml(self, tmp_path):
        """api_doc_tokens should survive YAML serialization round-trip."""
        policy = ScanPolicy.default()
        policy.pipeline.api_doc_tokens = ["custom_token"]

        yaml_path = tmp_path / "test_policy.yaml"
        policy.to_yaml(yaml_path)

        loaded = ScanPolicy.from_yaml(str(yaml_path))
        assert "custom_token" in loaded.pipeline.api_doc_tokens


class TestDangerousArgPatterns:
    """Verify dangerous_arg_patterns is correctly read from policy."""

    def test_default_policy_has_dangerous_arg_patterns(self):
        """Default policy should have dangerous_arg_patterns."""
        policy = ScanPolicy.default()
        patterns = policy.command_safety.dangerous_arg_patterns
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_strict_policy_has_more_patterns(self):
        """Strict policy should have more dangerous_arg_patterns than default."""
        default_policy = ScanPolicy.default()
        strict_policy = ScanPolicy.from_preset("strict")
        assert len(strict_policy.command_safety.dangerous_arg_patterns) >= len(
            default_policy.command_safety.dangerous_arg_patterns
        )

    def test_permissive_policy_has_fewer_patterns(self):
        """Permissive policy should have fewer dangerous_arg_patterns than default."""
        default_policy = ScanPolicy.default()
        permissive_policy = ScanPolicy.from_preset("permissive")
        assert len(permissive_policy.command_safety.dangerous_arg_patterns) <= len(
            default_policy.command_safety.dangerous_arg_patterns
        )

    def test_dangerous_arg_patterns_roundtrip_yaml(self, tmp_path):
        """dangerous_arg_patterns should survive YAML serialization round-trip."""
        policy = ScanPolicy.default()
        policy.command_safety.dangerous_arg_patterns = [r"\bcustom\s+pattern"]

        yaml_path = tmp_path / "test_policy.yaml"
        policy.to_yaml(yaml_path)

        loaded = ScanPolicy.from_yaml(str(yaml_path))
        assert r"\bcustom\s+pattern" in loaded.command_safety.dangerous_arg_patterns

    def test_python_inline_exec_pattern_present(self):
        """Default policy should have Python -c pattern."""
        policy = ScanPolicy.default()
        patterns = policy.command_safety.dangerous_arg_patterns
        assert any("python" in p and "-c" in p for p in patterns)


# ===================================================================
# CLI help text tests
# ===================================================================


class TestCLIHelpText:
    """Verify CLI help text improvements."""

    def test_detailed_help_mentions_markdown(self):
        """--detailed help should mention 'Markdown output only'."""
        result = subprocess.run(
            [sys.executable, "-m", "skill_scanner.cli.cli", "scan", "--help"],
            capture_output=True,
            text=True,
        )
        assert "Markdown" in result.stdout

    def test_rules_file_help_mentions_directory(self):
        """--rules-file help should mention 'directory'."""
        result = subprocess.run(
            [sys.executable, "-m", "skill_scanner.cli.cli", "validate-rules", "--help"],
            capture_output=True,
            text=True,
        )
        assert "directory" in result.stdout.lower()
