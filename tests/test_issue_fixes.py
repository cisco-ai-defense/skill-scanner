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

"""
Tests for issue fixes: #41, #38, #29, #40.

- #41: MetaAnalyzer.analyze() emits a warning instead of silently returning []
- #38: LLMAnalyzer emits a failure finding and populates analyzers_failed
- #29: CLI supports multiple --format flags with per-format output files
- #40: Azure OpenAI Entra ID (DefaultAzureCredential) token fallback
"""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.models import Finding, ScanResult, Severity, ThreatCategory

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_finding(fid: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        id=fid,
        rule_id=f"RULE_{fid}",
        category=ThreatCategory.POLICY_VIOLATION,
        severity=severity,
        title=f"Finding {fid}",
        description=f"Description {fid}",
        analyzer="static",
    )


def _mk_mock_skill(name: str = "test-skill"):
    skill = MagicMock()
    skill.name = name
    skill.description = "Test skill"
    skill.instruction_body = "Do nothing harmful"
    skill.manifest = MagicMock()
    skill.manifest.name = name
    skill.manifest.description = "Test skill"
    skill.get_scripts = MagicMock(return_value=[])
    skill.referenced_files = []
    skill.files = []
    return skill


# ============================================================================
# Issue #41: MetaAnalyzer.analyze() warns instead of silent no-op
# ============================================================================


class TestMetaAnalyzerWarning:
    """MetaAnalyzer.analyze() must emit a warning when called directly."""

    def test_analyze_returns_empty_list(self):
        """analyze() still returns [] (backward compatible)."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

        meta = MetaAnalyzer(model="test-model", api_key="fake-key")
        skill = _mk_mock_skill()
        result = meta.analyze(skill)
        assert result == []

    def test_analyze_emits_warning_log(self, caplog):
        """analyze() must log a WARNING explaining the misuse."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

        meta = MetaAnalyzer(model="test-model", api_key="fake-key")
        skill = _mk_mock_skill("my-skill")

        with caplog.at_level(logging.WARNING):
            meta.analyze(skill)

        assert any("MetaAnalyzer.analyze() was called directly" in m for m in caplog.messages)
        assert any("my-skill" in m for m in caplog.messages)

    def test_scanner_warns_when_meta_in_analyzers_list(self, caplog):
        """SkillScanner.__init__ warns if MetaAnalyzer is in the analyzers list."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer
        from skill_scanner.core.analyzers.static import StaticAnalyzer
        from skill_scanner.core.scanner import SkillScanner

        static = StaticAnalyzer()
        meta = MetaAnalyzer(model="test-model", api_key="fake-key")

        with caplog.at_level(logging.WARNING):
            SkillScanner(analyzers=[static, meta])

        assert any("MetaAnalyzer was passed in the analyzers list" in m for m in caplog.messages)

    def test_scanner_no_warning_without_meta(self, caplog):
        """SkillScanner.__init__ does NOT warn when MetaAnalyzer is absent."""
        from skill_scanner.core.analyzers.static import StaticAnalyzer
        from skill_scanner.core.scanner import SkillScanner

        with caplog.at_level(logging.WARNING):
            SkillScanner(analyzers=[StaticAnalyzer()])

        assert not any("MetaAnalyzer" in m for m in caplog.messages)


# ============================================================================
# Issue #38: LLMAnalyzer failure finding + analyzers_failed field
# ============================================================================


class TestLLMAnalyzerFailureSignal:
    """LLM failures produce a machine-readable signal in the scan output."""

    def test_scan_result_has_analyzers_failed_field(self):
        """ScanResult exposes an analyzers_failed list."""
        result = ScanResult(skill_name="s", skill_directory="/tmp/s")
        assert result.analyzers_failed == []

    def test_analyzers_failed_appears_in_to_dict_when_populated(self):
        """to_dict() includes analyzers_failed when non-empty."""
        result = ScanResult(
            skill_name="s",
            skill_directory="/tmp/s",
            analyzers_failed=[{"analyzer": "llm_analyzer", "error": "boom"}],
        )
        payload = result.to_dict()
        assert "analyzers_failed" in payload
        assert payload["analyzers_failed"][0]["analyzer"] == "llm_analyzer"

    def test_analyzers_failed_absent_in_to_dict_when_empty(self):
        """to_dict() omits analyzers_failed when empty (backward compat)."""
        result = ScanResult(skill_name="s", skill_directory="/tmp/s")
        payload = result.to_dict()
        assert "analyzers_failed" not in payload

    @pytest.mark.asyncio
    async def test_llm_analyzer_emits_failure_finding_on_exception(self):
        """When the LLM call raises, analyze_async emits an INFO finding."""
        from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

        analyzer = LLMAnalyzer(api_key="test-key")
        skill = _mk_mock_skill()

        with patch.object(
            analyzer.request_handler,
            "make_request",
            new_callable=AsyncMock,
            side_effect=RuntimeError("connection refused"),
        ):
            findings = await analyzer.analyze_async(skill)

        failure_findings = [f for f in findings if f.rule_id == "LLM_ANALYSIS_FAILED"]
        assert len(failure_findings) == 1
        assert failure_findings[0].severity == Severity.INFO
        assert "connection refused" in failure_findings[0].description
        assert failure_findings[0].analyzer == "llm_analyzer"
        assert analyzer.last_error == "connection refused"

    @pytest.mark.asyncio
    async def test_llm_analyzer_clears_last_error_on_success(self):
        """last_error is None after a successful analysis."""
        from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

        analyzer = LLMAnalyzer(api_key="test-key")
        skill = _mk_mock_skill()

        with patch.object(
            analyzer.request_handler,
            "make_request",
            new_callable=AsyncMock,
            return_value=json.dumps({"findings": [], "overall_assessment": "Safe", "primary_threats": []}),
        ):
            await analyzer.analyze_async(skill)

        assert analyzer.last_error is None

    @pytest.mark.asyncio
    async def test_llm_failure_finding_metadata_contains_model(self):
        """The failure finding's metadata includes the model name."""
        from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

        analyzer = LLMAnalyzer(model="claude-3-5-sonnet-20241022", api_key="test-key")
        skill = _mk_mock_skill()

        with patch.object(
            analyzer.request_handler,
            "make_request",
            new_callable=AsyncMock,
            side_effect=ValueError("bad schema"),
        ):
            findings = await analyzer.analyze_async(skill)

        failure = [f for f in findings if f.rule_id == "LLM_ANALYSIS_FAILED"][0]
        assert "llm_model" in failure.metadata
        assert "error" in failure.metadata


# ============================================================================
# Issue #29: Multiple --format flags
# ============================================================================


class TestMultipleFormats:
    """CLI supports multiple --format flags and per-format output files."""

    def test_get_formats_returns_default_summary(self):
        """No --format → ['summary']."""
        from skill_scanner.cli.cli import _get_formats

        args = argparse.Namespace(format=None)
        assert _get_formats(args) == ["summary"]

    def test_get_formats_returns_single_format(self):
        """Single --format json → ['json']."""
        from skill_scanner.cli.cli import _get_formats

        args = argparse.Namespace(format=["json"])
        assert _get_formats(args) == ["json"]

    def test_get_formats_returns_multiple_formats(self):
        """Multiple --format flags → list of formats."""
        from skill_scanner.cli.cli import _get_formats

        args = argparse.Namespace(format=["markdown", "sarif", "json"])
        assert _get_formats(args) == ["markdown", "sarif", "json"]

    def test_format_single_json(self):
        """_format_single produces valid JSON for 'json'."""
        from skill_scanner.cli.cli import _format_single

        result = ScanResult(
            skill_name="s",
            skill_directory="/tmp/s",
            findings=[_mk_finding("1")],
        )
        args = argparse.Namespace(compact=False, detailed=False)
        output = _format_single("json", args, result)
        parsed = json.loads(output)
        assert parsed["skill_name"] == "s"

    def test_format_single_sarif(self):
        """_format_single produces valid SARIF JSON for 'sarif'."""
        from skill_scanner.cli.cli import _format_single

        result = ScanResult(
            skill_name="s",
            skill_directory="/tmp/s",
            findings=[_mk_finding("1")],
        )
        args = argparse.Namespace(compact=False, detailed=False)
        output = _format_single("sarif", args, result)
        parsed = json.loads(output)
        assert parsed.get("$schema") or parsed.get("version")

    def test_write_output_writes_additional_formats(self, tmp_path):
        """_write_output writes secondary formats to --output-<fmt> files."""
        from skill_scanner.cli.cli import _write_output

        result = ScanResult(
            skill_name="s",
            skill_directory="/tmp/s",
            findings=[_mk_finding("1")],
        )

        sarif_path = str(tmp_path / "report.sarif")
        args = argparse.Namespace(
            format=["json", "sarif"],
            output=None,
            output_json=None,
            output_sarif=sarif_path,
            output_markdown=None,
            output_html=None,
            output_table=None,
            compact=False,
            detailed=False,
            _result_or_report=result,
        )

        # Primary (json) goes to stdout; sarif goes to file
        from skill_scanner.cli.cli import _format_single

        primary_output = _format_single("json", args, result)
        _write_output(args, primary_output)

        assert Path(sarif_path).exists()
        sarif_content = json.loads(Path(sarif_path).read_text())
        assert sarif_content.get("$schema") or sarif_content.get("version")

    def test_cli_accepts_multiple_format_flags(self):
        """Argparse accepts --format json --format sarif without error."""
        from skill_scanner.cli.cli import main

        # We just verify the parser doesn't reject multiple --format flags.
        # We use a non-existent path so it fails at scan time, not parse time.
        cmd = [
            sys.executable,
            "-m",
            "skill_scanner.cli.cli",
            "scan",
            "/nonexistent",
            "--format",
            "json",
            "--format",
            "sarif",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        # Should fail because /nonexistent doesn't exist, NOT because of arg parsing
        assert "unrecognized arguments" not in result.stderr
        assert result.returncode != 0  # fails on missing dir, which is expected


# ============================================================================
# Issue #40: Azure OpenAI Entra ID authentication
# ============================================================================


class TestAzureEntraIdAuth:
    """Azure Entra ID token fallback in ProviderConfig."""

    def test_azure_detected_from_model_string(self):
        """Models starting with 'azure/' are detected as Azure."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        config = ProviderConfig(model="azure/gpt-4", api_key="explicit-key")
        assert config.is_azure

    def test_azure_uses_explicit_api_key_when_provided(self):
        """Explicit api_key takes precedence over Entra ID."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        config = ProviderConfig(model="azure/gpt-4", api_key="my-key")
        assert config.api_key == "my-key"
        assert not config._using_entra_id

    def test_azure_uses_env_key_when_set(self):
        """SKILL_SCANNER_LLM_API_KEY takes precedence over Entra ID."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        with patch.dict("os.environ", {"SKILL_SCANNER_LLM_API_KEY": "env-key"}, clear=False):
            config = ProviderConfig(model="azure/gpt-4")
            assert config.api_key == "env-key"
            assert not config._using_entra_id

    @patch("skill_scanner.core.analyzers.llm_provider_config.AZURE_IDENTITY_AVAILABLE", True)
    def test_azure_falls_back_to_entra_id_token(self):
        """When no API key is set, Azure falls back to Entra ID."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        mock_token = MagicMock()
        mock_token.token = "entra-id-bearer-token"

        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "skill_scanner.core.analyzers.llm_provider_config.DefaultAzureCredential", create=True
            ) as mock_cred_cls,
        ):
            # We need to mock the import inside _try_azure_entra_id_token
            with patch(
                "skill_scanner.core.analyzers.llm_provider_config.AZURE_IDENTITY_AVAILABLE",
                True,
            ):
                mock_cred = MagicMock()
                mock_cred.get_token.return_value = mock_token

                with patch.dict(
                    "sys.modules",
                    {"azure": MagicMock(), "azure.identity": MagicMock()},
                ):
                    with patch(
                        "skill_scanner.core.analyzers.llm_provider_config.ProviderConfig._try_azure_entra_id_token",
                        return_value="entra-id-bearer-token",
                    ):
                        config = ProviderConfig(model="azure/gpt-4")

        assert config.api_key == "entra-id-bearer-token"

    @patch("skill_scanner.core.analyzers.llm_provider_config.AZURE_IDENTITY_AVAILABLE", False)
    def test_azure_without_azure_identity_raises_on_validate(self):
        """Azure without API key or azure-identity raises ValueError on validate()."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        with patch.dict("os.environ", {}, clear=True):
            config = ProviderConfig(model="azure/gpt-4")
            assert config.api_key is None
            with pytest.raises(ValueError, match="No API key or Entra ID"):
                config.validate()

    def test_entra_id_token_passed_as_azure_ad_token(self):
        """When using Entra ID, get_request_params uses azure_ad_token (not api_key)."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        config = ProviderConfig(model="azure/gpt-4", api_key="token-value")
        config._using_entra_id = True

        params = config.get_request_params()
        assert "azure_ad_token" in params
        assert params["azure_ad_token"] == "token-value"
        assert "api_key" not in params

    def test_regular_api_key_passed_as_api_key(self):
        """When using a regular API key, get_request_params uses api_key."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        config = ProviderConfig(model="azure/gpt-4", api_key="regular-key")

        params = config.get_request_params()
        assert "api_key" in params
        assert params["api_key"] == "regular-key"
        assert "azure_ad_token" not in params

    def test_azure_validate_gives_helpful_error(self):
        """validate() error message mentions az login and skill-scanner[azure]."""
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig

        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "skill_scanner.core.analyzers.llm_provider_config.AZURE_IDENTITY_AVAILABLE",
                False,
            ),
        ):
            config = ProviderConfig(model="azure/gpt-4")
            with pytest.raises(ValueError, match="az login"):
                config.validate()
