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
Tests for configuration module.

Inspired by MCP Scanner's test_config.py
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.config.config import Config
from skill_scanner.config.constants import SkillScannerConstants


class TestConfigInitialization:
    """Test Config class initialization."""

    def test_config_with_defaults(self):
        """Test config initialization with default values."""
        # Ensure SKILL_SCANNER_LLM_MODEL is not set to test true defaults

        env_without_llm = {k: v for k, v in os.environ.items() if not k.startswith("SKILL_SCANNER_LLM")}
        with patch.dict("os.environ", env_without_llm, clear=True):
            config = Config()

            assert config.llm_model == "claude-3-5-sonnet-20241022"
            assert config.llm_max_tokens == 4000
            assert config.llm_temperature == 0.0
            assert config.enable_static_analyzer

    def test_config_with_custom_values(self):
        """Test config with custom values."""
        config = Config(llm_model="gpt-4o", llm_max_tokens=8000, llm_temperature=0.5, enable_llm_analyzer=True)

        assert config.llm_model == "gpt-4o"
        assert config.llm_max_tokens == 8000
        assert config.llm_temperature == 0.5
        assert config.enable_llm_analyzer

    def test_config_from_env_variables(self):
        """Test config loading from environment variables."""
        with patch.dict(
            "os.environ",
            {
                "SKILL_SCANNER_LLM_API_KEY": "test-key-123",
                "SKILL_SCANNER_LLM_MODEL": "claude-3-opus-20240229",
                "AWS_REGION": "us-west-2",
                "ENABLE_LLM_ANALYZER": "true",
            },
        ):
            config = Config.from_env()

            assert config.llm_provider_api_key == "test-key-123"
            assert config.llm_model == "claude-3-opus-20240229"
            assert config.aws_region_name == "us-west-2"
            assert config.enable_llm_analyzer

    def test_config_api_key_uses_skill_scanner_env(self):
        """Test API key loading uses SKILL_SCANNER_LLM_API_KEY."""
        with patch.dict(
            "os.environ",
            {
                "SKILL_SCANNER_LLM_API_KEY": "scanner-key",
            },
        ):
            config = Config()

            # Should use SKILL_SCANNER_LLM_API_KEY
            assert config.llm_provider_api_key == "scanner-key"


class TestConfigAWS:
    """Test AWS-specific configuration."""

    def test_aws_region_configuration(self):
        """Test AWS region configuration."""
        config = Config(aws_region_name="eu-west-1")
        assert config.aws_region_name == "eu-west-1"

    def test_aws_profile_configuration(self):
        """Test AWS profile configuration."""
        config = Config(aws_profile_name="production")
        assert config.aws_profile_name == "production"

    def test_aws_session_token(self):
        """Test AWS session token configuration."""
        config = Config(aws_session_token="temp-session-token")
        assert config.aws_session_token == "temp-session-token"

    def test_aws_from_environment(self):
        """Test AWS config from environment variables."""
        with patch.dict(
            "os.environ", {"AWS_REGION": "ap-southeast-1", "AWS_PROFILE": "dev", "AWS_SESSION_TOKEN": "session-123"}
        ):
            config = Config.from_env()

            assert config.aws_region_name == "ap-southeast-1"
            assert config.aws_profile_name == "dev"
            assert config.aws_session_token == "session-123"


class TestConfigAnalyzerToggles:
    """Test analyzer enable/disable toggles."""

    def test_analyzer_defaults(self):
        """Test default analyzer states."""
        config = Config()

        assert config.enable_static_analyzer
        assert not config.enable_llm_analyzer
        assert not config.enable_behavioral_analyzer

    def test_enable_all_analyzers(self):
        """Test enabling all analyzers."""
        config = Config(enable_static_analyzer=True, enable_llm_analyzer=True, enable_behavioral_analyzer=True)

        assert config.enable_static_analyzer
        assert config.enable_llm_analyzer
        assert config.enable_behavioral_analyzer

    def test_analyzer_toggles_from_env(self):
        """Test analyzer toggles from environment."""
        with patch.dict(
            "os.environ",
            {"ENABLE_STATIC_ANALYZER": "false", "ENABLE_LLM_ANALYZER": "true", "ENABLE_BEHAVIORAL_ANALYZER": "1"},
        ):
            config = Config.from_env()

            assert not config.enable_static_analyzer
            assert config.enable_llm_analyzer
            assert config.enable_behavioral_analyzer


class TestConstants:
    """Test SkillScannerConstants."""

    def test_constants_paths_exist(self):
        """Test that constant paths are defined."""
        assert SkillScannerConstants.PROJECT_ROOT is not None
        assert SkillScannerConstants.PACKAGE_ROOT is not None
        assert SkillScannerConstants.PROMPTS_DIR is not None
        assert SkillScannerConstants.DATA_DIR is not None

    def test_get_prompts_path(self):
        """Test get_prompts_path method."""
        path = SkillScannerConstants.get_prompts_path()
        assert path is not None
        assert "prompts" in str(path)

    def test_get_data_path(self):
        """Test get_data_path method."""
        path = SkillScannerConstants.get_data_path()
        assert path is not None
        assert "data" in str(path)

    def test_get_yara_rules_path(self):
        """Test get_yara_rules_path method."""
        path = SkillScannerConstants.get_yara_rules_path()
        assert path is not None
        assert "yara_rules" in str(path)

    def test_severity_constants(self):
        """Test severity level constants."""
        assert SkillScannerConstants.SEVERITY_CRITICAL == "CRITICAL"
        assert SkillScannerConstants.SEVERITY_HIGH == "HIGH"
        assert SkillScannerConstants.SEVERITY_MEDIUM == "MEDIUM"
        assert SkillScannerConstants.SEVERITY_LOW == "LOW"

    def test_threat_category_constants(self):
        """Test threat category constants."""
        assert SkillScannerConstants.THREAT_PROMPT_INJECTION == "prompt_injection"
        assert SkillScannerConstants.THREAT_COMMAND_INJECTION == "command_injection"
        assert SkillScannerConstants.THREAT_DATA_EXFILTRATION == "data_exfiltration"


class TestConfigFromFile:
    """Test loading config from .env file."""

    def test_loads_from_env_file(self, tmp_path):
        """Test loading configuration from .env file."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            """
SKILL_SCANNER_LLM_API_KEY=test-key-from-file
SKILL_SCANNER_LLM_MODEL=claude-3-opus-20240229
AWS_REGION=eu-central-1
ENABLE_LLM_ANALYZER=true
        """
        )

        config = Config.from_file(env_file)

        assert config.llm_provider_api_key == "test-key-from-file"
        assert config.llm_model == "claude-3-opus-20240229"
        assert config.aws_region_name == "eu-central-1"
        assert config.enable_llm_analyzer

    def test_handles_nonexistent_env_file(self, tmp_path):
        """Test handling of nonexistent .env file."""
        nonexistent = tmp_path / "nonexistent.env"

        config = Config.from_file(nonexistent)

        # Should create config with defaults (or from existing env vars)
        assert config is not None
        assert config.llm_model is not None  # Will use default or env var
