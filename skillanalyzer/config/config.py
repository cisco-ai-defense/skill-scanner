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

"""
Configuration class for Skill Scanner.

Based on MCP Scanner's Config structure.
"""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """
    Configuration for Skill Scanner.

    Mirrors MCP Scanner's Config class structure.
    """

    # LLM Configuration
    llm_provider_api_key: str | None = None
    llm_model: str = "claude-3-5-sonnet-20241022"
    llm_base_url: str | None = None
    llm_api_version: str | None = None
    llm_max_tokens: int = 4000
    llm_temperature: float = 0.0
    llm_rate_limit_delay: float = 2.0
    llm_max_retries: int = 3
    llm_timeout: int = 120

    # AWS Bedrock Configuration
    aws_region_name: str = "us-east-1"
    aws_profile_name: str | None = None
    aws_session_token: str | None = None

    # Analyzer Configuration
    enable_static_analyzer: bool = True
    enable_llm_analyzer: bool = False
    enable_behavioral_analyzer: bool = False
    enable_aidefense: bool = False

    # VirusTotal Configuration
    virustotal_api_key: str | None = None
    virustotal_upload_files: bool = False

    # AI Defense Configuration
    aidefense_api_key: str | None = None

    # Scanning Options
    max_file_size_mb: int = 10
    scan_timeout_seconds: int = 300

    # Output Options
    output_format: str = "summary"
    detailed_output: bool = False

    def __post_init__(self):
        """Load configuration from environment variables if not provided."""

        # LLM API key from environment
        if self.llm_provider_api_key is None:
            self.llm_provider_api_key = os.getenv("SKILL_SCANNER_LLM_API_KEY")

        # LLM model from environment (only if still at default)
        if self.llm_model == "claude-3-5-sonnet-20241022":
            if env_model := os.getenv("SKILL_SCANNER_LLM_MODEL"):
                self.llm_model = env_model

        # AWS configuration from environment
        if env_region := os.getenv("AWS_REGION"):
            self.aws_region_name = env_region

        if env_profile := os.getenv("AWS_PROFILE"):
            self.aws_profile_name = env_profile

        if env_session := os.getenv("AWS_SESSION_TOKEN"):
            self.aws_session_token = env_session

        # Analyzer toggles from environment
        if os.getenv("ENABLE_STATIC_ANALYZER", "").lower() in ("false", "0"):
            self.enable_static_analyzer = False

        if os.getenv("ENABLE_LLM_ANALYZER", "").lower() in ("true", "1"):
            self.enable_llm_analyzer = True

        if os.getenv("ENABLE_BEHAVIORAL_ANALYZER", "").lower() in ("true", "1"):
            self.enable_behavioral_analyzer = True

        if os.getenv("ENABLE_AIDEFENSE", "").lower() in ("true", "1"):
            self.enable_aidefense = True

        # VirusTotal configuration from environment
        if self.virustotal_api_key is None:
            self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if os.getenv("VIRUSTOTAL_UPLOAD_FILES", "").lower() in ("true", "1"):
            self.virustotal_upload_files = True

        # AI Defense configuration from environment
        if self.aidefense_api_key is None:
            self.aidefense_api_key = os.getenv("AI_DEFENSE_API_KEY")

    @classmethod
    def from_env(cls) -> "Config":
        """
        Create configuration from environment variables.

        Returns:
            Config instance with values from environment
        """
        return cls()

    @classmethod
    def from_file(cls, config_file: Path) -> "Config":
        """
        Load configuration from .env file.

        Args:
            config_file: Path to .env file

        Returns:
            Config instance
        """
        # Load .env file
        if config_file.exists():
            with open(config_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip()

        return cls.from_env()
