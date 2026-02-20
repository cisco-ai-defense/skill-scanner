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

"""Configuration parser for Skill Scanner.

This module provides functionality to parse configuration files
and environment variables for Skill Scanner.
"""

import os
from pathlib import Path

from ..utils.logging_config import get_logger
from .config import Config
from .constants import SkillScannerConstants

logger = get_logger(__name__)


def parse_config_from_env() -> Config:
    """Parse configuration from environment variables.

    Returns:
        Config instance with values from environment variables.
    """
    config = Config()

    # Parse LLM configuration - use SKILL_SCANNER_* env vars only
    config.llm_provider_api_key = os.getenv("SKILL_SCANNER_LLM_API_KEY")
    config.llm_model = os.getenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")

    # Parse analyzer flags
    if os.getenv("USE_LLM_ANALYZER", "").lower() == "true":
        config.enable_llm_analyzer = True
    if os.getenv("USE_BEHAVIORAL_ANALYZER", "").lower() == "true":
        config.enable_behavioral_analyzer = True

    # Parse output format
    output_format = os.getenv("OUTPUT_FORMAT", "summary").lower()
    if output_format in ["json", "markdown", "summary", "table"]:
        config.output_format = output_format

    # Parse verbosity
    if os.getenv("VERBOSE", "").lower() == "true":
        config.detailed_output = True

    return config


def parse_config_file(config_path: str | None = None) -> Config:
    """Parse configuration from a file.

    Args:
        config_path: Path to configuration file (optional).

    Returns:
        Config instance with values from file and environment.
    """
    config = parse_config_from_env()

    if not config_path:
        # Try to find default config file
        default_paths = [
            Path.home() / ".skill_scanner" / "config.yaml",
            Path.home() / ".skill_scanner" / "config.json",
            Path.cwd() / ".skill_scanner.yaml",
            Path.cwd() / ".skill_scanner.json",
        ]

        for path in default_paths:
            if path.exists():
                config_path = str(path)
                logger.debug(f"Found config file: {config_path}")
                break

    if config_path and Path(config_path).exists():
        # For now, we'll parse environment variables
        # In the future, this could parse YAML/JSON config files
        logger.debug(f"Loading config from: {config_path}")
        # TODO: Implement file parsing if needed

    return config


class ConfigParser:
    """Parser for Skill Scanner configuration files."""

    def __init__(self):
        """Initialize the config parser."""
        self.constants = SkillScannerConstants

    def parse(self, config_path: str | None = None) -> Config:
        """Parse configuration from file and environment.

        Args:
            config_path: Optional path to configuration file.

        Returns:
            Parsed Config instance.
        """
        return parse_config_file(config_path)

    def get_default_config(self) -> Config:
        """Get default configuration.

        Returns:
            Default Config instance.
        """
        return Config()
