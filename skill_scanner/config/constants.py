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
Constants for Skill Scanner.

Mirrors MCP Scanner's constants structure.
"""

from pathlib import Path


class SkillScannerConstants:
    """Constants used throughout the analyzer."""

    # Version
    VERSION = "0.2.0"

    # Project paths
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    PACKAGE_ROOT = Path(__file__).parent.parent

    # Resource paths
    DATA_DIR = PACKAGE_ROOT / "data"
    PROMPTS_DIR = DATA_DIR / "prompts"
    YARA_RULES_DIR = DATA_DIR / "yara_rules"
    RULES_DIR = PACKAGE_ROOT / "core" / "rules"

    # Default values
    DEFAULT_MAX_FILE_SIZE_MB = 10
    DEFAULT_SCAN_TIMEOUT = 300
    DEFAULT_LLM_MODEL = "claude-3-5-sonnet-20241022"
    DEFAULT_LLM_MAX_TOKENS = 4000
    DEFAULT_LLM_TEMPERATURE = 0.0

    # Severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"
    SEVERITY_SAFE = "SAFE"

    # Threat categories
    THREAT_PROMPT_INJECTION = "prompt_injection"
    THREAT_COMMAND_INJECTION = "command_injection"
    THREAT_DATA_EXFILTRATION = "data_exfiltration"
    THREAT_UNAUTHORIZED_TOOL = "unauthorized_tool_use"
    THREAT_OBFUSCATION = "obfuscation"
    THREAT_HARDCODED_SECRETS = "hardcoded_secrets"
    THREAT_SOCIAL_ENGINEERING = "social_engineering"
    THREAT_RESOURCE_ABUSE = "resource_abuse"

    @classmethod
    def get_prompts_path(cls) -> Path:
        """Get path to prompts directory."""
        return cls.PROMPTS_DIR

    @classmethod
    def get_rules_path(cls) -> Path:
        """Get path to rules directory."""
        return cls.RULES_DIR

    @classmethod
    def get_data_path(cls) -> Path:
        """Get path to data directory."""
        return cls.DATA_DIR

    @classmethod
    def get_yara_rules_path(cls) -> Path:
        """Get path to YARA rules directory."""
        return cls.YARA_RULES_DIR
