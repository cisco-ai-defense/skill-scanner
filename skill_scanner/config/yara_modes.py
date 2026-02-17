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
YARA Mode Configuration System

Provides configurable detection modes to balance false positives vs true positives:
- STRICT: Maximum security, higher false positives acceptable
- BALANCED: Default mode, good tradeoff between FP and TP
- PERMISSIVE: Minimize false positives, may miss some threats
- CUSTOM: User-defined thresholds

Each mode configures:
- Rule-specific thresholds
- Post-processing filters
- Enabled/disabled rule sets
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class YaraMode(Enum):
    """YARA detection mode presets."""

    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"
    CUSTOM = "custom"


@dataclass
class UnicodeStegConfig:
    """Configuration for unicode steganography detection."""

    # Zero-width character thresholds
    zerowidth_threshold_with_decode: int = 50  # When dangerous code is present
    zerowidth_threshold_alone: int = 200  # Without dangerous code context

    # Enable/disable specific patterns
    detect_rtl_override: bool = True
    detect_ltl_override: bool = True
    detect_line_separators: bool = True
    detect_unicode_tags: bool = True
    detect_variation_selectors: bool = True


@dataclass
class CredentialHarvestingConfig:
    """Configuration for credential harvesting detection."""

    # Placeholder filtering
    filter_placeholder_patterns: bool = True

    # Specific API key patterns
    detect_ai_api_keys: bool = True
    detect_aws_keys: bool = True
    detect_ssh_keys: bool = True
    detect_env_exfiltration: bool = True


@dataclass
class ToolChainingConfig:
    """Configuration for tool chaining abuse detection."""

    # Post-filter settings
    filter_api_documentation: bool = True
    filter_generic_http_verbs: bool = True
    filter_email_field_mentions: bool = True

    # Pattern detection
    detect_read_send: bool = True
    detect_collect_exfil: bool = True
    detect_env_network: bool = True


@dataclass
class YaraModeConfig:
    """Complete YARA mode configuration."""

    mode: YaraMode = YaraMode.BALANCED
    description: str = ""

    # Rule-specific configs
    unicode_steg: UnicodeStegConfig = field(default_factory=UnicodeStegConfig)
    credential_harvesting: CredentialHarvestingConfig = field(default_factory=CredentialHarvestingConfig)
    tool_chaining: ToolChainingConfig = field(default_factory=ToolChainingConfig)

    # Global settings
    enabled_rules: set[str] = field(default_factory=set)  # Empty = all enabled
    disabled_rules: set[str] = field(default_factory=set)

    @classmethod
    def strict(cls) -> "YaraModeConfig":
        """
        STRICT mode: Maximum security, accept higher FP rate.

        Use when:
        - Scanning untrusted/external skills
        - Security audit requirements
        - Compliance scanning
        """
        return cls(
            mode=YaraMode.STRICT,
            description="Maximum security - flags more potential threats",
            unicode_steg=UnicodeStegConfig(
                zerowidth_threshold_with_decode=20,  # Lower threshold
                zerowidth_threshold_alone=100,
            ),
            credential_harvesting=CredentialHarvestingConfig(
                filter_placeholder_patterns=False,  # Don't filter - flag for review
            ),
            tool_chaining=ToolChainingConfig(
                filter_api_documentation=False,
                filter_generic_http_verbs=False,
            ),
        )

    @classmethod
    def balanced(cls) -> "YaraModeConfig":
        """
        BALANCED mode: Default - good tradeoff between FP and TP.

        Use when:
        - Regular skill scanning
        - CI/CD pipeline integration
        - Development workflow
        """
        return cls(
            mode=YaraMode.BALANCED,
            description="Balanced detection - default mode",
            unicode_steg=UnicodeStegConfig(
                zerowidth_threshold_with_decode=50,
                zerowidth_threshold_alone=200,
            ),
            credential_harvesting=CredentialHarvestingConfig(
                filter_placeholder_patterns=True,
            ),
            tool_chaining=ToolChainingConfig(
                filter_api_documentation=True,
                filter_generic_http_verbs=True,
                filter_email_field_mentions=True,
            ),
        )

    @classmethod
    def permissive(cls) -> "YaraModeConfig":
        """
        PERMISSIVE mode: Minimize false positives.

        Use when:
        - Scanning trusted/internal skills
        - High FP rate is disrupting workflow
        - Focus on critical threats only
        """
        return cls(
            mode=YaraMode.PERMISSIVE,
            description="Minimal false positives - may miss some threats",
            unicode_steg=UnicodeStegConfig(
                zerowidth_threshold_with_decode=100,  # Higher threshold
                zerowidth_threshold_alone=500,
                detect_line_separators=False,  # Common in some content
            ),
            credential_harvesting=CredentialHarvestingConfig(
                filter_placeholder_patterns=True,
            ),
            tool_chaining=ToolChainingConfig(
                filter_api_documentation=True,
                filter_generic_http_verbs=True,
                filter_email_field_mentions=True,
            ),
            # Disable noisier rules
            disabled_rules={
                "capability_inflation_generic",
                "indirect_prompt_injection_generic",
            },
        )

    @classmethod
    def custom(
        cls,
        unicode_steg: UnicodeStegConfig | None = None,
        credential_harvesting: CredentialHarvestingConfig | None = None,
        tool_chaining: ToolChainingConfig | None = None,
        enabled_rules: set[str] | None = None,
        disabled_rules: set[str] | None = None,
    ) -> "YaraModeConfig":
        """
        CUSTOM mode: User-defined configuration.

        Args:
            unicode_steg: Unicode steganography config
            credential_harvesting: Credential harvesting config
            tool_chaining: Tool chaining config
            enabled_rules: Set of rule names to enable (empty = all)
            disabled_rules: Set of rule names to disable
        """
        return cls(
            mode=YaraMode.CUSTOM,
            description="Custom user-defined configuration",
            unicode_steg=unicode_steg or UnicodeStegConfig(),
            credential_harvesting=credential_harvesting or CredentialHarvestingConfig(),
            tool_chaining=tool_chaining or ToolChainingConfig(),
            enabled_rules=enabled_rules or set(),
            disabled_rules=disabled_rules or set(),
        )

    @classmethod
    def from_mode_name(cls, mode_name: str) -> "YaraModeConfig":
        """Create config from mode name string."""
        mode_map = {
            "strict": cls.strict,
            "balanced": cls.balanced,
            "permissive": cls.permissive,
        }
        if mode_name.lower() in mode_map:
            return mode_map[mode_name.lower()]()
        raise ValueError(f"Unknown mode: {mode_name}. Use: strict, balanced, permissive, or custom")

    def is_rule_enabled(self, rule_name: str) -> bool:
        """Check if a specific rule is enabled in this mode."""
        # If enabled_rules is specified, only those are allowed
        if self.enabled_rules and rule_name not in self.enabled_rules:
            return False
        # Check if explicitly disabled
        if rule_name in self.disabled_rules:
            return False
        return True

    def to_dict(self) -> dict:
        """Convert config to dictionary for serialization."""
        return {
            "mode": self.mode.value,
            "description": self.description,
            "unicode_steg": {
                "zerowidth_threshold_with_decode": self.unicode_steg.zerowidth_threshold_with_decode,
                "zerowidth_threshold_alone": self.unicode_steg.zerowidth_threshold_alone,
                "detect_rtl_override": self.unicode_steg.detect_rtl_override,
                "detect_ltl_override": self.unicode_steg.detect_ltl_override,
                "detect_line_separators": self.unicode_steg.detect_line_separators,
                "detect_unicode_tags": self.unicode_steg.detect_unicode_tags,
                "detect_variation_selectors": self.unicode_steg.detect_variation_selectors,
            },
            "credential_harvesting": {
                "filter_placeholder_patterns": self.credential_harvesting.filter_placeholder_patterns,
                "detect_ai_api_keys": self.credential_harvesting.detect_ai_api_keys,
                "detect_aws_keys": self.credential_harvesting.detect_aws_keys,
                "detect_ssh_keys": self.credential_harvesting.detect_ssh_keys,
                "detect_env_exfiltration": self.credential_harvesting.detect_env_exfiltration,
            },
            "tool_chaining": {
                "filter_api_documentation": self.tool_chaining.filter_api_documentation,
                "filter_generic_http_verbs": self.tool_chaining.filter_generic_http_verbs,
                "filter_email_field_mentions": self.tool_chaining.filter_email_field_mentions,
                "detect_read_send": self.tool_chaining.detect_read_send,
                "detect_collect_exfil": self.tool_chaining.detect_collect_exfil,
                "detect_env_network": self.tool_chaining.detect_env_network,
            },
            "enabled_rules": list(self.enabled_rules),
            "disabled_rules": list(self.disabled_rules),
        }


# Default mode
DEFAULT_YARA_MODE = YaraModeConfig.balanced()


# Mode descriptions for CLI/API documentation
MODE_DESCRIPTIONS = {
    "strict": """
STRICT Mode - Maximum Security
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Lower detection thresholds
• Minimal post-processing filters
• Flags more potential threats
• Higher false positive rate acceptable

Use for: Untrusted skills, security audits, compliance
""",
    "balanced": """
BALANCED Mode - Default
━━━━━━━━━━━━━━━━━━━━━━━
• Moderate detection thresholds
• Context-aware post-processing
• Good tradeoff between FP and TP
• Suitable for most use cases

Use for: Regular scanning, CI/CD, development
""",
    "permissive": """
PERMISSIVE Mode - Minimal False Positives
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Higher detection thresholds
• Aggressive filtering
• Focus on critical threats only
• May miss some edge-case threats

Use for: Trusted skills, high FP disruption
""",
}
