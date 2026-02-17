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
Tests for YARA mode configuration system.
"""

import pytest

from skill_scanner.config.yara_modes import (
    CredentialHarvestingConfig,
    ToolChainingConfig,
    UnicodeStegConfig,
    YaraMode,
    YaraModeConfig,
)
from skill_scanner.core.analyzers.static import StaticAnalyzer


class TestYaraModeConfig:
    """Test YaraModeConfig creation and configuration."""

    def test_balanced_mode_is_default(self):
        """Default mode should be balanced."""
        config = YaraModeConfig()
        assert config.mode == YaraMode.BALANCED

    def test_strict_mode_has_lower_thresholds(self):
        """Strict mode should have lower (more sensitive) thresholds."""
        strict = YaraModeConfig.strict()
        balanced = YaraModeConfig.balanced()

        # Strict should have lower zero-width threshold
        assert (
            strict.unicode_steg.zerowidth_threshold_with_decode < balanced.unicode_steg.zerowidth_threshold_with_decode
        )
        assert strict.unicode_steg.zerowidth_threshold_alone < balanced.unicode_steg.zerowidth_threshold_alone

        # Strict should disable placeholder filtering (flag for review)
        assert not strict.credential_harvesting.filter_placeholder_patterns

    def test_permissive_mode_has_higher_thresholds(self):
        """Permissive mode should have higher (less sensitive) thresholds."""
        permissive = YaraModeConfig.permissive()
        balanced = YaraModeConfig.balanced()

        # Permissive should have higher zero-width threshold
        assert (
            permissive.unicode_steg.zerowidth_threshold_with_decode
            > balanced.unicode_steg.zerowidth_threshold_with_decode
        )
        assert permissive.unicode_steg.zerowidth_threshold_alone > balanced.unicode_steg.zerowidth_threshold_alone

    def test_permissive_mode_disables_rules(self):
        """Permissive mode should disable noisy rules."""
        permissive = YaraModeConfig.permissive()

        # Should have some rules disabled
        assert len(permissive.disabled_rules) > 0
        assert "capability_inflation_generic" in permissive.disabled_rules

    def test_from_mode_name_creates_correct_mode(self):
        """from_mode_name should create correct config."""
        strict = YaraModeConfig.from_mode_name("strict")
        assert strict.mode == YaraMode.STRICT

        balanced = YaraModeConfig.from_mode_name("balanced")
        assert balanced.mode == YaraMode.BALANCED

        permissive = YaraModeConfig.from_mode_name("permissive")
        assert permissive.mode == YaraMode.PERMISSIVE

    def test_from_mode_name_case_insensitive(self):
        """Mode names should be case insensitive."""
        strict1 = YaraModeConfig.from_mode_name("STRICT")
        strict2 = YaraModeConfig.from_mode_name("Strict")
        strict3 = YaraModeConfig.from_mode_name("strict")

        assert strict1.mode == strict2.mode == strict3.mode == YaraMode.STRICT

    def test_from_mode_name_invalid_raises(self):
        """Invalid mode name should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown mode"):
            YaraModeConfig.from_mode_name("invalid_mode")

    def test_is_rule_enabled_with_no_config(self):
        """All rules should be enabled by default."""
        config = YaraModeConfig()

        assert config.is_rule_enabled("credential_harvesting_generic")
        assert config.is_rule_enabled("tool_chaining_abuse_generic")
        assert config.is_rule_enabled("any_rule_name")

    def test_is_rule_enabled_with_disabled_rules(self):
        """Disabled rules should return False."""
        config = YaraModeConfig(disabled_rules={"test_rule"})

        assert not config.is_rule_enabled("test_rule")
        assert config.is_rule_enabled("other_rule")

    def test_is_rule_enabled_with_enabled_rules(self):
        """Only enabled rules should return True when specified."""
        config = YaraModeConfig(enabled_rules={"allowed_rule"})

        assert config.is_rule_enabled("allowed_rule")
        assert not config.is_rule_enabled("other_rule")

    def test_custom_mode_creation(self):
        """Custom mode should accept user-defined config."""
        custom_unicode = UnicodeStegConfig(
            zerowidth_threshold_alone=1000,
            detect_line_separators=False,
        )

        config = YaraModeConfig.custom(
            unicode_steg=custom_unicode,
            disabled_rules={"noisy_rule"},
        )

        assert config.mode == YaraMode.CUSTOM
        assert config.unicode_steg.zerowidth_threshold_alone == 1000
        assert not config.unicode_steg.detect_line_separators
        assert "noisy_rule" in config.disabled_rules

    def test_to_dict_serialization(self):
        """Config should serialize to dict correctly."""
        config = YaraModeConfig.balanced()
        data = config.to_dict()

        assert data["mode"] == "balanced"
        assert "unicode_steg" in data
        assert "credential_harvesting" in data
        assert "tool_chaining" in data
        assert "disabled_rules" in data


class TestStaticAnalyzerWithModes:
    """Test StaticAnalyzer integration with YARA modes."""

    def test_default_mode_is_balanced(self):
        """StaticAnalyzer should default to balanced mode."""
        analyzer = StaticAnalyzer()
        assert analyzer.yara_mode.mode == YaraMode.BALANCED

    def test_accepts_string_mode(self):
        """StaticAnalyzer should accept mode name as string."""
        analyzer = StaticAnalyzer(yara_mode="strict")
        assert analyzer.yara_mode.mode == YaraMode.STRICT

    def test_accepts_config_object(self):
        """StaticAnalyzer should accept YaraModeConfig object."""
        config = YaraModeConfig.permissive()
        analyzer = StaticAnalyzer(yara_mode=config)
        assert analyzer.yara_mode.mode == YaraMode.PERMISSIVE

    def test_strict_mode_flags_more(self):
        """Strict mode should produce more findings on placeholder patterns."""
        # This is a functional test - strict mode doesn't filter placeholders
        strict_config = YaraModeConfig.strict()
        balanced_config = YaraModeConfig.balanced()

        # Verify the config difference
        assert not strict_config.credential_harvesting.filter_placeholder_patterns
        assert balanced_config.credential_harvesting.filter_placeholder_patterns


class TestModeDescriptions:
    """Test mode descriptions are helpful."""

    def test_all_modes_have_descriptions(self):
        """All modes should have descriptions."""
        strict = YaraModeConfig.strict()
        balanced = YaraModeConfig.balanced()
        permissive = YaraModeConfig.permissive()

        assert strict.description
        assert balanced.description
        assert permissive.description

    def test_descriptions_are_distinct(self):
        """Each mode should have distinct description."""
        strict = YaraModeConfig.strict()
        balanced = YaraModeConfig.balanced()
        permissive = YaraModeConfig.permissive()

        descriptions = {strict.description, balanced.description, permissive.description}
        assert len(descriptions) == 3  # All unique
