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
Tests for threats taxonomy module.

Inspired by MCP Scanner's threat mapping tests.
"""

from unittest.mock import patch

import pytest

from skill_scanner.threats.threats import (
    BEHAVIORAL_THREAT_MAPPING,
    LLM_THREAT_MAPPING,
    YARA_THREAT_MAPPING,
    ThreatMapping,
    get_threat_category,
    get_threat_severity,
)


class TestThreatMappingStructure:
    """Test threat mapping data structure."""

    def test_llm_threats_defined(self):
        """Test that LLM threats are defined."""
        assert ThreatMapping.LLM_THREATS is not None
        assert len(ThreatMapping.LLM_THREATS) > 0

    def test_yara_threats_defined(self):
        """Test that YARA threats are defined."""
        assert ThreatMapping.YARA_THREATS is not None
        assert len(ThreatMapping.YARA_THREATS) > 0

    def test_behavioral_threats_defined(self):
        """Test that behavioral threats are defined."""
        assert ThreatMapping.BEHAVIORAL_THREATS is not None
        assert len(ThreatMapping.BEHAVIORAL_THREATS) > 0


class TestThreatMappingContent:
    """Test threat mapping content and structure."""

    def test_prompt_injection_mapping(self):
        """Test PROMPT INJECTION threat mapping."""
        threat = ThreatMapping.LLM_THREATS["PROMPT INJECTION"]

        assert threat["scanner_category"] == "PROMPT INJECTION"
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-1.1"
        assert threat["aitech_name"] == "Direct Prompt Injection"
        assert "aisubtech" in threat
        assert "description" in threat

    def test_data_exfiltration_mapping(self):
        """Test DATA EXFILTRATION threat mapping."""
        threat = ThreatMapping.LLM_THREATS["DATA EXFILTRATION"]

        assert threat["scanner_category"] == "SECURITY VIOLATION"
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-8.2"
        assert "Data Exfiltration" in threat["aitech_name"]

    def test_command_injection_mapping(self):
        """Test COMMAND INJECTION threat mapping."""
        threat = ThreatMapping.LLM_THREATS["COMMAND INJECTION"]

        assert threat["severity"] == "CRITICAL"
        assert threat["aitech"] == "AITech-9.1"
        assert "Injection" in threat["aisubtech_name"]

    def test_all_threats_have_required_fields(self):
        """Test that all threat definitions have required fields."""
        required_fields = [
            "scanner_category",
            "severity",
            "aitech",
            "aitech_name",
            "aisubtech",
            "aisubtech_name",
            "description",
        ]

        for analyzer_name, threats_dict in [
            ("LLM", ThreatMapping.LLM_THREATS),
            ("YARA", ThreatMapping.YARA_THREATS),
            ("BEHAVIORAL", ThreatMapping.BEHAVIORAL_THREATS),
        ]:
            for threat_name, threat_info in threats_dict.items():
                for field in required_fields:
                    assert field in threat_info, f"{analyzer_name} threat '{threat_name}' missing field '{field}'"


class TestGetThreatMapping:
    """Test get_threat_mapping method."""

    def test_get_llm_threat_mapping(self):
        """Test getting LLM threat mapping."""
        mapping = ThreatMapping.get_threat_mapping("llm", "PROMPT INJECTION")

        assert mapping is not None
        assert mapping["severity"] == "HIGH"
        assert mapping["aitech"] == "AITech-1.1"

    def test_get_yara_threat_mapping(self):
        """Test getting YARA threat mapping."""
        mapping = ThreatMapping.get_threat_mapping("yara", "CODE EXECUTION")

        assert mapping is not None
        assert "severity" in mapping
        assert "aitech" in mapping

    def test_get_behavioral_threat_mapping(self):
        """Test getting behavioral threat mapping."""
        mapping = ThreatMapping.get_threat_mapping("behavioral", "PROMPT INJECTION")

        assert mapping is not None
        assert mapping["severity"] == "HIGH"

    def test_get_static_threat_mapping(self):
        """Test getting static analyzer threat mapping (uses YARA taxonomy)."""
        mapping = ThreatMapping.get_threat_mapping("static", "INJECTION ATTACK")

        assert mapping is not None
        assert "severity" in mapping

    def test_unknown_analyzer_raises_error(self):
        """Test that unknown analyzer raises ValueError."""
        with pytest.raises(ValueError, match="Unknown analyzer"):
            ThreatMapping.get_threat_mapping("unknown_analyzer", "PROMPT INJECTION")

    def test_unknown_threat_returns_generic(self):
        """Test that unknown threat returns generic mapping."""
        mapping = ThreatMapping.get_threat_mapping("llm", "UNKNOWN_THREAT")

        # Should return generic mapping, not raise error
        assert mapping is not None
        assert mapping["scanner_category"] == "UNKNOWN"
        assert mapping["aitech"] == "AITech-99.9"


class TestSimplifiedMappings:
    """Test simplified mapping dictionaries."""

    def test_llm_threat_mapping_exists(self):
        """Test LLM_THREAT_MAPPING exists."""
        assert LLM_THREAT_MAPPING is not None
        assert len(LLM_THREAT_MAPPING) > 0

    def test_yara_threat_mapping_exists(self):
        """Test YARA_THREAT_MAPPING exists."""
        assert YARA_THREAT_MAPPING is not None
        assert len(YARA_THREAT_MAPPING) > 0

    def test_behavioral_threat_mapping_exists(self):
        """Test BEHAVIORAL_THREAT_MAPPING exists."""
        assert BEHAVIORAL_THREAT_MAPPING is not None
        assert len(BEHAVIORAL_THREAT_MAPPING) > 0

    def test_simplified_mapping_structure(self):
        """Test simplified mapping has correct structure."""
        for threat_name, threat_info in LLM_THREAT_MAPPING.items():
            assert "threat_category" in threat_info
            assert "threat_type" in threat_info
            assert "severity" in threat_info


class TestHelperFunctions:
    """Test helper functions for threat handling."""

    def test_get_threat_severity(self):
        """Test get_threat_severity function."""
        severity = get_threat_severity("llm", "PROMPT INJECTION")
        assert severity == "HIGH"

        severity = get_threat_severity("llm", "COMMAND INJECTION")
        assert severity == "CRITICAL"

    def test_get_threat_severity_unknown_returns_default(self):
        """Test that unknown threats return default severity."""
        severity = get_threat_severity("llm", "NONEXISTENT_THREAT")
        assert severity == "MEDIUM"  # Default

    def test_get_threat_category(self):
        """Test get_threat_category function."""
        category = get_threat_category("llm", "PROMPT INJECTION")
        assert category == "PROMPT INJECTION"

        category = get_threat_category("llm", "DATA EXFILTRATION")
        assert category == "SECURITY VIOLATION"

    def test_get_threat_category_unknown_returns_unknown(self):
        """Test that unknown threats return UNKNOWN category."""
        category = get_threat_category("llm", "NONEXISTENT_THREAT")
        assert category == "UNKNOWN"


class TestAITechTaxonomy:
    """Test AITech taxonomy codes."""

    def test_aitech_codes_format(self):
        """Test that AITech codes follow correct format."""
        for threats_dict in [ThreatMapping.LLM_THREATS, ThreatMapping.YARA_THREATS, ThreatMapping.BEHAVIORAL_THREATS]:
            for threat_name, threat_info in threats_dict.items():
                aitech = threat_info["aitech"]
                aisubtech = threat_info["aisubtech"]

                # Should follow AITech-X.Y format (allow None for new threats pending classification)
                if aitech is not None:
                    assert aitech.startswith("AITech-")
                    assert "." in aitech

                # Should follow AISubtech-X.Y.Z format (allow None for new threats)
                if aisubtech is not None:
                    assert aisubtech.startswith("AISubtech-")
                    assert aisubtech.count(".") >= 2

    def test_consistent_aitech_across_analyzers(self):
        """Test that same threat has consistent AITech code across analyzers."""
        # PROMPT INJECTION should have same AITech code everywhere
        llm_prompt = ThreatMapping.LLM_THREATS["PROMPT INJECTION"]
        yara_prompt = ThreatMapping.YARA_THREATS["PROMPT INJECTION"]
        behavioral_prompt = ThreatMapping.BEHAVIORAL_THREATS["PROMPT INJECTION"]

        assert llm_prompt["aitech"] == yara_prompt["aitech"] == behavioral_prompt["aitech"]
        assert llm_prompt["aitech"] == "AITech-1.1"


class TestSeverityLevels:
    """Test severity level consistency."""

    def test_valid_severity_levels(self):
        """Test that all severities use valid values."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        for threats_dict in [ThreatMapping.LLM_THREATS, ThreatMapping.YARA_THREATS, ThreatMapping.BEHAVIORAL_THREATS]:
            for threat_name, threat_info in threats_dict.items():
                assert threat_info["severity"] in valid_severities, (
                    f"Threat '{threat_name}' has invalid severity: {threat_info['severity']}"
                )

    def test_critical_threats_are_critical(self):
        """Test that command injection and data exfiltration are critical/high."""
        command_inj = ThreatMapping.LLM_THREATS["COMMAND INJECTION"]
        assert command_inj["severity"] in ["CRITICAL", "HIGH"]

        data_exfil = ThreatMapping.LLM_THREATS["DATA EXFILTRATION"]
        assert data_exfil["severity"] in ["CRITICAL", "HIGH"]
