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
Validate threats.py against Cisco AI Security Framework ground truth.

These tests ensure all AITech/AISubtech codes in threats.py exist in the
official taxonomy from https://learn-cloudsecurity.cisco.com/ai-security-framework

When these tests fail, it means threats.py contains codes that don't exist
in the official Cisco AI Security Framework. Fix by:
1. Correcting typos in the code
2. Using the correct code from cisco_ai_taxonomy.py
3. Or updating cisco_ai_taxonomy.py if the framework has been updated
"""

import json
import re
from pathlib import Path

import pytest

from skill_scanner.threats.cisco_ai_taxonomy import (
    VALID_AISUBTECH_CODES,
    VALID_AITECH_CODES,
    get_aisubtech_name,
    get_aitech_name,
)
from skill_scanner.threats.threats import ThreatMapping


class TestTaxonomyValidation:
    """Validate threats.py codes against Cisco AI Security Framework."""

    # Placeholder code for unclassified threats - skip validation
    PLACEHOLDER_CODE = "99.9"

    def _get_all_codes_from_threats(
        self,
    ) -> list[tuple[str, str, str | None, str | None]]:
        """Extract all AITech/AISubtech codes from threats.py.

        Returns:
            List of (dict_name, threat_name, aitech, aisubtech) tuples
        """
        results = []
        threat_dicts = [
            ("LLM_THREATS", ThreatMapping.LLM_THREATS),
            ("YARA_THREATS", ThreatMapping.YARA_THREATS),
            ("BEHAVIORAL_THREATS", ThreatMapping.BEHAVIORAL_THREATS),
        ]

        for dict_name, threats in threat_dicts:
            for threat_name, info in threats.items():
                results.append(
                    (
                        dict_name,
                        threat_name,
                        info.get("aitech"),
                        info.get("aisubtech"),
                    )
                )

        return results

    def test_all_aitech_codes_exist_in_taxonomy(self):
        """All AITech codes in threats.py must exist in official Cisco taxonomy."""
        invalid_codes = []

        for dict_name, threat_name, aitech, _ in self._get_all_codes_from_threats():
            if aitech and self.PLACEHOLDER_CODE not in aitech:
                if aitech not in VALID_AITECH_CODES:
                    invalid_codes.append(f"{dict_name}['{threat_name}']: '{aitech}' not in taxonomy")

        assert not invalid_codes, f"Found {len(invalid_codes)} invalid AITech code(s):\n" + "\n".join(
            f"  - {e}" for e in invalid_codes
        )

    def test_all_aisubtech_codes_exist_in_taxonomy(self):
        """All AISubtech codes in threats.py must exist in official Cisco taxonomy."""
        invalid_codes = []

        for dict_name, threat_name, _, aisubtech in self._get_all_codes_from_threats():
            if aisubtech and self.PLACEHOLDER_CODE not in aisubtech:
                if aisubtech not in VALID_AISUBTECH_CODES:
                    invalid_codes.append(f"{dict_name}['{threat_name}']: '{aisubtech}' not in taxonomy")

        assert not invalid_codes, f"Found {len(invalid_codes)} invalid AISubtech code(s):\n" + "\n".join(
            f"  - {e}" for e in invalid_codes
        )

    def test_taxonomy_names_match_codes(self):
        """AITech/AISubtech names in threats.py must match canonical taxonomy names."""
        mismatches = []

        for (
            dict_name,
            threat_name,
            aitech,
            aisubtech,
        ) in self._get_all_codes_from_threats():
            # Pull raw threat info for label comparison
            threat_dict = getattr(ThreatMapping, dict_name)
            info = threat_dict[threat_name]

            aitech_name = info.get("aitech_name")
            aisubtech_name = info.get("aisubtech_name")

            if aitech and self.PLACEHOLDER_CODE not in aitech:
                expected_aitech_name = get_aitech_name(aitech)
                if expected_aitech_name and aitech_name != expected_aitech_name:
                    mismatches.append(
                        f"{dict_name}['{threat_name}']: aitech_name '{aitech_name}' != '{expected_aitech_name}'"
                    )

            if aisubtech and self.PLACEHOLDER_CODE not in aisubtech:
                expected_aisubtech_name = get_aisubtech_name(aisubtech)
                if expected_aisubtech_name and aisubtech_name != expected_aisubtech_name:
                    mismatches.append(
                        f"{dict_name}['{threat_name}']: aisubtech_name '{aisubtech_name}' != '{expected_aisubtech_name}'"
                    )

        assert not mismatches, f"Found {len(mismatches)} taxonomy name mismatch(es):\n" + "\n".join(
            f"  - {e}" for e in mismatches
        )

    def test_aitech_code_format(self):
        """AITech codes must follow AITech-X.Y format."""
        pattern = re.compile(r"^AITech-\d+\.\d+$")
        invalid_format = []

        for dict_name, threat_name, aitech, _ in self._get_all_codes_from_threats():
            if aitech and not pattern.match(aitech):
                invalid_format.append(f"{dict_name}['{threat_name}']: '{aitech}' invalid format")

        assert not invalid_format, f"Found {len(invalid_format)} malformed AITech code(s):\n" + "\n".join(
            f"  - {e}" for e in invalid_format
        )

    def test_aisubtech_code_format(self):
        """AISubtech codes must follow AISubtech-X.Y.Z format."""
        pattern = re.compile(r"^AISubtech-\d+\.\d+\.\d+$")
        invalid_format = []

        for dict_name, threat_name, _, aisubtech in self._get_all_codes_from_threats():
            if aisubtech and not pattern.match(aisubtech):
                invalid_format.append(f"{dict_name}['{threat_name}']: '{aisubtech}' invalid format")

        assert not invalid_format, f"Found {len(invalid_format)} malformed AISubtech code(s):\n" + "\n".join(
            f"  - {e}" for e in invalid_format
        )

    def test_aisubtech_parent_matches_aitech(self):
        """AISubtech parent (X.Y) must match the AITech code."""
        mismatches = []

        for (
            dict_name,
            threat_name,
            aitech,
            aisubtech,
        ) in self._get_all_codes_from_threats():
            if aitech and aisubtech:
                if self.PLACEHOLDER_CODE in aitech or self.PLACEHOLDER_CODE in aisubtech:
                    continue

                # Extract parent from AISubtech-X.Y.Z -> X.Y
                aisubtech_parent = ".".join(aisubtech.replace("AISubtech-", "").split(".")[:2])
                aitech_suffix = aitech.replace("AITech-", "")

                if aisubtech_parent != aitech_suffix:
                    mismatches.append(f"{dict_name}['{threat_name}']: AITech={aitech} but AISubtech={aisubtech}")

        assert not mismatches, f"Found {len(mismatches)} AITech/AISubtech parent mismatch(es):\n" + "\n".join(
            f"  - {e}" for e in mismatches
        )


class TestTaxonomyCompleteness:
    """Test ground truth taxonomy file completeness."""

    def test_taxonomy_has_aitech_codes(self):
        """Ground truth must have AITech codes."""
        assert len(VALID_AITECH_CODES) > 0, "Taxonomy file has no AITech codes"
        assert len(VALID_AITECH_CODES) >= 40, "Expected at least 40 AITech codes"

    def test_taxonomy_has_aisubtech_codes(self):
        """Ground truth must have AISubtech codes."""
        assert len(VALID_AISUBTECH_CODES) > 0, "Taxonomy file has no AISubtech codes"
        assert len(VALID_AISUBTECH_CODES) >= 100, "Expected at least 100 AISubtech codes"

    def test_known_codes_present(self):
        """Spot-check that known codes are present."""
        # These are codes we know must exist
        assert "AITech-1.1" in VALID_AITECH_CODES, "Missing Direct Prompt Injection"
        assert "AITech-8.2" in VALID_AITECH_CODES, "Missing Data Exfiltration"
        assert "AITech-9.1" in VALID_AITECH_CODES, "Missing System Manipulation"
        assert "AITech-12.1" in VALID_AITECH_CODES, "Missing Tool Exploitation"
        assert "AITech-13.1" in VALID_AITECH_CODES, "Missing Disruption of Availability"
        assert "AISubtech-1.1.1" in VALID_AISUBTECH_CODES, "Missing Instruction Manipulation"
        assert "AISubtech-8.2.3" in VALID_AISUBTECH_CODES, "Missing Data Exfiltration via Agent Tooling"


class TestTaxonomyHelpers:
    """Test taxonomy helper functions."""

    def test_is_valid_aitech(self):
        """Test AITech validation helper."""
        from skill_scanner.threats.cisco_ai_taxonomy import is_valid_aitech

        assert is_valid_aitech("AITech-1.1") is True
        assert is_valid_aitech("AITech-99.99") is False
        assert is_valid_aitech("invalid") is False

    def test_is_valid_aisubtech(self):
        """Test AISubtech validation helper."""
        from skill_scanner.threats.cisco_ai_taxonomy import is_valid_aisubtech

        assert is_valid_aisubtech("AISubtech-1.1.1") is True
        assert is_valid_aisubtech("AISubtech-99.99.99") is False
        assert is_valid_aisubtech("invalid") is False

    def test_get_aitech_name(self):
        """Test AITech name lookup."""
        assert get_aitech_name("AITech-1.1") == "Direct Prompt Injection"
        assert get_aitech_name("AITech-8.2") == "Data Exfiltration / Exposure"
        assert get_aitech_name("AITech-99.99") is None

    def test_get_aisubtech_name(self):
        """Test AISubtech name lookup."""
        assert get_aisubtech_name("AISubtech-1.1.1") == "Instruction Manipulation (Direct Prompt Injection)"
        assert get_aisubtech_name("AISubtech-99.99.99") is None


class TestLLMAnalyzerTaxonomy:
    """Validate AITech codes in LLM analyzer and related files.

    These tests scan source files for AITech/AISubtech patterns and validate
    them against the official taxonomy. Files that don't exist are skipped.
    """

    # Regex patterns to find AITech/AISubtech codes in text
    AITECH_PATTERN = re.compile(r"AITech-\d+\.\d+")
    AISUBTECH_PATTERN = re.compile(r"AISubtech-\d+\.\d+\.\d+")

    # Files to scan (relative to project root)
    FILES_TO_SCAN = [
        "skill_scanner/core/analyzers/llm_analyzer.py",
        "skill_scanner/data/prompts/llm_response_schema.json",
        "skill_scanner/data/prompts/skill_meta_analysis_prompt.md",
        "skill_scanner/data/prompts/skill_threat_analysis_prompt.md",
    ]

    def _get_project_root(self) -> Path:
        """Get project root directory."""
        return Path(__file__).parent.parent

    def _extract_codes_from_file(self, filepath: Path) -> list[tuple[str, int, str]]:
        """Extract all AITech/AISubtech codes from a file.

        Returns:
            List of (code, line_number, line_content) tuples
        """
        if not filepath.exists():
            return []

        results = []
        content = filepath.read_text()

        for line_num, line in enumerate(content.splitlines(), start=1):
            # Find AITech codes
            for match in self.AITECH_PATTERN.finditer(line):
                results.append((match.group(), line_num, line.strip()[:80]))

            # Find AISubtech codes
            for match in self.AISUBTECH_PATTERN.finditer(line):
                results.append((match.group(), line_num, line.strip()[:80]))

        return results

    def test_llm_analyzer_aitech_codes_valid(self):
        """All AITech codes in LLM analyzer files must exist in taxonomy."""
        root = self._get_project_root()
        invalid_codes = []
        files_scanned = 0

        for file_path in self.FILES_TO_SCAN:
            full_path = root / file_path
            if not full_path.exists():
                continue

            files_scanned += 1
            codes = self._extract_codes_from_file(full_path)

            for code, line_num, _ in codes:
                if code.startswith("AITech-"):
                    if code not in VALID_AITECH_CODES:
                        invalid_codes.append(f"{file_path}:{line_num}: '{code}' not in taxonomy")
                elif code.startswith("AISubtech-"):
                    if code not in VALID_AISUBTECH_CODES:
                        invalid_codes.append(f"{file_path}:{line_num}: '{code}' not in taxonomy")

        # Skip test if no files found
        if files_scanned == 0:
            pytest.skip("No LLM analyzer files found to scan")

        assert not invalid_codes, (
            f"Found {len(invalid_codes)} invalid AITech/AISubtech code(s) in LLM files:\n"
            + "\n".join(f"  - {e}" for e in invalid_codes)
        )

    def test_llm_response_schema_enum_valid(self):
        """AITech enum in LLM response schema must only contain valid codes."""
        root = self._get_project_root()
        schema_path = root / "skill_scanner/data/prompts/llm_response_schema.json"

        if not schema_path.exists():
            pytest.skip("LLM response schema not found")

        schema = json.loads(schema_path.read_text())
        invalid_codes = []

        # Navigate to aitech enum in schema
        # Schema structure: properties -> findings -> items -> properties -> aitech -> enum
        try:
            aitech_enum = (
                schema.get("properties", {})
                .get("findings", {})
                .get("items", {})
                .get("properties", {})
                .get("aitech", {})
                .get("enum", [])
            )

            for code in aitech_enum:
                if code not in VALID_AITECH_CODES:
                    invalid_codes.append(f"'{code}' in schema enum not in taxonomy")

        except (KeyError, TypeError):
            # Schema structure might be different, fall back to regex scan
            pass

        assert not invalid_codes, f"Found {len(invalid_codes)} invalid AITech code(s) in schema enum:\n" + "\n".join(
            f"  - {e}" for e in invalid_codes
        )
