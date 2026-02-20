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
Pattern matching utilities for security rules.
"""

import re
from pathlib import Path
from typing import Any

import yaml

from ...core.models import Severity, ThreatCategory


class SecurityRule:
    """Represents a security detection rule."""

    def __init__(self, rule_data: dict[str, Any]):
        self.id = rule_data["id"]
        self.category = ThreatCategory(rule_data["category"])
        self.severity = Severity(rule_data["severity"])
        self.patterns = rule_data["patterns"]
        self.exclude_patterns = rule_data.get("exclude_patterns", [])
        self.file_types = rule_data.get("file_types", [])
        self.description = rule_data["description"]
        self.remediation = rule_data.get("remediation", "")

        # Compile regex patterns
        self.compiled_patterns = []
        for pattern in self.patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                print(f"Warning: Failed to compile pattern '{pattern}' for rule {self.id}: {e}")

        # Compile exclude patterns
        self.compiled_exclude_patterns = []
        for pattern in self.exclude_patterns:
            try:
                self.compiled_exclude_patterns.append(re.compile(pattern))
            except re.error as e:
                print(f"Warning: Failed to compile exclude pattern '{pattern}' for rule {self.id}: {e}")

    def matches_file_type(self, file_type: str) -> bool:
        """Check if this rule applies to the given file type."""
        if not self.file_types:
            return True  # Rule applies to all file types
        return file_type in self.file_types

    def scan_content(self, content: str, file_path: str | None = None) -> list[dict[str, Any]]:
        """
        Scan content for rule violations.

        Returns:
            List of matches with line numbers and snippets
        """
        matches = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # Check exclude patterns first
            excluded = False
            for exclude_pattern in self.compiled_exclude_patterns:
                if exclude_pattern.search(line):
                    excluded = True
                    break

            if excluded:
                continue

            for pattern in self.compiled_patterns:
                match = pattern.search(line)
                if match:
                    matches.append(
                        {
                            "line_number": line_num,
                            "line_content": line.strip(),
                            "matched_pattern": pattern.pattern,
                            "matched_text": match.group(0),
                            "file_path": file_path,
                        }
                    )

        return matches


class RuleLoader:
    """Loads security rules from YAML files."""

    def __init__(self, rules_file: Path | None = None):
        """
        Initialize rule loader.

        Args:
            rules_file: Path to rules YAML file. If None, uses default.
        """
        if rules_file is None:
            # Default to signatures.yaml in data/rules directory
            from ...data import DATA_DIR

            rules_file = DATA_DIR / "rules" / "signatures.yaml"

        self.rules_file = rules_file
        self.rules: list[SecurityRule] = []
        self.rules_by_id: dict[str, SecurityRule] = {}
        self.rules_by_category: dict[ThreatCategory, list[SecurityRule]] = {}

    def load_rules(self) -> list[SecurityRule]:
        """
        Load rules from YAML file.

        Returns:
            List of SecurityRule objects
        """
        try:
            with open(self.rules_file, encoding="utf-8") as f:
                rules_data = yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load rules from {self.rules_file}: {e}")

        self.rules = []
        self.rules_by_id = {}
        self.rules_by_category = {}

        for rule_data in rules_data:
            try:
                rule = SecurityRule(rule_data)
                self.rules.append(rule)
                self.rules_by_id[rule.id] = rule

                # Group by category
                if rule.category not in self.rules_by_category:
                    self.rules_by_category[rule.category] = []
                self.rules_by_category[rule.category].append(rule)
            except Exception as e:
                print(f"Warning: Failed to load rule {rule_data.get('id', 'unknown')}: {e}")

        return self.rules

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        """Get a specific rule by ID."""
        return self.rules_by_id.get(rule_id)

    def get_rules_for_file_type(self, file_type: str) -> list[SecurityRule]:
        """Get all rules that apply to a specific file type."""
        return [rule for rule in self.rules if rule.matches_file_type(file_type)]

    def get_rules_for_category(self, category: ThreatCategory) -> list[SecurityRule]:
        """Get all rules in a specific threat category."""
        return self.rules_by_category.get(category, [])
