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
YARA rule scanner for detecting malicious patterns in agent skills.
"""

from pathlib import Path
from typing import Any

import yara


class YaraScanner:
    """Scanner that uses YARA rules to detect malicious patterns."""

    def __init__(self, rules_dir: Path | None = None):
        """
        Initialize YARA scanner.

        Args:
            rules_dir: Path to directory containing .yara files
        """
        if rules_dir is None:
            # Default to yara_rules directory
            from ...data import YARA_RULES_DIR

            rules_dir = YARA_RULES_DIR

        self.rules_dir = Path(rules_dir)
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Load all YARA rules from directory."""
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"YARA rules directory not found: {self.rules_dir}")

        # Find all .yara files
        yara_files = list(self.rules_dir.glob("*.yara"))
        if not yara_files:
            raise FileNotFoundError(f"No .yara files found in {self.rules_dir}")

        # Compile all rules
        rules_dict = {}
        for yara_file in yara_files:
            namespace = yara_file.stem  # Use filename as namespace
            rules_dict[namespace] = str(yara_file)

        try:
            self.rules = yara.compile(filepaths=rules_dict)
        except yara.SyntaxError as e:
            raise RuntimeError(f"Failed to compile YARA rules: {e}")

    def scan_content(self, content: str, file_path: str | None = None) -> list[dict[str, Any]]:
        """
        Scan content with YARA rules.

        Args:
            content: Text content to scan
            file_path: Optional file path for context

        Returns:
            List of matches with metadata
        """
        if not self.rules:
            return []

        matches = []

        try:
            yara_matches = self.rules.match(data=content)

            for match in yara_matches:
                # Extract metadata from the rule
                meta = {
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                }

                # Find which strings matched and their locations
                matched_strings = []
                for string in match.strings:
                    for instance in string.instances:
                        # Find line number for this match
                        line_num = content[: instance.offset].count("\n") + 1
                        line_start = content.rfind("\n", 0, instance.offset) + 1
                        line_end = content.find("\n", instance.offset)
                        if line_end == -1:
                            line_end = len(content)
                        line_content = content[line_start:line_end].strip()

                        matched_strings.append(
                            {
                                "identifier": string.identifier,
                                "offset": instance.offset,
                                "matched_data": instance.matched_data.decode("utf-8", errors="ignore"),
                                "line_number": line_num,
                                "line_content": line_content,
                            }
                        )

                matches.append(
                    {
                        "rule_name": match.rule,
                        "namespace": match.namespace,
                        "file_path": file_path,
                        "meta": meta,
                        "strings": matched_strings,
                    }
                )

        except yara.Error as e:
            print(f"Warning: YARA scanning error: {e}")

        return matches

    def scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of matches
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            return self.scan_content(content, str(file_path))
        except (OSError, UnicodeDecodeError) as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            return []

    def get_loaded_rules(self) -> list[str]:
        """Get list of loaded rule names."""
        if not self.rules:
            return []
        # YARA doesn't provide easy access to rule names, return namespaces
        yara_files = list(self.rules_dir.glob("*.yara"))
        return [f.stem for f in yara_files]
