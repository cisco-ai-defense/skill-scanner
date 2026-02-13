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

import logging
from pathlib import Path
from typing import Any

import yara_x

logger = logging.getLogger(__name__)


class YaraScanner:
    """Scanner that uses YARA rules to detect malicious patterns."""

    def __init__(self, rules_dir: Path | None = None):
        """
        Initialize YARA scanner.

        Args:
            rules_dir: Path to directory containing .yara files
        """
        if rules_dir is None:
            from ...data import DATA_DIR

            # Prefer the pack-based yara/ directory (new layout)
            pack_yara = DATA_DIR / "packs" / "core" / "yara"
            if pack_yara.is_dir():
                rules_dir = pack_yara
            else:
                # Fallback for external/custom installs
                from ...data import YARA_RULES_DIR

                rules_dir = YARA_RULES_DIR

        self.rules_dir = Path(rules_dir)
        self.rules: yara_x.Rules | None = None
        self._load_rules()

    def _load_rules(self):
        """Load all YARA rules from directory."""
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"YARA rules directory not found: {self.rules_dir}")

        # Find all .yara files
        yara_files = list(self.rules_dir.glob("*.yara"))
        if not yara_files:
            raise FileNotFoundError(f"No .yara files found in {self.rules_dir}")

        # Compile all rules using the yara-x Compiler with namespaces
        compiler = yara_x.Compiler()
        try:
            for yara_file in yara_files:
                namespace = yara_file.stem  # Use filename as namespace
                compiler.new_namespace(namespace)
                source = yara_file.read_text(encoding="utf-8")
                compiler.add_source(source, origin=str(yara_file))
            self.rules = compiler.build()
        except yara_x.CompileError as e:
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
            # yara-x scans bytes, not str
            content_bytes = content.encode("utf-8")
            scan_results = self.rules.scan(content_bytes)

            for rule in scan_results.matching_rules:
                # Extract metadata from the rule
                # rule.metadata is a tuple of (key, value) pairs; convert to dict
                meta_dict = dict(rule.metadata)
                meta = {
                    "rule_name": rule.identifier,
                    "namespace": rule.namespace,
                    "tags": list(rule.tags),
                    "meta": meta_dict,
                }

                # Find which patterns matched and their locations
                matched_strings = []
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        # Extract matched data from content bytes
                        matched_data_bytes = content_bytes[match.offset : match.offset + match.length]

                        # YARA-X reports offsets in bytes. Compute line/column using
                        # byte slices to avoid drift on multi-byte UTF-8 content.
                        line_num = content_bytes[: match.offset].count(b"\n") + 1
                        line_start = content_bytes.rfind(b"\n", 0, match.offset) + 1
                        line_end = content_bytes.find(b"\n", match.offset)
                        if line_end == -1:
                            line_end = len(content_bytes)
                        line_content = content_bytes[line_start:line_end].decode("utf-8", errors="ignore").strip()

                        matched_strings.append(
                            {
                                "identifier": pattern.identifier,
                                "offset": match.offset,
                                "matched_data": matched_data_bytes.decode("utf-8", errors="ignore"),
                                "line_number": line_num,
                                "line_content": line_content,
                            }
                        )

                matches.append(
                    {
                        "rule_name": rule.identifier,
                        "namespace": rule.namespace,
                        "file_path": file_path,
                        "meta": meta,
                        "strings": matched_strings,
                    }
                )

        except yara_x.ScanError as e:
            logger.warning("YARA scanning error: %s", e)

        return matches

    def scan_file(self, file_path: Path | str, display_path: str | None = None) -> list[dict[str, Any]]:
        """
        Scan a file with YARA rules.

        For text files the content is read as UTF-8 and delegated to
        :meth:`scan_content` so that line numbers are available in results.

        For binary files (those that cannot be decoded as UTF-8) the scanner
        falls back to YARA-X's native ``Scanner.scan_file(...)`` which works
        directly on raw bytes.

        Args:
            file_path: Path to file to scan (absolute or relative).
            display_path: Optional path to show in match results instead of
                *file_path* (e.g. a relative path for cleaner output).

        Returns:
            List of matches in the same format as :meth:`scan_content`.
        """
        file_path = str(file_path)
        context_path = display_path or file_path

        # Try text-mode first (gives line numbers via scan_content)
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            return self.scan_content(content, context_path)
        except UnicodeDecodeError:
            pass  # Fall through to binary scanning
        except OSError as e:
            logger.warning("Could not read file %s: %s", file_path, e)
            return []

        # Binary fallback — use YARA-X native file scanning
        return self._scan_file_binary(file_path, context_path)

    def _scan_file_binary(self, file_path: str, display_path: str) -> list[dict[str, Any]]:
        """Scan a binary file using YARA-X's Scanner.scan_file.

        Since the file is not valid UTF-8, line numbers are not meaningful.
        Matched data is decoded with ``errors="ignore"`` and offsets are
        reported as byte offsets.
        """
        if not self.rules:
            return []

        matches = []
        try:
            # Read raw bytes for matched_data extraction
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            scanner = yara_x.Scanner(self.rules)
            scan_results = scanner.scan(file_bytes)

            for rule in scan_results.matching_rules:
                meta_dict = dict(rule.metadata)
                meta = {
                    "rule_name": rule.identifier,
                    "namespace": rule.namespace,
                    "tags": list(rule.tags),
                    "meta": meta_dict,
                }

                matched_strings = []
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        matched_data_bytes = file_bytes[match.offset : match.offset + match.length]
                        matched_strings.append(
                            {
                                "identifier": pattern.identifier,
                                "offset": match.offset,
                                "matched_data": matched_data_bytes.decode("utf-8", errors="ignore"),
                                "line_number": 0,  # Not meaningful for binary
                                "line_content": f"[binary file at byte offset {match.offset}]",
                            }
                        )

                matches.append(
                    {
                        "rule_name": rule.identifier,
                        "namespace": rule.namespace,
                        "file_path": display_path,
                        "meta": meta,
                        "strings": matched_strings,
                    }
                )

        except yara_x.ScanError as e:
            logger.warning("YARA binary scanning error for %s: %s", file_path, e)

        return matches

    def get_loaded_rules(self) -> list[str]:
        """Get list of loaded rule names."""
        if not self.rules:
            return []
        # Return namespaces based on .yara filenames
        yara_files = list(self.rules_dir.glob("*.yara"))
        return [f.stem for f in yara_files]
