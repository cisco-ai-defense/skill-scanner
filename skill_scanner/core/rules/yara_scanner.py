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
import re
from pathlib import Path
from typing import Any

import yara_x

logger = logging.getLogger(__name__)


_MAX_SCAN_FILE_SIZE = 50 * 1024 * 1024
_MAX_MATCHES_PER_PATTERN = 512
_NAMESPACE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_]+")


class YaraScanner:
    """Scanner that uses YARA rules to detect malicious patterns."""

    def __init__(
        self,
        rules_dir: Path | None = None,
        *,
        additional_rules_dirs: list[Path] | None = None,
        metadata_overrides: dict[str, dict[str, Any]] | None = None,
        max_scan_file_size: int = _MAX_SCAN_FILE_SIZE,
        max_matches_per_pattern: int = _MAX_MATCHES_PER_PATTERN,
    ):
        """
        Initialize YARA scanner.

        Args:
            rules_dir: Path to directory containing .yara files
            additional_rules_dirs: Additional directories compiled into the
                same atomic rules generation.  This is used for explicitly
                trusted rule packs; the primary directory remains the
                built-in or custom directory selected by ``rules_dir``.
            metadata_overrides: Manifest-authoritative metadata keyed by raw
                YARA identifier.  Overrides are accepted only for identifiers
                present in the compiled generation.
            max_scan_file_size: Maximum file size in bytes to scan (default 50 MB)
            max_matches_per_pattern: Maximum evidence occurrences retained for
                one YARA string. The rule still matches when the cap is reached.
        """
        if max_matches_per_pattern < 1:
            raise ValueError("max_matches_per_pattern must be at least 1")
        self.max_scan_file_size = max_scan_file_size
        self.max_matches_per_pattern = max_matches_per_pattern
        self._metadata_overrides = {
            identifier: dict(metadata) for identifier, metadata in (metadata_overrides or {}).items()
        }
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
        # ``rules_dir`` remains public for backwards compatibility.  The
        # ordered tuple is the complete generation used at runtime.
        self.rules_dirs = (self.rules_dir, *(Path(path) for path in additional_rules_dirs or []))
        self.rules: yara_x.Rules | None = None
        self._loaded_namespaces: list[str] = []
        self._load_rules()

    def _load_rules(self):
        """Load all selected YARA directories into one atomic generation."""
        sources: list[tuple[Path, str]] = []
        authoritative_namespaces: set[str] = set()
        multiple_directories = len(self.rules_dirs) > 1
        for directory_index, rules_dir in enumerate(self.rules_dirs):
            if not rules_dir.exists():
                raise FileNotFoundError(f"YARA rules directory not found: {rules_dir}")
            if not rules_dir.is_dir():
                raise NotADirectoryError(f"YARA rules path is not a directory: {rules_dir}")

            yara_files = sorted(rules_dir.glob("*.yara"), key=lambda path: path.name)
            if not yara_files:
                raise FileNotFoundError(f"No .yara files found in {rules_dir}")

            for file_index, yara_file in enumerate(yara_files):
                namespace = self._namespace_for_source(
                    rules_dir,
                    yara_file,
                    directory_index=directory_index,
                    file_index=file_index,
                    multiple_directories=multiple_directories,
                )
                sources.append((yara_file, namespace))
                if directory_index > 0 or (not multiple_directories and self._metadata_overrides):
                    authoritative_namespaces.add(namespace)

        # Compile all rules using the yara-x Compiler with namespaces
        # Rule sources are complete, immutable generation inputs.  YARA
        # ``include`` directives would allow a source to escape its validated
        # directory (including through an absolute path), while slow patterns
        # can turn package-controlled bytes into unbounded scan work.
        compiler = yara_x.Compiler(error_on_slow_pattern=True, includes_enabled=False)
        try:
            for yara_file, namespace in sources:
                compiler.new_namespace(namespace)
                source = yara_file.read_text(encoding="utf-8")
                compiler.add_source(source, origin=str(yara_file))
            rules = compiler.build()
        except yara_x.CompileError as e:
            raise RuntimeError(f"Failed to compile YARA rules: {e}") from e

        # YARA namespaces intentionally permit the same identifier in
        # different namespaces.  Skill Scanner's public finding identity does
        # not include that namespace (``YARA_<identifier>``), so accepting the
        # duplicate would make policy, suppression, and CEL gating ambiguous.
        seen_identifiers: dict[str, str] = {}
        populated_namespaces: set[str] = set()
        authoritative_identifiers: set[str] = set()
        for rule in rules:
            previous_namespace = seen_identifiers.get(rule.identifier)
            if previous_namespace is not None:
                raise RuntimeError(
                    "Duplicate YARA rule identifier "
                    f"'{rule.identifier}' in namespaces '{previous_namespace}' and '{rule.namespace}'"
                )
            seen_identifiers[rule.identifier] = rule.namespace
            populated_namespaces.add(rule.namespace)
            if rule.namespace in authoritative_namespaces:
                authoritative_identifiers.add(rule.identifier)

        empty_sources = [str(path) for path, namespace in sources if namespace not in populated_namespaces]
        if empty_sources:
            raise RuntimeError(f"YARA source file contains no rules: {', '.join(empty_sources)}")

        unknown_overrides = sorted(set(self._metadata_overrides) - set(seen_identifiers))
        if unknown_overrides:
            raise RuntimeError(
                "YARA metadata override(s) do not have compiled implementations: " + ", ".join(unknown_overrides)
            )

        if self._metadata_overrides:
            declared_identifiers = set(self._metadata_overrides)
            # Overrides may cover the primary bundled generation as well as
            # additional trusted namespaces. A declared override must exist
            # somewhere in the complete compiled generation.
            missing = sorted(declared_identifiers - set(seen_identifiers))
            unexpected = sorted(authoritative_identifiers - declared_identifiers)
            if missing or unexpected:
                details = []
                if missing:
                    details.append(f"missing: {', '.join(missing)}")
                if unexpected:
                    details.append(f"unexpected: {', '.join(unexpected)}")
                raise RuntimeError("Trusted YARA runtime implementation drift (" + "; ".join(details) + ")")

        # Publish only a completely compiled and identity-checked generation.
        self.rules = rules
        self._loaded_namespaces = [namespace for _, namespace in sources]

    @staticmethod
    def _namespace_for_source(
        rules_dir: Path,
        yara_file: Path,
        *,
        directory_index: int,
        file_index: int,
        multiple_directories: bool,
    ) -> str:
        """Return a deterministic, unique namespace for one source file.

        Preserve the historical filename-only namespace for the common
        single-directory case.  Multi-directory generations include the
        stable source ordinal and sanitized directory name so identically
        named files from separate trusted packs cannot collide.
        """
        if not multiple_directories:
            return yara_file.stem

        directory_name = _NAMESPACE_COMPONENT_RE.sub("_", rules_dir.name).strip("_") or "rules"
        file_name = _NAMESPACE_COMPONENT_RE.sub("_", yara_file.stem).strip("_") or "rules"
        return f"source_{directory_index:03d}_{directory_name}__{file_index:04d}_{file_name}"

    def _metadata_for_rule(self, rule: Any) -> dict[str, Any]:
        """Return compiled metadata with trusted manifest values applied."""

        metadata = dict(rule.metadata)
        metadata.update(self._metadata_overrides.get(rule.identifier, {}))
        return metadata

    def _new_scanner(self) -> yara_x.Scanner:
        """Build a per-scan YARA-X scanner with bounded match materialization."""

        if self.rules is None:  # pragma: no cover - guarded by public methods
            raise RuntimeError("YARA rules are not loaded")
        scanner = yara_x.Scanner(self.rules)
        scanner.max_matches_per_pattern(self.max_matches_per_pattern)
        return scanner

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
            if len(content_bytes) > self.max_scan_file_size:
                logger.warning(
                    "Skipping %s: encoded content size %d bytes exceeds scan limit",
                    file_path or "<memory>",
                    len(content_bytes),
                )
                return []
            scan_results = self._new_scanner().scan(content_bytes)

            for rule in scan_results.matching_rules:
                # Extract metadata from the rule
                # rule.metadata is a tuple of (key, value) pairs; convert to dict
                meta_dict = self._metadata_for_rule(rule)
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

        # Enforce the limit before attempting UTF-8 decoding.  Previously the
        # limit applied only after text decoding failed, so an arbitrarily
        # large valid-UTF-8 file could be read and scanned in full.
        try:
            file_size = Path(file_path).stat().st_size
        except OSError as e:
            logger.warning("Could not stat file %s: %s", file_path, e)
            return []
        if file_size > self.max_scan_file_size:
            logger.warning("Skipping %s: file size %d bytes exceeds scan limit", file_path, file_size)
            return []

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

        path = Path(file_path)
        try:
            file_size = path.stat().st_size
        except OSError as e:
            logger.warning("Could not stat file %s: %s", file_path, e)
            return []
        if file_size > self.max_scan_file_size:
            logger.warning("Skipping %s: file size %d bytes exceeds scan limit", file_path, file_size)
            return []

        matches = []
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            scan_results = self._new_scanner().scan(file_bytes)

            for rule in scan_results.matching_rules:
                meta_dict = self._metadata_for_rule(rule)
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
        """Get the deterministic namespaces in the compiled generation."""
        if not self.rules:
            return []
        return list(self._loaded_namespaces)
