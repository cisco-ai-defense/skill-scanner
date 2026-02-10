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
Orchestrator for archive and compound document extraction.

Extracts contents from ZIP, TAR, DOCX, XLSX, etc. with safety limits
(depth, size, file count, zip bomb detection, path traversal prevention).
"""

import logging
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from ..models import Finding, Severity, SkillFile, ThreatCategory

logger = logging.getLogger(__name__)


@dataclass
class ExtractionLimits:
    """Safety limits for archive extraction."""

    max_depth: int = 3
    max_total_size_bytes: int = 50 * 1024 * 1024  # 50MB
    max_file_count: int = 500
    max_compression_ratio: float = 100.0  # Zip bomb threshold


@dataclass
class ExtractionResult:
    """Result of extracting an archive."""

    extracted_files: list[SkillFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_extracted_size: int = 0
    total_extracted_count: int = 0


class ContentExtractor:
    """
    Extracts content from archives and compound documents.

    Supports: ZIP, TAR (gz/bz2/xz), DOCX/XLSX/PPTX (Office Open XML),
    JAR/WAR/APK (ZIP-based).
    """

    # ZIP-based formats (all are actually ZIP archives)
    ZIP_EXTENSIONS = {".zip", ".jar", ".war", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
    TAR_EXTENSIONS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"}
    # Office Open XML formats (special handling for VBA/macros)
    OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx"}

    def __init__(self, limits: ExtractionLimits | None = None):
        self.limits = limits or ExtractionLimits()
        self._temp_dirs: list[str] = []

    def extract_skill_archives(self, skill_files: list[SkillFile]) -> ExtractionResult:
        """
        Extract all archives found in a skill package.

        Args:
            skill_files: List of skill files to check for archives

        Returns:
            ExtractionResult with extracted files and findings
        """
        result = ExtractionResult()

        for skill_file in skill_files:
            ext = skill_file.path.suffix.lower()
            full_name = skill_file.path.name.lower()

            is_tar_gz = full_name.endswith(".tar.gz") or full_name.endswith(".tgz")
            is_tar = ext in (".tar", ".tar.bz2", ".tar.xz") or is_tar_gz
            is_zip = ext in self.ZIP_EXTENSIONS

            if not (is_zip or is_tar):
                continue

            if not skill_file.path.exists():
                continue

            try:
                self._extract_archive(
                    skill_file.path,
                    skill_file.relative_path,
                    result,
                    depth=0,
                )
            except Exception as e:
                logger.warning("Failed to extract %s: %s", skill_file.relative_path, e)
                result.findings.append(
                    Finding(
                        id=f"EXTRACTION_FAILED_{hash(skill_file.relative_path) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_EXTRACTION_FAILED",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Archive extraction failed",
                        description=f"Could not extract {skill_file.relative_path}: {e}",
                        file_path=skill_file.relative_path,
                        remediation="Ensure archive is not corrupted. Consider providing files directly.",
                        analyzer="static",
                    )
                )

        return result

    def _extract_archive(
        self,
        archive_path: Path,
        source_relative_path: str,
        result: ExtractionResult,
        depth: int,
    ) -> None:
        """Extract a single archive, recursively handling nested archives."""
        if depth > self.limits.max_depth:
            result.findings.append(
                Finding(
                    id=f"NESTED_ARCHIVE_{hash(source_relative_path) & 0xFFFFFFFF:08x}",
                    rule_id="ARCHIVE_NESTED_TOO_DEEP",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Deeply nested archive detected",
                    description=(
                        f"Archive {source_relative_path} has nesting depth > {self.limits.max_depth}. "
                        f"Deep nesting is a common obfuscation technique."
                    ),
                    file_path=source_relative_path,
                    remediation="Flatten archive structure.",
                    analyzer="static",
                )
            )
            return

        if result.total_extracted_count >= self.limits.max_file_count:
            return

        ext = archive_path.suffix.lower()
        name_lower = archive_path.name.lower()

        if name_lower.endswith(".tar.gz") or name_lower.endswith(".tgz") or ext in (".tar", ".tar.bz2", ".tar.xz"):
            self._extract_tar(archive_path, source_relative_path, result, depth)
        elif ext in self.ZIP_EXTENSIONS:
            self._extract_zip(archive_path, source_relative_path, result, depth)

    def _extract_zip(self, archive_path: Path, source_relative_path: str, result: ExtractionResult, depth: int) -> None:
        """Extract a ZIP-based archive."""
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                # Check for zip bomb
                total_uncompressed = sum(info.file_size for info in zf.infolist() if not info.is_dir())
                compressed_size = archive_path.stat().st_size
                if compressed_size > 0:
                    ratio = total_uncompressed / compressed_size
                    if ratio > self.limits.max_compression_ratio:
                        result.findings.append(
                            Finding(
                                id=f"ZIP_BOMB_{hash(source_relative_path) & 0xFFFFFFFF:08x}",
                                rule_id="ARCHIVE_ZIP_BOMB",
                                category=ThreatCategory.RESOURCE_ABUSE,
                                severity=Severity.CRITICAL,
                                title="Potential zip bomb detected",
                                description=(
                                    f"Archive {source_relative_path} has compression ratio {ratio:.0f}:1 "
                                    f"(threshold: {self.limits.max_compression_ratio:.0f}:1). "
                                    f"This may be a zip bomb designed to cause denial of service."
                                ),
                                file_path=source_relative_path,
                                remediation="Remove suspicious archive or verify its contents.",
                                analyzer="static",
                            )
                        )
                        return

                # Check for path traversal
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith("/"):
                        result.findings.append(
                            Finding(
                                id=f"PATH_TRAVERSAL_{hash(source_relative_path + info.filename) & 0xFFFFFFFF:08x}",
                                rule_id="ARCHIVE_PATH_TRAVERSAL",
                                category=ThreatCategory.COMMAND_INJECTION,
                                severity=Severity.CRITICAL,
                                title="Path traversal in archive",
                                description=(
                                    f"Archive {source_relative_path} contains entry with path traversal: "
                                    f"'{info.filename}'. This could overwrite files outside the extraction directory."
                                ),
                                file_path=source_relative_path,
                                remediation="Remove malicious archive entries.",
                                analyzer="static",
                            )
                        )
                        return

                # Extract to temp dir
                temp_dir = tempfile.mkdtemp(prefix="skill_extract_")
                self._temp_dirs.append(temp_dir)

                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if result.total_extracted_count >= self.limits.max_file_count:
                        break
                    if result.total_extracted_size + info.file_size > self.limits.max_total_size_bytes:
                        break

                    extracted_path = Path(temp_dir) / info.filename
                    extracted_path.parent.mkdir(parents=True, exist_ok=True)
                    zf.extract(info, temp_dir)

                    result.total_extracted_count += 1
                    result.total_extracted_size += info.file_size

                    # Create virtual SkillFile
                    virtual_relative = f"{source_relative_path}!/{info.filename}"
                    file_type = self._determine_file_type(extracted_path)
                    content = None
                    if file_type != "binary":
                        try:
                            content = extracted_path.read_text(encoding="utf-8")
                        except (UnicodeDecodeError, OSError):
                            file_type = "binary"

                    sf = SkillFile(
                        path=extracted_path,
                        relative_path=virtual_relative,
                        file_type=file_type,
                        content=content,
                        size_bytes=info.file_size,
                        extracted_from=source_relative_path,
                        archive_depth=depth + 1,
                    )
                    result.extracted_files.append(sf)

                # Check for Office-specific threats
                if archive_path.suffix.lower() in self.OFFICE_EXTENSIONS:
                    self._check_office_threats(archive_path, source_relative_path, zf, result)

                # Recursively extract nested archives
                for sf in list(result.extracted_files):
                    if sf.extracted_from == source_relative_path:
                        nested_ext = sf.path.suffix.lower()
                        nested_name = sf.path.name.lower()
                        is_nested_archive = (
                            nested_ext in self.ZIP_EXTENSIONS
                            or nested_ext in self.TAR_EXTENSIONS
                            or nested_name.endswith(".tar.gz")
                        )
                        if is_nested_archive and sf.path.exists():
                            self._extract_archive(sf.path, sf.relative_path, result, depth + 1)

        except zipfile.BadZipFile as e:
            result.findings.append(
                Finding(
                    id=f"BAD_ZIP_{hash(source_relative_path) & 0xFFFFFFFF:08x}",
                    rule_id="ARCHIVE_EXTRACTION_FAILED",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.MEDIUM,
                    title="Corrupt or malformed ZIP archive",
                    description=f"Archive {source_relative_path} is corrupt: {e}",
                    file_path=source_relative_path,
                    remediation="Remove corrupt archive.",
                    analyzer="static",
                )
            )

    def _extract_tar(self, archive_path: Path, source_relative_path: str, result: ExtractionResult, depth: int) -> None:
        """Extract a TAR-based archive."""
        try:
            mode = "r:*"  # Auto-detect compression
            with tarfile.open(archive_path, mode) as tf:
                # Safety: check for path traversal
                for member in tf.getmembers():
                    if ".." in member.name or member.name.startswith("/"):
                        result.findings.append(
                            Finding(
                                id=f"PATH_TRAVERSAL_{hash(source_relative_path + member.name) & 0xFFFFFFFF:08x}",
                                rule_id="ARCHIVE_PATH_TRAVERSAL",
                                category=ThreatCategory.COMMAND_INJECTION,
                                severity=Severity.CRITICAL,
                                title="Path traversal in archive",
                                description=(
                                    f"Archive {source_relative_path} contains entry with path traversal: "
                                    f"'{member.name}'."
                                ),
                                file_path=source_relative_path,
                                remediation="Remove malicious archive entries.",
                                analyzer="static",
                            )
                        )
                        return

                temp_dir = tempfile.mkdtemp(prefix="skill_extract_")
                self._temp_dirs.append(temp_dir)

                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    if result.total_extracted_count >= self.limits.max_file_count:
                        break
                    if result.total_extracted_size + member.size > self.limits.max_total_size_bytes:
                        break

                    tf.extract(member, temp_dir, filter="data")
                    extracted_path = Path(temp_dir) / member.name

                    result.total_extracted_count += 1
                    result.total_extracted_size += member.size

                    virtual_relative = f"{source_relative_path}!/{member.name}"
                    file_type = self._determine_file_type(extracted_path)
                    content = None
                    if file_type != "binary":
                        try:
                            content = extracted_path.read_text(encoding="utf-8")
                        except (UnicodeDecodeError, OSError):
                            file_type = "binary"

                    sf = SkillFile(
                        path=extracted_path,
                        relative_path=virtual_relative,
                        file_type=file_type,
                        content=content,
                        size_bytes=member.size,
                        extracted_from=source_relative_path,
                        archive_depth=depth + 1,
                    )
                    result.extracted_files.append(sf)

        except (tarfile.TarError, OSError) as e:
            result.findings.append(
                Finding(
                    id=f"BAD_TAR_{hash(source_relative_path) & 0xFFFFFFFF:08x}",
                    rule_id="ARCHIVE_EXTRACTION_FAILED",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.MEDIUM,
                    title="Corrupt or malformed TAR archive",
                    description=f"Archive {source_relative_path} is corrupt: {e}",
                    file_path=source_relative_path,
                    remediation="Remove corrupt archive.",
                    analyzer="static",
                )
            )

    def _check_office_threats(
        self, archive_path: Path, source_relative_path: str, zf: zipfile.ZipFile, result: ExtractionResult
    ) -> None:
        """Check for VBA macros and other threats in Office documents."""
        names = zf.namelist()

        # Check for VBA macros (vbaProject.bin)
        vba_files = [n for n in names if "vbaProject" in n or n.endswith(".bin")]
        if vba_files:
            result.findings.append(
                Finding(
                    id=f"VBA_MACRO_{hash(source_relative_path) & 0xFFFFFFFF:08x}",
                    rule_id="OFFICE_VBA_MACRO",
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=Severity.CRITICAL,
                    title="VBA macro detected in Office document",
                    description=(
                        f"Office document {source_relative_path} contains VBA macros: "
                        f"{', '.join(vba_files[:3])}. VBA macros can execute arbitrary code."
                    ),
                    file_path=source_relative_path,
                    remediation="Remove VBA macros or replace with a text-based format (Markdown, plain text).",
                    analyzer="static",
                )
            )

        # Check for embedded OLE objects
        ole_files = [n for n in names if "oleObject" in n or "embeddings" in n.lower()]
        if ole_files:
            result.findings.append(
                Finding(
                    id=f"OLE_OBJECT_{hash(source_relative_path) & 0xFFFFFFFF:08x}",
                    rule_id="OFFICE_EMBEDDED_OLE",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Embedded OLE object in Office document",
                    description=(
                        f"Office document {source_relative_path} contains embedded OLE objects. "
                        f"These can contain executables or other malicious content."
                    ),
                    file_path=source_relative_path,
                    remediation="Remove embedded objects from the document.",
                    analyzer="static",
                )
            )

    def _determine_file_type(self, path: Path) -> str:
        """Determine file type from extension."""
        ext = path.suffix.lower()
        if ext in (".py",):
            return "python"
        elif ext in (".sh", ".bash"):
            return "bash"
        elif ext in (".md", ".markdown"):
            return "markdown"
        elif ext in (".exe", ".so", ".dylib", ".dll", ".bin"):
            return "binary"
        else:
            return "other"

    def cleanup(self) -> None:
        """Remove all temporary extraction directories."""
        import shutil

        for temp_dir in self._temp_dirs:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
        self._temp_dirs.clear()
