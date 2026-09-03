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

import hashlib
import io
import logging
import os
import re
import stat
import struct
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ...utils.file_utils import get_file_type
from ..finding_identity import stable_finding_suffix
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
    ZIP_EXTENSIONS = {
        ".zip",
        ".jar",
        ".war",
        ".apk",
        ".docx",
        ".docm",
        ".xlsx",
        ".xlsm",
        ".pptx",
        ".pptm",
        ".odt",
        ".ods",
        ".odp",
    }
    TAR_EXTENSIONS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"}
    # Office Open XML formats (special handling for VBA/macros)
    OFFICE_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
    _OOXML_MAIN_PARTS = {
        ".docx": "word/document.xml",
        ".docm": "word/document.xml",
        ".xlsx": "xl/workbook.xml",
        ".xlsm": "xl/workbook.xml",
        ".pptx": "ppt/presentation.xml",
        ".pptm": "ppt/presentation.xml",
    }
    _MAX_EMBEDDED_OOXML_CLASSIFICATION_BYTES = 16 * 1024 * 1024
    _MAX_EMBEDDED_OOXML_MEMBER_COUNT = 2_048
    _MAX_EMBEDDED_OOXML_MEMBER_NAME_BYTES = 1_024
    _MAX_EMBEDDED_OOXML_CENTRAL_DIRECTORY_BYTES = 2 * 1024 * 1024
    _MAX_EMBEDDED_OOXML_DECLARED_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
    _MAX_EMBEDDED_OOXML_XML_PART_BYTES = 512 * 1024
    _MAX_EMBEDDED_OOXML_XML_ELEMENTS = 4_096

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

            is_tar = (
                ext == ".tar"
                or full_name.endswith(".tar.gz")
                or full_name.endswith(".tgz")
                or full_name.endswith(".tar.bz2")
                or full_name.endswith(".tar.xz")
            )
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
                        id=f"EXTRACTION_FAILED_{stable_finding_suffix(skill_file.relative_path)}",
                        rule_id="ARCHIVE_EXTRACTION_FAILED",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Archive extraction failed",
                        description=f"Could not extract {skill_file.relative_path}: {e}",
                        file_path=skill_file.relative_path,
                        remediation="Ensure archive is not corrupted. Consider providing files directly.",
                        analyzer="content_extractor",
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
                    id=f"NESTED_ARCHIVE_{stable_finding_suffix(source_relative_path)}",
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
                    analyzer="content_extractor",
                )
            )
            return

        if result.total_extracted_count >= self.limits.max_file_count:
            return

        ext = archive_path.suffix.lower()
        name_lower = archive_path.name.lower()

        is_tar = (
            ext == ".tar"
            or name_lower.endswith(".tar.gz")
            or name_lower.endswith(".tgz")
            or name_lower.endswith(".tar.bz2")
            or name_lower.endswith(".tar.xz")
        )
        if is_tar:
            self._extract_tar(archive_path, source_relative_path, result, depth)
        elif ext in self.ZIP_EXTENSIONS:
            self._extract_zip(archive_path, source_relative_path, result, depth)

    @staticmethod
    def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
        """Check whether a ZIP entry encodes a symbolic link.

        ZIP archives store Unix file-mode bits in the upper 16 bits of
        ``external_attr``.  A symlink is indicated by the ``S_IFLNK`` flag.
        """
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        return unix_mode != 0 and stat.S_ISLNK(unix_mode)

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
                                id=f"ZIP_BOMB_{stable_finding_suffix(source_relative_path)}",
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
                                analyzer="content_extractor",
                            )
                        )
                        return

                # Check for path traversal and symlinks
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith("/"):
                        result.findings.append(
                            Finding(
                                id=f"PATH_TRAVERSAL_{stable_finding_suffix(source_relative_path, info.filename)}",
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
                                analyzer="content_extractor",
                            )
                        )
                        return

                    if self._is_zip_symlink(info):
                        result.findings.append(
                            Finding(
                                id=f"SYMLINK_{stable_finding_suffix(source_relative_path, info.filename)}",
                                rule_id="ARCHIVE_SYMLINK",
                                category=ThreatCategory.COMMAND_INJECTION,
                                severity=Severity.CRITICAL,
                                title="Symlink entry in archive",
                                description=(
                                    f"Archive {source_relative_path} contains a symbolic link entry: "
                                    f"'{info.filename}'. Symlinks inside archives can be used to read or "
                                    f"overwrite files outside the extraction directory."
                                ),
                                file_path=source_relative_path,
                                remediation="Remove symbolic links from the archive and include files directly.",
                                analyzer="content_extractor",
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

                    # Post-extraction safety: verify no symlink was created on disk
                    if extracted_path.is_symlink():
                        extracted_path.unlink()
                        result.findings.append(
                            Finding(
                                id=f"SYMLINK_ON_DISK_{stable_finding_suffix(source_relative_path, info.filename)}",
                                rule_id="ARCHIVE_SYMLINK",
                                category=ThreatCategory.COMMAND_INJECTION,
                                severity=Severity.CRITICAL,
                                title="Symlink created during archive extraction",
                                description=(
                                    f"Extracting '{info.filename}' from {source_relative_path} created "
                                    f"a symbolic link on disk. The link has been removed."
                                ),
                                file_path=source_relative_path,
                                remediation="Remove symbolic links from the archive and include files directly.",
                                analyzer="content_extractor",
                            )
                        )
                        continue

                    result.total_extracted_count += 1
                    result.total_extracted_size += info.file_size

                    # Create virtual SkillFile
                    virtual_relative = f"{source_relative_path}!/{info.filename}"
                    file_type = get_file_type(extracted_path)
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
                            or nested_ext == ".tar"
                            or nested_name.endswith(".tar.gz")
                            or nested_name.endswith(".tgz")
                            or nested_name.endswith(".tar.bz2")
                            or nested_name.endswith(".tar.xz")
                        )
                        if is_nested_archive and sf.path.exists():
                            self._extract_archive(sf.path, sf.relative_path, result, depth + 1)

        except zipfile.BadZipFile as e:
            result.findings.append(
                Finding(
                    id=f"BAD_ZIP_{stable_finding_suffix(source_relative_path)}",
                    rule_id="ARCHIVE_EXTRACTION_FAILED",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.MEDIUM,
                    title="Corrupt or malformed ZIP archive",
                    description=f"Archive {source_relative_path} is corrupt: {e}",
                    file_path=source_relative_path,
                    remediation="Remove corrupt archive.",
                    analyzer="content_extractor",
                )
            )

    def _extract_tar(self, archive_path: Path, source_relative_path: str, result: ExtractionResult, depth: int) -> None:
        """Extract a TAR-based archive."""
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                # Safety: check for path traversal and symlinks/hardlinks
                for member in tf.getmembers():
                    if ".." in member.name or member.name.startswith("/"):
                        result.findings.append(
                            Finding(
                                id=f"PATH_TRAVERSAL_{stable_finding_suffix(source_relative_path, member.name)}",
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
                                analyzer="content_extractor",
                            )
                        )
                        return

                    if member.issym() or member.islnk():
                        result.findings.append(
                            Finding(
                                id=f"SYMLINK_{stable_finding_suffix(source_relative_path, member.name)}",
                                rule_id="ARCHIVE_SYMLINK",
                                category=ThreatCategory.COMMAND_INJECTION,
                                severity=Severity.CRITICAL,
                                title="Symlink or hardlink entry in archive",
                                description=(
                                    f"Archive {source_relative_path} contains a "
                                    f"{'symbolic' if member.issym() else 'hard'} link entry: "
                                    f"'{member.name}' -> '{member.linkname}'. Links inside archives "
                                    f"can be used to read or overwrite files outside the extraction directory."
                                ),
                                file_path=source_relative_path,
                                remediation="Remove symbolic/hard links from the archive and include files directly.",
                                analyzer="content_extractor",
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
                    file_type = get_file_type(extracted_path)
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

                # Recursively extract nested archives (mirrors ZIP path)
                for sf in list(result.extracted_files):
                    if sf.extracted_from == source_relative_path:
                        nested_ext = sf.path.suffix.lower()
                        nested_name = sf.path.name.lower()
                        is_nested_archive = (
                            nested_ext in self.ZIP_EXTENSIONS
                            or nested_ext == ".tar"
                            or nested_name.endswith(".tar.gz")
                            or nested_name.endswith(".tgz")
                            or nested_name.endswith(".tar.bz2")
                            or nested_name.endswith(".tar.xz")
                        )
                        if is_nested_archive and sf.path.exists():
                            self._extract_archive(sf.path, sf.relative_path, result, depth + 1)

        except (tarfile.TarError, OSError) as e:
            result.findings.append(
                Finding(
                    id=f"BAD_TAR_{stable_finding_suffix(source_relative_path)}",
                    rule_id="ARCHIVE_EXTRACTION_FAILED",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.MEDIUM,
                    title="Corrupt or malformed TAR archive",
                    description=f"Archive {source_relative_path} is corrupt: {e}",
                    file_path=source_relative_path,
                    remediation="Remove corrupt archive.",
                    analyzer="content_extractor",
                )
            )

    def _check_office_threats(
        self, archive_path: Path, source_relative_path: str, zf: zipfile.ZipFile, result: ExtractionResult
    ) -> None:
        """Check for VBA macros and other threats in Office documents."""
        names = zf.namelist()

        # Check for VBA macros (vbaProject.bin)
        vba_files = [n for n in names if "vbaproject" in n.lower()]
        if vba_files:
            result.findings.append(
                Finding(
                    id=f"VBA_MACRO_{hashlib.sha256(source_relative_path.encode()).hexdigest()[:8]}",
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
                    analyzer="content_extractor",
                )
            )

        # Office stores both dangerous OLE/active objects and ordinary nested
        # OOXML documents under ``*/embeddings``.  A path-only check treated a
        # benign embedded .xlsx chart workbook as executable OLE. Classify the
        # bounded inner object by magic and structure instead.
        embedded_names = sorted({n for n in names if "oleObject" in n or "/embeddings/" in n.lower()})
        embedded_objects = [self._classify_office_embedding(zf, name) for name in embedded_names]
        suspicious_objects = [item for item in embedded_objects if item["actionable"]]
        if suspicious_objects:
            classifications = sorted({str(item["classification"]) for item in suspicious_objects})
            result.findings.append(
                Finding(
                    id=f"OLE_OBJECT_{stable_finding_suffix(source_relative_path)}",
                    rule_id="OFFICE_EMBEDDED_OLE",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Embedded OLE object in Office document",
                    description=(
                        f"Office document {source_relative_path} contains {len(suspicious_objects)} "
                        f"actionable embedded object(s) classified as {', '.join(classifications)}. "
                        "Legacy OLE, executables, malformed containers, and active OOXML content "
                        "can hide executable behavior."
                    ),
                    file_path=source_relative_path,
                    remediation="Remove embedded objects from the document.",
                    analyzer="content_extractor",
                    metadata={
                        "embedded_object_count": len(suspicious_objects),
                        "embedded_objects": suspicious_objects[:32],
                        "semantic_facts": {
                            "evidence_kind": "office_embedding",
                            "evidence_value_class": "actionable_embedded_object",
                            "context_kind": "office_document",
                            "signal_kind": "office_embedded_ole",
                        },
                    },
                )
            )

    def _classify_office_embedding(self, zf: zipfile.ZipFile, name: str) -> dict[str, Any]:
        """Return bounded, content-derived metadata for one Office embedding."""

        base: dict[str, Any] = {
            "path": name[:1_024],
            "classification": "opaque_embedding",
            "inner_magic": "unknown",
            "inner_role": "embedded_object",
            "active_content": False,
            "actionable": True,
        }
        try:
            info = zf.getinfo(name)
        except KeyError:
            base["classification"] = "missing_embedding"
            return base
        if info.is_dir():
            base.update(classification="embedding_directory", actionable=False)
            return base
        try:
            with zf.open(info, "r") as handle:
                prefix = handle.read(8)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            base["classification"] = "unreadable_embedding"
            return base

        if prefix.startswith(b"PK\x03\x04"):
            base["inner_magic"] = "zip"
        elif prefix.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            base.update(classification="legacy_ole", inner_magic="ole_cfb")
            return base
        elif prefix.startswith(b"MZ"):
            base.update(classification="embedded_executable", inner_magic="pe")
            return base
        elif prefix.startswith(b"\x7fELF"):
            base.update(classification="embedded_executable", inner_magic="elf")
            return base
        elif prefix[:4] in {
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
        }:
            base.update(classification="embedded_executable", inner_magic="mach_o")
            return base

        suffix = Path(name).suffix.lower()
        expected_main_part = self._OOXML_MAIN_PARTS.get(suffix)
        if expected_main_part is None or base["inner_magic"] != "zip":
            if "oleobject" in name.lower():
                base["classification"] = "opaque_ole_object"
            return base
        if info.file_size > self._MAX_EMBEDDED_OOXML_CLASSIFICATION_BYTES:
            base["classification"] = "oversized_ooxml_embedding"
            return base

        try:
            with zf.open(info, "r") as handle:
                nested_bytes = handle.read(self._MAX_EMBEDDED_OOXML_CLASSIFICATION_BYTES + 1)
            if len(nested_bytes) != info.file_size:
                base["classification"] = "truncated_ooxml_embedding"
                return base
            central_error, preflight_names = self._preflight_embedded_ooxml_zip(nested_bytes)
            if central_error:
                base["classification"] = central_error
                return base
            with zipfile.ZipFile(io.BytesIO(nested_bytes), "r") as nested:
                inner_infos = [entry for entry in nested.infolist() if not entry.is_dir()]
                inner_names = {self._normalise_nested_member_name(entry.filename) for entry in inner_infos}
                if inner_names != preflight_names:
                    base["classification"] = "inconsistent_ooxml_inventory"
                    return base
                active_relationship = self._has_active_ooxml_relationship(nested, inner_infos)
                macro_content_type = self._has_macro_enabled_content_type(nested)
        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
            base["classification"] = "malformed_ooxml_embedding"
            return base

        required = {"[Content_Types].xml", expected_main_part}
        if not required.issubset(inner_names):
            base["classification"] = "malformed_ooxml_embedding"
            return base
        lower_names = {item.lower() for item in inner_names}
        active_names = sorted(
            item
            for item in inner_names
            if (
                "vbaproject" in item.lower()
                or "activex" in item.lower()
                or "oleobject" in item.lower()
                or "embeddings" in item.lower().split("/")
                or "externallinks" in item.lower().split("/")
                or "querytables" in item.lower().split("/")
                or "customui" in item.lower().split("/")
                or "macrosheets" in item.lower().split("/")
                or item.lower().endswith("/connections.xml")
            )
        )
        base["inner_role"] = f"embedded_ooxml_{suffix[1:]}"
        if active_names or active_relationship or macro_content_type:
            base.update(
                classification="active_ooxml_embedding",
                active_content=True,
                active_member_count=len(active_names),
                active_relationship=active_relationship,
                macro_enabled_content_type=macro_content_type,
            )
            return base
        base.update(classification="inert_ooxml_embedding", actionable=False)
        # Never expose inner filenames or content for benign objects. Presence
        # of the expected main part and absence of active members is enough.
        base["validated_parts"] = len(lower_names)
        return base

    @classmethod
    def _preflight_embedded_ooxml_zip(cls, payload: bytes) -> tuple[str, set[str]]:
        """Validate a nested ZIP central directory before ``ZipFile`` allocates it.

        The outer embedded object is already byte-bounded, but a small ZIP can
        still advertise a huge member population or decompressed size. This
        parser accepts only a single-disk, non-ZIP64 central directory with a
        bounded, unique, traversal-safe inventory. Any ambiguity remains an
        actionable embedding classification.
        """

        eocd_offset = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65_557))
        if eocd_offset < 0 or eocd_offset + 22 > len(payload):
            return "malformed_ooxml_embedding", set()
        try:
            (
                signature,
                disk_number,
                central_disk,
                disk_entries,
                total_entries,
                central_size,
                central_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2LH", payload, eocd_offset)
        except struct.error:
            return "malformed_ooxml_embedding", set()
        if signature != b"PK\x05\x06" or eocd_offset + 22 + comment_size != len(payload):
            return "malformed_ooxml_embedding", set()
        if disk_number or central_disk or disk_entries != total_entries:
            return "unsupported_multidisk_ooxml_embedding", set()
        if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            return "unsupported_zip64_ooxml_embedding", set()
        if total_entries > cls._MAX_EMBEDDED_OOXML_MEMBER_COUNT:
            return "excessive_ooxml_member_count", set()
        if central_size > cls._MAX_EMBEDDED_OOXML_CENTRAL_DIRECTORY_BYTES:
            return "oversized_ooxml_central_directory", set()
        central_end = central_offset + central_size
        if central_offset < 0 or central_end != eocd_offset:
            return "malformed_ooxml_embedding", set()

        cursor = central_offset
        names: set[str] = set()
        seen_names: set[str] = set()
        declared_total = 0
        for _ in range(total_entries):
            if cursor + 46 > central_end:
                return "malformed_ooxml_embedding", set()
            try:
                fields = struct.unpack_from("<4s6H3L5H2L", payload, cursor)
            except struct.error:
                return "malformed_ooxml_embedding", set()
            if fields[0] != b"PK\x01\x02":
                return "malformed_ooxml_embedding", set()
            flags = fields[3]
            compressed_size = fields[8]
            uncompressed_size = fields[9]
            name_size, extra_size, entry_comment_size = fields[10:13]
            disk_start = fields[13]
            external_attributes = fields[15]
            if flags & 0x1:
                return "encrypted_ooxml_embedding", set()
            if disk_start or compressed_size == 0xFFFFFFFF or uncompressed_size == 0xFFFFFFFF:
                return "unsupported_zip64_ooxml_embedding", set()
            if name_size == 0 or name_size > cls._MAX_EMBEDDED_OOXML_MEMBER_NAME_BYTES:
                return "invalid_ooxml_member_name", set()
            record_end = cursor + 46 + name_size + extra_size + entry_comment_size
            if record_end > central_end:
                return "malformed_ooxml_embedding", set()
            encoding = "utf-8" if flags & 0x800 else "cp437"
            try:
                decoded_name = payload[cursor + 46 : cursor + 46 + name_size].decode(encoding)
            except UnicodeDecodeError:
                return "invalid_ooxml_member_name", set()
            normalized = cls._normalise_nested_member_name(decoded_name)
            if not normalized or normalized in seen_names:
                return "duplicate_ooxml_member_name", set()
            if cls._is_unsafe_nested_member_name(decoded_name, normalized):
                return "unsafe_ooxml_member_path", set()
            mode = (external_attributes >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                return "symlink_ooxml_member", set()
            seen_names.add(normalized)
            if not decoded_name.replace("\\", "/").endswith("/"):
                names.add(normalized)
            declared_total += uncompressed_size
            if declared_total > cls._MAX_EMBEDDED_OOXML_DECLARED_UNCOMPRESSED_BYTES:
                return "oversized_ooxml_declared_content", set()
            cursor = record_end
        if cursor != central_end:
            return "malformed_ooxml_embedding", set()
        return "", names

    @staticmethod
    def _normalise_nested_member_name(name: str) -> str:
        return PurePosixPath(name.replace("\\", "/")).as_posix()

    @staticmethod
    def _is_unsafe_nested_member_name(original: str, normalized: str) -> bool:
        replaced = original.replace("\\", "/")
        path = PurePosixPath(replaced)
        return (
            "\x00" in original
            or path.is_absolute()
            or bool(re.match(r"^[A-Za-z]:", replaced))
            or ".." in path.parts
            or normalized.startswith("../")
        )

    @classmethod
    def _has_active_ooxml_relationship(
        cls,
        nested: zipfile.ZipFile,
        infos: list[zipfile.ZipInfo],
    ) -> bool:
        for info in infos:
            if not info.filename.lower().endswith(".rels"):
                continue
            if info.file_size > cls._MAX_EMBEDDED_OOXML_XML_PART_BYTES:
                return True
            with nested.open(info, "r") as handle:
                content = handle.read(cls._MAX_EMBEDDED_OOXML_XML_PART_BYTES + 1)
            if len(content) != info.file_size:
                return True
            lowered = content.lower()
            if b"<!doctype" in lowered or b"<!entity" in lowered:
                return True
            try:
                root = ET.fromstring(content)
            except (ET.ParseError, ValueError):
                return True
            if cls._xml_local_name(root.tag) != "relationships":
                return True
            relationships = list(root)
            if len(relationships) > cls._MAX_EMBEDDED_OOXML_XML_ELEMENTS:
                return True
            for relationship in relationships:
                if cls._xml_local_name(relationship.tag) != "relationship":
                    return True
                attributes = {
                    cls._xml_local_name(key): value.strip()
                    for key, value in relationship.attrib.items()
                    if isinstance(value, str)
                }
                relationship_type = attributes.get("type", "")
                target_mode = attributes.get("targetmode", "internal").lower()
                if not relationship_type or target_mode not in {"internal", "external"}:
                    return True
                if target_mode == "external":
                    return True
                relationship_kind = relationship_type.rstrip("/").rsplit("/", 1)[-1].lower()
                if relationship_kind in {"oleobject", "package", "externallink", "activex", "vbaproject"}:
                    return True
        return False

    @staticmethod
    def _xml_local_name(name: object) -> str:
        value = str(name)
        return value.rsplit("}", 1)[-1].rsplit(":", 1)[-1].lower()

    @classmethod
    def _has_macro_enabled_content_type(cls, nested: zipfile.ZipFile) -> bool:
        try:
            info = nested.getinfo("[Content_Types].xml")
        except KeyError:
            return True
        if info.file_size > cls._MAX_EMBEDDED_OOXML_XML_PART_BYTES:
            return True
        with nested.open(info, "r") as handle:
            content = handle.read(cls._MAX_EMBEDDED_OOXML_XML_PART_BYTES + 1).lower()
        if len(content) != info.file_size:
            return True
        return any(marker in content for marker in (b"macroenabled", b"vbaproject", b"activex", b"oleobject"))

    def cleanup(self) -> None:
        """Remove all temporary extraction directories."""
        import shutil

        for temp_dir in self._temp_dirs:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
        self._temp_dirs.clear()
