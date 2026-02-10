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
Tests for file magic byte detection (Feature #4 - file_magic.py).
"""

from pathlib import Path

import pytest

from skill_scanner.core.file_magic import (
    MagicMatch,
    check_extension_mismatch,
    detect_magic,
    detect_magic_from_bytes,
    get_extension_family,
)


class TestDetectMagic:
    """Test individual magic byte detection."""

    def test_detect_elf_magic(self, tmp_path):
        """ELF header bytes correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "executable"
        assert "ELF" in result.description

    def test_detect_pe_magic(self, tmp_path):
        """PE (MZ) header bytes correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "executable"
        assert "PE" in result.description or "Windows" in result.description

    def test_detect_macho_magic(self, tmp_path):
        """Mach-O header bytes correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "executable"
        assert "Mach-O" in result.description

    def test_detect_zip_magic(self, tmp_path):
        """ZIP (PK) header bytes correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "archive"
        assert "ZIP" in result.description

    def test_detect_pdf_magic(self, tmp_path):
        """%PDF header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"%PDF-1.4" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "document"
        assert "PDF" in result.description

    def test_detect_png_magic(self, tmp_path):
        """PNG header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "image"
        assert "PNG" in result.description

    def test_detect_jpeg_magic(self, tmp_path):
        """JPEG header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "image"
        assert "JPEG" in result.description

    def test_detect_gif_magic(self, tmp_path):
        """GIF header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"GIF89a" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "image"
        assert "GIF" in result.description

    def test_detect_gzip_magic(self, tmp_path):
        """GZIP header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\x1f\x8b\x08" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "archive"


class TestDetectMagicFromBytes:
    """Test detection from raw bytes."""

    def test_from_bytes_elf(self):
        result = detect_magic_from_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)
        assert result is not None
        assert result.content_family == "executable"

    def test_from_bytes_empty(self):
        result = detect_magic_from_bytes(b"")
        assert result is None

    def test_from_bytes_unknown(self):
        result = detect_magic_from_bytes(b"unknown data here")
        assert result is None


class TestExtensionMismatch:
    """Test extension vs. content mismatch detection."""

    def test_mismatch_image_ext_but_elf(self, tmp_path):
        """photo.png with ELF content -> CRITICAL."""
        f = tmp_path / "photo.png"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "CRITICAL"
        assert "executable" in description.lower() or "ELF" in description

    def test_mismatch_image_ext_but_zip(self, tmp_path):
        """diagram.jpg with ZIP content -> HIGH."""
        f = tmp_path / "diagram.jpg"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "HIGH"

    def test_mismatch_doc_ext_but_pe(self, tmp_path):
        """readme.pdf with PE content -> CRITICAL."""
        f = tmp_path / "readme.pdf"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "CRITICAL"

    def test_no_mismatch_real_png(self, tmp_path):
        """Actual PNG file with .png ext -> no finding."""
        f = tmp_path / "logo.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is None

    def test_no_mismatch_real_zip(self, tmp_path):
        """Actual ZIP file with .zip ext -> no finding (just matching families)."""
        f = tmp_path / "data.zip"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is None

    def test_no_mismatch_text_file(self, tmp_path):
        """Text files don't have reliable magic - no mismatch."""
        f = tmp_path / "script.py"
        f.write_bytes(b"import os\nprint('hello')\n")
        result = check_extension_mismatch(f)
        assert result is None

    def test_unknown_extension_no_mismatch(self, tmp_path):
        """Unknown extension -> no mismatch (nothing to compare against)."""
        f = tmp_path / "data.xyz"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is None


class TestGetExtensionFamily:
    """Test extension to family mapping."""

    def test_known_extensions(self):
        assert get_extension_family(".png") == "image"
        assert get_extension_family(".exe") == "executable"
        assert get_extension_family(".zip") == "archive"
        assert get_extension_family(".pdf") == "document"
        assert get_extension_family(".ttf") == "font"
        assert get_extension_family(".py") == "text"

    def test_unknown_extension(self):
        assert get_extension_family(".xyz") is None
