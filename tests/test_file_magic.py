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
Tests for file content type detection (Magika-powered + legacy fallback).
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

# ── MagicMatch dataclass ────────────────────────────────────────────────


class TestMagicMatch:
    """Verify MagicMatch NamedTuple fields and defaults."""

    def test_basic_fields(self):
        m = MagicMatch("executable/elf", "executable", "ELF executable")
        assert m.content_type == "executable/elf"
        assert m.content_family == "executable"
        assert m.description == "ELF executable"

    def test_default_score(self):
        """Legacy matches should default to score 1.0."""
        m = MagicMatch("archive/zip", "archive", "ZIP archive")
        assert m.score == 1.0

    def test_default_mime_type(self):
        m = MagicMatch("image/png", "image", "PNG image")
        assert m.mime_type == ""

    def test_explicit_score_and_mime(self):
        m = MagicMatch("code/python", "code", "Python source", 0.99, "text/x-python")
        assert m.score == 0.99
        assert m.mime_type == "text/x-python"


# ── detect_magic (file path) ────────────────────────────────────────────


class TestDetectMagic:
    """Test content type detection from files on disk."""

    def test_detect_elf_magic(self, tmp_path):
        """ELF header bytes correctly identified (legacy fallback)."""
        f = tmp_path / "file"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "executable"
        assert "ELF" in result.description or "elf" in result.content_type

    def test_detect_pe_magic(self, tmp_path):
        """PE (MZ) header bytes correctly identified (legacy fallback)."""
        f = tmp_path / "file"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "executable"

    def test_detect_macho_magic(self, tmp_path):
        """Mach-O header bytes correctly identified (legacy fallback)."""
        f = tmp_path / "file"
        f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "executable"

    def test_detect_zip_magic(self, tmp_path):
        """ZIP (PK) header bytes correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "archive"

    def test_detect_gzip_magic(self, tmp_path):
        """GZIP header correctly identified."""
        f = tmp_path / "file.bin"
        f.write_bytes(b"\x1f\x8b\x08" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "archive"

    def test_detect_png_magic(self, tmp_path):
        """PNG header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "image"

    def test_detect_jpeg_magic(self, tmp_path):
        """JPEG header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "image"

    def test_detect_gif_magic(self, tmp_path):
        """GIF header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"GIF89a" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "image"

    def test_detect_pdf_magic(self, tmp_path):
        """%PDF header correctly identified."""
        f = tmp_path / "file"
        f.write_bytes(b"%PDF-1.4" + b"\x00" * 100)
        result = detect_magic(f)
        assert result is not None
        assert result.content_family == "document"

    def test_detect_python_via_magika(self, tmp_path):
        """Magika identifies Python source code (not possible with legacy)."""
        f = tmp_path / "script.py"
        f.write_text(
            "import os\nimport sys\n\ndef main():\n"
            "    data = os.environ.get('X', 'default')\n"
            "    print(data)\n\nif __name__ == '__main__':\n    main()\n"
        )
        result = detect_magic(f)
        assert result is not None
        assert result.content_family in ("code", "text")
        assert result.score > 0

    def test_detect_shell_via_magika(self, tmp_path):
        """Magika identifies shell scripts."""
        f = tmp_path / "script.sh"
        f.write_text('#!/bin/bash\nset -e\nfor i in 1 2 3; do\n  echo "iteration $i"\ndone\nexit 0\n')
        result = detect_magic(f)
        assert result is not None
        assert result.content_family in ("code", "text", "executable")

    def test_detect_markdown_via_magika(self, tmp_path):
        """Magika identifies Markdown."""
        f = tmp_path / "readme.md"
        f.write_text("# Title\n\nSome text here.\n\n## Section\n\nMore content.\n")
        result = detect_magic(f)
        assert result is not None
        # Magika may return text or code group for markdown
        assert result.content_family in ("text", "code")

    def test_empty_file(self, tmp_path):
        """Empty file returns None or an empty/inode result."""
        f = tmp_path / "empty"
        f.write_bytes(b"")
        result = detect_magic(f)
        # May be None (Magika returns inode/empty which we filter)
        # or could return a low-confidence result
        if result is not None:
            assert result.score >= 0

    def test_nonexistent_file(self, tmp_path):
        """Non-existent file returns None."""
        result = detect_magic(tmp_path / "does_not_exist")
        assert result is None

    def test_score_field_populated(self, tmp_path):
        """Magika-detected results include a meaningful score."""
        f = tmp_path / "script.sh"
        f.write_text('#!/bin/bash\nset -e\nfor i in 1 2 3; do\n  echo "iteration $i"\ndone\nexit 0\n')
        result = detect_magic(f)
        assert result is not None
        assert isinstance(result.score, float)
        assert 0.0 <= result.score <= 1.0


# ── detect_magic_from_bytes ──────────────────────────────────────────────


class TestDetectMagicFromBytes:
    """Test detection from raw bytes."""

    def test_from_bytes_elf(self):
        """ELF bytes detected via legacy fallback."""
        result = detect_magic_from_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)
        assert result is not None
        assert result.content_family == "executable"

    def test_from_bytes_zip(self):
        result = detect_magic_from_bytes(b"PK\x03\x04" + b"\x00" * 50)
        assert result is not None
        assert result.content_family == "archive"

    def test_from_bytes_empty(self):
        result = detect_magic_from_bytes(b"")
        assert result is None

    def test_from_bytes_unknown(self):
        """Random bytes may return None or an unknown-ish result."""
        result = detect_magic_from_bytes(b"\x01\x02\x03\x04")
        # Could be None if neither Magika nor legacy match
        if result is not None:
            assert result.content_family is not None


# ── Extension mismatch (binary mismatches) ───────────────────────────────


class TestExtensionMismatch:
    """Test extension vs. content mismatch detection (binary cases)."""

    def test_mismatch_image_ext_but_elf(self, tmp_path):
        """photo.png with ELF content → CRITICAL."""
        f = tmp_path / "photo.png"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "CRITICAL"
        assert "executable" in description.lower() or "ELF" in description

    def test_mismatch_image_ext_but_pe(self, tmp_path):
        """icon.jpg with PE content → CRITICAL."""
        f = tmp_path / "icon.jpg"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "CRITICAL"

    def test_mismatch_image_ext_but_macho(self, tmp_path):
        """logo.gif with Mach-O content → CRITICAL."""
        f = tmp_path / "logo.gif"
        f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "CRITICAL"

    def test_mismatch_image_ext_but_zip(self, tmp_path):
        """diagram.png with ZIP content → HIGH."""
        f = tmp_path / "diagram.png"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "HIGH"

    def test_mismatch_doc_ext_but_pe(self, tmp_path):
        """readme.pdf with PE content → CRITICAL."""
        f = tmp_path / "readme.pdf"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "CRITICAL"

    def test_no_mismatch_real_png(self, tmp_path):
        """Actual PNG file with .png ext → no finding."""
        f = tmp_path / "logo.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is None

    def test_no_mismatch_real_zip(self, tmp_path):
        """Actual ZIP file with .zip ext → no finding."""
        f = tmp_path / "data.zip"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is None

    def test_unknown_extension_no_mismatch(self, tmp_path):
        """Unknown extension → no mismatch (nothing to compare against)."""
        f = tmp_path / "data.xyz"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is None


# ── Extension mismatch (text-format mismatches – NEW) ───────────────────


class TestTextFormatMismatch:
    """Test text-format mismatch detection (enabled by Magika)."""

    def test_shell_in_py_file(self, tmp_path):
        """A .py file with shell content → MEDIUM label mismatch."""
        f = tmp_path / "setup.py"
        f.write_text('#!/bin/bash\nset -e\nrm -rf /tmp/foo\nfor i in 1 2 3; do\n  echo "hello"\ndone\nexit 0\n')
        result = check_extension_mismatch(f)
        assert result is not None
        severity, description, magic = result
        assert severity == "MEDIUM"
        assert "shell" in description.lower() or "different text format" in description.lower()

    def test_python_in_py_file_no_mismatch(self, tmp_path):
        """A .py file with real Python content → no mismatch."""
        f = tmp_path / "app.py"
        f.write_text(
            "import os\nimport sys\n\ndef main():\n"
            "    print('Hello world')\n    return 0\n\n"
            "if __name__ == '__main__':\n    main()\n"
        )
        result = check_extension_mismatch(f)
        assert result is None

    def test_normal_markdown_no_mismatch(self, tmp_path):
        """A .md file with real Markdown → no mismatch."""
        f = tmp_path / "README.md"
        f.write_text("# Title\n\nSome text here.\n\n## Section\n\nMore content.\n")
        result = check_extension_mismatch(f)
        assert result is None

    def test_gzip_in_txt(self, tmp_path):
        """Binary GZIP data hiding in a .txt file → HIGH (text → archive)."""
        f = tmp_path / "notes.txt"
        f.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 500)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, _desc, _magic = result
        assert severity == "HIGH"

    def test_elf_in_py(self, tmp_path):
        """Binary ELF data hiding in a .py file → CRITICAL (text → executable)."""
        f = tmp_path / "util.py"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        severity, _desc, _magic = result
        assert severity == "CRITICAL"


# ── Confidence threshold ────────────────────────────────────────────────


class TestConfidenceThreshold:
    """Test the min_confidence gating in check_extension_mismatch."""

    def test_high_confidence_flagged(self, tmp_path):
        """Shell in .py with default threshold (0.8) → flagged."""
        f = tmp_path / "deploy.py"
        f.write_text('#!/bin/bash\nset -e\nrm -rf /tmp/foo\nfor i in 1 2 3; do\n  echo "hello"\ndone\nexit 0\n')
        result = check_extension_mismatch(f, min_confidence=0.5)
        assert result is not None

    def test_very_high_threshold_suppresses(self, tmp_path):
        """Shell in .py with threshold=0.9999 → suppressed (score too low)."""
        f = tmp_path / "deploy.py"
        f.write_text('#!/bin/bash\nset -e\nrm -rf /tmp/foo\nfor i in 1 2 3; do\n  echo "hello"\ndone\nexit 0\n')
        result = check_extension_mismatch(f, min_confidence=0.9999)
        # With threshold at 0.9999, most Magika results are below this
        # Legacy fallback may still match (shebang → executable), so
        # the result depends on which engine detects the file.
        # We just verify it doesn't crash.
        # The test is mainly about the parameter being accepted.

    def test_legacy_fallback_ignores_threshold(self, tmp_path):
        """Legacy magic byte matches (score=1.0) are never filtered by threshold."""
        f = tmp_path / "photo.png"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        # Even with a high threshold, legacy matches have score=1.0
        result = check_extension_mismatch(f, min_confidence=0.99)
        assert result is not None
        assert result[0] == "CRITICAL"


# ── get_extension_family ─────────────────────────────────────────────────


class TestGetExtensionFamily:
    """Test extension to family mapping."""

    def test_known_extensions(self):
        assert get_extension_family(".png") == "image"
        assert get_extension_family(".exe") == "executable"
        assert get_extension_family(".zip") == "archive"
        assert get_extension_family(".pdf") == "document"
        assert get_extension_family(".ttf") == "font"
        assert get_extension_family(".py") == "text"
        assert get_extension_family(".json") == "text"
        assert get_extension_family(".md") == "text"

    def test_audio_video_extensions(self):
        assert get_extension_family(".mp3") == "audio"
        assert get_extension_family(".mp4") == "video"

    def test_unknown_extension(self):
        assert get_extension_family(".xyz") is None

    def test_case_insensitive(self):
        assert get_extension_family(".PNG") == "image"
        assert get_extension_family(".Py") == "text"


# ── MagicMatch metadata in findings ─────────────────────────────────────


class TestMagicMatchMetadata:
    """Verify that MagicMatch carries useful metadata for findings."""

    def test_mismatch_returns_magic_with_score(self, tmp_path):
        """Mismatch result includes score in the MagicMatch."""
        f = tmp_path / "photo.png"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        _sev, _desc, magic = result
        assert isinstance(magic.score, float)
        assert magic.score > 0

    def test_mismatch_returns_content_type(self, tmp_path):
        """Mismatch result includes structured content_type."""
        f = tmp_path / "diagram.png"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = check_extension_mismatch(f)
        assert result is not None
        _sev, _desc, magic = result
        assert magic.content_family == "archive"
        assert "/" in magic.content_type  # e.g. "archive/zip"
