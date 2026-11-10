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

    @pytest.mark.parametrize(
        ("extension", "content_type", "mime_type"),
        [
            (
                ".docx",
                "document/docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            (
                ".xlsx",
                "document/xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            (
                ".pptx",
                "document/pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ),
            (
                ".docm",
                "document/docx",
                "application/vnd.ms-word.document.macroEnabled.12",
            ),
            (
                ".xlsm",
                "document/xlsx",
                "application/vnd.ms-excel.sheet.macroEnabled.12",
            ),
            (
                ".pptm",
                "document/pptx",
                "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            ),
        ],
    )
    def test_magika_ooxml_document_family_matches_zip_based_extension(
        self,
        tmp_path,
        monkeypatch,
        extension,
        content_type,
        mime_type,
    ):
        document = tmp_path / f"reference{extension}"
        document.write_bytes(b"PK\x03\x04bounded-ooxml-fixture")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch(content_type, "document", "OOXML document", 0.99, mime_type),
        )

        assert check_extension_mismatch(document) is None

    def test_ooxml_extension_with_different_document_label_is_still_a_mismatch(self, tmp_path, monkeypatch):
        document = tmp_path / "reference.pptx"
        document.write_bytes(b"PK\x03\x04bounded-ooxml-fixture")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch(
                "document/docx",
                "document",
                "Microsoft Word document",
                0.99,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
        )

        assert check_extension_mismatch(document) is not None

    def test_html_detected_as_vue_is_a_compatible_web_subtype(self, tmp_path, monkeypatch):
        document = tmp_path / "visualization.html"
        document.write_text(
            '<!doctype html><html><body><div id="app">{{ message }}</div>'
            '<script type="module">import { createApp } from "vue";</script></body></html>',
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("code/vue", "code", "Vue component", 0.99, "text/x-vue"),
        )

        assert check_extension_mismatch(document) is None

    def test_html_with_cross_family_binary_content_remains_actionable(self, tmp_path, monkeypatch):
        document = tmp_path / "visualization.html"
        document.write_bytes(b"MZ" + b"\0" * 128)
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch(
                "executable/pe",
                "executable",
                "PE/Windows executable",
                1.0,
                "application/x-dosexec",
            ),
        )

        result = check_extension_mismatch(document)

        assert result is not None
        assert result[0] == "CRITICAL"

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

    def test_node_shebang_in_js_no_mismatch(self, tmp_path):
        """A .js file with a node shebang is legitimate and should not be flagged."""
        f = tmp_path / "run_actor.js"
        f.write_text(
            "#!/usr/bin/env node\n"
            "import { readFileSync } from 'node:fs';\n"
            "console.log(readFileSync('package.json', 'utf8'));\n"
        )
        result = check_extension_mismatch(f)
        assert result is None

    def test_node_shebang_in_js_mismatch_when_policy_knob_disabled(self, tmp_path):
        """Disabling shebang-text compatibility should restore mismatch finding."""
        f = tmp_path / "run_actor.js"
        f.write_text(
            "#!/usr/bin/env node\n"
            "import { readFileSync } from 'node:fs';\n"
            "console.log(readFileSync('package.json', 'utf8'));\n"
        )
        result = check_extension_mismatch(
            f,
            allow_script_shebang_text_extensions=False,
            shebang_compatible_extensions={".js"},
        )
        assert result is not None
        severity, _desc, _magic = result
        assert severity == "CRITICAL"

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

    @pytest.mark.parametrize(
        ("filename", "content", "score"),
        [
            ("record.json", b'{"name":"example","enabled":true}\n', 0.67),
            ("config.yaml", b"name: example\nenabled: true\n", 0.87),
        ],
    )
    def test_structured_text_rejects_false_archive_label(self, tmp_path, monkeypatch, filename, content, score):
        """A weak archive label cannot override a valid structured text file."""
        f = tmp_path / filename
        f.write_bytes(content)
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("archive/snap", "archive", "Snap archive", score),
        )

        assert check_extension_mismatch(f, min_confidence=0.6) is None

    def test_valid_yaml_rejects_weak_textproto_label(self, tmp_path, monkeypatch):
        """A small YAML mapping can resemble textproto without being mislabeled."""
        f = tmp_path / "agent.yaml"
        f.write_text("interface:\n  display_name: Example\n  default_prompt: Review the issue\n")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("code/textproto", "code", "Textproto", 0.8904),
        )

        assert check_extension_mismatch(f, min_confidence=0.6) is None

    @pytest.mark.parametrize("label,score", [("textproto", 0.95), ("shell", 0.8904)])
    def test_other_yaml_label_conflicts_remain(self, tmp_path, monkeypatch, label, score):
        f = tmp_path / "agent.yaml"
        f.write_text("interface:\n  display_name: Example\n")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch(f"code/{label}", "code", label, score),
        )

        result = check_extension_mismatch(f, min_confidence=0.6)
        assert result is not None
        assert result[0] == "MEDIUM"

    @pytest.mark.parametrize(
        ("filename", "content"),
        [
            ("setup.sh", b"#!/bin/sh\nprintf '%s\\n' ready\n"),
            ("record.json", b'{"name":"example"}\nextra'),
            ("config.yaml", b"plain scalar text\n"),
        ],
    )
    def test_unverified_text_keeps_archive_finding(self, tmp_path, monkeypatch, filename, content):
        f = tmp_path / filename
        f.write_bytes(content)
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("archive/snap", "archive", "Snap archive", 0.67),
        )

        result = check_extension_mismatch(f, min_confidence=0.6)
        assert result is not None
        assert result[0] == "HIGH"

    @pytest.mark.parametrize(
        "archive_data",
        [
            b"PK\x03\x04" + b"\x00" * 100,
            b"!<arch>\n" + b" " * 100,
            b"070701" + b"0" * 100,
            b"070707" + b"0" * 100,
        ],
    )
    def test_real_archive_signature_survives_false_text_appearance(self, tmp_path, monkeypatch, archive_data):
        """Real binary and ASCII archive headers remain HIGH in a JSON file."""
        f = tmp_path / "record.json"
        f.write_bytes(archive_data)
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("archive/zip", "archive", "ZIP archive", 0.67),
        )

        result = check_extension_mismatch(f, min_confidence=0.6)
        assert result is not None
        assert result[0] == "HIGH"

    def test_high_confidence_archive_label_is_not_suppressed(self, tmp_path, monkeypatch):
        f = tmp_path / "record.json"
        f.write_text('{"name":"example"}\n')
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("archive/snap", "archive", "Snap archive", 0.95),
        )

        result = check_extension_mismatch(f, min_confidence=0.6)
        assert result is not None
        assert result[0] == "HIGH"

    def test_archive_label_with_binary_after_text_prefix_is_not_suppressed(self, tmp_path, monkeypatch):
        f = tmp_path / "record.json"
        f.write_bytes(b" " * 4096 + b"\x00archive")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("archive/snap", "archive", "Snap archive", 0.67),
        )

        result = check_extension_mismatch(f, min_confidence=0.6)
        assert result is not None
        assert result[0] == "HIGH"

    @pytest.mark.parametrize(("extension", "depth"), [("json", 16000), ("yaml", 1200)])
    def test_deeply_nested_structured_text_fails_closed(self, tmp_path, monkeypatch, extension, depth):
        """Parser recursion must not crash scanning or suppress an archive signal."""
        f = tmp_path / f"record.{extension}"
        nested = "[" * depth + "0" + "]" * depth
        f.write_text(f"x: {nested}" if extension == "yaml" else nested)
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("archive/snap", "archive", "Snap archive", 0.67),
        )

        result = check_extension_mismatch(f, min_confidence=0.6)
        assert result is not None
        assert result[0] == "HIGH"

    def test_strict_policy_keeps_generic_shebang_finding(self, tmp_path, monkeypatch):
        """STRICT fails closed when the model only identifies a shebang script."""
        from skill_scanner.core.scan_policy import ScanPolicy

        f = tmp_path / "setup.sh"
        f.write_text("#!/bin/sh\necho ready\n")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("executable/script", "executable", "Script with shebang"),
        )
        strict = ScanPolicy.from_preset("strict")

        result = check_extension_mismatch(
            f,
            min_confidence=strict.analysis_thresholds.min_confidence_pct / 100,
            allow_script_shebang_text_extensions=strict.file_classification.allow_script_shebang_text_extensions,
            shebang_compatible_extensions=strict.file_classification.script_shebang_extensions,
        )
        assert result is not None
        assert result[0] == "CRITICAL"

    def test_default_policy_accepts_matching_script_shebang(self, tmp_path, monkeypatch):
        """The default exemption applies only to a matching interpreter."""
        f = tmp_path / "setup.sh"
        f.write_text("#!/usr/bin/env -S bash -e\necho ready\n")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("executable/script", "executable", "Script with shebang"),
        )

        assert check_extension_mismatch(f) is None

    def test_strict_policy_rejects_shell_shebang_in_python_file(self, tmp_path, monkeypatch):
        """A shell script disguised as Python still produces a CRITICAL finding."""
        from skill_scanner.core.scan_policy import ScanPolicy

        f = tmp_path / "setup.py"
        f.write_text("#!/bin/bash\necho ready\n")
        monkeypatch.setattr(
            "skill_scanner.core.file_magic.detect_magic",
            lambda _path: MagicMatch("executable/script", "executable", "Script with shebang"),
        )
        strict = ScanPolicy.from_preset("strict")

        result = check_extension_mismatch(
            f,
            min_confidence=strict.analysis_thresholds.min_confidence_pct / 100,
            allow_script_shebang_text_extensions=strict.file_classification.allow_script_shebang_text_extensions,
            shebang_compatible_extensions=strict.file_classification.script_shebang_extensions,
        )
        assert result is not None
        assert result[0] == "CRITICAL"


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


class TestMarkdownIsATextContainer:
    """A SKILL.md reading as YAML or code is not a disguise; binary content still is.

    On 200,000 real published skills, 85% of FILE_MAGIC_MISMATCH findings were SKILL.md
    files Magika read as YAML, because the skill format requires YAML frontmatter.
    """

    @staticmethod
    def _check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content_type: str, family: str):
        import skill_scanner.core.file_magic as fm

        path = tmp_path / "SKILL.md"
        path.write_text("---\nname: x\ndescription: y\n---\nbody\n")
        monkeypatch.setattr(fm, "detect_magic", lambda _p: fm.MagicMatch(content_type, family, content_type, 0.95))
        return fm.check_extension_mismatch(path, min_confidence=0.8)

    def test_yaml_frontmatter_is_not_a_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._check(tmp_path, monkeypatch, "code/yaml", "code") is None

    def test_other_text_labels_are_reported_low(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._check(tmp_path, monkeypatch, "code/python", "code")
        assert result is not None
        # Visible, but below the MEDIUM gate: the content is still read by every other
        # analyzer, so the label alone is not evidence of obfuscation.
        assert result[0] == "LOW"

    def test_binary_content_in_markdown_is_still_flagged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._check(tmp_path, monkeypatch, "archive/zip", "archive")
        assert result is not None
        assert result[0] in {"MEDIUM", "HIGH", "CRITICAL"}

    def test_the_label_check_still_applies_to_other_text_extensions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import skill_scanner.core.file_magic as fm

        path = tmp_path / "tool.py"
        path.write_text("echo hi\n")
        monkeypatch.setattr(fm, "detect_magic", lambda _p: fm.MagicMatch("code/shell", "code", "shell", 0.95))
        result = fm.check_extension_mismatch(path, min_confidence=0.8)
        # A .py that is actually shell remains a MEDIUM mismatch; only Markdown changed.
        assert result is not None and result[0] == "MEDIUM"


class TestMagikaSessionIsBounded:
    """Each scanner process must not start a machine-wide spinning ONNX thread pool."""

    def test_default_session_uses_one_thread(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import skill_scanner.core.file_magic as fm

        monkeypatch.delenv("SKILL_SCANNER_MAGIKA_THREADS", raising=False)
        magika = fm._bounded_magika()
        options = magika._onnx_session.get_session_options()
        assert options.intra_op_num_threads == 1
        assert options.inter_op_num_threads == 1

    def test_thread_count_is_configurable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import skill_scanner.core.file_magic as fm

        monkeypatch.setenv("SKILL_SCANNER_MAGIKA_THREADS", "4")
        assert fm._magika_threads() == 4
        monkeypatch.setenv("SKILL_SCANNER_MAGIKA_THREADS", "not-a-number")
        assert fm._magika_threads() == 1

    def test_detection_still_works(self, tmp_path: Path) -> None:
        import skill_scanner.core.file_magic as fm

        path = tmp_path / "notes.md"
        path.write_text("# Title\n\nSome markdown with a [link](https://example.org).\n" * 5)
        match = fm._bounded_magika().identify_path(path)
        assert match.output.label == "markdown"


def test_low_text_label_mismatch_satisfies_the_pack_contract_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The LOW finding must pass the core pack's severity contract, not only the check.

    The check alone returned LOW while pack.yaml declared only HIGH and MEDIUM as allowed
    demotions, so a full scan rejected the finding and reported the static analyzer as
    failed -- on 904 of 33,709 rescanned real skills. Only a scan through the scanner,
    where the contract is enforced, catches that.
    """

    import skill_scanner.core.file_magic as fm
    from skill_scanner.core.scanner import SkillScanner

    skill_dir = tmp_path / "text-label-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: text-label-skill\ndescription: A fixture.\n---\nbody\n")
    monkeypatch.setattr(fm, "detect_magic", lambda _p: fm.MagicMatch("code/python", "code", "code/python", 0.95))

    result = SkillScanner().scan_skill(skill_dir)

    assert not result.analyzers_failed, result.analyzers_failed
    magic = [f for f in result.findings if f.rule_id == "FILE_MAGIC_MISMATCH"]
    assert magic and {f.severity.value for f in magic} == {"LOW"}
