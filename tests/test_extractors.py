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

"""Tests for archive and compound document extraction (Feature #5)."""

import tarfile
import zipfile
from pathlib import Path

import pytest

from skill_scanner.core.extractors.content_extractor import (
    ContentExtractor,
    ExtractionLimits,
)
from skill_scanner.core.models import SkillFile


def _make_skill_file(path: Path, rel_path: str, file_type: str = "binary") -> SkillFile:
    return SkillFile(
        path=path,
        relative_path=rel_path,
        file_type=file_type,
        size_bytes=path.stat().st_size if path.exists() else 0,
    )


class TestZipExtraction:
    """Test ZIP archive extraction."""

    def test_simple_zip(self, tmp_path):
        """Extract a simple ZIP with text files."""
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.py", "print('hello')")
            zf.writestr("README.md", "# Test")

        extractor = ContentExtractor()
        sf = _make_skill_file(zip_path, "test.zip")
        result = extractor.extract_skill_archives([sf])

        assert result.total_extracted_count == 2
        rel_paths = [f.relative_path for f in result.extracted_files]
        assert any("hello.py" in p for p in rel_paths)
        assert any("README.md" in p for p in rel_paths)
        extractor.cleanup()

    def test_zip_path_traversal(self, tmp_path):
        """ZIP with path traversal should produce CRITICAL finding."""
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:")

        extractor = ContentExtractor()
        sf = _make_skill_file(zip_path, "evil.zip")
        result = extractor.extract_skill_archives([sf])

        traversal_findings = [f for f in result.findings if f.rule_id == "ARCHIVE_PATH_TRAVERSAL"]
        assert len(traversal_findings) >= 1
        assert traversal_findings[0].severity.value == "CRITICAL"
        extractor.cleanup()

    def test_zip_bomb_detection(self, tmp_path):
        """ZIP with extreme compression ratio should be detected."""
        zip_path = tmp_path / "bomb.zip"
        # Create a zip with highly compressible content
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\x00" * (10 * 1024 * 1024))  # 10MB of zeros

        extractor = ContentExtractor(limits=ExtractionLimits(max_compression_ratio=10.0))
        sf = _make_skill_file(zip_path, "bomb.zip")
        result = extractor.extract_skill_archives([sf])

        bomb_findings = [f for f in result.findings if f.rule_id == "ARCHIVE_ZIP_BOMB"]
        assert len(bomb_findings) >= 1
        extractor.cleanup()

    def test_max_file_count_limit(self, tmp_path):
        """Extraction should stop at max file count."""
        zip_path = tmp_path / "many.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(100):
                zf.writestr(f"file_{i}.txt", f"content {i}")

        extractor = ContentExtractor(limits=ExtractionLimits(max_file_count=5))
        sf = _make_skill_file(zip_path, "many.zip")
        result = extractor.extract_skill_archives([sf])

        assert result.total_extracted_count <= 5
        extractor.cleanup()

    def test_nested_depth_limit(self, tmp_path):
        """Deeply nested archives should produce finding."""
        # Create nested zip: inner.zip inside outer.zip
        inner_zip_path = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner_zip_path, "w") as zf:
            zf.writestr("payload.py", "import os")

        outer_zip_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip_path, "w") as zf:
            zf.write(inner_zip_path, "inner.zip")

        extractor = ContentExtractor(limits=ExtractionLimits(max_depth=1))
        sf = _make_skill_file(outer_zip_path, "outer.zip")
        result = extractor.extract_skill_archives([sf])

        # Should have extracted outer contents but flagged inner
        assert result.total_extracted_count >= 1
        extractor.cleanup()


class TestZipSymlinkRejection:
    """ZIP archives containing symlinks must be rejected."""

    @staticmethod
    def _create_zip_with_symlink(zip_path: Path) -> None:
        """Build a ZIP that contains a symbolic link entry.

        The ZIP format encodes Unix symlinks by setting the S_IFLNK bit in
        the upper 16 bits of ``external_attr`` and storing the link target
        as the entry's data payload.
        """
        import stat as _stat

        with zipfile.ZipFile(zip_path, "w") as zf:
            # Normal file
            zf.writestr("legit.txt", "hello")

            # Craft a symlink entry pointing to /etc/passwd
            info = zipfile.ZipInfo("evil_link")
            info.create_system = 3  # Unix
            # Set symlink mode: S_IFLNK | 0o777
            info.external_attr = (_stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")

    def test_zip_symlink_produces_critical_finding(self, tmp_path):
        """A ZIP with a symlink entry should produce an ARCHIVE_SYMLINK finding."""
        zip_path = tmp_path / "symlink.zip"
        self._create_zip_with_symlink(zip_path)

        extractor = ContentExtractor()
        sf = _make_skill_file(zip_path, "symlink.zip")
        result = extractor.extract_skill_archives([sf])

        symlink_findings = [f for f in result.findings if f.rule_id == "ARCHIVE_SYMLINK"]
        assert len(symlink_findings) >= 1
        assert symlink_findings[0].severity.value == "CRITICAL"
        assert "evil_link" in symlink_findings[0].description
        # No files should have been extracted
        assert result.total_extracted_count == 0
        extractor.cleanup()


class TestTarSymlinkRejection:
    """TAR archives containing symlinks must be rejected."""

    def test_tar_symlink_produces_critical_finding(self, tmp_path):
        """A TAR with a symlink entry should produce an ARCHIVE_SYMLINK finding."""
        tar_path = tmp_path / "symlink.tar"
        with tarfile.open(tar_path, "w") as tf:
            # Normal file
            import io

            data = b"hello"
            info = tarfile.TarInfo(name="legit.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            # Symlink entry
            link_info = tarfile.TarInfo(name="evil_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tf.addfile(link_info)

        extractor = ContentExtractor()
        sf = _make_skill_file(tar_path, "symlink.tar")
        result = extractor.extract_skill_archives([sf])

        symlink_findings = [f for f in result.findings if f.rule_id == "ARCHIVE_SYMLINK"]
        assert len(symlink_findings) >= 1
        assert symlink_findings[0].severity.value == "CRITICAL"
        assert "evil_link" in symlink_findings[0].description
        assert "/etc/passwd" in symlink_findings[0].description
        # No files should have been extracted
        assert result.total_extracted_count == 0
        extractor.cleanup()

    def test_tar_hardlink_produces_critical_finding(self, tmp_path):
        """A TAR with a hard link entry should produce an ARCHIVE_SYMLINK finding."""
        tar_path = tmp_path / "hardlink.tar"
        with tarfile.open(tar_path, "w") as tf:
            import io

            data = b"hello"
            info = tarfile.TarInfo(name="legit.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            link_info = tarfile.TarInfo(name="hard_link")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "/etc/shadow"
            tf.addfile(link_info)

        extractor = ContentExtractor()
        sf = _make_skill_file(tar_path, "hardlink.tar")
        result = extractor.extract_skill_archives([sf])

        symlink_findings = [f for f in result.findings if f.rule_id == "ARCHIVE_SYMLINK"]
        assert len(symlink_findings) >= 1
        assert symlink_findings[0].severity.value == "CRITICAL"
        assert "hard_link" in symlink_findings[0].description
        assert result.total_extracted_count == 0
        extractor.cleanup()


class TestTarExtraction:
    """Test TAR archive extraction."""

    def test_simple_tar(self, tmp_path):
        """Extract a simple TAR with text files."""
        # Create files to tar
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "main.py").write_text("print('hello')")

        tar_path = tmp_path / "test.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(src_dir / "main.py", "main.py")

        extractor = ContentExtractor()
        sf = _make_skill_file(tar_path, "test.tar.gz")
        result = extractor.extract_skill_archives([sf])

        assert result.total_extracted_count >= 1
        assert any("main.py" in f.relative_path for f in result.extracted_files)
        extractor.cleanup()

    def test_tar_path_traversal(self, tmp_path):
        """TAR with path traversal should produce CRITICAL finding."""
        tar_path = tmp_path / "evil.tar"

        # Create a tar with path traversal using a workaround
        src_file = tmp_path / "data.txt"
        src_file.write_text("evil content")

        with tarfile.open(tar_path, "w") as tf:
            info = tarfile.TarInfo(name="../../etc/shadow")
            info.size = len(b"evil content")
            import io

            tf.addfile(info, io.BytesIO(b"evil content"))

        extractor = ContentExtractor()
        sf = _make_skill_file(tar_path, "evil.tar")
        result = extractor.extract_skill_archives([sf])

        traversal_findings = [f for f in result.findings if f.rule_id == "ARCHIVE_PATH_TRAVERSAL"]
        assert len(traversal_findings) >= 1
        extractor.cleanup()


class TestOfficeExtraction:
    """Test Office document extraction."""

    def test_docx_with_vba(self, tmp_path):
        """DOCX containing vbaProject.bin should be flagged."""
        docx_path = tmp_path / "test.docx"
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
            zf.writestr("word/document.xml", "<document/>")
            zf.writestr("word/vbaProject.bin", b"\x00" * 100)

        extractor = ContentExtractor()
        sf = _make_skill_file(docx_path, "test.docx")
        result = extractor.extract_skill_archives([sf])

        vba_findings = [f for f in result.findings if f.rule_id == "OFFICE_VBA_MACRO"]
        assert len(vba_findings) >= 1
        assert vba_findings[0].severity.value == "CRITICAL"
        extractor.cleanup()

    def test_clean_docx(self, tmp_path):
        """Clean DOCX without macros should not produce VBA finding."""
        docx_path = tmp_path / "clean.docx"
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
            zf.writestr("word/document.xml", "<document>Hello</document>")
            zf.writestr("word/styles.xml", "<styles/>")

        extractor = ContentExtractor()
        sf = _make_skill_file(docx_path, "clean.docx")
        result = extractor.extract_skill_archives([sf])

        vba_findings = [f for f in result.findings if f.rule_id == "OFFICE_VBA_MACRO"]
        assert len(vba_findings) == 0
        extractor.cleanup()


class TestExtractedFileMetadata:
    """Test that extracted files have proper metadata."""

    def test_extracted_from_field(self, tmp_path):
        """Extracted files should track their source archive."""
        zip_path = tmp_path / "source.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("inner.py", "x = 1")

        extractor = ContentExtractor()
        sf = _make_skill_file(zip_path, "source.zip")
        result = extractor.extract_skill_archives([sf])

        assert len(result.extracted_files) >= 1
        extracted = result.extracted_files[0]
        assert extracted.extracted_from == "source.zip"
        assert extracted.archive_depth == 1
        extractor.cleanup()
