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
File magic byte detection for identifying actual file content types.

Reads the first 16 bytes of a file and compares against known magic signatures
to determine the real content type, independent of file extension.
Zero external dependencies - uses only Python stdlib.
"""

from pathlib import Path
from typing import NamedTuple


class MagicMatch(NamedTuple):
    """Result of a magic byte check."""

    content_type: str  # e.g., "executable/elf", "image/png", "archive/zip"
    content_family: str  # e.g., "executable", "image", "archive", "document"
    description: str  # e.g., "ELF executable", "PNG image"


# Magic byte signatures: (offset, bytes, MagicMatch)
# Ordered by specificity (longer/more specific patterns first)
_MAGIC_SIGNATURES: list[tuple[int, bytes, MagicMatch]] = [
    # Executables
    (0, b"\x7fELF", MagicMatch("executable/elf", "executable", "ELF executable")),
    (0, b"MZ", MagicMatch("executable/pe", "executable", "PE/Windows executable")),
    (0, b"\xfe\xed\xfa\xce", MagicMatch("executable/macho32", "executable", "Mach-O 32-bit executable")),
    (0, b"\xfe\xed\xfa\xcf", MagicMatch("executable/macho64", "executable", "Mach-O 64-bit executable")),
    (0, b"\xce\xfa\xed\xfe", MagicMatch("executable/macho32le", "executable", "Mach-O 32-bit (LE) executable")),
    (0, b"\xcf\xfa\xed\xfe", MagicMatch("executable/macho64le", "executable", "Mach-O 64-bit (LE) executable")),
    (0, b"\xca\xfe\xba\xbe", MagicMatch("executable/macho_universal", "executable", "Mach-O Universal binary")),
    (0, b"#!", MagicMatch("executable/script", "executable", "Script with shebang")),
    # Archives
    (0, b"PK\x03\x04", MagicMatch("archive/zip", "archive", "ZIP archive")),
    (0, b"PK\x05\x06", MagicMatch("archive/zip_empty", "archive", "ZIP archive (empty)")),
    (0, b"PK\x07\x08", MagicMatch("archive/zip_spanned", "archive", "ZIP archive (spanned)")),
    (0, b"\x1f\x8b", MagicMatch("archive/gzip", "archive", "GZIP compressed")),
    (0, b"BZh", MagicMatch("archive/bzip2", "archive", "BZIP2 compressed")),
    (0, b"\xfd7zXZ\x00", MagicMatch("archive/xz", "archive", "XZ compressed")),
    (0, b"7z\xbc\xaf\x27\x1c", MagicMatch("archive/7z", "archive", "7-Zip archive")),
    (0, b"Rar!\x1a\x07", MagicMatch("archive/rar", "archive", "RAR archive")),
    (0, b"ustar", MagicMatch("archive/tar", "archive", "TAR archive")),
    (257, b"ustar", MagicMatch("archive/tar", "archive", "TAR archive")),
    # Images
    (0, b"\x89PNG\r\n\x1a\n", MagicMatch("image/png", "image", "PNG image")),
    (0, b"\xff\xd8\xff", MagicMatch("image/jpeg", "image", "JPEG image")),
    (0, b"GIF87a", MagicMatch("image/gif", "image", "GIF image (87a)")),
    (0, b"GIF89a", MagicMatch("image/gif", "image", "GIF image (89a)")),
    (0, b"BM", MagicMatch("image/bmp", "image", "BMP image")),
    (0, b"RIFF", MagicMatch("image/webp", "image", "WebP image")),  # Also AVI/WAV but for our purposes
    (0, b"II\x2a\x00", MagicMatch("image/tiff", "image", "TIFF image (LE)")),
    (0, b"MM\x00\x2a", MagicMatch("image/tiff", "image", "TIFF image (BE)")),
    (0, b"\x00\x00\x01\x00", MagicMatch("image/ico", "image", "ICO image")),
    # Documents
    (0, b"%PDF", MagicMatch("document/pdf", "document", "PDF document")),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", MagicMatch("document/ole", "document", "OLE/MS Office document")),
    # Java
    (0, b"\xca\xfe\xba\xbe", MagicMatch("executable/java_class", "executable", "Java class file")),
    # Python bytecode (common magic numbers)
    (0, b"\xa7\r\r\n", MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.11)")),
    (0, b"\xcb\r\r\n", MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.12)")),
    (0, b"\xef\r\r\n", MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.13)")),
    # Fonts
    (0, b"\x00\x01\x00\x00", MagicMatch("font/ttf", "font", "TrueType font")),
    (0, b"OTTO", MagicMatch("font/otf", "font", "OpenType font")),
    (0, b"wOFF", MagicMatch("font/woff", "font", "WOFF font")),
    (0, b"wOF2", MagicMatch("font/woff2", "font", "WOFF2 font")),
]

# Extension to expected content family mapping
_EXTENSION_FAMILY: dict[str, str] = {
    # Images
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".bmp": "image",
    ".webp": "image",
    ".ico": "image",
    ".tiff": "image",
    ".tif": "image",
    ".svg": "image",
    # Archives
    ".zip": "archive",
    ".gz": "archive",
    ".tar": "archive",
    ".tgz": "archive",
    ".bz2": "archive",
    ".xz": "archive",
    ".7z": "archive",
    ".rar": "archive",
    ".jar": "archive",
    ".war": "archive",
    ".apk": "archive",
    # Documents (ZIP-based Office formats)
    ".docx": "archive",
    ".xlsx": "archive",
    ".pptx": "archive",
    ".odt": "archive",
    ".ods": "archive",
    ".odp": "archive",
    # Documents (other)
    ".pdf": "document",
    ".doc": "document",
    ".xls": "document",
    ".ppt": "document",
    # Executables
    ".exe": "executable",
    ".dll": "executable",
    ".so": "executable",
    ".dylib": "executable",
    ".bin": "executable",
    # Fonts
    ".ttf": "font",
    ".otf": "font",
    ".woff": "font",
    ".woff2": "font",
    ".eot": "font",
    # Scripts (text-based)
    ".py": "text",
    ".sh": "text",
    ".bash": "text",
    ".js": "text",
    ".ts": "text",
    ".rb": "text",
    ".pl": "text",
    ".php": "text",
    # Text
    ".md": "text",
    ".txt": "text",
    ".json": "text",
    ".yaml": "text",
    ".yml": "text",
    ".xml": "text",
    ".html": "text",
    ".css": "text",
    ".csv": "text",
    ".rst": "text",
    ".toml": "text",
    ".cfg": "text",
    ".ini": "text",
    ".conf": "text",
}


def detect_magic(file_path: Path) -> MagicMatch | None:
    """
    Detect the actual content type of a file using magic bytes.

    Args:
        file_path: Path to the file to check

    Returns:
        MagicMatch if a known signature was found, None otherwise
    """
    try:
        with open(file_path, "rb") as f:
            # Read enough bytes for all signatures (max offset + max sig length)
            header = f.read(300)  # 257 (tar offset) + some padding
    except (OSError, PermissionError):
        return None

    if not header:
        return None

    for offset, signature, match in _MAGIC_SIGNATURES:
        if len(header) >= offset + len(signature):
            if header[offset : offset + len(signature)] == signature:
                return match

    return None


def detect_magic_from_bytes(data: bytes) -> MagicMatch | None:
    """
    Detect content type from raw bytes.

    Args:
        data: First 16+ bytes of the file

    Returns:
        MagicMatch if a known signature was found, None otherwise
    """
    if not data:
        return None

    for offset, signature, match in _MAGIC_SIGNATURES:
        if len(data) >= offset + len(signature):
            if data[offset : offset + len(signature)] == signature:
                return match

    return None


def get_extension_family(ext: str) -> str | None:
    """
    Get the expected content family for a file extension.

    Args:
        ext: File extension (e.g., ".png", ".exe")

    Returns:
        Content family string (e.g., "image", "executable") or None if unknown
    """
    return _EXTENSION_FAMILY.get(ext.lower())


def check_extension_mismatch(file_path: Path) -> tuple[str, str, MagicMatch] | None:
    """
    Check if a file's extension mismatches its actual content type.

    Args:
        file_path: Path to the file to check

    Returns:
        Tuple of (severity, description, magic_match) if mismatch found, None otherwise.
        Severity is one of: "CRITICAL", "HIGH", "MEDIUM"
    """
    ext = file_path.suffix.lower()
    if file_path.name.endswith(".tar.gz"):
        ext = ".tar.gz"

    expected_family = get_extension_family(ext)
    if expected_family is None:
        return None  # Unknown extension, can't compare

    magic = detect_magic(file_path)
    if magic is None:
        return None  # Can't determine actual type

    actual_family = magic.content_family

    # No mismatch
    if expected_family == actual_family:
        return None

    # text files don't have reliable magic bytes, skip
    if expected_family == "text":
        return None

    # Determine severity based on mismatch type
    if expected_family == "image" and actual_family == "executable":
        return (
            "CRITICAL",
            f"File '{file_path.name}' claims to be an image ({ext}) but is actually "
            f"an executable ({magic.description}). This is a strong indicator of intentional deception.",
            magic,
        )
    elif expected_family == "image" and actual_family == "archive":
        return (
            "HIGH",
            f"File '{file_path.name}' claims to be an image ({ext}) but is actually "
            f"an archive ({magic.description}). This may be an attempt to hide embedded files.",
            magic,
        )
    elif expected_family == "document" and actual_family == "executable":
        return (
            "CRITICAL",
            f"File '{file_path.name}' claims to be a document ({ext}) but is actually "
            f"an executable ({magic.description}). This is a strong indicator of intentional deception.",
            magic,
        )
    elif expected_family in ("image", "document", "font") and actual_family == "executable":
        return (
            "CRITICAL",
            f"File '{file_path.name}' claims to be a {expected_family} ({ext}) but is actually "
            f"an executable ({magic.description}).",
            magic,
        )
    elif actual_family != expected_family:
        return (
            "MEDIUM",
            f"File '{file_path.name}' extension ({ext}, expected {expected_family}) does not match "
            f"its actual content type ({magic.description}, {actual_family}).",
            magic,
        )

    return None
