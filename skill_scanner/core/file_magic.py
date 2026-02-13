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
File content type detection using Google Magika (AI-powered, 200+ types).

Uses Magika's deep learning model for high-accuracy content type identification,
with a fallback to classic magic byte signatures for cases where Magika returns
low-confidence results (e.g., truncated or synthetic files).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)


class MagicMatch(NamedTuple):
    """Result of a content type detection."""

    content_type: str  # e.g., "executable/elf", "image/png", "archive/zip"
    content_family: str  # e.g., "executable", "image", "archive", "code", "text"
    description: str  # e.g., "ELF executable", "PNG image"
    score: float = 1.0  # confidence score (0.0-1.0), 1.0 for legacy fallback
    mime_type: str = ""  # MIME type from Magika (e.g., "application/x-executable")


# ---------------------------------------------------------------------------
# Magika singleton
# ---------------------------------------------------------------------------

_magika_instance = None


def _get_magika():
    """Lazy-init singleton Magika instance (~100ms first call, ~5ms/file after)."""
    global _magika_instance
    if _magika_instance is None:
        from magika import Magika

        _magika_instance = Magika()
    return _magika_instance


# ---------------------------------------------------------------------------
# Map Magika groups to our content families
# ---------------------------------------------------------------------------

_MAGIKA_GROUP_TO_FAMILY: dict[str, str] = {
    "executable": "executable",
    "archive": "archive",
    "image": "image",
    "document": "document",
    "font": "font",
    "code": "code",
    "text": "text",
    "audio": "audio",
    "video": "video",
    "application": "application",
}

# Groups considered "text-like" — compatible at the family level.
# A .py file detected as 'code' and expected as 'text' is not a mismatch
# at the family level, but may still be a label-level mismatch.
_TEXT_COMPATIBLE_FAMILIES = frozenset({"text", "code"})


# ---------------------------------------------------------------------------
# Extension → expected family
# ---------------------------------------------------------------------------

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
    # Code / scripts
    ".py": "text",
    ".sh": "text",
    ".bash": "text",
    ".js": "text",
    ".ts": "text",
    ".rb": "text",
    ".pl": "text",
    ".php": "text",
    # Text / config / data
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
    # Audio
    ".mp3": "audio",
    ".wav": "audio",
    ".ogg": "audio",
    ".flac": "audio",
    # Video
    ".mp4": "video",
    ".mkv": "video",
    ".webm": "video",
    ".avi": "video",
}


# ---------------------------------------------------------------------------
# Extension → expected Magika label(s) for label-level mismatch detection
# ---------------------------------------------------------------------------

_EXTENSION_EXPECTED_LABELS: dict[str, frozenset[str]] = {
    ".py": frozenset({"python"}),
    ".sh": frozenset({"shell"}),
    ".bash": frozenset({"shell"}),
    ".js": frozenset({"javascript", "jsx"}),
    ".ts": frozenset({"typescript", "tsx"}),
    ".rb": frozenset({"ruby"}),
    ".pl": frozenset({"perl"}),
    ".php": frozenset({"php"}),
    ".json": frozenset({"json", "jsonl", "jsonc"}),
    ".yaml": frozenset({"yaml"}),
    ".yml": frozenset({"yaml"}),
    ".xml": frozenset({"xml", "svg", "rdf"}),
    ".html": frozenset({"html"}),
    ".css": frozenset({"css", "scss", "less"}),
    ".md": frozenset({"markdown"}),
    ".txt": frozenset({"txt", "txtascii", "txtutf8", "txtutf16"}),
    ".csv": frozenset({"csv", "tsv"}),
    ".rst": frozenset({"rst"}),
    ".toml": frozenset({"toml"}),
    ".ini": frozenset({"ini"}),
    ".cfg": frozenset({"ini", "txt", "txtascii", "txtutf8"}),
    ".conf": frozenset({"ini", "txt", "txtascii", "txtutf8", "shell"}),
}

# Script extensions where a shebang header is normal and not deceptive.
_DEFAULT_SHEBANG_COMPATIBLE_EXTENSIONS = frozenset(
    {
        ".py",
        ".sh",
        ".bash",
        ".js",
        ".ts",
        ".rb",
        ".pl",
        ".php",
    }
)


# ---------------------------------------------------------------------------
# Legacy magic byte fallback
# ---------------------------------------------------------------------------

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
    (0, b"RIFF", MagicMatch("image/webp", "image", "WebP image")),
    (0, b"II\x2a\x00", MagicMatch("image/tiff", "image", "TIFF image (LE)")),
    (0, b"MM\x00\x2a", MagicMatch("image/tiff", "image", "TIFF image (BE)")),
    (0, b"\x00\x00\x01\x00", MagicMatch("image/ico", "image", "ICO image")),
    # Documents
    (0, b"%PDF", MagicMatch("document/pdf", "document", "PDF document")),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", MagicMatch("document/ole", "document", "OLE/MS Office document")),
    # Java
    (0, b"\xca\xfe\xba\xbe", MagicMatch("executable/java_class", "executable", "Java class file")),
    # Python bytecode
    (0, b"\xa7\r\r\n", MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.11)")),
    (0, b"\xcb\r\r\n", MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.12)")),
    (0, b"\xef\r\r\n", MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.13)")),
    # Fonts
    (0, b"\x00\x01\x00\x00", MagicMatch("font/ttf", "font", "TrueType font")),
    (0, b"OTTO", MagicMatch("font/otf", "font", "OpenType font")),
    (0, b"wOFF", MagicMatch("font/woff", "font", "WOFF font")),
    (0, b"wOF2", MagicMatch("font/woff2", "font", "WOFF2 font")),
]


def _detect_magic_legacy(file_path: Path) -> MagicMatch | None:
    """Fallback: detect content type using classic magic byte signatures."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(300)
    except (OSError, PermissionError):
        return None
    if not header:
        return None
    return _match_magic_bytes(header)


def _detect_magic_from_bytes_legacy(data: bytes) -> MagicMatch | None:
    """Fallback: detect content type from raw bytes using classic signatures."""
    if not data:
        return None
    return _match_magic_bytes(data)


def _match_magic_bytes(data: bytes) -> MagicMatch | None:
    """Match raw bytes against known magic signatures."""
    for offset, signature, match in _MAGIC_SIGNATURES:
        if len(data) >= offset + len(signature):
            if data[offset : offset + len(signature)] == signature:
                return match
    return None


# Minimum score for Magika results to be trusted over legacy magic bytes.
# Below this threshold, we prefer legacy magic byte matches (which are
# deterministic and 100% precise for known signatures).  Magika excels at
# text/code detection (typically 0.95+), so a high floor ensures legacy
# handles truncated or synthetic binary files reliably.
_MAGIKA_CONFIDENCE_FLOOR: float = 0.85


def _magika_result_to_match(result) -> MagicMatch | None:
    """Convert a Magika result to a MagicMatch, or None if unusable."""
    if not result.ok:
        return None
    group = result.output.group
    if group in ("unknown", "inode"):
        return None
    label = result.output.label
    family = _MAGIKA_GROUP_TO_FAMILY.get(group, group)
    return MagicMatch(
        content_type=f"{group}/{label}",
        content_family=family,
        description=result.output.description,
        score=result.score,
        mime_type=result.output.mime_type,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_magic(file_path: Path) -> MagicMatch | None:
    """
    Detect the actual content type of a file.

    Uses Magika (AI-powered, 200+ types) as the primary engine. If Magika's
    confidence is below the floor threshold, classic magic byte signatures
    take priority. Falls back to low-confidence Magika results only if legacy
    finds nothing.

    Args:
        file_path: Path to the file to check

    Returns:
        MagicMatch if a content type was identified, None otherwise
    """
    magika_match: MagicMatch | None = None
    try:
        result = _get_magika().identify_path(file_path)
        magika_match = _magika_result_to_match(result)
    except Exception:
        logger.debug("Magika failed on %s, falling back to legacy", file_path)

    # Confident Magika result — use it directly
    if magika_match is not None and magika_match.score >= _MAGIKA_CONFIDENCE_FLOOR:
        return magika_match

    # Try legacy magic bytes (always reliable for strong binary signatures)
    legacy = _detect_magic_legacy(file_path)
    if legacy is not None:
        return legacy

    # Return low-confidence Magika result as last resort
    return magika_match


def detect_magic_from_bytes(data: bytes) -> MagicMatch | None:
    """
    Detect content type from raw bytes.

    Uses Magika as the primary engine, with the same confidence-floor
    fallback logic as :func:`detect_magic`.

    Args:
        data: File content bytes (at least a few hundred bytes for best results)

    Returns:
        MagicMatch if a content type was identified, None otherwise
    """
    if not data:
        return None

    magika_match: MagicMatch | None = None
    try:
        result = _get_magika().identify_bytes(data)
        magika_match = _magika_result_to_match(result)
    except Exception:
        logger.debug("Magika identify_bytes failed, falling back to legacy")

    if magika_match is not None and magika_match.score >= _MAGIKA_CONFIDENCE_FLOOR:
        return magika_match

    legacy = _detect_magic_from_bytes_legacy(data)
    if legacy is not None:
        return legacy

    return magika_match


def get_extension_family(ext: str) -> str | None:
    """
    Get the expected content family for a file extension.

    Args:
        ext: File extension (e.g., ".png", ".exe")

    Returns:
        Content family string (e.g., "image", "executable") or None if unknown
    """
    return _EXTENSION_FAMILY.get(ext.lower())


def check_extension_mismatch(
    file_path: Path,
    min_confidence: float = 0.8,
    allow_script_shebang_text_extensions: bool = True,
    shebang_compatible_extensions: set[str] | frozenset[str] | None = None,
) -> tuple[str, str, MagicMatch] | None:
    """
    Check if a file's extension mismatches its actual content type.

    Uses Magika for content detection, enabling both binary and text-format
    mismatch detection (e.g., a .py file that's actually shell, or a .json
    that's actually an executable).

    Args:
        file_path: Path to the file to check
        min_confidence: Minimum Magika confidence score to flag a mismatch
                        (0.0-1.0). Findings below this threshold are ignored
                        to avoid false positives. Does not apply to legacy
                        fallback detections (score == 1.0).

    Returns:
        Tuple of (severity, description, magic_match) if mismatch found,
        None otherwise.  Severity is one of: "CRITICAL", "HIGH", "MEDIUM"
    """
    shebang_exts = (
        set(shebang_compatible_extensions)
        if shebang_compatible_extensions is not None
        else set(_DEFAULT_SHEBANG_COMPATIBLE_EXTENSIONS)
    )

    ext = file_path.suffix.lower()
    if file_path.name.endswith(".tar.gz"):
        ext = ".tar.gz"

    expected_family = get_extension_family(ext)
    if expected_family is None:
        return None  # Unknown extension, can't compare

    magic = detect_magic(file_path)
    if magic is None:
        return None  # Can't determine actual type

    # Confidence gating: skip if Magika is uncertain (but always trust legacy
    # fallback matches which have score == 1.0)
    if magic.score < min_confidence:
        return None

    actual_family = magic.content_family

    # --- Group-level mismatch detection ---

    # Families match exactly → no group-level mismatch
    if expected_family == actual_family:
        pass  # Fall through to label-level check for text files
    # Text-compatible: both sides are text-like (text ↔ code)
    elif expected_family in _TEXT_COMPATIBLE_FAMILIES and actual_family in _TEXT_COMPATIBLE_FAMILIES:
        pass  # Fall through to label-level check
    else:
        # True group-level mismatch — apply severity rules
        return _severity_for_group_mismatch(
            file_path,
            ext,
            expected_family,
            actual_family,
            magic,
            allow_script_shebang_text_extensions=allow_script_shebang_text_extensions,
            shebang_compatible_extensions=shebang_exts,
        )

    # --- Label-level mismatch detection (text/code files only) ---
    if expected_family in _TEXT_COMPATIBLE_FAMILIES and actual_family in _TEXT_COMPATIBLE_FAMILIES:
        return _check_text_label_mismatch(file_path, ext, magic)

    return None


def _severity_for_group_mismatch(
    file_path: Path,
    ext: str,
    expected_family: str,
    actual_family: str,
    magic: MagicMatch,
    allow_script_shebang_text_extensions: bool = True,
    shebang_compatible_extensions: set[str] | frozenset[str] | None = None,
) -> tuple[str, str, MagicMatch] | None:
    """Determine severity for a group-level family mismatch."""
    name = file_path.name
    shebang_exts = (
        set(shebang_compatible_extensions)
        if shebang_compatible_extensions is not None
        else set(_DEFAULT_SHEBANG_COMPATIBLE_EXTENSIONS)
    )

    # Shebang scripts are legitimate for script-like extensions (e.g. .js with
    # "#!/usr/bin/env node"). Treat these as compatible, not deceptive.
    if (
        allow_script_shebang_text_extensions
        and expected_family in _TEXT_COMPATIBLE_FAMILIES
        and actual_family == "executable"
        and ext in shebang_exts
        and magic.content_type.startswith("executable/script")
    ):
        return None

    # Text/code extension but actually executable → CRITICAL
    if expected_family in _TEXT_COMPATIBLE_FAMILIES and actual_family == "executable":
        return (
            "CRITICAL",
            f"File '{name}' claims to be a text/code file ({ext}) but is actually "
            f"an executable ({magic.description}). This is a strong indicator of "
            f"intentional deception.",
            magic,
        )

    # Text/code extension but actually archive → HIGH
    if expected_family in _TEXT_COMPATIBLE_FAMILIES and actual_family == "archive":
        return (
            "HIGH",
            f"File '{name}' claims to be a text/code file ({ext}) but is actually "
            f"an archive ({magic.description}). This may hide embedded files.",
            magic,
        )

    # Image extension but actually executable → CRITICAL
    if expected_family == "image" and actual_family == "executable":
        return (
            "CRITICAL",
            f"File '{name}' claims to be an image ({ext}) but is actually "
            f"an executable ({magic.description}). This is a strong indicator of "
            f"intentional deception.",
            magic,
        )

    # Image extension but actually archive → HIGH
    if expected_family == "image" and actual_family == "archive":
        return (
            "HIGH",
            f"File '{name}' claims to be an image ({ext}) but is actually "
            f"an archive ({magic.description}). This may be an attempt to hide "
            f"embedded files.",
            magic,
        )

    # Document extension but actually executable → CRITICAL
    if expected_family == "document" and actual_family == "executable":
        return (
            "CRITICAL",
            f"File '{name}' claims to be a document ({ext}) but is actually "
            f"an executable ({magic.description}). This is a strong indicator of "
            f"intentional deception.",
            magic,
        )

    # Any non-text file claiming to be something it isn't with executable content
    if actual_family == "executable" and expected_family in ("image", "document", "font"):
        return (
            "CRITICAL",
            f"File '{name}' claims to be a {expected_family} ({ext}) but is actually "
            f"an executable ({magic.description}).",
            magic,
        )

    # Generic mismatch
    return (
        "MEDIUM",
        f"File '{name}' extension ({ext}, expected {expected_family}) does not match "
        f"its actual content type ({magic.description}, {actual_family}).",
        magic,
    )


def _check_text_label_mismatch(
    file_path: Path,
    ext: str,
    magic: MagicMatch,
) -> tuple[str, str, MagicMatch] | None:
    """
    Check for label-level mismatch within text/code files.

    E.g., a .py file detected as shell, or a .json file detected as XML.
    """
    expected_labels = _EXTENSION_EXPECTED_LABELS.get(ext)
    if expected_labels is None:
        return None  # No label expectation for this extension

    # Extract label from the Magika content_type (e.g., "code/shell" → "shell")
    actual_label = magic.content_type.split("/", 1)[-1] if "/" in magic.content_type else magic.content_type

    if actual_label in expected_labels:
        return None  # Label matches expectation

    # Benign aliases: e.g., .txt detected as "ini" or "markdown" is low-risk
    # Don't flag generic text detections for code files
    _BENIGN_TEXT_LABELS = frozenset(
        {
            "txt",
            "txtascii",
            "txtutf8",
            "txtutf16",
            "randomascii",
            "randomtxt",
            "empty",
        }
    )
    if actual_label in _BENIGN_TEXT_LABELS:
        return None

    name = file_path.name
    return (
        "MEDIUM",
        f"File '{name}' extension ({ext}) suggests one format but Magika detected "
        f"a different text format: {magic.description} ({actual_label}). "
        f"This may indicate content obfuscation or a misnamed file.",
        magic,
    )
