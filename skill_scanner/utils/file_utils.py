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
File utility functions.
"""

from pathlib import Path


class FileValidationError(Exception):
    """Raised by :func:`read_text_strict` when a file is not valid UTF-8 text."""


def read_text_strict(
    path: Path,
    *,
    max_size_bytes: int | None = None,
) -> str:
    """Read *path* as strict UTF-8 text, rejecting binary content.

    Raises :class:`FileValidationError` when the file is too large, contains
    NUL bytes, or is not valid UTF-8.  The ``utf-8-sig`` codec is used so that
    a leading BOM is silently stripped.
    """
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise FileValidationError(f"Failed to read {path.name}: {e}") from e
    if max_size_bytes is not None and len(raw) > max_size_bytes:
        raise FileValidationError(f"{path.name} exceeds maximum size ({max_size_bytes} bytes): {path}")
    if b"\x00" in raw:
        raise FileValidationError(f"{path.name} contains null bytes (binary content is not allowed): {path}")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise FileValidationError(f"{path.name} is not valid UTF-8: {path} ({e})") from e


def read_file_safe(file_path: Path, max_size_mb: int = 10) -> str | None:
    """
    Safely read a file with size limit.

    Args:
        file_path: Path to file
        max_size_mb: Maximum file size in MB

    Returns:
        File content or None if unreadable
    """
    try:
        size_bytes = file_path.stat().st_size
        max_bytes = max_size_mb * 1024 * 1024

        if size_bytes > max_bytes:
            return None

        with open(file_path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def get_file_type(file_path: Path) -> str:
    """
    Determine file type from extension.

    Args:
        file_path: Path to file

    Returns:
        File type string
    """
    suffix = file_path.suffix.lower()

    type_mapping = {
        ".py": "python",
        ".sh": "bash",
        ".bash": "bash",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".md": "markdown",
        ".markdown": "markdown",
        ".exe": "binary",
        ".so": "binary",
        ".dylib": "binary",
        ".dll": "binary",
        ".bin": "binary",
    }

    return type_mapping.get(suffix, "other")


def is_binary_file(file_path: Path) -> bool:
    """
    Check if file is binary.

    Args:
        file_path: Path to file

    Returns:
        True if binary
    """
    return get_file_type(file_path) == "binary"
