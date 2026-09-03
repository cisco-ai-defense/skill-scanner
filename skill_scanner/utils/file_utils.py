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

import os
import stat
from pathlib import Path


class FileValidationError(Exception):
    """Raised by :func:`read_text_strict` when a file is not valid UTF-8 text."""

    def __init__(
        self,
        message: str,
        *,
        size_bytes: int | None = None,
        limit_bytes: int | None = None,
    ) -> None:
        super().__init__(message)
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes


def resolve_path_within_root(
    path: str | Path,
    *,
    root: str | Path,
    must_exist: bool = True,
) -> Path:
    """Resolve *path* and require it to remain within *root*.

    Both paths are resolved through symlinks before comparison.  This helper
    is intentionally strict for package-controlled paths: absolute paths,
    ``..`` components, and symlinks are allowed only when their resolved
    target remains inside the selected package root.
    """

    raw_path = os.fspath(path)
    raw_root = os.fspath(root)
    if "\x00" in raw_path or "\x00" in raw_root:
        raise FileValidationError("Path contains a null byte")
    try:
        # CodeQL models this exact normalize-then-prefix-check sequence as a
        # safe path boundary. Keep the separator in the prefix so a sibling
        # such as ``/allowed-sibling`` cannot match ``/allowed``.
        normalized_root = os.path.normcase(os.path.realpath(os.path.expanduser(raw_root)))
        normalized_path = os.path.normcase(os.path.realpath(os.path.expanduser(raw_path)))
    except (OSError, RuntimeError, ValueError) as exc:
        raise FileValidationError(f"Failed to resolve path: {exc}") from exc
    root_prefix = normalized_root if normalized_root.endswith(os.sep) else normalized_root + os.sep
    if normalized_path == normalized_root:
        safe_path = normalized_root
    elif normalized_path.startswith(root_prefix):
        safe_path = normalized_path
    else:
        raise FileValidationError(f"Path escapes allowed root: {normalized_path}")

    resolved_root = Path(normalized_root)
    resolved_path = Path(safe_path)
    if not resolved_root.is_dir():
        raise FileValidationError(f"Path root is not a directory: {resolved_root}")
    if must_exist and not resolved_path.exists():
        raise FileValidationError(f"Path does not exist: {resolved_path}")
    return resolved_path


def read_text_strict(
    path: Path,
    *,
    max_size_bytes: int | None = None,
    root: str | Path | None = None,
) -> str:
    """Read *path* as strict UTF-8 text, rejecting binary content.

    Raises :class:`FileValidationError` when the file is too large, contains
    NUL bytes, or is not valid UTF-8.  The ``utf-8-sig`` codec is used so that
    a leading BOM is silently stripped.
    """
    try:
        candidate = (
            resolve_path_within_root(path, root=root, must_exist=True)
            if root is not None
            else Path(os.path.realpath(os.path.expanduser(os.fspath(path))))
        )
        candidate_metadata = candidate.stat()
        if not stat.S_ISREG(candidate_metadata.st_mode):
            raise FileValidationError(f"Path is not a regular file: {candidate}")
        with candidate.open("rb") as handle:
            # Reject an already-oversized file from descriptor metadata before
            # reading any package-controlled bytes. The bounded read also
            # protects against a file growing after the fstat check.
            descriptor = os.fstat(handle.fileno())
            if not stat.S_ISREG(descriptor.st_mode):
                raise FileValidationError(f"Path is not a regular file: {candidate}")
            size_bytes = descriptor.st_size
            if max_size_bytes is not None and size_bytes > max_size_bytes:
                raise FileValidationError(
                    f"{path.name} exceeds maximum size ({max_size_bytes} bytes): {path}",
                    size_bytes=size_bytes,
                    limit_bytes=max_size_bytes,
                )
            raw = handle.read() if max_size_bytes is None else handle.read(max_size_bytes + 1)
    except FileValidationError:
        raise
    except OSError as e:
        raise FileValidationError(f"Failed to read {path.name}: {e}") from e
    if max_size_bytes is not None and len(raw) > max_size_bytes:
        raise FileValidationError(
            f"{path.name} exceeds maximum size ({max_size_bytes} bytes): {path}",
            size_bytes=len(raw),
            limit_bytes=max_size_bytes,
        )
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
        max_bytes = max_size_mb * 1024 * 1024
        return read_text_strict(file_path, max_size_bytes=max_bytes)
    except (FileValidationError, OSError, UnicodeDecodeError):
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
        ".pkl": "binary",
        ".pickle": "binary",
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
