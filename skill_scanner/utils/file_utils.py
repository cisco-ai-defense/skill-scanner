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
