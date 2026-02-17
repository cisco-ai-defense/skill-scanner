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
Strict structural validator for Agent Skills directories.

Validates that a skill directory conforms to the Agent Skills specification
(https://agentskills.io/specification). Rejects anything not explicitly allowed.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import frontmatter

from .exceptions import SkillValidationError


class ValidationErrorCode(str, Enum):
    """Machine-readable validation error codes."""

    SYMLINK = "SYMLINK"
    HIDDEN_FILE = "HIDDEN_FILE"
    DISALLOWED_DIRECTORY = "DISALLOWED_DIRECTORY"
    DISALLOWED_FILE_EXTENSION = "DISALLOWED_FILE_EXTENSION"
    BINARY_CONTENT = "BINARY_CONTENT"
    FILE_NOT_UTF8 = "FILE_NOT_UTF8"
    MISSING_SKILL_MD = "MISSING_SKILL_MD"
    FRONTMATTER_PARSE_ERROR = "FRONTMATTER_PARSE_ERROR"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    NAME_INVALID_FORMAT = "NAME_INVALID_FORMAT"
    NAME_LENGTH_OUT_OF_RANGE = "NAME_LENGTH_OUT_OF_RANGE"
    NAME_DIR_MISMATCH = "NAME_DIR_MISMATCH"
    DESCRIPTION_EMPTY = "DESCRIPTION_EMPTY"
    DESCRIPTION_TOO_LONG = "DESCRIPTION_TOO_LONG"
    COMPATIBILITY_TOO_LONG = "COMPATIBILITY_TOO_LONG"


@dataclass
class ValidationError:
    """A single validation error."""

    code: ValidationErrorCode
    message: str
    file_path: str | None = None
    detail: str | None = None


@dataclass
class ValidationResult:
    """Result of validating a skill directory."""

    skill_directory: str
    errors: list[ValidationError] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_directory": self.skill_directory,
            "is_valid": self.is_valid,
            "errors": [
                {
                    "code": e.code.value,
                    "message": e.message,
                    "file_path": e.file_path,
                    "detail": e.detail,
                }
                for e in self.errors
            ],
        }


class SkillValidator:
    """Strict structural validator for Agent Skills directories."""

    ALLOWED_EXTENSIONS = frozenset(
        {
            ".md",
            ".py",
            ".sh",
            ".json",
            ".yaml",  # spec-defined
            ".txt",  # plain text (LICENSE.txt, etc.)
            ".js",
            ".ts",  # script languages
            ".html",
            ".css",
            ".svg",  # web assets
            ".xml",
            ".xsd",  # declarative data/schemas
        }
    )
    ALLOWED_SUBDIRS = frozenset({"scripts", "references", "assets"})
    NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$|^[a-z0-9]$")

    def validate(self, path: Path) -> ValidationResult:
        """Validate a skill directory against the Agent Skills specification.

        Args:
            path: Path to the skill directory.

        Returns:
            ValidationResult with all collected errors.
        """
        if not isinstance(path, Path):
            path = Path(path)

        result = ValidationResult(skill_directory=str(path))

        # Step 1: Directory exists and is a dir
        if not path.exists() or not path.is_dir():
            return result  # Nothing more to check

        # Step 2: Walk entries — reject hidden, disallowed dirs, disallowed extensions
        valid_files = self._validate_structure(path, result)

        # Step 3: Check file contents — reject binary and non-UTF-8
        self._validate_encoding(valid_files, path, result)

        # Step 4: Check SKILL.md exists (case-sensitive, even on case-insensitive FS)
        skill_md_path = path / "SKILL.md"
        has_skill_md = skill_md_path.is_file() and "SKILL.md" in [p.name for p in path.iterdir()]
        if not has_skill_md:
            result.errors.append(
                ValidationError(
                    code=ValidationErrorCode.MISSING_SKILL_MD,
                    message="SKILL.md not found (case-sensitive)",
                )
            )
        else:
            # Step 5: Parse and validate frontmatter
            self._validate_frontmatter(skill_md_path, path, result)

        return result

    def _validate_structure(self, root: Path, result: ValidationResult) -> list[Path]:
        """Walk directory tree and validate structure. Returns list of valid files."""
        valid_files: list[Path] = []

        for item in sorted(root.rglob("*")):
            rel = item.relative_to(root)
            parts = rel.parts

            # Check for symlinks (security risk — could escape skill directory)
            if item.is_symlink():
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.SYMLINK,
                        message=f"Symlink not allowed: {rel}",
                        file_path=str(rel),
                        detail=f"Target: {item.resolve()}",
                    )
                )
                continue

            # Check for hidden entries (any component starting with '.')
            if any(part.startswith(".") for part in parts):
                # Only report the hidden entry itself, not children
                hidden_part_idx = next(i for i, p in enumerate(parts) if p.startswith("."))
                if len(parts) == hidden_part_idx + 1 or len(parts) == 1:
                    result.errors.append(
                        ValidationError(
                            code=ValidationErrorCode.HIDDEN_FILE,
                            message=f"Hidden file or directory: {rel}",
                            file_path=str(rel),
                        )
                    )
                continue

            # Check directories
            if item.is_dir():
                # Top-level subdirectories must be in ALLOWED_SUBDIRS
                if len(parts) == 1 and parts[0] not in self.ALLOWED_SUBDIRS:
                    result.errors.append(
                        ValidationError(
                            code=ValidationErrorCode.DISALLOWED_DIRECTORY,
                            message=f"Disallowed top-level directory: {parts[0]}/",
                            file_path=str(rel),
                            detail=f"Allowed: {', '.join(sorted(self.ALLOWED_SUBDIRS))}",
                        )
                    )
                continue

            # Check file extensions
            if item.suffix.lower() not in self.ALLOWED_EXTENSIONS:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.DISALLOWED_FILE_EXTENSION,
                        message=f"Disallowed file extension: {item.suffix or '(none)'}",
                        file_path=str(rel),
                        detail=f"Allowed: {', '.join(sorted(self.ALLOWED_EXTENSIONS))}",
                    )
                )
                continue

            # File is structurally valid — check its content later
            # But skip files under disallowed directories
            if parts[0] in self.ALLOWED_SUBDIRS or len(parts) == 1:
                valid_files.append(item)

        return valid_files

    def _validate_encoding(self, files: list[Path], root: Path, result: ValidationResult) -> None:
        """Check that files are valid UTF-8 text without null bytes."""
        for file_path in files:
            rel = str(file_path.relative_to(root))
            try:
                data = file_path.read_bytes()
            except OSError:
                continue

            if b"\x00" in data:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.BINARY_CONTENT,
                        message="File contains null bytes (binary content)",
                        file_path=rel,
                    )
                )
                continue

            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.FILE_NOT_UTF8,
                        message="File is not valid UTF-8",
                        file_path=rel,
                    )
                )

    def _validate_frontmatter(self, skill_md_path: Path, root: Path, result: ValidationResult) -> None:
        """Parse SKILL.md frontmatter and validate fields."""
        try:
            content = skill_md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result.errors.append(
                ValidationError(
                    code=ValidationErrorCode.FRONTMATTER_PARSE_ERROR,
                    message="Failed to read SKILL.md",
                    file_path="SKILL.md",
                )
            )
            return

        try:
            post = frontmatter.loads(content)
            metadata = post.metadata
        except Exception as e:
            result.errors.append(
                ValidationError(
                    code=ValidationErrorCode.FRONTMATTER_PARSE_ERROR,
                    message="Failed to parse YAML frontmatter",
                    file_path="SKILL.md",
                    detail=str(e),
                )
            )
            return

        dir_name = root.name

        # Validate 'name'
        if "name" not in metadata:
            result.errors.append(
                ValidationError(
                    code=ValidationErrorCode.MISSING_REQUIRED_FIELD,
                    message="Missing required field: name",
                    file_path="SKILL.md",
                )
            )
        else:
            name = str(metadata["name"])
            if len(name) < 1 or len(name) > 64:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.NAME_LENGTH_OUT_OF_RANGE,
                        message=f"Name length {len(name)} outside allowed range 1-64",
                        file_path="SKILL.md",
                    )
                )
            if not self.NAME_PATTERN.match(name):
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.NAME_INVALID_FORMAT,
                        message="Name must be lowercase alphanumeric with single hyphens",
                        file_path="SKILL.md",
                        detail=f"Got: {name!r}",
                    )
                )
            if name != dir_name:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.NAME_DIR_MISMATCH,
                        message=f"Name {name!r} does not match directory name {dir_name!r}",
                        file_path="SKILL.md",
                    )
                )

        # Validate 'description'
        if "description" not in metadata:
            result.errors.append(
                ValidationError(
                    code=ValidationErrorCode.MISSING_REQUIRED_FIELD,
                    message="Missing required field: description",
                    file_path="SKILL.md",
                )
            )
        else:
            desc = str(metadata["description"])
            if not desc.strip():
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.DESCRIPTION_EMPTY,
                        message="Description must not be empty or whitespace-only",
                        file_path="SKILL.md",
                    )
                )
            elif len(desc) > 1024:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.DESCRIPTION_TOO_LONG,
                        message=f"Description length {len(desc)} exceeds maximum 1024",
                        file_path="SKILL.md",
                    )
                )

        # Validate optional 'compatibility'
        if "compatibility" in metadata and metadata["compatibility"] is not None:
            compat = str(metadata["compatibility"])
            if len(compat) > 500:
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.COMPATIBILITY_TOO_LONG,
                        message=f"Compatibility length {len(compat)} exceeds maximum 500",
                        file_path="SKILL.md",
                    )
                )

        # Validate optional 'metadata'
        if "metadata" in metadata and metadata["metadata"] is not None:
            if not isinstance(metadata["metadata"], dict):
                result.errors.append(
                    ValidationError(
                        code=ValidationErrorCode.FRONTMATTER_PARSE_ERROR,
                        message="metadata field must be a dict",
                        file_path="SKILL.md",
                    )
                )


def validate_skill(path: Path) -> ValidationResult:
    """Convenience function to validate a skill directory.

    Args:
        path: Path to the skill directory.

    Returns:
        ValidationResult with all collected errors.
    """
    return SkillValidator().validate(path)


def validate_skill_or_raise(path: Path) -> ValidationResult:
    """Validate a skill directory, raising on failure.

    Args:
        path: Path to the skill directory.

    Returns:
        ValidationResult if valid.

    Raises:
        SkillValidationError: If the skill directory is invalid.
    """
    result = validate_skill(path)
    if not result.is_valid:
        messages = [e.message for e in result.errors]
        raise SkillValidationError(
            f"Skill validation failed with {len(result.errors)} error(s): " + "; ".join(messages)
        )
    return result
