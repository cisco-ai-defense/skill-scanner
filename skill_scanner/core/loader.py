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
Skill package loader and SKILL.md parser.
"""

import re
from pathlib import Path

import frontmatter

from .models import Skill, SkillFile, SkillManifest


class SkillLoadError(Exception):
    """Exception raised when skill loading fails."""

    pass


class SkillLoader:
    """Loads and parses Claude Skill, Codex Skill, and Cursor Agent Skill packages.

    Supports the Agent Skills specification format used by Claude Skills,
    OpenAI Codex Skills, and Cursor Agent Skills. Skills are structured as:
    - SKILL.md (required): YAML frontmatter + Markdown instructions
    - scripts/ (optional): Executable code (Python, Bash)
    - references/ (optional): Documentation and data files
    - assets/ (optional): Templates, images, and other resources
    """

    # File type mappings
    PYTHON_EXTENSIONS = {".py"}
    BASH_EXTENSIONS = {".sh", ".bash"}
    MARKDOWN_EXTENSIONS = {".md", ".markdown"}
    BINARY_EXTENSIONS = {".exe", ".so", ".dylib", ".dll", ".bin"}

    def __init__(self, max_file_size_mb: int = 10):
        """
        Initialize skill loader.

        Args:
            max_file_size_mb: Maximum file size to read in MB
        """
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

    def load_skill(self, skill_directory: Path) -> Skill:
        """
        Load a skill package from a directory.

        Args:
            skill_directory: Path to the skill directory

        Returns:
            Parsed Skill object

        Raises:
            SkillLoadError: If skill cannot be loaded
        """
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)

        if not skill_directory.exists():
            raise SkillLoadError(f"Skill directory does not exist: {skill_directory}")

        if not skill_directory.is_dir():
            raise SkillLoadError(f"Path is not a directory: {skill_directory}")

        # Find SKILL.md
        skill_md_path = skill_directory / "SKILL.md"
        if not skill_md_path.exists():
            raise SkillLoadError(f"SKILL.md not found in {skill_directory}")

        # Parse SKILL.md
        manifest, instruction_body = self._parse_skill_md(skill_md_path)

        # Discover all files in the skill package
        files = self._discover_files(skill_directory)

        # Extract referenced files from instruction body
        referenced_files = self._extract_referenced_files(instruction_body)

        return Skill(
            directory=skill_directory,
            manifest=manifest,
            skill_md_path=skill_md_path,
            instruction_body=instruction_body,
            files=files,
            referenced_files=referenced_files,
        )

    def _parse_skill_md(self, skill_md_path: Path) -> tuple[SkillManifest, str]:
        """
        Parse SKILL.md file with YAML frontmatter.

        Args:
            skill_md_path: Path to SKILL.md

        Returns:
            Tuple of (SkillManifest, instruction_body)

        Raises:
            SkillLoadError: If parsing fails
        """
        try:
            with open(skill_md_path, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise SkillLoadError(f"Failed to read SKILL.md: {e}")

        # Parse with python-frontmatter
        try:
            post = frontmatter.loads(content)
            metadata = post.metadata
            body = post.content
        except Exception as e:
            raise SkillLoadError(f"Failed to parse YAML frontmatter: {e}")

        # Validate required fields
        if "name" not in metadata:
            raise SkillLoadError("SKILL.md missing required field: name")
        if "description" not in metadata:
            raise SkillLoadError("SKILL.md missing required field: description")

        # Extract metadata field - if YAML has a 'metadata' key, use it directly
        # Otherwise, collect remaining fields as metadata
        metadata_field = None
        if "metadata" in metadata and isinstance(metadata["metadata"], dict):
            # YAML has explicit metadata key (Codex Skills format)
            metadata_field = metadata["metadata"]
        else:
            # Collect remaining fields as metadata (Claude Skills format)
            # Exclude known fields from being collected as metadata
            known_fields = [
                "name",
                "description",
                "license",
                "compatibility",
                "allowed-tools",
                "allowed_tools",
                "metadata",
                "disable-model-invocation",
                "disable_model_invocation",
            ]
            metadata_field = {k: v for k, v in metadata.items() if k not in known_fields}
            # Only set metadata if there are remaining fields
            if not metadata_field:
                metadata_field = None

        # Extract disable-model-invocation (Cursor Agent Skills format)
        # Supports both kebab-case and snake_case variants
        # Use explicit None check to properly handle `false` values
        disable_model_invocation = metadata.get("disable-model-invocation")
        if disable_model_invocation is None:
            disable_model_invocation = metadata.get("disable_model_invocation", False)

        # Create manifest
        manifest = SkillManifest(
            name=metadata["name"],
            description=metadata["description"],
            license=metadata.get("license"),
            compatibility=metadata.get("compatibility"),
            allowed_tools=metadata.get("allowed-tools") or metadata.get("allowed_tools"),
            metadata=metadata_field,
            disable_model_invocation=bool(disable_model_invocation),
        )

        return manifest, body

    def _discover_files(self, skill_directory: Path) -> list[SkillFile]:
        """
        Discover all files in the skill package.

        Args:
            skill_directory: Path to skill directory

        Returns:
            List of SkillFile objects
        """
        files = []

        for path in skill_directory.rglob("*"):
            if not path.is_file():
                continue

            # Skip hidden files and __pycache__ (relative to the skill directory)
            #
            # Important: Skills may live under hidden parent directories like `.claude/skills/`.
            # We only want to skip hidden files/folders *inside* the skill package, not its parents.
            rel_parts = path.relative_to(skill_directory).parts
            if any(part.startswith(".") for part in rel_parts):
                continue
            if "__pycache__" in rel_parts:
                continue

            relative_path = str(path.relative_to(skill_directory))
            file_type = self._determine_file_type(path)
            size_bytes = path.stat().st_size

            # Read content if not too large and not binary
            content = None
            if size_bytes < self.max_file_size_bytes and file_type != "binary":
                try:
                    with open(path, encoding="utf-8") as f:
                        content = f.read()
                except (OSError, UnicodeDecodeError):
                    # Treat as binary if can't read as text
                    file_type = "binary"

            skill_file = SkillFile(
                path=path,
                relative_path=relative_path,
                file_type=file_type,
                content=content,
                size_bytes=size_bytes,
            )
            files.append(skill_file)

        return files

    def _determine_file_type(self, path: Path) -> str:
        """
        Determine the type of a file based on extension.

        Args:
            path: File path

        Returns:
            File type string
        """
        suffix = path.suffix.lower()

        if suffix in self.PYTHON_EXTENSIONS:
            return "python"
        elif suffix in self.BASH_EXTENSIONS:
            return "bash"
        elif suffix in self.MARKDOWN_EXTENSIONS:
            return "markdown"
        elif suffix in self.BINARY_EXTENSIONS:
            return "binary"
        else:
            return "other"

    def _extract_referenced_files(self, instruction_body: str) -> list[str]:
        """
        Extract file references from instruction body.

        Looks for markdown links, common file reference patterns, directives,
        and other ways files might be referenced.

        Args:
            instruction_body: The markdown instruction text

        Returns:
            List of referenced file paths
        """
        references = []

        # Match markdown links: [text](file.md)
        markdown_links = re.findall(r"\[([^\]]+)\]\(([^\)]+)\)", instruction_body)
        for _, link in markdown_links:
            # Filter out URLs, keep relative file paths
            if not link.startswith(("http://", "https://", "ftp://", "#")):
                references.append(link)

        # Match "see FILE.md" or "refer to FILE.md" patterns
        # Use backticks or quotes to identify actual file references, avoiding false matches like "the.py"
        see_patterns = re.findall(
            r"(?:see|refer to|check|read)\s+[`'\"]([A-Za-z0-9_\-./]+\.(?:md|py|sh|txt))[`'\"]",
            instruction_body,
            re.IGNORECASE,
        )
        references.extend(see_patterns)

        # Match script execution patterns: scripts/foo.py
        script_patterns = re.findall(
            r"(?:run|execute|invoke)\s+([A-Za-z0-9_\-./]+\.(?:py|sh))", instruction_body, re.IGNORECASE
        )
        references.extend(script_patterns)

        # Match @reference: directives (common in documentation)
        reference_directives = re.findall(r"@reference:\s*([A-Za-z0-9_\-./]+)", instruction_body, re.IGNORECASE)
        references.extend(reference_directives)

        # Match include: statements
        include_patterns = re.findall(
            r"(?:include|import|load):\s*([A-Za-z0-9_\-./]+\.(?:md|py|sh|txt|yaml|json))",
            instruction_body,
            re.IGNORECASE,
        )
        references.extend(include_patterns)

        # Match file paths in code blocks that look like references
        code_file_refs = re.findall(r"(?:from|import)\s+([A-Za-z0-9_]+)\s", instruction_body)
        # Only add if it looks like a local module (not standard lib)
        for ref in code_file_refs:
            if not ref.startswith(("os", "sys", "re", "json", "yaml", "typing")):
                references.append(f"{ref}.py")

        # Match references/* or assets/* patterns
        asset_patterns = re.findall(r"(?:references|assets|templates)/([A-Za-z0-9_\-./]+)", instruction_body)
        for pattern in asset_patterns:
            references.append(f"references/{pattern}")
            references.append(f"assets/{pattern}")
            references.append(f"templates/{pattern}")

        # Return unique references
        return list(set(references))

    def extract_references_from_file(self, file_path: Path, content: str) -> list[str]:
        """
        Extract references from a specific file based on its type.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of referenced file paths
        """
        references = []
        suffix = file_path.suffix.lower()

        if suffix in (".md", ".markdown"):
            # Use the standard markdown extraction
            references.extend(self._extract_referenced_files(content))

        elif suffix == ".py":
            # Extract Python imports that might be local modules
            import_patterns = re.findall(r"^from\s+([A-Za-z0-9_.]+)\s+import", content, re.MULTILINE)
            relative_imports = re.findall(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", content, re.MULTILINE)

            for imp in import_patterns:
                # Only include if it looks like a local module
                if not imp.startswith(("os", "sys", "re", "json", "pathlib", "typing", "collections")):
                    parts = imp.split(".")
                    references.append(f"{parts[0]}.py")

            for imp in relative_imports:
                if imp:
                    references.append(f"{imp}.py")

        elif suffix in (".sh", ".bash"):
            # Extract source commands
            source_patterns = re.findall(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))", content)
            references.extend(source_patterns)

        return list(set(references))


def load_skill(skill_directory: Path, max_file_size_mb: int = 10) -> Skill:
    """
    Convenience function to load a skill package.

    Args:
        skill_directory: Path to skill directory
        max_file_size_mb: Maximum file size to read

    Returns:
        Loaded Skill object
    """
    loader = SkillLoader(max_file_size_mb=max_file_size_mb)
    return loader.load_skill(skill_directory)
