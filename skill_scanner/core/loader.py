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

import logging
import re
import sys
from pathlib import Path

import frontmatter

from ..utils.file_utils import get_file_type
from .exceptions import SkillLoadError
from .models import Skill, SkillFile, SkillManifest

logger = logging.getLogger(__name__)


class SkillLoader:
    """Loads and parses Agent Skill packages.

    Supports the Agent Skills specification format used by
    OpenAI Codex Skills and Cursor Agent Skills. Skills are structured as:
    - SKILL.md (required): YAML frontmatter + Markdown instructions
    - scripts/ (optional): Executable code (Python, Bash)
    - references/ (optional): Documentation and data files
    - assets/ (optional): Templates, images, and other resources
    """

    def __init__(self, max_file_size_mb: int = 10, *, max_file_size_bytes: int | None = None):
        """
        Initialize skill loader.

        Args:
            max_file_size_mb: Maximum file size to read in MB (used if max_file_size_bytes not set)
            max_file_size_bytes: Maximum file size in bytes (takes precedence over max_file_size_mb)
        """
        if max_file_size_bytes is not None:
            self.max_file_size_bytes = max_file_size_bytes
        else:
            self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

    def load_skill(
        self,
        skill_directory: str | Path,
        *,
        lenient: bool = False,
        skill_file: str | None = None,
    ) -> Skill:
        """
        Load a skill package from a directory.

        Args:
            skill_directory: Path to the skill directory
            lenient: When True, tolerate missing/malformed fields and return
                a best-effort Skill instead of raising ``SkillLoadError``.
                When ``SKILL.md`` is absent and *lenient* is True, the loader
                falls back to scanning ``.md`` files in the directory as
                instruction bodies (supports non-Codex/Cursor formats such as
                Claude Code ``.claude/commands/*.md``).
            skill_file: Optional custom metadata filename to use instead of
                ``SKILL.md`` (e.g. ``"README.md"``).

        Returns:
            Parsed Skill object

        Raises:
            SkillLoadError: If skill cannot be loaded (strict mode only)
        """
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)

        if not skill_directory.exists():
            raise SkillLoadError(f"Skill directory does not exist: {skill_directory}")

        if not skill_directory.is_dir():
            raise SkillLoadError(f"Path is not a directory: {skill_directory}")

        # Find the skill metadata file
        if skill_file:
            skill_md_path = skill_directory / skill_file
            if not skill_md_path.exists():
                raise SkillLoadError(f"{skill_file} not found in {skill_directory}")
        else:
            skill_md_path = skill_directory / "SKILL.md"

        if skill_md_path.exists():
            # Standard path: parse the metadata file
            manifest, instruction_body = self._parse_skill_md(skill_md_path, lenient=lenient)
        elif lenient:
            # Lenient fallback: no SKILL.md, synthesize from .md files in the directory
            skill_md_path, manifest, instruction_body = self._synthesize_from_md_files(skill_directory)
        else:
            raise SkillLoadError(f"SKILL.md not found in {skill_directory}")

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

    def _synthesize_from_md_files(self, skill_directory: Path) -> tuple[Path, SkillManifest, str]:
        """Synthesize a Skill from ``.md`` files when ``SKILL.md`` is absent.

        Scans the directory for markdown files, concatenates their content as the
        instruction body, and builds a best-effort manifest from the directory name.

        Returns:
            Tuple of (primary_md_path, SkillManifest, instruction_body)

        Raises:
            SkillLoadError: If no ``.md`` files are found in the directory.
        """
        md_files = sorted(skill_directory.glob("*.md"))
        if not md_files:
            raise SkillLoadError(
                f"No SKILL.md and no .md files found in {skill_directory} "
                f"(lenient mode requires at least one markdown file)"
            )

        logger.warning(
            "SKILL.md not found in %s; falling back to %d .md file(s) (lenient mode)",
            skill_directory,
            len(md_files),
        )

        # Use the first .md file as the primary path
        primary_md = md_files[0]

        # Try to parse frontmatter from the primary file.
        # _parse_skill_md validates UTF-8 and rejects binary content;
        # let those errors propagate — a binary .md file should never
        # silently become an empty skill, even in lenient mode.
        try:
            manifest, body = self._parse_skill_md(primary_md, lenient=True)
        except SkillLoadError as e:
            err_msg = str(e)
            if "null bytes" in err_msg or "not valid UTF-8" in err_msg:
                raise
            # Frontmatter parsing failed but content is valid text — use raw
            try:
                body = primary_md.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                body = ""
            manifest = SkillManifest(
                name=skill_directory.name,
                description="(no description)",
            )

        # Append content from remaining .md files
        extra_bodies: list[str] = []
        for md_file in md_files[1:]:
            try:
                extra_bodies.append(md_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                continue
        if extra_bodies:
            body = body + "\n\n" + "\n\n".join(extra_bodies)

        return primary_md, manifest, body

    def _parse_skill_md(self, skill_md_path: Path, *, lenient: bool = False) -> tuple[SkillManifest, str]:
        """
        Parse SKILL.md file with YAML frontmatter.

        Args:
            skill_md_path: Path to SKILL.md
            lenient: When True, fill missing fields with defaults instead of
                raising ``SkillLoadError``.

        Returns:
            Tuple of (SkillManifest, instruction_body)

        Raises:
            SkillLoadError: If parsing fails (strict mode only)
        """
        try:
            raw = skill_md_path.read_bytes()
        except OSError as e:
            raise SkillLoadError(f"Failed to read {skill_md_path.name}: {e}")

        if b"\x00" in raw:
            raise SkillLoadError(
                f"{skill_md_path.name} contains null bytes (binary content); "
                f"skill metadata files must be valid UTF-8 text"
            )

        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise SkillLoadError(
                f"{skill_md_path.name} is not valid UTF-8: {e}; skill metadata files must be valid UTF-8 text"
            )

        # Parse with python-frontmatter
        try:
            post = frontmatter.loads(content)
            metadata = post.metadata
            body = post.content
        except Exception as e:
            if lenient:
                logger.warning("Failed to parse YAML frontmatter in %s: %s – using raw body", skill_md_path, e)
                metadata = {}
                body = content
            else:
                raise SkillLoadError(f"Failed to parse YAML frontmatter: {e}")

        # Validate required fields (lenient: fill defaults)
        if "name" not in metadata:
            if lenient:
                metadata["name"] = skill_md_path.parent.name
                logger.warning("SKILL.md missing 'name'; using directory name: %s", metadata["name"])
            else:
                raise SkillLoadError("SKILL.md missing required field: name")
        if "description" not in metadata:
            if lenient:
                metadata["description"] = "(no description)"
                logger.warning("SKILL.md missing 'description'; using placeholder")
            else:
                raise SkillLoadError("SKILL.md missing required field: description")

        # Extract metadata field - if YAML has a 'metadata' key, use it directly
        # Otherwise, collect remaining fields as metadata
        metadata_field = None
        if "metadata" in metadata and isinstance(metadata["metadata"], dict):
            # YAML has explicit metadata key (Codex Skills format)
            metadata_field = metadata["metadata"]
        else:
            # Collect remaining fields as metadata (Agent Skills format)
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

        # Coerce name/description to strings (YAML may parse nested mappings)
        raw_name = metadata["name"]
        name = raw_name if isinstance(raw_name, str) else str(raw_name)
        raw_desc = metadata["description"]
        description = raw_desc if isinstance(raw_desc, str) else str(raw_desc)

        # Create manifest
        manifest = SkillManifest(
            name=name,
            description=description,
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
        skill_root = skill_directory.resolve()

        for path in skill_directory.rglob("*"):
            if not path.is_file():
                continue
            if path.is_symlink():
                continue
            try:
                resolved = path.resolve()
                if not resolved.is_relative_to(skill_root):
                    continue
            except (OSError, ValueError):
                continue

            # Skip .git/ directory only (version control metadata, not an attack vector).
            # All other hidden files and __pycache__ are now discovered so they can be
            # flagged and scanned by downstream analyzers.
            #
            # Important: Skills may live under hidden parent directories like `.claude/skills/`.
            # We only want to skip .git *inside* the skill package, not its parents.
            rel_parts = path.relative_to(skill_directory).parts
            if any(part == ".git" for part in rel_parts):
                continue

            relative_path = str(path.relative_to(skill_directory))
            file_type = get_file_type(path)
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

    def _local_py_module_names_from_import_lines(self, text: str) -> list[str]:
        """Return top-level module names in *text* that look like real Python imports.

        Avoids matching English prose such as "read from the file" or "import the module"
        (which previously produced a bogus ``the.py`` reference).
        """
        names: list[str] = []

        # ``from x[.y] import …`` and ``from .x import …``
        for m in re.finditer(
            r"from\s+(\.?[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\s+import\b",
            text,
        ):
            mod_path = m.group(1)
            if mod_path.startswith("."):
                rest = mod_path.lstrip(".")
                top = rest.split(".")[0] if rest else ""
            else:
                top = mod_path.split(".")[0]
            if top:
                names.append(top)

        # ``import x`` / ``import x, y`` — only at line start (optional indent / markdown list marker)
        for m in re.finditer(r"(?m)^[ \t]*(?:[-*+][ \t]+)?import[ \t]+([^\\\n#;]+)", text):
            tail = m.group(1).strip()
            tail = tail.split("#")[0].strip()
            for part in tail.split(","):
                part = part.strip()
                if not part:
                    continue
                part = re.split(r"\s+as\s+", part, maxsplit=1)[0].strip()
                mod = part.split(".")[0].strip()
                if mod and re.fullmatch(r"[A-Za-z0-9_]+", mod):
                    names.append(mod)

        return names

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
                if ".." not in link and not link.startswith("/"):
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

        # Infer local *.py names from Python import syntax (strict — not bare "from|import" tokens).
        # A loose pattern like ``from (\w+)`` matches English ("from the documentation") and
        # yields false positives such as ``the.py``.
        code_file_refs = self._local_py_module_names_from_import_lines(instruction_body)
        stdlib_names = getattr(sys, "stdlib_module_names", set())
        KNOWN_THIRD_PARTY = {
            "requests",
            "numpy",
            "pandas",
            "flask",
            "django",
            "fastapi",
            "pydantic",
            "boto3",
            "httpx",
            "aiohttp",
            "celery",
            "sqlalchemy",
            "pytest",
            "click",
            "rich",
            "typer",
            "litellm",
            "openai",
            "anthropic",
        }
        skip_modules = stdlib_names | KNOWN_THIRD_PARTY
        for ref in code_file_refs:
            if ref.lower() not in skip_modules:
                references.append(f"{ref}.py")

        # Match references/* or assets/* patterns
        asset_patterns = re.findall(r"(?:references|assets|templates)/([A-Za-z0-9_\-./]+)", instruction_body)
        for pattern in asset_patterns:
            references.append(f"references/{pattern}")
            references.append(f"assets/{pattern}")
            references.append(f"templates/{pattern}")

        # Filter out any references with path traversal sequences
        return list({r for r in references if ".." not in r and not r.startswith("/")})

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

            stdlib_names = getattr(sys, "stdlib_module_names", set())
            _known_3p = {
                "requests",
                "numpy",
                "pandas",
                "flask",
                "django",
                "fastapi",
                "pydantic",
                "boto3",
                "httpx",
                "aiohttp",
                "celery",
                "sqlalchemy",
                "pytest",
                "click",
                "rich",
                "typer",
                "litellm",
                "openai",
                "anthropic",
            }
            skip_modules = stdlib_names | _known_3p
            for imp in import_patterns:
                top_module = imp.split(".")[0]
                if top_module.lower() not in skip_modules:
                    references.append(f"{top_module}.py")

            for imp in relative_imports:
                if imp:
                    references.append(f"{imp}.py")

        elif suffix in (".sh", ".bash"):
            # Extract source commands
            source_patterns = re.findall(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))", content)
            references.extend(source_patterns)

        # Filter out any references with path traversal sequences
        return list({r for r in references if ".." not in r and not r.startswith("/")})


def load_skill(
    skill_directory: str | Path, max_file_size_mb: int = 10, *, max_file_size_bytes: int | None = None
) -> Skill:
    """
    Convenience function to load a skill package.

    Args:
        skill_directory: Path to skill directory
        max_file_size_mb: Maximum file size to read in MB (used if max_file_size_bytes not set)
        max_file_size_bytes: Maximum file size in bytes (takes precedence over max_file_size_mb)

    Returns:
        Loaded Skill object
    """
    loader = SkillLoader(max_file_size_mb=max_file_size_mb, max_file_size_bytes=max_file_size_bytes)
    return loader.load_skill(skill_directory)
