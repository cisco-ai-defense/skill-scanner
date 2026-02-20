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
LLM Prompt Builder.

Handles prompt construction with injection protection using random delimiters.
"""

import secrets
from pathlib import Path

from ...core.models import Skill


class PromptBuilder:
    """Builds analysis prompts with injection protection."""

    def __init__(self):
        """Initialize prompt builder and load prompts."""
        self.protection_rules = ""
        self.threat_analysis_prompt = ""
        self._load_prompts()

    def _load_prompts(self):
        """Load analysis prompts from markdown files."""
        prompts_dir = Path(__file__).parent.parent.parent / "data" / "prompts"

        try:
            protection_file = prompts_dir / "boilerplate_protection_rule_prompt.md"
            threat_file = prompts_dir / "skill_threat_analysis_prompt.md"

            if protection_file.exists():
                self.protection_rules = protection_file.read_text(encoding="utf-8")
            else:
                print(f"Warning: Protection rules file not found at {protection_file}")
                self.protection_rules = "You are a security analyst analyzing agent skills."

            if threat_file.exists():
                self.threat_analysis_prompt = threat_file.read_text(encoding="utf-8")
            else:
                print(f"Warning: Threat analysis prompt not found at {threat_file}")
                self.threat_analysis_prompt = "Analyze for security threats."

        except Exception as e:
            print(f"Warning: Failed to load prompts: {e}")
            self.protection_rules = "You are a security analyst analyzing agent skills."
            self.threat_analysis_prompt = "Analyze for security threats."

    def build_threat_analysis_prompt(
        self,
        skill_name: str,
        description: str,
        manifest_details: str,
        instruction_body: str,
        code_files: str,
        referenced_files: str,
    ) -> tuple[str, bool]:
        """
        Create threat analysis prompt with prompt injection protection.

        Uses random delimiter tags to prevent prompt injection attacks.

        Args:
            skill_name: Name of the skill
            description: Skill description
            manifest_details: YAML manifest details
            instruction_body: SKILL.md content
            code_files: Formatted code files
            referenced_files: Referenced files

        Returns:
            Tuple of (prompt, injection_detected)
        """
        # Generate random delimiter tags
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        # Build comprehensive analysis content
        analysis_content = f"""Skill Name: {skill_name}
Description: {description}

YAML Manifest Details:
{manifest_details}

Instruction Body (SKILL.md markdown):
{instruction_body}

Script Files (Python/Bash):
{code_files}

Referenced Files:
{referenced_files}
"""

        # Check for delimiter injection (security violation)
        injection_detected = start_tag in analysis_content or end_tag in analysis_content

        if injection_detected:
            print(f"WARNING: Potential prompt injection detected in skill {skill_name}")

        # Replace placeholders with random tags
        protected_rules = self.protection_rules.replace("<!---UNTRUSTED_INPUT_START--->", start_tag).replace(
            "<!---UNTRUSTED_INPUT_END--->", end_tag
        )

        # Construct full prompt
        prompt = f"""{protected_rules}

{self.threat_analysis_prompt}

{start_tag}
{analysis_content}
{end_tag}
"""

        return prompt.strip(), injection_detected

    def format_manifest(self, manifest) -> str:
        """Format YAML manifest for LLM analysis."""
        lines = []
        lines.append(f"- name: {manifest.name}")
        lines.append(f"- description: {manifest.description}")
        lines.append(f"- license: {manifest.license or 'Not specified'}")
        lines.append(f"- compatibility: {manifest.compatibility or 'Not specified'}")
        lines.append(
            f"- allowed-tools: {', '.join(manifest.allowed_tools) if manifest.allowed_tools else 'Not specified'}"
        )
        if manifest.metadata:
            lines.append(f"- additional metadata: {manifest.metadata}")
        return "\n".join(lines)

    def format_code_files(self, skill: Skill) -> str:
        """Format code files for LLM analysis."""
        lines = []

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if content:
                truncated = content[:1500]
                if len(content) > 1500:
                    truncated += f"\n... (truncated, total {len(content)} chars)"

                lines.append(f"**File: {skill_file.relative_path}**")
                lines.append("```" + skill_file.file_type)
                lines.append(truncated)
                lines.append("```")
                lines.append("")

        return "\n".join(lines) if lines else "No script files found."

    def _is_path_within_directory(self, path: Path, directory: Path) -> bool:
        """
        Check if a path is within a directory (prevents path traversal attacks).

        Args:
            path: The path to check (will be resolved)
            directory: The directory that should contain the path

        Returns:
            True if the path is within the directory, False otherwise
        """
        try:
            # Resolve both paths to absolute paths, resolving symlinks
            resolved_path = path.resolve()
            resolved_directory = directory.resolve()

            # Check if the resolved path starts with the directory path
            # Using os.path.commonpath is more robust than string comparison
            return resolved_path.is_relative_to(resolved_directory)
        except (ValueError, OSError):
            # is_relative_to raises ValueError if paths are on different drives (Windows)
            # or other path resolution issues
            return False

    def format_referenced_files(self, skill: Skill, max_file_size: int = 2000) -> str:
        """
        Format referenced files for LLM analysis, including their content.

        This is critical for detecting hidden malicious payloads in referenced
        instruction files (e.g., rules/logic.md containing curl commands).

        SECURITY: Only reads files within the skill directory to prevent
        path traversal attacks (e.g., ../../../.env exfiltration).

        Args:
            skill: The skill being analyzed
            max_file_size: Maximum characters to include per file (default 2000)

        Returns:
            Formatted string with referenced file contents
        """
        if not skill.referenced_files:
            return "No referenced files."

        lines = []
        lines.append(f"Files referenced in instructions: {', '.join(skill.referenced_files)}")
        lines.append("")

        for ref_file_path in skill.referenced_files:
            # Skip paths that look like path traversal attempts
            if ".." in ref_file_path or ref_file_path.startswith("/"):
                lines.append(f"**Referenced File: {ref_file_path}** (blocked: path traversal attempt)")
                lines.append("")
                continue

            # Try to find the file in the skill directory
            full_path = skill.directory / ref_file_path
            if not full_path.exists():
                # Try alternative locations (all within skill directory)
                alt_paths = [
                    skill.directory / "rules" / Path(ref_file_path).name,
                    skill.directory / "references" / ref_file_path,
                    skill.directory / "assets" / ref_file_path,
                    skill.directory / "templates" / ref_file_path,
                ]
                for alt in alt_paths:
                    if alt.exists():
                        full_path = alt
                        break

            if not full_path.exists():
                lines.append(f"**Referenced File: {ref_file_path}** (not found)")
                lines.append("")
                continue

            # SECURITY: Verify the resolved path is within the skill directory
            # This prevents path traversal attacks like ../../../.env
            if not self._is_path_within_directory(full_path, skill.directory):
                lines.append(f"**Referenced File: {ref_file_path}** (blocked: outside skill directory)")
                lines.append("")
                continue

            try:
                content = full_path.read_text(encoding="utf-8")

                # Truncate if too large
                truncated = content[:max_file_size]
                if len(content) > max_file_size:
                    truncated += f"\n... (truncated, total {len(content)} chars)"

                # Determine file type for syntax highlighting
                suffix = full_path.suffix.lower()
                file_type = "markdown" if suffix in (".md", ".markdown") else "text"

                lines.append(f"**Referenced File: {ref_file_path}**")
                lines.append(f"```{file_type}")
                lines.append(truncated)
                lines.append("```")
                lines.append("")

            except Exception as e:
                lines.append(f"**Referenced File: {ref_file_path}** (error reading: {e})")
                lines.append("")

        return "\n".join(lines)
