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

import hashlib
import logging
import re
import secrets
from pathlib import Path

from ...core.models import Skill

logger = logging.getLogger(__name__)

_IMPORT_LINE = re.compile(
    r"^\s*(?:from\s+[\w.]+\s+import\b|import\s+[\w.]+|"
    r"(?:const|let|var)\s+\w+\s*=\s*require\s*\(|require\s*\(|use\s+[\w:]+)",
    re.IGNORECASE,
)
_HIGH_RISK_LINE = re.compile(
    r"\b(?:subprocess\s*\.\s*\w+|os\s*\.\s*(?:system|popen|exec\w*)|"
    r"socket\s*\.\s*\w+|requests?\s*\.\s*\w+|urllib\s*\.\s*\w+|"
    r"httpx\s*\.\s*\w+|aiohttp\s*\.\s*\w+|ftplib\s*\.\s*\w+|"
    r"smtplib\s*\.\s*\w+|pickle\s*\.\s*\w+|marshal\s*\.\s*\w+|"
    r"ctypes\s*\.\s*\w+|curl|wget|eval|exec|compile|__import__|urlopen|popen|system)\b",
    re.IGNORECASE,
)


def source_evidence_id(path: str) -> str:
    """Return a stable opaque identifier for one package artifact."""

    normalized = path.replace("\\", "/").lstrip("/")[:1024]
    digest = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"SRC:{digest}"


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
                logger.warning("Protection rules file not found at %s", protection_file)
                self.protection_rules = "You are a security analyst analyzing agent skills."

            if threat_file.exists():
                self.threat_analysis_prompt = threat_file.read_text(encoding="utf-8")
            else:
                logger.warning("Threat analysis prompt not found at %s", threat_file)
                self.threat_analysis_prompt = "Analyze for security threats."

        except Exception as e:
            logger.warning("Failed to load prompts: %s", e)
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
        *,
        enrichment_context: str | None = None,
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
            enrichment_context: Optional pre-computed context from other analyzers
                (file inventory, magic mismatches, static findings) to improve
                LLM analysis quality.

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

YAML Manifest Details [evidence_id={source_evidence_id("MANIFEST")}]:
{manifest_details}

Instruction Body (SKILL.md markdown) [evidence_id={source_evidence_id("SKILL.md")}]:
{instruction_body}

Script Files (Python/Bash):
{code_files}

Referenced Files:
{referenced_files}
"""

        # Add enrichment context if available
        if enrichment_context:
            analysis_content += f"""
TRUSTED_STRUCTURED_PRE_SCAN_CONTEXT_JSON:
{enrichment_context}
"""

        # Check for delimiter injection (security violation)
        injection_detected = start_tag in analysis_content or end_tag in analysis_content

        if injection_detected:
            logger.warning("Potential prompt injection detected in skill %s", skill_name)

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

    def format_code_files(
        self,
        skill: Skill,
        max_file_chars: int = 15_000,
        max_total_chars: int = 100_000,
        *,
        included_evidence_ids: set[str] | None = None,
    ) -> tuple[str, list[dict]]:
        """Format code files for LLM analysis with budget gating.

        Files that fit within the per-file and total budget are included in
        full. Oversized files contribute bounded, line-numbered excerpts when
        useful code can be selected; the caller is told that the analysis is
        partial.

        Args:
            skill: The skill being analyzed.
            max_file_chars: Per-file threshold for full inclusion and maximum excerpt size.
            max_total_chars: Remaining total character budget across all
                content sent to the LLM.
            included_evidence_ids: Optional set populated with IDs for files
                whose content is included in the returned text.

        Returns:
            Tuple of (formatted_text, budget_findings) where each dict has
            ``path``, ``size``, ``reason``, and ``threshold_name``. Partial
            entries also include ``partial`` and ``included_chars``.
        """
        lines: list[str] = []
        skipped: list[dict] = []
        total_chars = 0

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if not content:
                continue

            file_size = len(content)
            evidence_id = source_evidence_id(str(skill_file.relative_path))
            opening_fence = "```" + skill_file.file_type
            closing_fence = "```"
            full_header = f"**File: {skill_file.relative_path} [evidence_id={evidence_id}]**"
            partial_header = (
                f"**File: {skill_file.relative_path} [evidence_id={evidence_id}] "
                "(selected excerpts; original line numbers)**"
            )

            def rendered_block_size(header: str, body_chars: int) -> int:
                line_count = 5
                newline_count = line_count if lines else line_count - 1
                return len(header) + len(opening_fence) + body_chars + len(closing_fence) + newline_count

            per_file_exceeded = file_size > max_file_chars
            full_block_chars = rendered_block_size(full_header, file_size)
            total_exceeded = total_chars + full_block_chars > max_total_chars
            if per_file_exceeded or total_exceeded:
                remaining_total_budget = max(0, max_total_chars - total_chars)
                excerpt_framing_chars = rendered_block_size(partial_header, 0)
                remaining_excerpt_budget = max(0, remaining_total_budget - excerpt_framing_chars)
                remaining_budget = min(max_file_chars, remaining_excerpt_budget)
                line_comment = "#" if skill_file.file_type in ("python", "bash") else "//"
                excerpt = self._extract_oversized_code(content, remaining_budget, line_comment)
                if per_file_exceeded and total_exceeded:
                    if max_file_chars < remaining_excerpt_budget:
                        threshold_name = "llm_analysis.max_code_file_chars"
                        threshold_limit = max_file_chars
                    elif remaining_excerpt_budget < max_file_chars:
                        threshold_name = "llm_analysis.max_total_prompt_chars"
                        threshold_limit = remaining_excerpt_budget
                    else:
                        threshold_name = "llm_analysis.max_code_file_chars and llm_analysis.max_total_prompt_chars"
                        threshold_limit = remaining_excerpt_budget
                elif per_file_exceeded:
                    threshold_name = "llm_analysis.max_code_file_chars"
                    threshold_limit = max_file_chars
                else:
                    threshold_name = "llm_analysis.max_total_prompt_chars"
                    threshold_limit = remaining_excerpt_budget
                partial_block_chars = rendered_block_size(partial_header, len(excerpt))
                if excerpt:
                    lines.append(partial_header)
                    lines.append(opening_fence)
                    lines.append(excerpt)
                    lines.append(closing_fence)
                    lines.append("")
                    total_chars += partial_block_chars
                    if included_evidence_ids is not None:
                        included_evidence_ids.add(evidence_id)
                    reason = (
                        f"Only selected code excerpts ({len(excerpt):,} chars) from this "
                        f"{file_size:,}-character file were included; the full file was not "
                        f"analyzed because it exceeds {threshold_name} ({threshold_limit:,} chars)."
                    )
                    if per_file_exceeded and total_exceeded:
                        reason += f" The remaining total prompt budget was {remaining_total_budget:,} chars."
                    skipped.append(
                        {
                            "path": str(skill_file.relative_path),
                            "size": file_size,
                            "reason": reason,
                            "threshold_name": threshold_name,
                            "partial": True,
                            "included_chars": len(excerpt),
                        }
                    )
                else:
                    if threshold_name == "llm_analysis.max_code_file_chars":
                        reason = (
                            f"file size ({file_size:,} chars) exceeds per-file limit "
                            f"({max_file_chars:,}) and no bounded code excerpts fit the available budget"
                        )
                    else:
                        reason = (
                            f"including this file would exceed the total prompt budget "
                            f"({total_chars + full_block_chars:,} > {max_total_chars:,}) and no bounded code "
                            f"excerpts fit the remaining budget; binding limit is {threshold_name} "
                            f"({threshold_limit:,} chars)"
                        )
                    skipped.append(
                        {
                            "path": str(skill_file.relative_path),
                            "size": file_size,
                            "reason": reason,
                            "threshold_name": threshold_name,
                        }
                    )
                continue

            lines.append(full_header)
            lines.append(opening_fence)
            lines.append(content)
            lines.append(closing_fence)
            lines.append("")
            total_chars += full_block_chars
            if included_evidence_ids is not None:
                included_evidence_ids.add(evidence_id)

        formatted = "\n".join(lines) if lines else "No script files found."
        return formatted, skipped

    def _extract_oversized_code(self, content: str, max_chars: int, line_comment: str) -> str:
        """Select bounded executable lines, prioritizing imports and risky calls."""
        if max_chars <= 0:
            return ""

        source_lines = content.splitlines()
        executable_lines = [
            index
            for index, line in enumerate(source_lines)
            if line.strip()
            and not line.lstrip().startswith((line_comment, "/*", "*/"))
            and not (line_comment == "//" and line.lstrip().startswith("*"))
        ]
        if not executable_lines:
            return ""
        executable_line_set = set(executable_lines)

        rendered_executable_chars = sum(
            len(f"{line_comment} [source line {index + 1}] ") + len(source_lines[index].rstrip())
            for index in executable_lines
        ) + max(0, len(executable_lines) - 1)
        if rendered_executable_chars <= max_chars:
            candidates = [(index, 1) for index in executable_lines]
        else:
            priorities: dict[int, int] = {}
            high_risk_lines: list[int] = []
            for index in executable_lines:
                line = source_lines[index]
                if _HIGH_RISK_LINE.search(line):
                    priorities[index] = 3
                    high_risk_lines.append(index)
                elif _IMPORT_LINE.search(line):
                    priorities[index] = 2

            for index in high_risk_lines:
                for neighbor in (index - 1, index + 1):
                    if neighbor in executable_line_set:
                        priorities.setdefault(neighbor, 1)

            candidates = sorted(priorities.items(), key=lambda item: (-item[1], item[0]))
            if not candidates:
                candidates = [(index, 0) for index in executable_lines]

        selected: list[tuple[int, str]] = []
        used_chars = 0
        for index, _priority in candidates:
            separator_chars = 1 if selected else 0
            available = max_chars - used_chars - separator_chars
            if available <= 0:
                continue
            rendered = self._format_excerpt_line(source_lines[index], index + 1, available, line_comment)
            if rendered is None:
                continue
            selected.append((index, rendered))
            used_chars += len(rendered) + separator_chars

        selected.sort(key=lambda item: item[0])
        return "\n".join(line for _, line in selected)

    def _format_excerpt_line(self, line: str, line_number: int, max_chars: int, line_comment: str) -> str | None:
        """Render one source line without losing a matching sink in long lines."""
        prefix = f"{line_comment} [source line {line_number}] "
        available = max_chars - len(prefix)
        if available <= 0:
            return None

        source = line.rstrip()
        if len(source) <= available:
            return prefix + source

        marker = "..."
        if available <= len(marker) * 2:
            return None
        match = _HIGH_RISK_LINE.search(source) or _IMPORT_LINE.search(source)
        match_start = match.start() if match else 0
        content_chars = available - len(marker) * 2
        start = max(0, match_start - content_chars // 3)
        start = min(start, max(0, len(source) - content_chars))
        end = min(len(source), start + content_chars)
        excerpt = (marker if start else "") + source[start:end] + (marker if end < len(source) else "")
        return prefix + excerpt

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

    def format_referenced_files(
        self,
        skill: Skill,
        max_file_chars: int = 10_000,
        remaining_budget: int = 100_000,
        *,
        included_evidence_ids: set[str] | None = None,
    ) -> tuple[str, list[dict]]:
        """
        Format referenced files for LLM analysis with budget gating.

        Files that fit within the per-file and remaining budget are included
        in full — **no truncation**.  Files that exceed either limit are
        skipped and reported so the caller can emit actionable findings.

        This is critical for detecting hidden malicious payloads in referenced
        instruction files (e.g., rules/logic.md containing curl commands).

        SECURITY: Only reads files within the skill directory to prevent
        path traversal attacks (e.g., ../../../.env exfiltration).

        Args:
            skill: The skill being analyzed
            max_file_chars: Maximum characters per referenced file.
            remaining_budget: Remaining total character budget.
            included_evidence_ids: Optional set populated with IDs for files
                whose content is included in the returned text.

        Returns:
            Tuple of (formatted_text, skipped_files) where *skipped_files*
            is a list of dicts with keys ``path``, ``size``, ``reason``,
            and ``threshold_name``.
        """
        if not skill.referenced_files:
            return "No referenced files.", []

        lines: list[str] = []
        skipped: list[dict] = []
        total_chars = 0

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
                file_size = len(content)

                # Per-file budget check
                if file_size > max_file_chars:
                    skipped.append(
                        {
                            "path": ref_file_path,
                            "size": file_size,
                            "reason": (f"file size ({file_size:,} chars) exceeds per-file limit ({max_file_chars:,})"),
                            "threshold_name": "llm_analysis.max_referenced_file_chars",
                        }
                    )
                    lines.append(f"**Referenced File: {ref_file_path}** (skipped: exceeds budget)")
                    lines.append("")
                    continue

                # Total budget check
                if total_chars + file_size > remaining_budget:
                    skipped.append(
                        {
                            "path": ref_file_path,
                            "size": file_size,
                            "reason": (
                                f"including this file would exceed the total prompt budget "
                                f"({total_chars + file_size:,} > {remaining_budget:,})"
                            ),
                            "threshold_name": "llm_analysis.max_total_prompt_chars",
                        }
                    )
                    lines.append(f"**Referenced File: {ref_file_path}** (skipped: exceeds total budget)")
                    lines.append("")
                    continue

                # Determine file type for syntax highlighting
                suffix = full_path.suffix.lower()
                file_type = "markdown" if suffix in (".md", ".markdown") else "text"

                evidence_id = source_evidence_id(ref_file_path)
                lines.append(f"**Referenced File: {ref_file_path} [evidence_id={evidence_id}]**")
                lines.append(f"```{file_type}")
                lines.append(content)
                lines.append("```")
                lines.append("")
                total_chars += file_size
                if included_evidence_ids is not None:
                    included_evidence_ids.add(evidence_id)

            except Exception as e:
                lines.append(f"**Referenced File: {ref_file_path}** (error reading: {e})")
                lines.append("")

        return "\n".join(lines), skipped
