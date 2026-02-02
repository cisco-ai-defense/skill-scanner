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

import re
import uuid

from ..models import Finding, Severity, Skill, ThreatCategory
from .base import BaseAnalyzer

try:
    import tiktoken

    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False


class ReadinessAnalyzer(BaseAnalyzer):
    MAX_LINES = 500
    MAX_TOKENS = 2000
    MIN_DESCRIPTION_LENGTH = 50
    MAX_INLINE_CODE_LINES = 50

    TRIGGER_PATTERNS = [
        r"\buse when\b",
        r"\bwhen the user\b",
        r"\bwhen working with\b",
        r"\bwhen you need\b",
        r"\bif the user\b",
        r"\bfor\s+\w+\s+tasks\b",
    ]

    FIRST_SECOND_PERSON_PATTERNS = [
        r"\bI can\b",
        r"\bI will\b",
        r"\bI am\b",
        r"\byou can\b",
        r"\byou will\b",
        r"\byou should\b",
        r"\byour\b",
    ]

    TERMINOLOGY_GROUPS = [
        ["api endpoint", "url", "route", "path", "uri"],
        ["field", "box", "element", "control", "input"],
        ["function", "method", "procedure", "routine"],
        ["file", "document", "asset", "resource"],
    ]

    def __init__(self):
        super().__init__("readiness_analyzer")

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_skill_md_lines(skill))
        findings.extend(self._check_token_count(skill))
        findings.extend(self._check_file_references(skill))
        findings.extend(self._check_large_code_blocks(skill))
        findings.extend(self._check_description_trigger(skill))
        findings.extend(self._check_description_person(skill))
        findings.extend(self._check_description_length(skill))
        findings.extend(self._check_name_format(skill))
        findings.extend(self._check_reference_depth(skill))
        findings.extend(self._check_terminology_consistency(skill))
        findings.extend(self._check_conflicting_instructions(skill))
        findings.extend(self._check_python_error_handling(skill))
        findings.extend(self._check_shell_error_handling(skill))
        return findings

    def _make_finding(
        self,
        rule_id: str,
        severity: Severity,
        title: str,
        description: str,
        file_path: str | None = None,
        line_number: int | None = None,
        snippet: str | None = None,
        remediation: str | None = None,
    ) -> Finding:
        finding_id = f"{rule_id}-{uuid.uuid4().hex[:8]}"
        return Finding(
            id=finding_id,
            rule_id=rule_id,
            category=ThreatCategory.POLICY_VIOLATION,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            snippet=snippet,
            remediation=remediation,
            analyzer=self.name,
            metadata={},
        )

    def _check_skill_md_lines(self, skill: Skill) -> list[Finding]:
        line_count = len(skill.instruction_body.splitlines())
        if line_count > self.MAX_LINES:
            return [
                self._make_finding(
                    rule_id="SRDNS-001",
                    severity=Severity.MEDIUM,
                    title="SKILL.md exceeds recommended length",
                    description=f"SKILL.md has {line_count} lines (recommended: <{self.MAX_LINES})",
                    file_path="SKILL.md",
                    snippet=f"Line count: {line_count}",
                    remediation="Use progressive disclosure with file references to reduce size",
                )
            ]
        return []

    def _check_token_count(self, skill: Skill) -> list[Finding]:
        if not TIKTOKEN_AVAILABLE:
            return []
        try:
            encoding = tiktoken.get_encoding("cl100k_base")
            full_content = f"{skill.description}\n{skill.instruction_body}"
            token_count = len(encoding.encode(full_content))
        except Exception:
            return []
        if token_count > self.MAX_TOKENS:
            return [
                self._make_finding(
                    rule_id="SRDNS-002",
                    severity=Severity.MEDIUM,
                    title="SKILL.md exceeds recommended token count",
                    description=f"Estimated {token_count} tokens (recommended: <{self.MAX_TOKENS})",
                    file_path="SKILL.md",
                    snippet=f"Token count: {token_count}",
                    remediation="Split detailed content into referenced files",
                )
            ]
        return []

    def _check_file_references(self, skill: Skill) -> list[Finding]:
        line_count = len(skill.instruction_body.splitlines())
        if line_count > 100 and not skill.referenced_files:
            return [
                self._make_finding(
                    rule_id="SRDNS-003",
                    severity=Severity.MEDIUM,
                    title="No progressive disclosure utilized",
                    description="Large skill with no file references found",
                    file_path="SKILL.md",
                    snippet=f"Line count: {line_count}, References: 0",
                    remediation="Consider splitting detailed content into reference.md or examples.md",
                )
            ]
        return []

    def _check_large_code_blocks(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        code_block_pattern = r"```[\w]*\n(.*?)```"
        for match in re.finditer(code_block_pattern, skill.instruction_body, re.DOTALL):
            block_content = match.group(1)
            block_lines = len(block_content.splitlines())
            if block_lines > self.MAX_INLINE_CODE_LINES:
                start_pos = match.start()
                line_num = skill.instruction_body[:start_pos].count("\n") + 1
                findings.append(
                    self._make_finding(
                        rule_id="SRDNS-004",
                        severity=Severity.LOW,
                        title="Large code block inline",
                        description=f"Code block with {block_lines} lines (recommended: <{self.MAX_INLINE_CODE_LINES})",
                        file_path="SKILL.md",
                        line_number=line_num,
                        snippet=block_content[:200] + "..." if len(block_content) > 200 else block_content,
                        remediation="Move large code blocks to separate script files",
                    )
                )
        return findings

    def _check_description_trigger(self, skill: Skill) -> list[Finding]:
        description = skill.description or ""
        has_trigger = any(re.search(pattern, description, re.IGNORECASE) for pattern in self.TRIGGER_PATTERNS)
        if description and not has_trigger:
            return [
                self._make_finding(
                    rule_id="SRDNS-005",
                    severity=Severity.HIGH,
                    title="Description missing activation context",
                    description='Description lacks "Use when..." clause or similar trigger context',
                    file_path="SKILL.md",
                    snippet=description[:200] if len(description) > 200 else description,
                    remediation='Add activation context like "Use when working with PDF files"',
                )
            ]
        return []

    def _check_description_person(self, skill: Skill) -> list[Finding]:
        description = skill.description or ""
        for pattern in self.FIRST_SECOND_PERSON_PATTERNS:
            if re.search(pattern, description, re.IGNORECASE):
                return [
                    self._make_finding(
                        rule_id="SRDNS-006",
                        severity=Severity.MEDIUM,
                        title="Description uses first/second person",
                        description="Description should be written in third person",
                        file_path="SKILL.md",
                        snippet=description[:200] if len(description) > 200 else description,
                        remediation='Use third person: "Processes files" not "I can process files"',
                    )
                ]
        return []

    def _check_description_length(self, skill: Skill) -> list[Finding]:
        description = skill.description or ""
        if description and len(description) < self.MIN_DESCRIPTION_LENGTH:
            return [
                self._make_finding(
                    rule_id="SRDNS-007",
                    severity=Severity.HIGH,
                    title="Description too short",
                    description=f"Description is {len(description)} chars (recommended: >{self.MIN_DESCRIPTION_LENGTH})",
                    file_path="SKILL.md",
                    snippet=description,
                    remediation="Add specific details about what the skill does and when to use it",
                )
            ]
        return []

    def _check_name_format(self, skill: Skill) -> list[Finding]:
        name = skill.name
        if not name:
            return []
        name_pattern = r"^[a-z][a-z0-9-]*$"
        issues = []
        if len(name) > 64:
            issues.append(f"exceeds 64 chars ({len(name)})")
        if not re.match(name_pattern, name):
            issues.append("must be lowercase letters, numbers, and hyphens only")
        if issues:
            return [
                self._make_finding(
                    rule_id="SRDNS-010",
                    severity=Severity.MEDIUM,
                    title="Invalid name format",
                    description=f"Name '{name}' {'; '.join(issues)}",
                    file_path="SKILL.md",
                    snippet=f"name: {name}",
                    remediation="Use lowercase letters, numbers, and hyphens; max 64 chars",
                )
            ]
        return []

    def _check_reference_depth(self, skill: Skill) -> list[Finding]:
        if not skill.referenced_files:
            return []
        nested_refs: list[str] = []
        for ref_file in skill.referenced_files:
            for skill_file in skill.files:
                if skill_file.relative_path == ref_file and skill_file.content:
                    link_pattern = r"\[([^\]]+)\]\(([^)]+\.md)\)"
                    if re.search(link_pattern, skill_file.content):
                        nested_refs.append(ref_file)
                        break
        if nested_refs:
            return [
                self._make_finding(
                    rule_id="SRDNS-011",
                    severity=Severity.LOW,
                    title="Nested references detected",
                    description="Referenced files contain further markdown references",
                    file_path="SKILL.md",
                    snippet=f"Files with nested refs: {', '.join(nested_refs)}",
                    remediation="Keep references one level deep from SKILL.md",
                )
            ]
        return []

    def _check_terminology_consistency(self, skill: Skill) -> list[Finding]:
        full_content = f"{skill.description}\n{skill.instruction_body}"
        content_lower = full_content.lower()
        for term_group in self.TERMINOLOGY_GROUPS:
            found_terms: list[str] = []
            for term in term_group:
                if term in content_lower:
                    found_terms.append(term)
            if len(found_terms) > 1:
                return [
                    self._make_finding(
                        rule_id="SRDNS-012",
                        severity=Severity.LOW,
                        title="Mixed terminology detected",
                        description=f"Multiple terms used for same concept: {', '.join(found_terms)}",
                        file_path="SKILL.md",
                        snippet=f"Found: {', '.join(found_terms)}",
                        remediation="Choose one term and use it consistently throughout",
                    )
                ]
        return []

    def _check_conflicting_instructions(self, skill: Skill) -> list[Finding]:
        content = skill.instruction_body
        conflict_patterns = [
            (r"\buse\s+(\w+)\b.*?\bdon't use\s+\1\b", "contradictory use/don't use"),
            (r"\balways\b.*?\bsometimes\b", "mixed always/sometimes"),
            (r"\bnever\b.*?\bcan\b.*?\bif\b", "exception to never"),
            (r"\byou can use\s+(\w+).*?or\s+(\w+).*?or\s+(\w+)", "too many options"),
        ]
        for pattern, desc in conflict_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return [
                    self._make_finding(
                        rule_id="SRDNS-013",
                        severity=Severity.MEDIUM,
                        title="Potentially conflicting instructions",
                        description=f"Pattern detected: {desc}",
                        file_path="SKILL.md",
                        snippet=f"Pattern type: {desc}",
                        remediation="Provide clear defaults and explicit exceptions",
                    )
                ]
        return []

    def _check_python_error_handling(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for skill_file in skill.files:
            if skill_file.file_type != "python":
                continue
            content = skill_file.read_content()
            if not content:
                continue
            if skill_file.relative_path == "SKILL.md":
                continue
            has_try_except = "try:" in content and "except" in content
            if not has_try_except and len(content.splitlines()) > 20:
                findings.append(
                    self._make_finding(
                        rule_id="SRDNS-014",
                        severity=Severity.MEDIUM,
                        title="Python script missing error handling",
                        description="Script lacks try/except blocks for error handling",
                        file_path=skill_file.relative_path,
                        snippet=content[:200] + "..." if len(content) > 200 else content,
                        remediation="Add try/except blocks to handle potential errors",
                    )
                )
        return findings

    def _check_shell_error_handling(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for skill_file in skill.files:
            if skill_file.file_type != "bash":
                continue
            content = skill_file.read_content()
            if not content:
                continue
            has_set_e = "set -e" in content or "set -o errexit" in content
            if not has_set_e and len(content.splitlines()) > 10:
                findings.append(
                    self._make_finding(
                        rule_id="SRDNS-015",
                        severity=Severity.MEDIUM,
                        title="Shell script missing error handling",
                        description='Script lacks "set -e" for fail-fast behavior',
                        file_path=skill_file.relative_path,
                        snippet=content[:200] + "..." if len(content) > 200 else content,
                        remediation='Add "set -e" at the start of the script',
                    )
                )
        return findings
