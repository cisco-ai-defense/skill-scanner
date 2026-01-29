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
Trigger analyzer for detecting overly generic skill descriptions.

Claude uses skill descriptions to decide when to activate a skill.
Overly generic descriptions can cause trigger hijacking where a skill
activates for unrelated user requests.
"""

import re

from ..models import Finding, Severity, Skill, ThreatCategory
from .base import BaseAnalyzer


class TriggerAnalyzer(BaseAnalyzer):
    """Analyzes skill descriptions for trigger specificity issues."""

    # Generic patterns that are too broad for skill descriptions
    # Only match truly generic descriptions that could hijack any query
    # "Toolkit for X" is specific if X is specific, so we don't flag it
    GENERIC_PATTERNS = [
        r"^help\s*(me|you|with\s+anything)?\s*$",  # Just "help" or "help me"
        r"^(a|an|the)?\s*assistant\s*$",  # Just "assistant" with no context
        r"^(a|an|the)?\s*helper\s*$",  # Just "helper" with no context
        r"^(I |this )?(can |will )?do\s+(anything|everything)\s*(for you)?\.?$",
        r"^general\s+purpose\s+(assistant|tool|skill)\s*$",
        r"^universal\s+(assistant|tool|skill)\s*$",
        r"^default\s+(assistant|tool|skill)\s*$",
        r"^use\s+(this|me)\s+for\s+(everything|anything)\s*$",
    ]

    # Vague/generic words that shouldn't dominate a description
    GENERIC_WORDS = {
        "help",
        "helper",
        "helps",
        "helping",
        "assist",
        "assistant",
        "assists",
        "assisting",
        "do",
        "does",
        "doing",
        "thing",
        "things",
        "stuff",
        "general",
        "generic",
        "universal",
        "any",
        "anything",
        "everything",
        "something",
        "all",
        "various",
        "multiple",
        "many",
        "useful",
        "handy",
        "convenient",
        "tool",
        "utility",
    }

    # Words that indicate specificity (good)
    SPECIFIC_INDICATORS = {
        # Actions
        "convert",
        "parse",
        "format",
        "validate",
        "generate",
        "analyze",
        "create",
        "build",
        "compile",
        "transform",
        "extract",
        "process",
        "calculate",
        "compute",
        "summarize",
        "translate",
        "encode",
        "decode",
        # Domains
        "json",
        "yaml",
        "xml",
        "csv",
        "markdown",
        "html",
        "css",
        "sql",
        "python",
        "javascript",
        "typescript",
        "rust",
        "go",
        "java",
        "api",
        "database",
        "file",
        "image",
        "pdf",
        "document",
        "git",
        "docker",
        "kubernetes",
        "aws",
        "azure",
        "gcp",
        # Specific nouns
        "code",
        "test",
        "documentation",
        "report",
        "log",
        "config",
        "user",
        "data",
        "request",
        "response",
        "error",
        "exception",
    }

    def __init__(self):
        """Initialize trigger analyzer."""
        super().__init__("trigger_analyzer")
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.GENERIC_PATTERNS]

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill for trigger specificity issues.

        Args:
            skill: Skill to analyze

        Returns:
            List of findings related to trigger issues
        """
        findings = []

        # Check for generic patterns in description
        findings.extend(self._check_generic_patterns(skill))

        # Check description word count and specificity
        findings.extend(self._check_description_specificity(skill))

        # Check for keyword baiting (SEO-style stuffing)
        findings.extend(self._check_keyword_baiting(skill))

        return findings

    def _check_generic_patterns(self, skill: Skill) -> list[Finding]:
        """Check if description matches known generic patterns."""
        findings = []
        description = skill.description.strip()

        for pattern in self._compiled_patterns:
            if pattern.match(description):
                findings.append(
                    Finding(
                        id=f"TRIGGER_GENERIC_{hash(description) & 0xFFFFFFFF:08x}",
                        rule_id="TRIGGER_OVERLY_GENERIC",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.MEDIUM,
                        title="Skill description is overly generic",
                        description=(
                            f"Description '{description[:50]}...' matches a generic pattern. "
                            f"This may cause the skill to trigger for unrelated user requests, "
                            f"potentially hijacking conversations."
                        ),
                        file_path="SKILL.md",
                        remediation=(
                            "Make the description more specific by describing exactly what the skill does, "
                            "what inputs it accepts, and what outputs it produces."
                        ),
                        analyzer="trigger",
                    )
                )
                break  # One finding per skill is enough

        return findings

    def _check_description_specificity(self, skill: Skill) -> list[Finding]:
        """Check if description has sufficient specificity."""
        findings = []
        description = skill.description.strip()

        # Tokenize description
        words = re.findall(r"\b[a-zA-Z]+\b", description.lower())

        # Check word count
        if len(words) < 5:
            findings.append(
                Finding(
                    id=f"TRIGGER_SHORT_{hash(description) & 0xFFFFFFFF:08x}",
                    rule_id="TRIGGER_DESCRIPTION_TOO_SHORT",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.LOW,
                    title="Skill description is too short",
                    description=(
                        f"Description has only {len(words)} words. "
                        f"Short descriptions may not provide enough context for Claude to determine "
                        f"when this skill should be used."
                    ),
                    file_path="SKILL.md",
                    remediation=(
                        "Expand the description to at least 10-20 words explaining the skill's "
                        "purpose, capabilities, and appropriate use cases."
                    ),
                    analyzer="trigger",
                )
            )
            return findings  # Don't check further for very short descriptions

        # Calculate specificity ratio
        generic_count = sum(1 for w in words if w in self.GENERIC_WORDS)
        specific_count = sum(1 for w in words if w in self.SPECIFIC_INDICATORS)

        generic_ratio = generic_count / len(words) if words else 0

        # If more than 40% of words are generic, flag it
        if generic_ratio > 0.4 and specific_count < 2:
            findings.append(
                Finding(
                    id=f"TRIGGER_VAGUE_{hash(description) & 0xFFFFFFFF:08x}",
                    rule_id="TRIGGER_VAGUE_DESCRIPTION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.LOW,
                    title="Skill description lacks specificity",
                    description=(
                        f"Description contains {generic_count} generic words ({generic_ratio:.0%}) "
                        f"and only {specific_count} specific indicators. "
                        f"This may cause imprecise skill matching."
                    ),
                    file_path="SKILL.md",
                    remediation=(
                        "Replace generic terms with specific technical terms that describe "
                        "exactly what file types, technologies, or operations this skill handles."
                    ),
                    analyzer="trigger",
                )
            )

        return findings

    def _check_keyword_baiting(self, skill: Skill) -> list[Finding]:
        """Check for keyword stuffing / SEO-style baiting."""
        findings = []
        description = skill.description.strip()

        # Look for comma-separated lists of 8+ keywords (not just 5)
        # Also require the list to be at the START of description (SEO style)
        # or contain repeated/similar words
        keyword_lists = re.findall(r"[a-zA-Z]+(?:\s*,\s*[a-zA-Z]+){7,}", description)

        # Only flag if the list is suspiciously long AND at the start
        # OR contains repetitive patterns
        if keyword_lists:
            # Check if this is a legitimate "examples include" list
            context_before = description[: description.find(keyword_lists[0])].lower()
            if "example" in context_before or "such as" in context_before or "including" in context_before:
                # This is likely a legitimate examples list, not keyword baiting
                return findings

            # Check for repetitive words in the list
            words = [w.strip().lower() for w in keyword_lists[0].split(",")]
            unique_ratio = len(set(words)) / len(words) if words else 1

            # Only flag if many repeated words (ratio < 0.7) or list is at very start
            if unique_ratio < 0.7 or description.strip().startswith(keyword_lists[0][:20]):
                findings.append(
                    Finding(
                        id=f"TRIGGER_KEYWORD_BAIT_{hash(description) & 0xFFFFFFFF:08x}",
                        rule_id="TRIGGER_KEYWORD_BAITING",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.MEDIUM,
                        title="Skill description may contain keyword baiting",
                        description=(
                            "Description contains suspiciously long keyword list "
                            "that may be an attempt to trigger the skill for many unrelated queries."
                        ),
                        file_path="SKILL.md",
                        remediation=(
                            "Replace keyword lists with natural language sentences that describe "
                            "the skill's actual capabilities."
                        ),
                        analyzer="trigger",
                    )
                )

        return findings

    def get_specificity_score(self, description: str) -> float:
        """
        Calculate a specificity score for a description.

        Args:
            description: The skill description text

        Returns:
            Score from 0.0 (very generic) to 1.0 (very specific)
        """
        words = re.findall(r"\b[a-zA-Z]+\b", description.lower())
        if not words:
            return 0.0

        generic_count = sum(1 for w in words if w in self.GENERIC_WORDS)
        specific_count = sum(1 for w in words if w in self.SPECIFIC_INDICATORS)

        # Base score from word count (more words = more specific, up to a point)
        word_score = min(len(words) / 20, 1.0)

        # Penalty for generic words
        generic_penalty = generic_count / len(words) if words else 0

        # Bonus for specific words
        specific_bonus = min(specific_count / 5, 0.5)

        score = word_score - generic_penalty + specific_bonus
        return max(0.0, min(1.0, score))
