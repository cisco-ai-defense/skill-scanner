# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Trigger/description quality checks.

Rules: TRIGGER_OVERLY_GENERIC, TRIGGER_DESCRIPTION_TOO_SHORT,
       TRIGGER_VAGUE_DESCRIPTION, TRIGGER_KEYWORD_BAITING.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill

# ---------------------------------------------------------------------------
# Constants (previously class-level on TriggerAnalyzer)
# ---------------------------------------------------------------------------

GENERIC_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^help\s*(me|you|with\s+anything)?\s*$",
        r"^(a|an|the)?\s*assistant\s*$",
        r"^(a|an|the)?\s*helper\s*$",
        r"^(I |this )?(can |will )?do\s+(anything|everything)\s*(for you)?\.?$",
        r"^general\s+purpose\s+(assistant|tool|skill)\s*$",
        r"^universal\s+(assistant|tool|skill)\s*$",
        r"^default\s+(assistant|tool|skill)\s*$",
        r"^use\s+(this|me)\s+for\s+(everything|anything)\s*$",
    ]
]

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

SPECIFIC_INDICATORS = {
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


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------


def check_generic_patterns(skill: Skill) -> list[Finding]:
    """Check if description matches known generic patterns."""
    findings: list[Finding] = []
    description = skill.description.strip()

    for pattern in GENERIC_PATTERNS:
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
            break
    return findings


def check_description_specificity(skill: Skill) -> list[Finding]:
    """Check if description has sufficient specificity."""
    findings: list[Finding] = []
    description = skill.description.strip()
    words = re.findall(r"\b[a-zA-Z]+\b", description.lower())

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
                    f"Short descriptions may not provide enough context for the agent to determine "
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
        return findings

    generic_count = sum(1 for w in words if w in GENERIC_WORDS)
    specific_count = sum(1 for w in words if w in SPECIFIC_INDICATORS)
    generic_ratio = generic_count / len(words) if words else 0

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


def check_keyword_baiting(skill: Skill) -> list[Finding]:
    """Check for keyword stuffing / SEO-style baiting."""
    findings: list[Finding] = []
    description = skill.description.strip()

    keyword_lists = re.findall(r"[a-zA-Z]+(?:\s*,\s*[a-zA-Z]+){7,}", description)

    if keyword_lists:
        context_before = description[: description.find(keyword_lists[0])].lower()
        if "example" in context_before or "such as" in context_before or "including" in context_before:
            return findings

        words = [w.strip().lower() for w in keyword_lists[0].split(",")]
        unique_ratio = len(set(words)) / len(words) if words else 1

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
