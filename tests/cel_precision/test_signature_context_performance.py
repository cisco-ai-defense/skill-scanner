# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import skill_scanner.core.rules.patterns as patterns_module
from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Skill, SkillManifest
from skill_scanner.core.rules.patterns import SecurityRule, SignatureScanContext
from skill_scanner.core.scan_policy import ScanPolicy


def _rule(rule_id: str, pattern: str = r"eval\s*\(") -> SecurityRule:
    return SecurityRule(
        {
            "id": rule_id,
            "category": "command_injection",
            "severity": "HIGH",
            "patterns": [pattern],
            "file_types": ["markdown"],
            "description": "Synthetic signature-context performance rule",
        },
        strict=True,
    )


def _large_markdown(line_count: int = 2_000) -> str:
    lines = ["# Synthetic skill"]
    for line_number in range(line_count):
        if line_number % 400 == 0:
            lines.extend(["## Negative examples", "```python"])
        elif line_number % 400 == 200:
            lines.append("```")
        lines.append(
            "eval(user_input)  # synthetic candidate"
            if line_number % 100 == 0
            else f"ordinary instruction {line_number}"
        )
    return "\n".join(lines)


def test_shared_context_preserves_exact_signature_results() -> None:
    content = (
        "# Instructions\n"
        "eval(active_input)\n"
        "## Negative examples\n"
        "```python\n"
        "eval(unsafe_example)\n"
        "exec(unsafe_example)\n"
        "```\n"
        "## Recovery\n"
        "- No eval() or exec()\n"
    )
    rules = [_rule("EVAL_RULE"), _rule("EXEC_RULE", r"exec\s*\(")]

    independent = [rule.scan_content(content, "SKILL.md") for rule in rules]
    shared_context = SignatureScanContext(content)
    shared = [rule.scan_content(content, "SKILL.md", scan_context=shared_context) for rule in rules]

    assert shared == independent


def test_many_matching_rules_build_markdown_structure_once(monkeypatch) -> None:
    content = _large_markdown()
    rules = [_rule(f"SYNTHETIC_{index}") for index in range(24)]
    original = patterns_module._build_signature_line_contexts
    build_calls = 0

    def counted(lines: tuple[str, ...]) -> tuple[tuple[bool, bool], ...]:
        nonlocal build_calls
        build_calls += 1
        return original(lines)

    monkeypatch.setattr(patterns_module, "_build_signature_line_contexts", counted)
    shared_context = SignatureScanContext(content)

    results = [rule.scan_content(content, "SKILL.md", scan_context=shared_context) for rule in rules]

    assert all(results)
    assert build_calls == 1
    assert shared_context._line_contexts is not None
    assert len(shared_context._line_contexts) == len(shared_context.lines)


def test_static_instruction_scan_reuses_one_context_across_rules(
    tmp_path: Path,
    monkeypatch,
) -> None:
    content = _large_markdown(600)
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(content, encoding="utf-8")
    skill = Skill(
        directory=tmp_path,
        manifest=SkillManifest(
            name="context-performance",
            description="Verifies shared signature scan context",
        ),
        skill_md_path=skill_md,
        instruction_body=content,
        files=[],
        referenced_files=[],
    )
    rules = [_rule(f"STATIC_{index}") for index in range(12)]

    class _RuleLoader:
        @staticmethod
        def get_rules_for_file_type(file_type: str) -> list[SecurityRule]:
            assert file_type == "markdown"
            return rules

    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    analyzer._unreferenced_scripts = []
    analyzer.rule_loader = _RuleLoader()

    original = patterns_module._build_signature_line_contexts
    build_calls = 0

    def counted(lines: tuple[str, ...]) -> tuple[tuple[bool, bool], ...]:
        nonlocal build_calls
        build_calls += 1
        return original(lines)

    monkeypatch.setattr(patterns_module, "_build_signature_line_contexts", counted)

    findings = analyzer._scan_instruction_body(skill)

    assert findings
    assert build_calls == 1


def test_structural_walk_remains_lazy_when_no_rule_matches(monkeypatch) -> None:
    content = _large_markdown(500)
    rules = [_rule(f"NO_MATCH_{index}", r"definitely_absent_marker") for index in range(20)]
    build_calls = 0

    def unexpected(_lines: tuple[str, ...]) -> tuple[tuple[bool, bool], ...]:
        nonlocal build_calls
        build_calls += 1
        return ()

    monkeypatch.setattr(patterns_module, "_build_signature_line_contexts", unexpected)
    shared_context = SignatureScanContext(content)

    assert all(rule.scan_content(content, "SKILL.md", scan_context=shared_context) == [] for rule in rules)
    assert build_calls == 0
    assert shared_context._line_contexts is None


def test_shared_context_source_and_lines_are_immutable() -> None:
    context = SignatureScanContext("eval(user_input)")

    assert isinstance(context.lines, tuple)
    with pytest.raises(FrozenInstanceError):
        setattr(context, "content", "clean")


def test_context_for_different_string_object_is_not_reused() -> None:
    context = SignatureScanContext("eval(user_input)")

    assert _rule("STALE_CONTEXT").scan_content("clean", "SKILL.md", scan_context=context) == []
