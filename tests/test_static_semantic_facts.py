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

"""Structured semantic facts emitted by the static analyzer."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

from skill_scanner.core.analyzers import static as static_module
from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.file_magic import MagicMatch
from skill_scanner.core.models import Severity, Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.semantic.projector import ScanFactProjector


def _analyzer() -> StaticAnalyzer:
    """Construct the analyzer without loading unrelated signature/YARA packs."""
    analyzer = StaticAnalyzer.__new__(StaticAnalyzer)
    BaseAnalyzer.__init__(analyzer, "static_analyzer", policy=ScanPolicy.default())
    analyzer._unreferenced_scripts = []
    return analyzer


def _skill(
    tmp_path: Path,
    files: dict[str, tuple[str, str | bytes]],
    *,
    allowed_tools: list[str] | None = None,
    compatibility: str | None = None,
) -> Skill:
    directory = tmp_path / "semantic-skill"
    directory.mkdir()
    skill_md_path = directory / "SKILL.md"
    skill_md_path.write_text("# Semantic skill\n", encoding="utf-8")

    skill_files: list[SkillFile] = []
    for relative_path, (file_type, content) in files.items():
        path = directory / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
            cached_content = None
        else:
            path.write_text(content, encoding="utf-8")
            cached_content = content
        skill_files.append(
            SkillFile(
                path=path,
                relative_path=relative_path,
                file_type=file_type,
                content=cached_content,
                size_bytes=path.stat().st_size,
            )
        )

    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name="semantic-skill",
            description="Exercises structured analyzer metadata",
            compatibility=compatibility,
            allowed_tools=allowed_tools,
        ),
        skill_md_path=skill_md_path,
        instruction_body="# Semantic skill\n",
        files=skill_files,
        referenced_files=[],
    )


def _signal_kinds(finding) -> set[str]:
    return {signal["kind"] for signal in finding.metadata["semantic_facts"]["signals"] if isinstance(signal, dict)}


def test_hidden_script_carries_hidden_and_unreferenced_context(tmp_path: Path) -> None:
    skill = _skill(tmp_path, {".hidden.py": ("python", "print('hello')\n")})
    hidden_path = skill.directory / ".hidden.py"
    hidden_path.chmod(0o755)
    analyzer = _analyzer()

    analyzer._check_file_inventory(skill)
    findings = analyzer._check_hidden_files(skill)
    analyzer._annotate_unreferenced_script_context(findings)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "HIDDEN_EXECUTABLE_SCRIPT"
    assert finding.severity is Severity.HIGH
    assert _signal_kinds(finding) == {"hidden_executable", "unreferenced_executable"}

    facts = ScanFactProjector().project(skill, finding, findings)
    assert facts.projection.complete
    assert facts.candidate.evidence_kind == "file_inventory"
    assert facts.candidate.context_kind == "code"
    assert facts.candidate.file.hidden
    assert facts.candidate.file.executable
    assert not facts.candidate.file.referenced
    assert {signal.kind for signal in facts.skill.signals} >= {
        "hidden_executable",
        "unreferenced_executable",
    }


def test_binary_and_magic_findings_emit_projectable_signals(tmp_path: Path, monkeypatch) -> None:
    skill = _skill(
        tmp_path,
        {
            "payload.py": ("python", b"\x7fELF" + b"\x00" * 64),
            "payload.bin": ("binary", b"\x01\x02\x03\x04"),
        },
    )

    def fake_mismatch(path: Path, **_kwargs: Any):
        if path.name != "payload.py":
            return None
        return (
            "HIGH",
            "Python extension contains an ELF executable",
            MagicMatch("executable/elf", "executable", "ELF executable", 1.0),
        )

    monkeypatch.setattr("skill_scanner.core.file_magic.check_extension_mismatch", fake_mismatch)
    findings = _analyzer()._check_binary_files(skill)

    assert [finding.rule_id for finding in findings] == [
        "FILE_MAGIC_MISMATCH",
        "BINARY_FILE_DETECTED",
    ]
    magic, binary = findings
    assert magic.severity is Severity.HIGH
    assert magic.metadata["actual_family"] == "executable"
    assert _signal_kinds(magic) == {"file_magic_mismatch"}
    assert magic.metadata["semantic_facts"]["signals"][0]["value_class"] == "binary"
    assert binary.severity is Severity.INFO
    assert _signal_kinds(binary) == {"unanalyzable_binary"}
    assert binary.metadata["semantic_facts"]["signals"][0]["value_class"] == "binary"

    magic_facts = ScanFactProjector().project(skill, magic, findings)
    binary_facts = ScanFactProjector().project(skill, binary, findings)
    assert magic_facts.projection.complete, list(magic_facts.projection.error_codes)
    assert binary_facts.projection.complete, list(binary_facts.projection.error_codes)
    assert magic_facts.candidate.evidence_kind == "file_magic"
    assert binary_facts.candidate.evidence_kind == "file_inventory"
    assert {signal.kind for signal in magic_facts.skill.signals} >= {
        "file_magic_mismatch",
        "unanalyzable_binary",
    }


def test_embedded_shebang_yara_finding_has_binary_context(tmp_path: Path) -> None:
    skill = _skill(tmp_path, {"payload.bin": ("binary", b"xx#!/bin/sh\x00")})
    match = {
        "rule_name": "embedded_shebang_in_binary",
        "namespace": "default",
        "file_path": "payload.bin",
        "meta": {
            "meta": {
                "description": "Embedded shebang in binary",
                "threat_type": "CODE EXECUTION",
                "classification": "harmful",
            }
        },
        "strings": [
            {
                "identifier": "$shebang",
                "line_number": 1,
                "matched_data": "#!/bin/sh",
                "line_content": "xx#!/bin/sh",
            }
        ],
    }

    findings = _analyzer()._create_findings_from_yara_match(match, skill)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "YARA_embedded_shebang_in_binary"
    assert _signal_kinds(finding) == {"embedded_shebang"}
    facts = ScanFactProjector().project(skill, finding, findings)
    assert facts.candidate.evidence_kind == "binary_signature"
    assert facts.candidate.context_kind == "binary"


def test_homoglyph_finding_has_code_context(tmp_path: Path, monkeypatch) -> None:
    confusables = types.SimpleNamespace(
        is_dangerous=lambda *_args, **_kwargs: [{"character": "а"}],
        is_confusable=lambda *_args, **_kwargs: [{"alias": "CYRILLIC"}],
    )
    module = types.ModuleType("confusable_homoglyphs")
    setattr(module, "confusables", confusables)
    monkeypatch.setitem(sys.modules, "confusable_homoglyphs", module)
    content = "\n".join(f"а{i} = call()" for i in range(5))
    skill = _skill(tmp_path, {"scripts/main.py": ("python", content)})

    findings = _analyzer()._check_homoglyph_attacks(skill)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "HOMOGLYPH_ATTACK"
    assert finding.severity is Severity.HIGH
    assert _signal_kinds(finding) == {"unicode_homoglyph"}
    facts = ScanFactProjector().project(skill, finding, findings)
    assert facts.candidate.evidence_kind == "unicode_confusable"
    assert facts.candidate.context_kind == "code"


def test_network_and_tool_mismatches_emit_typed_candidates(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        {
            "scripts/main.py": (
                "python",
                "import requests\nimport subprocess\n"
                "requests.get('https://example.test')\n"
                "subprocess.run(['echo', 'ok'])\n",
            )
        },
        allowed_tools=["Read"],
    )

    findings = _analyzer()._check_consistency(skill)
    by_rule = {finding.rule_id: finding for finding in findings}

    assert set(by_rule) == {
        "TOOL_ABUSE_UNDECLARED_NETWORK",
        "ALLOWED_TOOLS_BASH_VIOLATION",
        "ALLOWED_TOOLS_NETWORK_USAGE",
    }
    network = by_rule["TOOL_ABUSE_UNDECLARED_NETWORK"]
    bash = by_rule["ALLOWED_TOOLS_BASH_VIOLATION"]
    assert network.severity is Severity.MEDIUM
    assert bash.severity is Severity.HIGH
    assert _signal_kinds(network) == {"undeclared_network"}
    assert _signal_kinds(bash) == {"undeclared_tool"}

    network_facts = ScanFactProjector().project(skill, network, findings)
    bash_facts = ScanFactProjector().project(skill, bash, findings)
    assert network_facts.candidate.flow.source_class == "skill_code"
    assert network_facts.candidate.flow.sink_class == "external_network"
    assert any(flow.sink_class == "external_network" for flow in network_facts.skill.flows)
    assert bash_facts.candidate.command.executable == "Bash"
    assert bash_facts.candidate.command.executes
    assert bash_facts.candidate.command.sink_class == "process_execution"
    assert any(command.executable == "Bash" for command in bash_facts.skill.commands)


def test_trusted_pack_dirs_are_forwarded_to_rule_loader(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class FakeRuleLoader:
        def __init__(self, rules_file=None, *, extra_rules_dirs=None, trusted_pack_dirs=None):
            captured.update(
                rules_file=rules_file,
                extra_rules_dirs=extra_rules_dirs,
                trusted_pack_dirs=trusted_pack_dirs,
            )

        def load_rules(self) -> None:
            return None

    monkeypatch.setattr(static_module, "RuleLoader", FakeRuleLoader)
    trusted = [tmp_path / "trusted-pack"]

    StaticAnalyzer(use_yara=False, trusted_pack_dirs=trusted)

    assert captured["trusted_pack_dirs"] == trusted
