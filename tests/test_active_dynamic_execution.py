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

"""High-confidence active dynamic-execution detection and fact projection."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import yaml

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, Skill, SkillFile, SkillManifest, ThreatCategory
from skill_scanner.core.rules.active_dynamic_execution import (
    MAX_DOCUMENT_BYTES,
    MAX_INLINE_CHARS,
    RULE_ID,
    _is_pure_prohibition,
    check_active_dynamic_execution,
    find_active_dynamic_execution,
)
from skill_scanner.core.semantic.projector import ScanFactProjector


def _skill(tmp_path: Path, body: str, *, line_offset: int = 0) -> Skill:
    directory = tmp_path / "active-dynamic-execution"
    directory.mkdir(exist_ok=True)
    skill_path = directory / "SKILL.md"
    skill_path.write_text(body, encoding="utf-8")
    return Skill(
        directory=directory,
        manifest=SkillManifest(
            name="active-dynamic-execution",
            description="Exercises syntax-aware dynamic execution detection",
        ),
        skill_md_path=skill_path,
        instruction_body=body,
        instruction_body_line_offset=line_offset,
        files=[
            SkillFile(
                path=skill_path,
                relative_path="SKILL.md",
                file_type="markdown",
                content=body,
                size_bytes=len(body.encode()),
            )
        ],
    )


def test_python_ast_and_javascript_tokens_detect_active_calls_once(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Install

```python
import subprocess as sp
sp.run(command)
eval(payload)
```

```typescript
import * as cp from "node:child_process";
cp.exec(command);
```
""",
        line_offset=4,
    )

    calls = find_active_dynamic_execution(skill)
    assert {call.api_class for call in calls} == {
        "javascript_child_process",
        "python_eval",
        "python_subprocess",
    }
    findings = check_active_dynamic_execution(skill)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.category is ThreatCategory.COMMAND_INJECTION
    assert finding.severity is Severity.HIGH
    assert finding.analyzer == "static"
    assert finding.line_number == calls[0].line_number + 4
    assert finding.metadata["analysis_basis"] == "bounded_commonmark_syntax"
    assert finding.metadata["api_classes"] == sorted(call.api_class for call in calls)


def test_active_inline_instruction_requires_actionable_code_context(tmp_path: Path) -> None:
    actionable = _skill(tmp_path, "# Usage\nUse `os.system(command)` to launch the selected program.\n")
    assert [call.api_class for call in find_active_dynamic_execution(actionable)] == ["python_os_system"]


def test_static_analyzer_integrates_rule_without_duplicate_finding(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Usage
```python
eval(payload)
eval(other_payload)
```
""",
    )

    findings = StaticAnalyzer(use_yara=False).analyze(skill)

    assert len([finding for finding in findings if finding.rule_id == RULE_ID]) == 1


def test_examples_prohibitions_strings_comments_and_shadowed_names_are_near_misses(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Safety

Never use `eval(payload)` or call os.system(command).
The scanner detects eval(payload) in unsafe source code.

# Examples

```python
eval(payload)
```

# Reference implementation

```javascript
// child_process.exec(command)
const text = "eval(payload)";
const eval = (value) => value;
eval(payload);
```
""",
    )

    assert find_active_dynamic_execution(skill) == []
    assert check_active_dynamic_execution(skill) == []


def test_long_coordinated_prohibition_is_parsed_without_regex_backtracking() -> None:
    prefix = "Don't call eval(payload),"
    repeated = " or call eval(payload),"
    suffix = " unexpected"
    repetitions = (MAX_INLINE_CHARS - len(prefix) - len(suffix)) // len(repeated)
    line = prefix + repeated * repetitions + suffix

    started = time.perf_counter()
    assert _is_pure_prohibition(line) is False
    assert time.perf_counter() - started < 1.0


def test_complete_coordinated_prohibition_keeps_existing_semantics() -> None:
    assert _is_pure_prohibition("12) Never use `eval(payload)`, or call os.system(command)!") is True


def test_bold_example_label_scopes_untyped_regex_fence_as_inert(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        r"""# Pattern authoring

**Examples:**
```
(eval|exec)\(    Matches: eval( or exec(
```
""",
    )

    assert find_active_dynamic_execution(skill) == []
    assert check_active_dynamic_execution(skill) == []


def test_bold_prose_does_not_reclassify_following_active_code(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Usage

**Run this carefully**
```python
eval(payload)
```
""",
    )

    assert [call.api_class for call in find_active_dynamic_execution(skill)] == ["python_eval"]


def test_bold_label_does_not_escape_parent_example_section(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Python integration example

**Initialization and remote access:**
```python
import subprocess
subprocess.run(command)
```
""",
    )

    assert find_active_dynamic_execution(skill) == []


def test_malformed_and_oversized_regions_decline_without_partial_finding(tmp_path: Path) -> None:
    malformed = _skill(
        tmp_path,
        """# Usage
```python
eval(payload
if (
```
""",
    )
    assert check_active_dynamic_execution(malformed) == []

    oversized = _skill(tmp_path, "x" * (MAX_DOCUMENT_BYTES + 1) + "\neval(payload)\n")
    assert check_active_dynamic_execution(oversized) == []


def test_finding_projects_complete_typed_command_facts(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Usage
```python
import os
os.system(command)
```
""",
    )
    findings = check_active_dynamic_execution(skill)
    assert len(findings) == 1

    facts = ScanFactProjector().project(skill, findings[0], findings)

    assert facts.projection.complete, list(facts.projection.error_codes)
    assert not facts.projection.truncated
    assert facts.candidate.rule_id == RULE_ID
    assert facts.candidate.analyzer == "static"
    assert facts.candidate.category == "command_injection"
    assert facts.candidate.severity == "HIGH"
    assert facts.candidate.evidence_kind == "command"
    assert facts.candidate.context_kind == "code"
    assert facts.candidate.evidence_value_class == "execution_api"
    assert facts.candidate.evidence_count == 1
    assert facts.candidate.command.executes
    assert facts.candidate.command.source_class == "skill_code"
    assert facts.candidate.command.sink_class == "process_execution"
    assert facts.candidate.command.file_path == "SKILL.md"
    assert "inline_code" in facts.candidate.command.argument_classes
    assert any(signal.kind == "fenced_code_language" for signal in facts.skill.signals)


def test_five_runs_have_exactly_stable_finding_identity_and_facts(tmp_path: Path) -> None:
    skill = _skill(
        tmp_path,
        """# Execute
```javascript
const { exec: launch } = require("node:child_process");
launch(command);
```
""",
    )

    runs = []
    for _ in range(5):
        findings = check_active_dynamic_execution(skill)
        facts = ScanFactProjector().project(skill, findings[0], findings)
        runs.append((findings[0].to_dict(), facts.SerializeToString(deterministic=True)))

    assert all(run == runs[0] for run in runs[1:])


def test_core_manifest_declares_authoritative_v2_metadata() -> None:
    manifest_path = Path(__file__).parents[1] / "skill_scanner" / "data" / "packs" / "core" / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 2
    assert manifest["rules"][RULE_ID] == {
        "source": "python",
        "analyzer": "static",
        "category": "command_injection",
        "severity": "HIGH",
        "knobs": {"enabled": True},
        "description": "Syntax-confirmed dynamic code or process execution in active SKILL.md instructions",
    }


def test_aggregate_development_evidence_is_hash_bound_to_rule_and_dataset_lock() -> None:
    repository = Path(__file__).parents[1]
    fixture = repository / "tests" / "fixtures" / "active_dynamic_execution_msb_non_test_2026-09-02.json"
    sidecar = fixture.with_suffix(fixture.suffix + ".sha256")
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    expected_fixture_hash = sidecar.read_text(encoding="utf-8").split(maxsplit=1)[0]
    actual_fixture_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    implementation = repository / "skill_scanner" / "core" / "rules" / "active_dynamic_execution.py"
    tokenizer = repository / "skill_scanner" / "core" / "static_analysis" / "javascript_tokens.py"

    assert actual_fixture_hash == expected_fixture_hash
    assert hashlib.sha256(implementation.read_bytes()).hexdigest() == payload["rule"]["implementation_sha256"]
    assert hashlib.sha256(tokenizer.read_bytes()).hexdigest() == payload["rule"]["tokenizer_sha256"]
    assert payload["rule"]["id"] == RULE_ID
    assert payload["dataset"]["sealed_test_rows"] == 0
    assert payload["dataset"]["raw_content_embedded"] is False
    assert payload["package_results"]["rule_hits_benign"] == 0
    assert payload["package_results"]["new_actionable_benign"] == 0
    assert payload["package_results"]["net_core_blocker_lift_malicious"] > 0
    assert payload["determinism"] == {
        "runs": 5,
        "stable": True,
        "normalization": (
            "ordered sample identity/label/calls(api_class,language,line,context), canonical compact sorted-key JSON"
        ),
        "normalized_output_sha256": "10b3635a0f21c7006ad035e1747e4a81c568cf083596e8fa9af7ed3500eec5b5",
    }
    assert "benchmark_id" not in fixture.read_text(encoding="utf-8")

    dataset_lock = json.loads(
        (repository / "evals" / "datasets" / "public-datasets.lock.json").read_text(encoding="utf-8")
    )
    locked = next(item for item in dataset_lock["datasets"] if item["id"] == payload["dataset"]["id"])
    assert locked["revision"] == payload["dataset"]["revision"]
    assert locked["integrity"]["artifact_manifest_sha256"] == payload["dataset"]["artifact_manifest_sha256"]
