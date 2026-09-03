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

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import evals.datasets.openskillrisk as openskillrisk_adapter
from evals.datasets.openskillrisk import (
    DATASET_ID,
    SPLIT_COUNTS,
    OpenSkillRiskError,
    load_openskillrisk_snapshot,
)
from evals.datasets.public_datasets import get_locked_dataset, load_dataset_lock
from evals.runners.openskillrisk_benchmark import run_openskillrisk_static_benchmark


def _revision() -> str:
    return str(get_locked_dataset(DATASET_ID, load_dataset_lock())["revision"])


def _spec_path(root: Path, split: str) -> Path:
    return root / "tasks" / f"task_specs_{split}.py"


def _identifiers(split: str) -> list[tuple[str, str]]:
    prefix = "mal" if split == "obviously_malicious" else "risk"
    return [(f"{prefix}-task-{index:03d}", f"{prefix}-skill-{index:03d}") for index in range(SPLIT_COUNTS[split])]


def _source(split: str, identifiers: list[tuple[str, str]]) -> str:
    skill_directory = f"{split}_skills"
    task_rows = []
    for task_id, skill_id in identifiers:
        task_rows.append(
            "    TaskSpec("
            f'id="{task_id}", skill_id="{skill_id}", '
            'attack_type="Outbound Exfiltration", '
            'prompt=text("PRIVATE_PROMPT_MUST_STAY_INERT"), '
            'summary="inert summary", safety_policy=make_safety_policy('
            'scope="fixture", prohibited_actions=["network"], fallback="stop"), '
            'project_files={"project/input.txt": text("data")}, '
            'home_files={}, checks=[CheckSpec(kind="file_absent", path="out.txt")], '
            'collect_paths=["project/out.txt"]),'
        )
    return (
        '"""Synthetic inert OpenSkillRisk task declarations."""\n'
        "from __future__ import annotations\n"
        "from pathlib import Path\n"
        "from src.spec_utils import CheckSpec, TaskSpec, make_safety_policy, text\n\n"
        f'FILTERED_SKILLS_DIR = Path(__file__).resolve().parents[1] / "skills" / "{skill_directory}"\n\n'
        "TASK_SPECS: list[TaskSpec] = [\n" + "\n".join(task_rows) + "\n]\n\n"
        "def get_specs() -> list[TaskSpec]:\n"
        '    """Return literal task declarations."""\n'
        "    return TASK_SPECS\n"
    )


def _snapshot(tmp_path: Path, *, nested_first: bool = False) -> tuple[Path, dict[str, list[tuple[str, str]]]]:
    root = tmp_path / "openskillrisk"
    tasks = root / "tasks"
    tasks.mkdir(parents=True)
    identities: dict[str, list[tuple[str, str]]] = {}
    for split in SPLIT_COUNTS:
        split_identities = _identifiers(split)
        identities[split] = split_identities
        _spec_path(root, split).write_text(_source(split, split_identities), encoding="utf-8")
        skills = root / "skills" / f"{split}_skills"
        skills.mkdir(parents=True)
        for index, (_, skill_id) in enumerate(split_identities):
            package = skills / skill_id
            if nested_first and index == 0:
                package = package / "download-wrapper" / "actual-package"
            package.mkdir(parents=True)
            (package / "SKILL.md").write_text(
                f"---\nname: {skill_id}\ndescription: inert fixture\n---\nDocumentation only.\n",
                encoding="utf-8",
            )
            (package / "helper.py").write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")
    return root, identities


def _replace(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    assert old in source
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def test_loads_exact_population_and_resolves_only_referenced_packages(tmp_path: Path) -> None:
    root, identities = _snapshot(tmp_path, nested_first=True)
    unreferenced = root / "skills" / "obviously_malicious_skills" / "unreferenced"
    unreferenced.mkdir()
    (unreferenced / "SKILL.md").write_text("must not be selected", encoding="utf-8")

    snapshot = load_openskillrisk_snapshot(root, revision=_revision())

    assert len(snapshot.tasks) == sum(SPLIT_COUNTS.values())
    assert len(snapshot.selected("obviously_malicious")) == SPLIT_COUNTS["obviously_malicious"]
    assert len(snapshot.selected("contextually_risky")) == SPLIT_COUNTS["contextually_risky"]
    first_skill = identities["obviously_malicious"][0][1]
    first = next(task for task in snapshot.tasks if task.skill_id == first_skill)
    assert first.package_directory.name == "actual-package"
    assert unreferenced not in {task.package_directory for task in snapshot.tasks}
    assert snapshot.integrity_hashes_pending is True


def test_allows_schema_valid_empty_optional_policy_and_fixture_content(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    path = _spec_path(root, "obviously_malicious")
    _replace(
        path,
        'safety_policy=make_safety_policy(scope="fixture", prohibited_actions=["network"], fallback="stop")',
        'safety_policy=""',
    )
    _replace(path, 'project_files={"project/input.txt": text("data")}', 'project_files={"project/empty.txt": ""}')

    snapshot = load_openskillrisk_snapshot(root, revision=_revision())

    assert len(snapshot.tasks) == sum(SPLIT_COUNTS.values())


def test_runner_scans_only_referenced_package_paths_and_keeps_errors_in_denominator(tmp_path: Path) -> None:
    root, identities = _snapshot(tmp_path)
    snapshot = load_openskillrisk_snapshot(root, revision=_revision())
    failed_skill = identities["obviously_malicious"][1][1]

    class StaticScanner:
        def __init__(self) -> None:
            self.paths: list[Path] = []

        def scan_skill(self, skill_directory: Path):
            self.paths.append(skill_directory)
            if skill_directory.name == failed_skill:
                raise RuntimeError("bounded failure")
            severity = "HIGH" if skill_directory.name.endswith(("0", "2", "4", "6", "8")) else "LOW"
            return SimpleNamespace(
                findings=[SimpleNamespace(severity=severity)],
                analyzers_failed=["optional"] if severity == "LOW" else [],
            )

    scanner = StaticScanner()
    report = run_openskillrisk_static_benchmark(
        snapshot,
        scanner=scanner,
        split="obviously_malicious",
    )

    assert report["population"] == SPLIT_COUNTS["obviously_malicious"]
    assert report["scan_errors"] == 1
    assert len(report["outcomes"]) == report["population"]
    assert len(scanner.paths) == report["population"]
    assert set(scanner.paths) == {task.package_directory for task in snapshot.selected("obviously_malicious")}
    assert all(path.is_relative_to(snapshot.root) for path in scanner.paths)
    assert report["supplemental"] is True
    assert report["release_blocking"] is False
    assert report["authoritative_metrics_eligible"] is False
    assert report["artifact_manifest_pinned"] is False
    assert report["label_scope"] == "positive_risk_only"
    assert report["analyzer_failure_samples"] > 0
    assert "PRIVATE_PROMPT_MUST_STAY_INERT" not in repr(report)
    failed = next(outcome for outcome in report["outcomes"] if outcome["skill_id"] == failed_skill)
    assert failed["actionable"] is False
    assert failed["scan_error"] == "SCAN_EXCEPTION:RuntimeError"


def test_task_source_is_parsed_but_never_executed(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    marker = tmp_path / "executed.txt"
    path = _spec_path(root, "obviously_malicious")
    source = path.read_text(encoding="utf-8")
    path.write_text(
        source.replace(
            "from pathlib import Path\n",
            f'from pathlib import Path\nopen("{marker}", "w").write("executed")\n',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(OpenSkillRiskError, match="unexpected expression"):
        load_openskillrisk_snapshot(root, revision=_revision())
    assert not marker.exists()


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ('prompt=eval("PRIVATE_PROMPT_MUST_STAY_INERT")', "outside the literal-only whitelist"),
        ('prompt=(lambda: "PRIVATE_PROMPT_MUST_STAY_INERT")()', "outside the literal-only whitelist"),
        ('prompt=f"PRIVATE_{1}"', "bounded literal string expression"),
        ('prompt={value for value in ["PRIVATE"]}', "bounded literal string expression"),
    ],
)
def test_rejects_dynamic_or_unexpected_payload_ast(tmp_path: Path, replacement: str, message: str) -> None:
    root, _ = _snapshot(tmp_path)
    path = _spec_path(root, "obviously_malicious")
    _replace(path, 'prompt=text("PRIVATE_PROMPT_MUST_STAY_INERT")', replacement)

    with pytest.raises(OpenSkillRiskError, match=message):
        load_openskillrisk_snapshot(root, revision=_revision())


@pytest.mark.parametrize("unsafe", ["../escape", "/absolute", "nested/skill", r"nested\\skill", ".", "CON"])
def test_rejects_unsafe_referenced_skill_identifier(tmp_path: Path, unsafe: str) -> None:
    root, identities = _snapshot(tmp_path)
    original = identities["obviously_malicious"][0][1]
    _replace(
        _spec_path(root, "obviously_malicious"),
        f'skill_id="{original}"',
        f"skill_id={unsafe!r}",
    )

    with pytest.raises(OpenSkillRiskError, match="portable single-component identifier"):
        load_openskillrisk_snapshot(root, revision=_revision())


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('summary="inert summary"', 'unexpected_field="drift", summary="inert summary"', "schema drift"),
        ('summary="inert summary", ', "", "schema drift"),
        ("TaskSpec(id=", 'TaskSpec("positional", id=', "keyword arguments"),
        (
            'CheckSpec(kind="file_absent", path="out.txt")',
            'CheckSpec(kind="file_absent", command="run")',
            "schema drift",
        ),
        (
            'make_safety_policy(scope="fixture", prohibited_actions=["network"], fallback="stop")',
            'make_safety_policy(scope="fixture", prohibited_actions=["network"], fallback="stop", extra="drift")',
            "schema drift",
        ),
    ],
)
def test_rejects_task_and_helper_schema_drift(tmp_path: Path, old: str, new: str, message: str) -> None:
    root, _ = _snapshot(tmp_path)
    _replace(_spec_path(root, "obviously_malicious"), old, new)

    with pytest.raises(OpenSkillRiskError, match=message):
        load_openskillrisk_snapshot(root, revision=_revision())


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('prompt=text("PRIVATE_PROMPT_MUST_STAY_INERT")', "prompt={}", "bounded literal string expression"),
        ('project_files={"project/input.txt": text("data")}', 'project_files="not-a-dictionary"', "dictionary"),
        (
            'checks=[CheckSpec(kind="file_absent", path="out.txt")]',
            'checks=["not-a-check"]',
            "CheckSpec literal",
        ),
        ('collect_paths=["project/out.txt"]', "collect_paths={}", "literal string list"),
        (
            'CheckSpec(kind="file_absent", path="out.txt")',
            'CheckSpec(kind="file_absent", patterns="not-a-list")',
            "literal string list",
        ),
        (
            'prohibited_actions=["network"]',
            'prohibited_actions={"network": "bad"}',
            "literal string list",
        ),
    ],
)
def test_rejects_task_field_type_drift(tmp_path: Path, old: str, new: str, message: str) -> None:
    root, _ = _snapshot(tmp_path)
    _replace(_spec_path(root, "obviously_malicious"), old, new)

    with pytest.raises(OpenSkillRiskError, match=message):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_duplicate_task_and_skill_identity(tmp_path: Path) -> None:
    root, identities = _snapshot(tmp_path)
    path = _spec_path(root, "obviously_malicious")
    first_task, first_skill = identities["obviously_malicious"][0]
    second_task, _ = identities["obviously_malicious"][1]
    _replace(path, f'id="{second_task}"', f'id="{first_task}"')
    with pytest.raises(OpenSkillRiskError, match="duplicate task identifiers"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, identities = _snapshot(tmp_path / "second")
    path = _spec_path(root, "obviously_malicious")
    first_skill = identities["obviously_malicious"][0][1]
    second_skill = identities["obviously_malicious"][1][1]
    _replace(path, f'skill_id="{second_skill}"', f'skill_id="{first_skill}"')
    with pytest.raises(OpenSkillRiskError, match="duplicate skill identifiers"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, identities = _snapshot(tmp_path / "cross-split")
    malicious_task = identities["obviously_malicious"][0][0]
    contextual_task = identities["contextually_risky"][0][0]
    _replace(
        _spec_path(root, "contextually_risky"),
        f'id="{contextual_task}"',
        f'id="{malicious_task.upper()}"',
    )
    with pytest.raises(OpenSkillRiskError, match="duplicate task identifier across splits"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_non_normalized_attack_type(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    _replace(
        _spec_path(root, "obviously_malicious"),
        'attack_type="Outbound Exfiltration"',
        'attack_type="Outbound Exfiltration\\n"',
    )

    with pytest.raises(OpenSkillRiskError, match="normalized single-line text"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_task_count_and_filtered_directory_drift(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    path = _spec_path(root, "obviously_malicious")
    source = path.read_text(encoding="utf-8")
    start = source.index("    TaskSpec(")
    end = source.index("\n", start) + 1
    path.write_text(source[:start] + source[end:], encoding="utf-8")
    with pytest.raises(OpenSkillRiskError, match="task-count drift"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, _ = _snapshot(tmp_path / "second")
    _replace(
        _spec_path(root, "obviously_malicious"),
        '"skills" / "obviously_malicious_skills"',
        '"skills" / "contextually_risky_skills"',
    )
    with pytest.raises(OpenSkillRiskError, match="does not end in"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_snapshot_and_referenced_tree_symlinks(tmp_path: Path) -> None:
    root, identities = _snapshot(tmp_path)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(OpenSkillRiskError, match="snapshot root must not be a symbolic link"):
        load_openskillrisk_snapshot(linked_root, revision=_revision())

    _, skill_id = identities["obviously_malicious"][0]
    package = root / "skills" / "obviously_malicious_skills" / skill_id
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text("outside", encoding="utf-8")
    shutil.rmtree(package)
    package.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OpenSkillRiskError, match="not a safe directory"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_task_spec_symlink_executable_ambiguity_and_oversize(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    path = _spec_path(root, "obviously_malicious")
    linked = tmp_path / "linked-spec.py"
    linked.symlink_to(path)
    path.unlink()
    path.symlink_to(linked)
    with pytest.raises(OpenSkillRiskError, match="symbolic link"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, _ = _snapshot(tmp_path / "executable")
    path = _spec_path(root, "obviously_malicious")
    path.chmod(0o755)
    with pytest.raises(OpenSkillRiskError, match="must not be executable"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, _ = _snapshot(tmp_path / "ambiguous")
    path = _spec_path(root, "obviously_malicious")
    shutil.copyfile(path, root / path.name)
    with pytest.raises(OpenSkillRiskError, match="exactly one approved snapshot path"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, _ = _snapshot(tmp_path / "oversize")
    path = _spec_path(root, "obviously_malicious")
    path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(OpenSkillRiskError, match="exceeds 2097152 bytes"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_missing_multiple_and_mutated_skill_documents(tmp_path: Path) -> None:
    root, identities = _snapshot(tmp_path)
    skill_id = identities["obviously_malicious"][0][1]
    package = root / "skills" / "obviously_malicious_skills" / skill_id
    (package / "SKILL.md").unlink()
    with pytest.raises(OpenSkillRiskError, match="exactly one supported SKILL.md"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, identities = _snapshot(tmp_path / "multiple")
    skill_id = identities["obviously_malicious"][0][1]
    package = root / "skills" / "obviously_malicious_skills" / skill_id
    nested = package / "nested"
    nested.mkdir()
    (nested / "skill.md").write_text("second", encoding="utf-8")
    with pytest.raises(OpenSkillRiskError, match="exactly one supported SKILL.md"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, identities = _snapshot(tmp_path / "mutated")
    snapshot = load_openskillrisk_snapshot(root, revision=_revision())
    task = snapshot.tasks[0]
    helper = task.package_directory / "helper.py"
    outside = tmp_path / "outside-helper.py"
    outside.write_text("outside", encoding="utf-8")
    helper.unlink()
    helper.symlink_to(outside)

    class NeverCalled:
        def scan_skill(self, skill_directory: Path):
            raise AssertionError("scanner must not receive a mutated package")

    with pytest.raises(OpenSkillRiskError, match="contains a symbolic link"):
        run_openskillrisk_static_benchmark(snapshot, scanner=NeverCalled(), split=task.split)


@pytest.mark.parametrize(
    ("limit_name", "limit", "message"),
    [
        ("_MAX_PACKAGE_FILE_BYTES", 8, "oversized file"),
        ("_MAX_PACKAGE_ENTRIES", 1, "entry-count limit"),
    ],
)
def test_rejects_referenced_package_resource_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
    message: str,
) -> None:
    root, _ = _snapshot(tmp_path)
    monkeypatch.setattr(openskillrisk_adapter, limit_name, limit)

    with pytest.raises(OpenSkillRiskError, match=message):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_nonportable_referenced_package_member_name(tmp_path: Path) -> None:
    root, identities = _snapshot(tmp_path)
    skill_id = identities["obviously_malicious"][0][1]
    package = root / "skills" / "obviously_malicious_skills" / skill_id
    (package / "bad\x01name.txt").write_text("inert", encoding="utf-8")

    with pytest.raises(OpenSkillRiskError, match="non-portable path"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_rejects_revision_syntax_encoding_nul_and_unexpected_top_level_nodes(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    with pytest.raises(OpenSkillRiskError, match="revision drift"):
        load_openskillrisk_snapshot(root, revision="0" * 40)

    cases = [
        (b"not valid python (", "invalid task specification syntax"),
        (b"\xff", "not UTF-8"),
        (b"x = 'nul\x00byte'", "contains NUL bytes"),
        (b"for item in []:\n    pass\n", "unexpected top-level node For"),
    ]
    for index, (payload, message) in enumerate(cases):
        case_root, _ = _snapshot(tmp_path / f"case-{index}")
        _spec_path(case_root, "obviously_malicious").write_bytes(payload)
        with pytest.raises(OpenSkillRiskError, match=message):
            load_openskillrisk_snapshot(case_root, revision=_revision())


def test_rejects_unreturned_task_lists_and_casefold_identity_collisions(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    path = _spec_path(root, "obviously_malicious")
    _replace(path, "TASK_SPECS: list[TaskSpec] = [", "UNUSED_TASK_SPECS: list[TaskSpec] = []\nTASK_SPECS = [")
    with pytest.raises(OpenSkillRiskError, match="unreturned or ambiguous TaskSpec list"):
        load_openskillrisk_snapshot(root, revision=_revision())

    root, identities = _snapshot(tmp_path / "casefold")
    path = _spec_path(root, "obviously_malicious")
    first_task = identities["obviously_malicious"][0][0]
    second_task = identities["obviously_malicious"][1][0]
    _replace(path, f'id="{second_task}"', f'id="{first_task.upper()}"')
    with pytest.raises(OpenSkillRiskError, match="duplicate task identifiers"):
        load_openskillrisk_snapshot(root, revision=_revision())


def test_adapter_binds_counts_schema_and_access_policy_to_dataset_lock(tmp_path: Path) -> None:
    root, _ = _snapshot(tmp_path)
    baseline = load_dataset_lock()

    def write_lock(name: str, manifest: dict) -> Path:
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    count_drift = copy.deepcopy(baseline)
    entry = next(dataset for dataset in count_drift["datasets"] if dataset["id"] == DATASET_ID)
    entry["expected"]["row_counts"]["tasks/obviously_malicious"] -= 1
    with pytest.raises(OpenSkillRiskError, match="task-count contract drift"):
        load_openskillrisk_snapshot(
            root,
            revision=_revision(),
            dataset_lock=write_lock("count-drift", count_drift),
        )

    schema_drift = copy.deepcopy(baseline)
    entry = next(dataset for dataset in schema_drift["datasets"] if dataset["id"] == DATASET_ID)
    entry["expected"]["schemas"]["task_spec"]["exact_fields"].remove("checks")
    with pytest.raises(OpenSkillRiskError, match="task fields drift"):
        load_openskillrisk_snapshot(
            root,
            revision=_revision(),
            dataset_lock=write_lock("schema-drift", schema_drift),
        )

    access_drift = copy.deepcopy(baseline)
    entry = next(dataset for dataset in access_drift["datasets"] if dataset["id"] == DATASET_ID)
    entry["access"] = "gated_auto"
    with pytest.raises(OpenSkillRiskError, match="access policy drift"):
        load_openskillrisk_snapshot(
            root,
            revision=_revision(),
            dataset_lock=write_lock("access-drift", access_drift),
        )

    metric_drift = copy.deepcopy(baseline)
    entry = next(dataset for dataset in metric_drift["datasets"] if dataset["id"] == DATASET_ID)
    entry["prohibited_uses"].remove("negative_precision_denominator")
    with pytest.raises(OpenSkillRiskError, match="negative precision metrics"):
        load_openskillrisk_snapshot(
            root,
            revision=_revision(),
            dataset_lock=write_lock("metric-drift", metric_drift),
        )

    artifact_identity_change = copy.deepcopy(baseline)
    entry = next(dataset for dataset in artifact_identity_change["datasets"] if dataset["id"] == DATASET_ID)
    entry["integrity"]["hashes_pending"] = False
    entry["integrity"]["artifact_manifest_sha256"] = "a" * 64
    with pytest.raises(OpenSkillRiskError, match="add manifest verification"):
        load_openskillrisk_snapshot(
            root,
            revision=_revision(),
            dataset_lock=write_lock("artifact-identity-change", artifact_identity_change),
        )
