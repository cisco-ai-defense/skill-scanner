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

"""Regression tests for supported Python and release packaging metadata."""

from __future__ import annotations

import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_python_range_classifiers_and_tool_targets_are_aligned() -> None:
    document = _pyproject()
    classifiers = set(document["project"]["classifiers"])

    requires_python = document["project"]["requires-python"]
    assert requires_python == ">=3.11,<3.15"
    supported_python = SpecifierSet(requires_python)
    assert Version("3.10") not in supported_python
    assert all(Version(version) in supported_python for version in ("3.11", "3.12", "3.13", "3.14"))
    assert Version("3.15.0a1") not in supported_python
    assert Version("3.15") not in supported_python
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    assert SpecifierSet(lock["requires-python"]) == supported_python
    assert "Programming Language :: Python :: 3.10" not in classifiers
    assert {
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    } <= classifiers
    assert "Programming Language :: Python :: Implementation :: CPython" in classifiers
    assert "Operating System :: OS Independent" not in classifiers
    assert {
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
    } <= classifiers
    assert document["tool"]["ruff"]["target-version"] == "py311"
    assert document["tool"]["mypy"]["python_version"] == "3.11"


def test_protobuf_is_core_and_retired_python_cel_binding_is_not_declared() -> None:
    document = _pyproject()
    parsed_requirements = [Requirement(value) for value in document["project"]["dependencies"]]
    requirements = {requirement.name: requirement for requirement in parsed_requirements}

    protobuf = requirements["protobuf"]
    assert Version("5.29") in protobuf.specifier
    assert Version("6.0") in protobuf.specifier
    assert Version("7.0") not in protobuf.specifier
    assert "cel-expr-python" not in requirements
    assert "cel" not in document["project"]["optional-dependencies"]


def test_unit_test_matrix_covers_every_supported_minor() -> None:
    workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/python-tests.yml").read_text(encoding="utf-8"))
    versions = workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]

    assert versions == ["3.11", "3.12", "3.13", "3.14"]


def _reusable_workflow_python_validation() -> tuple[str, str]:
    workflow_path = REPO_ROOT / ".github/workflows/scan-skills.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    document = yaml.safe_load(workflow)
    steps = document["jobs"]["scan"]["steps"]
    validation = next(step for step in steps if step.get("name") == "Validate supported Python version")
    return workflow, validation["run"]


def test_reusable_workflow_validates_supported_python_before_setup() -> None:
    workflow, validation = _reusable_workflow_python_validation()

    range_check = workflow.index("- name: Validate supported Python version")
    python_setup = workflow.index("- name: Set up Python", range_check)
    assert range_check < python_setup
    assert "python_version must be 3.11 or newer" in workflow
    assert "python_version must be 3.14 or older" in workflow
    assert "10#${BASH_REMATCH[1]} < 11" in validation
    assert "10#${BASH_REMATCH[1]} > 14" in validation


@pytest.mark.skipif(shutil.which("bash") is None, reason="the reusable workflow validation runs in Bash")
@pytest.mark.parametrize(
    ("version", "expected_error"),
    [
        ("3.10", "python_version must be 3.11 or newer"),
        ("3.15", "python_version must be 3.14 or older"),
    ],
)
def test_reusable_workflow_rejects_unsupported_python(version: str, expected_error: str) -> None:
    _, validation = _reusable_workflow_python_validation()
    environment = {**os.environ, "INPUT_PYTHON_VERSION": version}

    result = subprocess.run(
        ["bash", "-c", validation],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=10,
    )

    assert result.returncode == 1
    assert expected_error in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the reusable workflow validation runs in Bash")
@pytest.mark.parametrize("version", ["3.11", "3.12.9", "3.13", "3.14.1"])
def test_reusable_workflow_accepts_supported_python(version: str) -> None:
    _, validation = _reusable_workflow_python_validation()
    environment = {**os.environ, "INPUT_PYTHON_VERSION": version}

    result = subprocess.run(
        ["bash", "-c", validation],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_release_sbom_is_derived_from_the_all_extras_export() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    export = workflow.index("--all-extras")
    requirements = workflow.index("--output-file release-assets/requirements.txt", export)
    sbom = workflow.index("cyclonedx-py requirements", requirements)
    sbom_input = workflow.index("release-assets/requirements.txt", sbom)

    assert export < requirements < sbom < sbom_input


def test_release_sbom_root_graph_and_generator_warnings_fail_closed() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    start = workflow.index("- name: Generate CycloneDX SBOM")
    end = workflow.index("- name: Attest build provenance", start)
    block = workflow[start:end]
    generator = block[: block.index("scripts/export_cel_supply_chain.py")]

    assert "--pyproject" not in generator
    assert '2>"$RUNNER_TEMP/cyclonedx-stderr.txt"' in generator
    assert '[[ -s "$RUNNER_TEMP/cyclonedx-stderr.txt" ]]' in generator
    assert "--pyproject pyproject.toml" in block
    assert 'select(.name == "go-toolchain" and .version == "1.27.1")' in block
    assert '(.metadata.component["bom-ref"] == .metadata.component.purl)' in block
    assert 'select((.purl | startswith("pkg:pypi/")) or .name == "skill-scanner-cel-go")' in block


def test_release_builds_and_records_every_native_cel_target() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    for target in ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64"):
        assert f"target: {target}" in workflow
    assert 'go-version: "1.27.1"' in workflow
    assert "scripts/verify_cel_wheel.py" in workflow
    assert "scripts/smoke_cel_wheel_install.py" in workflow
    assert "scripts/smoke_cel_sdist_install.py" in workflow
    assert "--expected-python 3.12" in workflow
    assert "release-assets/cel-go-dependencies.json" in workflow
    assert "release-assets/cel-go-helpers.json" in workflow
    assert "scripts/export_cel_supply_chain.py" in workflow
    native_smoke = workflow.index("scripts/verify_cel_wheel.py")
    installed_smoke = workflow.index("scripts/smoke_cel_wheel_install.py", native_smoke)
    upload = workflow.index("- name: Upload platform wheel", installed_smoke)
    assert native_smoke < installed_smoke < upload
    sdist_build = workflow.index("uv build --sdist --out-dir dist")
    sdist_smoke = workflow.index("scripts/smoke_cel_sdist_install.py", sdist_build)
    publish = workflow.index("Publish package distributions to PyPI", sdist_smoke)
    assert sdist_build < sdist_smoke < publish
    assert "--target linux-amd64" in workflow[sdist_smoke:publish]


def test_sdist_contains_cel_build_hook_runtime_and_bootstrap() -> None:
    document = _pyproject()
    included = set(document["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])

    assert {
        "/hatch_build.py",
        "/scripts/build_cel_helper.py",
        "/scripts/cel_go_packaging.py",
        "/tools/cel_runtime/go.mod",
        "/tools/cel_runtime/go.sum",
        "/tools/cel_runtime/*.go",
    } <= included


def test_editable_build_reuses_only_an_integrity_verified_source_helper() -> None:
    hook = (REPO_ROOT / "hatch_build.py").read_text(encoding="utf-8")

    assert "verify_bundle_integrity" in hook
    assert 'manifest["helper"]["helper_version"] != package_version' in hook
    assert "checked-in CEL helper bundle is incomplete" in hook
    assert "--helper-version source-tree" in hook
