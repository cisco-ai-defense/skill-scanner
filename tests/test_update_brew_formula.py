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

"""Tests for architecture-sensitive Homebrew resource qualification."""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

import scripts.update_brew_formula as brew_formula
from scripts.update_brew_formula import (
    CEL_WHEEL_TAGS,
    HOMEBREW_MACOS_DEPLOYMENT_TARGET,
    HOMEBREW_PYTHON_PLATFORMS,
    SKIP_PACKAGES,
    download_verified_sdist,
    find_artifact,
    read_build_system_requirements,
    read_sdist_pyproject,
    render_formula,
    require_project_sdist,
    resolve_dependencies,
    select_macos_wheel_resource,
    select_macos_wheel_resources,
    validate_cel_project_wheels,
)

ROOT = Path(__file__).resolve().parents[1]


def _pypi_data(name: str, version: str, artifacts: list[tuple[str, str]]) -> dict:
    return {
        "info": {"name": name, "version": version},
        "urls": [
            {
                "filename": filename,
                "packagetype": package_type,
                "url": f"https://files.pythonhosted.org/{filename}",
                "digests": {"sha256": f"sha256-{index}"},
            }
            for index, (filename, package_type) in enumerate(artifacts)
        ],
    }


def _sdist(entries: list[tuple[str, bytes, str]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, payload, kind in entries:
            member = tarfile.TarInfo(name)
            if kind == "file":
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = payload.decode()
                archive.addfile(member)
            else:  # pragma: no cover - test helper misuse
                raise AssertionError(kind)
    return stream.getvalue()


def test_project_cel_wheels_require_both_exact_homebrew_architectures() -> None:
    data = _pypi_data(
        "cisco-ai-skill-scanner",
        "2.1.0",
        [(f"cisco_ai_skill_scanner-2.1.0-{CEL_WHEEL_TAGS['darwin-arm64']}.whl", "bdist_wheel")],
    )

    with pytest.raises(RuntimeError, match="darwin-amd64.*found 0"):
        validate_cel_project_wheels(data)


def test_project_cel_wheels_return_exact_urls_and_hashes() -> None:
    artifacts = [
        (f"cisco_ai_skill_scanner-2.1.0-{wheel_tag}.whl", "bdist_wheel") for wheel_tag in CEL_WHEEL_TAGS.values()
    ]
    data = _pypi_data("cisco-ai-skill-scanner", "2.1.0", artifacts)
    for index, entry in enumerate(data["urls"]):
        entry["digests"]["sha256"] = f"{index + 1:064x}"

    selected = validate_cel_project_wheels(data)

    assert set(selected) == {"darwin-amd64", "darwin-arm64"}
    assert selected["darwin-amd64"][1] == f"{1:064x}"
    assert selected["darwin-arm64"][1] == f"{2:064x}"


def test_existing_platform_wheel_fallback_remains_available() -> None:
    data = _pypi_data(
        "yara-x",
        "1.20.0",
        [
            ("yara_x-1.20.0-cp38-abi3-macosx_14_0_arm64.whl", "bdist_wheel"),
            ("yara_x-1.20.0-cp38-abi3-manylinux_2_28_x86_64.whl", "bdist_wheel"),
        ],
    )

    url, sha256 = find_artifact(data)

    assert url.endswith("macosx_14_0_arm64.whl")
    assert sha256 == "sha256-0"


def test_wheel_only_dependency_selects_independent_homebrew_architectures() -> None:
    data = _pypi_data(
        "yara-x",
        "1.20.0",
        [
            ("yara_x-1.20.0-cp38-abi3-macosx_14_0_arm64.whl", "bdist_wheel"),
            ("yara_x-1.20.0-cp38-abi3-macosx_14_0_x86_64.whl", "bdist_wheel"),
            ("yara_x-1.20.0-cp38-abi3-manylinux_2_28_x86_64.whl", "bdist_wheel"),
        ],
    )
    for index, entry in enumerate(data["urls"]):
        entry["digests"]["sha256"] = f"{index + 1:064x}"

    selected = select_macos_wheel_resources(data)

    assert selected["darwin-arm64"][0].endswith("macosx_14_0_arm64.whl")
    assert selected["darwin-amd64"][0].endswith("macosx_14_0_x86_64.whl")

    data["urls"] = [entry for entry in data["urls"] if "x86_64" not in entry["filename"]]
    with pytest.raises(RuntimeError, match="no CPython 3.12 wheel for darwin-amd64"):
        select_macos_wheel_resources(data)


def test_dependency_wheel_selection_prefers_a_portable_pure_wheel() -> None:
    data = _pypi_data(
        "example",
        "1.2.3",
        [
            ("example-1.2.3-cp312-none-macosx_14_0_arm64.whl", "bdist_wheel"),
            ("example-1.2.3-py3-none-any.whl", "bdist_wheel"),
            ("example-1.2.3.tar.gz", "sdist"),
        ],
    )
    for index, entry in enumerate(data["urls"]):
        entry["digests"]["sha256"] = f"{index + 1:064x}"

    url, sha256 = select_macos_wheel_resource(data, "darwin-arm64")

    assert url.endswith("example-1.2.3-py3-none-any.whl")
    assert sha256 == f"{2:064x}"


def test_dependency_wheel_selection_never_falls_back_to_an_sdist() -> None:
    data = _pypi_data("source-only", "1.0", [("source_only-1.0.tar.gz", "sdist")])

    with pytest.raises(RuntimeError, match="has no CPython 3.12 wheel"):
        select_macos_wheel_resource(data, "darwin-arm64")


def test_dependency_wheel_selection_rejects_an_unqualified_macos_floor() -> None:
    data = _pypi_data(
        "future-floor",
        "1.0",
        [("future_floor-1.0-cp312-none-macosx_15_0_arm64.whl", "bdist_wheel")],
    )
    data["urls"][0]["digests"]["sha256"] = "a" * 64

    with pytest.raises(RuntimeError, match="has no CPython 3.12 wheel"):
        select_macos_wheel_resource(data, "darwin-arm64")


def test_source_distribution_still_has_highest_priority() -> None:
    data = _pypi_data(
        "example",
        "1.2.3",
        [
            ("example-1.2.3-py3-none-any.whl", "bdist_wheel"),
            ("example-1.2.3.tar.gz", "sdist"),
        ],
    )

    url, sha256 = find_artifact(data)

    assert url.endswith("example-1.2.3.tar.gz")
    assert sha256 == "sha256-1"


def test_project_source_distribution_is_exact_and_mandatory() -> None:
    data = _pypi_data(
        "cisco-ai-skill-scanner",
        "2.1.0",
        [
            ("cisco_ai_skill_scanner-2.1.0.tar.gz", "sdist"),
            ("cisco_ai_skill_scanner-2.1.0-py3-none-any.whl", "bdist_wheel"),
        ],
    )
    data["urls"][0]["digests"]["sha256"] = "a" * 64

    assert require_project_sdist(data, "2.1.0") == (
        "https://files.pythonhosted.org/cisco_ai_skill_scanner-2.1.0.tar.gz",
        "a" * 64,
        "cisco_ai_skill_scanner-2.1.0.tar.gz",
    )
    with pytest.raises(RuntimeError, match="does not match requested"):
        require_project_sdist(data, "2.1.1")

    data["urls"] = [data["urls"][1]]
    with pytest.raises(RuntimeError, match="exactly one .tar.gz"):
        require_project_sdist(data, "2.1.0")


def test_sdist_pyproject_is_read_without_extracting_and_rejects_links() -> None:
    project = b'[project]\nname = "cisco-ai-skill-scanner"\nversion = "2.1.0"\n'
    payload = _sdist(
        [
            ("cisco_ai_skill_scanner-2.1.0/pyproject.toml", project, "file"),
            ("cisco_ai_skill_scanner-2.1.0/README.md", b"readme", "file"),
        ]
    )
    assert read_sdist_pyproject(payload) == project

    linked = _sdist(
        [
            ("cisco_ai_skill_scanner-2.1.0/pyproject.toml", project, "file"),
            ("cisco_ai_skill_scanner-2.1.0/linked", b"../../outside", "symlink"),
        ]
    )
    with pytest.raises(RuntimeError, match="unsupported source distribution member type"):
        read_sdist_pyproject(linked)


def test_sdist_download_is_bounded_and_hash_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"release-sdist"

    class Response:
        headers = {"Content-Length": str(len(payload))}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return payload

    monkeypatch.setattr(brew_formula.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())

    digest = hashlib.sha256(payload).hexdigest()
    assert download_verified_sdist("https://files.pythonhosted.org/release.tar.gz", digest) == payload
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        download_verified_sdist("https://files.pythonhosted.org/release.tar.gz", "0" * 64)


@pytest.mark.parametrize("python_platform", sorted(HOMEBREW_PYTHON_PLATFORMS.values()))
def test_dependency_resolution_uses_supplied_release_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, python_platform: str
) -> None:
    release_project = tmp_path / "release-sdist" / "pyproject.toml"
    release_project.parent.mkdir()
    release_project.write_text(
        """\
[build-system]
requires = ["hatchling>=1.27", "hatch-vcs>=0.5"]
build-backend = "hatchling.build"

[project]
name = "release"
version = "1"
dependencies = ["Example_Dep>=1"]
""",
        encoding="utf-8",
    )
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["cwd"] = kwargs["cwd"]
        observed["environment"] = kwargs["env"]
        observed["build_requirements"] = Path(command[4]).read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="Example_Dep==1.2.3\nhatchling==1.27.0\nhatch-vcs==0.5.0\npackaging==25.0\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert resolve_dependencies(release_project, python_platform=python_platform) == [
        ("example-dep", "1.2.3"),
        ("hatch-vcs", "0.5.0"),
        ("hatchling", "1.27.0"),
        ("packaging", "25.0"),
    ]
    command = observed["command"]
    assert isinstance(command, list)
    assert command[:4] == [
        "uv",
        "pip",
        "compile",
        str(release_project.resolve()),
    ]
    assert Path(command[4]).name.startswith("skill-scanner-build-system-")
    assert not Path(command[4]).exists()
    assert command[5:] == [
        "--no-header",
        "--no-annotate",
        "--only-binary",
        ":all:",
        "--python-version",
        "3.12",
        "--python-platform",
        python_platform,
    ]
    assert observed["build_requirements"] == "hatchling>=1.27\nhatch-vcs>=0.5\n"
    assert observed["cwd"] == release_project.parent.resolve()
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert environment["MACOSX_DEPLOYMENT_TARGET"] == HOMEBREW_MACOS_DEPLOYMENT_TARGET == "14.0"


def test_build_system_requirements_are_required_and_validated(tmp_path: Path) -> None:
    project_file = tmp_path / "pyproject.toml"
    project_file.write_text(
        '[build-system]\nrequires = ["hatchling", "hatch-vcs"]\nbuild-backend = "hatchling.build"\n',
        encoding="utf-8",
    )
    assert read_build_system_requirements(project_file) == ("hatchling", "hatch-vcs")

    project_file.write_text('[project]\nname = "missing-build-system"\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"missing \[build-system\]"):
        read_build_system_requirements(project_file)

    project_file.write_text('[build-system]\nrequires = [""]\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="non-empty strings"):
        read_build_system_requirements(project_file)


def test_current_build_backend_roots_are_included_in_formula_resolution() -> None:
    assert read_build_system_requirements(ROOT / "pyproject.toml") == ("hatchling", "hatch-vcs")
    assert "setuptools" not in SKIP_PACKAGES


def test_homebrew_dependency_resolution_requires_an_explicit_darwin_target(tmp_path: Path) -> None:
    project_file = tmp_path / "pyproject.toml"
    project_file.write_text(
        '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n',
        encoding="utf-8",
    )

    assert set(HOMEBREW_PYTHON_PLATFORMS.values()) == {
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    }
    with pytest.raises(ValueError, match="unsupported Homebrew Python platform"):
        resolve_dependencies(project_file, python_platform="linux")


def test_formula_builds_exact_host_helper_and_validates_rules() -> None:
    formula = render_formula(
        main_url="https://example.test/source.tar.gz",
        main_sha256="a" * 64,
        resources=[],
        cel_helper_wheels={
            "darwin-amd64": ("https://example.test/amd64.whl", "b" * 64),
            "darwin-arm64": ("https://example.test/arm64.whl", "c" * 64),
        },
        architecture_resources={
            "darwin-amd64": [("yara-x", "https://example.test/yara-amd64.whl", "d" * 64)],
            "darwin-arm64": [("yara-x", "https://example.test/yara-arm64.whl", "e" * 64)],
        },
    )

    assert "depends_on macos: :sonoma" in formula
    assert 'depends_on "go" => :build' in formula
    assert "on_arm do" in formula and "arm64.whl" in formula
    assert "on_intel do" in formula and "amd64.whl" in formula
    assert 'resource "yara-python"' not in formula
    assert 'depends_on "yara"' not in formula
    arm_block = formula.split("on_arm do", 1)[1].split("on_intel do", 1)[0]
    intel_block = formula.split("on_intel do", 1)[1].split("def install", 1)[0]
    assert 'resource "yara-x"' in arm_block
    assert 'resource "yara-x"' in intel_block
    assert "yara-arm64.whl" in arm_block and "yara-amd64.whl" not in arm_block
    assert "yara-amd64.whl" in intel_block and "yara-arm64.whl" not in intel_block
    assert 'Hardware::CPU.arm? ? "darwin-arm64" : "darwin-amd64"' in formula
    assert "SKILL_SCANNER_CEL_GO_PREBUILT_DIR" in formula
    assert 'ENV["PIP_NO_INDEX"] = "1"' in formula
    assert 'ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"' in formula
    assert 'venv = virtualenv_create(libexec, "python3.12")' in formula
    assert 'dependency_resources = resources.reject { |resource| resource.name == "cel-helper" }' in formula
    assert 'wheelhouse = buildpath/"dependency-wheelhouse"' in formula
    assert "dependency_resources.each { |resource| resource.stage(wheelhouse) }" in formula
    assert 'dependency_wheels.all? { |wheel| wheel.file? && wheel.extname == ".whl" }' in formula
    assert 'venv.pip_install dependency_wheels.join("\\n"), build_isolation: false' in formula
    assert formula.count("venv.pip_install dependency_wheels") == 1
    # Homebrew cache paths are hash-prefixed (sha256--distribution.whl) and are
    # invalid wheel filenames. The formula must stage each :nounzip resource to
    # recover its original basename before passing paths to pip.
    assert "resource.cached_download" not in formula
    assert "venv.pip_install_and_link buildpath, build_isolation: false" in formula
    assert "virtualenv_install_with_resources" not in formula
    assert "build_isolation: true" not in formula
    assert 'url "https://example.test/yara-amd64.whl", using: :nounzip' in formula
    assert 'url "https://example.test/yara-arm64.whl", using: :nounzip' in formula
    assert 'system "#{bin}/skill-scanner", "validate-rules"' in formula
    ruby = shutil.which("ruby")
    if ruby is not None:
        syntax = subprocess.run([ruby, "-c"], input=formula, capture_output=True, text=True, timeout=10)
        assert syntax.returncode == 0, syntax.stdout + syntax.stderr


def test_homebrew_workflow_uses_exact_tag_sdist_and_smokes_both_macos_architectures() -> None:
    workflow = (ROOT / ".github/workflows/update-homebrew.yml").read_text(encoding="utf-8")

    assert "Resolve exact tag commit" in workflow
    assert "ref: ${{ needs.resolve-release.outputs.release_sha }}" in workflow
    assert "macos-26\n" in workflow
    assert "macos-26-intel" in workflow
    assert "target: darwin-arm64" in workflow
    assert "target: darwin-amd64" in workflow
    assert "brew install --build-from-source generated-formula/skill-scanner.rb" in workflow
    assert "grep -F 'depends_on macos: :sonoma' Formula/skill-scanner.rb" in workflow
    assert 'assert helper["macos_minimum"] == "13.0"' in workflow
    assert 'assert helper["toolchain_version"] == "go1.27.1"' in workflow
    assert 'grep -F \'ENV["PIP_NO_INDEX"] = "1"\'' in workflow
    assert "dependency_resources = resources.reject" in workflow
    assert "resource.stage(wheelhouse)" in workflow
    assert 'venv.pip_install dependency_wheels.join("\\n"), build_isolation: false' in workflow
    assert "Generated formula must stage wheels under their valid distribution filenames" in workflow
    assert "venv.pip_install_and_link buildpath, build_isolation: false" in workflow
    assert "Generated formula must disable PEP 517 build isolation explicitly" in workflow
    assert '"$prefix/bin/skill-scanner" validate-rules' in workflow
    assert "brew test skill-scanner" in workflow
    assert workflow.index("smoke-homebrew:") < workflow.index("commit-formula:")
