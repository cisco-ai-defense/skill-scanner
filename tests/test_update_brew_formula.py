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
    download_verified_sdist,
    find_artifact,
    read_sdist_pyproject,
    render_formula,
    require_project_sdist,
    resolve_dependencies,
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


def test_dependency_resolution_uses_supplied_release_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_project = tmp_path / "release-sdist" / "pyproject.toml"
    release_project.parent.mkdir()
    release_project.write_text('[project]\nname = "release"\nversion = "1"\n', encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(command, 0, stdout="Example_Dep==1.2.3\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert resolve_dependencies(release_project) == [("example-dep", "1.2.3")]
    assert observed["command"] == [
        "uv",
        "pip",
        "compile",
        str(release_project.resolve()),
        "--no-header",
        "--no-annotate",
        "--python-version",
        "3.12",
    ]
    assert observed["cwd"] == release_project.parent.resolve()


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
    assert 'virtualenv_install_with_resources(without: "cel-helper")' in formula
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
    assert 'assert helper["macos_minimum"] == "13.0"' in workflow
    assert 'assert helper["toolchain_version"] == "go1.27.1"' in workflow
    assert '"$prefix/bin/skill-scanner" validate-rules' in workflow
    assert "brew test skill-scanner" in workflow
    assert workflow.index("smoke-homebrew:") < workflow.index("commit-formula:")
