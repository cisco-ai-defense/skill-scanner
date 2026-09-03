# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.export_cel_supply_chain import (
    download_module_metadata,
    enrich_sbom,
    load_project_component,
    parse_json_stream,
)


def test_parse_concatenated_go_mod_download_json() -> None:
    assert parse_json_stream('{"Path":"a"}\n{"Path":"b"}\n') == [{"Path": "a"}, {"Path": "b"}]


def test_module_export_cannot_mutate_checked_in_go_sum(tmp_path: Path, monkeypatch) -> None:
    module_dir = tmp_path / "source"
    module_dir.mkdir()
    (module_dir / "go.mod").write_text("module example.test/helper\n", encoding="utf-8")
    (module_dir / "go.sum").write_text("tidy-lock\n", encoding="utf-8")
    executed_in: list[Path] = []

    def fake_run(command, *, cwd, **kwargs):
        isolated = Path(cwd)
        executed_in.append(isolated)
        assert isolated != module_dir
        assert kwargs["env"]["GOWORK"] == "off"
        (isolated / "go.sum").write_text("expanded-by-go-download\n", encoding="utf-8")
        output = json.dumps(
            {
                "Path": "cel.dev/cel-go",
                "Version": "v0.32.0",
                "Sum": "h1:module",
                "GoModSum": "h1:gomod",
            }
        )
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr("scripts.export_cel_supply_chain.subprocess.run", fake_run)

    modules = download_module_metadata(module_dir)

    assert modules == [
        {
            "module": "cel.dev/cel-go",
            "version": "v0.32.0",
            "module_sum": "h1:module",
            "go_mod_sum": "h1:gomod",
        }
    ]
    assert executed_in
    assert (module_dir / "go.sum").read_text(encoding="utf-8") == "tidy-lock\n"


def test_sbom_includes_go_modules_helper_hash_and_dependency_edges() -> None:
    sbom = {
        "bomFormat": "CycloneDX",
        "metadata": {},
        "components": [
            {
                "type": "library",
                "bom-ref": "requirements-L1",
                "name": "pyyaml",
                "version": "6.0.3",
                "purl": "pkg:pypi/pyyaml@6.0.3",
            }
        ],
        "dependencies": [{"ref": "requirements-L1"}],
    }
    modules = [
        {
            "module": "cel.dev/cel-go",
            "version": "v0.32.0",
            "module_sum": "h1:module",
            "go_mod_sum": "h1:gomod",
        }
    ]
    helpers = [
        {
            "target": "linux-amd64",
            "wheel": "scanner-cp311.cp312.cp313.cp314-none-manylinux_2_17_x86_64.whl",
            "sha256": "a" * 64,
            "cel_go_version": "v0.32.0",
            "go_version": "go1.27.1",
            "toolchain_version": "go1.27.1",
        }
    ]

    result = enrich_sbom(sbom, modules=modules, helpers=helpers, project_version="1.2.3")

    root_ref = "pkg:pypi/cisco-ai-skill-scanner@1.2.3"
    helper_ref = "pkg:generic/skill-scanner-cel-go@1.2.3?target=linux-amd64"
    module_ref = "pkg:golang/cel.dev/cel-go@v0.32.0"
    python_ref = "pkg:pypi/pyyaml@6.0.3"
    toolchain_ref = "pkg:generic/go-toolchain@1.27.1"
    assert result["metadata"]["component"]["bom-ref"] == root_ref
    assert {component["bom-ref"] for component in result["components"]} == {
        helper_ref,
        module_ref,
        python_ref,
        toolchain_ref,
    }
    helper = next(component for component in result["components"] if component["bom-ref"] == helper_ref)
    assert helper["purl"] == helper_ref
    assert helper["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    dependencies = {entry["ref"]: entry.get("dependsOn", []) for entry in result["dependencies"]}
    assert dependencies[root_ref] == sorted([helper_ref, python_ref])
    assert dependencies[helper_ref] == sorted([module_ref, toolchain_ref])
    assert dependencies[python_ref] == []
    assert dependencies[toolchain_ref] == []


def test_project_component_is_canonical_and_version_bound() -> None:
    component = load_project_component(Path(__file__).resolve().parents[1] / "pyproject.toml", "1.2.3")

    assert component["name"] == "cisco-ai-skill-scanner"
    assert component["version"] == "1.2.3"
    assert component["bom-ref"] == component["purl"] == "pkg:pypi/cisco-ai-skill-scanner@1.2.3"
    assert component["licenses"] == [{"license": {"id": "Apache-2.0"}}]


def test_sbom_rejects_disconnected_or_inconsistent_supply_chain_inputs() -> None:
    with pytest.raises(RuntimeError, match="no Python components"):
        enrich_sbom(
            {"metadata": {}, "components": []},
            modules=[],
            helpers=[],
            project_version="1.2.3",
        )

    sbom = {
        "metadata": {},
        "components": [
            {
                "type": "library",
                "bom-ref": "requirements-L1",
                "name": "pyyaml",
                "version": "6.0.3",
                "purl": "pkg:pypi/pyyaml@6.0.3",
            }
        ],
    }
    with pytest.raises(RuntimeError, match="inconsistent Go toolchain"):
        enrich_sbom(
            sbom,
            modules=[],
            helpers=[
                {
                    "target": "linux-amd64",
                    "wheel": "scanner.whl",
                    "sha256": "a" * 64,
                    "cel_go_version": "v0.32.0",
                    "go_version": "go1.27.1",
                    "toolchain_version": "go1.27.0",
                }
            ],
            project_version="1.2.3",
        )
