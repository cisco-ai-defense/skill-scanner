#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Export Go dependency checksums and merge bundled CEL into a CycloneDX SBOM."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any

if __package__:
    from .cel_go_packaging import (  # type: ignore[import-not-found]
        CEL_GO_MODULE,
        CEL_GO_VERSION,
        SUPPORTED_TARGETS,
        verify_wheel,
    )
else:
    from cel_go_packaging import CEL_GO_MODULE, CEL_GO_VERSION, SUPPORTED_TARGETS, verify_wheel


def parse_json_stream(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    values: list[dict[str, Any]] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        value, index = decoder.raw_decode(text, index)
        if not isinstance(value, dict):
            raise RuntimeError("go mod download returned a non-object JSON value")
        values.append(value)
    return values


def download_module_metadata(module_dir: Path) -> list[dict[str, str]]:
    # Go may add checksums for transitive module go.mod files even when the
    # checked-in go.sum is already `go mod tidy` clean. Supply-chain export is
    # read-only: run it against a disposable module copy so release tooling can
    # never dirty or silently expand the source lock.
    with tempfile.TemporaryDirectory(prefix="skill-scanner-cel-go-mod-") as temp_dir:
        isolated_module = Path(temp_dir)
        shutil.copy2(module_dir / "go.mod", isolated_module / "go.mod")
        shutil.copy2(module_dir / "go.sum", isolated_module / "go.sum")
        env = os.environ.copy()
        env["GOWORK"] = "off"
        result = subprocess.run(
            ["go", "mod", "download", "-json", "all"],
            cwd=isolated_module,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
    modules: list[dict[str, str]] = []
    for value in parse_json_stream(result.stdout):
        if value.get("Main"):
            continue
        path = value.get("Path")
        version = value.get("Version")
        module_sum = value.get("Sum")
        go_mod_sum = value.get("GoModSum")
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(version, str)
            or not version
            or not isinstance(module_sum, str)
            or not module_sum
            or not isinstance(go_mod_sum, str)
            or not go_mod_sum
        ):
            raise RuntimeError(f"Go dependency is missing an immutable version/checksum: {value!r}")
        modules.append(
            {
                "module": path,
                "version": version,
                "module_sum": module_sum,
                "go_mod_sum": go_mod_sum,
            }
        )
    modules.sort(key=lambda value: (value["module"], value["version"]))
    if not any(value["module"] == CEL_GO_MODULE and value["version"] == CEL_GO_VERSION for value in modules):
        raise RuntimeError(f"Go dependency graph does not contain {CEL_GO_MODULE} {CEL_GO_VERSION}")
    return modules


def collect_wheel_helpers(wheel_dir: Path, expected_targets: set[str]) -> list[dict[str, Any]]:
    wheels = sorted(wheel_dir.glob("*.whl"))
    helpers: list[dict[str, Any]] = []
    used_wheels: set[Path] = set()
    for target_name in sorted(expected_targets):
        target = SUPPORTED_TARGETS[target_name]
        matches = [wheel for wheel in wheels if wheel.name.endswith(f"-{target.wheel_tag}.whl")]
        if len(matches) != 1:
            raise RuntimeError(f"expected one {target_name} wheel tagged {target.wheel_tag}, found {len(matches)}")
        manifest = verify_wheel(matches[0], target)
        helper = dict(manifest["helper"])
        helper["wheel"] = matches[0].name
        helpers.append(helper)
        used_wheels.add(matches[0])
    unexpected = [wheel.name for wheel in wheels if wheel not in used_wheels]
    if unexpected:
        raise RuntimeError(f"release contains unexpected or duplicate wheels: {unexpected}")
    return helpers


def _go_purl(module: str, version: str) -> str:
    quoted = urllib.parse.quote(module, safe="./-_")
    return f"pkg:golang/{quoted}@{urllib.parse.quote(version, safe='.-_')}"


def load_project_component(pyproject: Path, project_version: str) -> dict[str, Any]:
    """Build the canonical root component without asking the requirements parser.

    ``cyclonedx-py requirements --pyproject`` currently warns that the PEP 621
    root has no dependencies even though it parsed the frozen requirements
    inventory. Constructing the root here avoids that false warning and lets us
    bind every emitted Python component explicitly below.
    """

    document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = document.get("project")
    if not isinstance(project, dict):
        raise RuntimeError("pyproject.toml has no PEP 621 project table")
    name = project.get("name")
    if name != "cisco-ai-skill-scanner":
        raise RuntimeError(f"unexpected release project name: {name!r}")
    purl = f"pkg:pypi/{name}@{project_version}"
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": purl,
        "name": name,
        "version": project_version,
        "purl": purl,
    }
    description = project.get("description")
    if isinstance(description, str) and description:
        component["description"] = description
    license_value = project.get("license")
    if isinstance(license_value, dict) and license_value.get("text") == "Apache-2.0":
        component["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    return component


def _normalize_dependency_graph(
    sbom: dict[str, Any],
    components: list[dict[str, Any]],
    *,
    root_ref: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Normalize requirement-line refs to stable PURLs and preserve all edges."""

    ref_mapping: dict[str, str] = {}
    python_refs: list[str] = []
    seen_component_refs: set[str] = set()
    for component in components:
        old_ref = component.get("bom-ref")
        purl = component.get("purl")
        if not isinstance(old_ref, str) or not old_ref:
            raise RuntimeError("CycloneDX component has no bom-ref")
        new_ref = purl if isinstance(purl, str) and purl.startswith("pkg:pypi/") else old_ref
        if new_ref == root_ref or new_ref in seen_component_refs:
            raise RuntimeError(f"CycloneDX component bom-ref is duplicate or collides with the root: {new_ref}")
        seen_component_refs.add(new_ref)
        component["bom-ref"] = new_ref
        ref_mapping[old_ref] = new_ref
        if isinstance(purl, str) and purl.startswith("pkg:pypi/"):
            python_refs.append(new_ref)

    dependencies = sbom.setdefault("dependencies", [])
    if not isinstance(dependencies, list):
        raise RuntimeError("CycloneDX dependencies must be a list")
    by_ref: dict[str, dict[str, Any]] = {}
    for raw_entry in dependencies:
        if not isinstance(raw_entry, dict):
            raise RuntimeError("CycloneDX dependency entry must be an object")
        raw_ref = raw_entry.get("ref")
        if not isinstance(raw_ref, str) or not raw_ref:
            raise RuntimeError("CycloneDX dependency entry has no ref")
        ref = ref_mapping.get(raw_ref, root_ref if raw_ref == "root-component" else raw_ref)
        raw_children = raw_entry.get("dependsOn", [])
        if not isinstance(raw_children, list) or any(not isinstance(child, str) for child in raw_children):
            raise RuntimeError(f"CycloneDX dependency {raw_ref!r} has invalid dependsOn")
        children = {ref_mapping.get(child, root_ref if child == "root-component" else child) for child in raw_children}
        entry = by_ref.setdefault(ref, {"ref": ref, "dependsOn": []})
        entry["dependsOn"] = sorted(set(entry.get("dependsOn", [])) | children)
    return by_ref, sorted(python_refs)


def enrich_sbom(
    sbom: dict[str, Any],
    *,
    modules: list[dict[str, str]],
    helpers: list[dict[str, Any]],
    project_version: str,
    root_component: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = sbom.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise RuntimeError("CycloneDX metadata must be an object")
    canonical_root = root_component or {
        "type": "application",
        "bom-ref": f"pkg:pypi/cisco-ai-skill-scanner@{project_version}",
        "name": "cisco-ai-skill-scanner",
        "version": project_version,
        "purl": f"pkg:pypi/cisco-ai-skill-scanner@{project_version}",
    }
    root_ref = canonical_root.get("bom-ref")
    if not isinstance(root_ref, str) or root_ref != canonical_root.get("purl"):
        raise RuntimeError("CycloneDX root component must use its canonical PURL as bom-ref")
    metadata["component"] = canonical_root
    components = sbom.setdefault("components", [])
    if not isinstance(components, list):
        raise RuntimeError("CycloneDX components must be a list")
    if any(not isinstance(component, dict) for component in components):
        raise RuntimeError("CycloneDX components must contain only objects")
    typed_components = components
    by_ref, python_refs = _normalize_dependency_graph(sbom, typed_components, root_ref=root_ref)
    if not python_refs:
        raise RuntimeError("CycloneDX requirements inventory contains no Python components")

    module_refs: list[str] = []
    for module in modules:
        purl = _go_purl(module["module"], module["version"])
        module_refs.append(purl)
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": module["module"],
                "version": module["version"],
                "purl": purl,
                "properties": [
                    {"name": "skill-scanner:go-module-sum", "value": module["module_sum"]},
                    {"name": "skill-scanner:go-mod-sum", "value": module["go_mod_sum"]},
                ],
            }
        )

    helper_refs: list[str] = []
    toolchain_refs: set[str] = set()
    for helper in helpers:
        go_version = helper.get("go_version")
        toolchain_version = helper.get("toolchain_version")
        if (
            not isinstance(go_version, str)
            or not isinstance(toolchain_version, str)
            or go_version != toolchain_version
            or not go_version.startswith("go")
        ):
            raise RuntimeError(f"helper {helper.get('target')!r} has inconsistent Go toolchain provenance")
        toolchain_ref = f"pkg:generic/go-toolchain@{urllib.parse.quote(go_version.removeprefix('go'), safe='.-_')}"
        toolchain_refs.add(toolchain_ref)
        helper_ref = f"pkg:generic/skill-scanner-cel-go@{project_version}?target={helper['target']}"
        helper_refs.append(helper_ref)
        components.append(
            {
                "type": "application",
                "bom-ref": helper_ref,
                "group": "cisco-ai-defense",
                "name": "skill-scanner-cel-go",
                "version": project_version,
                "purl": helper_ref,
                "hashes": [{"alg": "SHA-256", "content": helper["sha256"]}],
                "properties": [
                    {"name": "skill-scanner:target", "value": helper["target"]},
                    {"name": "skill-scanner:wheel", "value": helper["wheel"]},
                    {"name": "skill-scanner:cel-go-version", "value": helper["cel_go_version"]},
                    {"name": "skill-scanner:go-version", "value": helper["go_version"]},
                    {"name": "skill-scanner:go-toolchain-ref", "value": toolchain_ref},
                ],
            }
        )
    for toolchain_ref in sorted(toolchain_refs):
        components.append(
            {
                "type": "application",
                "bom-ref": toolchain_ref,
                "name": "go-toolchain",
                "version": toolchain_ref.rsplit("@", 1)[-1],
                "purl": toolchain_ref,
            }
        )

    root_dependency = by_ref.setdefault(root_ref, {"ref": root_ref, "dependsOn": []})
    root_depends_on = root_dependency.setdefault("dependsOn", [])
    root_dependency["dependsOn"] = sorted(set(root_depends_on) | set(python_refs) | set(helper_refs))
    if len(toolchain_refs) != 1:
        raise RuntimeError("release helpers must use exactly one Go toolchain version")
    qualified_toolchain_ref = next(iter(toolchain_refs))
    for helper_ref in helper_refs:
        by_ref[helper_ref] = {"ref": helper_ref, "dependsOn": sorted([*module_refs, qualified_toolchain_ref])}
    for module_ref in module_refs:
        by_ref.setdefault(module_ref, {"ref": module_ref, "dependsOn": []})
    by_ref.setdefault(qualified_toolchain_ref, {"ref": qualified_toolchain_ref, "dependsOn": []})
    for python_ref in python_refs:
        by_ref.setdefault(python_ref, {"ref": python_ref, "dependsOn": []})
    sbom["dependencies"] = sorted(by_ref.values(), key=lambda entry: str(entry["ref"]))
    components.sort(key=lambda entry: str(entry.get("bom-ref", "")))
    return sbom


def validate_cyclonedx_file(path: Path) -> None:
    """Strictly validate the enriched document against its CycloneDX schema."""

    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    document = json.loads(path.read_text(encoding="utf-8"))
    versions = {
        "1.7": SchemaVersion.V1_7,
        "1.6": SchemaVersion.V1_6,
        "1.5": SchemaVersion.V1_5,
        "1.4": SchemaVersion.V1_4,
        "1.3": SchemaVersion.V1_3,
        "1.2": SchemaVersion.V1_2,
        "1.1": SchemaVersion.V1_1,
        "1.0": SchemaVersion.V1_0,
    }
    spec_version = document.get("specVersion")
    try:
        schema_version = versions[spec_version]
    except (KeyError, TypeError) as exc:
        raise RuntimeError(f"unsupported CycloneDX specVersion: {spec_version!r}") from exc
    errors = JsonStrictValidator(schema_version).validate_str(
        path.read_text(encoding="utf-8"),
        all_errors=True,
    )
    if errors:
        messages = "; ".join(str(error) for error in errors)
        raise RuntimeError(f"enriched CycloneDX SBOM failed schema validation: {messages}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--helper-manifest", type=Path, required=True)
    parser.add_argument("--project-version", required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--expected-target", action="append", choices=sorted(SUPPORTED_TARGETS))
    args = parser.parse_args()

    expected_targets = set(args.expected_target or SUPPORTED_TARGETS)
    modules = download_module_metadata(Path(__file__).resolve().parents[1] / "tools" / "cel_runtime")
    helpers = collect_wheel_helpers(args.wheel_dir, expected_targets)
    for helper in helpers:
        if helper.get("helper_version") != args.project_version:
            raise RuntimeError(
                f"helper {helper.get('target')} records version {helper.get('helper_version')!r}, "
                f"expected {args.project_version!r}"
            )

    toolchain_versions = {helper["toolchain_version"] for helper in helpers}
    if len(toolchain_versions) != 1:
        raise RuntimeError("release helper manifests do not bind one exact Go toolchain")
    dependency_lock = {
        "schema_version": 1,
        "runtime": CEL_GO_MODULE,
        "runtime_version": CEL_GO_VERSION,
        "go_toolchain_version": next(iter(toolchain_versions)),
        "modules": modules,
    }
    args.dependency_lock.parent.mkdir(parents=True, exist_ok=True)
    args.dependency_lock.write_text(json.dumps(dependency_lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    helper_manifest = {
        "schema_version": 1,
        "project_version": args.project_version,
        "helpers": helpers,
    }
    args.helper_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.helper_manifest.write_text(json.dumps(helper_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    root_component = load_project_component(args.pyproject, args.project_version)
    enrich_sbom(
        sbom,
        modules=modules,
        helpers=helpers,
        project_version=args.project_version,
        root_component=root_component,
    )
    args.sbom.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_cyclonedx_file(args.sbom)


if __name__ == "__main__":
    main()
