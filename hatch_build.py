# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Hatch build hook that gives every wheel exactly one native CEL helper."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# Hatch imports this file in an isolated environment without adding the
# project root to sys.path. Load only our checked-in build support module by
# absolute path; it is not a third-party build dependency.
_PROJECT_ROOT = Path(__file__).resolve().parent
_SUPPORT_PATH = _PROJECT_ROOT / "scripts" / "cel_go_packaging.py"
_SPEC = importlib.util.spec_from_file_location("_skill_scanner_cel_go_packaging", _SUPPORT_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"could not load CEL packaging support from {_SUPPORT_PATH}")
_PACKAGING = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _PACKAGING
_SPEC.loader.exec_module(_PACKAGING)

build_helper = _PACKAGING.build_helper
copy_prebuilt_bundle = _PACKAGING.copy_prebuilt_bundle
resolve_target = _PACKAGING.resolve_target
require_helper_version = _PACKAGING.require_helper_version
verify_wheel = _PACKAGING.verify_wheel
verify_bundle_integrity = _PACKAGING.verify_bundle_integrity
write_manifest = _PACKAGING.write_manifest


class CelGoBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return
        target = resolve_target()
        editable = version == "editable"
        package_version = "source-tree" if editable else str(self.metadata.version)
        if editable:
            work_dir: Path | None = None
            bundle_dir = Path(self.root) / "skill_scanner" / "core" / "cel" / "_bin"
            bundle_dir.mkdir(parents=True, exist_ok=True)
        else:
            work_dir = Path(tempfile.mkdtemp(prefix=f"cel-go-{target.name}-", dir=self.directory))
            bundle_dir = work_dir / "bundle"
            bundle_dir.mkdir(parents=True)

        prebuilt = os.environ.get("SKILL_SCANNER_CEL_GO_PREBUILT_DIR")
        if prebuilt:
            manifest = copy_prebuilt_bundle(source_dir=Path(prebuilt), destination_dir=bundle_dir, target=target)
            require_helper_version(manifest, package_version, editable=editable)
        elif editable and (bundle_dir / target.filename).exists() and (bundle_dir / "manifest.json").exists():
            binary = bundle_dir / target.filename
            manifest = verify_bundle_integrity(binary, bundle_dir / "manifest.json", target)
            if manifest["helper"]["helper_version"] != package_version:
                raise RuntimeError(
                    "checked-in CEL helper is not a source-tree build; run "
                    "`uv run --no-sync python scripts/build_cel_helper.py --in-place "
                    "--helper-version source-tree` with Go 1.27.1+"
                )
        elif editable and ((bundle_dir / target.filename).exists() or (bundle_dir / "manifest.json").exists()):
            raise RuntimeError(
                "checked-in CEL helper bundle is incomplete; remove the partial bundle and run "
                "`uv run --no-sync python scripts/build_cel_helper.py --in-place "
                "--helper-version source-tree` with Go 1.27.1+"
            )
        else:
            binary = bundle_dir / target.filename
            helper = build_helper(
                root=Path(self.root),
                target=target,
                output=binary,
                helper_version=package_version,
            )
            write_manifest(bundle_dir / "manifest.json", helper)
            manifest = {"schema_version": 1, "helper": helper}

        binary = bundle_dir / target.filename
        build_data["pure_python"] = False
        build_data["tag"] = target.wheel_tag
        build_data["force_include"][str(binary)] = f"skill_scanner/core/cel/_bin/{target.filename}"
        build_data["force_include"][str(bundle_dir / "manifest.json")] = "skill_scanner/core/cel/_bin/manifest.json"
        build_data["cel_go_target"] = target.name
        build_data["cel_go_manifest"] = manifest
        if work_dir is not None:
            build_data["cel_go_work_dir"] = str(work_dir)

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        if self.target_name != "wheel" or "cel_go_target" not in build_data:
            return
        if version == "editable":
            return
        target = resolve_target(str(build_data["cel_go_target"]))
        try:
            verify_wheel(Path(artifact_path), target)
        finally:
            work_dir = build_data.get("cel_go_work_dir")
            if isinstance(work_dir, str):
                shutil.rmtree(work_dir, ignore_errors=True)
