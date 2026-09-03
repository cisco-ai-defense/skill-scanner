#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Clean-install one sdist with an exact release-wheel CEL helper."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from cel_go_packaging import CEL_GO_VERSION, SUPPORTED_TARGETS, verify_wheel

QUALIFIED_GO_TOOLCHAIN = "go1.27.1"


def _parse_expected_python(value: str) -> tuple[int, int]:
    parts = value.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise argparse.ArgumentTypeError("expected a Python major.minor version")
    parsed = int(parts[0]), int(parts[1])
    if parsed not in {(3, 11), (3, 12), (3, 13), (3, 14)}:
        raise argparse.ArgumentTypeError("expected one of CPython 3.11, 3.12, 3.13, or 3.14")
    return parsed


def _environment_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "PYTHONHOME",
        "PYTHONPATH",
        "SKILL_SCANNER_CEL_GO_HELPER",
        "SKILL_SCANNER_CEL_GO_PREBUILT_DIR",
        "SKILL_SCANNER_CEL_GO_TARGET",
    ):
        environment.pop(name, None)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _one_artifact(directory: Path, pattern: str, description: str) -> Path:
    matches = sorted(directory.resolve().glob(pattern))
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {description} in {directory}, found {len(matches)}")
    return matches[0]


def _extract_prebuilt_bundle(wheel: Path, target_name: str, destination: Path) -> dict[str, object]:
    target = SUPPORTED_TARGETS[target_name]
    manifest = verify_wheel(wheel, target)
    binary_member = f"skill_scanner/core/cel/_bin/{target.filename}"
    manifest_member = "skill_scanner/core/cel/_bin/manifest.json"
    destination.mkdir(parents=True)
    with zipfile.ZipFile(wheel) as archive:
        binary = destination / target.filename
        binary.write_bytes(archive.read(binary_member))
        manifest_path = destination / "manifest.json"
        manifest_path.write_bytes(archive.read(manifest_member))
    if target.goos != "windows":
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
        raise SystemExit("extracted CEL helper manifest changed")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdist-dir", type=Path, required=True)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--target", choices=tuple(sorted(SUPPORTED_TARGETS)), required=True)
    parser.add_argument("--expected-python", type=_parse_expected_python, required=True)
    args = parser.parse_args()

    expected_python = args.expected_python
    actual_python = sys.version_info[:2]
    if actual_python != expected_python or sys.implementation.name != "cpython":
        expected = ".".join(map(str, expected_python))
        actual = f"{sys.implementation.name} {sys.version_info.major}.{sys.version_info.minor}"
        raise SystemExit(f"sdist smoke requires CPython {expected}; found {actual}")

    target = SUPPORTED_TARGETS[args.target]
    sdist = _one_artifact(args.sdist_dir, "*.tar.gz", "source distribution")
    wheel = _one_artifact(args.wheel_dir, f"*-{target.wheel_tag}.whl", f"{args.target} wheel")
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required for the isolated sdist-install smoke")

    environment = _clean_environment()
    with tempfile.TemporaryDirectory(prefix="skill-scanner-sdist-smoke-") as temp_dir:
        root = Path(temp_dir).resolve()
        prebuilt = root / "prebuilt"
        manifest = _extract_prebuilt_bundle(wheel, args.target, prebuilt)
        helper = manifest.get("helper")
        if not isinstance(helper, dict):
            raise SystemExit("release wheel has no CEL helper manifest")
        if helper.get("toolchain_version") != QUALIFIED_GO_TOOLCHAIN:
            raise SystemExit(
                "release wheel CEL helper toolchain mismatch: "
                f"expected {QUALIFIED_GO_TOOLCHAIN}, found {helper.get('toolchain_version')!r}"
            )
        if helper.get("cel_go_version") != CEL_GO_VERSION:
            raise SystemExit(
                f"release wheel CEL engine mismatch: expected {CEL_GO_VERSION}, found {helper.get('cel_go_version')!r}"
            )
        virtual_environment = root / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(virtual_environment)],
            check=True,
            cwd=root,
            env=environment,
            timeout=60,
        )
        python = _environment_python(virtual_environment)
        build_environment = {
            **environment,
            "SKILL_SCANNER_CEL_GO_PREBUILT_DIR": str(prebuilt),
            "SKILL_SCANNER_CEL_GO_TARGET": args.target,
        }
        subprocess.run(
            [uv, "pip", "install", "--python", str(python), str(sdist)],
            check=True,
            cwd=root,
            env=build_environment,
            timeout=600,
        )

        expected = ".".join(map(str, expected_python))
        import_probe = """
from importlib.metadata import version
from pathlib import Path
import json
import sys

import skill_scanner
from skill_scanner.core.cel.go_runtime import discover_cel_go_helper

environment = Path(sys.argv[1]).resolve()
expected_python = tuple(map(int, sys.argv[2].split(".")))
expected_target = sys.argv[3]
module_path = Path(skill_scanner.__file__).resolve()
assert sys.version_info[:2] == expected_python
assert environment in module_path.parents, (environment, module_path)
binary = discover_cel_go_helper().resolve()
assert environment in binary.parents, (environment, binary)
manifest = json.loads((binary.parent / "manifest.json").read_text(encoding="utf-8"))
assert manifest["helper"]["target"] == expected_target
print(f"installed {version('cisco-ai-skill-scanner')} from {module_path}; helper={binary}")
""".strip()
        subprocess.run(
            [python, "-I", "-c", import_probe, str(virtual_environment), expected, args.target],
            check=True,
            cwd=root,
            env=environment,
            timeout=30,
        )
        subprocess.run(
            [python, "-I", "-m", "skill_scanner.cli.cli", "validate-rules"],
            check=True,
            cwd=root,
            env=environment,
            timeout=180,
        )

    print(
        "installed-sdist smoke passed: "
        f"{sdist.name} with {wheel.name} ({helper['toolchain_version']}, {helper['cel_go_version']}) on CPython {expected}"
    )


if __name__ == "__main__":
    main()
