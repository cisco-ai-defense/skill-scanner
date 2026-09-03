#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Install one built wheel in isolation and exercise its packaged CEL runtime."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


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
    ):
        environment.pop(name, None)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--expected-python", type=_parse_expected_python, required=True)
    args = parser.parse_args()

    expected_python = args.expected_python
    actual_python = sys.version_info[:2]
    if actual_python != expected_python or sys.implementation.name != "cpython":
        expected = ".".join(map(str, expected_python))
        actual = f"{sys.implementation.name} {sys.version_info.major}.{sys.version_info.minor}"
        raise SystemExit(f"wheel smoke requires CPython {expected}; found {actual}")

    wheels = sorted(args.wheel_dir.resolve().glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {args.wheel_dir}, found {len(wheels)}")
    wheel = wheels[0]
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required for the isolated wheel-install smoke")

    environment = _clean_environment()
    with tempfile.TemporaryDirectory(prefix="skill-scanner-wheel-smoke-") as temp_dir:
        root = Path(temp_dir).resolve()
        virtual_environment = root / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(virtual_environment)],
            check=True,
            cwd=root,
            env=environment,
            timeout=60,
        )
        python = _environment_python(virtual_environment)
        subprocess.run(
            [uv, "pip", "install", "--python", str(python), str(wheel)],
            check=True,
            cwd=root,
            env=environment,
            timeout=300,
        )

        expected = ".".join(map(str, expected_python))
        import_probe = """
from importlib.metadata import version
from pathlib import Path
import sys

import skill_scanner
from skill_scanner.core.cel.go_runtime import discover_cel_go_helper
from skill_scanner.core.semantic import scan_facts_pb2

environment = Path(sys.argv[1]).resolve()
expected_python = tuple(map(int, sys.argv[2].split(".")))
module_path = Path(skill_scanner.__file__).resolve()
assert sys.version_info[:2] == expected_python
assert environment in module_path.parents, (environment, module_path)
assert scan_facts_pb2.ScanFacts(schema_version="v1").schema_version == "v1"
helper = discover_cel_go_helper()
print(f"installed {version('cisco-ai-skill-scanner')} from {module_path}; helper={helper}")
""".strip()
        subprocess.run(
            [python, "-I", "-c", import_probe, str(virtual_environment), expected],
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
            timeout=120,
        )

    print(f"installed-wheel smoke passed: {wheel.name} on CPython {expected}")


if __name__ == "__main__":
    main()
