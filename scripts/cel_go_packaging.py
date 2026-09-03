#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build and verify the bundled, platform-specific cel-go helper.

This module intentionally uses only the Python standard library so it can run
inside Hatch's isolated build environment and from a fresh source checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CEL_GO_MODULE = "cel.dev/cel-go"
CEL_GO_VERSION = "v0.32.0"
CEL_GO_SUM = "h1:irvpFKr5EuGPyxeME03ERh0rii1TX+BDAnB9eL3IvNk="
CEL_GO_TAG_COMMIT = "f2039bc647bca407d882d90436fc8b91bab1ae62"
HELPER_MODULE = "github.com/cisco-ai-defense/skill-scanner/tools/celruntime"
HELPER_PROTOCOL_VERSION = 2
SCAN_FACTS_DESCRIPTOR_SHA256 = "0dd0799a2276e2f6fc844bc1da5835e2a05ccbca3802d1dea635d3b0d4cd1a13"
MINIMUM_GO_VERSION = (1, 27, 1)
MANIFEST_SCHEMA_VERSION = 1
TARGET_ENV = "SKILL_SCANNER_CEL_GO_TARGET"


@dataclass(frozen=True)
class CelGoTarget:
    """One release-supported helper and wheel target."""

    name: str
    goos: str
    goarch: str
    wheel_platform: str
    executable_suffix: str = ""
    macos_minimum: tuple[int, int, int] | None = None

    @property
    def wheel_tag(self) -> str:
        # The helper is an external process, but the package intentionally
        # supports CPython only. A compressed, explicit interpreter set avoids
        # claiming an extension ABI or unbounded future-Python compatibility.
        return f"cp311.cp312.cp313.cp314-none-{self.wheel_platform}"

    @property
    def filename(self) -> str:
        return f"skill-scanner-cel-go-{self.goos}-{self.goarch}{self.executable_suffix}"


SUPPORTED_TARGETS: dict[str, CelGoTarget] = {
    "linux-amd64": CelGoTarget("linux-amd64", "linux", "amd64", "manylinux_2_17_x86_64"),
    "linux-arm64": CelGoTarget("linux-arm64", "linux", "arm64", "manylinux_2_17_aarch64"),
    # Go 1.27 raised the supported Darwin floor to macOS 13. The wheel tag,
    # Mach-O load command, packaged manifest, and runtime contract must agree.
    "darwin-amd64": CelGoTarget("darwin-amd64", "darwin", "amd64", "macosx_13_0_x86_64", macos_minimum=(13, 0, 0)),
    "darwin-arm64": CelGoTarget("darwin-arm64", "darwin", "arm64", "macosx_13_0_arm64", macos_minimum=(13, 0, 0)),
    "windows-amd64": CelGoTarget("windows-amd64", "windows", "amd64", "win_amd64", ".exe"),
}


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def infer_host_target(
    *,
    system: str | None = None,
    machine: str | None = None,
    implementation: str | None = None,
    libc: str | None = None,
) -> CelGoTarget:
    raw_system = (system or sys.platform).lower()
    raw_machine = (machine or platform.machine()).lower()
    raw_implementation = implementation or platform.python_implementation()
    if raw_implementation != "CPython":
        raise RuntimeError(f"CEL helper wheels support CPython only; found {raw_implementation}")
    goos = {
        "darwin": "darwin",
        "linux": "linux",
        "linux2": "linux",
        "win32": "windows",
        "cygwin": "windows",
    }.get(raw_system)
    goarch = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }.get(raw_machine)
    if goos == "linux":
        libc_name = (libc if libc is not None else platform.libc_ver()[0]).lower()
        if libc_name not in {"glibc", "gnu libc"}:
            raise RuntimeError(f"CEL helper wheels require glibc Linux; found {libc_name or 'unknown libc'}")
    name = f"{goos}-{goarch}"
    try:
        return SUPPORTED_TARGETS[name]
    except KeyError as exc:
        supported = ", ".join(sorted(SUPPORTED_TARGETS))
        raise RuntimeError(
            f"unsupported CEL helper build target {raw_system}/{raw_machine}; supported targets: {supported}"
        ) from exc


def resolve_target(value: str | None = None) -> CelGoTarget:
    requested = value or os.environ.get(TARGET_ENV)
    if requested is None:
        return infer_host_target()
    try:
        return SUPPORTED_TARGETS[requested]
    except KeyError as exc:
        supported = ", ".join(sorted(SUPPORTED_TARGETS))
        raise RuntimeError(f"unknown {TARGET_ENV} value {requested!r}; expected one of: {supported}") from exc


def parse_go_version(output: str) -> tuple[int, int, int]:
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", output)
    if match is None:
        raise RuntimeError(f"could not parse Go version from {output.strip()!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def verify_go_toolchain(go: str = "go", *, cwd: Path | None = None) -> str:
    executable = shutil.which(go)
    if executable is None:
        raise RuntimeError("Go 1.27.1+ is required to build the CEL helper; install Go and retry")
    result = subprocess.run(
        [executable, "version"],
        check=True,
        capture_output=True,
        cwd=cwd,
        text=True,
        timeout=30,
    )
    version = parse_go_version(result.stdout)
    if version < MINIMUM_GO_VERSION:
        required = ".".join(map(str, MINIMUM_GO_VERSION))
        actual = ".".join(map(str, version))
        raise RuntimeError(f"Go {required}+ is required to build the CEL helper; found {actual}")
    return result.stdout.strip().split()[2]


def verify_go_module(root: Path) -> None:
    module_dir = root / "tools" / "cel_runtime"
    go_mod = (module_dir / "go.mod").read_text(encoding="utf-8")
    required = re.search(r"(?m)^\s*cel\.dev/cel-go\s+(v\S+)\s*$", go_mod)
    if required is None or required.group(1) != CEL_GO_VERSION:
        actual = required.group(1) if required else "missing"
        raise RuntimeError(f"go.mod must pin {CEL_GO_MODULE} {CEL_GO_VERSION}; found {actual}")
    go_sum = (module_dir / "go.sum").read_text(encoding="utf-8")
    expected = f"{CEL_GO_MODULE} {CEL_GO_VERSION} {CEL_GO_SUM}"
    if expected not in go_sum.splitlines():
        raise RuntimeError(f"go.sum does not contain the qualified {CEL_GO_MODULE} {CEL_GO_VERSION} checksum")


def _binary_format_bytes(data: bytes, *, source: str) -> str:
    header = data[:4]
    if header == b"\x7fELF":
        return "elf"
    if header[:2] == b"MZ":
        return "pe"
    if header in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
        return "macho"
    raise RuntimeError(f"unrecognized helper executable format for {source}")


def _binary_format(path: Path) -> str:
    return _binary_format_bytes(path.read_bytes(), source=str(path))


def _macho_target_bytes(data: bytes) -> tuple[str, tuple[int, int, int]]:
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise RuntimeError("release helper must be a little-endian 64-bit Mach-O executable")
    if len(data) < 32:
        raise RuntimeError("truncated Mach-O header")
    cpu_type, command_count = struct.unpack_from("<I8xI", data, 4)
    goarch = {0x01000007: "amd64", 0x0100000C: "arm64"}.get(cpu_type)
    if goarch is None:
        raise RuntimeError(f"unsupported Mach-O CPU type 0x{cpu_type:08x}")
    offset = 32
    minimum: tuple[int, int, int] | None = None
    for _ in range(command_count):
        if offset + 8 > len(data):
            raise RuntimeError("truncated Mach-O load-command table")
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or offset + command_size > len(data):
            raise RuntimeError("invalid Mach-O load command size")
        if command == 0x32 and command_size >= 24:  # LC_BUILD_VERSION
            encoded = struct.unpack_from("<I", data, offset + 12)[0]
            minimum = (encoded >> 16, (encoded >> 8) & 0xFF, encoded & 0xFF)
        elif command == 0x24 and command_size >= 16:  # LC_VERSION_MIN_MACOSX
            encoded = struct.unpack_from("<I", data, offset + 8)[0]
            minimum = (encoded >> 16, (encoded >> 8) & 0xFF, encoded & 0xFF)
        offset += command_size
    if minimum is None:
        raise RuntimeError("Mach-O helper does not declare a minimum macOS version")
    return goarch, minimum


def _binary_arch_bytes(data: bytes, binary_format: str) -> tuple[str, tuple[int, int, int] | None]:
    if binary_format == "elf":
        if len(data) < 20 or data[5] != 1:
            raise RuntimeError("release helper must be a little-endian ELF executable")
        machine = struct.unpack_from("<H", data, 18)[0]
        goarch = {62: "amd64", 183: "arm64"}.get(machine)
        if goarch is None:
            raise RuntimeError(f"unsupported ELF machine {machine}")
        return goarch, None
    if binary_format == "pe":
        if len(data) < 0x40:
            raise RuntimeError("truncated PE executable")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise RuntimeError("invalid PE executable header")
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        if machine != 0x8664:
            raise RuntimeError(f"unsupported PE machine 0x{machine:04x}")
        return "amd64", None
    return _macho_target_bytes(data)


def _binary_arch(path: Path, binary_format: str) -> tuple[str, tuple[int, int, int] | None]:
    return _binary_arch_bytes(path.read_bytes(), binary_format)


def verify_binary(path: Path, target: CelGoTarget, *, go: str = "go") -> dict[str, str]:
    expected_format = {"linux": "elf", "darwin": "macho", "windows": "pe"}[target.goos]
    actual_format = _binary_format(path)
    if actual_format != expected_format:
        raise RuntimeError(
            f"helper format mismatch: target {target.name} requires {expected_format}, found {actual_format}"
        )
    actual_arch, macos_minimum = _binary_arch(path, actual_format)
    if actual_arch != target.goarch:
        raise RuntimeError(f"helper architecture mismatch: target {target.goarch}, found {actual_arch}")
    if target.macos_minimum is not None and macos_minimum != target.macos_minimum:
        expected = ".".join(map(str, target.macos_minimum[:2]))
        actual = ".".join(map(str, macos_minimum or ()))
        raise RuntimeError(
            f"macOS helper minimum version mismatch: wheel requires {expected}, binary declares {actual}"
        )

    result = subprocess.run(
        [go, "version", "-m", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    metadata = result.stdout
    requirements = (
        f"\tpath\t{HELPER_MODULE}\n",
        f"\tdep\t{CEL_GO_MODULE}\t{CEL_GO_VERSION}\t{CEL_GO_SUM}\n",
        "\tbuild\tCGO_ENABLED=0\n",
        f"\tbuild\tGOARCH={target.goarch}\n",
        f"\tbuild\tGOOS={target.goos}\n",
    )
    missing = [entry.strip() for entry in requirements if entry not in metadata]
    if missing:
        raise RuntimeError(f"helper Go metadata does not match {target.name}; missing: {', '.join(missing)}")
    go_version = metadata.splitlines()[0].rsplit(": ", 1)[-1]
    if parse_go_version(go_version) < MINIMUM_GO_VERSION:
        raise RuntimeError(f"helper was built with unsupported toolchain {go_version}")
    inspected = {"binary_format": actual_format, "go_version": go_version}
    if macos_minimum is not None:
        inspected["macos_minimum"] = ".".join(map(str, macos_minimum[:2]))
    return inspected


def build_helper(
    *,
    root: Path,
    target: CelGoTarget,
    output: Path,
    helper_version: str,
    go: str = "go",
) -> dict[str, Any]:
    """Cross-compile, inspect, and describe one qualified helper binary."""

    verify_go_module(root)
    module_dir = root / "tools" / "cel_runtime"
    toolchain_version = verify_go_toolchain(go, cwd=module_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "CGO_ENABLED": "0",
            "GOARCH": target.goarch,
            "GOOS": target.goos,
            "GOFLAGS": "-mod=readonly",
        }
    )
    subprocess.run(
        [
            go,
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags",
            f"-s -w -X main.helperVersion={helper_version}",
            "-o",
            str(output),
            ".",
        ],
        cwd=module_dir,
        env=env,
        check=True,
        timeout=300,
    )
    if target.goos != "windows":
        output.chmod(output.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    inspected = verify_binary(output, target, go=go)
    return {
        "binary_format": inspected["binary_format"],
        "cel_go_module": CEL_GO_MODULE,
        "cel_go_sum": CEL_GO_SUM,
        "cel_go_tag_commit": CEL_GO_TAG_COMMIT,
        "cel_go_version": CEL_GO_VERSION,
        "filename": target.filename,
        "go_version": inspected["go_version"],
        "goarch": target.goarch,
        "goos": target.goos,
        "helper_module": HELPER_MODULE,
        "helper_version": helper_version,
        "protocol_version": HELPER_PROTOCOL_VERSION,
        "scan_facts_descriptor_sha256": SCAN_FACTS_DESCRIPTOR_SHA256,
        "sha256": sha256_file(output),
        "size": output.stat().st_size,
        "target": target.name,
        "toolchain_version": toolchain_version,
        "wheel_tag": target.wheel_tag,
        **({"macos_minimum": inspected["macos_minimum"]} if "macos_minimum" in inspected else {}),
    }


def write_manifest(path: Path, helper: dict[str, Any]) -> None:
    payload = {"schema_version": MANIFEST_SCHEMA_VERSION, "helper": helper}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_helper_version(manifest: dict[str, Any], package_version: str, *, editable: bool) -> None:
    recorded_version = manifest["helper"]["helper_version"]
    if not editable and recorded_version != package_version:
        raise RuntimeError(
            f"prebuilt CEL helper version {recorded_version!r} does not match package version {package_version!r}"
        )


def validate_manifest_document(value: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "helper"}:
        raise RuntimeError(f"invalid CEL helper manifest root in {source}")
    if type(value.get("schema_version")) is not int or value["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise RuntimeError(f"unsupported CEL helper manifest in {source}")
    helper = value.get("helper")
    if not isinstance(helper, dict):
        raise RuntimeError(f"CEL helper manifest has no helper object: {source}")
    allowed_fields = {
        "binary_format",
        "cel_go_module",
        "cel_go_sum",
        "cel_go_tag_commit",
        "cel_go_version",
        "filename",
        "go_version",
        "goarch",
        "goos",
        "helper_module",
        "helper_version",
        "macos_minimum",
        "protocol_version",
        "scan_facts_descriptor_sha256",
        "sha256",
        "size",
        "target",
        "toolchain_version",
        "wheel_tag",
    }
    unknown = set(helper) - allowed_fields
    if unknown:
        raise RuntimeError(f"CEL helper manifest contains unknown fields in {source}: {sorted(unknown)}")
    required = {
        "cel_go_module": CEL_GO_MODULE,
        "cel_go_version": CEL_GO_VERSION,
        "cel_go_sum": CEL_GO_SUM,
        "cel_go_tag_commit": CEL_GO_TAG_COMMIT,
        "helper_module": HELPER_MODULE,
        "protocol_version": HELPER_PROTOCOL_VERSION,
        "scan_facts_descriptor_sha256": SCAN_FACTS_DESCRIPTOR_SHA256,
    }
    for key, expected in required.items():
        if helper.get(key) != expected:
            raise RuntimeError(f"CEL helper manifest {key} mismatch: expected {expected!r}, found {helper.get(key)!r}")
    required_strings = {
        "binary_format",
        "filename",
        "go_version",
        "goarch",
        "goos",
        "helper_version",
        "sha256",
        "target",
        "toolchain_version",
        "wheel_tag",
    }
    for key in required_strings:
        if not isinstance(helper.get(key), str) or not helper[key]:
            raise RuntimeError(f"CEL helper manifest {key} must be a nonempty string")
    if not re.fullmatch(r"[0-9a-f]{64}", helper["sha256"]):
        raise RuntimeError("CEL helper manifest SHA-256 is invalid")
    if isinstance(helper.get("size"), bool) or not isinstance(helper.get("size"), int) or helper["size"] <= 0:
        raise RuntimeError("CEL helper manifest size is invalid")
    for field in ("go_version", "toolchain_version"):
        if parse_go_version(helper[field]) < MINIMUM_GO_VERSION:
            required_go = ".".join(map(str, MINIMUM_GO_VERSION))
            raise RuntimeError(f"CEL helper manifest {field} must be Go {required_go}+")
    if "macos_minimum" in helper and helper["macos_minimum"] != "13.0":
        raise RuntimeError("CEL helper manifest macOS minimum must be 13.0")
    try:
        target = SUPPORTED_TARGETS[helper["target"]]
    except KeyError as exc:
        raise RuntimeError(f"CEL helper manifest target is unsupported: {helper['target']!r}") from exc
    expected = {
        "binary_format": {"linux": "elf", "darwin": "macho", "windows": "pe"}[target.goos],
        "filename": target.filename,
        "goarch": target.goarch,
        "goos": target.goos,
        "wheel_tag": target.wheel_tag,
    }
    for key, expected_value in expected.items():
        if helper[key] != expected_value:
            raise RuntimeError(
                f"CEL helper manifest {key} mismatch for {target.name}: "
                f"expected {expected_value!r}, found {helper[key]!r}"
            )
    if (helper.get("macos_minimum") is not None) != (target.macos_minimum is not None):
        raise RuntimeError(f"CEL helper manifest macOS minimum presence does not match target {target.name}")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return validate_manifest_document(value, source=str(path))


def verify_bundle_integrity(binary: Path, manifest_path: Path, target: CelGoTarget) -> dict[str, Any]:
    """Verify a checked-in/prebuilt bundle without requiring a Go toolchain.

    The manifest is strict and qualified, and the executable is rebound to its
    target, format, architecture, macOS floor, size, and digest. Release builds
    additionally call :func:`verify_bundle`, which checks embedded Go module
    metadata with the pinned toolchain.
    """

    if binary.is_symlink() or not binary.is_file():
        raise RuntimeError(f"CEL helper must be a regular non-symlink file: {binary}")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError(f"CEL helper manifest must be a regular non-symlink file: {manifest_path}")
    manifest = load_manifest(manifest_path)
    helper = manifest["helper"]
    if helper.get("target") != target.name or helper.get("filename") != target.filename:
        raise RuntimeError(f"CEL helper manifest target does not match {target.name}")
    if helper.get("wheel_tag") != target.wheel_tag:
        raise RuntimeError(f"CEL helper manifest wheel tag does not match {target.wheel_tag}")
    actual_sha = sha256_file(binary)
    if helper.get("sha256") != actual_sha:
        raise RuntimeError(f"CEL helper SHA-256 mismatch: expected {helper.get('sha256')}, found {actual_sha}")
    if helper.get("size") != binary.stat().st_size:
        raise RuntimeError("CEL helper size does not match its release manifest")
    binary_format = _binary_format(binary)
    actual_arch, macos_minimum = _binary_arch(binary, binary_format)
    if binary_format != helper["binary_format"] or actual_arch != target.goarch:
        raise RuntimeError(
            f"CEL helper payload architecture does not match {target.name}: found {binary_format}/{actual_arch}"
        )
    if target.macos_minimum is not None and macos_minimum != target.macos_minimum:
        expected = ".".join(map(str, target.macos_minimum[:2]))
        actual = ".".join(map(str, macos_minimum or ()))
        raise RuntimeError(f"CEL helper macOS minimum version mismatch: expected {expected}, found {actual}")
    return manifest


def verify_bundle(binary: Path, manifest_path: Path, target: CelGoTarget, *, go: str = "go") -> dict[str, Any]:
    manifest = verify_bundle_integrity(binary, manifest_path, target)
    verify_binary(binary, target, go=go)
    return manifest


def verify_wheel(wheel: Path, target: CelGoTarget) -> dict[str, Any]:
    if not wheel.name.endswith(f"-{target.wheel_tag}.whl"):
        raise RuntimeError(f"wheel {wheel.name} does not use exact target tag {target.wheel_tag}")
    binary_member = f"skill_scanner/core/cel/_bin/{target.filename}"
    manifest_member = "skill_scanner/core/cel/_bin/manifest.json"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        helpers = [name for name in names if "/_bin/skill-scanner-cel-go-" in name]
        if helpers != [binary_member]:
            raise RuntimeError(f"wheel must contain exactly {binary_member}; found {helpers}")
        if manifest_member not in names:
            raise RuntimeError("wheel does not contain the CEL helper release manifest")
        manifest = validate_manifest_document(
            json.loads(archive.read(manifest_member)), source=f"{wheel}!{manifest_member}"
        )
        helper = manifest.get("helper", {})
        payload = archive.read(binary_member)
        if helper.get("target") != target.name or helper.get("filename") != target.filename:
            raise RuntimeError("wheel helper and manifest target differ")
        if helper.get("wheel_tag") != target.wheel_tag:
            raise RuntimeError("wheel helper manifest records the wrong wheel tag")
        digest = hashlib.sha256(payload).hexdigest()
        if helper.get("sha256") != digest or helper.get("size") != len(payload):
            raise RuntimeError("wheel helper payload does not match its manifest hash/size")
        binary_format = _binary_format_bytes(payload, source=f"{wheel}!{binary_member}")
        actual_arch, macos_minimum = _binary_arch_bytes(payload, binary_format)
        if binary_format != helper["binary_format"] or actual_arch != target.goarch:
            raise RuntimeError(
                f"wheel helper payload architecture does not match {target.name}: found {binary_format}/{actual_arch}"
            )
        if target.macos_minimum is not None and macos_minimum != target.macos_minimum:
            expected = ".".join(map(str, target.macos_minimum[:2]))
            actual = ".".join(map(str, macos_minimum or ()))
            raise RuntimeError(f"wheel helper macOS minimum version mismatch: expected {expected}, found {actual}")
    return manifest


def copy_prebuilt_bundle(
    *, source_dir: Path, destination_dir: Path, target: CelGoTarget, go: str = "go"
) -> dict[str, Any]:
    binary = source_dir / target.filename
    manifest_path = source_dir / "manifest.json"
    manifest = verify_bundle(binary, manifest_path, target, go=go)
    destination_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, destination_dir / target.filename)
    shutil.copy2(manifest_path, destination_dir / "manifest.json")
    return manifest
