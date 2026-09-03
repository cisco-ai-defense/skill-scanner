# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

import scripts.cel_go_packaging as cel_packaging
from scripts.cel_go_packaging import (
    CEL_GO_MODULE,
    CEL_GO_SUM,
    CEL_GO_TAG_COMMIT,
    CEL_GO_VERSION,
    HELPER_MODULE,
    HELPER_PROTOCOL_VERSION,
    SCAN_FACTS_DESCRIPTOR_SHA256,
    SUPPORTED_TARGETS,
    infer_host_target,
    parse_go_version,
    require_helper_version,
    resolve_target,
    validate_manifest_document,
    verify_bundle_integrity,
    verify_go_module,
    verify_go_toolchain,
    verify_wheel,
)
from skill_scanner.core.cel.go_runtime import PROTOCOL_VERSION


def _manifest_for_payload(payload: bytes, target_name: str = "linux-amd64") -> dict[str, object]:
    target = SUPPORTED_TARGETS[target_name]
    return {
        "schema_version": 1,
        "helper": {
            "binary_format": {"linux": "elf", "darwin": "macho", "windows": "pe"}[target.goos],
            "cel_go_module": CEL_GO_MODULE,
            "cel_go_sum": CEL_GO_SUM,
            "cel_go_tag_commit": CEL_GO_TAG_COMMIT,
            "cel_go_version": CEL_GO_VERSION,
            "filename": target.filename,
            "go_version": "go1.27.1",
            "goarch": target.goarch,
            "goos": target.goos,
            "helper_module": HELPER_MODULE,
            "helper_version": "1.0.0",
            "protocol_version": HELPER_PROTOCOL_VERSION,
            "scan_facts_descriptor_sha256": SCAN_FACTS_DESCRIPTOR_SHA256,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "target": target.name,
            "toolchain_version": "go1.27.1",
            "wheel_tag": target.wheel_tag,
            **({"macos_minimum": "13.0"} if target.macos_minimum is not None else {}),
        },
    }


def _elf_fixture(machine: int = 62) -> bytes:
    payload = bytearray(20)
    payload[:4] = b"\x7fELF"
    payload[4] = 2  # 64-bit
    payload[5] = 1  # little-endian
    struct.pack_into("<H", payload, 18, machine)
    return bytes(payload)


def test_release_target_matrix_is_exact_and_cpython_abi_stable() -> None:
    assert HELPER_PROTOCOL_VERSION == PROTOCOL_VERSION == 2
    assert set(SUPPORTED_TARGETS) == {
        "linux-amd64",
        "linux-arm64",
        "darwin-amd64",
        "darwin-arm64",
        "windows-amd64",
    }
    assert {target.wheel_tag for target in SUPPORTED_TARGETS.values()} == {
        "cp311.cp312.cp313.cp314-none-manylinux_2_17_x86_64",
        "cp311.cp312.cp313.cp314-none-manylinux_2_17_aarch64",
        "cp311.cp312.cp313.cp314-none-macosx_13_0_x86_64",
        "cp311.cp312.cp313.cp314-none-macosx_13_0_arm64",
        "cp311.cp312.cp313.cp314-none-win_amd64",
    }


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("linux", "x86_64", "linux-amd64"),
        ("linux", "aarch64", "linux-arm64"),
        ("darwin", "arm64", "darwin-arm64"),
        ("darwin", "x86_64", "darwin-amd64"),
        ("win32", "AMD64", "windows-amd64"),
    ],
)
def test_host_target_normalization(system: str, machine: str, expected: str) -> None:
    assert infer_host_target(system=system, machine=machine, libc="glibc").name == expected


def test_unsupported_target_is_explicit() -> None:
    with pytest.raises(RuntimeError, match="unsupported CEL helper build target"):
        infer_host_target(system="linux", machine="riscv64", libc="glibc")
    with pytest.raises(RuntimeError, match="unknown SKILL_SCANNER_CEL_GO_TARGET"):
        resolve_target("windows-arm64")


def test_source_build_rejects_pypy_and_musl() -> None:
    with pytest.raises(RuntimeError, match="CPython only"):
        infer_host_target(system="linux", machine="x86_64", implementation="PyPy", libc="glibc")
    with pytest.raises(RuntimeError, match="require glibc Linux"):
        infer_host_target(system="linux", machine="x86_64", implementation="CPython", libc="musl")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("go version go1.23.0 linux/amd64", (1, 23, 0)), ("helper: go1.27.1", (1, 27, 1)), ("go1.24", (1, 24, 0))],
)
def test_go_version_parser(value: str, expected: tuple[int, int, int]) -> None:
    assert parse_go_version(value) == expected


def test_source_build_requires_go_1_27_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cel_packaging.shutil, "which", lambda _go: "/qualified/go")

    def go_version(version: str) -> None:
        monkeypatch.setattr(
            cel_packaging.subprocess,
            "run",
            lambda *_args, **_kwargs: subprocess.CompletedProcess(
                ["go", "version"], 0, stdout=f"go version go{version} darwin/arm64\n", stderr=""
            ),
        )

    go_version("1.27.0")
    with pytest.raises(RuntimeError, match=r"Go 1\.27\.1\+ is required"):
        verify_go_toolchain()

    go_version("1.27.1")
    assert verify_go_toolchain() == "go1.27.1"


def test_source_build_checks_go_version_in_module_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cel_packaging.shutil, "which", lambda _go: "/qualified/go")
    observed: dict[str, object] = {}

    def run(*_args, **kwargs):
        observed["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(["go", "version"], 0, stdout="go version go1.27.1 darwin/arm64\n")

    monkeypatch.setattr(cel_packaging.subprocess, "run", run)

    assert verify_go_toolchain(cwd=tmp_path) == "go1.27.1"
    assert observed["cwd"] == tmp_path


def test_qualified_module_and_sum_are_locked() -> None:
    verify_go_module(Path(__file__).resolve().parents[1])
    assert CEL_GO_VERSION == "v0.32.0"
    assert CEL_GO_SUM.startswith("h1:")


def test_release_build_rejects_prebuilt_helper_from_another_version() -> None:
    manifest = {"helper": {"helper_version": "1.2.3"}}

    require_helper_version(manifest, "1.2.3", editable=False)
    require_helper_version(manifest, "source-tree", editable=True)
    with pytest.raises(RuntimeError, match="does not match package version"):
        require_helper_version(manifest, "1.2.4", editable=False)


def test_source_bundle_integrity_does_not_require_go(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = SUPPORTED_TARGETS["linux-amd64"]
    payload = _elf_fixture()
    binary = tmp_path / target.filename
    manifest_path = tmp_path / "manifest.json"
    binary.write_bytes(payload)
    manifest = _manifest_for_payload(payload)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        cel_packaging.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("integrity-only source reuse must not invoke Go"),
    )

    assert verify_bundle_integrity(binary, manifest_path, target) == manifest

    binary.write_bytes(payload + b"tampered")
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        verify_bundle_integrity(binary, manifest_path, target)


def test_wheel_verifier_rejects_wrong_target_or_tampered_payload(tmp_path: Path) -> None:
    target = SUPPORTED_TARGETS["linux-amd64"]
    payload = _elf_fixture()
    manifest = _manifest_for_payload(payload)
    wheel = tmp_path / f"scanner-1.0-{target.wheel_tag}.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"skill_scanner/core/cel/_bin/{target.filename}", payload)
        archive.writestr("skill_scanner/core/cel/_bin/manifest.json", json.dumps(manifest))
    assert verify_wheel(wheel, target) == manifest

    wrong_target = SUPPORTED_TARGETS["linux-arm64"]
    with pytest.raises(RuntimeError, match="exact target tag"):
        verify_wheel(wheel, wrong_target)

    tampered = tmp_path / f"tampered-1.0-{target.wheel_tag}.whl"
    with zipfile.ZipFile(tampered, "w") as archive:
        archive.writestr(f"skill_scanner/core/cel/_bin/{target.filename}", payload + b"changed")
        archive.writestr("skill_scanner/core/cel/_bin/manifest.json", json.dumps(manifest))
    with pytest.raises(RuntimeError, match="hash/size"):
        verify_wheel(tampered, target)

    wrong_arch_payload = _elf_fixture(machine=183)
    wrong_arch_manifest = _manifest_for_payload(wrong_arch_payload)
    wrong_arch = tmp_path / f"wrong-arch-1.0-{target.wheel_tag}.whl"
    with zipfile.ZipFile(wrong_arch, "w") as archive:
        archive.writestr(f"skill_scanner/core/cel/_bin/{target.filename}", wrong_arch_payload)
        archive.writestr("skill_scanner/core/cel/_bin/manifest.json", json.dumps(wrong_arch_manifest))
    with pytest.raises(RuntimeError, match="payload architecture"):
        verify_wheel(wrong_arch, target)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("protocol_version", "protocol_version mismatch"),
        ("scan_facts_descriptor_sha256", "scan_facts_descriptor_sha256 mismatch"),
    ],
)
def test_manifest_requires_protocol_and_descriptor(field: str, message: str) -> None:
    manifest = _manifest_for_payload(b"fixture")
    manifest["helper"].pop(field)  # type: ignore[union-attr]

    with pytest.raises(RuntimeError, match=message):
        validate_manifest_document(manifest, source="test")


def test_manifest_rejects_unknown_fields() -> None:
    manifest = _manifest_for_payload(b"fixture")
    manifest["helper"]["unexpected"] = "value"  # type: ignore[index]

    with pytest.raises(RuntimeError, match="unknown fields"):
        validate_manifest_document(manifest, source="test")


@pytest.mark.parametrize("field", ["go_version", "toolchain_version"])
def test_manifest_rejects_prequalification_go_versions(field: str) -> None:
    manifest = _manifest_for_payload(b"fixture")
    manifest["helper"][field] = "go1.27.0"  # type: ignore[index]

    with pytest.raises(RuntimeError, match=rf"{field} must be Go 1\.27\.1\+"):
        validate_manifest_document(manifest, source="test")


def test_manifest_rejects_target_metadata_disagreement() -> None:
    manifest = _manifest_for_payload(b"fixture")
    manifest["helper"]["goarch"] = "arm64"  # type: ignore[index]

    with pytest.raises(RuntimeError, match="goarch mismatch"):
        validate_manifest_document(manifest, source="test")
