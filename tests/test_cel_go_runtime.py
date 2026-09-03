# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from skill_scanner.core.cel import CelGate, CelGoRuntime, CelMode, CelRule
from skill_scanner.core.cel.go_runtime import (
    _DISCOVERY_CONTEXTS,
    CEL_GO_MODULE,
    CEL_GO_SUM,
    CEL_GO_TAG_COMMIT,
    CEL_GO_VERSION,
    HELPER_ENV,
    HELPER_MODULE,
    PROTOCOL_VERSION,
    SCAN_FACTS_DESCRIPTOR_HASH,
    _ProtocolFailure,
    _target_name,
    _verify_packaged_helper,
    discover_cel_go_helper,
)
from skill_scanner.core.cel.runtime import CelRuntimeUnavailable
from skill_scanner.core.semantic import scan_facts_pb2

ROOT = Path(__file__).parents[1]
GO_HELPER_DIR = ROOT / "tools" / "cel_runtime"


@pytest.fixture(scope="session")
def cel_go_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain is unavailable")
    version = subprocess.run(
        [go, "version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    match = re.search(r"go(\d+)\.(\d+)(?:\.(\d+))?", version)
    parsed = None if match is None else tuple(int(part or 0) for part in match.groups())
    if parsed is None or parsed < (1, 27, 1):
        pytest.skip("the qualified CEL helper requires Go 1.27.1 or newer")
    suffix = ".exe" if os.name == "nt" else ""
    output = tmp_path_factory.mktemp("cel-go-helper") / f"skill-scanner-cel-go{suffix}"
    environment = dict(os.environ)
    environment["GOTOOLCHAIN"] = "local"
    subprocess.run(
        [go, "build", "-trimpath", "-buildvcs=false", "-o", str(output), "."],
        cwd=GO_HELPER_DIR,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return output


def _facts(rule_id: str, *, has_description: bool = False) -> scan_facts_pb2.ScanFacts:
    facts = scan_facts_pb2.ScanFacts(schema_version="v1")
    facts.skill.has_description = has_description
    facts.candidate.rule_id = rule_id
    facts.projection.complete = True
    for _ in range(8):
        size = facts.ByteSize()
        if facts.projection.serialized_bytes == size:
            break
        facts.projection.serialized_bytes = size
    assert facts.projection.serialized_bytes == facts.ByteSize()
    return facts


def test_production_runtime_persistently_evaluates_typed_true_and_false(
    cel_go_binary: Path,
) -> None:
    rules = [
        CelRule("KEEP", "f.projection.complete"),
        CelRule("DROP", "f.skill.has_description"),
    ]
    runtime = CelGoRuntime(rules, binary_path=cel_go_binary)
    process_id = runtime._process.pid
    try:
        keep = runtime.evaluate("KEEP", _facts("KEEP"))
        drop = runtime.evaluate("DROP", _facts("DROP"))

        assert keep.value is True and keep.error_code == ""
        assert drop.value is False and drop.error_code == ""
        assert keep.elapsed_ms > 0
        assert runtime._process.pid == process_id
        assert runtime._process.poll() is None
        assert runtime.runtime_name == "cel-go"
        assert runtime.engine_version == CEL_GO_VERSION
        assert runtime.version.startswith(f"{CEL_GO_VERSION};helper=")
        assert dict(runtime.fact_access_paths) == {
            "DROP": ("skill.has_description",),
            "KEEP": ("projection.complete",),
        }
    finally:
        runtime.close()
    assert runtime._process.poll() is not None


def test_production_runtime_batches_typed_results_in_input_order(cel_go_binary: Path) -> None:
    rules = [
        CelRule("KEEP", "f.skill.has_description"),
        CelRule("DROP", "f.skill.has_description"),
    ]
    with CelGoRuntime(rules, binary_path=cel_go_binary) as runtime:
        results = runtime.evaluate_batch(
            [
                ("KEEP", _facts("KEEP", has_description=True)),
                ("DROP", _facts("DROP", has_description=False)),
                ("MISSING", _facts("MISSING", has_description=True)),
            ]
        )

    assert [result.value for result in results] == [True, False, None]
    assert [result.error_code for result in results] == ["", "", "UNKNOWN_RULE_ID"]
    assert sum(result.elapsed_ms for result in results) > 0


def test_batch_runtime_rejects_non_scan_facts_without_writing_to_helper(cel_go_binary: Path) -> None:
    with CelGoRuntime([CelRule("RULE", "f.projection.complete")], binary_path=cel_go_binary) as runtime:
        results = runtime.evaluate_batch([("RULE", object())])  # type: ignore[list-item]

    assert len(results) == 1
    assert (results[0].value, results[0].elapsed_ms, results[0].error_code) == (
        None,
        0.0,
        "ACTIVATION_TYPE_ERROR",
    )


def test_batch_transport_corruption_fails_open_every_item(
    cel_go_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = CelGoRuntime([CelRule("RULE", "f.projection.complete")], binary_path=cel_go_binary)

    def corrupt_response(_payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        return {
            "ok": True,
            "expression_set_hash": runtime.expression_set_hash,
            "results": [{"ok": True, "value": False, "elapsed_ms": 0.01, "actual_cost": 1}],
        }

    monkeypatch.setattr(runtime, "_request", corrupt_response)
    try:
        results = runtime.evaluate_batch([("RULE", _facts("RULE")), ("RULE", _facts("RULE"))])
    finally:
        runtime.close()

    assert [result.value for result in results] == [None, None]
    assert [result.error_code for result in results] == ["PROTOCOL_ERROR", "PROTOCOL_ERROR"]


def test_batch_chunks_by_total_facts_and_exact_encoded_frame(
    cel_go_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = CelGoRuntime([CelRule("RULE", "f.projection.complete")], binary_path=cel_go_binary)
    monkeypatch.setattr("skill_scanner.core.cel.go_runtime.MAX_BATCH_FACT_BYTES", 120)
    monkeypatch.setattr("skill_scanner.core.cel.go_runtime.MAX_FRAME_BYTES", 700)
    requests: list[dict[str, Any]] = []

    def successful_response(payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        if payload.get("type") == "shutdown":
            return {"ok": True}
        requests.append(payload)
        return {
            "ok": True,
            "expression_set_hash": runtime.expression_set_hash,
            "results": [{"ok": True, "value": True, "elapsed_ms": 0.01, "actual_cost": 1} for _ in payload["items"]],
        }

    monkeypatch.setattr(runtime, "_request", successful_response)
    try:
        results = runtime.evaluate_batch([("RULE", _facts("RULE")) for _ in range(10)])
    finally:
        runtime.close()

    assert len(requests) > 1
    assert sum(len(request["items"]) for request in requests) == 10
    assert all(runtime._batch_frame_size(request["items"]) <= 700 for request in requests)
    assert all(result.value is True and result.error_code == "" for result in results)


def test_stale_protocol_v1_helper_is_rejected_during_initialization(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("shell fixture is POSIX-only")
    helper = tmp_path / "stale-v1-helper"
    helper.write_text(
        "#!/bin/sh\n"
        "IFS= read -r request\n"
        'printf \'%s\\n\' \'{"protocol_version":1,"type":"initialized",'
        '"request_id":1,"ok":false,"error_code":"PROTOCOL_VERSION_MISMATCH",'
        '"message":"stale helper"}\'\n',
        encoding="utf-8",
    )
    helper.chmod(0o700)

    with pytest.raises(CelRuntimeUnavailable, match="protocol|initialization"):
        CelGoRuntime([CelRule("RULE", "f.projection.complete")], binary_path=helper)


def test_production_runtime_supports_bounded_macros_and_string_methods(
    cel_go_binary: Path,
) -> None:
    expression = """
f.skill.files.exists(x, x.hidden) &&
f.skill.files.all(x, x.path.startsWith(".") || x.path.endsWith(".sh")) &&
f.candidate.rule_id in f.candidate.cooccurring_rule_ids &&
has(f.candidate.file) &&
f.candidate.file.path.contains("run") &&
f.candidate.file.path.matches("run[.]sh$")
""".strip()
    runtime = CelGoRuntime([CelRule("RULE", expression)], binary_path=cel_go_binary)
    try:
        facts = _facts("RULE")
        file_fact = facts.skill.files.add(path="run.sh", hidden=True)
        facts.candidate.file.CopyFrom(file_fact)
        facts.candidate.cooccurring_rule_ids.append("RULE")
        for _ in range(8):
            facts.projection.serialized_bytes = facts.ByteSize()
        result = runtime.evaluate("RULE", facts)
    finally:
        runtime.close()

    assert result.value is True
    assert result.error_code == ""
    assert runtime.fact_access_paths["RULE"] == (
        "candidate.cooccurring_rule_ids",
        "candidate.file",
        "candidate.file.path",
        "candidate.rule_id",
        "skill.files",
        "skill.files.hidden",
        "skill.files.path",
    )


def test_compiler_fact_access_paths_resolve_nested_comprehension_aliases(
    cel_go_binary: Path,
) -> None:
    expression = """
f.skill.commands.exists(command,
  command.source_class == "sensitive_data" &&
  command.argument_classes.exists(argument, argument == "encoded"))
""".strip()
    runtime = CelGoRuntime([CelRule("RULE", expression)], binary_path=cel_go_binary)
    try:
        assert runtime.fact_access_paths["RULE"] == (
            "skill.commands",
            "skill.commands.argument_classes",
            "skill.commands.source_class",
        )
    finally:
        runtime.close()


def test_incomplete_projection_is_rejected_by_helper_defense_in_depth(cel_go_binary: Path) -> None:
    runtime = CelGoRuntime([CelRule("RULE", "f.projection.complete")], binary_path=cel_go_binary)
    try:
        facts = _facts("RULE")
        facts.projection.complete = False
        for _ in range(8):
            facts.projection.serialized_bytes = facts.ByteSize()
        result = runtime.evaluate("RULE", facts)
    finally:
        runtime.close()

    assert result.value is None
    assert result.error_code == "PROJECTION_INCOMPLETE"


def test_truncated_projection_serializes_and_is_reported_in_compiler_access_mask(
    cel_go_binary: Path,
) -> None:
    runtime = CelGoRuntime([CelRule("RULE", "!f.projection.truncated")], binary_path=cel_go_binary)
    try:
        facts = _facts("RULE")
        facts.projection.truncated = True
        for _ in range(8):
            facts.projection.serialized_bytes = facts.ByteSize()
        result = runtime.evaluate("RULE", facts)
    finally:
        runtime.close()

    assert runtime.fact_access_paths["RULE"] == ("projection.truncated",)
    assert result.value is None
    assert result.error_code == "PROJECTION_INCOMPLETE"


def test_helper_crash_fails_open_and_opens_circuit(cel_go_binary: Path) -> None:
    runtime = CelGoRuntime(
        [CelRule("RULE", "f.projection.complete")],
        binary_path=cel_go_binary,
        failure_limit=1,
    )
    try:
        runtime._process.kill()
        runtime._process.wait(timeout=5)

        failed = runtime.evaluate("RULE", _facts("RULE"))
        circuit = runtime.evaluate("RULE", _facts("RULE"))
    finally:
        runtime.close()

    assert failed.value is None
    assert failed.error_code == "RUNTIME_UNAVAILABLE"
    assert circuit.error_code == "CIRCUIT_OPEN"


def test_gate_defaults_to_cel_go_and_reports_runtime_neutrally(
    cel_go_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(HELPER_ENV, str(cel_go_binary))
    gate = CelGate([CelRule("RULE", "f.projection.complete")], CelMode.SHADOW)
    try:
        assert isinstance(gate.runtime, CelGoRuntime)
        assert gate.runtime.runtime_name == "cel-go"
    finally:
        gate.close()


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("linux", "x86_64", ("linux", "amd64", "")),
        ("linux", "aarch64", ("linux", "arm64", "")),
        ("darwin", "x86_64", ("darwin", "amd64", "")),
        ("darwin", "arm64", ("darwin", "arm64", "")),
        ("win32", "amd64", ("windows", "amd64", ".exe")),
    ],
)
def test_supported_release_targets(system: str, machine: str, expected: tuple[str, str, str]) -> None:
    assert _target_name(system=system, machine=machine) == expected


def test_windows_arm_and_unknown_platforms_fail_with_support_matrix() -> None:
    with pytest.raises(CelRuntimeUnavailable, match="unsupported"):
        _target_name(system="win32", machine="arm64")
    with pytest.raises(CelRuntimeUnavailable, match="unsupported"):
        _target_name(system="freebsd", machine="amd64")


def test_explicit_helper_discovery_requires_a_real_executable(tmp_path: Path) -> None:
    missing = tmp_path / "missing-helper"
    with pytest.raises(CelRuntimeUnavailable, match=HELPER_ENV):
        discover_cel_go_helper(missing)

    helper = tmp_path / "helper"
    helper.write_bytes(b"placeholder")
    helper.chmod(0o700)
    assert discover_cel_go_helper(helper) == helper.resolve()


def test_missing_platform_helper_has_installation_hint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(HELPER_ENV, raising=False)
    _DISCOVERY_CONTEXTS.clear()
    monkeypatch.setattr("skill_scanner.core.cel.go_runtime.importlib.resources.files", lambda _package: tmp_path)

    with pytest.raises(CelRuntimeUnavailable, match="platform wheel"):
        discover_cel_go_helper()


def _packaged_manifest(binary: Path) -> dict[str, Any]:
    import hashlib

    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    goos, goarch, _suffix = _target_name()
    packaging = {
        ("linux", "amd64"): ("elf", "cp311.cp312.cp313.cp314-none-manylinux_2_17_x86_64", None),
        ("linux", "arm64"): ("elf", "cp311.cp312.cp313.cp314-none-manylinux_2_17_aarch64", None),
        ("darwin", "amd64"): ("macho", "cp311.cp312.cp313.cp314-none-macosx_13_0_x86_64", "13.0"),
        ("darwin", "arm64"): ("macho", "cp311.cp312.cp313.cp314-none-macosx_13_0_arm64", "13.0"),
        ("windows", "amd64"): ("pe", "cp311.cp312.cp313.cp314-none-win_amd64", None),
    }
    binary_format, wheel_tag, macos_minimum = packaging[(goos, goarch)]
    helper = {
        "binary_format": binary_format,
        "cel_go_module": CEL_GO_MODULE,
        "cel_go_sum": CEL_GO_SUM,
        "cel_go_tag_commit": CEL_GO_TAG_COMMIT,
        "cel_go_version": CEL_GO_VERSION,
        "filename": binary.name,
        "go_version": "go1.27.1",
        "goarch": goarch,
        "goos": goos,
        "helper_module": HELPER_MODULE,
        "helper_version": "development",
        "protocol_version": PROTOCOL_VERSION,
        "scan_facts_descriptor_sha256": SCAN_FACTS_DESCRIPTOR_HASH,
        "sha256": digest,
        "size": binary.stat().st_size,
        "target": f"{goos}-{goarch}",
        "toolchain_version": "go1.27.1",
        "wheel_tag": wheel_tag,
    }
    if macos_minimum is not None:
        helper["macos_minimum"] = macos_minimum
    return {
        "schema_version": 1,
        "helper": helper,
    }


def test_packaged_manifest_rejects_tamper_and_wrong_target(
    cel_go_binary: Path,
    tmp_path: Path,
) -> None:
    goos, goarch, _suffix = _target_name()
    binary = tmp_path / f"skill-scanner-cel-go-{goos}-{goarch}"
    shutil.copy2(cel_go_binary, binary)
    binary.chmod(0o700)
    document = _packaged_manifest(binary)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    _verify_packaged_helper(manifest, binary, goos=goos, goarch=goarch, filename=binary.name)

    document["helper"]["target"] = "linux-amd64" if goos != "linux" else "darwin-arm64"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="target"):
        _verify_packaged_helper(manifest, binary, goos=goos, goarch=goarch, filename=binary.name)

    document = _packaged_manifest(binary)
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with binary.open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(ValueError, match="size|digest"):
        _verify_packaged_helper(manifest, binary, goos=goos, goarch=goarch, filename=binary.name)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("helper_module", "example.invalid/untrusted-helper"),
        ("cel_go_sum", "h1:not-the-qualified-module-checksum"),
    ],
)
def test_packaged_manifest_binds_helper_and_cel_module_identity(
    cel_go_binary: Path,
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    goos, goarch, _suffix = _target_name()
    binary = tmp_path / f"skill-scanner-cel-go-{goos}-{goarch}"
    shutil.copy2(cel_go_binary, binary)
    binary.chmod(0o700)
    document = _packaged_manifest(binary)
    document["helper"][field] = value
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match=field):
        _verify_packaged_helper(manifest, binary, goos=goos, goarch=goarch, filename=binary.name)


@pytest.mark.parametrize("field", ["go_version", "toolchain_version"])
def test_packaged_manifest_rejects_prequalification_go_versions(
    cel_go_binary: Path,
    tmp_path: Path,
    field: str,
) -> None:
    goos, goarch, _suffix = _target_name()
    binary = tmp_path / f"skill-scanner-cel-go-{goos}-{goarch}"
    shutil.copy2(cel_go_binary, binary)
    binary.chmod(0o700)
    document = _packaged_manifest(binary)
    document["helper"][field] = "go1.27.0"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"{field} is older than Go 1\.27\.1"):
        _verify_packaged_helper(manifest, binary, goos=goos, goarch=goarch, filename=binary.name)


def test_cached_packaged_helper_is_rehashed_before_reuse(
    cel_go_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    goos, goarch, suffix = _target_name()
    resource_root = tmp_path / "resource-root"
    binary_dir = resource_root / "_bin"
    binary_dir.mkdir(parents=True)
    binary = binary_dir / f"skill-scanner-cel-go-{goos}-{goarch}{suffix}"
    shutil.copy2(cel_go_binary, binary)
    binary.chmod(0o700)
    (binary_dir / "manifest.json").write_text(json.dumps(_packaged_manifest(binary)), encoding="utf-8")
    monkeypatch.delenv(HELPER_ENV, raising=False)
    _DISCOVERY_CONTEXTS.clear()
    monkeypatch.setattr("skill_scanner.core.cel.go_runtime.importlib.resources.files", lambda _package: resource_root)

    assert discover_cel_go_helper() == binary.resolve()
    original_stat = binary.stat()
    with binary.open("r+b") as stream:
        first = stream.read(1)
        stream.seek(0)
        stream.write(bytes([first[0] ^ 0xFF]))
    os.utime(binary, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    assert binary.stat().st_size == original_stat.st_size
    assert binary.stat().st_mtime_ns == original_stat.st_mtime_ns

    with pytest.raises(CelRuntimeUnavailable, match="digest"):
        discover_cel_go_helper()


def test_packaged_helper_handshake_version_must_match_manifest(
    cel_go_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    goos, goarch, suffix = _target_name()
    resource_root = tmp_path / "resource-root"
    binary_dir = resource_root / "_bin"
    binary_dir.mkdir(parents=True)
    binary = binary_dir / f"skill-scanner-cel-go-{goos}-{goarch}{suffix}"
    shutil.copy2(cel_go_binary, binary)
    binary.chmod(0o700)
    document = _packaged_manifest(binary)
    document["helper"]["helper_version"] = "different-from-development"
    (binary_dir / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.delenv(HELPER_ENV, raising=False)
    _DISCOVERY_CONTEXTS.clear()
    monkeypatch.setattr("skill_scanner.core.cel.go_runtime.importlib.resources.files", lambda _package: resource_root)

    with pytest.raises(CelRuntimeUnavailable, match="build version.*manifest"):
        CelGoRuntime([CelRule("RULE", "f.projection.complete")])
    _DISCOVERY_CONTEXTS.clear()


def test_runtime_factory_rejects_invalid_budget_configuration(cel_go_binary: Path) -> None:
    rule = [CelRule("RULE", "f.projection.complete")]
    invalid: list[dict[str, Any]] = [
        {"eval_timeout_ms": 0},
        {"eval_timeout_ms": 51},
        {"cost_limit": 0},
        {"cost_limit": 1_000_001},
        {"response_timeout_s": 0.01},
    ]
    for options in invalid:
        with pytest.raises(ValueError):
            CelGoRuntime(rule, binary_path=cel_go_binary, **options)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda response: response.__setitem__("protocol_version", True),
        lambda response: response.__setitem__("request_id", True),
        lambda response: response.__setitem__("ok", 1),
        lambda response: response.__setitem__("error_code", "EVALUATION_ERROR"),
        lambda response: response.pop("value"),
    ],
)
def test_response_schema_rejects_type_confusion_and_contradictions(mutation: Any) -> None:
    response: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "type": "evaluation",
        "request_id": 7,
        "ok": True,
        "value": False,
        "elapsed_ms": 0.1,
        "actual_cost": 1,
        "expression_set_hash": "a" * 64,
    }
    mutation(response)

    with pytest.raises(_ProtocolFailure, match="response"):
        CelGoRuntime._validate_response_schema(response, "evaluation", 7)


def test_repeated_runtime_close_leaves_no_transport_threads(cel_go_binary: Path) -> None:
    prefixes = ("skill-scanner-cel-go-stdin", "skill-scanner-cel-go-stdout", "skill-scanner-cel-go-stderr")
    baseline = {thread.ident for thread in threading.enumerate() if thread.name.startswith(prefixes)}
    processes: list[subprocess.Popen[bytes]] = []

    for _ in range(20):
        runtime = CelGoRuntime([CelRule("RULE", "f.projection.complete")], binary_path=cel_go_binary)
        processes.append(runtime._process)
        runtime.close()

    assert all(process.poll() is not None for process in processes)
    leaked = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith(prefixes) and thread.ident not in baseline
    }
    assert leaked == set()
