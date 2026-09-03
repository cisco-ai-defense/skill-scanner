# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Persistent adapter for the production cel-go helper process."""

from __future__ import annotations

import base64
import hashlib
import importlib.resources
import json
import math
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import weakref
from collections import OrderedDict
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO

from google.protobuf import descriptor_pb2

from ..semantic import scan_facts_pb2
from .models import CelRule, expression_set_hash
from .runtime import CelRuntimeUnavailable, RuntimeEvaluation, _CircuitState
from .validator import validate_cel_expression

PROTOCOL_VERSION = 2
CEL_GO_MODULE = "cel.dev/cel-go"
CEL_GO_VERSION = "v0.32.0"
CEL_GO_SUM = "h1:irvpFKr5EuGPyxeME03ERh0rii1TX+BDAnB9eL3IvNk="
CEL_GO_TAG_COMMIT = "f2039bc647bca407d882d90436fc8b91bab1ae62"
HELPER_MODULE = "github.com/cisco-ai-defense/skill-scanner/tools/celruntime"
MINIMUM_GO_VERSION = "1.27.1"
SCAN_FACTS_DESCRIPTOR_HASH = "0dd0799a2276e2f6fc844bc1da5835e2a05ccbca3802d1dea635d3b0d4cd1a13"
HELPER_ENV = "SKILL_SCANNER_CEL_GO_HELPER"
MAX_FRAME_BYTES = 16 * 1024 * 1024
MAX_ACTIVATION_BYTES = 2 * 1024 * 1024
MAX_BATCH_ITEMS = 4_096
MAX_BATCH_FACT_BYTES = 8 * 1024 * 1024
DEFAULT_EVAL_TIMEOUT_MS = 50
DEFAULT_COST_LIMIT = 1_000_000
DEFAULT_INITIALIZE_TIMEOUT_S = 5.0
MAX_RULES = 1_024
MAX_EVAL_TIMEOUT_MS = 50
MAX_COST_LIMIT = 1_000_000
MAX_FACT_ACCESS_PATHS = 4_096
MAX_FACT_ACCESS_PATH_BYTES = 4_096
MAX_TOTAL_FACT_ACCESS_BYTES = 4 * 1_024 * 1_024
_MAX_ERROR_CODE_BYTES = 64
_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FACT_ACCESS_PATH_RE = re.compile(r"^(?:skill|candidate|projection)(?:\.[a-z_][a-z0-9_]*)+$")
_RESPONSE_FIELDS = frozenset(
    {
        "protocol_version",
        "type",
        "request_id",
        "ok",
        "value",
        "elapsed_ms",
        "actual_cost",
        "error_code",
        "message",
        "runtime",
        "runtime_version",
        "helper_version",
        "expression_set_hash",
        "descriptor_hash",
        "rule_count",
        "fact_access_paths",
        "results",
    }
)
_KNOWN_HELPER_ERROR_CODES = frozenset(
    {
        "ACTIVATION_FACT_LIMIT",
        "ACTIVATION_INVALID",
        "ACTIVATION_BATCH_SIZE_LIMIT",
        "ACTIVATION_UNKNOWN_FIELDS",
        "CANDIDATE_RULE_MISMATCH",
        "CEL_COMPILE_ERROR",
        "CEL_PROGRAM_ERROR",
        "CEL_GENERATION_NODE_LIMIT",
        "CEL_FACT_PATH_ERROR",
        "CEL_FACT_PATH_LIMIT",
        "CEL_SUBSET_ERROR",
        "COST_LIMIT_INVALID",
        "DESCRIPTOR_HASH_MISMATCH",
        "DESCRIPTOR_INVALID",
        "ENVIRONMENT_ERROR",
        "EVALUATION_COST_LIMIT",
        "EVALUATION_ERROR",
        "EVALUATION_PANIC",
        "EVALUATION_TIMEOUT",
        "EVAL_TIMEOUT_LIMIT",
        "EXPRESSION_HASH_INVALID",
        "EXPRESSION_HASH_MISMATCH",
        "FACT_SCHEMA_MISMATCH",
        "FILE_FACT_LIMIT",
        "GENERATION_MISMATCH",
        "INVALID_SHUTDOWN_REQUEST",
        "NON_BOOLEAN_EXPRESSION",
        "NON_BOOLEAN_RESULT",
        "NOT_INITIALIZED",
        "PROJECTION_INCOMPLETE",
        "PROTOCOL_ERROR",
        "PROTOCOL_VERSION_MISMATCH",
        "RULE_COUNT_LIMIT",
        "RULE_INVALID",
        "BATCH_ITEM_LIMIT",
        "SEMANTIC_FACT_LIMIT",
        "SERIALIZED_SIZE_MISMATCH",
        "UNKNOWN_REQUEST_TYPE",
        "UNKNOWN_RULE_ID",
    }
)
_VALIDATION_CACHE_LIMIT = 128
_VALIDATION_CACHE: OrderedDict[tuple[int, str, str], str] = OrderedDict()
_VALIDATION_CACHE_LOCK = threading.Lock()
_FORK_RUNTIMES: weakref.WeakSet[Any] = weakref.WeakSet()
_FORK_RUNTIMES_LOCK = threading.Lock()


@dataclass(frozen=True)
class _PackagedHelperExpectation:
    """Integrity and handshake identity of one packaged helper resource."""

    helper_version: str
    sha256: str
    size: int
    stat_identity: tuple[int, int, int, int]


@dataclass
class _DiscoveryContext:
    """Keep extracted resources alive and their last verified identity bound."""

    binary_path: Path
    manifest_path: Path
    stack: ExitStack
    expectation: _PackagedHelperExpectation


_DISCOVERY_CONTEXTS: dict[str, _DiscoveryContext] = {}
_DISCOVERY_CONTEXTS_LOCK = threading.Lock()

_PACKAGED_TARGETS: dict[tuple[str, str], tuple[str, str, str | None]] = {
    ("linux", "amd64"): ("elf", "cp311.cp312.cp313.cp314-none-manylinux_2_17_x86_64", None),
    ("linux", "arm64"): ("elf", "cp311.cp312.cp313.cp314-none-manylinux_2_17_aarch64", None),
    ("darwin", "amd64"): ("macho", "cp311.cp312.cp313.cp314-none-macosx_13_0_x86_64", "13.0"),
    ("darwin", "arm64"): ("macho", "cp311.cp312.cp313.cp314-none-macosx_13_0_arm64", "13.0"),
    ("windows", "amd64"): ("pe", "cp311.cp312.cp313.cp314-none-win_amd64", None),
}
_PACKAGED_HELPER_FIELDS = frozenset(
    {
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
        "protocol_version",
        "scan_facts_descriptor_sha256",
        "sha256",
        "size",
        "target",
        "toolchain_version",
        "wheel_tag",
    }
)


def _invalidate_child_runtimes() -> None:
    for runtime in tuple(_FORK_RUNTIMES):
        runtime._invalidate_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_invalidate_child_runtimes)


class _ProtocolFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _target_name(*, system: str | None = None, machine: str | None = None) -> tuple[str, str, str]:
    """Return the supported Go target and executable suffix."""

    raw_system = (system or sys.platform).lower()
    raw_machine = (machine or platform.machine()).lower()
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
    if goos is None or goarch is None or (goos == "windows" and goarch != "amd64"):
        raise CelRuntimeUnavailable(
            f"cel-go helper is unsupported on platform {raw_system}/{raw_machine}; "
            "supported targets are Linux amd64/arm64, macOS amd64/arm64, and Windows amd64"
        )
    suffix = ".exe" if goos == "windows" else ""
    return goos, goarch, suffix


def discover_cel_go_helper(
    explicit_path: str | os.PathLike[str] | None = None,
    *,
    system: str | None = None,
    machine: str | None = None,
) -> Path:
    """Resolve only an explicit or platform-wheel-packaged helper binary."""

    goos, goarch, suffix = _target_name(system=system, machine=machine)
    configured = explicit_path or os.environ.get(HELPER_ENV)
    if configured:
        try:
            resolved = Path(configured).expanduser().resolve(strict=True)
        except OSError:
            resolved = Path()
        if resolved.is_file() and (goos == "windows" or os.access(resolved, os.X_OK)):
            cached_pair = _discovery_context_for_path(resolved)
            if cached_pair is not None:
                _revalidate_discovery_context(cached_pair[0], cached_pair[1], goos=goos, goarch=goarch)
            return resolved

    if not configured:
        filename = f"skill-scanner-cel-go-{goos}-{goarch}{suffix}"
        target = f"{goos}-{goarch}"
        with _DISCOVERY_CONTEXTS_LOCK:
            cached_context = _DISCOVERY_CONTEXTS.get(target)
        if cached_context is not None:
            return _revalidate_discovery_context(target, cached_context, goos=goos, goarch=goarch)
        stack = ExitStack()
        try:
            package_root = importlib.resources.files("skill_scanner.core.cel")
            binary_dir = package_root.joinpath("_bin")
            manifest_path = stack.enter_context(importlib.resources.as_file(binary_dir.joinpath("manifest.json")))
            binary_path = stack.enter_context(importlib.resources.as_file(binary_dir.joinpath(filename)))
            resolved = binary_path.resolve(strict=True)
            expectation = _verify_packaged_helper(
                manifest_path,
                resolved,
                goos=goos,
                goarch=goarch,
                filename=filename,
            )
            if goos != "windows" and not os.access(resolved, os.X_OK):
                raise CelRuntimeUnavailable("packaged cel-go helper is not executable")
        except FileNotFoundError:
            stack.close()
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            stack.close()
            raise CelRuntimeUnavailable(f"packaged cel-go helper failed integrity validation: {exc}") from exc
        else:
            # ``as_file`` may materialize a zipped resource.  Keep that context
            # alive for callers of this path-returning compatibility API.
            with _DISCOVERY_CONTEXTS_LOCK:
                existing = _DISCOVERY_CONTEXTS.get(target)
                if existing is None:
                    _DISCOVERY_CONTEXTS[target] = _DiscoveryContext(
                        binary_path=resolved,
                        manifest_path=manifest_path,
                        stack=stack,
                        expectation=expectation,
                    )
            if existing is not None:
                stack.close()
                return _revalidate_discovery_context(target, existing, goos=goos, goarch=goarch)
            return resolved

    hint = (
        f"set {HELPER_ENV} to a trusted helper built from tools/cel_runtime"
        if configured
        else "install a platform wheel containing the cel-go helper or "
        "run `uv run python scripts/build_cel_helper.py --in-place`, or "
        f"set {HELPER_ENV} to a trusted helper built from tools/cel_runtime"
    )
    raise CelRuntimeUnavailable(f"CEL mode requires the official cel-go {CEL_GO_VERSION} helper; {hint}")


def _discovery_context_for_path(path: Path) -> tuple[str, _DiscoveryContext] | None:
    """Return the packaged-resource context for ``path``, if one exists."""

    with _DISCOVERY_CONTEXTS_LOCK:
        for target, context in _DISCOVERY_CONTEXTS.items():
            if context.binary_path == path:
                return target, context
    return None


def _revalidate_discovery_context(
    target: str,
    context: _DiscoveryContext,
    *,
    goos: str,
    goarch: str,
) -> Path:
    """Re-hash a cached packaged helper before returning it for execution."""

    filename = context.binary_path.name
    try:
        expectation = _verify_packaged_helper(
            context.manifest_path,
            context.binary_path,
            goos=goos,
            goarch=goarch,
            filename=filename,
        )
        if goos != "windows" and not os.access(context.binary_path, os.X_OK):
            raise ValueError("packaged cel-go helper is not executable")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        with _DISCOVERY_CONTEXTS_LOCK:
            if _DISCOVERY_CONTEXTS.get(target) is context:
                _DISCOVERY_CONTEXTS.pop(target)
        context.stack.close()
        raise CelRuntimeUnavailable(f"packaged cel-go helper failed integrity validation: {exc}") from exc

    context.expectation = expectation
    return context.binary_path


def _packaged_helper_expectation(path: Path) -> _PackagedHelperExpectation | None:
    """Return the verified packaged identity associated with a resolved path."""

    cached = _discovery_context_for_path(path)
    return cached[1].expectation if cached is not None else None


def _verify_packaged_helper(
    manifest_path: Path,
    binary_path: Path,
    *,
    goos: str,
    goarch: str,
    filename: str,
) -> _PackagedHelperExpectation:
    raw = manifest_path.read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("CEL helper manifest exceeds 64 KiB")
    document = json.loads(raw, object_pairs_hook=_strict_json_object)
    if not isinstance(document, dict) or set(document) != {"schema_version", "helper"}:
        raise ValueError("invalid CEL helper manifest root")
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("unsupported CEL helper manifest schema")
    helper = document.get("helper")
    if not isinstance(helper, dict):
        raise ValueError("invalid CEL helper manifest entry")
    try:
        binary_format, wheel_tag, macos_minimum = _PACKAGED_TARGETS[(goos, goarch)]
    except KeyError as exc:
        raise ValueError(f"unsupported packaged CEL helper target {goos}/{goarch}") from exc
    expected_fields = set(_PACKAGED_HELPER_FIELDS)
    if macos_minimum is not None:
        expected_fields.add("macos_minimum")
    if set(helper) != expected_fields:
        raise ValueError("packaged CEL helper manifest fields mismatch")
    expected = {
        "target": f"{goos}-{goarch}",
        "goos": goos,
        "goarch": goarch,
        "filename": filename,
        "binary_format": binary_format,
        "wheel_tag": wheel_tag,
        "cel_go_module": CEL_GO_MODULE,
        "cel_go_version": CEL_GO_VERSION,
        "cel_go_sum": CEL_GO_SUM,
        "cel_go_tag_commit": CEL_GO_TAG_COMMIT,
        "helper_module": HELPER_MODULE,
        "protocol_version": PROTOCOL_VERSION,
        "scan_facts_descriptor_sha256": SCAN_FACTS_DESCRIPTOR_HASH,
    }
    if macos_minimum is not None:
        expected["macos_minimum"] = macos_minimum
    for field, value in expected.items():
        if helper.get(field) != value or type(helper.get(field)) is not type(value):
            raise ValueError(f"CEL helper manifest {field!r} mismatch")
    if helper.get("filename") != binary_path.name:
        raise ValueError("CEL helper manifest filename does not match resource")
    declared_size = helper.get("size")
    if isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size <= 0:
        raise ValueError("invalid CEL helper manifest size")
    binary_stat = binary_path.stat()
    if binary_stat.st_size != declared_size:
        raise ValueError("packaged CEL helper size mismatch")
    declared_hash = helper.get("sha256")
    if not isinstance(declared_hash, str) or _SHA256_RE.fullmatch(declared_hash) is None:
        raise ValueError("invalid CEL helper manifest digest")
    actual_hash = _file_sha256(binary_path)
    if actual_hash != declared_hash:
        raise ValueError("packaged CEL helper digest mismatch")
    helper_version = helper.get("helper_version")
    if not isinstance(helper_version, str) or not helper_version or len(helper_version) > 128:
        raise ValueError("invalid packaged CEL helper version")
    for field in ("go_version", "toolchain_version"):
        value = helper.get(field)
        if not isinstance(value, str) or re.fullmatch(r"go\d+\.\d+(?:\.\d+)?", value) is None:
            raise ValueError(f"invalid packaged CEL helper {field}")
        actual = tuple(int(part) for part in value.removeprefix("go").split("."))
        actual = (*actual, *(0 for _ in range(3 - len(actual))))
        minimum = tuple(int(part) for part in MINIMUM_GO_VERSION.split("."))
        if actual < minimum:
            raise ValueError(f"packaged CEL helper {field} is older than Go {MINIMUM_GO_VERSION}")
    return _PackagedHelperExpectation(
        helper_version=helper_version,
        sha256=actual_hash,
        size=declared_size,
        stat_identity=(binary_stat.st_dev, binary_stat.st_ino, binary_stat.st_size, binary_stat.st_mtime_ns),
    )


def _descriptor_set_bytes() -> bytes:
    file_descriptor = descriptor_pb2.FileDescriptorProto()
    scan_facts_pb2.DESCRIPTOR.CopyToProto(file_descriptor)
    descriptor_set = descriptor_pb2.FileDescriptorSet(file=[file_descriptor])
    return bytes(descriptor_set.SerializeToString(deterministic=True))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_cel_go_generation(
    rules: list[CelRule],
    *,
    binary_path: str | os.PathLike[str] | None = None,
) -> str:
    """Authoritatively compile one immutable generation, once per process.

    CEL ``off`` disables decisions, not pack validation.  The exact helper
    digest participates in the cache key so replacing a development helper
    cannot reuse a prior successful qualification.
    """

    if not rules:
        return CEL_GO_VERSION
    helper = discover_cel_go_helper(binary_path)
    key = (os.getpid(), expression_set_hash(rules), _file_sha256(helper))
    with _VALIDATION_CACHE_LOCK:
        if key in _VALIDATION_CACHE:
            _VALIDATION_CACHE.move_to_end(key)
            return _VALIDATION_CACHE[key]
        with CelGoRuntime(rules, binary_path=helper) as runtime:
            runtime_version = runtime.version
        _VALIDATION_CACHE[key] = runtime_version
        while len(_VALIDATION_CACHE) > _VALIDATION_CACHE_LIMIT:
            _VALIDATION_CACHE.popitem(last=False)
        return runtime_version


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Stop the owned helper and close every inherited pipe."""

    if process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                pass


def _finalize_runtime(
    process: subprocess.Popen[bytes],
    writes: queue.Queue[_WriteFrame | None],
) -> None:
    _terminate_process(process)
    try:
        writes.put_nowait(None)
    except queue.Full:
        pass
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


class _StderrState:
    """Small shared buffer that does not retain its owning runtime."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tail = ""


class _WriteFrame:
    """One serialized write plus a bounded completion channel."""

    def __init__(self, frame: bytes) -> None:
        self.frame = frame
        self.result: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)


def _read_response_frames(stream: BinaryIO, responses: queue.Queue[bytes | BaseException]) -> None:
    try:
        while True:
            line = stream.readline(MAX_FRAME_BYTES + 1)
            if not line:
                raise EOFError("cel-go helper closed stdout")
            if len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
                raise ValueError("cel-go helper response exceeds frame limit")
            responses.put(line, timeout=0.1)
    except BaseException as exc:
        try:
            responses.put(exc, timeout=0.1)
        except queue.Full:
            pass


def _write_request_frames(stream: BinaryIO, writes: queue.Queue[_WriteFrame | None]) -> None:
    while True:
        job = writes.get()
        if job is None:
            return
        try:
            remaining = memoryview(job.frame)
            while remaining:
                written = stream.write(remaining)
                if not isinstance(written, int) or written <= 0:
                    raise BrokenPipeError("cel-go helper accepted a partial zero-length write")
                remaining = remaining[written:]
            stream.flush()
        except BaseException as exc:
            job.result.put(exc)
            return
        job.result.put(None)


def _drain_stderr(stream: BinaryIO, state: _StderrState) -> None:
    while True:
        try:
            chunk = stream.read(4096)
        except OSError:
            return
        if not chunk:
            return
        decoded = chunk.decode("utf-8", errors="replace")
        with state.lock:
            state.tail = (state.tail + decoded)[-8192:]


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


class CelGoRuntime:
    """Compile once and evaluate many through one bounded local cel-go process."""

    runtime_name = "cel-go"
    max_batch_items = MAX_BATCH_ITEMS

    def __init__(
        self,
        rules: list[CelRule],
        *,
        binary_path: str | os.PathLike[str] | None = None,
        slow_ms: float = 50.0,
        failure_limit: int = 3,
        circuit_cooldown_s: float = 30.0,
        eval_timeout_ms: int = DEFAULT_EVAL_TIMEOUT_MS,
        cost_limit: int = DEFAULT_COST_LIMIT,
        response_timeout_s: float = 0.5,
        initialize_timeout_s: float = DEFAULT_INITIALIZE_TIMEOUT_S,
    ) -> None:
        if not math.isfinite(slow_ms) or slow_ms <= 0:
            raise ValueError("CEL slow-evaluation threshold must be positive")
        if isinstance(failure_limit, bool) or not isinstance(failure_limit, int) or failure_limit <= 0:
            raise ValueError("CEL circuit-breaker failure limit must be positive")
        if not math.isfinite(circuit_cooldown_s) or circuit_cooldown_s <= 0:
            raise ValueError("CEL circuit-breaker cooldown must be positive")
        if (
            isinstance(eval_timeout_ms, bool)
            or not isinstance(eval_timeout_ms, int)
            or not 1 <= eval_timeout_ms <= MAX_EVAL_TIMEOUT_MS
        ):
            raise ValueError(f"CEL helper evaluation timeout must be between 1 and {MAX_EVAL_TIMEOUT_MS} milliseconds")
        if isinstance(cost_limit, bool) or not isinstance(cost_limit, int) or not 1 <= cost_limit <= MAX_COST_LIMIT:
            raise ValueError(f"CEL helper cost limit must be between 1 and {MAX_COST_LIMIT}")
        if not math.isfinite(response_timeout_s) or response_timeout_s <= eval_timeout_ms / 1000:
            raise ValueError("CEL helper response timeout must exceed the evaluation timeout")
        if not math.isfinite(initialize_timeout_s) or initialize_timeout_s <= response_timeout_s:
            raise ValueError("CEL helper initialization timeout must exceed the response timeout")
        if len({rule.rule_id for rule in rules}) != len(rules):
            raise ValueError("duplicate CEL rule IDs")
        if len(rules) > MAX_RULES:
            raise ValueError(f"CEL generation exceeds {MAX_RULES} rules")
        for rule in rules:
            validate_cel_expression(rule.expression)

        self.slow_ms = slow_ms
        self.failure_limit = failure_limit
        self.circuit_cooldown_s = circuit_cooldown_s
        self.response_timeout_s = response_timeout_s
        self.initialize_timeout_s = initialize_timeout_s
        self._expression_set_hash = expression_set_hash(rules)
        self._circuits = {rule.rule_id: _CircuitState() for rule in rules}
        self._io_lock = threading.Lock()
        self._responses: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=2)
        self._writes: queue.Queue[_WriteFrame | None] = queue.Queue(maxsize=1)
        self._stderr_state = _StderrState()
        self._request_id = 0
        self._closed = False
        self._owner_pid = os.getpid()

        helper = discover_cel_go_helper(binary_path)
        packaged_expectation = _packaged_helper_expectation(helper)
        is_windows = sys.platform == "win32"
        # The helper is a pure stdin/stdout evaluator.  Do not inherit
        # caller-controlled Go/debug/proxy environment or an arbitrary cwd.
        helper_environment = {"LANG": "C", "LC_ALL": "C"}
        if is_windows:
            for name in ("SYSTEMROOT", "WINDIR"):
                value = os.environ.get(name)
                if value:
                    helper_environment[name] = value
        creation_flags = 0x08000000 | 0x00000200 if is_windows else 0  # NO_WINDOW | NEW_PROCESS_GROUP
        try:
            process = subprocess.Popen(
                [str(helper)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                cwd=helper.parent,
                env=helper_environment,
                creationflags=creation_flags,
                start_new_session=not is_windows,
            )
        except OSError as exc:
            raise CelRuntimeUnavailable(f"failed to start cel-go helper {helper}: {exc}") from exc
        self._process = process
        self._finalizer = weakref.finalize(self, _finalize_runtime, process, self._writes)
        assert process.stdout is not None
        assert process.stderr is not None
        assert process.stdin is not None
        self._reader = threading.Thread(
            target=_read_response_frames,
            args=(process.stdout, self._responses),
            name="skill-scanner-cel-go-stdout",
            daemon=True,
        )
        self._writer = threading.Thread(
            target=_write_request_frames,
            args=(process.stdin, self._writes),
            name="skill-scanner-cel-go-stdin",
            daemon=True,
        )
        self._stderr_reader = threading.Thread(
            target=_drain_stderr,
            args=(process.stderr, self._stderr_state),
            name="skill-scanner-cel-go-stderr",
            daemon=True,
        )
        self._reader.start()
        self._writer.start()
        self._stderr_reader.start()
        with _FORK_RUNTIMES_LOCK:
            _FORK_RUNTIMES.add(self)

        descriptor_bytes = _descriptor_set_bytes()
        descriptor_hash = hashlib.sha256(descriptor_bytes).hexdigest()
        if descriptor_hash != SCAN_FACTS_DESCRIPTOR_HASH:
            self._shutdown_transport()
            raise CelRuntimeUnavailable("generated ScanFacts descriptor does not match the qualified cel-go schema")
        initialize = {
            "type": "initialize",
            "expression_set_hash": self._expression_set_hash,
            "descriptor_b64": base64.b64encode(descriptor_bytes).decode("ascii"),
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "expression": rule.expression,
                    "fact_schema": rule.fact_schema,
                }
                for rule in sorted(rules, key=lambda item: item.rule_id)
            ],
            "eval_timeout_ms": eval_timeout_ms,
            "cost_limit": cost_limit,
        }
        try:
            response = self._request(initialize, timeout=initialize_timeout_s)
            self._validate_initialize_response(
                response,
                rules,
                descriptor_hash,
                expected_helper_version=(
                    packaged_expectation.helper_version if packaged_expectation is not None else None
                ),
            )
        except _ProtocolFailure as exc:
            self._shutdown_transport()
            raise CelRuntimeUnavailable(
                f"cel-go helper protocol {PROTOCOL_VERSION} initialization failed ({exc.code})"
            ) from exc
        except Exception:
            self._shutdown_transport()
            raise

    @property
    def expression_set_hash(self) -> str:
        return self._expression_set_hash

    def _validate_initialize_response(
        self,
        response: dict[str, Any],
        rules: list[CelRule],
        descriptor_hash: str,
        *,
        expected_helper_version: str | None,
    ) -> None:
        if not response.get("ok"):
            code = self._error_code(response)
            message = str(response.get("message", "cel-go initialization failed"))[:2048]
            if code in {
                "CEL_COMPILE_ERROR",
                "CEL_GENERATION_NODE_LIMIT",
                "CEL_PROGRAM_ERROR",
                "CEL_SUBSET_ERROR",
                "NON_BOOLEAN_EXPRESSION",
                "RULE_INVALID",
                "EXPRESSION_HASH_MISMATCH",
            }:
                raise ValueError(message)
            raise CelRuntimeUnavailable(f"cel-go helper initialization failed ({code}): {message}")
        expected = {
            "type": "initialized",
            "runtime": self.runtime_name,
            "runtime_version": CEL_GO_VERSION,
            "expression_set_hash": self._expression_set_hash,
            "descriptor_hash": descriptor_hash,
            "rule_count": len(rules),
        }
        for field, value in expected.items():
            if response.get(field) != value:
                raise CelRuntimeUnavailable(f"cel-go helper returned invalid {field!r} during initialization")
        helper_version = response.get("helper_version")
        if not isinstance(helper_version, str) or not helper_version or len(helper_version) > 128:
            raise CelRuntimeUnavailable("cel-go helper returned an invalid build version")
        if expected_helper_version is not None and helper_version != expected_helper_version:
            raise CelRuntimeUnavailable("packaged cel-go helper build version does not match its manifest")
        self.engine_version = CEL_GO_VERSION
        self.helper_version = helper_version
        self.version = f"{CEL_GO_VERSION};helper={helper_version}"
        raw_paths = response.get("fact_access_paths")
        rule_ids = {rule.rule_id for rule in rules}
        if not isinstance(raw_paths, dict) or set(raw_paths) != rule_ids:
            raise CelRuntimeUnavailable("cel-go helper returned an invalid fact-access rule set")
        total_paths = 0
        total_bytes = 0
        validated_paths: dict[str, tuple[str, ...]] = {}
        for rule_id in sorted(rule_ids):
            values = raw_paths.get(rule_id)
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise CelRuntimeUnavailable("cel-go helper returned invalid fact-access paths")
            if values != sorted(set(values)):
                raise CelRuntimeUnavailable("cel-go helper returned non-canonical fact-access paths")
            for value in values:
                encoded_length = len(value.encode("utf-8"))
                if (
                    not value
                    or encoded_length > MAX_FACT_ACCESS_PATH_BYTES
                    or _FACT_ACCESS_PATH_RE.fullmatch(value) is None
                ):
                    raise CelRuntimeUnavailable("cel-go helper returned an invalid fact-access path")
                total_bytes += encoded_length
            total_paths += len(values)
            validated_paths[rule_id] = tuple(values)
        if total_paths > MAX_FACT_ACCESS_PATHS or total_bytes > MAX_TOTAL_FACT_ACCESS_BYTES:
            raise CelRuntimeUnavailable("cel-go helper returned oversized fact-access metadata")
        self.fact_access_paths = MappingProxyType(validated_paths)

    def evaluate(self, rule_id: str, facts: scan_facts_pb2.ScanFacts) -> RuntimeEvaluation:
        state = self._circuits.get(rule_id)
        if state is None:
            return RuntimeEvaluation(None, 0.0, "UNKNOWN_RULE_ID")
        with state.lock:
            if state.open:
                if time.monotonic() < state.open_until or state.probe_in_flight:
                    return RuntimeEvaluation(None, 0.0, "CIRCUIT_OPEN")
                state.probe_in_flight = True

        started = time.perf_counter()
        try:
            if not isinstance(facts, scan_facts_pb2.ScanFacts):
                raise _ProtocolFailure("ACTIVATION_TYPE_ERROR", "activation is not ScanFacts")
            facts_bytes = facts.SerializeToString(deterministic=True)
            if len(facts_bytes) > MAX_ACTIVATION_BYTES:
                raise _ProtocolFailure("ACTIVATION_SIZE_LIMIT", "ScanFacts exceeds the activation limit")
            response = self._request(
                {
                    "type": "evaluate",
                    "rule_id": rule_id,
                    "facts_b64": base64.b64encode(facts_bytes).decode("ascii"),
                    "expression_set_hash": self._expression_set_hash,
                },
                timeout=self.response_timeout_s,
            )
            if response.get("expression_set_hash") != self._expression_set_hash:
                raise _ProtocolFailure("GENERATION_MISMATCH", "cel-go response generation mismatch")
            elapsed_ms = (time.perf_counter() - started) * 1_000
            if not response.get("ok"):
                self._record_failure(state)
                return RuntimeEvaluation(None, elapsed_ms, self._error_code(response))
            engine_ms = response.get("elapsed_ms")
            if (
                isinstance(engine_ms, bool)
                or not isinstance(engine_ms, int | float)
                or not math.isfinite(engine_ms)
                or engine_ms < 0
            ):
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go engine timing")
            value = response.get("value")
            if not isinstance(value, bool):
                self._record_failure(state)
                return RuntimeEvaluation(None, elapsed_ms, "NON_BOOLEAN_RESULT")
            if elapsed_ms > self.slow_ms:
                self._record_failure(state)
            else:
                self._record_success(state)
            return RuntimeEvaluation(value, elapsed_ms)
        except _ProtocolFailure as exc:
            elapsed_ms = (time.perf_counter() - started) * 1_000
            self._record_failure(state)
            return RuntimeEvaluation(None, elapsed_ms, exc.code)
        except Exception:
            elapsed_ms = (time.perf_counter() - started) * 1_000
            self._record_failure(state)
            return RuntimeEvaluation(None, elapsed_ms, "EVALUATION_ERROR")

    def evaluate_batch(
        self,
        evaluations: list[tuple[str, scan_facts_pb2.ScanFacts]],
    ) -> list[RuntimeEvaluation]:
        """Evaluate one bounded candidate batch through a single IPC frame.

        Results preserve input order. Transport or response corruption fails
        open every eligible item in the batch; valid helper responses retain
        per-item Boolean/error decisions and apportion IPC overhead so summed
        telemetry equals the end-to-end batch wall time.
        """

        if not evaluations:
            return []
        if len(evaluations) > self.max_batch_items:
            return [RuntimeEvaluation(None, 0.0, "BATCH_ITEM_LIMIT") for _ in evaluations]

        results: list[RuntimeEvaluation | None] = [None] * len(evaluations)
        eligible: list[tuple[int, str, str, int, _CircuitState]] = []
        for index, (rule_id, facts) in enumerate(evaluations):
            state = self._circuits.get(rule_id)
            if state is None:
                results[index] = RuntimeEvaluation(None, 0.0, "UNKNOWN_RULE_ID")
                continue
            with state.lock:
                if state.open:
                    if time.monotonic() < state.open_until or state.probe_in_flight:
                        results[index] = RuntimeEvaluation(None, 0.0, "CIRCUIT_OPEN")
                        continue
                    state.probe_in_flight = True
            untrusted_facts: object = facts
            if not isinstance(untrusted_facts, scan_facts_pb2.ScanFacts):
                self._record_failure(state)
                results[index] = RuntimeEvaluation(None, 0.0, "ACTIVATION_TYPE_ERROR")
                continue
            facts_bytes = facts.SerializeToString(deterministic=True)
            if len(facts_bytes) > MAX_ACTIVATION_BYTES:
                self._record_failure(state)
                results[index] = RuntimeEvaluation(None, 0.0, "ACTIVATION_SIZE_LIMIT")
                continue
            eligible.append(
                (
                    index,
                    rule_id,
                    base64.b64encode(facts_bytes).decode("ascii"),
                    len(facts_bytes),
                    state,
                )
            )

        if not eligible:
            return [result or RuntimeEvaluation(None, 0.0, "EVALUATION_ERROR") for result in results]

        chunks: list[list[tuple[int, str, str, int, _CircuitState]]] = []
        current: list[tuple[int, str, str, int, _CircuitState]] = []
        current_facts_bytes = 0
        empty_frame_size = self._batch_frame_size([])
        current_frame_size = empty_frame_size
        for item in eligible:
            wire_item = {"rule_id": item[1], "facts_b64": item[2]}
            item_size = len(
                json.dumps(
                    wire_item,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            )
            candidate_frame_size = current_frame_size + item_size + (1 if current else 0)
            would_exceed = (
                current_facts_bytes + item[3] > MAX_BATCH_FACT_BYTES or candidate_frame_size > MAX_FRAME_BYTES
            )
            if current and would_exceed:
                chunks.append(current)
                current = []
                current_facts_bytes = 0
                current_frame_size = empty_frame_size
                candidate_frame_size = current_frame_size + item_size
            if candidate_frame_size > MAX_FRAME_BYTES:
                for index, _rule_id, _facts_b64, _facts_size, state in eligible:
                    self._record_failure(state)
                    results[index] = RuntimeEvaluation(None, 0.0, "ACTIVATION_BATCH_SIZE_LIMIT")
                return [result or RuntimeEvaluation(None, 0.0, "EVALUATION_ERROR") for result in results]
            current.append(item)
            current_facts_bytes += item[3]
            current_frame_size = candidate_frame_size
        if current:
            chunks.append(current)

        started = time.perf_counter()
        try:
            completed: list[tuple[tuple[int, str, str, int, _CircuitState], dict[str, Any], float]] = []
            for chunk in chunks:
                chunk_started = time.perf_counter()
                batch_response = self._request(
                    {
                        "type": "evaluate_batch",
                        "expression_set_hash": self._expression_set_hash,
                        "items": [
                            {"rule_id": rule_id, "facts_b64": facts_b64}
                            for _index, rule_id, facts_b64, _facts_size, _state in chunk
                        ],
                    },
                    timeout=self.response_timeout_s,
                )
                chunk_elapsed_ms = (time.perf_counter() - chunk_started) * 1_000
                if batch_response.get("expression_set_hash") != self._expression_set_hash:
                    raise _ProtocolFailure("GENERATION_MISMATCH", "cel-go response generation mismatch")
                if not batch_response.get("ok"):
                    raise _ProtocolFailure(self._error_code(batch_response), "cel-go batch evaluation failed")
                raw_results = batch_response.get("results")
                if not isinstance(raw_results, list) or len(raw_results) != len(chunk):
                    raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go batch result cardinality mismatch")
                engine_total = sum(float(raw["elapsed_ms"]) for raw in raw_results)
                transport_share = max(0.0, chunk_elapsed_ms - engine_total) / len(chunk)
                completed.extend(
                    (batch_item, raw, float(raw["elapsed_ms"]) + transport_share)
                    for batch_item, raw in zip(chunk, raw_results, strict=True)
                )

            for (index, _rule_id, _facts_b64, _facts_size, state), batch_result, item_elapsed in completed:
                if batch_result["ok"]:
                    value = batch_result["value"]
                    if item_elapsed > self.slow_ms:
                        self._record_failure(state)
                    else:
                        self._record_success(state)
                    results[index] = RuntimeEvaluation(value, item_elapsed)
                else:
                    self._record_failure(state)
                    results[index] = RuntimeEvaluation(None, item_elapsed, self._error_code(batch_result))
        except _ProtocolFailure as exc:
            elapsed_each = (time.perf_counter() - started) * 1_000 / len(eligible)
            for index, _rule_id, _facts_b64, _facts_size, state in eligible:
                self._record_failure(state)
                results[index] = RuntimeEvaluation(None, elapsed_each, exc.code)
        except Exception:
            elapsed_each = (time.perf_counter() - started) * 1_000 / len(eligible)
            for index, _rule_id, _facts_b64, _facts_size, state in eligible:
                self._record_failure(state)
                results[index] = RuntimeEvaluation(None, elapsed_each, "EVALUATION_ERROR")

        return [result or RuntimeEvaluation(None, 0.0, "EVALUATION_ERROR") for result in results]

    def _batch_frame_size(self, items: list[dict[str, str]]) -> int:
        """Return a conservative exact encoded frame size for chunking."""

        frame = {
            "protocol_version": PROTOCOL_VERSION,
            # Reserve the maximum uint64 width used by the Go wire schema so
            # concurrent request sequencing cannot make the real frame larger.
            "request_id": 18_446_744_073_709_551_615,
            "type": "evaluate_batch",
            "expression_set_hash": self._expression_set_hash,
            "items": items,
        }
        return len(json.dumps(frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1

    def _request(self, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        if not self._io_lock.acquire(timeout=timeout):
            raise _ProtocolFailure("EVALUATION_TIMEOUT", "cel-go helper request queue timed out")
        try:
            if os.getpid() != self._owner_pid:
                self._invalidate_after_fork()
                raise _ProtocolFailure("RUNTIME_FORKED", "cel-go runtime cannot be reused after fork")
            if self._closed or self._process.poll() is not None:
                raise _ProtocolFailure("RUNTIME_UNAVAILABLE", self._unavailable_message())
            self._request_id += 1
            request_id = self._request_id
            frame = {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                **payload,
            }
            encoded = json.dumps(frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(encoded) + 1 > MAX_FRAME_BYTES:
                raise _ProtocolFailure("PROTOCOL_FRAME_LIMIT", "cel-go request exceeds frame limit")
            write = _WriteFrame(encoded + b"\n")
            try:
                self._writes.put(write, timeout=self._remaining(deadline))
                write_result = write.result.get(timeout=self._remaining(deadline))
            except queue.Full as exc:
                self._abort_process()
                raise _ProtocolFailure("EVALUATION_TIMEOUT", "cel-go helper write queue timed out") from exc
            except queue.Empty as exc:
                self._abort_process()
                raise _ProtocolFailure("EVALUATION_TIMEOUT", "cel-go helper write timed out") from exc
            if isinstance(write_result, BaseException):
                self._abort_process()
                raise _ProtocolFailure("RUNTIME_UNAVAILABLE", self._unavailable_message()) from write_result
            try:
                item = self._responses.get(timeout=self._remaining(deadline))
            except queue.Empty as exc:
                self._abort_process()
                raise _ProtocolFailure("EVALUATION_TIMEOUT", "cel-go helper response timed out") from exc
            if isinstance(item, BaseException):
                self._abort_process()
                raise _ProtocolFailure("RUNTIME_UNAVAILABLE", self._unavailable_message()) from item
            try:
                response = json.loads(item, object_pairs_hook=_strict_json_object)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                self._abort_process()
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid JSON response from cel-go helper") from exc
            if not isinstance(response, dict):
                self._abort_process()
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go response type")
            unknown_fields = set(response).difference(_RESPONSE_FIELDS)
            if unknown_fields:
                self._abort_process()
                raise _ProtocolFailure("PROTOCOL_ERROR", "unknown field in cel-go response")
            expected_type = {
                "initialize": "initialized",
                "evaluate": "evaluation",
                "evaluate_batch": "batch_evaluation",
                "shutdown": "shutdown",
            }.get(str(payload.get("type")))
            if expected_type is None:
                self._abort_process()
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go request type")
            try:
                self._validate_response_schema(response, expected_type, request_id)
            except _ProtocolFailure:
                self._abort_process()
                raise
            return response
        finally:
            self._io_lock.release()

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise queue.Empty
        return remaining

    @staticmethod
    def _validate_response_schema(response: dict[str, Any], expected_type: str, request_id: int) -> None:
        """Reject type-confused or contradictory helper responses."""

        protocol = response.get("protocol_version")
        identity = response.get("request_id")
        if (
            isinstance(protocol, bool)
            or not isinstance(protocol, int)
            or protocol != PROTOCOL_VERSION
            or isinstance(identity, bool)
            or not isinstance(identity, int)
            or identity != request_id
        ):
            raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response identity mismatch")
        if response.get("type") != expected_type or not isinstance(response.get("type"), str):
            raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response type mismatch")
        ok = response.get("ok")
        if not isinstance(ok, bool):
            raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response ok field must be Boolean")

        common = {"protocol_version", "type", "request_id", "ok"}
        if expected_type == "initialized":
            operation_fields = (
                {
                    "runtime",
                    "runtime_version",
                    "helper_version",
                    "expression_set_hash",
                    "descriptor_hash",
                    "rule_count",
                    "fact_access_paths",
                }
                if ok
                else {"error_code", "message"}
            )
        elif expected_type == "evaluation":
            operation_fields = (
                {"value", "elapsed_ms", "actual_cost", "expression_set_hash"}
                if ok
                else {"error_code", "message", "elapsed_ms", "actual_cost", "expression_set_hash"}
            )
        elif expected_type == "batch_evaluation":
            operation_fields = (
                {"results", "elapsed_ms", "expression_set_hash"}
                if ok
                else {"error_code", "message", "elapsed_ms", "expression_set_hash"}
            )
        else:
            operation_fields = set() if ok else {"error_code", "message"}
        allowed = common | operation_fields
        if not set(response).issubset(allowed):
            raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response has missing or contradictory fields")

        required = set(common)
        if not ok:
            required.update({"error_code", "message"})
            if expected_type in {"evaluation", "batch_evaluation"}:
                required.add("expression_set_hash")
        elif expected_type == "initialized":
            required.update(operation_fields)
        elif expected_type == "evaluation":
            required.update({"value", "elapsed_ms", "expression_set_hash"})
        elif expected_type == "batch_evaluation":
            required.update({"results", "elapsed_ms", "expression_set_hash"})
        if not required.issubset(response):
            raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response is missing required fields")

        if ok and expected_type == "initialized":
            for field in ("runtime", "runtime_version", "helper_version", "expression_set_hash", "descriptor_hash"):
                if not isinstance(response.get(field), str):
                    raise _ProtocolFailure("PROTOCOL_ERROR", f"cel-go response {field} must be a string")
            rule_count = response.get("rule_count")
            if isinstance(rule_count, bool) or not isinstance(rule_count, int) or rule_count < 0:
                raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response rule_count must be an integer")
            if not isinstance(response.get("fact_access_paths"), dict):
                raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go response fact_access_paths must be an object")
        elif ok and expected_type == "evaluation":
            if not isinstance(response.get("value"), bool):
                raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go evaluation value must be Boolean")
        elif ok and expected_type == "batch_evaluation":
            CelGoRuntime._validate_batch_results(response.get("results"))

        if expected_type in {"evaluation", "batch_evaluation"}:
            expression_hash = response.get("expression_set_hash")
            if not isinstance(expression_hash, str) or _SHA256_RE.fullmatch(expression_hash) is None:
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid evaluation generation hash")
            elapsed = response.get("elapsed_ms")
            if elapsed is not None and (
                isinstance(elapsed, bool)
                or not isinstance(elapsed, int | float)
                or not math.isfinite(elapsed)
                or elapsed < 0
            ):
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go evaluation timing")
            actual_cost = response.get("actual_cost")
            if actual_cost is not None and (
                isinstance(actual_cost, bool) or not isinstance(actual_cost, int) or actual_cost < 0
            ):
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go evaluation cost")

        if not ok:
            if not isinstance(response.get("error_code"), str) or not isinstance(response.get("message"), str):
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go error response")

    @staticmethod
    def _validate_batch_results(raw_results: object) -> None:
        if not isinstance(raw_results, list) or not 1 <= len(raw_results) <= MAX_BATCH_ITEMS:
            raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go batch results")
        for item in raw_results:
            if not isinstance(item, dict) or not isinstance(item.get("ok"), bool):
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go batch result item")
            ok = item["ok"]
            required = {"ok", "elapsed_ms", "actual_cost", "value" if ok else "error_code"}
            if set(item) != required:
                raise _ProtocolFailure("PROTOCOL_ERROR", "contradictory cel-go batch result item")
            elapsed = item.get("elapsed_ms")
            actual_cost = item.get("actual_cost")
            if (
                isinstance(elapsed, bool)
                or not isinstance(elapsed, int | float)
                or not math.isfinite(elapsed)
                or elapsed < 0
                or isinstance(actual_cost, bool)
                or not isinstance(actual_cost, int)
                or actual_cost < 0
            ):
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go batch result metrics")
            if ok:
                if not isinstance(item.get("value"), bool):
                    raise _ProtocolFailure("PROTOCOL_ERROR", "cel-go batch value must be Boolean")
            elif not isinstance(item.get("error_code"), str) or CelGoRuntime._error_code(item) == "PROTOCOL_ERROR":
                raise _ProtocolFailure("PROTOCOL_ERROR", "invalid cel-go batch error code")

    def _unavailable_message(self) -> str:
        with self._stderr_state.lock:
            detail = self._stderr_state.tail.strip()
        return "cel-go helper is unavailable" + (f": {detail}" if detail else "")

    def _abort_process(self) -> None:
        self._shutdown_transport()

    def _shutdown_transport(self) -> None:
        """Idempotently stop the process and release all transport threads."""

        self._closed = True
        with _FORK_RUNTIMES_LOCK:
            _FORK_RUNTIMES.discard(self)
        self._finalizer()
        try:
            self._writes.put_nowait(None)
        except queue.Full:
            pass
        current = threading.current_thread()
        for thread in (self._writer, self._reader, self._stderr_reader):
            if thread is not current and thread.is_alive():
                thread.join(timeout=0.5)

    def _invalidate_after_fork(self) -> None:
        """Detach the child's inherited handles without killing the parent helper."""

        self._closed = True
        self._finalizer.detach()
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    @staticmethod
    def _error_code(response: dict[str, Any]) -> str:
        code = response.get("error_code")
        if (
            not isinstance(code, str)
            or len(code.encode("utf-8")) > _MAX_ERROR_CODE_BYTES
            or _ERROR_CODE_RE.fullmatch(code) is None
            or code not in _KNOWN_HELPER_ERROR_CODES
        ):
            return "PROTOCOL_ERROR"
        return code

    def close(self) -> None:
        if self._closed:
            return
        if os.getpid() != self._owner_pid:
            self._invalidate_after_fork()
            return
        try:
            self._request({"type": "shutdown"}, timeout=0.5)
        except Exception:
            pass
        finally:
            self._shutdown_transport()

    def __enter__(self) -> CelGoRuntime:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def _record_failure(self, state: _CircuitState) -> None:
        with state.lock:
            state.consecutive_failures += 1
            if state.consecutive_failures >= self.failure_limit:
                state.open = True
                state.open_until = time.monotonic() + self.circuit_cooldown_s
            state.probe_in_flight = False

    @staticmethod
    def _record_success(state: _CircuitState) -> None:
        with state.lock:
            state.consecutive_failures = 0
            state.open = False
            state.open_until = 0.0
            state.probe_in_flight = False
