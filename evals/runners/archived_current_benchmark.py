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

"""Isolated, provenance-locked archived-versus-current benchmark orchestration.

This module deliberately does not implement benchmark metrics.  Each worker
uses :class:`evals.runners.benchmark_runner.SkillBenchmarkRunner`, so the
committed golden-corpus runner remains the sole implementation of finding and
package metrics.  This layer supplies the controls that an old-versus-current
claim additionally needs:

* two explicit and distinct Python environments;
* caller-reviewed provenance locks for both scanner builds;
* five fresh worker processes per build, executed as counterbalanced pairs;
* a minimal environment, isolated HOME/cache directories, and Python socket
  denial before scanner code is imported;
* process-group containment and a hard worker timeout;
* pre/post hashes for the corpus, scanner package, resolved rules, CEL helper,
  and this harness; and
* a complete, timing-free semantic output fingerprint.

The worker and probe modes are implementation details of the driver.  They are
kept in this stdlib-only module so an archived environment does not need the
current project installed; it only needs its own ``skill_scanner`` build.  The
current repository is appended to ``sys.path`` *after* that build is imported,
which exposes the shared evaluation runner without shadowing the target build.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PAIR_COUNT = 5
_SHA256_HEX = frozenset("0123456789abcdef")
_BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_SEMANTIC_TIMING_KEYS = frozenset(
    {
        "elapsed_ms",
        "evaluation_ms",
        "projection_ms",
        "reported_scan_duration_ms",
        "scan_duration_ms",
        "scan_duration_seconds",
        "skills_per_second",
        "p50_scan_latency_ms",
        "p95_scan_latency_ms",
        "cel_time_ratio",
        "cel_elapsed_ms",
        "total_scan_ms",
        "total_cel_ms",
    }
)
_LOCK_FIELDS = frozenset(
    {
        "schema_version",
        "source_revision",
        "source_sha256",
        "evaluator_sha256",
        "rules_sha256",
        "policy_sha256",
        "helper_sha256",
        "environment_sha256",
        "python_version",
        "config",
        "packs",
        "cel_mode",
        "analyzer_classes",
    }
)
_ALLOWED_CONFIGS = frozenset({"static", "core", "full", "core-correlation", "full-correlation"})
_ALLOWED_CEL_MODES = frozenset({"off", "shadow", "enforce"})
_HOST_SYSTEM_ENV_KEYS = (
    "COMSPEC",
    "PATHEXT",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "WINDIR",
)

# Installed before runpy loads this module in a worker process.  The audit hook
# catches CPython socket events, while method replacement gives a clear error
# before common clients reach the operating system.  Native code outside the
# Python audit surface remains out of scope, so workers also build an explicit
# deterministic-analyzer allowlist below.
_NETWORK_GUARD_SOURCE = r"""
import socket as _benchmark_socket
import sys as _benchmark_sys

def _benchmark_network_denied(*_args, **_kwargs):
    raise PermissionError("network access is disabled in the archived/current benchmark worker")

for _name in ("accept", "bind", "connect", "connect_ex", "listen", "sendmsg", "sendto"):
    if hasattr(_benchmark_socket.socket, _name):
        setattr(_benchmark_socket.socket, _name, _benchmark_network_denied)
for _name in ("create_connection", "getaddrinfo", "gethostbyaddr", "gethostbyname", "gethostbyname_ex"):
    if hasattr(_benchmark_socket, _name):
        setattr(_benchmark_socket, _name, _benchmark_network_denied)

_DENIED_SOCKET_AUDIT_EVENTS = {
    "socket.bind",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.gethostbyaddr",
    "socket.gethostbyname",
    "socket.sendto",
}

def _benchmark_socket_audit(event, _args):
    if event in _DENIED_SOCKET_AUDIT_EVENTS:
        raise PermissionError("network access is disabled in the archived/current benchmark worker")

_benchmark_sys.addaudithook(_benchmark_socket_audit)
"""

_WORKER_BOOTSTRAP = (
    _NETWORK_GUARD_SOURCE
    + r"""
import runpy as _benchmark_runpy

_benchmark_script = _benchmark_sys.argv[1]
_benchmark_sys.argv = [_benchmark_script, *_benchmark_sys.argv[2:]]
_benchmark_runpy.run_path(_benchmark_script, run_name="__main__")
"""
)


class ArchivedCurrentBenchmarkError(RuntimeError):
    """Raised when evidence cannot support a trustworthy comparison."""


@dataclass(frozen=True)
class ArmLock:
    """Caller-reviewed identity for one scanner arm."""

    schema_version: int
    source_revision: str
    source_sha256: str
    evaluator_sha256: str
    rules_sha256: str
    policy_sha256: str
    helper_sha256: str | None
    environment_sha256: str
    python_version: str
    config: str
    packs: tuple[str, ...]
    cel_mode: str
    analyzer_classes: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["packs"] = list(self.packs)
        value["analyzer_classes"] = list(self.analyzer_classes)
        return value


@dataclass(frozen=True)
class ArmSpec:
    """Execution inputs for one arm."""

    name: str
    python: Path
    lock: ArmLock
    helper: Path | None


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _SHA256_HEX


def _require_sha256(value: Any, location: str) -> str:
    if not _valid_sha256(value):
        raise ArchivedCurrentBenchmarkError(f"{location} must be a lowercase SHA-256")
    return str(value)


def _strict_json(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ArchivedCurrentBenchmarkError(f"JSON input must be a regular non-symlink file: {path}")

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ArchivedCurrentBenchmarkError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicate)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchivedCurrentBenchmarkError(f"cannot read strict JSON {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ArchivedCurrentBenchmarkError(f"JSON root must be an object: {path}")
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _tree_manifest(root: Path, *, ignore_runtime_artifacts: bool) -> list[tuple[str, bytes]]:
    """Return a framed regular-file inventory and reject every symbolic link."""

    if root.is_symlink() or not root.is_dir():
        raise ArchivedCurrentBenchmarkError(f"tree root must be a regular non-symlink directory: {root}")
    members: list[tuple[str, bytes]] = []
    for current_name, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_name)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            member = current / name
            mode = member.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ArchivedCurrentBenchmarkError(f"tree contains symbolic link: {member}")
            if not stat.S_ISDIR(mode):
                raise ArchivedCurrentBenchmarkError(f"tree contains non-directory entry: {member}")
            if ignore_runtime_artifacts and name == "__pycache__":
                continue
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(file_names):
            member = current / name
            mode = member.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ArchivedCurrentBenchmarkError(f"tree contains symbolic link: {member}")
            if not stat.S_ISREG(mode):
                raise ArchivedCurrentBenchmarkError(f"tree contains non-regular file: {member}")
            if ignore_runtime_artifacts and member.suffix in {".pyc", ".pyo"}:
                continue
            members.append((member.relative_to(root).as_posix(), member.read_bytes()))
    members.sort(key=lambda item: item[0])
    return members


def _hash_tree(root: Path, *, namespace: bytes, ignore_runtime_artifacts: bool = True) -> str:
    digest = hashlib.sha256(namespace + b"\0")
    for relative, content in _tree_manifest(root, ignore_runtime_artifacts=ignore_runtime_artifacts):
        relative_bytes = relative.encode("utf-8")
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _hash_named_trees(roots: Sequence[tuple[str, Path]]) -> str:
    digest = hashlib.sha256(b"skill-scanner-resolved-rule-packs-v1\0")
    seen: set[str] = set()
    for label, root in roots:
        if label in seen:
            raise ArchivedCurrentBenchmarkError(f"duplicate resolved rule-pack label: {label}")
        seen.add(label)
        label_bytes = label.encode("utf-8")
        tree_hash = _hash_tree(root, namespace=b"skill-scanner-selected-rule-pack-v1")
        digest.update(len(label_bytes).to_bytes(8, "big"))
        digest.update(label_bytes)
        digest.update(bytes.fromhex(tree_hash))
    return digest.hexdigest()


def _environment_identity() -> tuple[str, list[dict[str, str]]]:
    """Bind the isolated interpreter to installed distribution metadata."""

    distributions: list[dict[str, str]] = []
    for distribution in importlib.metadata.distributions():
        name = str(distribution.metadata["Name"] or "").strip().lower()
        if not name:
            continue
        direct_url = distribution.read_text("direct_url.json") or ""
        record = distribution.read_text("RECORD") or ""
        distributions.append(
            {
                "name": name,
                "version": str(distribution.version),
                "direct_url_sha256": hashlib.sha256(direct_url.encode("utf-8")).hexdigest(),
                "record_sha256": hashlib.sha256(record.encode("utf-8")).hexdigest(),
            }
        )
    distributions.sort(key=lambda item: (item["name"], item["version"], item["direct_url_sha256"]))
    identity = {
        "implementation": sys.implementation.name,
        "python_version": sys.version.split()[0],
        "python_executable_sha256": _sha256_file(Path(sys.executable).resolve()),
        "prefix": str(Path(sys.prefix).resolve()),
        "base_prefix": str(Path(sys.base_prefix).resolve()),
        "distributions": distributions,
    }
    return hashlib.sha256(
        b"skill-scanner-benchmark-environment-v1\0" + _json_bytes(identity)
    ).hexdigest(), distributions


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _semantic_value(value: Any) -> Any:
    """Canonicalize arbitrary scanner metadata while removing only timings."""

    value = _enum_value(value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return str(value)
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _semantic_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in _SEMANTIC_TIMING_KEYS
            and not str(key).endswith("_duration_ms")
            and not str(key).endswith("_latency_ms")
        }
    if isinstance(value, (list, tuple)):
        return [_semantic_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_semantic_value(item) for item in value), key=lambda item: _json_bytes(item))
    return str(value)


def _normalize_finding_path(raw: Any, package: Path) -> str:
    if raw is None:
        return ""
    value = str(raw).replace("\\", "/")
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(package.resolve()).as_posix()
        except (OSError, ValueError) as exc:
            raise ArchivedCurrentBenchmarkError(f"finding path escapes scanned package: {candidate}") from exc
    while value.startswith("./"):
        value = value[2:]
    package_prefix = f"{package.name}/"
    return value[len(package_prefix) :] if value.startswith(package_prefix) else value


def _finding_semantics(finding: Any, package: Path) -> dict[str, Any]:
    serializer = getattr(finding, "to_dict", None)
    serialized = serializer() if callable(serializer) else None
    if not isinstance(serialized, Mapping):
        serialized = {
            field: getattr(finding, field, None)
            for field in (
                "id",
                "rule_id",
                "category",
                "severity",
                "title",
                "description",
                "file_path",
                "line_number",
                "snippet",
                "remediation",
                "analyzer",
                "metadata",
            )
        }
    result = dict(_semantic_value(serialized))
    result["id"] = str(getattr(finding, "id", result.get("id", "")))
    result["rule_id"] = str(getattr(finding, "rule_id", result.get("rule_id", "")))
    result["category"] = str(_enum_value(getattr(finding, "category", result.get("category", ""))))
    result["severity"] = str(_enum_value(getattr(finding, "severity", result.get("severity", "")))).upper()
    result["file_path"] = _normalize_finding_path(getattr(finding, "file_path", result.get("file_path")), package)
    line_number = getattr(finding, "line_number", result.get("line_number"))
    result["line_number"] = line_number if isinstance(line_number, int) and not isinstance(line_number, bool) else None
    result["analyzer"] = str(getattr(finding, "analyzer", result.get("analyzer", "")) or "")
    return result


def _scan_semantics(result: Any, package: Path) -> dict[str, Any]:
    findings = [_finding_semantics(finding, package) for finding in list(getattr(result, "findings", []) or [])]
    findings.sort(key=_json_bytes)
    metadata = getattr(result, "scan_metadata", {})
    metadata = metadata if isinstance(metadata, Mapping) else {}
    maximum_severity = getattr(result, "max_severity", "")
    return {
        "skill_name": str(getattr(result, "skill_name", "")),
        "is_safe": bool(getattr(result, "is_safe", False)),
        "max_severity": str(_enum_value(maximum_severity)).upper(),
        "findings": findings,
        "analyzers_used": sorted(str(value) for value in list(getattr(result, "analyzers_used", []) or [])),
        "analyzers_failed": _semantic_value(list(getattr(result, "analyzers_failed", []) or [])),
        "analyzability_score": _semantic_value(getattr(result, "analyzability_score", None)),
        "analyzability_details": _semantic_value(getattr(result, "analyzability_details", None)),
        "llm_usage": _semantic_value(getattr(result, "llm_usage", None)),
        "scan_metadata": _semantic_value(metadata),
        "cel": _semantic_value(metadata.get("cel", {})),
    }


class _CapturingScanner:
    def __init__(self, scanner: Any, eval_root: Path):
        self._scanner = scanner
        self._eval_root = eval_root.resolve()
        self.captures: dict[str, dict[str, Any]] = {}

    def scan_skill(self, package: Path, *args: Any, **kwargs: Any) -> Any:
        result = self._scanner.scan_skill(package, *args, **kwargs)
        resolved = Path(package).resolve()
        try:
            package_id = resolved.relative_to(self._eval_root).as_posix()
        except ValueError as exc:
            raise ArchivedCurrentBenchmarkError(f"scanner received package outside corpus: {resolved}") from exc
        if package_id in self.captures:
            raise ArchivedCurrentBenchmarkError(f"duplicate package scan: {package_id}")
        self.captures[package_id] = _scan_semantics(result, resolved)
        return result

    def close(self) -> None:
        close = getattr(self._scanner, "close", None)
        if callable(close):
            close()


def _load_target_package(repository_root: Path) -> tuple[Any, Path]:
    """Import the target build before exposing the current evaluation package."""

    import skill_scanner

    package_root = Path(skill_scanner.__file__).resolve().parent
    repository = repository_root.resolve()
    if str(repository) not in sys.path:
        # ``skill_scanner`` is already cached with the target environment's
        # package path, so prioritizing the repository here cannot replace it.
        # It does ensure the durable current evaluation runner wins over an
        # unrelated ``evals`` package that might exist in site-packages.
        sys.path.insert(0, str(repository))
    return skill_scanner, package_root


def _evaluator_path(repository_root: Path) -> Path:
    candidate = repository_root / "evals" / "runners" / "benchmark_runner.py"
    if candidate.is_symlink() or not candidate.is_file():
        raise ArchivedCurrentBenchmarkError(
            f"committed benchmark runner must be a regular non-symlink file: {candidate}"
        )
    return candidate.resolve()


def _build_scanner(config: str, packs: Sequence[str], cel_mode: str) -> tuple[Any, Any, list[str], str]:
    from skill_scanner.core.analyzer_factory import build_core_analyzers
    from skill_scanner.core.scan_policy import ScanPolicy
    from skill_scanner.core.scanner import SkillScanner
    from skill_scanner.data import DATA_DIR, resolve_rule_packs

    if config not in _ALLOWED_CONFIGS:
        raise ArchivedCurrentBenchmarkError(f"unsupported config: {config}")
    if cel_mode not in _ALLOWED_CEL_MODES:
        raise ArchivedCurrentBenchmarkError(f"unsupported CEL mode: {cel_mode}")
    if config in {"static", "core", "core-correlation"} and packs:
        raise ArchivedCurrentBenchmarkError(f"config {config!r} does not accept additional packs")
    if config.startswith("full") and not packs:
        raise ArchivedCurrentBenchmarkError("full config requires an explicit non-empty pack list")

    policy = ScanPolicy.default()
    policy.analyzers.static = True
    policy.analyzers.bytecode = config != "static"
    policy.analyzers.pipeline = config != "static"
    correlation = config.endswith("-correlation")
    if correlation and not hasattr(policy.analyzers, "correlation"):
        raise ArchivedCurrentBenchmarkError("target scanner does not support the requested correlation analyzer")
    if hasattr(policy.analyzers, "correlation"):
        policy.analyzers.correlation = correlation
    if hasattr(policy, "cel"):
        policy.cel.mode = type(policy.cel.mode)(cel_mode)
    elif cel_mode != "off":
        raise ArchivedCurrentBenchmarkError("target scanner does not support active CEL mode")

    extra_rules = resolve_rule_packs(list(packs)) if packs else None
    analyzers = build_core_analyzers(policy, extra_rules_dirs=extra_rules)
    analyzer_classes = sorted(f"{type(analyzer).__module__}.{type(analyzer).__qualname__}" for analyzer in analyzers)
    allowed_names = {"StaticAnalyzer"}
    if config != "static":
        allowed_names.update({"BytecodeAnalyzer", "PipelineAnalyzer"})
    if correlation:
        allowed_names.add("CorrelationAnalyzer")
    observed_names = {type(analyzer).__name__ for analyzer in analyzers}
    if observed_names != allowed_names:
        raise ArchivedCurrentBenchmarkError(
            f"deterministic analyzer allowlist mismatch: observed={sorted(observed_names)}, expected={sorted(allowed_names)}"
        )

    core_root = Path(DATA_DIR) / "packs" / "core"
    resolved_roots: list[tuple[str, Path]] = [("core", core_root)]
    for name, signatures in zip(packs, extra_rules or [], strict=True):
        signatures = Path(signatures).resolve()
        pack_root = signatures.parent
        expected_root = (Path(DATA_DIR) / "packs" / name).resolve()
        if pack_root != expected_root or signatures != expected_root / "signatures":
            raise ArchivedCurrentBenchmarkError(f"resolved pack {name!r} escaped the installed bundled-pack root")
        resolved_roots.append((name, pack_root))
    rules_sha256 = _hash_named_trees(resolved_roots)
    scanner = SkillScanner(analyzers=analyzers, policy=policy)
    return scanner, policy, analyzer_classes, rules_sha256


def _provenance(
    *,
    repository_root: Path,
    source_revision: str,
    config: str,
    packs: Sequence[str],
    cel_mode: str,
    helper: Path | None,
) -> tuple[dict[str, Any], Any]:
    if (cel_mode == "off") != (helper is None):
        raise ArchivedCurrentBenchmarkError(
            "CEL-off arms must omit a helper and active CEL arms must supply an explicit helper"
        )
    _, package_root = _load_target_package(repository_root)
    evaluator_path = _evaluator_path(repository_root)
    scanner, policy, analyzer_classes, rules_sha256 = _build_scanner(config, packs, cel_mode)
    environment_sha256, distributions = _environment_identity()
    helper_sha256 = _sha256_file(helper) if helper is not None else None
    policy_payload = json.dumps(policy._to_dict(), sort_keys=True, separators=(",", ":"))
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "source_revision": source_revision,
        "source_sha256": _hash_tree(package_root, namespace=b"skill-scanner-installed-source-v1"),
        "evaluator_sha256": _sha256_file(evaluator_path),
        "rules_sha256": rules_sha256,
        "policy_sha256": hashlib.sha256(policy_payload.encode("utf-8")).hexdigest(),
        "helper_sha256": helper_sha256,
        "environment_sha256": environment_sha256,
        "python_version": sys.version.split()[0],
        "config": config,
        "packs": list(packs),
        "cel_mode": cel_mode,
        "analyzer_classes": analyzer_classes,
        "package_root": str(package_root),
        "python_executable": sys.executable,
        "python_prefix": str(Path(sys.prefix).resolve()),
        "python_base_prefix": str(Path(sys.base_prefix).resolve()),
        "distributions": distributions,
    }
    return provenance, scanner


def _arm_lock_from_mapping(value: Mapping[str, Any], location: str) -> ArmLock:
    if set(value) != _LOCK_FIELDS:
        missing = sorted(_LOCK_FIELDS - set(value))
        unexpected = sorted(set(value) - _LOCK_FIELDS)
        raise ArchivedCurrentBenchmarkError(f"{location} fields mismatch (missing={missing}, unexpected={unexpected})")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ArchivedCurrentBenchmarkError(f"{location}.schema_version must be {SCHEMA_VERSION}")
    source_revision = value.get("source_revision")
    python_version = value.get("python_version")
    config = value.get("config")
    cel_mode = value.get("cel_mode")
    if not isinstance(source_revision, str) or not source_revision or source_revision == "unrecorded":
        raise ArchivedCurrentBenchmarkError(f"{location}.source_revision must be an explicit revision")
    if not isinstance(python_version, str) or not python_version:
        raise ArchivedCurrentBenchmarkError(f"{location}.python_version must be non-empty")
    if config not in _ALLOWED_CONFIGS:
        raise ArchivedCurrentBenchmarkError(f"{location}.config is unsupported")
    if cel_mode not in _ALLOWED_CEL_MODES:
        raise ArchivedCurrentBenchmarkError(f"{location}.cel_mode is unsupported")
    packs = value.get("packs")
    analyzers = value.get("analyzer_classes")
    if (
        isinstance(packs, (str, bytes))
        or not isinstance(packs, Sequence)
        or any(not isinstance(item, str) or not item for item in packs)
        or len(set(packs)) != len(packs)
    ):
        raise ArchivedCurrentBenchmarkError(f"{location}.packs must contain unique non-empty names")
    if (
        isinstance(analyzers, (str, bytes))
        or not isinstance(analyzers, Sequence)
        or any(not isinstance(item, str) or not item for item in analyzers)
        or len(set(analyzers)) != len(analyzers)
    ):
        raise ArchivedCurrentBenchmarkError(f"{location}.analyzer_classes must contain unique names")
    helper_value = value.get("helper_sha256")
    if helper_value is not None:
        helper_value = _require_sha256(helper_value, f"{location}.helper_sha256")
    if (cel_mode == "off") != (helper_value is None):
        raise ArchivedCurrentBenchmarkError(
            f"{location} must omit helper_sha256 for CEL off and require it for active CEL"
        )
    return ArmLock(
        schema_version=SCHEMA_VERSION,
        source_revision=source_revision,
        source_sha256=_require_sha256(value.get("source_sha256"), f"{location}.source_sha256"),
        evaluator_sha256=_require_sha256(value.get("evaluator_sha256"), f"{location}.evaluator_sha256"),
        rules_sha256=_require_sha256(value.get("rules_sha256"), f"{location}.rules_sha256"),
        policy_sha256=_require_sha256(value.get("policy_sha256"), f"{location}.policy_sha256"),
        helper_sha256=helper_value,
        environment_sha256=_require_sha256(value.get("environment_sha256"), f"{location}.environment_sha256"),
        python_version=python_version,
        config=config,
        packs=tuple(packs),
        cel_mode=cel_mode,
        analyzer_classes=tuple(analyzers),
    )


def _load_arm_lock(path: Path, location: str) -> ArmLock:
    return _arm_lock_from_mapping(_strict_json(path), location)


def _lock_projection(provenance: Mapping[str, Any]) -> dict[str, Any]:
    return {field: provenance.get(field) for field in sorted(_LOCK_FIELDS)}


def _validate_provenance(lock: ArmLock, provenance: Mapping[str, Any], location: str) -> None:
    expected = lock.to_json()
    actual = _lock_projection(provenance)
    if actual != expected:
        changed = sorted(field for field in expected if expected[field] != actual.get(field))
        raise ArchivedCurrentBenchmarkError(f"{location} provenance differs from reviewed lock: {changed}")


def _semantic_report_fingerprint(report: Mapping[str, Any]) -> str:
    """Hash all non-timing benchmark, finding, analyzer, and CEL semantics."""

    normalized = {
        "benchmark": _semantic_value(report.get("benchmark", {})),
        "individual_results": _semantic_value(report.get("individual_results", [])),
        "scan_semantics": _semantic_value(report.get("scan_semantics", {})),
    }
    return hashlib.sha256(b"skill-scanner-archived-current-output-v1\0" + _json_bytes(normalized)).hexdigest()


def _cel_evidence_errors(captures: Mapping[str, Mapping[str, Any]], expected_mode: str) -> list[str]:
    errors: list[str] = []
    evaluated = 0
    generations: set[str] = set()
    runtimes: set[str] = set()
    runtime_versions: set[str] = set()
    fact_schemas: set[str] = set()
    for package_id, capture in captures.items():
        cel = capture.get("cel", {})
        if not isinstance(cel, Mapping):
            errors.append(f"{package_id} has invalid CEL telemetry")
            continue
        mode = cel.get("mode")
        count = cel.get("evaluated", 0)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            errors.append(f"{package_id} has invalid CEL evaluated count")
            continue
        evaluated += count
        projection_incomplete = cel.get("projection_incomplete", 0)
        if (
            isinstance(projection_incomplete, bool)
            or not isinstance(projection_incomplete, int)
            or projection_incomplete != 0
        ):
            errors.append(f"{package_id} has incomplete CEL projection evidence")
        raw_errors = cel.get("errors", [])
        if not isinstance(raw_errors, list) or raw_errors:
            errors.append(f"{package_id} reports CEL evaluation errors")
        if expected_mode == "off":
            if mode not in {None, "", "off"}:
                errors.append(f"{package_id} reported CEL mode {mode!r} while off")
            for field in ("evaluated", "would_suppress", "suppressed", "fallbacks"):
                value = cel.get(field, 0)
                if isinstance(value, bool) or not isinstance(value, int) or value != 0:
                    errors.append(f"{package_id} reported nonzero CEL {field} while off")
        elif mode != expected_mode:
            errors.append(f"{package_id} reported CEL mode {mode!r}, expected {expected_mode!r}")
        elif not _valid_sha256(cel.get("expression_set_hash")):
            errors.append(f"{package_id} lacks a valid active CEL expression-set hash")
        else:
            generations.add(str(cel["expression_set_hash"]))
            runtimes.add(str(cel.get("runtime")))
            runtime_versions.add(str(cel.get("runtime_version")))
            fact_schemas.add(str(cel.get("fact_schema")))
    if expected_mode != "off" and evaluated <= 0:
        errors.append("active CEL arm did not evaluate any candidate")
    if expected_mode != "off" and len(generations) != 1:
        errors.append("active CEL arm did not retain one expression generation")
    if expected_mode != "off" and runtimes != {"cel-go"}:
        errors.append(f"active CEL arm used unexpected runtimes: {sorted(runtimes)}")
    if expected_mode != "off" and (len(runtime_versions) != 1 or "None" in runtime_versions):
        errors.append("active CEL arm did not retain one runtime version")
    if expected_mode != "off" and fact_schemas != {"v1"}:
        errors.append(f"active CEL arm used unexpected fact schemas: {sorted(fact_schemas)}")
    return errors


def _worker(args: argparse.Namespace) -> int:
    repository_root = Path(args.repository_root).resolve()
    corpus_root = Path(args.corpus_root).resolve()
    output = Path(args.output).resolve()
    harness = Path(__file__).resolve()
    harness_before = _sha256_file(harness)
    if harness_before != args.expected_harness_sha256:
        raise ArchivedCurrentBenchmarkError("worker harness digest differs from driver expectation")
    corpus_before = _hash_tree(
        corpus_root,
        namespace=b"skill-scanner-archived-current-corpus-v1",
        ignore_runtime_artifacts=False,
    )
    if corpus_before != args.expected_corpus_sha256:
        raise ArchivedCurrentBenchmarkError("worker corpus digest differs from driver expectation")
    helper = Path(args.helper).resolve() if args.helper else None
    if helper is not None and (helper.is_symlink() or not helper.is_file()):
        raise ArchivedCurrentBenchmarkError("worker helper must be a regular non-symlink file")
    helper_before = _sha256_file(helper) if helper is not None else None

    provenance_before, scanner = _provenance(
        repository_root=repository_root,
        source_revision=args.source_revision,
        config=args.config,
        packs=args.pack,
        cel_mode=args.cel_mode,
        helper=helper,
    )
    lock = _arm_lock_from_mapping(_strict_json(Path(args.lock)), "worker.lock")
    _validate_provenance(lock, provenance_before, "worker.start")

    import evals.runners.benchmark_runner as committed_runner

    runner_path = Path(committed_runner.__file__).resolve()
    expected_runner_path = _evaluator_path(repository_root)
    if runner_path != expected_runner_path:
        raise ArchivedCurrentBenchmarkError(
            f"evaluation runner path mismatch: imported={runner_path}, expected={expected_runner_path}"
        )
    if _sha256_file(runner_path) != lock.evaluator_sha256:
        raise ArchivedCurrentBenchmarkError("evaluation runner differs from the reviewed arm lock")
    SkillBenchmarkRunner = committed_runner.SkillBenchmarkRunner

    runner = SkillBenchmarkRunner.__new__(SkillBenchmarkRunner)
    runner.eval_skills_dir = corpus_root
    capturing = _CapturingScanner(scanner, corpus_root)
    setattr(runner, "scanner", capturing)
    runner.results = []
    try:
        benchmark = runner.run_benchmark()
    finally:
        capturing.close()
    benchmark_dict = asdict(benchmark)
    scan_errors = int(benchmark_dict.get("evaluation_errors", 0))
    cel_fallbacks = int(benchmark_dict.get("cel_fallbacks", 0))
    strict_count = int(benchmark_dict.get("strict_identity_skills", 0))
    total_count = int(benchmark_dict.get("total_skills_evaluated", 0))

    provenance_after, verification_scanner = _provenance(
        repository_root=repository_root,
        source_revision=args.source_revision,
        config=args.config,
        packs=args.pack,
        cel_mode=args.cel_mode,
        helper=helper,
    )
    close = getattr(verification_scanner, "close", None)
    if callable(close):
        close()
    _validate_provenance(lock, provenance_after, "worker.end")
    corpus_after = _hash_tree(
        corpus_root,
        namespace=b"skill-scanner-archived-current-corpus-v1",
        ignore_runtime_artifacts=False,
    )
    helper_after = _sha256_file(helper) if helper is not None else None
    harness_after = _sha256_file(harness)
    drifted = []
    if provenance_before != provenance_after:
        drifted.append("provenance")
    if corpus_before != corpus_after:
        drifted.append("corpus")
    if helper_before != helper_after:
        drifted.append("helper")
    if harness_before != harness_after:
        drifted.append("harness")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "errors": [],
        "provenance": provenance_before,
        "identity_verification": {
            "status": "passed" if not drifted else "failed",
            "drifted_fields": drifted,
            "start": _lock_projection(provenance_before),
            "end": _lock_projection(provenance_after),
            "corpus_sha256": corpus_before,
            "helper_sha256": helper_before,
            "harness_sha256": harness_before,
        },
        "benchmark": benchmark_dict,
        "individual_results": runner.results,
        "scan_semantics": {key: capturing.captures[key] for key in sorted(capturing.captures)},
    }
    report["semantic_sha256"] = _semantic_report_fingerprint(report)
    if scan_errors:
        report["errors"].append(f"benchmark recorded {scan_errors} evaluation error(s)")
    if cel_fallbacks:
        report["errors"].append(f"benchmark recorded {cel_fallbacks} CEL fallback(s)")
    if strict_count != total_count:
        report["errors"].append(
            f"benchmark evaluated {strict_count} strict identities for {total_count} total fixture(s)"
        )
    if len(capturing.captures) != total_count:
        report["errors"].append(
            f"semantic capture count {len(capturing.captures)} differs from benchmark denominator {total_count}"
        )
    report["errors"].extend(_cel_evidence_errors(capturing.captures, args.cel_mode))
    if drifted:
        report["errors"].append(f"worker identity drifted: {', '.join(drifted)}")
    if report["errors"]:
        report["status"] = "failed"
    _atomic_json(output, report)
    return 0 if report["status"] == "passed" else 1


def _minimal_environment(run_root: Path, helper: Path | None) -> dict[str, str]:
    home = run_root / "home"
    cache = run_root / "cache"
    temporary = run_root / "tmp"
    for directory in (home, cache, temporary):
        directory.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": os.defpath,
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "XDG_CACHE_HOME": str(cache),
        "HF_HOME": str(cache / "huggingface"),
        "TRANSFORMERS_CACHE": str(cache / "transformers"),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "PIP_NO_INDEX": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for key in _HOST_SYSTEM_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    if helper is not None:
        environment["SKILL_SCANNER_CEL_GO_HELPER"] = str(helper)
    return environment


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    """Terminate the worker and every descendant in its isolated group."""

    if os.name == "nt":
        if process.poll() is None:
            system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
            taskkill = system_root / "System32" / "taskkill.exe"
            try:
                subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


def _run_worker_process(
    *,
    script: Path,
    repository_root: Path,
    corpus_root: Path,
    corpus_sha256: str,
    harness_sha256: str,
    arm: ArmSpec,
    helper: Path | None,
    run_root: Path,
    output: Path,
    timeout_seconds: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = [
        str(arm.python),
        "-I",
        "-B",
        "-c",
        _WORKER_BOOTSTRAP,
        str(script),
        "worker",
        "--repository-root",
        str(repository_root),
        "--corpus-root",
        str(corpus_root),
        "--expected-corpus-sha256",
        corpus_sha256,
        "--expected-harness-sha256",
        harness_sha256,
        "--source-revision",
        arm.lock.source_revision,
        "--config",
        arm.lock.config,
        "--cel-mode",
        arm.lock.cel_mode,
        "--lock",
        str(run_root / "arm-lock.json"),
        "--output",
        str(output),
    ]
    for pack in arm.lock.packs:
        command.extend(("--pack", pack))
    if helper is not None:
        command.extend(("--helper", str(helper)))
    _atomic_json(run_root / "arm-lock.json", arm.lock.to_json())
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=run_root,
        env=_minimal_environment(run_root, helper),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name != "nt",
        creationflags=creationflags,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)
        stdout, stderr = process.communicate()
    finally:
        # A successful direct worker must not leave a helper/grandchild behind.
        _terminate_process_group(process)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if timed_out:
        raise ArchivedCurrentBenchmarkError(f"{arm.name} worker timed out after {timeout_seconds:.1f}s")
    if not output.is_file() or output.is_symlink():
        raise ArchivedCurrentBenchmarkError(
            f"{arm.name} worker did not produce a regular report (exit={process.returncode}): {stderr[-4000:]}"
        )
    report = _strict_json(output)
    if process.returncode != 0 or report.get("status") != "passed" or report.get("errors") != []:
        raise ArchivedCurrentBenchmarkError(
            f"{arm.name} worker failed (exit={process.returncode}, errors={report.get('errors')}): {stderr[-4000:]}"
        )
    _validate_provenance(arm.lock, _mapping(report.get("provenance"), "worker.provenance"), arm.name)
    execution = {
        "elapsed_ms": elapsed_ms,
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "stderr_nonempty": bool(stderr.strip()),
        "report_sha256": _sha256_file(output),
        "report_path": str(output),
    }
    return dict(report), execution


def _mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ArchivedCurrentBenchmarkError(f"{location} must be an object")
    return value


def _copy_immutable_helper(source: Path | None, expected_sha256: str | None, destination: Path) -> Path | None:
    if source is None:
        if expected_sha256 is not None:
            raise ArchivedCurrentBenchmarkError("helper lock has a digest but no helper path was supplied")
        return None
    if expected_sha256 is None:
        raise ArchivedCurrentBenchmarkError("helper path requires a reviewed helper_sha256 in the arm lock")
    if source.is_symlink() or not source.is_file():
        raise ArchivedCurrentBenchmarkError(f"helper must be a regular non-symlink file: {source}")
    actual = _sha256_file(source)
    if actual != expected_sha256:
        raise ArchivedCurrentBenchmarkError(f"helper digest mismatch: {actual} != {expected_sha256}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IRUSR | stat.S_IXUSR)
    if _sha256_file(destination) != expected_sha256:
        raise ArchivedCurrentBenchmarkError("immutable helper copy failed digest verification")
    return destination


def _pair_schedule() -> tuple[tuple[str, str], ...]:
    return tuple(("baseline", "current") if index % 2 == 0 else ("current", "baseline") for index in range(5))


def _validate_five_runs(arm: ArmSpec, runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(runs) != PAIR_COUNT:
        raise ArchivedCurrentBenchmarkError(f"{arm.name} must have exactly {PAIR_COUNT} independent runs")
    semantic_hashes = [run.get("semantic_sha256") for run in runs]
    if any(not _valid_sha256(value) for value in semantic_hashes) or len(set(semantic_hashes)) != 1:
        raise ArchivedCurrentBenchmarkError(f"{arm.name} semantic outputs are not stable across five runs")
    for index, run in enumerate(runs, 1):
        if run.get("status") != "passed" or run.get("errors") != []:
            raise ArchivedCurrentBenchmarkError(f"{arm.name} run {index} is not a completed error-free report")
        _validate_provenance(
            arm.lock,
            _mapping(run.get("provenance"), f"{arm.name}[{index}].provenance"),
            f"{arm.name}[{index}]",
        )
        verification = _mapping(run.get("identity_verification"), f"{arm.name}[{index}].identity_verification")
        if verification.get("status") != "passed" or verification.get("drifted_fields") != []:
            raise ArchivedCurrentBenchmarkError(f"{arm.name} run {index} has identity drift")
        benchmark = _mapping(run.get("benchmark"), f"{arm.name}[{index}].benchmark")
        if int(benchmark.get("evaluation_errors", -1)) != 0:
            raise ArchivedCurrentBenchmarkError(f"{arm.name} run {index} recorded evaluation errors")
        if int(benchmark.get("cel_fallbacks", -1)) != 0:
            raise ArchivedCurrentBenchmarkError(f"{arm.name} run {index} recorded CEL fallbacks")
    return {
        "runs": PAIR_COUNT,
        "stable": True,
        "semantic_sha256": semantic_hashes[0],
        "provenance": arm.lock.to_json(),
        "benchmark": runs[0]["benchmark"],
    }


def _finding_delta(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    def findings(report: Mapping[str, Any]) -> Counter[bytes]:
        result: Counter[bytes] = Counter()
        scans = _mapping(report.get("scan_semantics"), "scan_semantics")
        for package_id, scan in scans.items():
            scan = _mapping(scan, f"scan_semantics.{package_id}")
            raw_findings = scan.get("findings", [])
            if not isinstance(raw_findings, list):
                raise ArchivedCurrentBenchmarkError(f"scan_semantics.{package_id}.findings must be an array")
            for finding in raw_findings:
                result[_json_bytes({"package_id": package_id, "finding": finding})] += 1
        return result

    old = findings(baseline)
    new = findings(current)
    additions = new - old
    removals = old - new
    return {
        "added_count": sum(additions.values()),
        "removed_count": sum(removals.values()),
        "additions_sha256": hashlib.sha256(b"".join(sorted(additions.elements()))).hexdigest(),
        "removals_sha256": hashlib.sha256(b"".join(sorted(removals.elements()))).hexdigest(),
    }


def _require_comparable_arms(baseline: ArmSpec, current: ArmSpec) -> None:
    if baseline.lock.config != current.lock.config:
        raise ArchivedCurrentBenchmarkError("baseline and current must use the same analyzer configuration")
    if baseline.lock.packs != current.lock.packs:
        raise ArchivedCurrentBenchmarkError("baseline and current must select the same ordered rule packs")
    if baseline.lock.python_version != current.lock.python_version:
        raise ArchivedCurrentBenchmarkError("baseline and current must use the same exact Python version")
    if baseline.lock.evaluator_sha256 != current.lock.evaluator_sha256:
        raise ArchivedCurrentBenchmarkError("baseline and current must use the same committed metric runner")
    if baseline.lock.cel_mode != "off":
        raise ArchivedCurrentBenchmarkError("the archived baseline must run with CEL off")


def _finite_number(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArchivedCurrentBenchmarkError(f"{location} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ArchivedCurrentBenchmarkError(f"{location} must be finite")
    return result


def _benchmark_metric_deltas(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Compare metrics already calculated by the committed benchmark runner."""

    excluded = {
        "category_metrics",
        "scan_duration_seconds",
        "skills_per_second",
        "p95_scan_latency_ms",
        "cel_time_ratio",
        "finding_precision_confidence_interval_95",
        "finding_recall_confidence_interval_95",
        "package_block_recall_confidence_interval_95",
        "package_signal_recall_confidence_interval_95",
        "benign_actionable_fpr_confidence_interval_95",
    }
    fields = sorted((set(baseline) | set(current)) - excluded)
    result: dict[str, dict[str, Any]] = {}
    for field in fields:
        if field not in baseline or field not in current:
            raise ArchivedCurrentBenchmarkError(f"benchmark metric {field!r} exists in only one arm")
        baseline_value = _finite_number(baseline[field], f"baseline.benchmark.{field}")
        current_value = _finite_number(current[field], f"current.benchmark.{field}")
        absolute = current_value - baseline_value
        result[field] = {
            "baseline": baseline_value,
            "current": current_value,
            "absolute_delta": absolute,
            "relative_delta": absolute / abs(baseline_value) if baseline_value else None,
        }
    return result


def _nearest_rank_p95(values: Sequence[float], location: str) -> float:
    if not values:
        raise ArchivedCurrentBenchmarkError(f"{location} has no timing samples")
    return sorted(values)[max(0, math.ceil(0.95 * len(values)) - 1)]


def _performance_summary(
    reports: Sequence[Mapping[str, Any]], executions: Sequence[Mapping[str, Any]], location: str
) -> dict[str, Any]:
    scan_ms: list[float] = []
    cel_ms: list[float] = []
    for run_index, report in enumerate(reports, 1):
        raw_results = report.get("individual_results")
        if not isinstance(raw_results, list) or not raw_results:
            raise ArchivedCurrentBenchmarkError(f"{location} run {run_index} lacks individual timings")
        for sample_index, raw_result in enumerate(raw_results, 1):
            result = _mapping(raw_result, f"{location}[{run_index}].individual_results[{sample_index}]")
            if "error" in result:
                raise ArchivedCurrentBenchmarkError(
                    f"{location} run {run_index} sample {sample_index} contains an evaluation error"
                )
            sample_scan_ms = _finite_number(
                result.get("scan_duration_ms"),
                f"{location}[{run_index}].individual_results[{sample_index}].scan_duration_ms",
            )
            sample_cel_ms = _finite_number(
                result.get("cel_elapsed_ms"),
                f"{location}[{run_index}].individual_results[{sample_index}].cel_elapsed_ms",
            )
            if sample_scan_ms < 0 or sample_cel_ms < 0 or sample_cel_ms > sample_scan_ms + 1e-9:
                raise ArchivedCurrentBenchmarkError(f"{location} contains invalid scan/CEL timing")
            scan_ms.append(sample_scan_ms)
            cel_ms.append(sample_cel_ms)
    worker_ms = [
        _finite_number(execution.get("elapsed_ms"), f"{location}.executions[{index}].elapsed_ms")
        for index, execution in enumerate(executions, 1)
    ]
    if len(worker_ms) != PAIR_COUNT or any(value < 0 for value in worker_ms):
        raise ArchivedCurrentBenchmarkError(f"{location} lacks exactly five valid worker timings")
    ordered_worker = sorted(worker_ms)
    return {
        "scan_samples": len(scan_ms),
        "p95_scan_latency_ms": _nearest_rank_p95(scan_ms, f"{location}.scan_ms"),
        "cel_time_ratio": sum(cel_ms) / sum(scan_ms) if sum(scan_ms) else 0.0,
        "worker_elapsed_ms": worker_ms,
        "median_worker_elapsed_ms": ordered_worker[len(ordered_worker) // 2],
        "p95_worker_elapsed_ms": _nearest_rank_p95(worker_ms, f"{location}.worker_ms"),
    }


def _driver(args: argparse.Namespace) -> int:
    script = Path(__file__).resolve()
    repository_root = Path(args.repository_root).resolve()
    corpus_root = Path(args.corpus_root).resolve()
    output = Path(args.output).resolve()
    harness_sha256 = _sha256_file(script)
    if harness_sha256 != args.expected_harness_sha256:
        raise ArchivedCurrentBenchmarkError(
            f"harness digest mismatch: {harness_sha256} != {args.expected_harness_sha256}"
        )
    corpus_sha256 = _hash_tree(
        corpus_root,
        namespace=b"skill-scanner-archived-current-corpus-v1",
        ignore_runtime_artifacts=False,
    )
    if corpus_sha256 != args.expected_corpus_sha256:
        raise ArchivedCurrentBenchmarkError(f"corpus digest mismatch: {corpus_sha256} != {args.expected_corpus_sha256}")

    baseline = ArmSpec(
        name="baseline",
        python=Path(args.baseline_python).absolute(),
        lock=_load_arm_lock(Path(args.baseline_lock), "baseline_lock"),
        helper=Path(args.baseline_helper).absolute() if args.baseline_helper else None,
    )
    current = ArmSpec(
        name="current",
        python=Path(args.current_python).absolute(),
        lock=_load_arm_lock(Path(args.current_lock), "current_lock"),
        helper=Path(args.current_helper).absolute() if args.current_helper else None,
    )
    _require_comparable_arms(baseline, current)
    for arm in (baseline, current):
        if arm.python.is_symlink() and not arm.python.exists():
            raise ArchivedCurrentBenchmarkError(f"{arm.name} Python executable is a broken symlink")
        if not arm.python.is_file() or not os.access(arm.python, os.X_OK):
            raise ArchivedCurrentBenchmarkError(f"{arm.name} Python executable is missing or not executable")
    if baseline.python == current.python:
        raise ArchivedCurrentBenchmarkError("baseline and current must use distinct explicit Python environments")

    schedule = _pair_schedule()
    runs: dict[str, list[dict[str, Any]]] = {"baseline": [], "current": []}
    executions: dict[str, list[dict[str, Any]]] = {"baseline": [], "current": []}
    source_helpers = {"baseline": baseline.helper, "current": current.helper}
    arms = {"baseline": baseline, "current": current}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="skill-scanner-archived-current-") as temporary_name:
        temporary = Path(temporary_name)
        immutable_helpers = {
            name: _copy_immutable_helper(
                source_helpers[name],
                arms[name].lock.helper_sha256,
                temporary / "helpers" / f"{name}-cel-helper",
            )
            for name in ("baseline", "current")
        }
        for pair_index, order in enumerate(schedule, 1):
            for position, arm_name in enumerate(order, 1):
                arm = arms[arm_name]
                run_root = temporary / "runs" / f"pair-{pair_index}" / f"{position}-{arm_name}"
                run_root.mkdir(parents=True)
                report_path = output.parent / f"{output.stem}-runs" / arm_name / f"run-{pair_index}.json"
                report, execution = _run_worker_process(
                    script=script,
                    repository_root=repository_root,
                    corpus_root=corpus_root,
                    corpus_sha256=corpus_sha256,
                    harness_sha256=harness_sha256,
                    arm=arm,
                    helper=immutable_helpers[arm_name],
                    run_root=run_root,
                    output=report_path,
                    timeout_seconds=args.timeout_seconds,
                )
                runs[arm_name].append(report)
                executions[arm_name].append(execution)

    baseline_summary = _validate_five_runs(baseline, runs["baseline"])
    current_summary = _validate_five_runs(current, runs["current"])
    baseline_prefixes = {run["provenance"]["python_prefix"] for run in runs["baseline"]}
    current_prefixes = {run["provenance"]["python_prefix"] for run in runs["current"]}
    if len(baseline_prefixes) != 1 or len(current_prefixes) != 1 or baseline_prefixes == current_prefixes:
        raise ArchivedCurrentBenchmarkError(
            "baseline and current workers did not prove two stable distinct environments"
        )
    harness_after = _sha256_file(script)
    corpus_after = _hash_tree(
        corpus_root,
        namespace=b"skill-scanner-archived-current-corpus-v1",
        ignore_runtime_artifacts=False,
    )
    if harness_after != harness_sha256 or corpus_after != corpus_sha256:
        raise ArchivedCurrentBenchmarkError("harness or corpus changed during the paired matrix")

    baseline_performance = _performance_summary(runs["baseline"], executions["baseline"], "baseline")
    current_performance = _performance_summary(runs["current"], executions["current"], "current")
    performance_deltas = {
        field: {
            "baseline": baseline_performance[field],
            "current": current_performance[field],
            "absolute_delta": current_performance[field] - baseline_performance[field],
            "relative_delta": (
                (current_performance[field] - baseline_performance[field]) / baseline_performance[field]
                if baseline_performance[field]
                else None
            ),
        }
        for field in ("p95_scan_latency_ms", "cel_time_ratio", "median_worker_elapsed_ms", "p95_worker_elapsed_ms")
    }
    same_scanner_source = baseline.lock.source_sha256 == current.lock.source_sha256
    comparison_kind = (
        "cel_activation"
        if same_scanner_source and current.lock.cel_mode != "off"
        else "scanner_upgrade_with_cel"
        if current.lock.cel_mode != "off"
        else "scanner_upgrade"
    )

    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "errors": [],
        "method": {
            "pairs": PAIR_COUNT,
            "worker_processes": PAIR_COUNT * 2,
            "schedule": [list(order) for order in schedule],
            "counterbalanced": True,
            "isolated_environments": True,
            "python_isolated_mode": True,
            "python_socket_network_denial": True,
            "hosted_llm_analyzers": False,
            "harness_sha256": harness_sha256,
            "corpus_sha256": corpus_sha256,
        },
        "arms": {"baseline": baseline_summary, "current": current_summary},
        "executions": executions,
        "comparison": {
            "kind": comparison_kind,
            "baseline_semantic_sha256": baseline_summary["semantic_sha256"],
            "current_semantic_sha256": current_summary["semantic_sha256"],
            "semantic_outputs_changed": baseline_summary["semantic_sha256"] != current_summary["semantic_sha256"],
            "finding_delta": _finding_delta(runs["baseline"][0], runs["current"][0]),
            "metric_deltas": _benchmark_metric_deltas(
                _mapping(runs["baseline"][0].get("benchmark"), "baseline.benchmark"),
                _mapping(runs["current"][0].get("benchmark"), "current.benchmark"),
            ),
            "performance": {
                "baseline": baseline_performance,
                "current": current_performance,
                "deltas": performance_deltas,
                "p95_scan_latency_within_ten_percent": current_performance["p95_scan_latency_ms"]
                <= baseline_performance["p95_scan_latency_ms"] * 1.10 + 1e-12,
                "cel_time_within_five_percent": current_performance["cel_time_ratio"] <= 0.05 + 1e-12,
            },
        },
        "limitations": [
            "Committed golden fixtures are first-party regression evidence, not an independent release corpus.",
            "Python audit hooks and socket guards deny Python networking; native code outside CPython's audit surface "
            "requires an operating-system sandbox in release infrastructure.",
            "Source revisions are caller-reviewed labels cryptographically bound here to source, rule, policy, "
            "helper, and environment hashes; an archived source copy without VCS metadata cannot self-prove a commit.",
        ],
    }
    _atomic_json(output, report)
    print(json.dumps({"status": "passed", "output": str(output), "sha256": _sha256_file(output)}))
    return 0


def _probe(args: argparse.Namespace) -> int:
    helper = Path(args.helper).resolve() if args.helper else None
    if helper is not None and (helper.is_symlink() or not helper.is_file()):
        raise ArchivedCurrentBenchmarkError("probe helper must be a regular non-symlink file")
    helper_key = "SKILL_SCANNER_CEL_GO_HELPER"
    previous_helper = os.environ.get(helper_key)
    if helper is not None:
        os.environ[helper_key] = str(helper)
    try:
        provenance, scanner = _provenance(
            repository_root=Path(args.repository_root).resolve(),
            source_revision=args.source_revision,
            config=args.config,
            packs=args.pack,
            cel_mode=args.cel_mode,
            helper=helper,
        )
        close = getattr(scanner, "close", None)
        if callable(close):
            close()
    finally:
        if previous_helper is None:
            os.environ.pop(helper_key, None)
        else:
            os.environ[helper_key] = previous_helper
    _atomic_json(Path(args.output), _lock_projection(provenance))
    return 0


def _corpus_lock(args: argparse.Namespace) -> int:
    root = Path(args.corpus_root).resolve()
    members = _tree_manifest(root, ignore_runtime_artifacts=False)
    value = {
        "schema_version": SCHEMA_VERSION,
        "sha256": _hash_tree(
            root,
            namespace=b"skill-scanner-archived-current-corpus-v1",
            ignore_runtime_artifacts=False,
        ),
        "files": len(members),
        "bytes": sum(len(content) for _, content in members),
    }
    _atomic_json(Path(args.output), value)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    probe = subparsers.add_parser("probe", help="produce a reviewable provenance lock in one target environment")
    probe.add_argument("--repository-root", type=Path, required=True)
    probe.add_argument("--source-revision", required=True)
    probe.add_argument("--config", choices=sorted(_ALLOWED_CONFIGS), required=True)
    probe.add_argument("--pack", action="append", default=[])
    probe.add_argument("--cel-mode", choices=sorted(_ALLOWED_CEL_MODES), required=True)
    probe.add_argument("--helper", type=Path)
    probe.add_argument("--output", type=Path, required=True)

    corpus = subparsers.add_parser("corpus-lock", help="produce the strict corpus digest required by the driver")
    corpus.add_argument("--corpus-root", type=Path, required=True)
    corpus.add_argument("--output", type=Path, required=True)

    worker = subparsers.add_parser("worker", help=argparse.SUPPRESS)
    worker.add_argument("--repository-root", required=True)
    worker.add_argument("--corpus-root", required=True)
    worker.add_argument("--expected-corpus-sha256", required=True)
    worker.add_argument("--expected-harness-sha256", required=True)
    worker.add_argument("--source-revision", required=True)
    worker.add_argument("--config", choices=sorted(_ALLOWED_CONFIGS), required=True)
    worker.add_argument("--pack", action="append", default=[])
    worker.add_argument("--cel-mode", choices=sorted(_ALLOWED_CEL_MODES), required=True)
    worker.add_argument("--helper")
    worker.add_argument("--lock", required=True)
    worker.add_argument("--output", required=True)

    driver = subparsers.add_parser("driver", help="run the five-pair archived/current matrix")
    driver.add_argument("--repository-root", type=Path, required=True)
    driver.add_argument("--corpus-root", type=Path, required=True)
    driver.add_argument("--expected-corpus-sha256", required=True)
    driver.add_argument("--expected-harness-sha256", required=True)
    driver.add_argument("--baseline-python", type=Path, required=True)
    driver.add_argument("--current-python", type=Path, required=True)
    driver.add_argument("--baseline-lock", type=Path, required=True)
    driver.add_argument("--current-lock", type=Path, required=True)
    driver.add_argument("--baseline-helper", type=Path)
    driver.add_argument("--current-helper", type=Path)
    driver.add_argument("--timeout-seconds", type=float, default=600.0)
    driver.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if getattr(args, "timeout_seconds", 1.0) <= 0:
        raise ArchivedCurrentBenchmarkError("timeout-seconds must be positive")
    if args.mode == "worker":
        return _worker(args)
    if args.mode == "probe":
        return _probe(args)
    if args.mode == "corpus-lock":
        return _corpus_lock(args)
    return _driver(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArchivedCurrentBenchmarkError as exc:
        print(f"archived/current benchmark failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
