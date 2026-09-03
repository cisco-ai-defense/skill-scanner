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

from __future__ import annotations

import argparse
import copy
import json
import os
import stat
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.runners import archived_current_benchmark as benchmark


def _lock(*, marker: str = "a", cel_mode: str = "off", helper: str | None = None) -> benchmark.ArmLock:
    return benchmark.ArmLock(
        schema_version=1,
        source_revision=f"revision-{marker}",
        source_sha256=marker * 64,
        evaluator_sha256="e" * 64,
        rules_sha256=chr(ord(marker) + 1) * 64,
        policy_sha256=chr(ord(marker) + 2) * 64,
        helper_sha256=helper,
        environment_sha256=chr(ord(marker) + 3) * 64,
        python_version="3.11.9",
        config="core",
        packs=(),
        cel_mode=cel_mode,
        analyzer_classes=("skill_scanner.core.analyzers.static.StaticAnalyzer",),
    )


def _run(lock: benchmark.ArmLock, *, prefix: str, semantic: str = "f" * 64) -> dict[str, object]:
    provenance = {**lock.to_json(), "python_prefix": prefix}
    return {
        "status": "passed",
        "errors": [],
        "semantic_sha256": semantic,
        "provenance": provenance,
        "identity_verification": {"status": "passed", "drifted_fields": []},
        "benchmark": {"evaluation_errors": 0, "cel_fallbacks": 0, "p95_scan_latency_ms": 1.0},
        "individual_results": [{"scan_duration_ms": 1.0, "cel_elapsed_ms": 0.0}],
        "scan_semantics": {},
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_pair_schedule_is_exactly_five_and_counterbalanced() -> None:
    schedule = benchmark._pair_schedule()

    assert schedule == (
        ("baseline", "current"),
        ("current", "baseline"),
        ("baseline", "current"),
        ("current", "baseline"),
        ("baseline", "current"),
    )
    assert sum(arm == "baseline" for pair in schedule for arm in pair) == 5
    assert sum(arm == "current" for pair in schedule for arm in pair) == 5


def test_minimal_environment_drops_host_credentials_and_isolates_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "secret")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")
    helper = tmp_path / "helper"
    helper.write_bytes(b"helper")

    environment = benchmark._minimal_environment(tmp_path / "run", helper)

    assert "OPENAI_API_KEY" not in environment
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["HOME"].startswith(str(tmp_path))
    assert environment["XDG_CACHE_HOME"].startswith(str(tmp_path))
    assert environment["HF_HUB_OFFLINE"] == "1"
    assert environment["SKILL_SCANNER_CEL_GO_HELPER"] == str(helper)


def test_network_guard_denies_resolution_before_scanner_import() -> None:
    program = (
        benchmark._NETWORK_GUARD_SOURCE
        + "\ntry:\n"
        + "    _benchmark_socket.getaddrinfo('example.invalid', 443)\n"
        + "except PermissionError:\n"
        + "    print('denied')\n"
        + "else:\n"
        + "    raise SystemExit('network guard failed')\n"
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "denied"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_process_group_teardown_contains_worker_descendants(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    program = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
        "time.sleep(60)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", program],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not child_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert child_pid_path.exists()
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        assert os.getpgid(process.pid) == process.pid
        assert os.getpgid(child_pid) == process.pid

        benchmark._terminate_process_group(process)

        assert process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_tree_hash_rejects_symlinks_and_changes_on_mutation(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    payload = root / "payload.txt"
    payload.write_text("one", encoding="utf-8")
    before = benchmark._hash_tree(root, namespace=b"test")
    payload.write_text("two", encoding="utf-8")
    after = benchmark._hash_tree(root, namespace=b"test")
    assert before != after

    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="symbolic link"):
        benchmark._hash_tree(root, namespace=b"test")


def test_corpus_lock_emits_driver_digest_and_inventory(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "one").write_bytes(b"abc")
    (corpus / "two").write_bytes(b"defg")
    output = tmp_path / "corpus-lock.json"

    assert benchmark._corpus_lock(argparse.Namespace(corpus_root=corpus, output=output)) == 0

    value = json.loads(output.read_text(encoding="utf-8"))
    assert value == {
        "schema_version": 1,
        "sha256": benchmark._hash_tree(
            corpus,
            namespace=b"skill-scanner-archived-current-corpus-v1",
            ignore_runtime_artifacts=False,
        ),
        "files": 2,
        "bytes": 7,
    }


def test_immutable_helper_copy_requires_reviewed_digest_and_rejects_links(tmp_path: Path) -> None:
    source = tmp_path / "source-helper"
    source.write_bytes(b"trusted-helper")
    expected = benchmark._sha256_file(source)
    copied = benchmark._copy_immutable_helper(source, expected, tmp_path / "copy")

    assert copied is not None
    assert benchmark._sha256_file(copied) == expected
    if os.name != "nt":
        assert stat.S_IMODE(copied.stat().st_mode) == stat.S_IRUSR | stat.S_IXUSR
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="digest mismatch"):
        benchmark._copy_immutable_helper(source, "0" * 64, tmp_path / "bad-copy")

    link = tmp_path / "helper-link"
    try:
        link.symlink_to(source)
    except OSError:
        return
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="non-symlink"):
        benchmark._copy_immutable_helper(link, expected, tmp_path / "linked-copy")


def test_semantic_fingerprint_ignores_timings_but_binds_findings_analyzers_and_cel() -> None:
    report = {
        "benchmark": {"evaluation_errors": 0, "p95_scan_latency_ms": 1.0, "scan_duration_seconds": 2.0},
        "individual_results": [{"skill_name": "sample", "scan_duration_ms": 1.0, "cel_elapsed_ms": 0.2}],
        "scan_semantics": {
            "sample": {
                "analyzers_used": ["static"],
                "analyzers_failed": [],
                "cel": {"mode": "shadow", "evaluated": 1, "elapsed_ms": 0.2},
                "findings": [
                    {
                        "id": "evidence-1",
                        "rule_id": "RULE",
                        "category": "malware",
                        "severity": "HIGH",
                        "file_path": "payload.py",
                        "line_number": 7,
                        "analyzer": "static",
                        "cel": {"decision": "keep", "expression_hash": "a" * 64},
                    }
                ],
            }
        },
    }
    original = benchmark._semantic_report_fingerprint(report)
    timing_only = copy.deepcopy(report)
    timing_only["benchmark"]["p95_scan_latency_ms"] = 900.0
    timing_only["individual_results"][0]["cel_elapsed_ms"] = 12.0
    timing_only["scan_semantics"]["sample"]["cel"]["elapsed_ms"] = 12.0
    assert benchmark._semantic_report_fingerprint(timing_only) == original

    for mutate in (
        lambda value: value["scan_semantics"]["sample"]["findings"][0].update(id="evidence-2"),
        lambda value: value["scan_semantics"]["sample"].update(analyzers_used=["pipeline"]),
        lambda value: value["scan_semantics"]["sample"]["findings"][0]["cel"].update(decision="fallback"),
    ):
        changed = copy.deepcopy(report)
        mutate(changed)
        assert benchmark._semantic_report_fingerprint(changed) != original


def test_finding_semantics_bind_complete_payload_and_normalize_package_path(tmp_path: Path) -> None:
    package = tmp_path / "sample"
    package.mkdir()
    finding = SimpleNamespace(
        id="evidence-1",
        rule_id="RULE",
        category="malware",
        severity="high",
        file_path=str(package / "payload.py"),
        line_number=7,
        analyzer="static",
        to_dict=lambda: {
            "id": "evidence-1",
            "rule_id": "RULE",
            "category": "malware",
            "severity": "high",
            "title": "Complete title",
            "description": "Complete description",
            "file_path": str(package / "payload.py"),
            "line_number": 7,
            "snippet": "inert snippet",
            "remediation": "remove it",
            "analyzer": "static",
            "metadata": {"cel": {"decision": "keep"}, "structured": {"role": "executable"}},
        },
    )

    value = benchmark._finding_semantics(finding, package)

    assert value["file_path"] == "payload.py"
    assert value["severity"] == "HIGH"
    assert value["title"] == "Complete title"
    assert value["description"] == "Complete description"
    assert value["snippet"] == "inert snippet"
    assert value["remediation"] == "remove it"
    assert value["metadata"] == {"cel": {"decision": "keep"}, "structured": {"role": "executable"}}


def test_five_run_validation_rejects_wrong_count_errors_fallbacks_and_semantic_drift(tmp_path: Path) -> None:
    lock = _lock()
    arm = benchmark.ArmSpec("baseline", tmp_path / "python", lock, None)
    runs = [_run(lock, prefix="/baseline") for _ in range(5)]

    assert benchmark._validate_five_runs(arm, runs)["stable"] is True
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="exactly 5"):
        benchmark._validate_five_runs(arm, runs[:4])
    drifted = copy.deepcopy(runs)
    drifted[-1]["semantic_sha256"] = "e" * 64
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="not stable"):
        benchmark._validate_five_runs(arm, drifted)
    errored = copy.deepcopy(runs)
    errored[-1]["benchmark"]["evaluation_errors"] = 1
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="evaluation errors"):
        benchmark._validate_five_runs(arm, errored)
    fallback = copy.deepcopy(runs)
    fallback[-1]["benchmark"]["cel_fallbacks"] = 1
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="CEL fallbacks"):
        benchmark._validate_five_runs(arm, fallback)


def test_active_cel_evidence_requires_mode_expression_hash_and_evaluation() -> None:
    valid = {
        "sample": {
            "cel": {
                "mode": "shadow",
                "evaluated": 1,
                "expression_set_hash": "a" * 64,
                "runtime": "cel-go",
                "runtime_version": "v0.32.0;helper=test",
                "fact_schema": "v1",
                "projection_incomplete": 0,
                "errors": [],
                "fallbacks": 0,
            }
        }
    }
    assert benchmark._cel_evidence_errors(valid, "shadow") == []
    assert benchmark._cel_evidence_errors(valid, "enforce")
    no_evaluation = copy.deepcopy(valid)
    no_evaluation["sample"]["cel"]["evaluated"] = 0
    assert "did not evaluate" in " ".join(benchmark._cel_evidence_errors(no_evaluation, "shadow"))
    off_with_decisions = copy.deepcopy(valid)
    off_with_decisions["sample"]["cel"].update(mode="off", evaluated=1)
    assert benchmark._cel_evidence_errors(off_with_decisions, "off")


def test_driver_launches_five_counterbalanced_pairs_in_distinct_environments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "fixture.txt").write_text("fixture", encoding="utf-8")
    corpus_sha = benchmark._hash_tree(
        corpus,
        namespace=b"skill-scanner-archived-current-corpus-v1",
        ignore_runtime_artifacts=False,
    )
    baseline_lock = _lock(marker="a")
    current_lock = _lock(marker="1")
    baseline_lock_path = tmp_path / "baseline-lock.json"
    current_lock_path = tmp_path / "current-lock.json"
    _write_json(baseline_lock_path, baseline_lock.to_json())
    _write_json(current_lock_path, current_lock.to_json())
    baseline_python = tmp_path / "baseline-python"
    current_python = tmp_path / "current-python"
    for executable in (baseline_python, current_python):
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o700)

    observed: list[str] = []

    def fake_worker(**kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        arm = kwargs["arm"]
        assert isinstance(arm, benchmark.ArmSpec)
        observed.append(arm.name)
        prefix = f"/{arm.name}-environment"
        return _run(arm.lock, prefix=prefix, semantic=("b" if arm.name == "baseline" else "c") * 64), {
            "elapsed_ms": 1.0
        }

    monkeypatch.setattr(benchmark, "_run_worker_process", fake_worker)
    harness_sha = benchmark._sha256_file(Path(benchmark.__file__))
    output = tmp_path / "comparison.json"
    args = argparse.Namespace(
        repository_root=tmp_path,
        corpus_root=corpus,
        expected_corpus_sha256=corpus_sha,
        expected_harness_sha256=harness_sha,
        baseline_python=baseline_python,
        current_python=current_python,
        baseline_lock=baseline_lock_path,
        current_lock=current_lock_path,
        baseline_helper=None,
        current_helper=None,
        timeout_seconds=30.0,
        output=output,
    )

    assert benchmark._driver(args) == 0
    assert observed == [arm for pair in benchmark._pair_schedule() for arm in pair]
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert report["method"]["pairs"] == 5
    assert report["method"]["worker_processes"] == 10
    assert report["arms"]["baseline"]["runs"] == 5
    assert report["arms"]["current"]["runs"] == 5
    assert report["comparison"]["kind"] == "scanner_upgrade"
    assert report["comparison"]["metric_deltas"]["evaluation_errors"]["absolute_delta"] == 0.0
    assert report["comparison"]["performance"]["baseline"]["scan_samples"] == 5


def test_arm_lock_rejects_unreviewed_fields_and_duplicate_packs() -> None:
    value = _lock().to_json()
    value["packs"] = ["atr", "atr"]
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="unique"):
        benchmark._arm_lock_from_mapping(value, "lock")
    value = _lock().to_json()
    value["unexpected"] = True
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="fields mismatch"):
        benchmark._arm_lock_from_mapping(value, "lock")


def test_arm_comparability_and_active_helper_are_fail_closed(tmp_path: Path) -> None:
    baseline = benchmark.ArmSpec("baseline", tmp_path / "baseline-python", _lock(), None)
    current = benchmark.ArmSpec("current", tmp_path / "current-python", _lock(marker="1"), None)
    benchmark._require_comparable_arms(baseline, current)

    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="same analyzer configuration"):
        benchmark._require_comparable_arms(
            baseline,
            replace(current, lock=replace(current.lock, config="static")),
        )

    active_without_helper = _lock(marker="1").to_json()
    active_without_helper["cel_mode"] = "shadow"
    with pytest.raises(benchmark.ArchivedCurrentBenchmarkError, match="require it for active CEL"):
        benchmark._arm_lock_from_mapping(active_without_helper, "lock")
