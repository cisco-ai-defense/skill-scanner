# Copyright 2026 Cisco Systems, Inc.
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

"""Regression tests for scan-scoped logging context (issue #149)."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from skill_scanner.core.scanner import SkillScanner
from skill_scanner.utils.logging_context import get_scan_log_context, scan_log_context


def test_scan_context_prefixes_package_logs_and_restores(caplog) -> None:
    logger = logging.getLogger("skill_scanner.tests.context")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        with scan_log_context(skill_name="alpha", skill_path="/skills/alpha", scan_id="scan-1"):
            logger.warning("Invalid JSON response")
        logger.warning("Outside scan")

    contextual, outside = caplog.records[-2:]
    assert contextual.getMessage() == ("[skill=alpha path=/skills/alpha scan_id=scan-1] Invalid JSON response")
    assert contextual.skill_name == "alpha"
    assert contextual.skill_path == "/skills/alpha"
    assert contextual.scan_id == "scan-1"
    assert outside.getMessage() == "Outside scan"
    assert outside.skill_name is None


def test_nested_context_inherits_request_id_and_restores_parent() -> None:
    assert get_scan_log_context() is None

    with scan_log_context(scan_id="batch-1"):
        with scan_log_context(skill_name="nested", skill_path="/skills/nested") as nested:
            assert nested.scan_id == "batch-1"
            assert nested.skill_name == "nested"

        restored = get_scan_log_context()
        assert restored is not None
        assert restored.scan_id == "batch-1"
        assert restored.skill_name is None

    assert get_scan_log_context() is None


def test_context_escapes_control_characters(caplog) -> None:
    logger = logging.getLogger("skill_scanner.tests.untrusted_context")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        with scan_log_context(skill_name="line-one\nforged-warning"):
            logger.warning("real warning")

    assert caplog.records[-1].getMessage() == "[skill=line-one\\nforged-warning] real warning"


def test_parallel_thread_contexts_do_not_bleed() -> None:
    logger = logging.getLogger("skill_scanner.tests.parallel")
    barrier = threading.Barrier(2)
    records: list[logging.LogRecord] = []
    records_lock = threading.Lock()

    class RecordingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            with records_lock:
                records.append(record)

    handler = RecordingHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.propagate = False

    def emit_for(skill_name: str) -> None:
        with scan_log_context(skill_name=skill_name):
            barrier.wait(timeout=5)
            logger.warning("timed out")

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(emit_for, name) for name in ("alpha", "beta")]
            for future in futures:
                future.result(timeout=10)
    finally:
        logger.removeHandler(handler)
        logger.propagate = True

    by_skill = {record.skill_name: record.getMessage() for record in records}
    assert by_skill == {
        "alpha": "[skill=alpha] timed out",
        "beta": "[skill=beta] timed out",
    }


def test_scanner_binds_skill_name_and_canonical_path(monkeypatch, tmp_path: Path) -> None:
    scanner = SkillScanner(analyzers=[])
    skill = SimpleNamespace(name="bound-skill")
    captured = None

    def run_with_context(_skill, _path):
        nonlocal captured
        captured = get_scan_log_context()
        return "scan-result"

    monkeypatch.setattr(scanner, "_scan_single_skill_with_context", run_with_context)

    result = scanner._scan_single_skill(skill, tmp_path / "bound-skill")

    assert result == "scan-result"
    assert captured is not None
    assert captured.skill_name == "bound-skill"
    assert captured.skill_path == str((tmp_path / "bound-skill").resolve())
    assert get_scan_log_context() is None
