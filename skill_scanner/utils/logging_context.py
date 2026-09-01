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

"""Scan-scoped context for Skill Scanner log records.

The scanner is used from synchronous CLI code, asyncio tasks, and worker
threads.  A :class:`contextvars.ContextVar` keeps those concurrent scans
isolated without relying on mutable process-wide "current skill" state.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanLogContext:
    """Identifiers attached to log records emitted during a scan."""

    skill_name: str | None = None
    skill_path: str | None = None
    scan_id: str | None = None


_current_scan_context: ContextVar[ScanLogContext | None] = ContextVar(
    "skill_scanner_log_context",
    default=None,
)
_factory_lock = threading.Lock()


def _safe_label(value: str) -> str:
    """Render an identifier without allowing terminal/log-line injection."""

    return value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


def _install_context_record_factory() -> None:
    """Install a cooperative record factory that prefixes package logs."""

    with _factory_lock:
        previous_factory = logging.getLogRecordFactory()
        if getattr(previous_factory, "_skill_scanner_context_factory", False):
            return

        def context_record_factory(*args, **kwargs):
            record = previous_factory(*args, **kwargs)
            context = _current_scan_context.get()

            record.skill_name = context.skill_name if context else None
            record.skill_path = context.skill_path if context else None
            record.scan_id = context.scan_id if context else None

            if (
                context
                and record.name.startswith("skill_scanner")
                and not getattr(record, "_skill_scanner_context_applied", False)
            ):
                labels = []
                if context.skill_name:
                    labels.append(f"skill={_safe_label(context.skill_name)}")
                if context.skill_path:
                    labels.append(f"path={_safe_label(context.skill_path)}")
                if context.scan_id:
                    labels.append(f"scan_id={_safe_label(context.scan_id)}")
                if labels:
                    record.msg = f"[{' '.join(labels)}] {record.msg}"
                    record._skill_scanner_context_applied = True

            return record

        context_record_factory._skill_scanner_context_factory = True
        logging.setLogRecordFactory(context_record_factory)


def get_scan_log_context() -> ScanLogContext | None:
    """Return the context bound to the current task or thread."""

    return _current_scan_context.get()


@contextmanager
def scan_log_context(
    *,
    skill_name: str | None = None,
    skill_path: str | None = None,
    scan_id: str | None = None,
) -> Iterator[ScanLogContext]:
    """Bind scan identifiers for the duration of a scanner operation.

    Nested scopes inherit identifiers they do not explicitly replace.  This
    lets an API request bind ``scan_id`` in its worker thread while the core
    scanner adds the concrete skill name and path for each package.
    """

    _install_context_record_factory()
    parent = _current_scan_context.get()
    context = ScanLogContext(
        skill_name=skill_name if skill_name is not None else (parent.skill_name if parent else None),
        skill_path=skill_path if skill_path is not None else (parent.skill_path if parent else None),
        scan_id=scan_id if scan_id is not None else (parent.scan_id if parent else None),
    )
    token = _current_scan_context.set(context)
    try:
        yield context
    finally:
        _current_scan_context.reset(token)
