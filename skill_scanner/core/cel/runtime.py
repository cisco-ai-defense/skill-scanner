# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Runtime-neutral contracts shared by the production cel-go adapter.

Skill Scanner deliberately has one CEL interpreter: the pinned, persistent
``cel-go`` helper. Keeping these small value types in a neutral module avoids
coupling the decision gate to transport details without retaining the retired
``cel-expr-python`` interpreter.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


class CelRuntimeUnavailable(RuntimeError):
    """The qualified CEL runtime is unavailable for the selected operation."""


@dataclass(frozen=True)
class RuntimeEvaluation:
    """One fail-open CEL runtime result and its end-to-end latency."""

    value: bool | None
    elapsed_ms: float
    error_code: str = ""


@dataclass
class _CircuitState:
    """Mutable state for one rule's soft runtime circuit breaker."""

    consecutive_failures: int = 0
    open: bool = False
    open_until: float = 0.0
    probe_in_flight: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
