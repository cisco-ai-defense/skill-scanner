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

"""API module for Skill Scanner.

This module provides a FastAPI application for scanning agent skills packages.
"""

import os

from fastapi import FastAPI

from .. import __version__ as PACKAGE_VERSION
from ..telemetry import TelemetryConfig, setup_telemetry
from .router import router as api_router

app = FastAPI(
    title="Skill Scanner API",
    description="Security scanning API for agent skills packages",
    version=PACKAGE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(api_router)

# ---------------------------------------------------------------------------
# Optional OpenTelemetry instrumentation for the API server
# ---------------------------------------------------------------------------
# Activated when SKILL_SCANNER_OTEL_ENABLED=true (or 1/yes) is set.
# When enabled, FastAPI HTTP spans are exported alongside scanner spans so
# that a single trace covers the full request lifecycle.
# ---------------------------------------------------------------------------

_otel_enabled = os.getenv("SKILL_SCANNER_OTEL_ENABLED", "").lower() in ("1", "true", "yes")

if _otel_enabled:
    setup_telemetry(TelemetryConfig(enabled=True))

    # Auto-instrument FastAPI / Starlette with HTTP spans
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore[import]

        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        pass  # opentelemetry-instrumentation-fastapi not installed – skip silently
