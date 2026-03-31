# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
OpenTelemetry instrumentation for Skill Scanner.

This package provides optional observability (traces, metrics, logs) via the
OpenTelemetry SDK. All instrumentation is fully opt-in: if the SDK is not
installed or telemetry is not configured, every call in this module is a
no-op and the rest of the application is completely unaffected.

Activation:
    Set the environment variable ``SKILL_SCANNER_OTEL_ENABLED=true`` **or**
    pass ``--enable-otel`` on the CLI. Without at least one of these, the
    SDK is never initialised and zero overhead is incurred.

Configuration (standard OpenTelemetry env vars):
    OTEL_EXPORTER_OTLP_ENDPOINT  - OTLP collector endpoint (e.g. http://localhost:4317)
    OTEL_EXPORTER_OTLP_HEADERS   - comma-separated key=value auth headers
    OTEL_SERVICE_NAME            - service name reported to the backend
    OTEL_RESOURCE_ATTRIBUTES     - additional resource attributes
    OTEL_SDK_DISABLED            - set to "true" to hard-disable the SDK

Install extras:
    pip install cisco-ai-skill-scanner[otel]
"""

from .telemetry import (
    TelemetryConfig,
    get_logger,
    get_meter,
    get_tracer,
    is_enabled,
    record_analyzer_duration,
    record_scan_metrics,
    scan_span,
    setup_telemetry,
    shutdown_telemetry,
)

__all__ = [
    "TelemetryConfig",
    "get_tracer",
    "get_meter",
    "get_logger",
    "is_enabled",
    "setup_telemetry",
    "shutdown_telemetry",
    "scan_span",
    "record_scan_metrics",
    "record_analyzer_duration",
]
