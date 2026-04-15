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
Core OpenTelemetry setup and helper utilities for Skill Scanner.

Design principles
-----------------
* **Fully optional** – every public symbol degrades gracefully when the
  ``opentelemetry-sdk`` package is not installed, returning no-op stubs.
* **Zero overhead when disabled** – ``is_enabled()`` is checked once at
  startup; subsequent hot-path calls (``scan_span``, ``record_scan_metrics``)
  return immediately when telemetry is off.
* **Standard env vars** – respects the official OTEL_* environment variables
  so any compatible backend (Jaeger, Tempo, Dash0, Honeycomb, …) works out
  of the box without code changes.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

_ENABLED: bool = False
_TRACER: Any = None  # opentelemetry.trace.Tracer | None
_METER: Any = None   # opentelemetry.metrics.Meter | None

# Metric instruments (created lazily once the SDK is initialised)
_SCAN_DURATION_HISTOGRAM: Any = None
_FINDINGS_COUNTER: Any = None
_ANALYZER_DURATION_HISTOGRAM: Any = None
_SCANS_TOTAL_COUNTER: Any = None
_SCAN_ERRORS_COUNTER: Any = None

_INSTRUMENTATION_SCOPE = "skill_scanner"

# Populated lazily during setup_telemetry to match the service.version resource.
_INSTRUMENTATION_VERSION: str | None = None

# Regex: split on commas (and optional whitespace) that are followed by an OTLP header key.
# A key must start with a letter, contain only word chars or hyphens, and its '=' separator
# must NOT be immediately followed by another '=' (which would indicate base64 padding rather
# than a key=value separator).  This correctly preserves values like "Bearer abc,def==".
_HEADER_SPLIT_RE = re.compile(r",\s*(?=[a-zA-Z][\w-]*=(?!=))")

# ---------------------------------------------------------------------------
# Public configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class TelemetryConfig:
    """Runtime configuration for Skill Scanner telemetry.

    All fields map to the corresponding ``OTEL_*`` env vars and can be
    overridden programmatically when calling :func:`setup_telemetry`.

    Attributes:
        enabled: Master switch. When ``False`` the SDK is never initialised
            regardless of the other fields.
        service_name: ``service.name`` resource attribute reported to the
            backend.  Defaults to ``OTEL_SERVICE_NAME`` env var or
            ``"skill-scanner"``.
        otlp_endpoint: OTLP gRPC / HTTP endpoint.  Defaults to
            ``OTEL_EXPORTER_OTLP_ENDPOINT`` env var.
        otlp_headers: Extra HTTP headers for OTLP auth (e.g. Dash0 / Honeycomb
            ingestion keys).  Comma-separated ``key=value`` pairs.  Defaults to
            ``OTEL_EXPORTER_OTLP_HEADERS`` env var.
        resource_attributes: Additional ``key=value`` resource attributes
            appended to ``OTEL_RESOURCE_ATTRIBUTES``.
        export_logs: Whether to ship structured logs via OTLP (requires
            ``opentelemetry-exporter-otlp-proto-grpc`` ≥ 1.26).
        export_metrics: Whether to export metrics (default ``True``).
        export_traces: Whether to export traces (default ``True``).
    """

    enabled: bool = True
    service_name: str = field(default_factory=lambda: os.getenv("OTEL_SERVICE_NAME", "skill-scanner"))
    otlp_endpoint: str | None = field(default_factory=lambda: os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
    otlp_headers: str | None = field(default_factory=lambda: os.getenv("OTEL_EXPORTER_OTLP_HEADERS"))
    resource_attributes: dict[str, str] = field(default_factory=dict)
    export_logs: bool = True
    export_metrics: bool = True
    export_traces: bool = True


# ---------------------------------------------------------------------------
# SDK initialisation
# ---------------------------------------------------------------------------


def setup_telemetry(config: TelemetryConfig | None = None) -> bool:
    """Initialise the OpenTelemetry SDK with traces, metrics, and logs.

    This function is idempotent – calling it a second time with the SDK
    already initialised is a no-op and returns ``True``.

    Args:
        config: Optional :class:`TelemetryConfig`. When ``None``, values are
            read from the standard ``OTEL_*`` environment variables.

    Returns:
        ``True`` if telemetry was successfully initialised, ``False`` otherwise
        (SDK not installed, disabled by env var, or initialisation error).
    """
    global _ENABLED, _TRACER, _METER, _INSTRUMENTATION_VERSION  # noqa: PLW0603
    global _SCAN_DURATION_HISTOGRAM, _FINDINGS_COUNTER  # noqa: PLW0603
    global _ANALYZER_DURATION_HISTOGRAM, _SCANS_TOTAL_COUNTER, _SCAN_ERRORS_COUNTER  # noqa: PLW0603

    if _ENABLED:
        return True

    if config is None:
        config = TelemetryConfig()

    if not config.enabled:
        return False

    # Hard-disable via official env var
    if os.getenv("OTEL_SDK_DISABLED", "").lower() == "true":
        logger.debug("OpenTelemetry SDK disabled via OTEL_SDK_DISABLED=true")
        return False

    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import OTELResourceDetector, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.debug(
            "opentelemetry-sdk not installed. Run: pip install cisco-ai-skill-scanner[otel]. "
            "Telemetry will be disabled."
        )
        return False

    try:
        # Resolve version once so the tracer/meter scope matches the resource.
        if _INSTRUMENTATION_VERSION is None:
            _INSTRUMENTATION_VERSION = _get_package_version()

        # ---- Resource --------------------------------------------------------
        resource_attrs: dict[str, str] = {
            "service.name": config.service_name,
            "service.version": _INSTRUMENTATION_VERSION,
        }
        resource_attrs.update(config.resource_attributes)
        resource = Resource.create(resource_attrs)
        try:
            # Merge with auto-detected resource (host, process, etc.)
            resource = OTELResourceDetector().detect().merge(resource)
        except Exception:
            pass

        # ---- Traces ----------------------------------------------------------
        if config.export_traces:
            span_exporter = _build_span_exporter(config)
            tracer_provider = TracerProvider(resource=resource)
            if span_exporter:
                tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
            trace.set_tracer_provider(tracer_provider)
            _TRACER = trace.get_tracer(_INSTRUMENTATION_SCOPE, _INSTRUMENTATION_VERSION)

        # ---- Metrics ---------------------------------------------------------
        if config.export_metrics:
            metric_exporter = _build_metric_exporter(config)
            readers = []
            if metric_exporter:
                readers.append(PeriodicExportingMetricReader(metric_exporter))
            meter_provider = MeterProvider(resource=resource, metric_readers=readers)
            metrics.set_meter_provider(meter_provider)
            _METER = metrics.get_meter(_INSTRUMENTATION_SCOPE, _INSTRUMENTATION_VERSION)
            _create_metric_instruments()

        # ---- Logs ------------------------------------------------------------
        if config.export_logs:
            _setup_log_bridge(config, resource)

        _ENABLED = True
        logger.info(
            "OpenTelemetry enabled (service=%s, endpoint=%s)",
            config.service_name,
            config.otlp_endpoint or "<console>",
        )
        return True

    except Exception as exc:
        logger.warning("Failed to initialise OpenTelemetry: %s", exc, exc_info=True)
        return False


def shutdown_telemetry() -> None:
    """Flush all pending spans/metrics and shut down the SDK providers.

    Safe to call even when telemetry is disabled or the SDK is not installed.
    Typically called at process exit or at the end of a CLI command.
    """
    global _ENABLED, _TRACER, _METER  # noqa: PLW0603
    global _SCAN_DURATION_HISTOGRAM, _FINDINGS_COUNTER  # noqa: PLW0603
    global _ANALYZER_DURATION_HISTOGRAM, _SCANS_TOTAL_COUNTER, _SCAN_ERRORS_COUNTER  # noqa: PLW0603

    if not _ENABLED:
        return

    with contextlib.suppress(Exception):
        from opentelemetry import metrics, trace

        tp = trace.get_tracer_provider()
        # Flush buffered spans before shutdown to avoid data loss in short-lived CLI processes.
        if hasattr(tp, "force_flush"):
            tp.force_flush()
        if hasattr(tp, "shutdown"):
            tp.shutdown()

        mp = metrics.get_meter_provider()
        # Flush buffered metric records before shutdown.
        if hasattr(mp, "force_flush"):
            mp.force_flush()
        if hasattr(mp, "shutdown"):
            mp.shutdown()

    # Reset all globals so a subsequent setup_telemetry() can re-initialise cleanly.
    _ENABLED = False
    _TRACER = None
    _METER = None
    _SCAN_DURATION_HISTOGRAM = None
    _FINDINGS_COUNTER = None
    _ANALYZER_DURATION_HISTOGRAM = None
    _SCANS_TOTAL_COUNTER = None
    _SCAN_ERRORS_COUNTER = None
    logger.debug("OpenTelemetry shutdown complete")


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------


def is_enabled() -> bool:
    """Return ``True`` if the OpenTelemetry SDK has been successfully initialised."""
    return _ENABLED


def get_tracer() -> Any:
    """Return the global :class:`opentelemetry.trace.Tracer` instance.

    Returns a no-op tracer when telemetry is disabled.
    """
    if _ENABLED and _TRACER is not None:
        return _TRACER
    return _NoOpTracer()


def get_meter() -> Any:
    """Return the global :class:`opentelemetry.metrics.Meter` instance.

    Returns a no-op meter when telemetry is disabled.
    """
    if _ENABLED and _METER is not None:
        return _METER
    return _NoOpMeter()


def get_logger(name: str = _INSTRUMENTATION_SCOPE) -> logging.Logger:
    """Return a Python logger that is bridged to the OTel log pipeline.

    When OTel logs are disabled this is identical to ``logging.getLogger(name)``.
    """
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# High-level helpers used by the scanner
# ---------------------------------------------------------------------------


@contextmanager
def scan_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """Context manager that wraps an operation in an OpenTelemetry span.

    When telemetry is disabled this is a zero-overhead no-op::

        with scan_span("skill_scanner.scan_skill", {"skill.name": skill.name}) as span:
            ...  # your code here
            span.set_attribute("findings.count", len(findings))

    Args:
        name: Span name (dot-separated convention, e.g. ``skill_scanner.scan_skill``).
        attributes: Optional dict of span attributes set at span creation.

    Yields:
        The active :class:`opentelemetry.trace.Span` (or a no-op stub when
        telemetry is disabled).
    """
    if not _ENABLED or _TRACER is None:
        yield _NoOpSpan()
        return

    with _TRACER.start_as_current_span(name, attributes=attributes or {}) as span:
        try:
            yield span
        except Exception as exc:
            _record_exception(span, exc)
            raise


def record_scan_metrics(
    *,
    skill_name: str,
    duration_seconds: float,
    findings_count: int,
    findings_by_severity: dict[str, int],
    analyzers_used: list[str],
    is_safe: bool,
) -> None:
    """Record post-scan metric observations.

    This should be called once per completed skill scan with the final
    :class:`~skill_scanner.core.models.ScanResult` data.

    Args:
        skill_name: Human-readable skill name (used as a metric label).
        duration_seconds: Wall-clock scan time.
        findings_count: Total number of findings across all severities.
        findings_by_severity: ``{severity_label: count}`` dict.
        analyzers_used: Names of the analyzers that ran.
        is_safe: Whether the scan result was safe (no HIGH/CRITICAL findings).
    """
    if not _ENABLED:
        return

    common_attrs = {
        "skill.name": skill_name,
        "scan.is_safe": str(is_safe).lower(),
        "analyzers": ",".join(sorted(analyzers_used)),
    }

    if _SCAN_DURATION_HISTOGRAM is not None:
        _SCAN_DURATION_HISTOGRAM.record(duration_seconds, attributes=common_attrs)

    if _SCANS_TOTAL_COUNTER is not None:
        _SCANS_TOTAL_COUNTER.add(1, attributes=common_attrs)

    if _FINDINGS_COUNTER is not None:
        for severity, count in findings_by_severity.items():
            if count > 0:
                _FINDINGS_COUNTER.add(
                    count,
                    attributes={**common_attrs, "finding.severity": severity.upper()},
                )


def record_analyzer_duration(
    analyzer_name: str,
    duration_seconds: float,
    findings_count: int,
    skill_name: str = "",
) -> None:
    """Record per-analyzer timing and output metrics.

    Args:
        analyzer_name: Name of the analyzer (e.g. ``"static"``, ``"llm"``).
        duration_seconds: Wall-clock time the analyzer took.
        findings_count: Number of findings produced by this analyzer.
        skill_name: Optional skill name for additional label context.
    """
    if not _ENABLED or _ANALYZER_DURATION_HISTOGRAM is None:
        return

    _ANALYZER_DURATION_HISTOGRAM.record(
        duration_seconds,
        attributes={
            "analyzer.name": analyzer_name,
            "skill.name": skill_name,
            "findings.count": findings_count,
        },
    )


def record_scan_error(
    *,
    skill_directory: str,
    error_type: str = "unknown",
    reason: str = "",
) -> None:
    """Increment the scan-error counter for a skipped or failed skill.

    Args:
        skill_directory: Path to the skill that was skipped / errored.
        error_type: Short label for the error category (e.g. ``"load_error"``).
        reason: Human-readable reason string for diagnostic context.
    """
    if not _ENABLED or _SCAN_ERRORS_COUNTER is None:
        return

    _SCAN_ERRORS_COUNTER.add(
        1,
        attributes={
            "skill.directory": skill_directory,
            "error.type": error_type,
            "error.reason": reason[:256],
        },
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_package_version() -> str:
    try:
        from skill_scanner import __version__

        return __version__
    except Exception:
        return "unknown"


def _build_span_exporter(config: TelemetryConfig) -> Any:
    """Build an OTLP span exporter, falling back to a console exporter."""
    if config.otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

            headers = _parse_headers(config.otlp_headers)
            return OTLPSpanExporter(endpoint=config.otlp_endpoint, headers=headers)
        except ImportError:
            pass
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            headers = _parse_headers(config.otlp_headers)
            return OTLPSpanExporter(endpoint=f"{config.otlp_endpoint}/v1/traces", headers=headers)
        except ImportError:
            logger.warning(
                "OTLP trace exporter not available. "
                "Install opentelemetry-exporter-otlp-proto-grpc or -http."
            )
            return None

    # Fall back to console exporter so developers see spans in their terminal
    try:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        return ConsoleSpanExporter()
    except ImportError:
        return None


def _build_metric_exporter(config: TelemetryConfig) -> Any:
    """Build an OTLP metric exporter, falling back to a console exporter."""
    if config.otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

            headers = _parse_headers(config.otlp_headers)
            return OTLPMetricExporter(endpoint=config.otlp_endpoint, headers=headers)
        except ImportError:
            pass
        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

            headers = _parse_headers(config.otlp_headers)
            return OTLPMetricExporter(
                endpoint=f"{config.otlp_endpoint}/v1/metrics",
                headers=headers,
            )
        except ImportError:
            logger.warning(
                "OTLP metric exporter not available. "
                "Install opentelemetry-exporter-otlp-proto-grpc or -http."
            )
            return None

    try:
        from opentelemetry.sdk.metrics.export import ConsoleMetricExporter

        return ConsoleMetricExporter()
    except ImportError:
        return None


def _setup_log_bridge(config: TelemetryConfig, resource: Any) -> None:
    """Bridge Python's logging to the OTel log pipeline."""
    try:
        from opentelemetry._logs import set_logger_provider
        from opentelemetry.sdk._logs import LoggerProvider
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, SimpleLogRecordProcessor
    except ImportError:
        logger.debug("OTel log bridge not available – skipping log export")
        return

    log_provider = None
    try:
        log_provider = LoggerProvider(resource=resource)

        if config.otlp_endpoint:
            log_exporter = _build_log_exporter(config)
            if log_exporter:
                log_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        else:
            from opentelemetry.sdk._logs.export import ConsoleLogExporter

            log_provider.add_log_record_processor(SimpleLogRecordProcessor(ConsoleLogExporter()))

        set_logger_provider(log_provider)

        # Attach OTel handler to the skill_scanner logger hierarchy
        try:
            from opentelemetry.sdk._logs import LoggingHandler  # SDK ≥ 1.25

            handler = LoggingHandler(level=logging.DEBUG, logger_provider=log_provider)
            logging.getLogger("skill_scanner").addHandler(handler)
        except ImportError:
            pass

    except Exception as exc:
        logger.debug("Could not set up OTel log bridge: %s", exc)


def _build_log_exporter(config: TelemetryConfig) -> Any:
    if not config.otlp_endpoint:
        return None
    try:
        from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

        headers = _parse_headers(config.otlp_headers)
        return OTLPLogExporter(endpoint=config.otlp_endpoint, headers=headers)
    except ImportError:
        pass
    try:
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

        headers = _parse_headers(config.otlp_headers)
        return OTLPLogExporter(
            endpoint=f"{config.otlp_endpoint}/v1/logs",
            headers=headers,
        )
    except ImportError:
        return None


def _parse_headers(raw: str | None) -> dict[str, str]:
    """Parse ``key=value,key2=value2`` header string into a dict.

    Splits only on commas that are immediately followed by a header key
    (word chars or hyphens before ``=``), so base64 values that contain
    commas (e.g. ``Authorization=Bearer abc,def==``) are preserved intact.
    """
    if not raw:
        return {}
    headers: dict[str, str] = {}
    for pair in _HEADER_SPLIT_RE.split(raw):
        pair = pair.strip()
        if "=" in pair:
            k, _, v = pair.partition("=")
            headers[k.strip()] = v.strip()
    return headers


def _create_metric_instruments() -> None:
    """Create all metric instruments on the global meter."""
    global _SCAN_DURATION_HISTOGRAM, _FINDINGS_COUNTER  # noqa: PLW0603
    global _ANALYZER_DURATION_HISTOGRAM, _SCANS_TOTAL_COUNTER, _SCAN_ERRORS_COUNTER  # noqa: PLW0603

    if _METER is None:
        return

    # Explicit bucket boundaries produce more useful percentiles for scan workloads.
    _scan_duration_boundaries = [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300]
    _analyzer_duration_boundaries = [0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60]

    _SCAN_DURATION_HISTOGRAM = _METER.create_histogram(
        name="skill_scanner.scan.duration",
        unit="s",
        description="Wall-clock time taken to scan a single skill, in seconds.",
        explicit_bucket_boundaries=_scan_duration_boundaries,
    )
    _SCANS_TOTAL_COUNTER = _METER.create_counter(
        name="skill_scanner.scans.total",
        unit="{scan}",
        description="Total number of skill scans completed.",
    )
    _FINDINGS_COUNTER = _METER.create_counter(
        name="skill_scanner.findings.total",
        unit="{finding}",
        description="Total number of security findings produced, broken down by severity.",
    )
    _ANALYZER_DURATION_HISTOGRAM = _METER.create_histogram(
        name="skill_scanner.analyzer.duration",
        unit="s",
        description="Wall-clock time taken by each individual analyzer per skill.",
        explicit_bucket_boundaries=_analyzer_duration_boundaries,
    )
    _SCAN_ERRORS_COUNTER = _METER.create_counter(
        name="skill_scanner.scan.errors",
        unit="{error}",
        description="Total number of skill scan errors or skipped skills.",
    )


def _record_exception(span: Any, exc: Exception) -> None:
    """Record an exception on the given span and set error status."""
    with contextlib.suppress(Exception):
        from opentelemetry.trace import StatusCode

        span.record_exception(exc)
        span.set_status(StatusCode.ERROR, str(exc))


# ---------------------------------------------------------------------------
# No-op stubs (used when OTel is disabled or not installed)
# ---------------------------------------------------------------------------


class _NoOpSpan:
    """Minimal no-op span that accepts attribute mutations silently."""

    def set_attribute(self, _key: str, _value: Any) -> None:  # noqa: D102
        pass

    def set_status(self, *_args: Any, **_kwargs: Any) -> None:  # noqa: D102
        pass

    def add_event(self, _name: str, attributes: dict | None = None, **_kwargs: Any) -> None:  # noqa: D102
        pass

    def record_exception(self, _exc: Exception) -> None:  # noqa: D102
        pass


class _NoOpTracer:
    """Minimal no-op tracer."""

    @contextmanager
    def start_as_current_span(self, _name: str, **_kwargs: Any) -> Generator[_NoOpSpan, None, None]:
        yield _NoOpSpan()


class _NoOpMeter:
    """Minimal no-op meter."""

    def create_histogram(self, *_args: Any, **_kwargs: Any) -> _NoOpInstrument:
        return _NoOpInstrument()

    def create_counter(self, *_args: Any, **_kwargs: Any) -> _NoOpInstrument:
        return _NoOpInstrument()

    def create_up_down_counter(self, *_args: Any, **_kwargs: Any) -> _NoOpInstrument:
        return _NoOpInstrument()

    def create_observable_gauge(self, *_args: Any, **_kwargs: Any) -> _NoOpInstrument:
        return _NoOpInstrument()


class _NoOpInstrument:
    """No-op metric instrument."""

    def record(self, _value: float, _attributes: dict | None = None) -> None:  # noqa: D102
        pass

    def add(self, _value: int, _attributes: dict | None = None) -> None:  # noqa: D102
        pass
