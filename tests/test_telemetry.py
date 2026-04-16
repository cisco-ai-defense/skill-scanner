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

"""
Tests for the OpenTelemetry telemetry module.

All tests are designed to run without the opentelemetry-sdk installed (the
module must degrade gracefully to no-ops) and, when the SDK *is* available,
verify that spans and metrics are produced correctly.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

import skill_scanner.telemetry.telemetry as _tel_mod
from skill_scanner.telemetry import (
    TelemetryConfig,
    get_logger,
    get_meter,
    get_tracer,
    is_enabled,
    record_analyzer_duration,
    record_scan_error,
    record_scan_metrics,
    scan_span,
    setup_telemetry,
    shutdown_telemetry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sdk_available() -> bool:
    """Return True when the opentelemetry-sdk package can be imported."""
    try:
        import opentelemetry.sdk.trace  # noqa: F401

        return True
    except ImportError:
        return False


def _reset_telemetry():
    """Reset global telemetry state between tests, including SDK global providers."""
    _tel_mod._ENABLED = False
    _tel_mod._TRACER = None
    _tel_mod._METER = None
    _tel_mod._SCAN_DURATION_HISTOGRAM = None
    _tel_mod._FINDINGS_COUNTER = None
    _tel_mod._ANALYZER_DURATION_HISTOGRAM = None
    _tel_mod._SCANS_TOTAL_COUNTER = None
    _tel_mod._SCAN_ERRORS_COUNTER = None

    # Reset the SDK's global trace/meter providers so state doesn't leak across
    # tests when the opentelemetry-sdk is installed.
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.trace import TracerProvider

        trace.set_tracer_provider(TracerProvider())
        metrics.set_meter_provider(MeterProvider())
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_telemetry_state():
    """Ensure each test starts with a clean telemetry state."""
    _reset_telemetry()
    yield
    _reset_telemetry()


# ---------------------------------------------------------------------------
# No-op stubs (SDK absent or disabled)
# ---------------------------------------------------------------------------


class TestNoOpBehaviorWhenDisabled:
    """When telemetry is not initialised, all public calls must be no-ops."""

    def test_is_enabled_false_by_default(self):
        assert is_enabled() is False

    def test_get_tracer_returns_noop(self):
        tracer = get_tracer()
        assert tracer is not None
        # Must not raise when used as a context manager
        with tracer.start_as_current_span("test.span") as span:
            span.set_attribute("key", "value")

    def test_get_meter_returns_noop(self):
        meter = get_meter()
        assert meter is not None
        hist = meter.create_histogram("test.histogram", unit="s", description="test")
        hist.record(1.0, {"label": "value"})
        counter = meter.create_counter("test.counter")
        counter.add(1, {"label": "value"})

    def test_get_logger_returns_python_logger(self):
        log = get_logger("skill_scanner.test")
        import logging

        assert isinstance(log, logging.Logger)
        assert log.name == "skill_scanner.test"

    def test_scan_span_is_noop(self):
        """scan_span must yield a no-op span without raising."""
        with scan_span("skill_scanner.scan_skill", {"skill.name": "test-skill"}) as span:
            span.set_attribute("findings.total", 0)
            span.set_attribute("scan.is_safe", True)

    def test_noop_span_add_event_keyword_args(self):
        """_NoOpSpan.add_event must accept the full OTel signature without raising."""
        with scan_span("test.span") as span:
            # Must not raise even with optional keyword args matching the real OTel signature.
            span.add_event("my_event", attributes={"key": "val"})
            span.add_event("other_event", attributes=None, timestamp=12345)

    def test_record_scan_metrics_noop(self):
        """record_scan_metrics must silently do nothing when OTel is off."""
        record_scan_metrics(
            skill_name="test-skill",
            duration_seconds=0.5,
            findings_count=0,
            findings_by_severity={"HIGH": 0, "MEDIUM": 0},
            analyzers_used=["static"],
            is_safe=True,
        )

    def test_record_analyzer_duration_noop(self):
        """record_analyzer_duration must silently do nothing when OTel is off."""
        record_analyzer_duration(
            analyzer_name="static",
            duration_seconds=0.1,
            findings_count=2,
            skill_name="my-skill",
        )

    def test_record_scan_error_noop(self):
        """record_scan_error must silently do nothing when OTel is off."""
        record_scan_error(
            skill_directory="/some/skill",
            error_type="load_error",
            reason="SKILL.md not found",
        )

    def test_shutdown_telemetry_noop(self):
        """shutdown_telemetry must not raise when OTel is not initialised."""
        shutdown_telemetry()


# ---------------------------------------------------------------------------
# TelemetryConfig
# ---------------------------------------------------------------------------


class TestTelemetryConfig:
    def test_defaults_read_from_env(self, monkeypatch):
        monkeypatch.setenv("OTEL_SERVICE_NAME", "my-scanner")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer tok")

        cfg = TelemetryConfig()

        assert cfg.service_name == "my-scanner"
        assert cfg.otlp_endpoint == "http://localhost:4317"
        assert cfg.otlp_headers == "Authorization=Bearer tok"

    def test_disabled_config_prevents_setup(self):
        cfg = TelemetryConfig(enabled=False)
        result = setup_telemetry(cfg)
        assert result is False
        assert is_enabled() is False

    def test_otel_sdk_disabled_env_prevents_setup(self, monkeypatch):
        monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
        cfg = TelemetryConfig(enabled=True)
        result = setup_telemetry(cfg)
        assert result is False
        assert is_enabled() is False

    def test_resource_attributes_field(self):
        cfg = TelemetryConfig(resource_attributes={"deployment.environment": "test"})
        assert cfg.resource_attributes["deployment.environment"] == "test"


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


class TestHeaderParsing:
    def test_empty_string(self):
        assert _tel_mod._parse_headers(None) == {}
        assert _tel_mod._parse_headers("") == {}

    def test_single_pair(self):
        assert _tel_mod._parse_headers("Authorization=Bearer tok") == {
            "Authorization": "Bearer tok"
        }

    def test_multiple_pairs(self):
        result = _tel_mod._parse_headers("k1=v1, k2=v2")
        assert result == {"k1": "v1", "k2": "v2"}

    def test_value_with_equals(self):
        result = _tel_mod._parse_headers("x-key=abc=def")
        assert result["x-key"] == "abc=def"

    def test_base64_value_with_comma_not_split(self):
        """Base64 values that contain commas must not be split into separate pairs."""
        raw = "Authorization=Bearer abc,def==,x-tenant=my-org"
        result = _tel_mod._parse_headers(raw)
        assert result["Authorization"] == "Bearer abc,def=="
        assert result["x-tenant"] == "my-org"

    def test_single_base64_value(self):
        """A standalone base64 header value with an embedded comma is preserved."""
        raw = "X-Token=dGVzdA==,dGVzdA=="
        result = _tel_mod._parse_headers(raw)
        assert result["X-Token"] == "dGVzdA==,dGVzdA=="


# ---------------------------------------------------------------------------
# setup_telemetry with SDK available (mocked)
# ---------------------------------------------------------------------------


class TestSetupWithSDK:
    """Verify setup_telemetry when the OTel SDK is mocked as available."""

    def _make_sdk_mocks(self):
        """Return a dict of mock modules that stand in for the OTel SDK."""
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        mock_provider = MagicMock()
        mock_meter_provider = MagicMock()
        mock_resource = MagicMock()
        mock_resource.create = MagicMock(return_value=mock_resource)
        mock_resource.merge = MagicMock(return_value=mock_resource)

        mock_trace = MagicMock()
        mock_trace.get_tracer.return_value = mock_tracer

        mock_metrics = MagicMock()
        mock_metrics.get_meter.return_value = mock_meter

        return {
            "opentelemetry.sdk.resources": MagicMock(
                Resource=MagicMock(create=MagicMock(return_value=mock_resource)),
                OTELResourceDetector=MagicMock(
                    return_value=MagicMock(detect=MagicMock(return_value=mock_resource))
                ),
            ),
            "mock_tracer": mock_tracer,
            "mock_meter": mock_meter,
            "mock_provider": mock_provider,
            "mock_meter_provider": mock_meter_provider,
            "mock_resource": mock_resource,
            "mock_trace": mock_trace,
            "mock_metrics": mock_metrics,
        }

    def test_idempotent_setup(self):
        """Calling setup_telemetry twice must not re-initialise."""
        _tel_mod._ENABLED = True
        result = setup_telemetry(TelemetryConfig(enabled=True))
        assert result is True  # short-circuits on second call
        _tel_mod._ENABLED = False

    def test_import_error_returns_false(self, monkeypatch):
        """When opentelemetry-sdk is absent, setup must return False gracefully."""

        def _raise_import(*_args, **_kwargs):
            raise ImportError("opentelemetry not installed")

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        import builtins

        real_import = builtins.__import__

        def patched_import(name, *args, **kwargs):
            if name.startswith("opentelemetry"):
                raise ImportError("simulated missing SDK")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", patched_import)
        _reset_telemetry()
        result = setup_telemetry(TelemetryConfig(enabled=True))
        assert result is False
        assert is_enabled() is False


# ---------------------------------------------------------------------------
# shutdown_telemetry resets globals
# ---------------------------------------------------------------------------


class TestShutdownTelemetry:
    def test_shutdown_resets_enabled_flag(self):
        """After shutdown, is_enabled() must return False."""
        _tel_mod._ENABLED = True
        shutdown_telemetry()
        assert is_enabled() is False

    def test_shutdown_resets_tracer_and_meter(self):
        """After shutdown, _TRACER and _METER must be None so re-init can succeed."""
        _tel_mod._ENABLED = True
        _tel_mod._TRACER = MagicMock()
        _tel_mod._METER = MagicMock()
        shutdown_telemetry()
        assert _tel_mod._TRACER is None
        assert _tel_mod._METER is None

    def test_shutdown_resets_metric_instruments(self):
        """All metric instrument globals must be cleared on shutdown."""
        _tel_mod._ENABLED = True
        _tel_mod._SCAN_DURATION_HISTOGRAM = MagicMock()
        _tel_mod._FINDINGS_COUNTER = MagicMock()
        _tel_mod._ANALYZER_DURATION_HISTOGRAM = MagicMock()
        _tel_mod._SCANS_TOTAL_COUNTER = MagicMock()
        _tel_mod._SCAN_ERRORS_COUNTER = MagicMock()
        shutdown_telemetry()
        assert _tel_mod._SCAN_DURATION_HISTOGRAM is None
        assert _tel_mod._FINDINGS_COUNTER is None
        assert _tel_mod._ANALYZER_DURATION_HISTOGRAM is None
        assert _tel_mod._SCANS_TOTAL_COUNTER is None
        assert _tel_mod._SCAN_ERRORS_COUNTER is None

    @pytest.mark.skipif(not _sdk_available(), reason="opentelemetry-sdk not installed")
    def test_shutdown_calls_provider_force_flush_and_shutdown(self):
        """shutdown_telemetry must flush then shut down the SDK providers."""
        from opentelemetry import metrics, trace

        mock_tp = MagicMock()
        mock_mp = MagicMock()

        _tel_mod._ENABLED = True

        # Patch the already-imported trace/metrics modules directly so the
        # get_tracer_provider / get_meter_provider calls inside the
        # contextlib.suppress block see our mock objects.
        with (
            patch.object(trace, "get_tracer_provider", return_value=mock_tp),
            patch.object(metrics, "get_meter_provider", return_value=mock_mp),
        ):
            shutdown_telemetry()

        # force_flush before shutdown ensures buffered data is exported.
        mock_tp.force_flush.assert_called_once()
        mock_tp.shutdown.assert_called_once()
        mock_mp.force_flush.assert_called_once()
        mock_mp.shutdown.assert_called_once()


# ---------------------------------------------------------------------------
# record_analyzer_duration
# ---------------------------------------------------------------------------


class TestRecordAnalyzerDuration:
    def test_noop_when_disabled(self):
        """record_analyzer_duration must be silent when telemetry is off."""
        record_analyzer_duration("static", 0.5, 3, "my-skill")

    def test_records_when_instrument_available(self):
        """When the histogram instrument is set, record() must be called."""
        mock_hist = MagicMock()
        _tel_mod._ENABLED = True
        _tel_mod._ANALYZER_DURATION_HISTOGRAM = mock_hist

        record_analyzer_duration("llm", 2.3, 5, "skill-x")

        mock_hist.record.assert_called_once_with(
            2.3,
            attributes={
                "analyzer.name": "llm",
                "skill.name": "skill-x",
                "findings.count": 5,
            },
        )
        _tel_mod._ENABLED = False
        _tel_mod._ANALYZER_DURATION_HISTOGRAM = None


# ---------------------------------------------------------------------------
# scan_span exception recording
# ---------------------------------------------------------------------------


class TestScanSpanExceptionHandling:
    def test_exception_propagates_from_scan_span(self):
        """Exceptions inside scan_span must still propagate to the caller."""
        with pytest.raises(ValueError, match="boom"):
            with scan_span("test.span"):
                raise ValueError("boom")

    def test_noop_span_exception_propagates(self):
        """Same behaviour when OTel is disabled (no-op path)."""
        assert not is_enabled()
        with pytest.raises(RuntimeError, match="test error"):
            with scan_span("test.span"):
                raise RuntimeError("test error")


# ---------------------------------------------------------------------------
# record_scan_metrics (no-op when disabled, smoke test)
# ---------------------------------------------------------------------------


class TestRecordScanMetrics:
    def test_all_severities(self):
        """record_scan_metrics must accept all severity labels without raising."""
        record_scan_metrics(
            skill_name="my-skill",
            duration_seconds=1.23,
            findings_count=5,
            findings_by_severity={
                "CRITICAL": 1,
                "HIGH": 2,
                "MEDIUM": 1,
                "LOW": 1,
                "INFO": 0,
            },
            analyzers_used=["static", "behavioral", "llm"],
            is_safe=False,
        )

    def test_zero_findings(self):
        record_scan_metrics(
            skill_name="clean-skill",
            duration_seconds=0.1,
            findings_count=0,
            findings_by_severity={},
            analyzers_used=["static"],
            is_safe=True,
        )


# ---------------------------------------------------------------------------
# Integration: scanner produces spans without crashing (no SDK required)
# ---------------------------------------------------------------------------


class TestScannerIntegration:
    """Verify that the scanner instrumentation does not break scans."""

    def test_scan_skill_works_without_otel(self, tmp_path):
        """A real scan must succeed even when OTel is not enabled."""
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text(
            "---\nname: test-skill\ndescription: A test skill for unit testing.\n---\n\n"
            "# Instructions\nThis skill does nothing harmful.\n"
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner()
        result = scanner.scan_skill(skill_dir)

        assert result.skill_name == "test-skill"
        assert result.scan_duration_seconds >= 0

    def test_scan_directory_works_without_otel(self, tmp_path):
        """scan_directory must succeed even without OTel."""
        skills_root = tmp_path / "skills"
        skills_root.mkdir()
        for i in range(2):
            sd = skills_root / f"skill-{i}"
            sd.mkdir()
            (sd / "SKILL.md").write_text(
                f"---\nname: skill-{i}\ndescription: Test skill number {i}.\n---\n\n# Instr\n"
            )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner()
        report = scanner.scan_directory(skills_root, recursive=False)
        assert report.total_skills_scanned == 2


# ---------------------------------------------------------------------------
# SDK-available: verify real spans are created and exported
# ---------------------------------------------------------------------------


class TestSpanCreationWithSDK:
    """Verify that scan_span actually produces exportable spans when the SDK is installed."""

    @pytest.mark.skipif(
        not _sdk_available(),
        reason="opentelemetry-sdk not installed",
    )
    def test_scan_span_creates_span_with_sdk(self, tmp_path):
        """scan_span must emit a real span with the correct name and attributes."""
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        _tel_mod._TRACER = provider.get_tracer(_tel_mod._INSTRUMENTATION_SCOPE)
        _tel_mod._ENABLED = True

        with scan_span("skill_scanner.scan_skill", {"skill.name": "sdk-test-skill"}) as span:
            span.set_attribute("findings.total", 0)

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "skill_scanner.scan_skill"
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("skill.name") == "sdk-test-skill"

        _tel_mod._ENABLED = False
        _tel_mod._TRACER = None

    @pytest.mark.skipif(
        not _sdk_available(),
        reason="opentelemetry-sdk not installed",
    )
    def test_scan_span_records_exception_status(self, tmp_path):
        """When an exception is raised inside scan_span, the span status must be ERROR."""
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.trace import StatusCode

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        _tel_mod._TRACER = provider.get_tracer(_tel_mod._INSTRUMENTATION_SCOPE)
        _tel_mod._ENABLED = True

        with pytest.raises(ValueError):
            with scan_span("skill_scanner.test_error"):
                raise ValueError("test failure")

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].status.status_code == StatusCode.ERROR

        _tel_mod._ENABLED = False
        _tel_mod._TRACER = None
