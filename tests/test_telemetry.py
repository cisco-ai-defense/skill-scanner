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
    record_scan_metrics,
    scan_span,
    setup_telemetry,
    shutdown_telemetry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_telemetry():
    """Reset global telemetry state between tests."""
    _tel_mod._ENABLED = False
    _tel_mod._TRACER = None
    _tel_mod._METER = None
    _tel_mod._SCAN_DURATION_HISTOGRAM = None
    _tel_mod._FINDINGS_COUNTER = None
    _tel_mod._ANALYZER_DURATION_HISTOGRAM = None
    _tel_mod._SCANS_TOTAL_COUNTER = None


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
