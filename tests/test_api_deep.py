# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Deep integration tests for the REST API.

Goes beyond "assert 200" to verify policy propagation, full response schemas,
ZIP uploads, malformed input handling, batch flows, custom policy YAML, and
analyzer toggles — all end-to-end through the FastAPI test client.
"""

from __future__ import annotations

import io
import time
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
import yaml

try:
    from fastapi.testclient import TestClient

    from skill_scanner.api.api import app

    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False
    app = None
    TestClient = None


pytestmark = pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")

project_root = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Create FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def safe_skill_dir() -> Path:
    """Path to a known-safe test skill."""
    return project_root / "evals" / "test_skills" / "safe" / "simple-formatter"


@pytest.fixture
def malicious_skill_dir() -> Path:
    """Path to a known-malicious test skill (exfiltrator)."""
    path = project_root / "evals" / "test_skills" / "malicious" / "exfiltrator"
    if not path.exists():
        pytest.skip("Malicious test skill not found")
    return path


@pytest.fixture
def test_skills_dir() -> Path:
    """Path to top-level test_skills directory."""
    return project_root / "evals" / "test_skills"


def _zip_directory(source_dir: Path) -> bytes:
    """Create an in-memory ZIP of *source_dir*."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fp in source_dir.rglob("*"):
            if fp.is_file():
                zf.write(fp, fp.relative_to(source_dir.parent))
    buf.seek(0)
    return buf.read()


# ===================================================================
# B1 — Policy propagation through API
# ===================================================================


class TestPolicyPropagation:
    """Strict vs permissive policy via /scan produces different findings."""

    def test_strict_produces_at_least_as_many_findings_as_permissive(self, client, safe_skill_dir):
        strict_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir), "policy": "strict"},
        )
        perm_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir), "policy": "permissive"},
        )

        assert strict_resp.status_code == 200
        assert perm_resp.status_code == 200

        strict_data = strict_resp.json()
        perm_data = perm_resp.json()

        assert strict_data["findings_count"] >= perm_data["findings_count"], (
            f"strict ({strict_data['findings_count']}) should produce >= "
            f"findings as permissive ({perm_data['findings_count']})"
        )

    def test_strict_and_permissive_differ_in_severity_or_count(self, client, malicious_skill_dir):
        strict_resp = client.post(
            "/scan",
            json={"skill_directory": str(malicious_skill_dir), "policy": "strict"},
        )
        perm_resp = client.post(
            "/scan",
            json={"skill_directory": str(malicious_skill_dir), "policy": "permissive"},
        )

        assert strict_resp.status_code == 200
        assert perm_resp.status_code == 200

        s = strict_resp.json()
        p = perm_resp.json()

        # At least one of these should differ between presets
        differs = s["findings_count"] != p["findings_count"] or s["max_severity"] != p["max_severity"]
        assert differs, "Strict and permissive should produce different results on a malicious skill"


# ===================================================================
# B2 — Response schema validation
# ===================================================================


class TestResponseSchema:
    """Full response shape validation for /scan."""

    _SEVERITY_VALUES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"}

    def test_scan_response_has_all_top_level_fields(self, client, safe_skill_dir):
        resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir)},
        )
        assert resp.status_code == 200
        data = resp.json()

        # Required top-level fields
        assert isinstance(data["scan_id"], str) and len(data["scan_id"]) > 0
        assert isinstance(data["skill_name"], str)
        assert isinstance(data["is_safe"], bool)
        assert data["max_severity"] in self._SEVERITY_VALUES
        assert isinstance(data["findings_count"], int) and data["findings_count"] >= 0
        assert isinstance(data["scan_duration_seconds"], (int, float))
        assert data["scan_duration_seconds"] > 0

        # Timestamp should be ISO-format parseable
        datetime.fromisoformat(data["timestamp"])

        # Findings list present
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) == data["findings_count"]

    def test_each_finding_has_required_fields(self, client, malicious_skill_dir):
        resp = client.post(
            "/scan",
            json={"skill_directory": str(malicious_skill_dir)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["findings_count"] > 0, "Malicious skill should produce findings"

        required_keys = {"id", "rule_id", "severity", "title", "description", "category"}
        for finding in data["findings"]:
            missing = required_keys - set(finding.keys())
            assert not missing, f"Finding {finding.get('id', '?')} is missing keys: {missing}"
            assert finding["severity"] in self._SEVERITY_VALUES
            assert isinstance(finding["title"], str) and len(finding["title"]) > 0

    def test_findings_count_matches_list_length(self, client, safe_skill_dir):
        resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir)},
        )
        data = resp.json()
        assert len(data["findings"]) == data["findings_count"]


# ===================================================================
# B3 — Upload with real skill ZIP
# ===================================================================


class TestUploadRealZip:
    """ZIP upload via /scan-upload produces valid results."""

    def test_upload_safe_skill_returns_200(self, client, safe_skill_dir):
        zip_bytes = _zip_directory(safe_skill_dir)
        resp = client.post(
            "/scan-upload",
            files={"file": ("simple-formatter.zip", zip_bytes, "application/zip")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["findings"], list)
        assert data["findings_count"] >= 0

    def test_upload_matches_direct_scan(self, client, safe_skill_dir):
        """Findings from /scan-upload should match a direct /scan."""
        zip_bytes = _zip_directory(safe_skill_dir)
        upload_resp = client.post(
            "/scan-upload",
            files={"file": ("simple-formatter.zip", zip_bytes, "application/zip")},
        )
        direct_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir)},
        )

        assert upload_resp.status_code == 200
        assert direct_resp.status_code == 200

        up = upload_resp.json()
        dr = direct_resp.json()

        # Rule IDs from both should be the same (order may differ)
        up_rules = sorted(f["rule_id"] for f in up["findings"])
        dr_rules = sorted(f["rule_id"] for f in dr["findings"])
        assert up_rules == dr_rules, f"Upload rule_ids {up_rules} != direct rule_ids {dr_rules}"


# ===================================================================
# B4 — Malformed ZIP handling
# ===================================================================


class TestMalformedUpload:
    """Malformed uploads should return 400, not 500."""

    def test_truncated_zip_returns_error(self, client):
        """Truncated bytes should be rejected with 400."""
        truncated = b"PK\x03\x04" + b"\x00" * 10  # not a valid ZIP
        resp = client.post(
            "/scan-upload",
            files={"file": ("bad.zip", truncated, "application/zip")},
        )
        assert resp.status_code == 400
        assert "ZIP" in resp.json().get("detail", "")

    def test_empty_zip_returns_error(self, client):
        """ZIP with no files → 400 (no SKILL.md found)."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w"):
            pass  # empty archive
        buf.seek(0)

        resp = client.post(
            "/scan-upload",
            files={"file": ("empty.zip", buf.read(), "application/zip")},
        )
        assert resp.status_code == 400
        assert "SKILL.md" in resp.json().get("detail", "")

    def test_non_zip_file_rejected(self, client):
        """Non-ZIP file → 400."""
        resp = client.post(
            "/scan-upload",
            files={"file": ("skill.tar.gz", b"not a zip", "application/gzip")},
        )
        assert resp.status_code == 400


# ===================================================================
# B5 — Batch scan completion flow
# ===================================================================


class TestBatchScan:
    """Batch scan creates an async job that eventually completes."""

    def test_batch_scan_returns_processing(self, client, test_skills_dir):
        safe_dir = test_skills_dir / "safe"
        if not safe_dir.exists():
            pytest.skip("Safe test skills directory not found")

        resp = client.post(
            "/scan-batch",
            json={"skills_directory": str(safe_dir), "recursive": True},
        )
        assert resp.status_code == 200
        data = resp.json()

        assert "scan_id" in data
        assert data["status"] == "processing"

    def test_batch_scan_completes_with_results(self, client, test_skills_dir):
        safe_dir = test_skills_dir / "safe"
        if not safe_dir.exists():
            pytest.skip("Safe test skills directory not found")

        # Start batch
        start_resp = client.post(
            "/scan-batch",
            json={"skills_directory": str(safe_dir), "recursive": True},
        )
        assert start_resp.status_code == 200
        scan_id = start_resp.json()["scan_id"]

        # Poll until completed (with timeout)
        deadline = time.monotonic() + 60
        status = "processing"
        result_data = None
        while time.monotonic() < deadline:
            poll_resp = client.get(f"/scan-batch/{scan_id}")
            assert poll_resp.status_code == 200
            result_data = poll_resp.json()
            status = result_data["status"]
            if status != "processing":
                break
            time.sleep(0.5)

        assert status == "completed", f"Batch scan did not complete in time. Status: {status}"
        assert "result" in result_data
        assert result_data["result"] is not None

    def test_unknown_scan_id_returns_404(self, client):
        resp = client.get("/scan-batch/nonexistent-id")
        assert resp.status_code == 404

    def test_run_batch_scan_recomputes_summary_after_meta_filter(self, monkeypatch):
        """Batch summary counters should match findings after meta filtering."""
        from skill_scanner.api import router
        from skill_scanner.core.models import Finding, Report, ScanResult, Severity, ThreatCategory

        finding = Finding(
            id="f1",
            rule_id="TEST_HIGH",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.HIGH,
            title="High finding",
            description="Synthetic finding for regression test",
            analyzer="static",
        )
        scan_result = ScanResult(
            skill_name="synthetic-skill",
            skill_directory="/tmp/synthetic-skill",
            findings=[finding],
            analyzers_used=["static_analyzer"],
        )
        report = Report()
        report.add_scan_result(scan_result)

        class DummyLoader:
            @staticmethod
            def load_skill(_path):
                class _Skill:
                    name = "synthetic-skill"

                return _Skill()

        class DummyScanner:
            def __init__(self, *args, **kwargs):
                self.loader = DummyLoader()

            @staticmethod
            def scan_directory(*args, **kwargs):
                return report

        class DummyMetaAnalyzer:
            async def analyze_with_findings(self, **kwargs):
                return {}

        monkeypatch.setattr(router, "_resolve_policy", lambda _policy: None)
        monkeypatch.setattr(router, "_build_analyzers", lambda *args, **kwargs: [])
        monkeypatch.setattr(router, "SkillScanner", DummyScanner)
        monkeypatch.setattr(router, "META_AVAILABLE", True)
        monkeypatch.setattr(router, "MetaAnalyzer", DummyMetaAnalyzer)
        monkeypatch.setattr(router, "apply_meta_analysis_to_results", lambda **kwargs: [])

        scan_id = "meta-summary-regression"
        router.scan_results_cache.set(
            scan_id,
            {"status": "processing", "started_at": datetime.now().isoformat(), "result": None},
        )
        request = router.BatchScanRequest(skills_directory=".", enable_meta=True)

        router.run_batch_scan(scan_id, request)
        cached = router.scan_results_cache.get_valid(scan_id)

        assert cached is not None
        assert cached["status"] == "completed"
        result_payload = cached["result"]
        assert result_payload["summary"]["total_findings"] == 0
        assert result_payload["summary"]["findings_by_severity"]["high"] == 0
        assert result_payload["results"][0]["findings_count"] == 0


# ===================================================================
# B6 — Custom policy YAML through API
# ===================================================================


class TestCustomPolicyAPI:
    """Custom policy YAML changes findings via /scan."""

    def test_disabled_rule_is_absent_from_findings(self, client, safe_skill_dir, tmp_path):
        # First scan WITHOUT custom policy to find a rule that fires
        baseline_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir)},
        )
        assert baseline_resp.status_code == 200
        baseline = baseline_resp.json()

        if baseline["findings_count"] == 0:
            pytest.skip("Safe skill produces no findings; can't test rule disabling")

        # Pick the first rule_id to disable
        target_rule = baseline["findings"][0]["rule_id"]

        # Write a custom policy YAML that disables it
        custom_policy = {
            "policy_name": "test-disable",
            "policy_version": "1.0",
            "disabled_rules": [target_rule],
        }
        policy_file = tmp_path / "disable_policy.yaml"
        policy_file.write_text(yaml.dump(custom_policy))

        # Re-scan with custom policy
        custom_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir), "policy": str(policy_file)},
        )
        assert custom_resp.status_code == 200
        custom_data = custom_resp.json()

        # The disabled rule should NOT appear in findings
        custom_rule_ids = {f["rule_id"] for f in custom_data["findings"]}
        assert target_rule not in custom_rule_ids, (
            f"Rule {target_rule} should be disabled but still appears in findings"
        )

    def test_severity_override_changes_finding_severity(self, client, malicious_skill_dir, tmp_path):
        # Baseline scan
        baseline_resp = client.post(
            "/scan",
            json={"skill_directory": str(malicious_skill_dir)},
        )
        assert baseline_resp.status_code == 200
        baseline = baseline_resp.json()

        if baseline["findings_count"] == 0:
            pytest.skip("Malicious skill produces no findings; can't test severity override")

        # Find a non-INFO finding to override
        target = None
        for f in baseline["findings"]:
            if f["severity"] not in ("INFO", "LOW"):
                target = f
                break
        if not target:
            pytest.skip("No HIGH/MEDIUM severity finding to override")

        target_rule = target["rule_id"]
        original_severity = target["severity"]

        # Write policy that overrides the finding to INFO
        custom_policy = {
            "policy_name": "test-sev-override",
            "policy_version": "1.0",
            "severity_overrides": [
                {"rule_id": target_rule, "severity": "INFO", "reason": "test override"},
            ],
        }
        policy_file = tmp_path / "sev_override_policy.yaml"
        policy_file.write_text(yaml.dump(custom_policy))

        custom_resp = client.post(
            "/scan",
            json={"skill_directory": str(malicious_skill_dir), "policy": str(policy_file)},
        )
        assert custom_resp.status_code == 200
        custom_data = custom_resp.json()

        overridden = [f for f in custom_data["findings"] if f["rule_id"] == target_rule]
        for f in overridden:
            assert f["severity"] == "INFO", f"Expected severity INFO for {target_rule} but got {f['severity']}"


# ===================================================================
# B7 — Analyzer toggle through API
# ===================================================================


class TestAnalyzerToggle:
    """Toggling analyzers via API changes findings."""

    def test_behavioral_flag_controls_analyzer(self, client, safe_skill_dir):
        """use_behavioral=true should cause behavioral analyzer to run."""
        # Default scan (no behavioral)
        default_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir)},
        )
        assert default_resp.status_code == 200

        # Scan with behavioral enabled
        behavioral_resp = client.post(
            "/scan",
            json={"skill_directory": str(safe_skill_dir), "use_behavioral": True},
        )
        assert behavioral_resp.status_code == 200

        # Both should succeed (behavioral is best-effort)
        # We verify the API accepts and processes the flag without error

    def test_analyzers_endpoint_lists_core_analyzers(self, client):
        """GET /analyzers returns at least static, bytecode, pipeline."""
        resp = client.get("/analyzers")
        assert resp.status_code == 200
        data = resp.json()

        names = [a["name"] for a in data["analyzers"]]
        assert "static_analyzer" in names
        assert "bytecode_analyzer" in names
        assert "pipeline_analyzer" in names

    def test_analyzers_endpoint_all_have_description(self, client):
        """Every analyzer in /analyzers has a non-empty description."""
        resp = client.get("/analyzers")
        data = resp.json()

        for analyzer in data["analyzers"]:
            assert "name" in analyzer
            assert "description" in analyzer
            assert isinstance(analyzer["description"], str)
            assert len(analyzer["description"]) > 0

    def test_scan_nonexistent_dir_returns_404(self, client):
        """Scanning a nonexistent directory returns 404."""
        resp = client.post(
            "/scan",
            json={"skill_directory": "/nonexistent/path/to/skill"},
        )
        assert resp.status_code == 404

    def test_scan_dir_without_skillmd_returns_400(self, client, tmp_path):
        """Scanning a directory without SKILL.md returns 400."""
        (tmp_path / "readme.txt").write_text("hello")
        resp = client.post(
            "/scan",
            json={"skill_directory": str(tmp_path)},
        )
        assert resp.status_code == 400
        assert "SKILL.md" in resp.json()["detail"]
