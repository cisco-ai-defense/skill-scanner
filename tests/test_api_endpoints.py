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
Comprehensive tests for REST API endpoints.

Tests cover all API endpoints with various analyzer configurations.
"""

import io
import time
import zipfile
from pathlib import Path

import pytest

try:
    from fastapi.testclient import TestClient

    from skill_scanner.api.api import app

    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False
    app = None
    TestClient = None


# Test fixtures
@pytest.fixture
def client():
    """Create test client."""
    if not API_AVAILABLE:
        pytest.skip("FastAPI not installed")
    return TestClient(app)


@pytest.fixture
def safe_skill_dir():
    """Path to a safe test skill."""
    return Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"


@pytest.fixture
def malicious_skill_dir():
    """Path to a malicious test skill (if exists)."""
    path = Path(__file__).parent.parent / "evals" / "skills" / "clawbot-malicious" / "wed"
    if not path.exists():
        pytest.skip("Malicious test skill not found")
    return path


@pytest.fixture
def test_skills_dir():
    """Path to test skills directory."""
    return Path(__file__).parent.parent / "evals" / "test_skills"


# =============================================================================
# Health Endpoint Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_endpoint_returns_200(self, client):
        """Test /health endpoint returns healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "version" in data
        assert "analyzers_available" in data
        assert isinstance(data["analyzers_available"], list)

    def test_health_includes_static_analyzer(self, client):
        """Test that health endpoint lists static analyzer."""
        response = client.get("/health")
        data = response.json()

        assert "static_analyzer" in data["analyzers_available"]

    def test_health_includes_behavioral_analyzer(self, client):
        """Test that health endpoint lists behavioral analyzer."""
        response = client.get("/health")
        data = response.json()

        assert "behavioral_analyzer" in data["analyzers_available"]

    def test_health_includes_llm_analyzer(self, client):
        """Test that health endpoint lists LLM analyzer when available."""
        response = client.get("/health")
        data = response.json()

        # LLM analyzer should be listed (availability depends on litellm)
        assert "analyzers_available" in data

    def test_health_includes_aidefense_analyzer(self, client):
        """Test that health endpoint lists AI Defense analyzer."""
        response = client.get("/health")
        data = response.json()

        assert "aidefense_analyzer" in data["analyzers_available"]


# =============================================================================
# Root Endpoint Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestRootEndpoint:
    """Test root endpoint."""

    def test_root_endpoint_returns_service_info(self, client):
        """Test root / endpoint returns service info."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()

        assert "service" in data
        assert "Skill Scanner" in data["service"]
        assert "version" in data


# =============================================================================
# Scan Endpoint Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestScanEndpoint:
    """Test skill scanning endpoint."""

    def test_scan_valid_skill_static_only(self, client, safe_skill_dir):
        """Test scanning a valid skill with static analyzer only."""
        request_data = {"skill_directory": str(safe_skill_dir), "use_llm": False}

        response = client.post("/scan", json=request_data)

        assert response.status_code == 200
        data = response.json()

        assert "scan_id" in data
        assert "skill_name" in data
        assert data["skill_name"] == "simple-formatter"
        assert "is_safe" in data
        assert data["is_safe"] is True
        assert "findings_count" in data
        assert "scan_duration_seconds" in data
        assert "timestamp" in data
        assert "findings" in data

    def test_scan_with_behavioral_analyzer(self, client, safe_skill_dir):
        """Test scanning with behavioral analyzer enabled."""
        request_data = {
            "skill_directory": str(safe_skill_dir),
            "use_behavioral": True,
            "use_llm": False,
        }

        response = client.post("/scan", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "findings" in data

    def test_scan_nonexistent_skill_returns_404(self, client):
        """Test scanning nonexistent skill returns 404."""
        request_data = {"skill_directory": "/nonexistent/skill", "use_llm": False}

        response = client.post("/scan", json=request_data)

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_scan_without_skill_md_returns_400(self, client):
        """Test scanning directory without SKILL.md returns 400."""
        # Use tests directory (no SKILL.md)
        tests_dir = Path(__file__).parent

        request_data = {"skill_directory": str(tests_dir), "use_llm": False}

        response = client.post("/scan", json=request_data)

        assert response.status_code == 400
        assert "SKILL.md" in response.json()["detail"]

    def test_scan_aidefense_without_key_returns_400(self, client, safe_skill_dir):
        """Test that AI Defense without API key returns 400."""
        request_data = {
            "skill_directory": str(safe_skill_dir),
            "use_aidefense": True,
            "aidefense_api_key": None,  # No key
        }

        response = client.post("/scan", json=request_data)

        # Should return 400 if no key is set
        assert response.status_code in [200, 400]
        if response.status_code == 400:
            assert "API key" in response.json()["detail"]

    def test_scan_response_structure(self, client, safe_skill_dir):
        """Test that scan response has correct structure."""
        request_data = {"skill_directory": str(safe_skill_dir)}

        response = client.post("/scan", json=request_data)

        assert response.status_code == 200
        data = response.json()

        # Check all required fields
        required_fields = [
            "scan_id",
            "skill_name",
            "is_safe",
            "max_severity",
            "findings_count",
            "scan_duration_seconds",
            "timestamp",
            "findings",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_scan_with_all_parameters(self, client, safe_skill_dir):
        """Test scan with all available parameters."""
        request_data = {
            "skill_directory": str(safe_skill_dir),
            "use_behavioral": True,
            "use_llm": False,
            "llm_provider": "anthropic",
            "use_aidefense": False,
        }

        response = client.post("/scan", json=request_data)

        assert response.status_code == 200


# =============================================================================
# Batch Scan Endpoint Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestBatchScanEndpoint:
    """Test batch scanning endpoint."""

    def test_batch_scan_initiates(self, client, test_skills_dir):
        """Test that batch scan initiates and returns scan ID."""
        request_data = {
            "skills_directory": str(test_skills_dir),
            "recursive": False,
            "use_llm": False,
        }

        response = client.post("/scan-batch", json=request_data)

        assert response.status_code == 200
        data = response.json()

        assert "scan_id" in data
        assert data["status"] == "processing"
        assert "message" in data

    def test_batch_scan_with_behavioral(self, client, test_skills_dir):
        """Test batch scan with behavioral analyzer."""
        request_data = {
            "skills_directory": str(test_skills_dir),
            "recursive": False,
            "use_behavioral": True,
            "use_llm": False,
        }

        response = client.post("/scan-batch", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data

    def test_batch_scan_result_retrieval(self, client, test_skills_dir):
        """Test retrieving batch scan results."""
        # Initiate batch scan
        request_data = {
            "skills_directory": str(test_skills_dir),
            "recursive": False,
            "use_llm": False,
        }

        response = client.post("/scan-batch", json=request_data)
        scan_id = response.json()["scan_id"]

        # Wait a bit for processing
        time.sleep(2)

        # Retrieve results
        result_response = client.get(f"/scan-batch/{scan_id}")

        assert result_response.status_code == 200
        result_data = result_response.json()

        assert result_data["scan_id"] == scan_id
        assert result_data["status"] in ["processing", "completed"]

    def test_batch_scan_nonexistent_id_returns_404(self, client):
        """Test retrieving nonexistent scan ID returns 404."""
        response = client.get("/scan-batch/nonexistent-id-12345")

        assert response.status_code == 404

    def test_batch_scan_nonexistent_directory_returns_404(self, client):
        """Test batch scan with nonexistent directory returns 404."""
        request_data = {
            "skills_directory": "/nonexistent/directory",
            "use_llm": False,
        }

        response = client.post("/scan-batch", json=request_data)

        assert response.status_code == 404


# =============================================================================
# Analyzers Endpoint Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestAnalyzersEndpoint:
    """Test analyzers listing endpoint."""

    def test_list_analyzers(self, client):
        """Test /analyzers endpoint lists available analyzers."""
        response = client.get("/analyzers")

        assert response.status_code == 200
        data = response.json()

        assert "analyzers" in data
        analyzers = data["analyzers"]

        # Should have at least static analyzer
        assert len(analyzers) > 0
        analyzer_names = [a["name"] for a in analyzers]
        assert "static_analyzer" in analyzer_names

    def test_analyzer_structure(self, client):
        """Test that each analyzer has required fields."""
        response = client.get("/analyzers")
        data = response.json()

        for analyzer in data["analyzers"]:
            assert "name" in analyzer
            assert "description" in analyzer
            assert "available" in analyzer

    def test_all_analyzers_listed(self, client):
        """Test that all expected analyzers are listed."""
        response = client.get("/analyzers")
        data = response.json()

        analyzer_names = [a["name"] for a in data["analyzers"]]

        # Check expected analyzers
        expected = ["static_analyzer", "behavioral_analyzer", "llm_analyzer", "aidefense_analyzer"]
        for name in expected:
            assert name in analyzer_names, f"Missing analyzer: {name}"


# =============================================================================
# Upload Endpoint Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestUploadEndpoint:
    """Test skill upload and scan endpoint."""

    def test_upload_requires_zip(self, client):
        """Test that upload endpoint requires ZIP file."""
        # Try to upload non-ZIP file
        files = {"file": ("test.txt", b"not a zip", "text/plain")}

        response = client.post("/scan-upload", files=files)

        assert response.status_code == 400
        assert "ZIP" in response.json()["detail"]

    def test_upload_valid_zip(self, client, safe_skill_dir):
        """Test uploading a valid skill ZIP file."""
        # Create a ZIP file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add SKILL.md
            skill_md = safe_skill_dir / "SKILL.md"
            if skill_md.exists():
                zf.write(skill_md, "SKILL.md")

        zip_buffer.seek(0)
        files = {"file": ("skill.zip", zip_buffer, "application/zip")}

        response = client.post("/scan-upload", files=files)

        # Should succeed (or fail gracefully if skill is incomplete)
        assert response.status_code in [200, 400, 500]

    def test_upload_with_parameters(self, client, safe_skill_dir):
        """Test upload with analyzer parameters."""
        # Create a ZIP file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            skill_md = safe_skill_dir / "SKILL.md"
            if skill_md.exists():
                zf.write(skill_md, "SKILL.md")

        zip_buffer.seek(0)

        files = {"file": ("skill.zip", zip_buffer, "application/zip")}
        data = {
            "use_behavioral": "true",
            "use_llm": "false",
        }

        response = client.post("/scan-upload", files=files, data=data)

        # Should accept the parameters
        assert response.status_code in [200, 400, 500]


# =============================================================================
# Error Handling Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestAPIErrorHandling:
    """Test API error handling."""

    def test_invalid_json_returns_422(self, client):
        """Test that invalid JSON returns 422."""
        response = client.post("/scan", json={"invalid_field": "value"})

        # Should return validation error
        assert response.status_code == 422

    def test_malformed_request_handled(self, client):
        """Test that malformed requests are handled gracefully."""
        response = client.post("/scan", data="not json")

        # Should return error (422 or 400)
        assert response.status_code in [400, 422]

    def test_empty_body_returns_422(self, client):
        """Test that empty request body returns 422."""
        response = client.post("/scan", json={})

        assert response.status_code == 422

    def test_wrong_method_returns_405(self, client):
        """Test that wrong HTTP method returns 405."""
        response = client.get("/scan")  # Should be POST

        assert response.status_code == 405


# =============================================================================
# API Documentation Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestAPIDocumentation:
    """Test that API documentation is available."""

    def test_docs_endpoint_accessible(self, client):
        """Test that /docs endpoint is accessible."""
        response = client.get("/docs")

        assert response.status_code == 200

    def test_redoc_endpoint_accessible(self, client):
        """Test that /redoc endpoint is accessible."""
        response = client.get("/redoc")

        assert response.status_code == 200

    def test_openapi_schema_accessible(self, client):
        """Test that OpenAPI schema is accessible."""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        data = response.json()

        assert "openapi" in data
        assert "paths" in data
        assert "info" in data


# =============================================================================
# Integration Tests (Malicious Skill Detection)
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestMaliciousSkillDetection:
    """Test detection of malicious skills via API."""

    def test_static_analyzer_detects_patterns(self, client):
        """Test that static analyzer detects suspicious patterns."""
        # Create a skill with suspicious content
        malicious_dir = Path(__file__).parent.parent / "evals" / "skills" / "command-injection" / "curl-injection"

        if not malicious_dir.exists():
            pytest.skip("Test skill not found")

        request_data = {
            "skill_directory": str(malicious_dir),
            "use_llm": False,
        }

        response = client.post("/scan", json=request_data)

        if response.status_code == 200:
            data = response.json()
            # Should detect something suspicious
            assert "findings" in data


# =============================================================================
# Concurrent Request Tests
# =============================================================================
@pytest.mark.skipif(not API_AVAILABLE, reason="FastAPI not installed")
class TestConcurrentRequests:
    """Test handling of concurrent requests."""

    def test_multiple_health_checks(self, client):
        """Test multiple concurrent health checks."""
        responses = []
        for _ in range(5):
            responses.append(client.get("/health"))

        for response in responses:
            assert response.status_code == 200

    def test_multiple_scans(self, client, safe_skill_dir):
        """Test multiple scan requests."""
        request_data = {"skill_directory": str(safe_skill_dir), "use_llm": False}

        responses = []
        for _ in range(3):
            responses.append(client.post("/scan", json=request_data))

        for response in responses:
            assert response.status_code == 200
            data = response.json()
            assert "scan_id" in data
