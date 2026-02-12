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

"""Tests for VirusTotal analyzer behavior and parsing logic."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import httpx
import pytest

from skill_scanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Severity, ThreatCategory


class DeterministicVirusTotalAnalyzer(VirusTotalAnalyzer):
    """Test double that runs full analyze() logic without external API calls."""

    def __init__(self, hash_results: dict[str, tuple[dict | None, bool]]):
        super().__init__(api_key="test_key", enabled=True, upload_files=False)
        self.hash_results = hash_results
        self.queried_hashes: list[str] = []

    def _query_virustotal(self, file_hash: str) -> tuple[dict | None, bool]:
        self.queried_hashes.append(file_hash)
        return self.hash_results.get(file_hash, (None, False))


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class _FakeSession:
    def __init__(self, responses=None, error: Exception | None = None):
        self.responses = list(responses or [])
        self.error = error

    def get(self, _url: str, timeout: int = 10):  # noqa: ARG002
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


@pytest.fixture
def example_skills_dir() -> Path:
    return Path(__file__).parent.parent / "evals" / "test_skills"


def test_vt_analyzer_disabled_returns_empty(make_skill):
    skill = make_skill({"assets/test.bin": b"binary-content"})
    analyzer = VirusTotalAnalyzer(api_key="test_key", enabled=False)
    assert analyzer.analyze(skill) == []


def test_binary_file_detection_logic_uses_extension_filters():
    analyzer = VirusTotalAnalyzer(api_key="test_key")

    assert analyzer._is_binary_file("assets/image.png")
    assert analyzer._is_binary_file("assets/archive.zip")
    assert analyzer._is_binary_file("assets/payload.exe")

    assert not analyzer._is_binary_file("scripts/tool.py")
    assert not analyzer._is_binary_file("docs/README.md")
    assert not analyzer._is_binary_file("config/settings.yaml")
    assert not analyzer._is_binary_file("custom/file.unknown")


def test_analyze_only_queries_binary_files_and_tracks_validated(make_skill):
    skill = make_skill(
        {
            "assets/safe.bin": b"SAFE-BINARY",
            "assets/malicious.bin": b"MAL-BINARY",
            "scripts/ignored.py": "print('hello')",
            "docs/ignored.md": "# docs",
        }
    )

    safe_hash = hashlib.sha256(b"SAFE-BINARY").hexdigest()
    mal_hash = hashlib.sha256(b"MAL-BINARY").hexdigest()

    analyzer = DeterministicVirusTotalAnalyzer(
        hash_results={
            safe_hash: (
                {
                    "malicious": 0,
                    "suspicious": 0,
                    "total_engines": 64,
                    "permalink": f"https://www.virustotal.com/gui/file/{safe_hash}",
                },
                True,
            ),
            mal_hash: (
                {
                    "malicious": 19,
                    "suspicious": 3,
                    "total_engines": 64,
                    "permalink": f"https://www.virustotal.com/gui/file/{mal_hash}",
                },
                True,
            ),
        }
    )

    findings = analyzer.analyze(skill)

    assert len(analyzer.queried_hashes) == 2
    assert set(analyzer.queried_hashes) == {safe_hash, mal_hash}
    assert analyzer.validated_binary_files == ["assets/safe.bin"]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file_path == "assets/malicious.bin"
    assert finding.category == ThreatCategory.MALWARE
    assert finding.severity == Severity.HIGH
    assert finding.analyzer == "virustotal"
    assert finding.metadata["file_hash"] == mal_hash


def test_analyze_unknown_hash_without_upload_returns_no_findings(make_skill):
    skill = make_skill({"assets/unknown.bin": b"UNKNOWN"})
    unknown_hash = hashlib.sha256(b"UNKNOWN").hexdigest()

    analyzer = DeterministicVirusTotalAnalyzer(hash_results={})
    findings = analyzer.analyze(skill)

    assert analyzer.queried_hashes == [unknown_hash]
    assert findings == []
    assert analyzer.validated_binary_files == []


@pytest.mark.parametrize(
    ("malicious", "total", "expected_severity"),
    [
        (20, 60, Severity.CRITICAL),
        (8, 60, Severity.HIGH),
        (1, 60, Severity.MEDIUM),
        (0, 0, Severity.MEDIUM),
    ],
)
def test_create_finding_severity_thresholds(make_skill, malicious, total, expected_severity):
    skill = make_skill({"assets/sample.bin": b"SAMPLE"})
    sample_file = next(file for file in skill.files if file.relative_path == "assets/sample.bin")
    file_hash = hashlib.sha256(b"SAMPLE").hexdigest()

    analyzer = VirusTotalAnalyzer(api_key="test_key")
    finding = analyzer._create_finding(
        skill_file=sample_file,
        file_hash=file_hash,
        vt_result={
            "malicious": malicious,
            "suspicious": 0,
            "total_engines": total,
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
        },
    )

    assert finding.severity == expected_severity
    assert finding.file_path == "assets/sample.bin"
    assert finding.rule_id == "VIRUSTOTAL_MALICIOUS_FILE"
    assert finding.metadata["references"] == [f"https://www.virustotal.com/gui/file/{file_hash}"]


def test_query_virustotal_parses_success_response():
    file_hash = "a" * 64
    analyzer = VirusTotalAnalyzer(api_key="test_key")
    analyzer.session = _FakeSession(
        responses=[
            _FakeResponse(
                200,
                payload={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 2,
                                "suspicious": 1,
                                "undetected": 55,
                                "harmless": 6,
                            },
                            "last_analysis_date": 1735689600,
                        }
                    }
                },
            )
        ]
    )

    result, found = analyzer._query_virustotal(file_hash)

    assert found is True
    assert result is not None
    assert result["malicious"] == 2
    assert result["suspicious"] == 1
    assert result["total_engines"] == 64
    assert result["permalink"] == f"https://www.virustotal.com/gui/file/{file_hash}"


def test_query_virustotal_404_returns_not_found():
    analyzer = VirusTotalAnalyzer(api_key="test_key")
    analyzer.session = _FakeSession(responses=[_FakeResponse(404)])

    result, found = analyzer._query_virustotal("b" * 64)

    assert found is False
    assert result is None


def test_query_virustotal_request_error_returns_not_found():
    analyzer = VirusTotalAnalyzer(api_key="test_key")
    analyzer.session = _FakeSession(error=httpx.RequestError("network failed"))

    result, found = analyzer._query_virustotal("c" * 64)

    assert found is False
    assert result is None


def test_eicar_skill_structure(example_skills_dir: Path):
    loader = SkillLoader()
    eicar_skill_dir = example_skills_dir / "malicious" / "eicar-test"
    if not eicar_skill_dir.exists():
        pytest.skip("EICAR test skill not found")

    skill = loader.load_skill(eicar_skill_dir)
    binary_files = [f for f in skill.files if "assets" in f.relative_path]

    assert skill.name == "eicar-test"
    assert len(binary_files) > 0


@pytest.mark.skipif(not os.getenv("VIRUSTOTAL_API_KEY"), reason="Requires VIRUSTOTAL_API_KEY")
def test_virustotal_api_integration(example_skills_dir: Path):
    loader = SkillLoader()
    analyzer = VirusTotalAnalyzer(api_key=os.getenv("VIRUSTOTAL_API_KEY"), enabled=True)
    eicar_skill_dir = example_skills_dir / "malicious" / "eicar-test"

    if not eicar_skill_dir.exists():
        pytest.skip("EICAR test skill not found")

    skill = loader.load_skill(eicar_skill_dir)
    binary_files = [f for f in skill.files if analyzer._is_binary_file(f.relative_path)]
    if not binary_files:
        pytest.skip("No binary files found in test skill")

    findings = analyzer.analyze(skill)
    assert isinstance(findings, list)
