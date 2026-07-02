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

"""Tests for the OSV dependency vulnerability analyzer.

All OSV HTTP calls are mocked; no live network access occurs.
"""

from __future__ import annotations

import httpx
import pytest

from skill_scanner.core.analyzers.osv_analyzer import OSVAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Stand-in for httpx.Client that records the last payload."""

    def __init__(self, response: _FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.last_payload: dict | None = None

    def post(self, _url: str, json: dict):  # noqa: A002 - match httpx signature
        self.last_payload = json
        if self.error is not None:
            raise self.error
        return self.response


def _make_analyzer(client: _FakeClient) -> OSVAnalyzer:
    analyzer = OSVAnalyzer(enabled=True)
    analyzer._client = client
    return analyzer


class TestPinnedParsing:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("requests==2.31.0", ("requests", "2.31.0")),
            ("requests == 2.31.0  # comment", ("requests", "2.31.0")),
            ("flask[async]==2.0.1", ("flask", "2.0.1")),
            ("pkg===1.0", ("pkg", "1.0")),
            ("pkg==1.2.3 ; python_version >= '3.10'", ("pkg", "1.2.3")),
        ],
    )
    def test_parses_pinned(self, line, expected):
        assert OSVAnalyzer._parse_pinned(line) == expected

    @pytest.mark.parametrize(
        "line",
        ["requests>=2.31.0", "requests", "requests==2.*", "-r base.txt", "# comment", ""],
    )
    def test_ignores_non_exact_pins(self, line):
        assert OSVAnalyzer._parse_pinned(line) is None


class TestAnalyze:
    def test_disabled_returns_empty(self, make_skill):
        skill = make_skill({"requirements.txt": "requests==2.0.0\n"})
        analyzer = OSVAnalyzer(enabled=False)
        assert analyzer.analyze(skill) == []

    def test_vulnerable_package_flagged(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: osv\ndescription: A test skill\n---\n# osv\n",
                "requirements.txt": "requests==2.19.0\n",
            }
        )
        response = _FakeResponse({"results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))

        findings = analyzer.analyze(skill)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "SUPPLY_CHAIN_KNOWN_VULNERABILITY"
        assert finding.category == ThreatCategory.SUPPLY_CHAIN_ATTACK
        assert finding.severity == Severity.HIGH
        assert "GHSA-xxxx-yyyy-zzzz" in finding.metadata["vulnerability_ids"]
        assert finding.metadata["package"] == "requests"
        # Only pinned deps are queried.
        assert analyzer._client.last_payload["queries"][0]["version"] == "2.19.0"

    def test_clean_package_not_flagged(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: osv\ndescription: A test skill\n---\n# osv\n",
                "requirements.txt": "requests==2.31.0\n",
            }
        )
        response = _FakeResponse({"results": [{}]})  # no "vulns" key
        analyzer = _make_analyzer(_FakeClient(response=response))
        assert analyzer.analyze(skill) == []

    def test_unpinned_dependency_not_queried(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: osv\ndescription: A test skill\n---\n# osv\n",
                "requirements.txt": "requests>=2.19.0\n",
            }
        )
        client = _FakeClient(response=_FakeResponse({"results": []}))
        analyzer = _make_analyzer(client)
        # No pinned deps -> no query issued at all.
        assert analyzer.analyze(skill) == []
        assert client.last_payload is None

    def test_network_error_fails_open(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: osv\ndescription: A test skill\n---\n# osv\n",
                "requirements.txt": "requests==2.19.0\n",
            }
        )
        analyzer = _make_analyzer(_FakeClient(error=httpx.ConnectError("no network")))
        # Must not raise; returns no findings.
        assert analyzer.analyze(skill) == []

    def test_manifest_metadata_dependencies_queried(self, make_skill):
        skill = make_skill({"SKILL.md": "---\nname: osv\ndescription: A test skill\n---\n# osv\n"})
        skill.manifest.metadata = {"dependencies": ["flask==2.0.1"]}
        response = _FakeResponse({"results": [{"vulns": [{"id": "PYSEC-2023-0001"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))

        findings = analyzer.analyze(skill)
        assert len(findings) == 1
        assert findings[0].metadata["package"] == "flask"
