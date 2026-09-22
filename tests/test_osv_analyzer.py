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

import json

import httpx
import pytest

from skill_scanner.core.analyzers.osv_analyzer import OSVAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.semantic import ScanFactProjector


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


class _SequencedClient:
    """Returns one queued response per POST and records every payload sent."""

    def __init__(self, responses: list[_FakeResponse | Exception]):
        self.responses = list(responses)
        self.payloads: list[dict] = []

    @property
    def last_payload(self) -> dict | None:
        return self.payloads[-1] if self.payloads else None

    def post(self, _url: str, json: dict):  # noqa: A002 - match httpx signature
        self.payloads.append(json)
        queued = self.responses.pop(0) if self.responses else _FakeResponse({"results": []})
        if isinstance(queued, Exception):
            raise queued
        return queued


def _make_analyzer(client: _FakeClient | _SequencedClient) -> OSVAnalyzer:
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
        assert findings[0].file_path == "SKILL.md"

        facts = ScanFactProjector().project(skill, findings[0], findings)
        assert facts.candidate.file_path == "SKILL.md"
        assert facts.projection.complete is True
        assert "INVALID_PATH" not in facts.projection.error_codes


_SKILL_MD = "---\nname: osv\ndescription: A test skill\n---\n# osv\n"


def _pins(skill) -> dict[str, str]:
    """Map of ``name -> version`` for pins collected from a skill."""
    analyzer = OSVAnalyzer(enabled=True)
    return {dep.name: dep.version for dep in analyzer._collect_pinned_dependencies(skill)}


class TestPinnedSourceCoverage:
    """Exact pins are collected from every manifest format, ranges are ignored."""

    def test_pyproject_pins_collected(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "pyproject.toml": (
                    "[project]\n"
                    'name = "s"\n'
                    'dependencies = ["requests==2.19.0", "flask>=2"]\n'
                    "\n[project.optional-dependencies]\n"
                    'dev = ["pytest==8.0.0"]\n'
                ),
            }
        )
        assert _pins(skill) == {"requests": "2.19.0", "pytest": "8.0.0"}

    def test_setup_cfg_pins_collected(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "setup.cfg": "[options]\ninstall_requires =\n    requests==2.19.0\n    flask>=2\n",
            }
        )
        assert _pins(skill) == {"requests": "2.19.0"}

    def test_setup_py_pins_collected(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "setup.py": (
                    "from setuptools import setup\nsetup(name='s', install_requires=['requests==2.19.0', 'flask>=2'])\n"
                ),
            }
        )
        assert _pins(skill) == {"requests": "2.19.0"}

    def test_pipfile_pins_collected(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "Pipfile": ('[packages]\nrequests = "==2.19.0"\nflask = "*"\nhttpx = {version = "==0.27.0"}\n'),
            }
        )
        assert _pins(skill) == {"requests": "2.19.0", "httpx": "0.27.0"}

    def test_pyproject_pin_queried_end_to_end(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "pyproject.toml": '[project]\nname = "s"\ndependencies = ["requests==2.19.0"]\n',
            }
        )
        response = _FakeResponse({"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))
        findings = analyzer.analyze(skill)
        assert len(findings) == 1
        assert findings[0].metadata["package"] == "requests"
        assert analyzer._client.last_payload["queries"][0]["version"] == "2.19.0"


class TestNpmManifest:
    """package.json exact pins are queried against the npm ecosystem."""

    def test_exact_pin_queried_as_npm(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}})})
        response = _FakeResponse({"results": [{"vulns": [{"id": "GHSA-29mw-wpgm-hmr9"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))

        findings = analyzer.analyze(skill)
        assert len(findings) == 1
        query = analyzer._client.last_payload["queries"][0]
        assert query["package"] == {"ecosystem": "npm", "name": "lodash"}
        assert query["version"] == "4.17.15"
        assert findings[0].metadata["ecosystem"] == "npm"
        # npm coordinates read ``name@version``, not the PyPI ``name==version``.
        assert findings[0].snippet == "lodash@4.17.15"
        assert findings[0].file_path == "package.json"

    def test_finding_projects_into_facts(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}})})
        response = _FakeResponse({"results": [{"vulns": [{"id": "GHSA-29mw-wpgm-hmr9"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))

        findings = analyzer.analyze(skill)
        facts = ScanFactProjector().project(skill, findings[0], findings)
        assert facts.candidate.file_path == "package.json"
        assert facts.projection.complete is True
        assert "INVALID_PATH" not in facts.projection.error_codes

    def test_range_is_not_queried(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}})})
        client = _FakeClient(response=_FakeResponse({"results": []}))
        analyzer = _make_analyzer(client)

        assert analyzer.analyze(skill) == []
        assert client.last_payload is None

    def test_dev_dependency_is_recorded_in_metadata(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"devDependencies": {"jest": "29.7.0"}})})
        response = _FakeResponse({"results": [{"vulns": [{"id": "GHSA-dev"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))

        assert analyzer.analyze(skill)[0].metadata["dev"] is True

    def test_python_and_npm_dependencies_share_one_request(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "requirements.txt": "requests==2.19.0\n",
                "package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}}),
            }
        )
        analyzer = _make_analyzer(_FakeClient(response=_FakeResponse({"results": [{}, {}]})))
        analyzer.analyze(skill)

        queries = analyzer._client.last_payload["queries"]
        assert {(q["package"]["ecosystem"], q["package"]["name"]) for q in queries} == {
            ("PyPI", "requests"),
            ("npm", "lodash"),
        }

    def test_vendored_node_modules_manifests_not_queried(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "node_modules/vendored/package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}}),
            }
        )
        client = _FakeClient(response=_FakeResponse({"results": []}))
        analyzer = _make_analyzer(client)

        assert analyzer.analyze(skill) == []
        assert client.last_payload is None

    def test_aliased_dependency_queried_under_real_name(self, make_skill):
        skill = make_skill(
            {"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"alias": "npm:real-pkg@1.2.3"}})}
        )
        analyzer = _make_analyzer(_FakeClient(response=_FakeResponse({"results": [{}]})))
        analyzer.analyze(skill)

        assert analyzer._client.last_payload["queries"][0]["package"]["name"] == "real-pkg"


class TestMalformedResponses:
    """A shape-malformed response must fail open, not abort the scan."""

    def test_non_mapping_result_entry_fails_open(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}})})
        analyzer = _make_analyzer(_FakeClient(response=_FakeResponse({"results": ["not-a-mapping"]})))
        assert analyzer.analyze(skill) == []

    def test_non_mapping_vulnerability_entry_is_ignored(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}})})
        response = _FakeResponse({"results": [{"vulns": ["not-a-mapping", {"id": "GHSA-real"}]}]})
        analyzer = _make_analyzer(_FakeClient(response=response))

        findings = analyzer.analyze(skill)
        assert len(findings) == 1
        assert findings[0].metadata["vulnerability_ids"] == ["GHSA-real"]

    def test_results_not_a_list_fails_open(self, make_skill):
        skill = make_skill({"SKILL.md": _SKILL_MD, "package.json": json.dumps({"dependencies": {"lodash": "4.17.15"}})})
        analyzer = _make_analyzer(_FakeClient(response=_FakeResponse({"results": "nope"})))
        assert analyzer.analyze(skill) == []


class TestBoundsValidation:
    """Query bounds are positive integers; None keeps the default."""

    @pytest.mark.parametrize("value", [0, -1, -5, 1.5, "5"])
    def test_invalid_chunk_size_rejected(self, value):
        with pytest.raises(ValueError):
            OSVAnalyzer(enabled=True, chunk_size=value)

    @pytest.mark.parametrize("value", [0, -1, 2.5, "10"])
    def test_invalid_max_dependencies_rejected(self, value):
        with pytest.raises(ValueError):
            OSVAnalyzer(enabled=True, max_dependencies=value)

    def test_none_keeps_defaults(self):
        analyzer = OSVAnalyzer(enabled=True)
        assert analyzer.chunk_size == OSVAnalyzer.QUERY_CHUNK_SIZE
        assert analyzer.max_dependencies == OSVAnalyzer.MAX_DEPENDENCIES


class TestQueryBatching:
    """Lockfiles can list thousands of packages, so queries are bounded."""

    _THREE_PINS = {"SKILL.md": _SKILL_MD, "requirements.txt": "a==1.0.0\nb==2.0.0\nc==3.0.0\n"}

    def test_dependencies_are_split_into_chunks(self, make_skill):
        skill = make_skill(self._THREE_PINS)
        client = _SequencedClient(
            [
                _FakeResponse({"results": [{}, {"vulns": [{"id": "V-B"}]}]}),
                _FakeResponse({"results": [{"vulns": [{"id": "V-C"}]}]}),
            ]
        )
        analyzer = _make_analyzer(client)
        analyzer.chunk_size = 2

        findings = analyzer.analyze(skill)
        assert [len(payload["queries"]) for payload in client.payloads] == [2, 1]
        assert {finding.metadata["package"] for finding in findings} == {"b", "c"}

    def test_failed_chunk_does_not_discard_other_chunks(self, make_skill):
        skill = make_skill(self._THREE_PINS)
        client = _SequencedClient(
            [httpx.ConnectError("no network"), _FakeResponse({"results": [{"vulns": [{"id": "V-C"}]}]})]
        )
        analyzer = _make_analyzer(client)
        analyzer.chunk_size = 2

        findings = analyzer.analyze(skill)
        assert {finding.metadata["package"] for finding in findings} == {"c"}

    def test_dependency_cap_bounds_total_queries(self, make_skill):
        skill = make_skill(self._THREE_PINS)
        client = _SequencedClient([_FakeResponse({"results": [{}, {}]})])
        analyzer = _make_analyzer(client)
        analyzer.max_dependencies = 2

        analyzer.analyze(skill)
        assert sum(len(payload["queries"]) for payload in client.payloads) == 2


class TestDeduplication:
    """The same release declared twice is one query and one finding."""

    def test_same_name_in_two_ecosystems_stays_distinct(self, make_skill):
        # "requests" exists on both PyPI and npm; they are unrelated packages.
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "requirements.txt": "requests==2.19.0\n",
                "package.json": json.dumps({"dependencies": {"requests": "2.19.0"}}),
            }
        )
        client = _FakeClient(
            response=_FakeResponse({"results": [{"vulns": [{"id": "PYSEC-1"}]}, {"vulns": [{"id": "GHSA-1"}]}]})
        )
        analyzer = _make_analyzer(client)

        findings = analyzer.analyze(skill)
        assert len(findings) == 2
        assert {finding.id for finding in findings} == {"OSV_PyPI_requests_2.19.0", "OSV_npm_requests_2.19.0"}

    def test_pin_repeated_across_manifests_is_queried_once(self, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "requirements.txt": "requests==2.19.0\n",
                "pyproject.toml": '[project]\nname = "s"\ndependencies = ["requests==2.19.0"]\n',
            }
        )
        client = _FakeClient(response=_FakeResponse({"results": [{"vulns": [{"id": "V"}]}]}))
        analyzer = _make_analyzer(client)

        findings = analyzer.analyze(skill)
        assert len(client.last_payload["queries"]) == 1
        assert len(findings) == 1
