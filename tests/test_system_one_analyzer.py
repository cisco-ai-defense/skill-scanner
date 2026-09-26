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

"""The System One screening tier is advisory and cannot influence a verdict.

That constraint is the point of these tests. Measured on 439 records the model tested
scored *inverted* against the label, so a regression that let this tier emit findings or
change severity would actively degrade the scanner.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from skill_scanner.core.analyzers.system_one_analyzer import MAX_STATE_BYTES, SystemOneAnalyzer


def _skill(text: str = "x" * 100, name: str = "s") -> Any:
    return SimpleNamespace(
        name=name,
        files=[SimpleNamespace(relative_path="SKILL.md", content=text)],
    )


def _analyzer(**kwargs: Any) -> SystemOneAnalyzer:
    return SystemOneAnalyzer("https://api.example.invalid/v1/systemone", model="test-model", **kwargs)


class TestEndpointGuard:
    def test_https_is_accepted(self) -> None:
        assert _analyzer().endpoint.startswith("https://")

    @pytest.mark.parametrize("url", ["http://127.0.0.1:8311/v1/systemone", "http://localhost:8311/v1"])
    def test_loopback_plaintext_is_allowed(self, url: str) -> None:
        assert SystemOneAnalyzer(url, model="m").endpoint == url

    def test_plaintext_to_a_remote_host_is_refused(self) -> None:
        # Skill content would otherwise cross the network in clear text.
        with pytest.raises(ValueError, match="https"):
            SystemOneAnalyzer("http://example.invalid/v1/systemone", model="m")


class TestAdvisoryOnly:
    def test_never_emits_findings_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer()
        monkeypatch.setattr(analyzer, "_post", lambda state: {"answers": {"malicious": {"type": "noul", "noul": 0.97}}})
        assert analyzer.analyze(_skill()) == []
        assert analyzer.last_result is not None
        assert analyzer.last_result["probability"] == pytest.approx(0.97)
        assert analyzer.last_result["advisory_only"] is True

    def test_never_emits_findings_on_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer()

        def boom(state: str) -> dict:
            raise OSError("connection reset")

        monkeypatch.setattr(analyzer, "_post", boom)
        assert analyzer.analyze(_skill()) == []
        assert analyzer.last_result == {
            "status": "error",
            "reason": analyzer.last_error,
        }


class TestResponseHandling:
    def test_a_choice_answer_is_refused_rather_than_coerced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer()
        # A provider answering with a different type must not be read as a probability:
        # coercing it would manufacture confidence from a format error.
        monkeypatch.setattr(
            analyzer,
            "_post",
            lambda state: {"answers": {"malicious": {"type": "choice", "choice": "yes"}}},
        )
        assert analyzer.analyze(_skill()) == []
        assert analyzer.last_result["status"] == "unusable"

    @pytest.mark.parametrize("value", [-0.1, 1.5, "0.5", None])
    def test_out_of_range_or_non_numeric_is_refused(self, value: Any) -> None:
        payload = {"answers": {"malicious": {"type": "noul", "noul": value}}}
        assert SystemOneAnalyzer._read_probability(payload) is None

    def test_boundaries_are_accepted(self) -> None:
        for value in (0.0, 1.0):
            payload = {"answers": {"malicious": {"type": "noul", "noul": value}}}
            assert SystemOneAnalyzer._read_probability(payload) == value


class TestStateBudget:
    def test_oversize_content_is_skipped_not_truncated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = _analyzer()
        called = {"n": 0}

        def counting_post(state: str) -> dict:
            called["n"] += 1
            return {}

        monkeypatch.setattr(analyzer, "_post", counting_post)
        assert analyzer.analyze(_skill("y" * (MAX_STATE_BYTES + 1))) == []
        # Truncating and asking anyway would get a confident answer about content the
        # model never saw, which is a fail-open rather than a low score.
        assert called["n"] == 0
        assert analyzer.last_result["status"] == "skipped"

    def test_empty_content_is_skipped(self) -> None:
        analyzer = _analyzer()
        assert analyzer.analyze(SimpleNamespace(name="s", files=[])) == []
        assert analyzer.last_result["status"] == "skipped"


class TestFactoryWiring:
    def test_absent_by_default(self) -> None:
        from skill_scanner.core.analyzer_factory import build_analyzers
        from skill_scanner.core.scan_policy import ScanPolicy

        names = {a.get_name() for a in build_analyzers(ScanPolicy.default())}
        assert "system_one" not in names

    def test_endpoint_without_model_is_rejected(self) -> None:
        from skill_scanner.core.analyzer_factory import build_analyzers
        from skill_scanner.core.scan_policy import ScanPolicy

        with pytest.raises(ValueError, match="system_one_model"):
            build_analyzers(ScanPolicy.default(), system_one_endpoint="https://x.invalid/v1/systemone")

    def test_enabled_when_both_are_given(self) -> None:
        from skill_scanner.core.analyzer_factory import build_analyzers
        from skill_scanner.core.scan_policy import ScanPolicy

        names = {
            a.get_name()
            for a in build_analyzers(
                ScanPolicy.default(),
                system_one_endpoint="https://x.invalid/v1/systemone",
                system_one_model="m",
            )
        }
        assert "system_one" in names


class TestEndpointIsCheckedByHostname:
    """A prefix test on the URL string is not a loopback check.

    ``http://localhost.attacker.example/`` starts with ``http://localhost`` but resolves
    to a remote host, so a prefix match would send the skill's source and the bearer
    token over plaintext to an attacker-chosen server.
    """

    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://localhost.attacker.example/v1/systemone",
            "http://127.0.0.1.attacker.example/v1/systemone",
            "http://localhost@attacker.example/v1/systemone",
            "http://evil.example/v1/systemone",
        ],
    )
    def test_plaintext_to_a_non_loopback_host_is_refused(self, endpoint: str) -> None:
        with pytest.raises(ValueError, match="loopback"):
            SystemOneAnalyzer(endpoint, model="m")

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://api.example.com/v1/systemone",
            "http://127.0.0.1:8080/v1/systemone",
            "http://localhost:9000/v1/systemone",
            "http://[::1]:9000/v1/systemone",
        ],
    )
    def test_https_anywhere_and_http_on_loopback_are_allowed(self, endpoint: str) -> None:
        assert SystemOneAnalyzer(endpoint, model="m").endpoint == endpoint

    def test_a_non_http_scheme_is_refused(self) -> None:
        with pytest.raises(ValueError, match="http or https"):
            SystemOneAnalyzer("ftp://example.com/v1/systemone", model="m")


class TestRedirectsAreRefused:
    def test_a_redirect_does_not_forward_the_bearer_token(self) -> None:
        """urllib copies Authorization onto the redirected request.

        The constructor only vets the first hop, so a 302 to another origin or to
        plaintext http would hand the token and the skill's source to whatever the
        endpoint nominated. Exercised through the configured opener against two real
        loopback servers: the endpoint answers 302, and the redirect target must receive
        nothing.
        """
        import http.server
        import threading

        received: dict[str, list[str | None]] = {"endpoint": [], "target": []}

        def handler(name: str, location: str | None) -> type[http.server.BaseHTTPRequestHandler]:
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_POST(self) -> None:  # noqa: N802 - the stdlib's dispatch name
                    self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    received[name].append(self.headers.get("Authorization"))
                    self.send_response(302 if location else 200)
                    if location:
                        self.send_header("Location", location)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")

                # A followed 302 is re-issued as a GET, so the target must see either.
                do_GET = do_POST  # noqa: N815

                def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                    return

            return Handler

        target = http.server.HTTPServer(("127.0.0.1", 0), handler("target", None))
        endpoint = http.server.HTTPServer(
            ("127.0.0.1", 0), handler("endpoint", f"http://127.0.0.1:{target.server_port}/collect")
        )
        for server in (target, endpoint):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            analyzer = SystemOneAnalyzer(
                f"http://127.0.0.1:{endpoint.server_port}/v1/systemone", model="m", api_key="secret"
            )
            skill = SimpleNamespace(name="s", files=[SimpleNamespace(relative_path="SKILL.md", content="body")])
            assert analyzer.analyze(skill) == []
        finally:
            for server in (target, endpoint):
                server.shutdown()
                server.server_close()

        # The first hop carried the token, which is what makes following the redirect dangerous.
        assert received["endpoint"] == ["Bearer secret"]
        assert received["target"] == [], "the redirect was followed"
        assert analyzer.last_result is not None
        assert analyzer.last_result["status"] == "error"
        # The refusal reason must not carry the token.
        assert "secret" not in str(analyzer.last_error)


class TestMalformedAnswersDoNotCrash:
    @pytest.mark.parametrize("answers", [["unexpected"], "unexpected", 7, None])
    def test_a_non_mapping_answers_field_reads_as_unusable(self, answers: Any) -> None:
        # ``(payload.get("answers") or {}).get(...)`` raises AttributeError on a list,
        # outside the caller's error handling.
        assert SystemOneAnalyzer._read_probability({"answers": answers}) is None
