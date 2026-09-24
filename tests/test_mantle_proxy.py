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

"""The mantle signing proxy holds a credential that can spend money.

These cover the properties that keep that safe: loopback only, a required token,
and a bounded body. Nothing here reaches the network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from evals.lib import mantle_proxy


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    return tmp_path / "token"


def _serve(monkeypatch: pytest.MonkeyPatch, token: str, forward: Any) -> tuple[str, Any]:
    """Start the proxy on an ephemeral port with the forwarder stubbed out."""

    from http.server import ThreadingHTTPServer

    monkeypatch.setattr(mantle_proxy, "_sign_and_forward", forward)
    handler = mantle_proxy.build_handler(
        endpoint="https://example.invalid/openai/v1/chat/completions",
        region="us-east-1",
        token=token,
        timeout=5,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}", server


def _post(base: str, *, auth: str | None, path: str = "/v1/chat/completions", body: bytes = b"{}") -> tuple[int, bytes]:
    headers = {"Content-Type": "application/json"}
    if auth is not None:
        headers["Authorization"] = f"Bearer {auth}"
    request = urllib.request.Request(base + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


class TestBindAddress:
    def test_refuses_a_public_bind(self, token_file: Path) -> None:
        # Binding publicly would expose the signer to anything that can route here.
        with pytest.raises(SystemExit):
            mantle_proxy.main(["--host", "0.0.0.0", "--token-file", str(token_file)])

    def test_refuses_an_empty_token_file(self, token_file: Path) -> None:
        token_file.write_text("\n", encoding="utf-8")
        with pytest.raises(SystemExit):
            mantle_proxy.main(["--token-file", str(token_file)])


class TestAuthorization:
    def test_rejects_a_request_with_no_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[bytes] = []

        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            calls.append(body)
            return 200, b"{}"

        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, _ = _post(base, auth=None, body=b'{"messages":[]}')
        finally:
            server.shutdown()
        assert status == 401
        # Nothing may be signed for an unauthenticated caller.
        assert calls == []

    def test_rejects_a_wrong_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[bytes] = []

        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            calls.append(body)
            return 200, b"{}"

        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, _ = _post(base, auth="wrong", body=b'{"messages":[]}')
        finally:
            server.shutdown()
        assert status == 401
        assert calls == []

    def test_forwards_an_authorized_request_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[bytes] = []

        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            seen.append(body)
            return 200, b'{"choices":[]}'

        payload = b'{"model":"m","messages":[{"role":"user","content":"hi"}]}'
        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, response = _post(base, auth="secret", body=payload)
        finally:
            server.shutdown()
        assert status == 200
        # Byte-identical: SigV4 signs the body, so any rewrite would break the signature
        # and would also mean the two tools no longer send what their own code produced.
        assert seen == [payload]
        assert json.loads(response) == {"choices": []}


class TestRequestShape:
    def test_only_chat_completions_is_proxied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            raise AssertionError("must not be reached")

        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, _ = _post(base, auth="secret", path="/v1/embeddings", body=b"{}")
        finally:
            server.shutdown()
        assert status == 404

    def test_an_oversize_body_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            raise AssertionError("must not be reached")

        monkeypatch.setattr(mantle_proxy, "MAX_BODY_BYTES", 16)
        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, _ = _post(base, auth="secret", body=b"x" * 64)
        finally:
            server.shutdown()
        assert status == 413

    def test_an_upstream_status_is_passed_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            return 400, b'{"message":"schema rejected"}'

        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, response = _post(base, auth="secret", body=b'{"messages":[]}')
        finally:
            server.shutdown()
        # Collapsing this into a 500 would hide a schema rejection the caller falls back on.
        assert status == 400
        assert b"schema rejected" in response

    def test_a_forwarding_failure_does_not_leak_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            raise RuntimeError("secret-bearing detail about the request")

        base, server = _serve(monkeypatch, "secret", forward)
        try:
            status, response = _post(base, auth="secret", body=b'{"messages":[]}')
        finally:
            server.shutdown()
        assert status == 502
        # The type only. A message could carry skill content or a credential.
        assert b"RuntimeError" in response
        assert b"secret-bearing detail" not in response


class TestTokenFilePermissions:
    def test_the_token_file_is_created_0600_rather_than_chmod_ed_afterwards(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Asserting the *creation* mode, because the final mode cannot tell them apart.

        A write-then-chmod ends at 0600 too, so checking the resulting file would pass
        either way. What matters is that the file is never briefly readable by other
        local users, which means the mode has to be supplied at creation.
        """
        import os

        token_path = tmp_path / "token"
        modes: list[int] = []
        real_open = os.open

        def recording_open(path: Any, flags: int, mode: int = 0o777, **kwargs: Any) -> int:
            if str(path) == str(token_path):
                modes.append(mode)
            return real_open(path, flags, mode, **kwargs)

        monkeypatch.setattr(os, "open", recording_open)
        monkeypatch.setattr(mantle_proxy, "ThreadingHTTPServer", None)
        with pytest.raises(TypeError):
            # The server cannot start; the token is written before that point.
            mantle_proxy.main(["--token-file", str(token_path), "--endpoint", "https://example.invalid/x"])

        assert modes == [0o600], f"token file created with mode(s) {[oct(m) for m in modes]}"

    def test_an_existing_world_readable_token_is_refused(self, tmp_path: Path) -> None:
        token_path = tmp_path / "token"
        token_path.write_text("abc\n", encoding="utf-8")
        token_path.chmod(0o644)
        # Reusing a token other local users can read would let them drive the signer.
        with pytest.raises(SystemExit):
            mantle_proxy.main(["--token-file", str(token_path)])


class TestConnectionHandling:
    def test_a_refusal_closes_the_connection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A refusal returns before reading the body.

        Under HTTP/1.1 keep-alive the unread bytes stay in the socket, and the next
        request on that connection is parsed starting mid-body. A client that reuses
        connections then sees spurious errors, so the connection must be closed.
        """

        def forward(body: bytes, **_: Any) -> tuple[int, bytes]:
            raise AssertionError("must not be reached")

        handler_cls = mantle_proxy.build_handler(
            endpoint="https://example.invalid/x", region="us-east-1", token="secret", timeout=5
        )

        class Probe(handler_cls):  # type: ignore[valid-type,misc]
            def __init__(self) -> None:
                # Constructed without a socket: only _refuse's bookkeeping is under test.
                self.close_connection = False
                self.headers = {}
                self.sent: list[int] = []
                self.wfile = __import__("io").BytesIO()

            def send_response(self, code: int, message: str | None = None) -> None:
                self.sent.append(code)

            def send_header(self, *args: Any, **kwargs: Any) -> None:
                return None

            def end_headers(self) -> None:
                return None

        probe = Probe()
        probe._refuse(401, "missing or incorrect proxy token")
        assert probe.sent == [401]
        assert probe.close_connection is True
