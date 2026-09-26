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

"""Loopback SigV4 signer for the Bedrock mantle route.

The cross-tool benchmark compares this scanner against NVIDIA SkillSpector on the
*same* model, so that a measured gap is attributable to the engine rather than to
the model.  The model used, ``google.gemma-4-26b-a4b``, is reachable only through
the Bedrock mantle route, which authenticates with SigV4.  SkillSpector's
``openai_compatible`` provider sends a static bearer token and has no SigV4 path,
so it cannot reach that endpoint on its own.

This process bridges the two: it accepts OpenAI-compatible
``POST /v1/chat/completions`` on loopback, signs the body with SigV4, forwards it
to the mantle endpoint, and returns the response unchanged.  Nothing is
translated, so both tools send the body their own code produced.

Run it beside the benchmark::

    python evals/lib/mantle_proxy.py --port 8713 --token-file ~/.mantle-proxy-token &
    python evals/runners/cross_tool_benchmark.py \\
        --skillspector-compat-base-url http://127.0.0.1:8713/v1 \\
        --skillspector-compat-token-file ~/.mantle-proxy-token ...

Deliberate properties, because this holds a credential that can spend money:

* It binds to loopback only, and refuses any other bind address.
* It requires a shared token, so another local process cannot borrow the signer.
  The token authenticates callers to this proxy; it is not an AWS credential.
* It never logs request or response bodies, prompts, or headers.
* It is an evaluation helper. It is not part of the scanner and not on the
  release path.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# A single request can carry a whole skill, so the cap is generous; it exists only
# to stop an unbounded read.
MAX_BODY_BYTES = 8 * 1024 * 1024

DEFAULT_TIMEOUT_SECONDS = 300


def _sign_and_forward(body: bytes, *, endpoint: str, region: str, timeout: int) -> tuple[int, bytes]:
    """SigV4-sign *body* and forward it, returning the upstream status and bytes."""

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.session import Session

    from skill_scanner.core.analyzers.llm_provider_config import BEDROCK_MANTLE_SIGV4_SERVICE

    credentials = Session().get_credentials()
    if credentials is None:
        raise RuntimeError("no AWS credentials available to sign mantle requests")

    signed = AWSRequest(method="POST", url=endpoint, data=body, headers={"Content-Type": "application/json"})
    SigV4Auth(credentials.get_frozen_credentials(), BEDROCK_MANTLE_SIGV4_SERVICE, region).add_auth(signed)

    request = urllib.request.Request(endpoint, data=body, headers=dict(signed.headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https endpoint
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        # Forwarded verbatim: the caller needs the upstream status to decide whether
        # to fall back, and swallowing it into a 500 would hide a schema rejection.
        return int(error.code), error.read()


def build_handler(*, endpoint: str, region: str, token: str, timeout: int) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            """Silence the default logger.

            Its default line includes the request path. Bodies never reach it, but the
            proxy is deliberately quiet: nothing about a scanned skill should land in a
            terminal scrollback or a CI log.
            """

        def _refuse(self, status: int, message: str) -> None:
            # Every refusal returns before reading the request body. With HTTP/1.1
            # keep-alive the unread bytes stay in the socket and the next request on that
            # connection is parsed starting mid-body, so a client that reuses connections
            # sees spurious 400s. Closing is simpler than draining a body we rejected.
            self.close_connection = True
            payload = json.dumps({"error": {"message": message}}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802 - stdlib signature
            if not self.path.rstrip("/").endswith("/chat/completions"):
                self._refuse(404, "only /v1/chat/completions is proxied")
                return

            presented = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            # compare_digest so a wrong token cannot be recovered by timing.
            if not presented or not secrets.compare_digest(presented, token):
                self._refuse(401, "missing or incorrect proxy token")
                return

            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._refuse(400, "unreadable Content-Length")
                return
            if length <= 0:
                self._refuse(400, "empty request body")
                return
            if length > MAX_BODY_BYTES:
                self._refuse(413, "request body exceeds the proxy limit")
                return

            body = self.rfile.read(length)
            try:
                status, upstream = _sign_and_forward(body, endpoint=endpoint, region=region, timeout=timeout)
            except Exception as error:  # noqa: BLE001 - one bad request must not kill the proxy
                # The type and message only; a body or header could contain skill content
                # or a credential.
                self._refuse(502, f"mantle request failed: {type(error).__name__}")
                _ = error
                return

            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(upstream)))
            self.end_headers()
            self.wfile.write(upstream)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8713)
    parser.add_argument("--host", default="127.0.0.1", help="Loopback only; any other value is refused.")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Mantle chat-completions URL. Defaults to the one the scanner's provider config resolves.",
    )
    parser.add_argument(
        "--token-file",
        required=True,
        help="File holding the shared proxy token. Created with a fresh random token if absent.",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        # Binding publicly would expose a credential that can spend money to anything
        # that can route to this host.
        parser.error(f"refusing to bind a signing proxy to {args.host!r}; loopback only")

    token_path = Path(args.token_file).expanduser()
    if token_path.exists():
        if token_path.stat().st_mode & 0o077:
            parser.error(f"{token_path} is readable by other users; run chmod 600 on it first")
        token = token_path.read_text(encoding="utf-8").strip()
        if not token:
            parser.error(f"{token_path} is empty; delete it to have a token generated")
    else:
        token = secrets.token_urlsafe(32)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        # Created 0600 by os.open rather than written and then chmod-ed: write_text
        # applies the process umask, leaving the token readable by other local users for
        # the moment between the two calls.
        descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")

    endpoint = args.endpoint
    if endpoint is None:
        from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
        from skill_scanner.core.analyzers.llm_request_handler import LLMRequestHandler

        config = ProviderConfig(model="bedrock-mantle/google.gemma-4-26b-a4b", aws_region=args.region)
        endpoint = LLMRequestHandler(provider_config=config, max_tokens=16)._bedrock_mantle_endpoint()

    handler = build_handler(endpoint=endpoint, region=args.region, token=token, timeout=args.timeout)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    # The endpoint is printed; the token is not.
    print(f"signing mantle requests for http://{args.host}:{args.port}/v1 -> {endpoint}", flush=True)
    print(f"proxy token in {token_path} (mode 600)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
