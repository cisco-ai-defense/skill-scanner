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

"""Shared URL classification for static analysis.

The suspicious/legitimate domain lists and the matching logic used to live
inside :class:`ContextExtractor` and only ran over Python string literals.
They are extracted here so any analyzer (Python AST, config files, etc.) can
classify a URL through a single source of truth.
"""

from __future__ import annotations

import re

# ONLY flag URLs to explicitly suspicious domains - not all unknown URLs
# Reference: https://lots-project.com/ (Living Off Trusted Sites)
SUSPICIOUS_DOMAINS: list[str] = [
    # Known exfil/C2/paste services (LOTS: Download, Exfiltration, C&C)
    "pastebin.com",
    "hastebin.com",
    "paste.ee",
    "rentry.co",
    "zerobin.net",
    "textbin.net",
    "termbin.com",
    "sprunge.us",
    "clbin.com",
    "ix.io",
    "pastetext.net",
    "pastie.org",
    "ideone.com",
    # File sharing services (LOTS: Download, Exfiltration)
    "transfer.sh",
    "filebin.net",
    "gofile.io",
    "anonfiles.com",
    "mediafire.com",
    "mega.nz",
    "wetransfer.com",
    "filetransfer.io",
    "ufile.io",
    "4sync.com",
    "uplooder.net",
    "filecloudonline.com",
    "sendspace.com",
    "siasky.net",
    # Tunneling/webhook services (LOTS: C&C, Exfiltration)
    "webhook.site",
    "requestbin",
    "ngrok.io",
    "ngrok-free.dev",
    "ngrok-free.app",
    "ngrok.app",
    "pipedream.net",
    "localhost.run",
    "trycloudflare.com",
    "bore.pub",
    "serveo.net",
    "localtunnel.me",
    # Code execution services (LOTS: C&C, Download)
    "codepen.io",
    "repl.co",
    "glitch.me",
    # Explicitly malicious example domains
    "attacker.example.com",
    "evil.example.com",
    "malicious.com",
    "c2-server.com",
]

# Domains that are always safe (not flagged even if matched by SUSPICIOUS_DOMAINS pattern)
# NOTE: We intentionally exclude file-hosting/messaging services that appear in LOTS
# (https://lots-project.com/) with Download/C&C capabilities, even if commonly used.
LEGITIMATE_DOMAINS: list[str] = [
    # AI provider services (API endpoints only, not user content)
    "api.anthropic.com",
    "statsig.anthropic.com",
    "api.openai.com",
    "api.together.xyz",
    "api.cohere.ai",
    "generativelanguage.googleapis.com",
    # Package registries (read-only, no user-uploaded executables)
    "registry.npmjs.org",
    "npmjs.com",
    "npmjs.org",
    "yarnpkg.com",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "pythonhosted.org",
    "crates.io",
    "rubygems.org",
    "pkg.go.dev",
    # System packages
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "debian.org",
    # XML schemas (for OOXML document processing)
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "www.w3.org",
    "purl.org",
    "json-schema.org",
    # Localhost and development
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    # Common safe services (API-focused, not file hosting)
    "stripe.com",
    "zoom.us",
    "twilio.com",
    "mailgun.com",
    "sentry.io",
    "datadog.com",
    "newrelic.com",
    "elastic.co",
    "mongodb.com",
    "redis.io",
    "postgresql.org",
    # NOTE: The following are intentionally NOT in this list due to LOTS risk:
    # - github.com, gitlab.com, bitbucket.org (Download, C&C)
    # - raw.githubusercontent.com (Download, C&C)
    # - discord.com, telegram.org, slack.com (C&C, Exfil)
    # - amazonaws.com, googleapis.com, azure.com, cloudflare.com (wildcard hosting)
    # - google.com, microsoft.com (too broad, includes file hosting)
    # - sendgrid.com (email tracking/download)
]

# Matches http(s) URLs; stops at whitespace, quotes, and common delimiters.
_URL_RE = re.compile(r"https?://[^\s\"'`<>)\]}]+")


def classify_url(url: str) -> str:
    """Classify a URL as ``"legitimate"``, ``"suspicious"``, or ``"unknown"``.

    Legitimate domains take precedence: a URL matching both a legitimate and a
    suspicious substring is treated as legitimate (matching the historical
    behavior of ``ContextExtractor``).
    """
    if any(domain in url for domain in LEGITIMATE_DOMAINS):
        return "legitimate"
    if any(domain in url for domain in SUSPICIOUS_DOMAINS):
        return "suspicious"
    return "unknown"


def extract_urls(text: str) -> list[str]:
    """Return http(s) URLs found in arbitrary text, de-duplicated in order."""
    seen: set[str] = set()
    urls: list[str] = []
    for match in _URL_RE.findall(text):
        cleaned = match.rstrip(".,;")
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls
