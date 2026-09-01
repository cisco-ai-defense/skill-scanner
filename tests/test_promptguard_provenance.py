# Copyright 2026 Cisco Systems, Inc.
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

"""Provenance regression coverage for the PromptGuard pack (issue #169)."""

from pathlib import Path

import yaml

PACK_DIR = Path(__file__).parents[1] / "skill_scanner" / "data" / "packs" / "promptguard"
SOURCE_COMMIT = "699431857cc2021fed8d8fad9ec79c437bbae009"


def test_promptguard_pack_uses_immutable_in_repository_source() -> None:
    manifest = yaml.safe_load((PACK_DIR / "pack.yaml").read_text(encoding="utf-8"))
    source_url = manifest["pack"]["source_url"]

    assert SOURCE_COMMIT in source_url
    assert source_url.startswith("https://github.com/cisco-ai-defense/skill-scanner/tree/")
    assert "PR #89" in manifest["pack"]["author"]


def test_promptguard_pack_contains_no_dead_external_repository_links() -> None:
    pack_text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(PACK_DIR.rglob("*")) if path.is_file())

    assert "github.com/promptguard/promptguard" not in pack_text.lower()
    assert "github.com/cisco-ai-defense/skill-scanner/pull/89" in pack_text
