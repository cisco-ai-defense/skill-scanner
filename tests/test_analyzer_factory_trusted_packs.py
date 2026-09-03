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

"""Trusted rule-pack forwarding tests for the centralized analyzer factory."""

from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.core.analyzer_factory import build_analyzers, build_core_analyzers
from skill_scanner.core.scan_policy import ScanPolicy


@pytest.mark.parametrize("factory", [build_core_analyzers, build_analyzers])
def test_trusted_pack_dirs_forwarded_to_static_analyzer(factory, tmp_path: Path) -> None:
    """Both public factories pass trusted packs to ``StaticAnalyzer`` unchanged."""
    trusted_dirs = [tmp_path / "one", tmp_path / "two"]
    policy = ScanPolicy()
    policy.analyzers.bytecode = False
    policy.analyzers.pipeline = False

    with patch("skill_scanner.core.analyzer_factory.StaticAnalyzer") as static_analyzer:
        factory(policy, trusted_pack_dirs=trusted_dirs)

    static_analyzer.assert_called_once_with(
        custom_yara_rules_path=None,
        policy=policy,
        extra_rules_dirs=None,
        trusted_pack_dirs=trusted_dirs,
    )
