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

from __future__ import annotations

import pytest

from skill_scanner.core.cel import qualification
from skill_scanner.core.cel.go_runtime import CEL_GO_VERSION, PROTOCOL_VERSION, SCAN_FACTS_DESCRIPTOR_HASH


def test_qualification_is_exactly_bound_to_go_engine_protocol_and_descriptor() -> None:
    assert qualification.QUALIFIED_RUNTIME == "cel-go"
    assert qualification.QUALIFIED_ENGINE_VERSION == CEL_GO_VERSION == "v0.32.0"
    assert qualification.MINIMUM_GO_VERSION == "1.27.1"
    assert qualification.QUALIFIED_PROTOCOL_VERSION == PROTOCOL_VERSION == 2
    assert qualification.QUALIFIED_DESCRIPTOR_HASH == SCAN_FACTS_DESCRIPTOR_HASH
    assert qualification.QUALIFIED_DESCRIPTOR_HASH == (
        "0dd0799a2276e2f6fc844bc1da5835e2a05ccbca3802d1dea635d3b0d4cd1a13"
    )


def test_release_helper_must_match_scanner_producer_exactly() -> None:
    assert (
        qualification.qualification_error(
            "cel-go",
            "v0.32.0;helper=2.0.0",
            expected_helper_version="2.0.0",
        )
        is None
    )
    assert qualification.is_qualified_runtime(
        "cel-go",
        "v0.32.0;helper=2.0.0",
        expected_helper_version="2.0.0",
    )


@pytest.mark.parametrize(
    ("runtime", "runtime_version", "producer", "message"),
    [
        ("cel-expr-python", "v0.32.0;helper=2.0.0", "2.0.0", "runtime must be exactly"),
        ("cel-go", "v0.31.0;helper=2.0.0", "2.0.0", "runtime version must use"),
        ("cel-go", "v0.32.0;helper=development", "2.0.0", "non-development release build"),
        ("cel-go", "v0.32.0;helper=other", "2.0.0", "does not match scanner producer"),
        ("cel-go", "v0.32.0;helper=0.0.0+unknown", "0.0.0+unknown", "non-development release build"),
    ],
)
def test_unqualified_runtime_identity_is_rejected(
    runtime: str,
    runtime_version: str,
    producer: str,
    message: str,
) -> None:
    error = qualification.qualification_error(
        runtime,
        runtime_version,
        expected_helper_version=producer,
    )

    assert error is not None
    assert message in error
