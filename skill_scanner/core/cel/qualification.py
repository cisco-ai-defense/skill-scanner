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

"""Exact production qualification for the bundled cel-go helper.

Qualification is deliberately an identity check, not a compatible version
range.  The Python process already verifies the helper protocol and ScanFacts
descriptor during its initialization handshake; release evidence additionally
binds the helper build version to the scanner build that produced the report.
"""

from __future__ import annotations

from .go_runtime import CEL_GO_VERSION, MINIMUM_GO_VERSION, PROTOCOL_VERSION, SCAN_FACTS_DESCRIPTOR_HASH

QUALIFIED_RUNTIME = "cel-go"
QUALIFIED_MODULE = "cel.dev/cel-go"
QUALIFIED_ENGINE_VERSION = CEL_GO_VERSION
QUALIFIED_TAG = CEL_GO_VERSION
QUALIFIED_COMMIT = "f2039bc647bca407d882d90436fc8b91bab1ae62"
QUALIFIED_RELEASE_DATE = "2026-08-19"
QUALIFIED_PROTOCOL_VERSION = PROTOCOL_VERSION
QUALIFIED_DESCRIPTOR_HASH = SCAN_FACTS_DESCRIPTOR_HASH

_FORBIDDEN_HELPER_VERSIONS = frozenset(
    {
        "development",
        "not_loaded",
        "unknown",
        "unspecified",
        "0.0.0+unknown",
    }
)


def qualification_error(
    runtime: str,
    runtime_version: str,
    *,
    expected_helper_version: str,
) -> str | None:
    """Return why telemetry is not the exact qualified cel-go build.

    ``runtime_version`` is emitted by :class:`CelGoRuntime` as
    ``v0.32.0;helper=<release-build>``.  Development helpers are intentionally
    never release-qualified, even when their embedded cel-go engine matches.
    """

    if runtime != QUALIFIED_RUNTIME:
        return f"runtime must be exactly {QUALIFIED_RUNTIME!r}"
    prefix = f"{QUALIFIED_ENGINE_VERSION};helper="
    if not isinstance(runtime_version, str) or not runtime_version.startswith(prefix):
        return f"runtime version must use {prefix}<release-build>"
    helper_version = runtime_version[len(prefix) :]
    if (
        not helper_version
        or len(helper_version.encode("utf-8")) > 128
        or any(ord(character) < 33 or ord(character) == 127 for character in helper_version)
        or helper_version in _FORBIDDEN_HELPER_VERSIONS
    ):
        return "helper version must identify a non-development release build"
    if (
        not isinstance(expected_helper_version, str)
        or not expected_helper_version
        or expected_helper_version in _FORBIDDEN_HELPER_VERSIONS
    ):
        return "scanner producer version is not release-qualified"
    if helper_version != expected_helper_version:
        return f"helper build {helper_version!r} does not match scanner producer {expected_helper_version!r}"
    return None


def is_qualified_runtime(
    runtime: str,
    runtime_version: str,
    *,
    expected_helper_version: str,
) -> bool:
    """Whether telemetry identifies the exact qualified release helper."""

    return (
        qualification_error(
            runtime,
            runtime_version,
            expected_helper_version=expected_helper_version,
        )
        is None
    )
