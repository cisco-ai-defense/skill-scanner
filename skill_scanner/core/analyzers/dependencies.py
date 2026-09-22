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

"""Shared dependency record for advisory lookup.

A dependency is only queryable when it names one exact release, so every
collector normalizes to this record before the OSV analyzer batches it.
"""

from __future__ import annotations

from typing import NamedTuple

#: OSV ecosystem identifier for the JavaScript registry.
NPM_ECOSYSTEM = "npm"

#: OSV ecosystem identifier for the Python registry.
PYPI_ECOSYSTEM = "PyPI"


class ResolvedDependency(NamedTuple):
    """One dependency resolved to an exact version.

    Attributes:
        ecosystem: OSV ecosystem identifier (``PyPI``, ``npm``, ...).
        name: Package name as the registry knows it.
        version: Exact resolved version.
        source: Package-relative path of the declaring file.
        line_number: Best-effort 1-based line of the declaration.
        dev: True when the declaring file marks this a development dependency.
    """

    ecosystem: str
    name: str
    version: str
    source: str
    line_number: int | None
    dev: bool = False
