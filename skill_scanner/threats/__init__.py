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

"""
Threat mapping and taxonomy for Skill Scanner.

Aligned with Cisco AI Security Framework taxonomy.
"""

from .cisco_ai_taxonomy import (
    AISUBTECH_TAXONOMY,
    AITECH_TAXONOMY,
    VALID_AISUBTECH_CODES,
    VALID_AITECH_CODES,
    get_aisubtech_name,
    get_aitech_name,
    is_valid_aisubtech,
    is_valid_aitech,
)
from .threats import LLM_THREAT_MAPPING, YARA_THREAT_MAPPING, ThreatMapping

__all__ = [
    "ThreatMapping",
    "LLM_THREAT_MAPPING",
    "YARA_THREAT_MAPPING",
    "AITECH_TAXONOMY",
    "AISUBTECH_TAXONOMY",
    "VALID_AITECH_CODES",
    "VALID_AISUBTECH_CODES",
    "is_valid_aitech",
    "is_valid_aisubtech",
    "get_aitech_name",
    "get_aisubtech_name",
]
