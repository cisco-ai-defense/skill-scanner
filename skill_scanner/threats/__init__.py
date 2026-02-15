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
    AISUBTECH_FRAMEWORK_MAPPINGS,
    AISUBTECH_TAXONOMY,
    AITECH_FRAMEWORK_MAPPINGS,
    AITECH_TAXONOMY,
    TAXONOMY_ENV_VAR,
    VALID_AISUBTECH_CODES,
    VALID_AITECH_CODES,
    get_aisubtech_framework_mappings,
    get_aisubtech_name,
    get_aitech_framework_mappings,
    get_aitech_name,
    get_framework_mappings,
    get_taxonomy_source,
    is_valid_aisubtech,
    is_valid_aitech,
    reload_taxonomy,
)
from .threats import (
    LLM_THREAT_MAPPING,
    YARA_THREAT_MAPPING,
    ThreatMapping,
    configure_threat_mappings,
    get_threat_mapping_source,
)

__all__ = [
    "ThreatMapping",
    "LLM_THREAT_MAPPING",
    "YARA_THREAT_MAPPING",
    "AITECH_TAXONOMY",
    "AISUBTECH_TAXONOMY",
    "AITECH_FRAMEWORK_MAPPINGS",
    "AISUBTECH_FRAMEWORK_MAPPINGS",
    "TAXONOMY_ENV_VAR",
    "VALID_AITECH_CODES",
    "VALID_AISUBTECH_CODES",
    "is_valid_aitech",
    "is_valid_aisubtech",
    "get_aitech_name",
    "get_aisubtech_name",
    "get_aitech_framework_mappings",
    "get_aisubtech_framework_mappings",
    "get_framework_mappings",
    "reload_taxonomy",
    "get_taxonomy_source",
    "configure_threat_mappings",
    "get_threat_mapping_source",
]
