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
Data directory for Skill Scanner.

Contains prompts and rule files, matching MCP Scanner structure.
"""

from pathlib import Path

DATA_DIR = Path(__file__).parent
PROMPTS_DIR = DATA_DIR / "prompts"
YARA_RULES_DIR = DATA_DIR / "yara_rules"
RULES_DIR = DATA_DIR / "rules"

__all__ = ["DATA_DIR", "PROMPTS_DIR", "YARA_RULES_DIR", "RULES_DIR"]
