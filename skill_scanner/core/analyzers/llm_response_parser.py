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
LLM Response Parser.

Handles parsing of LLM responses, extracting JSON from various formats.
"""

import json
from typing import Any


class ResponseParser:
    """Parses LLM responses and extracts JSON."""

    @staticmethod
    def parse(response_content: str) -> dict[str, Any]:
        """
        Parse LLM response JSON.

        Handles multiple formats:
        - Direct JSON
        - JSON in markdown code blocks
        - JSON with surrounding text

        Args:
            response_content: Raw response content

        Returns:
            Parsed JSON dictionary

        Raises:
            ValueError: If JSON cannot be parsed
        """
        if not response_content or not response_content.strip():
            raise ValueError("Empty response from LLM")

        # Try direct JSON parse
        try:
            return json.loads(response_content.strip())
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code blocks
        if "```json" in response_content:
            start = response_content.find("```json") + 7
            end = response_content.find("```", start)
            response_content = response_content[start:end].strip()
        elif "```" in response_content:
            start = response_content.find("```") + 3
            end = response_content.find("```", start)
            response_content = response_content[start:end].strip()

        # Try to find JSON by braces
        start_idx = response_content.find("{")
        if start_idx != -1:
            brace_count = 0
            for i in range(start_idx, len(response_content)):
                if response_content[i] == "{":
                    brace_count += 1
                elif response_content[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        json_str = response_content[start_idx : i + 1]
                        return json.loads(json_str)

        raise ValueError(f"Could not parse JSON from response: {response_content[:200]}")
