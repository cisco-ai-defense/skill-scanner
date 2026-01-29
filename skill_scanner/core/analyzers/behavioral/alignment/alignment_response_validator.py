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

"""Alignment Response Validator for Semantic Verification.

This module validates and parses LLM responses from semantic alignment verification queries.

The validator:
- Parses JSON responses from LLM
- Validates response schema and required fields
- Handles parsing errors gracefully
"""

import json
import logging
from typing import Any


class AlignmentResponseValidator:
    """Validates alignment verification responses from LLM.

    Ensures LLM responses are properly formatted JSON with required
    alignment check fields.
    """

    def __init__(self):
        """Initialize the alignment response validator."""
        self.logger = logging.getLogger(__name__)

    def validate(self, response: str) -> dict[str, Any] | None:
        """Parse and validate alignment check response.

        Args:
            response: JSON response from LLM

        Returns:
            Parsed alignment check result or None if invalid
        """
        if not response or not response.strip():
            self.logger.warning("Empty response from LLM")
            return None

        try:
            # Try to parse JSON
            data = json.loads(response)

            # Validate it's a dictionary
            if not isinstance(data, dict):
                self.logger.warning(f"Response is not a JSON object: {type(data)}")
                return None

            # Check for required fields
            if not self._has_required_fields(data):
                self.logger.warning(f"Response missing required fields. Got: {list(data.keys())}")
                return None

            self.logger.debug(f"LLM response validated: mismatch_detected={data.get('mismatch_detected')}")
            return data

        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid JSON response: {e}")
            self.logger.debug(f"Raw response (first 500 chars): {response[:500]}")
            # Try to extract JSON from markdown code blocks
            return self._extract_json_from_markdown(response)
        except Exception as e:
            self.logger.error(f"Unexpected error validating response: {e}")
            return None

    def _has_required_fields(self, data: dict[str, Any]) -> bool:
        """Check if response has all required alignment check fields.

        Args:
            data: Parsed JSON response

        Returns:
            True if all required fields present
        """
        required_fields = ["mismatch_detected"]

        # Check required fields
        if not all(field in data for field in required_fields):
            return False

        # If mismatch detected, check for additional required fields
        if data.get("mismatch_detected"):
            mismatch_required = ["confidence", "summary"]
            if not all(field in data for field in mismatch_required):
                return False

        return True

    def _extract_json_from_markdown(self, response: str) -> dict[str, Any] | None:
        """Try to extract JSON from markdown code blocks.

        Sometimes LLMs wrap JSON in ```json ... ``` blocks.

        Args:
            response: Response that may contain markdown

        Returns:
            Parsed JSON or None
        """
        try:
            # Look for ```json ... ``` or ``` ... ```
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                json_str = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                json_str = response[start:end].strip()
            else:
                return None

            data = json.loads(json_str)
            if isinstance(data, dict) and self._has_required_fields(data):
                return data

        except Exception:
            pass

        return None
