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
JSON format reporter for scan results.
"""

import json

from ...core.models import Report, ScanResult


class JSONReporter:
    """Generates JSON format reports."""

    def __init__(self, pretty: bool = True):
        """
        Initialize JSON reporter.

        Args:
            pretty: If True, format JSON with indentation
        """
        self.pretty = pretty

    def generate_report(self, data: ScanResult | Report) -> str:
        """
        Generate JSON report.

        Args:
            data: ScanResult or Report object

        Returns:
            JSON string
        """
        report_dict = data.to_dict()

        if self.pretty:
            return json.dumps(report_dict, indent=2, default=str)
        else:
            return json.dumps(report_dict, default=str)

    def save_report(self, data: ScanResult | Report, output_path: str):
        """
        Save JSON report to file.

        Args:
            data: ScanResult or Report object
            output_path: Path to save file
        """
        report_json = self.generate_report(data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_json)
