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

"""Basic example of scanning a skill package."""

from pathlib import Path

from skill_scanner import SkillScanner
from skill_scanner.core.analyzers.static import StaticAnalyzer

# Create scanner with static analyzer
scanner = SkillScanner(analyzers=[StaticAnalyzer()])

# Scan a skill directory
# Update this path to point to a valid skill directory
skill_path = Path("evals/test_skills/safe/simple-formatter")
if not skill_path.exists():
    print(f"Error: Skill directory not found: {skill_path}")
    print("Please update the skill_path variable to point to a valid skill.")
    exit(1)

result = scanner.scan_skill(skill_path)

# Print results
print(f"Skill: {result.skill_name}")
print(f"Safe: {result.is_safe}")
print(f"Findings: {len(result.findings)}")

for finding in result.findings:
    print(f"  [{finding.severity.value}] {finding.title}")
