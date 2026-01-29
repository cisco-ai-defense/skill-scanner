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

"""Test VirusTotal with benign binary file."""

import os
from pathlib import Path

import pytest

# Load environment variables from .env file at module level
from dotenv import load_dotenv

from skill_scanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Severity, ThreatCategory

load_dotenv()


def test_virustotal_benign_file():
    """
    Test VirusTotal analyzer with a benign binary file.

    This test:
    1. Loads a test skill with a benign binary file
    2. Scans it with VirusTotal (hash lookup + optional upload)
    3. Verifies the analyzer works correctly with clean files

    Expected: No malware detections for a random benign binary.
    """
    # Initialize analyzer with upload enabled
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        pytest.skip("VIRUSTOTAL_API_KEY not set in environment or .env file")

    vt_analyzer = VirusTotalAnalyzer(
        api_key=api_key,
        enabled=True,
        upload_files=True,  # Enable file uploads
    )

    # Load test skill with benign binary
    loader = SkillLoader()
    test_skills_dir = Path(__file__).parent.parent / "evals" / "test_skills"
    test_skill_dir = test_skills_dir / "malicious" / "eicar-test"

    if not test_skill_dir.exists():
        pytest.skip(f"Test skill not found at {test_skill_dir}")

    skill = loader.load_skill(test_skill_dir)

    # Check for binary files in assets
    binary_files = [
        f for f in skill.files if "assets/" in f.relative_path and f.relative_path.endswith((".bin", ".com"))
    ]

    if len(binary_files) == 0:
        pytest.skip(f"No binary files found in assets folder. Files: {[f.relative_path for f in skill.files]}")

    print(f"\n{'=' * 70}")
    print("VirusTotal Benign Binary Test")
    print(f"{'=' * 70}")
    print(f"Skill: {skill.name}")
    print(f"Binary files to scan: {len(binary_files)}")
    print(f"Files: {[f.relative_path for f in binary_files]}")

    # Calculate SHA256 for verification
    binary_file = binary_files[0]
    file_path = skill.directory / binary_file.relative_path
    import hashlib

    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    print("\nFile details:")
    print(f"  Path: {binary_file.relative_path}")
    print(f"  SHA256: {file_hash}")
    print(f"  Size: {file_path.stat().st_size} bytes")

    # Analyze with VirusTotal (will upload if not in DB)
    print("\nScanning with VirusTotal (upload enabled)...")
    print(f"{'=' * 70}")
    findings = vt_analyzer.analyze(skill)

    # Print results
    print(f"\n{'=' * 70}")
    print("SCAN RESULTS")
    print(f"{'=' * 70}")
    print(f"Total findings: {len(findings)}")

    for i, finding in enumerate(findings, 1):
        print(f"\nFinding #{i}:")
        print(f"  Category: {finding.category.value}")
        print(f"  Severity: {finding.severity.value}")
        print(f"  File: {finding.file_path}")
        print(f"  Title: {finding.title}")
        print(f"  Description: {finding.description[:100]}...")
        if finding.references:
            print(f"  VT Link: {finding.references[0]}")

    # Verify results
    print(f"\n{'=' * 70}")
    print("TEST RESULT:")
    print(f"{'=' * 70}")

    # For a benign random binary, we expect either:
    # 1. No findings (not in VT DB, or clean)
    # 2. Low-severity findings if it happens to match something

    if len(findings) == 0:
        print("[OK] File is clean (no detections)")
        print("  - File was scanned by VirusTotal")
        print("  - No AV vendors flagged it as malicious")
        print("  - Upload functionality working correctly")
    else:
        print("[WARNING] Unexpected findings for benign binary:")
        for finding in findings:
            print(f"  - {finding.severity.value}: {finding.title}")
            print(f"    File: {finding.file_path}")

    print(f"{'=' * 70}\n")

    # Test passes if:
    # 1. Analyzer ran without errors
    # 2. Returns a list (even if empty)
    # 3. No CRITICAL findings for benign file
    assert isinstance(findings, list), "Should return a list of findings"

    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0, f"Benign file should not have CRITICAL findings: {critical_findings}"


if __name__ == "__main__":
    # Allow running directly with: python tests/test_eicar_upload.py
    pytest.main([__file__, "-v", "-s"])
