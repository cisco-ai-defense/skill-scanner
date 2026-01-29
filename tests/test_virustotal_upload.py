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

"""Test VirusTotal file upload with a fresh random file."""

import os
import secrets
import tempfile
from pathlib import Path

import pytest

# Load environment variables from .env file at module level
from dotenv import load_dotenv

from skill_scanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Skill, SkillFile

load_dotenv()


def test_virustotal_upload_fresh_file():
    """
    Test VirusTotal file upload with a randomly generated file.

    This creates a brand new file that VT has never seen before,
    forcing an actual upload to demonstrate the upload functionality.

    Expected: File gets uploaded, scanned, and should be clean (0 detections).
    """
    # Check for API key
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        pytest.skip("VIRUSTOTAL_API_KEY not set in environment or .env file")

    # Initialize analyzer with upload enabled
    vt_analyzer = VirusTotalAnalyzer(
        api_key=api_key,
        enabled=True,
        upload_files=True,  # Enable file uploads
    )

    # Create a temporary directory with a fresh random binary file
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        skill_md = tmpdir_path / "SKILL.md"
        skill_md.write_text("""---
name: vt-upload-test
description: Test skill for VirusTotal upload testing
license: MIT
---

# Test Skill for VT Upload

This is a temporary test skill for VirusTotal upload functionality testing.
It contains a randomly generated binary file for upload testing.
""")

        # Create assets directory
        assets_dir = tmpdir_path / "assets"
        assets_dir.mkdir()

        # Generate a random binary file (1KB of random data)
        # This guarantees VT has never seen this file before
        random_data = secrets.token_bytes(1024)
        random_file = assets_dir / "random_test.bin"
        random_file.write_bytes(random_data)

        # Calculate its hash for verification
        import hashlib

        file_hash = hashlib.sha256(random_data).hexdigest()

        print(f"\n{'=' * 70}")
        print("VirusTotal Upload Test (Fresh Random File)")
        print(f"{'=' * 70}")
        print("Generated new random binary file")
        print("  Path: assets/random_test.bin")
        print(f"  SHA256: {file_hash}")
        print(f"  Size: {len(random_data)} bytes")
        print("\nThis file has NEVER been seen by VirusTotal before.")
        print("It should trigger an upload...")

        # Load as a skill
        loader = SkillLoader()
        skill = loader.load_skill(tmpdir_path)

        # Analyze with VirusTotal (will upload since file is new)
        print(f"\n{'=' * 70}")
        print("Scanning with VirusTotal (upload enabled)...")
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

        # Verify results
        print(f"\n{'=' * 70}")
        print("TEST RESULT:")
        print(f"{'=' * 70}")

        # Random bytes should be clean (no detections expected)
        if len(findings) == 0:
            print("[OK] SUCCESS: File uploaded and scanned cleanly")
            print("   - File was uploaded to VirusTotal")
            print("   - Analysis completed successfully")
            print("   - No AV vendors flagged random data as malicious")
        else:
            print("[WARNING] Unexpected detections on random data:")
            for finding in findings:
                print(f"   - {finding.severity.value}: {finding.title}")

        print(f"{'=' * 70}\n")

        # Test assertions
        assert isinstance(findings, list), "Should return a list of findings"

        # Random data should not be flagged as malicious
        # (it's just random bytes, not actual malware)
        from skill_scanner.core.models import Severity

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0, f"Random data should not be flagged as CRITICAL: {critical_findings}"


if __name__ == "__main__":
    # Allow running directly with: python tests/test_virustotal_upload.py
    pytest.main([__file__, "-v", "-s"])
