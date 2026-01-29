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

"""Unit tests for VirusTotal analyzer."""

import os
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Severity, ThreatCategory


@pytest.fixture
def example_skills_dir():
    """Get path to example skills directory."""
    return Path(__file__).parent.parent / "evals" / "test_skills"


@pytest.fixture
def vt_analyzer_disabled():
    """Create a disabled VT analyzer (for testing without API key)."""
    return VirusTotalAnalyzer(api_key=None, enabled=False)


@pytest.fixture
def vt_analyzer_mock():
    """Create a VT analyzer with mock API key (won't make real requests)."""
    return VirusTotalAnalyzer(api_key="test_key_for_testing", enabled=True)


@pytest.fixture
def vt_analyzer_real():
    """
    Create a VT analyzer with real API key if available.
    Tests using this fixture will be skipped if no API key is set.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        pytest.skip("VIRUSTOTAL_API_KEY environment variable not set")
    return VirusTotalAnalyzer(api_key=api_key, enabled=True)


def test_vt_analyzer_disabled_returns_empty(vt_analyzer_disabled, example_skills_dir):
    """Test that disabled analyzer returns no findings."""
    loader = SkillLoader()
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    findings = vt_analyzer_disabled.analyze(skill)

    assert findings == []


def test_binary_file_detection(vt_analyzer_mock):
    """Test binary vs text file detection."""
    # Binary files that should be scanned
    assert vt_analyzer_mock._is_binary_file("test.png")
    assert vt_analyzer_mock._is_binary_file("document.pdf")
    assert vt_analyzer_mock._is_binary_file("archive.zip")
    assert vt_analyzer_mock._is_binary_file("image.jpg")
    assert vt_analyzer_mock._is_binary_file("program.exe")

    # Code/text files that should NOT be scanned
    assert not vt_analyzer_mock._is_binary_file("script.py")
    assert not vt_analyzer_mock._is_binary_file("README.md")
    assert not vt_analyzer_mock._is_binary_file("code.js")
    assert not vt_analyzer_mock._is_binary_file("style.css")
    assert not vt_analyzer_mock._is_binary_file("config.json")
    assert not vt_analyzer_mock._is_binary_file("data.yaml")
    assert not vt_analyzer_mock._is_binary_file("test.txt")


def test_excluded_extensions(vt_analyzer_mock):
    """Test that all excluded extensions are properly filtered."""
    excluded_exts = [".py", ".js", ".md", ".txt", ".json", ".yaml", ".html", ".css", ".xml", ".sh", ".sql"]

    for ext in excluded_exts:
        assert not vt_analyzer_mock._is_binary_file(f"file{ext}")


def test_binary_extensions(vt_analyzer_mock):
    """Test that all binary extensions are properly detected."""
    binary_exts = [".png", ".jpg", ".pdf", ".zip", ".exe", ".dll", ".doc", ".docx", ".xls", ".xlsx"]

    for ext in binary_exts:
        assert vt_analyzer_mock._is_binary_file(f"file{ext}")


def test_unknown_extension_defaults_to_not_binary(vt_analyzer_mock):
    """Test that unknown extensions default to not scanning (conservative)."""
    # Unknown/uncommon extensions should not be scanned by default
    assert not vt_analyzer_mock._is_binary_file("file.xyz")
    assert not vt_analyzer_mock._is_binary_file("file.unknown")
    assert not vt_analyzer_mock._is_binary_file("file.custom")


def test_analyzer_initialization():
    """Test analyzer initialization with different configurations."""
    # Without API key
    analyzer1 = VirusTotalAnalyzer(api_key=None)
    assert not analyzer1.enabled
    assert not analyzer1.upload_files

    # With API key (hash-only mode by default)
    analyzer2 = VirusTotalAnalyzer(api_key="test_key")
    assert analyzer2.enabled
    assert not analyzer2.upload_files

    # With file upload enabled
    analyzer3 = VirusTotalAnalyzer(api_key="test_key", upload_files=True)
    assert analyzer3.enabled
    assert analyzer3.upload_files

    # Explicitly disabled
    analyzer4 = VirusTotalAnalyzer(api_key="test_key", enabled=False)
    assert not analyzer4.enabled


def test_sha256_calculation(tmp_path, vt_analyzer_mock):
    """Test SHA256 hash calculation."""
    # Create a test file
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"Hello, World!")

    # Calculate hash
    file_hash = vt_analyzer_mock._calculate_sha256(test_file)

    # Verify it's a valid SHA256 hash (64 hex characters)
    assert len(file_hash) == 64
    assert all(c in "0123456789abcdef" for c in file_hash)

    # Verify it's consistent
    file_hash2 = vt_analyzer_mock._calculate_sha256(test_file)
    assert file_hash == file_hash2

    # Known hash for "Hello, World!"
    expected_hash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    assert file_hash == expected_hash


def test_no_real_api_calls_in_tests(vt_analyzer_mock, example_skills_dir):
    """
    Test that analyzer handles missing API gracefully.
    Note: This test won't make real API calls, it will just verify
    the analyzer doesn't crash with invalid credentials.
    """
    loader = SkillLoader()
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    # Should not crash, even with invalid API key
    # (will just print warnings and return empty findings)
    try:
        findings = vt_analyzer_mock.analyze(skill)
        # Should return empty list since no binary files or API will fail
        assert isinstance(findings, list)
    except Exception as e:
        # If it fails, it should be a network error, not a code error
        assert "request" in str(e).lower() or "connection" in str(e).lower()


def test_eicar_skill_structure(example_skills_dir):
    """
    Test that the EICAR test skill loads correctly and contains binary files.

    Note: Due to antivirus software potentially quarantining real EICAR files,
    we use a regular binary file for testing the file detection logic.
    """
    loader = SkillLoader()
    eicar_skill_dir = example_skills_dir / "malicious" / "eicar-test"

    # Check if test skill exists
    if not eicar_skill_dir.exists():
        pytest.skip("EICAR test skill not found")

    # Load the skill
    skill = loader.load_skill(eicar_skill_dir)

    # Verify skill loaded
    assert skill.name == "eicar-test"

    # Check for binary files in assets folder
    binary_files = [f for f in skill.files if "assets" in f.relative_path]
    assert len(binary_files) > 0, "Should have at least one file in assets folder"

    print("\n[OK] EICAR test skill structure verified")
    print(f"  Skill name: {skill.name}")
    print(f"  Total files: {len(skill.files)}")
    print(f"  Binary files in assets: {len(binary_files)}")


@pytest.mark.skipif(not os.getenv("VIRUSTOTAL_API_KEY"), reason="Requires VIRUSTOTAL_API_KEY")
def test_virustotal_api_integration(vt_analyzer_real, example_skills_dir):
    """
    Test VirusTotal API integration with a real binary file.

    This test requires VIRUSTOTAL_API_KEY environment variable.
    The test uses a regular binary file (not EICAR) to verify the
    VT API integration works correctly.

    Note: The file is random data, so VT will likely return "not found" (404),
    which is the expected behavior for unknown files.
    """
    loader = SkillLoader()
    eicar_skill_dir = example_skills_dir / "malicious" / "eicar-test"

    # Check if test skill exists
    if not eicar_skill_dir.exists():
        pytest.skip("EICAR test skill not found")

    # Load the skill containing binary file
    skill = loader.load_skill(eicar_skill_dir)

    # Verify we have binary files to scan
    binary_files = [f for f in skill.files if vt_analyzer_real._is_binary_file(f.relative_path)]

    if len(binary_files) == 0:
        pytest.skip("No binary files found in test skill")

    # Scan with VirusTotal (will make real API call)
    findings = vt_analyzer_real.analyze(skill)

    # For a random binary file, VT will likely return 404 (not found)
    # So we expect 0 findings, which is correct behavior
    assert isinstance(findings, list), "Should return a list of findings"

    print("\n[OK] VirusTotal API integration test passed!")
    print(f"  Binary files scanned: {len(binary_files)}")
    print(f"  Findings: {len(findings)}")
    print(f"  Status: {'Malicious files detected' if findings else 'No known threats (file not in VT database)'}")
