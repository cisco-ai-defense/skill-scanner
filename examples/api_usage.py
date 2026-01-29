#!/usr/bin/env python3
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
API usage example - interacting with the Skill Scanner API server.

This example demonstrates:
1. Starting the API server programmatically
2. Making API requests
3. Uploading and scanning ZIP files
4. Batch scanning via API

Prerequisites:
    pip install httpx

Usage:
    # Terminal 1: Start API server
    skill-scanner-api --port 8000

    # Terminal 2: Run this example
    python api_usage.py
"""

import json
import tempfile
import zipfile
from pathlib import Path

import httpx

API_BASE_URL = "http://localhost:8000"


def check_health():
    """Check API server health."""
    print("Checking API server health...")
    response = httpx.get(f"{API_BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200


def scan_skill_directory(skill_dir: str, use_llm: bool = False):
    """Scan a skill directory via API."""
    print(f"\nScanning skill directory: {skill_dir}")

    payload = {"skill_directory": skill_dir, "use_llm": use_llm, "llm_provider": "anthropic"}

    response = httpx.post(f"{API_BASE_URL}/scan", json=payload)

    if response.status_code == 200:
        result = response.json()
        print("[OK] Scan completed!")
        print(f"   Skill: {result['skill_name']}")
        print(f"   Safe: {result['is_safe']}")
        print(f"   Findings: {result['findings_count']}")
        return result
    else:
        print(f"[ERROR] Scan failed: {response.status_code}")
        print(f"   Error: {response.text}")
        return None


def scan_uploaded_zip(zip_path: Path, use_llm: bool = False):
    """Upload and scan a ZIP file."""
    print(f"\nUploading and scanning ZIP: {zip_path}")

    with open(zip_path, "rb") as f:
        files = {"file": (zip_path.name, f, "application/zip")}
        data = {"use_llm": str(use_llm).lower(), "llm_provider": "anthropic"}

        response = httpx.post(f"{API_BASE_URL}/scan-upload", files=files, data=data)

    if response.status_code == 200:
        result = response.json()
        print("[OK] Upload scan completed!")
        print(f"   Skill: {result['skill_name']}")
        print(f"   Safe: {result['is_safe']}")
        print(f"   Findings: {result['findings_count']}")
        return result
    else:
        print(f"[ERROR] Upload scan failed: {response.status_code}")
        print(f"   Error: {response.text}")
        return None


def batch_scan(skills_dir: str, recursive: bool = False):
    """Start a batch scan."""
    print(f"\nStarting batch scan: {skills_dir}")

    payload = {"skills_directory": skills_dir, "recursive": recursive, "use_llm": False}

    response = httpx.post(f"{API_BASE_URL}/scan-batch", json=payload)

    if response.status_code == 200:
        result = response.json()
        scan_id = result["scan_id"]
        print("[OK] Batch scan started!")
        print(f"   Scan ID: {scan_id}")
        print(f"   Status: {result['status']}")
        return scan_id
    else:
        print(f"[ERROR] Batch scan failed: {response.status_code}")
        print(f"   Error: {response.text}")
        return None


def get_batch_results(scan_id: str):
    """Get batch scan results."""
    print(f"\nGetting batch scan results: {scan_id}")

    response = httpx.get(f"{API_BASE_URL}/scan-batch/{scan_id}")

    if response.status_code == 200:
        result = response.json()
        print("[OK] Results retrieved!")
        print(f"   Status: {result['status']}")
        if result["status"] == "completed":
            print(f"   Total Skills: {result.get('total_skills_scanned', 0)}")
            print(f"   Safe Skills: {result.get('safe_count', 0)}")
            print(f"   Unsafe Skills: {result.get('unsafe_count', 0)}")
        return result
    else:
        print(f"[ERROR] Failed to get results: {response.status_code}")
        print(f"   Error: {response.text}")
        return None


def create_test_zip(skill_dir: Path, output_zip: Path):
    """Create a ZIP file from a skill directory."""
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file_path in skill_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(skill_dir)
                zipf.write(file_path, arcname)


def main():
    print("=" * 60)
    print("Skill Scanner API Usage Example")
    print("=" * 60)

    # Check health
    if not check_health():
        print("\n[ERROR] API server is not running!")
        print("Please start it with: skill-scanner-api --port 8000")
        return 1

    # Example 1: Scan a skill directory
    example_skill = Path("evals/test_skills/safe/simple-formatter")
    if example_skill.exists():
        scan_skill_directory(str(example_skill.absolute()), use_llm=False)

    # Example 2: Upload and scan a ZIP file
    if example_skill.exists():
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            zip_path = Path(tmp.name)
            create_test_zip(example_skill, zip_path)
            scan_uploaded_zip(zip_path, use_llm=False)
            zip_path.unlink()  # Cleanup

    # Example 3: Batch scan
    skills_dir = Path("evals/test_skills")
    if skills_dir.exists():
        scan_id = batch_scan(str(skills_dir.absolute()), recursive=False)
        if scan_id:
            import time

            print("\nWaiting for batch scan to complete...")
            time.sleep(2)  # Wait a bit
            get_batch_results(scan_id)

    print("\n" + "=" * 60)
    print("Example completed!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    exit(main())
