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
Pre-commit hook for scanning agent skills for security issues.

This hook scans staged skill directories for security vulnerabilities
and blocks commits that contain HIGH or CRITICAL severity findings.

Usage:
    1. Install as a pre-commit hook:
       skill-scanner-pre-commit install

    2. Or add to .pre-commit-config.yaml:
       - repo: local
         hooks:
           - id: skill-scanner
             name: Skill Scanner
             entry: skill-scanner-pre-commit
             language: python
             types: [file]
             pass_filenames: false

Configuration:
    Create a .skill_scannerrc file in your repo root:

    {
        "severity_threshold": "high",  # block on: critical, high, medium, low
        "skills_path": ".claude/skills",
        "fail_fast": true
    }
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Default configuration
DEFAULT_CONFIG = {
    "severity_threshold": "high",  # Block commits on HIGH or CRITICAL
    "skills_path": ".claude/skills",  # Default skills location
    "fail_fast": True,
    "use_behavioral": False,
    "use_trigger": True,
}

# Severity levels (higher number = more severe)
SEVERITY_LEVELS = {
    "safe": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def load_config(repo_root: Path) -> dict:
    """
    Load configuration from .skill_scannerrc file.

    Args:
        repo_root: Repository root directory

    Returns:
        Configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()

    config_paths = [
        repo_root / ".skill_scannerrc",
        repo_root / ".skill_scannerrc.json",
        repo_root / "skill_scanner.json",
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    user_config = json.load(f)
                    config.update(user_config)
                    break
            except (OSError, json.JSONDecodeError) as e:
                print(f"Warning: Failed to load config from {config_path}: {e}", file=sys.stderr)

    return config


def get_staged_files() -> list[str]:
    """
    Get list of staged files from git.

    Returns:
        List of staged file paths relative to repo root
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.split("\n") if f.strip()]
    except subprocess.CalledProcessError:
        return []


def get_affected_skills(staged_files: list[str], skills_path: str) -> set[Path]:
    """
    Identify skill directories affected by staged changes.

    Args:
        staged_files: List of staged file paths
        skills_path: Base path for skills

    Returns:
        Set of affected skill directory paths
    """
    affected_skills = set()
    skills_prefix = skills_path.rstrip("/") + "/"

    for file_path in staged_files:
        # Check if file is in skills directory
        if file_path.startswith(skills_prefix) or file_path.startswith(skills_path):
            # Extract the skill directory (first subdirectory under skills_path)
            relative = file_path[len(skills_path) :].lstrip("/")
            parts = relative.split("/")

            if parts:
                skill_dir = Path(skills_path) / parts[0]
                skill_md = skill_dir / "SKILL.md"
                if skill_md.exists():
                    affected_skills.add(skill_dir)

        # Also check for SKILL.md directly in case skills are at different paths
        if file_path.endswith("SKILL.md"):
            skill_dir = Path(file_path).parent
            affected_skills.add(skill_dir)

    return affected_skills


def scan_skill(skill_dir: Path, config: dict) -> dict:
    """
    Scan a skill directory and return findings.

    Args:
        skill_dir: Path to skill directory
        config: Configuration dictionary

    Returns:
        Scan results as dictionary
    """
    try:
        from ..core.analyzers.base import BaseAnalyzer
        from ..core.analyzers.static import StaticAnalyzer
        from ..core.scanner import SkillScanner

        analyzers: list[BaseAnalyzer] = [StaticAnalyzer()]

        # Add optional analyzers based on config
        if config.get("use_behavioral"):
            try:
                from ..core.analyzers.behavioral_analyzer import BehavioralAnalyzer

                analyzers.append(BehavioralAnalyzer(use_static_analysis=True))
            except ImportError:
                pass

        if config.get("use_trigger"):
            try:
                from ..core.analyzers.trigger_analyzer import TriggerAnalyzer

                analyzers.append(TriggerAnalyzer())
            except ImportError:
                pass

        scanner = SkillScanner(analyzers=analyzers)
        result = scanner.scan_skill(skill_dir)

        # Count findings by severity
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in result.findings:
            sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
            if sev in counts:
                counts[sev] += 1

        return {
            "skill_name": result.skill_name,
            "skill_directory": result.skill_directory,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                }
                for f in result.findings
            ],
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
        }

    except Exception as e:
        return {
            "skill_name": skill_dir.name,
            "skill_directory": str(skill_dir),
            "findings": [],
            "error": str(e),
        }


def check_severity_threshold(result: dict, threshold: str) -> bool:
    """
    Check if scan result exceeds severity threshold.

    Args:
        result: Scan result dictionary
        threshold: Severity threshold string

    Returns:
        True if threshold is exceeded (should block commit)
    """
    threshold_level = SEVERITY_LEVELS.get(threshold.lower(), SEVERITY_LEVELS["high"])

    for finding in result.get("findings", []):
        finding_level = SEVERITY_LEVELS.get(finding["severity"].lower(), 0)
        if finding_level >= threshold_level:
            return True

    return False


def format_finding(finding: dict) -> str:
    """Format a finding for console output."""
    severity = finding["severity"].upper()
    title = finding["title"]
    location = finding.get("file_path", "")

    if finding.get("line_number"):
        location = f"{location}:{finding['line_number']}"

    return f"  [{severity}] {title}\n    Location: {location}"


def main(args: list[str] | None = None) -> int:
    """
    Main entry point for pre-commit hook.

    Args:
        args: Command line arguments (for testing)

    Returns:
        Exit code (0 = success, 1 = blocked)
    """
    parser = argparse.ArgumentParser(description="Pre-commit hook for scanning agent skills")
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Override severity threshold from config",
    )
    parser.add_argument(
        "--skills-path",
        help="Override skills path from config",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all skills, not just staged ones",
    )
    parser.add_argument(
        "install",
        nargs="?",
        help="Install pre-commit hook",
    )

    parsed_args = parser.parse_args(args)

    # Handle install command
    if parsed_args.install == "install":
        return install_hook()

    # Find repo root
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        repo_root = Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        print("Error: Not a git repository", file=sys.stderr)
        return 1

    # Load config
    config = load_config(repo_root)

    # Apply command line overrides
    if parsed_args.severity:
        config["severity_threshold"] = parsed_args.severity
    if parsed_args.skills_path:
        config["skills_path"] = parsed_args.skills_path

    # Get staged files and affected skills
    if parsed_args.all:
        skills_dir = repo_root / config["skills_path"]
        if skills_dir.exists():
            affected_skills = {d for d in skills_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()}
        else:
            affected_skills = set()
    else:
        staged_files = get_staged_files()
        affected_skills = get_affected_skills(staged_files, config["skills_path"])

    if not affected_skills:
        # No skills affected, allow commit
        return 0

    print(f"Scanning {len(affected_skills)} skill(s)...")

    # Scan each affected skill
    blocked = False
    all_findings = []

    for skill_dir in sorted(affected_skills):
        print(f"\n📦 {skill_dir.name}")

        result = scan_skill(skill_dir, config)

        if result.get("error"):
            print(f"  ⚠️  Error: {result['error']}", file=sys.stderr)
            continue

        findings = result.get("findings", [])

        if not findings:
            print("  ✅ No issues found")
            continue

        # Check if threshold is exceeded
        if check_severity_threshold(result, config["severity_threshold"]):
            blocked = True
            print(f"  🚫 Blocked (threshold: {config['severity_threshold'].upper()})")
        else:
            print(f"  ⚠️  {len(findings)} finding(s) below threshold")

        # Print findings
        for finding in findings:
            print(format_finding(finding))
            all_findings.append(finding)

        if blocked and config.get("fail_fast"):
            break

    # Summary
    print(f"\n{'=' * 50}")
    if blocked:
        print("❌ Commit BLOCKED - fix security issues before committing")
        print(f"   Threshold: {config['severity_threshold'].upper()} and above")
        return 1
    elif all_findings:
        print(f"⚠️  {len(all_findings)} finding(s) detected (below threshold)")
        print("   Consider reviewing and fixing these issues")
        return 0
    else:
        print("✅ All skills passed security checks")
        return 0


def install_hook() -> int:
    """
    Install the pre-commit hook in the current repository.

    Returns:
        Exit code
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        repo_root = Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        print("Error: Not a git repository", file=sys.stderr)
        return 1

    hooks_dir = repo_root / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / "pre-commit"

    hook_script = """#!/bin/sh
# Skill Scanner Pre-commit Hook
# Automatically scans agent skills for security issues

skill-scanner-pre-commit "$@"
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo "To bypass this check (not recommended), use: git commit --no-verify"
fi

exit $exit_code
"""

    # Check if hook already exists
    if hook_path.exists():
        print(f"Warning: Pre-commit hook already exists at {hook_path}")
        response = input("Overwrite? [y/N] ").strip().lower()
        if response != "y":
            print("Aborted")
            return 1

    hook_path.write_text(hook_script)
    hook_path.chmod(0o755)

    print(f"✅ Pre-commit hook installed at {hook_path}")
    print("\nConfiguration:")
    print("  Create .skill_scannerrc in your repo root to customize behavior:")
    print('  { "severity_threshold": "high", "skills_path": ".claude/skills" }')

    return 0


if __name__ == "__main__":
    sys.exit(main())
