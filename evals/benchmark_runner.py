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

"""
Comprehensive evaluation benchmark runner for Skill Scanner.

Based on MCP Scanner's evaluation framework structure.
Evaluates analyzer accuracy across threat categories.
"""

import json
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.scanner import SkillScanner


@dataclass
class EvalMetrics:
    """Metrics for a single threat category."""

    category: str
    total_skills: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float


@dataclass
class BenchmarkResult:
    """Complete benchmark results."""

    total_skills_evaluated: int
    safe_skills: int
    malicious_skills: int
    overall_accuracy: float
    overall_precision: float
    overall_recall: float
    overall_f1: float
    category_metrics: list[EvalMetrics]
    scan_duration_seconds: float
    skills_per_second: float


class SkillBenchmarkRunner:
    """
    Runs comprehensive benchmarks on evaluation skills.

    Inspired by MCP Scanner's evaluation framework.
    """

    def __init__(self, eval_skills_dir: Path):
        """
        Initialize benchmark runner.

        Args:
            eval_skills_dir: Directory containing evaluation skills
        """
        self.eval_skills_dir = eval_skills_dir
        self.scanner = SkillScanner()
        self.results = []

    def run_benchmark(self) -> BenchmarkResult:
        """
        Run complete benchmark suite.

        Returns:
            BenchmarkResult with all metrics
        """
        print("[BENCHMARK] Starting Skill Scanner Benchmark")
        print("=" * 70)

        start_time = time.time()

        # Find all evaluation skills
        eval_skills = self._find_evaluation_skills()

        print(f"Found {len(eval_skills)} evaluation skills")
        print()

        # Scan each skill
        for skill_path, expected_file in eval_skills:
            self._evaluate_skill(skill_path, expected_file)

        # Calculate metrics
        duration = time.time() - start_time
        benchmark_result = self._calculate_benchmark_metrics(duration)

        return benchmark_result

    def _find_evaluation_skills(self) -> list[tuple]:
        """Find all evaluation skills with _expected.json files."""
        eval_skills = []

        for expected_file in self.eval_skills_dir.rglob("_expected.json"):
            skill_dir = expected_file.parent
            if (skill_dir / "SKILL.md").exists():
                eval_skills.append((skill_dir, expected_file))

        return eval_skills

    def _evaluate_skill(self, skill_path: Path, expected_file: Path):
        """Evaluate a single skill."""
        # Load expected results
        with open(expected_file) as f:
            expected = json.load(f)

        skill_name = expected.get("skill_name", skill_path.name)
        expected_safe = expected.get("expected_safe", True)
        expected_threats = expected.get("expected_threats", [])

        print(f"[EVAL] Evaluating: {skill_name}")
        print(f"   Expected: {'SAFE' if expected_safe else 'MALICIOUS'}")

        try:
            # Scan the skill
            scan_result = self.scanner.scan_skill(skill_path)

            # Compare results
            eval_result = self._compare_results(expected, scan_result, skill_name)

            self.results.append(eval_result)

            # Print result
            status = "[OK] PASS" if eval_result["correct"] else "[FAIL]"
            print(f"   Result: {status}")
            print(f"   Detected: {len(scan_result.findings)} findings")
            print()

        except Exception as e:
            print(f"   [ERROR] ERROR: {e}")
            print()
            self.results.append({"skill_name": skill_name, "error": str(e), "correct": False})

    def _compare_results(self, expected: dict, scan_result, skill_name: str) -> dict:
        """Compare expected vs actual results."""
        expected_safe = expected.get("expected_safe", True)
        actual_safe = scan_result.is_safe

        expected_threats = expected.get("expected_threats", [])
        actual_findings = scan_result.findings

        # Count matches by category
        matched_threats = 0
        for exp_threat in expected_threats:
            exp_category = exp_threat.get("category")

            # Check if we found this threat category
            for finding in actual_findings:
                if finding.category.value == exp_category:
                    matched_threats += 1
                    break

        # Calculate correctness
        safe_match = expected_safe == actual_safe
        threat_coverage = matched_threats / len(expected_threats) if expected_threats else 1.0

        correct = safe_match and (threat_coverage >= 0.5)  # At least 50% threats detected

        return {
            "skill_name": skill_name,
            "expected_safe": expected_safe,
            "actual_safe": actual_safe,
            "safe_match": safe_match,
            "expected_threat_count": len(expected_threats),
            "detected_threat_count": len(actual_findings),
            "matched_threats": matched_threats,
            "threat_coverage": threat_coverage,
            "correct": correct,
            "expected_severity": expected.get("expected_severity", "UNKNOWN"),
            "actual_severity": scan_result.max_severity.value,
        }

    def _calculate_benchmark_metrics(self, duration: float) -> BenchmarkResult:
        """Calculate aggregate benchmark metrics."""
        if not self.results:
            return BenchmarkResult(
                total_skills_evaluated=0,
                safe_skills=0,
                malicious_skills=0,
                overall_accuracy=0.0,
                overall_precision=0.0,
                overall_recall=0.0,
                overall_f1=0.0,
                category_metrics=[],
                scan_duration_seconds=duration,
                skills_per_second=0.0,
            )

        # Overall metrics
        total = len(self.results)
        correct = sum(1 for r in self.results if r.get("correct", False))
        safe_count = sum(1 for r in self.results if r.get("expected_safe", True))
        malicious_count = total - safe_count

        # Calculate TP, FP, TN, FN
        tp = sum(1 for r in self.results if not r.get("expected_safe") and not r.get("actual_safe"))
        fp = sum(1 for r in self.results if r.get("expected_safe") and not r.get("actual_safe"))
        tn = sum(1 for r in self.results if r.get("expected_safe") and r.get("actual_safe"))
        fn = sum(1 for r in self.results if not r.get("expected_safe") and r.get("actual_safe"))

        # Calculate metrics
        accuracy = correct / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # Per-category metrics (simplified for now)
        category_metrics = []

        return BenchmarkResult(
            total_skills_evaluated=total,
            safe_skills=safe_count,
            malicious_skills=malicious_count,
            overall_accuracy=accuracy,
            overall_precision=precision,
            overall_recall=recall,
            overall_f1=f1,
            category_metrics=category_metrics,
            scan_duration_seconds=duration,
            skills_per_second=total / duration if duration > 0 else 0.0,
        )

    def print_report(self, result: BenchmarkResult):
        """Print benchmark report."""
        print()
        print("=" * 70)
        print("[RESULTS] BENCHMARK RESULTS")
        print("=" * 70)
        print()

        print(f"Total Skills Evaluated: {result.total_skills_evaluated}")
        print(f"  - Safe Skills: {result.safe_skills}")
        print(f"  - Malicious Skills: {result.malicious_skills}")
        print()

        print("Performance:")
        print(f"  - Total Duration: {result.scan_duration_seconds:.2f}s")
        print(f"  - Skills/Second: {result.skills_per_second:.2f}")
        print()

        print("Detection Metrics:")
        print(f"  - Accuracy:  {result.overall_accuracy:.1%}")
        print(f"  - Precision: {result.overall_precision:.1%}")
        print(f"  - Recall:    {result.overall_recall:.1%}")
        print(f"  - F1 Score:  {result.overall_f1:.1%}")
        print()

        # Print individual results
        print("Individual Results:")
        for r in self.results:
            if "error" in r:
                print(f"  [FAIL] {r['skill_name']}: ERROR - {r['error']}")
            else:
                status = "[OK]" if r["correct"] else "[FAIL]"
                coverage = r["threat_coverage"] * 100
                print(
                    f"  {status} {r['skill_name']}: "
                    f"Safe={r['safe_match']}, "
                    f"Coverage={coverage:.0f}% "
                    f"({r['matched_threats']}/{r['expected_threat_count']})"
                )

        print()
        print("=" * 70)


def main():
    """Main entry point for benchmark."""
    import argparse

    parser = argparse.ArgumentParser(description="Run Skill Scanner benchmarks")
    parser.add_argument("--eval-dir", default="evals/skills", help="Directory containing evaluation skills")
    parser.add_argument("--output", help="Output file for JSON results")
    parser.add_argument("--category", help="Run only specific category (e.g., prompt-injection)")

    args = parser.parse_args()

    # Find eval directory
    eval_dir = Path(args.eval_dir)
    if not eval_dir.exists():
        print(f"Error: Evaluation directory not found: {eval_dir}")
        return 1

    # Filter by category if specified
    if args.category:
        eval_dir = eval_dir / args.category
        if not eval_dir.exists():
            print(f"Error: Category not found: {args.category}")
            return 1

    # Run benchmark
    runner = SkillBenchmarkRunner(eval_dir)
    result = runner.run_benchmark()

    # Print report
    runner.print_report(result)

    # Save JSON if requested
    if args.output:
        output_data = {"benchmark": asdict(result), "individual_results": runner.results}
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to: {args.output}")

    # Exit code based on accuracy
    if result.overall_accuracy < 0.8:
        print("[WARNING] Accuracy below 80%")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
