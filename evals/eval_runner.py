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
Evaluation runner for testing analyzer accuracy.

Mirrors MCP Scanner's evaluation framework.
"""

import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import os

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity
from skill_scanner.core.scanner import SkillScanner


@dataclass
class EvalResult:
    """Result from evaluating a single skill."""

    skill_name: str
    expected_safe: bool
    actual_safe: bool
    expected_findings_count: int
    actual_findings_count: int
    matched_findings: int
    false_positives: int
    false_negatives: int
    correct: bool
    scan_result: Any = field(default=None, repr=False)  # Store the actual scan result for displaying AITech codes


class EvaluationRunner:
    """Runs evaluation tests on analyzer accuracy."""

    def __init__(self, test_skills_dir: Path, use_llm: bool = False, use_meta: bool = False):
        """
        Initialize evaluation runner.

        Args:
            test_skills_dir: Directory containing test skills
            use_llm: Whether to use LLM analyzer
            use_meta: Whether to use Meta-Analyzer for false positive filtering
        """
        self.test_skills_dir = test_skills_dir
        self.use_meta = use_meta
        self.meta_analyzer = None

        # Build analyzers list
        analyzers = [StaticAnalyzer()]

        if use_llm:
            try:
                from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

                api_key = os.getenv("SKILL_SCANNER_LLM_API_KEY")
                model = os.getenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")
                base_url = os.getenv("SKILL_SCANNER_LLM_BASE_URL")
                api_version = os.getenv("SKILL_SCANNER_LLM_API_VERSION")

                if api_key:
                    llm_analyzer = LLMAnalyzer(
                        model=model,
                        api_key=api_key,
                        base_url=base_url,
                        api_version=api_version,
                    )
                    analyzers.append(llm_analyzer)
                    print(f"Using LLM analyzer with model: {model}")
            except Exception as e:
                print(f"Warning: Could not initialize LLM analyzer: {e}")

        # Initialize Meta-Analyzer if requested
        if use_meta:
            try:
                from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

                self.meta_analyzer = MetaAnalyzer()
                print("Using Meta-Analyzer for false positive filtering and prioritization")
            except Exception as e:
                print(f"Warning: Could not initialize Meta-Analyzer: {e}")

        self.scanner = SkillScanner(analyzers=analyzers)

    def run_evaluation(self) -> dict[str, Any]:
        """
        Run full evaluation suite.

        Returns:
            Evaluation results with metrics
        """
        results = []
        meta_stats = {"total_filtered": 0, "total_validated": 0, "skills_processed": 0}

        # Find all test skills with expected results
        for expected_file in self.test_skills_dir.rglob("_expected.json"):
            skill_dir = expected_file.parent

            try:
                # Load expected results
                with open(expected_file) as f:
                    expected = json.load(f)

                # Scan the skill
                scan_result = self.scanner.scan_skill(skill_dir)

                # Apply meta-analysis if enabled and there are findings
                if self.use_meta and self.meta_analyzer and scan_result.findings:
                    try:
                        import asyncio

                        from skill_scanner.core.analyzers.meta_analyzer import apply_meta_analysis_to_results
                        from skill_scanner.core.loader import SkillLoader

                        # Load skill for meta-analysis context
                        loader = SkillLoader()
                        skill = loader.load_skill(skill_dir)

                        original_count = len(scan_result.findings)

                        # Run meta-analysis asynchronously
                        meta_result = asyncio.run(
                            self.meta_analyzer.analyze_with_findings(
                                skill=skill,
                                findings=scan_result.findings,
                                analyzers_used=scan_result.analyzers_used,
                            )
                        )

                        validated_findings = apply_meta_analysis_to_results(
                            original_findings=scan_result.findings,
                            meta_result=meta_result,
                            skill=skill,
                        )
                        filtered_count = original_count - len(validated_findings)

                        # Update scan result with filtered findings
                        scan_result.findings = validated_findings
                        scan_result.findings_count = len(validated_findings)
                        # Note: is_safe is a computed property based on findings
                        scan_result.analyzers_used.append("meta_analyzer")

                        # Track meta stats
                        meta_stats["total_filtered"] += filtered_count
                        meta_stats["total_validated"] += len(validated_findings)
                        meta_stats["skills_processed"] += 1

                        print(
                            f"  Meta-analysis for {scan_result.skill_name}: "
                            f"{len(validated_findings)} validated, {filtered_count} filtered"
                        )
                    except Exception as e:
                        print(f"  Warning: Meta-analysis failed for {scan_result.skill_name}: {e}")

                # Compare with expected
                eval_result = self._compare_results(expected, scan_result)
                results.append(eval_result)

            except Exception as e:
                print(f"Error evaluating {skill_dir}: {e}")
                continue

        # Calculate aggregate metrics
        metrics = self._calculate_metrics(results)

        # Convert results to dict, excluding scan_result from serialization
        individual_results = []
        for r in results:
            result_dict = asdict(r)
            # Remove scan_result from dict (it's not JSON serializable easily)
            result_dict.pop("scan_result", None)
            individual_results.append(result_dict)

        result = {
            "individual_results": individual_results,
            "metrics": metrics,
            "total_skills": len(results),
            "eval_results_with_scan": results,  # Keep full results for display
        }

        # Add meta stats if meta analyzer was used
        if self.use_meta and meta_stats["skills_processed"] > 0:
            result["meta_analysis_stats"] = meta_stats

        return result

    def _compare_results(self, expected: dict, scan_result) -> EvalResult:
        """Compare expected vs actual results."""

        expected_safe = expected.get("expected_safe", True)
        actual_safe = scan_result.is_safe

        # Support both "expected_findings" and "expected_threats" keys for backward compatibility
        expected_findings = expected.get("expected_findings", expected.get("expected_threats", []))
        actual_findings = scan_result.findings

        # Count matches - try to match each expected finding to an actual finding
        matched = 0
        matched_actual_indices = set()

        for exp_finding in expected_findings:
            exp_category = exp_finding.get("category")
            exp_severity = exp_finding.get("severity")

            # Check if we found a matching finding (category + severity match)
            for idx, actual_finding in enumerate(actual_findings):
                if idx in matched_actual_indices:
                    continue  # Already matched
                if actual_finding.category.value == exp_category and actual_finding.severity.value == exp_severity:
                    matched += 1
                    matched_actual_indices.add(idx)
                    break

        # Calculate false positives/negatives
        # False positives: findings in SAFE skills, or findings that don't match expected patterns
        # False negatives: expected findings that weren't found

        if expected_safe:
            # For safe skills, ALL findings are false positives
            false_positives = len(actual_findings)
            false_negatives = 0
        else:
            # For unsafe skills:
            # - False negatives: expected findings we didn't find
            false_negatives = len(expected_findings) - matched
            # - False positives: only count if we have findings that are clearly wrong
            #   For now, we'll count unmatched findings as potential false positives
            #   BUT: if we found MORE threats than expected, that's actually good!
            #   So we only count false positives if we have findings that don't match expected patterns
            #   AND we're missing expected findings (suggesting we're finding wrong things)
            unmatched_actual = len(actual_findings) - matched
            if false_negatives > 0 and unmatched_actual > 0:
                # We're missing expected findings AND have extra findings - some might be false positives
                false_positives = min(unmatched_actual, false_negatives)
            else:
                # If we found all expected findings, extra findings are just additional true positives
                false_positives = 0

        # Overall correctness
        # A skill is correct if:
        # 1. Safe skills have no findings (false_positives == 0)
        # 2. Unsafe skills are detected as unsafe AND we found at least the expected findings
        if expected_safe:
            correct = actual_safe and false_positives == 0
        else:
            correct = not actual_safe and false_negatives == 0

        return EvalResult(
            skill_name=scan_result.skill_name,
            expected_safe=expected_safe,
            actual_safe=actual_safe,
            expected_findings_count=len(expected_findings),
            actual_findings_count=len(actual_findings),
            matched_findings=matched,
            false_positives=false_positives,
            false_negatives=false_negatives,
            correct=correct,
            scan_result=scan_result,  # Store scan result for AITech display
        )

    def _calculate_metrics(self, results: list[EvalResult]) -> dict[str, float]:
        """Calculate aggregate metrics."""
        if not results:
            return {}

        total = len(results)
        correct = sum(1 for r in results if r.correct)

        total_tp = sum(r.matched_findings for r in results)
        total_fp = sum(r.false_positives for r in results)
        total_fn = sum(r.false_negatives for r in results)
        total_tn = sum(1 for r in results if r.expected_safe and r.actual_safe)

        # Calculate metrics
        accuracy = correct / total if total > 0 else 0
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "true_positives": total_tp,
            "false_positives": total_fp,
            "true_negatives": total_tn,
            "false_negatives": total_fn,
        }


def print_metrics(results: dict, title: str = "Evaluation Results"):
    """Print evaluation metrics."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    print(f"Total Skills: {results['total_skills']}")
    print("\nMetrics:")
    for key, value in results["metrics"].items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2%}")
        else:
            print(f"  {key}: {value}")

    # Print meta-analysis stats if available
    if "meta_analysis_stats" in results:
        meta_stats = results["meta_analysis_stats"]
        print("\nMeta-Analysis Stats:")
        print(f"  Skills processed: {meta_stats['skills_processed']}")
        print(f"  Total findings validated: {meta_stats['total_validated']}")
        print(f"  Total false positives filtered: {meta_stats['total_filtered']}")
        if meta_stats["total_validated"] + meta_stats["total_filtered"] > 0:
            filter_rate = meta_stats["total_filtered"] / (meta_stats["total_validated"] + meta_stats["total_filtered"])
            print(f"  Filter rate: {filter_rate:.1%}")


def run_comparison(test_dir: Path, show_details: bool = False):
    """Run evaluation both with and without meta analyzer and compare results."""
    print("=" * 70)
    print("META ANALYZER COMPARISON EVALUATION")
    print("Running evaluations with and without Meta-Analyzer...")
    print("=" * 70)

    # Run WITHOUT meta
    print("\n[1/2] Running evaluation WITHOUT Meta-Analyzer...")
    runner_no_meta = EvaluationRunner(test_dir, use_llm=True, use_meta=False)
    results_no_meta = runner_no_meta.run_evaluation()

    # Run WITH meta
    print("\n[2/2] Running evaluation WITH Meta-Analyzer...")
    runner_with_meta = EvaluationRunner(test_dir, use_llm=True, use_meta=True)
    results_with_meta = runner_with_meta.run_evaluation()

    # Print comparison
    print("\n" + "=" * 70)
    print("COMPARISON RESULTS")
    print("=" * 70)

    # Side-by-side metrics
    m1 = results_no_meta["metrics"]
    m2 = results_with_meta["metrics"]

    print("\n{:<25} {:>15} {:>15} {:>12}".format("Metric", "Without Meta", "With Meta", "Change"))
    print("-" * 70)

    for key in ["accuracy", "precision", "recall", "f1_score"]:
        v1 = m1.get(key, 0)
        v2 = m2.get(key, 0)
        change = v2 - v1
        sign = "+" if change >= 0 else ""
        print("{:<25} {:>14.1%} {:>14.1%} {:>11}".format(key.replace("_", " ").title(), v1, v2, f"{sign}{change:.1%}"))

    print("-" * 70)
    for key in ["true_positives", "false_positives", "true_negatives", "false_negatives"]:
        v1 = m1.get(key, 0)
        v2 = m2.get(key, 0)
        change = v2 - v1
        sign = "+" if change >= 0 else ""
        print("{:<25} {:>15} {:>15} {:>12}".format(key.replace("_", " ").title(), v1, v2, f"{sign}{change}"))

    # Meta stats
    if "meta_analysis_stats" in results_with_meta:
        meta_stats = results_with_meta["meta_analysis_stats"]
        print("\n" + "-" * 70)
        print("Meta-Analyzer Impact:")
        print(f"  Total findings filtered: {meta_stats['total_filtered']}")
        print(f"  Total findings validated: {meta_stats['total_validated']}")
        total = meta_stats["total_filtered"] + meta_stats["total_validated"]
        if total > 0:
            print(f"  Noise reduction rate: {meta_stats['total_filtered'] / total:.1%}")

    # Per-skill comparison
    print("\n" + "=" * 70)
    print("PER-SKILL COMPARISON")
    print("=" * 70)
    print("\n{:<30} {:>8} {:>8} {:>10} {:>10}".format("Skill", "Before", "After", "Filtered", "Status"))
    print("-" * 70)

    results_no_meta_by_name = {r.skill_name: r for r in results_no_meta.get("eval_results_with_scan", [])}
    results_with_meta_by_name = {r.skill_name: r for r in results_with_meta.get("eval_results_with_scan", [])}

    for skill_name in results_no_meta_by_name:
        r1 = results_no_meta_by_name.get(skill_name)
        r2 = results_with_meta_by_name.get(skill_name)

        if r1 and r2:
            before = r1.actual_findings_count
            after = r2.actual_findings_count
            filtered = before - after

            # Determine status
            if r1.expected_safe:
                if r2.actual_safe:
                    status = "✓ SAFE (correct)"
                else:
                    status = "✗ FP detected"
            else:
                if not r2.actual_safe:
                    status = "✓ UNSAFE (correct)"
                else:
                    status = "✗ MISSED!"

            print(f"{skill_name[:30]:<30} {before:>8} {after:>8} {filtered:>10} {status:>10}")

    # Detailed per-skill analysis if requested
    if show_details:
        print("\n" + "=" * 70)
        print("DETAILED SKILL ANALYSIS")
        print("=" * 70)

        for skill_name in results_no_meta_by_name:
            r1 = results_no_meta_by_name.get(skill_name)
            r2 = results_with_meta_by_name.get(skill_name)

            if not r1 or not r2:
                continue

            print(f"\n--- {skill_name} ---")
            print(f"Expected: {'SAFE' if r1.expected_safe else 'UNSAFE'}")

            # Show what was filtered
            if r1.scan_result and r2.scan_result:
                before_ids = {f.id for f in r1.scan_result.findings}
                after_ids = {f.id for f in r2.scan_result.findings}
                filtered_ids = before_ids - after_ids

                if filtered_ids:
                    print("Filtered out:")
                    for f in r1.scan_result.findings:
                        if f.id in filtered_ids:
                            print(f"  - [{f.analyzer}] {f.category.value} [{f.severity.value}]: {f.title[:45]}...")

                print("Kept:")
                for f in r2.scan_result.findings:
                    conf = f.metadata.get("meta_confidence", "N/A")
                    print(f"  + [{f.analyzer}] {f.category.value} [{f.severity.value}] (conf: {conf})")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Count correctly classified
    safe_correct_before = sum(
        1 for r in results_no_meta.get("eval_results_with_scan", []) if r.expected_safe and r.actual_safe
    )
    safe_correct_after = sum(
        1 for r in results_with_meta.get("eval_results_with_scan", []) if r.expected_safe and r.actual_safe
    )
    unsafe_correct_before = sum(
        1 for r in results_no_meta.get("eval_results_with_scan", []) if not r.expected_safe and not r.actual_safe
    )
    unsafe_correct_after = sum(
        1 for r in results_with_meta.get("eval_results_with_scan", []) if not r.expected_safe and not r.actual_safe
    )

    total_safe = sum(1 for r in results_no_meta.get("eval_results_with_scan", []) if r.expected_safe)
    total_unsafe = sum(1 for r in results_no_meta.get("eval_results_with_scan", []) if not r.expected_safe)

    print(f"\nSafe Skills Detection:   {safe_correct_before}/{total_safe} -> {safe_correct_after}/{total_safe}")
    print(f"Unsafe Skills Detection: {unsafe_correct_before}/{total_unsafe} -> {unsafe_correct_after}/{total_unsafe}")

    # Key insight
    if "meta_analysis_stats" in results_with_meta:
        meta_stats = results_with_meta["meta_analysis_stats"]
        print("\nKey Insight:")
        print(f"  Meta-Analyzer filtered {meta_stats['total_filtered']} low-value findings")
        print(f"  while maintaining {unsafe_correct_after}/{total_unsafe} unsafe skill detection rate")

        if safe_correct_after >= safe_correct_before and unsafe_correct_after >= unsafe_correct_before:
            print("\n  ✓ Meta-Analyzer IMPROVED signal-to-noise without losing detection capability!")
        elif unsafe_correct_after < unsafe_correct_before:
            print("\n  ⚠ Warning: Meta-Analyzer may have filtered some true positives")

    return {"without_meta": results_no_meta, "with_meta": results_with_meta}


def main():
    """Main entry point for evaluation."""
    import argparse

    parser = argparse.ArgumentParser(description="Run Skill Scanner evaluations")
    parser.add_argument("--test-skills-dir", default="evals/skills", help="Directory containing test skills")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM analyzer in evaluation")
    parser.add_argument(
        "--use-meta",
        action="store_true",
        help="Use Meta-Analyzer to filter false positives and prioritize findings (requires --use-llm)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run both with and without Meta-Analyzer and show comparison",
    )
    parser.add_argument("--show-aitech", action="store_true", help="Show AITech taxonomy codes in detailed findings")
    parser.add_argument("--show-details", action="store_true", help="Show detailed per-skill analysis in compare mode")

    args = parser.parse_args()

    # Run evaluation
    test_dir = Path(args.test_skills_dir)
    if not test_dir.exists():
        print(f"Test skills directory not found: {test_dir}")
        print("Create test skills with _expected.json files")
        return 1

    # Compare mode - run both and compare
    if args.compare:
        comparison_results = run_comparison(test_dir, show_details=args.show_details)

        # Save if requested
        if args.output:
            # Make results JSON serializable
            output_data = {
                "without_meta": {
                    k: v for k, v in comparison_results["without_meta"].items() if k != "eval_results_with_scan"
                },
                "with_meta": {
                    k: v for k, v in comparison_results["with_meta"].items() if k != "eval_results_with_scan"
                },
            }
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            print(f"\nResults saved to: {args.output}")

        return 0

    # Single run mode
    # Validate args
    if args.use_meta and not args.use_llm:
        print("Warning: --use-meta requires --use-llm. Enabling LLM analyzer.")
        args.use_llm = True

    runner = EvaluationRunner(test_dir, use_llm=args.use_llm, use_meta=args.use_meta)
    results = runner.run_evaluation()

    # Print results
    mode = "With Meta-Analyzer" if args.use_meta else "Without Meta-Analyzer"
    print_metrics(results, f"Evaluation Results ({mode})")

    # Print detailed findings with AITech codes for each skill (if requested)
    if args.show_aitech:
        print("\n" + "=" * 60)
        print("Detailed Findings (with AITech Taxonomy)")
        print("=" * 60)
        eval_results = results.get("eval_results_with_scan", [])
        for eval_result in eval_results:
            print(f"\nSkill: {eval_result.skill_name}")
            print(f"  Expected Safe: {eval_result.expected_safe}, Actual Safe: {eval_result.actual_safe}")
            print(
                f"  Matched: {eval_result.matched_findings}, FP: {eval_result.false_positives}, FN: {eval_result.false_negatives}"
            )

            # Display findings with AITech codes from stored scan result
            if eval_result.scan_result and eval_result.scan_result.findings:
                print(f"  Findings ({len(eval_result.scan_result.findings)}):")
                for finding in eval_result.scan_result.findings[:5]:  # Show first 5 findings
                    aitech = finding.metadata.get("aitech", "N/A")
                    aitech_name = finding.metadata.get("aitech_name", "N/A")
                    aisubtech = finding.metadata.get("aisubtech")
                    print(f"    - {finding.category.value} [{finding.severity.value}]")
                    if aitech != "N/A":
                        aitech_info = f"AITech: {aitech} ({aitech_name})"
                        if aisubtech:
                            aisubtech_name = finding.metadata.get("aisubtech_name", "")
                            aitech_info += f" | AISubtech: {aisubtech}"
                            if aisubtech_name:
                                aitech_info += f" ({aisubtech_name})"
                        print(f"      {aitech_info}")
                if len(eval_result.scan_result.findings) > 5:
                    print(f"    ... and {len(eval_result.scan_result.findings) - 5} more findings")

    # Save if requested
    if args.output:
        # Remove non-serializable data
        output_results = {k: v for k, v in results.items() if k != "eval_results_with_scan"}
        with open(args.output, "w") as f:
            json.dump(output_results, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
