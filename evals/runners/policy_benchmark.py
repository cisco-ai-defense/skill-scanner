# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Policy benchmark runner — scans eval skills and large corpus with multiple policies,
then produces a comparison report.

Usage:
    uv run python evals/runners/policy_benchmark.py
    uv run python evals/runners/policy_benchmark.py --corpus .local_benchmark/extracted_s3
    uv run python evals/runners/policy_benchmark.py --policies evals/policies/04_compliance_audit.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class PolicyResult:
    """Aggregated results for one policy run."""

    policy_name: str
    policy_file: str
    # Eval skills metrics
    eval_total: int = 0
    eval_tp: int = 0
    eval_fp: int = 0
    eval_tn: int = 0
    eval_fn: int = 0
    eval_precision: float = 0.0
    eval_recall: float = 0.0
    eval_f1: float = 0.0
    eval_accuracy: float = 0.0
    # Finding-level eval metrics (category + severity matching)
    eval_finding_tp: int = 0
    eval_finding_fp: int = 0
    eval_finding_fn: int = 0
    eval_finding_precision: float = 0.0
    eval_finding_recall: float = 0.0
    eval_finding_f1: float = 0.0
    # Corpus metrics
    corpus_skills_scanned: int = 0
    corpus_total_findings: int = 0
    corpus_critical: int = 0
    corpus_high: int = 0
    corpus_medium: int = 0
    corpus_low: int = 0
    corpus_info: int = 0
    corpus_actionable: int = 0  # C + H + M
    corpus_security_actionable: int = 0  # Actionable minus policy-violation findings
    corpus_compliance_actionable: int = 0  # Actionable policy-violation findings
    corpus_unsafe_skills: int = 0
    corpus_findings_by_rule: dict[str, int] = field(default_factory=dict)
    # Timing
    eval_duration_s: float = 0.0
    corpus_duration_s: float = 0.0
    corpus_errors: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_skills(root: Path) -> list[Path]:
    """Find all directories containing a SKILL.md."""
    skills = []
    for skill_md in root.rglob("SKILL.md"):
        skills.append(skill_md.parent)
    return sorted(set(skills))


def _load_policy(policy_path: Path | None, preset: str | None = None) -> ScanPolicy:
    """Load a ScanPolicy from file or preset."""
    if preset:
        return ScanPolicy.from_preset(preset)
    if policy_path:
        return ScanPolicy.from_yaml(policy_path)
    return ScanPolicy.default()


def _severity_bucket(severity: Severity) -> str:
    return severity.value


# ---------------------------------------------------------------------------
# Eval skills benchmark
# ---------------------------------------------------------------------------


def run_eval_benchmark(scanner: SkillScanner, eval_dir: Path) -> dict:
    """Run against eval skills and calculate precision/recall."""
    results = []
    finding_tp = 0
    finding_fp = 0
    finding_fn = 0

    for expected_file in sorted(eval_dir.rglob("_expected.json")):
        skill_dir = expected_file.parent
        if not (skill_dir / "SKILL.md").exists():
            continue

        with open(expected_file) as f:
            expected = json.load(f)

        skill_name = expected.get("skill_name", skill_dir.name)
        expected_safe = expected.get("expected_safe", True)

        try:
            scan_result = scanner.scan_skill(skill_dir)
            actual_safe = scan_result.is_safe
            actual_pairs = [(f.category.value, f.severity.value) for f in scan_result.findings]

            expected_pairs = [
                (
                    str(item.get("category", "")).lower(),
                    str(item.get("severity", "")).upper(),
                )
                for item in (expected.get("expected_findings") or expected.get("expected_threats", []))
                if item.get("category") and item.get("severity")
            ]

            expected_counts: dict[tuple[str, str], int] = defaultdict(int)
            actual_counts: dict[tuple[str, str], int] = defaultdict(int)
            for pair in expected_pairs:
                expected_counts[pair] += 1
            for pair in actual_pairs:
                actual_counts[pair] += 1

            matched = 0
            for pair, exp_count in expected_counts.items():
                act_count = actual_counts.get(pair, 0)
                matched += min(exp_count, act_count)

            finding_tp += matched
            finding_fp += max(0, len(actual_pairs) - matched)
            finding_fn += max(0, len(expected_pairs) - matched)

            results.append(
                {
                    "skill_name": skill_name,
                    "expected_safe": expected_safe,
                    "actual_safe": actual_safe,
                    "finding_count": len(scan_result.findings),
                    "expected_findings": len(expected_pairs),
                }
            )
        except Exception as e:
            results.append(
                {
                    "skill_name": skill_name,
                    "expected_safe": expected_safe,
                    "actual_safe": True,  # assume safe on error
                    "finding_count": 0,
                    "expected_findings": len(expected.get("expected_findings") or expected.get("expected_threats", [])),
                    "error": str(e),
                }
            )

    # Calculate metrics
    tp = sum(1 for r in results if not r["expected_safe"] and not r["actual_safe"])
    fp = sum(1 for r in results if r["expected_safe"] and not r["actual_safe"])
    tn = sum(1 for r in results if r["expected_safe"] and r["actual_safe"])
    fn = sum(1 for r in results if not r["expected_safe"] and r["actual_safe"])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0
    finding_precision = finding_tp / (finding_tp + finding_fp) if (finding_tp + finding_fp) > 0 else 0.0
    finding_recall = finding_tp / (finding_tp + finding_fn) if (finding_tp + finding_fn) > 0 else 0.0
    finding_f1 = (
        2 * finding_precision * finding_recall / (finding_precision + finding_recall)
        if (finding_precision + finding_recall) > 0
        else 0.0
    )

    return {
        "total": len(results),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "finding_tp": finding_tp,
        "finding_fp": finding_fp,
        "finding_fn": finding_fn,
        "finding_precision": finding_precision,
        "finding_recall": finding_recall,
        "finding_f1": finding_f1,
        "details": results,
    }


# ---------------------------------------------------------------------------
# Corpus benchmark
# ---------------------------------------------------------------------------


def run_corpus_benchmark(scanner: SkillScanner, corpus_dir: Path, max_skills: int = 0) -> dict:
    """Scan a large corpus and aggregate findings."""
    skills = _find_skills(corpus_dir)
    if max_skills > 0:
        skills = skills[:max_skills]

    severity_counts: dict[str, int] = defaultdict(int)
    rule_counts: dict[str, int] = defaultdict(int)
    total_findings = 0
    unsafe_skills = 0
    errors = 0
    security_actionable = 0
    compliance_actionable = 0

    for i, skill_dir in enumerate(skills):
        try:
            result = scanner.scan_skill(skill_dir)
            total_findings += len(result.findings)

            if not result.is_safe:
                unsafe_skills += 1

            for f in result.findings:
                severity_counts[f.severity.value] += 1
                rule_counts[f.rule_id] += 1
                if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    if f.category == ThreatCategory.POLICY_VIOLATION:
                        compliance_actionable += 1
                    else:
                        security_actionable += 1

        except Exception:
            errors += 1

        # Progress
        if (i + 1) % 200 == 0:
            print(f"    ... {i + 1}/{len(skills)} skills scanned")

    return {
        "skills_scanned": len(skills),
        "total_findings": total_findings,
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "info": severity_counts.get("INFO", 0),
        "actionable": severity_counts.get("CRITICAL", 0)
        + severity_counts.get("HIGH", 0)
        + severity_counts.get("MEDIUM", 0),
        "security_actionable": security_actionable,
        "compliance_actionable": compliance_actionable,
        "unsafe_skills": unsafe_skills,
        "findings_by_rule": dict(sorted(rule_counts.items(), key=lambda x: -x[1])),
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_policy_benchmark(
    policy_configs: list[tuple[str, Path | None, str | None]],
    eval_dir: Path,
    corpus_dir: Path | None,
    max_skills: int = 0,
) -> list[PolicyResult]:
    """Run benchmarks across all policy configs."""
    all_results: list[PolicyResult] = []

    for name, policy_path, preset in policy_configs:
        print(f"\n{'=' * 70}")
        print(f"  POLICY: {name}")
        print(f"{'=' * 70}")

        # Load policy
        policy = _load_policy(policy_path, preset)
        scanner = SkillScanner(policy=policy)

        pr = PolicyResult(policy_name=name, policy_file=str(policy_path or preset or "default"))

        # --- Eval skills ---
        print("  [1/2] Running eval skills benchmark...")
        t0 = time.time()
        eval_result = run_eval_benchmark(scanner, eval_dir)
        pr.eval_duration_s = time.time() - t0
        pr.eval_total = eval_result["total"]
        pr.eval_tp = eval_result["tp"]
        pr.eval_fp = eval_result["fp"]
        pr.eval_tn = eval_result["tn"]
        pr.eval_fn = eval_result["fn"]
        pr.eval_precision = eval_result["precision"]
        pr.eval_recall = eval_result["recall"]
        pr.eval_f1 = eval_result["f1"]
        pr.eval_accuracy = eval_result["accuracy"]
        pr.eval_finding_tp = eval_result["finding_tp"]
        pr.eval_finding_fp = eval_result["finding_fp"]
        pr.eval_finding_fn = eval_result["finding_fn"]
        pr.eval_finding_precision = eval_result["finding_precision"]
        pr.eval_finding_recall = eval_result["finding_recall"]
        pr.eval_finding_f1 = eval_result["finding_f1"]
        print(f"         Precision={pr.eval_precision:.1%}  Recall={pr.eval_recall:.1%}  F1={pr.eval_f1:.1%}")
        print(
            f"         Finding Precision={pr.eval_finding_precision:.1%}  "
            f"Recall={pr.eval_finding_recall:.1%}  F1={pr.eval_finding_f1:.1%}"
        )

        # --- Corpus ---
        if corpus_dir and corpus_dir.exists():
            print("  [2/2] Running corpus benchmark...")
            t0 = time.time()
            corpus_result = run_corpus_benchmark(scanner, corpus_dir, max_skills)
            pr.corpus_duration_s = time.time() - t0
            pr.corpus_skills_scanned = corpus_result["skills_scanned"]
            pr.corpus_total_findings = corpus_result["total_findings"]
            pr.corpus_critical = corpus_result["critical"]
            pr.corpus_high = corpus_result["high"]
            pr.corpus_medium = corpus_result["medium"]
            pr.corpus_low = corpus_result["low"]
            pr.corpus_info = corpus_result["info"]
            pr.corpus_actionable = corpus_result["actionable"]
            pr.corpus_security_actionable = corpus_result["security_actionable"]
            pr.corpus_compliance_actionable = corpus_result["compliance_actionable"]
            pr.corpus_unsafe_skills = corpus_result["unsafe_skills"]
            pr.corpus_findings_by_rule = corpus_result["findings_by_rule"]
            pr.corpus_errors = corpus_result["errors"]
            print(
                f"         Skills={pr.corpus_skills_scanned}  Findings={pr.corpus_total_findings}  "
                f"Actionable={pr.corpus_actionable}  SecurityActionable={pr.corpus_security_actionable}  "
                f"Unsafe={pr.corpus_unsafe_skills}"
            )
        else:
            print("  [2/2] No corpus directory — skipping")

        all_results.append(pr)

    return all_results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(results: list[PolicyResult], output_path: Path) -> str:
    """Generate a markdown comparison report."""
    lines: list[str] = []
    w = lines.append

    w("# Policy Benchmark Comparison Report")
    w("")
    w(f"> Generated: {time.strftime('%Y-%m-%d %H:%M')}")
    w(f"> Policies tested: {len(results)}")
    if results and results[0].corpus_skills_scanned > 0:
        w(f"> Corpus size: {results[0].corpus_skills_scanned} skills")
    w("")
    w("---")
    w("")

    # ---- Eval skills table ----
    w("## Eval Skills (Ground Truth)")
    w("")
    w(
        "| # | Policy | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN | Finding Precision | Finding Recall | Finding F1 | Time |"
    )
    w(
        "|---|--------|-----------|--------|-----|----------|----|----|----|----|-------------------|----------------|------------|------|"
    )
    for i, r in enumerate(results, 1):
        w(
            f"| {i} | **{r.policy_name}** | {r.eval_precision:.1%} | {r.eval_recall:.1%} | "
            f"{r.eval_f1:.1%} | {r.eval_accuracy:.1%} | {r.eval_tp} | {r.eval_fp} | {r.eval_tn} | {r.eval_fn} | "
            f"{r.eval_finding_precision:.1%} | {r.eval_finding_recall:.1%} | {r.eval_finding_f1:.1%} | "
            f"{r.eval_duration_s:.2f}s |"
        )
    w("")

    # ---- Corpus summary table ----
    if any(r.corpus_skills_scanned > 0 for r in results):
        w("---")
        w("")
        w("## Corpus Findings Summary")
        w("")
        w(
            "| # | Policy | Total | Actionable | Security Actionable | Compliance Actionable | CRITICAL | HIGH | MEDIUM | LOW | INFO | Unsafe | Time |"
        )
        w(
            "|---|--------|-------|------------|---------------------|----------------------|----------|------|--------|-----|------|--------|------|"
        )
        for i, r in enumerate(results, 1):
            w(
                f"| {i} | **{r.policy_name}** | {r.corpus_total_findings:,} | {r.corpus_actionable:,} | "
                f"{r.corpus_security_actionable:,} | {r.corpus_compliance_actionable:,} | "
                f"{r.corpus_critical} | {r.corpus_high} | {r.corpus_medium} | {r.corpus_low} | "
                f"{r.corpus_info:,} | {r.corpus_unsafe_skills} | {r.corpus_duration_s:.1f}s |"
            )
        w("")

        # ---- Delta vs baseline ----
        baseline = results[0]
        if baseline.corpus_actionable > 0:
            w("### Delta vs Baseline (Policy 01)")
            w("")
            w(
                "| # | Policy | Δ Total | Δ Actionable | Δ Security Actionable | Δ Compliance Actionable | Δ Unsafe | Δ CRITICAL | Δ HIGH | Δ MEDIUM |"
            )
            w(
                "|---|--------|---------|--------------|-----------------------|------------------------|----------|------------|--------|----------|"
            )
            for i, r in enumerate(results, 1):
                dt = r.corpus_total_findings - baseline.corpus_total_findings
                da = r.corpus_actionable - baseline.corpus_actionable
                dsa = r.corpus_security_actionable - baseline.corpus_security_actionable
                dca = r.corpus_compliance_actionable - baseline.corpus_compliance_actionable
                du = r.corpus_unsafe_skills - baseline.corpus_unsafe_skills
                dc = r.corpus_critical - baseline.corpus_critical
                dh = r.corpus_high - baseline.corpus_high
                dm = r.corpus_medium - baseline.corpus_medium
                w(
                    f"| {i} | **{r.policy_name}** | {dt:+,} | {da:+,} | {dsa:+,} | {dca:+,} | "
                    f"{du:+,} | {dc:+,} | {dh:+,} | {dm:+,} |"
                )
            w("")

        # ---- Top rules per policy ----
        w("---")
        w("")
        w("## Top 10 Rules per Policy (Corpus)")
        w("")
        for i, r in enumerate(results, 1):
            if not r.corpus_findings_by_rule:
                continue
            w(f"### {i}. {r.policy_name}")
            w("")
            w("| Rule | Count |")
            w("|------|-------|")
            top_rules = sorted(r.corpus_findings_by_rule.items(), key=lambda x: -x[1])[:10]
            for rule, count in top_rules:
                w(f"| `{rule}` | {count} |")
            w("")

    # ---- Key observations ----
    w("---")
    w("")
    w("## Key Observations")
    w("")

    if any(r.corpus_skills_scanned > 0 for r in results):
        min_act = min(results, key=lambda r: r.corpus_security_actionable)
        max_act = max(results, key=lambda r: r.corpus_security_actionable)
        w(f"- **Lowest security-actionable findings:** {min_act.policy_name} ({min_act.corpus_security_actionable:,})")
        w(f"- **Highest security-actionable findings:** {max_act.policy_name} ({max_act.corpus_security_actionable:,})")
        if min_act.corpus_security_actionable > 0:
            ratio = max_act.corpus_security_actionable / min_act.corpus_security_actionable
            w(f"- **Range factor:** {ratio:.1f}x between most and least permissive")

    min_prec = min(results, key=lambda r: r.eval_precision)
    max_prec = max(results, key=lambda r: r.eval_precision)
    min_finding_prec = min(results, key=lambda r: r.eval_finding_precision)
    max_finding_prec = max(results, key=lambda r: r.eval_finding_precision)
    w(
        f"- **Eval precision range:** {min_prec.eval_precision:.1%} ({min_prec.policy_name}) to {max_prec.eval_precision:.1%} ({max_prec.policy_name})"
    )
    w(
        f"- **Finding precision range:** {min_finding_prec.eval_finding_precision:.1%} "
        f"({min_finding_prec.policy_name}) to {max_finding_prec.eval_finding_precision:.1%} "
        f"({max_finding_prec.policy_name})"
    )
    w("")

    report = "\n".join(lines)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report)

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Run policy benchmark comparison")
    parser.add_argument("--eval-dir", default="evals/skills", help="Eval skills directory")
    parser.add_argument("--corpus", default=".local_benchmark/corpus", help="Large corpus directory")
    parser.add_argument("--policies", nargs="*", help="Specific policy files (default: all in evals/policies/)")
    parser.add_argument("--max-skills", type=int, default=0, help="Max skills to scan from corpus (0=all)")
    parser.add_argument("--output", default="evals/results/POLICY_BENCHMARK_RESULTS.md", help="Output report path")
    parser.add_argument("--json-output", default="evals/results/policy_benchmark_results.json", help="JSON output path")
    parser.add_argument("--skip-corpus", action="store_true", help="Skip corpus scan (eval only)")
    args = parser.parse_args()

    eval_dir = Path(args.eval_dir)
    corpus_dir = None if args.skip_corpus else Path(args.corpus)

    # Build policy list
    policy_configs: list[tuple[str, Path | None, str | None]] = []

    if args.policies:
        for p in args.policies:
            path = Path(p)
            policy_configs.append((path.stem, path, None))
    else:
        # Default: 3 presets + all files in evals/policies/ (skip 01-03 which are presets)
        policy_configs.append(("01-baseline (balanced)", None, "balanced"))
        policy_configs.append(("02-strict", None, "strict"))
        policy_configs.append(("03-permissive", None, "permissive"))

        policies_dir = Path("evals/policies")
        if policies_dir.exists():
            for pf in sorted(policies_dir.glob("*.yaml")):
                # Skip the first 3 (they're covered by presets above)
                if pf.name.startswith(("01_", "02_", "03_")):
                    continue
                policy_configs.append((pf.stem, pf, None))

    print("Policy Benchmark Runner")
    print(f"  Eval dir:  {eval_dir}")
    print(f"  Corpus:    {corpus_dir or '(skipped)'}")
    print(f"  Policies:  {len(policy_configs)}")
    print(f"  Max skills: {'all' if args.max_skills == 0 else args.max_skills}")

    # Run
    results = run_policy_benchmark(policy_configs, eval_dir, corpus_dir, args.max_skills)

    # Generate report
    report = generate_report(results, Path(args.output))
    print(f"\n{'=' * 70}")
    print(f"Report saved to: {args.output}")
    print(f"{'=' * 70}\n")
    print(report)

    # Save JSON
    json_data = []
    for r in results:
        json_data.append(
            {
                "policy_name": r.policy_name,
                "policy_file": r.policy_file,
                "eval": {
                    "total": r.eval_total,
                    "tp": r.eval_tp,
                    "fp": r.eval_fp,
                    "tn": r.eval_tn,
                    "fn": r.eval_fn,
                    "precision": r.eval_precision,
                    "recall": r.eval_recall,
                    "f1": r.eval_f1,
                    "accuracy": r.eval_accuracy,
                    "finding_tp": r.eval_finding_tp,
                    "finding_fp": r.eval_finding_fp,
                    "finding_fn": r.eval_finding_fn,
                    "finding_precision": r.eval_finding_precision,
                    "finding_recall": r.eval_finding_recall,
                    "finding_f1": r.eval_finding_f1,
                    "duration_s": r.eval_duration_s,
                },
                "corpus": {
                    "skills_scanned": r.corpus_skills_scanned,
                    "total_findings": r.corpus_total_findings,
                    "critical": r.corpus_critical,
                    "high": r.corpus_high,
                    "medium": r.corpus_medium,
                    "low": r.corpus_low,
                    "info": r.corpus_info,
                    "actionable": r.corpus_actionable,
                    "security_actionable": r.corpus_security_actionable,
                    "compliance_actionable": r.corpus_compliance_actionable,
                    "unsafe_skills": r.corpus_unsafe_skills,
                    "findings_by_rule": r.corpus_findings_by_rule,
                    "errors": r.corpus_errors,
                    "duration_s": r.corpus_duration_s,
                },
            }
        )

    Path(args.json_output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.json_output, "w") as f:
        json.dump(json_data, f, indent=2)
    print(f"JSON saved to: {args.json_output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
