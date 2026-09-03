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

"""Static contracts for the staged detection-evaluation workflows."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

_RELEASE_CHAIN_WORKFLOWS = (
    "release.yml",
    "detection-release-gates.yml",
    "detection-release-evidence.yml",
    "update-homebrew.yml",
)


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _workflow_run_steps(name: str) -> list[tuple[str, str]]:
    document = yaml.safe_load(_workflow(name))
    return [
        (str(step.get("name", "<unnamed>")), run)
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if isinstance((run := step.get("run")), str)
    ]


def test_release_chain_never_interpolates_dispatch_inputs_into_shell_source() -> None:
    for workflow_name in _RELEASE_CHAIN_WORKFLOWS:
        for step_name, run in _workflow_run_steps(workflow_name):
            assert "${{ inputs." not in run, (workflow_name, step_name)
            assert "${{ github.event.inputs." not in run, (workflow_name, step_name)


@pytest.mark.parametrize(
    "release_ref",
    (
        "$(touch${IFS}PWNED)",
        "release`touch${IFS}PWNED`",
        "release;touch${IFS}PWNED",
    ),
)
def test_exact_release_tag_guard_treats_valid_shell_metacharacters_as_data(
    tmp_path: Path,
    release_ref: str,
) -> None:
    """A valid Git ref is not necessarily safe to splice into shell source."""

    resolve_job = yaml.safe_load(_workflow("release.yml"))["jobs"]["resolve-release"]
    resolve_step = next(step for step in resolve_job["steps"] if step.get("name") == "Resolve exact tag commit")
    script = resolve_step["run"]

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Release Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "release-test@example.invalid"], cwd=tmp_path, check=True)
    (tmp_path / "tracked").write_text("release\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "release"], cwd=tmp_path, check=True)
    subprocess.run(["git", "tag", release_ref], cwd=tmp_path, check=True)
    release_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    environment = {
        "PATH": str(Path(shutil.which("git") or "/usr/bin/git").parent) + ":/usr/bin:/bin",
        "RELEASE_REF": release_ref,
        "WORKFLOW_REF": f"refs/tags/{release_ref}",
        "WORKFLOW_SHA": release_sha,
    }
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", script],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "PWNED").exists()


def test_supported_python_versions_are_exercised_in_ci() -> None:
    workflow = _workflow("python-tests.yml")
    match = re.search(r"python-version:\s*\[([^]]+)]", workflow)
    assert match is not None
    configured = set(re.findall(r'"(3\.\d+)"', match.group(1)))
    assert configured == {"3.11", "3.12", "3.13", "3.14"}
    assert '"3.10"' not in workflow


def test_detection_gates_have_no_scheduled_or_nightly_workflow() -> None:
    assert not (WORKFLOWS / "detection-nightly.yml").exists()
    for name in (
        "detection-pr-gates.yml",
        "detection-release-gates.yml",
        "detection-release-evidence.yml",
    ):
        workflow = _workflow(name)
        assert "schedule:" not in workflow
        assert "nightly" not in workflow.casefold()


def test_detection_gates_validate_only_release_scoped_core_pack() -> None:
    for name in (
        "detection-pr-gates.yml",
        "detection-release-gates.yml",
        "detection-release-evidence.yml",
    ):
        workflow = _workflow(name)
        assert 'DATA_DIR / "packs" / "core"' in workflow
        assert '"detector_profile": "core_only"' in workflow
        assert "release dataset lock is not exactly core_only + source_disjoint" in workflow
        assert "full_packs" not in workflow


def test_release_job_requires_public_evidence_and_keeps_private_nonblocking() -> None:
    workflow = _workflow("detection-release-gates.yml")
    assert "public_corpus_artifact is required" in workflow
    assert "Waiver artifacts cannot satisfy or bypass mandatory release gates" in workflow
    assert "Waiver artifacts are not accepted as optional release evidence" in workflow
    assert "Download current committed exact-golden evidence" in workflow
    assert "release-committed-golden-${{ github.run_id }}" in workflow
    invocation = workflow.split("Run mandatory public and optional private corpus evaluation", 1)[1]
    assert "--public-corpus" in invocation
    assert "--committed-golden" in invocation
    assert "--private-corpus" in invocation
    assert "--require-private" not in workflow
    assert "private_args=()" in invocation
    private_download = workflow.split("Download frozen private holdout", 1)[1].split("Validate mandatory public", 1)[0]
    assert "continue-on-error: true" in private_download
    assert "private_ready" in invocation


def test_release_gate_binds_frozen_evidence_to_current_committed_goldens() -> None:
    workflow = _workflow("detection-release-gates.yml")
    safety = workflow.split("Validate mandatory public and quarantine optional private entries", 1)[1]
    safety = safety.split("Run mandatory public and optional private corpus evaluation", 1)[0]

    assert 'current_golden="$RUNNER_TEMP/release-corpora/current-golden/golden-corpus.json"' in safety
    assert 'bundled_golden="$public_root/golden-corpus.json"' in safety
    assert 'python - "$current_golden" "$bundled_golden"' in safety
    assert "if current != bundled:" in safety
    assert "cmp -s" not in safety


def test_publication_depends_on_same_revision_detection_gate() -> None:
    release = _workflow("release.yml")
    detection = _workflow("detection-release-gates.yml")

    assert "corpus_artifact_run_id:" in release
    assert "public_corpus_artifact:" in release
    assert "release-detection-gates:" in release
    resolve_job = release.split("resolve-release:", 1)[1].split("release-detection-gates:", 1)[0]
    gate_job = release.split("release-detection-gates:", 1)[1].split("build-platform-wheels:", 1)[0]
    assert "uses: ./.github/workflows/detection-release-gates.yml" in gate_job
    assert "WORKFLOW_REF: ${{ github.ref }}" in resolve_job
    assert "WORKFLOW_SHA: ${{ github.sha }}" in resolve_job
    assert '[[ "$WORKFLOW_REF" != "refs/tags/$RELEASE_REF" ]]' in resolve_job
    assert '[[ "$release_sha" != "$WORKFLOW_SHA" ]]' in resolve_job
    assert "release workflow must be dispatched from the exact release tag" in resolve_job
    assert "release_sha: ${{ github.sha }}" in gate_job
    assert "corpus_artifact_run_id: ${{ inputs.corpus_artifact_run_id }}" in gate_job
    assert "public_corpus_artifact: ${{ inputs.public_corpus_artifact }}" in gate_job

    build_job = release.split("build-platform-wheels:", 1)[1].split("pypi-publish:", 1)[0]
    publish_job = release.split("pypi-publish:", 1)[1]
    assert "- release-detection-gates" in build_job
    assert "- release-detection-gates" in publish_job
    assert "ref: ${{ github.sha }}" in build_job
    assert "ref: ${{ github.sha }}" in publish_job
    assert "needs.resolve-release.outputs.release_sha" not in release

    assert "ref: ${{ inputs.release_sha }}" in detection
    assert "Corpus evidence workflow run does not target the exact release commit" in detection
    assert 'artifact_status" != "completed"' in detection
    assert 'artifact_conclusion" != "success"' in detection
    assert 'artifact_workflow_path" != ".github/workflows/detection-release-evidence.yml"' in detection
    assert 'artifact_event" != "workflow_dispatch"' in detection
    assert "EXPECTED_PUBLIC_ARTIFACT: detection-release-evidence-${{ inputs.release_sha }}" in detection
    assert "EXPECTED_SOURCE_REVISION: ${{ inputs.release_sha }}" in detection
    assert '--expected-source-revision "$EXPECTED_SOURCE_REVISION"' in detection


def test_trusted_release_evidence_producer_is_pinned_offline_and_exact_sha() -> None:
    workflow = _workflow("detection-release-evidence.yml")
    benchmark_runner = (ROOT / "evals" / "runners" / "benchmark_runner.py").read_text(encoding="utf-8")

    assert "environment: detection-release-corpora" in workflow
    assert 'go-version: "1.27.1"' in workflow
    acquisition = workflow.split("Acquire and materialize locked public corpus", 1)[1]
    acquisition = acquisition.split("Run exact-SHA offline release evaluation", 1)[0]
    assert "uv sync --frozen --no-install-project --only-group datasets" in acquisition
    assert "setup-go" not in acquisition
    assert "d4b42ce5766a6e0359c987cf59c1007cb3795a90" in workflow
    assert "ProtectSkills/MaliciousSkillBench" in workflow
    for path in (
        "primary.parquet",
        "metadata.parquet",
        "attack_taxonomy.parquet",
        "impact_taxonomy.parquet",
        "splits/random.parquet",
        "splits/source_balanced_random.parquet",
        "splits/m_structural_disjoint.parquet",
        "splits/source_disjoint.parquet",
        "package_manifest.csv",
        "schema.json",
    ):
        assert path in workflow
    assert "load_dataset(" not in workflow
    assert "trust_remote_code" not in workflow
    assert "materialize_malicious_skill_bench.py" in workflow
    assert 'if [[ "$GITHUB_SHA" != "$RELEASE_SHA" ]]' in workflow
    assert "detection-release-evidence-${{ inputs.release_sha }}" in workflow

    scan_step = workflow.split("Run OFF plus exactly five active scans with OS-denied network", 1)[1]
    scan_step = scan_step.split("Resolve fixed release evidence artifact name", 1)[0]
    assert "sudo iptables -I OUTPUT" in scan_step
    assert "sudo ip6tables -I OUTPUT" in scan_step
    assert "network isolation failed" in scan_step
    assert 'parameters["use_llm"].default is not False' in scan_step
    assert 'parameters["use_osv"].default is not False' in scan_step
    assert "credential-bearing environment survived scan preflight" in scan_step
    assert "--cel-mode off" in scan_step
    assert "for iteration in 1 2 3 4 5" in scan_step
    assert "produce_release_evidence.py active-mode" in scan_step
    assert scan_step.count("--compact-release-evidence") == 2
    assert '--output "$work/committed-golden.json"' in scan_step
    assert scan_step.count('--golden "$work/golden-corpus.json"') == 1
    assert scan_step.count('--committed-golden "$work/golden-corpus.json"') == 1
    # The benchmark CLI always writes canonical exact-finding evidence beside
    # its requested summary output; keep both workflow consumers bound to that
    # concrete producer path.
    assert 'golden_path = output_path.parent / "golden-corpus.json"' in benchmark_runner
    assert '--expected-source-revision "$RELEASE_SHA"' in scan_step
    assert '.status == "passed"' in scan_step


def test_go_toolchain_is_exact_across_source_and_release_builds() -> None:
    go_mod = (ROOT / "tools" / "cel_runtime" / "go.mod").read_text(encoding="utf-8")
    pr = _workflow("detection-pr-gates.yml")
    release_gate = _workflow("detection-release-gates.yml")
    release = _workflow("release.yml")

    assert re.search(r"(?m)^go 1\.27\.1$", go_mod)
    assert 'go-version: "1.27.1"' in pr
    assert release_gate.count('go-version: "1.27.1"') == 2
    assert release.count('go-version: "1.27.1"') == 2
    for workflow_name in (
        "detection-pr-gates.yml",
        "detection-release-evidence.yml",
        "detection-release-gates.yml",
        "integration-tests.yml",
        "python-tests.yml",
        "release.yml",
        "update-homebrew.yml",
    ):
        versions = set(re.findall(r'go-version:\s*"([^"]+)"', _workflow(workflow_name)))
        assert versions == {"1.27.1"}, workflow_name


def test_release_workflows_pass_actionlint_when_available() -> None:
    actionlint = shutil.which("actionlint")
    if actionlint is None:
        return
    subprocess.run(
        [
            actionlint,
            str(WORKFLOWS / "release.yml"),
            str(WORKFLOWS / "detection-release-gates.yml"),
            str(WORKFLOWS / "detection-release-evidence.yml"),
        ],
        check=True,
    )


def test_committed_golden_workflows_require_exact_identity_and_five_runs() -> None:
    pr = _workflow("detection-pr-gates.yml")
    release = _workflow("detection-release-gates.yml")
    for workflow in (pr, release):
        assert "strict_identity_skills" in workflow
        assert "legacy_degraded_skills" in workflow
        assert "finding_false_positives" in workflow
        assert "finding_false_negatives" in workflow
    assert "for iteration in 1 2 3 4 5" in pr
    for timing_field in (
        "scan_duration_seconds",
        "scan_duration_ms",
        "skills_per_second",
        "p95_scan_latency_ms",
        "cel_time_ratio",
    ):
        assert f'"{timing_field}"' in pr
    assert '"cel_fallbacks"' not in pr.split("volatile =", 1)[1].split("}", 1)[0]
