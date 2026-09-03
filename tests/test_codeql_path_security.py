# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for externally influenced filesystem paths."""

from __future__ import annotations

import io
import os
import stat
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile

from skill_scanner.api import router as api_router
from skill_scanner.core.exceptions import SkillLoadError
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.utils.file_utils import (
    FileValidationError,
    read_text_strict,
    resolve_path_within_root,
)


def _skill(root: Path) -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: path-test\ndescription: containment fixture\n---\n\n# Safe\n",
        encoding="utf-8",
    )
    return root


def test_loader_rejects_custom_metadata_path_traversal_and_absolute_paths(tmp_path: Path) -> None:
    skill_root = _skill(tmp_path / "skill")
    outside = tmp_path / "outside.md"
    outside.write_text("---\nname: outside\ndescription: outside\n---\n", encoding="utf-8")

    for metadata_path in (
        "../outside.md",
        str(outside),
        "nested/README.md",
        "nested\\README.md",
        "bad\x00name.md",
    ):
        with pytest.raises(SkillLoadError, match="must be a filename contained"):
            SkillLoader().load_skill(skill_root, skill_file=metadata_path)


def test_loader_rejects_metadata_symlink_escape(tmp_path: Path) -> None:
    skill_root = tmp_path / "skill"
    skill_root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("---\nname: outside\ndescription: outside\n---\n", encoding="utf-8")
    (skill_root / "SKILL.md").symlink_to(outside)

    with pytest.raises(SkillLoadError, match="outside the skill directory"):
        SkillLoader().load_skill(skill_root)


def test_lenient_loader_does_not_follow_external_markdown_symlink(tmp_path: Path) -> None:
    skill_root = tmp_path / "skill"
    skill_root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("# outside", encoding="utf-8")
    (skill_root / "README.md").symlink_to(outside)

    with pytest.raises(SkillLoadError, match="No SKILL.md and no .md files"):
        SkillLoader().load_skill(skill_root, lenient=True)


def test_strict_reader_enforces_resolved_root_and_regular_file(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "inside.md"
    inside.write_text("inside", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    link = root / "link.md"
    link.symlink_to(outside)

    assert read_text_strict(inside, root=root) == "inside"
    with pytest.raises(FileValidationError, match="escapes allowed root"):
        read_text_strict(link, root=root)
    with pytest.raises(FileValidationError, match="escapes allowed root"):
        resolve_path_within_root(outside, root=root)
    with pytest.raises(FileValidationError, match="regular file"):
        read_text_strict(root)


def test_preset_selector_cannot_be_used_as_a_path() -> None:
    with pytest.raises(ValueError, match="Unknown preset"):
        ScanPolicy.from_preset("../../default_policy.yaml")


def test_local_library_still_loads_explicit_policy_outside_cwd(tmp_path: Path) -> None:
    policy_path = tmp_path / "local-policy.yaml"
    policy_path.write_text("policy_name: external-local-library\n", encoding="utf-8")

    policy = ScanPolicy.from_yaml(policy_path)

    assert policy.policy_name == "external-local-library"


def test_api_path_validation_always_enforces_a_nonempty_root_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    inside = allowed / "skill"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sibling_prefix = tmp_path / "allowed-sibling"
    sibling_prefix.mkdir()
    monkeypatch.setattr(api_router, "_ALLOWED_ROOTS", [allowed.resolve()])

    assert api_router._validate_path(str(inside)) == inside.resolve()
    for rejected in (outside, sibling_prefix, allowed / ".." / "outside"):
        with pytest.raises(HTTPException) as error:
            api_router._validate_path(str(rejected))
        assert error.value.status_code == 403


def test_api_default_roots_are_bounded() -> None:
    assert api_router._API_UPLOAD_ROOT.is_dir()
    assert api_router._API_UPLOAD_ROOT.is_relative_to(Path(tempfile.gettempdir()).resolve())
    if os.name != "nt":
        assert stat.S_IMODE(api_router._API_UPLOAD_ROOT.stat().st_mode) == 0o700


def test_api_default_does_not_expose_cwd_or_shared_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SKILL_SCANNER_ALLOWED_ROOTS", raising=False)
    monkeypatch.chdir(Path(tmp_path.anchor))

    roots = api_router._api_allowed_roots()

    assert roots == [api_router._API_UPLOAD_ROOT]
    assert Path.cwd().resolve() not in roots
    assert Path(tempfile.gettempdir()).resolve() not in roots


def test_api_configured_roots_are_explicit_additions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = tmp_path / "configured"
    configured.mkdir()
    monkeypatch.setenv("SKILL_SCANNER_ALLOWED_ROOTS", str(configured))

    assert api_router._api_allowed_roots() == [api_router._API_UPLOAD_ROOT, configured.resolve()]


def test_api_policy_path_requires_contained_regular_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy_path = allowed / "policy.yaml"
    policy_path.write_text("policy_name: api-contained\n", encoding="utf-8")
    outside = tmp_path / "outside.yaml"
    outside.write_text("policy_name: outside\n", encoding="utf-8")
    (allowed / "escape.yaml").symlink_to(outside)
    policy_directory = allowed / "directory.yaml"
    policy_directory.mkdir()
    monkeypatch.setattr(api_router, "_ALLOWED_ROOTS", [allowed.resolve()])

    assert api_router._resolve_policy(str(policy_path)).policy_name == "api-contained"
    with pytest.raises(ValueError, match="Unknown policy"):
        api_router._resolve_policy(str(allowed / "escape.yaml"))
    with pytest.raises(ValueError, match="must be a file"):
        api_router._resolve_policy(str(policy_directory))


@pytest.mark.asyncio
async def test_upload_filename_is_never_used_as_a_server_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(
            "SKILL.md",
            "---\nname: upload\ndescription: upload fixture\n---\n\n# Safe\n",
        )
    stream.seek(0)
    upload = UploadFile(filename="../escaped.zip", file=stream)
    working = api_router._API_UPLOAD_ROOT / "test-request"

    def fake_mkdtemp(*, prefix: str, dir: str) -> str:
        assert prefix == "request_"
        assert Path(dir) == api_router._API_UPLOAD_ROOT
        working.mkdir()
        return str(working)

    async def fake_scan_skill(*_args, **_kwargs):
        return {"status": "ok"}

    monkeypatch.setattr(api_router.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(api_router, "scan_skill", fake_scan_skill)

    result = await api_router.scan_uploaded_skill(
        file=upload,
        policy=None,
        cel_mode=None,
        trusted_rule_packs=None,
        custom_rules=None,
        use_llm=False,
        llm_provider="ollama",
        use_behavioral=False,
        use_virustotal=False,
        vt_api_key=None,
        vt_upload_files=False,
        use_aidefense=False,
        aidefense_api_key=None,
        aidefense_api_url=None,
        use_trigger=False,
        use_osv=False,
        enable_meta=False,
        llm_consensus_runs=1,
        llm_max_tokens=None,
        llm_reasoning_effort=None,
    )

    assert result == {"status": "ok"}
    assert not (tmp_path / "escaped.zip").exists()
