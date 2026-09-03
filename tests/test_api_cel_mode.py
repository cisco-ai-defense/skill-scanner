# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Focused API contract tests for CEL mode and trusted rule-pack isolation."""

from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from pydantic import ValidationError

from skill_scanner.api import router
from skill_scanner.api.api import app
from skill_scanner.api.router import BatchScanRequest, ScanRequest, _create_api_scanner, _resolve_policy
from skill_scanner.core.cel.models import CelMode
from skill_scanner.core.cel.runtime import CelRuntimeUnavailable
from skill_scanner.core.models import Report, ScanResult
from skill_scanner.core.scan_policy import ScanPolicy


@pytest.fixture(autouse=True)
def _allow_explicit_api_test_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        router,
        "_ALLOWED_ROOTS",
        [Path.cwd().resolve(), Path(tempfile.gettempdir()).resolve()],
    )


@pytest.mark.parametrize(
    "request_type,path_field", [(ScanRequest, "skill_directory"), (BatchScanRequest, "skills_directory")]
)
def test_remote_scan_models_do_not_override_policy_by_default(request_type, path_field):
    request = request_type(**{path_field: "/tmp/example"})

    assert request.cel_mode is None


def test_default_api_policy_resolves_cel_shadow():
    request = ScanRequest(skill_directory="/tmp/example")

    policy = _resolve_policy(request.policy, cel_mode=request.cel_mode)

    assert policy.cel.mode is CelMode.SHADOW


@pytest.mark.parametrize("mode", list(CelMode))
@pytest.mark.parametrize(
    "request_type,path_field", [(ScanRequest, "skill_directory"), (BatchScanRequest, "skills_directory")]
)
def test_remote_scan_models_accept_supported_cel_modes(request_type, path_field, mode):
    request = request_type(**{path_field: "/tmp/example", "cel_mode": mode.value})

    assert request.cel_mode is mode


def test_policy_resolution_applies_api_cel_override():
    policy = _resolve_policy("balanced", cel_mode=CelMode.SHADOW)

    assert policy.cel.mode is CelMode.SHADOW


def test_policy_resolution_preserves_yaml_cel_mode_without_override(tmp_path):
    policy_path = tmp_path / "shadow-policy.yaml"
    policy_path.write_text("cel:\n  mode: shadow\n", encoding="utf-8")

    policy = _resolve_policy(str(policy_path))

    assert policy.cel.mode is CelMode.SHADOW


def test_request_policy_omits_redundant_keyword_for_compatibility(monkeypatch):
    expected = ScanPolicy.default()
    calls: list[str | None] = []

    def legacy_wrapper(policy_name):
        calls.append(policy_name)
        return expected

    monkeypatch.setattr(router, "_resolve_policy", legacy_wrapper)

    assert router._resolve_request_policy("balanced", None) is expected
    assert calls == ["balanced"]


def test_batch_forwards_explicit_cel_mode(monkeypatch, tmp_path: Path):
    observed: dict[str, object] = {}
    expected_policy = ScanPolicy.default()
    expected_policy.cel.mode = CelMode.SHADOW

    def resolve(policy_name, cel_mode):
        observed["policy"] = policy_name
        observed["cel_mode"] = cel_mode
        return expected_policy

    class DummyScanner:
        def __init__(self, *, analyzers, policy, rule_registry):
            observed["scanner_policy"] = policy
            observed["rule_registry"] = rule_registry

        @staticmethod
        def close():
            return None

        @staticmethod
        def scan_directory(*args, **kwargs):
            return Report()

    monkeypatch.setattr(router, "_resolve_request_policy", resolve)
    monkeypatch.setattr(router, "_build_analyzers", lambda *args, **kwargs: [])
    monkeypatch.setattr(router, "SkillScanner", DummyScanner)
    registry = object()
    monkeypatch.setattr("skill_scanner.core.rule_registry.PackLoader.build_registry", lambda _self: registry)

    scan_id = "cel-mode-batch-test"
    request = BatchScanRequest(skills_directory=str(tmp_path), policy="strict", cel_mode="shadow")
    router.run_batch_scan(scan_id, request)

    cached = router.scan_results_cache.get_valid(scan_id)
    assert cached is not None
    assert cached["status"] == "completed"
    assert observed == {
        "policy": "strict",
        "cel_mode": CelMode.SHADOW,
        "scanner_policy": expected_policy,
        "rule_registry": registry,
    }


def test_api_scanner_attaches_bundled_registry_for_active_cel_mode(monkeypatch):
    policy = ScanPolicy.default()
    policy.cel.mode = CelMode.SHADOW
    registry = object()
    observed: dict[str, object] = {}

    monkeypatch.setattr("skill_scanner.core.rule_registry.PackLoader.build_registry", lambda _self: registry)

    class DummyScanner:
        def __init__(self, **kwargs):
            observed.update(kwargs)

    monkeypatch.setattr(router, "SkillScanner", DummyScanner)

    _create_api_scanner([], policy)

    assert observed == {"analyzers": [], "policy": policy, "rule_registry": registry}


def test_api_scanner_off_mode_still_validates_pack_registry(monkeypatch):
    policy = ScanPolicy.default()
    registry = object()
    observed: dict[str, object] = {}

    monkeypatch.setattr("skill_scanner.core.rule_registry.PackLoader.build_registry", lambda _self: registry)

    class DummyScanner:
        def __init__(self, **kwargs):
            observed.update(kwargs)

    monkeypatch.setattr(router, "SkillScanner", DummyScanner)

    _create_api_scanner([], policy)

    assert observed == {"analyzers": [], "policy": policy, "rule_registry": registry}


def test_scan_upload_forwards_explicit_cel_mode(monkeypatch):
    async def fake_scan_skill(request, vt_api_key=None, aidefense_api_key=None):
        return {"cel_mode": request.cel_mode.value}

    monkeypatch.setattr(router, "scan_skill", fake_scan_skill)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("sample/SKILL.md", "---\nname: sample\ndescription: sample\n---\n")

    response = TestClient(app).post(
        "/scan-upload",
        files={"file": ("sample.zip", archive.getvalue(), "application/zip")},
        data={"cel_mode": "shadow"},
    )

    assert response.status_code == 200
    assert response.json() == {"cel_mode": "shadow"}


def test_scan_endpoint_exposes_cel_runtime_configuration_error(monkeypatch, tmp_path: Path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: sample\ndescription: sample\n---\n",
        encoding="utf-8",
    )

    class FailingScanner:
        def __init__(self, *args, **kwargs):
            raise CelRuntimeUnavailable("CEL runtime needs a qualified official release")

    monkeypatch.setattr(router, "_build_analyzers", lambda *args, **kwargs: [])
    monkeypatch.setattr(router, "SkillScanner", FailingScanner)

    response = TestClient(app).post(
        "/scan",
        json={"skill_directory": str(tmp_path), "cel_mode": "shadow"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "CEL runtime needs a qualified official release"


def test_scan_endpoint_treats_invalid_bundled_cel_generation_as_server_error(monkeypatch, tmp_path: Path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: sample\ndescription: sample package\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(router, "_build_analyzers", lambda *args, **kwargs: [])

    def invalid_registry(_self):
        raise ValueError("rule CEL_BAD does not type-check")

    monkeypatch.setattr("skill_scanner.core.rule_registry.PackLoader.build_registry", invalid_registry)

    response = TestClient(app).post(
        "/scan",
        json={"skill_directory": str(tmp_path), "cel_mode": "shadow"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == ("Bundled rule-pack configuration failed: rule CEL_BAD does not type-check")


def test_scan_endpoint_exposes_cel_scan_metadata(monkeypatch, tmp_path: Path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: sample\ndescription: sample package\n---\n",
        encoding="utf-8",
    )
    result = ScanResult(
        skill_name="sample",
        skill_directory=str(tmp_path),
        scan_metadata={
            "cel": {
                "mode": "shadow",
                "evaluated": 3,
                "would_suppress": 1,
                "suppressed": 0,
            }
        },
    )

    class DummyScanner:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        @staticmethod
        def scan_skill(_skill_dir):
            return result

    monkeypatch.setattr(router, "_build_analyzers", lambda *args, **kwargs: [])
    monkeypatch.setattr(router, "_create_api_scanner", lambda _analyzers, _policy: DummyScanner())

    response = TestClient(app).post(
        "/scan",
        json={"skill_directory": str(tmp_path), "cel_mode": "shadow"},
    )

    assert response.status_code == 200
    assert response.json()["scan_metadata"] == result.scan_metadata


@pytest.mark.parametrize("field_name", ["trusted_rule_pack", "trusted_rule_packs"])
@pytest.mark.parametrize(
    "request_type,path_field", [(ScanRequest, "skill_directory"), (BatchScanRequest, "skills_directory")]
)
def test_remote_scan_models_reject_trusted_rule_pack_paths(request_type, path_field, field_name):
    with pytest.raises(ValidationError, match="local service administrator"):
        request_type(**{path_field: "/tmp/example", field_name: ["/srv/trusted-pack"]})


def test_scan_endpoint_rejects_unknown_cel_mode():
    response = TestClient(app).post(
        "/scan",
        json={"skill_directory": "/tmp/example", "cel_mode": "audit"},
    )

    assert response.status_code == 422


def test_scan_endpoint_rejects_trusted_rule_pack_paths_with_guidance():
    response = TestClient(app).post(
        "/scan",
        json={"skill_directory": "/tmp/example", "trusted_rule_packs": ["/srv/trusted-pack"]},
    )

    assert response.status_code == 422
    assert "local service administrator" in response.text


def test_scan_upload_rejects_trusted_rule_pack_paths_with_guidance():
    response = TestClient(app).post(
        "/scan-upload",
        files={"file": ("skill.zip", b"not-read", "application/zip")},
        data={"trusted_rule_packs": "/srv/trusted-pack"},
    )

    assert response.status_code == 422
    assert "local service administrator" in response.text


def test_openapi_exposes_bounded_cel_mode_on_scan_models():
    schema = TestClient(app).get("/openapi.json").json()
    cel_schema = schema["components"]["schemas"]["CelMode"]

    assert cel_schema["enum"] == ["off", "shadow", "enforce"]
    assert "cel_mode" in schema["components"]["schemas"]["ScanRequest"]["properties"]
    assert "cel_mode" in schema["components"]["schemas"]["BatchScanRequest"]["properties"]
    assert "scan_metadata" in schema["components"]["schemas"]["ScanResponse"]["properties"]
