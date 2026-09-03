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

"""API router for Skill Scanner endpoints.

This router provides the same functionality as ``api_server.py`` but in a
composable ``APIRouter`` form, allowing it to be mounted in other FastAPI
applications.  All parameters and behaviour mirror the standalone server for
full CLI/API parity.
"""

import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

try:
    from fastapi import APIRouter, BackgroundTasks, File, Form, Header, HTTPException, UploadFile
    from pydantic import BaseModel, Field, model_validator

    MULTIPART_AVAILABLE = True
except ImportError:
    raise ImportError("API server requires FastAPI. Install with: pip install fastapi uvicorn python-multipart")

from .. import __version__ as PACKAGE_VERSION
from ..core.analyzer_factory import build_analyzers
from ..core.cel.models import CelMode
from ..core.cel.runtime import CelRuntimeUnavailable
from ..core.exceptions import SkillLoadError
from ..core.scan_policy import ScanPolicy
from ..core.scanner import SkillScanner
from ..llm_reasoning import LLMReasoningEffort, ReasoningConfigurationError
from ..llm_token_options import resolve_llm_max_tokens
from ..utils.file_utils import FileValidationError, resolve_path_within_root
from ..utils.logging_context import scan_log_context

logger = logging.getLogger("skill_scanner.api")

LLMAnalyzer: type | None
try:
    from ..core.analyzers.llm_analyzer import LLMAnalyzer

    LLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LLM_AVAILABLE = False
    LLMAnalyzer = None

BehavioralAnalyzer: type | None
try:
    from ..core.analyzers.behavioral_analyzer import BehavioralAnalyzer

    BEHAVIORAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    BEHAVIORAL_AVAILABLE = False
    BehavioralAnalyzer = None

AIDefenseAnalyzer: type | None
try:
    from ..core.analyzers.aidefense_analyzer import AIDefenseAnalyzer

    AIDEFENSE_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AIDEFENSE_AVAILABLE = False
    AIDefenseAnalyzer = None

VirusTotalAnalyzer: type | None
try:
    from ..core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

    VIRUSTOTAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    VIRUSTOTAL_AVAILABLE = False
    VirusTotalAnalyzer = None

TriggerAnalyzer: type | None
try:
    from ..core.analyzers.trigger_analyzer import TriggerAnalyzer

    TRIGGER_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    TRIGGER_AVAILABLE = False
    TriggerAnalyzer = None

MetaAnalyzer: type | None
apply_meta_analysis_to_results: Callable[..., list] | None
merge_meta_analyzer_usage: Callable[..., None] | None
try:
    from ..core.analyzers.meta_analyzer import (
        MetaAnalyzer,
        apply_meta_analysis_to_results,
        merge_meta_analyzer_usage,
    )

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None
    merge_meta_analyzer_usage = None

router = APIRouter()

# ---------------------------------------------------------------------------
# Upload & cache safety limits
# ---------------------------------------------------------------------------

MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB max upload
MAX_ZIP_ENTRIES = 500  # max files extracted from uploaded ZIP
MAX_ZIP_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB uncompressed limit
MAX_CACHE_ENTRIES = 1_000  # evict oldest when exceeded
CACHE_TTL_SECONDS = 3600  # 1 hour


# In-memory storage for async scans with bounded LRU eviction and TTL.
# In production, use Redis or a database instead.
class _BoundedCache(OrderedDict[str, dict]):
    """OrderedDict with max-size eviction and per-entry TTL."""

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            value["_cached_at"] = time.monotonic()
            self[key] = value
            self.move_to_end(key)
            while len(self) > MAX_CACHE_ENTRIES:
                self.popitem(last=False)

    def get_valid(self, key: str) -> dict | None:
        with self._lock:
            entry = self.get(key)
            if entry is None:
                return None
            if time.monotonic() - entry.get("_cached_at", 0) > CACHE_TTL_SECONDS:
                del self[key]
                return None
            result: dict = entry
            return result


scan_results_cache = _BoundedCache()


class _RulePackStartupConfigurationError(RuntimeError):
    """The server's bundled rule generation failed startup validation."""


_API_UPLOAD_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory(prefix="skill_scanner_api_")
_API_UPLOAD_ROOT = Path(os.path.realpath(_API_UPLOAD_TEMPORARY_DIRECTORY.name))
_API_UPLOAD_ROOT.chmod(0o700)


def _api_allowed_roots() -> list[Path]:
    """Return resolved filesystem roots exposed to remote callers.

    Uploaded archives always use a process-private directory. Server-side
    paths are inaccessible unless an operator explicitly adds their roots.
    """

    configured = [
        Path(os.path.realpath(os.path.expanduser(value.strip())))
        for value in os.environ.get("SKILL_SCANNER_ALLOWED_ROOTS", "").split(os.pathsep)
        if value.strip()
    ]
    return list(dict.fromkeys((_API_UPLOAD_ROOT, *configured)))


# Environment-configurable allowlist of directories the API may access.
# It is deliberately never empty, but defaults only to server-owned uploads;
# deployments scanning server-side libraries must opt those roots in through
# SKILL_SCANNER_ALLOWED_ROOTS.
_ALLOWED_ROOTS: list[Path] = _api_allowed_roots()


def _validate_path(
    user_input: str,
    *,
    label: str = "path",
    must_exist: bool = False,
    expected_kind: str | None = None,
) -> Path:
    """Sanitize and validate a user-supplied filesystem path.

    Rejects null bytes and path-traversal attempts, resolves symlinks, and
    enforces the SKILL_SCANNER_ALLOWED_ROOTS allowlist.  For endpoints that
    require an existing path, disallowed paths are reported as missing so the
    API does not disclose whether arbitrary host paths exist.
    """
    if not user_input.strip():
        raise HTTPException(status_code=400, detail=f"Invalid {label}: path must not be empty")
    if "\x00" in user_input:
        raise HTTPException(status_code=400, detail=f"Invalid {label}: null bytes are not allowed")

    resolved: Path | None = None
    matched_root: Path | None = None
    for root in _ALLOWED_ROOTS:
        try:
            resolved = resolve_path_within_root(user_input, root=root, must_exist=False)
        except FileValidationError:
            continue
        matched_root = root
        break

    if resolved is None or matched_root is None:
        if must_exist:
            raise HTTPException(status_code=404, detail=f"{label} not found")
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {label} is outside the allowed directories",
        )

    if must_exist:
        try:
            resolved = resolve_path_within_root(user_input, root=matched_root, must_exist=True)
        except FileValidationError as exc:
            raise HTTPException(status_code=404, detail=f"{label} not found") from exc

    if expected_kind == "file" and not resolved.is_file():
        raise HTTPException(status_code=400, detail=f"{label} must be a file")
    if expected_kind == "directory" and not resolved.is_dir():
        raise HTTPException(status_code=400, detail=f"{label} must be a directory")

    return resolved


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class _RemoteScanConfig(BaseModel):
    """Common validation for scan configuration accepted over the API."""

    @model_validator(mode="before")
    @classmethod
    def _reject_trusted_rule_pack_paths(cls, data: object) -> object:
        """Keep trusted local rule packs behind a local administrator boundary."""
        if isinstance(data, Mapping):
            forbidden = {"trusted_rule_pack", "trusted_rule_packs"}.intersection(data)
            if forbidden:
                names = ", ".join(sorted(forbidden))
                raise ValueError(
                    f"{names} cannot be supplied over the remote API; "
                    "trusted rule packs must be configured by the local service administrator"
                )
        return data


class ScanRequest(_RemoteScanConfig):
    """Request model for scanning a skill."""

    skill_directory: str = Field(..., description="Path to skill directory")
    policy: str | None = Field(
        None,
        description="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    cel_mode: CelMode | None = Field(
        None,
        description="Optional CEL decision-mode override: off, shadow (observe only), or enforce",
    )
    custom_rules: str | None = Field(None, description="Path to custom YARA rules directory")
    use_llm: bool = Field(False, description="Enable LLM analyzer")
    llm_provider: str | None = Field("anthropic", description="LLM provider (anthropic or openai)")
    use_behavioral: bool = Field(False, description="Enable behavioral analyzer")
    use_virustotal: bool = Field(False, description="Enable VirusTotal binary file scanning")
    vt_upload_files: bool = Field(False, description="Upload unknown files to VirusTotal")
    use_aidefense: bool = Field(False, description="Enable AI Defense analyzer")
    aidefense_api_url: str | None = Field(None, description="AI Defense API URL")
    use_trigger: bool = Field(False, description="Enable trigger specificity analysis")
    use_osv: bool = Field(False, description="Enable OSV.dev dependency vulnerability scanning")
    enable_meta: bool = Field(False, description="Enable meta-analysis for false positive filtering")
    llm_consensus_runs: int = Field(1, description="Number of LLM consensus runs (majority vote)")
    llm_max_tokens: int | None = Field(
        None,
        gt=0,
        description="Maximum output tokens for LLM and meta-analysis responses",
    )
    llm_reasoning_effort: LLMReasoningEffort | None = Field(
        None,
        description="Optional LLM reasoning effort; unset preserves the provider default",
    )


class ScanResponse(BaseModel):
    """Response model for scan results."""

    scan_id: str
    skill_name: str
    is_safe: bool
    max_severity: str
    findings_count: int
    scan_duration_seconds: float
    timestamp: str
    findings: list[dict]
    scan_metadata: dict[str, object] = Field(
        default_factory=dict,
        description="Scan provenance and decision-layer telemetry, including CEL mode and counters",
    )
    llm_usage: dict[str, int] | None = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    analyzers_available: list[str]


class BatchScanRequest(_RemoteScanConfig):
    """Request for batch scanning."""

    skills_directory: str
    policy: str | None = Field(
        None,
        description="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    cel_mode: CelMode | None = Field(
        None,
        description="Optional CEL decision-mode override: off, shadow (observe only), or enforce",
    )
    custom_rules: str | None = Field(None, description="Path to custom YARA rules directory")
    recursive: bool = False
    check_overlap: bool = Field(False, description="Enable cross-skill description overlap detection")
    use_llm: bool = False
    llm_provider: str | None = "anthropic"
    use_behavioral: bool = False
    use_virustotal: bool = False
    vt_upload_files: bool = False
    use_aidefense: bool = False
    aidefense_api_url: str | None = None
    use_trigger: bool = False
    use_osv: bool = False
    enable_meta: bool = Field(False, description="Enable meta-analysis")
    llm_consensus_runs: int = Field(1, description="Number of LLM consensus runs (majority vote)")
    llm_max_tokens: int | None = Field(
        None,
        gt=0,
        description="Maximum output tokens for LLM and meta-analysis responses",
    )
    llm_reasoning_effort: LLMReasoningEffort | None = Field(
        None,
        description="Optional LLM reasoning effort; unset preserves the provider default",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_policy(policy_str: str | None, *, cel_mode: CelMode | str | None = None) -> ScanPolicy:
    """Resolve a policy string and apply an optional API-level CEL override."""
    if policy_str is None or not policy_str.strip():
        policy = ScanPolicy.default()
    else:
        policy_str = policy_str.strip()
        if policy_str.lower() in ("strict", "balanced", "permissive"):
            policy = ScanPolicy.from_preset(policy_str)
        else:
            try:
                policy_path = _validate_path(
                    policy_str,
                    label="policy path",
                    must_exist=True,
                    expected_kind="file",
                )
            except HTTPException as exc:
                if exc.status_code == 404:
                    raise ValueError(
                        f"Unknown policy '{policy_str}'. Use a preset name or a path to a YAML file."
                    ) from exc
                raise ValueError(str(exc.detail)) from exc
            if policy_path.suffix not in (".yaml", ".yml"):
                raise ValueError("Policy file must have a .yaml or .yml extension.")
            policy = ScanPolicy.from_yaml(policy_path)

    if cel_mode is not None:
        policy.cel.mode = CelMode(cel_mode)
    return policy


def _resolve_request_policy(policy_str: str | None, cel_mode: CelMode | str | None) -> ScanPolicy:
    """Resolve an API policy without passing a redundant override keyword.

    Keeping the no-override path identical to the historical one-argument call is
    useful for API embedders that wrap ``_resolve_policy`` for policy selection,
    while an explicitly requested CEL mode still takes the strict override path.
    """
    if cel_mode is None:
        return _resolve_policy(policy_str)
    return _resolve_policy(policy_str, cel_mode=cel_mode)


def _create_api_scanner(analyzers: list, policy: ScanPolicy | None) -> SkillScanner:
    """Create an API scanner with a strictly validated bundled generation.

    Remote callers cannot nominate trusted local pack paths, but active CEL
    modes must still compile and evaluate gates shipped in bundled packs.
    Validation is a startup invariant even when CEL is off; the pack loader
    process-caches the installed immutable generation.
    """
    from ..core.rule_registry import PackLoader

    try:
        registry = PackLoader().build_registry()
        return SkillScanner(analyzers=analyzers, policy=policy, rule_registry=registry)
    except CelRuntimeUnavailable:
        raise
    except ValueError as exc:
        # Rule parse/type/metadata failures are local service configuration
        # errors, not malformed scan requests from the remote caller.
        raise _RulePackStartupConfigurationError(f"Bundled rule-pack configuration failed: {exc}") from exc


def _skill_load_error_detail(error: SkillLoadError, skill_dir: Path) -> str:
    """Return client-safe validation detail for skill loading failures."""
    detail = str(error).replace(str(skill_dir), "skill directory")
    return f"Invalid skill package: {detail}"


def _build_analyzers(
    policy: ScanPolicy,
    *,
    custom_rules: str | None = None,
    use_behavioral: bool = False,
    use_llm: bool = False,
    llm_provider: str | None = "anthropic",
    use_virustotal: bool = False,
    vt_api_key: str | None = None,
    vt_upload_files: bool = False,
    use_aidefense: bool = False,
    aidefense_api_key: str | None = None,
    aidefense_api_url: str | None = None,
    use_trigger: bool = False,
    use_osv: bool = False,
    llm_consensus_runs: int = 1,
    llm_max_tokens: int | None = None,
    llm_reasoning_effort: str | None = None,
):
    """Build the analyzer list — delegates to the centralized factory."""
    return build_analyzers(
        policy,
        custom_yara_rules_path=custom_rules,
        use_behavioral=use_behavioral,
        use_llm=use_llm,
        llm_provider=llm_provider,
        use_virustotal=use_virustotal,
        vt_api_key=vt_api_key,
        vt_upload_files=vt_upload_files,
        use_aidefense=use_aidefense,
        aidefense_api_key=aidefense_api_key,
        aidefense_api_url=aidefense_api_url,
        use_trigger=use_trigger,
        use_osv=use_osv,
        llm_consensus_runs=llm_consensus_runs,
        llm_max_tokens=llm_max_tokens,
        llm_reasoning_effort=llm_reasoning_effort,
    )


def _recompute_report_summary(report) -> None:
    """Recompute Report aggregate counters from current per-skill findings."""
    report.total_skills_scanned = len(report.scan_results)
    report.total_findings = sum(len(r.findings) for r in report.scan_results)
    report.critical_count = 0
    report.high_count = 0
    report.medium_count = 0
    report.low_count = 0
    report.info_count = 0
    report.safe_count = sum(1 for r in report.scan_results if r.is_safe)

    all_findings = [f for r in report.scan_results for f in r.findings]
    cross = getattr(report, "cross_skill_findings", None) or []
    report.total_findings += len(cross)
    all_findings.extend(cross)

    for finding in all_findings:
        sev = getattr(finding.severity, "value", str(finding.severity)).upper()
        if sev == "CRITICAL":
            report.critical_count += 1
        elif sev == "HIGH":
            report.high_count += 1
        elif sev == "MEDIUM":
            report.medium_count += 1
        elif sev == "LOW":
            report.low_count += 1
        elif sev == "INFO":
            report.info_count += 1


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=dict)
async def root():
    """Root endpoint."""
    return {"service": "Skill Scanner API", "version": PACKAGE_VERSION, "docs": "/docs", "health": "/health"}


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    analyzers = ["static_analyzer", "bytecode_analyzer", "pipeline_analyzer"]
    if BEHAVIORAL_AVAILABLE:
        analyzers.append("behavioral_analyzer")
    if LLM_AVAILABLE:
        analyzers.append("llm_analyzer")
    if VIRUSTOTAL_AVAILABLE:
        analyzers.append("virustotal_analyzer")
    if AIDEFENSE_AVAILABLE:
        analyzers.append("aidefense_analyzer")
    if TRIGGER_AVAILABLE:
        analyzers.append("trigger_analyzer")
    if META_AVAILABLE:
        analyzers.append("meta_analyzer")

    return HealthResponse(status="healthy", version=PACKAGE_VERSION, analyzers_available=analyzers)


@router.post("/scan", response_model=ScanResponse)
async def scan_skill(
    request: ScanRequest,
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
):
    """Scan a single skill package."""
    import asyncio
    import concurrent.futures

    skill_dir = _validate_path(
        request.skill_directory,
        label="skill_directory",
        must_exist=True,
        expected_kind="directory",
    )

    if not (skill_dir / "SKILL.md").exists():
        raise HTTPException(status_code=400, detail="SKILL.md not found in directory")

    custom_rules_path: str | None = None
    if request.custom_rules:
        validated_rules = _validate_path(
            request.custom_rules,
            label="custom_rules",
            must_exist=True,
            expected_kind="directory",
        )
        custom_rules_path = str(validated_rules)

    try:
        policy = _resolve_request_policy(request.policy, request.cel_mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan_id = str(uuid.uuid4())

    def run_scan():
        # Context variables do not automatically cross executor boundaries,
        # so bind the request id inside the worker thread itself.
        with scan_log_context(scan_id=scan_id):
            analyzers = _build_analyzers(
                policy,
                custom_rules=custom_rules_path,
                use_behavioral=request.use_behavioral,
                use_llm=request.use_llm,
                llm_provider=request.llm_provider,
                use_virustotal=request.use_virustotal,
                vt_api_key=vt_api_key,
                vt_upload_files=request.vt_upload_files,
                use_aidefense=request.use_aidefense,
                aidefense_api_key=aidefense_api_key,
                aidefense_api_url=request.aidefense_api_url,
                use_trigger=request.use_trigger,
                use_osv=request.use_osv,
                llm_consensus_runs=request.llm_consensus_runs,
                llm_max_tokens=request.llm_max_tokens,
                llm_reasoning_effort=request.llm_reasoning_effort,
            )
            with _create_api_scanner(analyzers, policy) as scanner:
                return scanner.scan_skill(skill_dir)

    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(executor, run_scan)

        # Meta-analysis
        if (
            request.enable_meta
            and META_AVAILABLE
            and MetaAnalyzer is not None
            and apply_meta_analysis_to_results is not None
            and len(result.findings) > 0
        ):
            with scan_log_context(
                skill_name=result.skill_name,
                skill_path=str(skill_dir),
                scan_id=scan_id,
            ):
                try:
                    from ..core.loader import SkillLoader

                    meta_analyzer = MetaAnalyzer(
                        policy=policy,
                        max_tokens=resolve_llm_max_tokens(
                            request.llm_max_tokens,
                            meta=True,
                            default=policy.llm_analysis.max_output_tokens if policy else 8192,
                        ),
                        provider=request.llm_provider,
                        reasoning_effort=request.llm_reasoning_effort,
                    )
                    loader = SkillLoader()
                    skill = loader.load_skill(skill_dir)

                    meta_result = await meta_analyzer.analyze_with_findings(
                        skill=skill,
                        findings=result.findings,
                        analyzers_used=result.analyzers_used,
                    )

                    filtered_findings = apply_meta_analysis_to_results(
                        original_findings=result.findings,
                        meta_result=meta_result,
                        skill=skill,
                    )
                    result.findings = filtered_findings
                    result.analyzers_used.append("meta_analyzer")
                    if merge_meta_analyzer_usage is not None:
                        merge_meta_analyzer_usage(result, meta_analyzer)
                except ReasoningConfigurationError:
                    raise
                except Exception as meta_error:
                    logger.warning("Meta-analysis failed: %s", meta_error)

        return ScanResponse(
            scan_id=scan_id,
            skill_name=result.skill_name,
            is_safe=result.is_safe,
            max_severity=result.max_severity.value,
            findings_count=len(result.findings),
            scan_duration_seconds=result.scan_duration_seconds,
            timestamp=result.timestamp.isoformat(),
            findings=[f.to_dict() for f in result.findings],
            scan_metadata=result.scan_metadata or {},
            llm_usage=result.llm_usage,
        )

    except (CelRuntimeUnavailable, _RulePackStartupConfigurationError) as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except SkillLoadError as e:
        raise HTTPException(status_code=422, detail=_skill_load_error_detail(e, skill_dir)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Scan failed")
        raise HTTPException(status_code=500, detail="Internal scan error")


@router.post("/scan-upload")
async def scan_uploaded_skill(
    file: UploadFile = File(..., description="ZIP file containing skill package"),
    policy: str | None = Form(None, description="Scan policy: preset name or path to YAML"),
    cel_mode: CelMode | None = Form(
        None,
        description="Optional CEL decision-mode override: off, shadow (observe only), or enforce",
    ),
    trusted_rule_packs: list[str] | None = Form(
        None,
        description="Unsupported over the API; trusted packs require local administrator configuration",
    ),
    custom_rules: str | None = Form(None, description="Path to custom YARA rules directory"),
    use_llm: bool = Form(False, description="Enable LLM analyzer"),
    llm_provider: str = Form("anthropic", description="LLM provider"),
    use_behavioral: bool = Form(False, description="Enable behavioral analyzer"),
    use_virustotal: bool = Form(False, description="Enable VirusTotal scanner"),
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    vt_upload_files: bool = Form(False, description="Upload unknown files to VirusTotal"),
    use_aidefense: bool = Form(False, description="Enable AI Defense analyzer"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
    aidefense_api_url: str | None = Form(None, description="AI Defense API URL"),
    use_trigger: bool = Form(False, description="Enable trigger specificity analysis"),
    use_osv: bool = Form(False, description="Enable OSV.dev dependency vulnerability scanning"),
    enable_meta: bool = Form(False, description="Enable meta-analysis for FP filtering"),
    llm_consensus_runs: int = Form(1, description="Number of LLM consensus runs"),
    llm_max_tokens: int | None = Form(
        None,
        gt=0,
        description="Maximum output tokens for LLM and meta-analysis responses",
    ),
    llm_reasoning_effort: LLMReasoningEffort | None = Form(
        None,
        description="Optional LLM reasoning effort; unset preserves the provider default",
    ),
):
    """Scan an uploaded skill package (ZIP file)."""
    if trusted_rule_packs is not None:
        raise HTTPException(
            status_code=422,
            detail=(
                "trusted_rule_packs cannot be supplied over the remote API; "
                "trusted rule packs must be configured by the local service administrator"
            ),
        )

    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="request_",
            dir=str(_API_UPLOAD_ROOT),
        )
    )

    try:
        # Stream upload with size limit to avoid memory exhaustion
        # The multipart filename is display metadata, not a filesystem path.
        # A fixed server-owned name prevents absolute/relative path injection.
        zip_path = temp_dir / "upload.zip"
        total_read = 0
        chunk_size = 1024 * 1024  # 1 MB chunks
        with open(zip_path, "wb") as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB",
                    )
                f.write(chunk)

        import stat
        import zipfile

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                # Enforce entry count and uncompressed size limits
                entries = [info for info in zip_ref.infolist() if not info.is_dir()]
                if len(entries) > MAX_ZIP_ENTRIES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"ZIP contains {len(entries)} files, exceeding limit of {MAX_ZIP_ENTRIES}",
                    )
                total_uncompressed = sum(info.file_size for info in entries)
                if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"ZIP uncompressed size ({total_uncompressed // (1024 * 1024)} MB) "
                            f"exceeds limit of {MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024)} MB"
                        ),
                    )
                # Check for path traversal and symlinks using resolved extraction targets.
                extract_root = (temp_dir / "extracted").resolve()
                for info in zip_ref.infolist():
                    # Reject symlink entries — they can escape the extraction directory
                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    if unix_mode != 0 and stat.S_ISLNK(unix_mode):
                        raise HTTPException(status_code=400, detail="ZIP contains symbolic link entries")
                    dest_path = (extract_root / info.filename).resolve()
                    if not dest_path.is_relative_to(extract_root):
                        raise HTTPException(status_code=400, detail="ZIP contains path traversal entries")

                # Extract member-by-member, verifying no symlink appears on disk
                extract_root.mkdir(parents=True, exist_ok=True)
                for info in zip_ref.infolist():
                    zip_ref.extract(info, extract_root)
                    dest_path = (extract_root / info.filename).resolve()
                    if dest_path.is_symlink():
                        dest_path.unlink()
                        raise HTTPException(
                            status_code=400,
                            detail="ZIP extraction produced a symbolic link — rejected",
                        )
        except zipfile.BadZipFile as e:
            raise HTTPException(status_code=400, detail="Invalid ZIP archive") from e

        extracted_dir = temp_dir / "extracted"
        skill_dirs = list(extracted_dir.rglob("SKILL.md"))

        if not skill_dirs:
            raise HTTPException(status_code=400, detail="No SKILL.md found in uploaded archive")

        skill_dir = skill_dirs[0].parent

        request = ScanRequest(
            skill_directory=str(skill_dir),
            policy=policy,
            cel_mode=cel_mode,
            custom_rules=custom_rules,
            use_llm=use_llm,
            llm_provider=llm_provider,
            use_behavioral=use_behavioral,
            use_virustotal=use_virustotal,
            vt_upload_files=vt_upload_files,
            use_aidefense=use_aidefense,
            aidefense_api_url=aidefense_api_url,
            use_trigger=use_trigger,
            use_osv=use_osv,
            enable_meta=enable_meta,
            llm_consensus_runs=llm_consensus_runs,
            llm_max_tokens=llm_max_tokens,
            llm_reasoning_effort=llm_reasoning_effort,
        )

        return await scan_skill(request, vt_api_key=vt_api_key, aidefense_api_key=aidefense_api_key)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/scan-batch")
async def scan_batch(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks,
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
):
    """Scan multiple skills in a directory (batch scan)."""
    skills_dir = _validate_path(
        request.skills_directory,
        label="skills_directory",
        must_exist=True,
        expected_kind="directory",
    )

    scan_id = str(uuid.uuid4())
    scan_results_cache.set(scan_id, {"status": "processing", "started_at": datetime.now().isoformat(), "result": None})

    background_tasks.add_task(run_batch_scan, scan_id, request, vt_api_key, aidefense_api_key)

    return {
        "scan_id": scan_id,
        "status": "processing",
        "message": "Batch scan started. Use GET /scan-batch/{scan_id} to check status.",
    }


@router.get("/scan-batch/{scan_id}")
async def get_batch_scan_result(scan_id: str):
    """Get results of a batch scan."""
    cached = scan_results_cache.get_valid(scan_id)
    if cached is None:
        raise HTTPException(status_code=404, detail="Scan ID not found or expired")

    if cached["status"] == "processing":
        return {"scan_id": scan_id, "status": "processing", "started_at": cached["started_at"]}
    elif cached["status"] == "completed":
        return {
            "scan_id": scan_id,
            "status": "completed",
            "started_at": cached["started_at"],
            "completed_at": cached.get("completed_at"),
            "result": cached["result"],
        }
    else:
        return {"scan_id": scan_id, "status": "error", "error": cached.get("error", "Unknown error")}


def run_batch_scan(
    scan_id: str,
    request: BatchScanRequest,
    vt_api_key: str | None = None,
    aidefense_api_key: str | None = None,
):
    """Background task to run batch scan."""
    with scan_log_context(scan_id=scan_id):
        _run_batch_scan(scan_id, request, vt_api_key, aidefense_api_key)


def _run_batch_scan(
    scan_id: str,
    request: BatchScanRequest,
    vt_api_key: str | None = None,
    aidefense_api_key: str | None = None,
):
    """Run a batch scan with its request context already bound."""
    scanner: SkillScanner | None = None
    try:
        policy = _resolve_request_policy(request.policy, request.cel_mode)

        custom_rules_path: str | None = None
        if request.custom_rules:
            custom_rules_path = str(
                _validate_path(
                    request.custom_rules,
                    label="custom_rules",
                    must_exist=True,
                    expected_kind="directory",
                )
            )

        analyzers = _build_analyzers(
            policy,
            custom_rules=custom_rules_path,
            use_behavioral=request.use_behavioral,
            use_llm=request.use_llm,
            llm_provider=request.llm_provider,
            use_virustotal=request.use_virustotal,
            vt_api_key=vt_api_key,
            vt_upload_files=request.vt_upload_files,
            use_aidefense=request.use_aidefense,
            aidefense_api_key=aidefense_api_key,
            aidefense_api_url=request.aidefense_api_url,
            use_trigger=request.use_trigger,
            use_osv=request.use_osv,
            llm_consensus_runs=request.llm_consensus_runs,
            llm_max_tokens=request.llm_max_tokens,
            llm_reasoning_effort=request.llm_reasoning_effort,
        )

        scanner = _create_api_scanner(analyzers, policy)
        report = scanner.scan_directory(
            _validate_path(
                request.skills_directory,
                label="skills_directory",
                must_exist=True,
                expected_kind="directory",
            ),
            recursive=request.recursive,
            check_overlap=request.check_overlap,
        )

        # Meta-analysis per skill
        if (
            request.enable_meta
            and META_AVAILABLE
            and MetaAnalyzer is not None
            and apply_meta_analysis_to_results is not None
        ):
            import asyncio

            async def _run_batch_meta(scanner_ref, report_ref, policy_ref):
                meta_analyzer = MetaAnalyzer(
                    policy=policy_ref,
                    max_tokens=resolve_llm_max_tokens(
                        request.llm_max_tokens,
                        meta=True,
                        default=policy_ref.llm_analysis.max_output_tokens if policy_ref else 8192,
                    ),
                    provider=request.llm_provider,
                    reasoning_effort=request.llm_reasoning_effort,
                )
                for result in report_ref.scan_results:
                    if result.findings:
                        skill_dir_path = Path(result.skill_directory)
                        with scan_log_context(
                            skill_name=result.skill_name,
                            skill_path=str(skill_dir_path.resolve()),
                        ):
                            try:
                                skill = scanner_ref.loader.load_skill(skill_dir_path)
                                meta_result = await meta_analyzer.analyze_with_findings(
                                    skill=skill,
                                    findings=result.findings,
                                    analyzers_used=result.analyzers_used,
                                )
                                filtered_findings = apply_meta_analysis_to_results(
                                    original_findings=result.findings,
                                    meta_result=meta_result,
                                    skill=skill,
                                )
                                result.findings = filtered_findings
                                result.analyzers_used.append("meta_analyzer")
                                if merge_meta_analyzer_usage is not None:
                                    merge_meta_analyzer_usage(result, meta_analyzer)
                            except Exception:
                                pass

            try:
                asyncio.run(_run_batch_meta(scanner, report, policy))
            except ReasoningConfigurationError:
                raise
            except Exception:
                pass

        # Keep batch summary counters consistent with potentially mutated
        # per-skill findings (e.g., after meta-analysis filtering).
        _recompute_report_summary(report)

        started_at = scan_results_cache.get(scan_id, {}).get("started_at", datetime.now().isoformat())
        scan_results_cache.set(
            scan_id,
            {
                "status": "completed",
                "started_at": started_at,
                "completed_at": datetime.now().isoformat(),
                "result": report.to_dict(),
            },
        )

    except Exception as e:
        started_at = scan_results_cache.get(scan_id, {}).get("started_at", datetime.now().isoformat())
        scan_results_cache.set(
            scan_id,
            {
                "status": "error",
                "started_at": started_at,
                "error": str(e),
            },
        )
    finally:
        if scanner is not None:
            scanner.close()


@router.get("/analyzers")
async def list_analyzers():
    """List available analyzers."""
    analyzers = [
        {
            "name": "static_analyzer",
            "description": "Pattern-based detection using YAML and YARA rules",
            "available": True,
            "rules_count": "90+",
        },
        {
            "name": "bytecode_analyzer",
            "description": "Python bytecode integrity verification against source",
            "available": True,
        },
        {
            "name": "pipeline_analyzer",
            "description": "Command pipeline taint analysis for data exfiltration",
            "available": True,
        },
    ]

    if BEHAVIORAL_AVAILABLE:
        analyzers.append(
            {
                "name": "behavioral_analyzer",
                "description": "Static dataflow analysis for Python files",
                "available": True,
            }
        )

    if LLM_AVAILABLE:
        analyzers.append(
            {
                "name": "llm_analyzer",
                "description": "Semantic analysis using LLM as a judge",
                "available": True,
                "providers": ["anthropic", "openai", "azure", "bedrock", "gemini"],
            }
        )

    if VIRUSTOTAL_AVAILABLE:
        analyzers.append(
            {
                "name": "virustotal_analyzer",
                "description": "Hash-based malware detection for binary files via VirusTotal",
                "available": True,
                "requires_api_key": True,
            }
        )

    if AIDEFENSE_AVAILABLE:
        analyzers.append(
            {
                "name": "aidefense_analyzer",
                "description": "Cisco AI Defense cloud-based threat detection",
                "available": True,
                "requires_api_key": True,
            }
        )

    if TRIGGER_AVAILABLE:
        analyzers.append(
            {
                "name": "trigger_analyzer",
                "description": "Trigger specificity analysis for overly generic descriptions",
                "available": True,
            }
        )

    if META_AVAILABLE:
        analyzers.append(
            {
                "name": "meta_analyzer",
                "description": "Second-pass LLM analysis for false positive filtering",
                "available": True,
                "requires": "2+ analyzers, LLM API key",
            }
        )

    return {"analyzers": analyzers}
