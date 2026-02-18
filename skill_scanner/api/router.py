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
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

try:
    from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
    from pydantic import BaseModel, Field

    MULTIPART_AVAILABLE = True
except ImportError:
    raise ImportError("API server requires FastAPI. Install with: pip install fastapi uvicorn python-multipart")

from .. import __version__ as PACKAGE_VERSION
from ..core.analyzer_factory import build_analyzers
from ..core.scan_policy import ScanPolicy
from ..core.scanner import SkillScanner

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
try:
    from ..core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None

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

    def set(self, key: str, value: dict) -> None:
        value["_cached_at"] = time.monotonic()
        self[key] = value
        self.move_to_end(key)
        # Evict oldest entries beyond max size
        while len(self) > MAX_CACHE_ENTRIES:
            self.popitem(last=False)

    def get_valid(self, key: str) -> dict | None:
        entry = self.get(key)
        if entry is None:
            return None
        if time.monotonic() - entry.get("_cached_at", 0) > CACHE_TTL_SECONDS:
            del self[key]
            return None
        result: dict = entry
        return result


scan_results_cache = _BoundedCache()

# Environment-configurable allowlist of directories the API may access.
# When empty (default) any *resolved* absolute path is accepted — operators
# should set SKILL_SCANNER_ALLOWED_ROOTS to restrict access in production.
_ALLOWED_ROOTS: list[Path] = [
    Path(p).resolve() for p in os.environ.get("SKILL_SCANNER_ALLOWED_ROOTS", "").split(":") if p.strip()
]


def _validate_path(user_input: str, *, label: str = "path") -> Path:
    """Sanitize and validate a user-supplied filesystem path.

    Rejects null bytes and path-traversal attempts, resolves symlinks, and
    enforces the optional SKILL_SCANNER_ALLOWED_ROOTS allowlist.
    """
    if "\x00" in user_input:
        raise HTTPException(status_code=400, detail=f"Invalid {label}: null bytes are not allowed")

    resolved = Path(user_input).resolve()

    if _ALLOWED_ROOTS and not any(resolved == root or resolved.is_relative_to(root) for root in _ALLOWED_ROOTS):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {label} is outside the allowed directories",
        )

    return resolved


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request model for scanning a skill."""

    skill_directory: str = Field(..., description="Path to skill directory")
    policy: str | None = Field(
        None,
        description="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    custom_rules: str | None = Field(None, description="Path to custom YARA rules directory")
    use_llm: bool = Field(False, description="Enable LLM analyzer")
    llm_provider: str | None = Field("anthropic", description="LLM provider (anthropic or openai)")
    use_behavioral: bool = Field(False, description="Enable behavioral analyzer")
    use_virustotal: bool = Field(False, description="Enable VirusTotal binary file scanning")
    vt_api_key: str | None = Field(None, description="VirusTotal API key")
    vt_upload_files: bool = Field(False, description="Upload unknown files to VirusTotal")
    use_aidefense: bool = Field(False, description="Enable AI Defense analyzer")
    aidefense_api_key: str | None = Field(None, description="AI Defense API key")
    aidefense_api_url: str | None = Field(None, description="AI Defense API URL")
    use_trigger: bool = Field(False, description="Enable trigger specificity analysis")
    enable_meta: bool = Field(False, description="Enable meta-analysis for false positive filtering")
    llm_consensus_runs: int = Field(1, description="Number of LLM consensus runs (majority vote)")


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


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    analyzers_available: list[str]


class BatchScanRequest(BaseModel):
    """Request for batch scanning."""

    skills_directory: str
    policy: str | None = Field(
        None,
        description="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    custom_rules: str | None = Field(None, description="Path to custom YARA rules directory")
    recursive: bool = False
    check_overlap: bool = Field(False, description="Enable cross-skill description overlap detection")
    use_llm: bool = False
    llm_provider: str | None = "anthropic"
    use_behavioral: bool = False
    use_virustotal: bool = False
    vt_api_key: str | None = None
    vt_upload_files: bool = False
    use_aidefense: bool = False
    aidefense_api_key: str | None = None
    aidefense_api_url: str | None = None
    use_trigger: bool = False
    enable_meta: bool = Field(False, description="Enable meta-analysis")
    llm_consensus_runs: int = Field(1, description="Number of LLM consensus runs (majority vote)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_policy(policy_str: str | None) -> ScanPolicy:
    """Resolve a policy string to a ScanPolicy object."""
    if policy_str is None or not policy_str.strip():
        return ScanPolicy.default()
    policy_str = policy_str.strip()
    if policy_str.lower() in ("strict", "balanced", "permissive"):
        return ScanPolicy.from_preset(policy_str)
    policy_path = _validate_path(policy_str, label="policy path")
    if policy_path.exists():
        if not policy_path.is_file():
            raise ValueError(f"Policy path '{policy_str}' is not a file.")
        if policy_path.suffix not in (".yaml", ".yml"):
            raise ValueError("Policy file must have a .yaml or .yml extension.")
        return ScanPolicy.from_yaml(str(policy_path))
    raise ValueError(f"Unknown policy '{policy_str}'. Use a preset name or a path to a YAML file.")


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
    llm_consensus_runs: int = 1,
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
        llm_consensus_runs=llm_consensus_runs,
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

    for scan_result in report.scan_results:
        for finding in scan_result.findings:
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
async def scan_skill(request: ScanRequest):
    """Scan a single skill package."""
    import asyncio
    import concurrent.futures

    skill_dir = _validate_path(request.skill_directory, label="skill_directory")

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill directory not found: {skill_dir}")

    if not skill_dir.is_dir():
        raise HTTPException(status_code=400, detail="skill_directory must be a directory")

    if not (skill_dir / "SKILL.md").exists():
        raise HTTPException(status_code=400, detail="SKILL.md not found in directory")

    custom_rules_path: str | None = None
    if request.custom_rules:
        validated_rules = _validate_path(request.custom_rules, label="custom_rules")
        if not validated_rules.is_dir():
            raise HTTPException(status_code=400, detail="custom_rules must be a directory")
        custom_rules_path = str(validated_rules)

    try:
        policy = _resolve_policy(request.policy)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    def run_scan():
        analyzers = _build_analyzers(
            policy,
            custom_rules=custom_rules_path,
            use_behavioral=request.use_behavioral,
            use_llm=request.use_llm,
            llm_provider=request.llm_provider,
            use_virustotal=request.use_virustotal,
            vt_api_key=request.vt_api_key,
            vt_upload_files=request.vt_upload_files,
            use_aidefense=request.use_aidefense,
            aidefense_api_key=request.aidefense_api_key,
            aidefense_api_url=request.aidefense_api_url,
            use_trigger=request.use_trigger,
            llm_consensus_runs=request.llm_consensus_runs,
        )
        scanner = SkillScanner(analyzers=analyzers, policy=policy)
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
            try:
                from ..core.loader import SkillLoader

                meta_analyzer = MetaAnalyzer(policy=policy)
                loader = SkillLoader()
                skill = loader.load_skill(skill_dir)

                import asyncio as async_lib

                def run_meta():
                    return async_lib.run(
                        meta_analyzer.analyze_with_findings(
                            skill=skill,
                            findings=result.findings,
                            analyzers_used=result.analyzers_used,
                        )
                    )

                with concurrent.futures.ThreadPoolExecutor() as meta_executor:
                    meta_result = await loop.run_in_executor(meta_executor, run_meta)

                filtered_findings = apply_meta_analysis_to_results(
                    original_findings=result.findings,
                    meta_result=meta_result,
                    skill=skill,
                )
                result.findings = filtered_findings
                result.analyzers_used.append("meta_analyzer")
            except Exception as meta_error:
                logger.warning("Meta-analysis failed: %s", meta_error)

        scan_id = str(uuid.uuid4())
        return ScanResponse(
            scan_id=scan_id,
            skill_name=result.skill_name,
            is_safe=result.is_safe,
            max_severity=result.max_severity.value,
            findings_count=len(result.findings),
            scan_duration_seconds=result.scan_duration_seconds,
            timestamp=result.timestamp.isoformat(),
            findings=[f.to_dict() for f in result.findings],
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan-upload")
async def scan_uploaded_skill(
    file: UploadFile = File(..., description="ZIP file containing skill package"),
    policy: str | None = Form(None, description="Scan policy: preset name or path to YAML"),
    custom_rules: str | None = Form(None, description="Path to custom YARA rules directory"),
    use_llm: bool = Form(False, description="Enable LLM analyzer"),
    llm_provider: str = Form("anthropic", description="LLM provider"),
    use_behavioral: bool = Form(False, description="Enable behavioral analyzer"),
    use_virustotal: bool = Form(False, description="Enable VirusTotal scanner"),
    vt_api_key: str | None = Form(None, description="VirusTotal API key"),
    vt_upload_files: bool = Form(False, description="Upload unknown files to VirusTotal"),
    use_aidefense: bool = Form(False, description="Enable AI Defense analyzer"),
    aidefense_api_key: str | None = Form(None, description="AI Defense API key"),
    aidefense_api_url: str | None = Form(None, description="AI Defense API URL"),
    use_trigger: bool = Form(False, description="Enable trigger specificity analysis"),
    enable_meta: bool = Form(False, description="Enable meta-analysis for FP filtering"),
    llm_consensus_runs: int = Form(1, description="Number of LLM consensus runs"),
):
    """Scan an uploaded skill package (ZIP file)."""
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    temp_dir = Path(tempfile.mkdtemp(prefix="skill_scanner_"))

    try:
        # Stream upload with size limit to avoid memory exhaustion
        zip_path = temp_dir / file.filename
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
            custom_rules=custom_rules,
            use_llm=use_llm,
            llm_provider=llm_provider,
            use_behavioral=use_behavioral,
            use_virustotal=use_virustotal,
            vt_api_key=vt_api_key,
            vt_upload_files=vt_upload_files,
            use_aidefense=use_aidefense,
            aidefense_api_key=aidefense_api_key,
            aidefense_api_url=aidefense_api_url,
            use_trigger=use_trigger,
            enable_meta=enable_meta,
            llm_consensus_runs=llm_consensus_runs,
        )

        return await scan_skill(request)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/scan-batch")
async def scan_batch(request: BatchScanRequest, background_tasks: BackgroundTasks):
    """Scan multiple skills in a directory (batch scan)."""
    skills_dir = _validate_path(request.skills_directory, label="skills_directory")

    if not skills_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skills directory not found: {skills_dir}")

    if not skills_dir.is_dir():
        raise HTTPException(status_code=400, detail="skills_directory must be a directory")

    scan_id = str(uuid.uuid4())
    scan_results_cache.set(scan_id, {"status": "processing", "started_at": datetime.now().isoformat(), "result": None})

    background_tasks.add_task(run_batch_scan, scan_id, request)

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


def run_batch_scan(scan_id: str, request: BatchScanRequest):
    """Background task to run batch scan."""
    try:
        policy = _resolve_policy(request.policy)

        custom_rules_path: str | None = None
        if request.custom_rules:
            custom_rules_path = str(_validate_path(request.custom_rules, label="custom_rules"))

        analyzers = _build_analyzers(
            policy,
            custom_rules=custom_rules_path,
            use_behavioral=request.use_behavioral,
            use_llm=request.use_llm,
            llm_provider=request.llm_provider,
            use_virustotal=request.use_virustotal,
            vt_api_key=request.vt_api_key,
            vt_upload_files=request.vt_upload_files,
            use_aidefense=request.use_aidefense,
            aidefense_api_key=request.aidefense_api_key,
            aidefense_api_url=request.aidefense_api_url,
            use_trigger=request.use_trigger,
            llm_consensus_runs=request.llm_consensus_runs,
        )

        scanner = SkillScanner(analyzers=analyzers, policy=policy)
        report = scanner.scan_directory(
            _validate_path(request.skills_directory, label="skills_directory"),
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

            try:
                meta_analyzer = MetaAnalyzer(policy=policy)
                for result in report.scan_results:
                    if result.findings:
                        try:
                            skill_dir_path = Path(result.skill_directory)
                            skill = scanner.loader.load_skill(skill_dir_path)
                            meta_result = asyncio.run(
                                meta_analyzer.analyze_with_findings(
                                    skill=skill,
                                    findings=result.findings,
                                    analyzers_used=result.analyzers_used,
                                )
                            )
                            filtered_findings = apply_meta_analysis_to_results(
                                original_findings=result.findings,
                                meta_result=meta_result,
                                skill=skill,
                            )
                            result.findings = filtered_findings
                            result.analyzers_used.append("meta_analyzer")
                        except Exception:
                            pass
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
