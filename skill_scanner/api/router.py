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
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

try:
    from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, UploadFile
    from pydantic import BaseModel, Field

    MULTIPART_AVAILABLE = True
except ImportError:
    raise ImportError("API server requires FastAPI. Install with: pip install fastapi uvicorn python-multipart")

from ..core.analyzers.bytecode_analyzer import BytecodeAnalyzer
from ..core.analyzers.pipeline_analyzer import PipelineAnalyzer
from ..core.analyzers.static import StaticAnalyzer
from ..core.scan_policy import ScanPolicy
from ..core.scanner import SkillScanner

logger = logging.getLogger("skill_scanner.api")

try:
    from ..core.analyzers.llm_analyzer import LLMAnalyzer

    LLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LLM_AVAILABLE = False
    LLMAnalyzer = None

try:
    from ..core.analyzers.behavioral_analyzer import BehavioralAnalyzer

    BEHAVIORAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    BEHAVIORAL_AVAILABLE = False
    BehavioralAnalyzer = None

try:
    from ..core.analyzers.aidefense_analyzer import AIDefenseAnalyzer

    AIDEFENSE_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AIDEFENSE_AVAILABLE = False
    AIDefenseAnalyzer = None

try:
    from ..core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

    VIRUSTOTAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    VIRUSTOTAL_AVAILABLE = False
    VirusTotalAnalyzer = None

try:
    from ..core.analyzers.trigger_analyzer import TriggerAnalyzer

    TRIGGER_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    TRIGGER_AVAILABLE = False
    TriggerAnalyzer = None

try:
    from ..core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None

router = APIRouter()

# In-memory storage for async scans (in production, use Redis or database)
scan_results_cache = {}


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_policy(policy_str: str | None) -> ScanPolicy:
    """Resolve a policy string to a ScanPolicy object."""
    if policy_str is None:
        return ScanPolicy.default()
    if policy_str in ("strict", "balanced", "permissive"):
        return ScanPolicy.from_preset(policy_str)
    policy_path = Path(policy_str)
    if policy_path.exists():
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
):
    """Build the analyzer list from policy flags and request parameters."""
    import os

    from ..core.analyzers.base import BaseAnalyzer

    analyzers: list[BaseAnalyzer] = []

    if policy.analyzers.static:
        analyzers.append(StaticAnalyzer(custom_yara_rules_path=custom_rules, policy=policy))
    if policy.analyzers.bytecode:
        analyzers.append(BytecodeAnalyzer())
    if policy.analyzers.pipeline:
        analyzers.append(PipelineAnalyzer(policy=policy))

    if use_behavioral and BEHAVIORAL_AVAILABLE:
        analyzers.append(BehavioralAnalyzer())

    if use_llm and LLM_AVAILABLE:
        llm_model = os.getenv("SKILL_SCANNER_LLM_MODEL")
        provider_str = llm_provider or "anthropic"
        if llm_model:
            analyzers.append(LLMAnalyzer(model=llm_model))
        else:
            analyzers.append(LLMAnalyzer(provider=provider_str))

    if use_virustotal and VIRUSTOTAL_AVAILABLE:
        key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            raise ValueError("VirusTotal API key required (set VIRUSTOTAL_API_KEY or pass vt_api_key)")
        analyzers.append(VirusTotalAnalyzer(api_key=key, enabled=True, upload_files=vt_upload_files))

    if use_aidefense and AIDEFENSE_AVAILABLE:
        key = aidefense_api_key or os.getenv("AI_DEFENSE_API_KEY")
        if not key:
            raise ValueError("AI Defense API key required (set AI_DEFENSE_API_KEY or pass aidefense_api_key)")
        url = aidefense_api_url or os.getenv("AI_DEFENSE_API_URL")
        analyzers.append(AIDefenseAnalyzer(api_key=key, api_url=url))

    if use_trigger and TRIGGER_AVAILABLE:
        analyzers.append(TriggerAnalyzer())

    return analyzers


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=dict)
async def root():
    """Root endpoint."""
    return {"service": "Skill Scanner API", "version": "0.3.0", "docs": "/docs", "health": "/health"}


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

    return HealthResponse(status="healthy", version="0.3.0", analyzers_available=analyzers)


@router.post("/scan", response_model=ScanResponse)
async def scan_skill(request: ScanRequest):
    """Scan a single skill package."""
    import asyncio
    import concurrent.futures

    skill_dir = Path(request.skill_directory)

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill directory not found: {skill_dir}")

    if not (skill_dir / "SKILL.md").exists():
        raise HTTPException(status_code=400, detail="SKILL.md not found in directory")

    def run_scan():
        policy = _resolve_policy(request.policy)
        analyzers = _build_analyzers(
            policy,
            custom_rules=request.custom_rules,
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
        )
        scanner = SkillScanner(analyzers=analyzers, policy=policy)
        return scanner.scan_skill(skill_dir)

    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(executor, run_scan)

        # Meta-analysis
        if request.enable_meta and META_AVAILABLE and len(result.findings) > 0:
            try:
                from ..core.loader import SkillLoader

                meta_analyzer = MetaAnalyzer()
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
    policy: str | None = Query(None, description="Scan policy: preset name or path to YAML"),
    custom_rules: str | None = Query(None, description="Path to custom YARA rules directory"),
    use_llm: bool = Query(False, description="Enable LLM analyzer"),
    llm_provider: str = Query("anthropic", description="LLM provider"),
    use_behavioral: bool = Query(False, description="Enable behavioral analyzer"),
    use_virustotal: bool = Query(False, description="Enable VirusTotal scanner"),
    vt_api_key: str | None = Query(None, description="VirusTotal API key"),
    vt_upload_files: bool = Query(False, description="Upload unknown files to VirusTotal"),
    use_aidefense: bool = Query(False, description="Enable AI Defense analyzer"),
    aidefense_api_key: str | None = Query(None, description="AI Defense API key"),
    aidefense_api_url: str | None = Query(None, description="AI Defense API URL"),
    use_trigger: bool = Query(False, description="Enable trigger specificity analysis"),
    enable_meta: bool = Query(False, description="Enable meta-analysis for FP filtering"),
):
    """Scan an uploaded skill package (ZIP file)."""
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    temp_dir = Path(tempfile.mkdtemp(prefix="skill_scanner_"))

    try:
        zip_path = temp_dir / file.filename
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)

        import zipfile

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir / "extracted")

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
        )

        return await scan_skill(request)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/scan-batch")
async def scan_batch(request: BatchScanRequest, background_tasks: BackgroundTasks):
    """Scan multiple skills in a directory (batch scan)."""
    skills_dir = Path(request.skills_directory)

    if not skills_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skills directory not found: {skills_dir}")

    scan_id = str(uuid.uuid4())
    scan_results_cache[scan_id] = {"status": "processing", "started_at": datetime.now().isoformat(), "result": None}

    background_tasks.add_task(run_batch_scan, scan_id, request)

    return {
        "scan_id": scan_id,
        "status": "processing",
        "message": "Batch scan started. Use GET /scan-batch/{scan_id} to check status.",
    }


@router.get("/scan-batch/{scan_id}")
async def get_batch_scan_result(scan_id: str):
    """Get results of a batch scan."""
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    cached = scan_results_cache[scan_id]

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
        analyzers = _build_analyzers(
            policy,
            custom_rules=request.custom_rules,
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
        )

        scanner = SkillScanner(analyzers=analyzers, policy=policy)
        report = scanner.scan_directory(
            Path(request.skills_directory),
            recursive=request.recursive,
            check_overlap=request.check_overlap,
        )

        # Meta-analysis per skill
        if request.enable_meta and META_AVAILABLE:
            import asyncio

            try:
                meta_analyzer = MetaAnalyzer()
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

        scan_results_cache[scan_id] = {
            "status": "completed",
            "started_at": scan_results_cache[scan_id]["started_at"],
            "completed_at": datetime.now().isoformat(),
            "result": report.to_dict(),
        }

    except Exception as e:
        scan_results_cache[scan_id] = {
            "status": "error",
            "started_at": scan_results_cache[scan_id]["started_at"],
            "error": str(e),
        }


@router.get("/analyzers")
async def list_analyzers():
    """List available analyzers."""
    analyzers = [
        {
            "name": "static_analyzer",
            "description": "Pattern-based detection using YAML and YARA rules",
            "available": True,
            "rules_count": "58+",
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
