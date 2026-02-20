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
REST API server for Skill Scanner.

Provides HTTP endpoints for skill scanning, similar to MCP Scanner's API server.
"""

import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
    from pydantic import BaseModel, Field
except ImportError:
    raise ImportError("API server requires FastAPI. Install with: pip install fastapi uvicorn python-multipart")

from ..core.analyzers.static import StaticAnalyzer
from ..core.models import Report  # noqa: F401 - used in type hints
from ..core.scanner import SkillScanner

# Try to import LLM analyzer
try:
    from ..core.analyzers.llm_analyzer import LLMAnalyzer

    LLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LLM_AVAILABLE = False
    LLMAnalyzer = None

# Try to import Behavioral analyzer
try:
    from ..core.analyzers.behavioral_analyzer import BehavioralAnalyzer

    BEHAVIORAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    BEHAVIORAL_AVAILABLE = False
    BehavioralAnalyzer = None

# Try to import AI Defense analyzer
try:
    from ..core.analyzers.aidefense_analyzer import AIDefenseAnalyzer

    AIDEFENSE_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AIDEFENSE_AVAILABLE = False
    AIDefenseAnalyzer = None

# Try to import Meta analyzer
try:
    from ..core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None


# Pydantic models for API
class ScanRequest(BaseModel):
    """Request model for scanning a skill."""

    skill_directory: str = Field(..., description="Path to skill directory")
    use_llm: bool = Field(False, description="Enable LLM analyzer")
    llm_provider: str | None = Field("anthropic", description="LLM provider (anthropic or openai)")
    use_behavioral: bool = Field(False, description="Enable behavioral analyzer (dataflow analysis)")
    use_aidefense: bool = Field(False, description="Enable Cisco AI Defense analyzer")
    aidefense_api_key: str | None = Field(None, description="AI Defense API key (or use AI_DEFENSE_API_KEY env var)")
    enable_meta: bool = Field(
        False, description="Enable meta-analysis to filter false positives and prioritize findings"
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


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    analyzers_available: list[str]


class BatchScanRequest(BaseModel):
    """Request for batch scanning."""

    skills_directory: str
    recursive: bool = False
    use_llm: bool = False
    llm_provider: str | None = "anthropic"
    use_behavioral: bool = False
    use_aidefense: bool = False
    aidefense_api_key: str | None = None
    enable_meta: bool = Field(False, description="Enable meta-analysis to filter false positives")


# Create FastAPI app
app = FastAPI(
    title="Skill Scanner API",
    description="Security scanning API for agent skills packages",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# In-memory storage for async scans (in production, use Redis or database)
scan_results_cache = {}


@app.get("/", response_model=dict)
async def root():
    """Root endpoint."""
    return {"service": "Skill Scanner API", "version": "0.2.0", "docs": "/docs", "health": "/health"}


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    analyzers = ["static_analyzer"]
    if BEHAVIORAL_AVAILABLE:
        analyzers.append("behavioral_analyzer")
    if LLM_AVAILABLE:
        analyzers.append("llm_analyzer")
    if AIDEFENSE_AVAILABLE:
        analyzers.append("aidefense_analyzer")
    if META_AVAILABLE:
        analyzers.append("meta_analyzer")

    return HealthResponse(status="healthy", version="0.2.0", analyzers_available=analyzers)


@app.post("/scan", response_model=ScanResponse)
async def scan_skill(request: ScanRequest):
    """
    Scan a single skill package.

    Args:
        request: Scan request with skill directory and options

    Returns:
        Scan results with findings
    """
    import asyncio
    import concurrent.futures
    import os

    skill_dir = Path(request.skill_directory)

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill directory not found: {skill_dir}")

    if not (skill_dir / "SKILL.md").exists():
        raise HTTPException(status_code=400, detail="SKILL.md not found in directory")

    def run_scan():
        """Run the scan in a separate thread to avoid event loop conflicts."""
        from ..core.analyzers.base import BaseAnalyzer

        # Create scanner with configured analyzers
        analyzers: list[BaseAnalyzer] = [StaticAnalyzer()]

        if request.use_behavioral and BEHAVIORAL_AVAILABLE:
            behavioral_analyzer = BehavioralAnalyzer(use_static_analysis=True)
            analyzers.append(behavioral_analyzer)

        if request.use_llm and LLM_AVAILABLE:
            # Check for model override from environment
            llm_model = os.getenv("SKILL_SCANNER_LLM_MODEL")
            provider_str = request.llm_provider or "anthropic"
            if llm_model:
                # Use explicit model from environment
                llm_analyzer = LLMAnalyzer(model=llm_model)
            else:
                # Use provider default model
                llm_analyzer = LLMAnalyzer(provider=provider_str)
            analyzers.append(llm_analyzer)

        if request.use_aidefense and AIDEFENSE_AVAILABLE:
            api_key = request.aidefense_api_key or os.getenv("AI_DEFENSE_API_KEY")
            if not api_key:
                raise ValueError("AI Defense API key required (set AI_DEFENSE_API_KEY or pass aidefense_api_key)")
            aidefense_analyzer = AIDefenseAnalyzer(api_key=api_key)
            analyzers.append(aidefense_analyzer)

        scanner = SkillScanner(analyzers=analyzers)
        return scanner.scan_skill(skill_dir)

    try:
        # Run the scan in a thread pool to avoid nested event loop issues
        # (LLMAnalyzer.analyze() uses asyncio.run() which can't be called from a running loop)
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(executor, run_scan)

        # Run meta-analysis if enabled
        if request.enable_meta and META_AVAILABLE and len(result.findings) > 0:
            try:
                # Initialize meta-analyzer
                meta_analyzer = MetaAnalyzer()

                # Load skill for context
                from ..core.loader import SkillLoader

                loader = SkillLoader()
                skill = loader.load_skill(skill_dir)

                # Run meta-analysis
                import asyncio as async_lib

                meta_result = await loop.run_in_executor(
                    executor,
                    lambda: async_lib.run(
                        meta_analyzer.analyze_with_findings(
                            skill=skill,
                            findings=result.findings,
                            analyzers_used=result.analyzers_used,
                        )
                    ),
                )

                # Apply meta-analysis results
                filtered_findings = apply_meta_analysis_to_results(
                    original_findings=result.findings,
                    meta_result=meta_result,
                    skill=skill,
                )
                result.findings = filtered_findings
                result.analyzers_used.append("meta_analyzer")

            except Exception as meta_error:
                # Log but don't fail if meta-analysis errors
                print(f"Warning: Meta-analysis failed: {meta_error}")

        # Generate scan ID
        scan_id = str(uuid.uuid4())

        # Convert to response model
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


@app.post("/scan-upload")
async def scan_uploaded_skill(
    file: UploadFile = File(..., description="ZIP file containing skill package"),
    use_llm: bool = Query(False, description="Enable LLM analyzer"),
    llm_provider: str = Query("anthropic", description="LLM provider"),
    use_behavioral: bool = Query(False, description="Enable behavioral analyzer"),
    use_aidefense: bool = Query(False, description="Enable AI Defense analyzer"),
    aidefense_api_key: str | None = Query(None, description="AI Defense API key"),
):
    """
    Scan an uploaded skill package (ZIP file).

    Args:
        file: ZIP file containing skill package
        use_llm: Enable LLM analyzer
        llm_provider: LLM provider to use
        use_behavioral: Enable behavioral analyzer
        use_aidefense: Enable AI Defense analyzer
        aidefense_api_key: AI Defense API key

    Returns:
        Scan results
    """
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_scanner_"))

    try:
        # Save uploaded file
        zip_path = temp_dir / file.filename
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # Extract ZIP
        import zipfile

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir / "extracted")

        # Find skill directory (look for SKILL.md)
        extracted_dir = temp_dir / "extracted"
        skill_dirs = list(extracted_dir.rglob("SKILL.md"))

        if not skill_dirs:
            raise HTTPException(status_code=400, detail="No SKILL.md found in uploaded archive")

        skill_dir = skill_dirs[0].parent

        # Scan using the scan endpoint logic
        request = ScanRequest(
            skill_directory=str(skill_dir),
            use_llm=use_llm,
            llm_provider=llm_provider,
            use_behavioral=use_behavioral,
            use_aidefense=use_aidefense,
            aidefense_api_key=aidefense_api_key,
        )

        result = await scan_skill(request)

        return result

    finally:
        # Cleanup temporary files
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/scan-batch")
async def scan_batch(request: BatchScanRequest, background_tasks: BackgroundTasks):
    """
    Scan multiple skills in a directory (batch scan).

    Returns a scan ID. Use /scan-batch/{scan_id} to get results.

    Args:
        request: Batch scan request
        background_tasks: FastAPI background tasks

    Returns:
        Scan ID for tracking
    """
    skills_dir = Path(request.skills_directory)

    if not skills_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skills directory not found: {skills_dir}")

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Initialize result in cache
    scan_results_cache[scan_id] = {"status": "processing", "started_at": datetime.now().isoformat(), "result": None}

    # Start background scan
    background_tasks.add_task(
        run_batch_scan,
        scan_id,
        skills_dir,
        request.recursive,
        request.use_llm,
        request.llm_provider,
        request.use_behavioral,
        request.use_aidefense,
        request.aidefense_api_key,
        request.enable_meta,
    )

    return {
        "scan_id": scan_id,
        "status": "processing",
        "message": "Batch scan started. Use GET /scan-batch/{scan_id} to check status.",
    }


@app.get("/scan-batch/{scan_id}")
async def get_batch_scan_result(scan_id: str):
    """
    Get results of a batch scan.

    Args:
        scan_id: Scan ID from /scan-batch

    Returns:
        Scan results or status
    """
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


def run_batch_scan(
    scan_id: str,
    skills_dir: Path,
    recursive: bool,
    use_llm: bool,
    llm_provider: str | None,
    use_behavioral: bool = False,
    use_aidefense: bool = False,
    aidefense_api_key: str | None = None,
    enable_meta: bool = False,
):
    """
    Background task to run batch scan.

    Args:
        scan_id: Scan ID
        skills_dir: Directory containing skills
        recursive: Search recursively
        use_llm: Use LLM analyzer
        llm_provider: LLM provider
        use_behavioral: Use behavioral analyzer
        use_aidefense: Use AI Defense analyzer
        aidefense_api_key: AI Defense API key
        enable_meta: Enable meta-analysis
    """
    try:
        import os

        from ..core.analyzers.base import BaseAnalyzer

        # Create scanner
        analyzers: list[BaseAnalyzer] = [StaticAnalyzer()]

        if use_behavioral and BEHAVIORAL_AVAILABLE:
            try:
                behavioral_analyzer = BehavioralAnalyzer(use_static_analysis=True)
                analyzers.append(behavioral_analyzer)
            except Exception:
                pass  # Continue without behavioral analyzer

        if use_llm and LLM_AVAILABLE:
            try:
                # Check for model override from environment
                llm_model = os.getenv("SKILL_SCANNER_LLM_MODEL")
                provider_str = llm_provider or "anthropic"
                if llm_model:
                    # Use explicit model from environment
                    llm_analyzer = LLMAnalyzer(model=llm_model)
                else:
                    # Use provider default model
                    llm_analyzer = LLMAnalyzer(provider=provider_str)
                analyzers.append(llm_analyzer)
            except Exception:
                pass  # Continue without LLM analyzer

        if use_aidefense and AIDEFENSE_AVAILABLE:
            try:
                api_key = aidefense_api_key or os.getenv("AI_DEFENSE_API_KEY")
                if not api_key:
                    raise ValueError("AI Defense API key required (set AI_DEFENSE_API_KEY or pass aidefense_api_key)")
                aidefense_analyzer = AIDefenseAnalyzer(api_key=api_key)
                analyzers.append(aidefense_analyzer)
            except ValueError:
                raise  # Re-raise ValueError to fail the batch scan
            except Exception:
                pass  # Continue without AI Defense analyzer for other errors

        scanner = SkillScanner(analyzers=analyzers)

        # Scan directory
        report = scanner.scan_directory(skills_dir, recursive=recursive)

        # Run meta-analysis on each skill's results if enabled
        if enable_meta and META_AVAILABLE:
            import asyncio

            try:
                meta_analyzer = MetaAnalyzer()

                for result in report.scan_results:
                    if result.findings:
                        try:
                            # Load skill for context
                            skill_dir_path = Path(result.skill_directory)
                            skill = scanner.loader.load_skill(skill_dir_path)

                            # Run meta-analysis
                            meta_result = asyncio.run(
                                meta_analyzer.analyze_with_findings(
                                    skill=skill,
                                    findings=result.findings,
                                    analyzers_used=result.analyzers_used,
                                )
                            )

                            # Apply meta-analysis results
                            filtered_findings = apply_meta_analysis_to_results(
                                original_findings=result.findings,
                                meta_result=meta_result,
                                skill=skill,
                            )
                            result.findings = filtered_findings
                            result.analyzers_used.append("meta_analyzer")

                        except Exception:
                            pass  # Continue without meta-analysis for this skill

            except Exception:
                pass  # Continue without meta-analysis

        # Update cache
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


@app.get("/analyzers")
async def list_analyzers():
    """List available analyzers."""
    analyzers = [
        {
            "name": "static_analyzer",
            "description": "Pattern-based detection using YAML and YARA rules",
            "available": True,
            "rules_count": "40+",
        }
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

    if AIDEFENSE_AVAILABLE:
        analyzers.append(
            {
                "name": "aidefense_analyzer",
                "description": "Cisco AI Defense cloud-based threat detection",
                "available": True,
                "requires_api_key": True,
            }
        )

    if META_AVAILABLE:
        analyzers.append(
            {
                "name": "meta_analyzer",
                "description": "Second-pass LLM analysis for false positive filtering and finding prioritization",
                "available": True,
                "requires": "2+ analyzers, LLM API key",
                "features": [
                    "False positive filtering",
                    "Missed threat detection",
                    "Priority ranking",
                    "Correlation analysis",
                    "Remediation guidance",
                ],
            }
        )

    return {"analyzers": analyzers}


# Entry point for running the server
def run_server(host: str = "localhost", port: int = 8000, reload: bool = False):
    """
    Run the API server.

    Args:
        host: Host to bind to
        port: Port to bind to
        reload: Enable auto-reload for development
    """
    import uvicorn

    uvicorn.run("skill_scanner.api.api_server:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    run_server()
