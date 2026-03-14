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

"""API module for Skill Scanner.

This module provides a FastAPI application for scanning agent skills packages.

It also mounts a lightweight web GUI under ``/ui`` for drag-and-drop scanning
and interactive report viewing, built on top of the same HTTP API.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .. import __version__ as PACKAGE_VERSION
from .router import router as api_router

app = FastAPI(
    title="Skill Scanner API",
    description="Security scanning API for agent skills packages",
    version=PACKAGE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(api_router)

# Mount the bundled web UI (if present) at /ui.
_frontend_dir = Path(__file__).with_suffix("").parent / "frontend"
if _frontend_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(_frontend_dir), html=True), name="ui")

