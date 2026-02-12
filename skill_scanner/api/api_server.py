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
Standalone REST API server for Skill Scanner.

This module re-exports the canonical ``app`` from :mod:`skill_scanner.api.api`
and provides a convenience ``run_server()`` entry-point so that ``api_server``
can be used interchangeably with the router-based ``api`` module.

All endpoints, Pydantic models, and business logic live in ``router.py``.
"""


def run_server(host: str = "localhost", port: int = 8000, reload: bool = False) -> None:
    """Run the API server.

    Args:
        host: Host to bind to.
        port: Port to bind to.
        reload: Enable auto-reload for development.
    """
    import uvicorn

    uvicorn.run("skill_scanner.api.api:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    run_server()
