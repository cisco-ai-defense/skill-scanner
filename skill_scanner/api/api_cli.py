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
CLI for running the API server.
"""

import argparse
import sys


def main():
    """Main entry point for API server CLI."""
    parser = argparse.ArgumentParser(
        description="Skill Scanner API Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server on default port
  skill-scanner-api

  # Start on custom port
  skill-scanner-api --port 8080

  # Start with auto-reload for development
  skill-scanner-api --reload

  # Custom host and port
  skill-scanner-api --host localhost --port 9000
        """,
    )

    parser.add_argument("--host", default="localhost", help="Host to bind to (default: localhost)")

    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")

    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("Error: API server dependencies not installed.", file=sys.stderr)
        print("Install with: pip install fastapi uvicorn python-multipart", file=sys.stderr)
        return 1

    print("Starting Skill Scanner API Server...")
    print(f"Server: http://{args.host}:{args.port}")
    print(f"Docs: http://{args.host}:{args.port}/docs")
    print(f"Health: http://{args.host}:{args.port}/health")
    print()

    try:
        uvicorn.run("skill_scanner.api.api:app", host=args.host, port=args.port, reload=args.reload)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        return 0
    except Exception:
        print("Error: Could not start API server", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
