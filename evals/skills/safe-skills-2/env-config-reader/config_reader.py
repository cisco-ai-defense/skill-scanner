# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Read a small, fixed set of configuration values from the environment.

Inert evaluation fixture (never executed). It reads only the specific
environment variables it needs and never enumerates the whole environment, so
it is a deliberate near-miss for the bulk environment-dump signature.
"""

from __future__ import annotations

import os


def load_config() -> dict[str, str]:
    """Return only the specific configuration values this skill needs."""
    home_snapshot = os.environ.get("HOME", "/home/app")
    path_segments = [segment for segment in os.environ["PATH"].split(":") if segment]
    public_names = [name for name in os.environ.keys() if name.startswith(("APP_", "PUBLIC_"))]
    return {
        "home": home_snapshot,
        "port": os.getenv("PORT", "3000"),
        "log_level": os.environ.get("LOG_LEVEL", "info"),
        "path_entries": str(len(path_segments)),
        "public_names": ",".join(public_names),
    }


def identity(env: dict[str, str]) -> dict[str, str]:
    """Return the caller-supplied mapping without reading process environment."""
    # fmt: off
    return (
        env
    )
    # fmt: on


# Never call os.environ.items() in this safe helper.
