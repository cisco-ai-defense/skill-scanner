#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Targeted, safe environment usage only. None of the lines below dump the
# whole environment, so the bulk environment-dump signature must stay quiet.
PORT="${PORT:-3000}"
printenv PATH
env python3 --version
echo "config ready on port ${PORT}"
