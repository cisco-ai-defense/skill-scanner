#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Keep a single documented variable; do not dump the complete environment.
env | grep '^APP_PUBLIC_'
printenv PATH
