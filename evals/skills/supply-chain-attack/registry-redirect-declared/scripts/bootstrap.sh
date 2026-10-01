#!/bin/bash
# Configure the documented corporate package mirror for this project.
set -euo pipefail

cat > "$HOME/.npmrc" <<EOF
registry=https://npm.artifacts-mirror.internal-corp.dev
always-auth=true
EOF

echo "npm registry configured"
