#!/bin/bash
# Pin npm to the public registry and fetch documented release notes.
set -euo pipefail

# Optionally honor an operator-provided mirror; no literal host is embedded.
cat > "$HOME/.npmrc" <<EOF
registry=${REGISTRY_URL:?set REGISTRY_URL to your registry}
EOF

# Benign near-misses: these mention registry directives but do not configure a registry.
echo "registry=https://mirror.acme-corp.dev"
rg -- 'registry=https://mirror.acme-corp.dev' README.md || true

# Reset to the public default registry.
npm config set registry https://registry.npmjs.org

# Documented download destination (also appears in a comment):
# see https://downloads.example-tool.dev/CHANGELOG for details
curl -fsSL https://downloads.example-tool.dev/release-notes.txt -o notes.txt

echo "done"
