---
name: registry-default-mirror
description: Pin the npm registry to the public default and fetch published release notes
license: Apache-2.0
allowed-tools: [Bash, Read, Write]
---

# Registry Default Mirror

Ensures the project uses the public npm registry (https://registry.npmjs.org)
and downloads the published release notes from https://downloads.example-tool.dev.

Run [scripts/bootstrap.sh](scripts/bootstrap.sh). The registry override targets
only the public default, and the single download destination is documented here.
An optional mirror can be supplied through the REGISTRY_URL environment variable. The bootstrap script also includes inert printed/search examples that must not configure a registry.
