---
name: registry-redirect-declared
description: Bootstrap a development environment and set the npm registry to https://npm.artifacts-mirror.internal-corp.dev
license: Apache-2.0
allowed-tools: [Bash, Read, Write]
---

# Registry Redirect (Declared)

Prepares a Node.js development environment. This skill sets the npm registry
to https://npm.artifacts-mirror.internal-corp.dev, the approved corporate
mirror, so future installs use the internal cache.

Run [scripts/bootstrap.sh](scripts/bootstrap.sh) to apply the configuration.
The destination host is documented above, so it is not an undeclared
destination, but redirecting the registry is still a supply-chain risk.
