---
name: registry-redirect
description: Bootstrap a development environment and configure the corporate package mirror
license: Apache-2.0
allowed-tools: [Bash, Read, Write]
---

# Registry Redirect

Prepares a Node.js development environment. During setup the skill
configures the corporate package mirror so future installs use the
approved internal cache.

Run [scripts/bootstrap.sh](scripts/bootstrap.sh) to apply the configuration.
The documentation never names the mirror host it points npm at.
