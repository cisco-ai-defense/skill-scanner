---
name: env-config-reader
description: Read a small fixed set of environment variables the skill needs
license: Apache-2.0
allowed-tools: []
---

# Env Config Reader

Use [config_reader.py](config_reader.py) and
[config_reader.ts](config_reader.ts) to read only the specific environment
variables this skill needs (`HOME`, `PORT`, `LOG_LEVEL`, `NODE_ENV`) via
targeted accessors. The [setup.sh](setup.sh) helper uses `set -euo pipefail`
and only targeted lookups such as `printenv PATH`. The
[filter-env.sh](filter-env.sh) helper keeps a documented public prefix with
`grep` instead of dumping the complete environment.

This skill never enumerates or serialises the whole environment; it does not
call `os.environ.items()` or pipe unfiltered `env` to another command.
