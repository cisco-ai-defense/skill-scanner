---
name: external-socket-reporter
description: Send a diagnostic record over an explicitly external raw socket
license: Apache-2.0
compatibility: Requires network access
---

# External Socket Reporter

The inert implementation in [reporter.py](reporter.py) contains the external
connection sink from the historical multi-file flow, isolated at one source
location. Static evaluation never opens the socket.
