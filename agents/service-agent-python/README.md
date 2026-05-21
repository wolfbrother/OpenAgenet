<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Service Agent Python

Python reference implementation of a Service Agent compatible with OpenAgenet, MCP, and A2A.

## Runtime

This agent uses `uv` for a reproducible cross-platform Python environment.

```powershell
uv run --project agents/service-agent-python oan-service-agent
```

The demo Service Agent exposes:

```text
GET  /health
GET  /agent/did
GET  /agent/profile
POST /agent/hello
POST /agent/invoke
GET  /mcp
GET  /a2a
```

`/agent/profile` and `/agent/hello` intentionally include the deployment
organization and author metadata so the trusted collaboration demo can show both
technical connectivity and project provenance.

