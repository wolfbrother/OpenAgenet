<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# User Agent Python

Python reference implementation of a User Agent compatible with OpenAgentNet, MCP, and A2A.

## Runtime

This agent uses `uv` for a reproducible cross-platform Python environment.

```powershell
uv run --project agents/user-agent-python openagentnet-user-agent
```

The demo User Agent queries Discovery for a Service Agent, fetches the selected
Service Agent profile, calls `/agent/hello`, and prints the Discovery proof plus
the Service Agent deployment and author metadata.
