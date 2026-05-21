<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Examples

Runnable examples for registration, discovery, MCP/A2A demos, trusted invocation,
and negative security checks.

## Recommended runs

```powershell
.\scripts\run-e2e-demo.ps1
.\examples\trusted-invocation-negative-cases\run.ps1
```

## Scenario map

- `full-trusted-invocation`: full local happy-path system flow
- `trusted-invocation-negative-cases`: trusted invocation security regression checks
- `multi-registrar-discovery`: isolated multi Registrar / multi Discovery integration example
- `register-service-agent`: service registration flow
- `discover-agent`: discovery flow
- `a2a-service-agent-demo`: A2A-oriented service demo
- `mcp-service-agent-demo`: MCP-oriented service demo

## Notes

The examples are kept executable and protocol-focused. They are intended to
show how the services and agents fit together, not to replace the module-level
APIs or detailed design docs.
