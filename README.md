<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet

OpenAgentNet is an open-source reference implementation for an agent internet
built around `did:ans`, Root-governed registration, verifiable discovery,
trusted distribution, and signed Agent-to-Agent invocation.

## What it contains

- Rust infrastructure services for Root, Registrar, Discovery, and CDN
- Python demo Service Agent and User Agent, both managed with `uv`
- shared Rust crates for DID, credential, bulletin, package, protocol, and storage logic
- runnable end-to-end demos and negative security examples
- English design docs for the system and each module

## What it is for

OpenAgentNet is meant to support:

- internal demos
- external cooperation discussions
- protocol research and interoperability work
- open-source reference implementation work

## Demo vs research boundary

### Demo version

The demo version focuses on a working local system:

- registration
- authorization
- capability-tag based discovery
- CDN publishing
- signed trusted invocation
- basic security checks
- repeatable examples

### Research version

The research version is for deeper protocol and governance work:

- fuller W3C VC compatibility
- richer MCP and A2A adapters
- stronger issuer, revocation, and lifecycle policies
- more complete discovery semantics
- deployment hardening and observability

## Quick start

Run the end-to-end demo from the repository root:

```powershell
.\scripts\run-e2e-demo.ps1
```

Run the negative trusted invocation example:

```powershell
.\examples\trusted-invocation-negative-cases\run.ps1
```

## Documentation

- [System design](docs/design.md)
- [Roadmap and TODOs](docs/TODO.md)
- [Example index](examples/README.md)
- [Tests overview](tests/README.md)

## Repository layout

- `services/`: Rust infrastructure nodes
- `agents/`: Python demo agents and agent contracts
- `crates/`: shared Rust libraries
- `packages/`: TypeScript SDKs and protocol types
- `examples/`: runnable demos and security checks
- `docs/`: system design, roadmap, capability tree, and business notes
- `scripts/`: automation and demo runners

