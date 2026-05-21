<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Service Agent Python Detailed Design

## 1. Role

The Python Service Agent is a demo business Agent. It represents an Agent that provides callable capabilities and adapts to OAN trust requirements while remaining compatible with MCP and A2A endpoint conventions.

Unlike Root, Registrar, Discovery, and CDN, this module is a real Agent subject. Its DID Document uses `ansMetadata.subjectType = "agent"`.

## 2. Runtime

The module is a `uv` project:

```text
agents/service-agent-python/pyproject.toml
agents/service-agent-python/uv.lock
```

Command:

```text
uv run --project agents/service-agent-python oan-service-agent
```

The current implementation uses Python standard HTTP server APIs plus `cryptography` for Ed25519 signing and verification.

## 3. Local Identity and Credentials

Representative local data:

```text
data/demo-service-agent/did-document.json
data/demo-service-agent/keys/keypair.json
data/demo-service-agent/credentials/agent-registration.json
data/demo-service-agent/credentials/by-dimension/
```

The Service Agent holds its own DID Document, keypair, and registration credential locally. Credentials are not hosted by a custody service.

## 4. APIs

Current endpoints:

```text
GET  /health
GET  /agent/did
GET  /agent/profile
POST /agent/hello
POST /agent/invoke
GET  /mcp
GET  /a2a
```

`/agent/hello` and `/agent/invoke` currently share the same trusted invocation verification path.

## 5. OAN adapter Behavior

Before serving `/agent/hello`, the Service Agent verifies:

- invocation type is `OANTrustedInvocation`
- caller DID is present
- target DID equals the Service Agent DID
- nonce is present and has not been replayed in process memory
- timestamp is present
- caller DID Document exists and `callerDidDocument.id == callerDid`
- request signature verifies against the caller DID Document
- caller presents a local credential of type `UserAgentRegistrationCredential` or `AgentRegistrationCredential`
- credential subject equals caller DID
- credential status is `active`
- credential proof verifies against the Registrar DID Document

After verification, the Service Agent returns a signed `OANTrustedInvocationResponse`.

## 6. Provenance Metadata

The demo response intentionally includes:

- deployer: China Academy of Information and Communications Technology (CAICT)
- author: JINLIANG XU
- email: `xujinliang@caict.ac.cn`, `jlxufly@gmail.com`

This proves that the invocation path can carry Agent identity, service identity, deployment metadata, and callable endpoint data through the trusted demo.

## 7. MCP and A2A Compatibility

The current endpoints `/mcp` and `/a2a` expose protocol placeholders and profile data. Full MCP/A2A protocol negotiation is future work.

Future adapters should:

- perform DID/VC verification before MCP or A2A task execution
- expose verified caller identity to tools or tasks
- sign important responses and callbacks
- map protocol capabilities to DID Document capability metadata

## 8. Tests and Demo

The Service Agent is exercised by:

```text
scripts/run-e2e-demo.ps1
```

The E2E demo validates:

- Service Agent startup through `uv`
- User Agent VC verification by Service Agent
- User Agent request signature verification by Service Agent
- Service Agent signed response verification by User Agent
- Service Agent provenance metadata

## 9. Next Work

- persist nonce records in SQLite
- enforce timestamp windows
- verify peer DID Documents against Root-anchored packages
- support VC expiration and revocation checks
- extract signing and verification logic into a reusable Python Agent Adapter package
- implement real MCP and A2A protocol adapters

