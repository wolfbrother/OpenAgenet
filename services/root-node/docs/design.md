<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Root Node Design

## 1. Positioning

Root Node is the governance center of OpenAgentNet. It carries three core responsibilities:

- trust management hub
- data distribution hub
- semantic governance hub

Root Node is not a business Agent. It does not route Agent traffic, does not maintain reputation or rating systems, and does not provide recommendation logic. It reuses `did:ans` DID Document structure only to express infrastructure identity, keys, and endpoints. Its `ansMetadata.subjectType` must be `infrastructure-node`.

The current Rust MVP focuses on verifying complete Service Agent DID Documents submitted by Registrar Nodes, anchoring them into the bulletin, archiving versions, and producing the data needed by CDN and Discovery.

## 2. Configuration and Service Discovery

Config file: `services/root-node/config.example.toml`

Required inputs:

```text
[server]
host
port

[paths]
data_dir
keys_dir
bulletin_file
database_url
```

Path resolution follows the repository convention:

1. absolute paths are used directly
2. relative paths are resolved against the current working directory first
3. otherwise they are resolved against the config file directory

Root does not discover Registrar or Discovery through a config list. It publishes authorization facts through the bulletin and accepts protocol requests from those services.

## 3. HTTP APIs

Current APIs:

```text
GET  /health
GET  /root/did
GET  /bulletin
POST /root/registrars/authorize
POST /root/discovery-nodes/authorize
POST /root/discovery-nodes/{did}/domains
POST /root/nodes/{did}/revoke
POST /root/agents/verify-and-publish
POST /root/batches/publish-cdn
POST /root/batches/notify-discovery

GET  /api/v1/root/status
GET  /api/v1/root/registrars
GET  /api/v1/root/registrars/{did}
GET  /api/v1/root/discovery-nodes
GET  /api/v1/root/discovery-nodes/{did}
GET  /api/v1/root/agents
GET  /api/v1/root/agents/{did}
GET  /api/v1/root/agents/{did}/versions
GET  /api/v1/root/agents/{did}/versions/{version}
GET  /api/v1/root/queues/cdn-publish
GET  /api/v1/root/queues/discovery-notify
POST /api/v1/root/queues/cdn-publish/run
POST /api/v1/root/queues/discovery-notify/run
GET  /api/v1/root/capability-tree
POST /api/v1/root/capability-tree/validate-tags
GET  /api/v1/root/bulletin/events
GET  /api/v1/root/bulletin/events/{sequence}
```

The new `/api/v1` set is intended to support future web consoles directly, so frontend code can stay thin and data-constrained.

## 4. Verification Duties

Root should verify:

- `agentDid` is valid `did:ans`
- `didDocument.id == agentDid`
- DID Core context exists
- verification methods exist
- authentication methods exist
- assertion methods exist
- service endpoints exist
- `ansMetadata.subjectType == agent`
- capability tags are known in the configured capability tree
- registrar is authorized and not revoked
- `registrationCredential.issuer == registrarDid`
- `registrationCredential.subject == agentDid`
- `registrationCredential.status == active`
- `registrationCredential.proof` verifies against the registrar DID Document

Future work should add expiration, nonce, replay protection, request signatures, and full W3C VC proof-suite compatibility.

## 5. Streaming Pipeline

Root processes registration as a streaming pipeline. It should not keep large numbers of DID Documents in memory. Persistent state should live in:

- SQLite queues and indexes
- bulletin JSON
- versioned archive files
- verified package files

This matches the current implementation, which writes archive records and queue entries immediately after verification.

## 6. Bulletin

The bulletin is an append-only signed event log. It records:

- Root initialization
- CDN service information updates
- Registrar authorization and revocation
- Discovery authorization, domain updates, and revocation
- third-party VC issuer authorization and revocation
- Agent DID Document anchor/update/revocation
- capability tag tree updates

The bulletin also carries CDN service discovery information such as base URL, manifest URL, and package URL template. This is service discovery only, not CDN trust.

## 7. Capability Tree

Root maintains the semantic capability tree as external data:

```text
docs/capability-tree-v1.json
```

The tree is used by registration validation and Discovery domain authorization. Canonical tag IDs should be used in protocol storage and APIs.

## 8. Test Coverage

Current codebase status:

- `cargo check --workspace` passes
- `cargo test --workspace` passes
- Root has unit tests for request verification and queue behavior
- the newly added management APIs are implemented, but direct HTTP-level tests for all new endpoints still need to be added

## 9. Next Steps

- add direct tests for Root management APIs
- add stricter credential and replay checks
- migrate queues and indexes to role-specific SQLite schemas
- extend bulletin verification and root authorization status queries
