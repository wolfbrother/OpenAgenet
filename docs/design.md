<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet Design

OpenAgentNet is a local, open-source reference implementation for an Agent Internet built around `did:ans`, infrastructure authorization, full DID Document registration, trusted distribution, and verifiable discovery. It is a protocol and architecture workspace, not a business system.

## 1. Roles

OpenAgentNet models these roles:

- Root Node
- Registrar Node
- Discovery Node
- CDN Service
- Service Agent
- User Agent

The current repository focuses on infrastructure nodes and trusted metadata flow. Service Agent and User Agent remain loosely coupled and may be implemented in any language, as long as they follow the Agent access contract and can interoperate with MCP and A2A.

## 2. Core Positioning

Root Node is the governance center of the system. It has three responsibilities:

- Trust management hub
- Data distribution hub
- Semantic governance hub

Root Node is not a business Agent. It does not provide business capabilities, route Agent calls, or maintain Agent reputation, ratings, historical call records, or recommendation ranking. Discovery Nodes or marketplace services may keep those local ranking signals for their own experience layer, but they are not Root trust state.

Registrar Node receives complete Agent DID Documents from operators, stores intake records, and submits complete DID Documents to Root. Even updates are submitted as full DID Documents, not patches.

Discovery Node syncs Root-verified metadata from CDN, builds a local capability index, verifies Root proof and bulletin state, and returns signed discovery responses.

CDN Service is a traditional content distribution service. It is not an authorized OpenAgentNet node and is not trusted. Root may operate CDN itself or outsource it. Clients trust Root proof, DID Document hash, metadata hash, and bulletin state, not CDN.

## 3. Implementation Stack

The current reference implementation uses Rust for all four infrastructure services:

- `services/root-node`
- `services/registrar-node`
- `services/discovery-node`
- `services/cdn-node`

Shared crates include:

- `crates/oan-core`
- `crates/oan-did-ans`
- `crates/oan-crypto`
- `crates/oan-credentials`
- `crates/oan-bulletin`
- `crates/oan-package`
- `crates/oan-storage`
- `crates/oan-protocol`
- `crates/oan-client`

## 4. Agent Contract

OpenAgentNet does not prescribe Agent implementation language. Service Agent and User Agent are external participants. The repository currently treats Python as a convenient Agent option, while the infrastructure nodes are written in Rust. TypeScript remains a natural fit for web consoles, SDKs, and developer tooling.

Infrastructure nodes also use `did:ans` DID Documents, but Root, Registrar, and Discovery are not Agents. They reuse DID Document structure for infrastructure identity, keys, and endpoints. Their `ansMetadata.subjectType` should be `infrastructure-node`.

## 5. Trust Flow

1. Root authorizes Registrar and Discovery through bulletin events.
2. Registrar receives a full Service Agent DID Document and registration credential.
3. Registrar forwards the full DID Document, its own DID Document, metadata, and `registrationCredential` to Root.
4. Root verifies registrar authorization, DID syntax, DID Document structure, capability tags, and registration credential proof.
5. Root writes an Agent anchor or update event to the bulletin.
6. Root archives a full versioned copy of the DID Document and verified package.
7. Root queues the package for CDN publishing.
8. Root queues Discovery notification data according to batch policy and authorized domains.
9. CDN stores and serves the verified package.
10. Discovery reads CDN information from the Root bulletin, syncs packages, verifies Root proof and bulletin events, applies authorized-domain filtering, and indexes eligible Service Agents.
11. User Agent queries Discovery and verifies the signed response.
12. User Agent may invoke Service Agent using signed DID-based invocation.

## 6. Root Node

Root is the trust, data, and semantic governance hub. It:

- authorizes Registrar Nodes
- authorizes Discovery Nodes
- authorizes third-party VC issuers
- maintains signed bulletin events
- verifies complete Agent DID Documents
- verifies registration credential proof
- maintains multi-version DID Document archive
- produces Root-verified packages
- maintains capability tag tree governance
- queues CDN publishing and Discovery notification tasks

Root does not directly serve archived versions as the public distribution source. Public distribution is delegated to CDN. The archive is a governance and audit record.

### 6.1 DID Document Verification

Root should verify at least:

- `agentDid` syntax is valid `did:ans`
- `didDocument.id` equals `agentDid`
- DID Core context is present
- verification methods exist
- authentication methods exist
- assertion methods exist
- agent service endpoints exist
- `ansMetadata.subjectType` is `agent`
- capability tags are known in the configured capability tree
- registrar is authorized and not revoked
- `registrationCredential.issuer` equals `registrarDid`
- `registrationCredential.subject` equals `agentDid`
- `registrationCredential.status` is active
- `registrationCredential.proof` verifies against the registrar DID Document

Future checks should include expiration, nonce, replay protection, request signature, and full W3C VC proof-suite compatibility.

### 6.2 Registration Pipeline

Root processes submissions as a streaming concurrent pipeline. Each request carries a complete DID Document and required credential material. Root validates, hashes, classifies, archives, and enqueues inside the request scope. It should not keep all Agent DID Documents or discovery indexes resident in memory.

Persistent state should live in:

- SQLite indexes and queues
- append-only bulletin JSON
- versioned archive files
- verified package files

Only small governance data such as Root key, capability tree, and authorization cache should be held in memory.

### 6.3 Root APIs

Current Root APIs:

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

## 7. Bulletin

The bulletin is an append-only signed event log. It records:

- Root initialization
- CDN service information updates
- Registrar authorization and revocation
- Discovery authorization, domain updates, and revocation
- VC issuer authorization and revocation
- Agent DID Document anchor/update/revocation
- Capability tag tree updates

All roles may sync bulletin state as needed. Authorization state changes for Registrar Nodes, Discovery Nodes, and third-party VC issuers must be published to the bulletin.

The bulletin also carries CDN service discovery information, such as base URL, manifest URL, package URL template, and related metadata. This does not authorize CDN; it only tells other roles where the distribution service is.

## 8. CDN Service

CDN is a loosely coupled traditional distribution service. It may be operated by the Root operator or by an outsourced provider. It is not trusted and is not part of the authorized node set.

CDN responsibilities:

- receive verified packages from Root
- store DID Documents, metadata, and package objects
- maintain a manifest
- provide read APIs for Discovery and clients

Clients must verify:

- Root proof
- DID Document hash
- metadata hash
- bulletin event existence and status
- revocation status

Future access control may use Root-signed tokens or signed URLs. In that model, Root makes access decisions and CDN only enforces them.

### 8.1 CDN APIs

Current CDN APIs:

```text
GET  /health
GET  /cdn/manifest
GET  /cdn/updates
POST /cdn/packages
GET  /cdn/packages/{did}
GET  /cdn/documents/{did}
GET  /cdn/metadata/{did}

GET  /api/v1/cdn/status
GET  /api/v1/cdn/packages
GET  /api/v1/cdn/packages/{did}
GET  /api/v1/cdn/documents/{did}
GET  /api/v1/cdn/metadata/{did}
GET  /api/v1/cdn/manifest/stats
GET  /api/v1/cdn/publish/history
POST /api/v1/cdn/purge
```

## 9. Discovery Node

Discovery builds a queryable local index from Root-verified data. It is not responsible for Root authorization decisions and must not return unanchored or revoked Agents as trusted candidates.

Current Discovery behavior:

- reads `root_endpoint` from config
- fetches Root bulletin
- finds latest `CDN_SERVICE_INFO_UPDATED` event
- pulls CDN manifest and packages
- verifies DID Document hash
- verifies Root proof signature against Root DID Document public key
- verifies that the package bulletin event exists
- applies authorized-domain filtering
- indexes only `subjectType = agent` packages
- returns signed discovery responses

### 9.1 Discovery APIs

Current Discovery APIs:

```text
GET  /health
GET  /discovery/did
POST /discovery/sync
POST /discover/query
GET  /routes/{did}

GET  /api/v1/discovery/status
GET  /api/v1/discovery/root-authorization
GET  /api/v1/discovery/authorized-domains
POST /api/v1/discovery/sync
GET  /api/v1/discovery/sync/history
GET  /api/v1/discovery/index/stats
GET  /api/v1/discovery/index/agents
GET  /api/v1/discovery/index/agents/{did}
POST /api/v1/discovery/query
POST /api/v1/discovery/query/explain
GET  /api/v1/discovery/rejected-packages
GET  /api/v1/discovery/capability-tree
```

Future Discovery work:

- verify full bulletin hash chain
- verify every Root bulletin event signature
- validate `metadataHash`
- enforce Agent revocation and suspension status
- use capability-tree parent-child matching for `authorizedDomains`
- maintain optional local reputation, evaluation, and history signals

## 10. Capability Tree

Root maintains the capability tag tree as semantic governance data. The current v1 tree is externalized at:

```text
docs/capability-tree-v1.json
```

It is derived from `docs/GBT4754-2017_industry_tree.json` and serves as an initial capability tree. Runtime code can flatten the nested tree into tags with parent references. Agent registration and Discovery authorization should use canonical tag IDs.

## 11. Credentials and VC Compatibility

The current implementation uses VC-like JSON credentials. It aligns with W3C VC concepts such as issuer, subject, status, claims, and proof, but it does not claim full W3C VC proof-suite compatibility yet.

Credential local storage applies to:

- Registrar Node
- Discovery Node
- Agents

The design does not use VC hosting or credential custody services.

An Agent, Discovery Node, or Registrar Node may hold multiple credentials from multiple issuers across multiple dimensions. Local storage should therefore support dimension, issuer, subject, and credential ID paths.

Third-party VC issuers are not implemented as business logic in the current MVP, but they must be authorized by Root before being recognized by the ecosystem. Their authorization status must appear on the bulletin.

## 12. Storage

The implementation uses JSON files for audit-friendly artifacts and SQLite for operational indexes and queues.

JSON examples:

- DID Documents
- keypair files
- bulletin JSON
- archived versions
- verified packages
- local credentials

SQLite should hold:

- latest version indexes
- queues
- cursors
- authorization indexes
- package indexes
- discovery indexes

The MVP currently includes a namespace-based SQLite JSON helper.

## 13. Root Batch Strategy

Root-to-CDN publishing and Root-to-Discovery notification are not real-time requirements. Root should use configurable batch strategies.

Batch dimensions:

- maximum batch size
- maximum waiting time
- retry policy
- idempotency key
- target Discovery Node
- sequence range
- authorized domain filtering

Root should notify only relevant Discovery Nodes when Agent capability tags match the Discovery Node authorized-domain set. It should not broadcast every Agent update to every Discovery Node unless the Discovery Node is authorized for all domains.

## 14. Semantic Discovery

Discovery semantic search may follow this flow:

1. User task or query enters Discovery.
2. Discovery maps query semantics to capability tags.
3. Discovery retrieves candidate Agents from the verified local index.
4. Discovery filters by protocol, service type, status, and trust validity.
5. Discovery optionally applies local ranking signals.
6. Discovery returns a signed response.

The current MVP does not implement vector retrieval, LLM query rewriting, or detailed ontology reasoning. It only implements tags, service type, protocol, and simple ranking.

## 15. Configuration-Based Connectivity

The system should be able to establish a usable local network from configuration plus bulletin state.

Minimum configuration:

- Root endpoint for Registrar and Discovery
- local DID Document and keypair paths
- local data directories
- optional CDN fallback endpoint

Runtime discovery:

- Discovery finds CDN from Root bulletin
- CDN movement can be announced by a bulletin event
- whether a peer accepts a request depends on authorization and verification rules, not merely connectivity

## 16. Security Boundaries

Important boundaries:

- CDN is not trusted
- Root proof does not prove Agent service quality
- Root does not rank Agents
- Discovery-local reputation does not override Root revocation
- Agents are language-agnostic and loosely coupled
- full DID Document submission is required for create and update
- Root archive is not the public serving source
- credentials are local in the MVP

## 17. Current Status

The current codebase already includes:

- Root proof and bulletin-based verification
- Discovery verification of Root proof and bulletin event
- Discovery response signing
- Root authorization APIs
- SQLite helper support
- Root/Discovery batch queues
- capability tree externalization
- expanded management APIs for Root, Registrar, Discovery, and CDN

## 18. Remaining Gaps

Important remaining gaps:

- full W3C VC proof-suite compatibility
- request nonce and replay protection
- full bulletin hash-chain verification inside Discovery sync
- metadata hash verification in Discovery
- SQLite role-specific schemas
- real batch retry and partial failure handling
- end-to-end trusted invocation demo
- User Agent verification SDK
- Root-signed CDN access token or signed URL enforcement
- direct API tests for the newly added management endpoints
