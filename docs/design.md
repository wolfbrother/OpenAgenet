<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet System Design

OpenAgentNet is an open-source reference implementation for an Agent Internet built around `did:ans`, infrastructure authorization, complete DID Document registration, trusted distribution, verifiable discovery, and signed Agent-to-Agent invocation.

This document is the system-level design. It defines the architecture, role boundaries, trust model, cross-role flows, and global constraints. Detailed module behavior, configuration, API lists, storage layout, and tests are maintained in each module's own design document.

## 1. Document Scope

The design documents are split by responsibility:

- `docs/design.md`: system architecture, role model, trust boundaries, global flows, and roadmap-level constraints
- `services/root-node/docs/design.md`: Root Node implementation details
- `services/registrar-node/docs/design.md`: Registrar Node implementation details
- `services/discovery-node/docs/design.md`: Discovery Node implementation details
- `services/cdn-node/docs/design.md`: CDN Service implementation details
- `agents/service-agent-python/docs/design.md`: demo Service Agent implementation details
- `agents/user-agent-python/docs/design.md`: demo User Agent implementation details

System-level decisions should be recorded here. Endpoint lists, code-level storage paths, detailed validation steps, and module-local tests should live in the module documents.

## 2. Roles

OpenAgentNet currently models six roles:

- Root Node
- Registrar Node
- Discovery Node
- CDN Service
- Service Agent
- User Agent

Root Node, Registrar Node, and Discovery Node are infrastructure nodes. They reuse `did:ans` DID Documents to publish identity, keys, and endpoints, but they are not business Agents. Their DID Documents should use `ansMetadata.subjectType = "infrastructure-node"`.

Service Agent and User Agent are business Agent subjects. They may be implemented in any language as long as they satisfy the OpenAgentNet Agent access contract. The current demo Agents are written in Python and managed with `uv`.

CDN Service is a traditional content distribution service. It is not an authorized `did:ans` infrastructure node and is not trusted as a protocol authority.

## 3. Role Responsibilities

### 3.1 Root Node

Root Node is the governance center of the system. It is simultaneously:

- trust management hub
- data distribution hub
- semantic governance hub

Root authorizes infrastructure participants, maintains signed bulletin events, verifies complete Agent DID Documents, verifies registration credentials, archives DID Document versions, creates Root-verified packages, manages capability tree governance, and coordinates CDN publishing plus Discovery notification.

Root does not provide Agent business capabilities, route Agent calls, rank Agents, or maintain Agent reputation, evaluation, or invocation history.

### 3.2 Registrar Node

Registrar Node is the onboarding and registration gateway for Service Agents. It helps Agent operators create complete DID Documents, select capability tags, preserve custom tags, issue registration credentials, and submit complete DID Documents to Root.

Registrar recommendations are advisory. Root remains the final verifier.

### 3.3 Discovery Node

Discovery Node indexes Root-verified Agent packages and serves User Agents, applications, and orchestration systems. It syncs verified package data from CDN, verifies Root proofs and bulletin facts, filters by Root-authorized domains, builds a local index, and returns signed discovery responses.

Discovery may maintain local ranking, reputation, evaluation, or history signals. These are local Discovery signals and do not override Root trust state.

### 3.4 CDN Service

CDN stores and serves Root-verified DID Documents, metadata, verified packages, and manifests. CDN is only a distribution layer. Relying parties must verify Root proof, hashes, and bulletin state.

Root and CDN may be operated by the same entity, or CDN may be outsourced to a commercial provider. CDN is not authorized by Root; Root only publishes CDN service information on the bulletin so other roles can find it.

### 3.5 Service Agent

Service Agent is a business Agent that exposes callable capabilities. The demo Service Agent supports OpenAgentNet trusted invocation and exposes MCP/A2A-compatible endpoint placeholders.

For OpenAgentNet adaptation, a Service Agent should hold local DID material and credentials, verify peer DID/VC material before trusted calls, prevent replay, and sign responses.

### 3.6 User Agent

User Agent is a business Agent client. The demo User Agent queries Discovery, selects a Service Agent, builds a signed invocation envelope, presents its DID Document and local VC, calls the Service Agent, and verifies the signed response.

## 4. Implementation Stack

Infrastructure services are implemented in Rust:

- `services/root-node`
- `services/registrar-node`
- `services/discovery-node`
- `services/cdn-node`

Shared Rust crates include:

- `crates/oan-core`
- `crates/oan-did-ans`
- `crates/oan-crypto`
- `crates/oan-credentials`
- `crates/oan-bulletin`
- `crates/oan-package`
- `crates/oan-storage`
- `crates/oan-protocol`
- `crates/oan-client`

Demo Agents are implemented in Python:

- `agents/service-agent-python`
- `agents/user-agent-python`

The Python Agents use `uv` for cross-platform environment management. TypeScript remains a natural fit for web consoles, SDKs, and developer tooling.

## 5. Trust Flow

The current trusted registration, distribution, discovery, and invocation flow is:

1. Root authorizes Registrar and Discovery through bulletin events.
2. Service Agent or its operator creates a registration draft through Registrar.
3. Registrar assists capability tag selection using the Root-governed capability tree.
4. Service Agent confirms a complete DID Document, including custom tags if needed.
5. Registrar issues a signed `AgentRegistrationCredential`.
6. Registrar submits the complete DID Document, Registrar DID material, metadata, and registration credential to Root.
7. Root verifies Registrar authorization, DID syntax, DID Document structure, capability tags, nonce, optional request signature, and registration credential proof.
8. Root archives a full versioned copy and appends a signed bulletin event.
9. Root queues the verified package for CDN publishing.
10. Root publishes the verified package to CDN through batch execution.
11. After CDN publish succeeds, Root creates domain-filtered Discovery notification batches.
12. Discovery reads CDN service information from the bulletin, syncs packages from CDN, verifies Root proof and bulletin facts, filters by authorized domains, and indexes eligible Service Agents.
13. User Agent queries Discovery and receives a signed discovery response.
14. User Agent builds a signed trusted invocation envelope containing DID Document, local VC, nonce, timestamp, body hash, and request proof.
15. Service Agent verifies the User Agent DID Document, VC, nonce, target DID, and request signature before serving `/agent/hello`.
16. Service Agent returns a signed `OpenAgentNetTrustedInvocationResponse`.
17. User Agent verifies the Service Agent response signature.

This flow is verified by the local E2E demo script:

```text
scripts/run-e2e-demo.ps1
```

## 6. Agent Access Contract

OpenAgentNet does not prescribe Agent implementation language. It prescribes an access contract.

A minimally adapted Agent should support:

- local DID Document
- local keypair
- local credential storage by dimension, issuer, subject, and credential ID
- signed request or response envelopes
- peer DID Document validation
- peer VC validation
- nonce and timestamp checks
- protocol endpoint metadata in the DID Document
- compatibility with MCP and/or A2A when those protocols are exposed

The current Python demo implements this contract for the trusted hello flow. Full MCP/A2A protocol integration remains future work.

## 7. Capability Tree

Root governs the shared capability tree:

```text
docs/capability-tree-v1.json
```

The current v1 tree is derived from the GB/T 4754-2017 industry tree and is used as a practical initial semantic reference.

The capability tree is not a closed vocabulary. Tree-compatible tags support network-wide coarse discovery and Discovery authorization-domain routing. Custom tags are allowed and can support fine filtering after coarse eligibility is established.

## 8. Credentials and VC Compatibility

The current implementation uses VC-like JSON credentials. They align with core W3C VC concepts such as issuer, subject, status, claims, and proof, but full W3C VC proof-suite compatibility is not yet claimed.

Credential storage is local for:

- Registrar Node
- Discovery Node
- Service Agent
- User Agent

The MVP does not use VC hosting or credential custody services.

An Agent or infrastructure node may hold multiple credentials from multiple issuers across multiple dimensions.

Third-party VC issuers are not implemented as business services in the current MVP, but they must be Root-authorized before their credentials are recognized by the ecosystem. Their authorization status must appear on the bulletin.

## 9. Bulletin and Governance

The bulletin is an append-only signed governance log. It carries:

- Root initialization
- CDN service information
- Registrar authorization and revocation
- Discovery authorization, domain updates, and revocation
- third-party VC issuer authorization and revocation
- Agent DID Document anchor/update/revocation
- capability tree update events

All roles may sync bulletin state as needed. Authorization changes are governance facts and must be published to the bulletin.

CDN service information on the bulletin is service discovery data, not CDN trust.

## 10. Storage Model

The reference implementation uses:

- JSON files for audit-friendly artifacts
- SQLite for operational indexes, queues, and runtime lookup

JSON artifacts include DID Documents, keypair files, local credentials, Root bulletin, archived versions, CDN manifest files, and verified packages.

SQLite currently supports Root queues and indexes, Registrar drafts and records, and Discovery package indexes and sync history. Future work should move from namespace JSON records to role-specific relational schemas.

## 11. Batch and Distribution Model

Root-to-CDN publishing and Root-to-Discovery notification are not real-time requirements.

The current MVP uses explicit batch APIs. The intended ordering is:

1. Root publishes verified packages to CDN.
2. CDN stores package data and updates its manifest.
3. Root notifies relevant Discovery Nodes.
4. Discovery syncs from CDN and verifies package data.

Discovery notifications are domain-filtered by authorized capability domains. Root should not broadcast every Agent update to every Discovery Node unless the target Discovery Node is authorized for all domains.

## 12. Semantic Discovery Model

The current Discovery implementation supports tag, service type, protocol, and simple score-based matching.

Future semantic discovery may include:

1. mapping user tasks or natural-language queries to capability tags
2. retrieving candidates from verified local indexes
3. filtering by protocol, service type, authorization status, and trust validity
4. applying Discovery-local ranking signals
5. returning a signed response

Detailed vector retrieval, LLM query rewriting, ontology reasoning, and reputation systems are out of scope for the current MVP.

## 13. Configuration-Based Connectivity

The local network should be usable from configuration plus bulletin state.

Minimum configuration includes:

- Root endpoint for Registrar and Discovery
- local DID Document paths
- local keypair paths
- local data directories
- optional CDN fallback endpoint

Runtime discovery includes:

- Discovery finds CDN from Root bulletin
- CDN movement can be announced by bulletin event
- whether a peer accepts a request depends on authorization and verification rules, not merely connectivity

## 14. Security Boundaries

Important boundaries:

- CDN is not trusted
- Root proof does not prove Agent service quality
- Root does not rank Agents
- Discovery-local reputation does not override Root revocation
- Agents are language-agnostic and loosely coupled
- complete DID Document submission is required for create and update
- Root archive is not the public serving source
- credentials are local in the MVP
- demo keys are development fixtures only

## 15. Current Status

The current codebase includes:

- runnable Rust Root, Registrar, Discovery, and CDN services
- Python Service Agent and User Agent managed by `uv`
- `did:ans` DID Documents and development key fixtures
- Registrar-issued Agent registration credentials
- User Agent local registration credential
- Root verification of registration credential proof
- Root authorization APIs and persistent authorization state
- Root request nonce and optional request signature checks
- Root DID Document archive and verified package generation
- Root SQLite-backed CDN and Discovery queues
- Root domain-filtered batch notification
- CDN package publishing and manifest serving
- Discovery Root proof, metadata hash, bulletin hash-chain, and bulletin event verification
- Discovery authorized-domain filtering
- Discovery signed responses
- expanded management APIs for infrastructure services
- signed Agent-to-Agent trusted hello demo
- E2E verification of User Agent VC, User Agent request signature, Service Agent signed response, and provenance metadata

## 16. Demo and Research Boundary

The repository should be read as a two-layer reference:

- the demo layer proves the trust flow, registration flow, discovery flow, and signed invocation flow end to end
- the research layer expands protocol compatibility, governance policy, lifecycle checks, deployment hardening, and observability

The demo layer is intended for:

- internal demonstrations
- external cooperation discussions
- protocol validation

The research layer is intended for:

- deeper MCP and A2A alignment
- fuller W3C VC compatibility
- stronger issuer and revocation controls
- richer discovery semantics
- multi-node deployment and operational readiness

## 17. Remaining Gaps

Important gaps are tracked in:

```text
docs/TODO.md
```

The highest-priority areas are:

- formal Agent Adapter protocol specification
- negative E2E tests for trusted invocation failures
- full W3C VC compatibility profile
- VC expiration and revocation/status-list checks
- peer DID Document validation against Root-anchored package data
- real MCP and A2A protocol adapters
- Docker Compose and cross-platform E2E scripts
- role-specific relational SQLite schemas
- scheduled batch execution and retry policy
- structured logging, metrics, tracing, backup, and runbooks
