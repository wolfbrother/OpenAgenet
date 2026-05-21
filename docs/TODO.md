<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet TODO

This document records the current engineering status and the next development work for the OpenAgentNet reference implementation.

## Current Status

The repository currently contains four runnable Rust infrastructure services:

- Root Node
- Registrar Node
- Discovery Node
- CDN Service

The current implementation already covers the main local trusted-flow skeleton:

- Root authorizes infrastructure nodes through bulletin events.
- Registrar accepts a full Agent DID Document and forwards it to Root.
- Root verifies DID Document structure, capability tags, registrar authorization, and `registrationCredential` proof.
- Root anchors verified Agent document events to the bulletin.
- Root archives versions and queues data for CDN publishing and Discovery notification.
- CDN stores verified packages and exposes manifest/package/document/metadata read APIs.
- Discovery reads CDN information from Root bulletin, syncs verified packages, validates Root proof plus bulletin event existence, filters by `authorizedDomains`, builds a local capability index, and returns signed discovery responses.
- The capability tag tree is externalized as `docs/capability-tree-v1.json`.
- Capability tags now follow an open model: tree-compatible tags support network-wide coarse discovery, while custom tags remain allowed for fine filtering.
- SQLite JSON storage helpers are used for Root, Registrar, and Discovery runtime indexes.
- The management APIs for Root, Registrar, Discovery, and CDN now exist and are covered by tests.
- Registrar can issue a signed Agent registration credential from a registration draft.
- A local PowerShell end-to-end demo script exists at `scripts/run-e2e-demo.ps1`.
- The Python Service Agent and User Agent are managed with `uv` projects and lock files.
- The end-to-end demo now performs signed Agent-to-Agent trusted invocation:
  - User Agent holds a local `UserAgentRegistrationCredential`.
  - User Agent sends its DID Document, local VC, nonce, timestamp, body hash, and request proof.
  - Service Agent verifies the User Agent DID Document, VC, nonce, target DID, and request signature before `/agent/hello`.
  - Service Agent returns a signed hello response.
  - User Agent verifies the Service Agent response signature.

## Recently Completed

The following upgrades have been implemented:

1. Root verifies `registrationCredential` proof.
2. Discovery verifies Root proof and bulletin event presence.
3. Discovery responses are signed by the Discovery Node private key.
4. Root authorization APIs exist:
   - `POST /root/registrars/authorize`
   - `POST /root/discovery-nodes/authorize`
   - `POST /root/discovery-nodes/{did}/domains`
   - `POST /root/nodes/{did}/revoke`
5. Discovery applies basic `authorizedDomains` filtering.
6. SQLite JSON storage helper supports namespace-based upsert/read/delete/count.
7. Root keeps SQLite-backed CDN publish and Discovery notify queues.
8. Capability tree is loaded from an external JSON file.
9. Expanded `/api/v1` management APIs exist for Root, Registrar, Discovery, and CDN.
10. Direct tests for the new management APIs have been added and verified with `cargo test --workspace`.
11. Root authorization state persistence, request nonce replay checks, optional request signature verification, and Discovery metadata/bulletin verification have been added.
12. Root batch APIs now run domain-filtered batches and keep batch history.
13. Registrar draft records and Discovery package indexes are mirrored into SQLite.
14. Demo Python Agents are packaged as `uv` projects with command-line entry points and lock files.
15. The local E2E demo validates User Agent VC verification, User Agent request signature verification, Service Agent signed response verification, and Service Agent provenance metadata.

## Next Development Work

### 1. Complete Root Authorization State

Root now persists authorization state. Next work should enrich state and credentials:

- Generate and store local node authorization credentials.
- Support suspended, revoked, and recovered states.
- Expose authorization status query APIs.

### 2. Strengthen Registration Credential Checks

Root currently verifies credential signature and basic fields. Next checks should include:

- `expiresAt`
- `claims.didDocumentHash`
- credential type allowlist
- credential issuer authorization scope
- stricter request timestamp windows
- mandatory request-level registrar signature after compatibility period

### 3. Improve Discovery Validation

Discovery currently validates package document hash, metadata hash, Root proof signature, bulletin hash chain, and bulletin event presence. Next checks should include:

- Agent revoked/suspended status
- package freshness and version ordering
- Discovery self-authorization status at startup and during sync

### 4. Upgrade `authorizedDomains` Matching

Current matching uses the capability tree for coarse routing and preserves custom tags for query-time filtering. Next work:

- Normalize aliases.
- Match parent-child subtrees.
- Flag unknown authorized domains for operator review without blocking custom Agent tags.
- Reinterpret authorization after capability tree version changes.
- Store `tagTreeVersion` with Discovery authorization state.

### 5. Move Runtime Indexes To SQLite

JSON files remain audit-friendly artifacts, while SQLite is now the operational namespace JSON index for key runtime data. The next step is relational schemas.

Root next:

- `did_document_versions`
- `authorized_nodes`

Registrar next:

- submitted document hashes
- credential copies
- Root submission responses

Discovery next:

- bulletin cache
- sync cursor
- rejected package log
- optional local ranking signals

CDN:

- package index
- manifest entries
- publish history
- access log

### 6. Improve Batch Strategy

Root batch handling is now explicit and domain-filtered. Next it should become configurable and scheduler-driven:

- maximum batch size
- maximum delay
- retry policy
- idempotency key
- partial failure handling
- per-Discovery delivery endpoints when Discovery notification delivery is implemented

### 7. Harden Agent-To-Agent Trusted Invocation

The E2E demo now proves the basic Agent-to-Agent trust loop. Next work should move it from demo-grade to adapter-grade:

- Define the formal OpenAgentNet trusted invocation envelope.
- Specify canonical JSON, `bodyHash`, proof fields, `proofPurpose`, nonce, timestamp, and response-signing rules.
- Persist Service Agent nonce records instead of keeping them only in memory.
- Enforce timestamp windows for Agent invocation requests.
- Verify VC `expiresAt`, future VC status lists, issuer authorization status, and issuer authorization scope.
- Verify submitted peer DID Documents against Root-anchored package data instead of trusting the caller-provided copy alone.
- Add negative E2E tests for wrong signature, missing VC, wrong VC subject, expired timestamp, replayed nonce, and target DID mismatch.
- Extract duplicated Python signing and verification logic into a reusable Agent Adapter package.

### 8. Security Hardening

The MVP demonstrates trust flow, but production-grade security needs additional controls:

- Key protection:
  - encrypted local keys
  - file permission checks
  - optional KMS/HSM integration
  - key rotation and DID Document update handling
- Credential lifecycle:
  - expiration checks
  - revocation/status list support
  - issuer authorization checks against Root bulletin
  - multiple VC dimensions per Agent
- Access control:
  - Service Agent policy based on caller DID, VC type, issuer, claims, and requested capability
  - per-endpoint authorization rules
  - rate limiting and request quotas
- Audit:
  - registration audit events
  - discovery sync audit events
  - invocation accepted/rejected events
  - signature failure and nonce replay logs
  - structured security error codes

### 9. Protocol Compatibility

MCP and A2A are currently represented by endpoint compatibility and demo metadata. Next work should provide real protocol adapters:

- MCP:
  - perform DID/VC verification before MCP initialization or tool calls
  - expose verified caller identity to MCP tools
  - map MCP tool capabilities to DID Document capability metadata
  - support signed MCP responses where needed
- A2A:
  - map A2A agent card/capability data to DID Document service and capability fields
  - add identity handshake before task submission
  - sign task requests, task status updates, callbacks, and final responses
  - handle long-running and streaming task verification
- DID/VC compatibility:
  - align credentials closer to W3C VC structures such as `@context`, `credentialSubject`, `validFrom`, and `validUntil`
  - support Data Integrity Proof or JWT VC profiles
  - define DID resolution output and DID URL fragment behavior for `did:ans`
- SDKs:
  - Rust SDK for infrastructure and services
  - TypeScript SDK for web UI and clients
  - Python Agent Adapter SDK for demo and third-party Agents

### 10. Deployment Readiness

The local PowerShell demo works. Next work should make the system easy to run outside the development machine:

- Docker Compose for Root, Registrar, Discovery, CDN, Service Agent, and User Agent.
- Linux/macOS shell E2E script in addition to PowerShell.
- Unified configuration schema for listen address, DID path, key path, DB URL, bulletin URL, CDN URL, batch settings, and log level.
- Environment variable overrides for container and CI use.
- Clear separation between seed fixtures, runtime databases, archives, queues, credentials, keys, and logs.
- Multi-instance readiness for multiple Registrar Nodes and multiple Discovery Nodes.
- CI pipeline for formatting, linting, Rust tests, Python checks, schema validation, and E2E demo.

### 11. Governance Roadmap

Root should remain the trust management hub, data distribution hub, and semantic governance hub. Governance work should include:

- Root authorization lifecycle:
  - application
  - review
  - authorization
  - suspension
  - recovery
  - revocation
  - bulletin publication
- Discovery authorization domain governance:
  - capability tree subtrees
  - industry domains
  - VC type scopes
  - validity periods
  - domain changes over time
- Capability tree governance:
  - versioning
  - added/deprecated tags
  - alias normalization
  - mapping custom tags to canonical tags
  - compatibility across tree versions
- VC issuer governance:
  - Root authorization before ecosystem recognition
  - supported VC types
  - authorization scope
  - revocation events on bulletin
- DID Document update governance:
  - version archive
  - diff records
  - key rotation checks
  - endpoint change checks
  - capability change checks
- Bulletin governance:
  - event schemas
  - event type registry
  - hash-chain verification
  - snapshots
  - pagination
  - mirror support

### 12. Operations Readiness

Operational work should make the system observable and recoverable:

- Health endpoints:
  - liveness
  - readiness
  - database health
  - queue lag
  - CDN sync status
- Metrics:
  - registration request count
  - verification failures
  - VC failures
  - CDN publish success/failure
  - Discovery sync success/failure
  - discovery query latency
  - queue backlog
  - nonce replay count
- Logging and tracing:
  - structured JSON logs
  - request ID and trace ID
  - DID, operation, status, error code, latency
  - OpenTelemetry tracing across registration, distribution, discovery, and invocation
- Backup and recovery:
  - SQLite databases
  - Root archive
  - bulletin
  - keys
  - credentials
  - capability tree
- Database migration:
  - schema version table
  - migration scripts
  - backward compatibility plan
- Runbooks:
  - node initialization
  - authorization operations
  - key rotation
  - credential revocation
  - CDN inconsistency handling
  - bulletin verification failure handling

### 13. Documentation Follow-Up

Keep these docs synchronized with implementation:

- `docs/design.md`
- `docs/TODO.md`
- `services/root-node/docs/design.md`
- `services/registrar-node/docs/design.md`
- `services/discovery-node/docs/design.md`
- `services/cdn-node/docs/design.md`
