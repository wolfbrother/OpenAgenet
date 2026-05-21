<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgenet Large-Scale Production Ecosystem Guide

This document analyzes whether the current OpenAgenet design can support a large ecosystem and records the additional work required before the system can be considered mature for large-scale production use.

## 1. Current Assessment

OpenAgenet already has the architectural foundation of an ecosystem-level system.

The current design includes:

- language-neutral Agent access contract
- separated Root, Registrar, Discovery, CDN, Service Agent, and User Agent roles
- multi Registrar and multi Discovery deployment direction
- DID Document-based identity
- W3C VC-compatible registration credential direction
- Root authorization and bulletin events
- Root-verified package distribution through CDN
- Discovery verification of Root proof and bulletin event references
- signed Discovery responses
- signed Agent-to-Agent invocation
- standard capability tags plus custom tags
- local end-to-end demos and integration examples

This is more than a simple Agent registry or directory. It is a trust, registration, discovery, distribution, and invocation foundation for an Agent Internet.

However, a large-scale production ecosystem requires additional maturity in protocol governance, SDKs, security, operations, observability, deployment, data governance, and community process.

## 2. Production Maturity Goals

The long-term production ecosystem should support:

- many Registrar Nodes
- many Discovery Nodes
- many Service Agents and User Agents
- multiple organizations operating infrastructure
- multiple credential issuers authorized by Root
- large DID Document archive volume
- delayed and batched Root-to-CDN synchronization
- delayed and batched Root-to-Discovery notification
- verifiable CDN package retrieval
- flexible Discovery ranking and semantic search
- reliable authorization revocation propagation
- consistent protocol behavior across SDKs
- safe upgrades without ecosystem-wide breakage

The system should remain loosely coupled. Root should not become a business traffic gateway or a centralized Agent runtime.

## 3. Areas That Already Support Ecosystem Growth

### 3.1 Role Separation

The separation of Root, Registrar, Discovery, CDN, and Agents is suitable for ecosystem growth.

Root acts as:

- trust management hub
- data distribution hub
- semantic governance hub

Registrar Nodes handle onboarding. Discovery Nodes handle search and service discovery. CDN handles content distribution. Agents handle business behavior.

This separation allows different organizations to operate different roles.

### 3.2 Language-Neutral Agent Contract

OpenAgenet does not require Agents to be implemented in a specific language. This is essential for ecosystem expansion.

The system should continue to define:

- what an Agent must present
- what an Agent must verify
- what an Agent must sign
- how an Agent participates in registration and discovery

It should not define:

- which framework the Agent must use
- which language the Agent must use
- how the Agent implements its internal business logic

### 3.3 Standard and Custom Capability Tags

The combination of standard capability tags and custom tags is suitable for large-scale discovery.

Standard capability tags support:

- network-wide coarse filtering
- consistent Discovery indexing
- cross-organization interoperability
- semantic governance

Custom tags support:

- domain-specific expression
- fine filtering
- local innovation
- backward-compatible experimentation

### 3.4 Verifiable Distribution

The Root-to-CDN-to-Discovery flow is suitable for scalable distribution because Discovery Nodes can fetch packages from CDN and verify Root proofs independently.

The intended ordering should remain:

1. Registrar submits a complete Agent DID Document to Root.
2. Root verifies and archives the DID Document.
3. Root synchronizes verified data to CDN according to a batch policy.
4. Root notifies authorized Discovery Nodes after CDN synchronization is complete.
5. Discovery Nodes fetch from CDN and verify Root proof plus bulletin event references.

This avoids Discovery Nodes receiving notifications for data that is not yet available on CDN.

## 4. Required Enhancements for Large-Scale Production

### 4.1 Protocol Version Governance

Production ecosystems require explicit version governance.

Needed work:

- define protocol version fields for DID profiles
- define credential schema versions
- define bulletin event versions
- define package metadata versions
- define Discovery response versions
- define Agent-to-Agent invocation envelope versions
- define compatibility windows
- define deprecation policy
- define migration guidance

Without version governance, SDKs and nodes may diverge as the ecosystem grows.

### 4.2 SDK and Compliance Test Vectors

Large ecosystems cannot rely on manual protocol implementation.

Needed work:

- Rust core SDK
- TypeScript client and web SDK
- Python Agent adapter SDK
- canonical DID Document test vectors
- canonical credential proof test vectors
- request and response signature test vectors
- Root package verification test vectors
- Discovery response verification test vectors
- SDK compliance test suite

SDKs should make integration easy while keeping security behavior consistent.

### 4.3 Authorization Lifecycle

Root authorization must be production-grade.

Needed work:

- authorization issuance workflow
- authorization update workflow
- authorization revocation workflow
- authorization expiration
- authorization scope changes
- domain set changes for Discovery Nodes
- third-party VC issuer authorization
- bulletin event publication rules
- replayable authorization state reconstruction
- audit trail

Authorization status changes should be published to the bulletin so that all roles can synchronize as needed.

### 4.4 Credential Lifecycle

Credentials must support long-term operation.

Needed work:

- credential expiration
- credential renewal
- credential revocation
- credential status checking
- multiple credentials per Agent
- multiple credential issuers
- credential purpose declaration
- credential selection rules
- local credential storage guidance

Registrar Nodes, Discovery Nodes, and Agents should store their own credentials locally. VC hosting is not required in the current scope.

### 4.5 Key Lifecycle

Production systems require key lifecycle management.

Needed work:

- key generation guidance
- key rotation
- old key retention for historical verification
- compromised key handling
- signing key separation
- encryption key separation if introduced later
- verification method update rules
- DID Document version linkage

Root should archive DID Document versions to support historical verification, but the archive should not directly provide public business services.

### 4.6 Replay Protection and Request Security

Replay protection must be consistent across services and Agents.

Needed work:

- nonce cache persistence rules
- timestamp skew policy
- request body canonicalization
- body hash policy
- target DID validation
- audience validation
- signed response verification
- failure error-code consistency
- negative test cases for all service boundaries

This applies to Agent-to-Agent calls and management APIs where signing is required.

### 4.7 Batch Distribution and Queue Reliability

Root-to-CDN and Root-to-Discovery operations are generally not real-time. Production systems require reliable batch processing.

Needed work:

- durable queues
- retry policy
- dead-letter queue
- batch size policy
- batch interval policy
- idempotency keys
- package publish status
- notification status
- recovery after process restart
- operational metrics

Root should process Registrar submissions in a streaming concurrent manner and should avoid maintaining large in-memory state.

### 4.8 Storage and Database Evolution

SQLite is suitable for local demos and small deployments. Larger deployments may need a common production database option.

Needed work:

- define supported SQLite mode for demos and small nodes
- define PostgreSQL as a recommended production option if adopted
- define schema migration strategy
- define backup and restore procedure
- define index requirements
- define data retention policies
- define archive storage strategy

Root, Registrar, Discovery, and CDN should keep their storage responsibilities separate even if they use the same database technology.

### 4.9 Observability and Operations

Large deployments need operational visibility.

Needed work:

- health endpoints
- readiness endpoints
- metrics endpoints
- structured logs
- trace IDs
- audit logs
- queue depth metrics
- batch processing metrics
- authorization event metrics
- CDN sync metrics
- Discovery sync metrics
- error-code dashboards

Operational tools should support both local pilots and production environments.

### 4.10 Security Boundary Hardening

The system should clearly define what each role trusts and does not trust.

Needed work:

- Root trust assumptions
- Registrar trust assumptions
- Discovery trust assumptions
- CDN trust assumptions
- Agent trust assumptions
- compromised Registrar behavior
- compromised Discovery behavior
- malicious Agent behavior
- stale CDN data behavior
- revoked authorization behavior
- third-party VC issuer trust rules

CDN is a commercial content distribution service, not an authorized protocol authority. Data retrieved from CDN must be verified by consumers.

### 4.11 Privacy and Access-Controlled Distribution

Root may apply token-based or signature-based access control and distribution decisions, while delegating enforcement to CDN.

Needed work:

- distribution policy model
- signed CDN access tokens
- token expiration
- token audience
- package access scope
- Discovery-specific access policy
- audit log for protected package access
- failure behavior when CDN denies access

This is a future capability and is not required in the current implementation.

### 4.12 Multi-Node and Multi-Domain Evolution

The current system can demonstrate multiple Registrar and Discovery Nodes. Future large ecosystems may require stronger multi-domain support.

Needed work:

- multiple Registrar examples
- multiple Discovery examples
- cross-domain authorization model
- potential multi-Root model
- trust domain boundaries
- federation policy
- bulletin interoperability
- conflict handling

Multi-Root or federated trust should be treated as a later design stage. The current version can focus on one Root with multiple authorized infrastructure nodes.

### 4.13 Governance Process

Large ecosystems need governance beyond code.

Needed work:

- protocol proposal process
- capability tree proposal process
- authorization policy process
- security disclosure process
- release process
- compatibility policy
- maintainer policy
- working group structure
- public roadmap

Governance should be transparent enough to attract participation while stable enough to prevent fragmentation.

## 5. Recommended Development Roadmap

### Phase 1: Stabilize the Reference Implementation

- keep current Rust services passing tests
- strengthen end-to-end integration tests
- keep multi-node demos runnable
- align API errors with the error-code catalog
- document demo and research boundaries
- improve README and quick start

### Phase 2: Extract SDK Foundations

- extract Rust core protocol SDK
- publish canonical test vectors
- extract Python Agent adapter SDK
- implement TypeScript client SDK
- provide CLI tools for validation and registration

### Phase 3: Harden Production Operations

- add durable queue behavior
- add operational metrics
- add structured logs
- add health and readiness endpoints
- define backup and restore workflows
- define database migration strategy

### Phase 4: Mature Security and Governance

- implement credential revocation or status checking
- implement key rotation guidance
- formalize authorization lifecycle
- define third-party VC issuer governance
- publish security disclosure process
- define protocol proposal process

### Phase 5: Expand Ecosystem Integrations

- add MCP and A2A adapter examples
- add web consoles
- add industry-specific registration templates
- add Discovery ranking plugins
- add community SDK compliance tests
- support more deployment templates

## 6. Readiness Levels

### Demo-Ready

The system is demo-ready when:

- local services start reliably
- Service Agent and User Agent can complete trusted invocation
- Registrar, Root, CDN, and Discovery flow is demonstrated
- signatures and basic verification pass
- documentation explains the scenario clearly

The current system is close to or already within this level.

### Research-Ready

The system is research-ready when:

- architecture and protocol documents are coherent
- examples are reproducible
- multi-node scenarios are demonstrated
- design tradeoffs are documented
- open questions are explicit

The current system is suitable for research collaboration and external discussion, with continued documentation refinement.

### Pilot-Ready

The system is pilot-ready when:

- SDKs reduce integration cost
- deployment templates exist
- operational logs and health checks exist
- authorization lifecycle is reliable
- security boundaries are documented
- negative tests cover major failure modes

### Production-Ecosystem-Ready

The system is production-ecosystem-ready when:

- protocol versioning is stable
- SDK compliance tests exist
- credential and key lifecycle are mature
- durable queues and recovery are implemented
- observability is complete
- governance process is published
- security disclosure process is active
- multiple organizations can operate nodes safely

## 7. Key Risks

### 7.1 Protocol Drift

If SDKs and nodes implement protocol behavior differently, interoperability will degrade.

Mitigation:

- maintain canonical test vectors
- publish protocol versions
- require compliance tests for SDKs

### 7.2 Governance Ambiguity

If authorization, revocation, and capability tree changes are unclear, ecosystem participants may hesitate to adopt the system.

Mitigation:

- publish governance rules
- record decisions
- define proposal processes

### 7.3 Discovery Fragmentation

Discovery Nodes may diverge in ranking and metadata models.

Mitigation:

- standardize minimum response verification
- allow ranking differentiation
- keep standard capability tags stable

### 7.4 Security Inconsistency

If each Agent implements VC and request verification differently, trusted invocation will be unreliable.

Mitigation:

- provide Agent Adapter SDKs
- publish negative tests
- document required checks

### 7.5 Operational Complexity

Multi-node operation may become hard without deployment tooling.

Mitigation:

- provide Docker and Kubernetes templates
- document backup and restore
- expose metrics and health checks

## 8. Summary

OpenAgenet already has the right ecosystem-level architecture: separated roles, language-neutral Agents, Root-governed trust, Registrar-assisted onboarding, verifiable CDN distribution, Discovery-based search, and signed Agent-to-Agent invocation.

The next stage should focus less on adding isolated features and more on making the system stable, repeatable, observable, secure, and easy to integrate.

The most important production ecosystem work is:

- protocol version governance
- SDKs and compliance tests
- authorization and credential lifecycle
- durable batch distribution
- observability and operations
- security boundary hardening
- governance and community process

These improvements will move OpenAgenet from a strong demo and research foundation toward a sustainable large-scale Agent Internet ecosystem.

