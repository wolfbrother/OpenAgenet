<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgenet Future Development Strategy

This document summarizes the main gaps between OpenAgenet and domestic ANP / AIP routes, and turns those gaps into future development guidance for OpenAgenet.

The purpose is not to make OpenAgenet follow ANP or AIP. OpenAgenet's central mission is to build trusted Agent interconnection infrastructure. ANP and AIP are important domestic references and potential cooperation routes, but they should not become the product center of OpenAgenet.

OpenAgenet should develop from a runnable trusted registration, distribution, discovery, and verification system into a standardized, easy-to-integrate, deployable, governable, and ecosystem-ready infrastructure base for Agent interconnection and the Agent Internet.

## 1. Strategic Premise

OpenAgenet does not plan to define a full Agent interaction protocol system.

Agent interaction protocols and frameworks such as ANP, A2A, MCP, AIP-compatible flows, and future protocols may define how Agents communicate, negotiate, invoke tools, exchange messages, or coordinate tasks.

OpenAgenet should focus on the infrastructure capabilities around those interactions:

- trusted Agent registration
- Root-governed infrastructure authorization
- complete DID Document submission and verification
- Agent document archive and versioning
- CDN-backed verifiable distribution
- authorized Discovery synchronization
- capability-based discovery
- credential verification
- pre-connection verification
- signed request and response envelopes where needed
- SDKs and adapters that allow different Agent interaction protocols to enter the OpenAgenet ecosystem

Therefore, the gap between OpenAgenet and ANP / AIP should not be described as "OpenAgenet lacks a full interaction protocol." That is a deliberate boundary. The real gaps are in ecosystem awareness, formal specifications, SDKs, developer experience, production readiness, governance expression, semantic discovery, pilot cases, security completeness, and ecosystem organization.

## 2. Main Gap Areas

### 2.1 Ecosystem Awareness and Narrative Power

ANP and AIP have naming advantages because their names directly express Agent networks or Agent interconnection. Domestic AIP may also have a closer relationship with standardization discussions. This makes them easier for external audiences to understand as protocol or standard routes.

OpenAgenet already has a strong engineering foundation, but its external narrative still needs to be strengthened.

Current gap:

- external awareness is still limited
- positioning requires explanation
- the distinction between infrastructure layer and interaction protocol layer needs to be clearer
- OpenAgenet's value as a trusted infrastructure base needs stronger public materials

Future upgrade direction:

- strengthen README, white paper, diagrams, and public presentations
- publish a concise positioning statement
- explain the layer relationship with MCP, A2A, ANP, AIP, DNS-native systems, and ANS-type systems
- prepare demonstration and research boundary materials
- prepare standardization-oriented presentation materials

Target state:

- external audiences can quickly understand that OpenAgenet is not a simple Agent registry, Agent DNS, or interaction protocol
- OpenAgenet is recognized as trusted registration, governance, distribution, discovery, and verification infrastructure for Agent interconnection

### 2.2 Formal Specification Maturity

ANP and AIP are likely to be discussed as protocol or standardization systems. OpenAgenet currently has design documents and working code, but its core mechanisms need to be extracted into clearer specifications.

Current gap:

- system design is documented, but formal protocol specifications are not yet complete
- schemas and test vectors are not yet sufficient
- compatibility and deprecation rules are not yet mature

Future upgrade direction:

- define `did:ans` DID Document Profile
- define Agent Document Package Format
- define Root Bulletin Event Format
- define Registrar Submission Protocol
- define Root Verification Profile
- define Root-to-CDN Distribution Profile
- define Root-to-Discovery Notification Profile
- define Discovery Sync Protocol
- define Discovery Response Signature Format
- define Capability Tree Governance Profile
- define Pre-Connection Verification Profile
- define Error Code and Security Profile
- provide JSON Schemas and canonical examples
- provide versioning, compatibility, and deprecation policies
- provide conformance test vectors

Target state:

- OpenAgenet is not only runnable, but also implementable by independent teams according to stable specifications

### 2.3 SDK and Developer Access

OpenAgenet's infrastructure value depends on low-friction integration. If developers must understand all DID, VC, Root proof, bulletin, CDN package, Discovery response, and request-signing details manually, ecosystem adoption will be slow.

Current gap:

- shared SDKs are not yet extracted as stable packages
- Agent integration still depends heavily on demo code and repository knowledge
- protocol adapter support is not yet packaged

Future upgrade direction:

- Rust Core SDK for DID, VC, proof, package, and signature verification
- Python Agent Adapter SDK for Service Agent and User Agent integration
- TypeScript Client and Web SDK for dashboards and web consoles
- CLI for validation, registration, Discovery query, and local testing
- endpoint metadata helpers for multiple interaction protocols
- credential storage helpers
- Discovery query helpers
- Root proof and bulletin verification helpers
- conformance test runner
- adapter examples for open Agent interaction protocols

Target state:

- Agent developers can enter OpenAgenet through SDKs without reading all service internals
- interaction protocol support is available through adapters, but adapters remain an open extension capability rather than the product center

### 2.4 Developer Platform and Web Experience

ANP or AIP-oriented ecosystems may develop developer portals, conformance tools, or registration platforms. OpenAgenet currently has APIs and demos, but it still lacks user-friendly web entry points.

Current gap:

- no Registrar Web Console
- no Discovery Web Console
- no DID Document Builder
- no capability tag selection UI
- no visual bulletin or authorization status viewer
- no online interoperability test UI

Future upgrade direction:

- Registrar Web Console
- Discovery Web Console
- DID Document Builder
- capability tree browser
- custom tag editor
- registration credential viewer
- Root authorization bulletin viewer
- Discovery query UI
- multi-node topology view
- demo dashboard
- SDK documentation site

Target state:

- developers, enterprises, and pilot users can understand and operate OpenAgenet through visual workflows, not only APIs and scripts

### 2.5 Production Readiness and Operations

OpenAgenet has runnable demos and integration examples. To become a credible infrastructure base, it needs stronger production and operations capabilities.

Current gap:

- observability is still limited
- deployment templates are incomplete
- database migration and backup procedures are not mature
- production security lifecycle is incomplete

Future upgrade direction:

- health and readiness endpoints
- structured logs
- metrics
- tracing
- audit logs
- queue status and batch processing visibility
- authorization state recovery
- backup and restore guide
- schema migration strategy
- Docker Compose templates
- Kubernetes Helm Chart
- systemd and Windows service deployment notes
- PostgreSQL production profile if adopted
- observability dashboard
- deployment conformance checklist

Target state:

- OpenAgenet can support internal pilots and enterprise deployments with repeatable operational procedures

### 2.6 Governance and Standardization Expression

OpenAgenet already has strong governance ideas: Root authorization, bulletin events, capability tree governance, Registrar / Discovery authorization, and third-party VC issuer authorization. These need to be expressed in a more formal and reusable way.

Current gap:

- governance model is documented but not yet fully specified as processes
- capability tree evolution process is not yet formalized
- third-party VC issuer authorization process needs clearer expression
- community governance model needs more detail

Future upgrade direction:

- Governance Specification
- Infrastructure Authorization Process
- Registrar Authorization Guide
- Discovery Authorization Guide
- Third-Party VC Issuer Authorization Guide
- Bulletin Event Governance
- Capability Tree Governance Process
- Security Disclosure Policy
- Community Governance Guide
- standards-alignment notes for domestic AIP and other routes

Target state:

- OpenAgenet can be discussed as a governance-ready Agent infrastructure system, not only an engineering project

### 2.7 Semantic Discovery Capability

OpenAgenet already has a capability tree and allows custom tags. This is a practical foundation. However, large-scale Agent discovery requires richer descriptions and Discovery-side extension mechanisms.

Current gap:

- capability tree currently supports coarse discovery
- Agent capability description is still simple
- input/output schema and policy metadata are not mature
- semantic search engine implementation is intentionally out of current scope
- Discovery plugin interface is not yet defined

Future upgrade direction:

- Agent Description Profile
- Capability Metadata Profile
- input/output schema fields
- service-level metadata
- policy and credential requirement metadata
- multilingual labels
- capability tag extension process
- Discovery Index Profile
- Ranking Metadata Interface
- Discovery Plugin Interface
- reference semantic search plugin

Target state:

- Root governs shared semantic materials without controlling every Discovery policy
- Discovery Nodes can develop differentiated semantic search, ranking, reputation, and evaluation services

### 2.8 Pilot Cases and Demonstration Assets

ANP and AIP may gain influence through pilots, standards discussions, and visible ecosystem activities. OpenAgenet needs stronger demonstration assets that show its infrastructure value.

Current gap:

- existing demos prove the core flow, but use cases are still limited
- industry-facing examples are not yet rich
- website-based registration and discovery demos are not yet available

Future upgrade direction:

- trusted Service Agent hello demo
- MCP tool service registration and discovery demo
- A2A service registration and discovery demo
- generic open interaction protocol endpoint demo
- enterprise private Agent directory demo
- multi Registrar and multi Discovery production-style demo
- Registrar website demo
- Discovery website demo
- standardization testbed demo
- industry Agent directory demo

Target state:

- OpenAgenet can be demonstrated to research institutions, enterprises, developers, and standardization audiences through concrete scenarios

### 2.9 Security Completeness

OpenAgenet already includes DID, VC-compatible credentials, Root proof, bulletin event verification, signed responses, nonce, timestamp, and request signatures. A production-grade infrastructure requires a fuller security lifecycle.

Current gap:

- key rotation is not mature
- credential revocation and status checking are not mature
- DID Document historical verification needs more detail
- compromised Registrar / Discovery handling is not fully specified
- stale CDN package handling needs clearer rules
- security test matrix needs expansion

Future upgrade direction:

- Threat Model
- Security Profile
- Key Lifecycle Guide
- Credential Lifecycle Guide
- VC Status and Revocation Mechanism
- DID Document Historical Verification Profile
- Compromised Registrar Handling
- Compromised Discovery Handling
- Stale CDN Package Handling
- signed management API profile
- fuzz and property tests
- supply-chain security checklist

Target state:

- OpenAgenet can support security review, controlled pilots, and long-term infrastructure trust

### 2.10 Ecosystem Organization

ANP and AIP may have early mover advantages through names, communities, standards discussions, and partner networks. OpenAgenet needs its own ecosystem organization capacity.

Current gap:

- external contributors are still limited
- partner channels are not yet mature
- working groups are not yet formed
- contribution paths are not yet visible enough

Future upgrade direction:

- `CONTRIBUTING.md`
- `ROADMAP.md`
- issue labels for SDK, docs, examples, security, protocol, deployment, and governance
- SDK contributor guide
- plugin contributor guide
- research collaboration track
- enterprise pilot track
- standardization collaboration track
- Discovery operator guide
- Registrar operator guide
- security review process

Target state:

- OpenAgenet can attract developers, institutions, enterprises, and researchers to contribute around a clear infrastructure roadmap

## 3. Relationship to ANP and AIP

ANP and AIP should remain important domestic references, but they should not define the center of OpenAgenet's roadmap.

OpenAgenet should use the following stance:

- respect domestic ANP and AIP as important Agent Internet routes
- seek terminology and concept alignment where useful
- publish adapter SDKs and metadata profiles that allow open Agent communication and interconnection protocols to enter OpenAgenet
- avoid duplicating full interaction protocol systems
- keep OpenAgenet centered on trusted registration, governance, distribution, discovery, verification, and infrastructure operations
- use demos and specifications to show OpenAgenet's independent infrastructure value

The key sentence is:

> OpenAgenet does not compete to define every Agent interaction protocol. It aims to become the trusted infrastructure base where different Agent interaction protocols can be registered, discovered, verified, governed, and connected.

## 4. Version Upgrade Priorities

### 4.1 Short-Term Priorities

- formalize core specifications from existing design documents
- define endpoint metadata profile for multiple interaction protocols
- extract Rust Core SDK foundation
- extract Python Agent Adapter SDK foundation
- add TypeScript client SDK foundation
- improve README, architecture diagrams, and quick start
- add more multi-node and protocol-endpoint demos
- keep regression tests and integration tests reliable

### 4.2 Mid-Term Priorities

- build Registrar Web Console
- build Discovery Web Console
- define governance specifications
- define production deployment templates
- strengthen observability and audit logs
- add credential lifecycle and key lifecycle support
- define Discovery plugin interface
- publish conformance test vectors

### 4.3 Long-Term Priorities

- support larger-scale deployments
- support richer Discovery ecosystems
- support standardization-oriented testbeds
- support industry Agent directories
- support third-party SDK and adapter ecosystems
- support multi-domain or federated trust research if needed
- support mature community governance and partner programs

## 5. Summary

OpenAgenet's gap with ANP and AIP should not be reduced to protocol adaptation.

The real development task is to upgrade OpenAgenet from a runnable trusted registration, distribution, discovery, and verification reference implementation into a mature infrastructure base that is:

- formally specified
- easy to integrate
- SDK-supported
- web-console friendly
- production deployable
- governance-ready
- semantically extensible
- security-hardened
- demonstration-rich
- ecosystem-organized

ANP and AIP are important references and potential cooperation routes. OpenAgenet should respect and align with them where useful, but it should remain centered on its own infrastructure mission.

The long-term goal is clear:

> Build OpenAgenet into an open, trusted, interoperable infrastructure base for Agent interconnection and the Agent Internet.

