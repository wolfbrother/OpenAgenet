<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgenet Ecosystem Participation Guide

This document describes where community members, teams, companies, research institutions, and ecosystem partners can participate in OpenAgenet. It covers engineering collaboration, governance collaboration, deployment collaboration, and long-term ecosystem development.

## 1. Ecosystem Positioning

OpenAgenet should be developed as an Agent Internet infrastructure project rather than a single application.

The project provides:

- Agent identity and registration infrastructure
- Root-governed infrastructure authorization
- trusted DID Document distribution
- verifiable Agent discovery
- signed Agent-to-Agent invocation
- capability tag governance
- MCP and A2A-compatible Agent access expectations

The ecosystem should allow many independent parties to operate Agents, Registrar Nodes, Discovery Nodes, SDKs, tools, and industry-specific services while keeping the common trust and interoperability contract stable.

## 2. Participation Areas Needed by the System

### 2.1 Protocol and Access Contract

The system needs community feedback on the protocol surface because protocol decisions affect all future participants.

Collaboration topics:

- `did:ans` DID Document profile
- W3C VC-compatible registration credentials
- Agent-to-Agent trusted invocation envelope
- nonce, timestamp, and replay protection
- Root bulletin event format
- Discovery response signature format
- CDN package metadata format
- MCP and A2A compatibility expectations
- protocol versioning and deprecation rules
- error codes and failure semantics

This area should be governed carefully. Contributions should be reviewed for interoperability, security, and long-term compatibility.

### 2.2 SDK and Developer Tools

The system needs SDKs to reduce integration cost and prevent inconsistent protocol implementations.

Collaboration topics:

- Rust core protocol SDK
- TypeScript web and infrastructure SDK
- Python Agent adapter SDK
- CLI tools
- language-specific examples
- test vectors
- SDK compliance tests
- developer documentation

Community-maintained SDKs can be encouraged for Go, Java, Kotlin, Swift, and other ecosystems after the official test vectors are stable.

### 2.3 Agent Framework Integration

The ecosystem should support many existing Agent frameworks.

Collaboration topics:

- MCP Server and MCP Client adapters
- A2A-compatible Agent adapters
- LangChain and LangGraph integration
- AutoGen integration
- CrewAI integration
- enterprise internal Agent adapters
- low-code Agent platform adapters
- custom Agent runtime templates

The recommended approach is to keep business Agent logic independent and add an OAN adapter layer for DID, VC, signing, verification, and Discovery access.

### 2.4 Registrar Node Extensions

Registrar Nodes are important entry points for Agent onboarding.

Collaboration topics:

- registration web console
- DID Document draft assistant
- capability tag recommendation
- custom tag editing
- Agent operator review workflow
- registration credential issuance
- enterprise registration policy plugins
- industry-specific registration templates

Registrar Nodes can differ by organization, industry, or deployment environment while still submitting complete DID Documents to Root.

### 2.5 Discovery Node Extensions

Discovery Nodes have large room for differentiated services.

Collaboration topics:

- capability tag coarse filtering
- custom tag fine filtering
- semantic search
- ranking strategies
- multilingual search
- domain-specific Agent directories
- reputation and evaluation data
- Agent history collection
- privacy-preserving query design
- signed Discovery response verification

Root does not maintain Agent reputation, evaluation, or invocation history. Discovery Nodes may collect and use such data to provide better discovery services, subject to their own policies and applicable laws.

### 2.6 Capability Tag Governance

The current capability tree can serve as an initial shared taxonomy, but long-term ecosystem growth requires collaborative governance.

Collaboration topics:

- AI Agent-specific capability tags
- industry capability extensions
- MCP tool capability tags
- data processing capability tags
- security and compliance capability tags
- multilingual labels
- aliases and deprecated tags
- tag merge and split proposals
- compatibility between standard tags and custom tags

The standard capability tree should support network-wide coarse discovery. Custom tags should remain allowed for fine filtering and domain-specific expression.

### 2.7 Security Review

Security participation is essential because OpenAgenet is a trust infrastructure project.

Collaboration topics:

- DID Document validation
- credential proof verification
- Root proof verification
- Discovery response verification
- request and response signing
- replay protection
- key rotation
- authorization revocation
- bulletin event verification
- CDN package integrity
- threat modeling
- security test cases

Security reports should be handled through a clear vulnerability disclosure process.

### 2.8 Deployment and Operations

The project needs reproducible deployment paths for real adoption.

Collaboration topics:

- Docker Compose examples
- Kubernetes Helm charts
- systemd service templates
- Windows service examples
- SQLite and PostgreSQL deployment options
- backup and restore
- observability
- health checks
- log collection
- multi Registrar and multi Discovery examples
- upgrade and migration playbooks

Operational contributions are highly valuable because they help organizations move from local demos to internal pilots.

### 2.9 Documentation and Internationalization

Documentation is part of the ecosystem interface.

Collaboration topics:

- README and quick start
- architecture guide
- protocol specification
- API reference
- SDK documentation
- deployment guide
- governance guide
- security guide
- tutorial examples
- Chinese and English documentation
- diagrams and presentations

Documentation should clearly distinguish demo behavior, research behavior, and production expectations.

## 3. Participation Areas Likely to Attract the Community

Different participants will care about different parts of OpenAgenet.

### 3.1 Individual Developers

Individual developers are likely to care about:

- how to connect an Agent quickly
- SDK usability
- runnable examples
- MCP and A2A compatibility
- Discovery query APIs
- clear error messages
- simple local demos
- contribution issues with small scope

Good first issues should focus on examples, tests, SDK helpers, documentation, and small API improvements.

### 3.2 Enterprises

Enterprises are likely to care about:

- private deployment
- enterprise Agent directories
- authorization and auditability
- data boundary clarity
- integration with existing IAM and credential systems
- custom Registrar policy
- custom Discovery service
- operational support
- long-term compatibility

Enterprise participation may focus on deployment templates, policy plugins, audit logs, management APIs, and private network use cases.

### 3.3 Research Institutions

Research institutions are likely to care about:

- Agent Internet architecture
- DID and VC integration
- semantic governance
- Agent discovery models
- distributed trust models
- multi-root or multi-domain evolution
- standardization proposals
- academic evaluation scenarios

Research participation may produce architecture papers, evaluation benchmarks, governance proposals, and standard drafts.

### 3.4 Infrastructure Operators

Infrastructure operators may want to operate:

- Registrar Nodes
- Discovery Nodes
- VC issuer services
- CDN or storage services
- industry-specific Agent directories
- security audit services

They will care about authorization rules, service-level expectations, operational cost, and governance transparency.

### 3.5 Open-Source Maintainers

Open-source maintainers are likely to care about:

- repository boundaries
- contribution rules
- CI reliability
- code ownership
- release process
- issue triage
- review expectations
- long-term roadmap

The project should provide clear maintainer workflows before inviting broad external contribution.

## 4. Recommended Governance Structure

The ecosystem can be organized into working groups.

### 4.1 Protocol Working Group

Scope:

- DID profile
- credential schema
- proof formats
- bulletin events
- Agent invocation envelope
- versioning

### 4.2 SDK Working Group

Scope:

- Rust core SDK
- TypeScript SDK
- Python SDK
- CLI
- test vectors
- SDK compatibility

### 4.3 Agent Integration Working Group

Scope:

- MCP integration
- A2A integration
- framework adapters
- demo Agents
- trusted invocation middleware

### 4.4 Discovery Working Group

Scope:

- query model
- semantic search
- capability tags
- ranking
- signed responses
- domain-specific directories

### 4.5 Security Working Group

Scope:

- threat modeling
- audits
- vulnerability disclosure
- replay protection
- key lifecycle
- authorization revocation

### 4.6 Deployment Working Group

Scope:

- Docker
- Kubernetes
- systemd
- Windows service
- monitoring
- backup
- upgrade

### 4.7 Governance Working Group

Scope:

- infrastructure authorization
- bulletin governance
- third-party VC issuer admission
- capability tree evolution
- ecosystem participation rules

## 5. Contribution Stages

### Stage 1: Early Open Collaboration

Recommended open areas:

- documentation
- examples
- test cases
- SDK feedback
- deployment scripts
- capability tag suggestions
- bug reports

### Stage 2: Ecosystem Expansion

Recommended open areas:

- SDK packages
- Agent adapters
- Registrar plugins
- Discovery extensions
- web consoles
- operational templates
- industry examples

### Stage 3: Governance Maturity

Recommended open areas:

- protocol proposals
- authorization policy proposals
- bulletin governance proposals
- multi-domain trust proposals
- standardization work

## 6. Maintainer Responsibilities

Project maintainers should:

- preserve protocol compatibility
- keep trust boundaries clear
- prevent premature fragmentation
- maintain canonical test vectors
- review security-sensitive changes carefully
- keep documentation aligned with implementation
- publish roadmaps and release notes
- distinguish demo features from production-ready features

Open collaboration should not mean uncontrolled protocol drift. The ecosystem needs stable anchors to grow safely.

## 7. Recommended Public Materials

Before broad ecosystem outreach, the project should maintain:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `ROADMAP.md`
- architecture diagram
- quick start guide
- demo and research boundary document
- SDK roadmap
- governance participation guide
- protocol specification
- API reference
- multi-node deployment example

These materials help different participants understand how they can join without requiring deep code reading first.

## 8. Non-Goals

Community participation should not require:

- one mandatory Agent runtime
- one mandatory business model
- one mandatory Discovery ranking strategy
- one mandatory storage provider
- one mandatory CDN provider
- Root visibility into Agent business traffic

OpenAgenet should grow as a loosely coupled trust and interoperability ecosystem.

