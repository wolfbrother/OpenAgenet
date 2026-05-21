<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet Ecosystem Development Strategy

OpenAgentNet is an open-source reference implementation and infrastructure foundation for trusted Agent registration, governance, distribution, discovery, and pre-connection verification.

The Agent Internet ecosystem is still in an early stage. Many technical routes are emerging at the same time, including Agent communication protocols, tool protocols, naming and resolution systems, identity frameworks, discovery systems, and standardization efforts. At this stage, the most important goal is to expand the shared ecosystem, create interoperability opportunities, and help more developers, institutions, and enterprises participate.

OpenAgentNet therefore follows an ecosystem-first principle while keeping a clear infrastructure ambition:

> Build more bridges, create more partners, avoid unnecessary fragmentation, and develop OpenAgentNet into an open infrastructure base for Agent interconnection and the Agent Internet through implementation quality, openness, standardization contribution, and community execution.

This document describes how OpenAgentNet relates to major adjacent projects and protocols, and how it can develop together with the broader Agent Internet ecosystem.

## 1. Positioning

OpenAgentNet is positioned as an infrastructure base that can interoperate with MCP, A2A, ANP, AIP, DNS-native Agent discovery, Agent Name Service projects, and other adjacent routes.

Its preferred positioning is:

> OpenAgentNet is a trusted registration, governance, distribution, and discovery infrastructure base for open Agent networks. It is designed to interoperate with Agent communication protocols, tool protocols, naming systems, identity systems, and discovery systems while providing its own clear trust, governance, and distribution foundation.

The core value of OpenAgentNet is the system-level trust and coordination model:

- Root Node as trust management hub
- Root Node as data distribution hub
- Root Node as semantic governance hub
- Registrar Nodes for Agent onboarding and credential issuance
- Discovery Nodes for authorized synchronization, search, and differentiated discovery services
- CDN as loosely coupled content distribution, not a protocol authority
- Agent DID Documents as identity and service metadata carriers
- W3C VC-compatible credentials as trust evidence
- Root bulletin events as authorization and distribution coordination records
- capability tree as shared semantic governance material
- signed Agent-to-Agent invocation as a trusted collaboration baseline

This architecture allows OpenAgentNet to work with multiple protocol routes while providing a concrete foundation for trusted registration, verifiable distribution, authorized discovery, and ecosystem governance.

## 2. Ecosystem-First Principles

OpenAgentNet's ecosystem strategy is built on two equal priorities:

- open cooperation with adjacent protocols, projects, institutions, and communities
- steady development of OpenAgentNet as a trusted infrastructure base for Agent interconnection and the Agent Internet

Cooperation should strengthen OpenAgentNet's infrastructure role. OpenAgentNet is designed as a reusable base layer that can connect multiple protocol ecosystems while contributing its own trust, registration, governance, distribution, and discovery capabilities.

### 2.1 Expand the Shared Ecosystem

The Agent Internet is not yet a mature market with fixed boundaries. Domestic and international projects are still exploring identity, description, discovery, interaction, tool invocation, security, and governance models.

OpenAgentNet should help enlarge the shared ecosystem and treat adjacent projects as possible partners in building trustworthy Agent interconnection.

Practical implications:

- treat related projects as possible interoperability partners
- make the reference implementation easy to run and evaluate
- provide clear mapping documents where concepts overlap
- welcome joint demos and test cases
- use language that leaves room for multiple routes to coexist
- keep OpenAgentNet's infrastructure role visible in every cooperation narrative

### 2.2 Seek Common Ground and Preserve Differences

Different projects may choose different trust models, naming schemes, discovery mechanisms, or governance structures. These differences are useful at the early stage because they allow the ecosystem to test multiple paths.

OpenAgentNet should seek common ground in:

- Agent identity
- Agent description
- Agent registration
- Agent discovery
- endpoint metadata
- credential verification
- trusted invocation
- protocol compatibility
- semantic tags

At the same time, OpenAgentNet should preserve its own architectural characteristics:

- Root / Registrar / Discovery / CDN role separation
- complete DID Document registration and version archive
- Root bulletin governance
- verifiable CDN distribution
- Discovery authorization by domain sets
- capability tree governance
- loose coupling with Agent implementation languages and frameworks

### 2.3 Interoperability Before Exclusivity

OpenAgentNet should prefer optional compatibility profiles, adapters, and metadata mappings over exclusive protocol choices.

Interoperability does not mean dependency. OpenAgentNet should support multiple protocol routes from the position of an open infrastructure base. A protocol can be integrated into OpenAgentNet without making OpenAgentNet subordinate to that protocol.

Examples:

- an Agent DID Document may advertise MCP, A2A, ANP, or other endpoints
- Discovery Nodes may index Agents that use different interaction protocols
- DNS-native resolution can be used as an optional name resolution source
- SDKs can provide helpers for multiple protocol integrations
- capability tags can combine standard tree tags and custom tags

This keeps OpenAgentNet open to future ecosystem changes.

### 2.4 Interaction Protocol Neutrality

OpenAgentNet does not define a full Agent interaction protocol system. That is a deliberate boundary choice.

Agent interaction protocols such as ANP, A2A, MCP, domestic AIP-compatible interaction flows, and future protocols can define how Agents communicate, negotiate, invoke tools, exchange messages, or coordinate tasks. OpenAgentNet focuses on the infrastructure capabilities that make those interactions easier to trust and discover:

- trusted Agent registration
- infrastructure authorization
- DID Document distribution
- verifiable Discovery synchronization
- capability-based discovery
- credential verification
- pre-connection verification
- signed request and response envelopes where needed
- adapter SDKs for protocol integration

This keeps OpenAgentNet away from unnecessary competition with interaction protocols while giving those protocols a trusted path into the OpenAgentNet ecosystem.

The expected pattern is:

1. An Agent implements ANP, A2A, MCP, AIP-compatible flows, or another interaction protocol.
2. The Agent registers its DID Document and endpoint metadata through OpenAgentNet.
3. Discovery Nodes index and return the Agent with verifiable metadata.
4. A User Agent verifies identity, credentials, and endpoint metadata before interaction.
5. The actual task interaction proceeds through the Agent's chosen interaction protocol.

Adapter SDKs are therefore a key part of the OpenAgentNet roadmap. They should help different interaction protocols enter the OpenAgentNet ecosystem without forcing those protocols to be rewritten.

### 2.5 Public Value of Open Infrastructure

Open Agent networks need infrastructure that is open, verifiable, interoperable, and useful across different deployment contexts.

OpenAgentNet is designed to provide public value in several dimensions:

- for public-interest digital infrastructure, it offers a transparent reference implementation for trustworthy Agent interconnection
- for enterprises, it provides controlled registration, discovery, authorization, and governance capabilities
- for developers, it provides reusable models, SDK direction, examples, and verification logic
- for users, it supports safer Agent discovery and pre-connection verification
- for the broader ecosystem, it supports open implementation, interoperability, and standardization-oriented validation

This public value depends on both openness and architectural clarity. OpenAgentNet should cooperate broadly while continuing to develop as an open infrastructure foundation for trusted Agent networks.

## 3. Relationship With Major Protocol Routes

### 3.1 MCP and A2A

MCP and A2A should be treated as strongly complementary protocol layers.

MCP focuses on connecting AI applications to tools, data, and context. A2A focuses on Agent-to-Agent communication and task collaboration. OpenAgentNet focuses on trusted registration, authorization, verifiable distribution, discovery, and pre-connection verification.

OpenAgentNet can help Agents publish, register, discover, and verify endpoints that use MCP or A2A.

This relationship should be described as infrastructure enabling protocol use. MCP and A2A provide important interaction capabilities; OpenAgentNet provides the trusted registration, discovery, governance, and verification base around those capabilities.

Collaboration direction:

- include MCP and A2A endpoint metadata in Agent DID Documents
- provide examples where discovered Agents expose MCP or A2A services
- verify Agent identity and credentials before MCP or A2A interaction
- provide SDK helpers for MCP and A2A integration
- clearly state that OpenAgentNet complements MCP and A2A

### 3.2 Domestic AIP

Domestic AIP related to national standard drafts should be treated as a priority domestic alignment reference.

OpenAgentNet can align with domestic AIP through a constructive and confident positioning:

> Domestic AIP can provide important standardization terminology and Agent interconnection framework guidance. OpenAgentNet can provide an open infrastructure foundation and runnable reference implementation for trusted registration, authorization governance, distribution synchronization, semantic discovery, and pre-connection verification.

Domestic AIP should be treated with a higher level of care than a normal interaction protocol because it may represent a standardization-oriented Agent interconnection framework. OpenAgentNet can align with AIP-compatible identity, description, discovery, interaction, and tool-invocation concepts while keeping its own role focused on trusted infrastructure.

In this relationship, OpenAgentNet should be described as:

- aligned with AIP where terminology and concepts are compatible
- adaptable to AIP-compatible Agent metadata and endpoint models
- capable of carrying AIP-compatible Agents into a trusted registration and discovery ecosystem
- useful as a runnable infrastructure foundation for AIP-compatible validation scenarios
- independent in its own Root / Registrar / Discovery / CDN architecture

Potential complementary points:

- domestic AIP may define or influence higher-level Agent interconnection terminology and framework modules
- OpenAgentNet can operationalize and validate registration, authorization, discovery, and trusted invocation flows in runnable code
- domestic AIP identity, description, discovery, interaction, and tool invocation concepts can be mapped to OpenAgentNet DID Documents, Registrar Nodes, Discovery Nodes, Agent invocation, and MCP/A2A-compatible endpoint metadata
- OpenAgentNet's Root / Registrar / Discovery / CDN role separation can be used as a deployment and governance reference pattern
- OpenAgentNet's capability tree and custom tag model can support semantic discovery experiments
- OpenAgentNet's multi-node demos can support interoperability testing and deployment-oriented validation
- future OpenAgentNet SDKs can provide developer-facing implementation support for AIP-compatible flows where appropriate
- OpenAgentNet can serve as a neutral infrastructure layer where AIP-compatible Agents, services, and tools can be registered, discovered, and verified
- OpenAgentNet can verify AIP-compatible Agent identity and credentials before the Agent enters actual interaction or tool invocation flows

Collaboration direction:

- maintain a domestic AIP to OpenAgentNet concept mapping
- align terminology where domestic AIP terminology is already strong
- design examples that demonstrate AIP-compatible registration, discovery, and Agent interaction concepts without changing OpenAgentNet's core architecture
- propose joint validation scenarios around trusted registration, Discovery synchronization, and Agent-to-Agent pre-connection verification
- present OpenAgentNet as an open infrastructure base and implementation reference that can support AIP-compatible ecosystem development while preserving its own architecture
- provide adapter SDK guidance for AIP-compatible endpoint metadata, registration, Discovery lookup, credential verification, and pre-connection checks
- focus OpenAgentNet's AIP-related work on how AIP-compatible Agents enter and benefit from trusted registration, discovery, verification, and governance infrastructure

### 3.3 ANP

ANP should be treated as an important domestic-friendly interoperability reference.

OpenAgentNet and ANP can coexist as complementary routes. ANP can provide Agent network protocol concepts and interaction references, while OpenAgentNet can provide an infrastructure base for Root-governed trust, Registrar-assisted onboarding, verifiable distribution, and Discovery-node collaboration around compatible Agent metadata and endpoints.

OpenAgentNet does not need to reproduce ANP's interaction protocol scope. A stronger route is to make ANP-compatible Agents first-class participants in the OpenAgentNet ecosystem through endpoint metadata, Discovery indexing, credential verification, and adapter SDK support.

Potential complementary points:

- ANP can provide Agent network protocol concepts and interaction patterns
- OpenAgentNet can provide trusted registration, authorization, distribution, and Discovery-node collaboration around those concepts
- ANP Agent descriptions can be mapped to OpenAgentNet DID Document service metadata where fields are compatible
- OpenAgentNet Discovery Nodes can index Agents that expose ANP-compatible endpoints
- OpenAgentNet Agent-to-Agent pre-connection verification can be used before ANP-style interactions
- OpenAgentNet Root bulletin can provide infrastructure authorization context that ANP-style participants may reference
- OpenAgentNet can provide registration, discovery, and verification infrastructure for Agents that expose ANP-compatible interaction capabilities
- OpenAgentNet adapter SDKs can help ANP-compatible Agents register, publish endpoint metadata, query Discovery, and perform pre-connection verification

Collaboration direction:

- maintain an ANP to OpenAgentNet concept mapping
- support ANP endpoint metadata in Agent DID Documents if technically feasible
- prepare a demo where an OpenAgentNet-discovered Agent advertises ANP-compatible interaction capability
- keep ANP integration optional so OpenAgentNet remains protocol-neutral
- use public language that makes coexistence and cooperation natural
- keep OpenAgentNet's base-layer contribution clear: ANP compatibility is one supported route, not the full definition of OpenAgentNet
- provide adapter SDK examples that let ANP-compatible Agents enter OpenAgentNet without changing the ANP interaction layer itself

### 3.4 DNS-Native Agent Naming and Resolution

DNS-SD, DNS-AID, DN-ANR / DNS-ANR, and AgentDNS represent DNS-native or DNS-inspired Agent naming and resolution directions.

These systems often emphasize:

- reuse of existing DNS infrastructure
- low deployment friction
- natural caching
- domain-based ownership
- DNSSEC-based verification where available
- SVCB, TXT, TLSA, or similar DNS records for endpoint discovery

OpenAgentNet can interoperate with DNS-native systems while providing the higher-level infrastructure needed for governance, verification, and semantic discovery:

- Root authorization
- Registrar-assisted registration
- Discovery authorization by domain sets
- DID Document verification
- VC-compatible credentials
- capability tree governance
- CDN distribution and independent verification
- semantic discovery beyond endpoint lookup

Collaboration direction:

- design a DNS-native compatibility profile
- document how `did:ans` may relate to domain names, DNS records, or Agent identifiers
- support DNS-native resolution as an optional discovery source
- keep complex credentials, Root proofs, and semantic tags in layers that are suitable for verification and governance
- make OpenAgentNet Discovery richer than endpoint lookup while still consuming DNS-native hints where useful

### 3.5 Agent Name Service Projects

GoDaddy ANS and Cisco / OWASP ANS v1 represent Agent Name Service or secure Agent discovery directions.

ANS-type projects often focus on:

- Agent names
- Agent registry
- endpoint discovery
- certificates or PKI
- domain binding
- protocol adapters for MCP, A2A, or related protocols
- secure Agent discovery

OpenAgentNet can learn from and interoperate with this direction while preserving a broader infrastructure scope and a stronger ecosystem governance role:

- Root / Registrar / Discovery / CDN role separation
- DID Document version archive
- Root bulletin governance
- Discovery authorized domain sets
- capability tree governance
- multiple independent Registrar and Discovery operators
- verifiable CDN distribution
- standardization and industry collaboration positioning

Collaboration direction:

- provide a clear Agent identifier profile
- explain how `did:ans`, domain names, and service endpoints relate
- support ANS-like naming as one possible identifier form if useful
- describe OpenAgentNet as broader than an Agent Name Service
- use the phrase "trusted registration, distribution, and discovery infrastructure" to clarify the broader scope

### 3.6 NANDA and Other Agent Network Infrastructure Projects

NANDA and similar projects explore broad Agent network infrastructure, including discovery, identity, interoperability, and possibly reputation or interaction history.

OpenAgentNet should treat these projects as important international references and possible interoperability partners, while continuing to develop its own base-layer trust and discovery architecture.

OpenAgentNet's current design makes one clear choice: Root does not maintain Agent reputation, evaluation, or invocation history. Discovery Nodes may collect such data to provide differentiated services. This allows OpenAgentNet to keep the Root trust core focused while leaving room for richer Discovery ecosystems.

Collaboration direction:

- track registry, resolver, SDK, reputation, and interaction-history designs
- compare OpenAgentNet Discovery extensibility with related discovery systems
- explore shared test scenarios where useful
- keep OpenAgentNet modular enough to absorb external protocol compatibility

## 4. OpenAgentNet's Contribution to the Ecosystem

### 4.1 A Runnable Reference Implementation

Many Agent Internet discussions are still conceptual. OpenAgentNet contributes a concrete infrastructure implementation that can be run, tested, modified, and demonstrated.

The current reference implementation includes:

- Rust infrastructure services
- Python demo Agents
- DID Document registration
- W3C VC-compatible credential direction
- Root authorization
- bulletin events
- CDN synchronization
- Discovery synchronization
- signed Discovery responses
- signed Agent-to-Agent invocation
- multi Registrar and multi Discovery examples
- tests and negative cases

This implementation-driven approach can help standards, research, and industry pilots move from discussion to verification while giving OpenAgentNet a credible foundation role in the ecosystem.

### 4.2 A Trust and Governance Pattern

OpenAgentNet provides a clear trust and governance pattern:

- Root authorizes infrastructure participants
- Registrar Nodes assist Agent onboarding and issue credentials
- Root verifies complete DID Documents and archives versions
- Root synchronizes verified packages to CDN
- Root notifies authorized Discovery Nodes after CDN synchronization
- Discovery Nodes verify Root proof and bulletin references
- Agents verify credentials and signatures before trusted interaction

This pattern can be used as a reference and reusable base even by projects that choose different transport or naming protocols.

### 4.3 A Semantic Discovery Foundation

OpenAgentNet uses a capability tree as an initial shared semantic basis for coarse discovery, while allowing custom tags for fine filtering.

This creates a practical balance:

- standard tags support network-wide interoperability
- custom tags support local innovation and domain-specific expression
- Discovery Nodes can provide differentiated semantic search and ranking
- Root can govern shared semantic resources without controlling every Discovery policy

### 4.4 A Multi-Role Ecosystem Model

OpenAgentNet separates the roles of Root, Registrar, Discovery, CDN, Service Agent, and User Agent.

This enables an ecosystem where different organizations can participate in different ways:

- operate Registrar Nodes
- operate Discovery Nodes
- provide CDN services
- build SDKs
- build Agent adapters
- provide industry capability tags
- run interoperability tests
- build web consoles
- contribute security reviews

The goal is not a single monolithic platform, but a loosely coupled infrastructure base with shared trust and interoperability contracts.

## 5. Public Collaboration Agenda

OpenAgentNet welcomes collaboration in the following areas.

### 5.1 Protocol Mapping and Compatibility

Useful contributions include:

- MCP endpoint metadata examples
- A2A endpoint metadata examples
- ANP compatibility notes
- domestic AIP concept mapping
- DNS-native compatibility profile
- Agent identifier profile
- common test vectors

### 5.2 SDKs and Developer Experience

Useful contributions include:

- Rust core SDK
- TypeScript client and web SDK
- Python Agent adapter SDK
- protocol adapter SDKs for ANP, A2A, MCP, AIP-compatible flows, and future interaction protocols
- CLI tools
- framework adapters
- demo Agents
- integration examples

The SDK roadmap should make OpenAgentNet's protocol-neutral infrastructure position practical. SDKs should help protocol implementers and Agent developers:

- publish protocol endpoint metadata in DID Documents
- store and select local credentials
- query Discovery Nodes
- verify Root proof and bulletin references
- verify Agent credentials before interaction
- sign and verify pre-connection request and response envelopes
- enter the OpenAgentNet ecosystem without replacing the Agent's chosen interaction protocol

### 5.3 Discovery and Semantic Governance

Useful contributions include:

- capability tree improvement
- industry capability tags
- custom tag best practices
- semantic search experiments
- Discovery ranking extensions
- multilingual labels
- interoperability tests for Discovery responses

### 5.4 Security and Trust

Useful contributions include:

- DID Document validation
- credential verification
- request and response signing
- replay protection
- Root proof verification
- bulletin event verification
- key rotation guidance
- threat modeling
- negative test cases

### 5.5 Deployment and Operations

Useful contributions include:

- Docker Compose examples
- Kubernetes deployment templates
- monitoring and health checks
- backup and restore guidance
- multi-node deployment examples
- production hardening notes

## 6. Suggested Public Statements

For general positioning:

> OpenAgentNet is an open-source infrastructure foundation and reference implementation for trusted Agent registration, governance, distribution, discovery, and pre-connection verification. It is designed to interoperate with Agent communication protocols, tool protocols, naming systems, and discovery systems while providing a clear trust and governance base for Agent interconnection.

For MCP and A2A:

> OpenAgentNet complements MCP and A2A by providing the trusted registration, discovery, governance, and verification infrastructure around Agents that may use MCP, A2A, or other interaction protocols.

For domestic AIP:

> OpenAgentNet seeks common ground with domestic AIP. Domestic AIP can provide important standardization terminology and interconnection framework guidance, while OpenAgentNet can contribute an open infrastructure base, runnable trusted registration flows, Discovery synchronization, adapter SDK guidance, and interoperability test cases for AIP-compatible Agents.

For ANP:

> OpenAgentNet and ANP can coexist as complementary routes. ANP can provide Agent network protocol concepts and interaction references, while OpenAgentNet can provide an infrastructure base and adapter SDK path for Root-governed trust, Registrar-assisted onboarding, verifiable distribution, Discovery-node collaboration, and pre-connection verification around ANP-compatible Agents.

For interaction protocol neutrality:

> OpenAgentNet does not define a full Agent interaction protocol system. It enables Agents that use ANP, A2A, MCP, AIP-compatible flows, or future interaction protocols to be registered, discovered, verified, and connected through a trusted infrastructure base.

For DNS-native systems:

> DNS-native systems are useful for Agent naming and resolution. OpenAgentNet can interoperate with them while providing a higher-level infrastructure layer for registration governance, credential verification, semantic discovery, and authorized distribution.

For ANS-type systems:

> ANS systems focus on Agent naming and secure discovery. OpenAgentNet extends the scope to a broader infrastructure base for multi-role ecosystem governance, Registrar-assisted onboarding, Discovery authorization, CDN-backed verifiable distribution, and capability tree governance.

## 7. Near-Term Roadmap Suggestions

Recommended actions for the next stage:

1. Create a protocol landscape and comparison matrix.
2. Add MCP and A2A endpoint metadata examples to Agent DID Documents.
3. Define an Agent identifier profile for `did:ans`, domain names, and endpoint references.
4. Draft a DNS-native compatibility profile.
5. Maintain a domestic AIP to OpenAgentNet concept mapping.
6. Maintain an ANP to OpenAgentNet interoperability note.
7. Prepare cooperative positioning language for ANP and domestic AIP.
8. Define an interaction protocol neutrality profile for ANP, A2A, MCP, AIP-compatible flows, and future protocols.
9. Publish an OpenAgentNet infrastructure positioning note for public-interest, enterprise, developer, and user value.
10. Extract shared SDK foundations and publish test vectors.
11. Strengthen Discovery verification and query examples.
12. Keep multi-node demos and integration tests passing as the engineering reliability baseline.

## 8. Summary

OpenAgentNet is part of a broader Agent Internet exploration. It should grow through cooperation, interoperability, and implementation-driven contribution while steadily developing into an open infrastructure base for trusted Agent interconnection.

The preferred ecosystem stance is:

- complement MCP and A2A
- seek common ground with domestic AIP
- coexist and interoperate with ANP
- remain neutral to Agent interaction protocols while providing adapter SDKs
- interoperate with DNS-native naming and resolution where useful
- learn from ANS-type systems
- track NANDA and other Agent network infrastructure projects
- keep OpenAgentNet's own strengths clear through runnable trusted registration, governance, distribution, discovery, and pre-connection verification infrastructure

At the early stage of the Agent Internet ecosystem, the best strategy is to make the shared ecosystem larger while keeping OpenAgentNet's infrastructure ambition clear. OpenAgentNet should become a bridge, interoperability testbed, implementation foundation, and trusted base layer that helps more participants join the Agent Internet while preserving its own clear architectural contribution.
