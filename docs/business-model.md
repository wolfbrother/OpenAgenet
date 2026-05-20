<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet Ecosystem Business Model

This document analyzes possible revenue models for Root Node, Registrar Node, and Discovery Node in the OpenAgentNet ecosystem. It is a business design document only. No business charging logic should be implemented in the current Rust services.

## 1. Principles

The business model should support long-term operation without increasing protocol friction.

Core principles:

1. Root Node should not charge Service Agents or User Agents directly.
2. Root Node should mainly settle with infrastructure operators such as Registrar Node operators, Discovery Node operators, authorized VC issuers, governance organizations, and large ecosystem operators.
3. Root Node should not turn every Agent registration or update into an interruptive payment step.
4. Registrar Node may charge Agent operators for onboarding, compliance, credential issuance, and managed registration services.
5. Discovery Node may charge User Agents, applications, orchestration systems, and enterprise platforms for discovery, indexing, ranking, and SLA services.
6. Fees should be quota-based, package-based, subscription-based, or batch-settled where possible.
7. Commercial policy must not change protocol facts such as Root proof, bulletin status, DID Document hash, metadata hash, or revocation state.

CDN Service is a traditional commercial distribution service. It is not an authorized OpenAgentNet node and is not a trust source. CDN costs may be paid by Root operator, Registrar operators, Discovery operators, or enterprise customers through separate commercial contracts.

## 2. What Should Not Be Sold

OpenAgentNet should not sell trust conclusions as arbitrary business labels.

Root should not sell claims such as:

- This Agent is high quality.
- This Agent is recommended.
- This Agent has better reputation.
- This Agent should rank higher.

Root can only publish verifiable protocol facts:

- A node is authorized or revoked.
- An Agent DID Document is anchored or updated.
- A DID Document hash matches a submitted document.
- A verified package was produced by Root.
- A bulletin event exists and is signed by Root.
- A capability tag tree version is active.

Reputation, evaluations, call history, service quality scores, complaints, latency, and task success rates belong to Discovery-local or marketplace-local value-added services. They must be clearly separated from Root trust status.

## 3. Root Node Revenue Model

Root Node is the trust management, data distribution, and semantic governance hub. Its value comes from operating ecosystem governance infrastructure, not from high-frequency user traffic.

### 3.1 Customers

Root Node customers may include:

- Registrar Node operators
- Discovery Node operators
- third-party VC issuers
- industry governance organizations
- large enterprise ecosystem operators
- audit, compliance, and regulatory service users

Root should avoid direct billing relationships with individual Service Agents and User Agents.

### 3.2 Revenue Packages

Root fees should be consolidated into a small number of packages.

#### Node Authorization Package

Covers:

- Registrar authorization
- Discovery authorization
- VC issuer authorization
- authorization state maintenance
- revocation and recovery workflows
- bulletin publication for authorization events

Rationale:

Infrastructure operators receive long-term value from being recognized by the ecosystem. Charging at the infrastructure level lowers friction for individual Agents.

#### Trusted Infrastructure Package

Covers:

- DID Document verification quota
- bulletin event publication
- multi-version archive
- verified package generation
- CDN publish queue processing
- Discovery notification queue processing

Rationale:

Root bears verification, archive, signing, and distribution coordination costs. These costs should be settled in aggregate rather than charged on every individual Agent action.

#### Semantic Governance Package

Covers:

- capability tag tree maintenance
- industry taxonomy extension
- alias management
- tag deprecation and migration
- Discovery `authorizedDomains` governance
- tag tree version bulletin events

Rationale:

Capability taxonomy governance is a shared ecosystem resource. Discovery and Registrar operators benefit from consistent semantics.

#### Audit And Compliance Package

Covers:

- historical bulletin queries
- authorization status proofs
- Agent registration history proofs
- node audit reports
- compliance exports
- regulatory reporting support

Rationale:

Enterprises and governance bodies may need proof material and auditability beyond normal protocol operation.

#### Advanced Distribution Policy Package

Covers:

- high-priority security update distribution
- low-latency batch publication
- Root-signed access token policy
- Root-signed URL policy
- private distribution policy support

Rationale:

Some ecosystems need controlled distribution. Root can decide access policy while CDN executes it.

### 3.3 Single Submission Fee

Root may charge Registrar operators a small per-submission fee for each Agent DID Document submitted by a Discovery/Registrar workflow, including first registration and updates. A possible reference price is 0.1 RMB per submission.

However, this should not be a direct Agent-facing checkout step. It is better handled through Registrar quota packages, monthly settlement, or prepaid submission pools.

If an Agent does not need ecosystem-wide distribution, it may choose not to submit to Root. This preserves flexibility and avoids forcing every Agent into the global trust/distribution path.

## 4. Registrar Node Revenue Model

Registrar Node is the main commercial interface for Service Agent operators.

### 4.1 Customers

Registrar customers may include:

- Service Agent developers
- Agent platform operators
- enterprise Agent teams
- vertical industry Agent providers
- managed service providers

### 4.2 Revenue Points

Registrar may charge for:

- Agent onboarding
- DID Document creation assistance
- DID Document validation
- credential issuance and local storage support
- Root submission service
- update management
- compliance review before submission
- managed key rotation support
- recovery support
- private registration workflow for Agents not submitted to Root

### 4.3 Rationale

Registrar Node reduces the technical burden for Agent operators. It packages Root-facing complexity into a developer-friendly or enterprise-friendly service.

Registrar can absorb Root costs into subscription, quota, or service packages. This avoids forcing individual Agents to pay Root directly.

## 5. Discovery Node Revenue Model

Discovery Node provides user-facing and application-facing discovery value. It can compete on search quality, coverage, ranking, latency, enterprise integration, and vertical specialization.

### 5.1 Customers

Discovery customers may include:

- User Agents
- application platforms
- enterprise orchestration systems
- vertical search providers
- marketplaces
- workflow automation platforms

### 5.2 Revenue Points

Discovery may charge for:

- API query volume
- high-availability discovery service
- enterprise SLA
- private indexes
- vertical industry indexes
- advanced semantic search
- ranking customization
- local reputation and evaluation signals
- analytics and reporting
- compliance filtering
- integration with enterprise identity and policy systems

### 5.3 Discovery-Local Signals

Discovery may collect and maintain local data such as:

- user ratings
- task success rate
- historical availability
- latency
- complaint records
- enterprise preference signals
- marketplace evaluation data

These signals can improve ranking and user experience. They are not Root trust status and must not override Root revocation or missing Root anchor.

## 6. Third-Party VC Issuers

Third-party VC issuers may provide specialized attestations, such as compliance, domain qualification, security certification, organization identity, or industry credentials.

Constraints:

- VC issuers must be authorized by Root before their credentials are recognized by the ecosystem.
- VC issuer authorization status must be published on the bulletin.
- Agents, Discovery Nodes, and Registrar Nodes may hold multiple credentials from multiple issuers and multiple dimensions.
- Credential storage is local in the current design.
- VC issuer business implementation is out of scope for the MVP.

Possible revenue points for VC issuers:

- credential issuance
- credential renewal
- audit support
- compliance verification
- organization identity verification
- specialized domain certification

## 7. CDN Cost Model

CDN is a traditional infrastructure cost center or vendor service.

Possible payment models:

- Root operator pays CDN provider.
- Registrar operators contribute to distribution cost through Root packages.
- Discovery operators pay for high-volume sync and data access.
- Enterprises pay for private or high-SLA distribution.

CDN revenue must not be confused with trust. CDN cannot replace Root proof, hash verification, or bulletin status verification.

## 8. Recommended MVP Business Posture

For the open-source MVP:

- Do not implement billing logic.
- Do not add payment checks to protocol flows.
- Keep Root, Registrar, Discovery, and CDN fully runnable locally.
- Keep business model documentation separate from code.
- Use logs and metrics only for observability, not billing enforcement.

Recommended future commercial direction:

- Root charges infrastructure operators, not individual Agents.
- Registrar charges Agent operators for onboarding and managed registration.
- Discovery charges applications and enterprises for discovery quality and SLA.
- VC issuers charge for specialized credentials.
- CDN is handled as traditional infrastructure cost.

## 9. Summary

A healthy OpenAgentNet ecosystem should minimize friction for Agent registration, updates, discovery, and invocation. Root should remain a neutral governance and trust infrastructure layer. Registrar and Discovery Nodes can provide market-facing services, while Root preserves verifiable protocol facts and semantic governance.

