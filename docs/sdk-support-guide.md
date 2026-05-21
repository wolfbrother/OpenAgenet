<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# OpenAgentNet SDK Support Guide

This document defines the recommended SDK roadmap for OpenAgentNet. It is intended to guide future SDK design, repository splitting, language priorities, package boundaries, and developer experience.

## 1. Purpose

OpenAgentNet should not require every integrator to understand DID Documents, W3C VC-compatible credentials, request signing, replay protection, Root bulletin verification, CDN package verification, and Discovery response verification from scratch.

SDKs are required to make OpenAgentNet easy to adopt while keeping the protocol behavior consistent across languages and implementations.

The SDK strategy should serve five goals:

- reduce Agent integration cost
- keep DID, VC, signature, and bulletin verification consistent
- provide reusable clients for infrastructure services
- support web consoles and management tools
- preserve the language-neutral Agent access contract

OpenAgentNet does not require Agents to use a specific programming language. SDKs are convenience and safety layers, not mandatory runtime dependencies.

## 2. SDK Categories

### 2.1 Core Protocol SDK

The Core Protocol SDK should contain protocol-level primitives shared by all roles.

Recommended primary language: Rust.

Responsibilities:

- parse and validate `did:ans` DID Documents
- validate required `ansMetadata` fields
- validate verification methods and service endpoints
- verify W3C VC-compatible credential structure
- verify credential proofs
- create and verify request signatures
- create and verify response signatures
- validate nonce and timestamp envelopes
- validate Root-signed packages
- validate bulletin event references
- validate capability tags against an external capability tree
- expose stable data models for all protocol objects

The Rust implementation should be treated as the most authoritative reference implementation. Other language SDKs should align with its test vectors and data model.

Recommended package names:

- Rust crate: `openagentnet-core`
- NPM package with WASM bindings: `@openagentnet/core`

### 2.2 Agent Adapter SDK

The Agent Adapter SDK should help Service Agents and User Agents join OpenAgentNet with minimal changes to their own business logic.

Recommended initial language: Python.

Responsibilities:

- load local Agent DID Documents
- load local Agent registration credentials
- manage local nonce cache
- sign outbound Agent-to-Agent requests
- verify inbound Agent-to-Agent requests
- verify peer DID Documents and credentials
- verify target DID constraints
- verify timestamps and replay protection
- generate signed Agent responses
- provide middleware for common Python web frameworks
- provide helpers for MCP and A2A integration

The current demo Agents are Python projects managed by `uv`. The Python SDK should preserve that direction and provide a smooth path from demo code to reusable adapter package.

Recommended package names:

- Python package: `openagentnet-agent`
- Optional CLI package: `openagentnet-cli`

### 2.3 Infrastructure Client SDK

The Infrastructure Client SDK should simplify interaction with Root, Registrar, Discovery, and CDN services.

Recommended languages:

- Rust for infrastructure tools and service-side integration
- TypeScript for web consoles and operational dashboards

Responsibilities:

- Root management client
- Registrar management client
- Discovery query client
- CDN package client
- bulletin reader and verifier
- authorization state reader
- package sync helper
- typed error handling
- retry and timeout policy helpers
- test utilities for local multi-node environments

Recommended package names:

- Rust crate: `openagentnet-client`
- NPM package: `@openagentnet/client`

### 2.4 Discovery SDK

The Discovery SDK should help applications search for Agents and verify Discovery results.

Recommended languages:

- TypeScript for web applications
- Python for Agent applications
- Rust for infrastructure and CLI tools

Responsibilities:

- query Discovery Nodes by capability tags
- support standard capability tags and custom tags
- verify signed Discovery responses
- verify Root proof references
- verify bulletin event references
- support pagination and filtering
- normalize Agent summaries for UI display
- expose ranking metadata without enforcing one ranking model

Discovery ranking, reputation, evaluation, and history data are Discovery-side service capabilities. Root does not maintain those data.

### 2.5 Web Console SDK

Registrar and Discovery Nodes are expected to expose web pages in later versions. The Web Console SDK should reduce duplicated business logic in those frontends.

Recommended language: TypeScript.

Responsibilities:

- typed API clients
- DID Document draft builder
- capability tree browser
- capability tag recommendation helpers
- custom tag editor helpers
- registration credential display helpers
- authorization status display helpers
- error-code mapping
- form validation schemas

Recommended package names:

- NPM package: `@openagentnet/web`
- NPM package: `@openagentnet/forms`

## 3. Language Priority

The recommended language priority is:

1. Rust Core Protocol SDK
2. TypeScript Infrastructure and Web SDK
3. Python Agent Adapter SDK
4. Python and TypeScript Discovery clients
5. CLI tools built on the Rust and Python SDKs
6. Community-supported Go, Java, Kotlin, and Swift SDKs

Rust should be used for the deepest protocol logic because it provides strong type safety, high performance, reliable testing, and good suitability for reusable core packages.

TypeScript should be used for web consoles, dashboards, developer tools, and browser-compatible clients.

Python should be used for Agent adapter ergonomics, demos, and compatibility with current AI Agent development workflows.

## 4. Repository Strategy

The SDKs may be split into separate repositories after the reference implementation stabilizes.

Recommended repository layout:

- `openagentnet-core-rs`: Rust core protocol SDK
- `openagentnet-client-rs`: Rust infrastructure client SDK
- `openagentnet-agent-py`: Python Agent adapter SDK
- `openagentnet-sdk-js`: TypeScript clients and web helpers
- `openagentnet-cli`: CLI tools
- `openagentnet-examples`: cross-language examples

The main reference implementation can depend on released SDK packages once they are stable. During early development, shared code may remain inside the main repository to reduce coordination overhead.

## 5. Compatibility Rules

SDKs should follow these compatibility rules:

- protocol data structures must be versioned
- breaking changes must be explicit
- test vectors must be shared across SDKs
- signature algorithms must be declared in data structures
- timestamps must use a single canonical format
- error codes must align with `docs/error-codes.md`
- SDKs must not hide verification failures
- SDKs must expose enough details for audit and debugging

The Rust Core Protocol SDK should publish canonical test vectors for DID Documents, credentials, request signatures, response signatures, Root packages, and Discovery responses.

## 6. Minimum Agent Adapter Contract

Any Agent that wants to participate in OpenAgentNet should be able to perform the following minimum actions through an SDK or equivalent local implementation:

- store its own DID Document
- store one or more local credentials
- select the credential used for a specific interaction
- fetch or receive a peer DID Document
- verify peer credentials before trusted interaction
- sign outbound requests with nonce and timestamp
- reject replayed or expired requests
- verify signed responses
- expose metadata required by MCP or A2A when applicable

The system should continue to allow advanced Agents to implement this contract directly without using an official SDK.

## 7. Development Milestones

### Milestone 1: Extract Shared Rust Core

- move DID Document models into reusable Rust modules
- move credential proof verification into reusable Rust modules
- move request and response signing utilities into reusable Rust modules
- add canonical test vectors
- publish internal crate boundaries

### Milestone 2: Python Agent SDK

- extract reusable code from demo Service Agent and User Agent
- provide local credential storage helpers
- provide trusted invocation middleware
- support `uv`-based examples
- provide Agent-to-Agent hello demo based on the SDK

### Milestone 3: TypeScript Client SDK

- implement typed clients for Root, Registrar, Discovery, and CDN APIs
- implement capability tree loading and browsing helpers
- implement Discovery response verification
- provide frontend-ready validation helpers

### Milestone 4: CLI

- generate DID Document drafts
- validate DID Documents
- issue local test credentials
- register Agent documents through Registrar
- query Discovery
- verify CDN packages
- run local integration checks

### Milestone 5: Community SDK Program

- publish SDK contribution requirements
- publish compatibility test vectors
- add SDK compliance badges
- document community-maintained SDK expectations

## 8. Non-Goals

SDKs should not:

- force one Agent framework
- replace MCP or A2A
- centralize Agent runtime execution
- hide trust decisions from operators
- implement business billing logic
- require Root to observe Agent-to-Agent business traffic

SDKs should make correct integration easier while preserving the loose coupling of the OpenAgentNet architecture.
