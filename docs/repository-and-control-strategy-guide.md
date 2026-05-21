<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Repository and Control Strategy Guide

This document is a practical guide for structuring OpenAgentNet across
multiple repositories while preserving long-term governance clarity, release
consistency, and ecosystem continuity.

## 1. Goal

The project should remain easy to try, while deeper changes continue to require
clear coordination and compatibility work.

The preferred shape is:

- a small number of personally stewarded core repositories
- a larger organization-owned collaboration layer
- a stable set of public release artifacts and conformance rules

This keeps the project open to collaboration while preserving a coherent path
for protocol evolution, governance, and reference implementation updates.

## 2. Stewardship Principles

1. Steward the standard, not just the code.
2. Steward the release keys, not just the source tree.
3. Steward the governance path, not just the runtime.
4. Steward the compatibility suite, not just the demo.
5. Keep trial use simple, while deeper replacement still requires coordination.

The most important stewardship points are:

- canonical specs and schemas
- bulletin and authorization governance
- reference implementation release signing
- compatibility and conformance tests
- bootstrap and demo entry points
- official documentation and routing domains

## 3. Recommended Repository Layers

### 3.1 Personal Repositories

Keep the deepest and hardest-to-replace layers in repositories owned by your
personal GitHub account, so the foundation remains stable over time.

Good candidates:

- protocol core libraries
- DID / VC canonical schema generators
- bulletin contract and chain adapters
- release signing and package publishing tools
- capability tree tooling
- conformance test harnesses

These repositories should evolve under your direct stewardship and act as the
foundation for all higher layers.

### 3.2 Organization Repositories

Use the organization account for collaborative and product-facing layers.

Good candidates:

- reference services
- demo agents
- web consoles
- deployment scripts
- integration examples
- operator documentation
- SDK wrappers

These repositories can accept contributors, issue tracking, and team-level
collaboration without affecting the core governance plane.

### 3.3 Public Release Artifacts

Separate source control from public consumption.

Examples:

- `crates` releases
- `npm` packages
- container images
- protocol schemas
- signed release manifests

Public consumers should rely on versioned artifacts, not ad hoc branch state.

## 4. Suggested Split

### Personal-owned core

- protocol core
- bulletin contract
- schema definitions
- compatibility suite
- release signing tools
- chain and governance adapters

### Organization-owned collaboration

- Root / Registrar / Discovery / CDN reference services
- demo Service Agent / User Agent
- web UI and admin tools
- deployment and bootstrap scripts
- operational docs

### Public surfaces

- docs site
- package registries
- release archives
- signed demo bundles

## 5. What Must Stay Under Personal Control

These are the highest-leverage stewardship points:

- canonical protocol definitions
- bulletin write rules
- authorization semantics
- versioned capability tree source
- release signing keys
- package namespace ownership
- compatibility suite ownership
- official reference documentation

If these remain under personal stewardship, the ecosystem can collaborate
without losing a stable center of gravity.

## 6. What Can Be Shared More Freely

These layers are good candidates for organization ownership and community work:

- service implementations
- demo agents
- UI surfaces
- deployment automation
- adapter examples
- operator runbooks
- test fixtures

These parts benefit from broader participation and do not need to carry the
long-term control burden.

## 7. Operational Rules

1. Keep the core repositories small and explicit.
2. Avoid hiding governance in runtime quirks.
3. Prefer versioned interfaces over implicit coupling.
4. Require signed releases for official adoption.
5. Make conformance tests part of the acceptance path.
6. Keep demo onboarding easy.
7. Make production-level replacement require coordination.

## 8. Migration Strategy

When a repository moves from personal ownership to organization ownership:

1. freeze the current canonical release
2. publish a signed compatibility statement
3. keep the core interfaces stable
4. move only the collaboration layer
5. retain the canonical release authority in the personal core where needed

This avoids a hard break in the ecosystem and prevents silent governance drift.

## 9. Practical Default Layout

Recommended default:

- personal repos hold the protocol and control plane
- organization repos hold the service and collaboration plane
- public registries hold released artifacts only

This is the safest structure if the project is expected to grow into a real
community effort while still preserving individual stewardship of the
foundation.

## 10. Decision Test

Before placing something into an organization repo, ask:

- Does this define the standard?
- Does this sign or authorize releases?
- Does this control upgrade compatibility?
- Does this define governance or bulletin semantics?
- Would moving this repo later require community-wide coordination?

If the answer is yes, it probably belongs in the personal core layer.

## 11. Summary

Use the personal account for the bedrock, the organization for collaboration,
and package registries for public distribution.

That structure keeps the project open to contributors while preserving a clear
path for standards, releases, and long-term evolution.
