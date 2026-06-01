# OAN Protocol Common

Common protocol crates for OpenAgenet / OAN.

This repository is intended to hold reusable Rust crates for the stable protocol
surface shared by OAN services, SDKs, conformance tests, release tooling, and
third-party implementations.

## Purpose

`oan-protocol-common` should provide low-level, runtime-independent protocol
building blocks:

- `did:ans` types, parsing, and validation
- protocol data models and version constants
- DID Document and credential structures
- canonical JSON, hashing, signing, and verification helpers
- trusted invocation envelope structures
- discovery response and verified package models
- common error types and validation results
- test vectors and schema-oriented helpers where appropriate

The crate set should remain lightweight and avoid coupling the protocol layer to
specific service runtimes.

## Out of Scope

The common protocol layer should not contain:

- Axum HTTP handlers
- Tokio service orchestration
- SQL database logic
- full Root, Registrar, Discovery, or CDN implementations
- deployment scripts
- business-agent workflows
- UI or CLI application logic

Those belong in organization-owned implementation, SDK, adapter, and deployment
repositories.

## Recommended Workspace Shape

The preferred shape is one GitHub repository publishing multiple crates:

```text
crates/
  oan-did-ans/
  oan-crypto/
  oan-credentials/
  oan-protocol/
  oan-protocol-common/
```

The smaller crates can be used directly by advanced implementers. The
`oan-protocol-common` crate can act as a facade crate that re-exports the common
protocol pieces for simpler dependency management.

## Publishing Model

Each crate should be publishable to crates.io with explicit versions. Local
workspace dependencies should include both `path` and `version` so crates can be
developed together and published independently.

Official release artifacts should be generated and verified through
`oan-release-tools` once the release process is stable.
