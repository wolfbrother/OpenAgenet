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
- SQLite JSON storage helpers exist for indexes and queues.
- The management APIs for Root, Registrar, Discovery, and CDN now exist and are covered by tests.

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
6. SQLite JSON storage helper supports namespace-based upsert/read/delete.
7. Root keeps batch-style CDN publish and Discovery notify queues.
8. Capability tree is loaded from an external JSON file.
9. Expanded `/api/v1` management APIs exist for Root, Registrar, Discovery, and CDN.
10. Direct tests for the new management APIs have been added and verified with `cargo test --workspace`.

## Next Development Work

### 1. Complete Root Authorization State

Root authorization APIs currently append bulletin events. Next work should persist richer local authorization state and credentials:

- Generate and store local node authorization credentials.
- Maintain registrar authorization index.
- Maintain discovery authorization index.
- Maintain VC issuer authorization index.
- Support suspended, revoked, and recovered states.
- Expose authorization status query APIs.

### 2. Strengthen Registration Credential Checks

Root currently verifies credential signature and basic fields. Next checks should include:

- `expiresAt`
- `claims.didDocumentHash`
- credential type allowlist
- credential issuer authorization scope
- replay protection
- request timestamp and nonce
- request-level registrar signature

### 3. Improve Discovery Validation

Discovery currently validates package document hash, Root proof signature, and bulletin event presence. Next checks should include:

- bulletin hash chain verification
- Root bulletin event signature verification for every event
- Agent revoked/suspended status
- `metadataHash`
- package freshness and version ordering
- Discovery self-authorization status at startup and during sync

### 4. Upgrade `authorizedDomains` Matching

Current matching is direct tag or `"*"`. It should use the external capability tree:

- Normalize aliases.
- Match parent-child subtrees.
- Reject unknown authorized domains.
- Reinterpret authorization after capability tree version changes.
- Store `tagTreeVersion` with Discovery authorization state.

### 5. Move Runtime Indexes To SQLite

JSON files should remain audit-friendly artifacts, while SQLite should become the operational index and queue layer.

Root:

- `did_document_versions`
- `latest_did_document_versions`
- `cdn_publish_queue`
- `discovery_notify_queue`
- `authorized_nodes`

Registrar:

- registration records
- submitted document hashes
- credential copies
- Root submission responses

Discovery:

- capability index
- bulletin cache
- sync cursor
- rejected package log
- optional local ranking signals

CDN:

- package index
- manifest entries
- publish history
- access log

### 6. Implement Real Batch Strategy

Root batch handling should become configurable:

- maximum batch size
- maximum delay
- retry policy
- idempotency key
- partial failure handling
- per-Discovery targeted notification based on `authorizedDomains`

### 7. End-To-End Trusted Demo

Build a repeatable demo script:

1. Start Root, Registrar, CDN, and Discovery.
2. Authorize Registrar and Discovery.
3. Register a Service Agent.
4. Root verifies and queues publication.
5. Root publishes to CDN.
6. Discovery syncs from CDN.
7. User Agent queries Discovery.
8. User Agent verifies Discovery response signature.
9. User Agent invokes Service Agent with a signed request.

### 8. Documentation Follow-Up

Keep these docs synchronized with implementation:

- `docs/design.md`
- `docs/TODO.md`
- `services/root-node/docs/design.md`
- `services/registrar-node/docs/design.md`
- `services/discovery-node/docs/design.md`
- `services/cdn-node/docs/design.md`

