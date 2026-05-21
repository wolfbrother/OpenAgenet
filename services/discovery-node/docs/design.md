<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Discovery Node Detailed Design

## 1. Role

Discovery Node serves User Agents, applications, and enterprise orchestration systems. It indexes Root-verified Agent packages and returns queryable candidates.

Discovery Node is not a business Agent. It is an infrastructure node and must use `ansMetadata.subjectType = "infrastructure-node"`.

Discovery may maintain local reputation, evaluation, history, or enterprise preference signals. These are local Discovery signals only and do not override Root trust facts.

## 2. Current Implementation

The Rust MVP implements:

- Root bulletin fetch
- CDN service discovery from bulletin
- CDN manifest and package sync
- DID Document hash verification
- metadata hash verification
- Root proof signature verification
- bulletin hash-chain verification
- package bulletin event existence verification
- Root authorization status extraction
- `authorizedDomains` filtering
- local capability index
- simple discovery query
- query explain API
- signed discovery responses
- rejected package records
- sync history
- SQLite-backed index mirrors

Discovery indexes both canonical capability-tree tags and custom tags. Canonical tags support coarse discovery and authorization-domain routing. Custom tags support fine filtering after a package is eligible for the Discovery Node.

## 3. Configuration

Config file:

```text
services/discovery-node/config.example.toml
```

Important inputs:

```text
[server]
host
port

[upstream]
root_endpoint
cdn_endpoint

[paths]
data_dir
index_dir
keys_dir
credentials_dir
database_url
```

Runtime CDN discovery:

1. fetch Root bulletin from `root_endpoint`
2. verify or inspect latest CDN service event
3. extract `manifestUrl`, package URL template, and base URL
4. use bulletin CDN data first
5. use configured CDN endpoint only as fallback

CDN location data is not CDN trust.

## 4. APIs

Protocol APIs:

```text
GET  /health
GET  /discovery/did
POST /discovery/sync
POST /discover/query
GET  /routes/{did}
```

Management and web-support APIs:

```text
GET  /api/v1/discovery/status
GET  /api/v1/discovery/root-authorization
GET  /api/v1/discovery/authorized-domains
POST /api/v1/discovery/sync
GET  /api/v1/discovery/sync/history
GET  /api/v1/discovery/index/stats
GET  /api/v1/discovery/index/agents
GET  /api/v1/discovery/index/agents/{did}
POST /api/v1/discovery/query
POST /api/v1/discovery/query/explain
GET  /api/v1/discovery/rejected-packages
GET  /api/v1/discovery/capability-tree
```

These APIs are intended to support future discovery websites and operator consoles.

## 5. Sync Flow

Discovery sync performs:

1. fetch Root bulletin
2. derive Root DID and Root key information
3. resolve CDN service information from bulletin
4. download CDN manifest
5. download verified packages
6. verify DID Document hash
7. verify metadata hash
8. verify Root proof signature
9. verify bulletin hash chain
10. verify package bulletin event presence
11. reject non-Agent packages
12. filter by Discovery `authorizedDomains`
13. persist accepted packages into JSON and SQLite indexes
14. persist rejected package reasons
15. persist sync history

Discovery must not return unanchored, invalid, or Root-revoked Agents as trusted candidates.

## 6. Query Flow

Query input supports:

- `capabilityTags`
- `serviceType`
- `protocol`
- `limit`

The current scoring is intentionally simple. Semantic retrieval is out of scope for the current MVP. Future semantic engines can sit behind the same query API.

The `query/explain` endpoint returns match details for UI debugging and operator review.

## 7. Signed Responses

Discovery signs query responses with its local DID key. User Agents can verify that the candidate set came from the Discovery Node they queried.

The Discovery signature does not prove Agent service quality. It proves the Discovery response came from that Discovery Node over its current local index.

## 8. Authorized Domains

Discovery authorization is governed by Root bulletin events. `authorizedDomains` limits which Agent packages a Discovery Node may index.

Rules:

- `*` matches all canonical domains
- canonical capability-tree tags support subtree matching
- custom tags do not expand Root authorization scope
- custom tags remain queryable after a package passes coarse domain eligibility

## 9. Local Data

Representative local data:

```text
data/discovery/did-document.json
data/discovery/keys/keypair.json
data/discovery/credentials/node-authorization.json
data/discovery/credentials/by-dimension/
data/discovery/index/capabilities.json
data/discovery/index/rejected-packages.json
data/discovery/index/sync-history.json
data/discovery/discovery.db
```

JSON files remain readable artifacts. SQLite is the operational lookup index.

## 10. Tests

Current tests cover:

- authorized-domain filtering
- Root proof verification
- bulletin event presence verification
- response signing
- status API behavior
- query explain behavior
- revocation status detection

The repository passes:

```text
cargo test --workspace
```

## 11. Next Work

- verify Discovery self-authorization at startup and during sync
- add package freshness and version ordering checks
- enrich rejected package persistence
- add optional local ranking and evaluation indexes
- add semantic retrieval integration behind the existing API
- migrate namespace JSON SQLite records to relational schemas
