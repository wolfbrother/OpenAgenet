<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# CDN Service Detailed Design

## 1. Role

CDN Service is the traditional content distribution layer for OpenAgenet. It stores and serves Root-verified DID Documents, metadata, verified packages, manifests, and update data.

CDN is not an authorized `did:ans` infrastructure node and is not a protocol trust authority. It may be operated by the Root operator or outsourced to a commercial CDN/object-storage provider.

Clients and Discovery Nodes trust Root proofs, DID Document hashes, metadata hashes, and bulletin events, not CDN.

## 2. Current Implementation

The Rust MVP implements:

- local manifest serving
- DID Document serving by DID
- metadata serving by DID
- verified package serving by DID
- package publish API used by Root batch flow
- update endpoint
- status API
- package list and detail APIs
- manifest stats API
- publish history API
- purge API

CDN accepts Root-published verified packages in the local MVP. Root authentication enforcement is future work.

## 3. Configuration

Config file:

```text
services/cdn-node/config.example.toml
```

Important inputs:

```text
[server]
host
port

[paths]
data_dir
manifest_file
documents_dir
metadata_dir
packages_dir
database_url
```

Storage layout:

```text
data/cdn/manifest.json
data/cdn/documents/
data/cdn/metadata/
data/cdn/packages/
```

## 4. APIs

Protocol APIs:

```text
GET  /health
GET  /cdn/manifest
GET  /cdn/updates
POST /cdn/packages
GET  /cdn/packages/{did}
GET  /cdn/documents/{did}
GET  /cdn/metadata/{did}
```

Management APIs:

```text
GET  /api/v1/cdn/status
GET  /api/v1/cdn/packages
GET  /api/v1/cdn/packages/{did}
GET  /api/v1/cdn/documents/{did}
GET  /api/v1/cdn/metadata/{did}
GET  /api/v1/cdn/manifest/stats
GET  /api/v1/cdn/publish/history
POST /api/v1/cdn/purge
```

These APIs are enough for Discovery sync and future CDN/operator consoles.

## 5. Publish Flow

1. Root verifies an Agent DID Document and creates a verified package.
2. Root queues the package for CDN publish.
3. Root batch publish sends the package to CDN.
4. CDN stores the package, DID Document, and metadata.
5. CDN updates manifest entries.
6. Root later notifies Discovery Nodes.
7. Discovery fetches the package from CDN and verifies Root proof and hashes.

The intended order is Root-to-CDN publish before Root-to-Discovery notification, so Discovery does not receive package notifications before data is available.

## 6. Trust Boundary

CDN can distribute bytes, but it cannot make bytes trustworthy.

Relying parties must verify:

- DID Document hash
- metadata hash
- Root proof
- Root bulletin event existence
- bulletin hash chain
- Root revocation or suspension status

Future Root-controlled access policy may use tokens or signatures, with CDN executing distribution decisions delegated by Root.

## 7. Local Data

Representative local data:

```text
data/cdn/manifest.json
data/cdn/documents/<did>.json
data/cdn/metadata/<did>.json
data/cdn/packages/<did>.json
```

The current implementation is file-first. SQLite can later store package indexes, publish history, and access logs.

## 8. Tests

Current tests cover:

- status API
- manifest stats
- package detail shape
- purge endpoint shape

The repository passes:

```text
cargo test --workspace
```

## 9. Next Work

- enforce Root authentication for package publish
- add signed URL or token-based access control when Root policy requires it
- add incremental manifest updates
- add publish history persistence
- add CDN access logs
- migrate operational indexes to SQLite schemas

