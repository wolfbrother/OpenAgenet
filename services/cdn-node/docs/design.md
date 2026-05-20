<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# CDN Service Design

## 1. Positioning

CDN Service is the traditional content distribution layer for OpenAgentNet. It caches and serves Root-verified DID Documents, metadata, verified packages, and manifests.

CDN Service is not an authorized `did:ans` infrastructure node. It is not trusted as a protocol authority. It may be operated by the Root operator or outsourced to a commercial CDN/object-storage provider.

## 2. Configuration and Storage

Config file: `services/cdn-node/config.example.toml`

Current inputs:

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

Current Rust MVP reads from `data_dir` and uses the following layout:

```text
manifest.json
documents/
metadata/
packages/
```

CDN does not discover other nodes from the bulletin. Root publishes CDN service information into the bulletin so Discovery and clients can find CDN.

## 3. HTTP APIs

Current APIs:

```text
GET  /health
GET  /cdn/manifest
GET  /cdn/updates
POST /cdn/packages
GET  /cdn/packages/{did}
GET  /cdn/documents/{did}
GET  /cdn/metadata/{did}

GET  /api/v1/cdn/status
GET  /api/v1/cdn/packages
GET  /api/v1/cdn/packages/{did}
GET  /api/v1/cdn/documents/{did}
GET  /api/v1/cdn/metadata/{did}
GET  /api/v1/cdn/manifest/stats
GET  /api/v1/cdn/publish/history
POST /api/v1/cdn/purge
```

These APIs are enough for future operator consoles and for Discovery sync logic.

## 4. Publish Flow

1. Root sends a verified package
2. CDN stores DID Document, metadata, and package objects
3. CDN updates the manifest
4. CDN serves the material by DID

Current MVP does not yet enforce Root allowlists, signed URLs, or token-based access control. That is future work.

## 5. Trust Boundary

CDN is not the final source of trust. Clients must verify:

- Root proof
- DID Document hash
- metadata hash
- bulletin event existence
- revocation status

CDN can carry data, but it does not make data trustworthy by itself.

## 6. Test Coverage

Current codebase status:

- `cargo check --workspace` passes
- `cargo test --workspace` passes
- CDN has basic storage and publish behavior in code
- the new management APIs still need direct endpoint tests

## 7. Next Steps

- add API tests for manifest stats, package detail, and purge endpoints
- add Root authentication enforcement for publishes
- add update history and incremental manifest support
