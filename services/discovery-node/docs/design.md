<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Discovery Node Design

## 1. Positioning

Discovery Node serves User Agents, applications, and enterprise orchestration systems. It is not a business Agent. It indexes Root-verified Agent packages and returns queryable candidates.

Discovery Node is also an infrastructure node, so its `ansMetadata.subjectType` must be `infrastructure-node`.

Current MVP behavior:

- reads CDN service information from the Root bulletin
- downloads manifest and verified packages from CDN
- verifies package DID Document hash
- filters to `subjectType = agent`
- performs simple tag/service/protocol search
- returns a signed discovery response

## 2. Configuration and Service Discovery

Config file: `services/discovery-node/config.example.toml`

Required inputs:

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
database_url
```

Runtime discovery flow:

1. read `root_endpoint`
2. fetch Root bulletin
3. locate the latest `CDN_SERVICE_INFO_UPDATED` event
4. extract `manifestUrl`, `packagesUrlTemplate`, and `baseUrl`
5. connect to CDN from bulletin data
6. use the config CDN endpoint only as a fallback

The bulletin only tells Discovery where CDN is. It does not trust CDN.

## 3. HTTP APIs

Current APIs:

```text
GET  /health
GET  /discovery/did
POST /discovery/sync
POST /discover/query
GET  /routes/{did}

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

These APIs are intended to support future discovery web pages with minimal frontend business logic.

## 4. Sync and Verification

Discovery sync performs these steps:

1. fetch bulletin from Root
2. resolve CDN service information
3. download manifest
4. download each package
5. verify package DID Document hash
6. verify Root proof against Root DID Document key
7. verify bulletin event existence
8. filter by authorized domains
9. index valid Agent packages

The current MVP verifies the main trust anchors, but full bulletin hash-chain verification and `metadataHash` verification remain future work.

## 5. Query and Explain

Discovery query input currently supports:

- `capabilityTags`
- `serviceType`
- `protocol`
- `limit`

The `query/explain` endpoint returns why each candidate matched or did not match. This is useful for future UI debugging and operator review.

## 6. Local Data

Current storage layout:

```text
data/discovery/did-document.json
data/discovery/keys/keypair.json
data/discovery/credentials/node-authorization.json
data/discovery/index/capabilities.json
data/discovery/index/sync-history.json
```

The MVP still uses JSON files. SQLite migration is reserved for later.

## 7. Ranking Signals

Discovery may collect local ranking signals such as reputation, evaluation, history, or enterprise preference. These are local Discovery signals only. They do not override Root trust state.

Root revocation and missing Root proof always win.

## 8. Test Coverage

Current codebase status:

- `cargo check --workspace` passes
- `cargo test --workspace` passes
- Discovery has unit tests for authorized-domain filtering, Root proof verification, and response signing
- the new management APIs are implemented, but direct HTTP-level tests for all new endpoints still need to be added

## 9. Next Steps

- add tests for status, explain, and capability-tree endpoints
- add stronger bulletin verification
- add metadata hash verification
- move index state to SQLite when the schema is stable
