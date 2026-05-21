<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Root Node Detailed Design

## 1. Role

Root Node is the OAN governance center. It is simultaneously:

- the trust management hub
- the data distribution hub
- the semantic governance hub

Root Node is not a business Agent and does not serve user tasks. It reuses a `did:ans` DID Document to publish its infrastructure identity, public keys, and endpoints. Its DID Document must use `ansMetadata.subjectType = "infrastructure-node"`.

Root does not track Agent reputation, ratings, invocation history, or ranking. Those are Discovery-local or application-local concerns.

## 2. Current Implementation

The Rust MVP implements:

- Registrar and Discovery authorization APIs
- persistent authorization state
- signed bulletin events
- Service Agent DID Document verification
- Registrar-issued registration credential proof verification
- optional request signature verification
- request nonce replay protection
- DID Document archive versioning
- verified package generation
- SQLite-backed CDN publish queue
- SQLite-backed Discovery notification queue
- domain-filtered Discovery notification batches
- Root-to-CDN publish before Discovery notification
- external capability tree loading from `docs/capability-tree-v1.json`
- management APIs for future web consoles

Root accepts complete DID Documents for both first registration and update flows. This keeps Root verification stateless and request-scoped.

## 3. Configuration

Config file:

```text
services/root-node/config.example.toml
```

Important inputs:

```text
[server]
host
port

[paths]
data_dir
keys_dir
bulletin_file
authorization_state_file
capability_tree_file
database_url
archive_dir
verified_packages_dir
cdn_publish_queue_dir
discovery_notify_queue_dir
```

Path resolution follows the repository convention:

1. absolute paths are used directly
2. relative paths are resolved against the current working directory
3. otherwise they are resolved against the config file directory

## 4. APIs

Protocol APIs:

```text
GET  /health
GET  /root/did
GET  /bulletin
POST /root/registrars/authorize
POST /root/discovery-nodes/authorize
POST /root/discovery-nodes/{did}/domains
POST /root/nodes/{did}/revoke
POST /root/agents/verify-and-publish
POST /root/batches/publish-cdn
POST /root/batches/notify-discovery
```

Management APIs:

```text
GET  /api/v1/root/status
GET  /api/v1/root/registrars
GET  /api/v1/root/registrars/{did}
GET  /api/v1/root/discovery-nodes
GET  /api/v1/root/discovery-nodes/{did}
GET  /api/v1/root/agents
GET  /api/v1/root/agents/{did}
GET  /api/v1/root/agents/{did}/versions
GET  /api/v1/root/agents/{did}/versions/{version}
GET  /api/v1/root/queues/cdn-publish
GET  /api/v1/root/queues/discovery-notify
POST /api/v1/root/queues/cdn-publish/run
POST /api/v1/root/queues/discovery-notify/run
GET  /api/v1/root/capability-tree
POST /api/v1/root/capability-tree/validate-tags
GET  /api/v1/root/bulletin/events
GET  /api/v1/root/bulletin/events/{sequence}
```

The management APIs are intended to keep future web console logic thin and data-constrained.

## 5. Verification Duties

Root currently verifies:

- `agentDid` uses valid `did:ans` syntax
- `didDocument.id == agentDid`
- DID Core context exists
- verification methods exist
- authentication methods exist
- assertion methods exist
- service endpoints exist
- `ansMetadata.subjectType == "agent"`
- capability tags are valid strings
- capability-tree tags are recognized as canonical coarse-discovery tags
- custom capability tags are allowed and preserved for fine filtering
- Registrar is authorized and not revoked
- request nonce has not been replayed
- request signature verifies when present
- `registrationCredential.issuer == registrarDid`
- `registrationCredential.subject == agentDid`
- `registrationCredential.status == "active"`
- `registrationCredential.proof` verifies against the Registrar DID Document

Future verification should add:

- strict credential expiration checks
- `claims.didDocumentHash` matching
- credential type allowlists
- issuer authorization scope checks
- mandatory request signature after a compatibility period
- full W3C VC proof-suite compatibility
- DID Document update risk checks for key rotation, endpoint changes, and capability changes

## 6. Registration Pipeline

Root handles registration as a streaming concurrent pipeline:

1. receive a full DID Document and registration credential from Registrar
2. validate Registrar authorization
3. validate DID Document structure and `did:ans` identity
4. validate request nonce and optional request signature
5. validate `registrationCredential` proof
6. classify create/update
7. archive the package version
8. append a signed bulletin event
9. enqueue a verified package for CDN publishing
10. enqueue Discovery notification metadata

Root does not keep all Agent DID Documents or Discovery indexes in memory. Operational state is persisted in JSON artifacts and SQLite indexes.

## 7. Distribution Pipeline

Root uses explicit batch APIs:

- `POST /root/batches/publish-cdn`
- `POST /root/batches/notify-discovery`

The intended ordering is:

1. publish verified packages to CDN
2. confirm CDN publish success
3. notify relevant Discovery Nodes

Discovery notifications are domain-filtered. A Discovery Node receives package notifications only when its `authorizedDomains` match the Agent's canonical capability tags, unless it is authorized for `*`.

## 8. Bulletin

The bulletin is a signed append-only governance log. It carries:

- Root initialization
- CDN service information
- Registrar authorization, suspension, recovery, and revocation
- Discovery authorization, domain changes, suspension, recovery, and revocation
- third-party VC issuer authorization and revocation
- Agent DID Document anchor/update/revocation events
- capability tree version events

CDN information on the bulletin is service discovery data only. CDN is not authorized by the bulletin and is not trusted as a protocol authority.

## 9. Capability Tree

Root loads the capability tree from:

```text
docs/capability-tree-v1.json
```

The capability tree is a shared semantic reference, not a closed vocabulary. Tree-compatible tags improve network-wide coarse discovery and Discovery authorization-domain routing. Custom tags remain allowed for precise matching after coarse filtering.

## 10. Local Data

Representative local data:

```text
data/root/did-document.json
data/root/keys/keypair.json
data/root/bulletin.json
data/root/authorization-state.json
data/root/root.db
data/root/archive/
data/root/verified-packages/
data/root/queues/
data/root/indexes/
```

JSON files are audit-friendly artifacts. SQLite is the operational index and queue store.

## 11. Tests

Current tests cover:

- DID Document verification
- registration credential proof verification
- nonce replay protection
- optional request signature verification
- capability tree validation
- custom capability tag acceptance
- queue behavior
- status and management APIs
- authorization list APIs

The repository passes:

```text
cargo test --workspace
```

## 12. Next Work

- convert namespace JSON SQLite records to role-specific relational schemas
- add scheduler-driven batch windows
- add retry backoff and dead-letter queues
- add stricter credential expiration and issuer-scope checks
- add formal bulletin event schema validation
- expose richer authorization lifecycle APIs
