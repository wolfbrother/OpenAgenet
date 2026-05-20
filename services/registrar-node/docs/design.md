<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Registrar Node Design

## 1. Positioning

Registrar Node is the intake and registration gateway for Service Agents. It is not a business Agent. Its job is to help operators prepare a full DID Document package and submit the full document to Root.

Registrar Node is also an infrastructure node, so its `ansMetadata.subjectType` must be `infrastructure-node`.

The current Rust MVP performs these tasks:

- accepts Service Agent registration and update requests
- performs basic DID Document validation
- stores local submission records
- forwards complete DID Documents to Root
- returns Root verification results

## 2. Configuration and Connectivity

Config file: `services/registrar-node/config.example.toml`

Required inputs:

```text
[server]
host
port

[upstream]
root_endpoint

[paths]
data_dir
records_dir
database_url
```

Registrar connects upstream only to Root. Whether Root accepts the request depends on Root authorization state published on the bulletin.

Path resolution follows the same rule as other services: absolute paths win, then current working directory, then config file directory.

## 3. HTTP APIs

Current APIs:

```text
GET  /health
GET  /registrar/did
POST /agents/register
POST /agents/update

GET  /api/v1/registrar/status
GET  /api/v1/registrar/root-authorization
GET  /api/v1/agents
GET  /api/v1/agents/{did}
GET  /api/v1/agents/{did}/submissions
POST /api/v1/agents/draft
PUT  /api/v1/agents/draft/{draftId}
POST /api/v1/agents/draft/{draftId}/validate
POST /api/v1/agents/draft/{draftId}/issue-registration-credential
POST /api/v1/agents/draft/{draftId}/submit
POST /api/v1/agents/{did}/resubmit
GET  /api/v1/capability-tree
POST /api/v1/capability-tags/suggest
```

These APIs are designed to support future registrar web pages directly, so the web layer does not need to own draft persistence or validation logic.

## 4. Registration Flow

1. the operator creates or edits a draft
2. Registrar validates the draft locally
3. Registrar can issue an unsigned registration credential skeleton in the MVP
4. Registrar stores the draft and submission record locally
5. Registrar submits the complete request to Root
6. Root verifies the request and returns the verified package result

The design keeps create and update on the same full-document path, because Root requires the full DID Document even for updates.

## 5. Local Data

Current storage layout:

```text
data/registrar/did-document.json
data/registrar/keys/keypair.json
data/registrar/credentials/node-authorization.json
data/registrar/records/<agentDid>.json
data/registrar/drafts/<draftId>.json
```

VC-like credentials remain local files in the MVP. There is no credential hosting or custody service.

## 6. Validation and Boundary

Registrar does not decide Root trust status. It does not decide whether Discovery indexes a service. It does not manage agent reputation or business ranking.

Its validation responsibilities are intentionally thin:

- `agentDid == didDocument.id`
- DID Document structure is minimally valid
- draft content is internally consistent
- local record persistence is stable

Root remains the final verifier.

## 7. Test Coverage

Current codebase status:

- `cargo check --workspace` passes
- `cargo test --workspace` passes
- registrar management APIs are implemented
- direct API tests for the new registrar endpoints are still missing and should be added next

## 8. Next Steps

- add API tests for draft create/update/validate/submit flows
- add tests for capability-tree suggestion and read endpoints
- add real credential signing and signature verification hooks
- migrate records and indexes to SQLite when the schema stabilizes
