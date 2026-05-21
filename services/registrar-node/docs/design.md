<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Registrar Node Detailed Design

## 1. Role

Registrar Node is the intake and onboarding gateway for Service Agents. It helps Agent operators prepare complete DID Documents, select useful capability tags, obtain registration credentials, and submit full documents to Root.

Registrar Node is not a business Agent. It is an infrastructure node and must use `ansMetadata.subjectType = "infrastructure-node"`.

## 2. Current Implementation

The Rust MVP implements:

- basic registration and update APIs
- draft registration records for future web pages
- DID Document draft validation
- capability tag suggestion
- preservation of custom capability tags
- local Registrar DID Document and key loading
- signed `AgentRegistrationCredential` issuance
- full DID Document submission to Root
- local JSON records
- SQLite-backed draft and submission mirrors
- status and management APIs for future web consoles

Registrar recommendations are advisory. Tree-compatible tags are encouraged because they improve whole-network coarse discovery, but custom tags are allowed and preserved.

## 3. Configuration

Config file:

```text
services/registrar-node/config.example.toml
```

Important inputs:

```text
[server]
host
port

[upstream]
root_endpoint

[paths]
data_dir
records_dir
drafts_dir
keys_dir
credentials_dir
database_url
```

Registrar connects upstream to Root. Root acceptance depends on Root authorization state and bulletin facts.

## 4. APIs

Protocol APIs:

```text
GET  /health
GET  /registrar/did
POST /agents/register
POST /agents/update
```

Management and web-support APIs:

```text
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

These APIs are intended to support a future Registrar website. The website should wrap the APIs rather than reimplement registration business rules.

## 5. Registration Flow

1. Service Agent operator creates a draft.
2. Registrar suggests capability tags from the shared capability tree.
3. Operator selects tree-compatible tags and may add custom tags.
4. Registrar stores the draft.
5. Registrar validates basic DID Document consistency.
6. Registrar signs an `AgentRegistrationCredential`.
7. Registrar stores the credential locally and in the draft.
8. Registrar submits the complete DID Document and credential to Root.
9. Root returns verification, archive, CDN queue, and Discovery queue status.
10. Registrar stores the submission response.

Create and update use the same full-document path because Root verifies a complete DID Document every time.

## 6. Credential Issuance

The current credential is VC-like JSON:

```text
AgentRegistrationCredential
```

It includes:

- `id`
- `type`
- `issuer`
- `subject`
- `status`
- `issuedAt`
- `expiresAt`
- `claims`
- `proof`

The proof is an Ed25519 signature over the canonical unsigned credential hash. It is compatible with current OpenAgentNet verification logic, but full W3C VC proof-suite compatibility remains future work.

## 7. Local Data

Representative local data:

```text
data/registrar/did-document.json
data/registrar/keys/keypair.json
data/registrar/credentials/node-authorization.json
data/registrar/credentials/by-dimension/
data/registrar/records/<agentDid>.json
data/registrar/drafts/<draftId>.json
data/registrar/registrar.db
```

Credentials are local. The MVP does not use hosted VC custody.

## 8. Boundaries

Registrar does not:

- decide Root trust
- authorize itself
- decide whether Discovery indexes an Agent
- operate ranking or reputation systems
- host Agent credentials for third parties

Registrar does:

- assist DID Document preparation
- issue registration credentials
- preserve custom capability tags
- submit complete DID Documents to Root
- store local registration evidence

## 9. Tests

Current tests cover:

- status counts
- draft creation
- draft validation
- draft lookup
- management API behavior
- signed credential issuance path

The repository passes:

```text
cargo test --workspace
```

## 10. Next Work

- add full negative tests for draft update and submit failures
- validate capability-tree suggestion behavior more deeply
- support expiration and revocation of registration credentials
- add a Registrar web registration wizard
- migrate namespace JSON SQLite records to relational schemas
