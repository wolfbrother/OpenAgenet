// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Protocol models shared across OpenAgentNet nodes.

use chrono::{DateTime, Utc};
use oan_core::DidDocument;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(rename = "nodeType")]
    pub node_type: String,
    pub did: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeAuthorizeRequest {
    #[serde(rename = "nodeDid")]
    pub node_did: String,
    #[serde(rename = "nodeRole")]
    pub node_role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryAuthorizeRequest {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub endpoint: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDomainUpdateRequest {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    #[serde(rename = "authorizedDomains")]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "tagTreeVersion")]
    pub tag_tree_version: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRegisterRequest {
    #[serde(rename = "agentDid")]
    pub agent_did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub metadata: Value,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyAndPublishRequest {
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    #[serde(rename = "registrarDidDocument")]
    pub registrar_did_document: DidDocument,
    #[serde(rename = "agentDid")]
    pub agent_did: String,
    /// Full DID Document for both create and update operations.
    ///
    /// Root Node does not accept patch, diff, or partial DID Document updates.
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub metadata: Value,
    #[serde(rename = "registrationCredential")]
    pub registration_credential: Value,
    #[serde(
        rename = "requestTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_timestamp: Option<DateTime<Utc>>,
    #[serde(
        rename = "requestNonce",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_nonce: Option<String>,
    #[serde(
        rename = "requestSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootAuthorizeRequest {
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(rename = "targetRole")]
    pub target_role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryResponseProof {
    #[serde(rename = "proofType")]
    pub proof_type: String,
    pub creator: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryQuery {
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "serviceType", skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    10
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryCandidate {
    pub did: String,
    pub score: f32,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(default)]
    pub services: Vec<oan_core::ServiceEndpoint>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    pub candidates: Vec<DiscoveryCandidate>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub signature: String,
    pub proof: Option<DiscoveryResponseProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDiscoveryNotificationItem {
    #[serde(rename = "agentDid")]
    pub agent_did: String,
    pub operation: String,
    #[serde(rename = "documentVersion")]
    pub document_version: u64,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "bulletinSequence")]
    pub bulletin_sequence: u64,
    #[serde(rename = "bulletinEventHash")]
    pub bulletin_event_hash: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootDiscoveryBatchNotification {
    #[serde(rename = "notificationBatchId")]
    pub notification_batch_id: String,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "targetDiscoveryDid")]
    pub target_discovery_did: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "sequenceFrom")]
    pub sequence_from: u64,
    #[serde(rename = "sequenceTo")]
    pub sequence_to: u64,
    pub items: Vec<RootDiscoveryNotificationItem>,
    #[serde(rename = "cdnManifestUrl")]
    pub cdn_manifest_url: String,
    #[serde(rename = "cdnUpdatesUrl")]
    pub cdn_updates_url: String,
    pub proof: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationEnvelope {
    pub id: String,
    #[serde(rename = "callerDid")]
    pub caller_did: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    pub protocol: String,
    pub payload: Value,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub signature: String,
}
