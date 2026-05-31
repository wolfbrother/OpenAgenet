// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Protocol models shared across OpenAgenet nodes.

use chrono::{DateTime, Utc};
use oan_core::{DataIntegrityProof, DidDocument};
use oan_package::VerifiedPackage;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: &str = "ans-2026";
pub const PURPOSE_AGENT_REGISTRATION: &str = "agent-registration";
pub const PURPOSE_VERIFY_AND_PUBLISH: &str = "verify-and-publish";
pub const PURPOSE_CDN_PUBLISH: &str = "cdn-publish";
pub const PATH_ROOT_VERIFY_AND_PUBLISH: &str = "/root/agents/verify-and-publish";
pub const PATH_CDN_PACKAGES: &str = "/cdn/packages";
pub const REGISTRATION_FLOW: &str = "did-control";

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
pub struct SignedRequestEnvelope {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub purpose: String,
    pub method: String,
    pub path: String,
    pub aud: String,
    #[serde(rename = "requestTimestamp")]
    pub request_timestamp: DateTime<Utc>,
    #[serde(rename = "requestNonce")]
    pub request_nonce: String,
    #[serde(rename = "bodyHash")]
    pub body_hash: String,
    pub proof: DataIntegrityProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DidControlChallenge {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "draftId")]
    pub draft_id: String,
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub nonce: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubjectControlProofBundle {
    pub challenge: DidControlChallenge,
    pub proof: DataIntegrityProof,
    #[serde(rename = "verifiedAt", skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(
        rename = "verifiedVerificationMethod",
        skip_serializing_if = "Option::is_none"
    )]
    pub verified_verification_method: Option<String>,
    #[serde(rename = "proofHash", skip_serializing_if = "Option::is_none")]
    pub proof_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRegistrationSubmission {
    #[serde(rename = "agentDid")]
    pub agent_did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    pub metadata: Value,
    #[serde(rename = "registrationCredential")]
    pub registration_credential: Value,
    #[serde(rename = "subjectControlProof")]
    pub subject_control_proof: SubjectControlProofBundle,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyAndPublishRequest {
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub submission: AgentRegistrationSubmission,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CdnPublishRequest {
    pub package: VerifiedPackage,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
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

pub type DiscoveryResponseProof = DataIntegrityProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oan_core::{DataIntegrityProof, DidDocument};
    use serde_json::json;

    fn sample_did_document(did: &str) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
            ans_metadata: None,
        }
    }

    fn sample_proof() -> DataIntegrityProof {
        DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:ans:AGRG:test#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: Some("did:ans:AGRG:test#key-1".to_owned()),
        }
    }

    #[test]
    fn verify_and_publish_request_round_trips_with_binding_fields() {
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: "did:ans:AGDM:test".to_owned(),
            did_document_hash: "hash-1".to_owned(),
            registrar_did: "did:ans:AGRG:test".to_owned(),
            purpose: PURPOSE_AGENT_REGISTRATION.to_owned(),
            verification_method: "did:ans:AGDM:test#key-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        };
        let request = VerifyAndPublishRequest {
            registrar_did: "did:ans:AGRG:test".to_owned(),
            submission: AgentRegistrationSubmission {
                agent_did: "did:ans:AGDM:test".to_owned(),
                did_document: sample_did_document("did:ans:AGDM:test"),
                did_document_hash: "hash-1".to_owned(),
                metadata: json!({"source": "test"}),
                registration_credential: json!({
                    "issuer": "did:ans:AGRG:test",
                    "subject": "did:ans:AGDM:test",
                    "status": "active",
                    "claims": {
                        "didDocumentHash": "hash-1",
                        "registrationBinding": {
                            "flow": REGISTRATION_FLOW,
                            "draftId": "draft-1",
                            "challengeId": "challenge-1",
                            "subjectDid": "did:ans:AGDM:test",
                            "registrarDid": "did:ans:AGRG:test",
                            "purpose": PURPOSE_AGENT_REGISTRATION,
                            "verificationMethod": "did:ans:AGDM:test#key-1",
                            "proofHash": "proof-hash",
                            "verifiedAt": Utc::now(),
                        }
                    }
                }),
                subject_control_proof: SubjectControlProofBundle {
                    challenge,
                    proof: sample_proof(),
                    verified_at: Some(Utc::now()),
                    verified_verification_method: Some("did:ans:AGDM:test#key-1".to_owned()),
                    proof_hash: Some("proof-hash".to_owned()),
                },
            },
            upstream_auth: SignedRequestEnvelope {
                request_id: "request-1".to_owned(),
                protocol_version: PROTOCOL_VERSION.to_owned(),
                purpose: PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
                method: "POST".to_owned(),
                path: PATH_ROOT_VERIFY_AND_PUBLISH.to_owned(),
                aud: "did:ans:AGRT:test".to_owned(),
                request_timestamp: Utc::now(),
                request_nonce: "nonce-upstream".to_owned(),
                body_hash: "body-hash".to_owned(),
                proof: sample_proof(),
            },
        };

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["registrarDid"], "did:ans:AGRG:test");
        assert_eq!(
            value["submission"]["subjectControlProof"]["challenge"]["purpose"],
            PURPOSE_AGENT_REGISTRATION
        );
        let round_trip: VerifyAndPublishRequest = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, request);
    }
}
