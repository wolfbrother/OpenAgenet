// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Verified package, manifest, and metadata models.

use chrono::{DateTime, Utc};
use oan_core::{CryptoSuite, DataIntegrityProof, DidDocument};
use oan_crypto::{hash_json_with_suite, CryptoError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("did document hash mismatch")]
    DidDocumentHashMismatch,
    #[error("metadata hash mismatch")]
    MetadataHashMismatch,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub did: String,
    pub role: String,
    #[serde(rename = "identityType")]
    pub identity_type: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(default)]
    pub services: Vec<oan_core::ServiceEndpoint>,
    pub status: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootProof {
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "bulletinEventHash")]
    pub bulletin_event_hash: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "packageClaims", skip_serializing_if = "Option::is_none")]
    pub package_claims: Option<serde_json::Value>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedPackage {
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    pub did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(
        rename = "metadataHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata_hash: Option<String>,
    pub metadata: AgentMetadata,
    #[serde(rename = "rootProof")]
    pub root_proof: RootProof,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub did: String,
    pub role: String,
    #[serde(rename = "documentPath")]
    pub document_path: String,
    #[serde(rename = "metadataPath")]
    pub metadata_path: String,
    #[serde(rename = "packagePath")]
    pub package_path: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: DateTime<Utc>,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    pub packages: Vec<ManifestEntry>,
}

impl VerifiedPackage {
    fn effective_crypto_suite(&self) -> CryptoSuite {
        self.root_proof
            .crypto_suite
            .clone()
            .or_else(|| {
                self.root_proof
                    .proof
                    .as_ref()
                    .and_then(|proof| proof.crypto_suite())
            })
            .unwrap_or(CryptoSuite::Ed25519Sha256Legacy)
    }

    pub fn verify_document_hash(&self) -> Result<(), PackageError> {
        let actual_hash = hash_json_with_suite(self.effective_crypto_suite(), &self.did_document)?;
        if actual_hash == self.did_document_hash {
            Ok(())
        } else {
            Err(PackageError::DidDocumentHashMismatch)
        }
    }

    pub fn verify_metadata_hash(&self) -> Result<(), PackageError> {
        let Some(expected_hash) = self.metadata_hash.as_deref() else {
            return Ok(());
        };
        let actual_hash = hash_json_with_suite(self.effective_crypto_suite(), &self.metadata)?;
        if actual_hash == expected_hash {
            Ok(())
        } else {
            Err(PackageError::MetadataHashMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_core::{DataIntegrityProof, DidDocument, VerificationMethod};

    #[test]
    fn detects_hash_mismatch() {
        let package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            did_document: DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                service: vec![],
                ans_metadata: None,
            },
            did_document_hash: "wrong".to_owned(),
            metadata_hash: None,
            metadata: AgentMetadata {
                did: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
                role: "Demo Service Agent".to_owned(),
                identity_type: "demo-service-agent".to_owned(),
                did_document_hash: "wrong".to_owned(),
                capability_tags: vec![],
                services: vec![],
                status: "active".to_owned(),
                updated_at: Utc::now(),
            },
            root_proof: RootProof {
                root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: None,
                hash_algorithm: None,
            },
            created_at: Utc::now(),
        };

        assert!(matches!(
            package.verify_document_hash(),
            Err(PackageError::DidDocumentHashMismatch)
        ));
    }

    #[test]
    fn document_hash_uses_legacy_fallback_for_historical_root_proof() {
        let did_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            verification_method: vec![VerificationMethod {
                id: "did:ans:AGDM:efserviceagentservice1234#key-1".to_owned(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
                crypto_suite: None,
                public_key_format: None,
                public_key_multibase: Some("zExample".to_owned()),
                public_key_jwk: None,
            }],
            authentication: vec!["did:ans:AGDM:efserviceagentservice1234#key-1".to_owned()],
            assertion_method: vec!["did:ans:AGDM:efserviceagentservice1234#key-1".to_owned()],
            service: vec![],
            ans_metadata: None,
        };
        let did_document_hash =
            oan_crypto::hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &did_document)
                .unwrap();
        let metadata = AgentMetadata {
            did: did_document.id.clone(),
            role: "Demo Service Agent".to_owned(),
            identity_type: "demo-service-agent".to_owned(),
            did_document_hash: did_document_hash.clone(),
            capability_tags: vec![],
            services: vec![],
            status: "active".to_owned(),
            updated_at: Utc::now(),
        };

        let package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did_document.id.clone(),
            did_document,
            did_document_hash,
            metadata_hash: None,
            metadata,
            root_proof: RootProof {
                root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: Some(DataIntegrityProof {
                    proof_type: "Ed25519Signature2020".to_owned(),
                    creator: "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                    created: Utc::now(),
                    proof_purpose: "assertionMethod".to_owned(),
                    proof_value: "sig".to_owned(),
                    crypto_suite: None,
                    hash_algorithm: None,
                    verification_method: None,
                }),
                crypto_suite: None,
                hash_algorithm: None,
            },
            created_at: Utc::now(),
        };

        package.verify_document_hash().unwrap();
    }

    #[test]
    fn document_hash_respects_explicit_modern_suite() {
        let did_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
            ans_metadata: None,
        };
        let did_document_hash =
            oan_crypto::hash_json_with_suite(CryptoSuite::Ed25519Sha256, &did_document).unwrap();
        let metadata = AgentMetadata {
            did: did_document.id.clone(),
            role: "Demo Service Agent".to_owned(),
            identity_type: "demo-service-agent".to_owned(),
            did_document_hash: did_document_hash.clone(),
            capability_tags: vec![],
            services: vec![],
            status: "active".to_owned(),
            updated_at: Utc::now(),
        };

        let package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did_document.id.clone(),
            did_document,
            did_document_hash,
            metadata_hash: None,
            metadata,
            root_proof: RootProof {
                root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: Some(DataIntegrityProof {
                    proof_type: "Ed25519Signature2020".to_owned(),
                    creator: "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                    created: Utc::now(),
                    proof_purpose: "assertionMethod".to_owned(),
                    proof_value: "sig".to_owned(),
                    crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                    hash_algorithm: Some("SHA-256".to_owned()),
                    verification_method: Some(
                        "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                    ),
                }),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("SHA-256".to_owned()),
            },
            created_at: Utc::now(),
        };

        package.verify_document_hash().unwrap();
    }
}
