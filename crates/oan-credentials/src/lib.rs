// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Credential models and verification helpers.

use chrono::{DateTime, Utc};
use oan_crypto::{hash_json, sign_bytes, verify_bytes, CryptoError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("credential proof is missing")]
    MissingProof,
    #[error("credential signature is invalid")]
    InvalidSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub creator: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAuthorizationCredential {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub issuer: String,
    pub subject: String,
    pub role: String,
    pub status: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialProof>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRegistrationCredential {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub issuer: String,
    pub subject: String,
    pub status: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialProof>,
}

pub fn proof_payload_hash<T: Serialize>(credential: &T) -> Result<String, CredentialError> {
    Ok(hash_json(credential)?)
}

pub fn sign_credential<T>(
    credential_without_proof: &T,
    creator: String,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<CredentialProof, CredentialError>
where
    T: Serialize,
{
    let payload_hash = proof_payload_hash(credential_without_proof)?;
    Ok(CredentialProof {
        proof_type: "Ed25519Signature2020".to_owned(),
        creator,
        created: Utc::now(),
        proof_purpose: "assertionMethod".to_owned(),
        proof_value: sign_bytes(signing_key, payload_hash.as_bytes()),
    })
}

pub fn verify_signed_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    let payload_hash = proof_payload_hash(payload_without_proof)?;
    verify_bytes(verifying_key, payload_hash.as_bytes(), &proof.proof_value)
        .map_err(|_| CredentialError::InvalidSignature)
}

pub fn proof_matches_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
) -> Result<String, CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    let payload_hash = proof_payload_hash(payload_without_proof)?;
    let actual = hash_json(&serde_json::json!({
        "payloadHash": payload_hash,
        "proofValue": proof.proof_value
    }))?;
    Ok(actual)
}

impl NodeAuthorizationCredential {
    pub fn unsigned(issuer: String, subject: String, role: String, claims: Value) -> Self {
        Self {
            credential_type: "NodeAuthorizationCredential".to_owned(),
            issuer,
            subject,
            role,
            status: "active".to_owned(),
            issued_at: Utc::now(),
            expires_at: None,
            claims,
            proof: None,
        }
    }

    pub fn sign(
        mut self,
        key_id: String,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, CredentialError> {
        let unsigned = Self {
            proof: None,
            ..self.clone()
        };
        self.proof = Some(sign_credential(&unsigned, key_id, signing_key)?);
        Ok(self)
    }
}

impl AgentRegistrationCredential {
    pub fn unsigned(issuer: String, subject: String, claims: Value) -> Self {
        Self {
            credential_type: "AgentRegistrationCredential".to_owned(),
            issuer,
            subject,
            status: "active".to_owned(),
            issued_at: Utc::now(),
            expires_at: None,
            claims,
            proof: None,
        }
    }

    pub fn sign(
        mut self,
        key_id: String,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, CredentialError> {
        let unsigned = Self {
            proof: None,
            ..self.clone()
        };
        self.proof = Some(sign_credential(&unsigned, key_id, signing_key)?);
        Ok(self)
    }
}

pub fn verify_agent_registration_credential(
    credential: &AgentRegistrationCredential,
    issuer_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), CredentialError> {
    let unsigned = AgentRegistrationCredential {
        proof: None,
        ..credential.clone()
    };
    verify_signed_payload(&unsigned, credential.proof.as_ref(), issuer_verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_crypto::generate_ed25519_keypair;
    use serde_json::json;

    #[test]
    fn signs_registration_credential() {
        let key = generate_ed25519_keypair();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:efregistrarregistrar1234#key-1".to_owned(),
            &key,
        )
        .unwrap();

        let unsigned = AgentRegistrationCredential {
            proof: None,
            ..credential.clone()
        };
        verify_signed_payload(&unsigned, credential.proof.as_ref(), &key.verifying_key()).unwrap();
    }

    #[test]
    fn rejects_registration_credential_with_wrong_key() {
        let signing_key = generate_ed25519_keypair();
        let wrong_key = generate_ed25519_keypair();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:efregistrarregistrar1234#key-1".to_owned(),
            &signing_key,
        )
        .unwrap();

        assert!(
            verify_agent_registration_credential(&credential, &wrong_key.verifying_key()).is_err()
        );
    }

    #[test]
    fn signs_node_authorization_credential_with_local_claims() {
        let key = generate_ed25519_keypair();
        let credential = NodeAuthorizationCredential::unsigned(
            "did:ans:AGRT:efrootroot1234".to_owned(),
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "registrar".to_owned(),
            json!({"endpoint": "http://localhost:8001"}),
        )
        .sign("did:ans:AGRT:efrootroot1234#key-1".to_owned(), &key)
        .unwrap();

        let unsigned = NodeAuthorizationCredential {
            proof: None,
            ..credential.clone()
        };
        verify_signed_payload(&unsigned, credential.proof.as_ref(), &key.verifying_key()).unwrap();
        assert_eq!(credential.status, "active");
        assert_eq!(credential.claims["endpoint"], "http://localhost:8001");
    }
}
