// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Credential models and verification helpers.

use chrono::{DateTime, Utc};
use oan_core::{CryptoSuite, DataIntegrityProof};
use oan_crypto::{
    build_data_integrity_proof, hash_json_with_suite, signature_input, verify_payload_with_proof,
    CryptoError, SigningKey, VerifyingKey,
};
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

pub type CredentialProof = DataIntegrityProof;

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

pub fn proof_payload_hash<T: Serialize>(
    suite: CryptoSuite,
    credential: &T,
) -> Result<String, CredentialError> {
    Ok(hash_json_with_suite(suite, credential)?)
}

pub fn sign_credential<T>(
    credential_without_proof: &T,
    creator: String,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<CredentialProof, CredentialError>
where
    T: Serialize,
{
    Ok(build_data_integrity_proof(
        credential_without_proof,
        creator,
        verification_method,
        signing_key,
    )?)
}

pub fn verify_signed_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
    verifying_key: &VerifyingKey,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    verify_payload_with_proof(payload_without_proof, proof, verifying_key)
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
    let suite = proof
        .crypto_suite()
        .ok_or(CredentialError::InvalidSignature)?;
    let payload_input = signature_input(suite.clone(), payload_without_proof)?;
    let actual = hash_json_with_suite(
        suite,
        &serde_json::json!({
            "payloadInput": String::from_utf8_lossy(&payload_input),
            "proofValue": proof.proof_value
        }),
    )?;
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
        signing_key: &SigningKey,
    ) -> Result<Self, CredentialError> {
        let unsigned = Self {
            proof: None,
            ..self.clone()
        };
        self.proof = Some(sign_credential(
            &unsigned,
            key_id.clone(),
            key_id,
            signing_key,
        )?);
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
        signing_key: &SigningKey,
    ) -> Result<Self, CredentialError> {
        let unsigned = Self {
            proof: None,
            ..self.clone()
        };
        self.proof = Some(sign_credential(
            &unsigned,
            key_id.clone(),
            key_id,
            signing_key,
        )?);
        Ok(self)
    }
}

pub fn verify_agent_registration_credential(
    credential: &AgentRegistrationCredential,
    issuer_verifying_key: &VerifyingKey,
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
    use oan_crypto::{generate_keypair, public_key_multibase};
    use serde_json::json;

    #[test]
    fn signs_registration_credential_with_ed25519() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:efregistrarregistrar1234#key-1".to_owned(),
            &key.signing_key,
        )
        .unwrap();

        let unsigned = AgentRegistrationCredential {
            proof: None,
            ..credential.clone()
        };
        verify_signed_payload(&unsigned, credential.proof.as_ref(), &key.verifying_key).unwrap();
    }

    #[test]
    fn signs_registration_credential_with_sm2() {
        let key = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:zgregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:zserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:zgregistrarregistrar1234#key-1".to_owned(),
            &key.signing_key,
        )
        .unwrap();

        let unsigned = AgentRegistrationCredential {
            proof: None,
            ..credential.clone()
        };
        verify_signed_payload(&unsigned, credential.proof.as_ref(), &key.verifying_key).unwrap();
    }

    #[test]
    fn rejects_registration_credential_with_wrong_key() {
        let signing_key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let wrong_key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:efregistrarregistrar1234#key-1".to_owned(),
            &signing_key.signing_key,
        )
        .unwrap();

        assert!(
            verify_agent_registration_credential(&credential, &wrong_key.verifying_key).is_err()
        );
    }

    #[test]
    fn proof_exposes_suite_metadata() {
        let key = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:zgregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:zserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:zgregistrarregistrar1234#key-1".to_owned(),
            &key.signing_key,
        )
        .unwrap();

        assert_eq!(
            credential.proof.as_ref().unwrap().crypto_suite(),
            Some(CryptoSuite::Sm2Sm3)
        );
        assert_eq!(
            credential
                .proof
                .as_ref()
                .unwrap()
                .verification_method
                .as_deref(),
            Some("did:ans:AGRG:zgregistrarregistrar1234#key-1")
        );
        assert!(!public_key_multibase(&key.verifying_key).is_empty());
    }

    #[test]
    fn verifies_historical_registration_proof_without_crypto_suite() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let mut credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:efregistrarregistrar1234#key-1".to_owned(),
            &key.signing_key,
        )
        .unwrap();
        let proof = credential.proof.as_mut().unwrap();
        proof.crypto_suite = None;
        proof.hash_algorithm = None;
        proof.verification_method = None;

        let unsigned = AgentRegistrationCredential {
            proof: None,
            ..credential.clone()
        };
        verify_signed_payload(&unsigned, credential.proof.as_ref(), &key.verifying_key).unwrap();
    }

    #[test]
    fn modern_ed25519_suite_stays_distinct_from_legacy() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(
            "did:ans:AGRG:efregistrarregistrar1234#key-1".to_owned(),
            &key.signing_key,
        )
        .unwrap();

        assert_eq!(
            credential.proof.as_ref().unwrap().crypto_suite(),
            Some(CryptoSuite::Ed25519Sha256)
        );

        let unsigned = AgentRegistrationCredential {
            proof: None,
            ..credential.clone()
        };
        verify_signed_payload(&unsigned, credential.proof.as_ref(), &key.verifying_key).unwrap();
    }
}
