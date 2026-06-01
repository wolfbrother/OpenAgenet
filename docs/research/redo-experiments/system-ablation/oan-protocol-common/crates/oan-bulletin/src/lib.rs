// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Bulletin event and hash-chain primitives.

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
pub enum BulletinError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("event sequence mismatch at index {index}: expected {expected}, got {actual}")]
    SequenceMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("previous hash mismatch at sequence {sequence}")]
    PreviousHashMismatch { sequence: u64 },
    #[error("event hash mismatch at sequence {sequence}")]
    EventHashMismatch { sequence: u64 },
    #[error("event signature verification failed at sequence {sequence}")]
    SignatureMismatch { sequence: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BulletinEventType {
    RootInitialized,
    CdnServiceInfoUpdated,
    RegistrarAuthorized,
    RegistrarRevoked,
    DiscoveryNodeAuthorized,
    DiscoveryNodeDomainsUpdated,
    DiscoveryNodeRevoked,
    NodeRevoked,
    CapabilityTagTreeUpdated,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BulletinEventPayload {
    #[serde(flatten)]
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BulletinEventCore {
    pub sequence: u64,
    #[serde(rename = "previousHash")]
    pub previous_hash: Option<String>,
    #[serde(rename = "eventType")]
    pub event_type: BulletinEventType,
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    #[serde(rename = "actorDid")]
    pub actor_did: String,
    pub payload: Value,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BulletinEvent {
    #[serde(flatten)]
    pub core: BulletinEventCore,
    #[serde(rename = "eventHash")]
    pub event_hash: String,
    pub signature: String,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Bulletin {
    pub version: String,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub events: Vec<BulletinEvent>,
}

impl BulletinEventCore {
    pub fn hash(&self, suite: CryptoSuite) -> Result<String, BulletinError> {
        Ok(hash_json_with_suite(suite, self)?)
    }

    pub fn sign(self, signing_key: &SigningKey) -> Result<BulletinEvent, BulletinError> {
        let suite = signing_key.crypto_suite();
        let event_hash = self.hash(suite.clone())?;
        let proof = build_data_integrity_proof(
            &serde_json::json!({ "eventHash": event_hash }),
            self.actor_did.clone(),
            format!("{}#key-1", self.actor_did),
            signing_key,
        )?;
        Ok(BulletinEvent {
            core: self,
            event_hash: event_hash.clone(),
            signature: proof.proof_value.clone(),
            proof: Some(proof),
            crypto_suite: Some(suite.clone()),
            hash_algorithm: Some(suite.hash_algorithm().to_owned()),
        })
    }

    pub fn sign_legacy_ed25519(
        self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<BulletinEvent, BulletinError> {
        self.sign(&SigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: signing_key.clone(),
        })
    }
}

impl BulletinEvent {
    pub fn crypto_suite(&self) -> CryptoSuite {
        self.crypto_suite
            .clone()
            .or_else(|| self.proof.as_ref().and_then(|proof| proof.crypto_suite()))
            .unwrap_or(CryptoSuite::Ed25519Sha256Legacy)
    }
}

impl Bulletin {
    pub fn verify_hash_chain(&self, root_key: &VerifyingKey) -> Result<(), BulletinError> {
        let mut previous_hash: Option<String> = None;

        for (index, event) in self.events.iter().enumerate() {
            let expected_sequence = index as u64 + 1;
            if event.core.sequence != expected_sequence {
                return Err(BulletinError::SequenceMismatch {
                    index,
                    expected: expected_sequence,
                    actual: event.core.sequence,
                });
            }

            if event.core.previous_hash != previous_hash {
                return Err(BulletinError::PreviousHashMismatch {
                    sequence: event.core.sequence,
                });
            }

            let suite = event.crypto_suite();
            let event_hash = event.core.hash(suite.clone())?;
            if event_hash != event.event_hash {
                return Err(BulletinError::EventHashMismatch {
                    sequence: event.core.sequence,
                });
            }

            if let Some(proof) = &event.proof {
                verify_payload_with_proof(
                    &serde_json::json!({ "eventHash": event.event_hash }),
                    proof,
                    root_key,
                )
                .map_err(|_| BulletinError::SignatureMismatch {
                    sequence: event.core.sequence,
                })?;
            } else {
                let input =
                    signature_input(suite, &serde_json::json!({ "eventHash": event.event_hash }))?;
                oan_crypto::verify_bytes(root_key, &input, &event.signature).map_err(|_| {
                    BulletinError::SignatureMismatch {
                        sequence: event.core.sequence,
                    }
                })?;
            }

            previous_hash = Some(event.event_hash.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_crypto::generate_keypair;
    use serde_json::json;

    #[test]
    fn verifies_signed_hash_chain_with_ed25519() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let event = BulletinEventCore {
            sequence: 1,
            previous_hash: None,
            event_type: BulletinEventType::RootInitialized,
            subject_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            actor_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            payload: json!({"ok": true}),
            created_at: Utc::now(),
        }
        .sign(&key.signing_key)
        .unwrap();

        let bulletin = Bulletin {
            version: "0.1.0".to_owned(),
            root_did: event.core.subject_did.clone(),
            created_at: Utc::now(),
            events: vec![event],
        };

        bulletin.verify_hash_chain(&key.verifying_key).unwrap();
    }

    #[test]
    fn verifies_signed_hash_chain_with_sm2() {
        let key = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let event = BulletinEventCore {
            sequence: 1,
            previous_hash: None,
            event_type: BulletinEventType::RootInitialized,
            subject_did: "did:ans:AGRT:zfrootrootrootrootrootroot".to_owned(),
            actor_did: "did:ans:AGRT:zfrootrootrootrootrootroot".to_owned(),
            payload: json!({"ok": true}),
            created_at: Utc::now(),
        }
        .sign(&key.signing_key)
        .unwrap();

        let bulletin = Bulletin {
            version: "0.1.0".to_owned(),
            root_did: event.core.subject_did.clone(),
            created_at: Utc::now(),
            events: vec![event],
        };

        bulletin.verify_hash_chain(&key.verifying_key).unwrap();
    }

    #[test]
    fn verifies_historical_hash_chain_without_self_describing_fields() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let mut event = BulletinEventCore {
            sequence: 1,
            previous_hash: None,
            event_type: BulletinEventType::RootInitialized,
            subject_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            actor_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            payload: json!({"ok": true}),
            created_at: Utc::now(),
        }
        .sign(&key.signing_key)
        .unwrap();
        event.crypto_suite = None;
        event.hash_algorithm = None;
        if let Some(proof) = event.proof.as_mut() {
            proof.crypto_suite = None;
            proof.hash_algorithm = None;
            proof.verification_method = None;
        }

        let bulletin = Bulletin {
            version: "0.1.0".to_owned(),
            root_did: event.core.subject_did.clone(),
            created_at: Utc::now(),
            events: vec![event],
        };

        bulletin.verify_hash_chain(&key.verifying_key).unwrap();
    }
}
