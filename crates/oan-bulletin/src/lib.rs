// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Bulletin event and hash-chain primitives.

use chrono::{DateTime, Utc};
use oan_crypto::{hash_json, sign_bytes, verify_bytes, CryptoError};
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
    AgentDidDocumentAnchored,
    AgentDidDocumentUpdated,
    AgentRevoked,
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
    pub fn hash(&self) -> Result<String, BulletinError> {
        Ok(hash_json(self)?)
    }

    pub fn sign(
        self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<BulletinEvent, BulletinError> {
        let event_hash = self.hash()?;
        let signature = sign_bytes(signing_key, event_hash.as_bytes());
        Ok(BulletinEvent {
            core: self,
            event_hash,
            signature,
        })
    }
}

impl Bulletin {
    pub fn verify_hash_chain(
        &self,
        root_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), BulletinError> {
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

            let event_hash = event.core.hash()?;
            if event_hash != event.event_hash {
                return Err(BulletinError::EventHashMismatch {
                    sequence: event.core.sequence,
                });
            }

            verify_bytes(root_key, event.event_hash.as_bytes(), &event.signature).map_err(
                |_| BulletinError::SignatureMismatch {
                    sequence: event.core.sequence,
                },
            )?;

            previous_hash = Some(event.event_hash.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_crypto::generate_ed25519_keypair;
    use serde_json::json;

    #[test]
    fn verifies_signed_hash_chain() {
        let key = generate_ed25519_keypair();
        let event = BulletinEventCore {
            sequence: 1,
            previous_hash: None,
            event_type: BulletinEventType::RootInitialized,
            subject_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            actor_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            payload: json!({"ok": true}),
            created_at: Utc::now(),
        }
        .sign(&key)
        .unwrap();

        let bulletin = Bulletin {
            version: "0.1.0".to_owned(),
            root_did: event.core.subject_did.clone(),
            created_at: Utc::now(),
            events: vec![event],
        };

        bulletin.verify_hash_chain(&key.verifying_key()).unwrap();
    }
}
