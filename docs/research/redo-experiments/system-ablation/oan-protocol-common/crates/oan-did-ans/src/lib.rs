// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! did:ans parsing, generation, and validation.

use oan_core::CryptoSuite;
use oan_crypto::{generate_keypair, CryptoError, KeypairMaterial, VerifyingKey};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;
use thiserror::Error;

const DID_PREFIX: &str = "did:ans:";
const SUBJECT_CODE: &str = "AG";

fn did_regex() -> &'static Regex {
    static DID_RE: OnceLock<Regex> = OnceLock::new();
    DID_RE.get_or_init(|| Regex::new(r"^did:ans:AG[A-Za-z0-9]{2}:[A-Za-z0-9]{22,92}$").unwrap())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidAnsError {
    #[error("did must start with did:ans")]
    InvalidPrefix,
    #[error("did must have 4 colon-separated parts")]
    InvalidPartCount,
    #[error("semantic code must be 4 alphanumeric characters and start with AG")]
    InvalidSemanticCode,
    #[error("suffix must be 22 to 92 alphanumeric characters")]
    InvalidSuffix,
    #[error("invalid did:ans syntax")]
    InvalidSyntax,
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<CryptoError> for DidAnsError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidAns {
    value: String,
    semantic_code: String,
    suffix: String,
}

impl DidAns {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, DidAnsError> {
        let value = value.as_ref();
        if !value.starts_with(DID_PREFIX) {
            return Err(DidAnsError::InvalidPrefix);
        }

        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 4 {
            return Err(DidAnsError::InvalidPartCount);
        }

        let semantic_code = parts[2];
        if semantic_code.len() != 4
            || !semantic_code.starts_with(SUBJECT_CODE)
            || !semantic_code.chars().all(|ch| ch.is_ascii_alphanumeric())
        {
            return Err(DidAnsError::InvalidSemanticCode);
        }

        let suffix = parts[3];
        if !(22..=92).contains(&suffix.len())
            || !suffix.chars().all(|ch| ch.is_ascii_alphanumeric())
        {
            return Err(DidAnsError::InvalidSuffix);
        }

        if !did_regex().is_match(value) {
            return Err(DidAnsError::InvalidSyntax);
        }

        Ok(Self {
            value: value.to_owned(),
            semantic_code: semantic_code.to_owned(),
            suffix: suffix.to_owned(),
        })
    }

    pub fn from_public_key(
        semantic_code: &str,
        suite: CryptoSuite,
        public_key: &[u8],
    ) -> Result<Self, DidAnsError> {
        validate_semantic_code(semantic_code)?;
        let suffix = format!(
            "{}f{}",
            suite.did_prefix(),
            bs58::encode(public_key).into_string()
        );
        Self::parse(format!("{DID_PREFIX}{semantic_code}:{suffix}"))
    }

    pub fn generate(
        semantic_code: &str,
        suite: CryptoSuite,
    ) -> Result<(Self, KeypairMaterial), DidAnsError> {
        validate_semantic_code(semantic_code)?;
        let keypair = generate_keypair(suite.clone())?;
        let public_key_bytes = match &keypair.verifying_key {
            VerifyingKey::Ed25519 { key, .. } => key.as_bytes().to_vec(),
            VerifyingKey::Sm2 { key, .. } => key.to_sec1_bytes().into_vec(),
        };
        let did = Self::from_public_key(semantic_code, suite, &public_key_bytes)?;
        Ok((did, keypair))
    }

    pub fn generate_ed25519(
        semantic_code: &str,
    ) -> Result<(Self, ed25519_dalek::SigningKey), DidAnsError> {
        let (did, keypair) = Self::generate(semantic_code, CryptoSuite::Ed25519Sha256Legacy)?;
        let oan_crypto::SigningKey::Ed25519 {
            key: signing_key, ..
        } = keypair.signing_key
        else {
            return Err(DidAnsError::Crypto("unexpected_ed25519_keypair".to_owned()));
        };
        Ok((did, signing_key))
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn semantic_code(&self) -> &str {
        &self.semantic_code
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    pub fn key_id(&self, fragment: &str) -> String {
        let fragment = fragment.trim_start_matches('#');
        format!("{}#{fragment}", self.value)
    }
}

impl Display for DidAns {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl FromStr for DidAns {
    type Err = DidAnsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

pub fn validate(value: &str) -> Result<(), DidAnsError> {
    DidAns::parse(value).map(|_| ())
}

pub fn validate_semantic_code(value: &str) -> Result<(), DidAnsError> {
    if value.len() == 4
        && value.starts_with(SUBJECT_CODE)
        && value.chars().all(|ch| ch.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err(DidAnsError::InvalidSemanticCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_did() {
        let did =
            DidAns::parse("did:ans:AGDM:efDiiw27zktRjBQSYF1PWcCfF6DBJr7UeggNgqBFG8d7zv").unwrap();

        assert_eq!(did.semantic_code(), "AGDM");
        assert_eq!(
            did.suffix(),
            "efDiiw27zktRjBQSYF1PWcCfF6DBJr7UeggNgqBFG8d7zv"
        );
    }

    #[test]
    fn rejects_non_agent_subject_code() {
        let err = DidAns::parse("did:ans:NDRT:efDiiw27zktRjBQSYF1PWcCfF6DBJr7UeggNgqBFG8d7zv")
            .unwrap_err();
        assert_eq!(err, DidAnsError::InvalidSemanticCode);
    }

    #[test]
    fn generates_ed25519_did() {
        let (did, _key) = DidAns::generate_ed25519("AGUS").unwrap();
        assert_eq!(did.semantic_code(), "AGUS");
        assert!(did.as_str().starts_with("did:ans:AGUS:ef"));
    }

    #[test]
    fn generates_sm2_did() {
        let (did, _keypair) = DidAns::generate("AGUS", CryptoSuite::Sm2Sm3).unwrap();
        assert_eq!(did.semantic_code(), "AGUS");
        assert!(did.as_str().starts_with("did:ans:AGUS:zf"));
    }
}
