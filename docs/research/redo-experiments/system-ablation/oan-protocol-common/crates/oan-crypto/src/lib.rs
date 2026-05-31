// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Cryptographic helpers for OpenAgenet.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey, Verifier as _,
    VerifyingKey as Ed25519VerifyingKey,
};
use oan_core::{CryptoSuite, DataIntegrityProof, VerificationMethod};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use sm2::dsa::{
    signature::{Signer as Sm2Signer, Verifier as Sm2Verifier},
    Signature as Sm2Signature, SigningKey as Sm2SigningKey, VerifyingKey as Sm2VerifyingKey,
};
use sm3::{Digest as Sm3Digest, Sm3};
use thiserror::Error;

const DEFAULT_SM2_DISTINGUISHED_ID: &str = "1234567812345678";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported crypto suite")]
    UnsupportedCryptoSuite,
    #[error("invalid signing key")]
    InvalidSigningKey,
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
    #[error("invalid public key encoding")]
    InvalidPublicKeyEncoding,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("invalid proof")]
    InvalidProof,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("missing key material")]
    MissingKeyMaterial,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
pub enum SigningKey {
    Ed25519 {
        suite: CryptoSuite,
        key: Ed25519SigningKey,
    },
    Sm2 {
        suite: CryptoSuite,
        key: Sm2SigningKey,
    },
}

#[derive(Clone, Debug)]
pub enum VerifyingKey {
    Ed25519 {
        suite: CryptoSuite,
        key: Ed25519VerifyingKey,
    },
    Sm2 {
        suite: CryptoSuite,
        key: Sm2VerifyingKey,
    },
}

#[derive(Clone, Debug)]
pub struct KeypairMaterial {
    pub crypto_suite: CryptoSuite,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl SigningKey {
    pub fn crypto_suite(&self) -> CryptoSuite {
        match self {
            Self::Ed25519 { suite, .. } | Self::Sm2 { suite, .. } => suite.clone(),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519 { suite, key } => VerifyingKey::Ed25519 {
                suite: suite.clone(),
                key: key.verifying_key(),
            },
            Self::Sm2 { suite, key } => VerifyingKey::Sm2 {
                suite: suite.clone(),
                key: key.verifying_key().clone(),
            },
        }
    }
}

impl VerifyingKey {
    pub fn crypto_suite(&self) -> CryptoSuite {
        match self {
            Self::Ed25519 { suite, .. } | Self::Sm2 { suite, .. } => suite.clone(),
        }
    }
}

pub fn generate_keypair(suite: CryptoSuite) -> Result<KeypairMaterial, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let signing_key = Ed25519SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            Ok(KeypairMaterial {
                crypto_suite: suite.clone(),
                signing_key: SigningKey::Ed25519 {
                    suite: suite.clone(),
                    key: signing_key,
                },
                verifying_key: VerifyingKey::Ed25519 {
                    suite,
                    key: verifying_key,
                },
            })
        }
        CryptoSuite::Sm2Sm3 => {
            let signing_key = generate_sm2_keypair()?;
            let verifying_key = signing_key.verifying_key().clone();
            Ok(KeypairMaterial {
                crypto_suite: suite.clone(),
                signing_key: SigningKey::Sm2 {
                    suite: suite.clone(),
                    key: signing_key,
                },
                verifying_key: VerifyingKey::Sm2 {
                    suite,
                    key: verifying_key,
                },
            })
        }
    }
}

pub fn generate_ed25519_keypair() -> Ed25519SigningKey {
    Ed25519SigningKey::generate(&mut OsRng)
}

pub fn generate_sm2_keypair() -> Result<Sm2SigningKey, CryptoError> {
    for _ in 0..32 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(signing_key) = Sm2SigningKey::from_slice(DEFAULT_SM2_DISTINGUISHED_ID, &bytes) {
            return Ok(signing_key);
        }
    }
    Err(CryptoError::InvalidSigningKey)
}

pub fn signing_key_from_bytes(suite: CryptoSuite, bytes: &[u8]) -> Result<SigningKey, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidSigningKey)?;
            Ok(SigningKey::Ed25519 {
                suite,
                key: Ed25519SigningKey::from_bytes(&bytes),
            })
        }
        CryptoSuite::Sm2Sm3 => Sm2SigningKey::from_slice(DEFAULT_SM2_DISTINGUISHED_ID, bytes)
            .map(|key| SigningKey::Sm2 { suite, key })
            .map_err(|_| CryptoError::InvalidSigningKey),
    }
}

pub fn signing_key_from_legacy_ed25519_bytes(
    bytes: &[u8],
) -> Result<Ed25519SigningKey, CryptoError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    Ok(Ed25519SigningKey::from_bytes(&bytes))
}

pub fn verifying_key_from_bytes(
    suite: CryptoSuite,
    bytes: &[u8],
) -> Result<VerifyingKey, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidVerifyingKey)?;
            Ed25519VerifyingKey::from_bytes(&bytes)
                .map(|key| VerifyingKey::Ed25519 { suite, key })
                .map_err(|_| CryptoError::InvalidVerifyingKey)
        }
        CryptoSuite::Sm2Sm3 => {
            Sm2VerifyingKey::from_sec1_bytes(DEFAULT_SM2_DISTINGUISHED_ID, bytes)
                .map(|key| VerifyingKey::Sm2 { suite, key })
                .map_err(|_| CryptoError::InvalidVerifyingKey)
        }
    }
}

pub fn verifying_key_from_legacy_ed25519_bytes(
    bytes: &[u8],
) -> Result<Ed25519VerifyingKey, CryptoError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidVerifyingKey)?;
    Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidVerifyingKey)
}

pub fn verifying_key_from_public_key_multibase(
    suite: CryptoSuite,
    public_key_multibase: &str,
) -> Result<VerifyingKey, CryptoError> {
    let encoded = public_key_multibase
        .strip_prefix('z')
        .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
    verifying_key_from_bytes(suite, &bytes)
}

pub fn verifying_key_from_public_key_jwk(
    suite: CryptoSuite,
    public_key_jwk: &serde_json::Value,
) -> Result<VerifyingKey, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let x = public_key_jwk
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
            verifying_key_from_bytes(suite, &bytes)
        }
        CryptoSuite::Sm2Sm3 => {
            let x = public_key_jwk
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
            let y = public_key_jwk
                .get("y")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
            let x = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
            let y = URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(CryptoError::InvalidPublicKeyEncoding);
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            verifying_key_from_bytes(suite, &sec1)
        }
    }
}

pub fn sign_bytes(signing_key: &SigningKey, payload: &[u8]) -> Result<String, CryptoError> {
    match signing_key {
        SigningKey::Ed25519 { key, .. } => Ok(URL_SAFE_NO_PAD.encode(key.sign(payload).to_bytes())),
        SigningKey::Sm2 { key, .. } => {
            let signature: Sm2Signature = Sm2Signer::sign(key, payload);
            Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        }
    }
}

pub fn sign_legacy_ed25519_bytes(signing_key: &Ed25519SigningKey, payload: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(signing_key.sign(payload).to_bytes())
}

pub fn verify_bytes(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| CryptoError::InvalidSignature)?;
    match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => {
            let signature = Ed25519Signature::from_slice(&signature_bytes)
                .map_err(|_| CryptoError::InvalidSignature)?;
            key.verify(payload, &signature)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        VerifyingKey::Sm2 { key, .. } => {
            let signature = Sm2Signature::from_slice(&signature_bytes)
                .map_err(|_| CryptoError::InvalidSignature)?;
            Sm2Verifier::verify(key, payload, &signature)
                .map_err(|_| CryptoError::VerificationFailed)
        }
    }
}

pub fn verify_legacy_ed25519_bytes(
    verifying_key: &Ed25519VerifyingKey,
    payload: &[u8],
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Ed25519Signature::from_slice(&signature_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

pub fn hash_hex(suite: CryptoSuite, payload: impl AsRef<[u8]>) -> String {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            hex::encode(Sha256::digest(payload.as_ref()))
        }
        CryptoSuite::Sm2Sm3 => hex::encode(Sm3::digest(payload.as_ref())),
    }
}

pub fn sha256_hex(payload: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(payload.as_ref()))
}

pub fn sm3_hex(payload: impl AsRef<[u8]>) -> String {
    hex::encode(Sm3::digest(payload.as_ref()))
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_value(&value))
}

pub fn hash_json_with_suite<T: Serialize>(
    suite: CryptoSuite,
    value: &T,
) -> Result<String, CryptoError> {
    Ok(hash_hex(suite, canonical_json(value)?))
}

pub fn hash_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, value)
}

pub fn signature_input<T: Serialize>(
    suite: CryptoSuite,
    value: &T,
) -> Result<Vec<u8>, CryptoError> {
    let canonical = canonical_json(value)?;
    match suite {
        CryptoSuite::Ed25519Sha256Legacy => Ok(hash_hex(suite, canonical).into_bytes()),
        CryptoSuite::Ed25519Sha256 | CryptoSuite::Sm2Sm3 => Ok(canonical.into_bytes()),
    }
}

pub fn public_key_multibase(verifying_key: &VerifyingKey) -> String {
    let bytes = match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => key.as_bytes().to_vec(),
        VerifyingKey::Sm2 { key, .. } => key.to_sec1_bytes().into_vec(),
    };
    format!("z{}", bs58::encode(bytes).into_string())
}

pub fn public_key_jwk(verifying_key: &VerifyingKey) -> serde_json::Value {
    match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(key.as_bytes()),
        }),
        VerifyingKey::Sm2 { key, .. } => {
            let bytes = key.to_sec1_bytes();
            let x = &bytes[1..33];
            let y = &bytes[33..65];
            serde_json::json!({
                "kty": "EC",
                "crv": "SM2",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            })
        }
    }
}

pub fn crypto_suite_from_verification_method(
    method: &VerificationMethod,
) -> Result<CryptoSuite, CryptoError> {
    method
        .crypto_suite()
        .ok_or(CryptoError::UnsupportedCryptoSuite)
}

pub fn verifying_key_from_method(method: &VerificationMethod) -> Result<VerifyingKey, CryptoError> {
    let suite = crypto_suite_from_verification_method(method)?;
    if let Some(multibase) = &method.public_key_multibase {
        verifying_key_from_public_key_multibase(suite, multibase)
    } else if let Some(jwk) = &method.public_key_jwk {
        verifying_key_from_public_key_jwk(suite, jwk)
    } else {
        Err(CryptoError::MissingKeyMaterial)
    }
}

pub fn crypto_suite_from_proof(proof: &DataIntegrityProof) -> Result<CryptoSuite, CryptoError> {
    proof
        .crypto_suite()
        .ok_or(CryptoError::UnsupportedCryptoSuite)
}

pub fn verify_payload_with_proof<T: Serialize>(
    payload: &T,
    proof: &DataIntegrityProof,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let suite = crypto_suite_from_proof(proof)?;
    if suite != verifying_key.crypto_suite() {
        return Err(CryptoError::VerificationFailed);
    }
    let input = signature_input(suite, payload)?;
    verify_bytes(verifying_key, &input, &proof.proof_value)
}

pub fn build_data_integrity_proof<T: Serialize>(
    payload: &T,
    creator: String,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<DataIntegrityProof, CryptoError> {
    let suite = signing_key.crypto_suite();
    let input = signature_input(suite.clone(), payload)?;
    Ok(DataIntegrityProof {
        proof_type: suite.proof_type().to_owned(),
        creator,
        created: chrono::Utc::now(),
        proof_purpose: "assertionMethod".to_owned(),
        proof_value: sign_bytes(signing_key, &input)?,
        crypto_suite: Some(suite.clone()),
        hash_algorithm: Some(suite.hash_algorithm().to_owned()),
        verification_method: Some(verification_method),
    })
}

pub fn canonical_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_owned(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => {
            serde_json::to_string(value).expect("string serialization cannot fail")
        }
        serde_json::Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        }
        serde_json::Value::Object(map) => {
            let items = map
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serialization cannot fail"),
                        canonical_json_value(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{items}}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signs_and_verifies_ed25519_payload() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let signature = sign_bytes(&keypair.signing_key, b"hello").unwrap();

        verify_bytes(&keypair.verifying_key, b"hello", &signature).unwrap();
        assert!(verify_bytes(&keypair.verifying_key, b"HELLO", &signature).is_err());
    }

    #[test]
    fn signs_and_verifies_sm2_payload() {
        let keypair = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let signature = sign_bytes(&keypair.signing_key, b"hello").unwrap();

        verify_bytes(&keypair.verifying_key, b"hello", &signature).unwrap();
        assert!(verify_bytes(&keypair.verifying_key, b"HELLO", &signature).is_err());
    }

    #[test]
    fn canonical_json_orders_keys() {
        let value = json!({"b": 2, "a": 1});
        assert_eq!(canonical_json_value(&value), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn parses_ed25519_verifying_key_from_jwk_and_multibase() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let jwk = public_key_jwk(&keypair.verifying_key);
        let multibase = public_key_multibase(&keypair.verifying_key);

        let from_jwk =
            verifying_key_from_public_key_jwk(CryptoSuite::Ed25519Sha256Legacy, &jwk).unwrap();
        let from_multibase =
            verifying_key_from_public_key_multibase(CryptoSuite::Ed25519Sha256Legacy, &multibase)
                .unwrap();

        assert!(matches!(from_jwk, VerifyingKey::Ed25519 { .. }));
        assert!(matches!(from_multibase, VerifyingKey::Ed25519 { .. }));
    }

    #[test]
    fn parses_sm2_verifying_key_from_jwk_and_multibase() {
        let keypair = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let jwk = public_key_jwk(&keypair.verifying_key);
        let multibase = public_key_multibase(&keypair.verifying_key);

        let from_jwk = verifying_key_from_public_key_jwk(CryptoSuite::Sm2Sm3, &jwk).unwrap();
        let from_multibase =
            verifying_key_from_public_key_multibase(CryptoSuite::Sm2Sm3, &multibase).unwrap();

        assert!(matches!(from_jwk, VerifyingKey::Sm2 { .. }));
        assert!(matches!(from_multibase, VerifyingKey::Sm2 { .. }));
    }

    #[test]
    fn signature_input_keeps_legacy_hash_behavior() {
        let payload = json!({"a": 1});
        let legacy =
            String::from_utf8(signature_input(CryptoSuite::Ed25519Sha256Legacy, &payload).unwrap())
                .unwrap();
        let modern =
            String::from_utf8(signature_input(CryptoSuite::Sm2Sm3, &payload).unwrap()).unwrap();

        assert_eq!(legacy.len(), 64);
        assert_eq!(modern, r#"{"a":1}"#);
    }

    #[test]
    fn proof_verification_accepts_legacy_shape_without_crypto_suite() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let payload = json!({"a": 1});
        let input = signature_input(CryptoSuite::Ed25519Sha256Legacy, &payload).unwrap();
        let proof = DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:ans:AGDM:test#key-1".to_owned(),
            created: chrono::Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: sign_bytes(&keypair.signing_key, &input).unwrap(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: None,
        };

        verify_payload_with_proof(&payload, &proof, &keypair.verifying_key).unwrap();
    }

    #[test]
    fn proof_verification_uses_explicit_suite_without_downgrading() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let payload = json!({"a": 1});
        let proof = build_data_integrity_proof(
            &payload,
            "did:ans:AGDM:test#key-1".to_owned(),
            "did:ans:AGDM:test#key-1".to_owned(),
            &keypair.signing_key,
        )
        .unwrap();

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
        verify_payload_with_proof(&payload, &proof, &keypair.verifying_key).unwrap();
    }
}
