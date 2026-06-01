use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use oan_core::{DataIntegrityProof, DidDocument, VerificationMethod};
use oan_crypto::{
    build_data_integrity_proof, crypto_suite_from_verification_method, hash_json_with_suite,
    verify_payload_with_proof, verifying_key_from_method, SigningKey,
};
use oan_protocol::{
    DidControlChallenge, SignedRequestEnvelope, SubjectControlProofBundle, REGISTRATION_FLOW,
};
use oan_storage::JsonStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

pub const DEFAULT_MAX_NONCE_ENTRIES: usize = 10_000;
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static NONCE_STORE_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("{0}")]
    Message(String),
}

impl SecurityError {
    pub fn code(value: impl Into<String>) -> Self {
        Self::Message(value.into())
    }
}

impl From<anyhow::Error> for SecurityError {
    fn from(value: anyhow::Error) -> Self {
        Self::Message(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationRelationship {
    AssertionMethod,
    Authentication,
}

impl VerificationRelationship {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AssertionMethod => "assertionMethod",
            Self::Authentication => "authentication",
        }
    }
}

#[derive(Clone, Debug)]
pub enum AdminAuthMode {
    StaticToken {
        tokens: Vec<String>,
    },
    SignedDid {
        trusted_admin_documents: Vec<DidDocument>,
        max_clock_skew_seconds: i64,
        nonce_ttl_seconds: i64,
        nonce_store_path: PathBuf,
        audience: String,
    },
}

#[derive(Clone, Debug)]
pub struct AdminAuthConfig {
    pub mode: AdminAuthMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminPrincipal {
    pub subject: String,
    pub verification_method: String,
}

#[derive(Clone, Debug)]
pub struct TrustedUpstreamPolicy {
    pub expected_purpose: String,
    pub expected_method: String,
    pub expected_path: String,
    pub expected_audience: String,
    pub max_clock_skew_seconds: i64,
    pub nonce_ttl_seconds: i64,
    pub nonce_store_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedUpstreamContext {
    pub signer_did: String,
    pub verification_method: String,
    pub request_id: String,
}

#[derive(Clone, Debug)]
pub struct DidControlPolicy {
    pub challenge_ttl_seconds: i64,
    pub challenge_purpose: String,
}

#[derive(Clone, Debug)]
pub struct DidControlVerificationContext<'a> {
    pub expected_subject_did: &'a str,
    pub expected_did_document_hash: &'a str,
    pub expected_registrar_did: &'a str,
    pub expected_purpose: &'a str,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NonceStore {
    pub nonces: BTreeMap<String, DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
struct SignedEnvelopePayload<'a> {
    #[serde(rename = "requestId")]
    request_id: &'a str,
    #[serde(rename = "protocolVersion")]
    protocol_version: &'a str,
    purpose: &'a str,
    method: &'a str,
    path: &'a str,
    aud: &'a str,
    #[serde(rename = "requestTimestamp")]
    request_timestamp: DateTime<Utc>,
    #[serde(rename = "requestNonce")]
    request_nonce: &'a str,
    #[serde(rename = "bodyHash")]
    body_hash: &'a str,
}

fn envelope_payload(envelope: &SignedRequestEnvelope) -> SignedEnvelopePayload<'_> {
    SignedEnvelopePayload {
        request_id: &envelope.request_id,
        protocol_version: &envelope.protocol_version,
        purpose: &envelope.purpose,
        method: &envelope.method,
        path: &envelope.path,
        aud: &envelope.aud,
        request_timestamp: envelope.request_timestamp,
        request_nonce: &envelope.request_nonce,
        body_hash: &envelope.body_hash,
    }
}

pub fn create_signed_request_envelope<T: Serialize>(
    request_id: String,
    protocol_version: String,
    purpose: String,
    method: String,
    path: String,
    aud: String,
    payload: &T,
    creator: String,
    verification_method: String,
    signing_key: &SigningKey,
    nonce: String,
) -> Result<SignedRequestEnvelope> {
    let suite = signing_key.crypto_suite();
    let body_hash = hash_json_with_suite(suite, payload)?;
    let mut envelope = SignedRequestEnvelope {
        request_id,
        protocol_version,
        purpose,
        method,
        path,
        aud,
        request_timestamp: Utc::now(),
        request_nonce: nonce,
        body_hash,
        proof: DataIntegrityProof {
            proof_type: String::new(),
            creator: String::new(),
            created: Utc::now(),
            proof_purpose: String::new(),
            proof_value: String::new(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: None,
        },
    };
    let proof = build_data_integrity_proof(
        &envelope_payload(&envelope),
        creator,
        verification_method,
        signing_key,
    )?;
    envelope.proof = proof;
    Ok(envelope)
}

pub fn find_relationship_method<'a>(
    did_document: &'a DidDocument,
    relationship: VerificationRelationship,
    expected_method: Option<&str>,
) -> Result<&'a VerificationMethod, SecurityError> {
    let ids = match relationship {
        VerificationRelationship::AssertionMethod => &did_document.assertion_method,
        VerificationRelationship::Authentication => &did_document.authentication,
    };
    let method = did_document
        .verification_method
        .iter()
        .find(|method| {
            ids.iter().any(|id| id == &method.id)
                && expected_method
                    .map(|value| value == method.id)
                    .unwrap_or(true)
        })
        .ok_or_else(|| SecurityError::code("missing_verification_method"))?;
    Ok(method)
}

pub fn verify_signed_request_envelope<T: Serialize>(
    envelope: &SignedRequestEnvelope,
    payload: &T,
    signer_did: &str,
    signer_document: &DidDocument,
    policy: &TrustedUpstreamPolicy,
    now: DateTime<Utc>,
) -> Result<TrustedUpstreamContext, SecurityError> {
    if envelope.proof.proof_value.is_empty() {
        return Err(SecurityError::code("trusted_upstream_signature_missing"));
    }
    if envelope.method != policy.expected_method {
        return Err(SecurityError::code("trusted_upstream_method_mismatch"));
    }
    if envelope.path != policy.expected_path {
        return Err(SecurityError::code("trusted_upstream_path_mismatch"));
    }
    if envelope.purpose != policy.expected_purpose {
        return Err(SecurityError::code("trusted_upstream_purpose_mismatch"));
    }
    if envelope.aud != policy.expected_audience {
        return Err(SecurityError::code("trusted_upstream_audience_mismatch"));
    }
    verify_freshness(
        envelope.request_timestamp,
        now,
        policy.max_clock_skew_seconds,
        "trusted_upstream_timestamp_stale",
    )?;
    verify_and_store_nonce(
        &policy.nonce_store_path,
        &envelope.request_nonce,
        envelope.request_timestamp,
        now,
        policy.nonce_ttl_seconds,
    )?;
    let fallback_method = format!("{signer_did}#key-1");
    let expected_method = envelope
        .proof
        .verification_method
        .as_deref()
        .or(Some(fallback_method.as_str()))
        .map(str::to_owned);
    let method = find_relationship_method(
        signer_document,
        VerificationRelationship::AssertionMethod,
        expected_method.as_deref(),
    )?;
    let verifying_key = verifying_key_from_method(method)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    verify_payload_with_proof(&envelope_payload(envelope), &envelope.proof, &verifying_key)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    let suite = crypto_suite_from_verification_method(method)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    let actual_body_hash = hash_json_with_suite(suite, payload)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    if actual_body_hash != envelope.body_hash {
        return Err(SecurityError::code("trusted_upstream_body_hash_mismatch"));
    }
    Ok(TrustedUpstreamContext {
        signer_did: signer_did.to_owned(),
        verification_method: method.id.clone(),
        request_id: envelope.request_id.clone(),
    })
}

pub fn verify_signed_request_envelope_without_freshness<T: Serialize>(
    envelope: &SignedRequestEnvelope,
    payload: &T,
    signer_did: &str,
    signer_document: &DidDocument,
    policy: &TrustedUpstreamPolicy,
) -> Result<TrustedUpstreamContext, SecurityError> {
    if envelope.proof.proof_value.is_empty() {
        return Err(SecurityError::code("trusted_upstream_signature_missing"));
    }
    if envelope.method != policy.expected_method {
        return Err(SecurityError::code("trusted_upstream_method_mismatch"));
    }
    if envelope.path != policy.expected_path {
        return Err(SecurityError::code("trusted_upstream_path_mismatch"));
    }
    if envelope.purpose != policy.expected_purpose {
        return Err(SecurityError::code("trusted_upstream_purpose_mismatch"));
    }
    if envelope.aud != policy.expected_audience {
        return Err(SecurityError::code("trusted_upstream_audience_mismatch"));
    }
    let fallback_method = format!("{signer_did}#key-1");
    let expected_method = envelope
        .proof
        .verification_method
        .as_deref()
        .or(Some(fallback_method.as_str()))
        .map(str::to_owned);
    let method = find_relationship_method(
        signer_document,
        VerificationRelationship::AssertionMethod,
        expected_method.as_deref(),
    )?;
    let verifying_key = verifying_key_from_method(method)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    verify_payload_with_proof(&envelope_payload(envelope), &envelope.proof, &verifying_key)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    let suite = crypto_suite_from_verification_method(method)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    let actual_body_hash = hash_json_with_suite(suite, payload)
        .map_err(|_| SecurityError::code("trusted_upstream_signature_invalid"))?;
    if actual_body_hash != envelope.body_hash {
        return Err(SecurityError::code("trusted_upstream_body_hash_mismatch"));
    }
    Ok(TrustedUpstreamContext {
        signer_did: signer_did.to_owned(),
        verification_method: method.id.clone(),
        request_id: envelope.request_id.clone(),
    })
}

pub fn verify_freshness(
    timestamp: DateTime<Utc>,
    now: DateTime<Utc>,
    max_clock_skew_seconds: i64,
    code: &'static str,
) -> Result<(), SecurityError> {
    let skew = (now - timestamp).num_seconds().abs();
    if skew > max_clock_skew_seconds {
        return Err(SecurityError::code(code));
    }
    Ok(())
}

pub fn verify_and_store_nonce(
    nonce_store_path: &Path,
    nonce: &str,
    seen_at: DateTime<Utc>,
    now: DateTime<Utc>,
    ttl_seconds: i64,
) -> Result<(), SecurityError> {
    let lock = nonce_store_lock(nonce_store_path);
    let _guard = lock
        .lock()
        .map_err(|_| SecurityError::code("invalid_nonce_store"))?;
    let store = JsonStore::new(".");
    let mut nonce_store: NonceStore = if nonce_store_path.exists() {
        store
            .read(nonce_store_path)
            .map_err(|_| SecurityError::code("invalid_nonce_store"))?
    } else {
        NonceStore::default()
    };
    let cutoff = now - Duration::seconds(ttl_seconds);
    nonce_store.nonces.retain(|_, value| *value >= cutoff);
    if nonce_store.nonces.contains_key(nonce) {
        return Err(SecurityError::code("trusted_upstream_nonce_replayed"));
    }
    nonce_store.nonces.insert(nonce.to_owned(), seen_at);
    prune_nonce_store(
        &mut nonce_store,
        now,
        ttl_seconds,
        DEFAULT_MAX_NONCE_ENTRIES,
    );
    store
        .write(nonce_store_path, &nonce_store)
        .map_err(|_| SecurityError::code("invalid_nonce_store"))?;
    Ok(())
}

fn nonce_store_lock(path: &Path) -> Arc<Mutex<()>> {
    let registry = NONCE_STORE_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut guard = registry
        .lock()
        .expect("nonce store lock registry should remain usable");
    guard
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn prune_nonce_store(
    nonce_store: &mut NonceStore,
    now: DateTime<Utc>,
    ttl_seconds: i64,
    max_entries: usize,
) {
    let cutoff = now - Duration::seconds(ttl_seconds);
    nonce_store.nonces.retain(|_, value| *value >= cutoff);
    if nonce_store.nonces.len() <= max_entries {
        return;
    }
    let mut entries = nonce_store
        .nonces
        .iter()
        .map(|(nonce, seen_at)| (nonce.clone(), *seen_at))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, seen_at)| *seen_at);
    let overflow = entries.len().saturating_sub(max_entries);
    for (stale_nonce, _) in entries.into_iter().take(overflow) {
        nonce_store.nonces.remove(&stale_nonce);
    }
}

pub fn hash_proof(proof: &DataIntegrityProof) -> Result<String> {
    let suite = proof
        .crypto_suite()
        .ok_or_else(|| SecurityError::code("invalid_proof_hash"))?;
    hash_json_with_suite(suite, proof).map_err(Into::into)
}

pub fn create_did_control_challenge(
    draft_id: &str,
    subject_did: &str,
    did_document_hash: &str,
    registrar_did: &str,
    verification_method: &str,
    policy: &DidControlPolicy,
    nonce: String,
) -> DidControlChallenge {
    let issued_at = Utc::now();
    DidControlChallenge {
        challenge_id: format!("challenge-{draft_id}-{}", issued_at.timestamp_millis()),
        draft_id: draft_id.to_owned(),
        subject_did: subject_did.to_owned(),
        did_document_hash: did_document_hash.to_owned(),
        registrar_did: registrar_did.to_owned(),
        purpose: policy.challenge_purpose.clone(),
        verification_method: verification_method.to_owned(),
        nonce,
        issued_at,
        expires_at: issued_at + Duration::seconds(policy.challenge_ttl_seconds),
    }
}

pub fn verify_subject_control_proof(
    bundle: &SubjectControlProofBundle,
    did_document: &DidDocument,
    context: &DidControlVerificationContext<'_>,
) -> Result<String, SecurityError> {
    let challenge = &bundle.challenge;
    if challenge.subject_did != context.expected_subject_did {
        return Err(SecurityError::code("subject_control_subject_mismatch"));
    }
    if challenge.did_document_hash != context.expected_did_document_hash {
        return Err(SecurityError::code(
            "subject_control_did_document_hash_mismatch",
        ));
    }
    if challenge.registrar_did != context.expected_registrar_did {
        return Err(SecurityError::code("subject_control_registrar_mismatch"));
    }
    if challenge.purpose != context.expected_purpose {
        return Err(SecurityError::code("subject_control_purpose_mismatch"));
    }
    if context.now > challenge.expires_at {
        return Err(SecurityError::code("subject_control_challenge_expired"));
    }
    let method = find_relationship_method(
        did_document,
        VerificationRelationship::AssertionMethod,
        Some(&challenge.verification_method),
    )?;
    let verifying_key = verifying_key_from_method(method)
        .map_err(|_| SecurityError::code("subject_control_proof_invalid"))?;
    verify_payload_with_proof(challenge, &bundle.proof, &verifying_key)
        .map_err(|_| SecurityError::code("subject_control_proof_invalid"))?;
    if let Some(value) = &bundle.proof.verification_method {
        if value != &challenge.verification_method {
            return Err(SecurityError::code(
                "subject_control_verification_method_mismatch",
            ));
        }
    }
    Ok(method.id.clone())
}

pub fn verify_admin_token(
    provided_token: Option<&str>,
    config: &AdminAuthConfig,
) -> Result<AdminPrincipal, SecurityError> {
    match &config.mode {
        AdminAuthMode::StaticToken { tokens } => {
            let token = provided_token.ok_or_else(|| SecurityError::code("admin_auth_required"))?;
            if tokens.iter().any(|value| value == token) {
                Ok(AdminPrincipal {
                    subject: "static-admin".to_owned(),
                    verification_method: "static-token".to_owned(),
                })
            } else {
                Err(SecurityError::code("admin_auth_invalid"))
            }
        }
        AdminAuthMode::SignedDid { .. } => Err(SecurityError::code("admin_auth_required")),
    }
}

pub fn verify_registration_binding_claims(
    claims: &Value,
    subject_did: &str,
    did_document_hash: &str,
    registrar_did: &str,
    expected_purpose: &str,
    bundle: &SubjectControlProofBundle,
) -> Result<(), SecurityError> {
    let claim_hash = claims
        .get("didDocumentHash")
        .and_then(Value::as_str)
        .ok_or_else(|| SecurityError::code("registration_binding_invalid"))?;
    if claim_hash != did_document_hash {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    let binding = claims
        .get("registrationBinding")
        .ok_or_else(|| SecurityError::code("registration_binding_invalid"))?;
    if binding.get("subjectDid").and_then(Value::as_str) != Some(subject_did) {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if binding.get("challengeId").and_then(Value::as_str)
        != Some(bundle.challenge.challenge_id.as_str())
    {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if binding.get("draftId").and_then(Value::as_str) != Some(bundle.challenge.draft_id.as_str()) {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if binding.get("verificationMethod").and_then(Value::as_str)
        != Some(bundle.challenge.verification_method.as_str())
    {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if binding.get("registrarDid").and_then(Value::as_str) != Some(registrar_did) {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if binding.get("purpose").and_then(Value::as_str) != Some(expected_purpose) {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if binding.get("verifiedAt").is_none() {
        return Err(SecurityError::code("registration_binding_invalid"));
    }
    if let Some(expected) = &bundle.proof_hash {
        if binding.get("proofHash").and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(SecurityError::code("registration_binding_invalid"));
        }
    }
    Ok(())
}

pub fn bearer_token_from_header(value: Option<&str>) -> Option<&str> {
    value
        .and_then(|header| header.strip_prefix("Bearer "))
        .map(str::trim)
}

pub fn request_id(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{:016x}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub fn request_nonce(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{:016x}-{:08x}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed),
        rand::random::<u32>()
    )
}

pub fn build_registration_binding_claims(
    did_document_hash: &str,
    challenge: &DidControlChallenge,
    proof_hash: &str,
    verified_at: DateTime<Utc>,
) -> Value {
    json!({
        "didDocumentHash": did_document_hash,
        "registrationBinding": {
            "flow": REGISTRATION_FLOW,
            "draftId": challenge.draft_id,
            "challengeId": challenge.challenge_id,
            "subjectDid": challenge.subject_did,
            "registrarDid": challenge.registrar_did,
            "purpose": challenge.purpose,
            "verificationMethod": challenge.verification_method,
            "proofHash": proof_hash,
            "verifiedAt": verified_at,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_core::{AnsMetadata, CryptoSuite, ServiceEndpoint, SubjectType, VerificationMethod};
    use oan_crypto::{
        build_data_integrity_proof, generate_keypair, hash_json_with_suite, public_key_multibase,
        SigningKey, VerifyingKey,
    };
    use tempfile::tempdir;

    #[test]
    fn admin_static_token_accepts_known_token() {
        let config = AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: vec!["token-1".to_owned()],
            },
        };
        assert!(verify_admin_token(Some("token-1"), &config).is_ok());
        assert!(verify_admin_token(Some("bad"), &config).is_err());
    }

    #[test]
    fn builds_registration_binding_claims() {
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: "did:ans:AGDM:test".to_owned(),
            did_document_hash: "hash-1".to_owned(),
            registrar_did: "did:ans:AGRG:test".to_owned(),
            purpose: "agent-registration".to_owned(),
            verification_method: "did:ans:AGDM:test#key-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        };
        let claims =
            build_registration_binding_claims("hash-1", &challenge, "proof-hash", Utc::now());
        assert_eq!(claims["didDocumentHash"], "hash-1");
        assert_eq!(claims["registrationBinding"]["challengeId"], "challenge-1");
        assert_eq!(
            claims["registrationBinding"]["registrarDid"],
            "did:ans:AGRG:test"
        );
        assert_eq!(
            claims["registrationBinding"]["purpose"],
            "agent-registration"
        );
    }

    #[test]
    fn registration_binding_claims_reject_registrar_mismatch() {
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: "did:ans:AGDM:test".to_owned(),
            did_document_hash: "hash-1".to_owned(),
            registrar_did: "did:ans:AGRG:test".to_owned(),
            purpose: "agent-registration".to_owned(),
            verification_method: "did:ans:AGDM:test#key-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        let bundle = SubjectControlProofBundle {
            challenge: challenge.clone(),
            proof: DataIntegrityProof {
                proof_type: "Ed25519Signature2020".to_owned(),
                creator: "did:ans:AGDM:test#key-1".to_owned(),
                created: Utc::now(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: "sig".to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                hash_algorithm: Some("SHA-256".to_owned()),
                verification_method: Some("did:ans:AGDM:test#key-1".to_owned()),
            },
            verified_at: Some(Utc::now()),
            verified_verification_method: Some("did:ans:AGDM:test#key-1".to_owned()),
            proof_hash: Some("proof-hash".to_owned()),
        };
        let claims =
            build_registration_binding_claims("hash-1", &challenge, "proof-hash", Utc::now());
        assert!(verify_registration_binding_claims(
            &claims,
            "did:ans:AGDM:test",
            "hash-1",
            "did:ans:AGRG:other",
            "agent-registration",
            &bundle
        )
        .is_err());
    }

    #[test]
    fn subject_control_proof_rejects_registrar_and_purpose_mismatch() {
        let did = "did:ans:AGDM:test";
        let method_id = format!("{did}#key-1");
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let signing_key = match &keypair.signing_key {
            SigningKey::Ed25519 { .. } | SigningKey::Sm2 { .. } => keypair.signing_key.clone(),
        };
        let did_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(match &keypair.verifying_key {
                    VerifyingKey::Ed25519 { key, .. } => {
                        public_key_multibase(&VerifyingKey::Ed25519 {
                            suite: CryptoSuite::Ed25519Sha256Legacy,
                            key: *key,
                        })
                    }
                    _ => unreachable!(),
                }),
                public_key_jwk: None,
            }],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id.clone()],
            service: vec![ServiceEndpoint {
                id: format!("{did}#svc"),
                service_type: "AgentInvokeService".to_owned(),
                service_endpoint: "http://localhost".to_owned(),
                version: None,
                protocol: Some("http".to_owned()),
                server_type: None,
                port: None,
            }],
            ans_metadata: Some(AnsMetadata {
                subject_type: SubjectType::Agent,
                identity_type: "service-agent".to_owned(),
                ttl: None,
                address_bindings: vec![],
                agent_description: None,
                service_policy: None,
                network_scope: None,
                extra: Default::default(),
            }),
        };
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &did_document).unwrap();
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: did.to_owned(),
            did_document_hash: did_document_hash.clone(),
            registrar_did: "did:ans:AGRG:test".to_owned(),
            purpose: "agent-registration".to_owned(),
            verification_method: method_id.clone(),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        let proof =
            build_data_integrity_proof(&challenge, did.to_owned(), method_id.clone(), &signing_key)
                .unwrap();
        let bundle = SubjectControlProofBundle {
            challenge,
            proof,
            verified_at: Some(Utc::now()),
            verified_verification_method: Some(method_id),
            proof_hash: Some("proof-hash".to_owned()),
        };

        assert_eq!(
            verify_subject_control_proof(
                &bundle,
                &did_document,
                &DidControlVerificationContext {
                    expected_subject_did: did,
                    expected_did_document_hash: &did_document_hash,
                    expected_registrar_did: "did:ans:AGRG:other",
                    expected_purpose: "agent-registration",
                    now: Utc::now(),
                }
            )
            .unwrap_err()
            .to_string(),
            "subject_control_registrar_mismatch"
        );
        assert_eq!(
            verify_subject_control_proof(
                &bundle,
                &did_document,
                &DidControlVerificationContext {
                    expected_subject_did: did,
                    expected_did_document_hash: &did_document_hash,
                    expected_registrar_did: "did:ans:AGRG:test",
                    expected_purpose: "other-purpose",
                    now: Utc::now(),
                }
            )
            .unwrap_err()
            .to_string(),
            "subject_control_purpose_mismatch"
        );
    }

    #[test]
    fn nonce_store_rejects_replay_and_prunes_expired_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        let now = Utc::now();
        verify_and_store_nonce(&path, "nonce-1", now, now, 60).unwrap();
        assert_eq!(
            verify_and_store_nonce(&path, "nonce-1", now, now, 60)
                .unwrap_err()
                .to_string(),
            "trusted_upstream_nonce_replayed"
        );

        let old = now - Duration::seconds(120);
        verify_and_store_nonce(&path, "nonce-2", old, old, 60).unwrap();
        verify_and_store_nonce(&path, "nonce-3", now, now, 60).unwrap();
        let stored: NonceStore = JsonStore::new(".").read(&path).unwrap();
        assert!(!stored.nonces.contains_key("nonce-2"));
        assert!(stored.nonces.contains_key("nonce-3"));
    }

    #[test]
    fn nonce_store_enforces_max_entry_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        let store = JsonStore::new(".");
        let now = Utc::now();
        let mut nonces = BTreeMap::new();
        for index in 0..(DEFAULT_MAX_NONCE_ENTRIES + 5) {
            nonces.insert(
                format!("nonce-{index}"),
                now - Duration::milliseconds((DEFAULT_MAX_NONCE_ENTRIES + 5 - index) as i64),
            );
        }
        store.write(&path, &NonceStore { nonces }).unwrap();

        verify_and_store_nonce(&path, "fresh-nonce", now, now, 60).unwrap();

        let stored: NonceStore = JsonStore::new(".").read(&path).unwrap();
        assert_eq!(stored.nonces.len(), DEFAULT_MAX_NONCE_ENTRIES);
        assert!(!stored.nonces.contains_key("nonce-0"));
        assert!(stored.nonces.contains_key("fresh-nonce"));
    }

    #[test]
    fn request_nonce_produces_unique_values_under_burst_generation() {
        let mut nonces = std::collections::BTreeSet::new();
        for _ in 0..10_000 {
            let nonce = request_nonce("burst");
            assert!(nonces.insert(nonce));
        }
    }

    #[test]
    fn nonce_store_survives_concurrent_writers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        let start = Utc::now();
        let mut workers = Vec::new();
        for index in 0..32 {
            let path = path.clone();
            workers.push(std::thread::spawn(move || {
                let seen_at = start + Duration::milliseconds(index as i64);
                verify_and_store_nonce(&path, &format!("nonce-{index}"), seen_at, seen_at, 60)
                    .unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let stored: NonceStore = JsonStore::new(".").read(&path).unwrap();
        assert_eq!(stored.nonces.len(), 32);
        for index in 0..32 {
            assert!(stored.nonces.contains_key(&format!("nonce-{index}")));
        }
    }
}
