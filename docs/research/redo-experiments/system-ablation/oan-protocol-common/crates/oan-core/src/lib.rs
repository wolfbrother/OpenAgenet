// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Core domain types shared by OAN services.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSuite {
    #[serde(alias = "Ed25519Sha256Legacy")]
    Ed25519Sha256Legacy,
    #[serde(alias = "Ed25519Sha256")]
    Ed25519Sha256,
    #[serde(alias = "Sm2Sm3")]
    Sm2Sm3,
}

impl CryptoSuite {
    pub fn signing_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519",
            Self::Sm2Sm3 => "SM2",
        }
    }

    pub fn hash_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "SHA-256",
            Self::Sm2Sm3 => "SM3",
        }
    }

    pub fn verification_method_type(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519VerificationKey2020",
            Self::Sm2Sm3 => "SM2VerificationKey2020",
        }
    }

    pub fn proof_type(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519Signature2020",
            Self::Sm2Sm3 => "SM2Signature2020",
        }
    }

    pub fn did_prefix(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "e",
            Self::Sm2Sm3 => "z",
        }
    }

    pub fn from_verification_method_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519VerificationKey2020" => Some(Self::Ed25519Sha256Legacy),
            "SM2VerificationKey2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }

    pub fn from_proof_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519Signature2020" => Some(Self::Ed25519Sha256Legacy),
            "SM2Signature2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectType {
    Agent,
    InfrastructureNode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Root,
    Registrar,
    Discovery,
    ServiceAgent,
    UserAgent,
    TestAgent,
}

impl NodeRole {
    pub fn semantic_code(&self) -> &'static str {
        match self {
            Self::Root => "AGRT",
            Self::Registrar => "AGRG",
            Self::Discovery => "AGDS",
            Self::ServiceAgent => "AGDM",
            Self::UserAgent => "AGUS",
            Self::TestAgent => "AGTS",
        }
    }

    pub fn subject_type(&self) -> SubjectType {
        match self {
            Self::ServiceAgent | Self::UserAgent | Self::TestAgent => SubjectType::Agent,
            Self::Root | Self::Registrar | Self::Discovery => SubjectType::InfrastructureNode,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "publicKeyFormat", skip_serializing_if = "Option::is_none")]
    pub public_key_format: Option<String>,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

impl VerificationMethod {
    pub fn crypto_suite(&self) -> Option<CryptoSuite> {
        self.crypto_suite
            .clone()
            .or_else(|| CryptoSuite::from_verification_method_type(&self.method_type))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub creator: String,
    pub created: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

impl DataIntegrityProof {
    pub fn crypto_suite(&self) -> Option<CryptoSuite> {
        self.crypto_suite
            .clone()
            .or_else(|| CryptoSuite::from_proof_type(&self.proof_type))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "serverType", skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBinding {
    pub id: String,
    #[serde(rename = "addressType")]
    pub address_type: String,
    pub network: String,
    pub address: String,
    pub controller: String,
    pub purpose: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentDescription {
    #[serde(rename = "capabilityDescription")]
    pub capability_description: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "useCaseExamples", default)]
    pub use_case_examples: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnsMetadata {
    #[serde(rename = "subjectType")]
    pub subject_type: SubjectType,
    #[serde(rename = "identityType")]
    pub identity_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(rename = "addressBindings", default)]
    pub address_bindings: Vec<AddressBinding>,
    #[serde(rename = "agentDescription", skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<AgentDescription>,
    #[serde(rename = "servicePolicy", skip_serializing_if = "Option::is_none")]
    pub service_policy: Option<String>,
    #[serde(rename = "networkScope", skip_serializing_if = "Option::is_none")]
    pub network_scope: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", default)]
    pub assertion_method: Vec<String>,
    #[serde(default)]
    pub service: Vec<ServiceEndpoint>,
    #[serde(rename = "ansMetadata", skip_serializing_if = "Option::is_none")]
    pub ans_metadata: Option<AnsMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTag {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTreeNode {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CapabilityTreeNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTagTree {
    pub version: u64,
    #[serde(default)]
    pub tags: Vec<CapabilityTag>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<CapabilityTreeNode>,
}

impl CapabilityTagTree {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, oan_storage::StorageError> {
        let store = oan_storage::JsonStore::new(".");
        let mut tree: Self = store.read(path)?;
        if tree.tags.is_empty() && !tree.tree.is_empty() {
            tree.flatten_tree();
        }
        Ok(tree)
    }

    pub fn normalize_tag<'a>(&'a self, value: &str) -> Option<&'a str> {
        self.tags.iter().find_map(|tag| {
            if tag.id == value || tag.aliases.iter().any(|alias| alias == value) {
                Some(tag.id.as_str())
            } else {
                None
            }
        })
    }

    pub fn is_descendant_or_same(&self, tag_id: &str, domain_id: &str) -> bool {
        if domain_id == "*" || tag_id == domain_id {
            return true;
        }

        let by_id = self
            .tags
            .iter()
            .map(|tag| (tag.id.as_str(), tag))
            .collect::<BTreeMap<_, _>>();
        let mut current = by_id.get(tag_id).and_then(|tag| tag.parent.as_deref());
        let mut seen = BTreeSet::new();

        while let Some(parent) = current {
            if parent == domain_id {
                return true;
            }
            if !seen.insert(parent) {
                return false;
            }
            current = by_id.get(parent).and_then(|tag| tag.parent.as_deref());
        }

        false
    }

    pub fn matches_authorized_domains(
        &self,
        capability_tags: &[String],
        authorized_domains: &[String],
    ) -> bool {
        if authorized_domains.iter().any(|domain| domain == "*") {
            return true;
        }

        capability_tags.iter().any(|capability| {
            let normalized_capability = self.normalize_tag(capability).unwrap_or(capability);
            authorized_domains.iter().any(|domain| {
                let normalized_domain = self.normalize_tag(domain).unwrap_or(domain);
                self.is_descendant_or_same(normalized_capability, normalized_domain)
            })
        })
    }

    pub fn flatten_tree(&mut self) {
        if !self.tags.is_empty() || self.tree.is_empty() {
            return;
        }

        fn walk(node: &CapabilityTreeNode, parent: Option<&str>, tags: &mut Vec<CapabilityTag>) {
            tags.push(CapabilityTag {
                id: node.id.clone(),
                label: node.label.clone(),
                parent: parent.map(ToOwned::to_owned),
                aliases: vec![],
            });
            for child in &node.children {
                walk(child, Some(node.id.as_str()), tags);
            }
        }

        for node in &self.tree {
            walk(node, None, &mut self.tags);
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidDocumentError {
    #[error("did document id is empty")]
    EmptyId,
    #[error("did document context must include https://www.w3.org/ns/did/v1")]
    MissingDidCoreContext,
    #[error("did document must include at least one verification method")]
    MissingVerificationMethod,
    #[error("did document must include at least one authentication method")]
    MissingAuthentication,
    #[error("did document must include at least one assertion method")]
    MissingAssertionMethod,
}

impl DidDocument {
    pub fn validate_mvp(&self) -> Result<(), DidDocumentError> {
        if self.id.is_empty() {
            return Err(DidDocumentError::EmptyId);
        }
        if !self
            .context
            .iter()
            .any(|value| value == "https://www.w3.org/ns/did/v1")
        {
            return Err(DidDocumentError::MissingDidCoreContext);
        }
        if self.verification_method.is_empty() {
            return Err(DidDocumentError::MissingVerificationMethod);
        }
        if self.authentication.is_empty() {
            return Err(DidDocumentError::MissingAuthentication);
        }
        if self.assertion_method.is_empty() {
            return Err(DidDocumentError::MissingAssertionMethod);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn infrastructure_nodes_are_not_agents() {
        assert_eq!(
            NodeRole::Root.subject_type(),
            SubjectType::InfrastructureNode
        );
        assert_eq!(
            NodeRole::Registrar.subject_type(),
            SubjectType::InfrastructureNode
        );
        assert_eq!(
            NodeRole::Discovery.subject_type(),
            SubjectType::InfrastructureNode
        );
        assert_eq!(NodeRole::ServiceAgent.subject_type(), SubjectType::Agent);
    }

    #[test]
    fn capability_tree_matches_authorized_domain_subtrees() {
        let tree = CapabilityTagTree {
            version: 1,
            tags: vec![
                CapabilityTag {
                    id: "text-processing".to_owned(),
                    label: "Text Processing".to_owned(),
                    parent: None,
                    aliases: vec![],
                },
                CapabilityTag {
                    id: "translation".to_owned(),
                    label: "Translation".to_owned(),
                    parent: Some("text-processing".to_owned()),
                    aliases: vec!["translate".to_owned()],
                },
            ],
            tree: vec![],
        };

        assert!(tree.matches_authorized_domains(
            &["translation".to_owned()],
            &["text-processing".to_owned()]
        ));
        assert!(tree.matches_authorized_domains(
            &["translate".to_owned()],
            &["text-processing".to_owned()]
        ));
        assert!(
            !tree.matches_authorized_domains(&["translation".to_owned()], &["finance".to_owned()])
        );
    }

    #[test]
    fn loads_and_flattens_nested_tree_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tree.json");
        fs::write(
            &path,
            r#"{"version":1,"tree":[{"id":"a","label":"A","children":[{"id":"b","label":"B","children":[{"id":"c","label":"C"}]}]}]}"#,
        )
        .unwrap();

        let tree = CapabilityTagTree::load_from_path(&path).unwrap();

        assert_eq!(tree.tree.len(), 1);
        assert_eq!(tree.tags.len(), 3);
        assert_eq!(tree.tags[0].id, "a");
        assert_eq!(tree.tags[1].parent.as_deref(), Some("a"));
        assert_eq!(tree.tags[2].parent.as_deref(), Some("b"));
    }

    #[test]
    fn verification_method_prefers_explicit_crypto_suite() {
        let method = VerificationMethod {
            id: "did:ans:AGDM:test#key-1".to_owned(),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: "did:ans:AGDM:test".to_owned(),
            crypto_suite: Some(CryptoSuite::Ed25519Sha256),
            public_key_format: Some("multibase".to_owned()),
            public_key_multibase: Some("zExample".to_owned()),
            public_key_jwk: None,
        };

        assert_eq!(method.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
    }

    #[test]
    fn verification_method_infers_legacy_suite_for_historical_shape() {
        let method = VerificationMethod {
            id: "did:ans:AGDM:test#key-1".to_owned(),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: "did:ans:AGDM:test".to_owned(),
            crypto_suite: None,
            public_key_format: None,
            public_key_multibase: Some("zExample".to_owned()),
            public_key_jwk: None,
        };

        assert_eq!(
            method.crypto_suite(),
            Some(CryptoSuite::Ed25519Sha256Legacy)
        );
    }

    #[test]
    fn proof_prefers_explicit_crypto_suite() {
        let proof = DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:ans:AGDM:test#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: Some(CryptoSuite::Ed25519Sha256),
            hash_algorithm: Some("SHA-256".to_owned()),
            verification_method: Some("did:ans:AGDM:test#key-1".to_owned()),
        };

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
    }

    #[test]
    fn proof_infers_legacy_suite_for_historical_shape() {
        let proof = DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:ans:AGDM:test#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: None,
        };

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256Legacy));
    }
}
