// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use oan_core::{DidDocument, SubjectType};
use oan_crypto::{hash_json, sign_bytes, signing_key_from_bytes};
use oan_package::{Manifest, VerifiedPackage};
use oan_protocol::{
    DiscoveryCandidate, DiscoveryQuery, DiscoveryResponse, DiscoveryResponseProof, HealthResponse,
};
use oan_storage::JsonStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{
    env,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    upstream: UpstreamConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct UpstreamConfig {
    root_endpoint: String,
    #[serde(default)]
    cdn_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    index_dir: PathBuf,
    keys_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    index: JsonStore,
    config: Config,
    did: String,
    signing_key: ed25519_dalek::SigningKey,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/discovery-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let did_doc: DidDocument = JsonStore::new(&config.paths.data_dir).read("did-document.json")?;
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let signing_key = signing_key_from_bytes(&URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?)?;
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        index: JsonStore::new(&config.paths.index_dir),
        config: config.clone(),
        did: did_doc.id,
        signing_key,
        client: reqwest::Client::new(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/discovery/did", get(discovery_did_document))
        .route("/discovery/sync", post(sync_from_cdn))
        .route("/discover/query", post(query))
        .route("/routes/{did}", get(route_lookup))
        .route("/api/v1/discovery/status", get(api_status))
        .route(
            "/api/v1/discovery/root-authorization",
            get(api_root_authorization),
        )
        .route(
            "/api/v1/discovery/authorized-domains",
            get(api_authorized_domains),
        )
        .route("/api/v1/discovery/sync", post(sync_from_cdn))
        .route("/api/v1/discovery/sync/history", get(api_sync_history))
        .route("/api/v1/discovery/index/stats", get(api_index_stats))
        .route("/api/v1/discovery/index/agents", get(api_index_agents))
        .route("/api/v1/discovery/index/agents/{did}", get(api_index_agent_detail))
        .route("/api/v1/discovery/query", post(query))
        .route("/api/v1/discovery/query/explain", post(api_query_explain))
        .route("/api/v1/discovery/rejected-packages", get(api_rejected_packages))
        .route("/api/v1/discovery/capability-tree", get(api_capability_tree))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("discovery-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.index_dir = resolve_relative(base, &config.paths.index_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    Ok(config)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if path.exists() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "discovery".to_owned(),
        did: Some(state.did),
    })
}

async fn discovery_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(|err| ApiError::internal(err.into()))
}

async fn sync_from_cdn(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let bulletin = fetch_bulletin(&state).await.map_err(ApiError::internal)?;
    let authorized_domains = discovery_authorized_domains(&bulletin, &state.did);
    let root_key = root_verifying_key(&state).await.map_err(ApiError::internal)?;
    let cdn = resolve_cdn_service(&state, &bulletin)
        .await
        .map_err(ApiError::internal)?;
    let manifest: Manifest = state
        .client
        .get(&cdn.manifest_url)
        .send()
        .await
        .map_err(|err| ApiError::internal(err.into()))?
        .json()
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
    let mut indexed = Vec::<VerifiedPackage>::new();
    for entry in manifest.packages {
        let package: VerifiedPackage = state
            .client
            .get(cdn.package_url(&entry.did))
            .send()
            .await
            .map_err(|err| ApiError::internal(err.into()))?
            .json()
            .await
            .map_err(|err| ApiError::internal(err.into()))?;
        if is_indexable_agent(&package)
            && package.verify_document_hash().is_ok()
            && verify_package_root_proof(&package, &bulletin, &root_key)
            && authorized_domains_match(&package, &authorized_domains)
        {
            indexed.push(package);
        }
    }
    state
        .index
        .write("capabilities.json", &indexed)
        .map_err(|err| ApiError::internal(err.into()))?;
    let history = json!({
        "syncedAt": Utc::now(),
        "status": "synced",
        "syncedCount": indexed.len(),
        "cdnManifestUrl": cdn.manifest_url
    });
    append_json_log(&state.config.paths.index_dir.join("sync-history.json"), history)
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "synced",
        "syncedCount": indexed.len(),
        "latestSequence": null,
        "cdnManifestUrl": cdn.manifest_url
    })))
}

#[derive(Clone, Debug)]
struct CdnServiceInfo {
    manifest_url: String,
    packages_url_template: Option<String>,
    base_url: Option<String>,
}

impl CdnServiceInfo {
    fn package_url(&self, did: &str) -> String {
        if let Some(template) = &self.packages_url_template {
            return template.replace("{did}", did);
        }
        format!(
            "{}/cdn/packages/{}",
            self.base_url.as_deref().unwrap_or("").trim_end_matches('/'),
            did
        )
    }
}

async fn resolve_cdn_service(state: &AppState, bulletin: &Value) -> Result<CdnServiceInfo> {
    if let Some(payload) = bulletin["events"].as_array().and_then(|events| {
        events.iter().rev().find_map(|event| {
            (event["eventType"] == "CDN_SERVICE_INFO_UPDATED").then_some(&event["payload"])
        })
    }) {
        if let Some(manifest_url) = payload["manifestUrl"].as_str() {
            return Ok(CdnServiceInfo {
                manifest_url: manifest_url.to_owned(),
                packages_url_template: payload["packagesUrlTemplate"]
                    .as_str()
                    .map(ToOwned::to_owned),
                base_url: payload["baseUrl"].as_str().map(ToOwned::to_owned),
            });
        }
    }

    let fallback = state
        .config
        .upstream
        .cdn_endpoint
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("cdn_service_info_missing"))?;
    Ok(CdnServiceInfo {
        manifest_url: format!("{}/cdn/manifest", fallback.trim_end_matches('/')),
        packages_url_template: None,
        base_url: Some(fallback.clone()),
    })
}

async fn query(
    State(state): State<AppState>,
    Json(query): Json<DiscoveryQuery>,
) -> ApiResult<DiscoveryResponse> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let mut candidates = packages
        .into_iter()
        .filter(|package| matches_query(package, &query))
        .map(|package| DiscoveryCandidate {
            score: score(&package, &query),
            did: package.did,
            capability_tags: package.metadata.capability_tags,
            services: package.metadata.services,
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    candidates.truncate(query.limit as usize);
    let unsigned = DiscoveryResponse {
        discovery_did: state.did.clone(),
        candidates,
        created_at: Utc::now(),
        signature: String::new(),
        proof: None,
    };
    let signature = sign_discovery_response(&state.signing_key, &unsigned)
        .map_err(|err| ApiError::internal(err.into()))?;
    let response = DiscoveryResponse {
        signature: signature.clone(),
        proof: Some(DiscoveryResponseProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: format!("{}#key-1", state.did),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: signature,
        }),
        ..unsigned
    };
    Ok(Json(response))
}

async fn route_lookup(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let package = packages.into_iter().find(|package| package.did == did);
    Ok(Json(match package {
        Some(package) => json!({
            "did": package.did,
            "status": package.metadata.status,
            "services": package.metadata.services
        }),
        None => json!({"did": did, "status": "not-found"}),
    }))
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let history: Vec<Value> = state.index.read("sync-history.json").unwrap_or_default();
    Ok(Json(json!({
        "discoveryDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "cdnEndpoint": state.config.upstream.cdn_endpoint,
        "indexedAgentCount": packages.len(),
        "lastSync": history.last()
    })))
}

async fn api_root_authorization(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = fetch_bulletin(&state).await;
    match bulletin {
        Ok(bulletin) => Ok(Json(json!({
            "discoveryDid": state.did,
            "rootReachable": true,
            "status": discovery_authorization_status(&bulletin, &state.did),
            "authorizedDomains": discovery_authorized_domains(&bulletin, &state.did)
        }))),
        Err(err) => Ok(Json(json!({
            "discoveryDid": state.did,
            "rootReachable": false,
            "status": "unknown",
            "error": err.to_string()
        }))),
    }
}

async fn api_authorized_domains(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = fetch_bulletin(&state).await.map_err(ApiError::internal)?;
    let domains = discovery_authorized_domains(&bulletin, &state.did);
    Ok(Json(json!({
        "discoveryDid": state.did,
        "authorizedDomains": domains
    })))
}

async fn api_sync_history(State(state): State<AppState>) -> ApiResult<Value> {
    let history: Vec<Value> = state.index.read("sync-history.json").unwrap_or_default();
    Ok(Json(json!({ "items": history, "count": history.len() })))
}

async fn api_index_stats(State(state): State<AppState>) -> ApiResult<Value> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let mut tag_counts = serde_json::Map::new();
    for package in &packages {
        for tag in &package.metadata.capability_tags {
            let next = tag_counts.get(tag).and_then(Value::as_u64).unwrap_or(0) + 1;
            tag_counts.insert(tag.clone(), json!(next));
        }
    }
    Ok(Json(json!({
        "indexedAgentCount": packages.len(),
        "capabilityTagCounts": tag_counts
    })))
}

async fn api_index_agents(State(state): State<AppState>) -> ApiResult<Value> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let items = packages
        .into_iter()
        .map(|package| json!({
            "did": package.did,
            "capabilityTags": package.metadata.capability_tags,
            "services": package.metadata.services,
            "status": package.metadata.status,
            "updatedAt": package.metadata.updated_at
        }))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "items": items, "count": items.len() })))
}

async fn api_index_agent_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let package = packages.into_iter().find(|package| package.did == did);
    Ok(Json(json!({ "did": did, "package": package })))
}

async fn api_query_explain(
    State(state): State<AppState>,
    Json(query): Json<DiscoveryQuery>,
) -> ApiResult<Value> {
    let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap_or_default();
    let explanations = packages
        .iter()
        .map(|package| {
            let matched = matches_query(package, &query);
            json!({
                "did": package.did,
                "matched": matched,
                "score": if matched { score(package, &query) } else { 0.0 },
                "capabilityTagOverlap": query.capability_tags.iter()
                    .filter(|tag| package.metadata.capability_tags.iter().any(|candidate| candidate == *tag))
                    .cloned()
                    .collect::<Vec<_>>(),
                "serviceTypeMatched": query.service_type.as_ref().map(|service_type| {
                    package.metadata.services.iter().any(|service| &service.service_type == service_type)
                }),
                "protocolMatched": query.protocol.as_ref().map(|protocol| {
                    package.metadata.services.iter().any(|service| service.protocol.as_ref() == Some(protocol))
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "query": query, "items": explanations })))
}

async fn api_rejected_packages(State(state): State<AppState>) -> ApiResult<Value> {
    let items: Vec<Value> = state.index.read("rejected-packages.json").unwrap_or_default();
    Ok(Json(json!({ "items": items, "count": items.len() })))
}

async fn api_capability_tree(State(state): State<AppState>) -> ApiResult<Value> {
    let response = state
        .client
        .get(format!(
            "{}/api/v1/root/capability-tree",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            let value = response
                .json()
                .await
                .map_err(|err| ApiError::internal(err.into()))?;
            Ok(Json(value))
        }
        Ok(response) => Ok(Json(json!({
            "source": "root",
            "status": "unavailable",
            "statusCode": response.status().as_u16()
        }))),
        Err(err) => Ok(Json(json!({
            "source": "root",
            "status": "unavailable",
            "error": err.to_string()
        }))),
    }
}

async fn fetch_bulletin(state: &AppState) -> Result<Value> {
    Ok(state
        .client
        .get(format!(
            "{}/bulletin",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await?
        .json()
        .await?)
}

fn discovery_authorization_status(bulletin: &Value, discovery_did: &str) -> String {
    if bulletin["events"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["subjectDid"] == discovery_did
                    && event["eventType"] == "DISCOVERY_NODE_REVOKED"
            })
        })
        .unwrap_or(false)
    {
        "revoked".to_owned()
    } else {
        "active".to_owned()
    }
}

fn append_json_log(path: &Path, value: Value) -> Result<()> {
    let mut items: Vec<Value> = if path.exists() {
        serde_json::from_str(&fs::read_to_string(path)?)?
    } else {
        vec![]
    };
    items.push(value);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&items)?)?;
    Ok(())
}

fn is_indexable_agent(package: &VerifiedPackage) -> bool {
    package
        .did_document
        .ans_metadata
        .as_ref()
        .map(|metadata| metadata.subject_type == SubjectType::Agent)
        .unwrap_or(false)
        && !package.metadata.services.is_empty()
}

async fn root_verifying_key(state: &AppState) -> Result<ed25519_dalek::VerifyingKey> {
    let did_doc: DidDocument = state
        .client
        .get(format!(
            "{}/root/did",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await?
        .json()
        .await?;
    let method = did_doc
        .verification_method
        .iter()
        .find(|method| did_doc.assertion_method.iter().any(|id| id == &method.id))
        .ok_or_else(|| anyhow::anyhow!("missing_root_verification_method"))?;
    if let Some(jwk) = &method.public_key_jwk {
        oan_crypto::verifying_key_from_public_key_jwk(jwk).map_err(Into::into)
    } else if let Some(multibase) = &method.public_key_multibase {
        oan_crypto::verifying_key_from_public_key_multibase(multibase).map_err(Into::into)
    } else {
        Err(anyhow::anyhow!("invalid_root_key"))
    }
}

fn discovery_authorized_domains(bulletin: &Value, discovery_did: &str) -> Vec<String> {
    bulletin["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .rev()
                .find(|event| {
                    event["subjectDid"] == discovery_did
                        && event["eventType"] == "DISCOVERY_NODE_DOMAINS_UPDATED"
                })
                .map(|event| event["payload"].clone())
        })
        .and_then(|payload| payload["authorizedDomains"].as_array().cloned())
        .map(|values| {
            values
                .into_iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_else(|| vec!["*".to_owned()])
}

fn verify_package_root_proof(
    package: &VerifiedPackage,
    bulletin: &Value,
    root_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    let Some(event_hash) = package.root_proof.bulletin_event_hash.as_deref() else {
        return false;
    };
    let Some(signature) = package.root_proof.signature.as_deref() else {
        return false;
    };
    let event_exists = bulletin["events"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["eventHash"] == event_hash
                    && event["subjectDid"] == package.did
                    && event["eventType"].is_string()
            })
        })
        .unwrap_or(false);
    event_exists && oan_crypto::verify_bytes(root_key, event_hash.as_bytes(), signature).is_ok()
}

fn authorized_domains_match(package: &VerifiedPackage, authorized_domains: &[String]) -> bool {
    package.metadata.capability_tags.iter().any(|tag| {
        authorized_domains.iter().any(|domain| {
            if domain == "*" {
                true
            } else {
                tag == domain
            }
        })
    })
}

fn sign_discovery_response(
    signing_key: &ed25519_dalek::SigningKey,
    response: &DiscoveryResponse,
) -> Result<String, anyhow::Error> {
    let unsigned = serde_json::json!({
        "discoveryDid": response.discovery_did,
        "candidates": response.candidates,
        "createdAt": response.created_at,
    });
    let hash = hash_json(&unsigned)?;
    Ok(sign_bytes(signing_key, hash.as_bytes()))
}

fn matches_query(package: &VerifiedPackage, query: &DiscoveryQuery) -> bool {
    if !query.capability_tags.is_empty()
        && !query.capability_tags.iter().any(|tag| {
            package
                .metadata
                .capability_tags
                .iter()
                .any(|candidate| candidate == tag)
        })
    {
        return false;
    }
    if let Some(service_type) = &query.service_type {
        if !package
            .metadata
            .services
            .iter()
            .any(|service| &service.service_type == service_type)
        {
            return false;
        }
    }
    if let Some(protocol) = &query.protocol {
        if !package
            .metadata
            .services
            .iter()
            .any(|service| service.protocol.as_ref() == Some(protocol))
        {
            return false;
        }
    }
    package.metadata.status == "active"
}

fn score(package: &VerifiedPackage, query: &DiscoveryQuery) -> f32 {
    let tag_hits = query
        .capability_tags
        .iter()
        .filter(|tag| {
            package
                .metadata
                .capability_tags
                .iter()
                .any(|candidate| candidate == *tag)
        })
        .count() as f32;
    0.5 + tag_hits * 0.25
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oan_core::{AgentDescription, AnsMetadata, ServiceEndpoint};
    use oan_crypto::generate_ed25519_keypair;
    use oan_package::{AgentMetadata, RootProof};

    fn package_with_tags(tags: Vec<&str>) -> VerifiedPackage {
        let services = vec![ServiceEndpoint {
            id: "did:ans:AGDM:efserviceagentservice1234#invoke".to_owned(),
            service_type: "AgentInvokeService".to_owned(),
            service_endpoint: "http://localhost:9001/agent/invoke".to_owned(),
            version: None,
            protocol: Some("http".to_owned()),
            server_type: None,
            port: Some(9001),
        }];
        let did_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: services.clone(),
            ans_metadata: Some(AnsMetadata {
                subject_type: SubjectType::Agent,
                identity_type: "service-agent".to_owned(),
                ttl: None,
                address_bindings: vec![],
                agent_description: Some(AgentDescription {
                    capability_description: "demo".to_owned(),
                    capability_tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
                    use_case_examples: vec![],
                }),
                service_policy: None,
                network_scope: None,
                extra: Default::default(),
            }),
        };
        VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did_document.id.clone(),
            did_document_hash: hash_json(&did_document).unwrap(),
            metadata: AgentMetadata {
                did: did_document.id.clone(),
                role: "Service Agent".to_owned(),
                identity_type: "service-agent".to_owned(),
                did_document_hash: hash_json(&did_document).unwrap(),
                capability_tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
                services,
                status: "active".to_owned(),
                updated_at: Utc::now(),
            },
            did_document,
            root_proof: RootProof {
                root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                bulletin_event_hash: None,
                signature: None,
            },
            created_at: Utc::now(),
        }
    }

    #[test]
    fn authorized_domains_filter_packages_by_tag() {
        let package = package_with_tags(vec!["finance"]);

        assert!(authorized_domains_match(&package, &["*".to_owned()]));
        assert!(authorized_domains_match(&package, &["finance".to_owned()]));
        assert!(!authorized_domains_match(&package, &["translation".to_owned()]));
    }

    #[test]
    fn package_root_proof_requires_matching_bulletin_event_and_signature() {
        let root_key = generate_ed25519_keypair();
        let mut package = package_with_tags(vec!["finance"]);
        let event_hash = "event-hash";
        package.root_proof.bulletin_event_hash = Some(event_hash.to_owned());
        package.root_proof.signature = Some(sign_bytes(&root_key, event_hash.as_bytes()));
        let bulletin = json!({
            "events": [{
                "eventHash": event_hash,
                "subjectDid": package.did,
                "eventType": "AGENT_DID_DOCUMENT_ANCHORED"
            }]
        });

        assert!(verify_package_root_proof(
            &package,
            &bulletin,
            &root_key.verifying_key()
        ));

        let wrong_bulletin = json!({"events": []});
        assert!(!verify_package_root_proof(
            &package,
            &wrong_bulletin,
            &root_key.verifying_key()
        ));
    }

    #[test]
    fn discovery_response_signature_is_verifiable() {
        let signing_key = generate_ed25519_keypair();
        let response = DiscoveryResponse {
            discovery_did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            candidates: vec![],
            created_at: Utc::now(),
            signature: String::new(),
            proof: None,
        };

        let signature = sign_discovery_response(&signing_key, &response).unwrap();
        let unsigned = json!({
            "discoveryDid": response.discovery_did,
            "candidates": response.candidates,
            "createdAt": response.created_at,
        });
        let hash = hash_json(&unsigned).unwrap();

        assert!(oan_crypto::verify_bytes(
            &signing_key.verifying_key(),
            hash.as_bytes(),
            &signature
        )
        .is_ok());
    }

    #[tokio::test]
    async fn api_status_reports_basic_index_state() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: generate_ed25519_keypair(),
            client: reqwest::Client::new(),
        };
        state
            .index
            .write("capabilities.json", &vec![package_with_tags(vec!["finance"])])
            .unwrap();
        let response = api_status(State(state)).await.unwrap();
        assert_eq!(response.0["indexedAgentCount"], 1);
    }

    #[tokio::test]
    async fn api_query_explain_reports_matches() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: generate_ed25519_keypair(),
            client: reqwest::Client::new(),
        };
        state
            .index
            .write("capabilities.json", &vec![package_with_tags(vec!["finance"])])
            .unwrap();
        let response = api_query_explain(
            State(state),
            Json(DiscoveryQuery {
                capability_tags: vec!["finance".to_owned()],
                service_type: Some("AgentInvokeService".to_owned()),
                protocol: Some("http".to_owned()),
                limit: 10,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0["items"].as_array().unwrap().len(), 1);
        assert!(response.0["items"][0]["matched"].as_bool().unwrap());
    }

    #[test]
    fn discovery_authorization_status_detects_revocation() {
        let bulletin = json!({
            "events": [{
                "subjectDid": "did:ans:AGDS:efdiscoverydiscovery1234",
                "eventType": "DISCOVERY_NODE_REVOKED"
            }]
        });
        assert_eq!(
            discovery_authorization_status(&bulletin, "did:ans:AGDS:efdiscoverydiscovery1234"),
            "revoked"
        );
    }
}
