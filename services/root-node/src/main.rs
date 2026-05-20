// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use oan_bulletin::{Bulletin, BulletinEvent, BulletinEventCore, BulletinEventType};
use oan_core::{CapabilityTag, CapabilityTagTree, DidDocument, SubjectType};
use oan_credentials::{verify_agent_registration_credential, AgentRegistrationCredential};
use oan_crypto::{hash_json, sign_bytes, signing_key_from_bytes};
use oan_did_ans::DidAns;
use oan_package::{AgentMetadata, RootProof, VerifiedPackage};
use oan_protocol::{HealthResponse, RootAuthorizeRequest, VerifyAndPublishRequest};
use oan_storage::{did_to_file_name, JsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    keys_dir: PathBuf,
    bulletin_file: PathBuf,
    #[serde(default = "default_capability_tree_file")]
    capability_tree_file: PathBuf,
}

fn default_capability_tree_file() -> PathBuf {
    PathBuf::from("../../docs/capability-tree-v1.json")
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    root_did: String,
    signing_key: ed25519_dalek::SigningKey,
    tag_tree: CapabilityTagTree,
    lock: Arc<Mutex<()>>,
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
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

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

#[derive(Clone, Debug, Serialize)]
struct VerifyResponse {
    status: String,
    operation: String,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    #[serde(rename = "documentVersion")]
    document_version: u64,
    #[serde(rename = "bulletinSequence")]
    bulletin_sequence: u64,
    #[serde(rename = "bulletinEventHash")]
    bulletin_event_hash: String,
    #[serde(rename = "cdnDispatchStatus")]
    cdn_dispatch_status: String,
    #[serde(rename = "discoveryNotifyStatus")]
    discovery_notify_status: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    did: String,
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/root-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let data = JsonStore::new(&config.paths.data_dir);
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let signing_key = signing_key_from_bytes(&URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?)?;
    let state = AppState {
        data,
        config: config.clone(),
        root_did: key.did,
        signing_key,
        tag_tree: oan_core::CapabilityTagTree::load_from_path(&config.paths.capability_tree_file)
            .unwrap_or_else(|_| default_tag_tree()),
        lock: Arc::new(Mutex::new(())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/root/did", get(root_did_document))
        .route("/bulletin", get(bulletin))
        .route("/root/registrars/authorize", post(authorize_registrar))
        .route("/root/discovery-nodes/authorize", post(authorize_discovery))
        .route("/root/discovery-nodes/{did}/domains", post(update_discovery_domains))
        .route("/root/nodes/{did}/revoke", post(revoke_node))
        .route("/root/agents/verify-and-publish", post(verify_and_publish))
        .route("/root/batches/publish-cdn", post(publish_cdn_batch))
        .route(
            "/root/batches/notify-discovery",
            post(notify_discovery_batch),
        )
        .route("/api/v1/root/status", get(api_status))
        .route("/api/v1/root/registrars", get(api_registrars))
        .route("/api/v1/root/registrars/{did}", get(api_registrar_detail))
        .route("/api/v1/root/discovery-nodes", get(api_discovery_nodes))
        .route("/api/v1/root/discovery-nodes/{did}", get(api_discovery_detail))
        .route("/api/v1/root/agents", get(api_agents))
        .route("/api/v1/root/agents/{did}", get(api_agent_detail))
        .route("/api/v1/root/agents/{did}/versions", get(api_agent_versions))
        .route(
            "/api/v1/root/agents/{did}/versions/{version}",
            get(api_agent_version_detail),
        )
        .route("/api/v1/root/queues/cdn-publish", get(api_cdn_publish_queue))
        .route(
            "/api/v1/root/queues/discovery-notify",
            get(api_discovery_notify_queue),
        )
        .route(
            "/api/v1/root/queues/cdn-publish/run",
            post(publish_cdn_batch),
        )
        .route(
            "/api/v1/root/queues/discovery-notify/run",
            post(notify_discovery_batch),
        )
        .route("/api/v1/root/capability-tree", get(api_capability_tree))
        .route(
            "/api/v1/root/capability-tree/validate-tags",
            post(api_validate_tags),
        )
        .route("/api/v1/root/bulletin/events", get(api_bulletin_events))
        .route(
            "/api/v1/root/bulletin/events/{sequence}",
            get(api_bulletin_event_detail),
        )
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("root-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let text = std::fs::read_to_string(&path)?;
    let mut config: Config = toml::from_str(&text)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    config.paths.bulletin_file = resolve_relative(base, &config.paths.bulletin_file);
    if !config
        .paths
        .capability_tree_file
        .as_os_str()
        .is_empty()
    {
        config.paths.capability_tree_file =
            resolve_relative(base, &config.paths.capability_tree_file);
    }
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
        node_type: "root".to_owned(),
        did: Some(state.root_did),
    })
}

async fn root_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(|err| ApiError::internal(err.into()))
}

async fn bulletin(State(state): State<AppState>) -> ApiResult<Bulletin> {
    read_bulletin(&state).map(Json).map_err(ApiError::internal)
}

async fn verify_and_publish(
    State(state): State<AppState>,
    Json(request): Json<VerifyAndPublishRequest>,
) -> ApiResult<VerifyResponse> {
    let _guard = state.lock.lock().await;
    verify_request(&state, &request).map_err(ApiError::bad_request)?;

    let did_document_hash =
        hash_json(&request.did_document).map_err(|err| ApiError::internal(err.into()))?;
    let metadata = build_metadata(&state, &request, &did_document_hash)
        .map_err(|err| ApiError::internal(err.into()))?;
    let metadata_hash = hash_json(&metadata).map_err(|err| ApiError::internal(err.into()))?;
    let latest = read_latest_versions(&state).map_err(ApiError::internal)?;
    let previous = latest.get(&request.agent_did);
    let operation = match previous {
        None => "create",
        Some(value) if value["didDocumentHash"] == did_document_hash => "no-op",
        Some(_) => "update",
    }
    .to_owned();
    let document_version = previous
        .and_then(|value| value["documentVersion"].as_u64())
        .unwrap_or(0)
        + u64::from(operation != "no-op");

    let event_type = if operation == "update" {
        BulletinEventType::AgentDidDocumentUpdated
    } else {
        BulletinEventType::AgentDidDocumentAnchored
    };
    let event = append_event(
        &state,
        event_type,
        &request.agent_did,
        json!({
            "registrarDid": request.registrar_did,
            "didDocumentHash": did_document_hash,
            "metadataHash": metadata_hash,
            "documentVersion": document_version,
            "operation": operation,
            "capabilityTags": metadata.capability_tags
        }),
    )
    .map_err(ApiError::internal)?;

    let package = VerifiedPackage {
        package_version: "0.1.0".to_owned(),
        did: request.agent_did.clone(),
        did_document: request.did_document.clone(),
        did_document_hash: did_document_hash.clone(),
        metadata: metadata.clone(),
        root_proof: RootProof {
            root_did: state.root_did.clone(),
            bulletin_event_hash: Some(event.event_hash.clone()),
            signature: Some(sign_bytes(&state.signing_key, event.event_hash.as_bytes())),
        },
        created_at: Utc::now(),
    };

    archive_verified(&state, &request, &metadata, &package, document_version)
        .map_err(ApiError::internal)?;
    update_latest_version(
        &state,
        &request.agent_did,
        document_version,
        &did_document_hash,
        &metadata_hash,
        event.core.sequence,
    )
    .map_err(ApiError::internal)?;
    enqueue_cdn(&state, &package).map_err(ApiError::internal)?;
    enqueue_discovery(&state, &package, event.core.sequence, &event.event_hash)
        .map_err(ApiError::internal)?;

    Json(VerifyResponse {
        status: "verified-and-queued".to_owned(),
        operation,
        agent_did: request.agent_did,
        did_document_hash,
        metadata_hash,
        document_version,
        bulletin_sequence: event.core.sequence,
        bulletin_event_hash: event.event_hash,
        cdn_dispatch_status: "queued".to_owned(),
        discovery_notify_status: "queued".to_owned(),
    })
    .pipe(Ok)
}

async fn authorize_registrar(
    State(state): State<AppState>,
    Json(request): Json<RootAuthorizeRequest>,
) -> ApiResult<Value> {
    let _guard = state.lock.lock().await;
    append_event(
        &state,
        BulletinEventType::RegistrarAuthorized,
        &request.target_did,
        json!({
            "targetRole": request.target_role,
            "didDocumentHash": hash_json(&request.did_document).map_err(|err| ApiError::internal(err.into()))?,
        }),
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn authorize_discovery(
    State(state): State<AppState>,
    Json(request): Json<RootAuthorizeRequest>,
) -> ApiResult<Value> {
    let _guard = state.lock.lock().await;
    append_event(
        &state,
        BulletinEventType::DiscoveryNodeAuthorized,
        &request.target_did,
        json!({
            "targetRole": request.target_role,
            "didDocumentHash": hash_json(&request.did_document).map_err(|err| ApiError::internal(err.into()))?,
        }),
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn update_discovery_domains(
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let _guard = state.lock.lock().await;
    append_event(
        &state,
        BulletinEventType::DiscoveryNodeDomainsUpdated,
        &did,
        payload,
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn revoke_node(
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let _guard = state.lock.lock().await;
    append_event(&state, BulletinEventType::NodeRevoked, &did, payload).map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn publish_cdn_batch(State(state): State<AppState>) -> ApiResult<Value> {
    let queue: Vec<VerifiedPackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    let publish_url = cdn_publish_url(&state).map_err(ApiError::internal)?;
    let client = reqwest::Client::new();
    let mut published = 0usize;
    for package in &queue {
        let response = client
            .post(&publish_url)
            .json(package)
            .send()
            .await
            .map_err(|err| ApiError::internal(err.into()))?;
        if response.status().is_success() {
            published += 1;
        }
    }
    state
        .data
        .write("queues/cdn-publish.json", &Vec::<VerifiedPackage>::new())
        .map_err(|err| ApiError::internal(err.into()))?;
    Ok(Json(json!({"status": "ok", "publishedCount": published})))
}

fn cdn_publish_url(state: &AppState) -> Result<String> {
    let bulletin = read_bulletin(state)?;
    let payload = latest_event_payload(&bulletin, "CDN_SERVICE_INFO_UPDATED")
        .ok_or_else(|| anyhow!("cdn_service_info_missing"))?;
    if let Some(base_url) = payload["baseUrl"].as_str() {
        return Ok(format!("{}/cdn/packages", base_url.trim_end_matches('/')));
    }
    if let Some(template) = payload["packagesUrlTemplate"].as_str() {
        return Ok(template
            .trim_end_matches("/{did}")
            .trim_end_matches("{did}")
            .trim_end_matches('/')
            .to_owned());
    }
    Err(anyhow!("cdn_publish_url_missing"))
}

fn latest_event_payload<'a>(bulletin: &'a Bulletin, event_type: &str) -> Option<&'a Value> {
    bulletin
        .events
        .iter()
        .rev()
        .find(|event| {
            serde_json::to_value(&event.core.event_type)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .as_deref()
                == Some(event_type)
        })
        .map(|event| &event.core.payload)
}

async fn notify_discovery_batch(State(state): State<AppState>) -> ApiResult<Value> {
    let queue: Vec<Value> = state
        .data
        .read("queues/discovery-notify.json")
        .unwrap_or_default();
    Ok(Json(json!({
        "status": "ok",
        "notificationMode": "queued-local-mvp",
        "queuedCount": queue.len(),
        "items": queue
    })))
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let cdn_queue: Vec<VerifiedPackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    let discovery_queue: Vec<Value> = state
        .data
        .read("queues/discovery-notify.json")
        .unwrap_or_default();
    Ok(Json(json!({
        "rootDid": state.root_did,
        "bulletinEventCount": bulletin.events.len(),
        "latestVersionCount": latest_versions.len(),
        "cdnQueueCount": cdn_queue.len(),
        "discoveryQueueCount": discovery_queue.len(),
        "capabilityTreeVersion": state.tag_tree.version
    })))
}

async fn api_registrars(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let items: Vec<Value> = bulletin
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.core.event_type,
                BulletinEventType::RegistrarAuthorized | BulletinEventType::RegistrarRevoked
            )
        })
        .map(|event| json!({
            "did": event.core.subject_did,
            "eventType": event.core.event_type,
            "sequence": event.core.sequence,
            "payload": event.core.payload
        }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn api_registrar_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let events: Vec<Value> = bulletin
        .events
        .iter()
        .filter(|event| event.core.subject_did == did)
        .map(|event| json!({
            "sequence": event.core.sequence,
            "eventType": event.core.event_type,
            "payload": event.core.payload
        }))
        .collect();
    Ok(Json(json!({ "did": did, "events": events })))
}

async fn api_discovery_nodes(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let items: Vec<Value> = bulletin
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.core.event_type,
                BulletinEventType::DiscoveryNodeAuthorized
                    | BulletinEventType::DiscoveryNodeDomainsUpdated
                    | BulletinEventType::DiscoveryNodeRevoked
            )
        })
        .map(|event| json!({
            "did": event.core.subject_did,
            "eventType": event.core.event_type,
            "sequence": event.core.sequence,
            "payload": event.core.payload
        }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn api_discovery_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let latest_domains = bulletin
        .events
        .iter()
        .rev()
        .find(|event| {
            event.core.subject_did == did
                && matches!(event.core.event_type, BulletinEventType::DiscoveryNodeDomainsUpdated)
        })
        .map(|event| event.core.payload.clone())
        .unwrap_or_else(|| json!({"authorizedDomains": ["*"]}));
    Ok(Json(json!({
        "did": did,
        "status": latest_node_status(&bulletin, &did),
        "latestDomains": latest_domains,
        "events": bulletin.events.iter().filter(|event| event.core.subject_did == did).map(|event| json!({
            "sequence": event.core.sequence,
            "eventType": event.core.event_type,
            "payload": event.core.payload
        })).collect::<Vec<_>>()
    })))
}

async fn api_agents(State(state): State<AppState>) -> ApiResult<Value> {
    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let items: Vec<Value> = latest_versions
        .into_iter()
        .map(|(did, value)| json!({
            "did": did,
            "documentVersion": value["documentVersion"],
            "didDocumentHash": value["didDocumentHash"],
            "metadataHash": value["metadataHash"],
            "bulletinSequence": value["bulletinSequence"],
            "updatedAt": value["updatedAt"]
        }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn api_agent_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let latest = latest_versions.get(&did).cloned();
    let archive_root = format!("archive/{}", did_to_file_name(&did).trim_end_matches(".json"));
    Ok(Json(json!({
        "did": did,
        "latest": latest,
        "archiveRoot": archive_root
    })))
}

async fn api_agent_versions(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let prefix = format!("archive/{}", did_to_file_name(&did).trim_end_matches(".json"));
    let index = state
        .data
        .read::<Value>(format!("{prefix}/index.json"))
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    Ok(Json(json!({ "did": did, "items": index })))
}

async fn api_agent_version_detail(
    State(state): State<AppState>,
    AxumPath((did, version)): AxumPath<(String, String)>,
) -> ApiResult<Value> {
    let prefix = format!("archive/{}/v{}", did_to_file_name(&did).trim_end_matches(".json"), version);
    let did_document: Option<DidDocument> = state.data.read(format!("{prefix}/did-document.json")).ok();
    let metadata: Option<AgentMetadata> = state.data.read(format!("{prefix}/metadata.json")).ok();
    let package: Option<VerifiedPackage> = state.data.read(format!("{prefix}/package.json")).ok();
    Ok(Json(json!({
        "did": did,
        "version": version,
        "didDocument": did_document,
        "metadata": metadata,
        "package": package
    })))
}

async fn api_cdn_publish_queue(State(state): State<AppState>) -> ApiResult<Value> {
    let queue: Vec<VerifiedPackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    Ok(Json(json!({ "items": queue, "count": queue.len() })))
}

async fn api_discovery_notify_queue(State(state): State<AppState>) -> ApiResult<Value> {
    let queue: Vec<Value> = state
        .data
        .read("queues/discovery-notify.json")
        .unwrap_or_default();
    Ok(Json(json!({ "items": queue, "count": queue.len() })))
}

async fn api_capability_tree(State(state): State<AppState>) -> ApiResult<CapabilityTagTree> {
    Ok(Json(state.tag_tree.clone()))
}

async fn api_validate_tags(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let tags = payload["capabilityTags"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    let invalid_tags = tags
        .iter()
        .filter(|tag| state.tag_tree.normalize_tag(tag).is_none())
        .cloned()
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "valid": invalid_tags.is_empty(),
        "invalidTags": invalid_tags
    })))
}

async fn api_bulletin_events(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": bulletin.events })))
}

async fn api_bulletin_event_detail(
    State(state): State<AppState>,
    AxumPath(sequence): AxumPath<u64>,
) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let event = bulletin
        .events
        .into_iter()
        .find(|event| event.core.sequence == sequence);
    Ok(Json(json!({ "event": event })))
}

fn latest_node_status(bulletin: &Bulletin, did: &str) -> String {
    if bulletin.events.iter().any(|event| {
        event.core.subject_did == did
            && matches!(event.core.event_type, BulletinEventType::NodeRevoked)
    }) {
        "revoked".to_owned()
    } else {
        "active".to_owned()
    }
}

fn verify_request(
    state: &AppState,
    request: &VerifyAndPublishRequest,
) -> std::result::Result<(), String> {
    let bulletin = read_bulletin(state).map_err(|err| err.to_string())?;
    let registrar_active = bulletin.events.iter().any(|event| {
        event.core.subject_did == request.registrar_did
            && matches!(
                event.core.event_type,
                BulletinEventType::RegistrarAuthorized
            )
    });
    let registrar_revoked = bulletin.events.iter().any(|event| {
        event.core.subject_did == request.registrar_did
            && matches!(event.core.event_type, BulletinEventType::RegistrarRevoked)
    });
    if !registrar_active || registrar_revoked {
        return Err("registrar_not_authorized".to_owned());
    }
    DidAns::parse(&request.agent_did).map_err(|_| "invalid_did".to_owned())?;
    if request.did_document.id != request.agent_did {
        return Err("did_document_id_mismatch".to_owned());
    }
    request
        .did_document
        .validate_mvp()
        .map_err(|_| "invalid_did_document_structure".to_owned())?;
    let metadata = request
        .did_document
        .ans_metadata
        .as_ref()
        .ok_or_else(|| "invalid_subject_type".to_owned())?;
    if metadata.subject_type != SubjectType::Agent {
        return Err("invalid_subject_type".to_owned());
    }
    if request.did_document.service.is_empty() {
        return Err("invalid_service_endpoint".to_owned());
    }
    let tags = metadata
        .agent_description
        .as_ref()
        .map(|description| description.capability_tags.clone())
        .unwrap_or_default();
    for tag in &tags {
        if state.tag_tree.normalize_tag(tag).is_none() {
            return Err(format!("invalid_capability_tag:{tag}"));
        }
    }
    if request.registration_credential["issuer"] != request.registrar_did {
        return Err("invalid_registration_credential".to_owned());
    }
    if request.registration_credential["subject"] != request.agent_did {
        return Err("invalid_registration_credential".to_owned());
    }
    if request.registration_credential["status"] != "active" {
        return Err("invalid_registration_credential".to_owned());
    }
    let credential: AgentRegistrationCredential = serde_json::from_value(
        request.registration_credential.clone(),
    )
    .map_err(|_| "invalid_registration_credential".to_owned())?;
    verify_agent_registration_credential(
        &credential,
        &verify_issuer_key(&request.registrar_did_document)?,
    )
        .map_err(|_| "invalid_registration_credential_signature".to_owned())?;
    Ok(())
}

fn verify_issuer_key(did_document: &DidDocument) -> Result<ed25519_dalek::VerifyingKey, String> {
    let method = did_document
        .verification_method
        .iter()
        .find(|method| did_document.assertion_method.iter().any(|id| id == &method.id))
        .ok_or_else(|| "missing_issuer_verification_method".to_owned())?;
    if let Some(jwk) = &method.public_key_jwk {
        oan_crypto::verifying_key_from_public_key_jwk(jwk).map_err(|_| "invalid_issuer_key".to_owned())
    } else if let Some(multibase) = &method.public_key_multibase {
        oan_crypto::verifying_key_from_public_key_multibase(multibase)
            .map_err(|_| "invalid_issuer_key".to_owned())
    } else {
        Err("invalid_issuer_key".to_owned())
    }
}

fn build_metadata(
    state: &AppState,
    request: &VerifyAndPublishRequest,
    did_document_hash: &str,
) -> Result<AgentMetadata> {
    let ans = request
        .did_document
        .ans_metadata
        .as_ref()
        .ok_or_else(|| anyhow!("ansMetadata missing"))?;
    let mut tags = ans
        .agent_description
        .as_ref()
        .map(|description| description.capability_tags.clone())
        .unwrap_or_default()
        .into_iter()
        .map(|tag| {
            state
                .tag_tree
                .normalize_tag(&tag)
                .unwrap_or(&tag)
                .to_owned()
        })
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();
    Ok(AgentMetadata {
        did: request.agent_did.clone(),
        role: "Service Agent".to_owned(),
        identity_type: ans.identity_type.clone(),
        did_document_hash: did_document_hash.to_owned(),
        capability_tags: tags,
        services: request.did_document.service.clone(),
        status: "active".to_owned(),
        updated_at: Utc::now(),
    })
}

fn read_bulletin(state: &AppState) -> Result<Bulletin> {
    let store = JsonStore::new(".");
    if state.config.paths.bulletin_file.exists() {
        store
            .read(&state.config.paths.bulletin_file)
            .map_err(Into::into)
    } else {
        Ok(Bulletin {
            version: "0.1.0".to_owned(),
            root_did: state.root_did.clone(),
            created_at: Utc::now(),
            events: vec![],
        })
    }
}

fn write_bulletin(state: &AppState, bulletin: &Bulletin) -> Result<()> {
    JsonStore::new(".").write(&state.config.paths.bulletin_file, bulletin)?;
    Ok(())
}

fn append_event(
    state: &AppState,
    event_type: BulletinEventType,
    subject_did: &str,
    payload: Value,
) -> Result<BulletinEvent> {
    let mut bulletin = read_bulletin(state)?;
    let previous_hash = bulletin.events.last().map(|event| event.event_hash.clone());
    let event = BulletinEventCore {
        sequence: bulletin.events.len() as u64 + 1,
        previous_hash,
        event_type,
        subject_did: subject_did.to_owned(),
        actor_did: state.root_did.clone(),
        payload,
        created_at: Utc::now(),
    }
    .sign(&state.signing_key)?;
    bulletin.events.push(event.clone());
    write_bulletin(state, &bulletin)?;
    Ok(event)
}

fn archive_verified(
    state: &AppState,
    request: &VerifyAndPublishRequest,
    metadata: &AgentMetadata,
    package: &VerifiedPackage,
    version: u64,
) -> Result<()> {
    let name = did_to_file_name(&request.agent_did);
    let prefix = format!("archive/{}/v{version}", name.trim_end_matches(".json"));
    state
        .data
        .write(format!("{prefix}/did-document.json"), &request.did_document)?;
    state
        .data
        .write(format!("{prefix}/metadata.json"), metadata)?;
    state
        .data
        .write(format!("{prefix}/package.json"), package)?;
    state
        .data
        .write(format!("verified-packages/{name}"), package)?;
    Ok(())
}

fn read_latest_versions(state: &AppState) -> Result<BTreeMap<String, Value>> {
    Ok(state
        .data
        .read("indexes/latest-did-document-versions.json")
        .unwrap_or_default())
}

fn update_latest_version(
    state: &AppState,
    agent_did: &str,
    version: u64,
    did_hash: &str,
    metadata_hash: &str,
    sequence: u64,
) -> Result<()> {
    let mut latest = read_latest_versions(state)?;
    latest.insert(
        agent_did.to_owned(),
        json!({
            "documentVersion": version,
            "didDocumentHash": did_hash,
            "metadataHash": metadata_hash,
            "bulletinSequence": sequence,
            "updatedAt": Utc::now()
        }),
    );
    state
        .data
        .write("indexes/latest-did-document-versions.json", &latest)?;
    Ok(())
}

fn enqueue_cdn(state: &AppState, package: &VerifiedPackage) -> Result<()> {
    let mut queue: Vec<VerifiedPackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    queue.retain(|item| item.did != package.did);
    queue.push(package.clone());
    state.data.write("queues/cdn-publish.json", &queue)?;
    Ok(())
}

fn enqueue_discovery(
    state: &AppState,
    package: &VerifiedPackage,
    bulletin_sequence: u64,
    event_hash: &str,
) -> Result<()> {
    let mut queue: Vec<Value> = state
        .data
        .read("queues/discovery-notify.json")
        .unwrap_or_default();
    queue.push(json!({
        "agentDid": package.did,
        "operation": "upsert",
        "documentVersion": package.metadata.updated_at.timestamp(),
        "didDocumentHash": package.did_document_hash,
        "metadataHash": hash_json(&package.metadata)?,
        "bulletinSequence": bulletin_sequence,
        "bulletinEventHash": event_hash,
        "capabilityTags": package.metadata.capability_tags
    }));
    state.data.write("queues/discovery-notify.json", &queue)?;
    Ok(())
}

fn default_tag_tree() -> CapabilityTagTree {
    CapabilityTagTree {
        version: 1,
        tags: vec![
            tag("text-processing", "Text Processing", None, &[]),
            tag(
                "translation",
                "Translation",
                Some("text-processing"),
                &["translate"],
            ),
            tag(
                "summarization",
                "Summarization",
                Some("text-processing"),
                &["summary"],
            ),
            tag("echo", "Echo", Some("text-processing"), &[]),
            tag("mcp", "MCP", None, &[]),
            tag("a2a", "A2A", None, &[]),
        ],
        tree: vec![],
    }
}

fn tag(id: &str, label: &str, parent: Option<&str>, aliases: &[&str]) -> CapabilityTag {
    CapabilityTag {
        id: id.to_owned(),
        label: label.to_owned(),
        parent: parent.map(ToOwned::to_owned),
        aliases: aliases.iter().map(|value| (*value).to_owned()).collect(),
    }
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oan_core::{AgentDescription, AnsMetadata, ServiceEndpoint, VerificationMethod};
    use oan_credentials::AgentRegistrationCredential;
    use oan_crypto::{generate_ed25519_keypair, public_key_multibase};
    use serde_json::json;

    fn did_document_with_key(
        did: &str,
        subject_type: SubjectType,
        signing_key: &ed25519_dalek::SigningKey,
        tags: Vec<&str>,
    ) -> DidDocument {
        let key_id = format!("{did}#key-1");
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: Some(public_key_multibase(&signing_key.verifying_key())),
                public_key_jwk: None,
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: vec![ServiceEndpoint {
                id: format!("{did}#service"),
                service_type: "AgentInvokeService".to_owned(),
                service_endpoint: "http://localhost:9001/agent/invoke".to_owned(),
                version: None,
                protocol: Some("http".to_owned()),
                server_type: None,
                port: Some(9001),
            }],
            ans_metadata: Some(AnsMetadata {
                subject_type,
                identity_type: "demo".to_owned(),
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
        }
    }

    fn test_state(data_dir: &Path, bulletin_file: PathBuf) -> AppState {
        let root_key = generate_ed25519_keypair();
        AppState {
            data: JsonStore::new(data_dir),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8000,
                },
                paths: PathConfig {
                    data_dir: data_dir.to_path_buf(),
                    keys_dir: data_dir.join("keys"),
                    bulletin_file,
                    capability_tree_file: PathBuf::from("unused.json"),
                },
            },
            root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            signing_key: root_key,
            tag_tree: default_tag_tree(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    #[test]
    fn verify_request_accepts_signed_registration_credential() {
        let dir = tempfile::tempdir().unwrap();
        let registrar_key = generate_ed25519_keypair();
        let registrar_did = "did:ans:AGRG:efregistrarregistrar1234";
        let agent_did = "did:ans:AGDM:efserviceagentservice1234";
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        append_event(
            &state,
            BulletinEventType::RegistrarAuthorized,
            registrar_did,
            json!({}),
        )
        .unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            registrar_did.to_owned(),
            agent_did.to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(format!("{registrar_did}#key-1"), &registrar_key)
        .unwrap();
        let request = VerifyAndPublishRequest {
            registrar_did: registrar_did.to_owned(),
            registrar_did_document: did_document_with_key(
                registrar_did,
                SubjectType::InfrastructureNode,
                &registrar_key,
                vec!["registration"],
            ),
            agent_did: agent_did.to_owned(),
            did_document: did_document_with_key(
                agent_did,
                SubjectType::Agent,
                &generate_ed25519_keypair(),
                vec!["echo"],
            ),
            metadata: json!({}),
            registration_credential: serde_json::to_value(credential).unwrap(),
        };

        assert!(verify_request(&state, &request).is_ok());
    }

    #[test]
    fn verify_request_rejects_registration_credential_signed_by_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let registrar_key = generate_ed25519_keypair();
        let wrong_key = generate_ed25519_keypair();
        let registrar_did = "did:ans:AGRG:efregistrarregistrar1234";
        let agent_did = "did:ans:AGDM:efserviceagentservice1234";
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        append_event(
            &state,
            BulletinEventType::RegistrarAuthorized,
            registrar_did,
            json!({}),
        )
        .unwrap();
        let credential = AgentRegistrationCredential::unsigned(
            registrar_did.to_owned(),
            agent_did.to_owned(),
            json!({"capabilityTags": ["echo"]}),
        )
        .sign(format!("{registrar_did}#key-1"), &wrong_key)
        .unwrap();
        let request = VerifyAndPublishRequest {
            registrar_did: registrar_did.to_owned(),
            registrar_did_document: did_document_with_key(
                registrar_did,
                SubjectType::InfrastructureNode,
                &registrar_key,
                vec!["registration"],
            ),
            agent_did: agent_did.to_owned(),
            did_document: did_document_with_key(
                agent_did,
                SubjectType::Agent,
                &generate_ed25519_keypair(),
                vec!["echo"],
            ),
            metadata: json!({}),
            registration_credential: serde_json::to_value(credential).unwrap(),
        };

        assert_eq!(
            verify_request(&state, &request).unwrap_err(),
            "invalid_registration_credential_signature"
        );
    }

    #[test]
    fn enqueue_cdn_keeps_latest_package_per_did() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        let did = "did:ans:AGDM:efserviceagentservice1234".to_owned();
        let did_document = did_document_with_key(
            &did,
            SubjectType::Agent,
            &generate_ed25519_keypair(),
            vec!["echo"],
        );
        let mut package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did.clone(),
            did_document_hash: "hash-1".to_owned(),
            metadata: AgentMetadata {
                did: did.clone(),
                role: "Service Agent".to_owned(),
                identity_type: "demo".to_owned(),
                did_document_hash: "hash-1".to_owned(),
                capability_tags: vec!["echo".to_owned()],
                services: vec![],
                status: "active".to_owned(),
                updated_at: Utc::now(),
            },
            did_document: did_document.clone(),
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
            },
            created_at: Utc::now(),
        };
        enqueue_cdn(&state, &package).unwrap();
        package.did_document_hash = "hash-2".to_owned();
        enqueue_cdn(&state, &package).unwrap();

        let queue: Vec<VerifiedPackage> = state.data.read("queues/cdn-publish.json").unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].did_document_hash, "hash-2");
    }

    #[tokio::test]
    async fn api_status_reports_queue_and_archive_state() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        append_event(
            &state,
            BulletinEventType::RegistrarAuthorized,
            "did:ans:AGRG:efregistrarregistrar1234",
            json!({}),
        )
        .unwrap();
        update_latest_version(
            &state,
            "did:ans:AGDM:efserviceagentservice1234",
            1,
            "hash-1",
            "meta-1",
            1,
        )
        .unwrap();
        let queue_package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
            did_document: did_document_with_key(
                "did:ans:AGDM:efserviceagentservice1234",
                SubjectType::Agent,
                &generate_ed25519_keypair(),
                vec!["echo"],
            ),
            did_document_hash: "hash-1".to_owned(),
            metadata: AgentMetadata {
                did: "did:ans:AGDM:efserviceagentservice1234".to_owned(),
                role: "Service Agent".to_owned(),
                identity_type: "demo".to_owned(),
                did_document_hash: "hash-1".to_owned(),
                capability_tags: vec!["echo".to_owned()],
                services: vec![],
                status: "active".to_owned(),
                updated_at: Utc::now(),
            },
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
            },
            created_at: Utc::now(),
        };
        state
            .data
            .write("queues/cdn-publish.json", &vec![queue_package])
            .unwrap();
        state
            .data
            .write("queues/discovery-notify.json", &vec![serde_json::json!({"did": "x"})])
            .unwrap();

        let response = api_status(State(state)).await.unwrap();
        assert_eq!(response.0["rootDid"], "did:ans:AGRT:efrootrootrootrootrootroot");
        assert_eq!(response.0["bulletinEventCount"], 1);
        assert_eq!(response.0["latestVersionCount"], 1);
        assert_eq!(response.0["cdnQueueCount"], 1);
        assert_eq!(response.0["discoveryQueueCount"], 1);
    }

    #[tokio::test]
    async fn api_registrars_and_discovery_lists_reflect_bulletin_events() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        append_event(
            &state,
            BulletinEventType::RegistrarAuthorized,
            "did:ans:AGRG:efregistrarregistrar1234",
            json!({"note": "ok"}),
        )
        .unwrap();
        append_event(
            &state,
            BulletinEventType::DiscoveryNodeAuthorized,
            "did:ans:AGDS:efdiscoverydiscovery1234",
            json!({"note": "ok"}),
        )
        .unwrap();

        let registrars = api_registrars(State(state.clone())).await.unwrap();
        assert_eq!(registrars.0["items"].as_array().unwrap().len(), 1);
        let discovery_nodes = api_discovery_nodes(State(state)).await.unwrap();
        assert_eq!(discovery_nodes.0["items"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn api_capability_tree_and_validation_work() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        let tree = api_capability_tree(State(state.clone())).await.unwrap();
        assert_eq!(tree.0.version, 1);
        let result = api_validate_tags(
            State(state),
            Json(json!({"capabilityTags": ["echo", "unknown-tag"]})),
        )
        .await
        .unwrap();
        assert!(!result.0["valid"].as_bool().unwrap());
        assert_eq!(result.0["invalidTags"].as_array().unwrap().len(), 1);
    }
}
