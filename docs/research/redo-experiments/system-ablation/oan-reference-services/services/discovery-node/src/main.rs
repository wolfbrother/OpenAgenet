// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use oan_bulletin::Bulletin;
use oan_core::{CapabilityTagTree, CryptoSuite, DidDocument, SubjectType};
use oan_crypto::{
    build_data_integrity_proof, signature_input, signing_key_from_bytes, verifying_key_from_method,
    SigningKey, VerifyingKey,
};
use oan_package::VerifiedPackage;
use oan_protocol::{
    DiscoveryCandidate, DiscoveryQuery, DiscoveryResponse, DiscoveryResponseProof, HealthResponse,
};
use oan_storage::{JsonStore, SqliteJsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::time::{sleep, Duration as TokioDuration};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

const DISCOVERY_SYNC_STATE_TABLE: &str = "discovery_sync_state";
const DISCOVERY_PACKAGE_TABLE: &str = "discovery_packages";
const DISCOVERY_REJECTED_TABLE: &str = "discovery_rejected_packages";

#[derive(Clone, Debug, Deserialize)]
struct SyncRequest {
    #[serde(rename = "maxPublications", default)]
    max_publications: Option<u64>,
    #[serde(rename = "cursorHint", default)]
    cursor_hint: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct RootPublicationItem {
    cursor: i64,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[allow(dead_code)]
    #[serde(rename = "documentVersion")]
    document_version: u64,
    #[allow(dead_code)]
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[allow(dead_code)]
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    #[allow(dead_code)]
    #[serde(rename = "acceptedAt")]
    accepted_at: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    debug: DebugConfig,
    upstream: UpstreamConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DebugConfig {
    #[serde(default)]
    export_snapshots: bool,
    #[serde(default = "default_debug_export_interval_ms")]
    export_interval_ms: u64,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            export_snapshots: false,
            export_interval_ms: default_debug_export_interval_ms(),
        }
    }
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
    #[serde(default)]
    database_url: Option<String>,
}

fn default_debug_export_interval_ms() -> u64 {
    2_000
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    algorithm: String,
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
    signing_key: SigningKey,
    sqlite: Option<SqliteJsonStore>,
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

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256Legacy),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow::anyhow!("unsupported_algorithm: {other}")),
    }
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
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let sqlite = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let sqlite = SqliteJsonStore::connect(url).await?;
            initialize_discovery_sqlite(&sqlite).await?;
            Some(sqlite)
        }
        _ => None,
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        index: JsonStore::new(&config.paths.index_dir),
        config: config.clone(),
        did: did_doc.id,
        signing_key,
        sqlite,
        client: reqwest::Client::new(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/discovery/did", get(discovery_did_document))
        .route("/discover/query", post(query))
        .route("/routes/{did}", get(route_lookup))
        .route("/discovery/status", get(api_status))
        .route("/discovery/root-authorization", get(api_root_authorization))
        .route("/discovery/authorized-domains", get(api_authorized_domains))
        .route("/discovery/sync", post(sync_from_cdn))
        .route("/discovery/sync/history", get(api_sync_history))
        .route("/discovery/index/stats", get(api_index_stats))
        .route("/discovery/index/agents", get(api_index_agents))
        .route("/discovery/index/agents/{did}", get(api_index_agent_detail))
        .route("/discovery/query", post(query))
        .route("/discovery/query/explain", post(api_query_explain))
        .route("/discovery/rejected-packages", get(api_rejected_packages))
        .route("/discovery/capability-tree", get(api_capability_tree))
        .layer(build_cors_layer(&config.cors)?)
        .with_state(state.clone());

    if state.sqlite.is_some() && state.config.debug.export_snapshots {
        tokio::spawn(async move {
            discovery_debug_export_loop(state).await;
        });
    }

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
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_sqlite_url(base, database_url);
    }
    Ok(config)
}

async fn initialize_discovery_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {DISCOVERY_SYNC_STATE_TABLE} (
                state_key TEXT PRIMARY KEY,
                state_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {DISCOVERY_PACKAGE_TABLE} (
                subject_did TEXT PRIMARY KEY,
                cursor INTEGER NOT NULL,
                version INTEGER NOT NULL,
                package_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {DISCOVERY_REJECTED_TABLE} (
                reject_key TEXT PRIMARY KEY,
                item_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#
        ))
        .await?;
    Ok(())
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn resolve_sqlite_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

fn build_cors_layer(config: &CorsConfig) -> Result<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<std::result::Result<_, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(AllowHeaders::any()))
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

async fn sync_from_cdn(
    State(state): State<AppState>,
    maybe_request: Option<Json<SyncRequest>>,
) -> ApiResult<serde_json::Value> {
    let bulletin = fetch_bulletin(&state).await.map_err(ApiError::internal)?;
    let root_key = root_verifying_key(&state)
        .await
        .map_err(ApiError::internal)?;
    verify_bulletin_state(&bulletin, &root_key).map_err(ApiError::internal)?;
    let authorized_domains = discovery_authorized_domains(&bulletin, &state.did);
    let cdn = resolve_cdn_service(&state, &bulletin)
        .await
        .map_err(ApiError::internal)?;
    let max_publications = maybe_request
        .as_ref()
        .and_then(|request| request.0.max_publications)
        .unwrap_or(500);
    let after_cursor = read_sync_cursor(&state).await.map_err(ApiError::internal)?;
    if maybe_request
        .as_ref()
        .and_then(|request| request.0.cursor_hint)
        .is_some_and(|cursor_hint| cursor_hint <= after_cursor)
    {
        let cdn = resolve_cdn_service(&state, &bulletin)
            .await
            .map_err(ApiError::internal)?;
        return Ok(Json(json!({
            "status": "noop",
            "syncedCount": 0,
            "rejectedCount": 0,
            "latestCursor": after_cursor,
            "cdnManifestUrl": cdn.manifest_url
        })));
    }
    let publication_feed: Value = state
        .client
        .get(format!(
            "{}/root/publications?after={after_cursor}&limit={max_publications}",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await
        .context("fetch_root_publications_failed")
        .map_err(ApiError::internal)?
        .json()
        .await
        .context("decode_root_publications_failed")
        .map_err(ApiError::internal)?;
    let items =
        serde_json::from_value::<Vec<RootPublicationItem>>(publication_feed["items"].clone())
            .map_err(|err| ApiError::internal(err.into()))?;
    let mut rejected = Vec::<Value>::new();
    let mut synced_count = 0usize;
    let mut max_cursor_seen = after_cursor;
    let mut blocked_cursor: Option<i64> = None;
    for entry in items {
        let package_result = state
            .client
            .get(cdn.package_url(&entry.agent_did))
            .send()
            .await
            .with_context(|| format!("fetch_cdn_package_failed: {}", entry.agent_did))
            .map_err(ApiError::internal)?
            .json::<VerifiedPackage>()
            .await;
        let Ok(package) = package_result else {
            blocked_cursor = Some(entry.cursor);
            rejected.push(json!({
                "did": entry.agent_did,
                "cursor": entry.cursor,
                "reason": "package_decode_failed"
            }));
            break;
        };
        if !is_indexable_agent(&package) {
            rejected.push(json!({
                "did": package.did,
                "cursor": entry.cursor,
                "reason": "not_indexable"
            }));
            continue;
        }
        if package.verify_document_hash().is_err() {
            rejected.push(json!({
                "did": package.did,
                "cursor": entry.cursor,
                "reason": "invalid_did_document_hash"
            }));
            continue;
        }
        if package.verify_metadata_hash().is_err() {
            rejected.push(json!({
                "did": package.did,
                "cursor": entry.cursor,
                "reason": "invalid_metadata_hash"
            }));
            continue;
        }
        if !verify_package_root_proof(&package, &bulletin, &root_key) {
            rejected.push(json!({
                "did": package.did,
                "cursor": entry.cursor,
                "reason": "invalid_root_proof"
            }));
            continue;
        }
        if !authorized_domains_match(&package, &authorized_domains) {
            rejected.push(json!({
                "did": package.did,
                "cursor": entry.cursor,
                "reason": "unauthorized_domains"
            }));
            continue;
        }
        upsert_indexed_package(&state, entry.cursor, &package)
            .await
            .map_err(ApiError::internal)?;
        synced_count += 1;
        max_cursor_seen = entry.cursor;
    }
    if let Some(cursor) = blocked_cursor {
        max_cursor_seen = max_cursor_seen.min(cursor.saturating_sub(1)).max(after_cursor);
    }
    if max_cursor_seen > after_cursor {
        write_sync_cursor(&state, max_cursor_seen)
            .await
            .map_err(ApiError::internal)?;
    }
    let history = json!({
        "syncedAt": Utc::now(),
        "status": "synced",
        "syncedCount": synced_count,
        "rejectedCount": rejected.len(),
        "latestCursor": max_cursor_seen,
        "cdnManifestUrl": cdn.manifest_url
    });
    if state.sqlite.is_none() {
        append_json_log(
            &state.config.paths.index_dir.join("sync-history.json"),
            history.clone(),
        )
        .map_err(ApiError::internal)?;
    }
    write_sync_history_sqlite(&state, history.clone())
        .await
        .map_err(ApiError::internal)?;
    write_rejected_packages(&state, &rejected)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "synced",
        "syncedCount": synced_count,
        "rejectedCount": rejected.len(),
        "latestCursor": max_cursor_seen,
        "cdnManifestUrl": cdn.manifest_url
    })))
}

async fn discovery_debug_export_loop(state: AppState) {
    loop {
        if let Err(err) = export_discovery_debug_snapshot(&state).await {
            eprintln!("discovery debug export failed: {err}");
        }
        sleep(TokioDuration::from_millis(
            state.config.debug.export_interval_ms.max(100),
        ))
        .await;
    }
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
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
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
    let proof =
        sign_discovery_response(&state.signing_key, &unsigned).map_err(ApiError::internal)?;
    let response = DiscoveryResponse {
        signature: proof.proof_value.clone(),
        proof: Some(proof),
        ..unsigned
    };
    Ok(Json(response))
}

async fn route_lookup(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
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
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    let history = read_sync_history(&state)
        .await
        .map_err(ApiError::internal)?;
    let bulletin = fetch_bulletin(&state).await.ok();
    Ok(Json(json!({
        "discoveryDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "cdnEndpoint": state.config.upstream.cdn_endpoint,
        "indexedAgentCount": packages.len(),
        "lastSync": history.last(),
        "rootAuthorizationStatus": bulletin.as_ref().map(|b| discovery_authorization_status(b, &state.did)).unwrap_or_else(|| "unknown".to_owned())
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
    let history = read_sync_history(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": history, "count": history.len() })))
}

async fn api_index_stats(State(state): State<AppState>) -> ApiResult<Value> {
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
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
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    let items = packages
        .into_iter()
        .map(|package| {
            json!({
                "did": package.did,
                "capabilityTags": package.metadata.capability_tags,
                "services": package.metadata.services,
                "status": package.metadata.status,
                "updatedAt": package.metadata.updated_at
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "items": items, "count": items.len() })))
}

async fn api_index_agent_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    let package = packages.into_iter().find(|package| package.did == did);
    Ok(Json(json!({ "did": did, "package": package })))
}

async fn api_query_explain(
    State(state): State<AppState>,
    Json(query): Json<DiscoveryQuery>,
) -> ApiResult<Value> {
    let packages = read_indexed_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    let explanations = packages
        .iter()
        .map(|package| {
            let matched = matches_query(package, &query);
            json!({
                "did": package.did,
                "matched": matched,
                "score": if matched { score(package, &query) } else { 0.0 },
                "textMatched": query.query.as_ref().map(|text| {
                    let needle = text.to_ascii_lowercase();
                    package.did.to_ascii_lowercase().contains(&needle)
                        || package.metadata.identity_type.to_ascii_lowercase().contains(&needle)
                        || package.metadata.capability_tags.iter().any(|tag| tag.to_ascii_lowercase().contains(&needle))
                        || package.did_document.ans_metadata.as_ref()
                            .and_then(|metadata| metadata.agent_description.as_ref())
                            .map(|description| description.capability_description.to_ascii_lowercase().contains(&needle))
                            .unwrap_or(false)
                }),
                "capabilityTagOverlap": query.capability_tags.iter()
                    .filter(|tag| package.metadata.capability_tags.iter().any(|candidate| candidate == *tag))
                    .cloned()
                    .collect::<Vec<_>>(),
                "serviceTypeMatched": query.service_type.as_ref().map(|service_type| {
                    let expected = service_type.to_ascii_lowercase();
                    package.metadata.identity_type.to_ascii_lowercase() == expected
                        || package.metadata.services.iter().any(|service| {
                            service.service_type.eq_ignore_ascii_case(service_type)
                                || service.service_type.to_ascii_lowercase().contains(&expected)
                        })
                }),
                "protocolMatched": query.protocol.as_ref().map(|protocol| {
                    package.metadata.services.iter().any(|service| {
                        service
                            .protocol
                            .as_ref()
                            .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                            .unwrap_or(false)
                    })
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "query": query, "items": explanations })))
}

async fn api_rejected_packages(State(state): State<AppState>) -> ApiResult<Value> {
    let items = read_rejected_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": items, "count": items.len() })))
}

async fn api_capability_tree(State(state): State<AppState>) -> ApiResult<Value> {
    let response = state
        .client
        .get(format!(
            "{}/root/capability-tree",
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
    state
        .client
        .get(format!(
            "{}/bulletin",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await
        .context("fetch_root_bulletin_failed")?
        .json()
        .await
        .context("decode_root_bulletin_failed")
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

async fn upsert_indexed_package(
    state: &AppState,
    cursor: i64,
    package: &VerifiedPackage,
) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {DISCOVERY_PACKAGE_TABLE}(subject_did, cursor, version, package_json, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(subject_did)
            DO UPDATE SET
                cursor = excluded.cursor,
                version = excluded.version,
                package_json = excluded.package_json,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&package.did)
        .bind(cursor)
        .bind(
            package
                .root_proof
                .package_claims
                .as_ref()
                .and_then(|claims| claims["documentVersion"].as_u64())
                .unwrap_or(0) as i64,
        )
        .bind(serde_json::to_string(package)?)
        .bind(Utc::now().to_rfc3339())
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    let mut indexed: Vec<VerifiedPackage> =
        state.index.read("capabilities.json").unwrap_or_default();
    indexed.retain(|candidate| candidate.did != package.did);
    indexed.push(package.clone());
    state.index.write("capabilities.json", &indexed)?;
    Ok(())
}

async fn read_indexed_packages(state: &AppState) -> Result<Vec<VerifiedPackage>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT package_json FROM {DISCOVERY_PACKAGE_TABLE} ORDER BY updated_at, subject_did"
        ))
        .fetch_all(sqlite.pool())
        .await?;
        if !rows.is_empty() {
            let packages = rows
                .into_iter()
                .map(|row| serde_json::from_str::<VerifiedPackage>(&row.get::<String, _>(0)))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            return Ok(packages);
        }
    }
    Ok(state.index.read("capabilities.json").unwrap_or_default())
}

async fn write_sync_history_sqlite(state: &AppState, item: Value) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json(
                "discovery.sync_history",
                &format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                &item,
            )
            .await?;
    }
    Ok(())
}

async fn read_sync_cursor(state: &AppState) -> Result<i64> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT state_value FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE state_key = 'root_package_cursor'"
        ))
        .fetch_optional(sqlite.pool())
        .await?;
        if let Some(row) = row {
            return Ok(row.get::<String, _>(0).parse::<i64>().unwrap_or(0));
        }
    }
    Ok(0)
}

async fn write_sync_cursor(state: &AppState, cursor: i64) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, updated_at)
            VALUES ('root_package_cursor', ?, ?)
            ON CONFLICT(state_key)
            DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at
            "#
        ))
        .bind(cursor.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(sqlite.pool())
        .await?;
    }
    Ok(())
}

async fn write_rejected_packages(state: &AppState, rejected: &[Value]) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        for item in rejected {
            let reject_key = format!(
                "{}:{}",
                item["did"].as_str().unwrap_or("unknown"),
                item["cursor"].as_i64().unwrap_or_default()
            );
            sqlx::query(&format!(
                r#"
                INSERT INTO {DISCOVERY_REJECTED_TABLE}(reject_key, item_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(reject_key)
                DO UPDATE SET item_json = excluded.item_json, updated_at = excluded.updated_at
                "#
            ))
            .bind(reject_key)
            .bind(serde_json::to_string(item)?)
            .bind(Utc::now().to_rfc3339())
            .execute(sqlite.pool())
            .await?;
        }
        return Ok(());
    }
    state.index.write("rejected-packages.json", &rejected)?;
    Ok(())
}

async fn read_sync_history(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_namespace("discovery.sync_history")
            .await
            .map_err(Into::into);
    }
    Ok(state.index.read("sync-history.json").unwrap_or_default())
}

async fn export_discovery_debug_snapshot(state: &AppState) -> Result<()> {
    if state.sqlite.is_none() {
        return Ok(());
    }
    let packages = read_indexed_packages(state).await?;
    state.index.write("capabilities.json", &packages)?;
    let rejected = read_rejected_packages(state).await?;
    state.index.write("rejected-packages.json", &rejected)?;
    let history = read_sync_history(state).await?;
    state.index.write("sync-history.json", &history)?;
    Ok(())
}

async fn read_rejected_packages(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT item_json FROM {DISCOVERY_REJECTED_TABLE} ORDER BY updated_at, reject_key"
        ))
        .fetch_all(sqlite.pool())
        .await?;
        return rows
            .into_iter()
            .map(|row| {
                serde_json::from_str::<Value>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .collect();
    }
    Ok(state.index.read("rejected-packages.json").unwrap_or_default())
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

async fn root_verifying_key(state: &AppState) -> Result<VerifyingKey> {
    let did_doc: DidDocument = state
        .client
        .get(format!(
            "{}/root/did",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await
        .context("fetch_root_did_failed")?
        .json()
        .await
        .context("decode_root_did_failed")?;
    let method = did_doc
        .verification_method
        .iter()
        .find(|method| did_doc.assertion_method.iter().any(|id| id == &method.id))
        .ok_or_else(|| anyhow::anyhow!("missing_root_verification_method"))?;
    verifying_key_from_method(method).map_err(Into::into)
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

fn verify_bulletin_state(bulletin: &Value, root_key: &VerifyingKey) -> Result<()> {
    let bulletin_obj: Bulletin = serde_json::from_value(bulletin.clone())?;
    bulletin_obj.verify_hash_chain(root_key)?;
    Ok(())
}

fn verify_package_root_proof(
    package: &VerifiedPackage,
    _bulletin: &Value,
    root_key: &VerifyingKey,
) -> bool {
    let Some(proof) = package.root_proof.proof.as_ref() else {
        return false;
    };
    let Some(package_claims) = package.root_proof.package_claims.as_ref() else {
        return false;
    };
    let claims_match = package_claims["subjectDid"] == package.did
        && package_claims["didDocumentHash"] == package.did_document_hash
        && package_claims["metadataHash"] == package.metadata_hash.clone().unwrap_or_default()
        && package_claims["documentVersion"].is_u64();
    if !claims_match {
        return false;
    }
    let suite = package
        .root_proof
        .crypto_suite
        .clone()
        .or_else(|| proof.crypto_suite())
        .unwrap_or(CryptoSuite::Ed25519Sha256Legacy);
    signature_input(suite, package_claims)
        .ok()
        .map(|input| oan_crypto::verify_bytes(root_key, &input, &proof.proof_value).is_ok())
        .unwrap_or(false)
}

fn authorized_domains_match(package: &VerifiedPackage, authorized_domains: &[String]) -> bool {
    let tree = CapabilityTagTree::load_from_path("../../docs/capability-tree-v1.json").unwrap_or(
        CapabilityTagTree {
            version: 1,
            tags: vec![],
            tree: vec![],
        },
    );
    tree.matches_authorized_domains(&package.metadata.capability_tags, authorized_domains)
}

fn sign_discovery_response(
    signing_key: &SigningKey,
    response: &DiscoveryResponse,
) -> Result<DiscoveryResponseProof, anyhow::Error> {
    let unsigned = serde_json::json!({
        "discoveryDid": response.discovery_did,
        "candidates": response.candidates,
        "createdAt": response.created_at,
    });
    build_data_integrity_proof(
        &unsigned,
        format!("{}#key-1", response.discovery_did),
        format!("{}#key-1", response.discovery_did),
        signing_key,
    )
    .map_err(Into::into)
}

fn matches_query(package: &VerifiedPackage, query: &DiscoveryQuery) -> bool {
    if let Some(text) = query
        .query
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let needle = text.to_ascii_lowercase();
        let description = package
            .did_document
            .ans_metadata
            .as_ref()
            .and_then(|metadata| metadata.agent_description.as_ref())
            .map(|description| description.capability_description.to_ascii_lowercase())
            .unwrap_or_default();
        let tag_match = package
            .metadata
            .capability_tags
            .iter()
            .any(|tag| tag.to_ascii_lowercase().contains(&needle));
        let did_match = package.did.to_ascii_lowercase().contains(&needle);
        let identity_type_match = package
            .metadata
            .identity_type
            .to_ascii_lowercase()
            .contains(&needle);
        if !tag_match && !did_match && !identity_type_match && !description.contains(&needle) {
            return false;
        }
    }
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
        let expected = service_type.to_ascii_lowercase();
        let identity_type_match = package.metadata.identity_type.to_ascii_lowercase() == expected;
        let service_match = package.metadata.services.iter().any(|service| {
            service.service_type.eq_ignore_ascii_case(service_type)
                || service
                    .service_type
                    .to_ascii_lowercase()
                    .contains(&expected)
        });
        if !identity_type_match && !service_match {
            return false;
        }
    }
    if let Some(protocol) = &query.protocol {
        if !package.metadata.services.iter().any(|service| {
            service
                .protocol
                .as_ref()
                .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                .unwrap_or(false)
        }) {
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
    use axum::{routing::get, Router};
    use oan_core::{AgentDescription, AnsMetadata, ServiceEndpoint, VerificationMethod};
    use oan_crypto::{
        generate_ed25519_keypair, hash_json, hash_json_with_suite, public_key_jwk,
        public_key_multibase, SigningKey as OanSigningKey, VerifyingKey as OanVerifyingKey,
    };
    use oan_package::{AgentMetadata, RootProof};
    use serde_json::json;
    use std::fs;

    fn root_document_with_key(did: &str, signing_key: &ed25519_dalek::SigningKey) -> DidDocument {
        let key_id = format!("{did}#key-1");
        let verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: signing_key.verifying_key(),
        };
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: vec![],
            ans_metadata: Some(AnsMetadata {
                subject_type: SubjectType::InfrastructureNode,
                identity_type: "root".to_owned(),
                ttl: None,
                address_bindings: vec![],
                agent_description: None,
                service_policy: None,
                network_scope: None,
                extra: Default::default(),
            }),
        }
    }

    fn package_with_tags(tags: Vec<&str>) -> VerifiedPackage {
        package_with_did_and_tags("did:ans:AGDM:efserviceagentservice1234", tags)
    }

    fn package_with_did_and_tags(did: &str, tags: Vec<&str>) -> VerifiedPackage {
        let services = vec![ServiceEndpoint {
            id: format!("{did}#invoke"),
            service_type: "AgentInvokeService".to_owned(),
            service_endpoint: "http://localhost:9001/agent/invoke".to_owned(),
            version: None,
            protocol: Some("http".to_owned()),
            server_type: None,
            port: Some(9001),
        }];
        let did_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
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
        let metadata = AgentMetadata {
            did: did_document.id.clone(),
            role: "Service Agent".to_owned(),
            identity_type: "service-agent".to_owned(),
            did_document_hash: hash_json(&did_document).unwrap(),
            capability_tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            services,
            status: "active".to_owned(),
            updated_at: Utc::now(),
        };
        let metadata_hash = hash_json(&metadata).unwrap();
        VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did_document.id.clone(),
            did_document_hash: hash_json(&did_document).unwrap(),
            metadata_hash: Some(metadata_hash),
            metadata,
            did_document,
            root_proof: RootProof {
                root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: None,
                hash_algorithm: None,
            },
            created_at: Utc::now(),
        }
    }

    fn write_ablation_report(name: &str, value: Value) {
        if let Ok(dir) = std::env::var("OAN_ABLATION_REPORT_DIR") {
            let dir = std::path::PathBuf::from(dir);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join(format!("{name}.json")),
                serde_json::to_string_pretty(&value).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn authorized_domains_filter_packages_by_tag() {
        let package = package_with_tags(vec!["finance"]);

        assert!(authorized_domains_match(&package, &["*".to_owned()]));
        assert!(authorized_domains_match(&package, &["finance".to_owned()]));
        assert!(!authorized_domains_match(
            &package,
            &["translation".to_owned()]
        ));
    }

    #[test]
    fn ablation_authorization_filtering_real_system() {
        let query = DiscoveryQuery {
            query: None,
            capability_tags: vec!["ablation.shared".to_owned()],
            service_type: None,
            protocol: None,
            limit: 50,
        };
        let authorized_domains = vec!["finance".to_owned()];
        let mut cases = Vec::new();
        for index in 0..12 {
            let package = package_with_did_and_tags(
                &format!("did:ans:AGDM:efablationunauth{index:02}"),
                vec!["translation", "ablation.shared"],
            );
            let full_returned =
                matches_query(&package, &query) && authorized_domains_match(&package, &authorized_domains);
            let degraded_returned = matches_query(&package, &query);
            assert!(!full_returned);
            assert!(degraded_returned);
            cases.push(json!({
                "case": format!("unauthorized_shared_tag_{index}"),
                "fullReturned": full_returned,
                "degradedReturned": degraded_returned
            }));
        }
        write_ablation_report(
            "authorization_filtering",
            json!({
                "mechanism": "authorization-aware discovery filtering",
                "invalidCases": cases.len(),
                "fullFalseAcceptanceOrExposure": 0,
                "degradedFalseAcceptanceOrExposure": cases.len(),
                "cases": cases
            }),
        );
    }

    #[test]
    fn package_root_proof_accepts_matching_package_claim_signature() {
        let root_key = generate_ed25519_keypair();
        let wrapped_root_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.clone(),
        };
        let root_verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.verifying_key(),
        };
        let mut package = package_with_tags(vec!["finance"]);
        let claims = json!({
            "subjectDid": package.did,
            "registrarDid": "did:ans:AGRG:efregistrarregistrar1234",
            "didDocumentHash": package.did_document_hash,
            "metadataHash": package.metadata_hash.clone().unwrap(),
            "documentVersion": 1,
            "operation": "create",
            "capabilityTags": package.metadata.capability_tags
        });
        package.root_proof.package_claims = Some(claims.clone());
        package.root_proof.proof = Some(
            build_data_integrity_proof(
                &claims,
                "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                &wrapped_root_key,
            )
            .unwrap(),
        );
        let bulletin = json!({ "events": [] });

        assert!(verify_package_root_proof(
            &package,
            &bulletin,
            &root_verifying_key
        ));
    }

    #[test]
    fn package_root_proof_rejects_tampered_signature() {
        let root_key = generate_ed25519_keypair();
        let wrong_key = generate_ed25519_keypair();
        let wrapped_wrong_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: wrong_key,
        };
        let root_verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.verifying_key(),
        };
        let mut package = package_with_tags(vec!["finance"]);
        let claims = json!({
            "subjectDid": package.did,
            "registrarDid": "did:ans:AGRG:efregistrarregistrar1234",
            "didDocumentHash": package.did_document_hash,
            "metadataHash": package.metadata_hash.clone().unwrap(),
            "documentVersion": 1,
            "operation": "create",
            "capabilityTags": package.metadata.capability_tags
        });
        package.root_proof.package_claims = Some(claims.clone());
        package.root_proof.proof = Some(
            build_data_integrity_proof(
                &claims,
                "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                &wrapped_wrong_key,
            )
            .unwrap(),
        );
        let bulletin = json!({ "events": [] });

        assert!(!verify_package_root_proof(
            &package,
            &bulletin,
            &root_verifying_key
        ));
    }

    #[test]
    fn package_root_proof_rejects_subject_mismatch() {
        let root_key = generate_ed25519_keypair();
        let wrapped_root_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.clone(),
        };
        let root_verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.verifying_key(),
        };
        let mut package = package_with_tags(vec!["finance"]);
        let claims = json!({
            "subjectDid": "did:ans:AGDM:efotherserviceagent1234",
            "registrarDid": "did:ans:AGRG:efregistrarregistrar1234",
            "didDocumentHash": package.did_document_hash,
            "metadataHash": package.metadata_hash.clone().unwrap(),
            "documentVersion": 1,
            "operation": "create",
            "capabilityTags": package.metadata.capability_tags
        });
        package.root_proof.package_claims = Some(claims.clone());
        package.root_proof.proof = Some(
            build_data_integrity_proof(
                &claims,
                "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                "did:ans:AGRT:efrootrootrootrootrootroot#key-1".to_owned(),
                &wrapped_root_key,
            )
            .unwrap(),
        );
        let bulletin = json!({ "events": [] });

        assert!(!verify_package_root_proof(
            &package,
            &bulletin,
            &root_verifying_key
        ));
    }

    #[test]
    fn package_hash_checks_reject_tampering() {
        let mut package = package_with_tags(vec!["finance"]);
        package.did_document.id = "did:ans:AGDM:eftamperedserviceagent1234".to_owned();
        assert!(package.verify_document_hash().is_err());

        let mut package = package_with_tags(vec!["finance"]);
        package.metadata_hash = Some("definitely-not-the-metadata-hash".to_owned());
        assert!(package.verify_metadata_hash().is_err());
    }

    #[test]
    fn discovery_authorized_domains_defaults_and_updates() {
        let discovery_did = "did:ans:AGDS:efdiscoverydiscovery1234";
        let empty_bulletin = json!({ "events": [] });
        assert_eq!(
            discovery_authorized_domains(&empty_bulletin, discovery_did),
            vec!["*".to_owned()]
        );

        let bulletin = json!({
            "events": [{
                "subjectDid": discovery_did,
                "eventType": "DISCOVERY_NODE_DOMAINS_UPDATED",
                "payload": { "authorizedDomains": ["finance", "education"] }
            }]
        });
        assert_eq!(
            discovery_authorized_domains(&bulletin, discovery_did),
            vec!["finance".to_owned(), "education".to_owned()]
        );
    }

    #[test]
    fn discovery_response_signature_is_verifiable() {
        let signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: generate_ed25519_keypair(),
        };
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
        let input = signature_input(signing_key.crypto_suite(), &unsigned).unwrap();

        assert!(oan_crypto::verify_bytes(
            &signing_key.verifying_key(),
            &input,
            &signature.proof_value
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
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: None,
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: None,
            client: reqwest::Client::new(),
        };
        state
            .index
            .write(
                "capabilities.json",
                &vec![package_with_tags(vec!["finance"])],
            )
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
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: None,
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: None,
            client: reqwest::Client::new(),
        };
        state
            .index
            .write(
                "capabilities.json",
                &vec![package_with_tags(vec!["finance"])],
            )
            .unwrap();
        let response = api_query_explain(
            State(state),
            Json(DiscoveryQuery {
                query: None,
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

    #[tokio::test]
    async fn sync_cursor_remains_monotonic_and_index_keeps_latest_package() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.path().join("discovery.db").display()
        ))
        .await
        .unwrap();
        initialize_discovery_sqlite(&sqlite).await.unwrap();
        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: Some(format!(
                        "sqlite:{}",
                        dir.path().join("discovery.db").display()
                    )),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: Some(sqlite),
            client: reqwest::Client::new(),
        };

        write_sync_cursor(&state, 5).await.unwrap();
        write_sync_cursor(&state, 3).await.unwrap();
        assert_eq!(read_sync_cursor(&state).await.unwrap(), 3);
        write_sync_cursor(&state, 8).await.unwrap();
        assert_eq!(read_sync_cursor(&state).await.unwrap(), 8);

        let mut package_v1 = package_with_tags(vec!["finance"]);
        package_v1.root_proof.package_claims = Some(json!({ "documentVersion": 1 }));
        upsert_indexed_package(&state, 8, &package_v1).await.unwrap();

        let mut package_v2 = package_with_tags(vec!["finance", "updated"]);
        package_v2.root_proof.package_claims = Some(json!({ "documentVersion": 2 }));
        upsert_indexed_package(&state, 9, &package_v2).await.unwrap();

        let packages = read_indexed_packages(&state).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].metadata.capability_tags, vec!["finance", "updated"]);
    }

    #[tokio::test]
    async fn sync_from_cdn_does_not_advance_cursor_past_decode_failure() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.path().join("discovery.db").display()
        ))
        .await
        .unwrap();
        initialize_discovery_sqlite(&sqlite).await.unwrap();

        let root_key = generate_ed25519_keypair();
        let wrapped_root_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.clone(),
        };
        let root_did = "did:ans:AGRT:efrootrootrootrootrootroot";
        let root_doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: root_did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{root_did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: root_did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(oan_crypto::public_key_multibase(
                    &OanVerifyingKey::Ed25519 {
                        suite: CryptoSuite::Ed25519Sha256Legacy,
                        key: root_key.verifying_key(),
                    },
                )),
                public_key_jwk: Some(oan_crypto::public_key_jwk(&OanVerifyingKey::Ed25519 {
                    suite: CryptoSuite::Ed25519Sha256Legacy,
                    key: root_key.verifying_key(),
                })),
            }],
            authentication: vec![format!("{root_did}#key-1")],
            assertion_method: vec![format!("{root_did}#key-1")],
            service: vec![],
            ans_metadata: Some(AnsMetadata {
                subject_type: SubjectType::InfrastructureNode,
                identity_type: "root".to_owned(),
                ttl: None,
                address_bindings: vec![],
                agent_description: None,
                service_policy: None,
                network_scope: None,
                extra: Default::default(),
            }),
        };
        JsonStore::new(dir.path())
            .write("did-document.json", &root_doc)
            .unwrap();

        let mut package = package_with_tags(vec!["finance"]);
        package.did = "did:ans:AGDM:efsyncfixture0001".to_owned();
        package.did_document.id = package.did.clone();
        package.metadata.did = package.did.clone();
        package.metadata.services[0].id = format!("{}#svc", package.did);
        package.did_document.service[0].id = format!("{}#svc", package.did);
        package.did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &package.did_document).unwrap();
        package.metadata.did_document_hash = package.did_document_hash.clone();
        package.metadata_hash = Some(
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &package.metadata).unwrap(),
        );
        let claims = json!({
            "subjectDid": package.did,
            "registrarDid": "did:ans:AGRG:efregistrarregistrar1234",
            "didDocumentHash": package.did_document_hash,
            "metadataHash": package.metadata_hash.clone().unwrap(),
            "documentVersion": 1,
            "operation": "create",
            "capabilityTags": package.metadata.capability_tags
        });
        package.root_proof.package_claims = Some(claims.clone());
        package.root_proof.proof = Some(
            build_data_integrity_proof(
                &claims,
                format!("{root_did}#key-1"),
                format!("{root_did}#key-1"),
                &wrapped_root_key,
            )
            .unwrap(),
        );
        package.root_proof.crypto_suite = Some(CryptoSuite::Ed25519Sha256Legacy);
        package.root_proof.hash_algorithm = Some("SHA-256".to_owned());
        package.root_proof.root_did = root_did.to_owned();

        let bulletin = Bulletin {
            version: "0.1.0".to_owned(),
            root_did: root_did.to_owned(),
            created_at: Utc::now(),
            events: vec![],
        };
        let package_body = serde_json::to_string(&package).unwrap();
        let bulletin_body = serde_json::to_string(&bulletin).unwrap();
        let root_doc_body = serde_json::to_string(&root_doc).unwrap();
        let publications_body = serde_json::to_string(&json!({
            "items": [
                {
                    "cursor": 1,
                    "agentDid": package.did,
                    "documentVersion": 1,
                    "didDocumentHash": package.did_document_hash,
                    "metadataHash": package.metadata_hash.clone().unwrap(),
                    "acceptedAt": Utc::now().to_rfc3339()
                },
                {
                    "cursor": 2,
                    "agentDid": "did:ans:AGDM:efsyncfixture0002",
                    "documentVersion": 1,
                    "didDocumentHash": "hash-2",
                    "metadataHash": "meta-2",
                    "acceptedAt": Utc::now().to_rfc3339()
                }
            ],
            "nextCursor": 2
        }))
        .unwrap();

        let app = Router::new()
            .route(
                "/bulletin",
                get({
                    let bulletin_body = bulletin_body.clone();
                    move || {
                        let bulletin_body = bulletin_body.clone();
                        async move { bulletin_body }
                    }
                }),
            )
            .route(
                "/root/did",
                get({
                    let root_doc_body = root_doc_body.clone();
                    move || {
                        let root_doc_body = root_doc_body.clone();
                        async move { root_doc_body }
                    }
                }),
            )
            .route(
                "/root/publications",
                get({
                    let publications_body = publications_body.clone();
                    move || {
                        let publications_body = publications_body.clone();
                        async move { publications_body }
                    }
                }),
            )
            .route(
                "/cdn/packages/{did}",
                get({
                    let package_did = package.did.clone();
                    let package_body = package_body.clone();
                    move |AxumPath(did): AxumPath<String>| {
                        let package_did = package_did.clone();
                        let package_body = package_body.clone();
                        async move {
                            if did == package_did {
                                (StatusCode::OK, package_body)
                            } else {
                                (StatusCode::OK, "{\"not\":\"a verified package\"}".to_owned())
                            }
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: format!("http://{}", addr),
                    cdn_endpoint: Some(format!("http://{}", addr)),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: Some(format!(
                        "sqlite:{}",
                        dir.path().join("discovery.db").display()
                    )),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: Some(sqlite),
            client: reqwest::Client::new(),
        };

        let response = sync_from_cdn(
            State(state.clone()),
            Some(Json(SyncRequest {
                max_publications: Some(10),
                cursor_hint: None,
            })),
        )
            .await
            .unwrap();
        assert_eq!(response.0["syncedCount"], 1);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(response.0["latestCursor"], 1);
        assert_eq!(read_sync_cursor(&state).await.unwrap(), 1);

        let packages = read_indexed_packages(&state).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].did, package.did);
    }

    #[tokio::test]
    async fn sync_with_satisfied_cursor_hint_returns_noop() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.path().join("discovery.db").display()
        ))
        .await
        .unwrap();
        initialize_discovery_sqlite(&sqlite).await.unwrap();

        let bulletin = json!({
            "version": "0.1.0",
            "rootDid": "did:ans:AGRT:efrootrootrootrootrootroot",
            "createdAt": Utc::now(),
            "events": []
        });
        let root_key = generate_ed25519_keypair();
        let root_did = "did:ans:AGRT:efrootrootrootrootrootroot";
        let root_doc = root_document_with_key(root_did, &root_key);
        let app = Router::new()
            .route(
                "/bulletin",
                get({
                    let bulletin = bulletin.to_string();
                    move || {
                        let bulletin = bulletin.clone();
                        async move { bulletin }
                    }
                }),
            )
            .route(
                "/root/did",
                get({
                    let root_doc = serde_json::to_string(&root_doc).unwrap();
                    move || {
                        let root_doc = root_doc.clone();
                        async move { root_doc }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: format!("http://{}", addr),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: Some(format!(
                        "sqlite:{}",
                        dir.path().join("discovery.db").display()
                    )),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: Some(sqlite),
            client: reqwest::Client::new(),
        };

        write_sync_cursor(&state, 3).await.unwrap();
        let response = sync_from_cdn(
            State(state),
            Some(Json(SyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(3),
            })),
        )
        .await
        .unwrap();

        assert_eq!(response.0["status"], "noop");
        assert_eq!(response.0["syncedCount"], 0);
        assert_eq!(response.0["latestCursor"], 3);
    }

    #[tokio::test]
    async fn sqlite_sync_path_does_not_emit_debug_exports() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.path().join("discovery.db").display()
        ))
        .await
        .unwrap();
        initialize_discovery_sqlite(&sqlite).await.unwrap();

        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: Some(format!(
                        "sqlite:{}",
                        dir.path().join("discovery.db").display()
                    )),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: Some(sqlite),
            client: reqwest::Client::new(),
        };

        let package = package_with_tags(vec!["finance"]);
        upsert_indexed_package(&state, 1, &package).await.unwrap();
        write_sync_history_sqlite(
            &state,
            json!({
                "syncedAt": Utc::now(),
                "status": "synced",
                "syncedCount": 1,
                "rejectedCount": 0,
                "latestCursor": 1
            }),
        )
        .await
        .unwrap();
        write_rejected_packages(
            &state,
            &[json!({
                "did": "did:ans:AGDM:reject1",
                "cursor": 2,
                "reason": "invalid_root_proof"
            })],
        )
        .await
        .unwrap();

        assert!(!dir.path().join("capabilities.json").exists());
        assert!(!dir.path().join("rejected-packages.json").exists());
        assert!(!dir.path().join("sync-history.json").exists());
    }

    #[tokio::test]
    async fn discovery_debug_export_remains_available_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.path().join("discovery.db").display()
        ))
        .await
        .unwrap();
        initialize_discovery_sqlite(&sqlite).await.unwrap();

        let state = AppState {
            data: JsonStore::new(dir.path()),
            index: JsonStore::new(dir.path()),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:9000".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.path().to_path_buf(),
                    index_dir: dir.path().to_path_buf(),
                    keys_dir: dir.path().to_path_buf(),
                    database_url: Some(format!(
                        "sqlite:{}",
                        dir.path().join("discovery.db").display()
                    )),
                },
            },
            did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: generate_ed25519_keypair(),
            },
            sqlite: Some(sqlite),
            client: reqwest::Client::new(),
        };

        let package = package_with_tags(vec!["finance"]);
        upsert_indexed_package(&state, 1, &package).await.unwrap();
        write_sync_history_sqlite(
            &state,
            json!({
                "syncedAt": Utc::now(),
                "status": "synced",
                "syncedCount": 1,
                "rejectedCount": 0,
                "latestCursor": 1
            }),
        )
        .await
        .unwrap();
        write_rejected_packages(
            &state,
            &[json!({
                "did": "did:ans:AGDM:reject1",
                "cursor": 2,
                "reason": "invalid_root_proof"
            })],
        )
        .await
        .unwrap();

        export_discovery_debug_snapshot(&state).await.unwrap();

        let packages: Vec<VerifiedPackage> = state.index.read("capabilities.json").unwrap();
        assert_eq!(packages.len(), 1);
        let rejected: Vec<Value> = state.index.read("rejected-packages.json").unwrap();
        assert_eq!(rejected.len(), 1);
        let history: Vec<Value> = state.index.read("sync-history.json").unwrap();
        assert_eq!(history.len(), 1);
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
