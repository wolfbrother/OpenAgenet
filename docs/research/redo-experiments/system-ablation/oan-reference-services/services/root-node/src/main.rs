// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use oan_bulletin::{Bulletin, BulletinEvent, BulletinEventCore, BulletinEventType};
use oan_core::{CapabilityTag, CapabilityTagTree, CryptoSuite, DidDocument, SubjectType};
use oan_credentials::{verify_agent_registration_credential, AgentRegistrationCredential};
use oan_crypto::{
    build_data_integrity_proof, hash_json_with_suite, signing_key_from_bytes,
    verifying_key_from_method, SigningKey, VerifyingKey,
};
use oan_did_ans::DidAns;
use oan_package::{AgentMetadata, RootProof, VerifiedPackage};
use oan_protocol::{
    AgentRegistrationSubmission, CdnPublishRequest, HealthResponse, RootAuthorizeRequest,
    VerifyAndPublishRequest, PATH_CDN_PACKAGES, PATH_ROOT_VERIFY_AND_PUBLISH,
    PURPOSE_AGENT_REGISTRATION, PURPOSE_CDN_PUBLISH, PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_service_security::{
    bearer_token_from_header, create_signed_request_envelope, request_id, request_nonce,
    verify_admin_token, verify_registration_binding_claims, verify_signed_request_envelope,
    verify_signed_request_envelope_without_freshness, verify_subject_control_proof,
    AdminAuthConfig, AdminAuthMode, AdminPrincipal, DidControlVerificationContext,
    TrustedUpstreamPolicy,
};
use oan_storage::{did_to_file_name, JsonStore, SqliteJsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration as TokioDuration};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

const ROOT_CDN_JOB_TABLE: &str = "root_cdn_publish_jobs";
const ROOT_DISCOVERY_TARGET_TABLE: &str = "root_discovery_target_notifications";
const ROOT_BULLETIN_EVENT_TABLE: &str = "root_bulletin_events";
const ROOT_SUBJECT_LATEST_TABLE: &str = "root_subject_latest";
const ROOT_SUBJECT_VERSION_TABLE: &str = "root_subject_versions";
const ROOT_PACKAGE_JOB_TABLE: &str = "root_verified_package_jobs";
const ROOT_DEBUG_EXPORT_INTERVAL_MS: u64 = 2_000;

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    security: SecurityConfig,
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

#[derive(Clone, Debug, Default, Deserialize)]
struct SecurityConfig {
    #[serde(default)]
    admin: AdminSecurityConfig,
    #[serde(default)]
    trusted_upstream: TrustedUpstreamSecurityConfig,
    #[serde(default)]
    workers: WorkerSecurityConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct AdminSecurityConfig {
    #[serde(default = "default_admin_mode")]
    mode: String,
    #[serde(default)]
    static_tokens: Vec<String>,
    #[serde(default)]
    trusted_admin_dids: Vec<String>,
    #[serde(default = "default_clock_skew_seconds")]
    max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    nonce_ttl_seconds: i64,
    #[serde(default = "default_admin_nonce_file")]
    nonce_store_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
struct TrustedUpstreamSecurityConfig {
    #[serde(default = "default_clock_skew_seconds")]
    max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    nonce_ttl_seconds: i64,
}

impl Default for TrustedUpstreamSecurityConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: default_clock_skew_seconds(),
            nonce_ttl_seconds: default_nonce_ttl_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WorkerSecurityConfig {
    #[serde(default = "default_worker_enabled")]
    enabled: bool,
    #[serde(default = "default_cdn_worker_interval_ms")]
    cdn_interval_ms: u64,
    #[serde(default = "default_discovery_worker_interval_ms")]
    discovery_interval_ms: u64,
    #[serde(default = "default_cdn_worker_batch_size")]
    cdn_batch_size: usize,
    #[serde(default = "default_discovery_worker_batch_size")]
    discovery_batch_size: usize,
    #[serde(default = "default_worker_lease_seconds")]
    lease_seconds: i64,
    #[serde(default = "default_worker_retry_backoff_seconds")]
    retry_backoff_seconds: i64,
    #[serde(default = "default_worker_http_timeout_seconds")]
    http_timeout_seconds: u64,
}

impl Default for WorkerSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: default_worker_enabled(),
            cdn_interval_ms: default_cdn_worker_interval_ms(),
            discovery_interval_ms: default_discovery_worker_interval_ms(),
            cdn_batch_size: default_cdn_worker_batch_size(),
            discovery_batch_size: default_discovery_worker_batch_size(),
            lease_seconds: default_worker_lease_seconds(),
            retry_backoff_seconds: default_worker_retry_backoff_seconds(),
            http_timeout_seconds: default_worker_http_timeout_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    keys_dir: PathBuf,
    bulletin_file: PathBuf,
    #[serde(default = "default_authorization_state_file")]
    authorization_state_file: PathBuf,
    #[serde(default = "default_request_nonce_file")]
    request_nonce_file: PathBuf,
    #[serde(default = "default_capability_tree_file")]
    capability_tree_file: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_authorization_state_file() -> PathBuf {
    PathBuf::from("../../data/root/authorization-state.json")
}

fn default_request_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/request-nonces.json")
}

fn default_admin_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/admin-request-nonces.json")
}

fn default_capability_tree_file() -> PathBuf {
    PathBuf::from("../../docs/capability-tree-v1.json")
}

fn default_admin_mode() -> String {
    "static-token".to_owned()
}

fn default_worker_enabled() -> bool {
    true
}

fn default_cdn_worker_interval_ms() -> u64 {
    1_000
}

fn default_discovery_worker_interval_ms() -> u64 {
    1_500
}

fn default_cdn_worker_batch_size() -> usize {
    50
}

fn default_discovery_worker_batch_size() -> usize {
    100
}

fn default_worker_lease_seconds() -> i64 {
    60
}

fn default_worker_retry_backoff_seconds() -> i64 {
    15
}

fn default_worker_http_timeout_seconds() -> u64 {
    10
}

fn default_clock_skew_seconds() -> i64 {
    300
}

fn default_nonce_ttl_seconds() -> i64 {
    300
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256Legacy),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow!("unsupported_algorithm: {other}")),
    }
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    root_did: String,
    signing_key: SigningKey,
    tag_tree: CapabilityTagTree,
    sqlite: Option<SqliteJsonStore>,
    authorization_state: AuthorizationState,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscoveryNotifyTargetState {
    #[serde(rename = "discoveryDid")]
    discovery_did: String,
    #[serde(rename = "pendingCursor")]
    pending_cursor: i64,
    #[serde(rename = "deliveredCursor")]
    delivered_cursor: i64,
    status: String,
    #[serde(rename = "attemptCount")]
    attempt_count: i64,
    #[serde(rename = "leaseOwner")]
    lease_owner: Option<String>,
    #[serde(rename = "leaseExpiresAt")]
    lease_expires_at: Option<String>,
    #[serde(rename = "nextAttemptAt")]
    next_attempt_at: String,
    #[serde(rename = "lastError")]
    last_error: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Clone, Debug)]
struct DiscoveryNotifyTargetLease {
    discovery_did: String,
    target_cursor: i64,
    delivered_cursor: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AuthorizationState {
    registrars: BTreeMap<String, NodeAuthorizationState>,
    discovery_nodes: BTreeMap<String, DiscoveryAuthorizationState>,
    vc_issuers: BTreeMap<String, NodeAuthorizationState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeAuthorizationState {
    status: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    did_document_hash: String,
    #[serde(
        rename = "didDocumentSnapshot",
        skip_serializing_if = "Option::is_none"
    )]
    did_document_snapshot: Option<DidDocument>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscoveryAuthorizationState {
    status: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    did_document_hash: String,
    #[serde(
        rename = "didDocumentSnapshot",
        skip_serializing_if = "Option::is_none"
    )]
    did_document_snapshot: Option<DidDocument>,
    authorized_domains: Vec<String>,
    tag_tree_version: u64,
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

    fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.into().to_string(),
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
    #[serde(rename = "cdnDispatchStatus")]
    cdn_dispatch_status: String,
    #[serde(rename = "discoveryNotifyStatus")]
    discovery_notify_status: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    did: String,
    algorithm: String,
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
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let authorization_state =
        load_authorization_state(&config.paths.authorization_state_file).unwrap_or_default();
    let sqlite = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let sqlite = SqliteJsonStore::connect(url).await?;
            initialize_root_sqlite(&sqlite).await?;
            Some(sqlite)
        }
        _ => None,
    };
    let state = AppState {
        data,
        config: config.clone(),
        root_did: key.did,
        signing_key,
        tag_tree: oan_core::CapabilityTagTree::load_from_path(&config.paths.capability_tree_file)
            .unwrap_or_else(|_| default_tag_tree()),
        sqlite,
        authorization_state,
        client: reqwest::Client::builder()
            .timeout(TokioDuration::from_secs(
                config.security.workers.http_timeout_seconds,
            ))
            .build()?,
    };

    bootstrap_root_bulletin_from_json(&state).await?;
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/root/did", get(root_did_document))
        .route("/bulletin", get(bulletin))
        .route("/root/status", get(api_status))
        .route("/root/registrars", get(api_registrars))
        .route("/root/registrars/{did}", get(api_registrar_detail))
        .route("/root/discovery-nodes", get(api_discovery_nodes))
        .route("/root/discovery-nodes/{did}", get(api_discovery_detail))
        .route("/root/agents", get(api_agents))
        .route("/root/agents/{did}", get(api_agent_detail))
        .route("/root/agents/{did}/versions", get(api_agent_versions))
        .route("/root/publications", get(api_publications))
        .route(
            "/root/agents/{did}/versions/{version}",
            get(api_agent_version_detail),
        )
        .route("/root/queues/cdn-publish", get(api_cdn_publish_queue))
        .route(
            "/root/queues/discovery-notify",
            get(api_discovery_notify_queue),
        )
        .route("/root/capability-tree", get(api_capability_tree))
        .route(
            "/root/capability-tree/validate-tags",
            post(api_validate_tags),
        )
        .route("/root/bulletin/events", get(api_bulletin_events))
        .route(
            "/root/bulletin/events/{sequence}",
            get(api_bulletin_event_detail),
        )
        .layer(build_cors_layer(&config.cors)?);

    let admin_routes = Router::new()
        .route("/root/registrars/authorize", post(authorize_registrar))
        .route("/root/discovery-nodes/authorize", post(authorize_discovery))
        .route(
            "/root/discovery-nodes/{did}/domains",
            post(update_discovery_domains),
        )
        .route("/root/nodes/{did}/revoke", post(revoke_node))
        .route("/root/agents/verify-and-publish", post(verify_and_publish))
        .route("/root/batches/publish-cdn", post(publish_cdn_batch))
        .route(
            "/root/batches/notify-discovery",
            post(notify_discovery_batch),
        )
        .route("/root/queues/cdn-publish/run", post(publish_cdn_batch))
        .route(
            "/root/queues/discovery-notify/run",
            post(notify_discovery_batch),
        );

    let app = Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state.clone());

    if state.config.security.workers.enabled {
        spawn_root_workers(state.clone());
    }

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
    config.paths.authorization_state_file =
        resolve_relative(base, &config.paths.authorization_state_file);
    config.paths.request_nonce_file = resolve_relative(base, &config.paths.request_nonce_file);
    config.security.admin.nonce_store_file =
        resolve_relative(base, &config.security.admin.nonce_store_file);
    if !config.paths.capability_tree_file.as_os_str().is_empty() {
        config.paths.capability_tree_file =
            resolve_relative(base, &config.paths.capability_tree_file);
    }
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_sqlite_url(base, database_url);
    }
    Ok(config)
}

fn admin_auth_config(state: &AppState) -> AdminAuthConfig {
    match state.config.security.admin.mode.as_str() {
        "signed-did" => {
            let trusted_admin_documents = state
                .config
                .security
                .admin
                .trusted_admin_dids
                .iter()
                .filter_map(|did| load_authorized_registrar_document(state, did).ok())
                .collect::<Vec<_>>();
            AdminAuthConfig {
                mode: AdminAuthMode::SignedDid {
                    trusted_admin_documents,
                    max_clock_skew_seconds: state.config.security.admin.max_clock_skew_seconds,
                    nonce_ttl_seconds: state.config.security.admin.nonce_ttl_seconds,
                    nonce_store_path: state.config.security.admin.nonce_store_file.clone(),
                    audience: state.root_did.clone(),
                },
            }
        }
        _ => AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: state.config.security.admin.static_tokens.clone(),
            },
        },
    }
}

fn trusted_upstream_policy(state: &AppState, expected_path: &str) -> TrustedUpstreamPolicy {
    TrustedUpstreamPolicy {
        expected_purpose: PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: expected_path.to_owned(),
        expected_audience: state.root_did.clone(),
        max_clock_skew_seconds: state
            .config
            .security
            .trusted_upstream
            .max_clock_skew_seconds,
        nonce_ttl_seconds: state.config.security.trusted_upstream.nonce_ttl_seconds,
        nonce_store_path: state.config.paths.request_nonce_file.clone(),
    }
}

fn require_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> std::result::Result<AdminPrincipal, ApiError> {
    let config = admin_auth_config(state);
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| bearer_token_from_header(Some(value)));
    verify_admin_token(token, &config).map_err(|err| ApiError {
        status: StatusCode::UNAUTHORIZED,
        message: err.to_string(),
    })
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
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

fn spawn_root_workers(state: AppState) {
    let cdn_state = state.clone();
    tokio::spawn(async move {
        root_cdn_worker_loop(cdn_state).await;
    });
    let discovery_state = state.clone();
    tokio::spawn(async move {
        root_discovery_worker_loop(discovery_state).await;
    });
    if state.sqlite.is_some() {
        tokio::spawn(async move {
            root_debug_export_loop(state).await;
        });
    }
}

async fn root_cdn_worker_loop(state: AppState) {
    let interval_ms = state.config.security.workers.cdn_interval_ms.max(100);
    loop {
        if let Err(err) = run_cdn_publish_cycle(&state).await {
            eprintln!("root cdn worker cycle failed: {err}");
        }
        sleep(TokioDuration::from_millis(interval_ms)).await;
    }
}

async fn root_discovery_worker_loop(state: AppState) {
    let interval_ms = state.config.security.workers.discovery_interval_ms.max(100);
    loop {
        if let Err(err) = run_discovery_notify_cycle(&state).await {
            eprintln!("root discovery worker cycle failed: {err}");
        }
        sleep(TokioDuration::from_millis(interval_ms)).await;
    }
}

async fn root_debug_export_loop(state: AppState) {
    loop {
        if let Err(err) = export_root_debug_snapshot(&state).await {
            eprintln!("root debug export failed: {err}");
        }
        sleep(TokioDuration::from_millis(ROOT_DEBUG_EXPORT_INTERVAL_MS)).await;
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

async fn initialize_root_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {ROOT_BULLETIN_EVENT_TABLE} (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                actor_did TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT,
                event_hash TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_SUBJECT_LATEST_TABLE} (
                subject_did TEXT PRIMARY KEY,
                current_version INTEGER NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                operation TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_SUBJECT_VERSION_TABLE} (
                subject_did TEXT NOT NULL,
                version INTEGER NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                package_json TEXT NOT NULL,
                archive_path TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                PRIMARY KEY(subject_did, version)
            );
            CREATE TABLE IF NOT EXISTS {ROOT_PACKAGE_JOB_TABLE} (
                job_key TEXT PRIMARY KEY,
                subject_did TEXT NOT NULL,
                version INTEGER NOT NULL,
                package_json TEXT NOT NULL,
                status TEXT NOT NULL,
                operation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_DISCOVERY_TARGET_TABLE} (
                discovery_did TEXT PRIMARY KEY,
                pending_cursor INTEGER NOT NULL DEFAULT 0,
                delivered_cursor INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ready',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                updated_at TEXT NOT NULL
            );
            "#
        ))
        .await?;
    sqlite.ensure_leased_job_table(ROOT_CDN_JOB_TABLE).await?;
    Ok(())
}

async fn bootstrap_root_bulletin_from_json(state: &AppState) -> Result<()> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(());
    };
    let store = JsonStore::new(".");
    if !state.config.paths.bulletin_file.exists() {
        return Ok(());
    }
    let bulletin: Bulletin = store.read(&state.config.paths.bulletin_file)?;
    for event in bulletin.events {
        let event_json = serde_json::to_string(&event)?;
        let payload_json = serde_json::to_string(&event.core.payload)?;
        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_BULLETIN_EVENT_TABLE}(sequence, event_type, subject_did, actor_did, payload_json, previous_hash, event_hash, event_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sequence)
            DO UPDATE SET
                event_type = excluded.event_type,
                subject_did = excluded.subject_did,
                actor_did = excluded.actor_did,
                payload_json = excluded.payload_json,
                previous_hash = excluded.previous_hash,
                event_hash = excluded.event_hash,
                event_json = excluded.event_json,
                created_at = excluded.created_at
            "#
        ))
        .bind(event.core.sequence as i64)
        .bind(serde_json::to_value(&event.core.event_type)?.as_str().unwrap_or_default())
        .bind(&event.core.subject_did)
        .bind(&event.core.actor_did)
        .bind(payload_json)
        .bind(event.core.previous_hash.clone())
        .bind(&event.event_hash)
        .bind(event_json)
        .bind(event.core.created_at.to_rfc3339())
        .execute(sqlite.pool())
        .await?;
    }
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "root".to_owned(),
        did: Some(state.root_did),
    })
}

fn block_on_sqlite<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>> + Send,
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(future)
    }
}

async fn root_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(ApiError::internal)
}

async fn bulletin(State(state): State<AppState>) -> ApiResult<Bulletin> {
    read_bulletin(&state).map(Json).map_err(ApiError::internal)
}

async fn verify_and_publish(
    State(state): State<AppState>,
    Json(request): Json<VerifyAndPublishRequest>,
) -> ApiResult<VerifyResponse> {
    verify_request(&state, &request).map_err(ApiError::bad_request)?;

    let root_suite = state.signing_key.crypto_suite();
    let did_document_hash =
        hash_json_with_suite(root_suite.clone(), &request.submission.did_document)
            .map_err(ApiError::internal)?;
    let metadata = build_metadata(&state, &request.submission, &did_document_hash)
        .map_err(ApiError::internal)?;
    let metadata_hash =
        hash_json_with_suite(root_suite.clone(), &metadata).map_err(ApiError::internal)?;
    let (operation, document_version, package) = if state.sqlite.is_some() {
        persist_verified_acceptance_sqlite(
            &state,
            &request,
            &did_document_hash,
            &metadata_hash,
            &metadata,
        )
        .await
        .map_err(ApiError::internal)?
    } else {
        let previous = load_latest_version(&state, &request.submission.agent_did)
            .await
            .map_err(ApiError::internal)?;
        let operation = match previous {
            None => "create",
            Some(ref value) if value["didDocumentHash"] == did_document_hash => "no-op",
            Some(_) => "update",
        }
        .to_owned();
        let document_version = previous
            .as_ref()
            .and_then(|value| value["documentVersion"].as_u64())
            .unwrap_or(0)
            + u64::from(operation != "no-op");

        let package_claims = json!({
            "subjectDid": request.submission.agent_did,
            "registrarDid": request.registrar_did,
            "didDocumentHash": did_document_hash,
            "metadataHash": metadata_hash,
            "documentVersion": document_version,
            "operation": operation,
            "capabilityTags": metadata.capability_tags
        });

        let package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: request.submission.agent_did.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: did_document_hash.clone(),
            metadata_hash: Some(metadata_hash.clone()),
            metadata: metadata.clone(),
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: Some(package_claims.clone()),
                proof: Some(
                    build_data_integrity_proof(
                        &package_claims,
                        format!("{}#key-1", state.root_did),
                        format!("{}#key-1", state.root_did),
                        &state.signing_key,
                    )
                    .map_err(ApiError::internal)?,
                ),
                crypto_suite: Some(state.signing_key.crypto_suite()),
                hash_algorithm: Some(state.signing_key.crypto_suite().hash_algorithm().to_owned()),
            },
            created_at: Utc::now(),
        };

        persist_verified_acceptance(
            &state,
            &request.submission.agent_did,
            document_version,
            &did_document_hash,
            &metadata_hash,
            &operation,
            &package,
        )
        .await
        .map_err(ApiError::internal)?;
        (operation, document_version, package)
    };
    if state.sqlite.is_none() {
        archive_verified(
            &state,
            &request.submission,
            &metadata,
            &package,
            document_version,
        )
        .map_err(ApiError::internal)?;
    }

    Json(VerifyResponse {
        status: "verified-and-queued".to_owned(),
        operation,
        agent_did: request.submission.agent_did,
        did_document_hash,
        metadata_hash,
        document_version,
        cdn_dispatch_status: "queued".to_owned(),
        discovery_notify_status: "queued".to_owned(),
    })
    .pipe(Ok)
}

async fn persist_verified_acceptance_sqlite(
    state: &AppState,
    request: &VerifyAndPublishRequest,
    did_document_hash: &str,
    metadata_hash: &str,
    metadata: &AgentMetadata,
) -> Result<(String, u64, VerifiedPackage)> {
    let sqlite = state
        .sqlite
        .as_ref()
        .ok_or_else(|| anyhow!("sqlite_not_configured"))?;
    let now = Utc::now();
    let mut conn = sqlite.pool().acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result = async {
        let previous = sqlx::query(&format!(
            "SELECT current_version, did_document_hash FROM {ROOT_SUBJECT_LATEST_TABLE} WHERE subject_did = ?"
        ))
        .bind(&request.submission.agent_did)
        .fetch_optional(&mut *conn)
        .await?;

        let operation = match previous {
            None => "create",
            Some(ref row) if row.get::<String, _>(1) == did_document_hash => "no-op",
            Some(_) => "update",
        }
        .to_owned();
        let document_version = previous
            .as_ref()
            .map(|row| row.get::<i64, _>(0) as u64)
            .unwrap_or(0)
            + u64::from(operation != "no-op");

        let package_claims = json!({
            "subjectDid": request.submission.agent_did,
            "registrarDid": request.registrar_did,
            "didDocumentHash": did_document_hash,
            "metadataHash": metadata_hash,
            "documentVersion": document_version,
            "operation": operation,
            "capabilityTags": metadata.capability_tags
        });

        let package = VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: request.submission.agent_did.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: did_document_hash.to_owned(),
            metadata_hash: Some(metadata_hash.to_owned()),
            metadata: metadata.clone(),
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: Some(package_claims.clone()),
                proof: Some(build_data_integrity_proof(
                    &package_claims,
                    format!("{}#key-1", state.root_did),
                    format!("{}#key-1", state.root_did),
                    &state.signing_key,
                )?),
                crypto_suite: Some(state.signing_key.crypto_suite()),
                hash_algorithm: Some(state.signing_key.crypto_suite().hash_algorithm().to_owned()),
            },
            created_at: now,
        };

        let package_json = serde_json::to_string(&package)?;
        let archive_path = format!(
            "archive/{}/v{document_version}",
            did_to_file_name(&request.submission.agent_did).trim_end_matches(".json")
        );
        let package_job_key = format!("{}:{document_version}", request.submission.agent_did);
        let now_rfc3339 = now.to_rfc3339();
        let next_attempt_at = now_rfc3339.clone();

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_VERSION_TABLE}(subject_did, version, did_document_hash, metadata_hash, package_json, archive_path, accepted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did, version)
            DO UPDATE SET
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                package_json = excluded.package_json,
                archive_path = excluded.archive_path,
                accepted_at = excluded.accepted_at
            "#
        ))
        .bind(&request.submission.agent_did)
        .bind(document_version as i64)
        .bind(did_document_hash)
        .bind(metadata_hash)
        .bind(&package_json)
        .bind(&archive_path)
        .bind(&now_rfc3339)
        .execute(&mut *conn)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_LATEST_TABLE}(subject_did, current_version, did_document_hash, metadata_hash, operation, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did)
            DO UPDATE SET
                current_version = excluded.current_version,
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&request.submission.agent_did)
        .bind(document_version as i64)
        .bind(did_document_hash)
        .bind(metadata_hash)
        .bind(&operation)
        .bind(&now_rfc3339)
        .execute(&mut *conn)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_PACKAGE_JOB_TABLE}(job_key, subject_did, version, package_json, status, operation, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'accepted', ?, ?, ?)
            ON CONFLICT(job_key)
            DO UPDATE SET
                package_json = excluded.package_json,
                status = 'accepted',
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&package_job_key)
        .bind(&request.submission.agent_did)
        .bind(document_version as i64)
        .bind(&package_json)
        .bind(&operation)
        .bind(&now_rfc3339)
        .bind(&now_rfc3339)
        .execute(&mut *conn)
        .await?;

        sqlx::query("COMMIT").execute(&mut *conn).await?;

        sqlite
            .enqueue_leased_job(
                ROOT_CDN_JOB_TABLE,
                &package_job_key,
                &package,
                &next_attempt_at,
            )
            .await?;

        Ok((operation, document_version, package))
    }
    .await;

    if result.is_err() {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
    }

    result
}

async fn authorize_registrar(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<RootAuthorizeRequest>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    let suite = request
        .did_document
        .verification_method
        .iter()
        .find(|method| {
            request
                .did_document
                .assertion_method
                .iter()
                .any(|id| id == &method.id)
        })
        .and_then(|method| method.crypto_suite())
        .unwrap_or(CryptoSuite::Ed25519Sha256Legacy);
    let did_document_hash =
        hash_json_with_suite(suite, &request.did_document).map_err(ApiError::internal)?;
    append_event(
        &state,
        BulletinEventType::RegistrarAuthorized,
        &request.target_did,
        json!({
            "targetRole": request.target_role,
            "didDocumentHash": did_document_hash,
        }),
    )
    .map_err(ApiError::internal)?;
    update_authorization_state(
        &state,
        &request.target_did,
        NodeAuthorizationState {
            status: "active".to_owned(),
            updated_at: Utc::now(),
            did_document_hash,
            did_document_snapshot: Some(request.did_document),
        },
        &request.target_role,
        None,
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn authorize_discovery(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<RootAuthorizeRequest>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    let suite = request
        .did_document
        .verification_method
        .iter()
        .find(|method| {
            request
                .did_document
                .assertion_method
                .iter()
                .any(|id| id == &method.id)
        })
        .and_then(|method| method.crypto_suite())
        .unwrap_or(CryptoSuite::Ed25519Sha256Legacy);
    let did_document_hash =
        hash_json_with_suite(suite, &request.did_document).map_err(ApiError::internal)?;
    append_event(
        &state,
        BulletinEventType::DiscoveryNodeAuthorized,
        &request.target_did,
        json!({
            "targetRole": request.target_role,
            "didDocumentHash": did_document_hash,
        }),
    )
    .map_err(ApiError::internal)?;
    update_discovery_authorization_state(
        &state,
        &request.target_did,
        DiscoveryAuthorizationState {
            status: "active".to_owned(),
            updated_at: Utc::now(),
            did_document_hash,
            did_document_snapshot: Some(request.did_document),
            authorized_domains: vec!["*".to_owned()],
            tag_tree_version: state.tag_tree.version,
        },
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn update_discovery_domains(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    let domains = payload["authorizedDomains"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    append_event(
        &state,
        BulletinEventType::DiscoveryNodeDomainsUpdated,
        &did,
        payload,
    )
    .map_err(ApiError::internal)?;
    let mut authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    if let Some(entry) = authorization_state.discovery_nodes.get_mut(&did) {
        entry.authorized_domains = domains;
        entry.tag_tree_version = state.tag_tree.version;
        entry.updated_at = Utc::now();
        JsonStore::new(".")
            .write(
                &state.config.paths.authorization_state_file,
                &authorization_state,
            )
            .map_err(ApiError::internal)?;
    }
    Ok(Json(json!({"status": "ok"})))
}

async fn revoke_node(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    append_event(&state, BulletinEventType::NodeRevoked, &did, payload)
        .map_err(ApiError::internal)?;
    revoke_authorization_state(&state, &did).map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn publish_cdn_batch(headers: HeaderMap, State(state): State<AppState>) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    run_cdn_publish_cycle(&state)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn latest_event_payload_async(state: &AppState, event_type: &str) -> Result<Option<Value>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT event_json FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence"
        ))
        .fetch_all(sqlite.pool())
        .await?;
        for row in rows.into_iter().rev() {
            let event: BulletinEvent = serde_json::from_str(&row.get::<String, _>(0))?;
            let current = serde_json::to_value(&event.core.event_type)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned));
            if current.as_deref() == Some(event_type) {
                return Ok(Some(event.core.payload));
            }
        }
        return Ok(None);
    }
    Ok(latest_event_payload(&read_bulletin(state)?, event_type).cloned())
}

async fn cdn_publish_url_async(state: &AppState) -> Result<String> {
    let payload = latest_event_payload_async(state, "CDN_SERVICE_INFO_UPDATED")
        .await?
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

fn build_cdn_publish_request(
    state: &AppState,
    package: &VerifiedPackage,
) -> Result<CdnPublishRequest> {
    let verification_method = format!("{}#key-1", state.root_did);
    let envelope = create_signed_request_envelope(
        request_id("cdn-publish"),
        "ans-2026".to_owned(),
        PURPOSE_CDN_PUBLISH.to_owned(),
        "POST".to_owned(),
        PATH_CDN_PACKAGES.to_owned(),
        state.root_did.clone(),
        package,
        state.root_did.clone(),
        verification_method,
        &state.signing_key,
        request_nonce("cdn-publish"),
    )?;
    Ok(CdnPublishRequest {
        package: package.clone(),
        upstream_auth: envelope,
    })
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

async fn notify_discovery_batch(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    run_discovery_notify_cycle(&state)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn api_publications(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<BTreeMap<String, String>>,
) -> ApiResult<Value> {
    let after = params
        .get("after")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            r#"
            SELECT rowid, subject_did, version, did_document_hash, metadata_hash, accepted_at
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE rowid > ?
            ORDER BY rowid
            LIMIT ?
            "#
        ))
        .bind(after)
        .bind(limit)
        .fetch_all(sqlite.pool())
        .await
        .map_err(ApiError::internal)?;
        let items = rows
            .into_iter()
            .map(|row| {
                json!({
                    "cursor": row.get::<i64, _>(0),
                    "agentDid": row.get::<String, _>(1),
                    "documentVersion": row.get::<i64, _>(2),
                    "didDocumentHash": row.get::<String, _>(3),
                    "metadataHash": row.get::<String, _>(4),
                    "acceptedAt": row.get::<String, _>(5),
                })
            })
            .collect::<Vec<_>>();
        let next_cursor = items
            .last()
            .and_then(|item| item["cursor"].as_i64())
            .unwrap_or(after);
        return Ok(Json(json!({
            "items": items,
            "nextCursor": next_cursor
        })));
    }

    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let items = latest_versions
        .into_iter()
        .enumerate()
        .filter_map(|(index, (did, value))| {
            let cursor = index as i64 + 1;
            (cursor > after).then(|| {
                json!({
                    "cursor": cursor,
                    "agentDid": did,
                    "documentVersion": value["documentVersion"],
                    "didDocumentHash": value["didDocumentHash"],
                    "metadataHash": value["metadataHash"],
                    "acceptedAt": value["updatedAt"],
                })
            })
        })
        .take(limit as usize)
        .collect::<Vec<_>>();
    let next_cursor = items
        .last()
        .and_then(|item| item["cursor"].as_i64())
        .unwrap_or(after);
    Ok(Json(json!({
        "items": items,
        "nextCursor": next_cursor
    })))
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    let cdn_queue = read_cdn_queue(&state).await.map_err(ApiError::internal)?;
    let discovery_queue = read_discovery_queue(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "rootDid": state.root_did,
        "bulletinEventCount": bulletin.events.len(),
        "latestVersionCount": latest_versions.len(),
        "cdnQueueCount": cdn_queue.len(),
        "discoveryQueueCount": discovery_queue.len(),
        "capabilityTreeVersion": state.tag_tree.version,
        "registrarAuthorizationCount": authorization_state.registrars.len(),
        "discoveryAuthorizationCount": authorization_state.discovery_nodes.len(),
        "vcIssuerAuthorizationCount": authorization_state.vc_issuers.len()
    })))
}

async fn api_registrars(State(state): State<AppState>) -> ApiResult<Value> {
    let authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    let items: Vec<Value> = authorization_state
        .registrars
        .into_iter()
        .map(|(did, entry)| json!({ "did": did, "status": entry.status, "didDocumentHash": entry.did_document_hash, "updatedAt": entry.updated_at }))
        .collect();
    let items = if items.is_empty() {
        let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
        bulletin
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.core.event_type,
                    BulletinEventType::RegistrarAuthorized | BulletinEventType::RegistrarRevoked
                )
            })
            .map(|event| {
                json!({
                    "did": event.core.subject_did,
                    "eventType": event.core.event_type,
                    "sequence": event.core.sequence,
                    "payload": event.core.payload
                })
            })
            .collect::<Vec<_>>()
    } else {
        items
    };
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
        .map(|event| {
            json!({
                "sequence": event.core.sequence,
                "eventType": event.core.event_type,
                "payload": event.core.payload
            })
        })
        .collect();
    Ok(Json(json!({ "did": did, "events": events })))
}

async fn api_discovery_nodes(State(state): State<AppState>) -> ApiResult<Value> {
    let authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    let items: Vec<Value> = authorization_state
        .discovery_nodes
        .into_iter()
        .map(|(did, entry)| {
            json!({
                "did": did,
                "status": entry.status,
                "didDocumentHash": entry.did_document_hash,
                "authorizedDomains": entry.authorized_domains,
                "tagTreeVersion": entry.tag_tree_version,
                "updatedAt": entry.updated_at
            })
        })
        .collect();
    let items = if items.is_empty() {
        let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
        bulletin
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
            .map(|event| {
                json!({
                    "did": event.core.subject_did,
                    "eventType": event.core.event_type,
                    "sequence": event.core.sequence,
                    "payload": event.core.payload
                })
            })
            .collect::<Vec<_>>()
    } else {
        items
    };
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
                && matches!(
                    event.core.event_type,
                    BulletinEventType::DiscoveryNodeDomainsUpdated
                )
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
        .map(|(did, value)| {
            json!({
                "did": did,
                "documentVersion": value["documentVersion"],
                "didDocumentHash": value["didDocumentHash"],
                "metadataHash": value["metadataHash"],
                "updatedAt": value["updatedAt"]
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn api_agent_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let latest = latest_versions.get(&did).cloned();
    let archive_root = format!(
        "archive/{}",
        did_to_file_name(&did).trim_end_matches(".json")
    );
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
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            r#"
            SELECT version, did_document_hash, metadata_hash, accepted_at
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = ?
            ORDER BY version
            "#
        ))
        .bind(&did)
        .fetch_all(sqlite.pool())
        .await
        .map_err(ApiError::internal)?;
        let items = rows
            .into_iter()
            .map(|row| {
                json!({
                    "documentVersion": row.get::<i64, _>(0),
                    "didDocumentHash": row.get::<String, _>(1),
                    "metadataHash": row.get::<String, _>(2),
                    "acceptedAt": row.get::<String, _>(3),
                })
            })
            .collect::<Vec<_>>();
        return Ok(Json(json!({ "did": did, "items": items })));
    }
    let prefix = format!(
        "archive/{}",
        did_to_file_name(&did).trim_end_matches(".json")
    );
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
    if let Some(sqlite) = &state.sqlite {
        let parsed_version = version
            .parse::<i64>()
            .map_err(|_| ApiError::bad_request("invalid_version"))?;
        let row = sqlx::query(&format!(
            r#"
            SELECT package_json, accepted_at
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = ? AND version = ?
            "#
        ))
        .bind(&did)
        .bind(parsed_version)
        .fetch_optional(sqlite.pool())
        .await
        .map_err(ApiError::internal)?;
        let Some(row) = row else {
            return Ok(Json(json!({
                "did": did,
                "version": version,
                "didDocument": Value::Null,
                "metadata": Value::Null,
                "package": Value::Null
            })));
        };
        let package: VerifiedPackage =
            serde_json::from_str(&row.get::<String, _>(0)).map_err(ApiError::internal)?;
        return Ok(Json(json!({
            "did": did,
            "version": version,
            "acceptedAt": row.get::<String, _>(1),
            "didDocument": package.did_document,
            "metadata": package.metadata,
            "package": package
        })));
    }
    let prefix = format!(
        "archive/{}/v{}",
        did_to_file_name(&did).trim_end_matches(".json"),
        version
    );
    let did_document: Option<DidDocument> =
        state.data.read(format!("{prefix}/did-document.json")).ok();
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
    let queue = read_cdn_queue(&state).await.map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": queue, "count": queue.len() })))
}

async fn api_discovery_notify_queue(State(state): State<AppState>) -> ApiResult<Value> {
    let queue = read_discovery_queue(&state)
        .await
        .map_err(ApiError::internal)?;
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
    let custom_tags = tags
        .iter()
        .filter(|tag| state.tag_tree.normalize_tag(tag).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let canonical_tags = tags
        .iter()
        .filter_map(|tag| state.tag_tree.normalize_tag(tag).map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "valid": true,
        "canonicalTags": canonical_tags,
        "customTags": custom_tags,
        "note": "Capability tree tags are recommended for network-wide coarse discovery. Custom tags are allowed and can be used for later fine-grained filtering."
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

fn load_authorized_registrar_entry(
    state: &AppState,
    did: &str,
) -> std::result::Result<NodeAuthorizationState, String> {
    let authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    let entry = authorization_state
        .registrars
        .get(did)
        .cloned()
        .ok_or_else(|| "registrar_not_authorized".to_owned())?;
    if entry.status != "active" {
        return Err("registrar_not_authorized".to_owned());
    }
    Ok(entry)
}

fn load_authorized_registrar_document(state: &AppState, did: &str) -> Result<DidDocument> {
    let entry = load_authorized_registrar_entry(state, did).map_err(|err| anyhow!(err))?;
    entry
        .did_document_snapshot
        .ok_or_else(|| anyhow!("authorized_registrar_document_missing"))
}

fn verify_request(
    state: &AppState,
    request: &VerifyAndPublishRequest,
) -> std::result::Result<(), String> {
    verify_request_with_ablation(state, request, false, false)
}

fn verify_request_with_ablation(
    state: &AppState,
    request: &VerifyAndPublishRequest,
    skip_registration_credential_verification: bool,
    skip_preconnection_freshness: bool,
) -> std::result::Result<(), String> {
    let registrar_document = load_authorized_registrar_document(state, &request.registrar_did)
        .map_err(|_| "registrar_not_authorized".to_owned())?;
    let policy = trusted_upstream_policy(state, PATH_ROOT_VERIFY_AND_PUBLISH);
    if skip_preconnection_freshness {
        verify_signed_request_envelope_without_freshness(
            &request.upstream_auth,
            &request.submission,
            &request.registrar_did,
            &registrar_document,
            &policy,
        )
        .map_err(|err| err.to_string())?;
    } else {
        verify_signed_request_envelope(
            &request.upstream_auth,
            &request.submission,
            &request.registrar_did,
            &registrar_document,
            &policy,
            Utc::now(),
        )
        .map_err(|err| err.to_string())?;
    }
    verify_submission_content(&request.submission)?;
    let verified_method = verify_subject_control_proof(
        &request.submission.subject_control_proof,
        &request.submission.did_document,
        &DidControlVerificationContext {
            expected_subject_did: &request.submission.agent_did,
            expected_did_document_hash: &request.submission.did_document_hash,
            expected_registrar_did: &request.registrar_did,
            expected_purpose: PURPOSE_AGENT_REGISTRATION,
            now: Utc::now(),
        },
    )
    .map_err(|err| err.to_string())?;
    let credential: AgentRegistrationCredential =
        serde_json::from_value(request.submission.registration_credential.clone())
            .map_err(|_| "invalid_registration_credential".to_owned())?;
    if credential.issuer != request.registrar_did
        || credential.subject != request.submission.agent_did
        || credential.status != "active"
    {
        return Err("invalid_registration_credential".to_owned());
    }
    if !skip_registration_credential_verification {
        verify_agent_registration_credential(&credential, &verify_issuer_key(&registrar_document)?)
            .map_err(|_| "invalid_registration_credential_signature".to_owned())?;
        verify_registration_binding_claims(
            &credential.claims,
            &request.submission.agent_did,
            &request.submission.did_document_hash,
            &request.registrar_did,
            PURPOSE_AGENT_REGISTRATION,
            &request.submission.subject_control_proof,
        )
        .map_err(|err| err.to_string())?;
    }
    if request
        .submission
        .subject_control_proof
        .verified_verification_method
        .as_deref()
        != Some(verified_method.as_str())
    {
        return Err("registration_binding_invalid".to_owned());
    }
    Ok(())
}

fn verify_submission_content(
    submission: &AgentRegistrationSubmission,
) -> std::result::Result<(), String> {
    DidAns::parse(&submission.agent_did).map_err(|_| "invalid_did".to_owned())?;
    if submission.did_document.id != submission.agent_did {
        return Err("did_document_id_mismatch".to_owned());
    }
    submission
        .did_document
        .validate_mvp()
        .map_err(|_| "invalid_did_document_structure".to_owned())?;
    let metadata = submission
        .did_document
        .ans_metadata
        .as_ref()
        .ok_or_else(|| "invalid_subject_type".to_owned())?;
    if metadata.subject_type != SubjectType::Agent {
        return Err("invalid_subject_type".to_owned());
    }
    if submission.did_document.service.is_empty() {
        return Err("invalid_service_endpoint".to_owned());
    }
    let suite = submission
        .subject_control_proof
        .proof
        .crypto_suite()
        .unwrap_or(CryptoSuite::Ed25519Sha256Legacy);
    let actual_did_document_hash = hash_json_with_suite(suite, &submission.did_document)
        .map_err(|_| "subject_control_did_document_hash_mismatch".to_owned())?;
    if actual_did_document_hash != submission.did_document_hash {
        return Err("subject_control_did_document_hash_mismatch".to_owned());
    }
    Ok(())
}

fn verify_issuer_key(did_document: &DidDocument) -> Result<VerifyingKey, String> {
    let method = did_document
        .verification_method
        .iter()
        .find(|method| {
            did_document
                .assertion_method
                .iter()
                .any(|id| id == &method.id)
        })
        .ok_or_else(|| "missing_issuer_verification_method".to_owned())?;
    verifying_key_from_method(method).map_err(|_| "invalid_issuer_key".to_owned())
}

fn build_metadata(
    state: &AppState,
    submission: &AgentRegistrationSubmission,
    did_document_hash: &str,
) -> Result<AgentMetadata> {
    let ans = submission
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
        did: submission.agent_did.clone(),
        role: "Service Agent".to_owned(),
        identity_type: ans.identity_type.clone(),
        did_document_hash: did_document_hash.to_owned(),
        capability_tags: tags,
        services: submission.did_document.service.clone(),
        status: "active".to_owned(),
        updated_at: Utc::now(),
    })
}

fn read_bulletin(state: &AppState) -> Result<Bulletin> {
    if state.sqlite.is_some() {
        return read_bulletin_from_store(state);
    }
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

fn read_bulletin_from_store(state: &AppState) -> Result<Bulletin> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT event_json FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence"
            ))
            .fetch_all(sqlite.pool())
            .await?;
            let mut events = Vec::with_capacity(rows.len());
            for row in rows {
                events.push(serde_json::from_str::<BulletinEvent>(
                    &row.get::<String, _>(0),
                )?);
            }
            Ok(Bulletin {
                version: "0.1.0".to_owned(),
                root_did: state.root_did.clone(),
                created_at: Utc::now(),
                events,
            })
        });
    }
    Ok(Bulletin {
        version: "0.1.0".to_owned(),
        root_did: state.root_did.clone(),
        created_at: Utc::now(),
        events: vec![],
    })
}

fn latest_bulletin_event(state: &AppState) -> Result<Option<BulletinEvent>> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let row = sqlx::query(&format!(
                "SELECT event_json FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence DESC LIMIT 1"
            ))
            .fetch_optional(sqlite.pool())
            .await?;
            row.map(|row| {
                serde_json::from_str::<BulletinEvent>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .transpose()
        });
    }
    Ok(read_bulletin(state)?.events.into_iter().last())
}

fn persist_bulletin_event(state: &AppState, event: &BulletinEvent) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        let event_json = serde_json::to_string(event)?;
        let payload_json = serde_json::to_string(&event.core.payload)?;
        return block_on_sqlite(async {
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_BULLETIN_EVENT_TABLE}(sequence, event_type, subject_did, actor_did, payload_json, previous_hash, event_hash, event_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sequence)
                DO UPDATE SET
                    event_type = excluded.event_type,
                    subject_did = excluded.subject_did,
                    actor_did = excluded.actor_did,
                    payload_json = excluded.payload_json,
                    previous_hash = excluded.previous_hash,
                    event_hash = excluded.event_hash,
                    event_json = excluded.event_json,
                    created_at = excluded.created_at
                "#
            ))
            .bind(event.core.sequence as i64)
            .bind(serde_json::to_value(&event.core.event_type)?.as_str().unwrap_or_default())
            .bind(&event.core.subject_did)
            .bind(&event.core.actor_did)
            .bind(payload_json)
            .bind(event.core.previous_hash.clone())
            .bind(&event.event_hash)
            .bind(event_json)
            .bind(event.core.created_at.to_rfc3339())
            .execute(sqlite.pool())
            .await?;
            Ok(())
        });
    }
    Ok(())
}

fn load_authorization_state(path: &Path) -> Result<AuthorizationState> {
    let store = JsonStore::new(".");
    if path.exists() {
        store.read(path).map_err(Into::into)
    } else {
        Ok(AuthorizationState::default())
    }
}

fn update_authorization_state(
    state: &AppState,
    did: &str,
    entry: NodeAuthorizationState,
    role: &str,
    discovery: Option<DiscoveryAuthorizationState>,
) -> Result<()> {
    let mut authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    match role {
        "registrar" | "Registrar" | "Registrar Node" => {
            authorization_state.registrars.insert(did.to_owned(), entry);
        }
        "discovery" | "Discovery" | "Discovery Node" => {
            if let Some(entry) = discovery {
                authorization_state
                    .discovery_nodes
                    .insert(did.to_owned(), entry);
            }
        }
        "vc-issuer" | "VC Issuer" => {
            authorization_state.vc_issuers.insert(did.to_owned(), entry);
        }
        _ => {
            authorization_state.registrars.insert(did.to_owned(), entry);
        }
    }
    JsonStore::new(".").write(
        &state.config.paths.authorization_state_file,
        &authorization_state,
    )?;
    Ok(())
}

fn update_discovery_authorization_state(
    state: &AppState,
    did: &str,
    entry: DiscoveryAuthorizationState,
) -> Result<()> {
    let entry_status = entry.status.clone();
    let mut authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    authorization_state
        .discovery_nodes
        .insert(did.to_owned(), entry);
    JsonStore::new(".").write(
        &state.config.paths.authorization_state_file,
        &authorization_state,
    )?;
    if state.sqlite.is_some() {
        sync_discovery_target_state(state, did, &entry_status)?;
    }
    Ok(())
}

fn revoke_authorization_state(state: &AppState, did: &str) -> Result<()> {
    let mut authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    if let Some(entry) = authorization_state.registrars.get_mut(did) {
        entry.status = "revoked".to_owned();
        entry.updated_at = Utc::now();
    }
    if let Some(entry) = authorization_state.discovery_nodes.get_mut(did) {
        entry.status = "revoked".to_owned();
        entry.updated_at = Utc::now();
    }
    if let Some(entry) = authorization_state.vc_issuers.get_mut(did) {
        entry.status = "revoked".to_owned();
        entry.updated_at = Utc::now();
    }
    JsonStore::new(".").write(
        &state.config.paths.authorization_state_file,
        &authorization_state,
    )?;
    if state.sqlite.is_some() {
        sync_discovery_target_state(state, did, "revoked")?;
    }
    Ok(())
}

fn sync_discovery_target_state(state: &AppState, did: &str, auth_status: &str) -> Result<()> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(());
    };
    let did = did.to_owned();
    let auth_status = auth_status.to_owned();
    let now = Utc::now().to_rfc3339();
    block_on_sqlite(async {
        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                discovery_did,
                pending_cursor,
                delivered_cursor,
                status,
                attempt_count,
                lease_owner,
                lease_expires_at,
                next_attempt_at,
                last_error,
                updated_at
            )
            VALUES (?, 0, 0, ?, 0, NULL, NULL, ?, NULL, ?)
            ON CONFLICT(discovery_did)
            DO UPDATE SET
                status = excluded.status,
                next_attempt_at = CASE
                    WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                    ELSE ?
                END,
                lease_owner = CASE
                    WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.lease_owner
                    ELSE NULL
                END,
                lease_expires_at = CASE
                    WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.lease_expires_at
                    ELSE NULL
                END,
                last_error = CASE
                    WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.last_error
                    ELSE NULL
                END,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&did)
        .bind(&auth_status)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(sqlite.pool())
        .await?;
        Ok(())
    })
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
    let latest = latest_bulletin_event(state)?;
    let previous_hash = latest.as_ref().map(|event| event.event_hash.clone());
    let next_sequence = latest
        .as_ref()
        .map(|event| event.core.sequence + 1)
        .unwrap_or(1);
    let event = BulletinEventCore {
        sequence: next_sequence,
        previous_hash,
        event_type,
        subject_did: subject_did.to_owned(),
        actor_did: state.root_did.clone(),
        payload,
        created_at: Utc::now(),
    }
    .sign(&state.signing_key)?;
    if state.sqlite.is_some() {
        persist_bulletin_event(state, &event)?;
    } else {
        let mut bulletin = read_bulletin(state)?;
        bulletin.events.push(event.clone());
        write_bulletin(state, &bulletin)?;
    }
    Ok(event)
}

fn archive_verified(
    state: &AppState,
    submission: &AgentRegistrationSubmission,
    metadata: &AgentMetadata,
    package: &VerifiedPackage,
    version: u64,
) -> Result<()> {
    let name = did_to_file_name(&submission.agent_did);
    let prefix = format!("archive/{}/v{version}", name.trim_end_matches(".json"));
    state.data.write(
        format!("{prefix}/did-document.json"),
        &submission.did_document,
    )?;
    state
        .data
        .write(format!("{prefix}/metadata.json"), metadata)?;
    state
        .data
        .write(format!("{prefix}/package.json"), package)?;
    state.data.write(
        format!("{prefix}/subject-control-proof.json"),
        &submission.subject_control_proof,
    )?;
    state
        .data
        .write(format!("verified-packages/{name}"), package)?;
    Ok(())
}

async fn persist_verified_acceptance(
    state: &AppState,
    agent_did: &str,
    document_version: u64,
    did_hash: &str,
    metadata_hash: &str,
    operation: &str,
    package: &VerifiedPackage,
) -> Result<()> {
    let accepted_at = Utc::now();
    if let Some(sqlite) = &state.sqlite {
        let package_json = serde_json::to_string(package)?;
        let archive_path = format!(
            "archive/{}/v{document_version}",
            did_to_file_name(agent_did).trim_end_matches(".json")
        );
        let package_job_key = format!("{agent_did}:{document_version}");
        let now = accepted_at.to_rfc3339();
        let next_attempt_at = now.clone();
        let mut tx = sqlite.pool().begin().await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_VERSION_TABLE}(subject_did, version, did_document_hash, metadata_hash, package_json, archive_path, accepted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did, version)
            DO UPDATE SET
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                package_json = excluded.package_json,
                archive_path = excluded.archive_path,
                accepted_at = excluded.accepted_at
            "#
        ))
        .bind(agent_did)
        .bind(document_version as i64)
        .bind(did_hash)
        .bind(metadata_hash)
        .bind(&package_json)
        .bind(&archive_path)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_LATEST_TABLE}(subject_did, current_version, did_document_hash, metadata_hash, operation, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did)
            DO UPDATE SET
                current_version = excluded.current_version,
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(agent_did)
        .bind(document_version as i64)
        .bind(did_hash)
        .bind(metadata_hash)
        .bind(operation)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_PACKAGE_JOB_TABLE}(job_key, subject_did, version, package_json, status, operation, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'accepted', ?, ?, ?)
            ON CONFLICT(job_key)
            DO UPDATE SET
                package_json = excluded.package_json,
                status = 'accepted',
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&package_job_key)
        .bind(agent_did)
        .bind(document_version as i64)
        .bind(&package_json)
        .bind(operation)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        sqlite
            .enqueue_leased_job(
                ROOT_CDN_JOB_TABLE,
                &package_job_key,
                package,
                &next_attempt_at,
            )
            .await?;
        return Ok(());
    }

    update_latest_version(state, agent_did, document_version, did_hash, metadata_hash)?;
    enqueue_cdn_legacy(state, package).await?;
    Ok(())
}

fn read_latest_versions(state: &AppState) -> Result<BTreeMap<String, Value>> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT subject_did, current_version, did_document_hash, metadata_hash, updated_at FROM {ROOT_SUBJECT_LATEST_TABLE} ORDER BY subject_did"
            ))
            .fetch_all(sqlite.pool())
            .await?;
            let mut latest = BTreeMap::new();
            for row in rows {
                latest.insert(
                    row.get::<String, _>(0),
                    json!({
                        "documentVersion": row.get::<i64, _>(1),
                        "didDocumentHash": row.get::<String, _>(2),
                        "metadataHash": row.get::<String, _>(3),
                        "updatedAt": row.get::<String, _>(4),
                    }),
                );
            }
            Ok(latest)
        });
    }
    Ok(state
        .data
        .read("indexes/latest-did-document-versions.json")
        .unwrap_or_default())
}

async fn load_latest_version(state: &AppState, agent_did: &str) -> Result<Option<Value>> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT current_version, did_document_hash, metadata_hash, updated_at FROM {ROOT_SUBJECT_LATEST_TABLE} WHERE subject_did = ?"
        ))
        .bind(agent_did)
        .fetch_optional(sqlite.pool())
        .await?;
        if let Some(row) = row {
            return Ok(Some(json!({
                "documentVersion": row.get::<i64, _>(0),
                "didDocumentHash": row.get::<String, _>(1),
                "metadataHash": row.get::<String, _>(2),
                "updatedAt": row.get::<String, _>(3),
            })));
        }
    }
    Ok(read_latest_versions(state)?.get(agent_did).cloned())
}

fn update_latest_version(
    state: &AppState,
    agent_did: &str,
    version: u64,
    did_hash: &str,
    metadata_hash: &str,
) -> Result<()> {
    let mut latest = read_latest_versions(state)?;
    latest.insert(
        agent_did.to_owned(),
        json!({
            "documentVersion": version,
            "didDocumentHash": did_hash,
            "metadataHash": metadata_hash,
            "updatedAt": Utc::now()
        }),
    );
    state
        .data
        .write("indexes/latest-did-document-versions.json", &latest)?;
    Ok(())
}

async fn enqueue_cdn_legacy(state: &AppState, package: &VerifiedPackage) -> Result<()> {
    let mut queue: Vec<VerifiedPackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    queue.retain(|item| item.did != package.did);
    queue.push(package.clone());
    state.data.write("queues/cdn-publish.json", &queue)?;
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json("root.cdn_publish_queue", &package.did, package)
            .await?;
    }
    Ok(())
}

async fn read_cdn_queue(state: &AppState) -> Result<Vec<VerifiedPackage>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_active_leased_jobs(ROOT_CDN_JOB_TABLE)
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default())
}

async fn read_discovery_queue(state: &AppState) -> Result<Vec<Value>> {
    if state.sqlite.is_some() {
        let targets = read_discovery_target_states(state).await?;
        return Ok(targets
            .into_iter()
            .filter(|item| item.pending_cursor > item.delivered_cursor)
            .map(|item| {
                json!({
                    "discoveryDid": item.discovery_did,
                    "pendingCursor": item.pending_cursor,
                    "deliveredCursor": item.delivered_cursor,
                    "status": item.status,
                    "attemptCount": item.attempt_count,
                    "nextAttemptAt": item.next_attempt_at,
                    "lastError": item.last_error,
                    "updatedAt": item.updated_at
                })
            })
            .collect());
    }
    Ok(state
        .data
        .read("queues/discovery-notify.json")
        .unwrap_or_default())
}

async fn mark_cdn_queue_published(state: &AppState, did: &str) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT current_version FROM {ROOT_SUBJECT_LATEST_TABLE} WHERE subject_did = ?"
        ))
        .bind(did)
        .fetch_optional(sqlite.pool())
        .await?;
        if let Some(row) = row {
            let version = row.get::<i64, _>(0);
            sqlite
                .mark_leased_job_succeeded(ROOT_CDN_JOB_TABLE, &format!("{did}:{version}"))
                .await?;
            return Ok(());
        }
    }
    let mut queue: Vec<VerifiedPackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    queue.retain(|item| item.did != did);
    state.data.write("queues/cdn-publish.json", &queue)?;
    Ok(())
}

async fn export_root_debug_snapshot(state: &AppState) -> Result<()> {
    if state.sqlite.is_none() {
        return Ok(());
    }
    let bulletin = read_bulletin_from_store(state)?;
    write_bulletin(state, &bulletin)?;
    let latest = read_latest_versions(state)?;
    state
        .data
        .write("indexes/latest-did-document-versions.json", &latest)?;
    let cdn_queue = read_cdn_queue(state).await?;
    state.data.write("queues/cdn-publish.json", &cdn_queue)?;
    let discovery_queue = read_discovery_queue(state).await?;
    state
        .data
        .write("queues/discovery-notify.json", &discovery_queue)?;
    Ok(())
}

async fn read_discovery_target_states(state: &AppState) -> Result<Vec<DiscoveryNotifyTargetState>> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(&format!(
        r#"
        SELECT discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
               lease_owner, lease_expires_at, next_attempt_at, last_error, updated_at
        FROM {ROOT_DISCOVERY_TARGET_TABLE}
        ORDER BY discovery_did
        "#
    ))
    .fetch_all(sqlite.pool())
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| DiscoveryNotifyTargetState {
            discovery_did: row.get::<String, _>(0),
            pending_cursor: row.get::<i64, _>(1),
            delivered_cursor: row.get::<i64, _>(2),
            status: row.get::<String, _>(3),
            attempt_count: row.get::<i64, _>(4),
            lease_owner: row.get::<Option<String>, _>(5),
            lease_expires_at: row.get::<Option<String>, _>(6),
            next_attempt_at: row.get::<String, _>(7),
            last_error: row.get::<Option<String>, _>(8),
            updated_at: row.get::<String, _>(9),
        })
        .collect())
}

async fn claim_discovery_targets(
    state: &AppState,
    worker_id: &str,
    limit: usize,
    lease_seconds: i64,
) -> Result<Vec<DiscoveryNotifyTargetLease>> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(Vec::new());
    };
    let mut conn = sqlite.pool().acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let lease_expires_at = (now + chrono::Duration::seconds(lease_seconds)).to_rfc3339();
    let result = async {
        let rows = sqlx::query(&format!(
            r#"
            SELECT discovery_did, pending_cursor, delivered_cursor
            FROM {ROOT_DISCOVERY_TARGET_TABLE}
            WHERE status = 'active'
              AND pending_cursor > delivered_cursor
              AND next_attempt_at <= ?
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
            ORDER BY pending_cursor DESC, discovery_did
            LIMIT ?
            "#
        ))
        .bind(&now_rfc3339)
        .bind(&now_rfc3339)
        .bind(limit as i64)
        .fetch_all(&mut *conn)
        .await?;
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let discovery_did = row.get::<String, _>(0);
            let pending_cursor = row.get::<i64, _>(1);
            let delivered_cursor = row.get::<i64, _>(2);
            sqlx::query(&format!(
                r#"
                UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
                SET lease_owner = ?, lease_expires_at = ?, attempt_count = attempt_count + 1,
                    last_error = NULL, updated_at = ?
                WHERE discovery_did = ?
                "#
            ))
            .bind(worker_id)
            .bind(&lease_expires_at)
            .bind(&now_rfc3339)
            .bind(&discovery_did)
            .execute(&mut *conn)
            .await?;
            claimed.push(DiscoveryNotifyTargetLease {
                discovery_did,
                target_cursor: pending_cursor,
                delivered_cursor,
            });
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(claimed)
    }
    .await;
    if result.is_err() {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
    }
    result
}

async fn mark_discovery_target_notified(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
) -> Result<()> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(());
    };
    let now = Utc::now().to_rfc3339();
    sqlx::query(&format!(
        r#"
        UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
        SET delivered_cursor = MAX(delivered_cursor, ?),
            status = 'active',
            lease_owner = NULL,
            lease_expires_at = NULL,
            next_attempt_at = ?,
            last_error = NULL,
            updated_at = ?
        WHERE discovery_did = ?
        "#
    ))
    .bind(delivered_cursor)
    .bind(&now)
    .bind(&now)
    .bind(discovery_did)
    .execute(sqlite.pool())
    .await?;
    Ok(())
}

async fn mark_discovery_target_retry(
    state: &AppState,
    discovery_did: &str,
    error: &str,
) -> Result<()> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(());
    };
    let retry_after =
        (Utc::now() + chrono::Duration::seconds(state.config.security.workers.retry_backoff_seconds))
            .to_rfc3339();
    let now = Utc::now().to_rfc3339();
    sqlx::query(&format!(
        r#"
        UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
        SET lease_owner = NULL,
            lease_expires_at = NULL,
            next_attempt_at = ?,
            last_error = ?,
            updated_at = ?
        WHERE discovery_did = ?
        "#
    ))
    .bind(&retry_after)
    .bind(error)
    .bind(&now)
    .bind(discovery_did)
    .execute(sqlite.pool())
    .await?;
    Ok(())
}

async fn advance_discovery_target_watermarks(
    state: &AppState,
    package: &VerifiedPackage,
    publication_cursor: i64,
) -> Result<usize> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(0);
    };
    let authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    let now = Utc::now().to_rfc3339();
    let mut advanced = 0usize;
    for (discovery_did, auth) in authorization_state.discovery_nodes {
        if auth.status != "active" {
            continue;
        }
        if !state
            .tag_tree
            .matches_authorized_domains(&package.metadata.capability_tags, &auth.authorized_domains)
        {
            continue;
        }
        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
                lease_owner, lease_expires_at, next_attempt_at, last_error, updated_at
            )
            VALUES (?, ?, 0, 'active', 0, NULL, NULL, ?, NULL, ?)
            ON CONFLICT(discovery_did)
            DO UPDATE SET
                pending_cursor = MAX({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor),
                status = 'active',
                next_attempt_at = CASE
                    WHEN {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor < excluded.pending_cursor
                    THEN excluded.next_attempt_at
                    ELSE {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                END,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&discovery_did)
        .bind(publication_cursor)
        .bind(&now)
        .bind(&now)
        .execute(sqlite.pool())
        .await?;
        advanced += 1;
    }
    Ok(advanced)
}

async fn claim_cdn_jobs(
    state: &AppState,
    worker_id: &str,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<(String, VerifiedPackage)>> {
    if let Some(sqlite) = &state.sqlite {
        let leased = sqlite
            .lease_ready_jobs::<VerifiedPackage>(
                ROOT_CDN_JOB_TABLE,
                worker_id,
                limit,
                &Utc::now().to_rfc3339(),
                &(Utc::now() + chrono::Duration::seconds(lease_seconds)).to_rfc3339(),
            )
            .await?;
        return Ok(leased
            .into_iter()
            .map(|job| (job.job_key, job.payload))
            .collect());
    }
    Ok(read_cdn_queue(state)
        .await?
        .into_iter()
        .take(limit as usize)
        .map(|package| {
            let version = package
                .root_proof
                .package_claims
                .as_ref()
                .and_then(|claims| claims["documentVersion"].as_u64())
                .unwrap_or(0);
            (format!("{}:{version}", package.did), package)
        })
        .collect())
}

async fn mark_cdn_job_published(state: &AppState, job_key: &str, did: &str) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .mark_leased_job_succeeded(ROOT_CDN_JOB_TABLE, job_key)
            .await?;
        return Ok(());
    }
    mark_cdn_queue_published(state, did).await
}

async fn mark_cdn_job_retry(state: &AppState, job_key: &str, error: &str) -> Result<()> {
    let retry_after =
        Utc::now() + chrono::Duration::seconds(state.config.security.workers.retry_backoff_seconds);
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .mark_leased_job_retry(
                ROOT_CDN_JOB_TABLE,
                job_key,
                &retry_after.to_rfc3339(),
                Some(error),
            )
            .await?;
    }
    Ok(())
}

async fn publication_cursor_for_job(state: &AppState, job_key: &str) -> Result<Option<i64>> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(None);
    };
    let Some((subject_did, version_str)) = job_key.rsplit_once(':') else {
        return Ok(None);
    };
    let Ok(version) = version_str.parse::<i64>() else {
        return Ok(None);
    };
    let row = sqlx::query(&format!(
        r#"
        SELECT rowid
        FROM {ROOT_SUBJECT_VERSION_TABLE}
        WHERE subject_did = ? AND version = ?
        "#
    ))
    .bind(subject_did)
    .bind(version)
    .fetch_optional(sqlite.pool())
    .await?;
    Ok(row.map(|row| row.get::<i64, _>(0)))
}

async fn run_cdn_publish_cycle(state: &AppState) -> Result<Value> {
    let batch_size = state.config.security.workers.cdn_batch_size as i64;
    let queue = claim_cdn_jobs(
        state,
        "root-cdn-worker",
        batch_size,
        state.config.security.workers.lease_seconds,
    )
    .await?;
    let publish_url = cdn_publish_url_async(state).await?;
    let concurrency = state.config.security.workers.cdn_batch_size.max(1);
    let mut in_flight = JoinSet::new();
    let mut queue_iter = queue.into_iter();
    let mut published = Vec::new();
    let mut failed = Vec::new();

    loop {
        while in_flight.len() < concurrency {
            let Some((job_key, package)) = queue_iter.next() else {
                break;
            };
            let state = state.clone();
            let publish_url = publish_url.clone();
            in_flight.spawn(async move {
                let request = build_cdn_publish_request(&state, &package)?;
                let response = state.client.post(&publish_url).json(&request).send().await;
                match response {
                    Ok(response) if response.status().is_success() => {
                        if let Some(publication_cursor) =
                            publication_cursor_for_job(&state, &job_key).await?
                        {
                            advance_discovery_target_watermarks(
                                &state,
                                &package,
                                publication_cursor,
                            )
                            .await?;
                        }
                        mark_cdn_job_published(&state, &job_key, &package.did).await?;
                        Ok::<Value, anyhow::Error>(json!({
                            "did": package.did,
                            "status": "published"
                        }))
                    }
                    Ok(response) => {
                        let status = response.status().as_u16();
                        mark_cdn_job_retry(&state, &job_key, &format!("status:{status}")).await?;
                        Ok(json!({
                            "did": package.did,
                            "status": status
                        }))
                    }
                    Err(err) => {
                        let error = err.to_string();
                        mark_cdn_job_retry(&state, &job_key, &error).await?;
                        Ok(json!({
                            "did": package.did,
                            "error": error
                        }))
                    }
                }
            });
        }

        let Some(joined) = in_flight.join_next().await else {
            break;
        };
        match joined {
            Ok(Ok(result)) if result["status"] == "published" => {
                if let Some(did) = result["did"].as_str() {
                    published.push(did.to_owned());
                }
            }
            Ok(Ok(result)) => failed.push(result),
            Ok(Err(err)) => failed.push(json!({ "error": err.to_string() })),
            Err(err) => failed.push(json!({ "error": err.to_string() })),
        }
    }
    let result = json!({
        "status": if failed.is_empty() { "ok" } else { "partial" },
        "attemptedCount": published.len() + failed.len(),
        "publishedCount": published.len(),
        "publishedDids": published,
        "failed": failed
    });
    write_batch_history(
        state,
        "cdn-publish-history",
        json!({
            "batchType": "cdn-publish",
            "processedAt": Utc::now(),
            "trigger": "worker-cycle",
            "attemptedCount": result["attemptedCount"],
            "publishedCount": result["publishedCount"],
            "publishedDids": result["publishedDids"],
            "failed": result["failed"]
        }),
    )
    .await?;
    Ok(result)
}

fn discovery_sync_url(auth: &DiscoveryAuthorizationState) -> Result<String> {
    let did_document = auth
        .did_document_snapshot
        .as_ref()
        .ok_or_else(|| anyhow!("discovery_did_document_missing"))?;
    let endpoint = did_document
        .service
        .iter()
        .find(|service| {
            service
                .service_type
                .eq_ignore_ascii_case("AgentDiscoveryService")
        })
        .map(|service| service.service_endpoint.trim_end_matches('/').to_owned())
        .or_else(|| {
            did_document.ans_metadata.as_ref().and_then(|metadata| {
                metadata
                    .address_bindings
                    .iter()
                    .find(|binding| binding.purpose.eq_ignore_ascii_case("service"))
                    .map(|binding| binding.address.trim_end_matches('/').to_owned())
            })
        })
        .ok_or_else(|| anyhow!("discovery_service_endpoint_missing"))?;
    Ok(format!("{endpoint}/discovery/sync"))
}

async fn run_discovery_notify_cycle(state: &AppState) -> Result<Value> {
    let targets = claim_discovery_targets(
        state,
        "root-discovery-worker",
        state.config.security.workers.discovery_batch_size,
        state.config.security.workers.lease_seconds,
    )
    .await?;
    let authorization_state =
        load_authorization_state(&state.config.paths.authorization_state_file)
            .unwrap_or_else(|_| state.authorization_state.clone());
    let mut notified = Vec::new();
    let mut failed = Vec::<Value>::new();
    for lease in targets {
        let Some(auth) = authorization_state.discovery_nodes.get(&lease.discovery_did) else {
            mark_discovery_target_retry(state, &lease.discovery_did, "discovery_not_authorized")
                .await?;
            continue;
        };
        if auth.status != "active" {
            mark_discovery_target_retry(state, &lease.discovery_did, "discovery_not_active").await?;
            continue;
        }
        let sync_url = match discovery_sync_url(&auth) {
            Ok(url) => url,
            Err(err) => {
                mark_discovery_target_retry(state, &lease.discovery_did, &err.to_string()).await?;
                failed.push(json!({
                    "discoveryDid": lease.discovery_did,
                    "error": err.to_string()
                }));
                continue;
            }
        };
        let response = state
            .client
            .post(&sync_url)
            .json(&json!({
                "maxPublications": state.config.security.workers.discovery_batch_size,
                "cursorHint": lease.target_cursor
            }))
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {
                mark_discovery_target_notified(state, &lease.discovery_did, lease.target_cursor)
                    .await?;
                notified.push(json!({
                    "rootDid": state.root_did,
                    "targetDiscoveryDid": lease.discovery_did,
                    "authorizedDomains": auth.authorized_domains,
                    "deliveredCursor": lease.target_cursor,
                    "previousDeliveredCursor": lease.delivered_cursor,
                    "syncUrl": sync_url,
                    "createdAt": Utc::now()
                }));
            }
            Ok(response) => {
                let status = response.status().as_u16();
                mark_discovery_target_retry(
                    state,
                    &lease.discovery_did,
                    &format!("status:{status}"),
                )
                .await?;
                failed.push(json!({
                    "discoveryDid": lease.discovery_did,
                    "syncUrl": sync_url,
                    "status": status
                }));
            }
            Err(err) => {
                let error = err.to_string();
                mark_discovery_target_retry(state, &lease.discovery_did, &error).await?;
                failed.push(json!({
                    "discoveryDid": lease.discovery_did,
                    "syncUrl": sync_url,
                    "error": error
                }));
            }
        }
    }
    let result = json!({
        "status": if failed.is_empty() { "ok" } else { "partial" },
        "notificationMode": "worker-watermark-trigger",
        "targetCount": notified.len() + failed.len(),
        "notifiedCount": notified.len(),
        "targets": notified,
        "failed": failed
    });
    write_batch_history(
        state,
        "discovery-notify-history",
        json!({
            "batchType": "discovery-notify",
            "processedAt": Utc::now(),
            "trigger": "worker-cycle",
            "targetCount": result["targetCount"],
            "notifiedCount": result["notifiedCount"],
            "failed": result["failed"]
        }),
    )
    .await?;
    Ok(result)
}

async fn write_batch_history(state: &AppState, namespace: &str, item: Value) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json(
                namespace,
                &format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                &item,
            )
            .await?;
    }
    let mut history: Vec<Value> = state
        .data
        .read(format!("indexes/{namespace}.json"))
        .unwrap_or_default();
    history.push(item);
    state
        .data
        .write(format!("indexes/{namespace}.json"), &history)?;
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
    use axum::{routing::post, Router as TestRouter};
    use chrono::{Duration, Utc};
    use oan_core::{
        AgentDescription, AnsMetadata, CryptoSuite, ServiceEndpoint, VerificationMethod,
    };
    use oan_credentials::AgentRegistrationCredential;
    use oan_crypto::{
        build_data_integrity_proof, generate_ed25519_keypair, hash_json_with_suite, public_key_jwk,
        public_key_multibase, SigningKey as OanSigningKey, VerifyingKey as OanVerifyingKey,
    };
    use oan_protocol::{
        AgentRegistrationSubmission, DidControlChallenge, SubjectControlProofBundle,
    };
    use oan_service_security::{
        build_registration_binding_claims, create_signed_request_envelope, hash_proof, request_id,
        request_nonce, NonceStore, DEFAULT_MAX_NONCE_ENTRIES,
    };
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        fs,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    struct VerifyAndPublishFixture {
        _temp_dir: tempfile::TempDir,
        state: AppState,
        request: VerifyAndPublishRequest,
        registrar_signing_key: OanSigningKey,
        agent_signing_key: ed25519_dalek::SigningKey,
        registrar_did: String,
        agent_did: String,
    }

    fn wrapped_signing_key(signing_key: &ed25519_dalek::SigningKey) -> OanSigningKey {
        OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: signing_key.clone(),
        }
    }

    fn did_document_with_key(
        did: &str,
        subject_type: SubjectType,
        signing_key: &ed25519_dalek::SigningKey,
        tags: Vec<&str>,
    ) -> DidDocument {
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
                cors: CorsConfig::default(),
                security: SecurityConfig {
                    admin: AdminSecurityConfig {
                        mode: "static-token".to_owned(),
                        static_tokens: vec!["test-admin-token".to_owned()],
                        trusted_admin_dids: vec![],
                        max_clock_skew_seconds: default_clock_skew_seconds(),
                        nonce_ttl_seconds: default_nonce_ttl_seconds(),
                        nonce_store_file: data_dir.join("admin-request-nonces.json"),
                    },
                    trusted_upstream: TrustedUpstreamSecurityConfig::default(),
                    workers: WorkerSecurityConfig {
                        enabled: false,
                        ..WorkerSecurityConfig::default()
                    },
                },
                paths: PathConfig {
                    data_dir: data_dir.to_path_buf(),
                    keys_dir: data_dir.join("keys"),
                    bulletin_file,
                    authorization_state_file: data_dir.join("authorization-state.json"),
                    request_nonce_file: data_dir.join("request-nonces.json"),
                    capability_tree_file: PathBuf::from("unused.json"),
                    database_url: None,
                },
            },
            root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: root_key,
            },
            tag_tree: default_tag_tree(),
            sqlite: None,
            authorization_state: AuthorizationState::default(),
            client: reqwest::Client::builder()
                .timeout(TokioDuration::from_secs(2))
                .build()
                .unwrap(),
        }
    }

    fn admin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test-admin-token"),
        );
        headers
    }

    #[derive(serde::Serialize)]
    struct SignedEnvelopePayloadForTest<'a> {
        #[serde(rename = "requestId")]
        request_id: &'a str,
        #[serde(rename = "protocolVersion")]
        protocol_version: &'a str,
        purpose: &'a str,
        method: &'a str,
        path: &'a str,
        aud: &'a str,
        #[serde(rename = "requestTimestamp")]
        request_timestamp: chrono::DateTime<Utc>,
        #[serde(rename = "requestNonce")]
        request_nonce: &'a str,
        #[serde(rename = "bodyHash")]
        body_hash: &'a str,
    }

    fn resign_envelope(
        envelope: &mut oan_protocol::SignedRequestEnvelope,
        creator: String,
        verification_method: String,
        signing_key: &OanSigningKey,
    ) {
        envelope.proof = build_data_integrity_proof(
            &SignedEnvelopePayloadForTest {
                request_id: &envelope.request_id,
                protocol_version: &envelope.protocol_version,
                purpose: &envelope.purpose,
                method: &envelope.method,
                path: &envelope.path,
                aud: &envelope.aud,
                request_timestamp: envelope.request_timestamp,
                request_nonce: &envelope.request_nonce,
                body_hash: &envelope.body_hash,
            },
            creator,
            verification_method,
            signing_key,
        )
        .unwrap();
    }

    fn fixture_with_registrar_and_agent(
        registrar_did: &str,
        agent_did: &str,
        metadata_source: &str,
        capability_tags: Vec<&str>,
    ) -> VerifyAndPublishFixture {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        let registrar_key = generate_ed25519_keypair();
        let agent_key = generate_ed25519_keypair();
        let registrar_did = registrar_did.to_owned();
        let agent_did = agent_did.to_owned();
        authorize_registrar_for_fixture(&state, &registrar_did, &registrar_key);
        let did_document = did_document_with_key(
            &agent_did,
            SubjectType::Agent,
            &agent_key,
            capability_tags.clone(),
        );
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &did_document).unwrap();
        let challenge = DidControlChallenge {
            challenge_id: format!("challenge-{metadata_source}"),
            draft_id: format!("draft-{metadata_source}"),
            subject_did: agent_did.clone(),
            did_document_hash: did_document_hash.clone(),
            registrar_did: registrar_did.clone(),
            purpose: "agent-registration".to_owned(),
            verification_method: format!("{agent_did}#key-1"),
            nonce: format!("nonce-{metadata_source}"),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
        };
        let agent_signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: agent_key.clone(),
        };
        let proof = build_data_integrity_proof(
            &challenge,
            agent_did.clone(),
            format!("{agent_did}#key-1"),
            &agent_signing_key,
        )
        .unwrap();
        let proof_hash = hash_proof(&proof).unwrap();
        let verified_at = Utc::now();
        let subject_control_proof = SubjectControlProofBundle {
            challenge: challenge.clone(),
            proof,
            verified_at: Some(verified_at),
            verified_verification_method: Some(format!("{agent_did}#key-1")),
            proof_hash: Some(proof_hash.clone()),
        };
        let claims = build_registration_binding_claims(
            &did_document_hash,
            &challenge,
            &proof_hash,
            verified_at,
        );
        let credential = AgentRegistrationCredential::unsigned(
            registrar_did.clone(),
            agent_did.clone(),
            json!({
                "didDocumentHash": did_document_hash,
                "capabilityTags": capability_tags,
                "registrationBinding": claims["registrationBinding"].clone()
            }),
        )
        .sign(
            format!("{registrar_did}#key-1"),
            &wrapped_signing_key(&registrar_key),
        )
        .unwrap();
        let submission = AgentRegistrationSubmission {
            agent_did: agent_did.clone(),
            did_document,
            did_document_hash,
            metadata: json!({"source": metadata_source}),
            registration_credential: serde_json::to_value(credential).unwrap(),
            subject_control_proof,
        };
        let upstream_auth = create_signed_request_envelope(
            request_id("verify-and-publish"),
            "ans-2026".to_owned(),
            "verify-and-publish".to_owned(),
            "POST".to_owned(),
            "/root/agents/verify-and-publish".to_owned(),
            state.root_did.clone(),
            &submission,
            registrar_did.clone(),
            format!("{registrar_did}#key-1"),
            &wrapped_signing_key(&registrar_key),
            request_nonce("verify-and-publish"),
        )
        .unwrap();
        let registrar_signing_key = wrapped_signing_key(&registrar_key);
        VerifyAndPublishFixture {
            _temp_dir: dir,
            state,
            request: VerifyAndPublishRequest {
                registrar_did: registrar_did.clone(),
                submission,
                upstream_auth,
            },
            registrar_signing_key,
            agent_signing_key: agent_key,
            registrar_did,
            agent_did,
        }
    }

    fn build_update_request_from_fixture(
        fixture: &VerifyAndPublishFixture,
        metadata_source: &str,
        capability_tags: Vec<&str>,
    ) -> VerifyAndPublishRequest {
        let did_document = did_document_with_key(
            &fixture.agent_did,
            SubjectType::Agent,
            &fixture.agent_signing_key,
            capability_tags.clone(),
        );
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &did_document).unwrap();
        let challenge = DidControlChallenge {
            challenge_id: format!("challenge-{metadata_source}"),
            draft_id: format!("draft-{metadata_source}"),
            subject_did: fixture.agent_did.clone(),
            did_document_hash: did_document_hash.clone(),
            registrar_did: fixture.registrar_did.clone(),
            purpose: "agent-registration".to_owned(),
            verification_method: format!("{}#key-1", fixture.agent_did),
            nonce: format!("nonce-{metadata_source}"),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
        };
        let agent_signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: fixture.agent_signing_key.clone(),
        };
        let proof = build_data_integrity_proof(
            &challenge,
            fixture.agent_did.clone(),
            format!("{}#key-1", fixture.agent_did),
            &agent_signing_key,
        )
        .unwrap();
        let proof_hash = hash_proof(&proof).unwrap();
        let verified_at = Utc::now();
        let subject_control_proof = SubjectControlProofBundle {
            challenge: challenge.clone(),
            proof,
            verified_at: Some(verified_at),
            verified_verification_method: Some(format!("{}#key-1", fixture.agent_did)),
            proof_hash: Some(proof_hash.clone()),
        };
        let claims = build_registration_binding_claims(
            &did_document_hash,
            &challenge,
            &proof_hash,
            verified_at,
        );
        let credential = AgentRegistrationCredential::unsigned(
            fixture.registrar_did.clone(),
            fixture.agent_did.clone(),
            json!({
                "didDocumentHash": did_document_hash,
                "capabilityTags": capability_tags,
                "registrationBinding": claims["registrationBinding"].clone()
            }),
        )
        .sign(
            format!("{}#key-1", fixture.registrar_did),
            &fixture.registrar_signing_key,
        )
        .unwrap();
        let submission = AgentRegistrationSubmission {
            agent_did: fixture.agent_did.clone(),
            did_document,
            did_document_hash,
            metadata: json!({ "source": metadata_source }),
            registration_credential: serde_json::to_value(credential).unwrap(),
            subject_control_proof,
        };
        create_verify_request_from_submission(
            &fixture.state,
            &fixture.registrar_did,
            &fixture.registrar_signing_key,
            submission,
        )
    }

    fn create_verify_request_from_submission(
        state: &AppState,
        registrar_did: &str,
        registrar_signing_key: &OanSigningKey,
        submission: AgentRegistrationSubmission,
    ) -> VerifyAndPublishRequest {
        let upstream_auth = create_signed_request_envelope(
            request_id("verify-and-publish"),
            "ans-2026".to_owned(),
            "verify-and-publish".to_owned(),
            "POST".to_owned(),
            "/root/agents/verify-and-publish".to_owned(),
            state.root_did.clone(),
            &submission,
            registrar_did.to_owned(),
            format!("{registrar_did}#key-1"),
            registrar_signing_key,
            request_nonce("verify-and-publish"),
        )
        .unwrap();
        VerifyAndPublishRequest {
            registrar_did: registrar_did.to_owned(),
            submission,
            upstream_auth,
        }
    }

    fn fixture_with_agent(
        agent_did: &str,
        metadata_source: &str,
        capability_tags: Vec<&str>,
    ) -> VerifyAndPublishFixture {
        fixture_with_registrar_and_agent(
            "did:ans:AGRG:efregistrarregistrar1234",
            agent_did,
            metadata_source,
            capability_tags,
        )
    }

    fn authorize_registrar_for_fixture(
        state: &AppState,
        registrar_did: &str,
        registrar_key: &ed25519_dalek::SigningKey,
    ) {
        let did_document = did_document_with_key(
            registrar_did,
            SubjectType::InfrastructureNode,
            registrar_key,
            vec!["registration"],
        );
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &did_document).unwrap();
        update_authorization_state(
            state,
            registrar_did,
            NodeAuthorizationState {
                status: "active".to_owned(),
                updated_at: Utc::now(),
                did_document_hash,
                did_document_snapshot: Some(did_document),
            },
            "registrar",
            None,
        )
        .unwrap();
    }

    fn authorize_fixture_registrar(state: &AppState, fixture: &VerifyAndPublishFixture) {
        match &fixture.registrar_signing_key {
            OanSigningKey::Ed25519 { key, .. } => {
                authorize_registrar_for_fixture(state, &fixture.registrar_did, key);
            }
            _ => unreachable!(),
        }
    }

    fn authorize_test_discovery(
        state: &AppState,
        discovery_did: &str,
        service_endpoint: &str,
        authorized_domains: Vec<&str>,
    ) {
        let discovery_key = generate_ed25519_keypair();
        let mut discovery_doc = did_document_with_key(
            discovery_did,
            SubjectType::InfrastructureNode,
            &discovery_key,
            vec!["discovery"],
        );
        discovery_doc.service[0].service_type = "AgentDiscoveryService".to_owned();
        discovery_doc.service[0].service_endpoint = service_endpoint.to_owned();
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &discovery_doc).unwrap();
        update_discovery_authorization_state(
            state,
            discovery_did,
            DiscoveryAuthorizationState {
                status: "active".to_owned(),
                updated_at: Utc::now(),
                did_document_hash,
                did_document_snapshot: Some(discovery_doc),
                authorized_domains: authorized_domains
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect(),
                tag_tree_version: state.tag_tree.version,
            },
        )
        .unwrap();
    }

    fn verify_and_publish_fixture() -> VerifyAndPublishFixture {
        fixture_with_agent(
            "did:ans:AGDM:efserviceagentservice1234",
            "test",
            vec!["echo"],
        )
    }

    async fn append_cdn_service_info_for_test(state: &AppState, base_url: &str) {
        let state = state.clone();
        let base_url = base_url.to_owned();
        tokio::task::spawn_blocking(move || {
            append_event(
                &state,
                BulletinEventType::CdnServiceInfoUpdated,
                &state.root_did,
                json!({
                    "baseUrl": base_url,
                    "manifestUrl": format!("{}/cdn/manifest", base_url.trim_end_matches('/')),
                    "packagesUrlTemplate": format!("{}/cdn/packages/{{did}}", base_url.trim_end_matches('/'))
                }),
            )
            .unwrap();
        })
        .await
        .unwrap();
    }

    async fn spawn_test_post_server(path: &'static str, counter: Arc<AtomicUsize>) -> String {
        async fn handle(counter: Arc<AtomicUsize>) -> Json<Value> {
            counter.fetch_add(1, Ordering::SeqCst);
            Json(json!({"status": "ok"}))
        }

        let app = TestRouter::new().route(
            path,
            post({
                let counter = counter.clone();
                move || handle(counter.clone())
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn enqueue_cdn_keeps_latest_package_per_did() {
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
            metadata_hash: None,
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
                package_claims: None,
                proof: None,
                crypto_suite: None,
                hash_algorithm: None,
            },
            created_at: Utc::now(),
        };
        enqueue_cdn_legacy(&state, &package).await.unwrap();
        package.did_document_hash = "hash-2".to_owned();
        enqueue_cdn_legacy(&state, &package).await.unwrap();

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
            metadata_hash: None,
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
                package_claims: None,
                proof: None,
                crypto_suite: None,
                hash_algorithm: None,
            },
            created_at: Utc::now(),
        };
        state
            .data
            .write("queues/cdn-publish.json", &vec![queue_package])
            .unwrap();
        state
            .data
            .write(
                "queues/discovery-notify.json",
                &vec![serde_json::json!({"did": "x"})],
            )
            .unwrap();

        let response = api_status(State(state)).await.unwrap();
        assert_eq!(
            response.0["rootDid"],
            "did:ans:AGRT:efrootrootrootrootrootroot"
        );
        assert_eq!(response.0["bulletinEventCount"], 1);
        assert_eq!(response.0["latestVersionCount"], 1);
        assert_eq!(response.0["cdnQueueCount"], 1);
        assert_eq!(response.0["discoveryQueueCount"], 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_status_reports_sqlite_discovery_watermark_queue_count() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        authorize_test_discovery(
            &state,
            "did:ans:AGDS:status-discovery1234",
            "http://127.0.0.1:9/discovery",
            vec!["echo"],
        );

        let cdn_counter = Arc::new(AtomicUsize::new(0));
        let cdn_base_url = spawn_test_post_server("/cdn/packages", cdn_counter.clone()).await;
        append_cdn_service_info_for_test(&state, &cdn_base_url).await;
        let _ = run_cdn_publish_cycle(&state).await.unwrap();

        let response = api_status(State(state)).await.unwrap();
        assert_eq!(response.0["cdnQueueCount"], 0);
        assert_eq!(response.0["discoveryQueueCount"], 1);
    }

    #[tokio::test]
    async fn api_registrars_and_discovery_lists_reflect_bulletin_events() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let _ = authorize_registrar(
            admin_headers(),
            State(state.clone()),
            Json(RootAuthorizeRequest {
                target_did: "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
                target_role: "registrar".to_owned(),
                did_document: did_document_with_key(
                    "did:ans:AGRG:efregistrarregistrar1234",
                    SubjectType::InfrastructureNode,
                    &registrar_key,
                    vec![],
                ),
            }),
        )
        .await
        .unwrap();
        let _ = authorize_discovery(
            admin_headers(),
            State(state.clone()),
            Json(RootAuthorizeRequest {
                target_did: "did:ans:AGDS:efdiscoverydiscovery1234".to_owned(),
                target_role: "discovery".to_owned(),
                did_document: did_document_with_key(
                    "did:ans:AGDS:efdiscoverydiscovery1234",
                    SubjectType::InfrastructureNode,
                    &discovery_key,
                    vec![],
                ),
            }),
        )
        .await
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
        assert!(result.0["valid"].as_bool().unwrap());
        assert_eq!(result.0["canonicalTags"].as_array().unwrap().len(), 1);
        assert_eq!(result.0["customTags"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn verify_request_accepts_valid_submission() {
        let fixture = verify_and_publish_fixture();
        assert!(verify_request(&fixture.state, &fixture.request).is_ok());
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
    fn ablation_registration_credential_real_system() {
        let mut cases = Vec::new();
        for index in 0..6 {
            let mut fixture = fixture_with_agent(
                "did:ans:AGDM:efserviceagentservice1234",
                &format!("ablation-credential-{index}"),
                vec!["echo"],
            );
            let mut credential: AgentRegistrationCredential =
                serde_json::from_value(fixture.request.submission.registration_credential.clone())
                    .unwrap();
            credential.proof = None;
            fixture.request.submission.registration_credential =
                serde_json::to_value(credential).unwrap();
            fixture.request.upstream_auth.body_hash = hash_json_with_suite(
                CryptoSuite::Ed25519Sha256Legacy,
                &fixture.request.submission,
            )
            .unwrap();
            resign_envelope(
                &mut fixture.request.upstream_auth,
                fixture.request.registrar_did.clone(),
                format!("{}#key-1", fixture.request.registrar_did),
                &fixture.registrar_signing_key,
            );

            let full_error = verify_request(&fixture.state, &fixture.request).unwrap_err();
            let _ = fs::remove_file(&fixture.state.config.paths.request_nonce_file);
            let degraded_result =
                verify_request_with_ablation(&fixture.state, &fixture.request, true, false);
            assert_eq!(full_error, "invalid_registration_credential_signature");
            assert!(degraded_result.is_ok(), "{degraded_result:?}");
            cases.push(json!({
                "case": format!("unsigned_registration_credential_{index}"),
                "fullAccepted": false,
                "fullRejection": full_error,
                "degradedAccepted": true
            }));
        }
        write_ablation_report(
            "registration_credential",
            json!({
                "mechanism": "registration credential verification",
                "invalidCases": cases.len(),
                "fullFalseAcceptanceOrExposure": 0,
                "degradedFalseAcceptanceOrExposure": cases.len(),
                "cases": cases
            }),
        );
    }

    #[test]
    fn ablation_preconnection_freshness_real_system() {
        let mut cases = Vec::new();
        for index in 0..8 {
            let mut fixture = fixture_with_agent(
                "did:ans:AGDM:efserviceagentservice1234",
                &format!("ablation-freshness-{index}"),
                vec!["echo"],
            );
            if index < 4 {
                fixture.request.upstream_auth.request_timestamp =
                    Utc::now() - Duration::seconds(default_clock_skew_seconds() + 30 + index);
            }
            resign_envelope(
                &mut fixture.request.upstream_auth,
                fixture.request.registrar_did.clone(),
                format!("{}#key-1", fixture.request.registrar_did),
                &fixture.registrar_signing_key,
            );

            if index >= 4 {
                assert!(verify_request(&fixture.state, &fixture.request).is_ok());
            }
            let full_error = verify_request(&fixture.state, &fixture.request).unwrap_err();
            let degraded_result =
                verify_request_with_ablation(&fixture.state, &fixture.request, false, true);
            assert!(degraded_result.is_ok(), "{degraded_result:?}");
            cases.push(json!({
                "case": if index < 4 { format!("stale_timestamp_{index}") } else { format!("replayed_nonce_{index}") },
                "fullAccepted": false,
                "fullRejection": full_error,
                "degradedAccepted": true
            }));
        }
        write_ablation_report(
            "preconnection_freshness",
            json!({
                "mechanism": "pre-connection freshness validation",
                "invalidCases": cases.len(),
                "fullFalseAcceptanceOrExposure": 0,
                "degradedFalseAcceptanceOrExposure": cases.len(),
                "cases": cases
            }),
        );
    }

    #[tokio::test]
    async fn verify_and_publish_handler_persists_archive_indexes_and_queues() {
        let fixture = verify_and_publish_fixture();
        let state = fixture.state.clone();
        let request = fixture.request.clone();
        let response = verify_and_publish(State(state.clone()), Json(request))
            .await
            .unwrap();
        assert_eq!(response.0.status, "verified-and-queued");
        assert_eq!(response.0.operation, "create");
        assert_eq!(response.0.agent_did, fixture.agent_did);

        let latest: Value = state
            .data
            .read("indexes/latest-did-document-versions.json")
            .unwrap();
        assert!(latest
            .get(&fixture.agent_did)
            .and_then(|value| value.get("documentVersion"))
            .is_some());

        let archive_prefix = format!(
            "archive/{}/v1",
            did_to_file_name(&fixture.agent_did).trim_end_matches(".json")
        );
        let archived_document: DidDocument = state
            .data
            .read(format!("{archive_prefix}/did-document.json"))
            .unwrap();
        assert_eq!(archived_document.id, fixture.agent_did);
        let archived_package: VerifiedPackage = state
            .data
            .read(format!("{archive_prefix}/package.json"))
            .unwrap();
        assert_eq!(archived_package.did, fixture.agent_did);

        let cdn_queue: Vec<VerifiedPackage> = state.data.read("queues/cdn-publish.json").unwrap();
        assert_eq!(cdn_queue.len(), 1);
        assert_eq!(cdn_queue[0].did, fixture.agent_did);

        let discovery_queue: Vec<Value> = state
            .data
            .read("queues/discovery-notify.json")
            .unwrap_or_default();
        assert!(discovery_queue.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_and_publish_sqlite_path_persists_latest_and_leased_jobs() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);

        let response = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();
        assert_eq!(response.0.status, "verified-and-queued");

        let latest = load_latest_version(&state, &fixture.agent_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest["documentVersion"], 1);

        let cdn_queue = read_cdn_queue(&state).await.unwrap();
        assert_eq!(cdn_queue.len(), 1);
        assert_eq!(cdn_queue[0].did, fixture.agent_did);

        let discovery_queue = read_discovery_queue(&state).await.unwrap();
        assert!(discovery_queue.is_empty());

        let archive_prefix = format!(
            "archive/{}/v1",
            did_to_file_name(&fixture.agent_did).trim_end_matches(".json")
        );
        assert!(
            !state
                .config
                .paths
                .data_dir
                .join(format!("{archive_prefix}/package.json"))
                .exists()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_cdn_publish_cycle_advances_discovery_watermark_only_after_success() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        authorize_test_discovery(
            &state,
            "did:ans:AGDS:efdiscoverydiscovery1234",
            "http://127.0.0.1:9/discovery",
            vec!["echo"],
        );

        let discovery_queue_before = read_discovery_queue(&state).await.unwrap();
        assert!(discovery_queue_before.is_empty());

        let counter = Arc::new(AtomicUsize::new(0));
        let base_url = spawn_test_post_server("/cdn/packages", counter.clone()).await;
        append_cdn_service_info_for_test(&state, &base_url).await;

        let result = run_cdn_publish_cycle(&state).await.unwrap();
        assert_eq!(result["publishedCount"], 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let discovery_queue = read_discovery_queue(&state).await.unwrap();
        assert_eq!(discovery_queue.len(), 1);
        assert_eq!(
            discovery_queue[0]["discoveryDid"],
            "did:ans:AGDS:efdiscoverydiscovery1234"
        );
        assert_eq!(discovery_queue[0]["pendingCursor"], 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_cdn_publish_cycle_posts_to_cdn_and_acks_leased_job() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let base_url = spawn_test_post_server("/cdn/packages", counter.clone()).await;
        append_cdn_service_info_for_test(&state, &base_url).await;

        let queue_before = read_cdn_queue(&state).await.unwrap();
        assert_eq!(queue_before.len(), 1);

        let result = run_cdn_publish_cycle(&state).await.unwrap();
        assert_eq!(result["publishedCount"], 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let queue = read_cdn_queue(&state).await.unwrap();
        assert!(queue.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_discovery_notify_cycle_triggers_sync_and_acks_matching_jobs() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        let sync_counter = Arc::new(AtomicUsize::new(0));
        let discovery_base_url =
            spawn_test_post_server("/discovery/sync", sync_counter.clone()).await;
        let discovery_did = "did:ans:AGDS:efdiscoverydiscovery1234".to_owned();
        authorize_test_discovery(
            &state,
            &discovery_did,
            &discovery_base_url,
            vec!["echo"],
        );

        let cdn_counter = Arc::new(AtomicUsize::new(0));
        let cdn_base_url = spawn_test_post_server("/cdn/packages", cdn_counter.clone()).await;
        append_cdn_service_info_for_test(&state, &cdn_base_url).await;
        let publish_result = run_cdn_publish_cycle(&state).await.unwrap();
        assert_eq!(publish_result["publishedCount"], 1);
        assert_eq!(cdn_counter.load(Ordering::SeqCst), 1);

        let queue_before = read_discovery_queue(&state).await.unwrap();
        assert_eq!(queue_before.len(), 1);
        let result = run_discovery_notify_cycle(&state).await.unwrap();
        assert_eq!(result["notifiedCount"], 1);
        assert_eq!(sync_counter.load(Ordering::SeqCst), 1);
        assert_eq!(result["notificationMode"], "worker-watermark-trigger");

        let queue = read_discovery_queue(&state).await.unwrap();
        assert!(queue.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_trigger_model_allows_followup_sync_noop_after_notification() {
        async fn handle_sync(counter: Arc<AtomicUsize>) -> Json<Value> {
            let call = counter.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Json(json!({
                    "status": "synced",
                    "syncedCount": 1,
                    "rejectedCount": 0,
                    "latestCursor": 1
                }))
            } else {
                Json(json!({
                    "status": "noop",
                    "syncedCount": 0,
                    "rejectedCount": 0,
                    "latestCursor": 1
                }))
            }
        }

        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        let sync_counter = Arc::new(AtomicUsize::new(0));
        let app = TestRouter::new().route(
            "/discovery/sync",
            post({
                let counter = sync_counter.clone();
                move || handle_sync(counter.clone())
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let discovery_base_url = format!("http://{}", addr);

        authorize_test_discovery(
            &state,
            "did:ans:AGDS:efdiscoverydiscovery1234",
            &discovery_base_url,
            vec!["echo"],
        );

        let cdn_counter = Arc::new(AtomicUsize::new(0));
        let cdn_base_url = spawn_test_post_server("/cdn/packages", cdn_counter.clone()).await;
        append_cdn_service_info_for_test(&state, &cdn_base_url).await;

        let publish_result = run_cdn_publish_cycle(&state).await.unwrap();
        assert_eq!(publish_result["publishedCount"], 1);

        let notify_result = run_discovery_notify_cycle(&state).await.unwrap();
        assert_eq!(notify_result["notifiedCount"], 1);
        assert_eq!(sync_counter.load(Ordering::SeqCst), 1);

        let followup = reqwest::Client::new()
            .post(format!("{}/discovery/sync", discovery_base_url))
            .json(&json!({ "maxPublications": 10, "cursorHint": 1 }))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(followup["status"], "noop");
        assert_eq!(followup["latestCursor"], 1);
        assert_eq!(sync_counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn root_accepts_multiple_registrars_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let fixture_a = fixture_with_agent(
            "did:ans:AGDM:efserviceagentservice1235",
            "parallel-a",
            vec!["echo", "parallel-a"],
        );
        let fixture_b = fixture_with_registrar_and_agent(
            "did:ans:AGRG:efregistrarregistrar5678",
            "did:ans:AGDM:efserviceagentservice1236",
            "parallel-b",
            vec!["echo", "parallel-b"],
        );
        let mut state = fixture_a.state.clone();
        state.sqlite = Some(sqlite);
        authorize_fixture_registrar(&state, &fixture_a);
        authorize_fixture_registrar(&state, &fixture_b);

        let mut request_a = fixture_a.request.clone();
        request_a.upstream_auth.request_nonce = request_nonce("verify-and-publish");
        request_a.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &request_a.submission,
        )
        .unwrap();
        resign_envelope(
            &mut request_a.upstream_auth,
            request_a.registrar_did.clone(),
            format!("{}#key-1", request_a.registrar_did),
            &fixture_a.registrar_signing_key,
        );

        let mut request_b = fixture_b.request.clone();
        request_b.upstream_auth.request_nonce = request_nonce("verify-and-publish");
        request_b.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &request_b.submission,
        )
        .unwrap();
        resign_envelope(
            &mut request_b.upstream_auth,
            request_b.registrar_did.clone(),
            format!("{}#key-1", request_b.registrar_did),
            &fixture_b.registrar_signing_key,
        );

        let state_a = state.clone();
        let state_b = state.clone();
        let (response_a, response_b) = tokio::join!(
            verify_and_publish(State(state_a), Json(request_a)),
            verify_and_publish(State(state_b), Json(request_b))
        );

        assert_eq!(response_a.unwrap().0.status, "verified-and-queued");
        assert_eq!(response_b.unwrap().0.status, "verified-and-queued");

        let latest_versions = read_latest_versions(&state).unwrap();
        assert_eq!(latest_versions.len(), 2);
        assert!(latest_versions.contains_key("did:ans:AGDM:efserviceagentservice1235"));
        assert!(latest_versions.contains_key("did:ans:AGDM:efserviceagentservice1236"));

        let cdn_queue = read_cdn_queue(&state).await.unwrap();
        assert_eq!(cdn_queue.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_did_concurrent_accept_assigns_monotonic_versions() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);

        let initial = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();
        assert_eq!(initial.0.document_version, 1);

        let mut request_a =
            build_update_request_from_fixture(&fixture, "concurrent-a", vec!["echo", "update-a"]);
        request_a.upstream_auth.request_nonce = request_nonce("verify-and-publish");
        request_a.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &request_a.submission,
        )
        .unwrap();
        resign_envelope(
            &mut request_a.upstream_auth,
            request_a.registrar_did.clone(),
            format!("{}#key-1", request_a.registrar_did),
            &fixture.registrar_signing_key,
        );

        let mut request_b =
            build_update_request_from_fixture(&fixture, "concurrent-b", vec!["echo", "update-b"]);
        request_b.upstream_auth.request_nonce = request_nonce("verify-and-publish");
        request_b.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &request_b.submission,
        )
        .unwrap();
        resign_envelope(
            &mut request_b.upstream_auth,
            request_b.registrar_did.clone(),
            format!("{}#key-1", request_b.registrar_did),
            &fixture.registrar_signing_key,
        );

        let state_a = state.clone();
        let state_b = state.clone();
        let (response_a, response_b) = tokio::join!(
            verify_and_publish(State(state_a), Json(request_a)),
            verify_and_publish(State(state_b), Json(request_b))
        );

        let version_a = response_a.unwrap().0.document_version;
        let version_b = response_b.unwrap().0.document_version;
        assert!(version_a >= 1);
        assert!(version_b >= 1);

        let latest = load_latest_version(&state, &fixture.agent_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest["documentVersion"], json!(version_a.max(version_b)));

        let rows = sqlx::query(&format!(
            "SELECT version FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE subject_did = ? ORDER BY version"
        ))
        .bind(&fixture.agent_did)
        .fetch_all(state.sqlite.as_ref().unwrap().pool())
        .await
        .unwrap();
        let versions = rows
            .into_iter()
            .map(|row| row.get::<i64, _>(0))
            .collect::<Vec<_>>();
        assert!(versions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(versions.contains(&1));
        assert!(versions.iter().any(|version| *version >= 2));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn leased_jobs_recover_after_expiration() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        let leased = claim_cdn_jobs(&state, "worker-a", 10, 1).await.unwrap();
        assert_eq!(leased.len(), 1);
        assert!(read_cdn_queue(&state).await.unwrap().len() == 1);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let recovered = claim_cdn_jobs(&state, "worker-b", 10, 30).await.unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].0, leased[0].0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_watermark_routes_only_to_matching_domains() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        authorize_test_discovery(
            &state,
            "did:ans:AGDS:echo-discovery1234",
            "http://127.0.0.1:9/discovery",
            vec!["echo"],
        );
        authorize_test_discovery(
            &state,
            "did:ans:AGDS:mcp-discovery1234",
            "http://127.0.0.1:9/discovery",
            vec!["mcp"],
        );

        let cdn_counter = Arc::new(AtomicUsize::new(0));
        let cdn_base_url = spawn_test_post_server("/cdn/packages", cdn_counter.clone()).await;
        append_cdn_service_info_for_test(&state, &cdn_base_url).await;

        let result = run_cdn_publish_cycle(&state).await.unwrap();
        assert_eq!(result["publishedCount"], 1);

        let queue = read_discovery_queue(&state).await.unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0]["discoveryDid"], "did:ans:AGDS:echo-discovery1234");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_target_leases_recover_after_expiration() {
        let fixture = verify_and_publish_fixture();
        let dir = tempfile::tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("root.db").display()))
                .await
                .unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();

        let mut state = fixture.state.clone();
        state.sqlite = Some(sqlite);
        let _ = verify_and_publish(State(state.clone()), Json(fixture.request.clone()))
            .await
            .unwrap();

        authorize_test_discovery(
            &state,
            "did:ans:AGDS:lease-discovery1234",
            "http://127.0.0.1:9/discovery",
            vec!["echo"],
        );

        let cdn_counter = Arc::new(AtomicUsize::new(0));
        let cdn_base_url = spawn_test_post_server("/cdn/packages", cdn_counter.clone()).await;
        append_cdn_service_info_for_test(&state, &cdn_base_url).await;
        let _ = run_cdn_publish_cycle(&state).await.unwrap();

        let leased = claim_discovery_targets(&state, "worker-a", 10, 1)
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let recovered = claim_discovery_targets(&state, "worker-b", 10, 30)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].discovery_did, leased[0].discovery_did);
        assert_eq!(recovered[0].target_cursor, leased[0].target_cursor);
    }

    #[test]
    fn verify_request_rejects_replayed_nonce() {
        let fixture = verify_and_publish_fixture();
        assert!(verify_request(&fixture.state, &fixture.request).is_ok());
        assert_eq!(
            verify_request(&fixture.state, &fixture.request).unwrap_err(),
            "trusted_upstream_nonce_replayed"
        );
    }

    #[test]
    fn verify_request_rejects_stale_timestamp() {
        let mut fixture = verify_and_publish_fixture();
        fixture.request.upstream_auth.request_timestamp =
            Utc::now() - Duration::seconds(default_clock_skew_seconds() + 30);
        resign_envelope(
            &mut fixture.request.upstream_auth,
            fixture.request.registrar_did.clone(),
            format!("{}#key-1", fixture.request.registrar_did),
            &fixture.registrar_signing_key,
        );
        assert_eq!(
            verify_request(&fixture.state, &fixture.request).unwrap_err(),
            "trusted_upstream_timestamp_stale"
        );
    }

    #[test]
    fn verify_request_rejects_did_document_hash_mismatch() {
        let mut fixture = verify_and_publish_fixture();
        fixture.request.submission.did_document_hash = "wrong-hash".to_owned();
        fixture.request.submission.registration_credential["claims"]["didDocumentHash"] =
            json!("wrong-hash");
        fixture.request.submission.registration_credential["claims"]["registrationBinding"]
            ["proofHash"] = fixture
            .request
            .submission
            .subject_control_proof
            .proof_hash
            .clone()
            .unwrap()
            .into();
        fixture.request.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &fixture.request.submission,
        )
        .unwrap();
        resign_envelope(
            &mut fixture.request.upstream_auth,
            fixture.request.registrar_did.clone(),
            format!("{}#key-1", fixture.request.registrar_did),
            &fixture.registrar_signing_key,
        );
        assert_eq!(
            verify_request(&fixture.state, &fixture.request).unwrap_err(),
            "subject_control_did_document_hash_mismatch"
        );
    }

    #[test]
    fn verify_request_rejects_registration_binding_mismatch() {
        let mut fixture = verify_and_publish_fixture();
        fixture.request.submission.registration_credential["claims"]["registrationBinding"]
            ["subjectDid"] = json!("did:ans:AGDM:efotheragentservice1234");
        let credential = AgentRegistrationCredential::unsigned(
            fixture.registrar_did.clone(),
            fixture.agent_did.clone(),
            fixture.request.submission.registration_credential["claims"].clone(),
        )
        .sign(
            format!("{}#key-1", fixture.registrar_did),
            &fixture.registrar_signing_key,
        )
        .unwrap();
        fixture.request.submission.registration_credential =
            serde_json::to_value(credential).unwrap();
        fixture.request.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &fixture.request.submission,
        )
        .unwrap();
        resign_envelope(
            &mut fixture.request.upstream_auth,
            fixture.request.registrar_did.clone(),
            format!("{}#key-1", fixture.request.registrar_did),
            &fixture.registrar_signing_key,
        );
        assert_eq!(
            verify_request(&fixture.state, &fixture.request).unwrap_err(),
            "registration_binding_invalid"
        );
    }

    #[test]
    fn verify_request_rejects_subject_control_registrar_mismatch() {
        let mut fixture = verify_and_publish_fixture();
        fixture
            .request
            .submission
            .subject_control_proof
            .challenge
            .registrar_did = "did:ans:AGRG:efotherregistrar1234".to_owned();
        fixture.request.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &fixture.request.submission,
        )
        .unwrap();
        resign_envelope(
            &mut fixture.request.upstream_auth,
            fixture.request.registrar_did.clone(),
            format!("{}#key-1", fixture.request.registrar_did),
            &fixture.registrar_signing_key,
        );
        assert_eq!(
            verify_request(&fixture.state, &fixture.request).unwrap_err(),
            "subject_control_registrar_mismatch"
        );
    }

    #[test]
    fn verify_request_rejects_subject_control_purpose_mismatch() {
        let mut fixture = verify_and_publish_fixture();
        fixture
            .request
            .submission
            .subject_control_proof
            .challenge
            .purpose = "different-purpose".to_owned();
        fixture.request.upstream_auth.body_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256Legacy,
            &fixture.request.submission,
        )
        .unwrap();
        resign_envelope(
            &mut fixture.request.upstream_auth,
            fixture.request.registrar_did.clone(),
            format!("{}#key-1", fixture.request.registrar_did),
            &fixture.registrar_signing_key,
        );
        assert_eq!(
            verify_request(&fixture.state, &fixture.request).unwrap_err(),
            "subject_control_purpose_mismatch"
        );
    }

    #[tokio::test]
    async fn authorize_registrar_requires_admin_auth() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), dir.path().join("bulletin.json"));
        let response = authorize_registrar(
            HeaderMap::new(),
            State(state),
            Json(RootAuthorizeRequest {
                target_did: "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
                target_role: "registrar".to_owned(),
                did_document: did_document_with_key(
                    "did:ans:AGRG:efregistrarregistrar1234",
                    SubjectType::InfrastructureNode,
                    &generate_ed25519_keypair(),
                    vec!["registration"],
                ),
            }),
        )
        .await;
        assert_eq!(response.unwrap_err().status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verify_request_prunes_shared_nonce_store_to_max_entries() {
        let fixture = verify_and_publish_fixture();
        let now = Utc::now();
        let mut nonces = BTreeMap::new();
        for index in 0..(DEFAULT_MAX_NONCE_ENTRIES + 5) {
            nonces.insert(
                format!("nonce-{index}"),
                now - chrono::Duration::milliseconds(
                    (DEFAULT_MAX_NONCE_ENTRIES + 5 - index) as i64,
                ),
            );
        }
        JsonStore::new(".")
            .write(
                &fixture.state.config.paths.request_nonce_file,
                &NonceStore { nonces },
            )
            .unwrap();

        verify_request(&fixture.state, &fixture.request).unwrap();

        let stored: NonceStore = JsonStore::new(".")
            .read(&fixture.state.config.paths.request_nonce_file)
            .unwrap();
        assert_eq!(stored.nonces.len(), DEFAULT_MAX_NONCE_ENTRIES);
        assert!(!stored.nonces.contains_key("nonce-0"));
        assert!(stored
            .nonces
            .contains_key(&fixture.request.upstream_auth.request_nonce));
    }
}
