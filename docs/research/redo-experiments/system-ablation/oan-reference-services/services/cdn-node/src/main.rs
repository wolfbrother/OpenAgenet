// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use oan_core::DidDocument;
use oan_package::{Manifest, ManifestEntry, VerifiedPackage};
use oan_protocol::{CdnPublishRequest, PATH_CDN_PACKAGES, PURPOSE_CDN_PUBLISH};
use oan_service_security::{
    bearer_token_from_header, verify_admin_token, verify_signed_request_envelope, AdminAuthConfig,
    AdminAuthMode, AdminPrincipal, TrustedUpstreamPolicy,
};
use oan_storage::{did_to_file_name, JsonStore, SqliteJsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::time::{sleep, Duration as TokioDuration};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

const CDN_MANIFEST_ENTRY_TABLE: &str = "cdn_manifest_entries";
const CDN_PUBLISH_HISTORY_TABLE: &str = "cdn_publish_history";
const CDN_ROOT_META_TABLE: &str = "cdn_root_meta";

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    debug: DebugConfig,
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
struct AdminSecurityConfig {
    #[serde(default = "default_admin_mode")]
    mode: String,
    #[serde(default)]
    static_tokens: Vec<String>,
}

impl Default for AdminSecurityConfig {
    fn default() -> Self {
        Self {
            mode: default_admin_mode(),
            static_tokens: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct TrustedUpstreamSecurityConfig {
    #[serde(default = "default_clock_skew_seconds")]
    max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    nonce_ttl_seconds: i64,
    #[serde(default = "default_root_did")]
    root_did: String,
    #[serde(default = "default_root_did_document_file")]
    root_did_document_file: PathBuf,
    #[serde(default = "default_nonce_store_file")]
    nonce_store_file: PathBuf,
}

impl Default for TrustedUpstreamSecurityConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: default_clock_skew_seconds(),
            nonce_ttl_seconds: default_nonce_ttl_seconds(),
            root_did: default_root_did(),
            root_did_document_file: default_root_did_document_file(),
            nonce_store_file: default_nonce_store_file(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_admin_mode() -> String {
    "static-token".to_owned()
}

fn default_clock_skew_seconds() -> i64 {
    300
}

fn default_nonce_ttl_seconds() -> i64 {
    300
}

fn default_root_did() -> String {
    "did:ans:AGRT:efrootrootrootrootrootroot".to_owned()
}

fn default_root_did_document_file() -> PathBuf {
    PathBuf::from("../../data/root/did-document.json")
}

fn default_nonce_store_file() -> PathBuf {
    PathBuf::from("../../data/cdn/request-nonces.json")
}

fn default_debug_export_interval_ms() -> u64 {
    2_000
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    sqlite: Option<SqliteJsonStore>,
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

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
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

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/cdn-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let sqlite = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let sqlite = SqliteJsonStore::connect(url).await?;
            initialize_cdn_sqlite(&sqlite).await?;
            Some(sqlite)
        }
        _ => None,
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        sqlite,
    };
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/cdn/manifest", get(manifest))
        .route("/cdn/updates", get(manifest))
        .route("/cdn/packages/{did}", get(get_package))
        .route("/cdn/documents/{did}", get(get_document))
        .route("/cdn/metadata/{did}", get(get_metadata))
        .route("/cdn/status", get(api_status))
        .route("/cdn/catalog/packages", get(api_packages))
        .route("/cdn/catalog/packages/{did}", get(api_package_detail))
        .route("/cdn/catalog/documents/{did}", get(api_document_detail))
        .route("/cdn/catalog/metadata/{did}", get(api_metadata_detail))
        .route("/cdn/catalog/manifest/stats", get(api_manifest_stats))
        .route("/cdn/catalog/publish/history", get(api_publish_history))
        .layer(build_cors_layer(&config.cors)?);

    let admin_routes = Router::new()
        .route("/cdn/packages", post(publish_package))
        .route("/cdn/purge", post(api_purge));

    let app = Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state.clone());

    if state.sqlite.is_some() && state.config.debug.export_snapshots {
        tokio::spawn(async move {
            cdn_debug_export_loop(state).await;
        });
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("cdn-service listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_sqlite_url(base, database_url);
    }
    config.security.trusted_upstream.nonce_store_file =
        resolve_relative(base, &config.security.trusted_upstream.nonce_store_file);
    config.security.trusted_upstream.root_did_document_file = resolve_relative(
        base,
        &config.security.trusted_upstream.root_did_document_file,
    );
    Ok(config)
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

async fn initialize_cdn_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {CDN_MANIFEST_ENTRY_TABLE} (
                subject_did TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                role TEXT NOT NULL,
                document_path TEXT NOT NULL,
                metadata_path TEXT NOT NULL,
                package_path TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {CDN_PUBLISH_HISTORY_TABLE} (
                history_key TEXT PRIMARY KEY,
                item_json TEXT NOT NULL,
                published_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {CDN_ROOT_META_TABLE} (
                meta_key TEXT PRIMARY KEY,
                meta_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#
        ))
        .await?;
    Ok(())
}

fn admin_auth_config(state: &AppState) -> AdminAuthConfig {
    match state.config.security.admin.mode.as_str() {
        "static-token" => AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: state.config.security.admin.static_tokens.clone(),
            },
        },
        _ => AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: state.config.security.admin.static_tokens.clone(),
            },
        },
    }
}

fn trusted_upstream_policy(state: &AppState) -> TrustedUpstreamPolicy {
    TrustedUpstreamPolicy {
        expected_purpose: PURPOSE_CDN_PUBLISH.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: PATH_CDN_PACKAGES.to_owned(),
        expected_audience: state.config.security.trusted_upstream.root_did.clone(),
        max_clock_skew_seconds: state
            .config
            .security
            .trusted_upstream
            .max_clock_skew_seconds,
        nonce_ttl_seconds: state.config.security.trusted_upstream.nonce_ttl_seconds,
        nonce_store_path: state
            .config
            .security
            .trusted_upstream
            .nonce_store_file
            .clone(),
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

fn load_trusted_root_document(state: &AppState) -> std::result::Result<DidDocument, ApiError> {
    let did_document: DidDocument = state
        .data
        .read(
            &state
                .config
                .security
                .trusted_upstream
                .root_did_document_file,
        )
        .or_else(|_| {
            JsonStore::new(".").read(
                &state
                    .config
                    .security
                    .trusted_upstream
                    .root_did_document_file,
            )
        })
        .map_err(|err| ApiError::internal(err.into()))?;
    if did_document.id != state.config.security.trusted_upstream.root_did {
        return Err(ApiError::bad_request("trusted_root_document_id_mismatch"));
    }
    Ok(did_document)
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

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "nodeType": "cdn-service", "did": null}))
}

async fn manifest(State(state): State<AppState>) -> ApiResult<Manifest> {
    read_manifest(&state).map(Json).map_err(ApiError::internal)
}

async fn publish_package(
    State(state): State<AppState>,
    Json(request): Json<CdnPublishRequest>,
) -> ApiResult<serde_json::Value> {
    let root_document = load_trusted_root_document(&state)?;
    verify_signed_request_envelope(
        &request.upstream_auth,
        &request.package,
        &state.config.security.trusted_upstream.root_did,
        &root_document,
        &trusted_upstream_policy(&state),
        Utc::now(),
    )
    .map_err(|err| ApiError::bad_request(err.to_string()))?;
    request
        .package
        .verify_document_hash()
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    request
        .package
        .verify_metadata_hash()
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    if request.package.root_proof.root_did != state.config.security.trusted_upstream.root_did {
        return Err(ApiError::bad_request("trusted_upstream_root_did_mismatch"));
    }
    let package = request.package;
    let file = did_to_file_name(&package.did);
    state
        .data
        .write(format!("documents/{file}"), &package.did_document)
        .map_err(|err| ApiError::internal(err.into()))?;
    state
        .data
        .write(format!("metadata/{file}"), &package.metadata)
        .map_err(|err| ApiError::internal(err.into()))?;
    state
        .data
        .write(format!("packages/{file}"), &package)
        .map_err(|err| ApiError::internal(err.into()))?;
    upsert_manifest_entry(&state, &package)
        .await
        .map_err(ApiError::internal)?;
    let history_item = json!({
        "did": package.did,
        "version": package.root_proof.package_claims.as_ref().and_then(|claims| claims["documentVersion"].as_u64()).unwrap_or(0),
        "requestId": request.upstream_auth.request_id,
        "publishedAt": Utc::now()
    });
    append_publish_history(&state, history_item)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "published", "did": package.did})))
}

async fn get_package(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<VerifiedPackage> {
    read_by_did(&state, "packages", &did)
}

async fn get_document(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<oan_core::DidDocument> {
    read_by_did(&state, "documents", &did)
}

async fn get_metadata(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<oan_package::AgentMetadata> {
    read_by_did(&state, "metadata", &did)
}

async fn api_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let manifest = read_manifest(&state).map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "ok",
        "packageCount": manifest.packages.len(),
        "rootDid": manifest.root_did,
        "generatedAt": manifest.generated_at
    })))
}

async fn api_packages(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let manifest = read_manifest(&state).map_err(ApiError::internal)?;
    Ok(Json(
        json!({ "items": manifest.packages, "count": manifest.packages.len() }),
    ))
}

async fn api_package_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let package: Option<VerifiedPackage> = state
        .data
        .read(format!("packages/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "did": did, "package": package })))
}

async fn api_document_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let document: Option<oan_core::DidDocument> = state
        .data
        .read(format!("documents/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "did": did, "document": document })))
}

async fn api_metadata_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let metadata: Option<oan_package::AgentMetadata> = state
        .data
        .read(format!("metadata/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "did": did, "metadata": metadata })))
}

async fn api_manifest_stats(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let manifest = read_manifest(&state).map_err(ApiError::internal)?;
    let mut role_counts = serde_json::Map::new();
    for entry in &manifest.packages {
        let count = role_counts
            .get(&entry.role)
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + 1;
        role_counts.insert(entry.role.clone(), json!(count));
    }
    Ok(Json(json!({
        "packageCount": manifest.packages.len(),
        "roleCounts": role_counts,
        "version": manifest.version
    })))
}

async fn api_publish_history(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let history = read_publish_history(&state).map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": history, "count": history.len() })))
}

async fn api_purge(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<serde_json::Value> {
    let _principal = require_admin(&headers, &state)?;
    if let Some(did) = payload.get("did").and_then(|value| value.as_str()) {
        let _ = state
            .data
            .resolve(format!("packages/{}", did_to_file_name(did)));
    }
    Ok(Json(json!({
        "status": "accepted",
        "note": "MVP purge is advisory only"
    })))
}

async fn cdn_debug_export_loop(state: AppState) {
    loop {
        if let Err(err) = export_cdn_debug_snapshot(&state).await {
            eprintln!("cdn debug export failed: {err}");
        }
        sleep(TokioDuration::from_millis(
            state.config.debug.export_interval_ms.max(100),
        ))
        .await;
    }
}

fn read_manifest(state: &AppState) -> Result<Manifest> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT subject_did, role, document_path, metadata_path, package_path, did_document_hash, updated_at FROM {CDN_MANIFEST_ENTRY_TABLE} ORDER BY updated_at, subject_did"
            ))
            .fetch_all(sqlite.pool())
            .await?;
            let root_did = sqlx::query(&format!(
                "SELECT meta_value FROM {CDN_ROOT_META_TABLE} WHERE meta_key = 'root_did'"
            ))
            .fetch_optional(sqlite.pool())
            .await?
            .map(|row| row.get::<String, _>(0))
            .unwrap_or_default();
            let generated_at = sqlx::query(&format!(
                "SELECT meta_value FROM {CDN_ROOT_META_TABLE} WHERE meta_key = 'generated_at'"
            ))
            .fetch_optional(sqlite.pool())
            .await?
            .map(|row| row.get::<String, _>(0))
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
            let packages = rows
                .into_iter()
                .map(|row| ManifestEntry {
                    did: row.get::<String, _>(0),
                    role: row.get::<String, _>(1),
                    document_path: row.get::<String, _>(2),
                    metadata_path: row.get::<String, _>(3),
                    package_path: row.get::<String, _>(4),
                    did_document_hash: row.get::<String, _>(5),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>(6))
                        .map(|value| value.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
                .collect();
            Ok(Manifest {
                version: "0.1.0".to_owned(),
                generated_at,
                root_did,
                packages,
            })
        });
    }
    Ok(state.data.read("manifest.json").unwrap_or(Manifest {
        version: "0.1.0".to_owned(),
        generated_at: Utc::now(),
        root_did: String::new(),
        packages: vec![],
    }))
}

async fn upsert_manifest_entry(state: &AppState, package: &VerifiedPackage) -> Result<()> {
    let manifest = ManifestEntry {
        did: package.did.clone(),
        role: package.metadata.role.clone(),
        document_path: format!("/cdn/documents/{}", package.did),
        metadata_path: format!("/cdn/metadata/{}", package.did),
        package_path: format!("/cdn/packages/{}", package.did),
        did_document_hash: package.did_document_hash.clone(),
        updated_at: Utc::now(),
    };
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {CDN_MANIFEST_ENTRY_TABLE}(subject_did, version, role, document_path, metadata_path, package_path, did_document_hash, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did)
            DO UPDATE SET
                version = excluded.version,
                role = excluded.role,
                document_path = excluded.document_path,
                metadata_path = excluded.metadata_path,
                package_path = excluded.package_path,
                did_document_hash = excluded.did_document_hash,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&package.did)
        .bind(
            package
                .root_proof
                .package_claims
                .as_ref()
                .and_then(|claims| claims["documentVersion"].as_u64())
                .unwrap_or(0) as i64,
        )
        .bind(&manifest.role)
        .bind(&manifest.document_path)
        .bind(&manifest.metadata_path)
        .bind(&manifest.package_path)
        .bind(&manifest.did_document_hash)
        .bind(manifest.updated_at.to_rfc3339())
        .execute(sqlite.pool())
        .await?;
        upsert_root_meta(state, "root_did", &package.root_proof.root_did).await?;
        upsert_root_meta(state, "generated_at", &Utc::now().to_rfc3339()).await?;
        return Ok(());
    }
    write_manifest_json(state).await?;
    Ok(())
}

async fn upsert_root_meta(state: &AppState, key: &str, value: &str) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {CDN_ROOT_META_TABLE}(meta_key, meta_value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(meta_key)
            DO UPDATE SET meta_value = excluded.meta_value, updated_at = excluded.updated_at
            "#
        ))
        .bind(key)
        .bind(value)
        .bind(Utc::now().to_rfc3339())
        .execute(sqlite.pool())
        .await?;
    }
    Ok(())
}

async fn write_manifest_json(state: &AppState) -> Result<()> {
    let manifest = read_manifest(state)?;
    state.data.write("manifest.json", &manifest)?;
    Ok(())
}

async fn append_publish_history(state: &AppState, item: Value) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            "INSERT INTO {CDN_PUBLISH_HISTORY_TABLE}(history_key, item_json, published_at) VALUES (?, ?, ?)"
        ))
        .bind(format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()))
        .bind(serde_json::to_string(&item)?)
        .bind(Utc::now().to_rfc3339())
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    let mut history: Vec<Value> = state.data.read("publish-history.json").unwrap_or_default();
    history.push(item);
    state.data.write("publish-history.json", &history)?;
    Ok(())
}

fn read_publish_history(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT item_json FROM {CDN_PUBLISH_HISTORY_TABLE} ORDER BY published_at, history_key"
            ))
            .fetch_all(sqlite.pool())
            .await?;
            rows.into_iter()
                .map(|row| {
                    serde_json::from_str::<Value>(&row.get::<String, _>(0))
                        .map_err(anyhow::Error::from)
                })
                .collect()
        });
    }
    Ok(state.data.read("publish-history.json").unwrap_or_default())
}

async fn export_cdn_debug_snapshot(state: &AppState) -> Result<()> {
    if state.sqlite.is_none() {
        return Ok(());
    }
    let manifest = read_manifest(state)?;
    state.data.write("manifest.json", &manifest)?;
    let history = read_publish_history(state)?;
    state.data.write("publish-history.json", &history)?;
    Ok(())
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

fn read_by_did<T: serde::de::DeserializeOwned>(
    state: &AppState,
    kind: &str,
    did: &str,
) -> ApiResult<T> {
    state
        .data
        .read(format!("{kind}/{}", did_to_file_name(did)))
        .map(Json)
        .map_err(|_| ApiError::not_found(format!("{kind} not found for {did}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_core::{
        AgentDescription, AnsMetadata, CryptoSuite, ServiceEndpoint, VerificationMethod,
    };
    use oan_crypto::{
        generate_ed25519_keypair, hash_json_with_suite, public_key_jwk, public_key_multibase,
        SigningKey as OanSigningKey, VerifyingKey as OanVerifyingKey,
    };
    use oan_service_security::{
        create_signed_request_envelope, request_id, request_nonce, NonceStore,
        DEFAULT_MAX_NONCE_ENTRIES,
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

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
                subject_type: oan_core::SubjectType::InfrastructureNode,
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

    fn sample_package(did: &str) -> VerifiedPackage {
        let did_document = oan_core::DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![ServiceEndpoint {
                id: format!("{did}#service"),
                service_type: "AgentInvokeService".to_owned(),
                service_endpoint: "http://localhost:9001/invoke".to_owned(),
                version: None,
                protocol: Some("http".to_owned()),
                server_type: None,
                port: Some(9001),
            }],
            ans_metadata: Some(AnsMetadata {
                subject_type: oan_core::SubjectType::Agent,
                identity_type: "service-agent".to_owned(),
                ttl: None,
                address_bindings: vec![],
                agent_description: Some(AgentDescription {
                    capability_description: "demo".to_owned(),
                    capability_tags: vec!["echo".to_owned()],
                    use_case_examples: vec![],
                }),
                service_policy: None,
                network_scope: None,
                extra: Default::default(),
            }),
        };
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &did_document).unwrap();
        let metadata = oan_package::AgentMetadata {
            did: did.to_owned(),
            role: "Service Agent".to_owned(),
            identity_type: "service-agent".to_owned(),
            did_document_hash: did_document_hash.clone(),
            capability_tags: vec!["echo".to_owned()],
            services: did_document.service.clone(),
            status: "active".to_owned(),
            updated_at: Utc::now(),
        };
        let metadata_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, &metadata).unwrap();
        VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did.to_owned(),
            did_document_hash,
            metadata_hash: Some(metadata_hash),
            metadata,
            did_document,
            root_proof: oan_package::RootProof {
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

    fn app_state(dir: &std::path::Path) -> AppState {
        let root_did = "did:ans:AGRT:efrootrootrootrootrootroot";
        let root_key = generate_ed25519_keypair();
        let root_document = root_document_with_key(root_did, &root_key);
        JsonStore::new(".")
            .write(dir.join("trusted-root.json"), &root_document)
            .unwrap();
        AppState {
            data: JsonStore::new(dir),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8003,
                },
                cors: CorsConfig::default(),
                security: SecurityConfig {
                    admin: AdminSecurityConfig {
                        mode: "static-token".to_owned(),
                        static_tokens: vec!["test-admin-token".to_owned()],
                    },
                    trusted_upstream: TrustedUpstreamSecurityConfig {
                        max_clock_skew_seconds: default_clock_skew_seconds(),
                        nonce_ttl_seconds: default_nonce_ttl_seconds(),
                        root_did: root_did.to_owned(),
                        root_did_document_file: dir.join("trusted-root.json"),
                        nonce_store_file: dir.join("request-nonces.json"),
                    },
                },
                debug: DebugConfig::default(),
                paths: PathConfig {
                    data_dir: dir.to_path_buf(),
                    database_url: None,
                },
            },
            sqlite: None,
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

    fn signed_publish_request(state: &AppState, package: &VerifiedPackage) -> CdnPublishRequest {
        let root_did = state.config.security.trusted_upstream.root_did.clone();
        let secret_key = generate_ed25519_keypair();
        let trusted_root = root_document_with_key(&root_did, &secret_key);
        JsonStore::new(".")
            .write(
                &state
                    .config
                    .security
                    .trusted_upstream
                    .root_did_document_file,
                &trusted_root,
            )
            .unwrap();
        let signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: secret_key,
        };
        let upstream_auth = create_signed_request_envelope(
            request_id("cdn-publish"),
            "ans-2026".to_owned(),
            "cdn-publish".to_owned(),
            "POST".to_owned(),
            "/cdn/packages".to_owned(),
            root_did.clone(),
            package,
            root_did.clone(),
            format!("{root_did}#key-1"),
            &signing_key,
            request_nonce("cdn-publish"),
        )
        .unwrap();
        CdnPublishRequest {
            package: package.clone(),
            upstream_auth,
        }
    }

    fn resign_publish_request(
        state: &AppState,
        package: &VerifiedPackage,
        root_key: &ed25519_dalek::SigningKey,
    ) -> CdnPublishRequest {
        let root_did = state.config.security.trusted_upstream.root_did.clone();
        let signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: root_key.clone(),
        };
        let upstream_auth = create_signed_request_envelope(
            request_id("cdn-publish"),
            "ans-2026".to_owned(),
            "cdn-publish".to_owned(),
            "POST".to_owned(),
            "/cdn/packages".to_owned(),
            root_did.clone(),
            package,
            root_did.clone(),
            format!("{root_did}#key-1"),
            &signing_key,
            request_nonce("cdn-publish"),
        )
        .unwrap();
        CdnPublishRequest {
            package: package.clone(),
            upstream_auth,
        }
    }

    #[tokio::test]
    async fn api_status_and_manifest_stats_work() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        state
            .data
            .write(
                "manifest.json",
                &Manifest {
                    version: "0.1.0".to_owned(),
                    generated_at: Utc::now(),
                    root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                    packages: vec![],
                },
            )
            .unwrap();
        let status = api_status(State(state.clone())).await.unwrap();
        assert_eq!(status.0["status"], "ok");
        let stats = api_manifest_stats(State(state)).await.unwrap();
        assert_eq!(stats.0["packageCount"], 0);
    }

    #[tokio::test]
    async fn api_package_and_purge_endpoints_return_expected_shape() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let package = sample_package(did);
        state
            .data
            .write(format!("packages/{}", did_to_file_name(did)), &package)
            .unwrap();
        state
            .data
            .write(
                format!("documents/{}", did_to_file_name(did)),
                &package.did_document,
            )
            .unwrap();
        state
            .data
            .write(
                format!("metadata/{}", did_to_file_name(did)),
                &package.metadata,
            )
            .unwrap();

        let detail = api_package_detail(State(state.clone()), AxumPath(did.to_owned()))
            .await
            .unwrap();
        assert!(detail.0["package"].is_object());

        let purge = api_purge(admin_headers(), State(state), Json(json!({"did": did})))
            .await
            .unwrap();
        assert_eq!(purge.0["status"], "accepted");
    }

    #[tokio::test]
    async fn publish_package_rejects_missing_trusted_upstream_auth() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let package = sample_package("did:ans:AGDM:efserviceagentservice1234");
        let response = publish_package(
            State(state),
            Json(CdnPublishRequest {
                package,
                upstream_auth: oan_protocol::SignedRequestEnvelope {
                    request_id: "request-1".to_owned(),
                    protocol_version: "ans-2026".to_owned(),
                    purpose: "cdn-publish".to_owned(),
                    method: "POST".to_owned(),
                    path: "/cdn/packages".to_owned(),
                    aud: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                    request_timestamp: Utc::now(),
                    request_nonce: "nonce-1".to_owned(),
                    body_hash: "body-hash".to_owned(),
                    proof: oan_core::DataIntegrityProof {
                        proof_type: String::new(),
                        creator: String::new(),
                        created: Utc::now(),
                        proof_purpose: String::new(),
                        proof_value: String::new(),
                        crypto_suite: None,
                        hash_algorithm: None,
                        verification_method: None,
                    },
                },
            }),
        )
        .await;
        assert_eq!(
            response.unwrap_err().message,
            "trusted_upstream_signature_missing"
        );
    }

    #[tokio::test]
    async fn publish_package_accepts_signed_request_and_persists_history() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let package = sample_package(did);
        let request = signed_publish_request(&state, &package);

        let response = publish_package(State(state.clone()), Json(request))
            .await
            .unwrap();
        assert_eq!(response.0["status"], "published");

        let history: Vec<Value> = state.data.read("publish-history.json").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["did"], did);
    }

    #[tokio::test]
    async fn api_purge_requires_admin_auth() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let response = api_purge(
            HeaderMap::new(),
            State(state),
            Json(json!({"did": "did:ans:AGDM:x"})),
        )
        .await;
        assert_eq!(response.unwrap_err().status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn publish_package_prunes_shared_nonce_store_to_max_entries() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
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
                &state.config.security.trusted_upstream.nonce_store_file,
                &NonceStore { nonces },
            )
            .unwrap();

        let did = "did:ans:AGDM:efserviceagentservice1234";
        let package = sample_package(did);
        let request = signed_publish_request(&state, &package);

        let response = publish_package(State(state.clone()), Json(request.clone()))
            .await
            .unwrap();
        assert_eq!(response.0["status"], "published");

        let stored: NonceStore = JsonStore::new(".")
            .read(&state.config.security.trusted_upstream.nonce_store_file)
            .unwrap();
        assert_eq!(stored.nonces.len(), DEFAULT_MAX_NONCE_ENTRIES);
        assert!(!stored.nonces.contains_key("nonce-0"));
        assert!(stored
            .nonces
            .contains_key(&request.upstream_auth.request_nonce));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_package_is_idempotent_for_manifest_state() {
        let dir = tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("cdn.db").display()))
                .await
                .unwrap();
        initialize_cdn_sqlite(&sqlite).await.unwrap();
        let mut state = app_state(dir.path());
        state.sqlite = Some(sqlite);

        let did = "did:ans:AGDM:efserviceagentservice1234";
        let package = sample_package(did);
        let root_key = generate_ed25519_keypair();
        let root_did = state.config.security.trusted_upstream.root_did.clone();
        let trusted_root = root_document_with_key(&root_did, &root_key);
        JsonStore::new(".")
            .write(
                &state
                    .config
                    .security
                    .trusted_upstream
                    .root_did_document_file,
                &trusted_root,
            )
            .unwrap();
        let request_a = resign_publish_request(&state, &package, &root_key);
        let request_b = resign_publish_request(&state, &package, &root_key);

        let response_a = publish_package(State(state.clone()), Json(request_a))
            .await
            .unwrap();
        let response_b = publish_package(State(state.clone()), Json(request_b))
            .await
            .unwrap();
        assert_eq!(response_a.0["status"], "published");
        assert_eq!(response_b.0["status"], "published");

        let manifest = read_manifest(&state).unwrap();
        assert_eq!(manifest.packages.len(), 1);
        assert_eq!(manifest.packages[0].did, did);

        let history = read_publish_history(&state).unwrap();
        assert_eq!(history.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_publish_path_does_not_emit_manifest_or_history_exports() {
        let dir = tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("cdn.db").display()))
                .await
                .unwrap();
        initialize_cdn_sqlite(&sqlite).await.unwrap();
        let mut state = app_state(dir.path());
        state.sqlite = Some(sqlite);

        let did = "did:ans:AGDM:efserviceagentservice1234";
        let package = sample_package(did);
        let request = signed_publish_request(&state, &package);

        let response = publish_package(State(state.clone()), Json(request))
            .await
            .unwrap();
        assert_eq!(response.0["status"], "published");
        assert!(!dir.path().join("manifest.json").exists());
        assert!(!dir.path().join("publish-history.json").exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_snapshot_remains_available_as_explicit_debug_action() {
        let dir = tempdir().unwrap();
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.path().join("cdn.db").display()))
                .await
                .unwrap();
        initialize_cdn_sqlite(&sqlite).await.unwrap();
        let mut state = app_state(dir.path());
        state.sqlite = Some(sqlite);

        let did = "did:ans:AGDM:efserviceagentservice1234";
        let package = sample_package(did);
        let request = signed_publish_request(&state, &package);
        let _ = publish_package(State(state.clone()), Json(request))
            .await
            .unwrap();

        export_cdn_debug_snapshot(&state).await.unwrap();

        let manifest: Manifest = state.data.read("manifest.json").unwrap();
        assert_eq!(manifest.packages.len(), 1);
        let history: Vec<Value> = state.data.read("publish-history.json").unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn debug_config_defaults_to_no_snapshot_exports() {
        let debug = DebugConfig::default();
        assert!(!debug.export_snapshots);
        assert!(debug.export_interval_ms >= 100);
    }
}
