// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use oan_core::{CapabilityTagTree, CryptoSuite, DidDocument};
use oan_credentials::AgentRegistrationCredential;
use oan_crypto::{hash_json_with_suite, signing_key_from_bytes, SigningKey};
use oan_protocol::{
    AgentRegistrationSubmission, DidControlChallenge, HealthResponse, SubjectControlProofBundle,
    VerifyAndPublishRequest, PATH_ROOT_VERIFY_AND_PUBLISH, PROTOCOL_VERSION,
    PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_service_security::{
    build_registration_binding_claims, create_did_control_challenge,
    create_signed_request_envelope, hash_proof, request_id, request_nonce,
    verify_subject_control_proof, DidControlPolicy, DidControlVerificationContext,
};
use oan_storage::{did_to_file_name, JsonStore, SqliteJsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{
    collections::HashSet,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    security: SecurityConfig,
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
struct UpstreamConfig {
    root_endpoint: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SecurityConfig {
    #[serde(default)]
    subject_control: SubjectControlConfig,
    #[serde(default)]
    upstream: UpstreamSecurityConfig,
    #[serde(default)]
    submit: SubmitSecurityConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct SubjectControlConfig {
    #[serde(default = "default_challenge_ttl_seconds")]
    challenge_ttl_seconds: i64,
    #[serde(default = "default_subject_control_purpose")]
    challenge_purpose: String,
}

impl Default for SubjectControlConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_seconds: default_challenge_ttl_seconds(),
            challenge_purpose: default_subject_control_purpose(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct SubmitSecurityConfig {
    #[serde(default = "default_submit_max_in_flight")]
    max_in_flight: usize,
    #[serde(default = "default_submit_retry_after_seconds")]
    retry_after_seconds: u64,
    #[serde(default = "default_submit_upstream_timeout_ms")]
    upstream_timeout_ms: u64,
}

impl Default for SubmitSecurityConfig {
    fn default() -> Self {
        Self {
            max_in_flight: default_submit_max_in_flight(),
            retry_after_seconds: default_submit_retry_after_seconds(),
            upstream_timeout_ms: default_submit_upstream_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct UpstreamSecurityConfig {
    #[serde(default = "default_protocol_label")]
    protocol_label: String,
    #[serde(default = "default_root_did")]
    root_did: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    records_dir: PathBuf,
    #[serde(default = "default_keys_dir")]
    keys_dir: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/keys")
}

fn default_challenge_ttl_seconds() -> i64 {
    300
}

fn default_subject_control_purpose() -> String {
    "agent-registration".to_owned()
}

fn default_submit_max_in_flight() -> usize {
    32
}

fn default_submit_retry_after_seconds() -> u64 {
    1
}

fn default_submit_upstream_timeout_ms() -> u64 {
    15_000
}

fn default_protocol_label() -> String {
    PROTOCOL_VERSION.to_owned()
}

fn default_root_did() -> String {
    "did:ans:AGRT:efrootrootrootrootrootroot".to_owned()
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    did: String,
    signing_key: SigningKey,
    sqlite: Option<SqliteJsonStore>,
    client: reqwest::Client,
    submit_limiter: Arc<Semaphore>,
    inflight_draft_submissions: Arc<Mutex<HashSet<String>>>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DraftCoreRecord {
    #[serde(rename = "draftId")]
    draft_id: String,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "didDocument")]
    did_document: Option<DidDocument>,
    #[serde(rename = "didDocumentHash", skip_serializing_if = "Option::is_none")]
    did_document_hash: Option<String>,
    metadata: Value,
    #[serde(rename = "reviewStatus", default = "default_review_status")]
    review_status: String,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubjectControlRecord {
    #[serde(rename = "draftId")]
    draft_id: String,
    #[serde(
        rename = "subjectControlStatus",
        default = "default_subject_control_status"
    )]
    subject_control_status: String,
    #[serde(rename = "controlChallenge", skip_serializing_if = "Option::is_none")]
    control_challenge: Option<DidControlChallenge>,
    #[serde(
        rename = "subjectControlProof",
        skip_serializing_if = "Option::is_none"
    )]
    subject_control_proof: Option<SubjectControlProofBundle>,
    #[serde(rename = "verifiedAt", skip_serializing_if = "Option::is_none")]
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CredentialRecord {
    #[serde(rename = "draftId")]
    draft_id: String,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "registrationCredential")]
    registration_credential: Value,
    #[serde(rename = "credentialHash", skip_serializing_if = "Option::is_none")]
    credential_hash: Option<String>,
    #[serde(rename = "issuedAt")]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DraftRecord {
    #[serde(rename = "draftId")]
    draft_id: String,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "didDocument")]
    did_document: Option<DidDocument>,
    #[serde(rename = "didDocumentHash", skip_serializing_if = "Option::is_none")]
    did_document_hash: Option<String>,
    #[serde(rename = "registrationCredential")]
    registration_credential: Option<Value>,
    metadata: Value,
    #[serde(rename = "reviewStatus", default = "default_review_status")]
    review_status: String,
    #[serde(
        rename = "subjectControlStatus",
        default = "default_subject_control_status"
    )]
    subject_control_status: String,
    #[serde(rename = "controlChallenge", skip_serializing_if = "Option::is_none")]
    control_challenge: Option<DidControlChallenge>,
    #[serde(
        rename = "subjectControlProof",
        skip_serializing_if = "Option::is_none"
    )]
    subject_control_proof: Option<SubjectControlProofBundle>,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmissionRecord {
    #[serde(rename = "submissionId")]
    submission_id: String,
    #[serde(rename = "draftId")]
    draft_id: String,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "requestPurpose")]
    request_purpose: String,
    #[serde(rename = "requestPath")]
    request_path: String,
    #[serde(rename = "rootEndpoint")]
    root_endpoint: String,
    #[serde(rename = "requestBodyHash")]
    request_body_hash: String,
    status: String,
    #[serde(rename = "statusCode", skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(rename = "responseBody", skip_serializing_if = "Option::is_none")]
    response_body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(rename = "submittedAt")]
    submitted_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
}

const REGISTRAR_DRAFT_CORE_TABLE: &str = "registrar_draft_core";
const REGISTRAR_SUBJECT_CONTROL_TABLE: &str = "registrar_subject_control";
const REGISTRAR_CREDENTIAL_TABLE: &str = "registrar_credential";
const REGISTRAR_SUBMISSION_TABLE: &str = "registrar_submission";

fn default_review_status() -> String {
    "draft".to_owned()
}

fn default_subject_control_status() -> String {
    "not-started".to_owned()
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
    retry_after_seconds: Option<u64>,
}

struct SubmitAdmission {
    _permit: OwnedSemaphorePermit,
    inflight_drafts: Arc<Mutex<HashSet<String>>>,
    draft_id: String,
}

impl Drop for SubmitAdmission {
    fn drop(&mut self) {
        if let Ok(mut inflight_drafts) = self.inflight_drafts.lock() {
            inflight_drafts.remove(&self.draft_id);
        }
    }
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256Legacy),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow::anyhow!("unsupported_algorithm: {other}")),
    }
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
            retry_after_seconds: None,
        }
    }

    fn too_many_requests(message: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response();
        if let Some(retry_after_seconds) = self.retry_after_seconds {
            response.headers_mut().insert(
                "Retry-After",
                HeaderValue::from_str(&retry_after_seconds.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("1")),
            );
        }
        response
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

#[derive(Clone, Debug, Deserialize)]
struct RegisterRequest {
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "didDocument")]
    did_document: DidDocument,
    #[serde(rename = "registrationCredential")]
    registration_credential: Value,
    #[serde(default)]
    metadata: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/registrar-node/config.example.toml".to_owned());
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
            initialize_registrar_sqlite(&sqlite).await?;
            Some(sqlite)
        }
        _ => None,
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        did: did_doc.id,
        signing_key,
        sqlite,
        client: reqwest::Client::new(),
        submit_limiter: Arc::new(Semaphore::new(config.security.submit.max_in_flight.max(1))),
        inflight_draft_submissions: Arc::new(Mutex::new(HashSet::new())),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/registrar/did", get(registrar_did_document))
        .route("/agents/register", post(register_agent))
        .route("/agents/update", post(register_agent))
        .route("/registrar/status", get(api_status))
        .route("/registrar/root-authorization", get(api_root_authorization))
        .route("/agents", get(api_agents))
        .route("/agents/{did}", get(api_agent_detail))
        .route("/agents/{did}/submissions", get(api_agent_submissions))
        .route("/agents/draft", post(api_create_draft))
        .route("/agents/draft/{draftId}", put(api_update_draft))
        .route("/agents/draft/{draftId}/validate", post(api_validate_draft))
        .route(
            "/agents/draft/{draftId}/control-challenge",
            post(api_create_control_challenge),
        )
        .route(
            "/agents/draft/{draftId}/prove-control",
            post(api_submit_control_proof),
        )
        .route(
            "/agents/draft/{draftId}/issue-registration-credential",
            post(api_issue_registration_credential),
        )
        .route("/agents/draft/{draftId}/submit", post(api_submit_draft))
        .route("/agents/{did}/resubmit", post(api_resubmit_agent))
        .route("/capability-tree", get(api_capability_tree))
        .route("/capability-tags/suggest", post(api_suggest_tags))
        .layer(build_cors_layer(&config.cors)?)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("registrar-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn initialize_registrar_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {REGISTRAR_DRAFT_CORE_TABLE} (
                draft_id TEXT PRIMARY KEY,
                agent_did TEXT NOT NULL,
                did_document_json TEXT,
                did_document_hash TEXT,
                metadata_json TEXT NOT NULL,
                review_status TEXT NOT NULL,
                workflow_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {REGISTRAR_SUBJECT_CONTROL_TABLE} (
                draft_id TEXT PRIMARY KEY,
                control_status TEXT NOT NULL,
                challenge_json TEXT,
                proof_bundle_json TEXT,
                verified_at TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {REGISTRAR_CREDENTIAL_TABLE} (
                draft_id TEXT PRIMARY KEY,
                agent_did TEXT NOT NULL,
                credential_json TEXT NOT NULL,
                credential_hash TEXT,
                issued_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {REGISTRAR_SUBMISSION_TABLE} (
                submission_id TEXT PRIMARY KEY,
                draft_id TEXT NOT NULL,
                agent_did TEXT NOT NULL,
                request_purpose TEXT NOT NULL,
                request_path TEXT NOT NULL,
                root_endpoint TEXT NOT NULL,
                request_body_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                status_code INTEGER,
                response_body_json TEXT,
                last_error TEXT,
                submitted_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_registrar_submission_agent_submitted
            ON {REGISTRAR_SUBMISSION_TABLE}(agent_did, submitted_at DESC, submission_id DESC);
            "#
        ))
        .await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.records_dir = resolve_relative(base, &config.paths.records_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_sqlite_url(base, database_url);
    }
    Ok(config)
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
        node_type: "registrar".to_owned(),
        did: Some(state.did),
    })
}

async fn registrar_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(|err| ApiError::internal(err.into()))
}

async fn register_agent(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<Value> {
    if request.agent_did != request.did_document.id {
        return Err(ApiError::bad_request("did_document_id_mismatch"));
    }
    request
        .did_document
        .validate_mvp()
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    let record = json!({
        "agentDid": request.agent_did,
        "didDocumentHash": hash_json_with_suite(state.signing_key.crypto_suite(), &request.did_document)
            .map_err(|err| ApiError::internal(err.into()))?,
        "metadata": request.metadata,
        "registrationCredential": request.registration_credential,
        "submittedAt": chrono::Utc::now()
    });
    let records_root = JsonStore::new(&state.config.paths.records_dir);
    records_root
        .write(did_to_file_name(&request.agent_did), &record)
        .map_err(|err| ApiError::internal(err.into()))?;
    mirror_sqlite_json(&state, "registrar.records", &request.agent_did, &record)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "recorded",
        "record": record
    })))
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let agents = list_json_files(&state.config.paths.records_dir).map_err(ApiError::internal)?;
    let drafts = list_json_files(&state.config.paths.data_dir.join("drafts")).unwrap_or_default();
    Ok(Json(json!({
        "registrarDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "registeredAgentCount": agents.len(),
        "draftCount": drafts.len()
    })))
}

async fn api_root_authorization(State(state): State<AppState>) -> ApiResult<Value> {
    let response = state
        .client
        .get(format!(
            "{}/root/registrars/{}",
            state.config.upstream.root_endpoint.trim_end_matches('/'),
            state.did
        ))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            let body: Value = response
                .json()
                .await
                .map_err(|err| ApiError::internal(err.into()))?;
            Ok(Json(json!({
                "registrarDid": state.did,
                "rootEndpoint": state.config.upstream.root_endpoint,
                "rootReachable": true,
                "authorization": body
            })))
        }
        Ok(response) => Ok(Json(json!({
            "registrarDid": state.did,
            "rootEndpoint": state.config.upstream.root_endpoint,
            "rootReachable": true,
            "status": "unknown",
            "rootStatusCode": response.status().as_u16()
        }))),
        Err(err) => Ok(Json(json!({
            "registrarDid": state.did,
            "rootEndpoint": state.config.upstream.root_endpoint,
            "rootReachable": false,
            "error": err.to_string()
        }))),
    }
}

async fn api_agents(State(state): State<AppState>) -> ApiResult<Value> {
    let records =
        read_record_values(&state.config.paths.records_dir).map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": records, "count": records.len() })))
}

async fn api_agent_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record: Option<Value> = JsonStore::new(&state.config.paths.records_dir)
        .read(did_to_file_name(&did))
        .ok();
    Ok(Json(json!({ "did": did, "record": record })))
}

async fn api_agent_submissions(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let submissions = read_submission_values(&state, Some(&did))
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "did": did,
        "items": submissions,
        "count": submissions.len()
    })))
}

async fn api_create_draft(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let now = chrono::Utc::now();
    let did_document = parse_optional_did_document(payload.get("didDocument"))?;
    let agent_did = payload
        .get("agentDid")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| did_document.as_ref().map(|doc| doc.id.clone()))
        .unwrap_or_else(|| format!("draft-agent-{}", now.timestamp_millis()));
    let draft_id = payload
        .get("draftId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("draft-{}", now.timestamp_millis()));
    let draft = DraftCoreRecord {
        draft_id: draft_id.clone(),
        agent_did,
        did_document,
        did_document_hash: None,
        metadata: payload
            .get("metadata")
            .cloned()
            .unwrap_or_else(|| json!({})),
        review_status: default_review_status(),
        status: "draft".to_owned(),
        created_at: now,
        updated_at: now,
    };
    write_draft_core(&state, &draft).await?;
    let subject_control = SubjectControlRecord {
        draft_id: draft_id.clone(),
        subject_control_status: default_subject_control_status(),
        control_challenge: None,
        subject_control_proof: None,
        verified_at: None,
        updated_at: now,
    };
    write_subject_control(&state, &subject_control).await?;
    if let Some(registration_credential) = payload.get("registrationCredential").cloned() {
        write_credential(
            &state,
            &CredentialRecord {
                draft_id: draft_id.clone(),
                agent_did: draft.agent_did.clone(),
                credential_hash: hash_json_with_suite(
                    state.signing_key.crypto_suite(),
                    &registration_credential,
                )
                .ok(),
                registration_credential,
                issued_at: now,
                updated_at: now,
            },
        )
        .await?;
    }
    let draft = read_draft(&state, &draft.draft_id).await?;
    spawn_draft_projection_refresh(state.clone(), draft.draft_id.clone());
    Ok(Json(json!({ "status": "created", "draft": draft })))
}

async fn api_update_draft(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id).await.unwrap_or_else(|_| DraftRecord {
        draft_id: draft_id.clone(),
        agent_did: payload
            .get("agentDid")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        did_document: None,
        did_document_hash: None,
        registration_credential: None,
        metadata: json!({}),
        review_status: default_review_status(),
        subject_control_status: default_subject_control_status(),
        control_challenge: None,
        subject_control_proof: None,
        status: "draft".to_owned(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    if let Some(agent_did) = payload.get("agentDid").and_then(Value::as_str) {
        draft.agent_did = agent_did.to_owned();
    }
    if let Some(value) = payload.get("didDocument") {
        draft.did_document = Some(parse_did_document(value)?);
        if let Some(doc) = &draft.did_document {
            draft.agent_did = doc.id.clone();
            draft.did_document_hash = hash_did_document(&state, doc).ok();
            draft.control_challenge = None;
            draft.subject_control_proof = None;
            draft.subject_control_status = "not-started".to_owned();
        }
    }
    if let Some(value) = payload.get("registrationCredential") {
        write_credential(
            &state,
            &CredentialRecord {
                draft_id: draft.draft_id.clone(),
                agent_did: draft.agent_did.clone(),
                registration_credential: value.clone(),
                credential_hash: hash_json_with_suite(state.signing_key.crypto_suite(), value).ok(),
                issued_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        )
        .await?;
        draft.registration_credential = Some(value.clone());
    }
    if let Some(value) = payload.get("metadata") {
        draft.metadata = value.clone();
    }
    draft.updated_at = chrono::Utc::now();
    write_draft_core(
        &state,
        &DraftCoreRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            did_document: draft.did_document.clone(),
            did_document_hash: draft.did_document_hash.clone(),
            metadata: draft.metadata.clone(),
            review_status: draft.review_status.clone(),
            status: draft.status.clone(),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        },
    )
    .await?;
    write_subject_control(
        &state,
        &SubjectControlRecord {
            draft_id: draft.draft_id.clone(),
            subject_control_status: draft.subject_control_status.clone(),
            control_challenge: draft.control_challenge.clone(),
            subject_control_proof: draft.subject_control_proof.clone(),
            verified_at: draft
                .subject_control_proof
                .as_ref()
                .and_then(|proof| proof.verified_at),
            updated_at: draft.updated_at,
        },
    )
    .await?;
    spawn_draft_projection_refresh(state.clone(), draft.draft_id.clone());
    Ok(Json(json!({ "status": "updated", "draft": draft })))
}

async fn api_validate_draft(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id).await?;
    let validation = validate_draft_record(&draft);
    draft.review_status = if validation["valid"].as_bool().unwrap_or(false) {
        "validated".to_owned()
    } else {
        "draft".to_owned()
    };
    draft.updated_at = chrono::Utc::now();
    write_draft_core(
        &state,
        &DraftCoreRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            did_document: draft.did_document.clone(),
            did_document_hash: draft.did_document_hash.clone(),
            metadata: draft.metadata.clone(),
            review_status: draft.review_status.clone(),
            status: draft.status.clone(),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        },
    )
    .await?;
    spawn_draft_projection_refresh(state.clone(), draft.draft_id.clone());
    Ok(Json(json!({
        "draftId": draft_id,
        "validation": validation
    })))
}

async fn api_create_control_challenge(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id).await?;
    let did_document = draft
        .did_document
        .clone()
        .ok_or_else(|| ApiError::bad_request("draft_missing_did_document"))?;
    let method = did_document
        .assertion_method
        .first()
        .cloned()
        .ok_or_else(|| ApiError::bad_request("draft_missing_assertion_method"))?;
    let did_document_hash = draft
        .did_document_hash
        .clone()
        .or_else(|| hash_did_document(&state, &did_document).ok())
        .ok_or_else(|| ApiError::bad_request("invalid_did_document_hash"))?;
    draft.did_document_hash = Some(did_document_hash.clone());
    let challenge = create_did_control_challenge(
        &draft.draft_id,
        &draft.agent_did,
        &did_document_hash,
        &state.did,
        &method,
        &subject_control_policy(&state),
        request_nonce("did-control"),
    );
    let now = chrono::Utc::now();
    write_subject_control(
        &state,
        &SubjectControlRecord {
            draft_id: draft.draft_id.clone(),
            subject_control_status: "challenged".to_owned(),
            control_challenge: Some(challenge.clone()),
            subject_control_proof: None,
            verified_at: None,
            updated_at: now,
        },
    )
    .await?;
    draft.subject_control_status = "challenged".to_owned();
    draft.control_challenge = Some(challenge.clone());
    draft.updated_at = now;
    write_draft_core(
        &state,
        &DraftCoreRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            did_document: draft.did_document.clone(),
            did_document_hash: draft.did_document_hash.clone(),
            metadata: draft.metadata.clone(),
            review_status: draft.review_status.clone(),
            status: draft.status.clone(),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        },
    )
    .await?;
    spawn_draft_projection_refresh(state.clone(), draft.draft_id.clone());
    Ok(Json(json!({
        "status": "challenge-created",
        "challenge": challenge
    })))
}

async fn api_submit_control_proof(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id).await?;
    let did_document = draft
        .did_document
        .clone()
        .ok_or_else(|| ApiError::bad_request("draft_missing_did_document"))?;
    let challenge = draft
        .control_challenge
        .clone()
        .ok_or_else(|| ApiError::bad_request("subject_control_challenge_missing"))?;
    let proof: oan_core::DataIntegrityProof = serde_json::from_value(
        payload
            .get("proof")
            .cloned()
            .ok_or_else(|| ApiError::bad_request("subject_control_proof_missing"))?,
    )
    .map_err(|_| ApiError::bad_request("subject_control_proof_invalid"))?;
    let mut bundle = SubjectControlProofBundle {
        challenge: challenge.clone(),
        proof,
        verified_at: None,
        verified_verification_method: None,
        proof_hash: None,
    };
    let did_document_hash = draft
        .did_document_hash
        .clone()
        .or_else(|| hash_did_document(&state, &did_document).ok())
        .ok_or_else(|| ApiError::bad_request("invalid_did_document_hash"))?;
    let verified_method = verify_subject_control_proof(
        &bundle,
        &did_document,
        &DidControlVerificationContext {
            expected_subject_did: &draft.agent_did,
            expected_did_document_hash: &did_document_hash,
            expected_registrar_did: &state.did,
            expected_purpose: &state.config.security.subject_control.challenge_purpose,
            now: chrono::Utc::now(),
        },
    )
    .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let proof_hash =
        hash_proof(&bundle.proof).map_err(|err| ApiError::bad_request(err.to_string()))?;
    bundle.verified_at = Some(chrono::Utc::now());
    bundle.verified_verification_method = Some(verified_method.clone());
    bundle.proof_hash = Some(proof_hash.clone());
    let now = chrono::Utc::now();
    write_subject_control(
        &state,
        &SubjectControlRecord {
            draft_id: draft.draft_id.clone(),
            subject_control_status: "verified".to_owned(),
            control_challenge: Some(challenge.clone()),
            subject_control_proof: Some(bundle.clone()),
            verified_at: bundle.verified_at,
            updated_at: now,
        },
    )
    .await?;
    draft.subject_control_proof = Some(bundle.clone());
    draft.subject_control_status = "verified".to_owned();
    draft.status = "control-verified".to_owned();
    draft.updated_at = now;
    write_draft_core(
        &state,
        &DraftCoreRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            did_document: draft.did_document.clone(),
            did_document_hash: draft.did_document_hash.clone(),
            metadata: draft.metadata.clone(),
            review_status: draft.review_status.clone(),
            status: draft.status.clone(),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        },
    )
    .await?;
    spawn_draft_projection_refresh(state.clone(), draft.draft_id.clone());
    Ok(Json(json!({
        "status": "control-verified",
        "verificationMethod": verified_method,
        "proofHash": proof_hash
    })))
}

async fn api_issue_registration_credential(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id).await?;
    if draft.review_status != "validated" {
        return Err(ApiError::bad_request("draft_not_validated"));
    }
    if draft.subject_control_status != "verified" {
        return Err(ApiError::bad_request("subject_control_not_verified"));
    }
    let did_document_hash = draft
        .did_document_hash
        .clone()
        .ok_or_else(|| ApiError::bad_request("invalid_did_document_hash"))?;
    let subject_control_proof = draft
        .subject_control_proof
        .clone()
        .ok_or_else(|| ApiError::bad_request("subject_control_proof_missing"))?;
    let proof_hash = subject_control_proof
        .proof_hash
        .clone()
        .ok_or_else(|| ApiError::bad_request("subject_control_proof_missing"))?;
    let verified_at = subject_control_proof
        .verified_at
        .ok_or_else(|| ApiError::bad_request("subject_control_proof_missing"))?;
    let binding_claims = build_registration_binding_claims(
        &did_document_hash,
        &subject_control_proof.challenge,
        &proof_hash,
        verified_at,
    );
    let credential = AgentRegistrationCredential::unsigned(
        state.did.clone(),
        draft.agent_did.clone(),
        json!({
            "didDocumentHash": did_document_hash,
            "capabilityTags": draft.did_document.as_ref()
                .and_then(|doc| doc.ans_metadata.as_ref())
                .and_then(|metadata| metadata.agent_description.as_ref())
                .map(|description| description.capability_tags.clone())
                .unwrap_or_default(),
            "assistedBy": "registrar-capability-tree",
            "registrationFlow": "draft-confirm-submit",
            "registrationBinding": binding_claims["registrationBinding"]
        }),
    )
    .sign(format!("{}#key-1", state.did), &state.signing_key)
    .map_err(|err| ApiError::internal(err.into()))?;
    let credential =
        serde_json::to_value(credential).map_err(|err| ApiError::internal(err.into()))?;
    let now = chrono::Utc::now();
    write_credential(
        &state,
        &CredentialRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            credential_hash: hash_json_with_suite(state.signing_key.crypto_suite(), &credential)
                .ok(),
            registration_credential: credential.clone(),
            issued_at: now,
            updated_at: now,
        },
    )
    .await?;
    draft.registration_credential = Some(credential.clone());
    draft.status = "credential-issued".to_owned();
    draft.updated_at = now;
    write_draft_core(
        &state,
        &DraftCoreRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            did_document: draft.did_document.clone(),
            did_document_hash: draft.did_document_hash.clone(),
            metadata: draft.metadata.clone(),
            review_status: draft.review_status.clone(),
            status: draft.status.clone(),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        },
    )
    .await?;
    spawn_draft_projection_refresh(state.clone(), draft.draft_id.clone());
    Ok(Json(json!({
        "status": "issued",
        "credential": credential
    })))
}

async fn api_submit_draft(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let _submit_admission = acquire_submit_admission(&state, &draft_id)?;
    let mut draft = read_draft(&state, &draft_id).await?;
    let request = build_verify_and_publish_request(&state, &draft)?;
    let mut submission = build_submission_record(&state, &draft, &request);
    write_submission(&state, &submission)
        .await
        .map_err(ApiError::internal)?;
    let response = state
        .client
        .post(format!(
            "{}/root/agents/verify-and-publish",
            state.config.upstream.root_endpoint
        ))
        .json(&request)
        .timeout(Duration::from_millis(
            state.config.security.submit.upstream_timeout_ms,
        ))
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            submission.status = "transport-failed".to_owned();
            submission.error = Some(err.to_string());
            submission.updated_at = chrono::Utc::now();
            draft.status = "submit-failed".to_owned();
            draft.updated_at = submission.updated_at;
            write_submission(&state, &submission)
                .await
                .map_err(ApiError::internal)?;
            write_draft(&state, &draft).await?;
            return Err(ApiError::internal(err.into()));
        }
    };
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
    submission.status = if status.is_success() {
        "accepted".to_owned()
    } else {
        "rejected".to_owned()
    };
    submission.status_code = Some(status.as_u16());
    submission.response_body = Some(body.clone());
    submission.updated_at = chrono::Utc::now();
    write_submission(&state, &submission)
        .await
        .map_err(ApiError::internal)?;
    if status.is_success() {
        draft.status = "submitted".to_owned();
    } else {
        draft.status = "submit-failed".to_owned();
    }
    draft.updated_at = submission.updated_at;
    write_draft(&state, &draft).await?;
    if !status.is_success() {
        return Err(ApiError {
            status,
            message: body.to_string(),
            retry_after_seconds: None,
        });
    }
    Ok(Json(body))
}

async fn api_resubmit_agent(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record: Value = JsonStore::new(&state.config.paths.records_dir)
        .read(did_to_file_name(&did))
        .map_err(|_| ApiError::bad_request("agent_record_not_found"))?;
    Ok(Json(json!({
        "did": did,
        "status": "resubmit-requires-full-did-document",
        "record": record
    })))
}

async fn api_capability_tree(State(state): State<AppState>) -> ApiResult<Value> {
    let tree = fetch_root_value(&state, "/root/capability-tree").await;
    match tree {
        Ok(value) => Ok(Json(value)),
        Err(err) => Ok(Json(json!({
            "version": null,
            "tags": [],
            "tree": [],
            "source": "root-unreachable",
            "error": err.to_string()
        }))),
    }
}

async fn api_suggest_tags(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let keyword = payload
        .get("query")
        .or_else(|| payload.get("keyword"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let tree_value = fetch_root_value(&state, "/root/capability-tree").await.ok();
    let tree: Option<CapabilityTagTree> = tree_value
        .clone()
        .and_then(|value| serde_json::from_value(value).ok());
    let suggestions = tree
        .map(|tree| {
            tree.tags
                .into_iter()
                .filter(|tag| {
                    keyword.is_empty()
                        || tag.id.to_lowercase().contains(&keyword)
                        || tag.label.to_lowercase().contains(&keyword)
                        || tag
                            .aliases
                            .iter()
                            .any(|alias| alias.to_lowercase().contains(&keyword))
                })
                .take(20)
                .map(|tag| json!({ "id": tag.id, "label": tag.label, "parent": tag.parent }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Json(
        json!({ "items": suggestions, "count": suggestions.len() }),
    ))
}

async fn fetch_root_value(state: &AppState, path: &str) -> Result<Value> {
    Ok(state
        .client
        .get(format!(
            "{}{}",
            state.config.upstream.root_endpoint.trim_end_matches('/'),
            path
        ))
        .send()
        .await?
        .json()
        .await?)
}

async fn read_draft(
    state: &AppState,
    draft_id: &str,
) -> std::result::Result<DraftRecord, ApiError> {
    let core = read_draft_core(state, draft_id).await?;
    let subject_control = read_subject_control(state, draft_id)
        .await
        .unwrap_or_else(|_| {
        SubjectControlRecord {
            draft_id: draft_id.to_owned(),
            subject_control_status: default_subject_control_status(),
            control_challenge: None,
            subject_control_proof: None,
            verified_at: None,
            updated_at: core.updated_at,
        }
    });
    let credential = read_credential(state, draft_id).await.ok();
    Ok(DraftRecord {
        draft_id: core.draft_id,
        agent_did: core.agent_did,
        did_document: core.did_document,
        did_document_hash: core.did_document_hash,
        registration_credential: credential
            .as_ref()
            .map(|value| value.registration_credential.clone()),
        metadata: core.metadata,
        review_status: core.review_status,
        subject_control_status: subject_control.subject_control_status,
        control_challenge: subject_control.control_challenge,
        subject_control_proof: subject_control.subject_control_proof,
        status: core.status,
        created_at: core.created_at,
        updated_at: latest_timestamp(
            core.updated_at,
            credential
                .as_ref()
                .map(|record| record.updated_at)
                .unwrap_or(core.updated_at),
            subject_control.updated_at,
        ),
    })
}

async fn write_draft(
    state: &AppState,
    draft: &DraftRecord,
) -> std::result::Result<(), ApiError> {
    write_draft_core(
        state,
        &DraftCoreRecord {
            draft_id: draft.draft_id.clone(),
            agent_did: draft.agent_did.clone(),
            did_document: draft.did_document.clone(),
            did_document_hash: draft.did_document_hash.clone(),
            metadata: draft.metadata.clone(),
            review_status: draft.review_status.clone(),
            status: draft.status.clone(),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        },
    )
    .await?;
    write_subject_control(
        state,
        &SubjectControlRecord {
            draft_id: draft.draft_id.clone(),
            subject_control_status: draft.subject_control_status.clone(),
            control_challenge: draft.control_challenge.clone(),
            subject_control_proof: draft.subject_control_proof.clone(),
            verified_at: draft
                .subject_control_proof
                .as_ref()
                .and_then(|proof| proof.verified_at),
            updated_at: draft.updated_at,
        },
    )
    .await?;
    if let Some(registration_credential) = &draft.registration_credential {
        write_credential(
            state,
            &CredentialRecord {
                draft_id: draft.draft_id.clone(),
                agent_did: draft.agent_did.clone(),
                registration_credential: registration_credential.clone(),
                credential_hash: hash_json_with_suite(
                    state.signing_key.crypto_suite(),
                    registration_credential,
                )
                .ok(),
                issued_at: draft.updated_at,
                updated_at: draft.updated_at,
            },
        )
        .await?;
    }
    Ok(())
}

async fn read_draft_core(
    state: &AppState,
    draft_id: &str,
) -> std::result::Result<DraftCoreRecord, ApiError> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT agent_did, did_document_json, did_document_hash, metadata_json,
                   review_status, workflow_status, created_at, updated_at
            FROM {REGISTRAR_DRAFT_CORE_TABLE}
            WHERE draft_id = ?
            "#
        ))
        .bind(draft_id)
        .fetch_optional(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let Some(row) = row else {
            return Err(ApiError::bad_request("draft_not_found"));
        };
        let did_document = match row.get::<Option<String>, _>(1) {
            Some(value) => Some(
                serde_json::from_str::<DidDocument>(&value)
                    .map_err(|err| ApiError::internal(err.into()))?,
            ),
            None => None,
        };
        let metadata =
            serde_json::from_str::<Value>(&row.get::<String, _>(3)).map_err(|err| ApiError::internal(err.into()))?;
        return Ok(DraftCoreRecord {
            draft_id: draft_id.to_owned(),
            agent_did: row.get::<String, _>(0),
            did_document,
            did_document_hash: row.get::<Option<String>, _>(2),
            metadata,
            review_status: row.get::<String, _>(4),
            status: row.get::<String, _>(5),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>(6))
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|err| ApiError::internal(err.into()))?,
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>(7))
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|err| ApiError::internal(err.into()))?,
        });
    }
    state
        .data
        .read(format!("drafts/{}.json", storage_safe_id(draft_id)))
        .map_err(|_| ApiError::bad_request("draft_not_found"))
}

async fn write_draft_core(
    state: &AppState,
    draft: &DraftCoreRecord,
) -> std::result::Result<(), ApiError> {
    if let Some(sqlite) = &state.sqlite {
        let did_document_json = draft
            .did_document
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|err| ApiError::internal(err.into()))?;
        let metadata_json =
            serde_json::to_string(&draft.metadata).map_err(|err| ApiError::internal(err.into()))?;
        sqlx::query(&format!(
            r#"
            INSERT INTO {REGISTRAR_DRAFT_CORE_TABLE}(
                draft_id, agent_did, did_document_json, did_document_hash,
                metadata_json, review_status, workflow_status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(draft_id)
            DO UPDATE SET
                agent_did = excluded.agent_did,
                did_document_json = excluded.did_document_json,
                did_document_hash = excluded.did_document_hash,
                metadata_json = excluded.metadata_json,
                review_status = excluded.review_status,
                workflow_status = excluded.workflow_status,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&draft.draft_id)
        .bind(&draft.agent_did)
        .bind(did_document_json)
        .bind(&draft.did_document_hash)
        .bind(metadata_json)
        .bind(&draft.review_status)
        .bind(&draft.status)
        .bind(draft.created_at.to_rfc3339())
        .bind(draft.updated_at.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        return Ok(());
    }
    state
        .data
        .write(
            format!("drafts/{}.json", storage_safe_id(&draft.draft_id)),
            draft,
        )
        .map_err(|err| ApiError::internal(err.into()))
}

async fn read_subject_control(
    state: &AppState,
    draft_id: &str,
) -> std::result::Result<SubjectControlRecord, ApiError> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT control_status, challenge_json, proof_bundle_json, verified_at, updated_at
            FROM {REGISTRAR_SUBJECT_CONTROL_TABLE}
            WHERE draft_id = ?
            "#
        ))
        .bind(draft_id)
        .fetch_optional(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let Some(row) = row else {
            return Err(ApiError::bad_request("subject_control_not_found"));
        };
        return Ok(SubjectControlRecord {
            draft_id: draft_id.to_owned(),
            subject_control_status: row.get::<String, _>(0),
            control_challenge: match row.get::<Option<String>, _>(1) {
                Some(value) => Some(
                    serde_json::from_str::<DidControlChallenge>(&value)
                        .map_err(|err| ApiError::internal(err.into()))?,
                ),
                None => None,
            },
            subject_control_proof: match row.get::<Option<String>, _>(2) {
                Some(value) => Some(
                    serde_json::from_str::<SubjectControlProofBundle>(&value)
                        .map_err(|err| ApiError::internal(err.into()))?,
                ),
                None => None,
            },
            verified_at: match row.get::<Option<String>, _>(3) {
                Some(value) => Some(
                    chrono::DateTime::parse_from_rfc3339(&value)
                        .map(|value| value.with_timezone(&chrono::Utc))
                        .map_err(|err| ApiError::internal(err.into()))?,
                ),
                None => None,
            },
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>(4))
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|err| ApiError::internal(err.into()))?,
        });
    }
    state
        .data
        .read(format!("subject-control/{}.json", storage_safe_id(draft_id)))
        .map_err(|_| ApiError::bad_request("subject_control_not_found"))
}

async fn write_subject_control(
    state: &AppState,
    record: &SubjectControlRecord,
) -> std::result::Result<(), ApiError> {
    if let Some(sqlite) = &state.sqlite {
        let challenge_json = record
            .control_challenge
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|err| ApiError::internal(err.into()))?;
        let proof_bundle_json = record
            .subject_control_proof
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|err| ApiError::internal(err.into()))?;
        sqlx::query(&format!(
            r#"
            INSERT INTO {REGISTRAR_SUBJECT_CONTROL_TABLE}(
                draft_id, control_status, challenge_json, proof_bundle_json, verified_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(draft_id)
            DO UPDATE SET
                control_status = excluded.control_status,
                challenge_json = excluded.challenge_json,
                proof_bundle_json = excluded.proof_bundle_json,
                verified_at = excluded.verified_at,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&record.draft_id)
        .bind(&record.subject_control_status)
        .bind(challenge_json)
        .bind(proof_bundle_json)
        .bind(record.verified_at.map(|value| value.to_rfc3339()))
        .bind(record.updated_at.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        return Ok(());
    }
    state
        .data
        .write(
            format!("subject-control/{}.json", storage_safe_id(&record.draft_id)),
            record,
        )
        .map_err(|err| ApiError::internal(err.into()))
}

async fn read_credential(
    state: &AppState,
    draft_id: &str,
) -> std::result::Result<CredentialRecord, ApiError> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT agent_did, credential_json, credential_hash, issued_at, updated_at
            FROM {REGISTRAR_CREDENTIAL_TABLE}
            WHERE draft_id = ?
            "#
        ))
        .bind(draft_id)
        .fetch_optional(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let Some(row) = row else {
            return Err(ApiError::bad_request("credential_not_found"));
        };
        return Ok(CredentialRecord {
            draft_id: draft_id.to_owned(),
            agent_did: row.get::<String, _>(0),
            registration_credential: serde_json::from_str::<Value>(&row.get::<String, _>(1))
                .map_err(|err| ApiError::internal(err.into()))?,
            credential_hash: row.get::<Option<String>, _>(2),
            issued_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>(3))
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|err| ApiError::internal(err.into()))?,
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>(4))
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|err| ApiError::internal(err.into()))?,
        });
    }
    state
        .data
        .read(format!("credentials/{}.json", storage_safe_id(draft_id)))
        .map_err(|_| ApiError::bad_request("credential_not_found"))
}

async fn write_credential(
    state: &AppState,
    record: &CredentialRecord,
) -> std::result::Result<(), ApiError> {
    if let Some(sqlite) = &state.sqlite {
        let credential_json = serde_json::to_string(&record.registration_credential)
            .map_err(|err| ApiError::internal(err.into()))?;
        sqlx::query(&format!(
            r#"
            INSERT INTO {REGISTRAR_CREDENTIAL_TABLE}(
                draft_id, agent_did, credential_json, credential_hash, issued_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(draft_id)
            DO UPDATE SET
                agent_did = excluded.agent_did,
                credential_json = excluded.credential_json,
                credential_hash = excluded.credential_hash,
                issued_at = excluded.issued_at,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&record.draft_id)
        .bind(&record.agent_did)
        .bind(credential_json)
        .bind(&record.credential_hash)
        .bind(record.issued_at.to_rfc3339())
        .bind(record.updated_at.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        return Ok(());
    }
    state
        .data
        .write(
            format!("credentials/{}.json", storage_safe_id(&record.draft_id)),
            record,
        )
        .map_err(|err| ApiError::internal(err.into()))
}

fn latest_timestamp(
    first: chrono::DateTime<chrono::Utc>,
    second: chrono::DateTime<chrono::Utc>,
    third: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    std::cmp::max(first, std::cmp::max(second, third))
}

async fn write_submission(state: &AppState, submission: &SubmissionRecord) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {REGISTRAR_SUBMISSION_TABLE}(
                submission_id, draft_id, agent_did, request_purpose, request_path,
                root_endpoint, request_body_hash, status, status_code,
                response_body_json, last_error, submitted_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(submission_id)
            DO UPDATE SET
                draft_id = excluded.draft_id,
                agent_did = excluded.agent_did,
                request_purpose = excluded.request_purpose,
                request_path = excluded.request_path,
                root_endpoint = excluded.root_endpoint,
                request_body_hash = excluded.request_body_hash,
                status = excluded.status,
                status_code = excluded.status_code,
                response_body_json = excluded.response_body_json,
                last_error = excluded.last_error,
                submitted_at = excluded.submitted_at,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&submission.submission_id)
        .bind(&submission.draft_id)
        .bind(&submission.agent_did)
        .bind(&submission.request_purpose)
        .bind(&submission.request_path)
        .bind(&submission.root_endpoint)
        .bind(&submission.request_body_hash)
        .bind(&submission.status)
        .bind(submission.status_code.map(i64::from))
        .bind(
            submission
                .response_body
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        )
        .bind(&submission.error)
        .bind(submission.submitted_at.to_rfc3339())
        .bind(submission.updated_at.to_rfc3339())
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    state.data.write(
        format!(
            "submissions/{}.json",
            storage_safe_id(&submission.submission_id)
        ),
        submission,
    )?;
    Ok(())
}

async fn read_submission_values(state: &AppState, did: Option<&str>) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = if let Some(target_did) = did {
            sqlx::query(&format!(
                r#"
                SELECT submission_id, draft_id, agent_did, request_purpose, request_path,
                       root_endpoint, request_body_hash, status, status_code,
                       response_body_json, last_error, submitted_at, updated_at
                FROM {REGISTRAR_SUBMISSION_TABLE}
                WHERE agent_did = ?
                ORDER BY submitted_at DESC, submission_id DESC
                "#
            ))
            .bind(target_did)
            .fetch_all(sqlite.pool())
            .await?
        } else {
            sqlx::query(&format!(
                r#"
                SELECT submission_id, draft_id, agent_did, request_purpose, request_path,
                       root_endpoint, request_body_hash, status, status_code,
                       response_body_json, last_error, submitted_at, updated_at
                FROM {REGISTRAR_SUBMISSION_TABLE}
                ORDER BY submitted_at DESC, submission_id DESC
                "#
            ))
            .fetch_all(sqlite.pool())
            .await?
        };
        return rows
            .into_iter()
            .map(|row| {
                Ok(json!({
                    "submissionId": row.get::<String, _>(0),
                    "draftId": row.get::<String, _>(1),
                    "agentDid": row.get::<String, _>(2),
                    "requestPurpose": row.get::<String, _>(3),
                    "requestPath": row.get::<String, _>(4),
                    "rootEndpoint": row.get::<String, _>(5),
                    "requestBodyHash": row.get::<String, _>(6),
                    "status": row.get::<String, _>(7),
                    "statusCode": row.get::<Option<i64>, _>(8),
                    "responseBody": match row.get::<Option<String>, _>(9) {
                        Some(value) => Some(serde_json::from_str::<Value>(&value)?),
                        None => None,
                    },
                    "error": row.get::<Option<String>, _>(10),
                    "submittedAt": row.get::<String, _>(11),
                    "updatedAt": row.get::<String, _>(12),
                }))
            })
            .collect::<Result<Vec<_>>>();
    }
    let dir = state.config.paths.data_dir.join("submissions");
    let mut values = read_record_values(&dir)?;
    if let Some(target_did) = did {
        values.retain(|value| value["agentDid"].as_str() == Some(target_did));
    }
    values.sort_by(|left, right| {
        right["submittedAt"]
            .as_str()
            .cmp(&left["submittedAt"].as_str())
            .then_with(|| right["submissionId"].as_str().cmp(&left["submissionId"].as_str()))
    });
    Ok(values)
}

fn acquire_submit_admission(
    state: &AppState,
    draft_id: &str,
) -> std::result::Result<SubmitAdmission, ApiError> {
    let permit = state
        .submit_limiter
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::too_many_requests(
                "submit_backpressure_active",
                state.config.security.submit.retry_after_seconds,
            )
        })?;
    let inflight_drafts = state.inflight_draft_submissions.clone();
    {
        let mut inflight = inflight_drafts
            .lock()
            .map_err(|_| ApiError::internal(anyhow::anyhow!("submit_admission_lock_poisoned")))?;
        if inflight.contains(draft_id) {
            drop(inflight);
            drop(permit);
            return Err(ApiError::too_many_requests(
                "draft_submission_in_progress",
                state.config.security.submit.retry_after_seconds,
            ));
        }
        inflight.insert(draft_id.to_owned());
    }
    Ok(SubmitAdmission {
        _permit: permit,
        inflight_drafts,
        draft_id: draft_id.to_owned(),
    })
}

fn validate_draft_record(draft: &DraftRecord) -> Value {
    let mut errors = Vec::new();
    match &draft.did_document {
        Some(doc) => {
            if doc.id != draft.agent_did {
                errors.push("did_document_id_mismatch".to_owned());
            }
            if let Err(err) = doc.validate_mvp() {
                errors.push(err.to_string());
            }
        }
        None => errors.push("missing_did_document".to_owned()),
    }
    json!({ "valid": errors.is_empty(), "errors": errors })
}

fn subject_control_policy(state: &AppState) -> DidControlPolicy {
    DidControlPolicy {
        challenge_ttl_seconds: state.config.security.subject_control.challenge_ttl_seconds,
        challenge_purpose: state
            .config
            .security
            .subject_control
            .challenge_purpose
            .clone(),
    }
}

fn hash_did_document(state: &AppState, did_document: &DidDocument) -> Result<String> {
    hash_json_with_suite(state.signing_key.crypto_suite(), did_document).map_err(Into::into)
}

fn parse_optional_did_document(
    value: Option<&Value>,
) -> std::result::Result<Option<DidDocument>, ApiError> {
    value.map(parse_did_document).transpose()
}

fn parse_did_document(value: &Value) -> std::result::Result<DidDocument, ApiError> {
    serde_json::from_value(value.clone())
        .map_err(|err| ApiError::bad_request(format!("invalid_did_document: {}", err)))
}

fn build_verify_and_publish_request(
    state: &AppState,
    draft: &DraftRecord,
) -> std::result::Result<VerifyAndPublishRequest, ApiError> {
    let did_document = draft
        .did_document
        .clone()
        .ok_or_else(|| ApiError::bad_request("draft_missing_did_document"))?;
    let credential = draft
        .registration_credential
        .clone()
        .ok_or_else(|| ApiError::bad_request("draft_missing_registration_credential"))?;
    let subject_control_proof = draft
        .subject_control_proof
        .clone()
        .ok_or_else(|| ApiError::bad_request("subject_control_proof_missing"))?;
    let did_document_hash = draft
        .did_document_hash
        .clone()
        .or_else(|| hash_did_document(state, &did_document).ok())
        .ok_or_else(|| ApiError::bad_request("invalid_did_document_hash"))?;
    let submission = AgentRegistrationSubmission {
        agent_did: draft.agent_did.clone(),
        did_document,
        did_document_hash,
        metadata: draft.metadata.clone(),
        registration_credential: credential,
        subject_control_proof,
    };
    let upstream_auth = create_signed_request_envelope(
        request_id("verify-and-publish"),
        state.config.security.upstream.protocol_label.clone(),
        PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
        "POST".to_owned(),
        PATH_ROOT_VERIFY_AND_PUBLISH.to_owned(),
        root_did_for_audience(state),
        &submission,
        state.did.clone(),
        format!("{}#key-1", state.did),
        &state.signing_key,
        request_nonce("verify-and-publish"),
    )
    .map_err(|err| ApiError::internal(err.into()))?;
    Ok(VerifyAndPublishRequest {
        registrar_did: state.did.clone(),
        submission,
        upstream_auth,
    })
}

fn build_submission_record(
    state: &AppState,
    draft: &DraftRecord,
    request: &VerifyAndPublishRequest,
) -> SubmissionRecord {
    let now = chrono::Utc::now();
    SubmissionRecord {
        submission_id: request.upstream_auth.request_id.clone(),
        draft_id: draft.draft_id.clone(),
        agent_did: draft.agent_did.clone(),
        request_purpose: request.upstream_auth.purpose.clone(),
        request_path: request.upstream_auth.path.clone(),
        root_endpoint: state.config.upstream.root_endpoint.clone(),
        request_body_hash: request.upstream_auth.body_hash.clone(),
        status: "ready".to_owned(),
        status_code: None,
        response_body: None,
        error: None,
        submitted_at: now,
        updated_at: now,
    }
}

fn root_did_for_audience(state: &AppState) -> String {
    state.config.security.upstream.root_did.clone()
}

fn list_json_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            files.push(path);
        }
    }
    Ok(files)
}

fn read_record_values(dir: &Path) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    for path in list_json_files(dir)? {
        let text = fs::read_to_string(path)?;
        values.push(serde_json::from_str(&text)?);
    }
    Ok(values)
}

fn storage_safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

async fn mirror_sqlite_json<T: Serialize>(
    state: &AppState,
    namespace: &str,
    key: &str,
    value: &T,
) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlite.upsert_json(namespace, key, value).await?;
    }
    Ok(())
}

fn spawn_draft_projection_refresh(state: AppState, draft_id: String) {
    if state.sqlite.is_some() {
        return;
    }
    tokio::spawn(async move {
        if let Ok(draft) = read_draft(&state, &draft_id).await {
            let _ = mirror_sqlite_json(&state, "registrar.drafts", &draft_id, &draft).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    use oan_core::{AgentDescription, AnsMetadata, CryptoSuite, ServiceEndpoint};
    use oan_crypto::{
        build_data_integrity_proof, generate_ed25519_keypair, public_key_jwk, public_key_multibase,
        SigningKey as OanSigningKey, VerifyingKey as OanVerifyingKey,
    };
    use reqwest::Client;
    use tempfile::tempdir;

    fn sample_did_document_with_key(
        did: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> DidDocument {
        let verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256Legacy,
            key: signing_key.verifying_key(),
        };
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![oan_core::VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![format!("{did}#key-1")],
            assertion_method: vec![format!("{did}#key-1")],
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
        }
    }

    fn sample_did_document(did: &str) -> DidDocument {
        sample_did_document_with_key(did, &generate_ed25519_keypair())
    }

    fn app_state(dir: &std::path::Path) -> AppState {
        AppState {
            data: JsonStore::new(dir),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8001,
                },
                cors: CorsConfig::default(),
                security: SecurityConfig {
                    subject_control: SubjectControlConfig::default(),
                    upstream: UpstreamSecurityConfig {
                        protocol_label: default_protocol_label(),
                        root_did: default_root_did(),
                    },
                    submit: SubmitSecurityConfig::default(),
                },
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                },
                paths: PathConfig {
                    data_dir: dir.to_path_buf(),
                    records_dir: dir.join("records"),
                    keys_dir: dir.join("keys"),
                    database_url: None,
                },
            },
            did: "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: oan_crypto::generate_ed25519_keypair(),
            },
            sqlite: None,
            client: reqwest::Client::new(),
            submit_limiter: Arc::new(Semaphore::new(default_submit_max_in_flight())),
            inflight_draft_submissions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    async fn app_state_with_sqlite(dir: &std::path::Path) -> AppState {
        let mut state = app_state(dir);
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.join("registrar-test.db").display()
        ))
        .await
        .unwrap();
        initialize_registrar_sqlite(&sqlite).await.unwrap();
        state.sqlite = Some(sqlite);
        state
    }

    fn app_state_with_root(dir: &std::path::Path, root_endpoint: &str) -> AppState {
        let mut state = app_state(dir);
        state.config.upstream.root_endpoint = root_endpoint.to_owned();
        state
    }

    async fn spawn_test_root_server(
        status: StatusCode,
        body: Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        async fn handler(
            State((status, body)): State<(StatusCode, Value)>,
        ) -> (StatusCode, Json<Value>) {
            (status, Json(body))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/root/agents/verify-and-publish", post(handler))
            .with_state((status, body));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{}", addr), handle)
    }

    async fn spawn_delayed_root_server(
        delay_ms: u64,
        status: StatusCode,
        body: Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        async fn handler(
            State((delay_ms, status, body)): State<(u64, StatusCode, Value)>,
        ) -> (StatusCode, Json<Value>) {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            (status, Json(body))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/root/agents/verify-and-publish", post(handler))
            .with_state((delay_ms, status, body));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{}", addr), handle)
    }

    async fn spawn_registrar_test_server(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/agents/draft/{draftId}/submit", post(api_submit_draft))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{}", addr), handle)
    }

    #[tokio::test]
    async fn api_status_counts_drafts_and_records() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let safe = storage_safe_id(did);
        state
            .data
            .write(format!("records/{}.json", safe), &json!({"did": did}))
            .unwrap();
        state
            .data
            .write(
                format!("drafts/{}.json", storage_safe_id("draft-1")),
                &json!({"draftId": "draft-1", "agentDid": did}),
            )
            .unwrap();

        let response = api_status(State(state)).await.unwrap();
        assert_eq!(response.0["registeredAgentCount"], 1);
        assert_eq!(response.0["draftCount"], 1);
    }

    #[tokio::test]
    async fn api_create_validate_and_read_draft() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let response = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": sample_did_document_with_key(did, &agent_key),
                "registrationCredential": {"issuer": "did:ans:AGRG:efregistrarregistrar1234", "subject": did, "status": "active"},
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        assert_eq!(response.0["status"], "created");

        let validation = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        assert!(validation.0["validation"]["valid"].as_bool().unwrap());

        state
            .data
            .write(
                format!("records/{}.json", storage_safe_id(did)),
                &json!({"did": did, "status": "submitted"}),
            )
            .unwrap();
        let list = api_agents(State(state.clone())).await.unwrap();
        assert_eq!(list.0["count"], 1);

        let detail = api_agent_detail(State(state.clone()), AxumPath(did.to_owned()))
            .await
            .unwrap();
        assert!(detail.0["record"].is_object());

        let submissions = api_agent_submissions(State(state), AxumPath(did.to_owned()))
            .await
            .unwrap();
        assert_eq!(submissions.0["count"], 0);
    }

    #[tokio::test]
    async fn api_create_draft_rejects_invalid_did_document_shape() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";

        let response = api_create_draft(
            State(state),
            Json(json!({
                "draftId": "draft-invalid",
                "agentDid": did,
                "didDocument": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": did,
                    "verificationMethod": [],
                    "authentication": [],
                    "assertionMethod": [],
                    "service": [],
                    "ansMetadata": {
                        "subjectType": "Agent",
                        "identityType": "service-agent",
                        "addressBindings": []
                    }
                }
            })),
        )
        .await;

        let error = response.unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.starts_with("invalid_did_document:"));
    }

    #[tokio::test]
    async fn issue_registration_credential_requires_control_proof() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": sample_did_document_with_key(did, &agent_key),
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();

        let response =
            api_issue_registration_credential(State(state), AxumPath("draft-1".to_owned())).await;
        assert_eq!(
            response.unwrap_err().message,
            "subject_control_not_verified"
        );
    }

    #[tokio::test]
    async fn control_proof_flow_issues_bound_registration_credential() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let proof_response = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        assert_eq!(proof_response.0["status"], "control-verified");

        let issue_response =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        assert_eq!(issue_response.0["status"], "issued");
        assert_eq!(
            issue_response.0["credential"]["claims"]["didDocumentHash"],
            read_draft(&state, "draft-1")
                .await
                .unwrap()
                .did_document_hash
                .unwrap()
        );
        assert_eq!(
            issue_response.0["credential"]["claims"]["registrationBinding"]["subjectDid"],
            did
        );
        assert_eq!(
            issue_response.0["credential"]["claims"]["registrationBinding"]["registrarDid"],
            state.did
        );
        assert_eq!(
            issue_response.0["credential"]["claims"]["registrationBinding"]["purpose"],
            state.config.security.subject_control.challenge_purpose
        );
    }

    #[tokio::test]
    async fn submit_draft_requires_subject_control_proof() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": sample_did_document(did),
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();

        let response = api_submit_draft(State(state), AxumPath("draft-1".to_owned())).await;
        assert_eq!(
            response.unwrap_err().message,
            "draft_missing_registration_credential"
        );
    }

    #[tokio::test]
    async fn submit_backpressure_returns_429_when_in_flight_limit_is_exhausted() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.security.submit.max_in_flight = 1;
        state.config.security.submit.retry_after_seconds = 7;
        state.submit_limiter = Arc::new(Semaphore::new(1));
        let permit = state.submit_limiter.clone().try_acquire_owned().unwrap();

        let error = api_submit_draft(State(state), AxumPath("draft-1".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.message, "submit_backpressure_active");
        assert_eq!(error.retry_after_seconds, Some(7));

        drop(permit);
    }

    #[tokio::test]
    async fn submit_backpressure_rejects_same_draft_while_submission_is_in_progress() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.security.submit.retry_after_seconds = 5;
        state.submit_limiter = Arc::new(Semaphore::new(2));
        let permit = state.submit_limiter.clone().try_acquire_owned().unwrap();
        state
            .inflight_draft_submissions
            .lock()
            .unwrap()
            .insert("draft-1".to_owned());

        let error = api_submit_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.message, "draft_submission_in_progress");
        assert_eq!(error.retry_after_seconds, Some(5));

        drop(permit);
        state
            .inflight_draft_submissions
            .lock()
            .unwrap()
            .remove("draft-1");
    }

    #[tokio::test]
    async fn too_many_requests_response_carries_retry_after_header() {
        let error = ApiError::too_many_requests("submit_backpressure_active", 9);
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get("Retry-After").unwrap(),
            "9"
        );
    }

    #[tokio::test]
    async fn build_verify_and_publish_request_binds_submission_and_upstream_auth() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let _ =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();

        let draft = read_draft(&state, "draft-1").await.unwrap();
        let request = build_verify_and_publish_request(&state, &draft).unwrap();
        assert_eq!(request.registrar_did, state.did);
        assert_eq!(request.submission.agent_did, did);
        assert_eq!(
            request.upstream_auth.aud,
            state.config.security.upstream.root_did
        );
        assert_eq!(request.upstream_auth.purpose, PURPOSE_VERIFY_AND_PUBLISH);
        assert_eq!(request.upstream_auth.path, PATH_ROOT_VERIFY_AND_PUBLISH);
        assert_eq!(
            request.submission.subject_control_proof.challenge.purpose,
            state.config.security.subject_control.challenge_purpose
        );
    }

    #[tokio::test]
    async fn write_submission_persists_independent_submission_record() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let draft = DraftRecord {
            draft_id: "draft-1".to_owned(),
            agent_did: did.to_owned(),
            did_document: Some(sample_did_document(did)),
            did_document_hash: Some("hash-1".to_owned()),
            registration_credential: Some(json!({"issuer": state.did, "subject": did})),
            metadata: json!({"source": "test"}),
            review_status: "validated".to_owned(),
            subject_control_status: "verified".to_owned(),
            control_challenge: None,
            subject_control_proof: Some(SubjectControlProofBundle {
                challenge: DidControlChallenge {
                    challenge_id: "challenge-1".to_owned(),
                    draft_id: "draft-1".to_owned(),
                    subject_did: did.to_owned(),
                    registrar_did: state.did.clone(),
                    did_document_hash: "hash-1".to_owned(),
                    verification_method: format!("{did}#key-1"),
                    purpose: state.config.security.subject_control.challenge_purpose.clone(),
                    nonce: "nonce-1".to_owned(),
                    issued_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now(),
                },
                proof: oan_core::DataIntegrityProof {
                    proof_type: "DataIntegrityProof".to_owned(),
                    creator: format!("{did}#key-1"),
                    created: chrono::Utc::now(),
                    proof_purpose: "assertionMethod".to_owned(),
                    proof_value: "proof-1".to_owned(),
                    crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                    hash_algorithm: Some("SHA-256".to_owned()),
                    verification_method: Some(format!("{did}#key-1")),
                },
                verified_at: Some(chrono::Utc::now()),
                verified_verification_method: Some(format!("{did}#key-1")),
                proof_hash: Some("proof-hash-1".to_owned()),
            }),
            status: "credential-issued".to_owned(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let request = build_verify_and_publish_request(&state, &draft).unwrap();
        let submission = build_submission_record(&state, &draft, &request);
        write_submission(&state, &submission).await.unwrap();

        let submissions = read_submission_values(&state, Some(did)).await.unwrap();
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0]["submissionId"], submission.submission_id);
        assert_eq!(submissions[0]["status"], "ready");
    }

    #[tokio::test]
    async fn draft_serialization_no_longer_carries_submission_history_fields() {
        let draft = DraftRecord {
            draft_id: "draft-1".to_owned(),
            agent_did: "did:ans:AGDM:test".to_owned(),
            did_document: None,
            did_document_hash: None,
            registration_credential: None,
            metadata: json!({}),
            review_status: default_review_status(),
            subject_control_status: default_subject_control_status(),
            control_challenge: None,
            subject_control_proof: None,
            status: "draft".to_owned(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let value = serde_json::to_value(&draft).unwrap();
        assert!(value.get("submissionCount").is_none());
        assert!(value.get("lastSubmissionStatus").is_none());
        assert!(value.get("lastSubmissionResponse").is_none());
    }

    #[tokio::test]
    async fn subject_control_and_credential_are_persisted_in_dedicated_namespaces() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let issue_response =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();

        let subject_control: SubjectControlRecord = state
            .data
            .read(format!(
                "subject-control/{}.json",
                storage_safe_id("draft-1")
            ))
            .unwrap();
        assert_eq!(subject_control.subject_control_status, "verified");
        assert!(subject_control.subject_control_proof.is_some());

        let credential: CredentialRecord = state
            .data
            .read(format!("credentials/{}.json", storage_safe_id("draft-1")))
            .unwrap();
        assert_eq!(credential.agent_did, did);
        assert_eq!(
            credential.registration_credential,
            issue_response.0["credential"]
        );

        let aggregated = read_draft(&state, "draft-1").await.unwrap();
        assert_eq!(aggregated.subject_control_status, "verified");
        assert_eq!(
            aggregated.registration_credential.unwrap(),
            issue_response.0["credential"]
        );
    }

    #[tokio::test]
    async fn submit_draft_records_transport_failure_without_corrupting_checkpoints() {
        let dir = tempdir().unwrap();
        let state = app_state_with_root(dir.path(), "http://127.0.0.1:9");
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let issue_response =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();

        let error = api_submit_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);

        let submissions = read_submission_values(&state, Some(did)).await.unwrap();
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0]["status"], "transport-failed");
        assert!(submissions[0]["error"].as_str().is_some());

        let draft = read_draft(&state, "draft-1").await.unwrap();
        assert_eq!(draft.status, "submit-failed");
        assert_eq!(
            draft.registration_credential.unwrap(),
            issue_response.0["credential"]
        );
        let subject_control: SubjectControlRecord = state
            .data
            .read(format!(
                "subject-control/{}.json",
                storage_safe_id("draft-1")
            ))
            .unwrap();
        assert_eq!(subject_control.subject_control_status, "verified");
    }

    #[tokio::test]
    async fn submit_draft_times_out_slow_root_and_releases_capacity() {
        let dir = tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        let mut state = app_state_with_root(dir.path(), &format!("http://{}", addr));
        state.config.security.submit.upstream_timeout_ms = 50;
        state.config.security.submit.max_in_flight = 1;
        state.submit_limiter = Arc::new(Semaphore::new(1));
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let _ =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();

        let error = api_submit_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(state.submit_limiter.available_permits(), 1);
        assert!(
            state
                .inflight_draft_submissions
                .lock()
                .unwrap()
                .is_empty()
        );

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submit_http_flow_shows_saturation_then_429_then_recovers() {
        let dir = tempdir().unwrap();
        let (root_endpoint, root_server) = spawn_delayed_root_server(
            200,
            StatusCode::OK,
            json!({"status": "accepted"}),
        )
        .await;
        let mut state = app_state_with_root(dir.path(), &root_endpoint);
        state.config.security.submit.max_in_flight = 1;
        state.config.security.submit.retry_after_seconds = 2;
        state.submit_limiter = Arc::new(Semaphore::new(1));
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let _ =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();

        let (registrar_base, registrar_server) = spawn_registrar_test_server(state.clone()).await;
        let client = Client::new();
        let submit_url = format!("{registrar_base}/agents/draft/draft-1/submit");

        let first = {
            let client = client.clone();
            let submit_url = submit_url.clone();
            tokio::spawn(async move { client.post(&submit_url).send().await.unwrap() })
        };

        tokio::time::sleep(Duration::from_millis(30)).await;

        let second = client.post(&submit_url).send().await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.headers().get("Retry-After").unwrap(), "2");
        let second_body: Value = second.json().await.unwrap();
        assert_eq!(second_body["error"], "submit_backpressure_active");

        let first = first.await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let third = client.post(&submit_url).send().await.unwrap();
        assert_eq!(third.status(), StatusCode::OK);

        let submissions = read_submission_values(&state, Some(did)).await.unwrap();
        let accepted_count = submissions
            .iter()
            .filter(|item| item["status"] == "accepted")
            .count();
        assert_eq!(accepted_count, 2);

        registrar_server.abort();
        root_server.abort();
    }

    #[tokio::test]
    async fn submit_draft_records_root_rejection_without_marking_submitted() {
        let dir = tempdir().unwrap();
        let (root_endpoint, server) = spawn_test_root_server(
            StatusCode::BAD_REQUEST,
            json!({"error": "root_rejected"}),
        )
        .await;
        let state = app_state_with_root(dir.path(), &root_endpoint);
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let _ =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();

        let error = api_submit_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        let submissions = read_submission_values(&state, Some(did)).await.unwrap();
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0]["status"], "rejected");
        assert_eq!(submissions[0]["statusCode"], 400);
        assert_eq!(submissions[0]["responseBody"]["error"], "root_rejected");

        let draft = read_draft(&state, "draft-1").await.unwrap();
        assert_eq!(draft.status, "submit-failed");
        server.abort();
    }

    #[tokio::test]
    async fn request_can_be_rebuilt_from_checkpoint_files_only() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let now = chrono::Utc::now();
        write_draft_core(
            &state,
            &DraftCoreRecord {
                draft_id: "draft-1".to_owned(),
                agent_did: did.to_owned(),
                did_document: Some(sample_did_document(did)),
                did_document_hash: Some("hash-1".to_owned()),
                metadata: json!({"source": "checkpoint"}),
                review_status: "validated".to_owned(),
                status: "credential-issued".to_owned(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
        write_subject_control(
            &state,
            &SubjectControlRecord {
                draft_id: "draft-1".to_owned(),
                subject_control_status: "verified".to_owned(),
                control_challenge: Some(DidControlChallenge {
                    challenge_id: "challenge-1".to_owned(),
                    draft_id: "draft-1".to_owned(),
                    subject_did: did.to_owned(),
                    registrar_did: state.did.clone(),
                    did_document_hash: "hash-1".to_owned(),
                    verification_method: format!("{did}#key-1"),
                    purpose: state.config.security.subject_control.challenge_purpose.clone(),
                    nonce: "nonce-1".to_owned(),
                    issued_at: now,
                    expires_at: now,
                }),
                subject_control_proof: Some(SubjectControlProofBundle {
                    challenge: DidControlChallenge {
                        challenge_id: "challenge-1".to_owned(),
                        draft_id: "draft-1".to_owned(),
                        subject_did: did.to_owned(),
                        registrar_did: state.did.clone(),
                        did_document_hash: "hash-1".to_owned(),
                        verification_method: format!("{did}#key-1"),
                        purpose: state.config.security.subject_control.challenge_purpose.clone(),
                        nonce: "nonce-1".to_owned(),
                        issued_at: now,
                        expires_at: now,
                    },
                    proof: oan_core::DataIntegrityProof {
                        proof_type: "DataIntegrityProof".to_owned(),
                        creator: format!("{did}#key-1"),
                        created: now,
                        proof_purpose: "assertionMethod".to_owned(),
                        proof_value: "proof-1".to_owned(),
                        crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                        hash_algorithm: Some("SHA-256".to_owned()),
                        verification_method: Some(format!("{did}#key-1")),
                    },
                    verified_at: Some(now),
                    verified_verification_method: Some(format!("{did}#key-1")),
                    proof_hash: Some("proof-hash-1".to_owned()),
                }),
                verified_at: Some(now),
                updated_at: now,
            },
        )
        .await
        .unwrap();
        write_credential(
            &state,
            &CredentialRecord {
                draft_id: "draft-1".to_owned(),
                agent_did: did.to_owned(),
                registration_credential: json!({"issuer": state.did, "subject": did}),
                credential_hash: Some("credential-hash-1".to_owned()),
                issued_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

        let draft = read_draft(&state, "draft-1").await.unwrap();
        let request = build_verify_and_publish_request(&state, &draft).unwrap();
        assert_eq!(request.submission.agent_did, did);
        assert_eq!(request.submission.did_document_hash, "hash-1");
        assert_eq!(
            request.submission.registration_credential["subject"],
            did
        );
    }

    #[tokio::test]
    async fn metadata_update_does_not_rewrite_existing_credential_checkpoint() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "ui"}
            })),
        )
        .await
        .unwrap();
        let _ = api_validate_draft(State(state.clone()), AxumPath("draft-1".to_owned()))
            .await
            .unwrap();
        let challenge_response =
            api_create_control_challenge(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let challenge: DidControlChallenge =
            serde_json::from_value(challenge_response.0["challenge"].clone()).unwrap();
        let proof = build_data_integrity_proof(
            &challenge,
            did.to_owned(),
            format!("{did}#key-1"),
            &OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256Legacy,
                key: agent_key.clone(),
            },
        )
        .unwrap();
        let _ = api_submit_control_proof(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({ "proof": proof })),
        )
        .await
        .unwrap();
        let _ =
            api_issue_registration_credential(State(state.clone()), AxumPath("draft-1".to_owned()))
                .await
                .unwrap();
        let credential_before: CredentialRecord = state
            .data
            .read(format!("credentials/{}.json", storage_safe_id("draft-1")))
            .unwrap();

        let _ = api_update_draft(
            State(state.clone()),
            AxumPath("draft-1".to_owned()),
            Json(json!({
                "metadata": {"source": "updated-ui", "note": "only-metadata"}
            })),
        )
        .await
        .unwrap();

        let credential_after: CredentialRecord = state
            .data
            .read(format!("credentials/{}.json", storage_safe_id("draft-1")))
            .unwrap();
        assert_eq!(
            credential_before.registration_credential,
            credential_after.registration_credential
        );
        assert_eq!(
            credential_before.credential_hash,
            credential_after.credential_hash
        );
    }

    #[tokio::test]
    async fn sqlite_checkpoint_rows_drive_aggregated_draft_and_submission_views() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let sqlite = state.sqlite.as_ref().unwrap();
        let now = chrono::Utc::now();
        let did_document_json = serde_json::to_string(&sample_did_document(did)).unwrap();
        let metadata_json = serde_json::to_string(&json!({"source": "sqlite"})).unwrap();
        let challenge_json = serde_json::to_string(&DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: did.to_owned(),
            registrar_did: state.did.clone(),
            did_document_hash: "hash-1".to_owned(),
            verification_method: format!("{did}#key-1"),
            purpose: state.config.security.subject_control.challenge_purpose.clone(),
            nonce: "nonce-1".to_owned(),
            issued_at: now,
            expires_at: now,
        })
        .unwrap();
        let proof_bundle_json = serde_json::to_string(&SubjectControlProofBundle {
            challenge: DidControlChallenge {
                challenge_id: "challenge-1".to_owned(),
                draft_id: "draft-1".to_owned(),
                subject_did: did.to_owned(),
                registrar_did: state.did.clone(),
                did_document_hash: "hash-1".to_owned(),
                verification_method: format!("{did}#key-1"),
                purpose: state.config.security.subject_control.challenge_purpose.clone(),
                nonce: "nonce-1".to_owned(),
                issued_at: now,
                expires_at: now,
            },
            proof: oan_core::DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_owned(),
                creator: format!("{did}#key-1"),
                created: now,
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: "proof-1".to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                hash_algorithm: Some("SHA-256".to_owned()),
                verification_method: Some(format!("{did}#key-1")),
            },
            verified_at: Some(now),
            verified_verification_method: Some(format!("{did}#key-1")),
            proof_hash: Some("proof-hash-1".to_owned()),
        })
        .unwrap();
        let credential_json = serde_json::to_string(&AgentRegistrationCredential::unsigned(
            state.did.clone(),
            did.to_owned(),
            json!({"didDocumentHash": "hash-1"}),
        ))
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {REGISTRAR_DRAFT_CORE_TABLE}(draft_id, agent_did, did_document_json, did_document_hash, metadata_json, review_status, workflow_status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind("draft-1")
        .bind(did)
        .bind(did_document_json)
        .bind("hash-1")
        .bind(metadata_json)
        .bind("validated")
        .bind("credential-issued")
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {REGISTRAR_SUBJECT_CONTROL_TABLE}(draft_id, control_status, challenge_json, proof_bundle_json, verified_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        ))
        .bind("draft-1")
        .bind("verified")
        .bind(challenge_json)
        .bind(proof_bundle_json)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {REGISTRAR_CREDENTIAL_TABLE}(draft_id, agent_did, credential_json, credential_hash, issued_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        ))
        .bind("draft-1")
        .bind(did)
        .bind(credential_json)
        .bind("credential-hash-1")
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .unwrap();
        let core_row = sqlx::query(&format!(
            "SELECT review_status, workflow_status FROM {REGISTRAR_DRAFT_CORE_TABLE} WHERE draft_id = ?"
        ))
        .bind("draft-1")
        .fetch_one(sqlite.pool())
        .await
        .unwrap();
        assert_eq!(core_row.get::<String, _>(0), "validated");
        assert_eq!(core_row.get::<String, _>(1), "credential-issued");

        let control_row = sqlx::query(&format!(
            "SELECT control_status FROM {REGISTRAR_SUBJECT_CONTROL_TABLE} WHERE draft_id = ?"
        ))
        .bind("draft-1")
        .fetch_one(sqlite.pool())
        .await
        .unwrap();
        assert_eq!(control_row.get::<String, _>(0), "verified");

        let credential_row = sqlx::query(&format!(
            "SELECT credential_json FROM {REGISTRAR_CREDENTIAL_TABLE} WHERE draft_id = ?"
        ))
        .bind("draft-1")
        .fetch_one(sqlite.pool())
        .await
        .unwrap();
        let credential_json: Value =
            serde_json::from_str(&credential_row.get::<String, _>(0)).unwrap();
        assert_eq!(credential_json["subject"], did);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_create_draft_persists_did_document_in_primary_table() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let did_document = sample_did_document_with_key(did, &agent_key);
        let did_document_id = did_document.id.clone();

        let response = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-sqlite",
                "agentDid": did,
                "didDocument": did_document,
                "metadata": {"source": "sqlite-test"}
            })),
        )
        .await
        .unwrap();

        assert_eq!(response.0["draft"]["didDocument"]["id"], did_document_id);

        let stored = sqlx::query_scalar::<_, String>(&format!(
            "SELECT did_document_json FROM {REGISTRAR_DRAFT_CORE_TABLE} WHERE draft_id = ?"
        ))
        .bind("draft-sqlite")
        .fetch_one(state.sqlite.as_ref().unwrap().pool())
        .await
        .unwrap();
        let stored_document: DidDocument = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored_document.id, did);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_update_draft_rejects_invalid_did_document_shape() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let did = "did:ans:AGDM:efserviceagentservice1234";
        let agent_key = generate_ed25519_keypair();
        let _ = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-update-invalid",
                "agentDid": did,
                "didDocument": sample_did_document_with_key(did, &agent_key),
                "metadata": {"source": "sqlite-test"}
            })),
        )
        .await
        .unwrap();

        let response = api_update_draft(
            State(state),
            AxumPath("draft-update-invalid".to_owned()),
            Json(json!({
                "didDocument": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": did,
                    "verificationMethod": [],
                    "authentication": [],
                    "assertionMethod": [],
                    "service": [],
                    "ansMetadata": {
                        "subjectType": "Agent",
                        "identityType": "service-agent",
                        "addressBindings": []
                    }
                }
            })),
        )
        .await;

        let error = response.unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.starts_with("invalid_did_document:"));
    }

    #[tokio::test]
    async fn sqlite_submission_rows_are_sorted_by_submitted_at_desc() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let sqlite = state.sqlite.as_ref().unwrap();
        sqlx::query(&format!(
            "INSERT INTO {REGISTRAR_SUBMISSION_TABLE}(submission_id, draft_id, agent_did, request_purpose, request_path, root_endpoint, request_body_hash, status, status_code, response_body_json, last_error, submitted_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind("sub-1")
        .bind("draft-1")
        .bind("did:ans:AGDM:a")
        .bind("verify-and-publish")
        .bind(PATH_ROOT_VERIFY_AND_PUBLISH)
        .bind("http://root")
        .bind("hash-1")
        .bind("accepted")
        .bind(200_i64)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind("2026-01-01T00:00:00Z")
        .bind("2026-01-01T00:00:00Z")
        .execute(sqlite.pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {REGISTRAR_SUBMISSION_TABLE}(submission_id, draft_id, agent_did, request_purpose, request_path, root_endpoint, request_body_hash, status, status_code, response_body_json, last_error, submitted_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind("sub-2")
        .bind("draft-2")
        .bind("did:ans:AGDM:a")
        .bind("verify-and-publish")
        .bind(PATH_ROOT_VERIFY_AND_PUBLISH)
        .bind("http://root")
        .bind("hash-2")
        .bind("rejected")
        .bind(400_i64)
        .bind(Some("{\"error\":\"reject\"}".to_owned()))
        .bind(Option::<String>::None)
        .bind("2026-01-02T00:00:00Z")
        .bind("2026-01-02T00:00:00Z")
        .execute(sqlite.pool())
        .await
        .unwrap();

        let rows = sqlx::query(&format!(
            "SELECT submission_id FROM {REGISTRAR_SUBMISSION_TABLE} WHERE agent_did = ? ORDER BY submitted_at DESC, submission_id DESC"
        ))
        .bind("did:ans:AGDM:a")
        .fetch_all(sqlite.pool())
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>(0), "sub-2");
        assert_eq!(rows[1].get::<String, _>(0), "sub-1");
    }

    #[tokio::test]
    async fn sqlite_subject_control_row_round_trips_full_bundle() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let now = chrono::Utc::now();
        let record = SubjectControlRecord {
            draft_id: "draft-1".to_owned(),
            subject_control_status: "verified".to_owned(),
            control_challenge: Some(DidControlChallenge {
                challenge_id: "challenge-1".to_owned(),
                draft_id: "draft-1".to_owned(),
                subject_did: "did:ans:AGDM:test".to_owned(),
                registrar_did: state.did.clone(),
                did_document_hash: "hash-1".to_owned(),
                verification_method: "did:ans:AGDM:test#key-1".to_owned(),
                purpose: state.config.security.subject_control.challenge_purpose.clone(),
                nonce: "nonce-1".to_owned(),
                issued_at: now,
                expires_at: now,
            }),
            subject_control_proof: Some(SubjectControlProofBundle {
                challenge: DidControlChallenge {
                    challenge_id: "challenge-1".to_owned(),
                    draft_id: "draft-1".to_owned(),
                    subject_did: "did:ans:AGDM:test".to_owned(),
                    registrar_did: state.did.clone(),
                    did_document_hash: "hash-1".to_owned(),
                    verification_method: "did:ans:AGDM:test#key-1".to_owned(),
                    purpose: state.config.security.subject_control.challenge_purpose.clone(),
                    nonce: "nonce-1".to_owned(),
                    issued_at: now,
                    expires_at: now,
                },
                proof: oan_core::DataIntegrityProof {
                    proof_type: "DataIntegrityProof".to_owned(),
                    creator: "did:ans:AGDM:test#key-1".to_owned(),
                    created: now,
                    proof_purpose: "assertionMethod".to_owned(),
                    proof_value: "proof-1".to_owned(),
                    crypto_suite: Some(CryptoSuite::Ed25519Sha256Legacy),
                    hash_algorithm: Some("SHA-256".to_owned()),
                    verification_method: Some("did:ans:AGDM:test#key-1".to_owned()),
                },
                verified_at: Some(now),
                verified_verification_method: Some("did:ans:AGDM:test#key-1".to_owned()),
                proof_hash: Some("proof-hash-1".to_owned()),
            }),
            verified_at: Some(now),
            updated_at: now,
        };
        let sqlite = state.sqlite.as_ref().unwrap();
        let challenge_json = serde_json::to_string(record.control_challenge.as_ref().unwrap()).unwrap();
        let proof_bundle_json = serde_json::to_string(record.subject_control_proof.as_ref().unwrap()).unwrap();
        sqlx::query(&format!(
            "INSERT INTO {REGISTRAR_SUBJECT_CONTROL_TABLE}(draft_id, control_status, challenge_json, proof_bundle_json, verified_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        ))
        .bind("draft-1")
        .bind("verified")
        .bind(challenge_json)
        .bind(proof_bundle_json)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(sqlite.pool())
        .await
        .unwrap();
        let row = sqlx::query(&format!(
            "SELECT control_status, challenge_json, proof_bundle_json FROM {REGISTRAR_SUBJECT_CONTROL_TABLE} WHERE draft_id = ?"
        ))
        .bind("draft-1")
        .fetch_one(sqlite.pool())
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>(0), "verified");
        assert!(row.get::<Option<String>, _>(1).is_some());
        assert!(row.get::<Option<String>, _>(2).is_some());
    }
}
