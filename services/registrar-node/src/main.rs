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
    routing::{get, post, put},
    Json, Router,
};
use oan_core::{CapabilityTagTree, DidDocument};
use oan_crypto::hash_json;
use oan_protocol::{HealthResponse, VerifyAndPublishRequest};
use oan_storage::{did_to_file_name, JsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    records_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    did: String,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DraftRecord {
    #[serde(rename = "draftId")]
    draft_id: String,
    #[serde(rename = "agentDid")]
    agent_did: String,
    #[serde(rename = "didDocument")]
    did_document: Option<DidDocument>,
    #[serde(rename = "registrationCredential")]
    registration_credential: Option<Value>,
    metadata: Value,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
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
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        did: did_doc.id,
        client: reqwest::Client::new(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/registrar/did", get(registrar_did_document))
        .route("/agents/register", post(register_agent))
        .route("/agents/update", post(register_agent))
        .route("/api/v1/registrar/status", get(api_status))
        .route(
            "/api/v1/registrar/root-authorization",
            get(api_root_authorization),
        )
        .route("/api/v1/agents", get(api_agents))
        .route("/api/v1/agents/{did}", get(api_agent_detail))
        .route("/api/v1/agents/{did}/submissions", get(api_agent_submissions))
        .route("/api/v1/agents/draft", post(api_create_draft))
        .route("/api/v1/agents/draft/{draftId}", put(api_update_draft))
        .route("/api/v1/agents/draft/{draftId}/validate", post(api_validate_draft))
        .route(
            "/api/v1/agents/draft/{draftId}/issue-registration-credential",
            post(api_issue_registration_credential),
        )
        .route("/api/v1/agents/draft/{draftId}/submit", post(api_submit_draft))
        .route("/api/v1/agents/{did}/resubmit", post(api_resubmit_agent))
        .route("/api/v1/capability-tree", get(api_capability_tree))
        .route("/api/v1/capability-tags/suggest", post(api_suggest_tags))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("registrar-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.records_dir = resolve_relative(base, &config.paths.records_dir);
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
        "didDocumentHash": hash_json(&request.did_document).map_err(|err| ApiError::internal(err.into()))?,
        "metadata": request.metadata,
        "registrationCredential": request.registration_credential,
        "submittedAt": chrono::Utc::now()
    });
    let records_root = JsonStore::new(&state.config.paths.records_dir);
    records_root
        .write(did_to_file_name(&request.agent_did), &record)
        .map_err(|err| ApiError::internal(err.into()))?;

    let root_request = VerifyAndPublishRequest {
        registrar_did: state.did.clone(),
        registrar_did_document: JsonStore::new(&state.config.paths.data_dir).read("did-document.json").map_err(|err| ApiError::internal(err.into()))?,
        agent_did: request.agent_did,
        did_document: request.did_document,
        metadata: record["metadata"].clone(),
        registration_credential: request.registration_credential,
    };
    let response = state
        .client
        .post(format!(
            "{}/root/agents/verify-and-publish",
            state.config.upstream.root_endpoint
        ))
        .json(&root_request)
        .send()
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
    if !status.is_success() {
        return Err(ApiError {
            status,
            message: body.to_string(),
        });
    }
    Ok(Json(body))
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
            "{}/api/v1/root/registrars/{}",
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
    let records = read_record_values(&state.config.paths.records_dir).map_err(ApiError::internal)?;
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
    let record: Option<Value> = JsonStore::new(&state.config.paths.records_dir)
        .read(did_to_file_name(&did))
        .ok();
    let submissions = record
        .map(|value| vec![value])
        .unwrap_or_default();
    Ok(Json(json!({ "did": did, "items": submissions, "count": submissions.len() })))
}

async fn api_create_draft(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let now = chrono::Utc::now();
    let did_document: Option<DidDocument> = payload
        .get("didDocument")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
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
    let draft = DraftRecord {
        draft_id: draft_id.clone(),
        agent_did,
        did_document,
        registration_credential: payload.get("registrationCredential").cloned(),
        metadata: payload.get("metadata").cloned().unwrap_or_else(|| json!({})),
        status: "draft".to_owned(),
        created_at: now,
        updated_at: now,
    };
    write_draft(&state, &draft)?;
    Ok(Json(json!({ "status": "created", "draft": draft })))
}

async fn api_update_draft(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id).unwrap_or_else(|_| DraftRecord {
        draft_id: draft_id.clone(),
        agent_did: payload
            .get("agentDid")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        did_document: None,
        registration_credential: None,
        metadata: json!({}),
        status: "draft".to_owned(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    if let Some(agent_did) = payload.get("agentDid").and_then(Value::as_str) {
        draft.agent_did = agent_did.to_owned();
    }
    if let Some(value) = payload.get("didDocument") {
        draft.did_document = serde_json::from_value(value.clone()).ok();
        if let Some(doc) = &draft.did_document {
            draft.agent_did = doc.id.clone();
        }
    }
    if let Some(value) = payload.get("registrationCredential") {
        draft.registration_credential = Some(value.clone());
    }
    if let Some(value) = payload.get("metadata") {
        draft.metadata = value.clone();
    }
    draft.updated_at = chrono::Utc::now();
    write_draft(&state, &draft)?;
    Ok(Json(json!({ "status": "updated", "draft": draft })))
}

async fn api_validate_draft(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let draft = read_draft(&state, &draft_id)?;
    Ok(Json(json!({
        "draftId": draft_id,
        "validation": validate_draft_record(&draft)
    })))
}

async fn api_issue_registration_credential(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let mut draft = read_draft(&state, &draft_id)?;
    let credential = json!({
        "type": "AgentRegistrationCredential",
        "issuer": state.did,
        "subject": draft.agent_did,
        "status": "draft-unsigned",
        "issuedAt": chrono::Utc::now(),
        "claims": {
            "capabilityTags": draft.did_document.as_ref()
                .and_then(|doc| doc.ans_metadata.as_ref())
                .and_then(|metadata| metadata.agent_description.as_ref())
                .map(|description| description.capability_tags.clone())
                .unwrap_or_default()
        },
        "proof": null
    });
    draft.registration_credential = Some(credential.clone());
    draft.status = "credential-issued-draft".to_owned();
    draft.updated_at = chrono::Utc::now();
    write_draft(&state, &draft)?;
    Ok(Json(json!({
        "status": "issued-draft",
        "credential": credential,
        "note": "MVP returns an unsigned credential skeleton; production signing is handled by the registrar credential module."
    })))
}

async fn api_submit_draft(
    State(state): State<AppState>,
    AxumPath(draft_id): AxumPath<String>,
) -> ApiResult<Value> {
    let draft = read_draft(&state, &draft_id)?;
    let did_document = draft
        .did_document
        .clone()
        .ok_or_else(|| ApiError::bad_request("draft_missing_did_document"))?;
    let credential = draft
        .registration_credential
        .clone()
        .ok_or_else(|| ApiError::bad_request("draft_missing_registration_credential"))?;
    register_agent(
        State(state),
        Json(RegisterRequest {
            agent_did: draft.agent_did,
            did_document,
            registration_credential: credential,
            metadata: draft.metadata,
        }),
    )
    .await
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
    let tree = fetch_root_value(&state, "/api/v1/root/capability-tree").await;
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
    let tree_value = fetch_root_value(&state, "/api/v1/root/capability-tree").await.ok();
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
                        || tag.aliases.iter().any(|alias| alias.to_lowercase().contains(&keyword))
                })
                .take(20)
                .map(|tag| json!({ "id": tag.id, "label": tag.label, "parent": tag.parent }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Json(json!({ "items": suggestions, "count": suggestions.len() })))
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

fn read_draft(state: &AppState, draft_id: &str) -> std::result::Result<DraftRecord, ApiError> {
    state
        .data
        .read(format!("drafts/{}.json", storage_safe_id(draft_id)))
        .map_err(|_| ApiError::bad_request("draft_not_found"))
}

fn write_draft(state: &AppState, draft: &DraftRecord) -> std::result::Result<(), ApiError> {
    state
        .data
        .write(
            format!("drafts/{}.json", storage_safe_id(&draft.draft_id)),
            draft,
        )
        .map_err(|err| ApiError::internal(err.into()))?;
    Ok(())
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
    if draft.registration_credential.is_none() {
        errors.push("missing_registration_credential".to_owned());
    }
    json!({ "valid": errors.is_empty(), "errors": errors })
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

#[cfg(test)]
mod tests {
    use super::*;
    use oan_core::{AgentDescription, AnsMetadata, ServiceEndpoint};
    use tempfile::tempdir;

    fn sample_did_document(did: &str) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![oan_core::VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: Some("zDummyKeyForTest".to_owned()),
                public_key_jwk: None,
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

    fn app_state(dir: &std::path::Path) -> AppState {
        AppState {
            data: JsonStore::new(dir),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8001,
                },
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8000".to_owned(),
                },
                paths: PathConfig {
                    data_dir: dir.to_path_buf(),
                    records_dir: dir.join("records"),
                },
            },
            did: "did:ans:AGRG:efregistrarregistrar1234".to_owned(),
            client: reqwest::Client::new(),
        }
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
            .write(format!("drafts/{}.json", storage_safe_id("draft-1")), &json!({"draftId": "draft-1", "agentDid": did}))
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
        let response = api_create_draft(
            State(state.clone()),
            Json(json!({
                "draftId": "draft-1",
                "agentDid": did,
                "didDocument": sample_did_document(did),
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
        assert_eq!(submissions.0["count"], 1);
    }
}
