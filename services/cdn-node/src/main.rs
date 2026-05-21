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
use oan_package::{Manifest, ManifestEntry, VerifiedPackage};
use oan_storage::{did_to_file_name, JsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
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
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
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
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        lock: Arc::new(Mutex::new(())),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/cdn/manifest", get(manifest))
        .route("/cdn/updates", get(manifest))
        .route("/cdn/packages", post(publish_package))
        .route("/cdn/packages/{did}", get(get_package))
        .route("/cdn/documents/{did}", get(get_document))
        .route("/cdn/metadata/{did}", get(get_metadata))
        .route("/api/v1/cdn/status", get(api_status))
        .route("/api/v1/cdn/packages", get(api_packages))
        .route("/api/v1/cdn/packages/{did}", get(api_package_detail))
        .route("/api/v1/cdn/documents/{did}", get(api_document_detail))
        .route("/api/v1/cdn/metadata/{did}", get(api_metadata_detail))
        .route("/api/v1/cdn/manifest/stats", get(api_manifest_stats))
        .route("/api/v1/cdn/publish/history", get(api_publish_history))
        .route("/api/v1/cdn/purge", post(api_purge))
        .with_state(state);

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
    Ok(config)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "nodeType": "cdn-service", "did": null}))
}

async fn manifest(State(state): State<AppState>) -> ApiResult<Manifest> {
    state
        .data
        .read("manifest.json")
        .map(Json)
        .map_err(|err| ApiError::internal(err.into()))
}

async fn publish_package(
    State(state): State<AppState>,
    Json(package): Json<VerifiedPackage>,
) -> ApiResult<serde_json::Value> {
    let _guard = state.lock.lock().await;
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
    let mut manifest: Manifest = state.data.read("manifest.json").unwrap_or(Manifest {
        version: "0.1.0".to_owned(),
        generated_at: Utc::now(),
        root_did: package.root_proof.root_did.clone(),
        packages: vec![],
    });
    manifest.root_did = package.root_proof.root_did.clone();
    manifest.generated_at = Utc::now();
    manifest.packages.retain(|entry| entry.did != package.did);
    manifest.packages.push(ManifestEntry {
        did: package.did.clone(),
        role: package.metadata.role.clone(),
        document_path: format!("/cdn/documents/{}", package.did),
        metadata_path: format!("/cdn/metadata/{}", package.did),
        package_path: format!("/cdn/packages/{}", package.did),
        did_document_hash: package.did_document_hash.clone(),
        updated_at: Utc::now(),
    });
    state
        .data
        .write("manifest.json", &manifest)
        .map_err(|err| ApiError::internal(err.into()))?;
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
    let manifest: Manifest = state.data.read("manifest.json").unwrap_or(Manifest {
        version: "0.1.0".to_owned(),
        generated_at: Utc::now(),
        root_did: String::new(),
        packages: vec![],
    });
    Ok(Json(json!({
        "status": "ok",
        "packageCount": manifest.packages.len(),
        "rootDid": manifest.root_did,
        "generatedAt": manifest.generated_at
    })))
}

async fn api_packages(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let manifest: Manifest = state.data.read("manifest.json").unwrap_or(Manifest {
        version: "0.1.0".to_owned(),
        generated_at: Utc::now(),
        root_did: String::new(),
        packages: vec![],
    });
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
    let manifest: Manifest = state.data.read("manifest.json").unwrap_or(Manifest {
        version: "0.1.0".to_owned(),
        generated_at: Utc::now(),
        root_did: String::new(),
        packages: vec![],
    });
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
    let history: Vec<Value> = state.data.read("publish-history.json").unwrap_or_default();
    Ok(Json(json!({ "items": history, "count": history.len() })))
}

async fn api_purge(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<serde_json::Value> {
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
    use oan_core::{AgentDescription, AnsMetadata, ServiceEndpoint};
    use tempfile::tempdir;

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
        VerifiedPackage {
            package_version: "0.1.0".to_owned(),
            did: did.to_owned(),
            did_document_hash: "hash-1".to_owned(),
            metadata_hash: None,
            metadata: oan_package::AgentMetadata {
                did: did.to_owned(),
                role: "Service Agent".to_owned(),
                identity_type: "service-agent".to_owned(),
                did_document_hash: "hash-1".to_owned(),
                capability_tags: vec!["echo".to_owned()],
                services: did_document.service.clone(),
                status: "active".to_owned(),
                updated_at: Utc::now(),
            },
            did_document,
            root_proof: oan_package::RootProof {
                root_did: "did:ans:AGRT:efrootrootrootrootrootroot".to_owned(),
                bulletin_event_hash: None,
                signature: None,
            },
            created_at: Utc::now(),
        }
    }

    fn app_state(dir: &std::path::Path) -> AppState {
        AppState {
            data: JsonStore::new(dir),
            lock: Arc::new(Mutex::new(())),
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

        let purge = api_purge(State(state), Json(json!({"did": did})))
            .await
            .unwrap();
        assert_eq!(purge.0["status"], "accepted");
    }
}
