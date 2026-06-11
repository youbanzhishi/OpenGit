//! Git Smart HTTP Protocol

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;

use crate::api::SharedState;

/// GET /{repo}/info/refs — Git discovery endpoint
pub async fn info_refs(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // For P0, return a simple response indicating the repo exists
    // Full Smart HTTP implementation requires spawning git processes
    (StatusCode::OK, "Smart HTTP P0 - repo found").into_response()
}

/// POST /{repo}/git-upload-pack — Clone/fetch/pull
pub async fn upload_pack(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // P0: placeholder for git-upload-pack
    (StatusCode::OK, "upload-pack P0").into_response()
}

/// POST /{repo}/git-receive-pack — Push
pub async fn receive_pack(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // P0: placeholder for git-receive-pack
    // In production, this would go through the hook pipeline for policy evaluation
    (StatusCode::OK, "receive-pack P0").into_response()
}
