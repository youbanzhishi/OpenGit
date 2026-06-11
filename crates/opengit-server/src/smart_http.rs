//! Git Smart HTTP Protocol — Streaming implementation
//!
//! Implements the Git Smart HTTP protocol by spawning
//! git-upload-pack / git-receive-pack processes.
//!
//! P2: Streaming for upload_pack (prevents OOM on large repos),
//!     webhook triggers on receive_pack success.

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::api::SharedState;
use crate::middleware::IdentityName;
use crate::webhook::{WebhookEvent, WebhookPayload};

/// Query parameters for info/refs endpoint
#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    service: Option<String>,
}

/// GET /{repo}/info/refs — Git discovery endpoint
///
/// This is the first request a git client makes. It advertises
/// the refs available in the repository.
pub async fn info_refs(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
    Query(query): Query<InfoRefsQuery>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // Determine service from query parameter
    let service = match query.service.as_deref() {
        Some("git-upload-pack") => "git-upload-pack",
        Some("git-receive-pack") => "git-receive-pack",
        _ => "git-upload-pack",
    };

    // For receive-pack, require push permission
    if service == "git-receive-pack" {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate(&repo_name, &identity.0, opengit_core::policy::Action::Push);
        drop(engine); // Release lock before git operation
        if !result.is_allowed() {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "DRAGON_FIREWALL: Push denied for '{}' — {}",
                    identity.0,
                    result.reason.unwrap_or_else(|| "policy denied".into())
                ),
            )
                .into_response();
        }
    }

    // Spawn the git process for ref advertisement
    let output = Command::new(service)
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(&repo_path)
        .output()
        .await;

    match output {
        Ok(output) if output.status.success() => {
            let content_type = format!("application/x-{}-advertisement", service);
            // Smart HTTP response: pkt-line header + flush + ref advertisement
            let pkt_header = format!("# service={}\n", service);
            let pkt_len = pkt_header.len() + 4;
            let header_line = format!("{:04x}{}", pkt_len, pkt_header);
            let flush = "0000";

            let mut body = Vec::new();
            body.extend_from_slice(header_line.as_bytes());
            body.extend_from_slice(flush.as_bytes());
            body.extend_from_slice(&output.stdout);

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CACHE_CONTROL, "no-cache".into()),
                ],
                body,
            )
                .into_response()
        }
        Ok(output) => {
            error!(
                "git {} --advertise-refs failed: {}",
                service,
                String::from_utf8_lossy(&output.stderr)
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Git protocol error during ref advertisement",
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to spawn {}: {}", service, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to execute git command",
            )
                .into_response()
        }
    }
}

/// POST /{repo}/git-upload-pack — Clone/fetch/pull (STREAMING)
///
/// Handles the pack negotiation for read operations.
/// Streams stdout directly to the client to avoid OOM on large repos.
pub async fn upload_pack(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
    body: axum::body::Bytes,
) -> Response {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // Check read permission
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate(&repo_name, &identity.0, opengit_core::policy::Action::Read);
        drop(engine);
        if !result.is_allowed() {
            state.stats.record_denial();
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "DRAGON_FIREWALL: Read denied for '{}' — {}",
                    identity.0,
                    result.reason.unwrap_or_else(|| "policy denied".into())
                ),
            )
                .into_response();
        }
    }

    debug!("upload_pack: repo={} identity={}", repo_name, identity.0);
    state.stats.record_clone();

    // Spawn git-upload-pack --stateless-rpc
    let mut child = match Command::new("git-upload-pack")
        .arg("--stateless-rpc")
        .arg(&repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to spawn git-upload-pack: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to execute git command",
            )
                .into_response();
        }
    };

    // Write request body to stdin in a background task
    if let Some(stdin) = child.stdin.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stdin = stdin;
            if let Err(e) = stdin.write_all(&body).await {
                tracing::error!("Failed to write to git-upload-pack stdin: {}", e);
            }
        });
    }

    // Stream stdout directly to response
    let stdout = child.stdout.take().unwrap();
    let reader = tokio::io::BufReader::new(stdout);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let response_body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-result")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(response_body)
        .unwrap()
}

/// POST /{repo}/git-receive-pack — Push (STREAMING + WEBHOOKS)
///
/// Handles the pack negotiation for write operations.
/// Streams stdout to the client, triggers webhooks on success.
pub async fn receive_pack(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
    body: axum::body::Bytes,
) -> Response {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // Pre-check: evaluate push permission
    let push_result = {
        let engine = state.policy_engine.read().await;
        engine.evaluate(&repo_name, &identity.0, opengit_core::policy::Action::Push)
    };
    if !push_result.is_allowed() {
        warn!(
            "Push denied for '{}' on '{}': {}",
            identity.0,
            repo_name,
            push_result.reason.as_deref().unwrap_or("policy denied")
        );
        state.audit_log.log(opengit_core::audit::AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            repo: repo_name.clone(),
            identity: identity.0.clone(),
            action: "Push".into(),
            ref_name: None,
            allowed: false,
            reason: push_result.reason.clone(),
        });
        state.stats.record_denial();

        return (
            StatusCode::FORBIDDEN,
            format!(
                "DRAGON_FIREWALL: Push denied for '{}' — {}",
                identity.0,
                push_result.reason.unwrap_or_else(|| "policy denied".into())
            ),
        )
            .into_response();
    }

    info!("receive_pack: repo={} identity={}", repo_name, identity.0);

    // Spawn git-receive-pack --stateless-rpc
    let mut child = match Command::new("git-receive-pack")
        .arg("--stateless-rpc")
        .arg(&repo_path)
        .env("OPENGIT_IDENTITY", &identity.0)
        .env("OPENGIT_REPO", &repo_name)
        .env("OPENGIT_REPO_PATH", &repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to spawn git-receive-pack: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to execute git command",
            )
                .into_response();
        }
    };

    // Write request body to stdin in a background task
    if let Some(stdin) = child.stdin.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stdin = stdin;
            if let Err(e) = stdin.write_all(&body).await {
                tracing::error!("Failed to write to git-receive-pack stdin: {}", e);
            }
        });
    }

    // Take stdout for streaming
    let stdout = child.stdout.take().unwrap();

    // Background task: wait for child exit → audit + webhook
    let webhook_state = state.clone();
    let webhook_identity = identity.0.clone();
    let webhook_repo = repo_name.clone();
    tokio::spawn(async move {
        match child.wait().await {
            Ok(status) if status.success() => {
                info!(
                    "Push succeeded: repo={} identity={}",
                    webhook_repo, webhook_identity
                );
                webhook_state.stats.record_push();

                webhook_state
                    .audit_log
                    .log(opengit_core::audit::AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        repo: webhook_repo.clone(),
                        identity: webhook_identity.clone(),
                        action: "Push".into(),
                        ref_name: None,
                        allowed: true,
                        reason: None,
                    });

                // Trigger webhooks
                let webhooks = webhook_state.webhooks.read().await;
                let payload = WebhookPayload {
                    repo: webhook_repo.clone(),
                    identity: webhook_identity.clone(),
                    event: "push".into(),
                    ref_name: "refs/heads/master".into(), // Best-effort — actual ref parsed by hooks
                    old_sha: String::new(),
                    new_sha: String::new(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                crate::webhook::deliver_all(&webhooks, &payload, WebhookEvent::Push).await;
                webhook_state.stats.record_webhook();
            }
            Ok(status) => {
                warn!(
                    "Push failed for {}: exit code {:?}",
                    webhook_repo,
                    status.code()
                );
                webhook_state
                    .audit_log
                    .log(opengit_core::audit::AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        repo: webhook_repo,
                        identity: webhook_identity,
                        action: "Push".into(),
                        ref_name: None,
                        allowed: false,
                        reason: Some(format!(
                            "git-receive-pack exited with code {:?}",
                            status.code()
                        )),
                    });
            }
            Err(e) => {
                error!("Failed to wait for git-receive-pack: {}", e);
            }
        }
    });

    // Stream stdout to response
    let reader = tokio::io::BufReader::new(stdout);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let response_body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-result",
        )
        .body(response_body)
        .unwrap()
}
