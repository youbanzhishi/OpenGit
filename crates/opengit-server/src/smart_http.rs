//! Git Smart HTTP Protocol — Full implementation
//!
//! Implements the Git Smart HTTP protocol by spawning
//! git-upload-pack / git-receive-pack processes.
//!
//! References:
//! - https://git-scm.com/docs/http-protocol
//! - https://git-scm.com/docs/git-upload-pack
//! - https://git-scm.com/docs/git-receive-pack

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::api::SharedState;
use crate::middleware::IdentityName;

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
        let result = state.policy_engine.evaluate(
            &repo_name,
            &identity.0,
            opengit_core::policy::Action::Push,
        );
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

/// POST /{repo}/git-upload-pack — Clone/fetch/pull
///
/// Handles the pack negotiation for read operations.
pub async fn upload_pack(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // Check read permission
    let result =
        state
            .policy_engine
            .evaluate(&repo_name, &identity.0, opengit_core::policy::Action::Read);
    if !result.is_allowed() {
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

    debug!("upload_pack: repo={} identity={}", repo_name, identity.0);

    // Spawn git-upload-pack --stateless-rpc
    let child = Command::new("git-upload-pack")
        .arg("--stateless-rpc")
        .arg(&repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = stdin.write_all(&body).await {
                    error!("Failed to write to git-upload-pack stdin: {}", e);
                    let _ = child.kill().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Git protocol error")
                        .into_response();
                }
                drop(stdin);
            }

            match child.wait_with_output().await {
                Ok(output) if output.status.success() => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
                    output.stdout,
                )
                    .into_response(),
                Ok(output) => {
                    error!(
                        "git-upload-pack failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    (StatusCode::INTERNAL_SERVER_ERROR, "Git upload-pack failed").into_response()
                }
                Err(e) => {
                    error!("git-upload-pack wait error: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Git protocol error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Failed to spawn git-upload-pack: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to execute git command",
            )
                .into_response()
        }
    }
}

/// POST /{repo}/git-receive-pack — Push
///
/// Handles the pack negotiation for write operations.
/// Runs the full policy evaluation pipeline before accepting the push.
pub async fn receive_pack(
    Path(repo_name): Path<String>,
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", repo_name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    // Pre-check: evaluate push permission
    let push_result =
        state
            .policy_engine
            .evaluate(&repo_name, &identity.0, opengit_core::policy::Action::Push);
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
    // Inject identity into environment so hooks can pick it up
    let child = Command::new("git-receive-pack")
        .arg("--stateless-rpc")
        .arg(&repo_path)
        .env("OPENGIT_IDENTITY", &identity.0)
        .env("OPENGIT_REPO", &repo_name)
        .env("OPENGIT_REPO_PATH", &repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = stdin.write_all(&body).await {
                    error!("Failed to write to git-receive-pack stdin: {}", e);
                    let _ = child.kill().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Git protocol error")
                        .into_response();
                }
                drop(stdin);
            }

            match child.wait_with_output().await {
                Ok(output) if output.status.success() => {
                    info!("Push succeeded: repo={} identity={}", repo_name, identity.0);

                    state.audit_log.log(opengit_core::audit::AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        repo: repo_name.clone(),
                        identity: identity.0.clone(),
                        action: "Push".into(),
                        ref_name: None,
                        allowed: true,
                        reason: None,
                    });

                    (
                        StatusCode::OK,
                        [(
                            header::CONTENT_TYPE,
                            "application/x-git-receive-pack-result",
                        )],
                        output.stdout,
                    )
                        .into_response()
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("git-receive-pack failed: {}", stderr);

                    if stderr.contains("DRAGON_FIREWALL") || stderr.contains("DENIED") {
                        return (StatusCode::FORBIDDEN, stderr.to_string()).into_response();
                    }

                    (StatusCode::INTERNAL_SERVER_ERROR, "Git receive-pack failed").into_response()
                }
                Err(e) => {
                    error!("git-receive-pack wait error: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Git protocol error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Failed to spawn git-receive-pack: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to execute git command",
            )
                .into_response()
        }
    }
}
