//! Git Smart HTTP Protocol — Streaming implementation
//!
//! Implements the Git Smart HTTP protocol by spawning
//! git-upload-pack / git-receive-pack processes.
//!
//! P3: Precise webhook delivery with ref parsing from receive-pack output.

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
use crate::webhook::{WebhookEvent, WebhookPayload, RefUpdate};

/// Query parameters for info/refs endpoint
#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    service: Option<String>,
}

/// GET /{repo}/info/refs — Git discovery endpoint
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

    let service = match query.service.as_deref() {
        Some("git-upload-pack") => "git-upload-pack",
        Some("git-receive-pack") => "git-receive-pack",
        _ => "git-upload-pack",
    };

    if service == "git-receive-pack" {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate(&repo_name, &identity.0, opengit_core::policy::Action::Push);
        drop(engine);
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

    let output = Command::new(service)
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(&repo_path)
        .output()
        .await;

    match output {
        Ok(output) if output.status.success() => {
            let content_type = format!("application/x-{}-advertisement", service);
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

    if let Some(stdin) = child.stdin.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stdin = stdin;
            if let Err(e) = stdin.write_all(&body).await {
                tracing::error!("Failed to write to git-upload-pack stdin: {}", e);
            }
        });
    }

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

    // Parse ref updates from the request body for precise webhook delivery
    // The pack data starts after the ref update lines (terminated by a flush packet "0000")
    let ref_updates = parse_ref_updates_from_pack(&body);

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

    if let Some(stdin) = child.stdin.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stdin = stdin;
            if let Err(e) = stdin.write_all(&body).await {
                tracing::error!("Failed to write to git-receive-pack stdin: {}", e);
            }
        });
    }

    let stdout = child.stdout.take().unwrap();

    // Background task: wait for child exit → audit + webhook with precise ref info
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

                // Deliver webhooks with precise ref info
                let webhooks = webhook_state.webhooks.read().await;
                if !ref_updates.is_empty() {
                    let sent = crate::webhook::deliver_for_refs(
                        &webhooks,
                        &webhook_repo,
                        &webhook_identity,
                        &ref_updates,
                    )
                    .await;
                    for _ in 0..sent {
                        webhook_state.stats.record_webhook();
                    }
                } else {
                    // Fallback: generic push event
                    let payload = WebhookPayload {
                        repo: webhook_repo.clone(),
                        identity: webhook_identity.clone(),
                        event: "push".into(),
                        ref_name: "refs/heads/master".into(),
                        old_sha: String::new(),
                        new_sha: String::new(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    crate::webhook::deliver_all(&webhooks, &payload, WebhookEvent::Push).await;
                    webhook_state.stats.record_webhook();
                }
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

/// Parse ref updates from a git-receive-pack request body.
///
/// The first part of the body contains "want" and "have" lines,
/// but for receive-pack, the client sends ref update commands
/// in pkt-line format. We try to extract ref updates from the
/// command section of the request.
fn parse_ref_updates_from_pack(body: &[u8]) -> Vec<RefUpdate> {
    // Git receive-pack request format:
    //   First line: <old-sha> <new-sha> <ref-name>\0<capabilities>
    //   Additional lines: <old-sha> <new-sha> <ref-name>
    //   Flush: 0000
    //   Then pack data
    let mut updates = Vec::new();
    let mut pos = 0;

    while pos + 4 <= body.len() {
        // Read pkt-line length
        let len_str = match std::str::from_utf8(&body[pos..pos + 4]) {
            Ok(s) => s,
            Err(_) => break,
        };
        let len = match u16::from_str_radix(len_str, 16) {
            Ok(l) => l as usize,
            Err(_) => break,
        };

        if len == 0 {
            // Flush packet — end of commands
            pos += 4;
            break;
        }

        if len < 4 || pos + len > body.len() {
            break;
        }

        let line = match std::str::from_utf8(&body[pos + 4..pos + len]) {
            Ok(s) => s.trim_end(),
            Err(_) => {
                pos += len;
                continue;
            }
        };

        // Parse: <old-sha> <new-sha> <ref-name>\0<capabilities>
        let line_no_caps = line.split('\0').next().unwrap_or(line);
        let parts: Vec<&str> = line_no_caps.split_whitespace().collect();
        if parts.len() >= 3 && parts[0].len() == 40 && parts[1].len() == 40 {
            updates.push(RefUpdate {
                old_sha: parts[0].to_string(),
                new_sha: parts[1].to_string(),
                ref_name: parts[2].to_string(),
            });
        }

        pos += len;
    }

    if !updates.is_empty() {
        debug!(
            "Parsed {} ref updates from receive-pack request",
            updates.len()
        );
    }

    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ref_updates_from_pack() {
        // Simulate a git-receive-pack request with one ref update
        // Format: pkt-line with "old_sha new_sha refs/heads/master\0capabilities"
        let old_sha = "abc1230000000000000000000000000000000000";
        let new_sha = "def4560000000000000000000000000000000000";
        let cmd = format!(
            "{} {} refs/heads/master\0report-status side-band-6k",
            old_sha, new_sha
        );
        let len = cmd.len() + 4;
        let pkt_line = format!("{:04x}{}", len, cmd);
        let flush = "0000";
        let body = format!("{}{}some-pack-data", pkt_line, flush);

        let updates = parse_ref_updates_from_pack(body.as_bytes());
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].ref_name, "refs/heads/master");
        assert_eq!(updates[0].old_sha, old_sha);
        assert_eq!(updates[0].new_sha, new_sha);
    }
}
