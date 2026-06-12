//! OpenGit SSH Server — Git over SSH transport
//!
//! P4: SSH protocol support for git clone/push operations.
//! SSH public keys are mapped to OpenGit identities.
//!
//! Usage:
//!   opengit-sshd --config config/server.toml --ssh-bind 0.0.0.0:2222

use anyhow::{Context, Result};
use clap::Parser;
use opengit_core::identity::IdentityStore;
use russh::keys::ssh_key;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, MethodSet, Server};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Parser, Debug)]
#[command(
    name = "opengit-sshd",
    version,
    about = "OpenGit SSH Server — Git over SSH transport"
)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config/server.toml")]
    config: PathBuf,
    /// SSH bind address
    #[arg(long, default_value = "0.0.0.0:2222")]
    ssh_bind: String,
    /// Host key path (ED25519)
    #[arg(long, default_value = "config/ssh_host_key")]
    host_key: PathBuf,
    /// Repository storage directory
    #[arg(short, long)]
    repos_dir: Option<PathBuf>,
}

/// Shared server state for SSH handlers
struct SshServerState {
    repos_dir: PathBuf,
    identity_store: RwLock<IdentityStore>,
    policy_file: PathBuf,
    audit_file: PathBuf,
}

impl Server for SshServerState {
    type Handler = SshSession;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let _ = peer_addr;
        SshSession {
            identity: None,
            state: Arc::new(SshServerState {
                repos_dir: self.repos_dir.clone(),
                identity_store: RwLock::new(
                    self.identity_store
                        .try_read()
                        .map(|s| s.clone())
                        .unwrap_or_default(),
                ),
                policy_file: self.policy_file.clone(),
                audit_file: self.audit_file.clone(),
            }),
        }
    }
}

/// Per-connection SSH session handler
struct SshSession {
    identity: Option<String>,
    state: Arc<SshServerState>,
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<bool, Self::Error> {
        // Will handle exec commands in channel_data
        let _ = (channel, session);
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let key_fingerprint = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        tracing::info!("SSH auth attempt: user={user}, key={key_fingerprint}");

        // Look up identity by SSH key
        let store = self.state.identity_store.read().await;
        for identity in store.list() {
            for stored_key in &identity.ssh_keys {
                // Compare fingerprint
                if stored_key == &key_fingerprint || stored_key == public_key.to_openssh() {
                    tracing::info!("SSH auth success: {} -> {}", user, identity.name);
                    self.identity = Some(identity.name.clone());
                    return Ok(Auth::Accept);
                }
            }
        }

        tracing::warn!("SSH auth denied: user={user}, key={key_fingerprint}");
        Ok(Auth::Reject {
            proceed_with_methods: MethodSet::PUBLICKEY,
        })
    }

    async fn channel_exec(
        &mut self,
        program: &str,
        data: &[u8],
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<bool, Self::Error> {
        let _ = (data, session);
        let identity = self
            .identity
            .clone()
            .unwrap_or_else(|| "anonymous".to_string());

        tracing::info!("SSH exec: identity={identity}, program={program}");

        // Parse git command: git-upload-pack '<repo>' or git-receive-pack '<repo>'
        let (command, repo_name) = parse_git_command(program);

        match command {
            Some(cmd) => {
                let repo_path = self.state.repos_dir.join(format!("{repo_name}.git"));

                if !repo_path.exists() {
                    let _ = channel.data(
                        format!(
                            "Repository not found: {repo_name}
"
                        )
                        .as_bytes(),
                    );
                    let _ = channel.eof();
                    return Ok(true);
                }

                if cmd == "git-receive-pack" {
                    // Check push permission
                    let engine = if self.state.policy_file.exists() {
                        opengit_core::PolicyEngine::from_file(&self.state.policy_file)
                            .unwrap_or_default()
                    } else {
                        opengit_core::PolicyEngine::new()
                    };
                    let result =
                        engine.evaluate(&repo_name, &identity, opengit_core::policy::Action::Push);
                    if !result.is_allowed() {
                        let _ = channel.data(
                            format!(
                                "DRAGON_FIREWALL: Push denied for '{identity}' — {}
",
                                result.reason.unwrap_or_else(|| "policy denied".into())
                            )
                            .as_bytes(),
                        );
                        let _ = channel.eof();
                        return Ok(true);
                    }
                }

                // Execute git command
                let mut child = tokio::process::Command::new(cmd)
                    .arg(&repo_path)
                    .env("OPENGIT_IDENTITY", &identity)
                    .env("OPENGIT_REPO", &repo_name)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .context("Failed to spawn git command")?;

                // Stream stdout to channel
                if let Some(mut stdout) = child.stdout.take() {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        use tokio::io::AsyncReadExt;
                        match stdout.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let _ = channel.data(&buf[..n]);
                            }
                            Err(_) => break,
                        }
                    }
                }

                let _ = child.wait().await;
                let _ = channel.eof();
            }
            None => {
                let _ = channel.data(
                    format!(
                        "Unsupported command: {program}
"
                    )
                    .as_bytes(),
                );
                let _ = channel.eof();
            }
        }

        Ok(true)
    }
}

/// Parse SSH git command into (command, repo_name)
///
/// Examples:
///   git-upload-pack '/OpenDAW' -> Some(("git-upload-pack", "OpenDAW"))
///   git-receive-pack 'my-repo' -> Some(("git-receive-pack", "my-repo"))
fn parse_git_command(input: &str) -> (Option<&str>, String) {
    let trimmed = input.trim();

    if let Some(rest) = trimmed.strip_prefix("git-upload-pack ") {
        let repo = extract_repo_name(rest);
        (Some("git-upload-pack"), repo)
    } else if let Some(rest) = trimmed.strip_prefix("git-receive-pack ") {
        let repo = extract_repo_name(rest);
        (Some("git-receive-pack"), repo)
    } else if let Some(rest) = trimmed.strip_prefix("git-upload-archive ") {
        let repo = extract_repo_name(rest);
        (Some("git-upload-archive"), repo)
    } else {
        (None, String::new())
    }
}

/// Extract repo name from quoted argument: 'repo' or "repo" or repo
fn extract_repo_name(arg: &str) -> String {
    let trimmed = arg.trim();
    let s = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(trimmed);
    s.trim_start_matches('/').trim_end_matches('/').to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("opengit_ssh=debug,opengit_core=debug")
        .init();

    let cli = Cli::parse();

    tracing::info!("🐉 OpenGit SSH Server starting...");
    tracing::info!("   SSH bind:  {}", cli.ssh_bind);
    tracing::info!(
        "   Repos:     {}",
        cli.repos_dir
            .as_ref()
            .map_or("./repos", |p| p.display().to_string())
    );

    let repos_dir = cli.repos_dir.unwrap_or_else(|| PathBuf::from("./repos"));

    // Load identity store
    let identity_file = PathBuf::from("config/identities.yaml");
    let identity_store = if identity_file.exists() {
        IdentityStore::from_file(&identity_file)?
    } else {
        IdentityStore::new()
    };

    // Generate host key if not exists
    if !cli.host_key.exists() {
        tracing::info!("Generating SSH host key...");
        if let Some(parent) = cli.host_key.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key = russh_keys::generate_signature(russh_keys::Algorithm::Ed25519)?;
        russh_keys::write_key_file(&cli.host_key, &key)?;
        tracing::info!("Host key saved to {}", cli.host_key.display());
    }

    let config = russh::server::Config {
        keys: vec![
            russh_keys::load_secret_key(&cli.host_key).context("Failed to load SSH host key")?
        ],
        ..Default::default()
    };

    let server_state = SshServerState {
        repos_dir,
        identity_store: RwLock::new(identity_store),
        policy_file: PathBuf::from("config/policies.yaml"),
        audit_file: PathBuf::from("data/audit.json"),
    };

    let server = russh::server::Server::new(Arc::new(server_state), config, cli.ssh_bind.parse()?);

    tracing::info!("🐉 OpenGit SSH Server listening on {}", cli.ssh_bind);
    server.run().await?;

    Ok(())
}
