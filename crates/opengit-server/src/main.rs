//! OpenGit Server — Lightweight private Git service, agent-first
//!
//! P4: SSH transport + Hook Plugin System.
//!     Dual-server: HTTP (Smart HTTP + API) + SSH (git transport).

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod api;
mod config;
mod middleware;
mod smart_http;
mod stats;
mod webhook;

use config::ServerConfig;

#[derive(Parser, Debug)]
#[command(
    name = "opengit",
    version,
    about = "Lightweight private Git service, agent-first"
)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config/server.toml")]
    config: PathBuf,

    /// Repository storage directory
    #[arg(short, long)]
    repos_dir: Option<PathBuf>,

    /// Bind address
    #[arg(short, long)]
    bind: Option<String>,

    /// Policy file path
    #[arg(short, long)]
    policy: Option<PathBuf>,

    /// Enable SSH server
    #[arg(long)]
    ssh: bool,

    /// SSH bind address (overrides config)
    #[arg(long)]
    ssh_bind: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("opengit=debug,opengit_core=debug")
        .init();

    let cli = Cli::parse();
    let config = ServerConfig::load(&cli)?;

    // Load plugins
    let plugins = opengit_core::PluginsFile::load(&config.plugin_file)?;
    let plugin_manager = opengit_core::PluginManager::load_from_config(&plugins);
    let plugin_names = plugin_manager.plugin_names();

    tracing::info!("🐉 OpenGit starting...");
    tracing::info!("   Repos:    {}", config.repos_dir.display());
    tracing::info!("   Bind:     {}", config.bind);
    tracing::info!("   Policy:   {}", config.policy_file.display());
    tracing::info!("   Identity: {}", config.identity_file.display());
    tracing::info!("   Webhook:  {}", config.webhook_file.display());
    tracing::info!("   Audit:    {}", config.audit_file.display());
    tracing::info!("   Plugins:  {}", plugin_names.join(", "));

    let ssh_enabled = cli.ssh || !config.ssh_bind.is_empty();
    let ssh_bind = cli
        .ssh_bind
        .or(if ssh_enabled {
            Some(config.ssh_bind.clone())
        } else {
            None
        })
        .unwrap_or_default();

    if ssh_enabled && !ssh_bind.is_empty() {
        tracing::info!("   SSH:      {} (enabled)", ssh_bind);
    } else {
        tracing::info!("   SSH:      disabled");
    }

    let app = api::build_router(&config)?;

    // HTTP server
    let http_bind = config.bind.clone();
    let http_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&http_bind).await?;
        tracing::info!("🐉 OpenGit HTTP listening on {}", http_bind);
        axum::serve(listener, app).await
    });

    // SSH server (if enabled)
    let ssh_server = if ssh_enabled && !ssh_bind.is_empty() {
        let repos_dir = config.repos_dir.clone();
        let identity_file = config.identity_file.clone();
        let policy_file = config.policy_file.clone();
        let host_key_path = config.ssh_host_key.clone();

        Some(tokio::spawn(async move {
            match start_ssh_server(&ssh_bind, &repos_dir, &identity_file, &policy_file, &host_key_path).await {
                Ok(()) => tracing::info!("🐉 OpenGit SSH server stopped"),
                Err(e) => tracing::error!("SSH server error: {e}"),
            }
        }))
    } else {
        None
    };

    // Wait for servers
    tokio::select! {
        r = http_server => {
            r??;
        }
        Some(r) = ssh_server => {
            r?;
        }
    }

    Ok(())
}

/// Start the SSH server
async fn start_ssh_server(
    bind: &str,
    repos_dir: &PathBuf,
    identity_file: &PathBuf,
    policy_file: &PathBuf,
    host_key_path: &PathBuf,
) -> Result<()> {
    use opengit_core::identity::IdentityStore;
    use russh::server::Server as SshServer;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Load identities
    let identity_store = if identity_file.exists() {
        IdentityStore::from_file(identity_file)?
    } else {
        IdentityStore::new()
    };

    // Generate host key if needed
    if !host_key_path.exists() {
        if let Some(parent) = host_key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key = russh_keys::generate_signature(russh_keys::Algorithm::Ed25519)?;
        russh_keys::write_key_file(host_key_path, &key)?;
        tracing::info!("Generated SSH host key: {}", host_key_path.display());
    }

    let ssh_config = russh::server::Config {
        keys: vec![russh_keys::load_secret_key(host_key_path)?],
        ..Default::default()
    };

    struct SshState {
        repos_dir: PathBuf,
        identity_store: RwLock<IdentityStore>,
        policy_file: PathBuf,
    }

    impl russh::server::Server for SshState {
        type Handler = opengit_ssh::SshSession;

        fn new_client(
            &mut self,
            _peer_addr: Option<std::net::SocketAddr>,
        ) -> Self::Handler {
            let store = self.identity_store.try_read().map(|s| s.clone()).unwrap_or_default();
            opengit_ssh::SshSession::new(
                self.repos_dir.clone(),
                self.policy_file.clone(),
                store,
            )
        }
    }

    let state = Arc::new(SshState {
        repos_dir: repos_dir.clone(),
        identity_store: RwLock::new(identity_store),
        policy_file: policy_file.clone(),
    });

    let server = russh::server::Server::new(state, ssh_config, bind.parse()?);
    tracing::info!("🐉 OpenGit SSH listening on {}", bind);
    server.run().await?;

    Ok(())
}
