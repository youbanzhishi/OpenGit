//! OpenGit Server - Lightweight private Git service, agent-first
//!
//! P4: SSH transport + Hook Plugin System.
//! P5: Docker deployment + Repository mirroring.

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

    // Load mirrors
    let mirrors = opengit_core::MirrorsFile::load(&config.mirror_file)?;
    let mirror_manager = opengit_core::MirrorManager::new(&mirrors);
    let mirror_names = mirror_manager.mirror_names();

    tracing::info!("🐉 OpenGit starting...");
    tracing::info!("   Repos:    {}", config.repos_dir.display());
    tracing::info!("   Bind:     {}", config.bind);
    tracing::info!("   Policy:   {}", config.policy_file.display());
    tracing::info!("   Identity: {}", config.identity_file.display());
    tracing::info!("   Webhook:  {}", config.webhook_file.display());
    tracing::info!("   Audit:    {}", config.audit_file.display());
    tracing::info!("   Plugins:  {}", plugin_names.join(", "));
    if mirror_names.is_empty() {
        tracing::info!("   Mirrors:  none configured");
    } else {
        tracing::info!("   Mirrors:  {}", mirror_names.join(", "));
    }

    let ssh_enabled = cli.ssh || !config.ssh_bind.is_empty();
    if ssh_enabled {
        tracing::info!(
            "   SSH:      {} (run `opengit-sshd` separately)",
            config.ssh_bind
        );
    } else {
        tracing::info!("   SSH:      disabled");
    }

    let app = api::build_router(&config)?;

    // HTTP server
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!("🐉 OpenGit HTTP listening on {}", config.bind);

    axum::serve(listener, app).await?;

    Ok(())
}
