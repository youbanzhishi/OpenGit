//! OpenGit Server — Lightweight private Git service, agent-first
//!
//! P2: Streaming Smart HTTP, persistent state, webhooks, stats, auth-protected API.

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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("opengit=debug,opengit_core=debug")
        .init();

    let cli = Cli::parse();
    let config = ServerConfig::load(&cli)?;

    tracing::info!("🐉 OpenGit starting...");
    tracing::info!("   Repos:    {}", config.repos_dir.display());
    tracing::info!("   Bind:     {}", config.bind);
    tracing::info!("   Policy:   {}", config.policy_file.display());
    tracing::info!("   Identity: {}", config.identity_file.display());
    tracing::info!("   Webhook:  {}", config.webhook_file.display());
    tracing::info!("   Audit:    {}", config.audit_file.display());

    let app = api::build_router(&config)?;

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!("🐉 OpenGit listening on {}", config.bind);

    axum::serve(listener, app).await?;

    Ok(())
}
