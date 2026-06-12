//! OpenGit CLI — Command-line management tool
//!
//! `og` — Manage OpenGit servers: identities, policies, repos, webhooks, audit.
//!
//! P3: Full CLI management client for OpenGit server.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(
    name = "og",
    version,
    about = "OpenGit CLI — Manage your OpenGit server"
)]
struct Cli {
    /// Server URL
    #[arg(long, default_value = "http://localhost:9418", global = true)]
    server: String,

    /// Authentication token
    #[arg(long, env = "OPENGIT_TOKEN", global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List repositories
    Repos {
        /// Create a new repository
        #[arg(short, long)]
        create: Option<String>,
        /// Delete a repository (requires confirmation)
        #[arg(short, long)]
        delete: Option<String>,
    },
    /// List and manage refs for a repository
    Refs {
        /// Repository name
        repo: String,
    },
    /// Manage identities
    Identities {
        #[command(subcommand)]
        action: IdentityActions,
    },
    /// Manage policies
    Policy {
        #[command(subcommand)]
        action: PolicyActions,
    },
    /// View audit log
    Audit {
        /// Show only denied operations
        #[arg(long)]
        denied: bool,
    },
    /// Manage webhooks
    Webhooks {
        #[command(subcommand)]
        action: WebhookActions,
    },
    /// View server stats
    Stats,
    /// Import a repository from external Git URL
    Import {
        /// Remote Git URL to import (e.g., https://github.com/user/repo.git)
        url: String,
        /// Local repository name (derived from URL if not specified)
        #[arg(short, long)]
        name: Option<String>,
        /// Username for HTTPS authentication
        #[arg(short, long)]
        username: Option<String>,
        /// Password/token for HTTPS authentication
        #[arg(short, long)]
        password: Option<String>,
        /// Repository description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Migrate repositories from Gitea
    MigrateGitea {
        /// Gitea server URL (e.g., https://gitea.example.com)
        server_url: String,
        /// Gitea API token
        #[arg(long, env = "GITEA_TOKEN")]
        token: String,
        /// Owner/organization to migrate
        #[arg(short, long)]
        owner: Option<String>,
        /// Specific repos to migrate (comma-separated)
        #[arg(short, long)]
        repos: Option<String>,
        /// Include labels
        #[arg(long, default_value = "true")]
        include_labels: bool,
        /// Include milestones
        #[arg(long, default_value = "true")]
        include_milestones: bool,
        /// Include releases
        #[arg(long)]
        include_releases: bool,
        /// Name prefix for imported repos
        #[arg(long, default_value = "")]
        name_prefix: String,
        /// Clone username (if different from API token)
        #[arg(long)]
        clone_username: Option<String>,
        /// Clone password
        #[arg(long)]
        clone_password: Option<String>,
    },
    /// View import status
    ImportStatus,
    /// Health check
    Health,
}

#[derive(Subcommand, Debug)]
enum IdentityActions {
    /// List all identities
    List,
    /// Register a new identity
    Register {
        /// Identity name
        name: String,
        /// Kind: agent or human
        #[arg(long, default_value = "agent")]
        kind: String,
        /// Display name
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Generate a token for an identity
    Token {
        /// Identity name
        name: String,
        /// Token label
        #[arg(short, long, default_value = "default")]
        label: String,
    },
    /// Delete an identity
    Delete {
        /// Identity name
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyActions {
    /// List policy rules
    Rules,
    /// Add a policy rule
    AddRule {
        /// Identity pattern (e.g., "agent-deploy", "human-*")
        #[arg(long)]
        identity: String,
        /// Action (push, force-push, delete-branch, tag, read, admin, etc.)
        #[arg(long)]
        action: String,
        /// Permission (allow, deny, audit-log, confirm)
        #[arg(long)]
        permission: String,
        /// Repository pattern (default: "*" = all repos)
        #[arg(long, default_value = "*")]
        repo: Option<String>,
        /// Reason for the rule
        #[arg(long)]
        reason: Option<String>,
    },
    /// Evaluate a policy (dry run)
    Eval {
        /// Repository name
        #[arg(long)]
        repo: String,
        /// Identity name
        #[arg(long)]
        identity: String,
        /// Action to evaluate
        #[arg(long)]
        action: String,
    },
}

#[derive(Subcommand, Debug)]
enum WebhookActions {
    /// List webhooks
    List,
    /// Add a webhook
    Add {
        /// Webhook URL
        url: String,
        /// Secret for HMAC-SHA256 signing
        #[arg(long)]
        secret: Option<String>,
        /// Events (comma-separated: push,tag,delete-branch)
        #[arg(long, default_value = "push,tag,delete-branch")]
        events: String,
    },
    /// Delete a webhook by index
    Delete {
        /// Webhook index (from list)
        idx: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("og=debug").init();

    let cli = Cli::parse();
    let client = ApiClient::new(&cli.server, cli.token.as_deref());

    match cli.command {
        Commands::Repos { create, delete } => {
            if let Some(name) = create {
                let repo = client.create_repo(&name).await?;
                println!("✅ Created repo: {} ({})", repo.name, repo.path);
            } else if let Some(name) = delete {
                client.delete_repo(&name).await?;
                println!("✅ Deleted repo: {}", name);
            } else {
                let repos = client.list_repos().await?;
                if repos.is_empty() {
                    println!("No repositories found.");
                } else {
                    println!("{:<30} {:<10} PATH", "NAME", "BARE");
                    for r in &repos {
                        println!("{:<30} {:<10} {}", r.name, r.bare, r.path);
                    }
                    println!("\n{} repos total", repos.len());
                }
            }
        }
        Commands::Refs { repo } => {
            let refs = client.list_refs(&repo).await?;
            if refs.is_empty() {
                println!("No refs found for {}", repo);
            } else {
                println!("{:<40} {:<8} SHA", "REF", "KIND");
                for r in &refs {
                    println!("{:<40} {:<8} {}", r.name, r.kind, r.sha);
                }
            }
        }
        Commands::Identities { action } => match action {
            IdentityActions::List => {
                let identities = client.list_identities().await?;
                if identities.is_empty() {
                    println!("No identities found.");
                } else {
                    println!("{:<20} {:<10} {:<20} TOKENS", "NAME", "KIND", "DISPLAY");
                    for i in &identities {
                        println!(
                            "{:<20} {:<10} {:<20} {}",
                            i.name,
                            i.kind,
                            i.display_name.as_deref().unwrap_or("-"),
                            i.token_count
                        );
                    }
                }
            }
            IdentityActions::Register {
                name,
                kind,
                display_name,
            } => {
                let info = client
                    .register_identity(&name, &kind, display_name.as_deref())
                    .await?;
                println!("✅ Registered {} ({})", info.name, info.kind);
            }
            IdentityActions::Token { name, label } => {
                let resp = client.generate_token(&name, &label).await?;
                println!("🔑 Token for {} (label: {}):", resp.identity, resp.label);
                println!("   {}", resp.token);
                println!("\n⚠️  Save this token — it won't be shown again!");
            }
            IdentityActions::Delete { name } => {
                client.delete_identity(&name).await?;
                println!("✅ Deleted identity: {}", name);
            }
        },
        Commands::Policy { action } => match action {
            PolicyActions::Rules => {
                let rules = client.list_policy_rules().await?;
                if rules.is_empty() {
                    println!("No custom policy rules found.");
                } else {
                    println!(
                        "{:<20} {:<20} {:<15} {:<10} REASON",
                        "IDENTITY", "ACTION", "PERMISSION", "REPO"
                    );
                    for r in &rules {
                        println!(
                            "{:<20} {:<20} {:<15} {:<10} {}",
                            r.identity,
                            r.action,
                            r.permission,
                            r.repo,
                            r.reason.as_deref().unwrap_or("-")
                        );
                    }
                }
            }
            PolicyActions::AddRule {
                identity,
                action,
                permission,
                repo,
                reason,
            } => {
                client
                    .add_policy_rule(
                        repo.as_deref(),
                        &identity,
                        &action,
                        &permission,
                        reason.as_deref(),
                    )
                    .await?;
                println!(
                    "✅ Added policy rule: {} → {} → {}",
                    identity, action, permission
                );
            }
            PolicyActions::Eval {
                repo,
                identity,
                action,
            } => {
                let result = client.eval_policy(&repo, &identity, &action).await?;
                println!(
                    "{}: {} can {} on {} — {:?}{}",
                    if result.permission.is_allowed() {
                        "✅ ALLOW"
                    } else {
                        "❌ DENY"
                    },
                    identity,
                    action,
                    repo,
                    result.permission,
                    result
                        .reason
                        .map(|r| format!(" ({})", r))
                        .unwrap_or_default()
                );
            }
        },
        Commands::Audit { denied } => {
            let entries = if denied {
                client.denied_audit().await?
            } else {
                client.audit().await?
            };
            if entries.is_empty() {
                println!("No audit entries found.");
            } else {
                println!(
                    "{:<25} {:<15} {:<20} {:<15} RESULT",
                    "TIME", "IDENTITY", "REPO", "ACTION"
                );
                for e in &entries {
                    println!(
                        "{:<25} {:<15} {:<20} {:<15} {}",
                        &e.timestamp[..23.min(e.timestamp.len())],
                        e.identity,
                        e.repo,
                        e.action,
                        if e.allowed { "✅" } else { "❌" }
                    );
                }
            }
        }
        Commands::Webhooks { action } => match action {
            WebhookActions::List => {
                let webhooks = client.list_webhooks().await?;
                if webhooks.is_empty() {
                    println!("No webhooks configured.");
                } else {
                    for (i, w) in webhooks.iter().enumerate() {
                        let events: Vec<&str> = w
                            .events
                            .iter()
                            .map(|e| match e {
                                WebhookEventInfo::Push => "push",
                                WebhookEventInfo::Tag => "tag",
                                WebhookEventInfo::DeleteBranch => "delete-branch",
                            })
                            .collect();
                        println!(
                            "[{}] {} — events: {} — active: {}",
                            i,
                            w.url,
                            events.join(","),
                            w.active
                        );
                    }
                }
            }
            WebhookActions::Add {
                url,
                secret,
                events,
            } => {
                let event_list: Vec<String> =
                    events.split(',').map(|s| s.trim().to_string()).collect();
                client
                    .add_webhook(&url, secret.as_deref(), &event_list)
                    .await?;
                println!("✅ Added webhook: {}", url);
            }
            WebhookActions::Delete { idx } => {
                client.delete_webhook(idx).await?;
                println!("✅ Deleted webhook [{}]", idx);
            }
        },
        Commands::Stats => {
            let stats = client.stats().await?;
            println!("🐉 OpenGit Server Stats");
            println!("   Repos:          {}", stats.total_repos);
            println!("   Total pushes:   {}", stats.total_pushes);
            println!("   Total clones:   {}", stats.total_clones);
            println!("   Total denials:  {}", stats.total_denials);
            println!("   Webhooks sent:  {}", stats.total_webhooks_sent);
            println!("   Uptime:         {}s", stats.uptime_seconds);
        }
        Commands::Import {
            url,
            name,
            username,
            password,
            description,
        } => {
            let result = client
                .import_repo(
                    &url,
                    name.as_deref(),
                    username.as_deref(),
                    password.as_deref(),
                    description.as_deref(),
                )
                .await?;
            if result.success {
                println!(
                    "✅ Imported: {} ({} branches, {} tags)",
                    result.name, result.branches, result.tags
                );
                println!("   Source: {}", result.source_url);
                println!("   Time: {:.1}s", result.elapsed_secs);
            } else {
                println!(
                    "❌ Import failed: {}",
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
        Commands::MigrateGitea {
            server_url,
            token,
            owner,
            repos,
            include_labels,
            include_milestones,
            include_releases,
            name_prefix,
            clone_username,
            clone_password,
        } => {
            let repo_list: Vec<String> = repos
                .as_deref()
                .map(|s| s.split(',').map(|r| r.trim().to_string()).collect())
                .unwrap_or_default();

            println!("🔄 Starting Gitea migration from {}...", server_url);
            let result = client
                .migrate_gitea(
                    &server_url,
                    &token,
                    owner.as_deref(),
                    &repo_list,
                    include_labels,
                    include_milestones,
                    include_releases,
                    &name_prefix,
                    clone_username.as_deref(),
                    clone_password.as_deref(),
                )
                .await?;

            println!("\n🐉 Migration complete!");
            println!("   Total discovered: {}", result.total);
            println!("   Successfully imported: {}", result.imported);
            println!("   Failed: {}", result.failed);
            println!("   Time: {:.1}s", result.elapsed_secs);

            if result.failed > 0 {
                println!("\n❌ Failed imports:");
                for r in &result.results {
                    if !r.success {
                        println!(
                            "   {} — {}",
                            r.name,
                            r.error.as_deref().unwrap_or("unknown")
                        );
                    }
                }
            }
        }
        Commands::ImportStatus => {
            let status = client.import_status().await?;
            if status.is_empty() {
                println!("No imports recorded.");
            } else {
                println!(
                    "{:<25} {:<8} {:<8} {:<8} RESULT",
                    "NAME", "BRANCHES", "TAGS", "TIME"
                );
                for r in &status {
                    println!(
                        "{:<25} {:<8} {:<8} {:<8.1} {}",
                        r.name,
                        r.branches,
                        r.tags,
                        r.elapsed_secs,
                        if r.success { "✅" } else { "❌" }
                    );
                }
            }
        }
        Commands::Health => match client.health().await {
            Ok(msg) => println!("✅ {}", msg),
            Err(e) => println!("❌ Server unreachable: {}", e),
        },
    }

    Ok(())
}

// ─── API Client ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoInfo {
    name: String,
    path: String,
    bare: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefInfo {
    name: String,
    sha: String,
    kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityInfo {
    name: String,
    kind: String,
    display_name: Option<String>,
    token_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenerateTokenResponse {
    identity: String,
    token: String,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyRuleInfo {
    identity: String,
    action: String,
    permission: String,
    repo: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvalResult {
    permission: opengit_core::policy::Permission,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEntry {
    timestamp: String,
    identity: String,
    repo: String,
    action: String,
    allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookInfo {
    url: String,
    events: Vec<WebhookEventInfo>,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WebhookEventInfo {
    Push,
    Tag,
    DeleteBranch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatsInfo {
    total_repos: u64,
    total_pushes: u64,
    total_clones: u64,
    total_denials: u64,
    total_webhooks_sent: u64,
    uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImportResultInfo {
    name: String,
    source_url: String,
    branches: usize,
    tags: usize,
    elapsed_secs: f64,
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationResultInfo {
    total: usize,
    imported: usize,
    failed: usize,
    results: Vec<ImportResultInfo>,
    elapsed_secs: f64,
}

struct ApiClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl ApiClient {
    fn new(base_url: &str, token: Option<&str>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.map(|t| t.to_string()),
            http: reqwest::Client::new(),
        }
    }

    fn auth_header(&self) -> Option<String> {
        self.token.as_ref().map(|t| format!("Bearer {}", t))
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let mut req = self.http.get(format!("{}{}", self.base_url, path));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("Request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", status, body);
        }
        resp.json().await.context("Failed to parse response")
    }

    #[allow(dead_code)]
    async fn post_empty<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let mut req = self.http.post(format!("{}{}", self.base_url, path));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("Request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", status, body);
        }
        resp.json().await.context("Failed to parse response")
    }

    async fn post_json<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let mut req = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .json(body);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("Request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", status, body);
        }
        resp.json().await.context("Failed to parse response")
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let mut req = self.http.delete(format!("{}{}", self.base_url, path));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("Request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", status, body);
        }
        Ok(())
    }

    // ─── API Methods ──────────────────────────────────────────────

    async fn health(&self) -> Result<String> {
        self.get::<String>("/health").await
    }

    async fn list_repos(&self) -> Result<Vec<RepoInfo>> {
        self.get("/api/repos").await
    }

    async fn create_repo(&self, name: &str) -> Result<RepoInfo> {
        self.post_json("/api/repos", &serde_json::json!({ "name": name }))
            .await
    }

    async fn delete_repo(&self, name: &str) -> Result<()> {
        self.delete(&format!("/api/repos/{}", name)).await
    }

    async fn list_refs(&self, repo: &str) -> Result<Vec<RefInfo>> {
        self.get(&format!("/api/repos/{}/refs", repo)).await
    }

    async fn list_identities(&self) -> Result<Vec<IdentityInfo>> {
        self.get("/api/identities").await
    }

    async fn register_identity(
        &self,
        name: &str,
        kind: &str,
        display_name: Option<&str>,
    ) -> Result<IdentityInfo> {
        self.post_json(
            "/api/identities",
            &serde_json::json!({
                "name": name,
                "kind": kind,
                "display_name": display_name
            }),
        )
        .await
    }

    async fn generate_token(&self, name: &str, label: &str) -> Result<GenerateTokenResponse> {
        self.post_json(
            &format!("/api/identities/{}/tokens", name),
            &serde_json::json!({ "label": label }),
        )
        .await
    }

    async fn delete_identity(&self, name: &str) -> Result<()> {
        self.delete(&format!("/api/identities/{}", name)).await
    }

    async fn list_policy_rules(&self) -> Result<Vec<PolicyRuleInfo>> {
        self.get("/api/policy/rules").await
    }

    async fn add_policy_rule(
        &self,
        repo: Option<&str>,
        identity: &str,
        action: &str,
        permission: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut req = self
            .http
            .post(format!("{}/api/policy/rules", self.base_url))
            .json(&serde_json::json!({
                "repo": repo,
                "identity": identity,
                "action": action,
                "permission": permission,
                "reason": reason
            }));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("Request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", status, body);
        }
        Ok(())
    }

    async fn eval_policy(&self, repo: &str, identity: &str, action: &str) -> Result<EvalResult> {
        self.post_json(
            "/api/policy/eval",
            &serde_json::json!({
                "repo": repo,
                "identity": identity,
                "action": action
            }),
        )
        .await
    }

    async fn audit(&self) -> Result<Vec<AuditEntry>> {
        self.get("/api/audit").await
    }

    async fn denied_audit(&self) -> Result<Vec<AuditEntry>> {
        self.get("/api/audit/denied").await
    }

    async fn list_webhooks(&self) -> Result<Vec<WebhookInfo>> {
        self.get("/api/webhooks").await
    }

    async fn add_webhook(&self, url: &str, secret: Option<&str>, events: &[String]) -> Result<()> {
        let mut req = self
            .http
            .post(format!("{}/api/webhooks", self.base_url))
            .json(&serde_json::json!({
                "url": url,
                "secret": secret,
                "events": events
            }));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("Request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", status, body);
        }
        Ok(())
    }

    async fn delete_webhook(&self, idx: usize) -> Result<()> {
        self.delete(&format!("/api/webhooks/{}", idx)).await
    }

    async fn stats(&self) -> Result<StatsInfo> {
        self.get("/api/stats").await
    }

    // ─── Import & Migration API Methods ──────────────────────────

    async fn import_repo(
        &self,
        url: &str,
        name: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        description: Option<&str>,
    ) -> Result<ImportResultInfo> {
        self.post_json(
            "/api/import",
            &serde_json::json!({
                "url": url,
                "name": name,
                "mirror": true,
                "username": username,
                "password": password,
                "description": description,
            }),
        )
        .await
    }

    async fn migrate_gitea(
        &self,
        server_url: &str,
        token: &str,
        owner: Option<&str>,
        repos: &[String],
        include_labels: bool,
        include_milestones: bool,
        include_releases: bool,
        name_prefix: &str,
        clone_username: Option<&str>,
        clone_password: Option<&str>,
    ) -> Result<MigrationResultInfo> {
        self.post_json(
            "/api/import/gitea",
            &serde_json::json!({
                "server_url": server_url,
                "token": token,
                "owner": owner,
                "repos": repos,
                "include_labels": include_labels,
                "include_milestones": include_milestones,
                "include_releases": include_releases,
                "name_prefix": name_prefix,
                "clone_username": clone_username,
                "clone_password": clone_password,
            }),
        )
        .await
    }

    async fn import_status(&self) -> Result<Vec<ImportResultInfo>> {
        self.get("/api/import/status").await
    }
}
