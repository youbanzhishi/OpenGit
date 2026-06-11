//! Pre-receive hook — Evaluate policy for all ref updates atomically
//!
//! This binary is installed as a Git pre-receive hook.
//! It reads ref updates from stdin, evaluates them against policy,
//! and rejects the entire push if any ref violates policy.
//!
//! Environment variables (set by OpenGit server):
//!   OPENGIT_IDENTITY — The authenticated identity name
//!   OPENGIT_REPO     — The repository name
//!   OPENGIT_POLICY   — Path to policies.yaml
//!   OPENGIT_REPO_PATH — Path to the bare repo (for force push detection)

use std::io::{self, BufRead};
use std::path::PathBuf;

fn main() {
    let identity = std::env::var("OPENGIT_IDENTITY").unwrap_or_else(|_| "anonymous".into());
    let repo = std::env::var("OPENGIT_REPO").unwrap_or_else(|_| "unknown".into());
    let policy_path =
        std::env::var("OPENGIT_POLICY").unwrap_or_else(|_| "config/policies.yaml".into());
    let repo_path = std::env::var("OPENGIT_REPO_PATH").unwrap_or_else(|_| ".".into());

    // Load policy engine
    let engine = match opengit_core::PolicyEngine::from_file(&PathBuf::from(&policy_path)) {
        Ok(e) => e,
        Err(_) => opengit_core::PolicyEngine::new(),
    };

    // Read ref updates from stdin
    let stdin = io::stdin();
    let mut updates = Vec::new();

    for line in stdin.lock().lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            break;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            updates.push((
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            ));
        }
    }

    if updates.is_empty() {
        std::process::exit(0);
    }

    // Evaluate each ref update
    let mut denied = false;
    for (old_sha, new_sha, ref_name) in &updates {
        let result = engine.evaluate_push_with_repo(
            &repo,
            &identity,
            ref_name,
            old_sha,
            new_sha,
            &PathBuf::from(&repo_path),
        );

        if !result.is_allowed() {
            let action_str = format!("{:?}", result.action);
            eprintln!(
                "DRAGON_FIREWALL: DENIED — {} on {} by {} — {}",
                action_str,
                ref_name,
                identity,
                result.reason.as_deref().unwrap_or("policy denied"),
            );
            denied = true;
        }
    }

    if denied {
        std::process::exit(1);
    }
}
