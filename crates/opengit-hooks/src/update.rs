//! Update hook — Evaluate policy for a single ref update
//!
//! Called once per ref being updated, after pre-receive succeeds.
//! This is a secondary check — pre-receive is the primary gate.

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: update <ref> <old-sha> <new-sha>");
        std::process::exit(1);
    }

    let ref_name = &args[1];
    let old_sha = &args[2];
    let new_sha = &args[3];

    let identity = std::env::var("OPENGIT_IDENTITY").unwrap_or_else(|_| "anonymous".into());
    let repo = std::env::var("OPENGIT_REPO").unwrap_or_else(|_| "unknown".into());
    let policy_path =
        std::env::var("OPENGIT_POLICY").unwrap_or_else(|_| "config/policies.yaml".into());
    let repo_path = std::env::var("OPENGIT_REPO_PATH").unwrap_or_else(|_| ".".into());

    let engine = match opengit_core::PolicyEngine::from_file(&PathBuf::from(&policy_path)) {
        Ok(e) => e,
        Err(_) => opengit_core::PolicyEngine::new(),
    };

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
        std::process::exit(1);
    }
}
