//! Pre-receive hook — Evaluates push operations against policy
//!
//! Installed as: repo.git/hooks/pre-receive
//! Reads stdin: <old-sha> <new-sha> <ref-name>\n
//! Exit 0 = allow, Exit 1 = deny

use opengit_core::{
    audit::AuditLog,
    hook::{HookContext, HookPipeline, HookType, RefUpdate},
    policy::PolicyEngine,
};
use std::io::{self, Read};

fn main() {
    let repo = std::env::var("OPENGIT_REPO").unwrap_or_else(|_| "unknown".into());
    let identity = std::env::var("OPENGIT_IDENTITY").unwrap_or_else(|_| "unknown".into());

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap_or_default();

    let updates = HookPipeline::parse_pre_receive_input(&input);
    if updates.is_empty() {
        std::process::exit(0);
    }

    let policy_engine = PolicyEngine::new(); // In production, load from config
    let audit_log = AuditLog::new();
    let pipeline = HookPipeline::new(policy_engine, audit_log);

    let ctx = HookContext {
        repo,
        identity,
        hook_type: HookType::PreReceive,
        env: Default::default(),
    };

    let result = pipeline.process_pre_receive(&ctx, &updates);

    if !result.allowed {
        eprintln!("{}", result.message);
        std::process::exit(1);
    }

    std::process::exit(0);
}
