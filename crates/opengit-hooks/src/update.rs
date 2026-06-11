//! Update hook — Per-ref evaluation (runs after pre-receive)
//!
//! Installed as: repo.git/hooks/update
//! Args: <ref-name> <old-sha> <new-sha>
//! Exit 0 = allow, Exit 1 = deny

use opengit_core::{
    audit::AuditLog,
    hook::{HookContext, HookPipeline, HookType, RefUpdate},
    policy::PolicyEngine,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        std::process::exit(1);
    }

    let ref_name = &args[1];
    let old_sha = &args[2];
    let new_sha = &args[3];

    let repo = std::env::var("OPENGIT_REPO").unwrap_or_else(|_| "unknown".into());
    let identity = std::env::var("OPENGIT_IDENTITY").unwrap_or_else(|_| "unknown".into());

    let policy_engine = PolicyEngine::new();
    let audit_log = AuditLog::new();
    let pipeline = HookPipeline::new(policy_engine, audit_log);

    let ctx = HookContext {
        repo,
        identity,
        hook_type: HookType::Update,
        env: Default::default(),
    };

    let update = RefUpdate {
        ref_name: ref_name.clone(),
        old_sha: old_sha.clone(),
        new_sha: new_sha.clone(),
    };

    let result = pipeline.process_update(&ctx, &update);

    if !result.allowed {
        eprintln!("{}", result.message);
        std::process::exit(1);
    }

    std::process::exit(0);
}
