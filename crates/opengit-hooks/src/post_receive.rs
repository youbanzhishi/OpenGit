//! Post-receive hook — Logging and notifications
//!
//! Installed as: repo.git/hooks/post-receive
//! Reads stdin: <old-sha> <new-sha> <ref-name>\n
//! Always exits 0 (non-blocking)

use opengit_core::hook::HookPipeline;
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap_or_default();

    let updates = HookPipeline::parse_pre_receive_input(&input);

    // Log accepted push
    for update in &updates {
        eprintln!(
            "✅ Accepted push: {} ({} -> {})",
            update.ref_name,
            &update.old_sha[..7.min(update.old_sha.len())],
            &update.new_sha[..7.min(update.new_sha.len())]
        );
    }

    std::process::exit(0);
}
