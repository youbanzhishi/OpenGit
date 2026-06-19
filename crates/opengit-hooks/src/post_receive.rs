//! Post-receive hook — Log and notify after a successful push
//!
//! Called after all refs have been updated successfully.
//! Used for audit logging and webhook notifications.

use std::io::{self, BufRead};

fn main() {
    let identity = std::env::var("OPENGIT_IDENTITY").unwrap_or_else(|_| "anonymous".into());

    let stdin = io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            eprintln!(
                "🐉 OpenGit: {} pushed {} → {} on {}",
                identity,
                &parts[0][..7.min(parts[0].len())],
                &parts[1][..7.min(parts[1].len())],
                parts[2],
            );
        }
    }
}
