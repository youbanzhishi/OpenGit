//! Hook Installer — Install policy-enforcing hooks into bare repos

use anyhow::{Context, Result};
use std::path::Path;

/// Installs OpenGit hooks into a bare repository
pub struct HookInstaller;

impl HookInstaller {
    /// Install pre-receive, update, and post-receive hooks
    pub fn install(repo_path: &Path) -> Result<()> {
        let hooks_dir = repo_path.join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;

        // pre-receive hook
        Self::write_hook(&hooks_dir, "pre-receive", PRE_RECEIVE_SCRIPT)?;
        // update hook
        Self::write_hook(&hooks_dir, "update", UPDATE_SCRIPT)?;
        // post-receive hook
        Self::write_hook(&hooks_dir, "post-receive", POST_RECEIVE_SCRIPT)?;

        Ok(())
    }

    fn write_hook(hooks_dir: &Path, name: &str, content: &str) -> Result<()> {
        let path = hooks_dir.join(name);
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write hook: {}", name))?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }
}

const PRE_RECEIVE_SCRIPT: &str = r#"#!/bin/sh
# OpenGit pre-receive hook
# Evaluates push operations against policy
#
# Environment variables:
#   OPENGIT_REPO     - Repository name
#   OPENGIT_IDENTITY - Identity making the push
#   OPENGIT_CONFIG   - Path to OpenGit config directory

REPO="${OPENGIT_REPO:-unknown}"
IDENTITY="${OPENGIT_IDENTITY:-unknown}"

while read oldsha newsha refname; do
    # Delete branch check
    if [ "$newsha" = "0000000000000000000000000000000000000000" ]; then
        # Only humans can delete branches
        case "$IDENTITY" in
            agent-*)
                echo "❌ DENIED: delete-branch — 删除远程分支绝对禁止 ($refname) by $IDENTITY"
                exit 1
                ;;
        esac
    fi

    # Force push check (simplified — full check needs git rev-list)
    # In production, use opengit-pre-receive binary for full policy evaluation
done

exit 0
"#;

const UPDATE_SCRIPT: &str = r#"#!/bin/sh
# OpenGit update hook
# Per-ref evaluation

REFNAME="$1"
OLDSHA="$2"
NEWSHA="$3"
REPO="${OPENGIT_REPO:-unknown}"
IDENTITY="${OPENGIT_IDENTITY:-unknown}"

# Delete branch check
if [ "$NEWSHA" = "0000000000000000000000000000000000000000" ]; then
    case "$IDENTITY" in
        agent-*)
            echo "❌ DENIED: delete-branch — 删除远程分支绝对禁止 ($REFNAME) by $IDENTITY"
            exit 1
            ;;
    esac
fi

exit 0
"#;

const POST_RECEIVE_SCRIPT: &str = r#"#!/bin/sh
# OpenGit post-receive hook
# Logging only — non-blocking

while read oldsha newsha refname; do
    echo "✅ OpenGit: accepted push to $refname"
done

exit 0
"#;
