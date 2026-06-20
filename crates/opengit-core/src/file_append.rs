//! File Append API - Direct file append without full clone
//!
//! P8.3: API to append files to repository without cloning the entire repo.
//! Only allows appending new files, prevents modification or deletion.

use anyhow::{Context, Result};
use git2::{Signature, Tree, Repository as Git2Repo};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::SystemTime;

/// Request to append a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendFileRequest {
    /// Path of the file to append (must not already exist)
    pub path: String,
    /// Content of the file
    pub content: String,
    /// Commit message
    #[serde(default = "default_message")]
    pub message: String,
    /// Author information
    #[serde(default)]
    pub author: Option<AuthorInfo>,
}

fn default_message() -> String {
    "Append file via API".to_string()
}

/// Author information for the commit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorInfo {
    pub name: String,
    pub email: String,
}

impl Default for AuthorInfo {
    fn default() -> Self {
        Self {
            name: "opengit".to_string(),
            email: "opengit@local".to_string(),
        }
    }
}

/// Response from append operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendFileResponse {
    pub success: bool,
    pub sha: String,
    pub commit_id: String,
    pub path: String,
    pub message: String,
}

/// Append a file to a repository without cloning
pub fn append_file(
    repo_path: &Path,
    branch: &str,
    request: &AppendFileRequest,
) -> Result<AppendFileResponse> {
    // Open the repository
    let repo = Git2Repo::open(repo_path)
        .with_context(|| format!("Failed to open repository: {}", repo_path.display()))?;

    // Get the branch reference
    let branch_ref = format!("refs/heads/{}", branch);
    let branch_oid = repo.refname_to_id(&branch_ref)
        .with_context(|| format!("Failed to find branch: {}", branch))?;

    let branch_commit = repo.find_commit(branch_oid)
        .with_context(|| "Failed to find branch commit")?;

    let tree = branch_commit.tree()
        .with_context(|| "Failed to get branch tree")?;

    // Check if file already exists (prevent overwriting)
    if tree.get_path(std::path::Path::new(&request.path)).is_ok() {
        anyhow::bail!(
            "File '{}' already exists. Append API only allows creating new files.",
            request.path
        );
    }

    // Create the new blob with the file content
    let blob_oid = repo.blob(request.content.as_bytes())
        .with_context(|| "Failed to create blob")?;

    // Build new tree with the new file
    let mut tree_builder = repo.treebuilder(Some(&tree))?;
    tree_builder.insert(&request.path, blob_oid, 0o100644)?;

    let new_tree_oid = tree_builder.write()
        .with_context(|| "Failed to write tree")?;
    let new_tree = repo.find_tree(new_tree_oid)?;

    // Get signature
    let author = match &request.author {
        Some(a) => Signature::now(&a.name, &a.email)
            .with_context(|| "Invalid author signature")?,
        None => {
            // Try to get from config, fallback to default
            repo.signature()
                .unwrap_or_else(|_| Signature::now("opengit", "opengit@local").unwrap())
        }
    };

    // Create commit
    let commit_oid = repo.commit(
        Some(&branch_ref),
        &author,
        &author,
        &request.message,
        &new_tree,
        &[&branch_commit],
    ).with_context(|| "Failed to create commit")?;

    Ok(AppendFileResponse {
        success: true,
        sha: blob_oid.to_string(),
        commit_id: commit_oid.to_string(),
        path: request.path.clone(),
        message: request.message.clone(),
    })
}

/// Check if a file exists in a branch
pub fn file_exists(repo_path: &Path, branch: &str, path: &str) -> Result<bool> {
    let repo = Git2Repo::open(repo_path)
        .with_context(|| "Failed to open repository")?;

    let branch_ref = format!("refs/heads/{}", branch);
    let branch_oid = repo.refname_to_id(&branch_ref)?;

    let commit = repo.find_commit(branch_oid)?;
    let tree = commit.tree()?;

    Ok(tree.get_path(std::path::Path::new(path)).is_ok())
}

/// List files in a directory (recursive)
pub fn list_files(repo_path: &Path, branch: &str, dir: Option<&str>) -> Result<Vec<String>> {
    let repo = Git2Repo::open(repo_path)?;
    let branch_ref = format!("refs/heads/{}", branch);
    let branch_oid = repo.refname_to_id(&branch_ref)?;
    let commit = repo.find_commit(branch_oid)?;
    let tree = commit.tree()?;

    let prefix = dir.unwrap_or("");
    let mut files = Vec::new();

    collect_files_recursive(&repo, &tree, prefix, &mut files);

    Ok(files)
}

fn collect_files_recursive(repo: &Git2Repo, tree: &Tree, prefix: &str, files: &mut Vec<String>) {
    let entry_iter = tree.iter();

    for entry in entry_iter {
        if entry.kind() == Some(git2::ObjectType::Blob) {
            let name = entry.name().unwrap_or("");
            if prefix.is_empty() {
                files.push(name.to_string());
            } else {
                files.push(format!("{}/{}", prefix, name));
            }
        } else if entry.kind() == Some(git2::ObjectType::Tree) {
            let name = entry.name().unwrap_or("");
            let sub_prefix = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{}/{}", prefix, name)
            };
            if let Ok(sub_tree) = entry.to_object(repo).and_then(|obj| obj.into_tree().map_err(|e| e)) {
                collect_files_recursive(repo, &sub_tree, &sub_prefix, files);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_append_new_file() {
        // Create a temp git repo
        let temp_dir = TempDir::new().unwrap();
        let repo = Git2Repo::init(temp_dir.path()).unwrap();

        // Create initial commit
        let sig = Signature::now("test", "test@test.com").unwrap();
        let blob_oid = repo.blob(b"initial content").unwrap();
        let mut tree_builder = repo.treebuilder(None).unwrap();
        tree_builder.insert("README.md", blob_oid, 0o100644).unwrap();
        let tree_oid = tree_builder.write().unwrap();

        let tree = repo.find_tree(tree_oid).unwrap();
        repo.commit(
            Some("refs/heads/main"),
            &sig,
            &sig,
            "Initial commit",
            &tree,
            &[],
        ).unwrap();

        // Append a new file
        let request = AppendFileRequest {
            path: "new_file.txt".to_string(),
            content: "Hello, World!".to_string(),
            message: "Add new file via API".to_string(),
            author: None,
        };

        let result = append_file(temp_dir.path(), "main", &request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.success);
        assert_eq!(response.path, "new_file.txt");
    }

    #[test]
    fn test_append_prevents_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let repo = Git2Repo::init(temp_dir.path()).unwrap();

        let sig = Signature::now("test", "test@test.com").unwrap();
        let blob_oid = repo.blob(b"existing").unwrap();
        let mut tree_builder = repo.treebuilder(None).unwrap();
        tree_builder.insert("existing.txt", blob_oid, 0o100644).unwrap();
        let tree_oid = tree_builder.write().unwrap();

        let tree = repo.find_tree(tree_oid).unwrap();
        repo.commit(
            Some("refs/heads/main"),
            &sig,
            &sig,
            "Initial",
            &tree,
            &[],
        ).unwrap();

        // Try to append to existing file
        let request = AppendFileRequest {
            path: "existing.txt".to_string(),
            content: "should fail".to_string(),
            message: "Try overwrite".to_string(),
            author: None,
        };

        let result = append_file(temp_dir.path(), "main", &request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }
}
