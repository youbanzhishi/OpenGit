//! Group — Organization/group management for repository classification
//!
//! Supports hierarchical groups: Organization -> Team -> Project Group
//! Allows quick filtering and bulk operations on repositories.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Visibility level for groups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,   // Visible to all
    Internal, // Visible to authenticated users
    Private,  // Only visible to members
}

impl Default for Visibility {
    fn default() -> Self {
        Visibility::Private
    }
}

/// A repository group/organization for classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier
    pub id: String,
    /// Group name (e.g., "AI产品线", "Infrastructure")
    pub name: String,
    /// URL-friendly slug (auto-generated from name)
    pub slug: String,
    /// Optional description
    pub description: Option<String>,
    /// Parent group ID (for hierarchy support)
    pub parent_id: Option<String>,
    /// Visibility level
    #[serde(default)]
    pub visibility: Visibility,
    /// Repository count (cached)
    #[serde(default)]
    pub repo_count: usize,
    /// Tags for additional classification
    #[serde(default)]
    pub tags: Vec<String>,
    /// Created timestamp
    #[serde(default)]
    pub created_at: String,
    /// Updated timestamp
    #[serde(default)]
    pub updated_at: String,
}

impl Group {
    /// Create a new group
    pub fn new(name: &str) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            slug: Self::to_slug(name),
            description: None,
            parent_id: None,
            visibility: Visibility::default(),
            repo_count: 0,
            tags: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Create with full details
    pub fn with_details(
        name: &str,
        description: Option<String>,
        parent_id: Option<String>,
        visibility: Visibility,
        tags: Vec<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            slug: Self::to_slug(name),
            description,
            parent_id,
            visibility,
            repo_count: 0,
            tags,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Convert name to URL-friendly slug
    pub fn to_slug(name: &str) -> String {
        name.to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c
                } else if c.is_whitespace() || c == '-' || c == '_' {
                    '-'
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Update timestamp
    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
        self.touch();
    }

    /// Remove a tag
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
        self.touch();
    }
}

/// Storage for all groups
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupsFile {
    /// Groups indexed by ID
    pub groups: HashMap<String, Group>,
    /// Groups indexed by slug (for fast lookup)
    #[serde(skip)]
    pub by_slug: HashMap<String, String>,
    /// Group tree structure (parent -> children)
    #[serde(skip)]
    pub children: HashMap<String, Vec<String>>,
}

impl GroupsFile {
    /// Create a new groups store
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read groups file: {}", path.display()))?;
        let mut file: GroupsFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse groups file: {}", path.display()))?;
        file.rebuild_indices();
        Ok(file)
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .with_context(|| "Failed to serialize groups")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write groups file: {}", path.display()))?;
        Ok(())
    }

    /// Rebuild lookup indices
    pub fn rebuild_indices(&mut self) {
        self.by_slug.clear();
        self.children.clear();
        
        for (id, group) in &self.groups {
            self.by_slug.insert(group.slug.clone(), id.clone());
            if let Some(ref parent_id) = group.parent_id {
                self.children
                    .entry(parent_id.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
    }

    /// Create a new group
    pub fn create(&mut self, name: &str) -> Group {
        let group = Group::new(name);
        self.groups.insert(group.id.clone(), group.clone());
        self.by_slug.insert(group.slug.clone(), group.id.clone());
        group
    }

    /// Create with full details
    pub fn create_with_details(
        &mut self,
        name: &str,
        description: Option<String>,
        parent_id: Option<String>,
        visibility: Visibility,
        tags: Vec<String>,
    ) -> Result<Group> {
        // Check slug uniqueness
        let slug = Group::to_slug(name);
        if self.by_slug.contains_key(&slug) {
            anyhow::bail!("Group with slug '{}' already exists", slug);
        }
        
        // Validate parent exists if specified
        if let Some(ref pid) = parent_id {
            if !self.groups.contains_key(pid) {
                anyhow::bail!("Parent group '{}' not found", pid);
            }
        }

        let group = Group::with_details(name, description, parent_id, visibility, tags);
        self.groups.insert(group.id.clone(), group.clone());
        self.by_slug.insert(group.slug.clone(), group.id.clone());
        
        // Update children index
        if let Some(ref pid) = group.parent_id {
            self.children
                .entry(pid.clone())
                .or_default()
                .push(group.id.clone());
        }
        
        Ok(group)
    }

    /// Get group by ID
    pub fn get(&self, id: &str) -> Option<&Group> {
        self.groups.get(id)
    }

    /// Get group by slug
    pub fn get_by_slug(&self, slug: &str) -> Option<&Group> {
        self.by_slug.get(slug).and_then(|id| self.groups.get(id))
    }

    /// Get group by ID (mutable)
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Group> {
        self.groups.get_mut(id)
    }

    /// Update a group
    pub fn update(&mut self, id: &str, name: Option<&str>, description: Option<String>, visibility: Option<Visibility>) -> Result<Option<&Group>> {
        if let Some(group) = self.groups.get_mut(id) {
            if let Some(n) = name {
                group.name = n.to_string();
                group.slug = Group::to_slug(n);
            }
            if let Some(d) = description {
                group.description = Some(d);
            }
            if let Some(v) = visibility {
                group.visibility = v;
            }
            group.touch();
            self.rebuild_indices();
            Ok(Some(&self.groups[id]))
        } else {
            Ok(None)
        }
    }

    /// Delete a group (fails if it has children)
    pub fn delete(&mut self, id: &str) -> Result<bool> {
        if self.children.contains_key(id) && !self.children[id].is_empty() {
            anyhow::bail!("Cannot delete group with children");
        }
        
        if let Some(group) = self.groups.remove(id) {
            self.by_slug.remove(&group.slug);
            if let Some(ref parent_id) = group.parent_id {
                if let Some(children) = self.children.get_mut(parent_id) {
                    children.retain(|c| c != id);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all groups
    pub fn list(&self) -> Vec<&Group> {
        self.groups.values().collect()
    }

    /// List groups by parent (None for root groups)
    pub fn list_by_parent(&self, parent_id: Option<&str>) -> Vec<&Group> {
        self.groups
            .values()
            .filter(|g| g.parent_id.as_deref() == parent_id)
            .collect()
    }

    /// List groups by tag
    pub fn list_by_tag(&self, tag: &str) -> Vec<&Group> {
        self.groups
            .values()
            .filter(|g| g.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Get children of a group
    pub fn children(&self, id: &str) -> Vec<&Group> {
        self.children
            .get(id)
            .map(|ids| ids.iter().filter_map(|i| self.groups.get(i)).collect())
            .unwrap_or_default()
    }

    /// Search groups by name or tag
    pub fn search(&self, query: &str) -> Vec<&Group> {
        let q = query.to_lowercase();
        self.groups
            .values()
            .filter(|g| {
                g.name.to_lowercase().contains(&q)
                    || g.slug.contains(&q)
                    || g.description.as_ref().map(|d| d.to_lowercase().contains(&q)).unwrap_or(false)
                    || g.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Update repo count for a group
    pub fn update_repo_count(&mut self, id: &str, count: usize) {
        if let Some(group) = self.groups.get_mut(id) {
            group.repo_count = count;
        }
    }

    /// Get root groups (no parent)
    pub fn root_groups(&self) -> Vec<&Group> {
        self.list_by_parent(None)
    }
}

/// Group membership tracking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupMembership {
    /// group_id -> Vec<repo_name>
    pub memberships: HashMap<String, Vec<String>>,
}

impl GroupMembership {
    /// Add repository to group
    pub fn add_repo(&mut self, group_id: &str, repo_name: &str) {
        self.memberships
            .entry(group_id.to_string())
            .or_default()
            .push(repo_name.to_string());
    }

    /// Remove repository from group
    pub fn remove_repo(&mut self, group_id: &str, repo_name: &str) {
        if let Some(repos) = self.memberships.get_mut(group_id) {
            repos.retain(|r| r != repo_name);
            if repos.is_empty() {
                self.memberships.remove(group_id);
            }
        }
    }

    /// Get repos in group
    pub fn get_repos(&self, group_id: &str) -> Vec<&str> {
        self.memberships
            .get(group_id)
            .map(|r| r.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get groups for a repo
    pub fn get_groups_for_repo(&self, repo_name: &str) -> Vec<&str> {
        self.memberships
            .iter()
            .filter(|(_, repos)| repos.contains(&repo_name.to_string()))
            .map(|(g, _)| g.as_str())
            .collect()
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .with_context(|| "Failed to serialize group membership")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write membership file: {}", path.display()))?;
        Ok(())
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read membership file: {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse membership file: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slug_generation() {
        assert_eq!(Group::to_slug("AI 产品线"), "ai-产品线");
        assert_eq!(Group::to_slug("Infrastructure-Team"), "infrastructure-team");
        assert_eq!(Group::to_slug("数据库 DB"), "数据库-db");
    }

    #[test]
    fn test_group_crud() {
        let mut groups = GroupsFile::new();
        let g1 = groups.create("测试组");
        assert_eq!(g1.slug, "测试组");

        let g2 = groups.create_with_details(
            "子组",
            Some("这是一个子组".into()),
            Some(g1.id.clone()),
            Visibility::Internal,
            vec!["test".into()],
        ).unwrap();
        assert_eq!(g2.parent_id, Some(g1.id.clone()));

        assert_eq!(groups.list_by_parent(Some(&g1.id)).len(), 1);
        assert_eq!(groups.children(&g1.id).len(), 1);
    }

    #[test]
    fn test_membership() {
        let mut membership = GroupMembership::new();
        membership.add_repo("group1", "repo-a");
        membership.add_repo("group1", "repo-b");
        
        assert_eq!(membership.get_repos("group1").len(), 2);
        assert_eq!(membership.get_groups_for_repo("repo-a").len(), 1);
        
        membership.remove_repo("group1", "repo-a");
        assert_eq!(membership.get_repos("group1").len(), 1);
    }
}
