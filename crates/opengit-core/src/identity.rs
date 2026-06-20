//! Identity — Agent and Human identity with authentication
//!
//! P2: Added find_mut() and remove() for runtime mutations.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Kind of identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    /// Autonomous agent (AI, CI/CD, bot)
    Agent,
    /// Human user
    Human,
}

/// An identity (agent or human) that can interact with Git
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique name (e.g., "agent-deploy", "human-alice")
    pub name: String,
    /// Kind of identity
    pub kind: IdentityKind,
    /// Associated tokens
    pub tokens: Vec<Token>,
    /// SSH public keys (for human users)
    pub ssh_keys: Vec<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Description
    pub description: Option<String>,
}

impl Identity {
    pub fn agent(name: &str) -> Self {
        Self {
            name: format!("agent-{}", name),
            kind: IdentityKind::Agent,
            tokens: Vec::new(),
            ssh_keys: Vec::new(),
            display_name: None,
            description: None,
        }
    }

    pub fn human(name: &str) -> Self {
        Self {
            name: format!("human-{}", name),
            kind: IdentityKind::Human,
            tokens: Vec::new(),
            ssh_keys: Vec::new(),
            display_name: None,
            description: None,
        }
    }

    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Generate a new token for this identity, returning the raw secret
    pub fn generate_token(&mut self, label: &str) -> String {
        let raw_secret = format!("og_{}_{}_{}", self.name, label, uuid::Uuid::new_v4());
        let token = Token::from_raw_secret(&self.name, label, &raw_secret);
        self.tokens.push(token);
        raw_secret
    }

    /// Verify a token against this identity
    pub fn verify_token(&self, secret: &str) -> bool {
        self.tokens.iter().any(|t| t.verify(secret))
    }

    /// Check if this identity is an agent
    pub fn is_agent(&self) -> bool {
        self.kind == IdentityKind::Agent
    }

    /// Check if this identity is a human
    pub fn is_human(&self) -> bool {
        self.kind == IdentityKind::Human
    }

    /// Check if this identity can perform a specific action (Agent-specific)
    /// Returns true if the action is allowed for agents
    pub fn agent_can_do(&self, action: &str) -> bool {
        if self.is_human() {
            return true; // Humans can do everything
        }

        // Agent permissions - restrictive by default
        match action {
            // Allowed for agents
            "read" | "Read" => true,
            "create_repo" | "CreateRepo" => true,
            "push" | "Push" => true,
            "tag" | "Tag" => true,
            "add_webhook" | "AddWebhook" => true,
            "add_mirror" | "AddMirror" => true,
            "add_policy" | "AddPolicy" => true,
            "import" | "Import" => true,
            "write_config" | "WriteConfig" => true,

            // Explicitly forbidden for agents
            "delete_repo" | "DeleteRepo" => false,
            "delete_policy" | "DeletePolicy" => false,
            "delete_webhook" | "DeleteWebhook" => false,
            "delete_mirror" | "DeleteMirror" => false,
            "admin" | "Admin" => false,
            "confirm" | "Confirm" => false,
            "force_push" | "ForcePush" => false,
            "delete_branch" | "DeleteBranch" => false,

            // Unknown actions - default to allowed for read, denied for write
            _ => {
                if action.starts_with("read") || action.starts_with("get") || action.starts_with("list") {
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// An authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token label (e.g., "deploy-key", "laptop")
    pub label: String,
    /// SHA256 hash of the secret (we never store the raw secret)
    pub secret_hash: String,
    /// When the token was created
    pub created_at: String,
    /// When the token expires (None = never)
    pub expires_at: Option<String>,
    /// Whether this token is revoked
    pub revoked: bool,
}

impl Token {
    /// Generate a new token, returning the Token struct
    pub fn generate(identity: &str, label: &str) -> Self {
        let secret = format!("og_{}_{}_{}", identity, label, uuid::Uuid::new_v4());
        Self::from_raw_secret(identity, label, &secret)
    }

    /// Create a Token from a raw secret string
    pub fn from_raw_secret(_identity: &str, label: &str, secret: &str) -> Self {
        let hash = Self::hash_secret(secret);
        Self {
            label: label.into(),
            secret_hash: hash,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            revoked: false,
        }
    }

    /// Hash a secret for storage
    fn hash_secret(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify a secret against this token
    pub fn verify(&self, secret: &str) -> bool {
        if self.revoked {
            return false;
        }
        Self::hash_secret(secret) == self.secret_hash
    }

    /// Revoke this token
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Identity store — manages all identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStore {
    identities: HashMap<String, Identity>,
}

#[allow(clippy::new_without_default)]
impl IdentityStore {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
        }
    }

    /// Load from a YAML file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read identity file: {}", path.display()))?;
        let store: IdentityStore =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse identity store")?;
        Ok(store)
    }

    /// Save to a YAML file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content =
            serde_yaml::to_string(self).with_context(|| "Failed to serialize identity store")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write identity file: {}", path.display()))?;
        Ok(())
    }

    /// Register a new identity
    pub fn register(&mut self, identity: Identity) {
        self.identities.insert(identity.name.clone(), identity);
    }

    /// Find an identity by name
    pub fn find(&self, name: &str) -> Option<&Identity> {
        self.identities.get(name)
    }

    /// Find a mutable reference to an identity by name
    pub fn find_mut(&mut self, name: &str) -> Option<&mut Identity> {
        self.identities.get_mut(name)
    }

    /// Remove an identity by name
    pub fn remove(&mut self, name: &str) -> Option<Identity> {
        self.identities.remove(name)
    }

    /// Find an identity by token
    pub fn find_by_token(&self, secret: &str) -> Option<&Identity> {
        self.identities.values().find(|i| i.verify_token(secret))
    }

    /// Authenticate with a token, returning the identity name
    pub fn authenticate(&self, secret: &str) -> Option<String> {
        self.find_by_token(secret).map(|i| i.name.clone())
    }

    /// List all identities
    pub fn list(&self) -> Vec<&Identity> {
        self.identities.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_identity() {
        let mut agent = Identity::agent("deploy");
        assert_eq!(agent.name, "agent-deploy");
        assert!(agent.is_agent());
        assert!(!agent.is_human());

        let secret = agent.generate_token("ci-key");
        assert!(agent.verify_token(&secret));
        assert!(!agent.verify_token("wrong-token"));
    }

    #[test]
    fn test_human_identity() {
        let mut human = Identity::human("alice").with_display_name("Alice");
        assert_eq!(human.name, "human-alice");
        assert!(human.is_human());

        let secret = human.generate_token("laptop");
        assert!(human.verify_token(&secret));
    }

    #[test]
    fn test_identity_store() {
        let mut store = IdentityStore::new();

        let mut agent = Identity::agent("deploy");
        agent.generate_token("ci");
        store.register(agent);

        let mut human = Identity::human("bob");
        human.generate_token("laptop");
        store.register(human);

        assert_eq!(store.list().len(), 2);
        assert!(store.find("agent-deploy").is_some());
        assert!(store.find("human-bob").is_some());
    }

    #[test]
    fn test_token_revocation() {
        let mut agent = Identity::agent("test");
        let secret = agent.generate_token("key");
        assert!(agent.verify_token(&secret));

        agent.tokens[0].revoke();
        assert!(!agent.verify_token(&secret));
    }

    #[test]
    fn test_identity_store_mutations() {
        let mut store = IdentityStore::new();

        let mut agent = Identity::agent("test");
        agent.generate_token("key");
        store.register(agent);

        // Find mutable
        let found = store.find_mut("agent-test");
        assert!(found.is_some());
        let found = found.unwrap();
        found.generate_token("second-key");

        assert_eq!(store.find("agent-test").unwrap().tokens.len(), 2);

        // Remove
        let removed = store.remove("agent-test");
        assert!(removed.is_some());
        assert!(store.find("agent-test").is_none());
    }

    #[test]
    fn test_identity_persistence() {
        let dir = std::env::temp_dir().join("opengit_identity_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("identities.yaml");

        {
            let mut store = IdentityStore::new();
            let mut agent = Identity::agent("ci");
            agent.generate_token("deploy");
            store.register(agent);
            store.save_to_file(&path).unwrap();
        }

        // Reload and verify
        let store = IdentityStore::from_file(&path).unwrap();
        assert!(store.find("agent-ci").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
