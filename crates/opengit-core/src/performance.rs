//! Performance module — Connection pooling, caching, and lazy loading
//!
//! P10: Performance optimization for production use
//!
//! Features:
//! - Git object cache (in-memory)
//! - Connection pool for HTTP/HTTPS
//! - Ref resolution cache
//! - Lazy loading for large repositories

use ahash::{AHashMap, AHashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Git object cache for frequently accessed objects
pub struct GitObjectCache {
    /// Cache entries by path + object id
    entries: RwLock<AHashMap<CacheKey, CacheEntry>>,
    /// Access statistics
    stats: RwLock<CacheStats>,
    /// Maximum cache size (bytes)
    max_size: usize,
    /// Current cache size (bytes)
    current_size: RwLock<usize>,
    /// TTL for entries
    ttl: Duration,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    repo_path: PathBuf,
    object_id: String,
    object_type: String,
}

struct CacheEntry {
    data: Vec<u8>,
    size: usize,
    created: Instant,
    last_accessed: Instant,
    access_count: u64,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    total_size: usize,
}

impl GitObjectCache {
    pub fn new(max_size_mb: usize, ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(AHashMap::new()),
            stats: RwLock::new(CacheStats::default()),
            max_size: max_size_mb * 1024 * 1024,
            current_size: RwLock::new(0),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get an entry from cache
    pub async fn get(
        &self,
        repo_path: &Path,
        object_id: &str,
        object_type: &str,
    ) -> Option<Vec<u8>> {
        let key = CacheKey {
            repo_path: repo_path.to_path_buf(),
            object_id: object_id.to_string(),
            object_type: object_type.to_string(),
        };

        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(&key) {
            // Check TTL
            if entry.created.elapsed() > self.ttl {
                entries.remove(&key);
                drop(entries);
                self.record_miss().await;
                return None;
            }

            // Update access info
            entry.last_accessed = Instant::now();
            entry.access_count += 1;

            drop(entries);
            self.record_hit().await;

            let entries = self.entries.read().await;
            return entries.get(&key).map(|e| e.data.clone());
        }

        drop(entries);
        self.record_miss().await;
        None
    }

    /// Insert an entry into cache
    pub async fn put(
        &self,
        repo_path: PathBuf,
        object_id: String,
        object_type: String,
        data: Vec<u8>,
    ) {
        let size = data.len();
        let key = CacheKey {
            repo_path,
            object_id,
            object_type,
        };

        // Evict if necessary
        self.evict_if_needed(size).await;

        let mut entries = self.entries.write().await;
        let entry = CacheEntry {
            data: data.clone(),
            size,
            created: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
        };

        let old_size = entries.insert(key, entry).map(|e| e.size).unwrap_or(0);
        drop(entries);

        let mut current = self.current_size.write().await;
        *current = current.saturating_sub(old_size) + size;
    }

    async fn evict_if_needed(&self, new_size: usize) {
        let mut current = self.current_size.write().await;
        if *current + new_size <= self.max_size {
            return;
        }

        // Need to evict
        let mut entries = self.entries.write().await;

        // Sort by access time (oldest first)
        let mut entries_vec: Vec<_> = entries.iter_mut().collect();
        entries_vec.sort_by_key(|a| a.1.last_accessed);

        let mut freed = 0;
        let target = *current + new_size - self.max_size;
        let mut keys_to_remove: Vec<_> = Vec::new();

        while freed < target && !entries_vec.is_empty() {
            if let Some((key, entry)) = entries_vec.pop() {
                freed += entry.size;
                keys_to_remove.push(key.clone());
            }
        }

        for key in keys_to_remove {
            entries.remove(&key);
        }

        *current = current.saturating_sub(freed);

        let mut stats = self.stats.write().await;
        stats.evictions += 1;
    }

    async fn record_hit(&self) {
        let mut stats = self.stats.write().await;
        stats.hits += 1;
    }

    async fn record_miss(&self) {
        let mut stats = self.stats.write().await;
        stats.misses += 1;
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStatsSnapshot {
        let stats = self.stats.read().await;
        let current_size = *self.current_size.read().await;
        let entry_count = self.entries.read().await.len();

        CacheStatsSnapshot {
            hits: stats.hits,
            misses: stats.misses,
            hit_rate: if stats.hits + stats.misses > 0 {
                stats.hits as f64 / (stats.hits + stats.misses) as f64
            } else {
                0.0
            },
            evictions: stats.evictions,
            current_size_mb: current_size as f64 / 1024.0 / 1024.0,
            max_size_mb: self.max_size as f64 / 1024.0 / 1024.0,
            entry_count,
        }
    }

    /// Clear the cache
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        let mut current = self.current_size.write().await;
        *current = 0;
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub evictions: u64,
    pub current_size_mb: f64,
    pub max_size_mb: f64,
    pub entry_count: usize,
}

/// HTTP connection pool settings
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per host
    pub max_per_host: usize,
    /// Maximum total connections
    pub max_total: usize,
    /// Connection timeout (seconds)
    pub connect_timeout_secs: u64,
    /// Request timeout (seconds)
    pub request_timeout_secs: u64,
    /// Idle connection timeout (seconds)
    pub idle_timeout_secs: u64,
    /// Enable TCP keepalive
    pub tcp_keepalive: bool,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_per_host: 32,
            max_total: 256,
            connect_timeout_secs: 30,
            request_timeout_secs: 60,
            idle_timeout_secs: 90,
            tcp_keepalive: true,
        }
    }
}

/// HTTP client builder with connection pooling
pub fn create_http_client(config: &ConnectionPoolConfig) -> reqwest::Client {
    reqwest::ClientBuilder::new()
        .pool_max_idle_per_host(config.max_per_host)
        .tcp_keepalive(config.tcp_keepalive.then_some(Duration::from_secs(60)))
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()
        .expect("Failed to create HTTP client")
}

/// Ref resolution cache
pub struct RefCache {
    /// Cache entries by repo + ref name
    entries: RwLock<AHashMap<RefKey, RefEntry>>,
    /// TTL for entries
    ttl: Duration,
    /// Maximum entries
    max_entries: usize,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RefKey {
    repo_path: PathBuf,
    ref_name: String,
}

struct RefEntry {
    sha: String,
    resolved: Instant,
}

impl RefCache {
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(AHashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
            max_entries,
        }
    }

    /// Get cached SHA for a ref
    pub async fn get(&self, repo_path: &Path, ref_name: &str) -> Option<String> {
        let key = RefKey {
            repo_path: repo_path.to_path_buf(),
            ref_name: ref_name.to_string(),
        };

        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(&key) {
            if entry.resolved.elapsed() < self.ttl {
                return Some(entry.sha.clone());
            }
            entries.remove(&key);
        }
        None
    }

    /// Store SHA for a ref
    pub async fn put(&self, repo_path: PathBuf, ref_name: String, sha: String) {
        let key = RefKey {
            repo_path,
            ref_name,
        };

        let mut entries = self.entries.write().await;

        // Evict oldest if at capacity
        if entries.len() >= self.max_entries {
            // Find and remove oldest
            let oldest_key = entries
                .iter()
                .min_by_key(|(_, e)| e.resolved)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                entries.remove(&key);
            }
        }

        entries.insert(
            key,
            RefEntry {
                sha,
                resolved: Instant::now(),
            },
        );
    }

    /// Invalidate cache for a repository
    pub async fn invalidate_repo(&self, repo_path: &Path) {
        let mut entries = self.entries.write().await;
        entries.retain(|k, _| k.repo_path != *repo_path);
    }

    /// Clear the cache
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}

/// Repository metadata cache
#[allow(dead_code)]
pub struct RepoMetaCache {
    entries: RwLock<AHashMap<PathBuf, RepoMeta>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RepoMeta {
    branch_count: usize,
    tag_count: usize,
    total_refs: usize,
    last_modified: Instant,
    file_count: usize,
    size_bytes: u64,
}

impl RepoMetaCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(AHashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub async fn get(&self, repo_path: &Path) -> Option<RepoMeta> {
        let entries = self.entries.read().await;
        entries.get(repo_path).cloned()
    }

    pub async fn put(&self, repo_path: PathBuf, meta: RepoMeta) {
        let mut entries = self.entries.write().await;
        entries.insert(repo_path, meta);
    }

    pub async fn invalidate(&self, repo_path: &Path) {
        let mut entries = self.entries.write().await;
        entries.remove(repo_path);
    }
}

/// Lazy repository scanner
pub struct LazyRepoScanner {
    /// Repositories that have been scanned
    scanned: RwLock<AHashSet<PathBuf>>,
    /// Scan in progress
    scanning: RwLock<AHashSet<PathBuf>>,
}

impl LazyRepoScanner {
    pub fn new() -> Self {
        Self {
            scanned: RwLock::new(AHashSet::new()),
            scanning: RwLock::new(AHashSet::new()),
        }
    }

    /// Check if repository needs scanning
    pub async fn needs_scan(&self, repo_path: &Path) -> bool {
        let scanned = self.scanned.read().await;
        !scanned.contains(repo_path)
    }

    /// Mark repository as scanning
    pub async fn start_scan(&self, repo_path: &Path) -> bool {
        let mut scanning = self.scanning.write().await;
        if scanning.contains(repo_path) {
            return false;
        }
        scanning.insert(repo_path.to_path_buf());
        true
    }

    /// Mark repository as scanned
    pub async fn finish_scan(&self, repo_path: &Path) {
        let mut scanned = self.scanned.write().await;
        scanned.insert(repo_path.to_path_buf());

        let mut scanning = self.scanning.write().await;
        scanning.remove(repo_path);
    }

    /// Reset all scanned state
    pub async fn reset(&self) {
        let mut scanned = self.scanned.write().await;
        scanned.clear();
        let mut scanning = self.scanning.write().await;
        scanning.clear();
    }
}

impl Default for LazyRepoScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerfConfig {
    /// Enable performance features
    pub enabled: bool,

    /// Object cache size (MB)
    pub cache_size_mb: usize,

    /// Cache TTL (seconds)
    pub cache_ttl_secs: u64,

    /// Enable ref cache
    pub enable_ref_cache: bool,

    /// Ref cache size
    pub ref_cache_size: usize,

    /// Enable HTTP connection pool
    pub enable_connection_pool: bool,

    /// Connection pool settings
    pub connection_pool: ConnectionPoolConfig,

    /// Enable lazy repository scanning
    pub enable_lazy_scan: bool,
}

impl Default for PerfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size_mb: 128,
            cache_ttl_secs: 300,
            enable_ref_cache: true,
            ref_cache_size: 1000,
            enable_connection_pool: true,
            connection_pool: ConnectionPoolConfig::default(),
            enable_lazy_scan: true,
        }
    }
}

/// Performance manager
#[allow(dead_code)]
pub struct PerfManager {
    object_cache: GitObjectCache,
    ref_cache: RefCache,
    repo_meta_cache: RepoMetaCache,
    lazy_scanner: LazyRepoScanner,
    config: PerfConfig,
}

impl PerfManager {
    pub fn new(config: PerfConfig) -> Self {
        Self {
            object_cache: GitObjectCache::new(config.cache_size_mb, config.cache_ttl_secs),
            ref_cache: RefCache::new(60, config.ref_cache_size),
            repo_meta_cache: RepoMetaCache::new(60),
            lazy_scanner: LazyRepoScanner::new(),
            config,
        }
    }

    pub fn object_cache(&self) -> &GitObjectCache {
        &self.object_cache
    }

    pub fn ref_cache(&self) -> &RefCache {
        &self.ref_cache
    }

    pub fn repo_meta_cache(&self) -> &RepoMetaCache {
        &self.repo_meta_cache
    }

    pub fn lazy_scanner(&self) -> &LazyRepoScanner {
        &self.lazy_scanner
    }

    /// Get performance statistics
    pub async fn stats(&self) -> PerfStats {
        PerfStats {
            object_cache: self.object_cache.stats().await,
            ref_cache_entries: self.ref_cache.entries.read().await.len(),
            repo_meta_entries: self.repo_meta_cache.entries.read().await.len(),
        }
    }

    /// Clear all caches
    pub async fn clear_caches(&self) {
        self.object_cache.clear().await;
        self.ref_cache.clear().await;
        self.lazy_scanner.reset().await;
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerfStats {
    pub object_cache: CacheStatsSnapshot,
    pub ref_cache_entries: usize,
    pub repo_meta_entries: usize,
}
