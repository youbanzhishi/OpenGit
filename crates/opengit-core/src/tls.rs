//! TLS/HTTPS support for OpenGit
//!
//! P11: Security hardening - HTTPS, token encryption, security headers
//!
//! Features:
//! - HTTPS server support
//! - TLS certificate management
//! - Security headers (HSTS, CSP, etc.)
//! - Token encryption at rest

use rand::RngCore;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, IpAddr, ServerName};
use rustls::{ServerConfig, crypto::ring::default_provider};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::net::IpAddr as StdIpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// TLS configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsConfig {
    /// Enable HTTPS
    pub enabled: bool,

    /// Path to TLS certificate (PEM format)
    pub cert_file: String,

    /// Path to TLS private key (PEM format)
    pub key_file: String,

    /// Minimum TLS version
    pub min_version: TlsVersion,

    /// Enable HTTP/2
    pub http2: bool,

    /// TLS cipher suites
    #[serde(default)]
    pub cipher_suites: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: "config/tls/cert.pem".into(),
            key_file: "config/tls/key.pem".into(),
            min_version: TlsVersion::Tls13,
            http2: true,
            cipher_suites: vec![],
        }
    }
}

impl TlsConfig {
    /// Load TLS configuration from file
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: TlsConfig = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Create RustTLS server config
    pub fn into_server_config(self) -> std::io::Result<ServerConfig> {
        let cert_file = File::open(&self.cert_file)?;
        let key_file = File::open(&self.key_file)?;

        let certs_data: Vec<CertificateDer> = certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let keys_data: Vec<PrivateKeyDer> = pkcs8_private_keys(&mut BufReader::new(key_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let key = keys_data.into_iter().next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No private key found"))?;

        let provider = default_provider();
        let mut config = ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .with_no_client_auth()
            .with_single_cert(certs_data, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Configure ALPN for HTTP/2
        if self.http2 {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }

        Ok(config)
    }

    /// Check if TLS is properly configured
    pub fn is_valid(&self) -> bool {
        if !self.enabled {
            return true;
        }
        Path::new(&self.cert_file).exists() && Path::new(&self.key_file).exists()
    }
}

/// Generate self-signed certificate for development
pub fn generate_self_signed_cert(output_dir: &Path) -> std::io::Result<TlsConfig> {
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "localhost");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    
    let dns_name = rustls::pki_types::DnsName::from_str("localhost")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let ip_addr = IpAddr::from(StdIpAddr::from([127, 0, 0, 1]));
    
    params.subject_alt_names = vec![
        SanType::DnsName(dns_name),
        SanType::IpAddress(ip_addr),
    ];

    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let key_pair = cert.get_key_pair();

    // Generate private key
    let private_key_pem = cert.serialize_private_key_pem();

    // Generate certificate
    let cert_pem = cert.serialize_pem()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Write files
    std::fs::create_dir_all(output_dir)?;

    let cert_path = output_dir.join("cert.pem");
    let key_path = output_dir.join("key.pem");

    std::fs::write(&cert_path, cert_pem.clone())?;
    std::fs::write(&key_path, private_key_pem.clone())?;

    Ok(TlsConfig {
        enabled: true,
        cert_file: cert_path.to_string_lossy().to_string(),
        key_file: key_path.to_string_lossy().to_string(),
        min_version: TlsVersion::Tls13,
        http2: true,
        cipher_suites: vec![],
    })
}

/// Token encryption for storage
pub mod token_encryption {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    const NONCE_SIZE: usize = 12;

    /// Encrypt a token for storage
    pub fn encrypt_token(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .expect("Invalid key length");

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("Encryption failed");

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        result
    }

    /// Decrypt a token from storage
    pub fn decrypt_token(ciphertext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return None;
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .expect("Invalid key length");

        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let encrypted = &ciphertext[NONCE_SIZE..];

        cipher.decrypt(nonce, encrypted).ok()
    }

    /// Generate a random encryption key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Hash a token for lookup (not reversible)
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Security headers configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityHeadersConfig {
    /// Enable security headers
    pub enabled: bool,

    /// Strict-Transport-Security max-age (seconds)
    pub hsts_max_age: u64,

    /// Enable HSTS preload
    pub hsts_preload: bool,

    /// Content-Security-Policy
    pub csp: String,

    /// X-Frame-Options
    pub x_frame_options: String,

    /// X-Content-Type-Options
    pub x_content_type_options: String,

    /// X-XSS-Protection
    pub x_xss_protection: String,

    /// Referrer-Policy
    pub referrer_policy: String,

    /// Permissions-Policy
    pub permissions_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hsts_max_age: 31536000, // 1 year
            hsts_preload: false,
            csp: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".into(),
            x_frame_options: "DENY".into(),
            x_content_type_options: "nosniff".into(),
            x_xss_protection: "1; mode=block".into(),
            referrer_policy: "strict-origin-when-cross-origin".into(),
            permissions_policy: "geolocation=(), microphone=(), camera=()".into(),
        }
    }
}

impl SecurityHeadersConfig {
    /// Get all security headers as (name, value) pairs
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        if !self.enabled {
            return vec![];
        }

        let mut headers = Vec::new();

        // HSTS
        let mut hsts = format!("max-age={}", self.hsts_max_age);
        if self.hsts_preload {
            hsts.push_str("; preload");
        }
        headers.push(("Strict-Transport-Security", hsts));

        // CSP
        headers.push(("Content-Security-Policy", self.csp.clone()));

        // X-Frame-Options
        headers.push(("X-Frame-Options", self.x_frame_options.clone()));

        // X-Content-Type-Options
        headers.push(("X-Content-Type-Options", self.x_content_type_options.clone()));

        // X-XSS-Protection
        headers.push(("X-XSS-Protection", self.x_xss_protection.clone()));

        // Referrer-Policy
        headers.push(("Referrer-Policy", self.referrer_policy.clone()));

        // Permissions-Policy
        headers.push(("Permissions-Policy", self.permissions_policy.clone()));

        headers
    }
}

/// Audit log encryption
pub mod audit_encryption {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use rand::RngCore;

    /// Encrypt audit log entry
    pub fn encrypt_entry(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .expect("Invalid key length");

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .expect("Encryption failed");

        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        result
    }

    /// Decrypt audit log entry
    pub fn decrypt_entry(ciphertext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
        if ciphertext.len() < 12 {
            return None;
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .expect("Invalid key length");

        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted = &ciphertext[12..];

        cipher.decrypt(nonce, encrypted).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(!config.enabled);
        assert!(!config.is_valid());
    }

    #[test]
    fn test_security_headers() {
        let config = SecurityHeadersConfig::default();
        let headers = config.headers();
        assert!(!headers.is_empty());
    }

    #[test]
    fn test_token_encryption() {
        let key = token_encryption::generate_key();
        let token = b"my-secret-token";

        let encrypted = token_encryption::encrypt_token(token, &key);
        let decrypted = token_encryption::decrypt_token(&encrypted, &key);

        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), token);
    }

    #[test]
    fn test_hash_token() {
        let hash1 = token_encryption::hash_token("token123");
        let hash2 = token_encryption::hash_token("token123");
        let hash3 = token_encryption::hash_token("token456");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
