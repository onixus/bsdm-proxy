//! BSDM-Proxy library

pub mod auth;

// Re-export commonly used types
pub use auth::{AuthBackend, AuthConfig, AuthManager, LdapConfig, NtlmConfig, UserInfo};
