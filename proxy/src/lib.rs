//! BSDM-Proxy library

pub mod auth;

// Re-export commonly used types
pub use auth::{AuthBackend, AuthConfig, AuthManager, UserInfo};

// Conditional re-exports based on features
#[cfg(feature = "auth-ldap")]
pub use auth::LdapConfig;

#[cfg(feature = "auth-ntlm")]
pub use auth::NtlmConfig;
