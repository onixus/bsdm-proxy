//! BSDM-Proxy library

pub mod acl;
pub mod auth;
pub mod categorization;

// Re-export commonly used types
pub use acl::{AclAction, AclDecision, AclEngine, AclRule};
pub use auth::{AuthBackend, AuthConfig, AuthManager, UserInfo};
pub use categorization::{CategorizationConfig, CategorizationEngine, Category};

// Conditional re-exports based on features
#[cfg(feature = "auth-ldap")]
pub use auth::LdapConfig;

#[cfg(feature = "auth-ntlm")]
pub use auth::NtlmConfig;
