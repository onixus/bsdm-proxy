//! BSDM-Proxy library

pub mod acl;
pub mod auth;
pub mod categorization;
pub mod hierarchy;
pub mod icp;
pub mod peers;
pub mod selection;

// Re-export commonly used types
pub use acl::{AclAction, AclDecision, AclEngine, AclRule};
pub use auth::{AuthBackend, AuthConfig, AuthManager, UserInfo};
pub use categorization::{CategorizationConfig, CategorizationEngine, Category};
pub use hierarchy::{HierarchyConfig, HierarchyManager, HierarchyResult};
pub use icp::{IcpClient, IcpMessage, IcpOpcode, IcpServer};
pub use peers::{CachePeer, PeerConfig, PeerRegistry, PeerType};
pub use selection::{parse_strategy, SelectionStrategy};

// Conditional re-exports based on features
#[cfg(feature = "auth-ldap")]
pub use auth::LdapConfig;

#[cfg(feature = "auth-ntlm")]
pub use auth::NtlmConfig;

#[cfg(test)]
mod tests {
    use super::parse_strategy;

    #[test]
    fn hierarchy_modules_are_linked() {
        assert_eq!(parse_strategy("round-robin").name(), "round-robin");
        assert_eq!(parse_strategy("weighted").name(), "weighted");
    }
}
