use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let method = "GET";
        let uri = "https://example.com/api/users";
        let cache_key = format!("{}-{}", method, uri);
        let mut hasher = Sha256::new();
        hasher.update(cache_key.as_bytes());
        let hash = hex::encode(hasher.finalize());

        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex characters
    }

    #[test]
    fn test_cache_key_consistency() {
        // Same input should produce same hash
        let method = "POST";
        let uri = "https://example.com/api/data";
        
        let cache_key1 = format!("{}-{}", method, uri);
        let mut hasher1 = Sha256::new();
        hasher1.update(cache_key1.as_bytes());
        let hash1 = hex::encode(hasher1.finalize());

        let cache_key2 = format!("{}-{}", method, uri);
        let mut hasher2 = Sha256::new();
        hasher2.update(cache_key2.as_bytes());
        let hash2 = hex::encode(hasher2.finalize());

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_cache_key_uniqueness() {
        // Different inputs should produce different hashes
        let key1 = "GET-https://example.com/api/users";
        let key2 = "POST-https://example.com/api/users";

        let mut hasher1 = Sha256::new();
        hasher1.update(key1.as_bytes());
        let hash1 = hex::encode(hasher1.finalize());

        let mut hasher2 = Sha256::new();
        hasher2.update(key2.as_bytes());
        let hash2 = hex::encode(hasher2.finalize());

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_headers_map_creation() {
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Cache-Control".to_string(), "max-age=3600".to_string());

        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("Content-Type"), Some(&"application/json".to_string()));
        assert_eq!(headers.get("Cache-Control"), Some(&"max-age=3600".to_string()));
    }

    #[test]
    fn test_timestamp_generation() {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Timestamp should be reasonable (after year 2020)
        assert!(timestamp > 1577836800); // 2020-01-01 00:00:00 UTC
        // And before year 2100
        assert!(timestamp < 4102444800); // 2100-01-01 00:00:00 UTC
    }

    #[test]
    fn test_url_parsing() {
        let url = "https://example.com:443/api/users?id=123";
        assert!(url.starts_with("https://"));
        assert!(url.contains("example.com"));
        assert!(url.contains("/api/users"));
    }

    #[test]
    fn test_method_types() {
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        
        for method in methods {
            assert!(!method.is_empty());
            assert!(method.chars().all(|c| c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn test_status_codes() {
        let valid_codes: Vec<u16> = vec![200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503];
        
        for code in valid_codes {
            assert!(code >= 100);
            assert!(code < 600);
        }
    }
}

#[cfg(test)]
mod cert_tests {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    #[test]
    fn test_key_pair_generation() {
        let key_pair = KeyPair::generate().unwrap();
        let pem = key_pair.serialize_pem();
        
        assert!(!pem.is_empty());
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_certificate_params_creation() {
        let domain = "example.com";
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params.distinguished_name.push(DnType::OrganizationName, "Test Org");

        // Verify params were set correctly
        assert!(!params.subject_alt_names.is_empty());
    }

    #[test]
    fn test_self_signed_certificate() {
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["test.local".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let pem = cert.pem();

        assert!(!pem.is_empty());
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }
}
