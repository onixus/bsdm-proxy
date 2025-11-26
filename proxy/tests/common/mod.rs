// Common test utilities

use std::collections::HashMap;

pub fn create_test_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("User-Agent".to_string(), "Test-Agent/1.0".to_string());
    headers
}

pub fn create_test_url(path: &str) -> String {
    format!("https://example.com{}", path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_headers() {
        let headers = create_test_headers();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("Content-Type"));
        assert!(headers.contains_key("User-Agent"));
    }

    #[test]
    fn test_create_test_url() {
        let url = create_test_url("/api/users");
        assert_eq!(url, "https://example.com/api/users");
    }
}
