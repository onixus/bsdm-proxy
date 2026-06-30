//! Load ACL rules from JSON configuration files.

use crate::acl::{AclAction, AclEngine, AclRule};
use serde::Deserialize;
use tracing::info;

pub fn parse_acl_action(value: &str) -> AclAction {
    match value.to_ascii_lowercase().as_str() {
        "deny" => AclAction::Deny,
        "redirect" => AclAction::Redirect,
        _ => AclAction::Allow,
    }
}

#[derive(Debug, Deserialize)]
struct AclRulesFile {
    #[serde(default)]
    default_action: Option<String>,
    #[serde(default)]
    rules: Vec<AclRule>,
}

/// Load ACL engine from a JSON rules file (`default_action` + `rules` array).
pub fn load_acl_engine_from_file(
    path: &str,
    fallback_default: AclAction,
) -> Result<AclEngine, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read ACL rules file: {}", e))?;
    let file: AclRulesFile = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse ACL rules JSON: {}", e))?;

    let default_action = file
        .default_action
        .as_deref()
        .map(parse_acl_action)
        .unwrap_or(fallback_default);

    let mut engine = AclEngine::new(default_action);
    engine.load_rules(file.rules);
    info!("Loaded {} ACL rules from {}", engine.rule_count(), path);
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_rules_from_json_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{
  "default_action": "deny",
  "rules": [
    {{
      "id": "r1",
      "name": "block evil",
      "enabled": true,
      "priority": 100,
      "action": "deny",
      "rule_type": {{ "Domain": "evil.test" }},
      "redirect_url": null,
      "comment": null
    }}
  ]
}}"#
        )
        .unwrap();

        let engine =
            load_acl_engine_from_file(file.path().to_str().unwrap(), AclAction::Allow).unwrap();
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.default_action(), AclAction::Deny);
        let decision =
            engine.check_access("https://evil.test/path", "evil.test", &[], None, &[], None);
        assert_eq!(decision.action, AclAction::Deny);
    }

    #[test]
    fn parse_acl_action_values() {
        assert_eq!(parse_acl_action("deny"), AclAction::Deny);
        assert_eq!(parse_acl_action("ALLOW"), AclAction::Allow);
        assert_eq!(parse_acl_action("redirect"), AclAction::Redirect);
    }
}
