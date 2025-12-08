# Configuration Directory

This directory contains runtime configuration files for BSDM-Proxy.

## Files

### `.env`
Main environment variables file. Copy from `.env.example` and customize:

```bash
cp .env.example .env
```

### `acl-rules.json`
ACL (Access Control List) rules in JSON format. Created automatically when ACL is enabled in Web UI.

Example:
```json
{
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-work",
      "name": "Allow work domains",
      "enabled": true,
      "priority": 10,
      "action": "allow",
      "rule_type": {
        "Domain": "*.example.com"
      }
    },
    {
      "id": "block-malware",
      "name": "Block malware",
      "enabled": true,
      "priority": 100,
      "action": "deny",
      "rule_type": {
        "Category": "malware"
      }
    }
  ]
}
```

### `custom-categories.json`
Custom URL categorization database. Created when custom categories are enabled.

Example:
```json
{
  "categories": {
    "internal": {
      "domains": [
        "intranet.company.com",
        "*.internal.local"
      ]
    },
    "blocked-apps": {
      "domains": [
        "*.tiktok.com",
        "*.instagram.com"
      ]
    }
  }
}
```

## Usage

### Via Web UI
1. Open http://localhost:8080
2. Configure settings in the web interface
3. Click **"Apply Configuration"** to save and restart containers

### Manual Configuration
1. Edit `.env` file
2. Edit ACL/category files if needed
3. Restart containers:
   ```bash
   docker-compose restart proxy cache-indexer
   ```

## File Permissions

The `web-ui` container needs read/write access to this directory:

```bash
chmod 755 config
chmod 644 config/.env config/*.json
```
