# BSDM-Proxy Web Configurator

> **New:** The unified admin console lives in [`admin-console/`](../admin-console/) — React SPA with dashboard, logs, policies, and settings. This directory remains as a zero-dependency static fallback.

🌐 Web-based configuration interface for BSDM-Proxy.

> Project wiki: [docs/README.md](../docs/README.md) · Deployment: [docs/deployment.md](../docs/deployment.md)

## Features

- **8 configuration tabs** — General, Cache, Performance, Kafka, Auth, ACL, Categories, Monitoring
- **Export** — `bsdm-proxy.env`, `docker-compose.yml` (aligned with repo layout), `acl-rules.json`
- **Import** — load existing `.env` into the form
- **ACL quick rules** — category blocks + REST API token / auto-reload
- **Zero backend** — static HTML/CSS/JS; open locally or via `python3 -m http.server`

> Live runtime ACL editing: use proxy REST API on `:METRICS_PORT/api/acl/*` (see [docs/acl.md](../docs/acl.md)).

## Quick Start

### Option 1: Open Locally

```bash
cd web-config
open index.html  # macOS
# or
xdg-open index.html  # Linux
# or
start index.html  # Windows
```

### Option 2: Simple HTTP Server

```bash
cd web-config
python3 -m http.server 8080
# Open http://localhost:8080
```

### Option 3: Docker

```bash
docker run -d -p 8080:80 -v $(pwd)/web-config:/usr/share/nginx/html:ro nginx:alpine
# Open http://localhost:8080
```

## Usage

### 1. Configure Settings

**General Tab:**
- Proxy port (default: 1488)
- Metrics port (default: 9090)
- Log level (error/warn/info/debug/trace)
- Max body size (MB)

**Cache Tab:**
- Cache capacity (entries)
- TTL (seconds)
- L2 cache toggle
- Memory estimates

**Kafka Tab:**
- Broker list (comma-separated)
- Topic name
- Batch size & timeout

**Authentication Tab:**
- Enable/disable
- Backend selection (Basic/LDAP; NTLM shown in generator but **not supported** in proxy v0.2.x — use LDAP for AD)
- LDAP configuration
  - Servers, Base DN, Bind DN
  - User filter, TLS

> **NTLM:** not implemented — see [docs/authentication.md](../docs/authentication.md). Do not deploy `AUTH_BACKEND=ntlm`.

**Monitoring Tab:**
- Prometheus toggle
- Grafana toggle
- ClickHouse URL, database, table
- Access URLs reference

### 2. Generate Configuration

Click **"Generate Configuration"** to:
- Preview environment variables
- Validate settings
- Copy to clipboard

### 3. Export Files

**Export .env:**
```bash
HTTP_PORT=1488
METRICS_PORT=9090
RUST_LOG=info
CACHE_CAPACITY=10000
...
```

**Export docker-compose.yml:**
- Complete docker-compose.yml with all services
- Includes: Zookeeper, Kafka, ClickHouse, Prometheus, Grafana, Proxy, Cache-Indexer
- Pre-configured with your settings

### 4. Deploy

```bash
# Save exported docker-compose.yml
vi docker-compose.yml

# Start services
docker-compose up -d

# Verify
docker-compose ps
```

## Configuration Presets

### Development
```javascript
{
  CACHE_CAPACITY: 1000,
  CACHE_TTL_SECONDS: 300,
  RUST_LOG: "debug",
  AUTH_ENABLED: false
}
```

### Production (High Traffic)
```javascript
{
  CACHE_CAPACITY: 100000,
  CACHE_TTL_SECONDS: 1800,
  MAX_CACHE_BODY_SIZE: 1048576, // 1MB
  RUST_LOG: "info",
  AUTH_ENABLED: true,
  AUTH_BACKEND: "ldap"
}
```

### Corporate (AD Integration)
```javascript
{
  AUTH_ENABLED: true,
  AUTH_BACKEND: "ldap",
  LDAP_SERVERS: "ldaps://dc1.corp.local:636,ldaps://dc2.corp.local:636",
  LDAP_BASE_DN: "dc=corp,dc=local",
  LDAP_USE_TLS: true
}
```

## Screenshots

### General Settings
![General](_screenshots/general.png)

### Authentication (LDAP)
![Auth](_screenshots/auth-ldap.png)

### Export Modal
![Export](_screenshots/export.png)

## Advanced Features

### Memory Estimation

Cache tab shows real-time memory estimates:
```
10,000 entries ≈ 1.2 MB memory
100,000 entries ≈ 12 MB memory
```

### Validation

- Port ranges (1-65535)
- Number limits (capacity, TTL, etc.)
- Required fields highlighted
- Backend-specific settings

### Conditional Inputs

- LDAP settings appear only when LDAP backend selected
- NTLM settings appear only when NTLM backend selected
- Auth options hidden when authentication disabled

## Keyboard Shortcuts

- `Ctrl/Cmd + S` - Generate Configuration
- `Ctrl/Cmd + E` - Export .env
- `Ctrl/Cmd + D` - Export docker-compose.yml
- `Esc` - Close modal

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Development

### File Structure

```
web-config/
├── index.html       # Main HTML
├── styles.css       # Dark theme CSS
├── script.js        # Configuration logic
└── README.md        # This file
```

### Customization

**Change Theme Colors:**

Edit `styles.css`:
```css
:root {
    --bg-primary: #1a1a2e;    /* Main background */
    --accent: #e94560;         /* Accent color */
    --success: #4ecca3;        /* Success color */
}
```

**Add New Settings:**

1. Add HTML input in `index.html`
2. Add to `collectConfig()` in `script.js`
3. Update `generateDockerCompose()` if needed

## Troubleshooting

### Configuration Not Saving

- Check browser console for errors
- Ensure all required fields filled
- Try different export method

### Modal Not Opening

- Check JavaScript enabled
- Clear browser cache
- Try different browser

### Docker Compose Export Issues

- Verify all paths correct
- Check environment variable format
- Ensure proper YAML indentation

## Security Notes

⚠️ **Important:**

- Passwords visible in generated config
- Do NOT commit `.env` with secrets
- Use environment variable substitution for production
- Restrict access to config UI in production

## Integration

### With CI/CD

```yaml
# .github/workflows/deploy.yml
- name: Generate Config
  run: |
    # Use headless browser or curl to generate config
    curl -X POST http://config-ui:8080/api/generate \
      -d @config.json > .env
```

### With Kubernetes

Export as ConfigMap:
```bash
kubectl create configmap bsdm-config --from-env-file=.env
```

## License

MIT - Same as BSDM-Proxy main project

## Contributing

1. Fork repository
2. Create feature branch
3. Test in multiple browsers
4. Submit PR with screenshots

---

**Made with ♥️ for BSDM-Proxy**
