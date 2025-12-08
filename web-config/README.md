# BSDM-Proxy Web UI (Docker)

🌐 **Web-based configuration interface in Docker container**

## 🚀 Quick Start

### Deploy with Docker Compose

```bash
# Clone and checkout
git checkout feature/web-config-ui

# Create config directory
mkdir -p config

# Start all services
docker-compose up -d

# Access web UI
open http://localhost:8080
```

## 📦 Architecture

```
web-ui container:
├── nginx (port 80)          # Serves static files
├── FastAPI (port 8000)      # Backend API
├── /config volume           # Shared configs
└── /var/run/docker.sock     # Docker control
```

## ⚙️ Features

### Configuration Management
- ✅ Edit configs via web interface
- ✅ Save to `/config` directory (shared volume)
- ✅ Generate `.env`, `docker-compose.yml`
- ✅ Upload/download config files
- ✅ Auto-backup on changes

### Container Control
- ✅ View running containers
- ✅ Restart individual containers
- ✅ Apply config changes (restart proxy)
- ✅ Health status monitoring

### API Endpoints

```
GET  /api/health                    # Health check
GET  /api/config/env                # Get .env
POST /api/config/env                # Update .env
GET  /api/config/docker-compose     # Get docker-compose.yml
POST /api/config/docker-compose     # Update docker-compose.yml
GET  /api/config/acl-rules          # Get ACL rules
POST /api/config/acl-rules          # Update ACL rules
GET  /api/docker/containers         # List containers
POST /api/docker/restart/{name}     # Restart container
POST /api/docker/restart-all        # Restart all
POST /api/config/upload             # Upload file
GET  /api/config/download/{type}    # Download file
```

## 📁 Volume Mounts

### `/config` - Configuration Files
```
config/
├── .env                          # Environment variables
├── docker-compose.yml            # Docker Compose config
├── acl-rules.json                # ACL rules
├── custom-categories.json        # Custom URL categories
├── *.backup                      # Auto-backups
```

### `/var/run/docker.sock` - Docker Control
- Read-only mount
- Allows container restart
- Container status monitoring

## 🔧 Usage

### 1. Configure via Web UI
```bash
# Open browser
open http://localhost:8080

# Edit settings in tabs:
# - General, Cache, Kafka, Auth, ACL, Categories, Monitoring

# Click "Generate Configuration"
# Click "Save & Apply"
```

### 2. Configs Saved to Volume
```bash
# Check generated configs
cat config/.env
cat config/docker-compose.yml
cat config/acl-rules.json
```

### 3. Apply Changes
```bash
# Option 1: Via Web UI
# Click "Restart Containers" button

# Option 2: Manually
docker-compose restart proxy cache-indexer

# Option 3: Full redeploy
docker-compose up -d --force-recreate
```

## 🔄 Workflow

```
1. Edit config in Web UI (localhost:8080)
   ↓
2. Save → /config volume
   ↓
3. Apply → Restart containers
   ↓
4. Services read new config from /config
```

## 🛡️ Security

### Docker Socket Access
Web UI has **read-only** access to Docker socket:
- Can list containers
- Can restart containers
- **Cannot** delete/modify containers
- **Cannot** access host system

### Production Recommendations
```yaml
web-ui:
  # Add authentication
  environment:
    - BASIC_AUTH_USER=admin
    - BASIC_AUTH_PASS=secure_password
  
  # Limit to internal network
  networks:
    - internal
  
  # Remove external port
  ports: []
  
  # Access via reverse proxy
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.web-ui.rule=Host(`config.example.com`)"
```

## 🐛 Troubleshooting

### Web UI not accessible
```bash
# Check container status
docker-compose ps web-ui

# Check logs
docker-compose logs web-ui

# Verify port
curl http://localhost:8080/health
```

### Cannot restart containers
```bash
# Check Docker socket mount
docker-compose exec web-ui ls -la /var/run/docker.sock

# Test API
curl http://localhost:8080/api/docker/containers
```

### Config changes not applied
```bash
# Check volume mount
docker-compose exec web-ui ls -la /config

# Verify config files
docker-compose exec proxy cat /app/.env

# Manual restart
docker-compose restart proxy
```

### API errors
```bash
# Check API logs
docker-compose logs web-ui | grep api

# Test API directly
curl http://localhost:8080/api/health
```

## 📊 Monitoring

### Access Points
- Web UI: http://localhost:8080
- Prometheus: http://localhost:9091
- Grafana: http://localhost:3000 (admin/admin)
- OpenSearch: http://localhost:9200
- OpenSearch Dashboards: http://localhost:5601

### Health Checks
```bash
# Web UI
curl http://localhost:8080/health

# API
curl http://localhost:8080/api/health

# Proxy
curl http://localhost:9090/health
```

## 🔐 Environment Variables

```env
# Web UI Configuration
API_HOST=0.0.0.0
API_PORT=8000
CONFIG_DIR=/config

# Optional: Authentication
BASIC_AUTH_ENABLED=false
BASIC_AUTH_USER=admin
BASIC_AUTH_PASS=changeme

# Optional: HTTPS
SSL_CERT=/certs/cert.pem
SSL_KEY=/certs/key.pem
```

## 📚 Development

### Local Development
```bash
cd web-config

# Install dependencies
pip install -r requirements.txt

# Run API locally
python api.py

# Run frontend
python -m http.server 8080

# Access
open http://localhost:8080
```

### Build Container
```bash
cd web-config
docker build -t bsdm-proxy-web-ui .
docker run -p 8080:80 \
  -v ./config:/config \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  bsdm-proxy-web-ui
```

## 🤝 Contributing

- Add new configuration options
- Improve API endpoints
- Enhance UI/UX
- Add authentication methods
- Improve error handling

## 📝 License

MIT License - See [LICENSE](../LICENSE)
