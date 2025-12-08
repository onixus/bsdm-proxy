# BSDM-Proxy Web Configuration UI

🔧 **Modern web interface for configuring and monitoring BSDM-Proxy**

![Fluent Design](https://img.shields.io/badge/design-Fluent-0078D4?style=flat-square)
![Nord Theme](https://img.shields.io/badge/theme-Nord-5E81AC?style=flat-square)
![Status](https://img.shields.io/badge/status-ready-green?style=flat-square)

## ✨ Features

### 👀 Real-time Monitoring
- **Server metrics**: CPU, Memory, Disk, Network
- **Container stats**: Status, CPU, Memory per container
- **System info**: Hostname, Uptime, Platform
- **Auto-refresh**: Updates every 5 seconds

### ⚙️ Configuration Management
- **8 configuration tabs**: General, Status, Cache, Kafka, Auth, ACL, Categories, Monitoring
- **Live validation** of all settings
- **Auto-save** to localStorage (instant)
- **Server persistence** to .env file
- **Import/Export** configuration files
- **One-click apply** (save + restart)

### 🔐 Security Features
- **Authentication**: Basic Auth, LDAP, NTLM
- **ACL rules**: Domain, URL, Category, Time-based
- **URL categorization**: Shallalist, URLhaus, PhishTank
- **Threat protection**: Malware, Phishing, Spyware

### 🐳 Docker Integration
- **Container management**: List, restart, monitor
- **Health checks**: Real-time status
- **Automatic restarts** on config changes

## 🚀 Quick Start

### Prerequisites

```bash
# Required
- Docker 20.10+
- Docker Compose 2.0+
- Git

# System
- Linux/macOS (Windows WSL2)
- Port 8080 available
- 512MB RAM minimum
```

### Installation

```bash
# 1. Clone and checkout branch
git clone https://github.com/onixus/bsdm-proxy.git
cd bsdm-proxy
git checkout feature/web-config-ui

# 2. Create config directory
mkdir -p config

# 3. Give Docker socket permissions (IMPORTANT!)
sudo chmod 666 /var/run/docker.sock

# 4. Build and start
docker-compose build web-ui
docker-compose up -d web-ui

# 5. Check status
docker-compose logs -f web-ui
```

### ✅ Expected Output

```log
🔧 Entrypoint starting...
⚙️  Docker socket found at /var/run/docker.sock
✅ Docker socket permissions set to 666
✅ Docker socket is readable and writable
✅ Config directory ready: /config
✅ .env already exists (17 lines)
🚀 Starting application...
---
✅ Config directory: /config (exists: True)
   - Writeable: True
✅ Docker client connected via unix:///var/run/docker.sock
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Access Web UI

**URL:** http://localhost:8080

## 🐛 Troubleshooting

### ❌ Problem: Docker API unavailable

**Symptoms:**
```
⚠️  Docker not available: Error while fetching server API version
```

**Solutions:**

```bash
# Step 1: Check docker-compose.yml volume
grep -A 5 "web-ui:" docker-compose.yml | grep docker.sock
# Must show: - /var/run/docker.sock:/var/run/docker.sock:rw

# Step 2: Fix if missing :rw
sed -i 's|/var/run/docker.sock:/var/run/docker.sock|/var/run/docker.sock:/var/run/docker.sock:rw|' docker-compose.yml

# Step 3: Give permissions on host
sudo chmod 666 /var/run/docker.sock

# Step 4: Verify inside container
docker exec $(docker ps -qf "name=web-ui") ls -la /var/run/docker.sock
# Should show: srw-rw-rw- (666 permissions)

# Step 5: Full rebuild
docker-compose down
docker-compose build --no-cache web-ui
docker-compose up -d web-ui

# Step 6: Check logs
docker-compose logs web-ui | grep "Docker client"
# Should show: ✅ Docker client connected via unix:///var/run/docker.sock
```

### ❌ Problem: Config not saving

**Symptoms:**
```
❌ Permission error writing .env
```

**Solutions:**

```bash
# Fix directory permissions
sudo chown -R $USER:$USER config/
chmod 755 config/
chmod 644 config/.env

# Restart
docker-compose restart web-ui
```

### ❌ Problem: .env is a directory

**Symptoms:**
```
Error reading .env: [Errno 21] Is a directory
```

**Solutions:**

```bash
# Remove and recreate as file
rm -rf config/.env
cp config/.env.example config/.env

# Or let container create it
docker-compose restart web-ui
```

### ❌ Problem: Port 8080 in use

**Solutions:**

```bash
# Find what's using port
sudo lsof -i :8080

# Change port in docker-compose.yml
# Change: "8080:80" to "8081:80"

# Access at new port
open http://localhost:8081
```

### ❌ Problem: Tabs not switching

**Check browser console (F12):**
```javascript
// Should not show errors
// If "monitoring not defined", refresh page
location.reload()
```

## 📚 API Documentation

### Health Check
```bash
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "docker_available": true,
  "config_dir_exists": true,
  "env_file_exists": true,
  "config_dir_writable": true
}
```

### Get Monitoring Stats
```bash
GET /api/monitoring/stats
```

**Response:**
```json
{
  "system": {
    "cpu": {"percent": 15.2, "count": 8},
    "memory": {
      "total": 16777216000,
      "used": 8388608000,
      "percent": 50.0
    },
    "disk": {"total": 500107862016, "used": 250053931008, "percent": 50.0},
    "network": {"bytes_sent": 1048576, "bytes_recv": 2097152},
    "system": {
      "hostname": "proxy-server",
      "uptime": 86400,
      "platform": "Linux"
    }
  },
  "containers": [
    {
      "id": "abc123",
      "name": "bsdm-proxy-1",
      "status": "running",
      "image": "bsdm-proxy:latest",
      "cpu_percent": 5.2,
      "memory_usage": 104857600,
      "memory_percent": 10.5
    }
  ]
}
```

### Get Configuration
```bash
GET /api/config/env
```

**Response:**
```json
{
  "exists": true,
  "content": "HTTP_PORT=1488\nMETRICS_PORT=9090\n...",
  "source": "file"
}
```

### Save Configuration
```bash
POST /api/config/env
Content-Type: application/json

{
  "HTTP_PORT": "1488",
  "METRICS_PORT": "9090",
  "RUST_LOG": "info",
  "CACHE_CAPACITY": "10000"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated"
}
```

### Restart All Containers
```bash
POST /api/docker/restart-all
```

**Response:**
```json
{
  "success": true,
  "message": "Restarted 2 containers",
  "containers": ["bsdm-proxy-1", "cache-indexer-1"]
}
```

## 🎨 Design System

### Fluent Design
- **Acrylic blur** effects
- **Neumorphic** shadows
- **Smooth** transitions
- **Microsoft** typography
- **Focus** indicators

### Nord Color Palette
- **Polar Night** (`#2E3440` - `#3B4252` - `#434C5E` - `#4C566A`)
- **Snow Storm** (`#D8DEE9` - `#E5E9F0` - `#ECEFF4`)
- **Frost** (`#8FBCBB` - `#88C0D0` - `#81A1C1` - `#5E81AC`)
- **Aurora** (`#BF616A` - `#D08770` - `#EBCB8B` - `#A3BE8C` - `#B48EAD`)

## 🛠️ Architecture

### Container Structure
```
web-ui container:
├── nginx:80           # Static files (HTML/CSS/JS)
├── uvicorn:8000       # FastAPI backend
├── supervisord        # Process manager
├── /config            # Volume mount (configs)
└── /var/run/docker.sock  # Docker API
```

### File Structure
```
web-config/
├── api.py              # FastAPI backend (16KB)
├── index.html          # Main UI (25KB)
├── styles.css          # Fluent Design (15KB)
├── script.js           # Config logic (20KB)
├── monitoring.js       # Real-time stats (8KB)
├── nginx.conf          # Web server config
├── supervisord.conf    # Process manager
├── Dockerfile          # Build instructions
├── entrypoint.sh       # Startup script
├── requirements.txt    # Python deps
├── .env.example        # Config template
└── README.md           # This file
```

### Tech Stack
- **Backend**: Python 3.11, FastAPI, Uvicorn
- **Frontend**: Vanilla JS (no frameworks needed)
- **Monitoring**: psutil, docker-py
- **Web Server**: Nginx
- **Process Manager**: Supervisor
- **Container**: Alpine Linux 3.19

## 📝 Configuration Reference

### General Settings
```env
HTTP_PORT=1488                    # Proxy port
METRICS_PORT=9090                 # Prometheus metrics
RUST_LOG=info                     # Log level (error/warn/info/debug/trace)
MAX_CACHE_BODY_SIZE=10485760      # Max cacheable size (bytes)
```

### Cache Settings
```env
CACHE_CAPACITY=10000              # Max entries in L1 cache
CACHE_TTL_SECONDS=3600            # Entry lifetime (1 hour)
```

### Kafka Settings
```env
KAFKA_BROKERS=kafka:9092          # Broker addresses (comma-separated)
KAFKA_TOPIC=cache-events          # Topic name
KAFKA_BATCH_SIZE=50               # Events per batch
KAFKA_BATCH_TIMEOUT=5             # Batch timeout (seconds)
```

### Authentication
```env
AUTH_ENABLED=false                # Enable auth
AUTH_BACKEND=basic                # basic/ldap/ntlm
AUTH_REALM=BSDM-Proxy             # Realm name
AUTH_CACHE_TTL=300                # Cache auth results (5 min)

# LDAP settings
LDAP_SERVERS=ldap://dc.example.com:389
LDAP_BASE_DN=dc=example,dc=com
LDAP_BIND_DN=cn=proxy,ou=services,dc=example,dc=com
LDAP_BIND_PASSWORD=secret
LDAP_USER_FILTER=(sAMAccountName={username})
LDAP_USE_TLS=false

# NTLM settings
NTLM_DOMAIN=WORKGROUP
NTLM_WORKSTATION=PROXY01
```

### ACL Rules
```env
ACL_ENABLED=false                 # Enable access control
ACL_DEFAULT_ACTION=allow          # Default: allow/deny
ACL_RULES_PATH=/config/acl-rules.json
```

### URL Categorization
```env
CATEGORIZATION_ENABLED=false
CATEGORIZATION_CACHE_TTL=3600

# Shallalist (60+ categories)
SHALLALIST_ENABLED=false
SHALLALIST_PATH=/var/lib/shallalist

# URLhaus (malware detection)
URLHAUS_ENABLED=false
URLHAUS_API=https://urlhaus-api.abuse.ch/v1/url/

# PhishTank (phishing detection)
PHISHTANK_ENABLED=false
PHISHTANK_API=https://checkurl.phishtank.com/checkurl/

# Custom database
CUSTOM_DB_ENABLED=false
CUSTOM_DB_PATH=/config/custom-categories.json
```

## 🔗 Useful Links

- **Main Repository**: https://github.com/onixus/bsdm-proxy
- **Docker Hub**: (coming soon)
- **Documentation**: ../README.md
- **Issues**: https://github.com/onixus/bsdm-proxy/issues

## 📝 License

MIT License - See [LICENSE](../LICENSE)

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and test thoroughly
4. Commit: `git commit -m 'Add amazing feature'`
5. Push: `git push origin feature/amazing-feature`
6. Open Pull Request

### Areas for Improvement
- [ ] Add more authentication backends (OAuth2, SAML)
- [ ] Implement config diff/history
- [ ] Add bulk operations for ACL rules
- [ ] Improve mobile responsiveness
- [ ] Add dark/light theme toggle
- [ ] Integrate with Grafana dashboards
- [ ] Add config validation
- [ ] Implement backup/restore

## ❓ Support

**Having issues?**

1. Check **Troubleshooting** section above
2. Search [existing issues](https://github.com/onixus/bsdm-proxy/issues)
3. Create new issue with:
   - Output of `docker-compose logs web-ui`
   - Browser console errors (F12 → Console)
   - Steps to reproduce
   - Expected vs actual behavior

**Quick diagnostics:**
```bash
# Full diagnostic
docker-compose logs web-ui | tail -50
curl http://localhost:8080/api/health | jq .
ls -la config/

# Test Docker API
docker exec $(docker ps -qf "name=web-ui") python3 -c "
import docker
client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
print('Containers:', len(client.containers.list(all=True)))
"
```

---

**Made with ❤️ using Fluent Design + Nord Theme**
