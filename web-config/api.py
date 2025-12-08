#!/usr/bin/env python3
"""FastAPI backend for web-config UI."""

import json
import os
import sys
import time
import psutil
import socket
from pathlib import Path
from typing import Dict, Any, Optional, List

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.connection import create_connection
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import yaml

app = FastAPI(title="BSDM-Proxy Config API")

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config paths (mounted volumes)
CONFIG_DIR = Path("/config")
ENV_FILE = CONFIG_DIR / ".env"
ENV_EXAMPLE_FILE = CONFIG_DIR / ".env.example"
DOCKER_COMPOSE_FILE = CONFIG_DIR / "docker-compose.yml"
ACL_RULES_FILE = CONFIG_DIR / "acl-rules.json"
CUSTOM_CATEGORIES_FILE = CONFIG_DIR / "custom-categories.json"

# Ensure config directory exists
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
print(f"✅ Config directory: {CONFIG_DIR} (exists: {CONFIG_DIR.exists()})")
print(f"   - Writeable: {os.access(CONFIG_DIR, os.W_OK)}")

# Default configuration
DEFAULT_ENV = """# BSDM-Proxy Default Configuration
HTTP_PORT=1488
METRICS_PORT=9090
RUST_LOG=info
MAX_CACHE_BODY_SIZE=10485760
CACHE_CAPACITY=10000
CACHE_TTL_SECONDS=3600
KAFKA_BROKERS=kafka:9092
KAFKA_TOPIC=cache-events
KAFKA_BATCH_SIZE=50
KAFKA_BATCH_TIMEOUT=5
AUTH_ENABLED=false
ACL_ENABLED=false
CATEGORIZATION_ENABLED=false
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
OPENSEARCH_URL=http://opensearch:9200
"""


class UnixSocketAdapter(HTTPAdapter):
    """HTTP adapter that uses Unix socket."""
    
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        super().__init__()
    
    def get_connection(self, url, proxies=None):
        conn = super().get_connection(url, proxies)
        # Monkey patch the connection to use Unix socket
        original_connect = conn.connect
        
        def unix_connect():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)
            conn.sock = sock
        
        conn.connect = unix_connect
        return conn


class DockerClient:
    """Simple Docker client using direct HTTP API over Unix socket."""
    
    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path
        self.session = requests.Session()
        self.session.mount('http+docker://', UnixSocketAdapter(socket_path))
        self.base_url = 'http+docker://localhost'
    
    def ping(self) -> bool:
        """Ping Docker daemon."""
        try:
            resp = self.session.get(f'{self.base_url}/_ping', timeout=2)
            return resp.status_code == 200
        except Exception as e:
            print(f"Ping failed: {e}", file=sys.stderr)
            return False
    
    def list_containers(self, all: bool = True) -> List[Dict[str, Any]]:
        """List containers."""
        params = {'all': 1 if all else 0}
        resp = self.session.get(f'{self.base_url}/containers/json', params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    
    def inspect_container(self, container_id: str) -> Dict[str, Any]:
        """Inspect container."""
        resp = self.session.get(f'{self.base_url}/containers/{container_id}/json', timeout=5)
        resp.raise_for_status()
        return resp.json()
    
    def container_stats(self, container_id: str) -> Dict[str, Any]:
        """Get container stats (one-shot, no stream)."""
        resp = self.session.get(
            f'{self.base_url}/containers/{container_id}/stats',
            params={'stream': 0},
            timeout=10
        )
        resp.raise_for_status()
        return resp.json()
    
    def restart_container(self, container_id: str, timeout: int = 10) -> None:
        """Restart container."""
        resp = self.session.post(
            f'{self.base_url}/containers/{container_id}/restart',
            params={'t': timeout},
            timeout=timeout + 5
        )
        resp.raise_for_status()


# Docker client - use custom Unix socket client
docker_client = None
DOCKER_AVAILABLE = False

SOCKET_PATH = "/var/run/docker.sock"
if os.path.exists(SOCKET_PATH):
    print(f"✅ Docker socket found: {SOCKET_PATH}")
    try:
        docker_client = DockerClient(SOCKET_PATH)
        if docker_client.ping():
            DOCKER_AVAILABLE = True
            print(f"✅ Docker client connected via Unix socket: {SOCKET_PATH}")
        else:
            print(f"❌ Docker ping failed", file=sys.stderr)
            docker_client = None
            DOCKER_AVAILABLE = False
    except Exception as e:
        print(f"❌ Docker connection failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        docker_client = None
        DOCKER_AVAILABLE = False
else:
    print(f"❌ Docker socket not found: {SOCKET_PATH}")
    DOCKER_AVAILABLE = False


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "docker_available": DOCKER_AVAILABLE,
        "config_dir_exists": CONFIG_DIR.exists(),
        "env_file_exists": ENV_FILE.exists(),
        "config_dir_writable": os.access(CONFIG_DIR, os.W_OK) if CONFIG_DIR.exists() else False
    }


@app.get("/api/monitoring/stats")
async def get_monitoring_stats():
    """Get system and container monitoring stats."""
    try:
        # System stats
        cpu_percent = psutil.cpu_percent(interval=0.1, percpu=False)
        cpu_count = psutil.cpu_count()
        
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        net_io = psutil.net_io_counters()
        
        # System info
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
        
        system_stats = {
            "cpu": {
                "percent": round(cpu_percent, 1),
                "count": cpu_count,
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": round(memory.percent, 1),
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": round(disk.percent, 1),
            },
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
            },
            "system": {
                "hostname": os.uname().nodename,
                "uptime": uptime_seconds,
                "platform": os.uname().sysname,
            }
        }
        
        # Container stats
        containers_stats = []
        if DOCKER_AVAILABLE and docker_client:
            try:
                containers = docker_client.list_containers(all=True)
                for container in containers:
                    try:
                        stats = docker_client.container_stats(container['Id'])
                        
                        # Calculate CPU percentage
                        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                                    stats['precpu_stats']['cpu_usage']['total_usage']
                        system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                                       stats['precpu_stats']['system_cpu_usage']
                        cpu_percent = 0.0
                        if system_delta > 0:
                            cpu_count = len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', [1]))
                            cpu_percent = (cpu_delta / system_delta) * cpu_count * 100
                        
                        # Memory stats
                        mem_usage = stats['memory_stats'].get('usage', 0)
                        mem_limit = stats['memory_stats'].get('limit', 1)
                        mem_percent = (mem_usage / mem_limit) * 100 if mem_limit > 0 else 0
                        
                        # Get container name (remove leading /)
                        name = container['Names'][0].lstrip('/')
                        
                        containers_stats.append({
                            "id": container['Id'][:12],
                            "name": name,
                            "status": container['State'],
                            "image": container['Image'],
                            "cpu_percent": round(cpu_percent, 1),
                            "memory_usage": mem_usage,
                            "memory_limit": mem_limit,
                            "memory_percent": round(mem_percent, 1),
                        })
                    except Exception as e:
                        # Container might not have stats (stopped)
                        name = container['Names'][0].lstrip('/')
                        containers_stats.append({
                            "id": container['Id'][:12],
                            "name": name,
                            "status": container['State'],
                            "image": container['Image'],
                            "cpu_percent": 0,
                            "memory_usage": 0,
                            "memory_limit": 0,
                            "memory_percent": 0,
                        })
            except Exception as e:
                print(f"Error getting container stats: {e}", file=sys.stderr)
        
        return {
            "system": system_stats,
            "containers": containers_stats,
            "timestamp": int(time.time())
        }
    except Exception as e:
        print(f"Error in monitoring stats: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/env")
async def get_env_config():
    """Get current .env configuration."""
    try:
        if ENV_FILE.exists():
            content = ENV_FILE.read_text()
            return {"exists": True, "content": content, "source": "file"}
        elif ENV_EXAMPLE_FILE.exists():
            content = ENV_EXAMPLE_FILE.read_text()
            return {"exists": False, "content": content, "source": "example"}
        else:
            return {"exists": False, "content": DEFAULT_ENV, "source": "default"}
    except Exception as e:
        print(f"Error reading .env: {e}", file=sys.stderr)
        return {"exists": False, "content": DEFAULT_ENV, "source": "default", "error": str(e)}


@app.post("/api/config/env")
async def update_env_config(config: Dict[str, Any]):
    """Update .env configuration."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        env_content = "\n".join([f"{k}={v}" for k, v in config.items()])
        
        if ENV_FILE.exists():
            try:
                backup = CONFIG_DIR / ".env.backup"
                backup.write_text(ENV_FILE.read_text())
            except Exception as e:
                print(f"Warning: Could not create backup: {e}", file=sys.stderr)
        
        ENV_FILE.write_text(env_content)
        print(f"✅ Configuration written to {ENV_FILE}")
        
        return {"success": True, "message": "Configuration updated"}
    except PermissionError as e:
        print(f"❌ Permission error writing .env: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"Permission denied: {e}")
    except Exception as e:
        print(f"❌ Error writing .env: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/docker-compose")
async def get_docker_compose():
    """Get current docker-compose.yml."""
    if not DOCKER_COMPOSE_FILE.exists():
        return {"exists": False, "content": ""}
    
    try:
        content = DOCKER_COMPOSE_FILE.read_text()
        return {"exists": True, "content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/config/docker-compose")
async def update_docker_compose(content: Dict[str, str]):
    """Update docker-compose.yml."""
    try:
        yaml_content = content.get("content", "")
        
        try:
            yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
        
        if DOCKER_COMPOSE_FILE.exists():
            backup = CONFIG_DIR / "docker-compose.yml.backup"
            backup.write_text(DOCKER_COMPOSE_FILE.read_text())
        
        DOCKER_COMPOSE_FILE.write_text(yaml_content)
        
        return {"success": True, "message": "docker-compose.yml updated"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/acl-rules")
async def get_acl_rules():
    """Get ACL rules."""
    if not ACL_RULES_FILE.exists():
        return {"exists": False, "rules": []}
    
    try:
        content = ACL_RULES_FILE.read_text()
        rules = json.loads(content)
        return {"exists": True, "rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/config/acl-rules")
async def update_acl_rules(rules: Dict[str, Any]):
    """Update ACL rules."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        if ACL_RULES_FILE.exists():
            backup = CONFIG_DIR / "acl-rules.json.backup"
            backup.write_text(ACL_RULES_FILE.read_text())
        
        ACL_RULES_FILE.write_text(json.dumps(rules, indent=2))
        
        return {"success": True, "message": "ACL rules updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/docker/containers")
async def list_containers():
    """List Docker containers."""
    if not DOCKER_AVAILABLE or not docker_client:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        containers = docker_client.list_containers(all=True)
        return {
            "containers": [
                {
                    "id": c['Id'][:12],
                    "name": c['Names'][0].lstrip('/'),
                    "status": c['State'],
                    "image": c['Image']
                }
                for c in containers
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/docker/restart/{container_name}")
async def restart_container(container_name: str):
    """Restart a specific container."""
    if not DOCKER_AVAILABLE or not docker_client:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        # Find container by name
        containers = docker_client.list_containers(all=True)
        container_id = None
        for c in containers:
            if container_name in c['Names'][0]:
                container_id = c['Id']
                break
        
        if not container_id:
            raise HTTPException(status_code=404, detail=f"Container {container_name} not found")
        
        docker_client.restart_container(container_id, timeout=10)
        return {"success": True, "message": f"Container {container_name} restarted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/docker/restart-all")
async def restart_all_containers():
    """Restart all BSDM-Proxy related containers."""
    if not DOCKER_AVAILABLE or not docker_client:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        containers = docker_client.list_containers(all=True)
        
        restarted = []
        for container in containers:
            name = container['Names'][0].lstrip('/')
            # Filter by label or name pattern
            if "bsdm-proxy" in name.lower() and "web-ui" not in name:
                docker_client.restart_container(container['Id'], timeout=10)
                restarted.append(name)
        
        return {
            "success": True,
            "message": f"Restarted {len(restarted)} containers",
            "containers": restarted
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/config/upload")
async def upload_config(file: UploadFile = File(...)):
    """Upload configuration file."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        content = await file.read()
        
        if file.filename.endswith('.json'):
            json.loads(content)
            target = ACL_RULES_FILE if 'acl' in file.filename.lower() else CUSTOM_CATEGORIES_FILE
        elif file.filename.endswith('.env'):
            target = ENV_FILE
        elif file.filename.endswith('.yml') or file.filename.endswith('.yaml'):
            yaml.safe_load(content)
            target = DOCKER_COMPOSE_FILE
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")
        
        if target.exists():
            backup = target.with_suffix(target.suffix + '.backup')
            backup.write_text(target.read_text())
        
        target.write_bytes(content)
        
        return {
            "success": True,
            "message": f"File {file.filename} uploaded successfully",
            "path": str(target)
        }
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except yaml.YAMLError:
        raise HTTPException(status_code=400, detail="Invalid YAML")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/download/{file_type}")
async def download_config(file_type: str):
    """Download configuration file."""
    files = {
        "env": ENV_FILE,
        "docker-compose": DOCKER_COMPOSE_FILE,
        "acl-rules": ACL_RULES_FILE,
        "custom-categories": CUSTOM_CATEGORIES_FILE
    }
    
    file_path = files.get(file_type)
    if not file_path:
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="application/octet-stream"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
