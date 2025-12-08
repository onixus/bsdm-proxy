#!/usr/bin/env python3
"""FastAPI backend for web-config UI."""

import json
import os
import time
import psutil
from pathlib import Path
from typing import Dict, Any, Optional

import docker
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
DOCKER_COMPOSE_FILE = CONFIG_DIR / "docker-compose.yml"
ACL_RULES_FILE = CONFIG_DIR / "acl-rules.json"
CUSTOM_CATEGORIES_FILE = CONFIG_DIR / "custom-categories.json"

# Docker client (requires mounted socket)
try:
    docker_client = docker.from_env()
    DOCKER_AVAILABLE = True
except Exception as e:
    print(f"Warning: Docker not available: {e}")
    DOCKER_AVAILABLE = False


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "docker_available": DOCKER_AVAILABLE,
        "config_dir_exists": CONFIG_DIR.exists()
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
        if DOCKER_AVAILABLE:
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    try:
                        stats = container.stats(stream=False)
                        
                        # Calculate CPU percentage
                        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                                    stats['precpu_stats']['cpu_usage']['total_usage']
                        system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                                       stats['precpu_stats']['system_cpu_usage']
                        cpu_percent = 0.0
                        if system_delta > 0:
                            cpu_percent = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', [1])) * 100
                        
                        # Memory stats
                        mem_usage = stats['memory_stats'].get('usage', 0)
                        mem_limit = stats['memory_stats'].get('limit', 1)
                        mem_percent = (mem_usage / mem_limit) * 100 if mem_limit > 0 else 0
                        
                        containers_stats.append({
                            "id": container.id[:12],
                            "name": container.name,
                            "status": container.status,
                            "image": container.image.tags[0] if container.image.tags else "unknown",
                            "cpu_percent": round(cpu_percent, 1),
                            "memory_usage": mem_usage,
                            "memory_limit": mem_limit,
                            "memory_percent": round(mem_percent, 1),
                        })
                    except Exception as e:
                        # Container might not have stats (stopped)
                        containers_stats.append({
                            "id": container.id[:12],
                            "name": container.name,
                            "status": container.status,
                            "image": container.image.tags[0] if container.image.tags else "unknown",
                            "cpu_percent": 0,
                            "memory_usage": 0,
                            "memory_limit": 0,
                            "memory_percent": 0,
                        })
            except Exception as e:
                print(f"Error getting container stats: {e}")
        
        return {
            "system": system_stats,
            "containers": containers_stats,
            "timestamp": int(time.time())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/env")
async def get_env_config():
    """Get current .env configuration."""
    if not ENV_FILE.exists():
        return {"exists": False, "content": ""}
    
    try:
        content = ENV_FILE.read_text()
        return {"exists": True, "content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/config/env")
async def update_env_config(config: Dict[str, Any]):
    """Update .env configuration."""
    try:
        # Convert dict to .env format
        env_content = "\n".join([f"{k}={v}" for k, v in config.items()])
        
        # Backup existing
        if ENV_FILE.exists():
            backup = CONFIG_DIR / ".env.backup"
            ENV_FILE.rename(backup)
        
        # Write new config
        ENV_FILE.write_text(env_content)
        
        return {"success": True, "message": "Configuration updated"}
    except Exception as e:
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
        
        # Validate YAML
        try:
            yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
        
        # Backup existing
        if DOCKER_COMPOSE_FILE.exists():
            backup = CONFIG_DIR / "docker-compose.yml.backup"
            DOCKER_COMPOSE_FILE.rename(backup)
        
        # Write new config
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
        # Backup existing
        if ACL_RULES_FILE.exists():
            backup = CONFIG_DIR / "acl-rules.json.backup"
            ACL_RULES_FILE.rename(backup)
        
        # Write new rules
        ACL_RULES_FILE.write_text(json.dumps(rules, indent=2))
        
        return {"success": True, "message": "ACL rules updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/docker/containers")
async def list_containers():
    """List Docker containers."""
    if not DOCKER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        containers = docker_client.containers.list(all=True)
        return {
            "containers": [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else "unknown"
                }
                for c in containers
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/docker/restart/{container_name}")
async def restart_container(container_name: str):
    """Restart a specific container."""
    if not DOCKER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        container = docker_client.containers.get(container_name)
        container.restart(timeout=10)
        return {"success": True, "message": f"Container {container_name} restarted"}
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail=f"Container {container_name} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/docker/restart-all")
async def restart_all_containers():
    """Restart all BSDM-Proxy related containers."""
    if not DOCKER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        containers = docker_client.containers.list(
            filters={"label": "com.docker.compose.project=bsdm-proxy"}
        )
        
        restarted = []
        for container in containers:
            if "web-ui" not in container.name:  # Don't restart ourselves
                container.restart(timeout=10)
                restarted.append(container.name)
        
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
        content = await file.read()
        
        # Determine file type and save
        if file.filename.endswith('.json'):
            # Validate JSON
            json.loads(content)
            target = ACL_RULES_FILE if 'acl' in file.filename.lower() else CUSTOM_CATEGORIES_FILE
        elif file.filename.endswith('.env'):
            target = ENV_FILE
        elif file.filename.endswith('.yml') or file.filename.endswith('.yaml'):
            # Validate YAML
            yaml.safe_load(content)
            target = DOCKER_COMPOSE_FILE
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")
        
        # Backup and save
        if target.exists():
            backup = target.with_suffix(target.suffix + '.backup')
            target.rename(backup)
        
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
