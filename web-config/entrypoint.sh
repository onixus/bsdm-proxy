#!/bin/sh
set -e

echo "🔧 Entrypoint starting..."

# Fix Docker socket permissions if mounted
if [ -S /var/run/docker.sock ]; then
    echo "⚙️  Docker socket found at /var/run/docker.sock"
    
    # Try to change permissions
    if chmod 666 /var/run/docker.sock 2>/dev/null; then
        echo "✅ Docker socket permissions set to 666"
    else
        echo "⚠️  Could not change Docker socket permissions (may need sudo on host)"
        echo "   Run on host: sudo chmod 666 /var/run/docker.sock"
    fi
    
    # Verify socket is readable and writable
    if [ -r /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
        echo "✅ Docker socket is readable and writable"
    else
        echo "❌ Docker socket is not accessible (permissions issue)"
        ls -la /var/run/docker.sock
    fi
else
    echo "❌ Docker socket not found at /var/run/docker.sock"
    echo "   Check docker-compose.yml volumes:"
    echo "   - /var/run/docker.sock:/var/run/docker.sock:rw"
fi

# Ensure /config directory exists
mkdir -p /config
chmod 755 /config
echo "✅ Config directory ready: /config"

# Fix .env if it's accidentally a directory
if [ -d /config/.env ]; then
    echo "⚠️  .env is a directory! Removing..."
    rm -rf /config/.env
fi

# Create .env file if it doesn't exist
if [ ! -f /config/.env ]; then
    if [ -f /config/.env.example ]; then
        echo "✅ Creating .env from /config/.env.example"
        cp /config/.env.example /config/.env
    else
        echo "⚠️  Creating default .env (no .env.example found)"
        cat > /config/.env << 'EOF'
# BSDM-Proxy Default Configuration
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
EOF
    fi
else
    echo "ℹ️  .env already exists"
fi

# Verify .env is a valid file
if [ -f /config/.env ]; then
    echo "✅ .env is a valid file ($(wc -l < /config/.env) lines)"
else
    echo "❌ .env is not a file!"
    ls -la /config/.env 2>&1 || true
fi

echo "🚀 Starting application..."
echo ""

# Execute CMD
exec "$@"
