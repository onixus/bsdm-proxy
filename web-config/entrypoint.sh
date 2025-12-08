#!/bin/sh
set -e

echo "🔧 Entrypoint starting..."

# Fix Docker socket permissions if mounted (ignore errors if not accessible)
if [ -S /var/run/docker.sock ]; then
    echo "⚙️  Fixing Docker socket permissions..."
    chmod 666 /var/run/docker.sock 2>/dev/null || echo "⚠️  Could not change Docker socket permissions (may need sudo on host)"
else
    echo "⚠️  Docker socket not found at /var/run/docker.sock"
fi

# Ensure /config directory exists
mkdir -p /config
chmod 755 /config
echo "✅ Config directory exists: /config"

# List contents for debugging
echo "📂 Contents of /config before:"
ls -la /config/ || echo "  (empty or no access)"

# Fix .env if it's accidentally a directory
if [ -d /config/.env ]; then
    echo "⚠️  .env is a directory! Removing..."
    rm -rf /config/.env
fi

# Create .env file if it doesn't exist
if [ ! -f /config/.env ]; then
    if [ -f /config/.env.example ]; then
        echo "✅ Creating .env from /config/.env.example (volume)"
        cp /config/.env.example /config/.env
    else
        echo "⚠️  No .env.example found in /config, creating default"
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
        echo "✅ Created default .env"
    fi
else
    echo "ℹ️  .env already exists as a file"
fi

# Verify .env is a file
if [ -f /config/.env ]; then
    echo "✅ .env is a valid file"
else
    echo "❌ .env is not a file!"
    ls -la /config/.env || true
fi

# List contents after for debugging
echo "📂 Contents of /config after:"
ls -la /config/ || echo "  (error listing)"

echo "🚀 Starting application..."

# Execute CMD
exec "$@"
