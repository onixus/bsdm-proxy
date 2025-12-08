#!/bin/sh
set -e

# Fix Docker socket permissions if mounted
if [ -e /var/run/docker.sock ]; then
    echo "⚙️  Fixing Docker socket permissions..."
    chmod 666 /var/run/docker.sock 2>/dev/null || true
fi

# Ensure config directory exists and has correct permissions
mkdir -p /config
chmod 755 /config

# Copy .env.example if .env doesn't exist
if [ ! -f /config/.env ] && [ -f /config/.env.example ]; then
    echo "✅ Creating default .env from .env.example"
    cp /config/.env.example /config/.env
fi

# Execute CMD
exec "$@"
