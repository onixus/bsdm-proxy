#!/usr/bin/env bash
# Install repository git hooks (pre-push: fmt + clippy).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

chmod +x .githooks/pre-push scripts/pre-push-check.sh

git config core.hooksPath .githooks

echo "Git hooks installed (core.hooksPath=.githooks)"
echo "Pre-push will run: scripts/pre-push-check.sh"
echo ""
echo "To skip once: git push --no-verify"
