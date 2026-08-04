#!/usr/bin/env bash
# Generate a BasicAuth JSON user entry (SHA-256 hex password hash).
#
# Usage:
#   ./scripts/gen-basic-auth-user.sh pilot 's3cret' users
#   ./scripts/gen-basic-auth-user.sh pilot 's3cret' users >> config/basic-auth-users.json
#
# Password hashing matches AuthManager::hash_password_stable (SHA-256 of password bytes).
set -euo pipefail

USER="${1:-}"
PASS="${2:-}"
ROLE="${3:-users}"

if [[ -z "$USER" || -z "$PASS" ]]; then
  echo "usage: $0 <username> <password> [role]" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  HASH="$(printf '%s' "$PASS" | sha256sum | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  HASH="$(printf '%s' "$PASS" | shasum -a 256 | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
  HASH="$(printf '%s' "$PASS" | openssl dgst -sha256 | awk '{print $NF}')"
else
  echo "need sha256sum, shasum, or openssl" >&2
  exit 1
fi

python3 - "$USER" "$HASH" "$ROLE" <<'PY'
import json, sys
user, h, role = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"username": user, "password_hash": h, "role": role}, indent=2))
PY
