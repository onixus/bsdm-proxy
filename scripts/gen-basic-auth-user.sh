#!/usr/bin/env bash
# Generate a BasicAuth JSON user entry (SHA-256 hex password hash).
#
# Usage (preferred — the password never appears in argv):
#   ./scripts/gen-basic-auth-user.sh pilot                    # prompts twice on a tty
#   ./scripts/gen-basic-auth-user.sh --role admins pilot
#   printf '%s' "$PASS" | ./scripts/gen-basic-auth-user.sh --stdin pilot
#   ./scripts/gen-basic-auth-user.sh --password-file /run/secrets/pw pilot
#
# Deprecated (kept for compatibility, prints a warning):
#   ./scripts/gen-basic-auth-user.sh pilot 's3cret' [role]
#
# Output goes to stdout, e.g.:
#   ./scripts/gen-basic-auth-user.sh pilot >> config/basic-auth-users.json
#
# !!! DO NOT CHANGE THE HASHING ALGORITHM !!!
# The unsalted SHA-256 of the raw password bytes is fixed by the Rust side:
# AuthManager::hash_password_stable (proxy/src/auth.rs). Switching to bcrypt /
# argon2 / adding a salt here silently invalidates every existing user database
# — all logins fail after the next restart. Any change must land in the Rust
# verifier and a migration path first.
set -euo pipefail

usage() {
  sed -n '2,22p' "$0" >&2
  exit 1
}

PASS=""
PASS_SET=false
MODE="prompt"
PASS_FILE=""
ROLE_OPT=""
ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      [[ $# -ge 2 ]] || { echo "error: --role requires a value" >&2; exit 2; }
      ROLE_OPT="$2"
      shift 2
      ;;
    --stdin)
      MODE="stdin"
      shift
      ;;
    --password-file)
      [[ $# -ge 2 ]] || { echo "error: --password-file requires a path" >&2; exit 2; }
      MODE="file"
      PASS_FILE="$2"
      shift 2
      ;;
    -h|--help) usage ;;
    --*)
      echo "error: unknown option: $1" >&2
      exit 2
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

USER="${ARGS[0]:-}"
[[ -n "$USER" ]] || usage

# Positional layout is kept exactly as it was — <username> <password> [role] —
# so existing runbooks keep working; only the 1-argument form is new. The role
# for the new form comes from --role, never from a positional, otherwise
# `... pilot users` would be ambiguous with `... pilot <password>`.
case "${#ARGS[@]}" in
  1) ROLE="${ROLE_OPT:-users}" ;;
  2 | 3)
    # Deprecated positional form: <username> <password> [role].
    PASS="${ARGS[1]}"
    PASS_SET=true
    ROLE="${ARGS[2]:-${ROLE_OPT:-users}}"
    ;;
  *)
    echo "error: too many positional arguments" >&2
    usage
    ;;
esac

if [[ "$PASS_SET" == true ]]; then
  echo "warning: passing the password as a command-line argument is deprecated." >&2
  echo "         It is visible to every user on the host via ps(1) and is stored" >&2
  echo "         in your shell history. Use --stdin or --password-file instead." >&2
  if [[ "$MODE" != "prompt" ]]; then
    echo "error: positional password conflicts with --stdin/--password-file" >&2
    exit 2
  fi
elif [[ "$MODE" == "stdin" ]]; then
  IFS= read -r PASS || true
elif [[ "$MODE" == "file" ]]; then
  [[ -f "$PASS_FILE" ]] || { echo "error: password file not found: ${PASS_FILE}" >&2; exit 2; }
  IFS= read -r PASS < "$PASS_FILE" || true
else
  if [[ ! -t 0 ]]; then
    echo "error: stdin is not a terminal; use --stdin or --password-file" >&2
    exit 2
  fi
  read -rs -p "Password for ${USER}: " PASS
  echo >&2
  read -rs -p "Repeat password: " PASS_CONFIRM
  echo >&2
  [[ "$PASS" == "$PASS_CONFIRM" ]] || { echo "error: passwords do not match" >&2; exit 2; }
  unset PASS_CONFIRM
fi

if [[ -z "$PASS" ]]; then
  echo "error: empty password" >&2
  exit 2
fi

# Unsalted SHA-256 hex — must match AuthManager::hash_password_stable. See the
# warning at the top of this file before touching anything below.
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
unset PASS

python3 - "$USER" "$HASH" "$ROLE" <<'PY'
import json, sys
user, h, role = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"username": user, "password_hash": h, "role": role}, indent=2))
PY
