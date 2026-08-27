#!/usr/bin/env bash
# Generate a BasicAuth JSON user entry (Argon2id PHC password hash).
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
# Hash format: Argon2id PHC string, e.g.
#   $argon2id$v=19$m=19456,t=2,p=1$<salt-b64>$<hash-b64>
# The algorithm is defined in exactly one place — proxy/src/auth.rs
# (hash_password_argon2). This script does NOT reimplement it: it shells out to
# `proxy hash-password` (password on stdin), so the script and the verifier can
# never drift apart.
#
# Migration: legacy entries (64-hex unsalted SHA-256, pre-0.9.14) keep working.
# The proxy upgrades each of them to Argon2id on the first successful login and
# rewrites BASIC_USERS_FILE atomically (disable with
# BASIC_AUTH_REHASH_ON_LOGIN=false). To migrate offline instead, regenerate the
# entry with this script and replace it in config/basic-auth-users.json.
#
# Binary lookup order: $BSDM_PROXY_BIN, ./target/release/proxy,
# ./target/debug/proxy, `proxy` on $PATH.
set -euo pipefail

usage() {
  sed -n '2,14p' "$0" >&2
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

# Single source of truth for the hashing algorithm: the proxy binary itself.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_BIN="${BSDM_PROXY_BIN:-}"
if [[ -z "$PROXY_BIN" ]]; then
  for candidate in \
    "$REPO_ROOT/target/release/proxy" \
    "$REPO_ROOT/target/debug/proxy" \
    "$(command -v proxy 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      PROXY_BIN="$candidate"
      break
    fi
  done
fi
if [[ -z "$PROXY_BIN" || ! -x "$PROXY_BIN" ]]; then
  echo "error: proxy binary not found — Argon2id hashing is done by the proxy itself." >&2
  echo "       Build it (cargo build --release -p bsdm-proxy) or set BSDM_PROXY_BIN=/path/to/proxy." >&2
  exit 1
fi

HASH="$(printf '%s' "$PASS" | "$PROXY_BIN" hash-password)" || {
  echo "error: ${PROXY_BIN} hash-password failed" >&2
  exit 1
}
unset PASS
if [[ -z "$HASH" ]]; then
  echo "error: empty hash returned by ${PROXY_BIN} hash-password" >&2
  exit 1
fi

python3 - "$USER" "$HASH" "$ROLE" <<'PY'
import json, sys
user, h, role = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"username": user, "password_hash": h, "role": role}, indent=2))
PY
