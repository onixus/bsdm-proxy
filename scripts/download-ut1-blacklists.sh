#!/usr/bin/env bash
# Download UT1 Blacklists (Université Toulouse 1 Capitole) for local domain categorization.
# Layout: $UT1_PATH/blacklists/<category>/domains
# Official source: https://dsi.ut-capitole.fr/blacklists/
set -euo pipefail

UT1_PATH="${UT1_PATH:-/var/lib/ut1-blacklists}"
UT1_URL="${UT1_URL:-https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz}"

mkdir -p "$(dirname "$UT1_PATH")"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "Downloading UT1 blacklists from $UT1_URL ..."
curl -fsSL "$UT1_URL" -o "$tmpdir/blacklists.tar.gz"
tar -xzf "$tmpdir/blacklists.tar.gz" -C "$tmpdir"

if [[ -d "$tmpdir/blacklists" ]]; then
    rm -rf "$UT1_PATH"
    mv "$tmpdir/blacklists" "$UT1_PATH"
elif [[ -d "$tmpdir/BL" ]]; then
    # Some archives unpack to BL/
    rm -rf "$UT1_PATH"
    mkdir -p "$UT1_PATH/blacklists"
    mv "$tmpdir/BL"/* "$UT1_PATH/blacklists/" 2>/dev/null || true
else
  echo "Unexpected archive layout; expected blacklists/ or BL/ at top level" >&2
  ls -la "$tmpdir" >&2
  exit 1
fi

count="$(find "$UT1_PATH" -name domains -type f 2>/dev/null | wc -l | tr -d ' ')"
echo "UT1 blacklists installed at $UT1_PATH ($count category lists)"
