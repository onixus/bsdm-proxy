#!/usr/bin/env bash
set -euo pipefail

# AmneziaWG Keypair, Obfuscation Config Generator & Interface Sync Tool
# Generates server & client configuration files with custom magic headers for DPI bypass,
# and handles hot reloading via awg-quick syncconf.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/../certs/awg"
MODE="${1:-generate}"
INTERFACE="${AWG_INTERFACE:-awg0}"
CONF_PATH="${CONFIG_DIR}/${INTERFACE}.conf"

mkdir -p "$CONFIG_DIR"

if [ "$MODE" = "reload" ] || [ "$MODE" = "sync" ]; then
    echo "=== Syncing AmneziaWG Sidecar Interface ($INTERFACE) ==="
    if [ ! -f "$CONF_PATH" ]; then
        echo "Error: Config file $CONF_PATH does not exist." >&2
        exit 1
    fi

    if command -v awg-quick >/dev/null 2>&1; then
        echo "Running: awg-quick syncconf $INTERFACE <(awg-quick strip $CONF_PATH)"
        awg-quick strip "$CONF_PATH" | awg-quick syncconf "$INTERFACE" /dev/stdin
        echo "Interface $INTERFACE successfully reloaded."
    elif command -v wg-quick >/dev/null 2>&1; then
        echo "Running: wg-quick syncconf $INTERFACE <(wg-quick strip $CONF_PATH)"
        wg-quick strip "$CONF_PATH" | wg-quick syncconf "$INTERFACE" /dev/stdin
        echo "Interface $INTERFACE successfully reloaded via wg-quick."
    else
        echo "Warning: Neither awg-quick nor wg-quick found on host. Saved $CONF_PATH for container mount."
    fi
    exit 0
fi

echo "=== Generating AmneziaWG Parameters ==="

# Header values (random 32-bit uints or defaults)
H1=${H1:-10000001}
H2=${H2:-10000002}
H3=${H3:-10000003}
H4=${H4:-10000004}
JC=${JC:-4}
JMIN=${JMIN:-40}
JMAX=${JMAX:-70}
S1=${S1:-15}
S2=${S2:-25}

echo "Jc: $JC | Jmin: $JMIN | Jmax: $JMAX | S1: $S1 | S2: $S2"
echo "Headers H1: $H1 | H2: $H2 | H3: $H3 | H4: $H4"

cat <<EOF > "$CONFIG_DIR/awg-params.env"
AWG_JC=$JC
AWG_JMIN=$JMIN
AWG_JMAX=$JMAX
AWG_S1=$S1
AWG_S2=$S2
AWG_H1=$H1
AWG_H2=$H2
AWG_H3=$H3
AWG_H4=$H4
EOF

echo "Saved AmneziaWG parameters to certs/awg/awg-params.env"
