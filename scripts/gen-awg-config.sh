#!/usr/bin/env bash
set -euo pipefail

# AmneziaWG Keypair & Obfuscation Config Generator
# Generates server & client configuration files with custom magic headers for DPI bypass.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/../certs/awg"

mkdir -p "$CONFIG_DIR"

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
