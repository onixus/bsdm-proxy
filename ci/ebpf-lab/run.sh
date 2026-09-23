#!/usr/bin/env bash
# eBPF/XDP lab run against a real kernel, inside a throwaway network namespace.
#
# Runs in the container started by ci/ebpf-lab/Jenkinsfile (--privileged
# --network none). Topology:
#
#   [container netns]  xdp0 (10.99.0.1, fd99::1)  ← XDP program attached here
#          │ veth
#   [netns "peer"]     xdp0p (10.99.0.2, fd99::2) ← traffic source for probes
#
# The proxy is armed with EBPF_XDP_ALLOW_RUNTIME_ENABLE=true and driven through
# scripts/run-ebpf-lab-smoke.sh, which also checks that packets from the
# blocked peer are really dropped by the kernel.
set -euo pipefail

PROXY_BIN="${PROXY_BIN:-/target/debug/proxy}"
IFACE=xdp0
PEER_NS=peer
LOG_DIR="${LOG_DIR:-ci-logs}"
mkdir -p "$LOG_DIR"

echo "== kernel / tools"
uname -a
ip -V
bpftool version
clang --version | head -1

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

echo "== topology"
ip link set lo up
ip netns add "$PEER_NS"
ip link add "$IFACE" type veth peer name xdp0p
ip link set xdp0p netns "$PEER_NS"
ip addr add 10.99.0.1/24 dev "$IFACE"
ip -6 addr add fd99::1/64 dev "$IFACE" nodad
ip link set "$IFACE" up
ip -n "$PEER_NS" link set lo up
ip -n "$PEER_NS" addr add 10.99.0.2/24 dev xdp0p
ip -n "$PEER_NS" -6 addr add fd99::2/64 dev xdp0p nodad
ip -n "$PEER_NS" link set xdp0p up
ping -c 1 -W 2 10.99.0.2 >/dev/null
ping -6 -c 1 -W 2 fd99::2 >/dev/null
echo "veth pair up, v4/v6 reachable"

# The proxy compiles bpf/xdp_drop.o on demand relative to its cwd; start from
# a clean slate so the run exercises that path.
rm -f bpf/xdp_drop.o

echo "== proxy"
# The proxy applies ./bsdm-proxy.env on top of its environment (Admin Console
# persistence), and the repo copy is a kill-switch: MITM on, eBPF unarmed.
# Point it at an empty file so the variables below are what the run sees.
: >"$LOG_DIR/lab.env"
CONFIG_ENV_PATH="$LOG_DIR/lab.env" \
MITM_ENABLED=false \
POLICY_MODE=sni \
HTTP_PORT=3128 \
METRICS_PORT=9090 \
CONTROL_API_ALLOW_INSECURE=true \
EBPF_XDP_ALLOW_RUNTIME_ENABLE=true \
EBPF_XDP_IFACE="$IFACE" \
EBPF_XDP_MODE=skb \
RUST_LOG="${RUST_LOG:-info}" \
  "$PROXY_BIN" >"$LOG_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  curl -fsS -o /dev/null http://127.0.0.1:9090/health 2>/dev/null && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$LOG_DIR/proxy.log"; echo "proxy died"; exit 1; }
  sleep 1
done
curl -fsS -o /dev/null http://127.0.0.1:9090/health || { cat "$LOG_DIR/proxy.log"; exit 1; }
echo "proxy healthy (pid $PROXY_PID)"

rc=0
EBPF_IFACE="$IFACE" \
EBPF_MODE=skb \
EBPF_TEST_IP=10.99.0.2 \
EBPF_TEST_IP_V6=fd99::2 \
EBPF_PROBE_NETNS="$PEER_NS" \
EBPF_PREBUILD=0 \
EBPF_PROBE_TARGET=10.99.0.1 \
EBPF_PROBE_TARGET_V6=fd99::1 \
  ./scripts/run-ebpf-lab-smoke.sh || rc=$?

echo "== proxy log (eBPF lines)"
grep -iE 'ebpf|xdp|bpf' "$LOG_DIR/proxy.log" || true
exit "$rc"
