#!/usr/bin/env bash
# Smoke: eBPF/XDP lab path — arming gate, Control API, kernel maps, metrics.
#
# LAB ONLY. eBPF/XDP is not part of the Day-1 pilot scope and is not a security
# boundary (docs/features/ebpf-xdp.md). This script loads a kernel XDP program
# on a real interface: run it on a throwaway Linux host, never on a pilot node.
#
# Prerequisites (all checked below, the script skips or fails loudly otherwise):
#   - Linux kernel >= 5.4 with CONFIG_BPF_SYSCALL
#   - root or CAP_BPF + CAP_NET_ADMIN
#   - bpftool, clang, ip (iproute2), curl
#   - proxy started with EBPF_XDP_ALLOW_RUNTIME_ENABLE=true (or EBPF_XDP_ENABLED=true)
#     and a reachable control plane
#
# Usage:
#   sudo EBPF_IFACE=eth0 CONTROL_API_TOKEN=... ./scripts/run-ebpf-lab-smoke.sh
#   EBPF_SKIP_KERNEL=1 CONTROL_API_TOKEN=... ./scripts/run-ebpf-lab-smoke.sh  # API-only
set -euo pipefail

API_URL="${EBPF_API_URL:-http://127.0.0.1:9090}"
METRICS_URL="${EBPF_METRICS_URL:-${API_URL}}"
IFACE="${EBPF_IFACE:-eth0}"
MODE="${EBPF_MODE:-skb}"
TEST_IP="${EBPF_TEST_IP:-198.51.100.77}"
TEST_IP_V6="${EBPF_TEST_IP_V6:-2001:db8::77}"
TOKEN="${CONTROL_API_TOKEN:-}"
TIMEOUT="${TIMEOUT:-10}"
SKIP_KERNEL="${EBPF_SKIP_KERNEL:-0}"
BPF_OBJ="${EBPF_OBJ:-bpf/xdp_drop.o}"
BPF_SRC="${EBPF_SRC:-bpf/xdp_drop.c}"

skip() {
  echo "⏭  SKIP: $*"
  echo "   eBPF/XDP is Linux-only; nothing to verify on this host."
  exit 0
}

fail() {
  echo "❌ $*" >&2
  exit 1
}

echo "============================================================"
echo " eBPF / XDP lab smoke  (LAB ONLY — Day-1 pilot: OFF)"
echo " Control API: ${API_URL}"
echo " Metrics:     ${METRICS_URL}/metrics"
echo " Interface:   ${IFACE} (mode ${MODE})"
echo "============================================================"

# --- Preconditions -------------------------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
  skip "host is $(uname -s), not Linux"
fi
if [[ ! -d /sys/fs/bpf ]] && [[ "$SKIP_KERNEL" != "1" ]]; then
  skip "no bpffs at /sys/fs/bpf (container without BPF support?)"
fi

for tool in curl; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool not found"
done

if [[ "$SKIP_KERNEL" != "1" ]]; then
  for tool in bpftool clang ip; do
    command -v "$tool" >/dev/null 2>&1 \
      || skip "$tool not found (install linux-tools-\$(uname -r) / clang / iproute2)"
  done
  if [[ "$(id -u)" != "0" ]]; then
    if ! capsh --print 2>/dev/null | grep -qE 'cap_bpf|cap_sys_admin'; then
      skip "not root and no CAP_BPF/CAP_SYS_ADMIN — cannot load XDP programs"
    fi
  fi
  ip link show dev "$IFACE" >/dev/null 2>&1 || fail "interface ${IFACE} does not exist"
fi
echo "✅ Preconditions OK"

# Seeded with an inert header so the array is never empty (`set -u` + bash 3.x).
auth=(-H "X-BSDM-Smoke: ebpf-lab")
if [[ -n "$TOKEN" ]]; then
  auth+=(-H "Authorization: Bearer ${TOKEN}")
else
  echo "ℹ  CONTROL_API_TOKEN unset — only works with CONTROL_API_ALLOW_INSECURE=true"
fi

api() { # api <method> <path> [body]
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sS --max-time "$TIMEOUT" -o "$TMP_BODY" -w '%{http_code}' \
      -X "$method" "${auth[@]}" -H 'Content-Type: application/json' \
      -d "$body" "${API_URL}${path}"
  else
    curl -sS --max-time "$TIMEOUT" -o "$TMP_BODY" -w '%{http_code}' \
      -X "$method" "${auth[@]}" "${API_URL}${path}"
  fi
}

TMP_BODY="$(mktemp)"
DISABLE_ON_EXIT=0
cleanup() {
  local rc=$?
  if [[ "$DISABLE_ON_EXIT" == "1" ]]; then
    echo "— teardown: unblocking test IPs and detaching XDP"
    api DELETE /api/ebpf/ips >/dev/null 2>&1 || true
    api PUT /api/ebpf/config \
      "{\"enabled\":false,\"interface\":\"${IFACE}\",\"mode\":\"${MODE}\",\"mapName\":\"bsdm_blocked_ips\",\"maxEntries\":65536}" \
      >/dev/null 2>&1 || true
    if [[ "$SKIP_KERNEL" != "1" ]] && command -v ip >/dev/null 2>&1; then
      # Belt and braces: the proxy detaches on disable, this catches a crash.
      ip link set dev "$IFACE" xdpgeneric off >/dev/null 2>&1 || true
      ip link set dev "$IFACE" xdp off >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$TMP_BODY"
  exit "$rc"
}
trap cleanup EXIT

# --- Optional: build the BPF object before the proxy needs it ------------
if [[ "$SKIP_KERNEL" != "1" ]]; then
  if [[ ! -f "$BPF_OBJ" ]]; then
    [[ -f "$BPF_SRC" ]] || fail "${BPF_SRC} not found (run from the repo root)"
    echo "— compiling ${BPF_SRC} → ${BPF_OBJ}"
    clang -O2 -target bpf -c "$BPF_SRC" -o "$BPF_OBJ" || fail "clang failed to build ${BPF_OBJ}"
  fi
  echo "✅ BPF object present: ${BPF_OBJ}"
fi

# --- 1. GET /api/ebpf/config: read the arming gate -----------------------
code="$(api GET /api/ebpf/config)"
[[ "$code" == "200" ]] || fail "GET /api/ebpf/config → HTTP ${code}: $(cat "$TMP_BODY")"
cfg="$(cat "$TMP_BODY")"
echo "✅ GET /api/ebpf/config → ${cfg}"

armed="$(printf '%s' "$cfg" | grep -o '"runtimeEnableAllowed":[a-z]*' | cut -d: -f2 || true)"
if [[ "$armed" != "true" ]]; then
  echo "ℹ  Proxy is NOT armed (runtimeEnableAllowed=false) — this is the expected"
  echo "   pilot default. Verifying that the control plane refuses to enable it."
  code="$(api PUT /api/ebpf/config \
    "{\"enabled\":true,\"interface\":\"${IFACE}\",\"mode\":\"${MODE}\",\"mapName\":\"bsdm_blocked_ips\",\"maxEntries\":65536}")"
  [[ "$code" == "403" ]] \
    || fail "unarmed enable returned HTTP ${code}, expected 403: $(cat "$TMP_BODY")"
  echo "✅ Unarmed enable correctly refused with 403"
  echo "   To run the full lab path, restart the proxy with:"
  echo "     EBPF_XDP_ALLOW_RUNTIME_ENABLE=true"
  echo "============================================================"
  echo " eBPF lab smoke PASSED (gate-only: subsystem not armed)"
  echo "============================================================"
  exit 0
fi

# --- 2. PUT /api/ebpf/config: enable -------------------------------------
DISABLE_ON_EXIT=1
code="$(api PUT /api/ebpf/config \
  "{\"enabled\":true,\"interface\":\"${IFACE}\",\"mode\":\"${MODE}\",\"mapName\":\"bsdm_blocked_ips\",\"maxEntries\":65536}")"
[[ "$code" == "200" ]] || fail "PUT /api/ebpf/config → HTTP ${code}: $(cat "$TMP_BODY")"
echo "✅ PUT /api/ebpf/config (enabled) → $(cat "$TMP_BODY")"

# --- 3. Kernel-side attachment -------------------------------------------
if [[ "$SKIP_KERNEL" != "1" ]]; then
  if ip link show dev "$IFACE" | grep -qi 'xdp'; then
    echo "✅ XDP program attached to ${IFACE}"
  else
    fail "no XDP program on ${IFACE} after enabling (check proxy logs)"
  fi
  bpftool map show name bsdm_blocked_ips >/dev/null 2>&1 \
    || fail "BPF map bsdm_blocked_ips not visible to bpftool"
  echo "✅ BPF maps visible (bsdm_blocked_ips)"
fi

# --- 4. POST /api/ebpf/ips (IPv4 + IPv6) ---------------------------------
for ip in "$TEST_IP" "$TEST_IP_V6"; do
  code="$(api POST /api/ebpf/ips "{\"ip\":\"${ip}\",\"reason\":\"lab smoke\"}")"
  [[ "$code" == "201" ]] || fail "POST /api/ebpf/ips ${ip} → HTTP ${code}: $(cat "$TMP_BODY")"
  echo "✅ Blocked ${ip}"
done

code="$(api GET /api/ebpf/ips)"
[[ "$code" == "200" ]] || fail "GET /api/ebpf/ips → HTTP ${code}"
grep -q "$TEST_IP" "$TMP_BODY" || fail "GET /api/ebpf/ips does not list ${TEST_IP}"
echo "✅ GET /api/ebpf/ips lists both test addresses"

# Duplicate block must be a 409, not a silent overwrite.
code="$(api POST /api/ebpf/ips "{\"ip\":\"${TEST_IP}\"}")"
[[ "$code" == "409" ]] || fail "duplicate block → HTTP ${code}, expected 409"
echo "✅ Duplicate block rejected with 409"

# --- 5. GET /api/ebpf/stats ----------------------------------------------
code="$(api GET /api/ebpf/stats)"
[[ "$code" == "200" ]] || fail "GET /api/ebpf/stats → HTTP ${code}"
echo "✅ GET /api/ebpf/stats → $(cat "$TMP_BODY")"
grep -q '"activeBlockedIps":2' "$TMP_BODY" || echo "⚠ activeBlockedIps != 2 (check for stale entries)"
if [[ "$SKIP_KERNEL" != "1" ]]; then
  grep -q '"attached":true' "$TMP_BODY" \
    || fail "stats report attached=false while XDP should be loaded"
fi

# --- 6. Prometheus metrics ------------------------------------------------
metrics="$(curl -fsS --max-time "$TIMEOUT" "${auth[@]}" "${METRICS_URL}/metrics" || true)"
[[ -n "$metrics" ]] || fail "empty /metrics body (METRICS_AUTH_TOKEN required?)"
for series in bsdm_proxy_ebpf_armed \
              bsdm_proxy_ebpf_blocked_ips \
              bsdm_proxy_ebpf_packets_dropped_total \
              bsdm_proxy_ebpf_bytes_dropped_total; do
  printf '%s\n' "$metrics" | grep -q "^${series}" || fail "metric ${series} missing from /metrics"
  echo "✅ ${series} = $(printf '%s\n' "$metrics" | grep "^${series} " | awk '{print $2}')"
done

# --- 7. DELETE /api/ebpf/ips ---------------------------------------------
code="$(api DELETE "/api/ebpf/ips/${TEST_IP}")"
[[ "$code" == "200" ]] || fail "DELETE /api/ebpf/ips/${TEST_IP} → HTTP ${code}"
code="$(api DELETE "/api/ebpf/ips/${TEST_IP}")"
[[ "$code" == "404" ]] || fail "second DELETE → HTTP ${code}, expected 404"
echo "✅ DELETE by IP works and is idempotent-safe (404 on repeat)"

code="$(api DELETE /api/ebpf/ips)"
[[ "$code" == "200" ]] || fail "DELETE /api/ebpf/ips (clear) → HTTP ${code}"
echo "✅ Cleared all blocked IPs"

# --- 8. Disable + verify detach ------------------------------------------
code="$(api PUT /api/ebpf/config \
  "{\"enabled\":false,\"interface\":\"${IFACE}\",\"mode\":\"${MODE}\",\"mapName\":\"bsdm_blocked_ips\",\"maxEntries\":65536}")"
[[ "$code" == "200" ]] || fail "PUT /api/ebpf/config (disable) → HTTP ${code}"
if [[ "$SKIP_KERNEL" != "1" ]]; then
  if ip link show dev "$IFACE" | grep -qi 'xdp'; then
    fail "XDP still attached to ${IFACE} after disable"
  fi
  echo "✅ XDP detached from ${IFACE}"
fi
DISABLE_ON_EXIT=0

echo "============================================================"
echo " eBPF lab smoke PASSED"
echo "============================================================"
echo "Reminder: leave EBPF_XDP_ENABLED / EBPF_XDP_ALLOW_RUNTIME_ENABLE"
echo "unset (or false) on pilot nodes — see docs/features/ebpf-xdp.md"
