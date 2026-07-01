#!/usr/bin/env bash
# HTTP Archive / proxy bench profiles: map BENCH_PROFILE to WORKER_COUNT and related env.
#
# Usage (source from another script):
#   source "$(dirname "$0")/bench-profile.sh"
#   apply_bench_profile
#
# Profiles:
#   warm — WORKER_COUNT=1 (warm-heavy sites bench; less L1 lock contention)
#   cold — WORKER_COUNT=4 (cold/MISS parallelism; multi accept workers)
#
# Override any exported variable after sourcing if needed.

apply_bench_profile() {
  local profile="${BENCH_PROFILE:-warm}"
  case "${profile,,}" in
    warm)
      export BENCH_PROFILE=warm
      export WORKER_COUNT="${WORKER_COUNT:-1}"
      ;;
    cold)
      export BENCH_PROFILE=cold
      export WORKER_COUNT="${WORKER_COUNT:-4}"
      ;;
    *)
      echo "Unknown BENCH_PROFILE='${profile}' (use warm or cold)" >&2
      return 1
      ;;
  esac
  export CACHE_SHARDS="${CACHE_SHARDS:-16}"
  export PERF_FAST_CACHE_HIT="${PERF_FAST_CACHE_HIT:-true}"
  export METRICS_SAMPLE_RATE="${METRICS_SAMPLE_RATE:-100}"
  export HTTP_PRESERVE_HEADER_CASE="${HTTP_PRESERVE_HEADER_CASE:-false}"
}

print_bench_profile() {
  echo "BENCH_PROFILE=${BENCH_PROFILE:-unset} WORKER_COUNT=${WORKER_COUNT:-unset} CACHE_SHARDS=${CACHE_SHARDS:-unset}"
}
