#!/usr/bin/env python3

import json
import glob

print("")
print("=" * 80)
print(" BSDM-Proxy Performance Comparison")
print("=" * 80)
print("")

phases = ["baseline", "phase1", "phase2", "phase3"]

print(f"{'Phase':<15} {'Throughput':<20} {'Latency p50':<15} {'Latency p99':<15}")
print("-" * 80)

for phase in phases:
    try:
        with open(f"results/vegeta-{phase}.json", "r") as f:
            data = json.load(f)
            
            throughput = data.get("throughput", 0)
            p50 = data.get("latencies", {}).get("50th", 0) / 1e6  # ns to ms
            p99 = data.get("latencies", {}).get("99th", 0) / 1e6
            
            print(f"{phase:<15} {throughput:>15,.0f} req/s {p50:>10.2f} ms {p99:>10.2f} ms")
    except FileNotFoundError:
        print(f"{phase:<15} {'N/A':<20} {'N/A':<15} {'N/A':<15}")

print("-" * 80)
print("")
print("Expected improvements:")
print("  Phase 1: +3-5x throughput, -80% latency")
print("  Phase 2: +5-7x from Phase 1, horizontal scaling")
print("  Phase 3: +2-3x from Phase 2, advanced optimizations")
print("")
print("Total expected: 50x baseline throughput!")
print("")
