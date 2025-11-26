#!/bin/bash

set -e

echo "======================================"
echo "BSDM-Proxy Performance Benchmarks"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test phases
PHASES=("baseline" "phase1" "phase2" "phase3")
TARGET="https://localhost:1488"

for PHASE in "${PHASES[@]}"; do
    echo "${YELLOW}Testing $PHASE...${NC}"
    
    # wrk test
    echo "${GREEN}[wrk] HTTP load test${NC}"
    wrk -t12 -c400 -d30s --latency \
        -s benchmarks/wrk-benchmark.lua \
        $TARGET > results/wrk-$PHASE.txt
    
    # vegeta test
    echo "${GREEN}[vegeta] Constant rate test${NC}"
    vegeta attack \
        -targets=benchmarks/vegeta-targets.txt \
        -duration=30s \
        -rate=10000 \
        -timeout=30s \
        | vegeta report -type=json > results/vegeta-$PHASE.json
    
    # Wait between tests
    sleep 10
done

echo ""
echo "${GREEN}Benchmarks complete! Results in results/ directory${NC}"
echo ""

# Generate comparison report
echo "${YELLOW}Generating comparison report...${NC}"
python3 benchmarks/compare-results.py

echo "${GREEN}Done!${NC}"
