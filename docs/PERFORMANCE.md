# BSDM-Proxy Performance Guide

## Текущая производительность

### Baseline (main branch)
```
Throughput:  ~10,000 req/s   (1 core)
Latency p50: 5-10ms
Latency p99: 50-100ms
Memory:      ~200MB
CPU:         70-80% @ 10k req/s
```

### Phase 1: Quick Wins (+3-5x)
```
Throughput:  ~40,000 req/s   (1 core)
Latency p50: 1-2ms
Latency p99: 10-20ms
Memory:      ~150MB
CPU:         60-70% @ 40k req/s
```

**Оптимизации:**
- DashMap вместо RwLock (+50% throughput)
- xxHash3 вместо SHA256 (-80% CPU на хеширование)
- Async Kafka channel с batching (-95% latency)
- jemalloc allocator (-15% fragmentation)
- Async FS operations

### Phase 2: Architecture (+5-7x from Phase 1)
```
Throughput:  ~250,000 req/s  (4 cores, 4 replicas)
Latency p50: 0.5-1ms
Latency p99: 5-10ms
Memory:      ~150MB (на инстанс)
CPU:         60-70% @ 60k req/s (на ядро)
```

**Оптимизации:**
- Redis shared cert cache
- Horizontal scaling (4 replicas)
- Kafka tuning (8 network threads, 16 I/O threads, lz4)
- OpenSearch sharding (4 shards)
- HTTP/2 multiplexing (128 streams)
- Prometheus + Grafana monitoring

### Phase 3: Advanced (+2-3x from Phase 2)
```
Throughput:  ~500,000+ req/s (8 cores, 8 replicas)
Latency p50: 0.2-0.5ms
Latency p99: 2-5ms
Memory:      ~120MB (на инстанс)
CPU:         50-60% @ 60k req/s (на ядро)
```

**Оптимизации:**
- io_uring для zero-copy I/O (Linux 5.10+)
- SIMD JSON parsing (simd-json)
- eBPF traffic filtering
- Custom memory allocator tuning

## Запуск Performance Edition

### Phase 1
```bash
git checkout performance
docker-compose -f docker-compose.yml up -d
```

### Phase 2
```bash
docker-compose -f docker-compose.performance.yml up -d
```

### Phase 3
```bash
docker-compose -f docker-compose.ultimate.yml up -d
```

## Benchmarking

### wrk - HTTP benchmarking
```bash
# Install
sudo apt-get install wrk

# Test
wrk -t12 -c400 -d30s --latency https://localhost:1488/test

# With custom script
wrk -t12 -c400 -d30s -s scripts/benchmark.lua https://localhost:1488
```

### vegeta - Load testing
```bash
# Install
go install github.com/tsenart/vegeta@latest

# Test
echo "GET https://localhost:1488/test" | \
  vegeta attack -duration=30s -rate=10000 | \
  vegeta report -type=text

# JSON report
echo "GET https://localhost:1488/test" | \
  vegeta attack -duration=30s -rate=10000 | \
  vegeta report -type=json > results.json
```

### Grafana Dashboards

Откройте http://localhost:3000 (admin/admin)

**Готовые дашборды:**
- Proxy Performance - throughput, latency, CPU, memory
- Kafka Metrics - lag, throughput, broker stats
- OpenSearch - indexing rate, search latency, shard stats

## Метрики

### Просмотр Prometheus

http://localhost:9090/graph

**Ключевые метрики:**
```promql
# Requests per second
rate(pingora_http_requests_total[1m])

# Latency p99
histogram_quantile(0.99, rate(pingora_http_request_duration_seconds_bucket[5m]))

# Cache hit rate
rate(pingora_cache_hits_total[1m]) / rate(pingora_cache_requests_total[1m])

# Kafka lag
kafka_consumer_lag_seconds
```

## Tuning Tips

### Увеличение file descriptors (Linux)
```bash
# /etc/security/limits.conf
* soft nofile 1000000
* hard nofile 1000000

# Sysctl
sudo sysctl -w fs.file-max=2097152
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=8192
```

### Docker resource limits
```yaml
proxy:
  deploy:
    resources:
      limits:
        cpus: '4'
        memory: 2G
      reservations:
        cpus: '2'
        memory: 512M
```

### Redis tuning
```bash
# Увеличение maxmemory
redis-cli CONFIG SET maxmemory 4gb

# Eviction policy
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

## Troubleshooting

### Высокий CPU
1. Проверьте profiling: `perf record -F 99 -p <PID>`
2. Увеличьте количество workers: `PINGORA_THREADS=8`
3. Проверьте Kafka batching

### Высокая память
1. Проверьте cert cache size: `redis-cli DBSIZE`
2. Уменьшите TTL: `CERT_CACHE_TTL=1800`
3. Включите jemalloc stats: `MALLOC_CONF=stats_print:true`

### Высокая латентность
1. Проверьте Kafka lag
2. Увеличьте batch size
3. Проверьте network latency

---

[← README](../README.md) | [Architecture](../docs/ARCHITECTURE.md)
