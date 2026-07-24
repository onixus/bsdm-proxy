# Troubleshooting

## Proxy не стартует

Проверьте:

```bash
docker compose ps
docker compose logs --tail=200 proxy
```

Частая причина при `MITM_ENABLED=true` — отсутствие `certs/ca.key` и
`certs/ca.crt`:

```bash
./scripts/gen-ca.sh
```

Для проверки без MITM задайте `MITM_ENABLED=false`.

## Клиент не доверяет HTTPS

Установите `certs/ca.crt` в trust store клиента. Передавайте именно сертификат,
не private key.

Проверка:

```bash
curl --cacert certs/ca.crt \
  -x http://127.0.0.1:1488 \
  https://httpbin.org/get
```

## Нет cache HIT для HTTPS

HTTPS cache требует MITM. При `MITM_ENABLED=false` CONNECT создаёт opaque tunnel,
поэтому proxy не видит HTTP response.

Проверьте response header `X-Cache-Status` и metrics:

```bash
curl http://127.0.0.1:9090/metrics | grep bsdm_proxy_cache
```

Upstream `Cache-Control`, method, status и `MAX_CACHE_BODY_SIZE` также могут
запретить сохранение.

## cache-indexer не стартует

Indexer с `INDEX_STORE=clickhouse` проверяет доступность ClickHouse и таблицы при
старте:

```bash
docker compose logs --tail=200 cache-indexer
curl http://127.0.0.1:8123/ping
curl 'http://127.0.0.1:8123/?query=SHOW+TABLES+FROM+bsdm'
```

Примените:

```bash
clickhouse-client --multiquery < scripts/clickhouse/http_cache.sql
clickhouse-client --multiquery < scripts/clickhouse/ml_features.sql
```

До включения DLP/CASB analytics синхронизируйте event mapper и ClickHouse schema.

## Kafka lag растёт

Проверьте:

- доступность Kafka из proxy и indexer;
- `KAFKA_BROKERS`, topic и consumer group;
- ошибки batch insert ClickHouse;
- ClickHouse disk space и merge backlog.

Не увеличивайте `KAFKA_SAMPLE_RATE` вслепую: `0` означает все события, `N` —
примерно одно из N.

## ClickHouse занимает слишком много диска

Проверьте TTL и parts:

```sql
SHOW CREATE TABLE bsdm.http_cache;

SELECT
    table,
    sum(bytes_on_disk) AS bytes,
    count() AS parts
FROM system.parts
WHERE active AND database = 'bsdm'
GROUP BY table
ORDER BY bytes DESC;
```

Пилотный TTL: [Пилот на 100 пользователей](pilot-deployment.md).

## Redis растёт без ограничения

Задайте:

```text
maxmemory 2gb
maxmemory-policy allkeys-lfu
```

После изменения проверьте eviction rate и cache hit ratio.

## DNS sinkhole не запускает DoH/DoT

DoH/DoT требуют:

- `DNS_SINKHOLE_TLS_CERT`;
- `DNS_SINKHOLE_TLS_KEY`;
- свободные bind ports;
- корректный `DNS_SINKHOLE_ZONE_PATH`.

Без TLS-файлов процесс продолжит UDP path, но зашифрованные listeners не будут
готовы.

## ML работает только для одной модели

`ML_MODEL` выбирается на процесс. Запускайте отдельный `ml-worker` для каждой
одновременно требуемой модели и назначайте уникальные metrics ports.

## Проверка конфигурации

Сравните deployment environment с:

- `packaging/config/*.env.example`;
- [Configuration](../ops-and-dev/configuration.md);
- фактическими переменными в исходном коде.

Admin Console может показывать поля, которые ещё не поддерживаются runtime.

## Ссылки

- [Deployment](deployment.md)
- [Project status](../project-status.md)
- [Logging](../ops-and-dev/logging.md)
- [Capacity planning](../architecture/capacity-planning.md)
