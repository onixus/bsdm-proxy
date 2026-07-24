# Установка BSDM-Proxy

Актуальная версия проекта — `0.6.1-1`. Этот файл оставлен как короткая
точка входа; подробные инструкции поддерживаются в
[руководстве по развёртыванию](docs/getting-started/deployment.md).

## Пилот на 100 пользователей

Для согласованного пилотного профиля без DLP, reverse proxy, ICAP и ClamAV,
с хранением аналитики до пяти дней, используйте
[отдельный runbook и сайзинг](docs/getting-started/pilot-deployment.md).

Рекомендуемый стартовый сервер: **12 vCPU, 24 GiB RAM, 200 GB NVMe, 1 GbE**.
Это расчётная отправная точка; перед вводом в эксплуатацию выполните нагрузочный
тест на реальном профиле трафика.

## Docker Compose

```bash
git clone https://github.com/onixus/bsdm-proxy.git
cd bsdm-proxy
./scripts/gen-ca.sh
docker compose up -d --build
docker compose ps
```

Основной Compose поднимает proxy, Kafka, ClickHouse, indexer, Prometheus и
Grafana. Опциональные сервисы запускаются своими profiles; точный состав
описан в [deployment.md](docs/getting-started/deployment.md).

Проверка:

```bash
curl http://127.0.0.1:9090/health
curl -x http://127.0.0.1:1488 http://httpbin.org/get
curl --cacert certs/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/uuid
```

## Lite и локальная разработка

```bash
# Proxy + SQLite indexer, без Kafka и ClickHouse
docker compose -f docker-compose.lite.yml up -d --build

# Локальная сборка основного proxy
cargo build -p bsdm-proxy --bin proxy
```

Для Cargo-сборки используйте актуальный Rust stable, совместимый с lockfile;
toolchain в репозитории сейчас не зафиксирован. Системные зависимости перечислены в
[руководстве разработчика](docs/ops-and-dev/development.md).

## Native package и Kubernetes

- Native package: `./scripts/build-package.sh`, затем инструкции из
  [packaging/README.md](packaging/README.md).
- Kubernetes: Helm chart и ограничения описаны в
  [charts/bsdm/README.md](charts/bsdm/README.md).

Не используйте `charts/bsdm/values-prod.yaml` как готовый сайзинг пилота:
это исторический HA-профиль для существенно большей нагрузки.

## Перед эксплуатацией

- Распространите `certs/ca.crt` только на управляемые клиенты.
- Не публикуйте proxy, ClickHouse, Kafka и административные endpoints в
  интернет.
- Задайте токены API и внешние секреты вместо значений из примеров.
- Проверьте фактический retention ClickHouse, Kafka и Prometheus.
- Сверьте ограничения функций в [project-status.md](docs/project-status.md).
