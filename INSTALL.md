# Установка BSDM-Proxy

Актуальная версия проекта — `0.9.14`. Этот файл оставлен как короткая
точка входа; подробные инструкции поддерживаются в
[руководстве по развёртыванию](docs/getting-started/deployment.md).

## Интерактивный установщик

Для быстрого развёртывания в Linux/macOS доступен интерактивный мастер:

```bash
git clone https://github.com/onixus/bsdm-proxy.git
cd bsdm-proxy
./install.sh
```

Мастер проверит пререквизиты, сгенерирует CA-сертификаты, поможет выбрать
профиль развёртывания (Docker Compose, Native systemd, Lite) и подготовит `.env`.

## Пилот на 100 пользователей

Для согласованного пилотного профиля без DLP, reverse proxy, ICAP и ClamAV,
с хранением аналитики до пяти дней, используйте
[отдельный runbook и сайзинг](docs/getting-started/pilot-deployment.md).

Рекомендуемый стартовый сервер: **12 vCPU, 24 GiB RAM, 200 GB NVMe, 1 GbE**.
Это расчётная отправная точка; перед вводом в эксплуатацию выполните нагрузочный
тест на реальном профиле трафика. Готовый compose-override:
`deploy/compose/docker-compose.pilot.yml`.

## Docker Compose

```bash
git clone https://github.com/onixus/bsdm-proxy.git
cd bsdm-proxy
# 0. Обязательные секреты (стек fail-closed и не стартует без них)
export GRAFANA_ADMIN_PASSWORD='...'
export CONTROL_API_TOKEN="$(openssl rand -hex 32)"
export SEARCH_API_TOKEN="$(openssl rand -hex 32)"
# AUTH_ENABLED=true по умолчанию: подставьте свой файл пользователей
# (scripts/gen-basic-auth-user.sh), иначе смонтируется пример с публичными хешами.
export BASIC_AUTH_USERS_HOST=./config/basic-auth-users.json
# MITM CA: 4096-bit RSA, 730 дней (2 года), CA:TRUE pathlen:0,
# keyUsage=keyCertSign,cRLSign. Срок переопределяется: --days N.
# Ротация раз в два года: docs/ops-and-dev/ca-lifecycle.md (scripts/rotate-ca.sh).
./scripts/gen-ca.sh
docker compose up -d --build
docker compose ps
```

Основной Compose поднимает proxy, Kafka, ClickHouse, indexer, Prometheus и
Grafana. Дополнительные сервисы запускаются через профили:

```bash
# Threat Intelligence коллектор (OpenPhish, PhishStats, Phishing.Database, URLhaus)
docker compose --profile threat-intel up -d --build

# SIEM вебхуки и ML-скоринг
docker compose --profile alerts --profile ml up -d --build

# DNS Sinkhole / RPZ сайдкар
docker compose --profile dns-sinkhole up -d --build
```

Проверка:

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/ready
curl -x http://127.0.0.1:3128 http://httpbin.org/get
curl --cacert certs/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/uuid
```

Admin Console доступна по адресу `http://127.0.0.1:9090/admin/`.

## Lite и локальная разработка

```bash
# Proxy + SQLite indexer, без Kafka и ClickHouse
docker compose -f deploy/compose/docker-compose.lite.yml up -d --build

# Локальная сборка основного proxy
cargo build -p bsdm-proxy --bin proxy
```

Для Cargo-сборки используйте актуальный Rust stable (1.85+), совместимый с lockfile.
Системные зависимости перечислены в
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
