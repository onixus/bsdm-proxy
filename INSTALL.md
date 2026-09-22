# Установка BSDM-Proxy

Актуальная версия проекта — `0.9.15`. Этот файл оставлен как короткая
точка входа; подробные инструкции поддерживаются в
[руководстве по развёртыванию](docs/getting-started/deployment.md).

## Готовый пакет без сборки (Linux, systemd)

На целевом сервере не нужны ни Rust, ни Node, ни Docker. Бинарники в релизе
статические (musl) и запускаются на любом Linux x86_64 / aarch64:

```bash
curl -fsSL https://raw.githubusercontent.com/onixus/bsdm-proxy/main/scripts/install-release.sh \
  | sudo bash -s -- --version 0.9.15
```

Скрипт скачивает тарболл релиза с GitHub, сверяет `.sha256`, ставит бинарники
в `/opt/bsdm-proxy`, Admin Console в `/opt/bsdm-proxy/share/admin-console`,
конфиги в `/etc/bsdm-proxy` и systemd-юниты. Сервис не запускается: положите
CA в `/etc/bsdm-proxy/certs`, проверьте `bsdm-proxy.env` и выполните
`systemctl enable --now bsdm-proxy`. Офлайн-установка: скачайте тарболл и
`.sha256` заранее и передайте `--archive /path/to/bsdm-proxy-<ver>-linux-<arch>.tar.gz`.
Подробнее: [packaging/README.md](packaging/README.md).

## Интерактивный установщик

Для быстрого развёртывания в Linux/macOS доступен интерактивный мастер:

```bash
git clone https://github.com/onixus/bsdm-proxy.git
cd bsdm-proxy
./install.sh
```

Мастер проверит пререквизиты, сгенерирует CA-сертификаты, поможет выбрать
профиль развёртывания и подготовит `.env`. Режимы:

1. **Docker Compose** — опубликованные образы из ghcr.io, сборка не нужна.
2. **Native из готового релиза** — тот же `scripts/install-release.sh`, плюс
   генерация CA, настройка портов и запуск сервиса. Компилятор не нужен.
3. **Native из исходников** — сборка `cargo` + `npm` на этом хосте.

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
# Готовые образы из ghcr.io (сборка на хосте не нужна). BSDM_IMAGE_TAG
# выбирает релиз; `up -d --build` вместо pull пересобирает из исходников.
docker compose pull
docker compose up -d
docker compose ps
```

Основной Compose поднимает proxy, Kafka, ClickHouse, indexer, Prometheus и
Grafana. Дополнительные сервисы запускаются через профили:

```bash
# Threat Intelligence коллектор (OpenPhish, PhishStats, Phishing.Database, URLhaus)
docker compose --profile threat-intel pull && docker compose --profile threat-intel up -d

# SIEM вебхуки и ML-скоринг
docker compose --profile alerts --profile ml pull && docker compose --profile alerts --profile ml up -d

# DNS Sinkhole / RPZ сайдкар
docker compose --profile dns-sinkhole pull && docker compose --profile dns-sinkhole up -d
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

- Native package: готовый тарболл из GitHub Releases (см. выше) или сборка
  `./scripts/build-package.sh --docker`, затем инструкции из
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
