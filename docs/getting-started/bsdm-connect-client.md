# BSDM Connect — Нативный клиент AmneziaWG и BSDM (Rust)

**BSDM Connect (`bsdm-connect`)** — это независимый нативный клиент на Rust для подключения к корпоративному шлюзу **BSDM-Proxy** и защищенному обфусцированному VPN-туннелю **AmneziaWG (AWG)**.

Клиент объединяет функции VPN-агента (автоматический провижининг ключей, управление сетевым интерфейсом, обфускация handshake) и агента политик безопасности (локальная фильтрация доменов, OCSP/CRL, реал-тайм синхронизация ACL по WebSocket и телеметрия).

---

## Возможности

- **Автоматический провижининг туннеля (Zero-Touch Provisioning)**: Генерация ключевой пары Curve25519, квантово-устойчивого Pre-Shared Key (PSK), выделение корпоративного IP-адреса и получение параметров обфускации (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4`).
- **Управление туннелем AmneziaWG**: Запуск (`tunnel up`), остановка (`tunnel down`) и мониторинг (`tunnel status`) интерфейса через `awg-quick`, `wg-quick` или системный сервис.
- **Безопасное хранение конфигураций**: Запись `.conf` файлов с атомарной заменой и строгими Unix-правами доступа `0600` (только владелец).
- **Синхронизация политик в реальном времени**: Подписка на обновления ACL и списка доверенных доменов через WebSocket / long-polling.
- **Режим демона**: Непрерывная работа в фоне с периодическим Heartbeat и отправкой телеметрии трафика (bytes RX/TX, handshake timestamp).

---

## Сборка и установка

### Сборка из исходников

```bash
# Сборка бинарника bsdm-connect
cargo build --release -p agent-spike --bin bsdm-connect

# Бинарник доступен в:
./target/release/bsdm-connect --help
```

### Сборка пакетов для развертывания

```bash
./scripts/build-agent-binaries.sh ./dist/agent
```

---

## Руководство по командам CLI

### 1. Регистрация устройства (`enroll`)

Регистрирует устройство на сервере управления BSDM, получает токен устройства (`DEVICE_TOKEN`) и генерирует клиентский конфиг AmneziaWG:

```bash
# Регистрация с автоматическим созданием VPN-туннеля
bsdm-connect enroll \
  --control-url http://127.0.0.1:9090 \
  --token secret-enroll-token \
  --device-id dev-laptop-01 \
  --device-name "Alice MacBook" \
  --with-tunnel

# Результат:
# DEVICE_ID=dev-laptop-01
# DEVICE_TOKEN=bsdm_dev_tok_...
# AWG_CONFIG_PATH=~/.bsdm/awg0.conf
# Состояние сохранено в ~/.bsdm/state.json
```

### 2. Управление туннелем AmneziaWG

#### Запуск туннеля (`tunnel up`)
```bash
# Тестовый прогон без изменения сетевых интерфейсов
bsdm-connect tunnel up --dry-run

# Реальный запуск туннеля (требуются права root/sudo для awg-quick)
sudo bsdm-connect tunnel up --config ~/.bsdm/awg0.conf
```

#### Проверка статуса и телеметрии (`tunnel status`)
```bash
bsdm-connect tunnel status --interface awg0
```
Вывод:
```json
{
  "interface": "awg0",
  "active": true,
  "rx_bytes": 1048576,
  "tx_bytes": 2097152,
  "latest_handshake_secs": 1721812900,
  "endpoint": "proxy.corp.internal:51820",
  "message": "Connected (handshake 12s ago, rx: 1048576 bytes, tx: 2097152 bytes)"
}
```

#### Остановка туннеля (`tunnel down`)
```bash
sudo bsdm-connect tunnel down --config ~/.bsdm/awg0.conf
```

### 3. Экспорт конфигурации туннеля (`tunnel get-config`)

Выгрузка свежего клиентского `.conf` файла напрямую из Control Plane:

```bash
# Выгрузка в stdout
bsdm-connect tunnel get-config --device-id dev-laptop-01 --token bsdm_dev_tok_...

# Выгрузка в файл
bsdm-connect tunnel get-config \
  --device-id dev-laptop-01 \
  --format conf \
  --output ./corporate-awg.conf
```

### 4. Фоновый демон (`run` / `daemon`)

Запуск клиента в фоновом режиме:
```bash
bsdm-connect daemon \
  --control-url http://127.0.0.1:9090 \
  --state-file ~/.bsdm/state.json \
  --with-tunnel
```

---

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `CONTROL_PLANE_URL` | `http://127.0.0.1:9090` | URL панели управления BSDM |
| `AGENT_ENROLL_TOKEN` | — | Токен первичной регистрации |
| `DEVICE_TOKEN` | — | Выданный токен аутентификации устройства |
| `BSDM_STATE_FILE` | `~/.bsdm/state.json` | Путь к локальному файлу состояния |
| `AWG_CLIENT_CONFIG_PATH` | `~/.bsdm/awg0.conf` | Путь к сгенерированному файлу AmneziaWG |
| `AWG_UP_CMD` | `awg-quick up {config}` | Кастомная команда поднятия туннеля |
| `AWG_DOWN_CMD` | `awg-quick down {config}` | Кастомная команда остановки туннеля |
| `AWG_DRY_RUN` | `false` | Режим симуляции команд без изменения интерфейсов |
