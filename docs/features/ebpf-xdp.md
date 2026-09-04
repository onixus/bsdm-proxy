# eBPF / XDP kernel packet filter (lab)

> **⚠ LAB ONLY. Day-1 пилота: OFF. Это не security boundary.**
>
> XDP-фильтр отбрасывает пакеты на уровне драйвера NIC до того, как их увидит
> сетевой стек. Он ничего не знает о политике прокси, ACL, категориях и
> пользователях — это грубый IP-блоклист. Обход тривиален (смена адреса),
> отказ — «тихий» (трафик просто пропадает). Никакие требования пилота на
> фильтрацию не закрываются этим модулем: за это отвечают ACL, DNS RPZ и
> Hybrid Policy.
>
> Зрелость: **Beta (lab)** — см. [project-status.md](../project-status.md).

Код: `proxy/src/ebpf.rs`, `bpf/xdp_drop.c`, `proxy/src/control_api.rs`
(`/api/ebpf/*`). Смоук: `scripts/run-ebpf-lab-smoke.sh`.

## Модель включения (два барьера)

eBPF выключен и **не может быть включён из control plane**, пока оператор явно
не «взвёл» подсистему в окружении процесса. Это тот же fail-safe подход, что и у
TI-enforcement (`TI_ENFORCEMENT_MODE=enforce`, `proxy/src/ti_enforce.rs`).

| Барьер | Где | По умолчанию |
|---|---|---|
| 1. Arming (окружение процесса, требует рестарта) | `EBPF_XDP_ENABLED=true` **или** `EBPF_XDP_ALLOW_RUNTIME_ENABLE=true` | не задано → **off** |
| 2. Runtime toggle (control plane) | `PUT /api/ebpf/config` с `{"enabled": true}` | `false` |

Следствия:

- Без барьера 1 любой `PUT /api/ebpf/config` с `enabled: true` возвращает
  **`403 Forbidden`** и ничего не применяет. Тело запроса не может «взвести»
  подсистему: поле `runtimeEnableAllowed` — read-only (`skip_deserializing`).
- `EBPF_XDP_ENABLED=true` подключает XDP-программу сразу при старте.
- `EBPF_XDP_ALLOW_RUNTIME_ENABLE=true` только взводит: при старте ничего не
  подключается, но control plane получает право включить фильтр.
- Конфигурация с `enabled: true` без arming безопасно понижается до
  `disabled` с предупреждением в логе — программа не загружается.
- Выключение (`enabled: false`) разрешено всегда, независимо от arming.

Где проверяется дефолт:

| Место | Значение |
|---|---|
| `EbpfXdpConfig::default()` / `from_env()` | `enabled=false`, `runtimeEnableAllowed=false` |
| `packaging/config/bsdm-proxy.env.example` | переменные отсутствуют → off |
| `charts/bsdm/values.yaml` | ключа нет, env не выставляется → off |
| `deploy/compose/docker-compose.pilot.yml` | явный kill-switch: обе переменные `"false"` |
| `bsdm-proxy.env` (локальный lab-артефакт) | `EBPF_XDP_ENABLED=false` |

Инвариант зафиксирован тестами `ebpf::tests::test_default_config_is_disabled_and_unarmed`,
`ebpf::tests::test_update_config_refuses_to_enable_when_unarmed` и
`control_api::tests::test_ebpf_control_api_cannot_enable_unarmed_filter`.

## Требования лабораторного стенда

- Linux, ядро ≥ 5.4 (`CONFIG_BPF_SYSCALL`, `CONFIG_XDP_SOCKETS` для driver-режима).
- `CAP_BPF` + `CAP_NET_ADMIN` (или root). В Docker: `cap_add: [BPF, NET_ADMIN]`,
  `network_mode: host` — XDP цепляется к netdev хоста, а не к veth в bridge-сети.
- Утилиты в PATH контейнера/хоста: `bpftool` (linux-tools), `clang` (сборка
  `bpf/xdp_drop.o`), `ip` (iproute2).
- Смонтированный `/sys/fs/bpf`.
- Существующий интерфейс в `EBPF_XDP_IFACE`. Driver-режим требует поддержки
  XDP в драйвере; при сомнениях используйте `skb`.

## Переменные окружения

| Переменная | Значение по умолчанию | Назначение |
|---|---|---|
| `EBPF_XDP_ENABLED` | `false` | Arming + подключение XDP при старте |
| `EBPF_XDP_ALLOW_RUNTIME_ENABLE` | `false` | Arming без подключения при старте |
| `EBPF_XDP_IFACE` | `eth0` | Netdev для attach (1..=15 символов) |
| `EBPF_XDP_MODE` | `skb` | `skb` \| `driver` (`native`) \| `offload` (`hw`) |
| `EBPF_XDP_MAX_ENTRIES` | `65536` | Должно быть ≤ значения, скомпилированного в `bpf/xdp_drop.c` |

## Как включить (lab)

```bash
# 1. Взвести подсистему (рестарт обязателен)
EBPF_XDP_ALLOW_RUNTIME_ENABLE=true \
EBPF_XDP_IFACE=eth0 \
EBPF_XDP_MODE=skb \
  cargo run -p bsdm-proxy

# 2. Включить фильтр из control plane
curl -sS -X PUT -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,"interface":"eth0","mode":"skb",
       "mapName":"bsdm_blocked_ips","maxEntries":65536}' \
  http://127.0.0.1:9090/api/ebpf/config

# 3. Прогнать смоук целиком
sudo EBPF_IFACE=eth0 CONTROL_API_TOKEN=... ./scripts/run-ebpf-lab-smoke.sh
```

`scripts/run-ebpf-lab-smoke.sh` явно скипается (exit 0) на не-Linux хостах и
при отсутствии `bpftool`/`clang`/capabilities; на невзведённом прокси он
проверяет ровно один факт — что `enabled: true` отвергается с 403.

## Control API `/api/ebpf/*`

Все эндпоинты требуют Bearer `CONTROL_API_TOKEN` (в production-профиле —
обязательно; `CONTROL_API_ALLOW_INSECURE=true` только для lab).

| Метод | Путь | Ответ | Комментарий |
|---|---|---|---|
| `GET` | `/api/ebpf/config` | `200` | Текущая конфигурация + read-only `runtimeEnableAllowed` |
| `PUT` | `/api/ebpf/config` | `200` / `400` / `403` / `500` | `400` — невалидные значения; `403` — подсистема не взведена; `500` — ядро отказало в attach |
| `GET` | `/api/ebpf/stats` | `200` | Счётчики ядра + `attached` + `runtimeEnableAllowed` |
| `GET` | `/api/ebpf/ips` | `200` | Список блокировок с аудит-метаданными |
| `POST` | `/api/ebpf/ips` | `201` / `400` / `409` / `500` | Тело `{"ip":"…","reason":"…"}`; IPv4 и IPv6 |
| `DELETE` | `/api/ebpf/ips/{id\|ip}` | `200` / `404` / `500` | Удаление одной записи |
| `DELETE` | `/api/ebpf/ips` | `200` / `500` | Очистка всего блоклиста |

`EbpfXdpConfig` (JSON, camelCase):

```json
{
  "enabled": false,
  "interface": "eth0",
  "mode": "skb",
  "mapName": "bsdm_blocked_ips",
  "maxEntries": 65536,
  "runtimeEnableAllowed": false
}
```

Валидация `PUT /api/ebpf/config` (все нарушения → `400`):

- `interface`: 1..=15 символов, только `[A-Za-z0-9_.:@-]` (защита от shell-инъекции
  в `ip link`).
- `mapName`: строго `bsdm_blocked_ips` — карта, объявленная в `bpf/xdp_drop.c`.
- `maxEntries`: 1..=65536 (значение скомпилировано в BPF-объект).

`EbpfStats`:

```json
{
  "enabled": true,
  "attached": true,
  "interface": "eth0",
  "mode": "skb",
  "activeBlockedIps": 2,
  "packetsDroppedTotal": 0,
  "bytesDroppedTotal": 0,
  "kernelLatencyUs": null,
  "cpuUsageUserPercent": 0.0,
  "runtimeEnableAllowed": true
}
```

`enabled` — это запрошенная конфигурация, `attached` — факт загрузки программы
на интерфейс. Расхождение (`enabled=true`, `attached=false`) означает, что
трафик **не фильтруется**; прокси пишет об этом warning каждые 15 секунд.
`kernelLatencyUs` всегда `null` — измерения нет, синтетическое значение не
подставляется.

## Метрики

| Метрика | Тип | Значение |
|---|---|---|
| `bsdm_proxy_ebpf_armed` | Gauge | `1`, если подсистема взведена окружением. **Пилотный инвариант: должно быть `0`.** |
| `bsdm_proxy_ebpf_blocked_ips` | Gauge | Число адресов в блоклисте |
| `bsdm_proxy_ebpf_packets_dropped_total` | Counter | Дельты счётчика ядра из карты `bsdm_drop_stats` |
| `bsdm_proxy_ebpf_bytes_dropped_total` | Counter | То же для байтов |

Счётчики ядра монотонны только между attach; при переподключении карты
обнуляются, и репортёр перебазируется вместо отрицательной дельты.

Алерт для пилота:

```promql
bsdm_proxy_ebpf_armed > 0
```

## Как выключить и выгрузить

```bash
# Runtime: detach без рестарта
curl -sS -X PUT -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":false,"interface":"eth0","mode":"skb",
       "mapName":"bsdm_blocked_ips","maxEntries":65536}' \
  http://127.0.0.1:9090/api/ebpf/config

# Проверить, что на netdev ничего не висит
ip link show dev eth0 | grep -i xdp   # пусто = отцеплено

# Аварийная ручная выгрузка (например, после kill -9 прокси)
sudo ip link set dev eth0 xdpgeneric off
sudo ip link set dev eth0 xdp off

# Persistent: убрать arming и перезапустить
EBPF_XDP_ENABLED=false EBPF_XDP_ALLOW_RUNTIME_ENABLE=false
```

Прокси сам отцепляет программу при штатном завершении (`Drop for ManagerInner`,
только у последнего владельца shared state). При `SIGKILL` программа остаётся
на интерфейсе — выгружайте вручную.

## Известные ограничения

1. **Не security boundary.** Блоклист по IP: смена адреса обходит фильтр,
   NAT/CDN дают ложные срабатывания на весь пул.
2. Attach выполняется через shell-out в `ip link` / `bpftool`, а не через
   libbpf: нет BTF, CO-RE и pinned links. Утилиты обязаны быть в PATH.
3. Блоклист хранится в памяти и **не персистится**: после рестарта прокси
   карты ядра пусты, записи из `POST /api/ebpf/ips` теряются.
4. Пока фильтр выключен, `POST /api/ebpf/ips` пишет только в in-memory реестр;
   в карты ядра записи попадут при следующем включении (re-sync).
5. `kernelLatencyUs` и `cpuUsageUserPercent` не измеряются (`null` / `0.0`).
6. `bpf/xdp_drop.c` жёстко задаёт `max_entries=65536` и имена карт; изменение
   требует правки C-исходника и пересборки объекта.
7. XDP цепляется к netdev **хоста**. В bridge-сети Docker фильтр применится к
   veth, а не к внешнему трафику — нужен `network_mode: host`.
8. Панель eBPF в Admin Console помечена frozen и при ошибке API показывает
   моки, а не реальное состояние. Источник правды — `GET /api/ebpf/stats`.

## Ссылки

- [project-status.md](../project-status.md) — матрица зрелости
- [roadmap.md](../roadmap.md) — Scope Freeze
- [pilot-deployment.md](../getting-started/pilot-deployment.md) — чек-лист Day-1
- [configuration.md](../ops-and-dev/configuration.md) — справочник переменных
