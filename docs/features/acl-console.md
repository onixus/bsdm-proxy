# Политики в Admin Console

> См. также: [ACL](acl-policy.md) · [категоризация](categorization.md) · [control plane](control-plane.md)

Страница **Policies** (`/admin/#/policies`) — живой CRUD ACL на порту метрик (`METRICS_PORT`, обычно `:9090`). Это не демо-таблица и не инвентарь UT1.

## Две разные панели

| Панель | Что это | Что не это |
|---|---|---|
| **Категории** | Только правила `rule_type.Category`, которые уже созданы | Не список сайтов и не содержимое UT1 |
| **Домены и прочие** | Domain / URL / regex / IP / время / пользователь | Не повтор категорий |

Раньше каталог из ~35 имён рисовался как будто все они — активные политики, а те же Category-правила ещё раз попадали в общую таблицу. Теперь:

- верхняя таблица — только живые Category-правила;
- имена без правила живут только в форме **Добавить категорию**;
- нижняя таблица категории не дублирует.

## Категория — метка, не сайт

Поток:

1. На CONNECT/запрос категоризатор смотрит хост (`CATEGORIZATION_ENABLED=true`).
2. Локальная база UT1 (`UT1_ENABLED=true`, `UT1_PATH`) ставит метку: `vk.com` → `social`, `dropbox.com` → `filehosting`, `rt.pornhub.com` → `adult`.
3. ACL сравнивает метку с правилом `{ "Category": "social" }`.
4. Совпало — действие правила (`deny` / `allow` / `redirect`). Не совпало ни одно правило — `ACL_DEFAULT_ACTION` (на пилоте `allow`).

Если категоризация или UT1 выключены (Settings → Filtering), метки пустые. Category-правила в этом режиме **молчат**. Доменные правила продолжают работать.

Папки UT1 и ACL-имена не всегда совпадают. Примеры:

| Папка UT1 | ACL id в консоли |
|---|---|
| `social_networks` | `social` |
| `filehosting` | `filehosting` |
| `adult` | `adult` |
| `publicite` | `adv` |
| `agressif` | `violence` |
| — (Zapret-info) | `rkn` |

Каталог в форме «Добавить» — **статический справочник** этих ACL id. Он не спрашивает диск и не показывает, сколько доменов реально загружено из UT1. Пока у имени нет строки в верхней таблице, оно никого не блокирует.

## Зачем тогда доменные правила

UT1 знает витрину и часто не знает CDN/API:

- `vk.com` → категория `social`
- `st1-30.vkvideo.ru`, `*.userapi.com` — часто без категории → нужны `Domain`
- `drive.google.com` нет в `filehosting`; `drive.usercontent.google.com` не матчится на `*.drive.google.com`

Нижняя таблица — как раз эти точечные хосты. Это не дубль категорий, а дырки списков.

## Кнопки

| Кнопка | Эффект |
|---|---|
| **Включить** на категории без правила | `POST /api/acl/rules` + сразу `POST /api/acl/persist` |
| **Выключить** | `PUT` `enabled: false` + persist. Правило остаётся, метка больше не режется |
| **Добавить категорию** | Форма: ACL id из каталога или своё имя, приоритет, deny/allow/redirect |
| **Сохранить** (шапка) | Память → `ACL_RULES_PATH` |
| **Перезагрузить из файла** | Файл → память. Несохранённое пропадёт |
| **Обновить** | Повторный `GET /api/acl/rules` |

Консоль пишет persist после мутаций специально: при `ACL_AUTO_RELOAD=true` файл раз в минуту перечитывается и иначе откатил бы UI.

Нужен токен вкладки (Settings → Console API / `ACL_API_TOKEN` или `CONTROL_API_TOKEN`). Пустой токен режет мутации на клиенте.

## Приоритет

Первое совпавшее правило побеждает. Больше число — раньше.

Типичная сетка пилота:

- 180 — malware / phishing
- 150 — adult
- 141 — доменные CDN/API
- 140 — social / filehosting
- иначе — `allow`

## Что проверить, если «не режет»

1. В верхней таблице у категории `enabled`, не серая.
2. Settings → Filtering: `CATEGORIZATION_ENABLED` и `UT1_ENABLED`.
3. Хост вообще есть в UT1 (логи: `categories=["social"]`). Если `categories=[]` — ставьте Domain, а не Category.
4. После UI-правок не нажимали **Reload from file** со старым JSON.
5. `GET /api/acl/rules` — то же `count` и `enabled`, что на экране.

## API

Те же эндпоинты, что в [acl-policy.md](acl-policy.md): `GET/POST /api/acl/rules`, `PUT/DELETE /api/acl/rules/:id`, `POST /api/acl/persist`, `POST /api/acl/reload`.
