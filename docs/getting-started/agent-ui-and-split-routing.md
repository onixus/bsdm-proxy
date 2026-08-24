# Управление маршрутизацией по доменам и UI агента (macOS & Android)

Клиент **`bsdm-connect`** предоставляет возможность раздельной маршрутизации трафика (Domain-Based Split Routing / Smart PAC) и встроенный графический интерфейс для настольных (macOS/Windows/Linux) и мобильных (Android/iOS) устройств.

---

## 1. Разграничение маршрутов по доменам (Split Routing)

Каждому домену или группе доменов можно назначить целевой маршрут:
- **`direct`**: Прямое подключение к интернету в обход прокси и VPN.
- **`proxy`**: Направление трафика через корпоративный защищенный прокси-сервер BSDM (`HTTP_PORT=3128`).
- **`tunnel`**: Маршрутизация через зашифрованный туннель AmneziaWG с обфускацией.
- **`block`**: Локальный sinkhole (блокировка трекеров, вредоносных доменов).

### Управление маршрутами через CLI

```bash
# Просмотр таблицы маршрутов:
bsdm-connect routes list

# Добавление правила для домена:
bsdm-connect routes add --pattern "*.corp.internal; wiki.company.com" --target proxy --comment "Корпоративные сервисы"

# Добавление правила для прямого доступа:
bsdm-connect routes add --pattern "*.youtube.com; *.zoom.us" --target direct --comment "Видеосвязь без прокси"

# Добавление правила для туннеля:
bsdm-connect routes add --pattern "*.vpn.internal; 10.0.0.0/8" --target tunnel --comment "Защищенные базы данных"

# Экспорт PAC (Proxy Auto-Configuration) файла:
bsdm-connect routes export-pac --output ~/.bsdm/proxy.pac
```

---

## 2. Графический интерфейс агента (Agent UI)

Агент включает встроенный веб-интерфейс, оптимизированный под экраны мобильных устройств (Android/iOS) и десктопные системы (macOS/Windows/Linux).

### Запуск UI сервера

```bash
# Запуск только UI и PAC сервера на порту 8765:
bsdm-connect ui --port 8765

# Запуск постоянного демона (синхронизация политик + туннель + UI сервер):
bsdm-connect daemon
```

Интерфейс доступен по адресу: **`http://127.0.0.1:8765/`**

### Возможности интерфейса:
- **Быстрый туннель**: Кнопка включения/выключения туннеля AmneziaWG в один клик.
- **Телеметрия**: Объем переданных (TX) и принятых (RX) байт, таймер последнего handshake, статус соединения.
- **Режимы маршрутизации**:
  - `Smart (PAC)`: Автоматическое переключение маршрутов по доменам.
  - `Global Proxy`: Перенаправление всего трафика через BSDM Proxy.
  - `Прямой доступ`: Отключение перехвата трафика.
- **Менеджер правил**: Визуальное добавление, редактирование и удаление правил для доменов.

---

## 3. macOS App & Автоматическая настройка (PAC)

### Сборка macOS приложения (`BSDMConnect.app`)

```bash
./packaging/agent/macos/create-macos-app.sh
open ./dist/BSDMConnect.app
```

### Настройка Auto-Proxy (PAC) в macOS через консоль:

```bash
# Установка PAC URL в системные настройки macOS:
networksetup -setautoproxyurl "Wi-Fi" "http://127.0.0.1:8765/proxy.pac"
networksetup -setautoproxystate "Wi-Fi" on
```

---

## 4. Android Client & VPN Service

Для мобильных устройств под управлением Android подготовлен проект в директории `packaging/agent/android/`:

- **WebView Dashboard**: Адаптивный мобильный интерфейс управления соединением и маршрутами.
- **Android VpnService**: Защищенный локальный туннель для корпоративных адресов.
- **Android PAC**: Настройка Proxy Auto-Config URL в параметрах Wi-Fi / APN (`http://<ip-агента>:8765/proxy.pac`).

### Сборка Android APK:

```bash
cd packaging/agent/android
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```
