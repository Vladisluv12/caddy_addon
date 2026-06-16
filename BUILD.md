# forwardproxy-traffic

Нативный модуль Caddy forwardproxy с per-user подсчётом трафика.

## Что добавлено

- **Per-user счётчики RX/TX** — считаются байты, переданные через CONNECT-туннель для каждого аутентифицированного пользователя
- **Счётчик активных соединений** — количество открытых туннелей на пользователя
- **Автоматическая запись в JSON-файл** — каждые 5 секунд сбрасывает статистику в `/etc/rixxx-panel/naive_users.json`
- **Caddyfile-опция `traffic_file`** — позволяет указать свой путь для файла статистики

## Структура

```
forwardproxy-traffic/
├── traffic.go              # NEW: счётчики + atomic flush в JSON
├── forwardproxy.go         # MODIFIED: интеграция подсчёта в dualStream
├── caddyfile.go            # MODIFIED: +traffic_file директива
├── acl.go                  # копия из klzgrad/forwardproxy
├── httpclient/httpclient.go # копия из klzgrad/forwardproxy
├── go.mod
├── go.sum                  # нужен для сборки
└── BUILD.md                # этот файл
```

## Сборка

Требуется Go 1.21+, xcaddy:

```bash
# Установить xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Скачать go.sum оригинального модуля
cd forwardproxy-traffic
go mod download

# Собрать Caddy с нашим модулем
xcaddy build --with github.com/caddyserver/forwardproxy=.
```

После сборки — бинарник `caddy` в текущей директории.

## Caddyfile

```caddyfile
{
  order forward_proxy before file_server
}
:443, example.com {
  tls me@example.com
  forward_proxy {
    basic_auth user1 pass1
    basic_auth user2 pass2
    hide_ip
    hide_via
    probe_resistance
    traffic_file /etc/rixxx-panel/naive_users.json   # опционально, это путь по умолчанию
  }
  file_server {
    root /var/www/html
  }
}
```

## Формат выходного JSON

Файл `/etc/rixxx-panel/naive_users.json`:

```json
{
  "users": {
    "user1": {"rx": 1048576, "tx": 524288, "conns": 2},
    "user2": {"rx": 2097152, "tx": 1048576, "conns": 1}
  },
  "updated_at": 1718400000
}
```

- `rx` — байты, отправленные сервером клиенту (download)
- `tx` — байты, полученные сервером от клиента (upload)
- `conns` — количество активных CONNECT-туннелей
- `updated_at` — unix timestamp последнего обновления

## Интеграция с панелью

Node.js панель читает этот файл и добавляет per-user данные в `GET /api/traffic`.
Код интеграции — см. `panel/server/traffic.js` (функция `collectNaiveUsers`).

## Тестирование

```bash
cd forwardproxy-traffic
go test ./... -v -run TestTraffic
```
