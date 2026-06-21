# Forward Proxy ACL — Справочник

Расширенная ACL для NaiveProxy/Caddy forward proxy модуля с поддержкой GeoIP, Geosite, фильтрации по протоколу/порту и настраиваемой обработкой приватных IP.

**Приватные IP заблокированы по умолчанию.** Используйте `bypass_private` для разрешения доступа.

---

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Директивы Caddyfile](#директивы-caddyfile)
3. [ACL-правила](#acl-правила)
   - [IP и CIDR](#ip-и-cidr)
   - [Домены](#домены)
   - [GeoIP](#geoip)
   - [Geosite](#geosite)
   - [Протокол/Порт](#протоколпорт)
4. [Обработка приватных IP](#обработка-приватных-ip)
5. [Порядок правил](#порядок-правил)
6. [Полные примеры](#полные-примеры)

---

## Быстрый старт

```caddyfile
:443 {
    forward_proxy {
        basic_auth user1 password1
        hide_ip
        hide_via
        probe_resistance

        # GeoIP/Geosite (опционально)
        geoip_dat /usr/local/share/geoip/geoip.dat
        geosite_dat /usr/local/share/geosite/geosite.dat

        acl {
            # Приватные IP уже заблокированы по умолчанию.
            # Чтобы разрешить доступ к ним:
            # bypass_private

            # Разрешаем только определённые страны
            geoip:RU allow
            geoip:!CN allow
            geoip:all deny

            # Разрешаем google-сервисы
            geosite:google allow

            # Разрешаем только HTTP и HTTPS
            allow tcp/80
            allow tcp/443
            deny tcp/all
        }
    }
}
```

---

## Директивы Caddyfile

### Базовые

| Директива | Описание | Пример |
|-----------|----------|--------|
| `basic_auth` | Аутентификация по логину/паролю | `basic_auth user1 pass1` |
| `hide_ip` | Скрыть IP клиента в Forwarded | `hide_ip` |
| `hide_via` | Убрать заголовок Via | `hide_via` |
| `probe_resistance` | Скрытие прокси от проверок | `probe_resistance example.com` |
| `serve_pac` | Путь к PAC-файлу | `serve_pac /proxy.pac` |
| `dial_timeout` | Таймаут соединения | `dial_timeout 10s` |
| `max_idle_conns` | Макс. idle-соединений (глобально) | `max_idle_conns 100` |
| `max_idle_conns_per_host` | Макс. idle-соединений на хост | `max_idle_conns_per_host 10` |
| `upstream` | Upstream-прокси | `upstream https://parent:8443` |
| `traffic_file` | Файл статистики трафика | `traffic_file /var/log/traffic.json` |
| `ports` | Разрешённые порты (вне ACL) | `ports 80 443 8080` |

### GeoIP/Geosite файлы

| Директива | Описание | Пример |
|-----------|----------|--------|
| `geoip_dat` | Путь к geoip.dat (V2Ray-формат) | `geoip_dat /usr/share/geoip/geoip.dat` |
| `geosite_dat` | Путь к geosite.dat (V2Ray-формат) | `geosite_dat /usr/share/geosite/geosite.dat` |

---

## ACL-правила

Блок `acl` содержит список правил, обрабатываемых **сверху вниз**, первое совпадение определяет результат.

### Синтаксис

```
acl {
    <директива> <цель> [allow|deny]
}
```

### IP и CIDR

Разрешает/запрещает доступ по IP-адресу или сети.

```
acl {
    allow 8.8.8.8              # один IP
    allow 10.0.0.0/8           # CIDR-сеть
    deny 192.168.1.0/24        # запрет подсети
    allow all                  # разрешить всё (остаток)
}
```

- **IPv4 и IPv6** — оба поддерживаются
- **Одиночный IP** — автоматически преобразуется в `/32` или `/128`
- **`all`** — специальный субъект, совпадает с любым адресом

### Домены

Разрешает/запрещает доступ по доменному имени.

```
acl {
    allow example.com              # точное совпадение
    allow *.example.com            # домен + все поддомены
    deny ads.example.com           # точный запрет
    deny *.tracker.com             # запрет домена и поддоменов
}
```

- `*.` префикс — включает поддомены (`sub.example.com` совпадёт с `*.example.com`)
- Без `*.` — только точное совпадение

### GeoIP

Матчинг IP-адресов по стране. Требует `geoip_dat` с V2Ray geoip.dat.

```
acl {
    geoip:RU allow        # разрешить Россию
    geoip:!CN deny        # запретить всё, кроме Китая
    geoip:US allow        # разрешить США
    geoip:all deny        # запретить все остальные страны
}
```

- Двухбуквенные коды стран (ISO 3166-1 alpha-2): `RU`, `US`, `CN`, `DE`, `JP`...
- `!` префикс — инверсия: правило применяется к IP, **не** принадлежащим указанной стране
- Работает на уровне IP после DNS-резолва (до или вместо подключения)

### Geosite

Матчинг доменов по категориям (группам доменов). Требует `geosite_dat` с V2Ray geosite.dat.

```
acl {
    geosite:google allow         # разрешить Google-сервисы
    geosite:cn deny              # заблокировать китайские сайты
    geosite:ads deny             # заблокировать рекламные домены
    geosite:!cn allow            # разрешить всё, кроме китайских
}
```

- Категории определяются содержимым geosite.dat (стандартные: `google`, `cn`, `ads`, `facebook`, `telegram`...)
- `!` префикс — инверсия: правило применяется к доменам, **не** входящим в категорию

### Протокол/Порт

Фильтрация по протоколу (TCP/UDP) и номеру порта. Можно комбинировать с IP/доменами.

```
acl {
    allow tcp/80            # разрешить HTTP
    allow tcp/443           # разрешить HTTPS
    allow udp/53            # разрешить DNS
    deny tcp/22             # заблокировать SSH
    deny tcp/3389           # заблокировать RDP
    allow tcp/80-443        # разрешить диапазон портов
    allow tcp/all           # разрешить все TCP-порты
}
```

**Формат:** `<proto>/<port>`

| Поле | Значения | Описание |
|------|----------|----------|
| `proto` | `tcp`, `udp`, `any` | Протокол транспорта |
| `port` | `N` (1-65535), `N-M` (диапазон), `all` | Порт или диапазон |

**Специальный синтаксис:** если указан `proto/port` без субъекта, субъект становится `all` (любой адрес/домен):

```
allow tcp/443        # эквивалент: allow all tcp/443
```

**Комбинация с IP/доменом:**

```
allow 10.0.0.0/8 tcp/80    # разрешить HTTP только для 10.0.0.0/8
deny example.com udp/53     # запретить DNS для example.com
```

---

## Обработка приватных IP

По умолчанию приватные IP-адреса **запрещены** (bypass). Это предотвращает SSRF-атаки через прокси.

### Диапазоны приватных IP

| Сеть | Описание |
|------|----------|
| `10.0.0.0/8` | Class A private |
| `100.64.0.0/10` | CGNAT (RFC 6598) |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `172.16.0.0/12` | Class B private |
| `192.168.0.0/16` | Class C private |
| `::1/128` | IPv6 loopback |
| `fc00::/7` | IPv6 ULA |
| `fe80::/10` | IPv6 link-local |

### Директивы управления

По умолчанию приватные IP **заблокированы** (добавляются deny-правила). Директива `bypass_private` отключает эту блокировку.

```
acl {
    bypass_private    # отключить блокировку приватных IP (разрешить доступ)
}
```

```
acl {
    private deny      # явно заблокировать (эквивалент поведения по умолчанию)
}
```

```
acl {
    private allow     # явно разрешить приватные IP
}
```

### Поведение

| Директива | Результат |
|-----------|-----------|
| *(ничего)* | Приватные IP **заблокированы** (deny правила добавляются автоматически) |
| `bypass_private` | Блокировка **отключена** — приватные IP разрешены, deny-правила не добавляются |
| `private deny` | Приватные IP **заблокированы** (explicit deny правила) |
| `private allow` | Приватные IP **разрешены** (explicit allow правила добавляются в ACL) |

**Важно:** `private deny` / `private allow` добавляют explicit правила в ACL. Если нужно переопределить поведение для конкретных адресов, добавьте правила **до** `private deny`/`private allow`.

---

## Порядок правил

Правила обрабатываются **сверху вниз**. Первое совпадение определяет результат (allow/deny). Если ни одно правило не совпало — по умолчанию **deny**.

```
acl {
    # 1. Разрешаем свой DNS
    allow 8.8.8.8
    allow 8.8.4.4

    # 2. Блокируем приватные сети
    private deny

    # 3. Разрешаем только HTTPS
    allow tcp/443
    deny tcp/all

    # 4. Всё остальное — запрещено
    deny all
}
```

**Порядок важен!** Правило `deny all` в начале блокирует всё, даже если позже есть `allow`.

### Рекомендуемый порядок

1. **Allow whitelist** — разрешённые адреса/домены/страны
2. **Deny blacklist** — запрещённые адреса/домены/страны
3. **Proto/port фильтры** — ограничения по протоколу/порту
4. **Private IP handling** — `bypass_private` (если нужно разрешить), `private deny` / `private allow`
5. **Catch-all** — `deny all` (неявный, если нет явного)

---

## Полные примеры

### Простой прокси с базовой ACL

```caddyfile
:443 {
    forward_proxy {
        basic_auth admin secret
        hide_ip
        # приватные IP заблокированы по умолчанию
    }
}
```

### Прокси с GeoIP-ограничениями

```caddyfile
:443 {
    forward_proxy {
        basic_auth user pass
        hide_ip
        hide_via

        geoip_dat /usr/local/share/geoip/geoip.dat

        acl {
            # Разрешаем только РФ и США
            geoip:RU allow
            geoip:US allow

            # Всё остальное — запрещено
            deny all
        }
    }
}
```

### Прокси с Geosite-блокировкой рекламы

```caddyfile
:443 {
    forward_proxy {
        basic_auth user pass

        geosite_dat /usr/local/share/geosite/geosite.dat

        acl {
            geosite:ads deny
            geosite:tracker deny
            # приватные IP уже заблокированы по умолчанию
        }
    }
}
```

### Прокси с фильтрацией портов

```caddyfile
:443 {
    forward_proxy {
        basic_auth user pass

        acl {
            # Разрешаем только HTTP/HTTPS
            allow tcp/80
            allow tcp/443

            # Разрешаем DNS
            allow udp/53

            # Блокируем опасные порты
            deny tcp/22
            deny tcp/23
            deny tcp/3389
            deny tcp/445

            # Всё остальное TCP — запрещено
            deny tcp/all
        }
    }
}
```

### Комплексный пример

```caddyfile
:443 {
    forward_proxy {
        basic_auth admin s3cret
        hide_ip
        hide_via
        probe_resistance
        dial_timeout 15s
        max_idle_conns 200

        geoip_dat /usr/local/share/geoip/geoip.dat
        geosite_dat /usr/local/share/geosite/geosite.dat
        traffic_file /var/log/naive_proxy/traffic.json

        acl {
            # 1. Whitelist: разрешаем себя
            allow 127.0.0.0/8
            allow ::1

            # 2. GeoIP: разрешаем свои страны
            geoip:RU allow
            geoip:BY allow
            geoip:KZ allow

            # 3. Geosite: разрешаем популярные сервисы
            geosite:google allow
            geosite:youtube allow
            geosite:telegram allow

            # 4. Глобальная блокировка по гео
            deny all

            # 5. Порт-фильтр
            allow tcp/80
            allow tcp/443
            allow tcp/8080
            deny tcp/all

            # 6. Приватные сети уже заблокированы по умолчанию
            # Для разрешения: bypass_private
        }
    }
}
```

---

## Устранение проблем

| Проблема | Решение |
|----------|---------|
| GeoIP/Geosite правила не работают | Проверьте путь в `geoip_dat`/`geosite_dat` |
| `geoip:XX` не матчит IP | Проверьте, что IP в geoip.dat есть эта страна |
| `geosite:XX` не матчит домен | Проверьте, что домен есть в geosite.dat |
| Приватные IP разрешены когда не надо | По умолчанию они заблокированы; если включили `bypass_private`, уберите его |
| Нужен доступ к приватным сетям | Добавьте `bypass_private` |
| Правило не срабатывает | Проверьте порядок — первое совпадение побеждает |
| `tcp/all` не работает | Используйте `ports` директиву или `allow tcp/1-65535` |
