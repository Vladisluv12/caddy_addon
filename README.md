# caddy_addon — forwardproxy with per-user traffic counting

Fork of [klzgrad/forwardproxy@naive](https://github.com/klzgrad/forwardproxy) (the server-side
module for [naiveproxy](https://github.com/klzgrad/naiveproxy)), with added per-user traffic
accounting.

## What is this

A Caddy v2 HTTP handler module (`http.handlers.forward_proxy`) that provides an HTTPS forward
proxy with the naiveproxy **padding protocol** for censorship circumvention, plus atomic
per-user RX/TX counters and connection tracking.

The padding protocol (Fast Open, `Padding` header, first-8-packet padding in CONNECT tunnels)
is fully compatible with the naiveproxy client (`naive`). All original features — probe
resistance, ACL, PAC file, upstream chaining — are preserved.

## Attribution

Based on:
- [caddyserver/forwardproxy](https://github.com/caddyserver/forwardproxy) by Google Inc. (Apache 2.0)
- [klzgrad/forwardproxy](https://github.com/klzgrad/forwardproxy) — naiveproxy padding protocol (Apache 2.0)
- [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy) — Chromium-based client (BSD 3-Clause)

## Changes from klzgrad/forwardproxy@naive

- **Per-user traffic counters** — RX (download) and TX (upload) bytes counted via atomic uint64
- **Active connection tracking** — per-user CONNECT tunnel count
- **Automatic JSON flush** — stats written to disk every 5 seconds
- **Caddyfile option `traffic_file`** — configurable path for the JSON output
- **SHA-256 hashed credentials** — constant-time comparison for basic auth (improved over upstream)
- **Refactored `ServeHTTP`** — separated into `handleAuthAndRouting` / `handleConnect` / `handleNonConnect`

## Build

Requires Go 1.21+ and [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
git clone https://github.com/Vladisluv12/caddy_addon
cd caddy_addon
go mod download
xcaddy build --with github.com/caddyserver/forwardproxy=.
```

Produces a `caddy` binary with the module baked in.

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
    traffic_file /etc/rixxx-panel/naive_users.json   # optional, this is the default
  }
  file_server {
    root /var/www/html
  }
}
```

Run:

```bash
sudo setcap cap_net_bind_service=+ep ./caddy
./caddy start
```

## Traffic JSON format

File at `traffic_file` path (default `/etc/rixxx-panel/naive_users.json`):

```json
{
  "users": {
    "user1": {"rx": 1048576, "tx": 524288, "conns": 2},
    "user2": {"rx": 2097152, "tx": 1048576, "conns": 1}
  },
  "updated_at": 1718400000
}
```

| Field | Meaning |
|-------|---------|
| `rx`  | Bytes server→client (download) |
| `tx`  | Bytes client→server (upload) |
| `conns` | Active CONNECT tunnels |
| `updated_at` | Unix timestamp of last flush |

Counters are atomic — safe for concurrent reads by external panels.

## Client setup

Use the standard [naiveproxy client](https://github.com/klzgrad/naiveproxy/releases):

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://user:pass@example.com"
}
```

Or any HTTP/2 CONNECT-capable client that supports the naiveproxy padding protocol.

## Full directive reference

```
forward_proxy {
    basic_auth <user> <pass>
    hosts <host...>
    ports <port...>
    hide_ip
    hide_via
    disable_insecure_upstreams_check
    probe_resistance [secret.domain]
    serve_pac [/path.pac]
    dial_timeout <seconds>
    max_idle_conns <int>
    max_idle_conns_per_host <int>
    upstream <https://user:pass@upstream:443>
    traffic_file <path>
    acl {
        allow <subnet|hostname...>
        deny  <subnet|hostname...>
        allow_file <path>
        deny_file  <path>
    }
}
```

## Testing

```bash
cd caddy_addon
go test ./... -v -count=1
```

Integration tests spin up 11 Caddy virtual servers with TLS and internal CA.

## License

Copyright 2017 Google Inc.  
Licensed under the Apache License, Version 2.0.
